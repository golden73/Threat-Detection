"""
Step 4: AI SOC assistant.

Reads outputs/incidents.json + outputs/alerts.json and produces an analyst-style
report for an incident: what happened, ATT&CK mapping, and response steps for a
small IT team in Lusaka, Zambia.

Two modes:
  llm      uses the Anthropic API (needs: pip install anthropic, env var ANTHROPIC_API_KEY)
  offline  deterministic knowledge-base report, no internet or key needed (demo-safe)
  auto     llm if a key is available, otherwise offline  (default)

Usage:
    python step4_assistant.py                      # explain the most severe incident
    python step4_assistant.py --incident INC-003
    python step4_assistant.py --incident INC-003 --mode offline
    python step4_assistant.py --ask "Which incident should I handle first and why?"
"""
import argparse
import json
import os
from pathlib import Path

MODEL = os.environ.get("ASSISTANT_MODEL", "claude-sonnet-5-5")
SEV_ORDER = ["low", "medium", "high", "critical"]

# ---- ATT&CK knowledge base (what the assistant is grounded on) -------------
KB = {
    "T1595": {
        "name": "Active Scanning", "tactic": "Reconnaissance",
        "meaning": "The source actively probed the target network from outside to discover "
                   "open ports and running services before attempting any further attack. "
                   "This is pre-compromise reconnaissance: the scanner is preparing to find "
                   "and hit an exposed service.",
        "immediate": ["Block or rate-limit the scanning source at the firewall.",
                      "Check which ports and services responded, and whether any should not be exposed.",
                      "Expect a follow-up attack and watch for brute force, exploit, or flood traffic."],
        "longer_term": ["Close unused ports and disable unneeded services.",
                        "Segment the network so one exposed host does not reveal everything.",
                        "Enable port-scan detection on the firewall/IDS (e.g. Suricata, Snort) and alert on scans.",
                        "Document your external exposure so you know what is reachable from the internet."],
        "mitigations": ["M1056 Pre-compromise", "M1031 Network Intrusion Prevention",
                        "M1030 Network Segmentation", "M1042 Disable or Remove Feature or Program"],
    },
    "T1498": {
        "name": "Network Denial of Service", "tactic": "Impact",
        "meaning": "A flood of traffic aimed at the target to exhaust bandwidth or server resources "
                   "and make a service unavailable.",
        "immediate": ["Confirm service impact (is the site or system actually slow or down?).",
                      "Contact your ISP/upstream provider to filter or rate-limit the flood.",
                      "Apply rate limiting or a temporary block on the source at the edge firewall."],
        "longer_term": ["Put public services behind a CDN or DDoS-protection service.",
                        "Configure rate limits, SYN-flood protection and connection limits.",
                        "Prepare a written DoS runbook with the ISP's contact details."],
        "mitigations": ["M1037 Filter Network Traffic"],
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing", "tactic": "Credential Access",
        "meaning": "Many login attempts against a service (here FTP or SSH) to guess valid credentials. "
                   "If one succeeds, the attacker gains access to the system.",
        "immediate": ["Block the source and check authentication logs for any SUCCESSFUL login from it.",
                      "If a login succeeded, treat the account as compromised: reset the password, "
                      "end sessions, and review what the account did."],
        "longer_term": ["Enforce strong passwords and account lockout / fail2ban.",
                        "Use SSH keys and multi-factor authentication; avoid plain FTP (use SFTP).",
                        "Do not expose SSH/FTP to the internet unless necessary; restrict by IP or VPN."],
        "mitigations": ["M1036 Account Use Policies", "M1032 Multi-factor Authentication",
                        "M1027 Password Policies", "M1018 User Account Management"],
    },
}

SMB_CONTEXT = (
    "The audience is a small IT team at an organisation in Lusaka, Zambia (for example a school, clinic, "
    "SACCO or small business) with few security staff and a limited budget. Prefer free or open-source "
    "tools, practical steps, and mention contacting the ISP/upstream provider for flooding attacks. "
    "You may suggest reporting serious incidents to the national CIRT (ZM-CIRT at ZICTA) but tell the "
    "reader to verify current contacts and legal reporting duties; do not invent legal specifics."
)

SYSTEM_PROMPT = (
    "You are a SOC assistant. Explain security incidents to a junior analyst. "
    "Use ONLY the incident data and ATT&CK knowledge provided; do not invent IPs, times, or counts. "
    "The detections come from an ML model on network-flow data, so state uncertainty honestly "
    "(a detection is not proof of compromise). " + SMB_CONTEXT + " "
    "Format: 1) Summary, 2) Timeline, 3) ATT&CK mapping (technique IDs), "
    "4) Likely attacker goal, 5) Immediate actions, 6) Longer-term fixes, 7) Caveats. "
    "Keep it under 350 words."
)


def load():
    inc = json.load(open("outputs/incidents.json"))
    alerts = {a["alert_id"]: a for a in json.load(open("outputs/alerts.json"))}
    return inc, alerts


def context_for(incident, alerts):
    chain = [alerts[i] for i in incident["alert_ids"]]
    kb = {a["technique_id"]: KB[a["technique_id"]] for a in chain if a["technique_id"] in KB}
    return {"incident": incident, "alerts": chain, "attack_knowledge": kb}


def offline_report(incident, alerts):
    chain = [alerts[i] for i in incident["alert_ids"]]
    lines = [f'# {incident["incident_id"]}  ({incident["severity"].upper()})', ""]
    lines.append("## Summary")
    tactics = " -> ".join(incident["tactics"])
    lines.append(f'Source {incident["source_ip"]} showed {len(chain)} detected activity burst(s) '
                 f'({incident["total_flows"]:,} flows) between {incident["first_seen"]} and '
                 f'{incident["last_seen"]}, covering the tactics: {tactics}. '
                 f'Target(s): {", ".join(incident["targets"])}.')
    if len(incident["tactics"]) >= 2:
        lines.append("Multiple stages from one source suggest a deliberate, staged attack "
                     "rather than a one-off event.")
    lines += ["", "## Timeline"]
    for a in chain:
        lines.append(f'- {a["first_seen"]} to {a["last_seen"]}: {a["attack_type"]} '
                     f'({a["flows"]:,} flows, {a["target_ports"]} target ports, '
                     f'avg confidence {a["avg_confidence"]:.2f})')
    lines += ["", "## ATT&CK mapping"]
    seen = []
    for a in chain:
        t = a["technique_id"]
        if t not in seen:
            seen.append(t)
            k = KB[t]
            lines.append(f'- **{t} {k["name"]}** (tactic: {k["tactic"]}): {k["meaning"]}')
    lines += ["", "## Immediate actions"]
    for t in seen:
        lines += [f"- {s}" for s in KB[t]["immediate"]]
    lines += ["", "## Longer-term fixes"]
    for t in seen:
        lines += [f"- {s}" for s in KB[t]["longer_term"]]
    lines += ["", "## ATT&CK mitigations", "- " + "; ".join(m for t in seen for m in KB[t]["mitigations"])]
    lines += ["", "## Caveats",
              "- Detections come from an ML model on network flow data; confirm with firewall, "
              "server and authentication logs before concluding compromise.",
              "- Source IPs may be NAT or shared addresses; attribution is not implied."]
    return "\n".join(lines)


def llm_call(user_content):
    import anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(model=MODEL, max_tokens=1200, system=SYSTEM_PROMPT,
                                  messages=[{"role": "user", "content": user_content}])
    return "".join(b.text for b in resp.content if b.type == "text")


def llm_available():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
        return True
    except ImportError:
        return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--incident")
    ap.add_argument("--mode", choices=["auto", "llm", "offline"], default="auto")
    ap.add_argument("--ask")
    args = ap.parse_args()

    incidents, alerts = load()
    mode = args.mode
    if mode == "auto":
        mode = "llm" if llm_available() else "offline"
    print(f"[mode: {mode}]\n")

    if args.ask:
        if mode != "llm":
            raise SystemExit("--ask needs LLM mode (set ANTHROPIC_API_KEY and pip install anthropic).")
        ctx = [context_for(i, alerts) for i in incidents]
        print(llm_call(f"Incidents and knowledge:\n{json.dumps(ctx, indent=1)}\n\nQuestion: {args.ask}"))
        return

    if args.incident:
        inc = next((i for i in incidents if i["incident_id"] == args.incident), None)
        if inc is None:
            raise SystemExit(f"No such incident. Available: {[i['incident_id'] for i in incidents]}")
    else:
        inc = max(incidents, key=lambda i: SEV_ORDER.index(i["severity"]))

    if mode == "llm":
        text = llm_call(f"Explain this incident:\n{json.dumps(context_for(inc, alerts), indent=1)}")
    else:
        text = offline_report(inc, alerts)

    print(text)
    Path("outputs/reports").mkdir(parents=True, exist_ok=True)
    out = Path("outputs/reports") / f'{inc["incident_id"]}_{mode}.md'
    out.write_text(text, encoding="utf-8")
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
