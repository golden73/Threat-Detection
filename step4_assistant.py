"""
Step 4: AI SOC assistant.

Reads outputs/incidents.json + outputs/alerts.json and produces an analyst-style
report for an incident: what happened, ATT&CK mapping, and response steps for a
small IT team in Lusaka, Zambia.

Modes:
  llm      uses a hosted LLM (Anthropic, Gemini, OpenRouter or Groq)
  offline  deterministic knowledge-base report, no internet or key needed (demo-safe)
  auto     llm if any provider key is available, otherwise offline  (default)

Usage:
    python step4_assistant.py                       # explain the most severe incident
    python step4_assistant.py --incident INC-003
    python step4_assistant.py --incident INC-003 --mode offline
    python step4_assistant.py --incident INC-003 --provider gemini
    python step4_assistant.py --ask "Which incident should I handle first and why?"
"""
import argparse
import json
import os
from pathlib import Path

import llm_providers

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
    seen, unmapped = [], []
    for a in chain:
        t = a["technique_id"]
        if t not in seen:
            seen.append(t)
            if t not in KB:
                unmapped.append(t)
                lines.append(f'- **{t} {a["attack_type"]}** (tactic: {a["tactic"]}): '
                             f'No knowledge-base entry yet; treat as generic detection.')
            else:
                k = KB[t]
                lines.append(f'- **{t} {k["name"]}** (tactic: {k["tactic"]}): {k["meaning"]}')
    kb_ids = [t for t in seen if t in KB]  # unmapped techniques have no KB guidance
    if unmapped:
        lines.append(f'  • UNMAPPED technique IDs with no KB entry: {", ".join(unmapped)}')
    lines += ["", "## Immediate actions"]
    for t in kb_ids:
        lines += [f"- {s}" for s in KB[t]["immediate"]]
    lines += ["", "## Longer-term fixes"]
    for t in kb_ids:
        lines += [f"- {s}" for s in KB[t]["longer_term"]]
    lines += ["", "## ATT&CK mitigations"]
    mit = "; ".join(m for t in kb_ids for m in KB[t]["mitigations"])
    lines.append(f"- {mit}" if mit else "- none (no mapped techniques)")
    lines += ["", "## Caveats",
              "- Detections come from an ML model on network flow data; confirm with firewall, "
              "server and authentication logs before concluding compromise.",
              "- Source IPs may be NAT or shared addresses; attribution is not implied."]
    return "\n".join(lines)


def llm_call(user_content, provider=None, model=None, key=None):
    """Call one hosted provider with the SOC system prompt."""
    provider = provider or os.environ.get("LLM_PROVIDER") or llm_providers.ORDER[0]
    model = model or os.environ.get("LLM_MODEL")
    return llm_providers.call(provider, model, key or llm_providers.api_key(provider),
                              SYSTEM_PROMPT, user_content)


def llm_available(provider=None, key=None) -> bool:
    if provider:
        return llm_providers.configured(provider, key)
    return llm_providers.available(key, provider) is not None


def make_report(incident, alerts, mode="auto", provider=None, model=None,
                key=None) -> tuple[str, str]:
    """Return (effective_mode, markdown) for one incident.

    Used by both the CLI and the live engine. If an LLM call fails (bad key,
    quota, network), fall back to the offline report and say so in the output —
    a live feed should never stall just because the API is unavailable.
    """
    provider = provider or os.environ.get("LLM_PROVIDER")
    if mode == "auto":
        chosen = llm_providers.available(key, provider)
        mode = "llm" if chosen else "offline"
        provider = chosen or provider
    if mode != "llm":
        return "offline", offline_report(incident, alerts)

    provider = provider or llm_providers.ORDER[0]
    model = model or llm_providers.default_model(provider)
    try:
        ctx = context_for(incident, alerts)
        text = llm_call(f"Explain this incident:\n{json.dumps(ctx, indent=1)}",
                        provider=provider, model=model, key=key)
        return "llm", text
    except Exception as exc:
        text = offline_report(incident, alerts)
        text += (f"\n\n## LLM unavailable\n- {llm_providers.PROVIDERS[provider]['label']} "
                 f"({model}) failed, so this report fell back to the offline knowledge base: "
                 f"{type(exc).__name__}: {exc}\n")
        return "offline", text


def save_report(incident_id: str, mode: str, text: str) -> Path:
    """Write a report where the dashboard's /api/reports endpoints can find it."""
    folder = Path("outputs/reports")
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{incident_id}_{mode}.md"
    path.write_text(text, encoding="utf-8")
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--incident")
    ap.add_argument("--mode", choices=["auto", "llm", "offline"], default="auto")
    ap.add_argument("--provider", choices=list(llm_providers.ORDER),
                    help="LLM provider (default: first configured, or gemini)")
    ap.add_argument("--model", help="model ID override for the chosen provider")
    ap.add_argument("--ask")
    ap.add_argument("--rag", action="store_true",
                    help="augment the offline report with passages retrieved from a local corpus (RAG)")
    args = ap.parse_args()

    incidents, alerts = load()
    mode = args.mode
    provider = args.provider or os.environ.get("LLM_PROVIDER")
    if mode == "auto":
        chosen = llm_providers.available(override_provider=provider)
        mode = "llm" if chosen else "offline"
        provider = chosen or provider
    print(f"[mode: {mode}" + (f" · provider: {provider}" if mode == "llm" and provider else "") + "]\n")

    if args.ask:
        if mode != "llm":
            raise SystemExit("--ask needs an LLM key. Set one of: " +
                             ", ".join(llm_providers.PROVIDERS[p]["env"]
                                       for p in llm_providers.ORDER))
        ctx = [context_for(i, alerts) for i in incidents]
        print(llm_call(f"Incidents and knowledge:\n{json.dumps(ctx, indent=1)}\n\nQuestion: {args.ask}",
                       provider=provider, model=args.model))
        return

    if args.incident:
        inc = next((i for i in incidents if i["incident_id"] == args.incident), None)
        if inc is None:
            raise SystemExit(f"No such incident. Available: {[i['incident_id'] for i in incidents]}")
    else:
        inc = max(incidents, key=lambda i: SEV_ORDER.index(i["severity"]))

    effective, text = make_report(inc, alerts, mode, provider=provider, model=args.model)

    if args.rag and effective != "llm":
        try:
            from rag import RagIndex
            idx = RagIndex.from_paths(["writeups", "README.md", "data/README.md"])
            hits = idx.retrieve(f"{inc['summary']} " + " ".join(inc.get('tactics', [])), k=4)
            text += "\n\n## Retrieved context (RAG)\n"
            if not hits:
                text += "- No relevant passages found in the local corpus.\n"
            else:
                for chunk, score in hits:
                    text += f"- (score {score:.2f}) {chunk[:280].replace(chr(10), ' ')}\n"
        except Exception as e:
            text += f"\n\n## Retrieved context (RAG)\n- RAG unavailable: {e}\n"

    print(text)
    suffix = ("rag" if args.rag else "offline") if effective != "llm" else (provider or "llm")
    out = save_report(inc["incident_id"], suffix, text)
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
