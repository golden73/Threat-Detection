#!/usr/bin/env python3
"""
Step 4: AI SOC assistant (Enhanced with multiple LLM providers).
"""
import argparse
import json
import os
from pathlib import Path

MODEL = os.environ.get("ASSISTANT_MODEL", "claude-sonnet-4-5")
SEV_ORDER = ["low", "medium", "high", "critical"]

# ---- ATT&CK knowledge base (what the assistant is grounded on) -------------
KB = {
    "T1595": {
        "name": "Active Scanning", "tactic": "Reconnaissance",
        "meaning": "The source actively probed the target network from outside to discover open ports and running services before attempting any further attack.",
        "immediate": ["Block or rate-limit the scanning source at the firewall.",
                      "Check which ports and services responded, and whether any should not be exposed.",
                      "Expect a follow-up attack and watch for brute force, exploit, or flood traffic."],
        "longer_term": ["Close unused ports and disable unneeded services.",
                        "Segment the network so one exposed host does not reveal everything.",
                        "Enable port-scan detection on the firewall/IDS."],
        "mitigations": ["M1056 Pre-compromise", "M1031 Network Intrusion Prevention",
                        "M1030 Network Segmentation", "M1042 Disable or Remove Feature or Program"],
    },
    "T1498": {
        "name": "Network Denial of Service", "tactic": "Impact",
        "meaning": "A flood of traffic aimed at the target to exhaust bandwidth or server resources and make a service unavailable.",
        "immediate": ["Confirm service impact.",
                      "Contact your ISP/upstream provider to filter or rate-limit the flood.",
                      "Apply rate limiting or a temporary block on the source at the edge firewall."],
        "longer_term": ["Put public services behind a CDN or DDoS-protection service.",
                        "Configure rate limits, SYN-flood protection and connection limits.",
                        "Prepare a written DoS runbook with the ISP's contact details."],
        "mitigations": ["M1037 Filter Network Traffic"],
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing", "tactic": "Credential Access",
        "meaning": "Many login attempts against a service (here FTP or SSH) to guess valid credentials.",
        "immediate": ["Block the source and check authentication logs for any SUCCESSFUL login from it.",
                      "If a login succeeded, treat the account as compromised: reset the password, end sessions, and review what the account did."],
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
    "You are an AI SOC assistant helping a small IT team respond to network security incidents. "
    "Be practical, specific, and concise. Ground your advice in MITRE ATT&CK. "
    + SMB_CONTEXT +
    "\n\nProvide a structured report: Incident summary, What happened, ATT&CK mapping, "
    "Immediate actions (prioritized), Longer-term fixes, Indicators to watch for, "
    "Quick checklist, and Caveats."
)

def load():
    with open("outputs/incidents.json") as f:
        incidents = json.load(f)
    with open("outputs/alerts.json") as f:
        alerts = json.load(f)
    return incidents, alerts


def context_for(inc, alerts):
    chain = [a for a in alerts if a["incident_id"] == inc["incident_id"]]
    return {
        "incident": inc,
        "alerts": chain,
        "techniques": list({a["technique_id"] for a in chain}),
    }


def offline_report(inc, alerts):
    chain = [a for a in alerts if a["incident_id"] == inc["incident_id"]]
    sev = inc["severity"].upper()
    lines = []
    lines.append(f"# Incident report: {inc['incident_id']} — {sev}")
    lines.append(f"**Summary:** {inc['summary']}")
    lines.append(f"**Time window:** {inc['start_time']} → {inc['end_time']}")
    lines.append(f"**Alert count:** {len(chain)} | **Source IPs:** {', '.join(inc['src_ips'])}")
    lines.append(f"**Target/affected ports/services:** {inc['ports_services']}")
    lines += ["", "## What happened"]
    lines.append("Based on correlated network flow alerts, this incident shows a pattern consistent with the techniques below.")
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
              "- Detections come from an ML model on network flow data; confirm with firewall, server and authentication logs before concluding compromise.",
              "- Source IPs may be NAT or shared addresses; attribution is not implied."]
    return "\n".join(lines)


def call_ollama(user_content, model="llama3.2"):
    try:
        import requests
        resp = requests.post("http://localhost:11434/v1/chat/completions", 
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content}
                ],
                "temperature": 0.3,
                "max_tokens": 1200
            }, timeout=300)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return f"Error: {resp.text}"
    except Exception as e:
        return f"Ollama error: {e}\nMake sure Ollama is running (ollama serve) and model is pulled (ollama pull {model})"


def call_openrouter(user_content, model="deepseek-chat"):
    try:
        import requests
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise Exception("OPENROUTER_API_KEY not set")
        resp = requests.post("https://openrouter.ai/api/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "HTTP-Referer": "https://github.com/golden73/Threat-Detection"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_content}
                ],
                "temperature": 0.3,
                "max_tokens": 1200
            }, timeout=300)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        return f"Error: {resp.text}"
    except Exception as e:
        return f"OpenRouter error: {e}"


def call_anthropic(user_content):
    try:
        import anthropic
        client = anthropic.Anthropic()
        resp = client.messages.create(model=MODEL, max_tokens=1200, system=SYSTEM_PROMPT,
                                      messages=[{"role": "user", "content": user_content}])
        return "".join(b.text for b in resp.content if b.type == "text")
    except Exception as e:
        return f"Anthropic error: {e}"


def llm_available():
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            import anthropic  # noqa
            return True
        except:
            pass
    if os.environ.get("OPENROUTER_API_KEY"):
        return True
    try:
        import requests
        resp = requests.get("http://localhost:11434/api/version", timeout=2)
        if resp.status_code == 200:
            return True
    except:
        pass
    return False


def main():
    ap = argparse.ArgumentParser(description="AI SOC Assistant - Enhanced with multiple providers")
    ap.add_argument("--incident")
    ap.add_argument("--mode", choices=["auto", "llm", "ollama", "openrouter", "anthropic", "offline"], default="auto")
    ap.add_argument("--ask")
    ap.add_argument("--model", help="Model name for ollama/openrouter")
    args = ap.parse_args()

    incidents, alerts = load()
    mode = args.mode
    
    if mode == "auto":
        if os.environ.get("ANTHROPIC_API_KEY"):
            try:
                import anthropic
                mode = "anthropic"
            except:
                pass
        elif os.environ.get("OPENROUTER_API_KEY"):
            mode = "openrouter"
        else:
            try:
                import requests
                resp = requests.get("http://localhost:11434/api/version", timeout=2)
                if resp.status_code == 200:
                    mode = "ollama"
                else:
                    mode = "offline"
            except:
                mode = "offline"
    
    print(f"[mode: {mode}]\n")

    if args.ask:
        if mode == "offline":
            raise SystemExit("--ask needs an LLM (use --mode ollama/openrouter/anthropic).")
        ctx = [context_for(i, alerts) for i in incidents]
        prompt = f"Incidents and knowledge:\n{json.dumps(ctx, indent=1)}\n\nQuestion: {args.ask}"
        if mode == "ollama":
            text = call_ollama(prompt, args.model or "llama3.2")
        elif mode == "openrouter":
            text = call_openrouter(prompt, args.model or "deepseek-chat")
        elif mode == "anthropic":
            text = call_anthropic(prompt)
        else:
            text = offline_report(incidents[0], alerts) if incidents else ""
        print(text)
        return

    if args.incident:
        inc = next((i for i in incidents if i["incident_id"] == args.incident), None)
        if inc is None:
            raise SystemExit(f"No such incident. Available: {[i['incident_id'] for i in incidents]}")
    else:
        inc = max(incidents, key=lambda i: SEV_ORDER.index(i["severity"]))

    prompt = f"Explain this incident:\n{json.dumps(context_for(inc, alerts), indent=1)}"
    
    if mode == "ollama":
        text = call_ollama(prompt, args.model or "llama3.2")
    elif mode == "openrouter":
        text = call_openrouter(prompt, args.model or "deepseek-chat")
    elif mode == "anthropic":
        text = call_anthropic(prompt)
    elif mode == "llm":  # backward compat
        text = call_anthropic(prompt)
    else:
        text = offline_report(inc, alerts)

    print(text)
    Path("outputs/reports").mkdir(parents=True, exist_ok=True)
    out = Path("outputs/reports") / f'{inc["incident_id"]}_{mode}.md'
    out.write_text(text, encoding="utf-8")
    print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
