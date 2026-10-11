"""
Step 6: Build outputs/demo.html - one offline page for the live demo.
No Streamlit or internet needed: it just opens in a browser.

Usage (after steps 2-5 and step4 for each incident):
    python step6_demo_page.py
    start outputs\\demo.html
"""
import html
import json
import re
from pathlib import Path

OUT = Path("outputs")


CSS = """
[data-mode=dark]{--bg:#0d0f12;--surface:#15181d;--surface2:#1b1f26;--fg:#e8eaed;--muted:#9aa3b2;--border:#2a303a;--shadow:0 1px 2px rgba(0,0,0,.4);
  --blue:#5b9bff;--blue-soft:rgba(91,155,255,.16);--gold:#d9ad3f;--gold-soft:rgba(217,173,63,.16)}
[data-mode=light]{--bg:#f2f4f7;--surface:#ffffff;--surface2:#eaecf0;--fg:#101828;--muted:#475467;--border:#c9ced6;--shadow:0 1px 3px rgba(16,24,40,.14);
  --blue:#1d4ed8;--blue-soft:rgba(29,78,216,.10);--gold:#946a00;--gold-soft:rgba(148,106,0,.12)}
*{box-sizing:border-box}
body{font-family:Inter,system-ui,"Segoe UI",Roboto,Arial,sans-serif;max-width:1180px;margin:0 auto;padding:20px 20px 60px;
  background:var(--bg);color:var(--fg);line-height:1.55;transition:background .2s,color .2s}
.hero{padding-bottom:14px;border-bottom:3px solid;border-image:linear-gradient(90deg,var(--blue),var(--gold)) 1}
h1{margin:6px 0 0;font-size:30px;font-weight:700;letter-spacing:-.02em;color:var(--fg)}
.sub{color:var(--muted);margin:6px 0 0;font-size:15px}
h2{display:flex;align-items:center;gap:10px;margin:40px 0 14px;font-size:19px;font-weight:650;letter-spacing:-.01em}
h2::before{content:"";width:5px;height:22px;border-radius:3px;background:linear-gradient(180deg,var(--blue),var(--gold))}
h3{font-size:17px;margin:12px 0 6px}
h4{margin:16px 0 6px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}
p{margin:6px 0} ul{margin:6px 0;padding-left:20px} li{margin:3px 0}
.topbar{display:flex;justify-content:flex-end;padding:6px 0 10px}
.topbar button{background:var(--surface);color:var(--fg);border:1px solid var(--border);border-radius:999px;padding:7px 16px;
  cursor:pointer;font:inherit;font-size:13px;font-weight:600;box-shadow:var(--shadow)}
.topbar button:hover{border-color:var(--blue)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
.card{background:var(--surface);border:1px solid var(--border);position:relative;overflow:hidden;border-radius:14px;
  padding:18px;color:var(--muted);font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;box-shadow:var(--shadow)}
.card::before{content:"";position:absolute;left:0;right:0;top:0;height:4px;background:linear-gradient(90deg,var(--blue),var(--gold))}
.card b{display:block;font-size:28px;letter-spacing:-.02em;text-transform:none;color:var(--fg);margin-bottom:2px}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:14px;margin:8px 0;background:var(--surface);
  border:1px solid var(--border);border-radius:12px;overflow:hidden;box-shadow:var(--shadow)}
th{background:var(--surface2);color:var(--fg);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:700;text-align:left;padding:10px 12px;border-bottom:2px solid var(--blue)}
td{padding:10px 12px;border-top:1px solid var(--border)}
tr:hover td{background:var(--surface2)}
.note{color:var(--muted);border-left:4px solid;border-image:linear-gradient(180deg,var(--blue),var(--gold)) 1;padding:2px 0 2px 12px;margin:12px 0}
details{background:var(--surface);border:1px solid var(--border);border-radius:14px;margin:12px 0;box-shadow:var(--shadow);overflow:hidden}
details[open]>summary{border-bottom:1px solid var(--border)}
details>:not(summary){margin-left:18px;margin-right:18px}
summary{cursor:pointer;font-weight:650;padding:14px 18px;list-style:none}
summary::-webkit-details-marker{display:none}
summary::after{content:"+";float:right;color:var(--gold);font-weight:700} details[open]>summary::after{content:"\\2212"}
.sev{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-size:11px;font-weight:700;letter-spacing:.05em;margin-right:6px}
.sev.critical{background:#b3102a}.sev.high{background:#d92d34}.sev.medium{background:#b87700}.sev.low{background:#1f7a3a}
@media print{.topbar{display:none}}
"""

JS = """
(function(){
  var root=document.documentElement;
  var mode=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark';
  try{mode=localStorage.getItem('tdMode')||mode;}catch(e){}
  function apply(){
    root.setAttribute('data-mode',mode);
    document.getElementById('btnMode').textContent=mode==='dark'?'\u2600 Light mode':'\u263E Dark mode';
    try{localStorage.setItem('tdMode',mode);}catch(e){}
  }
  document.getElementById('btnMode').onclick=function(){mode=(mode==='dark')?'light':'dark';apply();};
  apply();
})();
"""

def jload(name, default):
    p = OUT / name
    return json.load(open(p)) if p.exists() else default


def md_to_html(md: str) -> str:
    out, in_list = [], False
    for line in md.splitlines():
        s = html.escape(line)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        if line.startswith("- "):
            if not in_list:
                out.append("<ul>"); in_list = True
            out.append(f"<li>{s[2:]}</li>")
            continue
        if in_list:
            out.append("</ul>"); in_list = False
        if line.startswith("## "):
            out.append(f"<h4>{s[3:]}</h4>")
        elif line.startswith("# "):
            out.append(f"<h3>{s[2:]}</h3>")
        elif line.strip():
            out.append(f"<p>{s}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def pct(x):
    return f"{x * 100:.2f}%"


def main():
    metrics = jload("metrics.json", {})
    hard = jload("hard_eval.json", {})
    alerts = jload("alerts.json", [])
    incidents = jload("incidents.json", [])

    parts = []
    # 1. Detection performance
    if metrics:
        parts.append("<h2>1. Detection performance (baseline, random split)</h2><div class='cards'>"
                     f"<div class='card'><b>{pct(metrics['precision'])}</b>precision</div>"
                     f"<div class='card'><b>{pct(metrics['recall'])}</b>recall</div>"
                     f"<div class='card'><b>{pct(metrics['f1'])}</b>F1</div>"
                     f"<div class='card'><b>{metrics['false_positive_rate'] * 100:.4f}%</b>false-positive rate</div></div>")
    chrono = hard.get("chronological")
    if chrono:
        o = chrono["overall"]
        parts.append("<h2>2. Honest evaluation</h2><h4>Chronological split (train early, test later)</h4>"
                     f"<p>Precision {pct(o['precision'])}, recall {pct(o['recall'])}, "
                     f"F1 {pct(o['f1'])}, false-positive rate {o['fpr'] * 100:.4f}%</p>")
    loo = hard.get("leave_one_attack_out")
    if loo:
        rows = "".join(f"<tr><td>{html.escape(k)}</td><td>{pct(v['unseen_attack_recall'])}</td>"
                       f"<td>{v['benign_fpr'] * 100:.4f}%</td></tr>" for k, v in loo.items())
        parts.append("<h4>Leave-one-attack-out (attack type never seen in training)</h4>"
                     "<table><tr><th>Held-out attack</th><th>Detected when unseen</th><th>Benign FPR</th></tr>"
                     f"{rows}</table><p class='note'>Limitation: the supervised model is strong on known attacks "
                     "but weak on unseen ones. Future work: add an anomaly-detection layer.</p>")

    # 3. Alerts
    rows = "".join(
        f"<tr><td>{a['alert_id']}</td><td>{a['first_seen'].replace('T', ' ')}</td><td>{a['source_ip']}</td>"
        f"<td>{a['attack_type']}</td><td>{a['technique_id']} {html.escape(a['technique'])}</td>"
        f"<td>{a['tactic']}</td><td>{a['flows']:,}</td><td>{a['severity']}</td></tr>" for a in alerts)
    parts.append("<h2>3. Alerts mapped to MITRE ATT&amp;CK</h2><table><tr><th>ID</th><th>First seen</th>"
                 "<th>Source</th><th>Attack</th><th>Technique</th><th>Tactic</th><th>Flows</th>"
                 f"<th>Severity</th></tr>{rows}</table>")

    # 4 + 5. Incidents and assistant reports
    parts.append("<h2>4. Correlated incidents and AI SOC assistant</h2>")
    for inc in incidents:
        rp = OUT / "reports" / f"{inc['incident_id']}_offline.md"
        llm = OUT / "reports" / f"{inc['incident_id']}_llm.md"
        body = ""
        if llm.exists():
            body += "<h4>LLM assistant report</h4>" + md_to_html(llm.read_text(encoding="utf-8"))
        if rp.exists():
            body += "<h4>Knowledge-base assistant report</h4>" + md_to_html(rp.read_text(encoding="utf-8"))
        if not body:
            body = "<p class='note'>No report generated yet. Run step4_assistant.py --incident " \
                   f"{inc['incident_id']}.</p>"
        parts.append(
            f"<details {'open' if inc['severity'] == 'critical' else ''}><summary>"
            f"<span class='sev {inc['severity']}'>{inc['severity'].upper()}</span> "
            f"{inc['incident_id']} - {html.escape(inc['summary'])}</summary>{body}</details>")

    page = f"""<!doctype html><html lang="en" data-mode="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI-Assisted Threat Detection &amp; Response System</title>
<style>
{CSS}
</style></head><body>
<div class="topbar"><button id="btnMode">Mode</button></div>
<div class="hero"><h1>AI-Assisted Threat Detection &amp; Response System</h1>
<p class="sub">Log-based detection, correlation and an AI SOC assistant mapped to MITRE ATT&amp;CK. Dataset: CICIDS2017 (subset).</p></div>
{''.join(parts)}
<script>{JS}</script>
</body></html>"""
    (OUT / "demo.html").write_text(page, encoding="utf-8")
    print("saved outputs/demo.html  (open it in your browser)")


if __name__ == "__main__":
    main()
