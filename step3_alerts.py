"""
Step 3 (patched): Predictions -> alerts -> correlated incidents, mapped to MITRE ATT&CK.

What changed vs. the original
  - Unmapped attack classes no longer crash the script (KeyError). They get an
    "UNMAPPED" entry and a warning is printed, so no detection is silently lost.
    Unknown tactics are ignored when deciding multi-stage CRITICAL escalation.
  - Incident summaries collapse consecutive identical steps, so a scan split by the
    alert gap reads "PortScan -> DDoS" instead of "PortScan -> PortScan -> DDoS".
    (The individual alerts are unchanged.)
  - Small cleanups: the fragile `r._1` is gone and JSON files are closed properly.

Usage:
    python step3_alerts.py outputs/predictions.csv

Outputs:
    outputs/alerts.json      one alert per (source IP, attack type, time burst)
    outputs/incidents.json   alerts from the same source IP chained into incidents
"""
import json
import sys
from pathlib import Path

import pandas as pd

MIN_CONF = 0.90                       # ignore low-confidence detections
ALERT_GAP = pd.Timedelta(minutes=30)  # silence longer than this starts a new alert
INCIDENT_GAP = pd.Timedelta(minutes=60)  # alerts closer than this join one incident
MIN_FLOWS = 5                         # drop tiny bursts (likely false positives)

BRUTE = {"technique_id": "T1110.001", "technique": "Brute Force: Password Guessing",
         "tactic": "Credential Access", "severity": "high"}
MITRE = {
    "PortScan": {"technique_id": "T1046", "technique": "Network Service Discovery",
                 "tactic": "Discovery", "severity": "medium"},
    "DDoS": {"technique_id": "T1498", "technique": "Network Denial of Service",
             "tactic": "Impact", "severity": "high"},
    "FTP-Patator": BRUTE,
    "SSH-Patator": BRUTE,
}
SEV_ORDER = ["low", "medium", "high", "critical"]
UNMAPPED_TACTIC = "Unknown"


def mitre_for(attack: str) -> dict:
    """ATT&CK entry for an attack class; a safe placeholder if it has no mapping."""
    return MITRE.get(attack, {"technique_id": "UNMAPPED", "technique": attack,
                              "tactic": UNMAPPED_TACTIC, "severity": "medium"})


def build_alerts(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # CICIDS dates are day/month/year and times have no AM/PM. The capture ran
    # 8:00-17:00, so hours 1-7 are afternoon (13:00-19:00).
    df["ts"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    df["ts"] = df["ts"].where(df["ts"].dt.hour >= 8, df["ts"] + pd.Timedelta(hours=12))
    df = df.dropna(subset=["ts"])
    det = df[(df["predicted"] != "BENIGN") & (df["confidence"] >= MIN_CONF)]
    det = det.sort_values(["Source IP", "predicted", "ts"]).copy()

    grp = det.groupby(["Source IP", "predicted"])
    det["win"] = (grp["ts"].diff() > ALERT_GAP).groupby(
        [det["Source IP"], det["predicted"]]).cumsum()

    alerts = (det.groupby(["Source IP", "predicted", "win"])
              .agg(first_seen=("ts", "min"), last_seen=("ts", "max"),
                   flows=("ts", "size"), target_hosts=("Destination IP", "nunique"),
                   target_ports=("Destination Port", "nunique"),
                   top_target=("Destination IP", lambda s: s.mode().iloc[0]),
                   avg_confidence=("confidence", "mean"))
              .reset_index()
              .rename(columns={"Source IP": "source_ip"})
              .sort_values("first_seen")
              .reset_index(drop=True))
    alerts = alerts[alerts["flows"] >= MIN_FLOWS].reset_index(drop=True)
    alerts["alert_id"] = [f"ALR-{i + 1:04d}" for i in range(len(alerts))]
    return alerts


def alerts_to_records(alerts: pd.DataFrame) -> list[dict]:
    recs = []
    for r in alerts.itertuples():
        m = mitre_for(r.predicted)
        recs.append({
            "alert_id": r.alert_id, "source_ip": r.source_ip, "attack_type": r.predicted,
            "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
            "flows": int(r.flows), "target_hosts": int(r.target_hosts),
            "target_ports": int(r.target_ports), "top_target": r.top_target,
            "avg_confidence": round(float(r.avg_confidence), 4), **m,
        })
    return recs


def build_incidents(alert_recs: list[dict]) -> list[dict]:
    by_src: dict[str, list[dict]] = {}
    for a in sorted(alert_recs, key=lambda a: a["first_seen"]):
        by_src.setdefault(a["source_ip"], []).append(a)

    incidents = []
    for src, items in by_src.items():
        chains, cur = [], [items[0]]
        for a in items[1:]:
            gap = pd.Timestamp(a["first_seen"]) - pd.Timestamp(cur[-1]["last_seen"])
            if gap > INCIDENT_GAP:
                chains.append(cur)
                cur = [a]
            else:
                cur.append(a)
        chains.append(cur)

        for chain in chains:
            tactics = list(dict.fromkeys(a["tactic"] for a in chain))
            sev = max((a["severity"] for a in chain), key=SEV_ORDER.index)
            known_tactics = [t for t in tactics if t != UNMAPPED_TACTIC]
            if len(known_tactics) >= 2:  # multi-stage activity from one source
                sev = "critical"
            # collapse consecutive identical steps (e.g. one scan split by the alert gap)
            steps = " -> ".join(dict.fromkeys(
                f'{a["attack_type"]} ({a["technique_id"]})' for a in chain))
            incidents.append({
                "source_ip": src,
                "first_seen": chain[0]["first_seen"],
                "last_seen": max(a["last_seen"] for a in chain),
                "alert_ids": [a["alert_id"] for a in chain],
                "tactics": tactics,
                "techniques": [a["technique_id"] for a in chain],
                "total_flows": sum(a["flows"] for a in chain),
                "targets": sorted({a["top_target"] for a in chain}),
                "severity": sev,
                "summary": f"{src}: {steps}",
            })
    incidents.sort(key=lambda i: i["first_seen"])
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:03d}"
    return incidents


def main(path: str) -> None:
    df = pd.read_csv(path, low_memory=False)
    alerts = build_alerts(df)
    alert_recs = alerts_to_records(alerts)
    incidents = build_incidents(alert_recs)

    unmapped = sorted({a["attack_type"] for a in alert_recs if a["technique_id"] == "UNMAPPED"})
    if unmapped:
        print(f"WARNING: no ATT&CK mapping for {unmapped}. Add them to MITRE in this file "
              f"(and to the knowledge base in step 4) to get proper reports.\n")

    Path("outputs").mkdir(exist_ok=True)
    with open("outputs/alerts.json", "w") as f:
        json.dump(alert_recs, f, indent=2)
    with open("outputs/incidents.json", "w") as f:
        json.dump(incidents, f, indent=2)

    print(f"{len(alert_recs)} alerts -> {len(incidents)} incidents\n")
    print("Alerts:")
    for a in alert_recs:
        print(f'  {a["alert_id"]}  {a["first_seen"]}  {a["source_ip"]:<16} '
              f'{a["attack_type"]:<12} {a["technique_id"]:<10} flows={a["flows"]}')
    print("\nIncidents:")
    for i in incidents:
        print(f'  {i["incident_id"]}  [{i["severity"].upper()}]  {i["summary"]}')
    print("\nsaved outputs/alerts.json and outputs/incidents.json")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "outputs/predictions.csv")