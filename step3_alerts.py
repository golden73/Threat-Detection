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
    "PortScan": {"technique_id": "T1595", "technique": "Active Scanning",
                 "tactic": "Reconnaissance", "severity": "medium"},
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


def _union_find(n):
    parent = list(range(n))
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    return parent, find, union


def build_graph_incidents(alert_recs: list[dict], link_gap_minutes: int = 30) -> list[dict]:
    """Correlate alerts into incidents using a graph (union-find).

    Two alerts are linked when they share a source IP, a target host, or occur
    within ``link_gap_minutes`` of each other, so distributed/multi-source
    attacks collapse into a single incident.
    """
    n = len(alert_recs)
    if n == 0:
        return []
    parent, find, union = _union_find(n)
    gap = pd.Timedelta(minutes=link_gap_minutes)
    order = sorted(range(n), key=lambda i: alert_recs[i]["first_seen"])
    for i in range(n):
        a = alert_recs[order[i]]
        for j in range(i + 1, n):
            b = alert_recs[order[j]]
            if pd.Timestamp(b["first_seen"]) - pd.Timestamp(a["last_seen"]) > gap:
                break
            if (a["source_ip"] == b["source_ip"]
                    or a["top_target"] == b["top_target"]):
                union(order[i], order[j])

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    incidents = []
    for members in groups.values():
        chain = sorted((alert_recs[i] for i in members), key=lambda a: a["first_seen"])
        tactics = list(dict.fromkeys(a["tactic"] for a in chain))
        sev = max((a["severity"] for a in chain), key=SEV_ORDER.index)
        known = [t for t in tactics if t != UNMAPPED_TACTIC]
        if len(known) >= 2:
            sev = "critical"
        steps = " -> ".join(dict.fromkeys(
            f'{a["attack_type"]} ({a["technique_id"]})' for a in chain))
        incidents.append({
            "source_ips": sorted({a["source_ip"] for a in chain}),
            "first_seen": chain[0]["first_seen"],
            "last_seen": max(a["last_seen"] for a in chain),
            "alert_ids": [a["alert_id"] for a in chain],
            "tactics": tactics,
            "techniques": [a["technique_id"] for a in chain],
            "total_flows": sum(a["flows"] for a in chain),
            "targets": sorted({a["top_target"] for a in chain}),
            "severity": sev,
            "summary": f"graph incident: {steps}",
        })
    incidents.sort(key=lambda i: i["first_seen"])
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"GINC-{n:03d}"
    return incidents


def main(path: str, graph: bool = False, out_dir: str = "outputs") -> None:
    df = pd.read_csv(path, low_memory=False)
    alerts = build_alerts(df)
    alert_recs = alerts_to_records(alerts)
    incidents = build_incidents(alert_recs)

    unmapped = sorted({a["attack_type"] for a in alert_recs if a["technique_id"] == "UNMAPPED"})
    if unmapped:
        print(f"WARNING: no ATT&CK mapping for {unmapped}. Add them to MITRE in this file "
              f"(and to the knowledge base in step 4) to get proper reports.\n")

    # Guard against accidental clobbering of the real committed artifacts by
    # dev/smoke runs on a different predictions file.
    a_json = Path(out_dir) / "alerts.json"
    if str(path) != "outputs/predictions.csv" and a_json.exists() and out_dir == "outputs":
        raise SystemExit(
            f"refusing to overwrite {a_json} while reading '{path}'.\n"
            "Point the run elsewhere instead: --out-dir /tmp/smoke/outputs")

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    with open(a_json, "w") as f:
        json.dump(alert_recs, f, indent=2)
    with open(Path(out_dir) / "incidents.json", "w") as f:
        json.dump(incidents, f, indent=2)

    print(f"{len(alert_recs)} alerts -> {len(incidents)} incidents\n")
    print("Alerts:")
    for a in alert_recs:
        print(f'  {a["alert_id"]}  {a["first_seen"]}  {a["source_ip"]:<16} '
              f'{a["attack_type"]:<12} {a["technique_id"]:<10} flows={a["flows"]}')
    print("\nIncidents:")
    for i in incidents:
        print(f'  {i["incident_id"]}  [{i["severity"].upper()}]  {i["summary"]}')

    if graph:
        g_incidents = build_graph_incidents(alert_recs)
        with open(Path(out_dir) / "incidents_graph.json", "w") as f:
            json.dump(g_incidents, f, indent=2)
        print(f"\ngraph correlation: {len(g_incidents)} graph incidents -> {out_dir}/incidents_graph.json")
        for i in g_incidents:
            print(f'  {i["incident_id"]}  [{i["severity"].upper()}]  sources={i["source_ips"]} '
                  f'alerts={len(i["alert_ids"])} flows={i["total_flows"]:,}')

    print(f"\nsaved {out_dir}/alerts.json and {out_dir}/incidents.json" + (" (+ incidents_graph.json)" if graph else ""))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="outputs/predictions.csv")
    ap.add_argument("--graph", action="store_true",
                    help="also run graph-based correlation -> outputs/incidents_graph.json")
    ap.add_argument("--out-dir", default="outputs",
                    help="where to write alerts.json / incidents.json")
    a = ap.parse_args()
    main(a.path, a.graph, a.out_dir)