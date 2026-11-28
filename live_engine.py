#!/usr/bin/env python3
"""Live detection engine: score a stream of flows and publish fresh alerts.

Two sources are supported:

  replay   replay labelled flows from data/clean.csv in timestamp order at a
           configurable rate. Works with no special privileges; useful for
           demos and for verifying the whole live path end to end.

  tshark   capture real packets with tshark and aggregate them into flows.
           Requires CAP_NET_RAW / CAP_NET_ADMIN (or root) on the interface.
           Packet-derived features are an approximation of CICIDS2017 — see
           README for the caveat.

The engine never overwrites the batch pipeline artifacts. It writes to
outputs/live/ and to outputs/reports/LIVE-*.md, which the dashboard serves.

Usage:
    python live_engine.py --source replay --rate 10 --ai-mode auto
    python live_engine.py --source tshark --interface eth0 --ai-mode llm
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import step3_alerts  # noqa: E402
import step4_assistant  # noqa: E402

LIVE_DIR = ROOT / "outputs" / "live"
FEED_PATH = LIVE_DIR / "feed.jsonl"
ALERTS_PATH = LIVE_DIR / "alerts.json"
INCIDENTS_PATH = LIVE_DIR / "incidents.json"
STATUS_PATH = LIVE_DIR / "status.json"

META = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "source_file"]
NOT_FEATURES = META + ["Destination Port", "Label", "is_attack"]
STOP = False


def _stop(signum, frame):
    global STOP
    STOP = True


def _utcnow() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _atomic_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _feature_columns(data_path: Path) -> list[str]:
    head = pd.read_csv(data_path, nrows=500, low_memory=False)
    head.columns = head.columns.str.strip()
    drop = [c for c in NOT_FEATURES if c in head.columns]
    return [c for c in head.columns if c not in drop]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class Detector:
    def __init__(self, data_path: Path, contamination: float):
        self.features = _feature_columns(data_path)
        self.model = XGBClassifier()
        self.model.load_model(str(ROOT / "models" / "xgb.json"))
        self.classes = json.loads((ROOT / "models" / "classes.json").read_text())
        self.iso = joblib.load(ROOT / "models" / "anomaly_iforest.joblib")

        # The batch anomaly scores are min/max normalised, which cannot be
        # reproduced on a stream. Calibrate a raw-score threshold on benign
        # traffic instead, at the same contamination rate.
        sample = pd.read_csv(data_path, usecols=self.features, nrows=100_000, low_memory=False)
        Xb = sample[self.features].astype("float32")
        self.raw_benign = -self.iso.score_samples(Xb)
        self.anomaly_threshold = float(np.quantile(self.raw_benign, 1 - contamination))
        print(f"loaded model ({len(self.features)} features) and anomaly layer "
              f"(threshold {self.anomaly_threshold:.4f})", flush=True)

    def score(self, rows: list[dict]) -> list[dict]:
        X = pd.DataFrame(rows)[self.features].astype("float32")
        proba = self.model.predict_proba(X)
        best = proba.argmax(axis=1)
        anomaly_raw = -self.iso.score_samples(X)
        events = []
        for row, idx, p, raw in zip(rows, best, proba, anomaly_raw):
            is_anomaly = bool(raw >= self.anomaly_threshold)
            predicted = str(self.classes[idx])
            events.append({
                "ts": _utcnow(),
                "Timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                "Flow ID": row.get("Flow ID", "live-flow"),
                "Source IP": row.get("Source IP", "0.0.0.0"),
                "Source Port": row.get("Source Port", 0),
                "Destination IP": row.get("Destination IP", "0.0.0.0"),
                "Destination Port": row.get("Destination Port", 0),
                "predicted": predicted,
                "confidence": round(float(p[idx]), 4),
                "attack": predicted.upper() != "BENIGN",
                "anomaly_score": round(float(raw), 4),
                "anomaly": is_anomaly,
                "fused": bool(predicted.upper() != "BENIGN" or is_anomaly),
                "true_label": row.get("Label"),
                "source": row.get("source_file", "live-capture"),
            })
        return events


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
def replay_source(data_path: Path, count: int, rate: float, seed: int):
    """Yield rows sampled from the clean dataset, in timestamp order.

    count > 0: replay exactly that many flows, then stop.
    count = 0: keep replaying fresh samples until the stream is stopped.
    """
    cols = _feature_columns(data_path) + [
        "Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
        "Timestamp", "Label", "source_file",
    ]
    df = pd.read_csv(data_path, usecols=lambda c: c.strip() in cols, low_memory=False)
    df.columns = df.columns.str.strip()
    labels = df["Label"].astype(str).str.strip().str.upper()
    ts = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    df["_ts"] = ts.where(ts.dt.hour >= 8, ts + pd.Timedelta(hours=12))

    attack = df[labels != "BENIGN"]
    benign = df[labels == "BENIGN"]
    rng = np.random.RandomState(seed)
    chunk = count if count > 0 else min(2000, len(df))

    def sample_chunk() -> pd.DataFrame:
        n_atk = min(len(attack), int(chunk * 0.8))
        n_ben = min(len(benign), chunk - n_atk)
        return pd.concat([
            attack.iloc[rng.choice(len(attack), n_atk, replace=False)] if n_atk else attack.iloc[:0],
            benign.iloc[rng.choice(len(benign), n_ben, replace=False)] if n_ben else benign.iloc[:0],
        ]).sort_values("_ts")

    sample = sample_chunk()
    print(f"replaying {len(sample):,} flows at {rate:g}/s"
          + (" continuously (press Stop to end)" if count == 0 else ""), flush=True)
    interval = 1.0 / rate if rate > 0 else 0
    while True:
        for row in sample.to_dict("records"):
            if STOP:
                return
            time.sleep(interval)
            yield row
        if count > 0:
            return
        sample = sample_chunk()  # fresh 80/20 mix for the next pass


def _flow_row(key, flow: dict, features: list[str]) -> dict:
    """Turn one aggregated tshark flow into a CICIDS-shaped feature row."""
    src, dst, sport, dport, proto = key
    durations = max(flow["last"] - flow["first"], 1e-6)
    lengths = flow["lengths"]
    row = {c: 0.0 for c in features}
    known = {
        "Destination Port": dport,
        "Protocol": proto,
        "Flow Duration": durations * 1e6,
        "Total Fwd Packets": flow["count"],
        "Total Length of Fwd Packets": sum(lengths),
        "Fwd Packet Length Max": max(lengths),
        "Fwd Packet Length Min": min(lengths),
        "Fwd Packet Length Mean": float(np.mean(lengths)),
        "Fwd Packet Length Std": float(np.std(lengths)),
        "Flow Bytes/s": sum(lengths) / durations,
        "Flow Packets/s": flow["count"] / durations,
        "Flow IAT Mean": durations / max(flow["count"] - 1, 1) * 1e6,
        "Fwd IAT Total": durations * 1e6,
        "Fwd IAT Mean": durations / max(flow["count"] - 1, 1) * 1e6,
    }
    for name, value in known.items():
        if name in row:
            row[name] = value
    row["Flow ID"] = f"{src}-{sport}-{dst}-{dport}-{proto}"
    row["Source IP"] = src
    row["Source Port"] = sport
    row["Destination IP"] = dst
    row["Destination Port"] = dport
    row["Timestamp"] = datetime.fromtimestamp(flow["first"]).strftime("%d/%m/%Y %H:%M:%S")
    row["source_file"] = "live-capture"
    return row


def tshark_source(interface: str, features: list[str], idle_timeout: float = 30.0):
    """Capture packets with tshark, aggregate into flows, yield finished flows."""
    cmd = [
        "tshark", "-i", interface, "-l", "-n", "-T", "fields",
        "-E", "separator=\t", "-E", "quote=n",
        "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst", "-e", "ip.proto",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len", "-e", "_ws.col.Protocol",
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
    except FileNotFoundError as exc:
        raise RuntimeError("tshark is not installed; install Wireshark/tshark or use --source replay") from exc

    flows: dict[tuple, dict] = {}
    print(f"capturing on {interface} with tshark", flush=True)

    def flush(now: float):
        for key in [k for k, v in flows.items() if now - v["last"] >= idle_timeout]:
            yield _flow_row(key, flows.pop(key), features)

    try:
        for line in proc.stdout:
            if STOP:
                break
            parts = line.rstrip("\r\n").split("\t")
            if len(parts) < 9 or not parts[0] or not parts[1] or not parts[2]:
                continue
            try:
                ts = float(parts[0])
                length = int(parts[8] or 0)
            except ValueError:
                continue
            sport = parts[4] or parts[6] or "0"
            dport = parts[5] or parts[7] or "0"
            proto = parts[3] or "0"
            key = (parts[1], parts[2], int(sport), int(dport), str(proto))
            f = flows.setdefault(key, {"first": ts, "last": ts, "count": 0, "lengths": []})
            f["last"] = ts
            f["count"] += 1
            f["lengths"].append(length)
            yield from flush(ts)
    finally:
        for key, flow in flows.items():
            yield _flow_row(key, flow, features)
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        err = proc.stderr.read()
        if err and not STOP:
            print(f"tshark: {err.strip()[:500]}", flush=True)


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------
def append_feed(events: list[dict], max_events: int) -> None:
    LIVE_DIR.mkdir(parents=True, exist_ok=True)
    with FEED_PATH.open("a", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")

    # Keep the file bounded without rewriting on every event.
    with FEED_PATH.open(encoding="utf-8") as fh:
        total = sum(1 for _ in fh)
    if total > max_events * 2:
        with FEED_PATH.open(encoding="utf-8") as fh:
            keep = deque(fh, max_events)
        tmp = FEED_PATH.with_suffix(".tmp")
        tmp.write_text("".join(keep), encoding="utf-8")
        os.replace(tmp, FEED_PATH)


def load_events() -> list[dict]:
    if not FEED_PATH.exists():
        return []
    out = []
    with FEED_PATH.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def republish(ai_mode: str, provider: str | None = None,
              model: str | None = None) -> tuple[int, int]:
    """Recompute alerts/incidents from the live feed; generate new AI reports."""
    events = load_events()
    good = [e for e in events if "predicted" in e]
    alerts, incidents = [], []
    if good:
        df = pd.DataFrame(good)
        raw = step3_alerts.build_alerts(df)
        alerts = step3_alerts.alerts_to_records(raw)
        for n, a in enumerate(alerts, 1):
            a["alert_id"] = f"LIVE-ALR-{n:04d}"
        incidents = step3_alerts.build_incidents(alerts)
        for n, inc in enumerate(incidents, 1):
            inc["incident_id"] = f"LIVE-INC-{n:03d}"
            inc["live"] = True

    _atomic_json(ALERTS_PATH, alerts)
    _atomic_json(INCIDENTS_PATH, incidents)

    by_id = {a["alert_id"]: a for a in alerts}
    for inc in incidents:
        existing = list((ROOT / "outputs" / "reports").glob(f'{inc["incident_id"]}_*.md'))
        if existing:
            continue
        effective, text = step4_assistant.make_report(inc, by_id, ai_mode,
                                                      provider=provider, model=model)
        path = step4_assistant.save_report(inc["incident_id"], effective, text)
        print(f"new {inc['incident_id']} ({inc['severity']}) -> {path.name}", flush=True)
    return len(alerts), len(incidents)


def main() -> int:
    ap = argparse.ArgumentParser(description="Live threat detection stream")
    ap.add_argument("--source", choices=["replay", "tshark"], default="replay")
    ap.add_argument("--data", default="data/clean.csv")
    ap.add_argument("--interface", default="eth0")
    ap.add_argument("--rate", type=float, default=10.0, help="replay flows/second")
    ap.add_argument("--count", type=int, default=0,
                    help="flows to replay (0 = continuous until stopped)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--ai-mode", choices=["auto", "llm", "offline"], default="auto")
    ap.add_argument("--provider", choices=list(step4_assistant.llm_providers.ORDER),
                    help="LLM provider (default: first configured)")
    ap.add_argument("--model", help="model ID override for the chosen provider")
    ap.add_argument("--contamination", type=float, default=0.01)
    ap.add_argument("--max-events", type=int, default=2000)
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    LIVE_DIR.mkdir(parents=True, exist_ok=True)

    started = time.time()
    meta = {
        "running": True,
        "source": args.source,
        "interface": args.interface if args.source == "tshark" else None,
        "rate": args.rate if args.source == "replay" else None,
        "ai_mode": args.ai_mode,
        "provider": args.provider,
        "model": args.model,
        "started_at": _utcnow(),
        "events": 0,
        "detections": 0,
        "alerts": 0,
        "incidents": 0,
        "error": None,
    }
    _atomic_json(STATUS_PATH, meta)

    events_processed = detections = 0
    last_publish = 0.0
    try:
        detector = Detector(ROOT / args.data, args.contamination)
        if args.source == "replay":
            source = replay_source(ROOT / args.data, args.count, args.rate, args.seed)
        else:
            source = tshark_source(args.interface, detector.features)

        for row in source:
            if STOP:
                break
            ev_list = detector.score([row])
            append_feed(ev_list, args.max_events)
            events_processed += 1
            detections += sum(1 for e in ev_list if e["fused"])
            if events_processed % 25 == 0:
                print(f"scored {events_processed:,} flows · {detections:,} flagged", flush=True)

            if time.time() - last_publish >= 2.0:
                meta["alerts"], meta["incidents"] = republish(args.ai_mode, args.provider, args.model)
                last_publish = time.time()
                _atomic_json(STATUS_PATH, {**meta, "events": events_processed,
                                           "detections": detections})

        meta["alerts"], meta["incidents"] = republish(args.ai_mode, args.provider, args.model)
    except Exception as exc:
        meta["error"] = f"{type(exc).__name__}: {exc}"
        print(f"ERROR: {meta['error']}", flush=True)
        append_feed([{"ts": _utcnow(), "error": meta["error"], "predicted": None}],
                    args.max_events)
        return 1
    finally:
        meta["running"] = False
        meta["events"] = events_processed
        meta["detections"] = detections
        meta["uptime_seconds"] = round(time.time() - started, 1)
        _atomic_json(STATUS_PATH, meta)
    print(f"done: {events_processed:,} flows scored, "
          f"{detections:,} flagged, {meta['alerts']} alerts, "
          f"{meta['incidents']} incidents", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
