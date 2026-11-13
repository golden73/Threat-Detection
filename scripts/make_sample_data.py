"""
Generate a small SYNTHETIC CICIDS2017-like dataset for CI / smoke testing.

Produces data/raw/MachineLearningCVE/<8 day files>.csv with a realistic column
schema (a subset of the real CICIDS2017 feature names) and plausible traffic
statistics. All values are randomly generated — no real data is used or needed.

Usage:
    python scripts/make_sample_data.py --out data/raw --rows-per-file 500
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

# Representative subset of CICIDS2017 "MachineLearningCVE" feature columns.
FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Fwd IAT Mean", "Bwd IAT Mean", "Fwd Packets Length Mean",
    "Bwd Packets Length Mean", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "SYN Flag Count",
    "ACK Flag Count", "Average Packet Size", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "active Mean", "idle Mean",
]
ATTACKS = {
    "Monday-WorkingHours.pcap_ISCX.csv": ["BENIGN"],
    "Tuesday-WorkingHours.pcap_ISCX.csv": ["BENIGN", "FTP-Patator", "SSH-Patator"],
    "Wednesday-workingHours.pcap_ISCX.csv": ["BENIGN", "DoS slowloris"],
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": ["BENIGN", "Web Attack  Brute Force"],
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": ["BENIGN", "Infiltration"],
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": ["BENIGN", "Bot"],
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": ["BENIGN", "PortScan"],
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": ["BENIGN", "DDoS"],
}


def _row(rng: np.random.RandomState, label: str) -> dict:
    """One synthetic flow. Attacks get more extreme statistics than benign."""
    attack = label != "BENIGN"
    scale = 4.0 if attack else 1.0
    fwd_pkts = rng.gamma(2.0, 10.0 * scale)
    bwd_pkts = rng.gamma(2.0, 8.0 if not attack else 2.0)
    return {
        "Flow Duration": float(rng.gamma(2.0, 1e6) * scale),
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": fwd_pkts * rng.uniform(50, 800) * scale,
        "Total Length of Bwd Packets": bwd_pkts * rng.uniform(50, 800),
        "Flow Bytes/s": abs(rng.normal(1e5 * scale, 5e4)),
        "Flow Packets/s": abs(rng.normal(50 * scale, 20)),
        "Flow IAT Mean": abs(rng.normal(1e5, 4e4)),
        "Flow IAT Std": abs(rng.normal(1e5, 4e4)),
        "Fwd IAT Mean": abs(rng.normal(1e5, 4e4)),
        "Bwd IAT Mean": abs(rng.normal(1e5, 4e4)),
        "Fwd Packets Length Mean": abs(rng.normal(200 * scale, 100)),
        "Bwd Packets Length Mean": abs(rng.normal(200, 100)),
        "Min Packet Length": rng.uniform(20, 60),
        "Max Packet Length": abs(rng.normal(1400 * scale, 400)),
        "Packet Length Mean": abs(rng.normal(200 * scale, 100)),
        "Packet Length Std": abs(rng.normal(300, 150)),
        "SYN Flag Count": rng.poisson(3 * scale),
        "ACK Flag Count": rng.poisson(10),
        "Average Packet Size": abs(rng.normal(200 * scale, 100)),
        "Init_Win_bytes_forward": rng.choice([255, 512, 1024, 8192]),
        "Init_Win_bytes_backward": rng.choice([255, 512, 1024, 8192]),
        "active Mean": abs(rng.normal(1e4, 5e3)),
        "idle Mean": abs(rng.normal(1e5, 5e4)),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/raw")
    ap.add_argument("--rows-per-file", type=int, default=500)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    base = Path(args.out)
    out_dir = base if base.name == "MachineLearningCVE" else base / "MachineLearningCVE"
    out_dir.mkdir(parents=True, exist_ok=True)

    rng = np.random.RandomState(args.seed)
    for fname, labels in ATTACKS.items():
        n = args.rows_per_file
        # keep mostly benign, like the real dataset
        chosen = rng.choice(labels, size=n) if len(labels) == 1 else \
            rng.choice(labels, size=n, p=[0.9] + [0.1 / (len(labels) - 1)] * (len(labels) - 1))
        df = pd.DataFrame([_row(rng, lbl) for lbl in chosen])
        df["Label"] = chosen
        # metadata columns step3 needs for alert context
        df["Flow ID"] = [f"synthetic-{i}" for i in range(n)]
        df["Source IP"] = [f"192.168.{rng.randint(0, 5)}.{rng.randint(2, 250)}" for _ in range(n)]
        df["Destination IP"] = [f"10.0.{rng.randint(0, 3)}.{rng.randint(2, 250)}" for _ in range(n)]
        df["Source Port"] = rng.randint(1024, 65535, size=n)
        df["Destination Port"] = rng.choice([22, 21, 80, 443, 53], size=n)
        df["Timestamp"] = [f"13/11/2026 {i % 24:02d}:{i % 60:02d}:00" for i in range(n)]
        # inject the real dataset's quirks: header spaces + an inf value
        df = df.rename(columns={"Flow Duration": " Flow Duration"})
        df.loc[df.index[0], "Flow Bytes/s"] = np.inf
        df.to_csv(out_dir / fname, index=False)
        print(f"wrote {out_dir / fname}: {n} rows, classes={sorted(set(chosen))}")


if __name__ == "__main__":
    main()
