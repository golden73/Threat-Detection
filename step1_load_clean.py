"""
Step 1: Load and clean CICIDS2017 (MachineLearningCVE CSVs), or convert a Zeek
conn.log to the same schema.

Usage:
    python step1_load_clean.py data/raw data/clean.csv
    python step1_load_clean.py --zeek conn.log outputs/zeek_flows.csv

Put the downloaded CSV files in data/raw/ first (see data/README.md).
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Zeek conn.log -> CICIDS-ish column mapping (best effort)
_ZEEK_FIELD_MAP = {
    "duration": "Flow Duration",
    "orig_pkts": "Total Fwd Packets",
    "resp_pkts": "Total Backward Packets",
    "orig_bytes": "Total Length of Fwd Packets",
    "resp_bytes": "Total Length of Bwd Packets",
    "id.orig_p": "Source Port",
    "id.resp_p": "Destination Port",
    "id.orig_h": "Source IP",
    "id.resp_h": "Destination IP",
    "proto": "Protocol",
    "ts": "Timestamp",
}


def _parse_zeek(path: Path, max_rows=None):
    fields = None
    rows = []
    with path.open() as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or line.startswith("#separator"):
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or fields is None:
                continue
            parts = line.split("\t")
            rows.append(dict(zip(fields, parts)))
            if max_rows and len(rows) >= max_rows:
                break
    return fields, rows


def load_zeek(path: Path, max_rows=None) -> pd.DataFrame:
    fields, rows = _parse_zeek(path, max_rows)
    if not rows:
        raise SystemExit(f"No data rows found in {path}")
    out = []
    for rec in rows:
        row = {}
        for src, dst in _ZEEK_FIELD_MAP.items():
            v = rec.get(src, "-")
            if v in ("-", "", None):
                v = 0
            row[dst] = v
        row["Label"] = "UNKNOWN"
        row["is_attack"] = np.nan
        row["source_file"] = "zeek_conn.log"
        for k in ("Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                  "Total Length of Fwd Packets", "Total Length of Bwd Packets",
                  "Source Port", "Destination Port"):
            try:
                row[k] = float(row[k])
            except (ValueError, TypeError):
                row[k] = 0.0
        row["Flow Duration"] = row["Flow Duration"] * 1e6  # seconds -> microseconds
        out.append(row)
    return pd.DataFrame(out)


def load_all(raw_dir: Path) -> pd.DataFrame:
    # README layout: data/raw/<MachineLearningCVE|TrafficLabelling>/*.csv. The
    # two labelling variants are the same flows with different cleaning, so only
    # one is needed — prefer MachineLearningCVE when both are present.
    files = sorted((raw_dir / "MachineLearningCVE").glob("*.csv"))
    if not files:
        files = sorted((raw_dir / "TrafficLabelling").glob("*.csv"))
    if not files:
        files = sorted(raw_dir.glob("*.csv"))  # flat layout, e.g. data/raw/*.csv
    if not files:
        raise SystemExit(f"No CSV files found in {raw_dir} "
                         f"(expected a MachineLearningCVE or TrafficLabelling subdir, "
                         f"or top-level CSVs; see data/README.md)")
    frames = []
    for f in files:
        df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        df.columns = df.columns.str.strip()  # headers have stray spaces
        df["source_file"] = f.name           # keeps day/attack context
        frames.append(df)
        print(f"loaded {f.name}: {len(df):,} rows")
    return pd.concat(frames, ignore_index=True)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan)
    # Drop rows missing core feature values, but keep rows with an unknown label
    # (is_attack NaN) so live captures are not discarded.
    if "is_attack" in df.columns:
        bad = df.drop(columns=["is_attack"]).isna().any(axis=1)
        df = df[~bad]
    else:
        df = df.dropna()
    df = df.drop_duplicates()
    print(f"cleaned: {before:,} -> {len(df):,} rows")
    # Binary target (MVP) plus the original multi-class label.
    # "UNKNOWN" (e.g. live captures) has no label -> NaN so supervised steps skip it.
    labels = df["Label"].astype(str).str.strip().str.upper()
    df["is_attack"] = np.where(labels == "UNKNOWN", np.nan,
                               (labels != "BENIGN").astype(int))
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?", default="data/raw",
                    help="raw dir (CICIDS) or conn.log path with --zeek")
    ap.add_argument("output", nargs="?", default="data/clean.csv")
    ap.add_argument("--zeek", action="store_true",
                    help="treat input as a Zeek conn.log and convert it")
    ap.add_argument("--max-rows", type=int, default=None)
    args = ap.parse_args()

    src = Path(args.input)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    if args.zeek:
        data = clean(load_zeek(src, args.max_rows))
    else:
        data = clean(load_all(src))

    print("\nLabel distribution:")
    print(data["Label"].value_counts())
    data.to_csv(out, index=False)
    print(f"\nsaved -> {out}")


if __name__ == "__main__":
    main()
