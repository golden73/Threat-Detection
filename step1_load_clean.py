"""
Step 1: Load and clean CICIDS2017 (MachineLearningCVE CSVs).

Usage:
    python step1_load_clean.py data/raw data/clean.csv

Put the downloaded CSV files in data/raw/ first.
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd


def load_all(raw_dir: Path) -> pd.DataFrame:
    frames = []
    for f in sorted(raw_dir.glob("*.csv")):
        df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        df.columns = df.columns.str.strip()  # headers have stray spaces
        df["source_file"] = f.name           # keeps day/attack context
        frames.append(df)
        print(f"loaded {f.name}: {len(df):,} rows")
    return pd.concat(frames, ignore_index=True)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df = df.drop_duplicates()
    print(f"cleaned: {before:,} -> {len(df):,} rows")
    # Binary target (MVP) plus the original multi-class label
    df["is_attack"] = (df["Label"].str.strip().str.upper() != "BENIGN").astype(int)
    return df


if __name__ == "__main__":
    raw = Path(sys.argv[1] if len(sys.argv) > 1 else "data/raw")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "data/clean.csv")
    out.parent.mkdir(parents=True, exist_ok=True)

    data = clean(load_all(raw))
    print("\nLabel distribution:")
    print(data["Label"].value_counts())
    data.to_csv(out, index=False)
    print(f"\nsaved -> {out}")
