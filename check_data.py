"""
Data check: row count, capture files, attack classes, duplicate count.

Usage:
    python check_data.py [data/clean.csv]

Records:
    prints summary + writes outputs/data_check.json
"""
import json
import sys
from pathlib import Path

import pandas as pd


def main(path: str) -> None:
    df = pd.read_csv(path, low_memory=False)
    df["Label"] = df["Label"].astype(str).str.strip()
    dupes = int(df.duplicated().sum())
    uniq = int(df["Label"].nunique())

    info = {
        "rows": int(len(df)),
        "columns": int(len(df.columns)),
        "capture_files": df["source_file"].value_counts().to_dict(),
        "attack_classes": df["Label"].value_counts().to_dict(),
        "n_attack_classes": uniq,
        "duplicate_rows": dupes,
        "unique_flows": int(len(df) - dupes),
    }
    print(json.dumps(info, indent=2))

    Path("outputs").mkdir(exist_ok=True)
    with open("outputs/data_check.json", "w") as f:
        json.dump(info, f, indent=2)
    print("\nsaved outputs/data_check.json")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data/clean.csv")