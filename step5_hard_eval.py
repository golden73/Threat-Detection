"""
Step 5: Harder evaluation (more honest than the random split in step 2).

  A) Chronological split: within each capture file, train on the first 70% of the
     time range and test on the last 30% (the model never sees the future).
  B) Leave-one-attack-out: train WITHOUT one attack type, then test whether the
     model still flags it (a proxy for detecting unseen / novel attacks).
  C) Cross-capture: train on N-1 capture files, test on the one held out. Flags
     each class as "also in training" (seen) or "NOT TESTED" (a real zero-shot
     test, because the class is absent from training entirely).

By default the destination port is NOT a model feature (it nearly gives the
label away, see step2). Pass --with-dest-port to include it; that run writes
outputs/hard_eval_with_port.json and does not overwrite the default file.

Usage:
    python step5_hard_eval.py data/clean.csv
    python step5_hard_eval.py data/clean.csv --with-dest-port

Output: printed tables + outputs/hard_eval.json (or _with_port.json)
"""
import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from xgboost import XGBClassifier

SEED = 42
META = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "source_file"]
NOT_FEATURES = META + ["Destination Port", "Label", "is_attack"]  # port excluded by default
BENIGN_CAP = 150_000   # max benign flows used for training
ATTACK_CAP = 40_000    # max flows per attack type used for training


def parse_ts(s: pd.Series) -> pd.Series:
    # day/month/year, no AM/PM; capture ran 8:00-17:00 so hours 1-7 are afternoon
    ts = pd.to_datetime(s, format="mixed", dayfirst=True, errors="coerce")
    return ts.where(ts.dt.hour >= 8, ts + pd.Timedelta(hours=12))


def cap(df: pd.DataFrame, n: int) -> pd.DataFrame:
    return df if len(df) <= n else df.sample(n, random_state=SEED)


def fit(X: pd.DataFrame, y: np.ndarray) -> XGBClassifier:
    m = XGBClassifier(n_estimators=100, max_depth=8, learning_rate=0.1,
                      tree_method="hist", n_jobs=-1, random_state=SEED)
    m.fit(X, y)
    return m


def prf(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_true == 1) & (y_pred == 1)).sum()); fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum()); tn = int(((y_true == 0) & (y_pred == 0)).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0,
            "fpr": round(fp / (fp + tn), 6) if fp + tn else 0.0}


def _per_attack(test: pd.DataFrame, pred: np.ndarray, train_labels: set[str]) -> dict:
    """Per-class recall for the test set, flagging classes unseen in training."""
    per = {}
    for lab, g in test[test.is_attack == 1].groupby("Label"):
        seen = lab in train_labels
        per[lab] = {
            "test_flows": int(len(g)),
            "recall": round(float(pred[test.index.get_indexer(g.index)].mean()), 4),
            "flag": "also in training" if seen else "NOT TESTED",
        }
    return per


def chronological(df: pd.DataFrame, feats: list[str]) -> dict:
    df = df.copy()
    df["ts"] = parse_ts(df["Timestamp"])
    df = df.dropna(subset=["ts"])
    is_train = pd.Series(False, index=df.index)
    for _, g in df.groupby("source_file"):
        cut = g["ts"].quantile(0.7)
        is_train[g.index[g["ts"] <= cut]] = True
    train, test = df[is_train], df[~is_train]

    train = pd.concat([cap(train[train.is_attack == 0], BENIGN_CAP), train[train.is_attack == 1]])
    model = fit(train[feats].astype("float32"), train["is_attack"].values)
    pred = model.predict(test[feats].astype("float32"))

    res = {"overall": prf(test["is_attack"].values, pred),
           "per_attack_recall": _per_attack(test, pred, set(train["Label"].unique()))}
    print(f"train flows: {len(train):,}  test flows: {len(test):,}")
    print("Overall (attack vs benign):", res["overall"])
    for lab, v in res["per_attack_recall"].items():
        print(f"  {lab:<12} test flows={v['test_flows']:>7,}  recall={v['recall']:.4f}  ({v['flag']})")
    return res


def leave_one_attack_out(df: pd.DataFrame, feats: list[str]) -> dict:
    benign = df[df.is_attack == 0]
    b_test = benign.sample(frac=0.3, random_state=SEED)
    b_train = benign.drop(b_test.index)
    attacks = sorted(df.loc[df.is_attack == 1, "Label"].unique())
    res = {}
    for held in attacks:
        others = [cap(df[df.Label == a], ATTACK_CAP) for a in attacks if a != held]
        train = pd.concat([cap(b_train, BENIGN_CAP)] + others)
        model = fit(train[feats].astype("float32"), train["is_attack"].values)
        a_test = df[df.Label == held]
        recall = float(model.predict(a_test[feats].astype("float32")).mean())
        fpr = float(model.predict(b_test[feats].astype("float32")).mean())
        res[held] = {"unseen_attack_recall": round(recall, 4), "benign_fpr": round(fpr, 6)}
        print(f"  held out {held:<12} recall on unseen attack = {recall:.4f}   benign FPR = {fpr:.6f}")
    return res


def cross_capture(df: pd.DataFrame, feats: list[str]) -> dict:
    files = sorted(df["source_file"].unique())
    res = {}
    for held in files:
        train = df[df["source_file"] != held]
        test = df[df["source_file"] == held]
        train = pd.concat([cap(train[train.is_attack == 0], BENIGN_CAP),
                           train[train.is_attack == 1]])
        model = fit(train[feats].astype("float32"), train["is_attack"].values)
        pred = model.predict(test[feats].astype("float32"))
        per = _per_attack(test, pred, set(train["Label"].unique()))
        res[held] = {"overall": prf(test["is_attack"].values, pred),
                     "per_attack_recall": per}
        print(f"\nheld out capture: {held}")
        print(f"  train flows: {len(train):,}  test flows: {len(test):,}")
        print("  Overall (attack vs benign):", res[held]["overall"])
        for lab, v in per.items():
            print(f"    {lab:<12} test flows={v['test_flows']:>7,}  recall={v['recall']:.4f}  ({v['flag']})")
    return res


def main(path: str, with_port: bool) -> None:
    df = pd.read_csv(path, low_memory=False)
    df["Label"] = df["Label"].str.strip()
    feats = [c for c in df.columns if c not in NOT_FEATURES]
    if with_port:
        feats.append("Destination Port")

    print(f"features: {len(feats)} (destination port {'IS' if with_port else 'is NOT'} a feature)")
    print("\n=== A) Chronological split (train early, test late) ===")
    a = chronological(df, feats)
    print("\n=== B) Leave-one-attack-out (unseen attack types) ===")
    b = leave_one_attack_out(df, feats)
    print("\n=== C) Cross-capture (train on N-1 captures, test on held-out) ===")
    c = cross_capture(df, feats)

    Path("outputs").mkdir(exist_ok=True)
    out = "outputs/hard_eval.json" if not with_port else "outputs/hard_eval_with_port.json"
    with open(out, "w") as f:
        json.dump({"chronological": a, "leave_one_attack_out": b,
                   "cross_capture": c, "destination_port_as_feature": with_port},
                  f, indent=2)
    print(f"\nsaved {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="data/clean.csv")
    ap.add_argument("--with-dest-port", action="store_true")
    args = ap.parse_args()
    main(args.path, args.with_dest_port)