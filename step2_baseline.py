"""
Step 2 (patched): Baseline detector (XGBoost) on the cleaned CICIDS2017 data.

What changed vs. the original
  1. "Destination Port" is no longer a model feature. It almost gives the label
     away in CICIDS2017 (21=FTP-Patator, 22=SSH-Patator, 80=DDoS), so it inflates
     scores and hides real generalisation. It is still written to predictions.csv
     because step 3 uses it for reporting.
  2. Predictions now cover EVERY flow, not a random 30% sample. This is done with
     stratified k-fold "out-of-fold" scoring: each flow is predicted by a model that
     never saw it in training. Step 3 therefore sees the full traffic timeline and
     real flow counts. Metrics are computed on these out-of-fold predictions.
  3. models/xgb.json is a final model trained on all flows (benign capped).

Usage:
    python step2_baseline.py data/clean.csv
    python step2_baseline.py data/clean.csv --folds 3          # faster
    python step2_baseline.py data/clean.csv --with-dest-port   # comparison run only

--with-dest-port trains WITH the port feature and writes only
outputs/metrics_with_port.json, so you can show the "before vs after" on a slide.
It does not overwrite the model or predictions.

Outputs:
    models/xgb.json            final model (all flows, benign capped)
    models/classes.json        label names
    outputs/metrics.json       precision / recall / F1 / FPR (out-of-fold, all flows)
    outputs/predictions.csv    per-flow out-of-fold predictions (input for step 3)
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

SEED = 42
BENIGN_TRAIN_CAP = 150_000  # downsample benign in training for speed + balance

# Identifiers kept for alerts/correlation, but NOT used as model features
META = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "source_file"]
NOT_FEATURES = META + ["Destination Port", "Label", "is_attack"]


def train_model(X: pd.DataFrame, y: np.ndarray, idx: np.ndarray, benign_code: int):
    """Fit XGBoost on rows `idx` (positions), downsampling benign to BENIGN_TRAIN_CAP."""
    rng = np.random.RandomState(SEED)
    benign_idx = idx[y[idx] == benign_code]
    keep = rng.choice(benign_idx, size=min(BENIGN_TRAIN_CAP, len(benign_idx)), replace=False)
    sel = np.sort(np.concatenate([idx[y[idx] != benign_code], keep]))
    model = XGBClassifier(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.1,
        tree_method="hist",
        objective="multi:softprob",
        n_jobs=-1,
        random_state=SEED,
    )
    model.fit(X.iloc[sel], y[sel])
    return model, len(sel)


def binary_metrics(y_true: np.ndarray, pred: np.ndarray, benign_code: int) -> dict:
    """Any non-benign prediction counts as an alert."""
    t_bin, p_bin = y_true != benign_code, pred != benign_code
    tp = int((t_bin & p_bin).sum()); fp = int((~t_bin & p_bin).sum())
    fn = int((t_bin & ~p_bin).sum()); tn = int((~t_bin & ~p_bin).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": fpr, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def main(path: str, folds: int, with_port: bool) -> None:
    df = pd.read_csv(path, low_memory=False)
    df["Label"] = df["Label"].str.strip()

    drop = [c for c in NOT_FEATURES if not (with_port and c == "Destination Port")]
    feats = [c for c in df.columns if c not in drop]
    X = df[feats].astype("float32")
    le = LabelEncoder()
    y = le.fit_transform(df["Label"])
    benign_code = int(le.transform(["BENIGN"])[0])
    print(f"{len(df):,} flows, {len(feats)} features "
          f"(Destination Port {'INCLUDED' if with_port else 'excluded'})")
    print("class counts:")
    print(df["Label"].value_counts().to_string())

    if folds < 2:
        print(f"WARNING: --folds {folds} is invalid (sklearn needs >= 2); "
              f"using 2 folds. Use --folds 3+ for a real evaluation.")
        folds = 2

    counts = np.bincount(y)
    if counts.min() < folds:
        rare = [le.classes_[i] for i in np.where(counts < folds)[0]]
        print(f"WARNING: classes with fewer than {folds} flows: {rare}. "
              f"Lower --folds or drop those classes if training fails.")

    # Out-of-fold scoring: every flow is predicted by a model that did not train on it
    proba = np.zeros((len(df), len(le.classes_)), dtype="float32")
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for k, (tr, te) in enumerate(skf.split(np.zeros(len(y)), y), 1):
        model, n_train = train_model(X, y, tr, benign_code)
        proba[te] = model.predict_proba(X.iloc[te])
        print(f"fold {k}/{folds}: trained on {n_train:,} flows, scored {len(te):,}")
    pred = proba.argmax(axis=1)

    print("\n=== Multi-class report (out-of-fold, all flows) ===")
    print(classification_report(y, pred, target_names=le.classes_, digits=4, zero_division=0))
    print("Confusion matrix (rows = true, cols = predicted):")
    print(pd.DataFrame(confusion_matrix(y, pred), index=le.classes_, columns=le.classes_))

    metrics = binary_metrics(y, pred, benign_code)
    metrics["evaluation"] = f"{folds}-fold out-of-fold on all {len(df)} flows"
    metrics["destination_port_as_feature"] = with_port
    print("\n=== Binary (attack vs benign) ===")
    print(json.dumps(metrics, indent=2))

    Path("outputs").mkdir(exist_ok=True)
    if with_port:
        json.dump(metrics, open("outputs/metrics_with_port.json", "w"), indent=2)
        print("\ncomparison run only: saved outputs/metrics_with_port.json "
              "(model and predictions NOT overwritten)")
        return

    # Final model on all flows, plus artifacts for the later steps
    Path("models").mkdir(exist_ok=True)
    final_model, n_final = train_model(X, y, np.arange(len(df)), benign_code)
    print(f"\nfinal model trained on {n_final:,} flows")
    final_model.save_model("models/xgb.json")
    json.dump(list(le.classes_), open("models/classes.json", "w"))
    json.dump(metrics, open("outputs/metrics.json", "w"), indent=2)

    # Destination Port is kept here for reporting only; it was NOT a model feature.
    out = df[["Flow ID", "Source IP", "Destination IP", "Destination Port", "Timestamp", "Label"]].copy()
    out["predicted"] = le.inverse_transform(pred)
    out["confidence"] = proba.max(axis=1).round(4)
    out.to_csv("outputs/predictions.csv", index=False)
    print("saved model, metrics and outputs/predictions.csv (all flows)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="data/clean.csv")
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--with-dest-port", action="store_true",
                    help="comparison run: include Destination Port as a feature")
    a = ap.parse_args()
    main(a.path, a.folds, a.with_dest_port)