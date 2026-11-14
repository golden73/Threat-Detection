"""
Step 7: Unsupervised anomaly layer (IsolationForest) fused with the supervised
XGBoost detector.

Motivation: the supervised model generalises poorly to attack types it never saw
(leave-one-attack-out recall 0.04%-45%). An unsupervised layer that learns the
shape of benign traffic can flag flows that look unlike anything benign, which
is exactly what a zero-day or novel attack looks like.

What it does
  1. Trains an IsolationForest on a sample of BENIGN flows (no labels needed
     beyond "this is normal traffic").
  2. Scores every flow with an anomaly score in [0, 1] (higher = more anomalous).
  3. Fuses the score with the supervised XGBoost prediction:
       fused = 1 if (xgb says attack) OR (anomaly_score >= threshold)
  4. Reports how many of the known attacks each layer catches, plus the benign
     false-positive rate of the anomaly layer alone.

Usage:
    python step7_anomaly.py data/clean.csv
    python step7_anomaly.py data/clean.csv --contamination 0.01

Outputs:
    models/anomaly_iforest.joblib      trained IsolationForest
    outputs/anomaly_scores.csv        per-flow anomaly score + fused decision
    outputs/anomaly_metrics.json      per-layer and fused metrics
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

SEED = 42
META = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp", "source_file"]
NOT_FEATURES = META + ["Destination Port", "Label", "is_attack"]

CONTAMINATION_DEFAULT = 0.01


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    drop = [c for c in NOT_FEATURES if c in df.columns]
    X = df.drop(columns=drop, errors="ignore").select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    return X


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default="data/clean.csv")
    ap.add_argument("--contamination", type=float, default=CONTAMINATION_DEFAULT)
    ap.add_argument("--benign-cap", type=int, default=100_000)
    args = ap.parse_args()

    df = pd.read_csv(args.path, low_memory=False)
    df.columns = df.columns.str.strip()
    y = (df["Label"].str.strip().str.upper() != "BENIGN").astype(int).to_numpy()
    X = feature_matrix(df)

    benign_idx = np.where(y == 0)[0]
    rng = np.random.RandomState(SEED)
    train_idx = rng.choice(benign_idx, size=min(args.benign_cap, len(benign_idx)), replace=False)

    print(f"Training IsolationForest on {len(train_idx):,} benign flows...")
    iso = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=SEED,
        n_jobs=-1,
    )
    iso.fit(X.iloc[train_idx])

    raw = -iso.score_samples(X)  # higher = more anomalous
    # normalise to [0, 1]
    lo, hi = raw.min(), raw.max()
    anomaly = (raw - lo) / (hi - lo + 1e-12)

    threshold = float(np.quantile(anomaly[y == 0], 1 - args.contamination))
    anomaly_pred = (anomaly >= threshold).astype(int)

    # Fuse with supervised predictions if available
    pred_path = Path("outputs/predictions.csv")
    if pred_path.exists():
        preds = pd.read_csv(pred_path, low_memory=False)
        _col = "predicted" if "predicted" in preds.columns else ("pred_label" if "pred_label" in preds.columns else None)
        xgb_pred = (preds[_col].str.strip().str.upper() != "BENIGN").astype(int).to_numpy() \
            if _col else np.zeros(len(df), dtype=int)
    else:
        xgb_pred = np.zeros(len(df), dtype=int)

    fused = ((xgb_pred == 1) | (anomaly_pred == 1)).astype(int)

    def metrics(pred_bin):
        tp = int(((y == 1) & (pred_bin == 1)).sum())
        fp = int(((y == 0) & (pred_bin == 1)).sum())
        fn = int(((y == 1) & (pred_bin == 0)).sum())
        tn = int(((y == 0) & (pred_bin == 0)).sum())
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        return {"precision": prec, "recall": rec, "f1": f1, "fpr": fpr,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn}

    m_xgb = metrics(xgb_pred)
    m_iso = metrics(anomaly_pred)
    m_fused = metrics(fused)

    Path("models").mkdir(exist_ok=True)
    joblib.dump(iso, "models/anomaly_iforest.joblib")

    out = pd.DataFrame({
        "anomaly_score": anomaly,
        "anomaly_pred": anomaly_pred,
        "xgb_pred_attack": xgb_pred,
        "fused_pred_attack": fused,
        "is_attack": y,
    })
    Path("outputs").mkdir(exist_ok=True)
    out.to_csv("outputs/anomaly_scores.csv", index=False)

    report = {
        "contamination": args.contamination,
        "threshold": threshold,
        "n_flows": len(df),
        "xgboost_only": m_xgb,
        "isolation_forest_only": m_iso,
        "fused": m_fused,
        "note": "Unsupervised layer flags flows unlike benign traffic; fused = OR of the two.",
    }
    Path("outputs/anomaly_metrics.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))

    # ------------------------------------------------------------------
    # Cross-capture anomaly evaluation: for each capture day, train the
    # IsolationForest on benign flows from the OTHER days only, then score
    # the held-out day. This measures whether the unsupervised layer
    # generalises to unseen captures — the scenario where XGBoost fails
    # (cross-capture recall 0.04%-4%).
    # ------------------------------------------------------------------
    if "source_file" not in df.columns:
        print("no source_file column; skipping cross-capture anomaly eval")
        return

    files = sorted(df["source_file"].unique())
    x_cc = X.reset_index(drop=True)
    src = df["source_file"].reset_index(drop=True).to_numpy()
    yy = pd.Series(y).reset_index(drop=True).to_numpy()
    cc_report = {}
    print(f"\nCross-capture anomaly eval over {len(files)} captures...")
    for held in files:
        tr_mask, te_mask = src != held, src == held
        if tr_mask.sum() == 0 or te_mask.sum() == 0:
            continue
        tr_idx = np.where(tr_mask & (yy == 0))[0]
        tr_idx = rng.choice(tr_idx, size=min(args.benign_cap, len(tr_idx)), replace=False)
        iso_cc = IsolationForest(n_estimators=200, contamination=args.contamination,
                                 random_state=SEED, n_jobs=-1)
        iso_cc.fit(x_cc.iloc[tr_idx])
        raw_cc = -iso_cc.score_samples(x_cc[te_mask])
        lo, hi = raw_cc.min(), raw_cc.max()
        anom_cc = (raw_cc - lo) / (hi - lo + 1e-12)
        # threshold must come from TRAINING benign only, never the held-out
        # day's benign traffic (would leak distribution info into the FPR)
        raw_tr = -iso_cc.score_samples(x_cc.iloc[tr_idx])
        lo_tr, hi_tr = raw_tr.min(), raw_tr.max()
        anom_tr = (raw_tr - lo_tr) / (hi_tr - lo_tr + 1e-12)
        thr_cc = float(np.quantile(anom_tr, 1 - args.contamination))
        pred_cc = (anom_cc >= thr_cc).astype(int)
        te_y = yy[te_mask]
        recall = float(pred_cc[te_y == 1].mean()) if (te_y == 1).any() else 0.0
        fpr = float(pred_cc[te_y == 0].mean()) if (te_y == 0).any() else 0.0
        cc_report[held] = {"unseen_capture_attack_recall": recall,
                           "benign_fpr": fpr,
                           "attack_flows": int((te_y == 1).sum())}
        print(f"  {held}: recall={recall:.4f} fpr={fpr:.4f}")
    report["cross_capture_anomaly"] = cc_report
    Path("outputs/anomaly_metrics.json").write_text(json.dumps(report, indent=2))
    print("\nCross-capture anomaly section appended to outputs/anomaly_metrics.json")


if __name__ == "__main__":
    main()
