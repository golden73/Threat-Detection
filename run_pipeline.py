#!/usr/bin/env python3
"""One-command runner for the full pipeline (steps 1-6).

Usage:
    python run_pipeline.py

Step 1 is skipped when data/clean.csv already exists. All commands run with
the same Python interpreter that launched this script.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable


def run(cmd, desc):
    print(f"\n{'=' * 60}")
    print(f"Running: {desc}")
    print(f"{'=' * 60}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        print(f"ERROR: {desc} failed with return code {result.returncode}")
        sys.exit(result.returncode)
    print(f"SUCCESS: {desc} completed")


def main():
    os.chdir(ROOT)
    (ROOT / "outputs" / "reports").mkdir(parents=True, exist_ok=True)

    # Step 1: only needed when the cleaned dataset is missing.
    if (ROOT / "data" / "clean.csv").exists():
        print("Found data/clean.csv, skipping step 1")
    elif (ROOT / "data" / "raw").exists():
        run([PY, "step1_load_clean.py", "data/raw", "data/clean.csv"],
            "Step 1: Load and clean data")
    else:
        print("ERROR: No data/clean.csv and no data/raw found. "
              "See data/README.md for how to obtain the dataset.")
        sys.exit(1)

    # Step 2: baseline plus the destination-port comparison run.
    run([PY, "step2_baseline.py", "data/clean.csv", "--folds", "3"],
        "Step 2: Train XGBoost baseline (3-fold OOF)")
    run([PY, "step2_baseline.py", "data/clean.csv", "--folds", "3",
         "--with-dest-port"],
        "Step 2b: Destination-port comparison (metrics only)")

    # Step 3: predictions -> alerts -> incidents.
    run([PY, "step3_alerts.py", "outputs/predictions.csv"],
        "Step 3: Generate alerts and incidents")

    # Step 4: one offline report per incident actually present on disk.
    incidents = json.loads((ROOT / "outputs" / "incidents.json").read_text())
    for inc in incidents:
        incident_id = inc["incident_id"]
        run([PY, "step4_assistant.py", "--incident", incident_id,
             "--mode", "offline"],
            f"Step 4: AI assistant report for {incident_id}")

    # Step 5: hard evaluation, default and destination-port variants.
    run([PY, "step5_hard_eval.py", "data/clean.csv"],
        "Step 5: Hard evaluation (chronological + LOAO + cross-capture)")
    run([PY, "step5_hard_eval.py", "data/clean.csv", "--with-dest-port"],
        "Step 5b: Hard evaluation with destination port (comparison)")

    # Step 6: demo page.
    run([PY, "step6_demo_page.py"], "Step 6: Build demo page")

    print(f"\n{'=' * 60}")
    print("Pipeline completed successfully!")
    print(f"{'=' * 60}")
    print("\nOutputs:")
    print("  - outputs/metrics.json")
    print("  - outputs/metrics_with_port.json")
    print("  - outputs/predictions.csv")
    print("  - outputs/alerts.json")
    print("  - outputs/incidents.json")
    print("  - outputs/hard_eval.json")
    print("  - outputs/hard_eval_with_port.json")
    print("  - outputs/demo.html")
    print("  - outputs/reports/*.md")
    print("\nOpen outputs/demo.html in your browser to view the demo.")


if __name__ == "__main__":
    main()
