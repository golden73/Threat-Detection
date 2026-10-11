========================================================================
WRITEUPS INDEX - collaboration log (OpenCode + Kilo)
========================================================================
Every task agent performs gets a dated txt file in this folder so both
agents and the human can audit what happened and reproduce results.

Format: YYYY-MM-DD_<short-task-name>.txt
Templates: see PROMPT_FOR_KILO.txt (paste it into Kilo)

------------------------------------------------------------------------
LOG
------------------------------------------------------------------------
2026-10-11  final_gap_closing.txt
            OpenCode: after Kilo's wrap-up. Re-ran with-port step2 at
            3-fold (same as metrics.json) -> synced README/slides/demo
            to 3-fold numbers; rebuilt slides.pdf (build_slides.py) +
            demo.pdf (chromium); ran clean-venv run-order test (ALL
            steps pass in fresh venv); fixed step2 --folds 1 edge case.

2026-10-11  pipeline_rerun.txt
            OpenCode: full rerun under patched scripts. check_data.py +
            data_check.json; step2 --folds 3 (both variants); step3
            (7 alerts -> 5 incidents); step4 reports x5; step5 patched
            (--with-dest-port, cross-capture, "NOT TESTED" flags) +
            both evals; step6 demo upgraded + verified vs JSON.

2026-10-11  portscan_mapping_change.txt
            OpenCode: PortScan MITRE mapping T1046 -> T1595
            (Active Scanning / Reconnaissance). DDoS kept as T1498.
            step3_alerts.py + step4_assistant.py edited; step3/4/6
            rerun; artifacts verified consistent.

========================================================================
ENVIRONMENT NOTE (for reproduction)
========================================================================
- Use venv/bin/python (venv now inherits system site-packages).
- Deps: numpy 2.4.6, pandas 2.3.3, scikit-learn 1.9.1, xgboost 3.4.1,
  anthropic 1.13.0.
- requirements.txt still needs regenerating for the project only.
========================================================================