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