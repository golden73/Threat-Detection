# AI-Assisted Threat Detection & Response System — Project Report

**Date:** 28 November 2026  
**Repository:** `golden73/Threat-Detection`  
**Scope:** CICIDS2017 network-flow detection, alert correlation, MITRE ATT&CK mapping, AI analyst reports, and a live local dashboard.

---

## 1. Executive Summary

This project implements an end-to-end SOC prototype that turns raw network flows into correlated, explainable incidents and analyst-ready reports.

Key results:

- **957,445 flows** cleaned from three CICIDS2017 capture files; **5 classes** (BENIGN plus four attack families).
- Supervised **XGBoost** model: **F1 = 0.99987**, false-positive rate **0.000061** under 3-fold out-of-fold evaluation.
- Unsupervised **IsolationForest** layer added for anomaly awareness; OR-fusion keeps **recall = 0.99988** but raises FPR to **0.0101**, showing the trade-off clearly.
- Hard evaluation reveals the real limitation: unseen-attack recall drops to **0.04–45%** in leave-one-attack-out tests and **0.25–4.4%** across unseen captures.
- Batch output: **7 alerts**, **5 incidents**, **5 offline analyst reports**, all mapped to MITRE ATT&CK techniques.
- A **live engine** and **local dashboard** were added: continuous replay or tshark capture, real-time scoring, auto-generated `LIVE-*` incidents and reports, and LLM-backed analysis via **Gemini**, **OpenRouter**, and **Groq routed through OpenRouter**.
- All secrets stay local: a gitignored `.env` file, or session memory for keys pasted in the UI. No keys are committed.

The system is a strong in-distribution demo and a complete architectural prototype, but **not a validated production sensor**.

---

## 2. Objectives

1. Build a reproducible pipeline from raw CICIDS2017 CSVs to detection artifacts.
2. Detect malicious flows with a trained supervised model.
3. Add an unsupervised anomaly layer to expose unusual traffic.
4. Correlate detections into alerts and multi-stage incidents.
5. Map alerts to MITRE ATT&CK techniques and tactics.
6. Generate analyst-style reports, offline or with a hosted LLM.
7. Provide a live stream path and a browser dashboard for demonstration.
8. Keep all data, keys, and generated outputs local.

---

## 3. Dataset

Source: CICIDS2017 `MachineLearningCVE` CSVs.

| Property | Value |
|---|---|
| Cleaned rows | 957,445 |
| Raw columns | 87 (78 model features after cleaning) |
| Duplicate rows | 0 |
| Unique flows | 957,445 |
| Attack classes | 5 including BENIGN |

Class distribution:

| Class | Flows |
|---|---:|
| BENIGN | 656,784 |
| PortScan | 158,804 |
| DDoS | 128,025 |
| FTP-Patator | 7,935 |
| SSH-Patator | 5,897 |

Capture files:

| File | Rows |
|---|---:|
| Tuesday-WorkingHours | 445,641 |
| Friday-WorkingHours-Afternoon-PortScan | 286,095 |
| Friday-WorkingHours-Afternoon-DDos | 225,709 |

The dataset is synthetic/aged. It is useful for pipeline validation, not for estimating real-world deployment performance.

---

## 4. System Architecture

### Batch pipeline

| Stage | Script | Output |
|---|---|---|
| 1. Load & clean | `step1_load_clean.py` | `data/clean.csv` |
| 2. Baseline model | `step2_baseline.py` | `models/xgb.json`, `models/classes.json`, `outputs/predictions.csv`, `outputs/metrics.json` |
| 3. Correlation | `step3_alerts.py` | `outputs/alerts.json`, `outputs/incidents.json` |
| 4. AI assistant | `step4_assistant.py` | `outputs/reports/*.md` |
| 5. Hard evaluation | `step5_hard_eval.py` | `outputs/hard_eval.json` |
| 6. Demo page | `step6_demo_page.py` | `outputs/demo.html`, `outputs/demo.pdf` |
| 7. Anomaly layer | `step7_anomaly.py` | `models/anomaly_iforest.joblib`, `outputs/anomaly_metrics.json`, `outputs/anomaly_scores.csv` |
| Orchestrator | `run_pipeline.py` | Runs steps 1–7 |

### Live path

| Component | Role |
|---|---|
| `live_engine.py` | Scores replayed or captured flows, publishes feed/alerts/incidents/status, generates `LIVE-*` reports |
| `llm_providers.py` | Provider-agnostic LLM layer (stdlib only) |
| `webapp.py` | Local HTTP server, live process management, JSON APIs |
| `web/index.html`, `web/app.js`, `web/style.css` | Dashboard UI |

Live artifacts are isolated in `outputs/live/` and `outputs/reports/LIVE-*.md`; batch artifacts are never overwritten.

---

## 5. Detection Models

### 5.1 Supervised XGBoost

- 3-fold out-of-fold evaluation over all 957,445 flows.
- Destination Port excluded from the baseline to reduce trivial leakage.

| Metric | No port | With port |
|---|---:|---:|
| Precision | 0.999867 | 0.999887 |
| Recall | 0.999880 | 0.999910 |
| F1 | 0.999874 | 0.999899 |
| FPR | 0.0000609 | 0.0000518 |
| TP / FP / FN / TN | 300,625 / 40 / 36 / 656,744 | 300,634 / 34 / 27 / 656,750 |

The port adds only marginal benefit, so the port-free model is the primary baseline.

### 5.2 Unsupervised anomaly layer

IsolationForest trained on benign traffic, contamination `0.01`.

| Layer | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|
| XGBoost only | 0.99987 | 0.99988 | 0.99987 | 0.00006 |
| IsolationForest only | 0.1573 | 0.0041 | 0.0079 | 0.0100 |
| OR fusion | 0.9785 | 0.99988 | 0.9891 | 0.0101 |

The anomaly layer is useful as a signal for unusual traffic, not as a standalone detector. OR-fusion preserves recall at the cost of many more false positives.

---

## 6. Hard Evaluation and Generalization

### Chronological split

| Metric | Value |
|---|---:|
| Precision | 0.9995 |
| Recall | 0.9970 |
| F1 | 0.9982 |
| FPR | 0.000108 |

Seen attack families remain detectable in a future-time split.

### Leave-one-attack-out

| Unseen attack | Recall | Benign FPR |
|---|---:|---:|
| DDoS | 0.4496 | 0.000041 |
| FTP-Patator | 0.0745 | 0.000061 |
| PortScan | 0.0004 | 0.000046 |
| SSH-Patator | 0.0027 | 0.000066 |

### Cross-capture

| Capture | Overall recall | Key attack recall |
|---|---:|---:|
| Friday DDoS | 0.0025 | DDoS 0.0025 |
| Friday PortScan | 0.0004 | PortScan 0.0004 |
| Tuesday | 0.0437 | FTP-Patator 0.0741, SSH-Patator 0.0029 |

**Interpretation:** the model memorizes dataset-specific signatures extremely well but generalizes poorly to attacks or captures it was not trained on. This is the most important technical caveat.

---

## 7. Alert Correlation and MITRE ATT&CK

`step3_alerts.py` groups predictions by source IP and time window, then chains related alerts into incidents.

Batch results:

- **7 alerts**: DDoS ×3, PortScan ×2, FTP-Patator ×1, SSH-Patator ×1.
- Severity: high ×5, medium ×2.
- **5 incidents**:

| Incident | Severity | Summary |
|---|---|---|
| INC-001 | high | FTP-Patator from `172.16.0.1` |
| INC-002 | high | SSH-Patator from `172.16.0.1` |
| INC-003 | critical | PortScan → DDoS chain from `172.16.0.1` |
| INC-004 | high | DDoS from `192.168.10.9` |
| INC-005 | high | DDoS from `192.168.10.5` |

ATT&CK mapping:

| Technique | Name | Tactic |
|---|---|---|
| T1595 | Active Scanning | Reconnaissance |
| T1110.001 | Brute Force: Password Guessing | Credential Access |
| T1498 | Network Denial of Service | Impact |

---

## 8. AI Analyst

`step4_assistant.py` has one report generator used by both batch and live paths:

- `make_report(incident, alerts, mode, provider, model)` returns `(effective_mode, markdown)`.
- `save_report()` writes `outputs/reports/<INCIDENT>_<suffix>.md`.
- On any API failure it falls back to the offline knowledge base and records why.

Modes:

- `offline` — deterministic knowledge-base report, no network.
- `auto` — first configured provider, otherwise offline.
- `llm` — require a configured provider.

Providers in `llm_providers.py` (standard library only):

| Provider | Key env var | Default model |
|---|---|---|
| Google Gemini | `GEMINI_API_KEY` / `GOOGLE_API_KEY` | `gemini-3.5-flash-lite` |
| OpenRouter | `OPENROUTER_API_KEY` | `openrouter/free` |
| Groq via OpenRouter | `OPENROUTER_API_KEY` | `meta-llama/llama-3.1-8b-instruct` with `provider.only = ["groq"]` |

No direct `api.groq.com` calls and no OpenAI provider remain in the final build.

Reports include: summary, timeline, ATT&CK mapping, likely attacker goal, recommended response actions for a small IT team, and caveats.

---

## 9. Live Detection

### Sources

- **Replay** — samples flows from `data/clean.csv` in an 80/20 attack/benign mix, in timestamp order. `count = 0` means continuous replay until Stop; a positive count runs a fixed batch. No privileges required.
- **tshark** — captures real packets and aggregates them into flows every 30 seconds. Requires `tshark` plus `CAP_NET_RAW`/`CAP_NET_ADMIN` or root. Packet-derived features only approximate CICIDS2017.

### Processing

Each flow is scored by XGBoost and IsolationForest, fused with OR, appended to `outputs/live/feed.jsonl`, and periodically re-correlated into live alerts/incidents. New incidents trigger `LIVE-*.md` reports automatically.

### Live outputs

| File | Purpose |
|---|---|
| `outputs/live/feed.jsonl` | Scored event stream |
| `outputs/live/alerts.json` | Correlated live alerts |
| `outputs/live/incidents.json` | Live incidents |
| `outputs/live/status.json` | Engine status and counters |
| `outputs/live/live.log` | Engine log |
| `outputs/reports/LIVE-*.md` | Auto-generated AI reports |

Starting a new session clears only these live artifacts.

---

## 10. Dashboard and API

The dashboard (`webapp.py` + `web/`) is a local-only, standard-library HTTP app with seven pages:

1. Overview
2. Live Detection
3. Alerts
4. Incidents
5. AI Reports
6. Evaluation
7. Pipeline

It exposes 17 JSON endpoints under `/api/` for overview data, alerts, incidents, reports, evaluation, pipeline control/logs, and live control:

- `GET /api/live?offset=N&log_offset=M` or `?tail=60`
- `POST /api/live/start`, `/api/live/stop`, `/api/live/key`
- Equivalent pipeline endpoints for batch runs.

The Live page streams new events, updates alerts/incidents/reports, shows a sidebar live dot, and auto-refreshes other pages while streaming.

---

## 11. Security and Data Handling

- Keys are stored in a local `.env` (gitignored, mode `600`) and loaded at startup.
- Keys pasted in the UI live only in server memory and are discarded on restart.
- No API keys, generated live feeds, or `LIVE-*.md` reports are committed.
- Model IDs and interface names are validated before being passed to subprocesses.
- The dashboard binds locally; there is no authentication layer, so it is intended for local demonstration only.

---

## 12. Limitations

1. CICIDS2017 is synthetic and dated; results do not represent real traffic.
2. Supervised model has poor zero-shot generalization: LOAO recall 0.04–45%.
3. Cross-capture recall is 0.25–4.4%; deployment would require retraining on real Zeek/Suricata flows.
4. IsolationForest OR-fusion has a ~1% FPR, unacceptable for many production SOCs.
5. tshark-derived features approximate, but do not reproduce, CICIDS2017 features.
6. LLM reports can hallucinate; they are analyst aids, not ground truth.
7. Free-tier quotas and provider model IDs change over time.
8. The dashboard has no user authentication or role separation.
9. Real packet capture could not be validated in this environment because `CAP_NET_RAW`/`CAP_NET_ADMIN` were unavailable.

---

## 13. Setup and Usage

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Optional local keys
cat > .env <<'EOF'
GEMINI_API_KEY=...
OPENROUTER_API_KEY=...
EOF
chmod 600 .env

# Batch pipeline
python run_pipeline.py

# Dashboard
python webapp.py --port 8080
# open http://127.0.0.1:8080/#/live
```

Live CLI examples:

```bash
python live_engine.py --source replay --rate 25 --count 0 --ai-mode auto
python live_engine.py --source tshark --interface eth0 --ai-mode llm --provider gemini
python step4_assistant.py --incident INC-003 --mode llm --provider openrouter
```

Tests and validation scripts:

```bash
./venv/bin/python -m unittest discover -s tests
./venv/bin/python scripts/validate_outputs.py
```

---

## 14. Conclusion and Future Work

The project successfully demonstrates a complete path from raw network data to correlated incidents and AI-generated analyst reports, including a working live stream and dashboard. Its in-distribution metrics are excellent, but hard evaluation clearly shows the generalization gap that must be addressed before any operational use.

Recommended next steps:

1. Collect and label real enterprise/Zeek/Suricata flows.
2. Replace port-dependent signatures with protocol- and behavior-level features.
3. Add drift monitoring and scheduled retraining.
4. Use active learning so analyst feedback improves the model.
5. Add authentication, RBAC, and audit logging to the dashboard.
6. Containerize the pipeline and live engine.
7. Expand CI with data validation, determinism checks, and API smoke tests.
8. Validate tshark flow features against a labeled dataset.

---

## 15. Artifact Inventory

| Artifact | Description |
|---|---|
| `data/clean.csv` | Cleaned 957,445-flow dataset |
| `models/xgb.json`, `models/classes.json` | Trained supervised model and labels |
| `models/anomaly_iforest.joblib` | Trained IsolationForest |
| `outputs/metrics.json` | Baseline OOF metrics |
| `outputs/metrics_with_port.json` | Port-inclusive comparison |
| `outputs/anomaly_metrics.json` | Anomaly and fusion metrics |
| `outputs/hard_eval.json` | Chronological, LOAO, cross-capture results |
| `outputs/alerts.json`, `outputs/incidents.json` | Batch correlation output |
| `outputs/reports/*.md` | Offline/LLM analyst reports |
| `outputs/live/*` | Live stream state (gitignored) |
| `outputs/reports/LIVE-*.md` | Live AI reports (gitignored) |
| `outputs/demo.html`, `outputs/demo.pdf` | Standalone demo |
| `webapp.py`, `web/` | Local dashboard |
| `live_engine.py`, `llm_providers.py` | Live detection and LLM layer |
