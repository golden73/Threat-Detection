# AI-Assisted Threat Detection & Response System

End-to-end threat detection pipeline built on CICIDS2017 network traffic.
Implements ML detection, alert correlation, MITRE ATT&CK mapping, AI-assisted
analyst reports, and a standalone demo page — all offline-capable.

## Project Structure

```
.
├── data/
│   ├── raw/                 # Original CICIDS2017 CSVs (download separately)
│   ├── subset/              # Pre-cleaned subset (optional)
│   ├── clean.csv            # Merged & cleaned data (957K flows, 80 features)
│   └── README.md            # How to obtain and regenerate the data
├── models/
│   ├── xgb.json             # Trained XGBoost model
│   └── classes.json         # Class labels
├── outputs/
│   ├── metrics.json         # Baseline metrics (no port)
│   ├── metrics_with_port.json  # Comparison with Destination Port
│   ├── predictions.csv      # Per-flow out-of-fold predictions (gitignored)
│   ├── alerts.json          # Correlated alerts with ATT&CK
│   ├── incidents.json       # Multi-alert incidents
│   ├── hard_eval.json       # Chronological + LOAO + cross-capture
│   ├── demo.html            # Standalone demo page
│   └── reports/             # AI assistant reports (Markdown)
├── step1_load_clean.py      # Load & clean CICIDS2017 CSVs
├── step2_baseline.py        # XGBoost baseline (k-fold OOF, no port)
├── step3_alerts.py          # Predictions → alerts → incidents + ATT&CK
├── step4_assistant.py       # AI SOC assistant (LLM or offline KB)
├── step5_hard_eval.py       # Chronological / LOAO / cross-capture eval
├── step6_demo_page.py       # Build demo.html
├── step7_anomaly.py         # Unsupervised anomaly layer (IsolationForest) + fusion
├── run_pipeline.py          # One-command runner for steps 1-7
├── webapp.py                # Local web dashboard (standard library only)
├── web/                     # Dashboard frontend (no build step)
│   ├── index.html
│   ├── style.css
│   └── app.js
├── scripts/                 # Dev utilities
│   ├── make_sample_data.py  # Synthetic CICIDS-like CSVs for CI / smoke tests
│   └── validate_outputs.py  # Assert output artifacts exist & are well-formed
├── tests/test_smoke.py      # Structure / compile smoke tests
├── tests/test_webapp.py     # Dashboard API / HTTP smoke tests
└── requirements.txt         # Python dependencies
```

## Quick Start

### 1. Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Get Data

Download CICIDS2017 "MachineLearningCVE" CSVs and place in `data/raw/` (see
`data/README.md` for sources: the official UNB page, a Kaggle mirror, and a
Hugging Face mirror). Verify your downloads against `CHECKSUMS.sha256`:

```bash
sha256sum --check CHECKSUMS.sha256        # if raw CSVs live in data/raw/
# or: (cd data && sha256sum --check ../CHECKSUMS.sha256) — adjust paths as needed
```

The checksums were computed from the `MachineLearningCVE` and
`TrafficLabelling` variants; both are accepted by the loader, you only need one.
- Tuesday-WorkingHours.pcap_ISCX.csv
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
- Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv

`data/` is gitignored; see `data/README.md` for download and regeneration
details. If `data/clean.csv` already exists locally, step 1 is skipped.

### 3. Run Pipeline

Run everything with one command:

```bash
python run_pipeline.py
```

Or run the steps individually:

```bash
# Step 1: Clean data (if starting from raw CSVs)
python step1_load_clean.py data/raw data/clean.csv

# Step 2: Train & evaluate XGBoost (k-fold OOF, all flows)
python step2_baseline.py data/clean.csv --folds 3

# Step 2b: Comparison run WITH Destination Port (metrics only)
python step2_baseline.py data/clean.csv --folds 3 --with-dest-port

# Step 3: Correlate predictions into alerts & incidents
python step3_alerts.py outputs/predictions.csv

# Step 4: Generate AI assistant reports (offline mode)
python step4_assistant.py --incident INC-001 --mode offline
python step4_assistant.py --incident INC-002 --mode offline
python step4_assistant.py --incident INC-003 --mode offline
python step4_assistant.py --incident INC-004 --mode offline
python step4_assistant.py --incident INC-005 --mode offline

# Step 5: Hard evaluation (chronological + LOAO + cross-capture)
python step5_hard_eval.py data/clean.csv

# Step 6: Build demo page
python step6_demo_page.py

# Open demo
# Linux: xdg-open outputs/demo.html
# macOS: open outputs/demo.html
# Windows: start outputs/demo.html
```

### 4. Open the dashboard

A local web dashboard turns the pipeline artifacts into a live, navigable view:

```bash
python3 webapp.py           # http://127.0.0.1:8080
python3 webapp.py --open    # start and open the browser
python3 webapp.py --port 9000
```

It uses only the Python standard library (no Node, no build step, no CDN) and
reads the files in `outputs/` directly, so it stays fully offline.

| Page | What it shows |
|------|---------------|
| **Overview** | KPI cards, dataset composition, confusion matrix, pipeline stage strip, MITRE coverage, recent incidents |
| **Alerts** | Filterable/searchable alert table; click a row for source, targets, confidence and ATT&CK details |
| **Incidents** | Multi-stage incident cards; detail view with linked alerts and the AI analyst report |
| **AI Reports** | Rendered knowledge-base (and LLM, when present) reports per incident |
| **Evaluation** | Chronological split, leave-one-attack-out bars, cross-capture tables, with/without destination-port toggle |
| **Pipeline** | Per-stage status and artifacts, plus **Run/Stop** controls and a live streaming console |

The dashboard also detects a pipeline that was started elsewhere (e.g.
`python run_pipeline.py` in another terminal) and shows it as an external run
instead of starting a second one.

HTTP API (used by the frontend, handy for scripting):

```
GET  /api/overview              counts, metrics, pipeline stages
GET  /api/alerts                alerts.json
GET  /api/incidents             incidents.json
GET  /api/incidents/<id>        incident + linked alerts + reports
GET  /api/reports               report index
GET  /api/reports/<id>          rendered Markdown source
GET  /api/hard-eval             hard_eval.json + with-port variant
GET  /api/pipeline              run state + stage status
GET  /api/pipeline/log?offset=  incremental pipeline log
POST /api/pipeline/start        start run_pipeline.py
POST /api/pipeline/stop         stop a dashboard-started run
```

## Going Live (real-time detection + LLM reports)

Open the dashboard and select **Live** in the sidebar. The stream controls let
you choose the source, rate, AI mode, LLM provider/model, and (optionally) an
API key.

```bash
python3 webapp.py                       # then open http://127.0.0.1:8080/#/live
```

**1. Live AI reports.** Three hosted options are supported through one
interface (`llm_providers.py`, standard library only):

| Provider | Key env var | Default model | Free tier |
|---|---|---|---|
| Google Gemini | `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | `gemini-3.5-flash-lite` | Yes |
| OpenRouter | `OPENROUTER_API_KEY` | `openrouter/free` | 15 free models |
| Groq (via OpenRouter) | `OPENROUTER_API_KEY` | `meta-llama/llama-3.1-8b-instruct` | Groq-hosted, routed via OpenRouter |

Groq is reached through OpenRouter with `provider: {"only": ["groq"]}` — no
direct Groq API calls and no separate Groq key are needed.

For a mini-project setup, keep keys in a local `.env` file in the project root
(gitignored, mode 600) — they are loaded on startup, so dashboard restarts keep
working:

```bash
cat > .env <<'EOF'
GEMINI_API_KEY=...
OPENROUTER_API_KEY=...
EOF
chmod 600 .env
python3 webapp.py
```

You can also paste a key into the Live page for the current session (provider
memory only), or export one before starting the dashboard. Never commit `.env`.

Modes: `auto` uses the first configured provider and falls back to the offline
knowledge base if none is configured, `llm` requires a key for the chosen
provider, `offline` never calls an API. If a call fails, the report falls back
to offline mode and says so. Model IDs and free quotas change; override the
model field at any time (e.g. `google/gemma-4-26b-a4b-it:free` on OpenRouter,
`gemini-3.5-flash-lite` on Gemini).

**2. Live traffic feed.** Two sources:

- `replay` (default) — replays flows from `data/clean.csv` in timestamp order,
  with an 80/20 attack/benign mix at a configurable rate. Needs no privileges.
  `Flows to replay = 0` (the default) means continuous replay until you press
  Stop; set a positive count for a one-off batch.
- `tshark` — captures real packets on an interface and aggregates them into
  flows every 30 seconds. Requires `tshark` and capture permission:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin+eip "$(dirname "$(readlink -f "$(command -v tshark)")")/dumpcap"
  python live_engine.py --source tshark --interface eth0 --ai-mode auto
  ```

  Packet-derived features approximate the CICIDS2017 feature set; treat live
  capture detections as a demo/prototype, not a validated production sensor.

The engine scores each flow with the trained XGBoost model **and** the
IsolationForest anomaly layer, fuses them with OR, and writes to
`outputs/live/` (`feed.jsonl`, `alerts.json`, `incidents.json`, `status.json`,
`live.log`) plus `outputs/reports/LIVE-*.md`. It never overwrites the batch
pipeline artifacts. Starting a new stream clears the previous live session.

**3. Live dashboard.** The Live page streams new events into the table, updates
alerts/incidents/reports automatically, and keeps the other pages fresh while a
stream is running. The sidebar dot shows when a stream is active.

HTTP API for the live path:

```
GET  /api/live?offset=N&log_offset=M   status + feed + alerts + incidents + log
GET  /api/live?tail=60                 last 60 feed events instead
POST /api/live/start                   {"source":"replay","rate":10,"count":600,"ai_mode":"auto","provider":"gemini"}
POST /api/live/stop
POST /api/live/key                     {"provider":"groq","key":"...","model":"..."}   (session memory only)
```

Command line equivalents:

```bash
python step4_assistant.py --incident INC-003 --mode llm --provider gemini
python live_engine.py --source replay --ai-mode auto --provider openrouter --model openrouter/free
```

## Key Features

- **No label leakage**: Destination Port excluded from model features
- **Honest evaluation**: k-fold out-of-fold on ALL flows, not random split
- **MITRE ATT&CK aligned**: T1595 (Reconnaissance), T1498 (Impact), T1110.001 (Credential Access)
- **Multi-stage correlation**: Alerts chained into incidents with severity escalation
- **AI assistant**: Offline knowledge-base mode (no API key needed)
- **Lusaka-contextualized**: Free tools, ISP contact, ZM-CIRT awareness
- **Single-file demo**: `outputs/demo.html` opens in any browser

## Evaluation Results (Summary)

| Evaluation | Precision | Recall | F1 | FPR |
|------------|-----------|--------|-----|-----|
| Baseline (3-fold OOF, no port) | 0.99987 | 0.99988 | 0.99987 | 6.1×10⁻⁵ |
| Baseline (3-fold OOF, with port) | 0.99989 | 0.99991 | 0.99990 | 5.2×10⁻⁵ |
| Chronological split | 0.9995 | 0.9970 | 0.9982 | 1.1×10⁻⁴ |
| LOAO (DDoS unseen) | — | 0.4496 | — | 4.1×10⁻⁵ |
| LOAO (PortScan unseen) | — | 0.0004 | — | 4.6×10⁻⁵ |

## MITRE ATT&CK Mappings

| Attack Class | Technique ID | Technique Name | Tactic | Severity |
|--------------|--------------|----------------|--------|----------|
| PortScan | T1595 | Active Scanning (T1595.001) | Reconnaissance | Medium |
| DDoS | T1498 | Network Denial of Service (T1498.001) | Impact | High |
| FTP-Patator | T1110.001 | Brute Force: Password Guessing | Credential Access | High |
| SSH-Patator | T1110.001 | Brute Force: Password Guessing | Credential Access | High |

## AI Assistant Modes

- **offline**: Deterministic knowledge-base report (default, no dependencies)
- **llm**: Gemini, OpenRouter or Groq via OpenRouter (requires a provider API key)
- **auto**: LLM if any provider key is available, otherwise offline

```bash
# Offline (default)
python step4_assistant.py --incident INC-003

# LLM mode with a specific provider
export GEMINI_API_KEY=...
python step4_assistant.py --incident INC-003 --mode llm --provider gemini
```

The assistant runs fully offline by default; set one of the provider keys above
and use `--mode llm` (optionally `--provider` / `--model`) to enable hosted reports.

## Limitations

1. **Supervised only** — poor zero-shot generalization (LOAO 0.04–45% recall)
2. **CICIDS2017 synthetic** — validate on production Zeek/Suricata flows
3. **Flow-level only** — no payload/L7 visibility
4. **Single-source correlation** — misses distributed attacks
5. **LLM not evaluated** — "implemented, not evaluated" (no API key in test env)

## Future Work

- Add unsupervised anomaly detection layer
- Live packet capture integration (Zeek, Suricata)
- Graph-based multi-source correlation
- LLM-assisted triage with RAG on local KB
- Edge deployment (Raspberry Pi, Jetson)

## License

MIT — free for research, education, and operational use.

## Citation

If you use this in research, please cite:
- CICIDS2017 dataset: Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"
- MITRE ATT&CK framework: https://attack.mitre.org/