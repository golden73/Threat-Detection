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
├── run_pipeline.py          # One-command runner for steps 1-6
├── tests/test_smoke.py      # Structure / compile smoke tests
├── slides.md                # Presentation outline (12 slides)
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

Download CICIDS2017 "MachineLearningCVE" CSVs and place in `data/raw/`:
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
- **llm**: Anthropic Claude (requires `ANTHROPIC_API_KEY` and `pip install anthropic`)
- **auto**: LLM if key available, otherwise offline

```bash
# Offline (default)
python step4_assistant.py --incident INC-003

# LLM mode
export ANTHROPIC_API_KEY=sk-...
python step4_assistant.py --incident INC-003 --mode llm
```

The assistant runs fully offline by default; set `ANTHROPIC_API_KEY` and use
`--mode llm` to enable Anthropic Claude.

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