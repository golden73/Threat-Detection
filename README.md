# AI-Assisted Threat Detection & Response System

An end-to-end pipeline that detects network attacks from CICIDS2017 flow data,
correlates detections into incidents, maps them to MITRE ATT&CK, and generates
analyst-style reports — tuned for small, resource-constrained IT teams (demo
context: a school/clinic/SACCO/small business in Lusaka, Zambia).

## What it does

| Step | Script | Purpose | Key outputs |
|---|---|---|---|
| 1 | `step1_load_clean.py` | Load + clean CICIDS2017 CSVs | `data/clean.csv` |
| 2 | `step2_baseline.py` | Train XGBoost; out-of-fold predictions on every flow | `models/xgb.json`, `outputs/metrics.json`, `outputs/predictions.csv` |
| 3 | `step3_alerts.py` | Predictions → alerts → correlated incidents + ATT&CK mapping | `outputs/alerts.json`, `outputs/incidents.json` |
| 4 | `step4_assistant.py` | Analyst-style incident reports (offline KB or LLM) | `outputs/reports/*.md` |
| 5 | `step5_hard_eval.py` | Harder evaluation: chronological split + leave-one-attack-out | `outputs/hard_eval.json` |
| 6 | `step6_demo_page.py` | Self-contained offline demo page | `outputs/demo.html` |

## Pipeline

```
data/raw/*.csv ─→ step1 → data/clean.csv ─→ step2 → models/ + predictions.csv
                                                      │
predictions.csv ─→ step3 → alerts.json + incidents.json ─→ step4 → reports/*.md
                                                      └→ step5 → hard_eval.json
                                        step6 ←─ (all of the above) → demo.html
```

## Quick start

```bash
# 1. Environment
python -m venv venv
venv/bin/pip install -r requirements.txt
# (if pip tries to fetch a huge nvidia wheel for xgboost and the network
#  drops, set include-system-site-packages = true in venv/pyvenv.cfg and
#  reuse a system Python that already has the stack.)

# 2. Data (skip if data/clean.csv already present)
mkdir -p data/raw
#  ... place the CICIDS2017 "MachineLearningCVE" CSVs in data/raw/
venv/bin/python step1_load_clean.py data/raw data/clean.csv

# 3. Model + predictions (fast 3-fold out-of-fold scoring)
venv/bin/python step2_baseline.py data/clean.csv --folds 3

# 4. Comparison run WITH the destination-port feature (slide material)
venv/bin/python step2_baseline.py data/clean.csv --folds 3 --with-dest-port

# 5. Alerts + incidents
venv/bin/python step3_alerts.py outputs/predictions.csv

# 6. Reports (offline / LLM / auto)
venv/bin/python step4_assistant.py --incident INC-001            # auto mode
venv/bin/python step4_assistant.py --incident INC-001 --mode offline
venv/bin/python step4_assistant.py --ask "Which incident should I handle first?"

# 7. Hard evaluation
venv/bin/python step5_hard_eval.py data/clean.csv

# 8. Demo page
venv/bin/python step6_demo_page.py
# open outputs/demo.html in a browser (no server needed)
```

## Dataset

**CICIDS2017** (subset of 8 capture days → 3 capture files used here):

| source_file | rows (clean) |
|---|---|
| Tuesday-WorkingHours | 445,641 |
| Friday-WorkingHours-Afternoon-PortScan | 286,095 |
| Friday-WorkingHours-Afternoon-DDos | 225,709 |
| **Total clean flows** | **957,445** |

**Classes** (4 attack types + benign — see *Why only four attack types?*):

| Label | flows | MITRE ATT&CK |
|---|---|---|
| BENIGN | 656,784 | — |
| PortScan | 158,804 | **T1595** Active Scanning (Reconnaissance) · T1595.001 |
| DDoS | 128,025 | **T1498** Network Denial of Service (Impact) · T1498.001 |
| FTP-Patator | 7,935 | **T1110.001** Brute Force: Password Guessing |
| SSH-Patator | 5,897 | **T1110.001** Brute Force: Password Guessing |

> Mapping rationale: PortScan is external, pre-compromise scanning of the victim
> infrastructure → `T1595` Active Scanning (PRO comparison: `T1046` Network
> Service Discovery describes post-compromise, in-network discovery). The DDoS is
> a network-bandwidth flood → `T1498`, not endpoint-level `T1499`.

## Model & honest evaluation

- **Model**: XGBoost, multi-class (`objective=multi:softprob`), 200 trees,
  depth 8, lr 0.1. IPC metadata (IPs, ports, timestamps) excluded as features.
- **Scoring**: stratified k-fold **out-of-fold** — every flow is predicted by a
  model that never trained on it, so step 3 sees the full traffic timeline.
- `--with-dest-port` comparison exists because the destination port nearly
  gives the label away (21=FTP, 22=SSH, 80=DDoS); that run writes only
  `outputs/metrics_with_port.json`.

Numbers live in `outputs/metrics.json` and `outputs/hard_eval.json` (baseline,
chronological split, and leave-one-attack-out including per-class "unseen
attack" recall).

## LLM mode (step 4)

```bash
ANTHROPIC_API_KEY=sk-ant-... venv/bin/python step4_assistant.py --mode llm --incident INC-001
```

Default is `auto`: LLM if the key is present, otherwise the offline
knowledge-base report. The offline mode is demo-safe (no internet needed).

## Repository layout

```
data/          raw captures, clean.csv, mini subset/
models/        xgb.json + classes.json (final model)
outputs/       metrics, predictions, alerts, incidents, hard_eval,
               reports/*.md, demo.html
writeups/      audit log of changes (OpenCode + Kilo) and PROMPT_FOR_KILO.txt
step1..6.py    pipeline scripts
```

## Notes & caveats

- Detections are ML predictions on flow data — **not proof of compromise**;
  confirm with firewall/server/auth logs before acting.
- Source IPs may be NAT/shared; do not attribute beyond the data.
- `UNMAPPED` attack classes don't crash step 3 (they become a placeholder plus
  a printed warning) — add the mapping to step 3 + step 4 KB and rerun 3/4/6.

## Collaboration

Two agents work in this repo (OpenCode + Kilo in VS Code). Changes are logged
under `writeups/` so either agent can audit decisions and reproduce results.
See `writeups/PROMPT_FOR_KILO.txt`.