# AI-IDS v2.0

AI-IDS v2.0 is a flow-based, Flask-powered intrusion detection system built on CIC-IDS2017 traffic features. It replaces the earlier packet-by-packet NSL-KDD-style live pipeline with a two-stage flow classifier, a richer monitoring dashboard, and configurable multi-channel alerting.

Version history in this repository:
- v1.x: the original packet-oriented live IDS and legacy model artifacts remain in repository history and selected legacy files.
- v2.0: the current release in this working tree, centered on `live_ids.py`, `flow_table.py`, `flow_record.py`, the `models/` directory, and the Watchfloor UI.

## What problem v2.0 solves

The original live IDS pipeline had three practical limitations:
- It classified individual packets instead of complete flows, which made detection shallow and less faithful to how CIC-IDS2017 features are defined.
- It relied on hardcoded local alert settings, which made deployment, testing, and secret handling fragile.
- It lacked the operational feedback needed to tell the difference between successful packet capture, delayed flow expiry, interface-selection issues, and alert-delivery failures.

v2.0 solves this by:
- assembling packets into bidirectional flows using CICFlowMeter-style logic
- running a binary `BENIGN` vs `ATTACK` model first, then an attack-type model only for flows classified as attacks
- separating runtime configuration into `.env` and local alert state
- exposing a dedicated dashboard, alerts page, CSV prediction page, and single-sample prediction page
- supporting Email, Telegram, Twilio WhatsApp, and Meta WhatsApp Cloud alert channels
- adding a Telegram chat discovery helper for the bot `https://t.me/limitidsbot`

## Core features in v2.0

- Flow-based live capture with Scapy
- Two-stage RandomForest inference pipeline
- CIC-IDS2017-derived 78-feature flow classification
- Live dashboard with packet totals, active flows, verdict history, and flow-detail modal
- Standalone pages for alert configuration, CSV scoring, and single-sample scoring
- Multi-channel alerts with server-managed secrets support
- Frontend-driven alert configuration stored locally in `alert_channels.local.json`
- Environment-based configuration with `.env.example`
- Training and validation scripts for rebuilding the dataset and model artifacts

## Attack classes supported

The binary model classifies each flow as `BENIGN` or `ATTACK`.

If a flow is marked `ATTACK`, the multiclass model can label it as one of:
- `DDoS`
- `PortScan`
- `DoS Hulk`
- `DoS GoldenEye`
- `DoS slowloris`
- `DoS Slowhttptest`
- `FTP-Patator`
- `SSH-Patator`
- `Bot`
- `Web Attack - Brute Force`
- `Web Attack - XSS`
- `Web Attack - SQL Injection`
- `Infiltration`
- `Heartbleed`

Note: `Heartbleed`, `Infiltration`, and `Web Attack - SQL Injection` are ultra-rare in CIC-IDS2017 and therefore less strongly validated than the common classes.

## Repository layout for v2.0

Important v2.0 files:
- `live_ids.py`: Flask application, live capture loop, API routes, and dashboard data source
- `alerting.py`: alert manager and external delivery integrations
- `flow_record.py`: per-flow state and feature computation
- `flow_table.py`: flow table, artifact loading, and inference bridge
- `survey_dataset.py`: dataset survey and merge entry point (`01_survey_dataset.py` in the docstring)
- `02_survey_full.py`, `03_clean_and_split.py`, `04_train_models.py`, `05_validate_artifacts.py`: training pipeline
- `models/`: runtime model artifacts required by v2.0
- `templates/`, `static/`: Watchfloor frontend
- `.env.example`: environment configuration template
- `processed/label_mapping.csv`, `processed/sample_1000rows.csv`: lightweight reference files

Files intentionally not committed for v2.0 deployment:
- `.env`
- `alert_channels.local.json`
- virtual environments
- raw CIC-IDS2017 CSVs
- generated `.parquet` training splits and merged raw archives
- runtime logs and temporary validation files

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/T-MARC-DONALD/AI-IDS.git
cd AI-IDS
```

### 2. Create and activate a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Prepare configuration

```bash
cp .env.example .env
```

Then edit `.env` and set at least:
- model path (`MODELS_DIR`, default `./models`)
- optional alert credentials
- flow timeout tunables if you want faster demo expiry

### 5. Run the application

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe .\live_ids.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Alert channels

Configured channels in v2.0:
- Email (SMTP)
- Telegram (Bot API)
- WhatsApp via Twilio
- WhatsApp via Meta Cloud API

Highlights:
- Email can be server-managed so only the recipient email stays editable in the UI.
- Telegram can be server-managed so only the recipient chat ID stays editable in the UI.
- The Telegram helper links users to `https://t.me/limitidsbot` and can auto-fill the latest chat ID after the user presses `Start` in Telegram.

## Training pipeline

The repository includes the full rebuild path for the v2.0 artifacts:

1. `survey_dataset.py`
  merges the 8 CIC-IDS2017 CSV files and writes `processed/merged_raw.parquet`
2. `02_survey_full.py`
  reports class balance and data quality issues
3. `03_clean_and_split.py`
  cleans duplicates/bad rows and creates train/test splits
4. `04_train_models.py`
  trains the binary and multiclass RandomForest models
5. `05_validate_artifacts.py`
  validates the saved artifacts end to end

## Detailed documentation

See `docs/VERSION_2_0.md` for:
- the engineering rationale behind v2.0
- a detailed runbook
- alert configuration guidance
- training workflow
- validation strategy
- deployment notes and limitations

## Recommended first tests

Recommended order of validation:
- use the alerts page to send Email and Telegram test alerts
- run a controlled `PortScan` from a second host
- run a benign browsing/download test to check for over-flagging
- run CSV and single-sample predictions to validate offline inference

## Operational limitations

- This IDS only sees traffic available to the host interface it is capturing from.
- Flow-based classification happens on flow expiry, not necessarily on the first packet.
- HTTPS traffic limits deep application-layer visibility; the system is strongest at traffic-flow detection, not full WAF-style payload inspection.
- Correct interpreter version matters: the saved artifacts were trained with `scikit-learn 1.9.0`.

## Author

Built by TONGA NOUDJA MARC-DONALD.
