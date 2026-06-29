# AI-IDS Version 2.0 Documentation

## 1. Release summary

AI-IDS v2.0 is the second major version of this project. It shifts the system from a packet-oriented live classifier to a flow-oriented IDS that is much closer to how CIC-IDS2017 data is structured and how network intrusion behavior is usually expressed.

This release is not just a UI refresh. It changes the operating model, the data path, the alerting architecture, and the way the system is configured and validated.

## 2. The problem being solved

The earlier version of the project was good as a proof of concept, but it carried several structural problems:

### 2.1 Packet-level inference did not match the dataset well

The earlier live IDS attempted to classify individual packets using NSL-KDD-style engineered features. That approach is weak for CIC-IDS2017-derived behavior because many important features only make sense over the lifetime of a flow, not a single packet.

Examples:
- packet and byte totals in each direction
- inter-arrival timing statistics
- flow duration
- burst behavior
- active and idle window statistics

### 2.2 Operational visibility was not strong enough

When a user clicked `Start capture`, the system could be capturing packets successfully while still showing no classifications yet. That created confusion because the UI did not clearly distinguish:
- packets observed
- flows still assembling
- flows expired and classified
- alert delivery success or failure

### 2.3 Configuration and secrets were too rigid

The original alert path depended on hardcoded or tightly embedded settings. That made reuse, deployment, and testing difficult, especially once the system needed multiple delivery methods.

### 2.4 The system needed broader, real operational alerting

A practical IDS should not stop at on-screen detection. It should notify operators through common channels such as Email or Telegram and make those channels testable and manageable through the UI.

## 3. How v2.0 solves the problem

### 3.1 Flow-based capture and classification

The core fix is the move to a flow-based architecture:
- packets are captured with Scapy
- packets are grouped into bidirectional flows using a normalized 5-tuple
- the system computes CICFlowMeter-style flow features
- the flow is classified only after inactivity timeout or forced flush

This aligns the live inference path with the kind of features the model was trained on.

### 3.2 Two-stage model pipeline

v2.0 uses two models:

1. Binary model
   classifies each flow as `BENIGN` or `ATTACK`

2. Multiclass model
   runs only when the binary model says `ATTACK`, then labels the attack type

This reduces unnecessary multiclass inference on benign traffic and produces clearer operator-facing results.

### 3.3 Better operational feedback in the UI

The Watchfloor UI now exposes:
- selected capture interface
- packet totals
- active flow count
- attack totals
- recent classified flows
- a modal with the full 78-feature vector for a selected flow
- explicit alert-channel status

This helps the operator understand whether the issue is capture, classification delay, interface selection, or alerting.

### 3.4 Environment-based secret handling

The app now reads runtime settings from `.env`.

This keeps secret material out of the codebase and enables a safer split between:
- server-managed secrets in `.env`
- local UI-configured destinations in `alert_channels.local.json`

### 3.5 Multi-channel alerting

v2.0 adds a centralized `AlertManager` with support for:
- Email via SMTP
- Telegram Bot API
- WhatsApp via Twilio
- WhatsApp via Meta Cloud API

The system exposes dedicated alert routes so channels can be:
- enabled/disabled
- saved from the frontend
- tested without waiting for a real attack

### 3.6 Telegram usability improvements

Telegram is harder for users than Email because bots normally require a numeric `chat_id` rather than a username. To reduce friction, v2.0 includes a helper flow:
- the UI points the user to `https://t.me/limitidsbot`
- the user opens the bot and presses `Start`
- the app can fetch the latest Telegram update and auto-fill the recipient chat ID

## 4. Architecture overview

### 4.1 Runtime components

- `live_ids.py`
  Flask app, routes, sniffer loop, dashboard data, and alert endpoints

- `flow_record.py`
  per-flow counters and CICFlowMeter-style feature computation

- `flow_table.py`
  active-flow registry, artifact loading, and flow-to-model prediction

- `alerting.py`
  alert channel abstraction, local persistence, and external delivery

- `templates/`
  Jinja views for dashboard, alerts, CSV prediction, and single-sample prediction

- `static/`
  CSS and browser logic for the Watchfloor interface

### 4.2 Data flow

1. packets arrive on the selected interface
2. Scapy captures them
3. `FlowTable` adds them to a normalized bidirectional flow
4. `FlowSweeper` expires idle flows
5. features are computed from the flow record
6. binary model predicts `BENIGN` or `ATTACK`
7. if `ATTACK`, multiclass model predicts attack type
8. dashboard state is updated
9. if `ATTACK`, enabled alert channels are dispatched asynchronously

## 5. Shipped files in the v2.0 update

The v2.0 GitHub update should include:
- source code for the live IDS and alerting
- frontend templates and assets
- model artifacts required for runtime inference
- `.env.example`
- `requirements.txt`
- documentation
- lightweight reference files such as `processed/label_mapping.csv`

The v2.0 GitHub update should not include:
- `.env`
- `alert_channels.local.json`
- local virtual environments
- server logs
- temporary validation files
- raw CIC-IDS2017 CSVs
- generated training `.parquet` files or merged raw archives

## 6. How to run v2.0

### 6.1 Prerequisites

- Python 3.11+ is recommended
- a working virtual environment
- packet capture permissions
- Npcap on Windows if packet sniffing is required
- model artifacts in `./models`

### 6.2 Installation

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 6.3 Configure environment variables

At minimum, verify:
- `MODELS_DIR=./models`
- `FLOW_ACTIVITY_TIMEOUT`
- `FLOW_SWEEP_INTERVAL`

Optional alert settings:
- Email SMTP settings
- Telegram bot token and optional chat ID
- Twilio WhatsApp settings
- Meta WhatsApp Cloud settings

### 6.4 Start the application

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe .\live_ids.py
```

Open:

```text
http://127.0.0.1:5000
```

### 6.5 Select the interface and begin capture

1. open the dashboard
2. choose the active Ethernet or Wi-Fi adapter
3. click `Set interface`
4. click `Start capture`
5. monitor packet totals and active flows

Important: flow-based systems classify on flow expiry, so a successful capture can still show no verdict yet until a flow times out or capture is stopped and active flows are flushed.

## 7. Alert configuration

### 7.1 Email

If SMTP settings are server-managed in `.env`, the UI only exposes the recipient email.

### 7.2 Telegram

If the bot token is server-managed in `.env`, the UI only exposes the recipient chat ID.

Telegram helper flow:
1. open `https://t.me/limitidsbot`
2. press `Start`
3. go to the Alerts page
4. click `Use latest chat ID`
5. click `Save settings`
6. click `Send test`

### 7.3 WhatsApp channels

Twilio and Meta Cloud configuration can be saved through the Alerts page once credentials are provided.

## 8. Training and rebuild workflow

The full v2.0 training path is included in the repository.

### Step 1: survey and merge raw CIC-IDS2017 CSVs

Run:

```bash
python survey_dataset.py
```

Outputs:
- `processed/sample_1000rows.csv`
- `processed/merged_raw.parquet`

### Step 2: inspect class balance and data quality

Run:

```bash
python 02_survey_full.py
```

### Step 3: clean and split the dataset

Run:

```bash
python 03_clean_and_split.py
```

This step:
- fixes label encoding artifacts
- removes duplicates
- removes bad rate rows
- creates binary and multiclass train/test splits

### Step 4: train the binary and multiclass models

Run:

```bash
python 04_train_models.py
```

Outputs in `models/`:
- `binary_model.joblib`
- `binary_scaler.joblib`
- `multiclass_model.joblib`
- `multiclass_scaler.joblib`
- `multiclass_label_encoder.joblib`
- `feature_columns.joblib`

### Step 5: validate saved artifacts

Run:

```bash
python 05_validate_artifacts.py
```

This confirms:
- artifacts load successfully
- binary inference works
- multiclass inference works
- single-row live prediction latency is reasonable

## 9. Validation strategy for v2.0

Recommended validation order:

### 9.1 Alert channel self-test

Use the Alerts page to send test messages for Email and Telegram first.

### 9.2 Live `PortScan` test

Best first live test:
- run the IDS on one host
- generate a low-rate port sweep from a second host
- wait for flow expiry or stop capture to flush
- verify dashboard verdicts and alert delivery

### 9.3 Benign traffic test

Generate normal browsing or file-download traffic and verify the system does not over-flag the behavior.

### 9.4 Offline scoring

Use the CSV and single-sample pages to confirm the non-live prediction paths work.

## 10. Known operational constraints

### 10.1 Visibility depends on capture position

The system only inspects traffic visible to the host interface it captures from.

### 10.2 Classification is delayed by design

Flow systems need enough traffic and enough inactivity to define a finished feature vector.

### 10.3 Rare classes are less validated

`Heartbleed`, `Infiltration`, and `Web Attack - SQL Injection` are present in training but had no meaningful held-out test coverage.

### 10.4 Version mismatch can break model loading

The artifacts were trained with `scikit-learn 1.9.0`. Running them with the wrong interpreter or dependency set can fail at load time.

## 11. Recommended deployment patterns

Best-fit placements for v2.0:
- a dedicated monitoring workstation
- a gateway host
- a SPAN/mirror-port sensor
- a VM with mirrored traffic
- a server hosting a website or reverse proxy

It is suitable for protecting website infrastructure, but it is not a browser-side website plugin.

## 12. Final note on versioning

v1 remains part of the repository history as the earlier packet-based generation.

v2.0 is the current supported architecture and should be treated as the primary runtime path going forward.
