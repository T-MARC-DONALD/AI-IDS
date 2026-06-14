# AI-IDS v2.0

Flow-based real-time Intrusion Detection System using a two-stage RandomForest pipeline trained on CIC-IDS2017.

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/T-MARC-DONALD/AI-IDS.git
cd AI-IDS

# 2. Install runtime dependencies
pip install -r requirements.txt

# 3. Download pre-trained model artifacts
#    Linux / macOS:
bash download_models.sh
#    Windows PowerShell:
.\download_models.ps1

# 4. Configure environment
cp .env.example .env   # edit .env with your values

# 5. Run the IDS
python live_ids.py
```

## Training Pipeline

To rebuild the model artifacts from the CIC-IDS2017 dataset, install training dependencies:

```bash
pip install -r requirements-training.txt
```

Then run the training scripts in order:

```bash
python training/survey_dataset.py
python training/02_survey_full.py
python training/03_clean_and_split.py
python training/04_train_models.py
python training/05_validate_artifacts.py
```

## Project Structure

| File | Purpose |
|------|---------|
| `live_ids.py` | Main application — Flask server + Scapy packet capture |
| `alerting.py` | Multi-channel alert dispatch (email, Telegram, WhatsApp) |
| `flow_record.py` | Per-flow state and feature extraction |
| `flow_table.py` | Flow assembly, sweeper, and model artifact loading |
| `training/` | Data survey, cleaning, training, and validation scripts |
| `models/` | Pre-trained model artifacts (download via scripts above) |
| `templates/` | Flask HTML templates |
| `static/` | CSS, JS, and image assets |
