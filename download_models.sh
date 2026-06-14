#!/usr/bin/env bash
set -euo pipefail

# Update this URL to point to your hosted models zip
DOWNLOAD_URL="https://github.com/T-MARC-DONALD/AI-IDS/releases/download/v2.0/models.zip"

MODELS_DIR="./models"
EXPECTED_FILES=(
  "binary_model.joblib"
  "binary_scaler.joblib"
  "multiclass_model.joblib"
  "multiclass_scaler.joblib"
  "multiclass_label_encoder.joblib"
  "feature_columns.joblib"
)

mkdir -p "$MODELS_DIR"

echo "Downloading model artifacts from:"
echo "  $DOWNLOAD_URL"
curl -fSL "$DOWNLOAD_URL" -o /tmp/models.zip

echo "Extracting into $MODELS_DIR ..."
unzip -o /tmp/models.zip -d "$MODELS_DIR"
rm -f /tmp/models.zip

echo ""
echo "Verifying expected files..."
all_present=true
for f in "${EXPECTED_FILES[@]}"; do
  if [ -f "$MODELS_DIR/$f" ]; then
    echo "  [OK] $f"
  else
    echo "  [MISSING] $f"
    all_present=false
  fi
done

if [ "$all_present" = true ]; then
  echo ""
  echo "All 6 model artifacts present. Ready to run: python live_ids.py"
else
  echo ""
  echo "ERROR: Some files are missing. Check the download URL and try again."
  exit 1
fi
