#Requires -Version 5.1

# Update this URL to point to your hosted models zip
$DownloadUrl = "https://github.com/T-MARC-DONALD/AI-IDS/releases/download/v2.0/models.zip"

$ModelsDir = "./models"
$ExpectedFiles = @(
    "binary_model.joblib"
    "binary_scaler.joblib"
    "multiclass_model.joblib"
    "multiclass_scaler.joblib"
    "multiclass_label_encoder.joblib"
    "feature_columns.joblib"
)

if (-not (Test-Path $ModelsDir)) {
    New-Item -ItemType Directory -Path $ModelsDir | Out-Null
}

Write-Host "Downloading model artifacts from:"
Write-Host "  $DownloadUrl"
$zipPath = Join-Path $env:TEMP "models.zip"
Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath -UseBasicParsing

Write-Host "Extracting into $ModelsDir ..."
Expand-Archive -Path $zipPath -DestinationPath $ModelsDir -Force
Remove-Item $zipPath

Write-Host ""
Write-Host "Verifying expected files..."
$allPresent = $true
foreach ($f in $ExpectedFiles) {
    $path = Join-Path $ModelsDir $f
    if (Test-Path $path) {
        Write-Host "  [OK] $f"
    } else {
        Write-Host "  [MISSING] $f"
        $allPresent = $false
    }
}

if ($allPresent) {
    Write-Host ""
    Write-Host "All 6 model artifacts present. Ready to run: python live_ids.py"
} else {
    Write-Host ""
    Write-Host "ERROR: Some files are missing. Check the download URL and try again."
    exit 1
}
