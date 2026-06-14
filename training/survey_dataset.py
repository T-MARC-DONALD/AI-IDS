"""
01_survey_dataset.py

Loads all 8 CIC-IDS2017 MachineLearningCSV files, cleans up column names,
merges them, and reports:
  - row counts per file
  - binary class distribution (BENIGN vs ATTACK)
  - multi-class distribution (per attack label)
  - missing / infinite value counts per column
  - memory usage

Run from inside the folder containing the 8 CSVs, or set DATA_DIR below.

Usage:
    python 01_survey_dataset.py
"""

import os
import glob
import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# CONFIG - adjust this path to wherever you unzipped MachineLearningCSV.zip
# ---------------------------------------------------------------------------
DATA_DIR = "../MachineLearningCVE"   # <-- change me if needed
OUTPUT_DIR = "../processed"

os.makedirs(OUTPUT_DIR, exist_ok=True)


def clean_columns(df):
    """Strip whitespace and normalize column names."""
    df.columns = [c.strip() for c in df.columns]
    return df


def load_all_csvs(data_dir):
    csv_files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in '{data_dir}'. "
            "Check DATA_DIR points to the unzipped MachineLearningCSV folder."
        )

    print(f"Found {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"  - {os.path.basename(f)}")
    print()

    frames = []
    for f in csv_files:
        # low_memory=False avoids dtype-guessing warnings on mixed columns
        df = pd.read_csv(f, low_memory=False, encoding="latin1")
        df = clean_columns(df)
        df["__source_file"] = os.path.basename(f)
        n_rows = len(df)
        print(f"{os.path.basename(f):55s} -> {n_rows:>10,} rows")
        frames.append(df)

    merged = pd.concat(frames, ignore_index=True)
    print(f"\nTotal merged rows: {len(merged):,}")
    print(f"Total columns: {merged.shape[1]}")
    return merged


def report_label_distribution(df):
    if "Label" not in df.columns:
        print("\n[WARN] No 'Label' column found. Columns are:")
        print(list(df.columns))
        return

    print("\n--- Multi-class label distribution (Label column) ---")
    counts = df["Label"].value_counts()
    pct = (counts / len(df) * 100).round(3)
    summary = pd.DataFrame({"count": counts, "pct": pct})
    print(summary.to_string())

    print("\n--- Binary distribution (BENIGN vs ATTACK) ---")
    binary = df["Label"].apply(lambda x: "BENIGN" if x.strip() == "BENIGN" else "ATTACK")
    bcounts = binary.value_counts()
    bpct = (bcounts / len(df) * 100).round(3)
    bsummary = pd.DataFrame({"count": bcounts, "pct": bpct})
    print(bsummary.to_string())

    return summary, bsummary


def report_data_quality(df):
    print("\n--- Data quality checks ---")

    numeric_df = df.select_dtypes(include=[np.number])

    # Infinite values
    inf_counts = np.isinf(numeric_df).sum()
    inf_cols = inf_counts[inf_counts > 0]
    if len(inf_cols) > 0:
        print("\nColumns containing Infinity values:")
        print(inf_cols.to_string())
    else:
        print("\nNo Infinity values found.")

    # NaN values
    nan_counts = df.isna().sum()
    nan_cols = nan_counts[nan_counts > 0]
    if len(nan_cols) > 0:
        print("\nColumns containing NaN values:")
        print(nan_cols.to_string())
    else:
        print("\nNo NaN values found.")

    # Negative values in columns that should logically be >= 0
    # (quick sanity check - not exhaustive)
    suspicious_negative = {}
    for col in numeric_df.columns:
        if numeric_df[col].min() < 0:
            suspicious_negative[col] = numeric_df[col].min()
    if suspicious_negative:
        print("\nColumns with negative values (may be legitimate, e.g. some flag/diff features):")
        for col, val in suspicious_negative.items():
            print(f"  {col}: min = {val}")

    # Memory usage
    mem_mb = df.memory_usage(deep=True).sum() / (1024 ** 2)
    print(f"\nApprox memory usage: {mem_mb:.1f} MB")


def main():
    df = load_all_csvs(DATA_DIR)

    report_label_distribution(df)
    report_data_quality(df)

    # Save a sample for quick inspection, and the full merged file for next steps
    sample_path = os.path.join(OUTPUT_DIR, "sample_1000rows.csv")
    df.sample(min(1000, len(df)), random_state=42).to_csv(sample_path, index=False)
    print(f"\nSaved a 1000-row sample to: {sample_path}")

    merged_path = os.path.join(OUTPUT_DIR, "merged_raw.parquet")
    df.to_parquet(merged_path, index=False)
    print(f"Saved full merged dataset (parquet) to: {merged_path}")
    print("\nDone. Review the label distribution above before deciding on")
    print("binary-first vs multi-class-first training strategy.")


if __name__ == "__main__":
    main()
