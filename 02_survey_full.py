"""
02_survey_full.py

Run this on the full merged_raw.parquet produced by 01_survey_dataset.py.
Reports:
  - exact label distribution (binary + multi-class)
  - Infinity / NaN counts per column
  - basic stats on Flow Bytes/s and Flow Packets/s (the usual culprits)

Usage:
    python 02_survey_full.py
"""

import numpy as np
import pandas as pd

PARQUET_PATH = "./processed/merged_raw.parquet"


def main():
    df = pd.read_parquet(PARQUET_PATH)
    print(f"Loaded {len(df):,} rows, {df.shape[1]} columns\n")

    # Clean label column (strip whitespace)
    df["Label"] = df["Label"].astype(str).str.strip()

    print("--- Multi-class label distribution ---")
    counts = df["Label"].value_counts()
    pct = (counts / len(df) * 100).round(4)
    print(pd.DataFrame({"count": counts, "pct": pct}).to_string())

    print("\n--- Binary distribution ---")
    binary = df["Label"].apply(lambda x: "BENIGN" if x == "BENIGN" else "ATTACK")
    bcounts = binary.value_counts()
    print(pd.DataFrame({
        "count": bcounts,
        "pct": (bcounts / len(df) * 100).round(3)
    }).to_string())

    print("\n--- Infinity / NaN check ---")
    numeric_df = df.select_dtypes(include=[np.number])
    inf_counts = np.isinf(numeric_df).sum()
    inf_cols = inf_counts[inf_counts > 0]
    print("Columns with Infinity values:")
    print(inf_cols.to_string() if len(inf_cols) else "  (none)")

    nan_counts = df.isna().sum()
    nan_cols = nan_counts[nan_counts > 0]
    print("\nColumns with NaN values:")
    print(nan_cols.to_string() if len(nan_cols) else "  (none)")

    # Drill into the usual suspects
    for col in ("Flow Bytes/s", "Flow Packets/s"):
        if col in df.columns:
            s = df[col]
            n_inf = np.isinf(s).sum()
            n_nan = s.isna().sum()
            print(f"\n{col}: {n_inf:,} inf, {n_nan:,} nan, "
                  f"min={s[~np.isinf(s)].min()}, max={s[~np.isinf(s)].max()}")

    # Duplicate rows (CIC-IDS2017 has a known duplicate-row issue)
    n_dupes = df.drop(columns=["__source_file"]).duplicated().sum()
    print(f"\nDuplicate rows (excluding __source_file): {n_dupes:,} "
          f"({n_dupes/len(df)*100:.2f}%)")


if __name__ == "__main__":
    main()
