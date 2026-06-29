"""
03_clean_and_split.py

Cleans the merged CIC-IDS2017 dataset and produces train/test splits
for both binary (BENIGN vs ATTACK) and multi-class (attack type) models.

Steps:
  1. Load merged_raw.parquet
  2. Fix mojibake in Web Attack labels (encoding artifact)
  3. Drop exact duplicate rows (10.89% of data - critical for valid metrics)
  4. Drop rows with Infinity/NaN/negative values in rate columns (~0.15%)
  5. Create Label_binary (BENIGN/ATTACK) and keep Label as multiclass target
  6. Stratified train/test split for binary
  7. For multiclass: handle ultra-rare classes (Heartbleed=11, Infiltration=36,
     Sql Injection=21) by grouping into 'Rare' or using a fixed split since
     standard stratified split fails when a class has < n_splits members

Outputs (in ./processed/):
  - train_binary.parquet / test_binary.parquet
  - train_multiclass.parquet / test_multiclass.parquet  (ATTACK rows only)
  - label_mapping.csv (for reference)

Usage:
    python 03_clean_and_split.py
"""

import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

PARQUET_PATH = "./processed/merged_raw.parquet"
OUTPUT_DIR = "./processed"

# Below this count, a class can't be reliably stratified into train/test.
# We'll still keep these rows but route them via a non-stratified split.
RARE_CLASS_THRESHOLD = 50

# Label fixes: mojibake -> clean label
LABEL_FIXES = {
    "Web Attack ï¿½ Brute Force": "Web Attack - Brute Force",
    "Web Attack ï¿½ XSS": "Web Attack - XSS",
    "Web Attack ï¿½ Sql Injection": "Web Attack - SQL Injection",
}


def fix_labels(df):
    df["Label"] = df["Label"].astype(str).str.strip()
    df["Label"] = df["Label"].replace(LABEL_FIXES)
    return df


def drop_bad_rows(df):
    """Drop rows with inf/nan/negative values in rate columns."""
    rate_cols = ["Flow Bytes/s", "Flow Packets/s"]
    before = len(df)

    mask_bad = pd.Series(False, index=df.index)
    for col in rate_cols:
        if col in df.columns:
            mask_bad |= np.isinf(df[col]) | df[col].isna() | (df[col] < 0)

    df_clean = df[~mask_bad].copy()
    dropped = before - len(df_clean)
    print(f"Dropped {dropped:,} rows with inf/nan/negative rate values "
          f"({dropped/before*100:.3f}%)")
    return df_clean


def dedupe(df):
    before = len(df)
    feature_cols = [c for c in df.columns if c not in ("__source_file",)]
    df_clean = df.drop_duplicates(subset=feature_cols).copy()
    dropped = before - len(df_clean)
    print(f"Dropped {dropped:,} duplicate rows ({dropped/before*100:.2f}%)")
    return df_clean


def main():
    print("Loading merged dataset...")
    df = pd.read_parquet(PARQUET_PATH)
    print(f"Initial: {len(df):,} rows\n")

    df = fix_labels(df)
    df = dedupe(df)
    df = drop_bad_rows(df)

    # Drop helper column, reset index
    df = df.drop(columns=["__source_file"], errors="ignore").reset_index(drop=True)
    print(f"\nFinal cleaned dataset: {len(df):,} rows")

    # --- Binary labels ---
    df["Label_binary"] = np.where(df["Label"] == "BENIGN", "BENIGN", "ATTACK")

    print("\n--- Cleaned binary distribution ---")
    print(df["Label_binary"].value_counts())

    print("\n--- Cleaned multiclass distribution ---")
    print(df["Label"].value_counts())

    # ------------------------------------------------------------------
    # Binary split (stratified - classes are large enough)
    # ------------------------------------------------------------------
    X = df.drop(columns=["Label", "Label_binary"])
    y_bin = df["Label_binary"]

    X_train, X_test, y_bin_train, y_bin_test = train_test_split(
        X, y_bin, test_size=0.2, random_state=42, stratify=y_bin
    )

    train_binary = X_train.copy()
    train_binary["Label_binary"] = y_bin_train
    test_binary = X_test.copy()
    test_binary["Label_binary"] = y_bin_test

    train_binary.to_parquet(os.path.join(OUTPUT_DIR, "train_binary.parquet"))
    test_binary.to_parquet(os.path.join(OUTPUT_DIR, "test_binary.parquet"))
    print(f"\nBinary split: train={len(train_binary):,}, test={len(test_binary):,}")

    # ------------------------------------------------------------------
    # Multiclass split - ATTACK rows only
    # ------------------------------------------------------------------
    attack_df = df[df["Label"] != "BENIGN"].copy()
    label_counts = attack_df["Label"].value_counts()

    rare_classes = label_counts[label_counts < RARE_CLASS_THRESHOLD].index.tolist()
    common_classes = label_counts[label_counts >= RARE_CLASS_THRESHOLD].index.tolist()

    print(f"\nRare classes (<{RARE_CLASS_THRESHOLD} samples, excluded from "
          f"stratified split, added to train only): {rare_classes}")

    common_df = attack_df[attack_df["Label"].isin(common_classes)]
    rare_df = attack_df[attack_df["Label"].isin(rare_classes)]

    X_mc = common_df.drop(columns=["Label", "Label_binary"])
    y_mc = common_df["Label"]

    X_mc_train, X_mc_test, y_mc_train, y_mc_test = train_test_split(
        X_mc, y_mc, test_size=0.2, random_state=42, stratify=y_mc
    )

    train_multi = X_mc_train.copy()
    train_multi["Label"] = y_mc_train

    # Add rare classes entirely to train (too few to test on meaningfully;
    # report this limitation explicitly in your write-up)
    if len(rare_df) > 0:
        rare_X = rare_df.drop(columns=["Label", "Label_binary"])
        rare_y = rare_df["Label"]
        rare_train = rare_X.copy()
        rare_train["Label"] = rare_y
        train_multi = pd.concat([train_multi, rare_train], ignore_index=True)

    test_multi = X_mc_test.copy()
    test_multi["Label"] = y_mc_test

    train_multi.to_parquet(os.path.join(OUTPUT_DIR, "train_multiclass.parquet"))
    test_multi.to_parquet(os.path.join(OUTPUT_DIR, "test_multiclass.parquet"))
    print(f"Multiclass split: train={len(train_multi):,}, test={len(test_multi):,}")

    # ------------------------------------------------------------------
    # Label mapping reference
    # ------------------------------------------------------------------
    mapping = df["Label"].value_counts().reset_index()
    mapping.columns = ["Label", "count"]
    mapping.to_csv(os.path.join(OUTPUT_DIR, "label_mapping.csv"), index=False)

    print("\nDone. Files written to ./processed/")
    print("  train_binary.parquet / test_binary.parquet")
    print("  train_multiclass.parquet / test_multiclass.parquet")
    print("  label_mapping.csv")
    print("\nNOTE: Rare classes (Heartbleed, Infiltration, SQL Injection) are")
    print("present only in train_multiclass - document this limitation in")
    print("your report (no held-out test examples for these classes).")


if __name__ == "__main__":
    main()
