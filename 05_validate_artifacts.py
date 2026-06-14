"""
05_validate_artifacts.py

Sanity check: loads the saved .joblib artifacts and runs predictions
on a few rows from the test sets to confirm everything loads correctly
and the binary -> multiclass pipeline works end-to-end as it would
in live_ids.py.

Simulates the real inference flow:
  1. Take a raw feature vector (as if computed by the flow assembler)
  2. Scale it with binary_scaler
  3. Predict BENIGN/ATTACK with binary_model
  4. If ATTACK: scale with multiclass_scaler, predict attack type

Usage:
    python 05_validate_artifacts.py
"""

import os
import numpy as np
import pandas as pd
import joblib

PROCESSED_DIR = "./processed"
MODELS_DIR = "./models"

N_SAMPLES = 20  # how many test rows to run through the pipeline


def load_artifacts():
    artifacts = {}
    for name in [
        "binary_model", "binary_scaler",
        "multiclass_model", "multiclass_scaler", "multiclass_label_encoder",
        "feature_columns",
    ]:
        path = os.path.join(MODELS_DIR, f"{name}.joblib")
        artifacts[name] = joblib.load(path)
        print(f"Loaded {name}.joblib")

    # IMPORTANT: force single-threaded prediction.
    # n_jobs=-1 (set at training time) spawns a multiprocessing pool on
    # EVERY .predict() call. For single-row live inference this overhead
    # (~70ms) dwarfs the actual computation (<1ms). Force n_jobs=1 for
    # low-latency single-row predictions.
    artifacts["binary_model"].n_jobs = 1
    artifacts["multiclass_model"].n_jobs = 1

    return artifacts


def predict_one(features_row, artifacts):
    """
    features_row: pandas Series with the 78 feature columns, in any order
    (will be reindexed to feature_columns order).

    Returns: (binary_label, attack_type_or_None)
    """
    feature_cols = artifacts["feature_columns"]

    # Keep as a DataFrame (not .values) so scalers see the same feature
    # names they were fitted with - avoids the
    # "X does not have valid feature names" warning and protects against
    # silent column-order mismatches.
    x = features_row.reindex(feature_cols).to_frame().T

    # Stage 1: binary
    x_scaled = artifacts["binary_scaler"].transform(x)
    binary_pred = artifacts["binary_model"].predict(x_scaled)[0]

    if binary_pred == "BENIGN":
        return binary_pred, None

    # Stage 2: multiclass (only if ATTACK)
    x_scaled_mc = artifacts["multiclass_scaler"].transform(x)
    mc_pred_encoded = artifacts["multiclass_model"].predict(x_scaled_mc)[0]
    attack_type = artifacts["multiclass_label_encoder"].inverse_transform([mc_pred_encoded])[0]

    return binary_pred, attack_type


def main():
    print("Loading artifacts...")
    artifacts = load_artifacts()

    print(f"\nExpected feature columns ({len(artifacts['feature_columns'])}):")
    print(artifacts["feature_columns"])

    print("\n--- Test 1: Mixed samples from binary test set ---")
    test_binary = pd.read_parquet(os.path.join(PROCESSED_DIR, "test_binary.parquet"))
    sample = test_binary.sample(N_SAMPLES, random_state=123)

    correct = 0
    for idx, row in sample.iterrows():
        true_label = row["Label_binary"]
        features = row.drop("Label_binary")
        pred_binary, pred_attack_type = predict_one(features, artifacts)

        match = "OK" if pred_binary == true_label else "MISMATCH"
        if pred_binary == true_label:
            correct += 1

        extra = f" -> attack_type={pred_attack_type}" if pred_attack_type else ""
        print(f"[{match}] true={true_label:8s} pred={pred_binary:8s}{extra}")

    print(f"\nBinary-stage accuracy on this sample: {correct}/{N_SAMPLES}")

    print("\n--- Test 2: Attack samples from multiclass test set "
          "(checking full pipeline incl. attack-type) ---")
    test_multi = pd.read_parquet(os.path.join(PROCESSED_DIR, "test_multiclass.parquet"))
    sample_mc = test_multi.sample(min(N_SAMPLES, len(test_multi)), random_state=456)

    correct_binary = 0
    correct_type = 0
    for idx, row in sample_mc.iterrows():
        true_type = row["Label"]
        features = row.drop("Label")
        pred_binary, pred_attack_type = predict_one(features, artifacts)

        binary_ok = (pred_binary == "ATTACK")
        type_ok = (pred_attack_type == true_type)
        correct_binary += int(binary_ok)
        correct_type += int(type_ok)

        flag = "OK" if (binary_ok and type_ok) else "CHECK"
        print(f"[{flag}] true_type={true_type:28s} "
              f"pred_binary={pred_binary:8s} pred_type={pred_attack_type}")

    print(f"\nBinary-stage caught attack: {correct_binary}/{len(sample_mc)}")
    print(f"Attack-type exact match:     {correct_type}/{len(sample_mc)}")

    print("\n--- Test 3: Single-row inference timing "
          "(relevant for live performance) ---")
    import time
    row = sample.iloc[0].drop("Label_binary")
    n_runs = 100
    start = time.perf_counter()
    for _ in range(n_runs):
        predict_one(row, artifacts)
    elapsed = time.perf_counter() - start
    print(f"Avg time per prediction: {elapsed/n_runs*1000:.3f} ms "
          f"({n_runs} runs)")

    print("\nDone. If both stages produced sensible predictions above,")
    print("artifacts are ready for integration into the flow-based live_ids.py.")


if __name__ == "__main__":
    main()
