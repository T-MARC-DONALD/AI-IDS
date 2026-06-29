"""
04_train_models.py

Trains two RandomForest models on the cleaned CIC-IDS2017 splits:
  1. Binary model: BENIGN vs ATTACK
  2. Multiclass model: attack type classification (ATTACK rows only)

For each model, reports:
  - accuracy (for context only)
  - precision / recall / F1 per class
  - confusion matrix
  - feature importances (top 15)

Saves artifacts to ./models/:
  - binary_model.joblib
  - binary_scaler.joblib
  - multiclass_model.joblib
  - multiclass_scaler.joblib
  - multiclass_label_encoder.joblib
  - feature_columns.joblib (shared - same 78 features for both)

Usage:
    python 04_train_models.py
"""

import os
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)

PROCESSED_DIR = "./processed"
MODELS_DIR = "./models"

os.makedirs(MODELS_DIR, exist_ok=True)


def load_split(name):
    train = pd.read_parquet(os.path.join(PROCESSED_DIR, f"train_{name}.parquet"))
    test = pd.read_parquet(os.path.join(PROCESSED_DIR, f"test_{name}.parquet"))
    return train, test


def get_feature_columns(df, label_cols):
    """Return numeric feature columns, excluding label columns."""
    cols = [c for c in df.columns if c not in label_cols]
    # Keep only numeric columns - drop any stray non-numeric (e.g. IPs if present)
    numeric_cols = df[cols].select_dtypes(include=[np.number]).columns.tolist()
    return numeric_cols


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def train_binary():
    print_section("BINARY MODEL: BENIGN vs ATTACK")

    train, test = load_split("binary")
    feature_cols = get_feature_columns(train, ["Label_binary"])
    print(f"Using {len(feature_cols)} feature columns")

    X_train, y_train = train[feature_cols], train["Label_binary"]
    X_test, y_test = test[feature_cols], test["Label_binary"]

    print(f"Train: {len(X_train):,} rows | Test: {len(X_test):,} rows")
    print("Train label distribution:")
    print(y_train.value_counts())

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train
    print("\nTraining RandomForest...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )
    clf.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_scaled)

    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}  "
          "(context only - see precision/recall/F1 below for real picture)")
    print("\nClassification report:")
    print(classification_report(y_test, y_pred))

    print("Confusion matrix (rows=true, cols=predicted):")
    labels = sorted(y_test.unique())
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    cm_df = pd.DataFrame(cm, index=labels, columns=labels)
    print(cm_df.to_string())

    # Feature importances
    importances = pd.Series(clf.feature_importances_, index=feature_cols)
    print("\nTop 15 feature importances:")
    print(importances.sort_values(ascending=False).head(15).to_string())

    # Save artifacts
    joblib.dump(clf, os.path.join(MODELS_DIR, "binary_model.joblib"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "binary_scaler.joblib"))
    joblib.dump(feature_cols, os.path.join(MODELS_DIR, "feature_columns.joblib"))
    print(f"\nSaved binary_model.joblib, binary_scaler.joblib, feature_columns.joblib")

    return feature_cols


def train_multiclass(feature_cols):
    print_section("MULTICLASS MODEL: Attack Type Classification")

    train, test = load_split("multiclass")

    # Sanity: ensure same feature columns exist
    missing = [c for c in feature_cols if c not in train.columns]
    if missing:
        raise ValueError(f"Feature columns missing from multiclass data: {missing}")

    X_train, y_train_raw = train[feature_cols], train["Label"]
    X_test, y_test_raw = test[feature_cols], test["Label"]

    print(f"Train: {len(X_train):,} rows | Test: {len(X_test):,} rows")
    print("Train label distribution:")
    print(y_train_raw.value_counts())
    print("\nTest label distribution:")
    print(y_test_raw.value_counts())

    # Encode labels
    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(y_train_raw)
    y_test = label_encoder.transform(y_test_raw)

    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train
    print("\nTraining RandomForest (multiclass)...")
    clf = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
        verbose=0,
    )
    clf.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_scaled)

    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}  "
          "(meaningless alone given class imbalance - see report below)")

    print("\nClassification report:")
    target_names = label_encoder.classes_
    print(classification_report(
        y_test, y_pred,
        labels=range(len(target_names)),
        target_names=target_names,
        zero_division=0,
    ))

    print("Confusion matrix (rows=true, cols=predicted):")
    cm = confusion_matrix(y_test, y_pred, labels=range(len(target_names)))
    cm_df = pd.DataFrame(cm, index=target_names, columns=target_names)
    print(cm_df.to_string())

    # Feature importances
    importances = pd.Series(clf.feature_importances_, index=feature_cols)
    print("\nTop 15 feature importances:")
    print(importances.sort_values(ascending=False).head(15).to_string())

    # Save artifacts
    joblib.dump(clf, os.path.join(MODELS_DIR, "multiclass_model.joblib"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "multiclass_scaler.joblib"))
    joblib.dump(label_encoder, os.path.join(MODELS_DIR, "multiclass_label_encoder.joblib"))
    print("\nSaved multiclass_model.joblib, multiclass_scaler.joblib, "
          "multiclass_label_encoder.joblib")


def main():
    feature_cols = train_binary()
    train_multiclass(feature_cols)

    print_section("DONE")
    print("All artifacts saved to ./models/")
    print("\nReminders for your report:")
    print("- Heartbleed/Infiltration/SQL Injection have NO test examples")
    print("  (too few samples to stratify) - they trained but can't be")
    print("  evaluated. Mention this explicitly.")
    print("- Report precision/recall/F1 per class, not just accuracy.")
    print("- The binary model is your primary detection layer; the")
    print("  multiclass model adds attack-type labeling on top.")


if __name__ == "__main__":
    main()
