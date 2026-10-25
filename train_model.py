"""Train, evaluate, and save PhishGuard's model and held-out metrics.

Input: data/phishing_urls.csv with feature columns from utils/features.py,
plus `url` and `label` where 0=benign and 1=phishing.
Metrics are for this dataset and split, not guaranteed real-world performance.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from utils.features import FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR / "data" / "phishing_urls.csv"
MODEL_PATH = BASE_DIR / "models" / "phishing_model.joblib"
METRICS_PATH = BASE_DIR / "models" / "model_metrics.json"


def main() -> None:
    if not DATA_PATH.exists():
        print(f"ERROR: Dataset not found: {DATA_PATH}")
        print("Place the downloaded CSV at data/phishing_urls.csv")
        sys.exit(1)

    print(f"Loading dataset: {DATA_PATH.relative_to(BASE_DIR)}")
    try:
        data = pd.read_csv(DATA_PATH, low_memory=False)
    except Exception as exc:
        print(f"ERROR: Could not read CSV: {exc}")
        sys.exit(1)

    required = set(FEATURE_NAMES + ["label", "url"])
    missing = sorted(required - set(data.columns))
    if missing:
        print("ERROR: The CSV does not have the expected columns:", ", ".join(missing))
        print("Available columns:", data.columns.tolist())
        sys.exit(1)

    source_rows = len(data)
    data = data.copy()
    data["label"] = pd.to_numeric(data["label"], errors="coerce")
    for column in FEATURE_NAMES:
        data[column] = pd.to_numeric(data[column], errors="coerce")

    data = data.dropna(subset=FEATURE_NAMES + ["label", "url"])
    data = data[data["label"].isin([0, 1])]
    data["label"] = data["label"].astype(int)
    data["url"] = data["url"].astype(str).str.strip()
    data = data[data["url"].ne("")]
    rows_after_cleaning = len(data)
    data = data.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    usable_rows = len(data)
    duplicates_removed = rows_after_cleaning - usable_rows

    if data["label"].nunique() != 2:
        print("ERROR: Both label values 0 (benign) and 1 (phishing) are required.")
        print("Found labels:", sorted(data["label"].unique().tolist()))
        sys.exit(1)
    if usable_rows < 20:
        print(f"ERROR: Only {usable_rows} usable rows found; at least 20 are needed.")
        sys.exit(1)

    X = data[FEATURE_NAMES]
    y = data["label"]
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.20, random_state=42, stratify=y
        )
    except ValueError as exc:
        print(f"ERROR: Could not create a stratified train/test split: {exc}")
        sys.exit(1)

    label_counts = y.value_counts().sort_index()
    print(f"Rows in source CSV: {source_rows:,}")
    print(f"Rows after cleaning: {rows_after_cleaning:,}")
    print(f"Duplicate URLs removed: {duplicates_removed:,}")
    print(f"Usable unique URLs: {usable_rows:,}")
    print("Label counts (0=benign, 1=phishing):")
    print(label_counts.to_string())
    print(f"Training rows: {len(X_train):,}; testing rows: {len(X_test):,}")
    print("Training Random Forest; this may take a little while...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
        min_samples_leaf=1,
    )
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    classes = list(model.classes_)
    phishing_column = classes.index(1)
    phishing_probabilities = model.predict_proba(X_test)[:, phishing_column]

    accuracy = float(accuracy_score(y_test, predictions))
    report = classification_report(
        y_test,
        predictions,
        labels=[0, 1],
        target_names=["benign", "phishing"],
        output_dict=True,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    try:
        roc_auc = float(roc_auc_score(y_test, phishing_probabilities))
    except ValueError:
        roc_auc = None

    print("\n=== Held-out test results ===")
    print(f"Accuracy: {accuracy:.4f}")
    print("\nClassification report:")
    print(classification_report(
        y_test, predictions, labels=[0, 1],
        target_names=["benign", "phishing"], zero_division=0
    ))
    print("Confusion matrix (rows=true [benign, phishing], columns=predicted [benign, phishing]):")
    print(matrix)
    print(f"ROC-AUC: {roc_auc:.4f}" if roc_auc is not None else "ROC-AUC: unavailable for this test split")

    metrics_payload = {
        "evaluated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset_file": "data/phishing_urls.csv",
        "model_name": "Random Forest",
        "label_definition": {"0": "benign", "1": "phishing"},
        "source_rows": int(source_rows),
        "rows_after_cleaning": int(rows_after_cleaning),
        "duplicates_removed": int(duplicates_removed),
        "usable_unique_urls": int(usable_rows),
        "label_counts": {"benign": int(label_counts.get(0, 0)), "phishing": int(label_counts.get(1, 0))},
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "metrics": {
            "accuracy": accuracy,
            "precision_macro": float(report["macro avg"]["precision"]),
            "recall_macro": float(report["macro avg"]["recall"]),
            "f1_macro": float(report["macro avg"]["f1-score"]),
            "benign": {
                "precision": float(report["benign"]["precision"]),
                "recall": float(report["benign"]["recall"]),
                "f1_score": float(report["benign"]["f1-score"]),
                "support": int(report["benign"]["support"]),
            },
            "phishing": {
                "precision": float(report["phishing"]["precision"]),
                "recall": float(report["phishing"]["recall"]),
                "f1_score": float(report["phishing"]["f1-score"]),
                "support": int(report["phishing"]["support"]),
            },
            "roc_auc": roc_auc,
        },
        "confusion_matrix": matrix.astype(int).tolist(),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")
    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Evaluation metrics saved to: {METRICS_PATH}")
    print("Note: these metrics describe this dataset and split; they do not prove reliability on every live URL.")


if __name__ == "__main__":
    main()
