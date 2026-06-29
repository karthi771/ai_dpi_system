import argparse
import json
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from flow_features import (
    CICIDS_REQUIRED_COLUMNS,
    FEATURE_COLUMNS,
    extract_from_cicids_dataframe,
    normalize_label,
)


warnings.filterwarnings("ignore", category=UserWarning)


def load_features_from_csv(csv_path, max_rows):
    print(f"Loading {csv_path.name}...")
    df = pd.read_csv(csv_path, encoding="cp1252", low_memory=False, nrows=max_rows)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=CICIDS_REQUIRED_COLUMNS, inplace=True)

    features = extract_from_cicids_dataframe(df)
    labels = df["Label"].map(normalize_label)
    return features, labels


def build_dataset(data_dir, max_rows_per_file):
    feature_frames = []
    label_frames = []

    for csv_path in sorted(data_dir.glob("*.csv")):
        features, labels = load_features_from_csv(csv_path, max_rows_per_file)
        if features.empty:
            continue
        feature_frames.append(features)
        label_frames.append(labels)

    if not feature_frames:
        raise RuntimeError(f"No CICIDS CSV files found in {data_dir}")

    X = pd.concat(feature_frames, ignore_index=True)
    y = pd.concat(label_frames, ignore_index=True)
    return X, y


def balance_dataset(X, y, max_per_class):
    if not max_per_class:
        return X, y

    sampled_indexes = []
    for label in sorted(y.unique()):
        label_indexes = y[y == label].index
        sample_size = min(len(label_indexes), max_per_class)
        sampled_indexes.extend(
            pd.Series(label_indexes).sample(n=sample_size, random_state=42).tolist()
        )

    sampled_indexes = pd.Series(sampled_indexes).sample(frac=1, random_state=42).tolist()
    return X.loc[sampled_indexes].reset_index(drop=True), y.loc[sampled_indexes].reset_index(drop=True)


def oversample_training_data(X_train, y_train, min_train_per_class):
    if not min_train_per_class:
        return X_train, y_train

    train_df = X_train.copy()
    train_df["label"] = y_train.values
    sampled_frames = []

    for label, group in train_df.groupby("label"):
        if len(group) < min_train_per_class:
            group = group.sample(
                n=min_train_per_class,
                replace=True,
                random_state=42,
            )
        sampled_frames.append(group)

    oversampled = (
        pd.concat(sampled_frames, ignore_index=True)
        .sample(frac=1, random_state=42)
        .reset_index(drop=True)
    )
    return oversampled[FEATURE_COLUMNS], oversampled["label"]


def train_and_evaluate(X, y, output_model, min_train_per_class):
    stratify = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=stratify,
    )
    original_train_rows = len(X_train)
    X_train, y_train = oversample_training_data(X_train, y_train, min_train_per_class)

    model = RandomForestClassifier(
        n_estimators=250,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )

    print("\nTraining multi-class Random Forest...")
    start = time.perf_counter()
    model.fit(X_train, y_train)
    train_seconds = time.perf_counter() - start

    print("Evaluating model...")
    start = time.perf_counter()
    predictions = model.predict(X_test)
    prediction_seconds = time.perf_counter() - start

    joblib.dump(model, output_model)

    labels = sorted(y.unique().tolist())
    report = {
        "model": str(output_model),
        "rows_total": int(len(X)),
        "rows_train_original": int(original_train_rows),
        "rows_train_effective": int(len(X_train)),
        "rows_test": int(len(X_test)),
        "labels": labels,
        "class_distribution": y.value_counts().sort_index().to_dict(),
        "effective_training_distribution": y_train.value_counts().sort_index().to_dict(),
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "training_seconds": round(float(train_seconds), 3),
        "prediction_rows_per_second": round(len(X_test) / max(prediction_seconds, 1e-9), 1),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=labels,
            zero_division=0,
            output_dict=True,
        ),
        "confusion_matrix": {
            "labels": labels,
            "matrix": confusion_matrix(y_test, predictions, labels=labels).tolist(),
        },
    }
    return report


def print_report(report):
    print("\nMULTI-CLASS CICIDS TRAINING REPORT")
    print("=" * 44)
    print(f"Model saved to: {report['model']}")
    print(f"Total rows: {report['rows_total']}")
    print(f"Train rows before oversampling: {report['rows_train_original']}")
    print(f"Train rows after oversampling: {report['rows_train_effective']}")
    print(f"Test rows: {report['rows_test']}")
    print(f"Classes: {', '.join(report['labels'])}")
    print(f"Accuracy: {report['accuracy']:.4f}")
    print(f"Training time: {report['training_seconds']}s")
    print(f"Prediction speed: {report['prediction_rows_per_second']} rows/sec")

    print("\nPer-class F1-score:")
    for label in report["labels"]:
        score = report["classification_report"][label]["f1-score"]
        support = report["classification_report"][label]["support"]
        print(f"- {label}: F1={score:.4f}, support={int(support)}")

    print("\nDetailed report saved to multiclass_training_report.json")


def main():
    parser = argparse.ArgumentParser(description="Train a multi-class CICIDS2017 traffic classifier.")
    parser.add_argument("--data-dir", default="data/MachineLearningCVE")
    parser.add_argument("--max-rows-per-file", type=int, default=None)
    parser.add_argument("--max-per-class", type=int, default=100000)
    parser.add_argument("--min-train-per-class", type=int, default=0)
    parser.add_argument("--output-model", default="traffic_model_multiclass.pkl")
    parser.add_argument("--replace-current-model", action="store_true")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_model = Path(args.output_model)

    X, y = build_dataset(data_dir, args.max_rows_per_file)
    print("\nOriginal class distribution:")
    print(y.value_counts().sort_index())

    X, y = balance_dataset(X, y, args.max_per_class)
    print("\nTraining class distribution:")
    print(y.value_counts().sort_index())

    final_model = Path("traffic_model.pkl") if args.replace_current_model else output_model
    report = train_and_evaluate(X, y, final_model, args.min_train_per_class)

    Path("multiclass_training_report.json").write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )
    print_report(report)


if __name__ == "__main__":
    main()
