import argparse
import json
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from flow_features import CICIDS_REQUIRED_COLUMNS, extract_from_cicids_dataframe, normalize_label


warnings.filterwarnings("ignore", category=UserWarning)


def load_cicids_features(csv_path, max_rows):
    df = pd.read_csv(csv_path, encoding="cp1252", low_memory=False, nrows=max_rows)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=CICIDS_REQUIRED_COLUMNS, inplace=True)

    features = extract_from_cicids_dataframe(df)
    return features, df["Label"].map(normalize_label)


def load_model(path):
    start = time.perf_counter()
    model = joblib.load(path)
    if hasattr(model, "n_jobs"):
        model.n_jobs = 1
    return model, time.perf_counter() - start


def evaluate_classifier(model, data_dir, max_rows):
    y_true_all = []
    y_pred_all = []
    file_results = []

    for csv_path in sorted(data_dir.glob("*.csv")):
        features, labels = load_cicids_features(csv_path, max_rows)
        if features.empty:
            continue

        start = time.perf_counter()
        predictions = model.predict(features)
        elapsed = time.perf_counter() - start

        y_true_all.extend(labels.tolist())
        y_pred_all.extend(map(str, predictions.tolist()))

        file_results.append(
            {
                "file": csv_path.name,
                "rows": int(len(features)),
                "true_labels": sorted(labels.unique().tolist()),
                "predicted_labels": sorted(set(map(str, predictions.tolist()))),
                "accuracy": round(float(accuracy_score(labels, predictions)), 4),
                "rows_per_second": round(len(features) / max(elapsed, 1e-9), 1),
            }
        )

    labels_seen = sorted(set(y_true_all) | set(y_pred_all))
    return {
        "overall_accuracy": round(float(accuracy_score(y_true_all, y_pred_all)), 4),
        "classification_report": classification_report(
            y_true_all,
            y_pred_all,
            labels=labels_seen,
            zero_division=0,
            output_dict=True,
        ),
        "confusion_matrix": {
            "labels": labels_seen,
            "matrix": confusion_matrix(y_true_all, y_pred_all, labels=labels_seen).tolist(),
        },
        "files": file_results,
    }


def evaluate_anomaly_detector(model, data_dir, max_rows):
    file_results = []
    totals = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}

    for csv_path in sorted(data_dir.glob("*.csv")):
        features, labels = load_cicids_features(csv_path, max_rows)
        if features.empty:
            continue

        start = time.perf_counter()
        raw_predictions = model.predict(features)
        elapsed = time.perf_counter() - start

        predicted_anomaly = raw_predictions == -1
        actual_anomaly = labels != "BENIGN"

        tp = int((predicted_anomaly & actual_anomaly).sum())
        fp = int((predicted_anomaly & ~actual_anomaly).sum())
        tn = int((~predicted_anomaly & ~actual_anomaly).sum())
        fn = int((~predicted_anomaly & actual_anomaly).sum())

        for key, value in {"tp": tp, "fp": fp, "tn": tn, "fn": fn}.items():
            totals[key] += value

        total = tp + fp + tn + fn
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-9)

        file_results.append(
            {
                "file": csv_path.name,
                "rows": int(total),
                "actual_anomaly_rate": round(float(actual_anomaly.mean()), 4),
                "predicted_anomaly_rate": round(float(predicted_anomaly.mean()), 4),
                "precision": round(float(precision), 4),
                "recall": round(float(recall), 4),
                "f1": round(float(f1), 4),
                "accuracy": round(float((tp + tn) / max(total, 1)), 4),
                "rows_per_second": round(len(features) / max(elapsed, 1e-9), 1),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
            }
        )

    tp, fp, tn, fn = totals["tp"], totals["fp"], totals["tn"], totals["fn"]
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    total = tp + fp + tn + fn

    return {
        "overall": {
            "accuracy": round(float((tp + tn) / max(total, 1)), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        },
        "files": file_results,
    }


def print_summary(results):
    classifier = results["classifier"]
    anomaly = results["anomaly_detector"]
    traffic_model_name = next(
        name for name in results["model_load_seconds"] if name != "anomaly_model.pkl"
    )

    print("\nAI DPI SYSTEM - PERFORMANCE EVALUATION")
    print("=" * 44)
    print(f"Rows sampled per CICIDS file: {results['rows_sampled_per_file']}")
    print(f"Traffic model: {traffic_model_name}")
    print(f"Traffic model load time: {results['model_load_seconds'][traffic_model_name]:.3f}s")
    print(f"Anomaly model load time: {results['model_load_seconds']['anomaly_model.pkl']:.3f}s")

    print("\nTraffic Classifier")
    print("-" * 44)
    print(f"Overall accuracy: {classifier['overall_accuracy']:.4f}")
    print("Classes predicted by current model:")
    predicted = sorted({label for row in classifier["files"] for label in row["predicted_labels"]})
    print(", ".join(predicted))

    print("\nPer-file classifier accuracy:")
    for row in classifier["files"]:
        print(f"- {row['file']}: {row['accuracy']:.4f} at {row['rows_per_second']} rows/sec")

    print("\nAnomaly Detector")
    print("-" * 44)
    overall = anomaly["overall"]
    print(f"Accuracy:  {overall['accuracy']:.4f}")
    print(f"Precision: {overall['precision']:.4f}")
    print(f"Recall:    {overall['recall']:.4f}")
    print(f"F1-score:  {overall['f1']:.4f}")
    print(f"TP={overall['tp']} FP={overall['fp']} TN={overall['tn']} FN={overall['fn']}")

    print("\nResult written to evaluation_results.json")


def main():
    parser = argparse.ArgumentParser(description="Evaluate the AI DPI models on CICIDS2017 samples.")
    parser.add_argument("--data-dir", default="data/MachineLearningCVE")
    parser.add_argument("--max-rows", type=int, default=50000)
    parser.add_argument("--traffic-model", default=None)
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    traffic_model_path = args.traffic_model
    if traffic_model_path is None:
        traffic_model_path = "traffic_model_multiclass.pkl"
        if not Path(traffic_model_path).exists():
            traffic_model_path = "traffic_model.pkl"

    traffic_model, traffic_load_time = load_model(traffic_model_path)
    anomaly_model, anomaly_load_time = load_model("anomaly_model.pkl")

    results = {
        "rows_sampled_per_file": args.max_rows,
        "model_load_seconds": {
            traffic_model_path: round(traffic_load_time, 4),
            "anomaly_model.pkl": round(anomaly_load_time, 4),
        },
        "classifier": evaluate_classifier(traffic_model, data_dir, args.max_rows),
        "anomaly_detector": evaluate_anomaly_detector(anomaly_model, data_dir, args.max_rows),
    }

    Path("evaluation_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print_summary(results)


if __name__ == "__main__":
    main()
