import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np


def load_results(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def get_traffic_model_name(results):
    for name in results["model_load_seconds"]:
        if name != "anomaly_model.pkl":
            return name
    return "traffic_model.pkl"


def create_confusion_matrix_image(results, output_path):
    matrix_data = results["classifier"]["confusion_matrix"]
    labels = matrix_data["labels"]
    matrix = np.array(matrix_data["matrix"])

    fig_width = max(10, len(labels) * 0.75)
    fig_height = max(8, len(labels) * 0.65)
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    image = ax.imshow(matrix, interpolation="nearest", cmap="Blues")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)

    ax.set_title("Traffic Classifier Confusion Matrix")
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("Actual Label")
    ax.set_xticks(np.arange(len(labels)))
    ax.set_yticks(np.arange(len(labels)))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(labels, fontsize=8)

    max_value = matrix.max() if matrix.size else 0
    threshold = max_value / 2 if max_value else 0
    for i in range(matrix.shape[0]):
        for j in range(matrix.shape[1]):
            value = matrix[i, j]
            if value:
                ax.text(
                    j,
                    i,
                    str(value),
                    ha="center",
                    va="center",
                    color="white" if value > threshold else "black",
                    fontsize=7,
                )

    fig.tight_layout()
    fig.savefig(output_path, dpi=180)
    plt.close(fig)


def write_markdown_report(results, output_path, chart_path):
    classifier = results["classifier"]
    anomaly = results["anomaly_detector"]["overall"]
    model_name = get_traffic_model_name(results)
    report = classifier["classification_report"]

    lines = [
        "# AI DPI System Evaluation Report",
        "",
        "## Summary",
        "",
        f"- Traffic model: `{model_name}`",
        f"- Rows sampled per CICIDS file: `{results['rows_sampled_per_file']}`",
        f"- Classifier accuracy: `{classifier['overall_accuracy']:.4f}`",
        f"- Anomaly detector F1-score: `{anomaly['f1']:.4f}`",
        "",
        "## Classifier Per-Class Metrics",
        "",
        "| Class | Precision | Recall | F1-score | Support |",
        "|---|---:|---:|---:|---:|",
    ]

    for label in classifier["confusion_matrix"]["labels"]:
        if label not in report:
            continue
        row = report[label]
        lines.append(
            f"| {label} | {row['precision']:.4f} | {row['recall']:.4f} | "
            f"{row['f1-score']:.4f} | {int(row['support'])} |"
        )

    lines.extend(
        [
            "",
            "## Per-File Accuracy",
            "",
            "| CICIDS File | Rows | Accuracy | Rows/sec | Predicted Labels |",
            "|---|---:|---:|---:|---|",
        ]
    )

    for row in classifier["files"]:
        labels = ", ".join(row["predicted_labels"])
        lines.append(
            f"| {row['file']} | {row['rows']} | {row['accuracy']:.4f} | "
            f"{row['rows_per_second']} | {labels} |"
        )

    lines.extend(
        [
            "",
            "## Confusion Matrix",
            "",
            f"![Confusion Matrix]({chart_path})",
            "",
            "## Interview Note",
            "",
            "The supervised classifier is the primary detection component. The anomaly detector is kept as a secondary signal for unusual traffic patterns, but its current F1-score shows it needs further tuning before being used as the main alert source.",
        ]
    )

    Path(output_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    results = load_results("evaluation_results.json")
    chart_path = "confusion_matrix.png"
    create_confusion_matrix_image(results, chart_path)
    write_markdown_report(results, "EVALUATION_REPORT.md", chart_path)
    print("Created EVALUATION_REPORT.md")
    print("Created confusion_matrix.png")


if __name__ == "__main__":
    main()
