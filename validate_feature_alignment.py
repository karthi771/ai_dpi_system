"""Validate that PCAP feature extraction matches CICIDS/CICFlowMeter conventions."""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from flow_features import (
    CICIDS_REQUIRED_COLUMNS,
    MIN_FLOW_DURATION_SECONDS,
    compute_bytes_per_second,
    extract_from_cicids_dataframe,
    extract_from_packets,
    recompute_bytes_per_second_from_cicids,
)


def validate_cicids_bytes_per_second(df: pd.DataFrame) -> dict:
    recomputed = recompute_bytes_per_second_from_cicids(df)
    csv_values = df["Flow Bytes/s"].replace([np.inf, -np.inf], np.nan)
    recomputed = recomputed.replace([np.inf, -np.inf], np.nan)

    finite_mask = csv_values.notna() & recomputed.notna()
    if not finite_mask.any():
        return {"rows_checked": len(df), "finite_match_rate": 0.0}

    match_rate = float(
        np.isclose(
            recomputed[finite_mask],
            csv_values[finite_mask],
            rtol=1e-4,
            atol=1.0,
        ).mean()
    )
    return {
        "rows_checked": int(len(df)),
        "finite_rows": int(finite_mask.sum()),
        "finite_match_rate": round(match_rate, 4),
    }


def validate_cicids_feature_mapping(df: pd.DataFrame) -> dict:
    mapped = extract_from_cicids_dataframe(df)
    expected_packet_count = df["Total Fwd Packets"] + df["Total Backward Packets"]
    packet_count_match = float((mapped["packet_count"] == expected_packet_count).mean())
    duration_match = float(
        np.isclose(mapped["flow_duration"], df["Flow Duration"] / 1e6, rtol=0, atol=0).mean()
    )
    return {
        "packet_count_match_rate": round(packet_count_match, 4),
        "flow_duration_match_rate": round(duration_match, 4),
    }


def validate_live_extraction_examples() -> list[dict]:
    examples = []

    # Example 1: two forward packets, no backward (mirrors common CICIDS BENIGN rows)
    packets = [
        {
            "timestamp": 1000.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "packet_length": 6,
            "syn_flag": 0,
            "ack_flag": 1,
            "fin_flag": 0,
        },
        {
            "timestamp": 1000.000003,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "packet_length": 6,
            "syn_flag": 0,
            "ack_flag": 1,
            "fin_flag": 0,
        },
    ]
    features = extract_from_packets(packets)
    examples.append(
        {
            "name": "two-packet forward flow",
            "packet_count": features["packet_count"] == 2,
            "duration_seconds": abs(features["flow_duration"] - 3e-6) < 1e-9,
            "bytes_per_second": abs(features["bytes_per_second"] - 4_000_000) < 1.0,
            "forward_packet_count": features["forward_packet_count"] == 2,
        }
    )

    # Example 2: out-of-order arrival should still use earliest packet as forward direction
    out_of_order = [
        {
            "timestamp": 2000.000010,
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.1",
            "packet_length": 60,
            "syn_flag": 0,
            "ack_flag": 1,
            "fin_flag": 0,
        },
        {
            "timestamp": 2000.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "packet_length": 54,
            "syn_flag": 1,
            "ack_flag": 0,
            "fin_flag": 0,
        },
    ]
    ordered_features = extract_from_packets(out_of_order)
    examples.append(
        {
            "name": "forward direction from first timestamp",
            "forward_packet_count": ordered_features["forward_packet_count"] == 1,
            "backward_packet_count": ordered_features["backward_packet_count"] == 1,
            "syn_count": ordered_features["syn_count"] == 1,
            "ack_count": ordered_features["ack_count"] == 1,
        }
    )

    # Example 3: zero-duration flow should use 1 microsecond floor, not 1 millisecond
    single_packet = [
        {
            "timestamp": 3000.0,
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "packet_length": 12,
            "syn_flag": 0,
            "ack_flag": 1,
            "fin_flag": 0,
        }
    ]
    single_features = extract_from_packets(single_packet)
    expected_bps = 12 / MIN_FLOW_DURATION_SECONDS
    examples.append(
        {
            "name": "single-packet zero-duration flow",
            "flow_duration_zero": single_features["flow_duration"] == 0.0,
            "bytes_per_second": abs(single_features["bytes_per_second"] - expected_bps) < 1.0,
            "not_using_old_1ms_floor": single_features["bytes_per_second"] > 100_000,
        }
    )

    return examples


def run_validation(data_dir: Path, max_rows: int) -> dict:
    csv_files = sorted(data_dir.glob("*.csv"))
    csv_path = csv_files[0] if csv_files else None
    if csv_path is None:
        raise FileNotFoundError(f"No CICIDS CSV files found in {data_dir}")

    df = pd.read_csv(csv_path, encoding="cp1252", low_memory=False, nrows=max_rows)
    df.columns = df.columns.str.strip()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=CICIDS_REQUIRED_COLUMNS, inplace=True)

    live_examples = validate_live_extraction_examples()
    return {
        "sample_file": csv_path.name,
        "cicids_bytes_per_second": validate_cicids_bytes_per_second(df),
        "cicids_feature_mapping": validate_cicids_feature_mapping(df),
        "live_extraction_examples": live_examples,
    }


def print_report(report: dict) -> None:
    print("\nFEATURE ALIGNMENT VALIDATION")
    print("=" * 40)
    print(f"Sample CICIDS file: {report['sample_file']}")

    bps = report["cicids_bytes_per_second"]
    print("\nCICIDS bytes/sec formula check")
    print(f"- Rows checked: {bps['rows_checked']}")
    print(f"- Finite rows compared: {bps['finite_rows']}")
    print(f"- Match rate: {bps['finite_match_rate']:.2%}")

    mapping = report["cicids_feature_mapping"]
    print("\nCICIDS feature mapping check")
    print(f"- packet_count match: {mapping['packet_count_match_rate']:.2%}")
    print(f"- flow_duration match: {mapping['flow_duration_match_rate']:.2%}")

    print("\nLive PCAP extraction checks")
    for example in report["live_extraction_examples"]:
        checks = {key: value for key, value in example.items() if key != "name"}
        passed = all(checks.values())
        status = "PASS" if passed else "FAIL"
        print(f"- [{status}] {example['name']}")
        if not passed:
            for check_name, ok in checks.items():
                if not ok:
                    print(f"    x {check_name}")


def main():
    parser = argparse.ArgumentParser(description="Validate CICIDS and PCAP feature alignment.")
    parser.add_argument("--data-dir", default="data/MachineLearningCVE")
    parser.add_argument("--max-rows", type=int, default=10000)
    args = parser.parse_args()

    report = run_validation(Path(args.data_dir), args.max_rows)
    print_report(report)


if __name__ == "__main__":
    main()
