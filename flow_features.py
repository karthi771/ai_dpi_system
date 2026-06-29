"""Shared flow feature definitions aligned with CICIDS2017 / CICFlowMeter."""

from __future__ import annotations

import numpy as np
import pandas as pd

# CICIDS stores flow duration in microseconds; inference uses seconds.
MIN_FLOW_DURATION_SECONDS = 1e-6

FEATURE_COLUMNS = [
    "packet_count",
    "avg_packet_size",
    "max_packet_size",
    "min_packet_size",
    "std_packet_size",
    "flow_duration",
    "bytes_per_second",
    "syn_count",
    "ack_count",
    "fin_count",
]

CICIDS_REQUIRED_COLUMNS = [
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Packet Length Mean",
    "Max Packet Length",
    "Min Packet Length",
    "Packet Length Std",
    "Flow Duration",
    "Flow Bytes/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "FIN Flag Count",
    "Label",
]


def normalize_label(label) -> str:
    label = str(label).strip()
    label = label.replace("ï¿½", "-").replace("�", "-")
    return " ".join(label.split())


def compute_bytes_per_second(total_bytes: float, flow_duration_seconds: float) -> float:
    """Match CICFlowMeter: total bytes / duration, with a 1 microsecond floor."""
    duration = max(float(flow_duration_seconds), MIN_FLOW_DURATION_SECONDS)
    return float(total_bytes) / duration


def determine_forward_direction(packets: list[dict]) -> tuple[str | None, str | None]:
    """CICFlowMeter forward direction follows the first packet in time order."""
    if not packets:
        return None, None

    ordered = sorted(packets, key=lambda packet: packet.get("timestamp", 0.0))
    first = ordered[0]
    return first.get("src_ip"), first.get("dst_ip")


def split_forward_backward(
    packets: list[dict],
    forward_src: str | None,
    forward_dst: str | None,
) -> tuple[list[dict], list[dict]]:
    if not forward_src or not forward_dst:
        return packets, []

    forward_packets = [
        packet
        for packet in packets
        if packet.get("src_ip") == forward_src and packet.get("dst_ip") == forward_dst
    ]
    backward_packets = [
        packet
        for packet in packets
        if packet.get("src_ip") == forward_dst and packet.get("dst_ip") == forward_src
    ]
    return forward_packets, backward_packets


def _packet_length(packet: dict) -> int:
    return int(packet.get("packet_length", 0))


def extract_from_packets(packets: list[dict]) -> dict:
    """Extract CICIDS-aligned features from parsed PCAP packet dictionaries."""
    if not packets:
        return {column: 0 for column in FEATURE_COLUMNS}

    ordered = sorted(packets, key=lambda packet: packet.get("timestamp", 0.0))
    packet_sizes = [_packet_length(packet) for packet in ordered]
    forward_src, forward_dst = determine_forward_direction(ordered)
    forward_packets, backward_packets = split_forward_backward(
        ordered,
        forward_src,
        forward_dst,
    )

    forward_bytes = sum(_packet_length(packet) for packet in forward_packets)
    backward_bytes = sum(_packet_length(packet) for packet in backward_packets)
    total_bytes = forward_bytes + backward_bytes

    timestamps = [packet.get("timestamp", 0.0) for packet in ordered]
    flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0.0

    size_array = np.asarray(packet_sizes, dtype=float)
    features = {
        "packet_count": len(packet_sizes),
        "avg_packet_size": float(np.mean(size_array)) if packet_sizes else 0.0,
        "max_packet_size": int(np.max(size_array)) if packet_sizes else 0,
        "min_packet_size": int(np.min(size_array)) if packet_sizes else 0,
        # CICFlowMeter uses population standard deviation (ddof=0).
        "std_packet_size": float(np.std(size_array, ddof=0)) if packet_sizes else 0.0,
        "flow_duration": float(flow_duration),
        "bytes_per_second": compute_bytes_per_second(total_bytes, flow_duration),
        "syn_count": sum(int(packet.get("syn_flag", 0)) for packet in ordered),
        "ack_count": sum(int(packet.get("ack_flag", 0)) for packet in ordered),
        "fin_count": sum(int(packet.get("fin_flag", 0)) for packet in ordered),
        "forward_packet_count": len(forward_packets),
        "backward_packet_count": len(backward_packets),
        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,
    }
    return features


def extract_from_cicids_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Map CICIDS CSV columns to the same feature schema used at inference time."""
    features = pd.DataFrame()
    features["packet_count"] = df["Total Fwd Packets"] + df["Total Backward Packets"]
    features["avg_packet_size"] = df["Packet Length Mean"]
    features["max_packet_size"] = df["Max Packet Length"]
    features["min_packet_size"] = df["Min Packet Length"]
    features["std_packet_size"] = df["Packet Length Std"]
    features["flow_duration"] = df["Flow Duration"] / 1e6
    features["bytes_per_second"] = df["Flow Bytes/s"]
    features["syn_count"] = df["SYN Flag Count"]
    features["ack_count"] = df["ACK Flag Count"]
    features["fin_count"] = df["FIN Flag Count"]
    return features[FEATURE_COLUMNS]


def recompute_bytes_per_second_from_cicids(df: pd.DataFrame) -> pd.Series:
    """Recompute Flow Bytes/s from length and duration columns for validation."""
    total_bytes = df["Total Length of Fwd Packets"] + df["Total Length of Bwd Packets"]
    duration_seconds = df["Flow Duration"] / 1e6
    duration_seconds = duration_seconds.clip(lower=MIN_FLOW_DURATION_SECONDS)
    return total_bytes / duration_seconds


def features_to_model_frame(features: dict) -> pd.DataFrame:
    return pd.DataFrame([{column: features[column] for column in FEATURE_COLUMNS}])
