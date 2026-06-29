import tempfile
from collections import Counter
from pathlib import Path

import pandas as pd
import streamlit as st
from scapy.all import rdpcap

from ai_classifier import AIClassifier
from anomaly_detector import AnomalyDetector
from dpi_engine import DPIEngine
from feature_extractor import FeatureExtractor
from flow_tracker import FlowTracker
from packet_parser import PacketParser


st.set_page_config(
    page_title="AI DPI Security Dashboard",
    page_icon="",
    layout="wide",
)


def apply_styles():
    st.markdown(
        """
        <style>
        .block-container {
            padding-top: 1.5rem;
            padding-bottom: 2rem;
            max-width: 1320px;
        }
        .metric-card {
            border: 1px solid #d9dee7;
            border-radius: 8px;
            padding: 14px 16px;
            background: #ffffff;
        }
        .metric-label {
            color: #5b6472;
            font-size: 0.82rem;
            margin-bottom: 0.35rem;
        }
        .metric-value {
            color: #111827;
            font-size: 1.55rem;
            font-weight: 700;
            line-height: 1.2;
        }
        .status-good {
            color: #0f766e;
            font-weight: 700;
        }
        .status-alert {
            color: #b42318;
            font-weight: 700;
        }
        div[data-testid="stDataFrame"] {
            border: 1px solid #d9dee7;
            border-radius: 8px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


@st.cache_resource
def load_components():
    return {
        "parser": PacketParser(),
        "tracker": FlowTracker(),
        "extractor": FeatureExtractor(),
        "classifier": AIClassifier(),
        "detector": AnomalyDetector(),
        "dpi": DPIEngine(),
    }


def metric_card(label, value):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def read_uploaded_or_sample(uploaded_file):
    if uploaded_file is None:
        sample_path = Path("data/sample.pcap")
        if not sample_path.exists():
            return [], "No PCAP selected"
        return rdpcap(str(sample_path)), "data/sample.pcap"

    suffix = Path(uploaded_file.name).suffix or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
        handle.write(uploaded_file.getbuffer())
        temp_path = handle.name
    return rdpcap(temp_path), uploaded_file.name


def analyze_packets(packets):
    components = load_components()
    parser = components["parser"]
    tracker = FlowTracker()
    extractor = components["extractor"]
    classifier = components["classifier"]
    detector = components["detector"]
    dpi = components["dpi"]

    parsed_packets = 0
    dpi_alerts = []
    dpi_alerts_by_flow = {}

    for packet in packets:
        parsed = parser.parse(packet)
        if not parsed:
            continue

        parsed_packets += 1
        tracker.add_packet(parsed)

        dpi_alert = dpi.inspect_payload(parsed["payload"])
        if dpi_alert:
            flow_key = tracker.get_flow_key(parsed)
            dpi_alerts_by_flow.setdefault(flow_key, []).append(dpi_alert)
            dpi_alerts.append(
                {
                    "Source IP": parsed["src_ip"],
                    "Destination IP": parsed["dst_ip"],
                    "Protocol": parsed["protocol"],
                    "Alert": dpi_alert,
                }
            )

    rows = []
    for flow, flow_packets in tracker.flows.items():
        features = extractor.extract(flow_packets)
        features.setdefault("forward_packet_count", features["packet_count"])
        features.setdefault("backward_packet_count", 0)
        features.setdefault("forward_bytes", 0)
        features.setdefault("backward_bytes", 0)
        prediction = classifier.predict(features, flow)
        anomaly = detector.detect(features)
        signature_alerts = sorted(set(dpi_alerts_by_flow.get(flow, [])))
        signature_detection = "; ".join(signature_alerts)
        effective_detection = signature_detection or prediction

        is_malicious = prediction != "BENIGN" or anomaly is not None or bool(signature_alerts)
        if signature_alerts:
            severity = "High"
        elif prediction in {"DDoS", "PortScan", "Heartbleed"}:
            severity = "High"
        elif prediction != "BENIGN":
            severity = "Medium"
        elif anomaly:
            severity = "Low"
        else:
            severity = "None"

        rows.append(
            {
                "Source IP": flow[0],
                "Destination IP": flow[1],
                "Source Port": flow[2],
                "Destination Port": flow[3],
                "Protocol": flow[4],
                "Packets": features["packet_count"],
                "Forward Packets": features["forward_packet_count"],
                "Backward Packets": features["backward_packet_count"],
                "Forward Bytes": features["forward_bytes"],
                "Backward Bytes": features["backward_bytes"],
                "Avg Packet Size": round(features["avg_packet_size"], 2),
                "Bytes/sec": round(features["bytes_per_second"], 2),
                "SYN": features["syn_count"],
                "ACK": features["ack_count"],
                "FIN": features["fin_count"],
                "Prediction": prediction,
                "Signature Detection": signature_detection,
                "Effective Detection": effective_detection,
                "Anomaly": anomaly or "",
                "Severity": severity,
                "Risk": "Alert" if is_malicious else "Normal",
            }
        )

    return {
        "total_packets": len(packets),
        "parsed_packets": parsed_packets,
        "flows": pd.DataFrame(rows),
        "dpi_alerts": pd.DataFrame(dpi_alerts),
    }


def safe_bar_chart(dataframe, column, title):
    if dataframe.empty or column not in dataframe.columns:
        st.info(f"No data available for {title.lower()}.")
        return

    counts = dataframe[column].replace("", "None").value_counts().reset_index()
    counts.columns = [column, "Count"]
    st.bar_chart(counts, x=column, y="Count", use_container_width=True)


def dataframe_to_markdown(dataframe):
    if dataframe.empty:
        return ""

    columns = list(dataframe.columns)
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for _, row in dataframe.iterrows():
        values = [str(row[column]).replace("|", "\\|") for column in columns]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def build_markdown_report(source_name, results, flows, alerts, dpi_alerts):
    prediction_counts = flows["Prediction"].value_counts().to_dict() if not flows.empty else {}
    effective_counts = flows["Effective Detection"].value_counts().to_dict() if not flows.empty else {}
    severity_counts = flows["Severity"].value_counts().to_dict() if not flows.empty else {}
    risk_counts = flows["Risk"].value_counts().to_dict() if not flows.empty else {}
    top_sources = Counter(flows["Source IP"]).most_common(10) if not flows.empty else []

    lines = [
        "# AI DPI Security Analysis Report",
        "",
        "## Capture Summary",
        "",
        f"- Capture: `{source_name}`",
        f"- Total packets: `{results['total_packets']}`",
        f"- Parsed IP packets: `{results['parsed_packets']}`",
        f"- Flows analyzed: `{len(flows)}`",
        f"- Alert flows: `{len(alerts)}`",
        f"- DPI payload alerts: `{len(dpi_alerts)}`",
        "",
        "## Risk Summary",
        "",
    ]

    if risk_counts:
        for risk, count in risk_counts.items():
            lines.append(f"- {risk}: `{count}`")
    else:
        lines.append("- No flow records found.")

    lines.extend(["", "## Predicted Traffic Types", ""])
    if prediction_counts:
        for label, count in prediction_counts.items():
            lines.append(f"- {label}: `{count}`")
    else:
        lines.append("- No predictions available.")

    lines.extend(["", "## Effective Detections", ""])
    if effective_counts:
        for label, count in effective_counts.items():
            lines.append(f"- {label}: `{count}`")
    else:
        lines.append("- No detections available.")

    lines.extend(["", "## Severity Summary", ""])
    if severity_counts:
        for label, count in severity_counts.items():
            lines.append(f"- {label}: `{count}`")
    else:
        lines.append("- No severity values available.")

    lines.extend(["", "## Top Source IPs", ""])
    if top_sources:
        for ip, count in top_sources:
            lines.append(f"- {ip}: `{count}` flows")
    else:
        lines.append("- No source IPs available.")

    lines.extend(["", "## Suspicious Flows", ""])
    if alerts.empty:
        lines.append("No suspicious flows detected.")
    else:
        report_columns = [
            "Source IP",
            "Destination IP",
            "Protocol",
            "Packets",
            "Prediction",
            "Signature Detection",
            "Effective Detection",
            "Anomaly",
            "Severity",
            "Risk",
        ]
        lines.append(dataframe_to_markdown(alerts[report_columns]))

    lines.extend(["", "## DPI Payload Alerts", ""])
    if dpi_alerts.empty:
        lines.append("No signature-based payload alerts found.")
    else:
        lines.append(dataframe_to_markdown(dpi_alerts))

    return "\n".join(lines) + "\n"


def main():
    apply_styles()

    st.title("AI DPI Security Dashboard")
    st.caption("PCAP analysis with multi-class traffic classification, anomaly detection, and payload signatures.")

    with st.sidebar:
        st.header("Analysis")
        uploaded_file = st.file_uploader("Upload PCAP", type=["pcap", "pcapng", "cap"])
        analyze_button = st.button("Analyze Traffic", type="primary", use_container_width=True)
        st.divider()
        st.write("Current model")
        classifier = load_components()["classifier"]
        classes = list(getattr(classifier.model, "classes_", []))
        st.write(f"{len(classes)} classes")
        with st.expander("View classes"):
            st.write(", ".join(map(str, classes)))

    if not analyze_button:
        st.info("Upload a PCAP or use the included sample, then choose Analyze Traffic.")
        return

    try:
        packets, source_name = read_uploaded_or_sample(uploaded_file)
        results = analyze_packets(packets)
    except Exception as exc:
        st.error(f"Could not analyze this capture: {exc}")
        return

    flows = results["flows"]
    alerts = flows[flows["Risk"] == "Alert"] if not flows.empty else flows
    dpi_alerts = results["dpi_alerts"]

    st.subheader(f"Capture: {source_name}")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("Packets", results["total_packets"])
    with c2:
        metric_card("Parsed IP Packets", results["parsed_packets"])
    with c3:
        metric_card("Flows", len(flows))
    with c4:
        metric_card("Alert Flows", len(alerts))

    report_text = build_markdown_report(source_name, results, flows, alerts, dpi_alerts)
    export_col1, export_col2, export_col3 = st.columns([1, 1, 2])
    with export_col1:
        st.download_button(
            "Download Report",
            data=report_text,
            file_name="ai_dpi_security_report.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with export_col2:
        st.download_button(
            "Download Flows CSV",
            data=flows.to_csv(index=False).encode("utf-8"),
            file_name="ai_dpi_flows.csv",
            mime="text/csv",
            use_container_width=True,
            disabled=flows.empty,
        )

    tab_overview, tab_flows, tab_alerts, tab_metrics = st.tabs(
        ["Overview", "Flows", "Alerts", "Model Metrics"]
    )

    with tab_overview:
        left, right = st.columns(2)
        with left:
            st.markdown("#### Predicted Traffic Types")
            safe_bar_chart(flows, "Prediction", "Predicted Traffic Types")
        with right:
            st.markdown("#### Effective Detections")
            safe_bar_chart(flows, "Effective Detection", "Effective Detections")

        left2, right2 = st.columns(2)
        with left2:
            st.markdown("#### Risk Summary")
            safe_bar_chart(flows, "Risk", "Risk Summary")
        with right2:
            st.markdown("#### Severity Summary")
            safe_bar_chart(flows, "Severity", "Severity Summary")

        st.markdown("#### Top Source IPs")
        if flows.empty:
            st.info("No flows found.")
        else:
            top_sources = Counter(flows["Source IP"]).most_common(10)
            top_df = pd.DataFrame(top_sources, columns=["Source IP", "Flows"])
            st.bar_chart(top_df, x="Source IP", y="Flows", use_container_width=True)

    with tab_flows:
        st.markdown("#### Flow-Level Predictions")
        if flows.empty:
            st.info("No flow records were created from this capture.")
        else:
            selected_risk = st.segmented_control(
                "Filter",
                ["All", "Alert", "Normal"],
                default="All",
            )
            visible_flows = flows if selected_risk == "All" else flows[flows["Risk"] == selected_risk]
            st.dataframe(
                visible_flows,
                use_container_width=True,
                hide_index=True,
            )

    with tab_alerts:
        st.markdown("#### Suspicious Flows")
        if alerts.empty:
            st.markdown('<span class="status-good">No suspicious flows detected.</span>', unsafe_allow_html=True)
        else:
            st.dataframe(alerts, use_container_width=True, hide_index=True)

        st.markdown("#### DPI Payload Alerts")
        if dpi_alerts.empty:
            st.info("No signature-based payload alerts found.")
        else:
            st.download_button(
                "Download DPI Alerts CSV",
                data=dpi_alerts.to_csv(index=False).encode("utf-8"),
                file_name="ai_dpi_payload_alerts.csv",
                mime="text/csv",
                use_container_width=True,
            )
            st.dataframe(dpi_alerts, use_container_width=True, hide_index=True)

    with tab_metrics:
        st.markdown("#### Evaluation Report")
        report_path = Path("EVALUATION_REPORT.md")
        chart_path = Path("confusion_matrix.png")

        if report_path.exists():
            st.markdown(report_path.read_text(encoding="utf-8"))
        else:
            st.info("Run the evaluator to create EVALUATION_REPORT.md.")

        if chart_path.exists():
            st.image(str(chart_path), caption="Confusion Matrix", use_container_width=True)


if __name__ == "__main__":
    main()
