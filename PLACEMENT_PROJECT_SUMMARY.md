# AI-Based Deep Packet Inspection System

## Project Pitch

This project is an ML-assisted network security system that analyzes network traffic using flow-level machine learning, statistical anomaly detection, and signature-based deep packet inspection. It processes live traffic or PCAP files, groups packets into flows, extracts CICIDS-aligned features, classifies traffic into 15 classes, and surfaces suspicious connections through a Streamlit dashboard.

## Problem Statement

Modern networks generate high-volume encrypted and plaintext traffic, making manual inspection difficult. This prototype identifies suspicious traffic patterns using machine learning plus rule-based packet inspection — similar to how real IDS/IPS systems combine behavioral analysis and signatures.

## Architecture

1. Packet input from live capture or PCAP files.
2. Parsing of IPs, ports, protocol, TCP flags, timestamps, and payload.
3. Bidirectional flow grouping.
4. Flow-level feature extraction via shared `flow_features.py` (aligned with CICIDS2017).
5. Random Forest multi-class classification (15 labels).
6. Isolation Forest anomaly detection (secondary signal).
7. Regex DPI for SQL injection, XSS, sensitive paths, and credential patterns.
8. Streamlit dashboard + CLI network graph for visualization.

## Technologies Used

- Python, Scapy, Pandas, NumPy, Scikit-learn, Joblib
- Matplotlib, NetworkX, Streamlit
- CICIDS2017 dataset

## Current Performance

- **Classifier:** ~89.8% accuracy on sampled CICIDS2017 flows; strongest on DDoS, PortScan, DoS slowloris, FTP-Patator.
- **Weak areas:** Bot, SQL Injection, XSS — rare classes with class imbalance.
- **Anomaly detector:** F1 ~0.03 — kept as experimental; supervised classifier is the primary alert source.

## Strengths

- End-to-end working security pipeline.
- Multi-layer detection: ML + anomaly + DPI signatures.
- Recognized cybersecurity dataset (CICIDS2017).
- Streamlit dashboard with PCAP upload and report export.
- Shared feature module ensures training/inference alignment.
- Evaluation reports with per-class metrics and confusion matrix.

## Limitations

- Only 10 flow features used (not full 78 CICIDS features); classifier does not see payload content.
- Anomaly detection is not production-ready.
- DPI regex signatures can false-positive on benign traffic.
- Live capture requires admin privileges and Npcap (Windows).

## Interview Explanation

I built this to understand how ML supports network security monitoring. The system combines flow-level behavior classification with signature-based payload inspection — similar to real intrusion detection systems.

Training and inference use the same feature schema in `flow_features.py`, mapped from CICIDS CSV columns and recomputed from PCAP packets using CICFlowMeter conventions (IP-layer length, microsecond duration, timestamp-based forward direction).

I'm honest about limitations: the model is strongest on volumetric attacks (DDoS, PortScan) and weaker on rare web attacks due to class imbalance. The anomaly detector is a secondary signal, not the primary alert source.

## Demo Flow (2 minutes)

1. `streamlit run streamlit_dashboard.py`
2. Upload a PCAP or use the sample capture.
3. Show flow table, prediction labels, and any DPI alerts.
4. Open **Model Metrics** tab → point to evaluation report and confusion matrix.
5. Mention `validate_feature_alignment.py` if asked about train/inference consistency.

## Resume Bullet

Built an ML-assisted Deep Packet Inspection and intrusion detection prototype using Python, Scapy, Scikit-learn, and CICIDS2017 — combining flow-level Random Forest classification (15 classes), Isolation Forest anomaly detection, regex payload inspection, and a Streamlit PCAP analysis dashboard.
