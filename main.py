from packet_reader import PacketReader
from packet_parser import PacketParser
from flow_tracker import FlowTracker
from feature_extractor import FeatureExtractor
from ai_classifier import AIClassifier
from anomaly_detector import AnomalyDetector
from attack_visualizer import AttackVisualizer
from security_dashboard import SecurityDashboard
import time
from dpi_engine import DPIEngine


def main():

    classifier = AIClassifier()
    dpi = DPIEngine()
    
    print("\n===== AI DPI Network Security System =====\n")
    print("Select Input Mode:\n")
    print("1 → Live Network Monitoring")
    print("2 → Analyze PCAP File\n")

    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "2":
        reader = PacketReader("data/sample.pcap", "pcap")
        live_mode = False
    else:
        reader = PacketReader(None, "live")
        live_mode = True

    parser = PacketParser()
    tracker = FlowTracker()
    extractor = FeatureExtractor()
    detector = AnomalyDetector()
    visualizer = AttackVisualizer()
    dashboard = SecurityDashboard()

    print("\nSystem started...\n")

    while True:

        packets = reader.read_packets()

        # Parse packets
        for pkt in packets:
            parsed = parser.parse(pkt)
            if parsed:
                tracker.add_packet(parsed)
                
                # NEW: Deep Packet Inspection
                dpi_alert = dpi.inspect_payload(parsed['payload'])
                if dpi_alert:
                    print(f"🛑 {dpi_alert} from {parsed['src_ip']}")

        # FIX: Only print summaries if actual TCP/UDP flows were successfully parsed
        if not tracker.flows:
            if not live_mode:
                break
            continue

        print("\nFlow Summary\n")
        tracker.summary()

        print("\nFlow Features\n")

        for flow, packets in tracker.flows.items():

            features = extractor.extract(packets)

            label = classifier.predict(features, flow)

            attack = detector.detect(features)

            is_anomaly = attack is not None

            src = flow[0]
            dst = flow[1]

            dashboard.add_flow(src, dst, is_anomaly)

            visualizer.add_connection(src, dst, is_anomaly)

            if attack:
                print("⚠ ALERT:", attack)

            print(flow)
            print(features)
            print("Traffic Type:", label)
            print()

        if packets:
            visualizer.draw()
            tracker.flows.clear()  # <-- FIX: Clears the memory buffer so it doesn't reprint old flows infinitely

        # If using PCAP file, run once only
        if not live_mode:
            break

        print("\nWaiting for next packet batch...\n")
        time.sleep(0.5)

    print("\n[✅ ANALYSIS COMPLETE]")
    dashboard.show()
    import matplotlib.pyplot as plt
    plt.ioff()
    plt.show()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[User aborted capture via Ctrl+C. Shutting down gracefully...]")