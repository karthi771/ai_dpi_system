from scapy.layers.inet import IP, TCP, UDP


class PacketParser:
    def parse(self, packet):
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        src_port = None
        dst_port = None

        payload_data = ""
        if packet.haslayer("Raw"):
            payload_data = packet["Raw"].load.decode("utf-8", errors="ignore")

        timestamp = float(packet.time) if hasattr(packet, "time") else 0.0
        # CICFlowMeter uses IP-layer total length, not full Ethernet frame size.
        packet_length = int(packet[IP].len)
        flags = ""
        syn_flag = 0
        ack_flag = 0
        fin_flag = 0

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = packet[TCP].flags
            flags = str(tcp_flags)
            syn_flag = int(bool(tcp_flags.S))
            ack_flag = int(bool(tcp_flags.A))
            fin_flag = int(bool(tcp_flags.F))
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "syn_flag": syn_flag,
            "ack_flag": ack_flag,
            "fin_flag": fin_flag,
            "packet_length": packet_length,
            "payload": payload_data,
        }
