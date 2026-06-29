from collections import Counter


class SecurityDashboard:

    def __init__(self):
        self.src_counter = Counter()
        self.dst_counter = Counter()
        self.suspicious_ips = Counter()

    def add_flow(self, src, dst, suspicious=False):
        self.src_counter[src] += 1
        self.dst_counter[dst] += 1

        if suspicious:
            self.suspicious_ips[src] += 1

    def show(self):

        print("\n========== SECURITY DASHBOARD ==========\n")

        print("Top Talkers:")
        for ip, count in self.src_counter.most_common(5):
            print(ip, "→", count, "flows")

        print("\nTop Targets:")
        for ip, count in self.dst_counter.most_common(5):
            print(ip, "←", count, "connections")

        if self.suspicious_ips:
            print("\nSuspicious IPs:")
            for ip, count in self.suspicious_ips.most_common(5):
                print("⚠", ip, "triggered", count, "alerts")

        print("\n========================================\n")