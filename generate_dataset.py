import random
import csv

def generate_data():
    with open('traffic_dataset.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['packet_count', 'avg_packet_size', 'max_packet_size', 'min_packet_size', 'std_packet_size', 'flow_duration', 'bytes_per_second', 'syn_count', 'ack_count', 'fin_count', 'label'])
        
        # HTTPS Traffic (Long-lived, high volume, mixed flags)
        for _ in range(30):
            writer.writerow([
                random.randint(5, 50), random.uniform(80, 500), random.randint(100, 1500), random.randint(40, 60), random.uniform(20, 100),
                random.uniform(1.0, 10.0), random.uniform(100.0, 5000.0), 1, random.randint(4, 40), random.randint(0, 1), 'HTTPS (Encrypted)'
            ])
            
        # HTTP Traffic (Medium lived)
        for _ in range(20):
            writer.writerow([
                random.randint(3, 20), random.uniform(60, 300), random.randint(100, 1000), random.randint(40, 55), random.uniform(10, 80),
                random.uniform(0.5, 5.0), random.uniform(50.0, 2000.0), 1, random.randint(2, 18), 1, 'HTTP (Plaintext)'
            ])

        # DNS Traffic (Single packet UDP usually, short lived, no TCP flags)
        for _ in range(20):
            writer.writerow([
                random.randint(1, 4), random.uniform(40, 100), random.randint(40, 150), random.randint(40, 80), random.uniform(0, 20),
                random.uniform(0.001, 0.1), random.uniform(10.0, 500.0), 0, 0, 0, 'DNS Query'
            ])

        # Anomaly: Port Scan (Lots of SYN packets, small size, fast)
        for _ in range(20):
            writer.writerow([
                random.randint(20, 100), random.uniform(40, 54), random.randint(40, 54), random.randint(40, 54), random.uniform(0, 2),
                random.uniform(0.01, 0.5), random.uniform(500.0, 10000.0), random.randint(20, 100), 0, 0, 'Port Scan'
            ])

        # Anomaly: DDoS (Huge packet count, large flow duration, high bandwidth)
        for _ in range(10):
            pcount = random.randint(200, 1000)
            writer.writerow([
                pcount, random.uniform(800, 1400), 1500, 60, random.uniform(100, 300),
                random.uniform(5.0, 20.0), random.uniform(10000.0, 50000.0), random.randint(10, 50), random.randint(100, 500), 0, 'DDoS Attack'
            ])

if __name__ == '__main__':
    generate_data()
