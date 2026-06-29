from scapy.all import rdpcap, sniff
import threading
import queue
import time

class PacketReader:

    def __init__(self, source, mode="pcap"):
        self.source = source
        self.mode = mode
        self.packet_queue = queue.Queue()
        self.is_capturing = False
        self.capture_thread = None

    def _sniff_continuous(self):
        """Background thread function to capture packets without drops."""
        print("Started continuous live capture...")
        sniff(prn=lambda pkt: self.packet_queue.put(pkt), store=False)

    def start_live_capture(self):
        """Starts the background capture thread for live mode."""
        if self.mode == "live" and not self.is_capturing:
            self.is_capturing = True
            self.capture_thread = threading.Thread(target=self._sniff_continuous, daemon=True)
            self.capture_thread.start()

    def read_packets(self, batch_size=100):
        """Returns a batch of packets from PCAP or live queue."""
        if self.mode == "pcap":
            packets = rdpcap(self.source)
            print("Loaded", len(packets), "packets")
            return packets
        elif self.mode == "live":
            # Start capture thread if not already started
            self.start_live_capture()
            
            packets = []
            # Gather up to batch_size packets currently in queue
            # To ensure the UI updates, we block briefly for at least one packet, 
            # then take whatever else is immediately available up to batch_size
            try:
                # Wait for at least one packet
                first_pkt = self.packet_queue.get(timeout=2.0)
                packets.append(first_pkt)
                
                # Get the rest without blocking
                while len(packets) < batch_size and not self.packet_queue.empty():
                    packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                pass # Queue is empty, return whatever we have
            
            # if packets:
            #     print(f"Processing batch of {len(packets)} packets...")
            return packets