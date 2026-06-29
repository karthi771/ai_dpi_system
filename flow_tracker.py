class FlowTracker:

    def __init__(self):
        self.flows = {}

    @staticmethod
    def get_flow_key(packet):
        if packet["src_ip"] < packet["dst_ip"]:
            return (packet["src_ip"], packet["dst_ip"],
                    packet["src_port"], packet["dst_port"], packet["protocol"])
        return (packet["dst_ip"], packet["src_ip"],
                packet["dst_port"], packet["src_port"], packet["protocol"])

    def add_packet(self, packet):

        # Bi-directional flow key 
        key = self.get_flow_key(packet)

        if key not in self.flows:
            self.flows[key] = []

        self.flows[key].append(packet)

    def summary(self):

        print("\nFlow Summary\n")

        for flow, packets in self.flows.items():
            print(flow, "Packets:", len(packets))
