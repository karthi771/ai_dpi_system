from flow_features import extract_from_packets


class FeatureExtractor:

    def extract(self, flow):
        return extract_from_packets(flow)
