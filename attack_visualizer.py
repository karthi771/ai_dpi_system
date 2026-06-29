import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict


class AttackVisualizer:

    def __init__(self):
        self.graph = nx.Graph()
        self.node_traffic = defaultdict(int)
        self.suspicious_nodes = set()
        plt.ion()

    def add_connection(self, src, dst, suspicious=False):

        # track traffic volume
        self.node_traffic[src] += 1
        self.node_traffic[dst] += 1

        # mark suspicious nodes
        if suspicious:
            self.suspicious_nodes.add(src)

        # update edge weight
        if self.graph.has_edge(src, dst):
            self.graph[src][dst]["weight"] += 1
        else:
            self.graph.add_edge(src, dst, weight=1)

    def draw(self):

        plt.clf()
        if not self.graph.nodes():
            return
            
        pos = nx.spring_layout(self.graph, k=0.7)

        node_colors = []
        node_sizes = []

        for node in self.graph.nodes():

            if node in self.suspicious_nodes:
                node_colors.append("red")
            else:
                node_colors.append("lightblue")

            # traffic heatmap (bigger node = more traffic)
            size = 1000 + self.node_traffic[node] * 200
            node_sizes.append(size)

        edges = self.graph.edges()
        weights = [self.graph[u][v]["weight"] for u, v in edges]

        nx.draw(
            self.graph,
            pos,
            with_labels=True,
            node_color=node_colors,
            node_size=node_sizes,
            width=weights,
            edge_color="green",
            font_size=8
        )

        plt.title("Network Traffic Heatmap & Attack Map")
        plt.pause(0.01)