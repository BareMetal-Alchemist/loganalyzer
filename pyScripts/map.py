import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt

# Load the CSV from the previous script
df = pd.read_csv('post_phish_email_activity.csv')

# Build graph
G = nx.DiGraph()
for _, row in df.iterrows():
    G.add_edge(row['sender'], row['recipient'], timestamp=row['timestamp'])

# Draw graph
plt.figure(figsize=(10, 7))
pos = nx.spring_layout(G, k=1)
nx.draw(G, pos, with_labels=True, node_color='skyblue', edge_color='gray', node_size=1500, font_size=10)
nx.draw_networkx_edge_labels(G, pos, edge_labels={(u, v): d['timestamp'] for u, v, d in G.edges(data=True)}, font_size=8)

plt.title("Post-Phishing Email Flow")
plt.tight_layout()
plt.show()
