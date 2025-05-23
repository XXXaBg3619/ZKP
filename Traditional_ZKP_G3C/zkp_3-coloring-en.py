#Traditional ZKP with G3C Problem
#Author: 林伯叡、黃杬霆
#Date: 2025/05/15

# =============================================
# 將生成圖片的部分修改成英文
# =============================================

import random
import copy
import networkx as nx
import matplotlib
import matplotlib.pyplot as plt
# matplotlib.rcParams['font.family'] = 'Microsoft JhengHei'  # 微軟正黑體
matplotlib.rcParams['axes.unicode_minus'] = False  # 避免負號變成亂碼

# === 圖與著色 ===
graph_A = {
    0: [1, 4], 1: [0, 2, 5], 2: [1, 3, 6], 3: [2, 7],
    4: [0, 5, 8], 5: [1, 4, 6, 9], 6: [2, 5, 7, 10], 7: [3, 6, 11],
    8: [4, 9, 12], 9: [5, 8, 10, 13], 10: [6, 9, 11, 14], 11: [7, 10],
    12: [8, 13], 13: [9, 12, 14], 14: [10, 13]
}

colors_A = {
    0: 1, 1: 2, 2: 3, 3: 1, 4: 2, 5: 3,
    6: 1, 7: 2, 8: 3, 9: 1, 10: 2, 11: 3,
    12: 1, 13: 2, 14: 3
}

graph_B = copy.deepcopy(graph_A)
graph_B[0].append(3)
graph_B[3].append(0)  # 非法邊

# === ZKP 模擬函式 ===
def simulate_zkp_rounds(graph, colors, is_valid=True, rounds=20):
    total_messages = 0
    conflict_hits = 0
    conflict_history = []
    log = []

    edge_set = set()
    for u in graph:
        for v in graph[u]:
            if (v, u) not in edge_set:
                edge_set.add((u, v))
    edge_list = list(edge_set)

    for r in range(1, rounds + 1):
        messages = 0
        log.append(f"🔁 第 {r} 輪：")
        messages += 1
        log.append(f"  - Prover 傳送承諾（1 次）")
        u, v = random.choice(edge_list)
        messages += 1
        log.append(f"  - Verifier 挑邊 ({u}, {v})（1 次）")
        messages += 2
        log.append(f"  - Prover 解鎖節點 {u} 色 {colors[u]}，節點 {v} 色 {colors[v]}（2 次）")

        if colors[u] == colors[v]:
            log.append(f"  ❌ 顏色衝突，驗證失敗")
            conflict_hits += 1
            conflict_history.append(1)
        else:
            log.append(f"  ✅ 驗證通過")
            conflict_history.append(0)

        total_messages += messages
        log.append(f"  📦 本輪傳遞訊息總數：{messages}")

        if not is_valid:
            empirical_p = sum(conflict_history) / r
            theoretical_p = 1 - (1 - (1 / len(edge_list))) ** r
            log.append(f"  📈 累積實測機率：{empirical_p:.4f}，理論機率：約 {theoretical_p:.4f}")

    log.append(f"\n📊 模擬結束，共 {rounds} 輪")
    log.append(f"📨 總訊息傳遞次數：{total_messages}")
    if not is_valid:
        log.append(f"❗ 選中衝突邊次數：{conflict_hits}")
        final_empirical = sum(conflict_history) / rounds
        final_theoretical = 1 - (1 - (1 / len(edge_list))) ** rounds
        log.append(f"📈 最終實測機率：約 {final_empirical:.4f}")
        log.append(f"📈 最終理論機率：約 {final_theoretical:.4f}")

    return log

# === 繪圖函式 ===
def draw_single_graph(graph, colors, title, highlight_conflict=False):
    G = nx.Graph()
    for u in graph:
        for v in graph[u]:
            G.add_edge(u, v)

    pos = nx.spring_layout(G, seed=42)
    color_map = {1: 'red', 2: 'green', 3: 'yellow'}
    node_colors = [color_map[colors[n]] for n in G.nodes()]

    conflict_edges = []
    normal_edges = []
    for u, v in G.edges():
        if colors[u] == colors[v] and highlight_conflict:
            conflict_edges.append((u, v))
        else:
            normal_edges.append((u, v))

    plt.figure(figsize=(7, 6))
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=800)
    nx.draw_networkx_edges(G, pos, edgelist=normal_edges, edge_color='gray')
    if highlight_conflict:
        nx.draw_networkx_edges(G, pos, edgelist=conflict_edges, edge_color='red', width=2.5)
    nx.draw_networkx_labels(G, pos, labels={n: f"{n}({colors[n]})" for n in G.nodes()}, font_size=10)
    plt.title(title)
    plt.axis("off")
    plt.tight_layout()
    plt.show()

# === 合法性檢查（推薦搭配） ===
def check_graph_validity(graph, colors):
    for u in graph:
        for v in graph[u]:
            if u < v and colors[u] == colors[v]:
                print(f"❌ 發現衝突邊 ({u}, {v})，同為色 {colors[u]}")
                return False
    print("✅ 著色合法，無衝突邊")
    return True


enable_check = "FALSE"  

assert enable_check in [
    "TRUE",
    "FALSE",
], f"Unsupported enable_check: {enable_check}"

enable_plotcurve = "TRUE"

assert enable_plotcurve in [
    "TRUE",
    "FALSE",
], f"Unsupported enable_plotcurve: {enable_plotcurve}"

if enable_check == "TRUE":
    # === 執行檢查與單圖繪製 ===
    print("\n🧪 檢查 Graph A 合法性：")
    check_graph_validity(graph_A, colors_A)

    print("\n🧪 檢查 Graph B 合法性：")
    check_graph_validity(graph_B, colors_A)

    draw_single_graph(graph_A, colors_A, "Graph A（合法）", highlight_conflict=True)
    draw_single_graph(graph_B, colors_A, "Graph B（含衝突邊）", highlight_conflict=True)


# === 執行模擬 ===
rounds_A = 20 
rounds_B = 3000

log_A = simulate_zkp_rounds(graph_A, colors_A, is_valid=True, rounds=rounds_A)
log_B = simulate_zkp_rounds(graph_B, colors_A, is_valid=False, rounds=rounds_B)

print("\n====== Graph A（合法）ZKP 模擬 ======")
for line in log_A:
    print(line)

print("\n====== Graph B（非法）ZKP 模擬 ======")
for line in log_B:
    print(line)

if enable_plotcurve == "TRUE":
    def extract_conflict_history(log):
        return [1 if "❌ 顏色衝突" in line else 0 for line in log if "✅ 驗證通過" in line or "❌ 顏色衝突" in line]

    conflict_history = extract_conflict_history(log_B)
    total_edges = sum(len(neigh) for neigh in graph_B.values()) // 2
    empirical_probs = []
    conflict_sum = 0
    for r in range(1, len(conflict_history)+1):
        conflict_sum += conflict_history[r - 1]
        empirical_probs.append(conflict_sum / r)
    theoretical_probs = [1 - (1 - 1 / total_edges) ** r for r in range(1, len(conflict_history)+1)]

    # # 畫圖
    # plt.figure(figsize=(10, 5))
    # plt.plot(range(1, rounds_B + 1), empirical_probs, label="實測機率", color='Green')
    # # plt.plot(range(1, rounds_B + 1), theoretical_probs, label="理論機率", linestyle='--', color='Red')
    # plt.xlabel("執行輪數 r")
    # plt.ylabel("至少命中一次衝突邊的機率")
    # plt.title("ZKP 模擬：Graph B (Not G3C) 實測機率")
    # # plt.title("ZKP 模擬：Graph B 實測機率 vs 理論機率")
    # plt.grid(True)
    # plt.legend()
    # plt.tight_layout()
    # plt.show()

    # Plotting
    plt.figure(figsize=(10, 5))
    plt.plot(range(1, rounds_B + 1), empirical_probs, label="Empirical Probability", color='Green')
    # plt.plot(range(1, rounds_B + 1), theoretical_probs, label="Theoretical Probability", linestyle='--', color='Red')
    plt.xlabel("Round number r")
    plt.ylabel("Probability of hitting at least one conflicting edge")
    plt.title("ZKP Simulation: Graph B (Not G3C) Empirical Probability")
    # plt.title("ZKP Simulation: Graph B - Empirical vs Theoretical Probability")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.savefig("zkp_graph_b_plot.png", dpi=300)





