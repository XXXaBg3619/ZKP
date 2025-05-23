# -*- coding: utf-8 -*-
"""
Fiat–Shamir Schnorr (Non‑interactive ZKP) – All‑in‑One Implementation
====================================================================
Phase‑1  單一挑戰 (k = 1)
Phase‑2  多組挑戰 (任意 k)
Phase‑3  安全性模擬與可視化 (偽造成功率)

* 作者：林伯叡、黃杬霆  (2025‑05‑24)
* 相依：sympy、matplotlib (僅模擬 / 畫圖需要)
* 執行：
    python3 fiat_shamir_all.py                 # 預設 demo + 模擬
    python3 fiat_shamir_all.py --k 1 5 10 20   # 指定 k 列表
    python3 fiat_shamir_all.py --trials 50000  # 指定試驗次數
"""

from __future__ import annotations

import argparse
import hashlib
import random
import textwrap
from pathlib import Path
from typing import List, Tuple
import matplotlib.pyplot as plt
from sympy import isprime
from tqdm import tqdm

# ---------------------------------------------------------------------------
# 共用工具
# ---------------------------------------------------------------------------

def generate_safe_prime(bits: int = 128) -> Tuple[int, int]:
    """產生安全質數 p 與大質數因子 q (簡化：q* r + 1)。"""
    while True:
        q = random.getrandbits(bits) | 1
        if not isprime(q):
            continue
        for r in range(2, 20):
            p = q * r + 1
            if isprime(p):
                return p, q

def find_generator(p: int, q: int) -> int:
    for g in range(2, p):
        if pow(g, q, p) == 1:
            return g
    raise ValueError("無法找到生成元 – 請重試參數建構")

# ---------------------------------------------------------------------------
# Phase‑1：單一挑戰 (k=1)
# ---------------------------------------------------------------------------

def _hash_challenge(f: int, y: int, context: str, q: int) -> int:
    data = f"{f}|{y}|{context}".encode()
    return int(hashlib.sha256(data).hexdigest(), 16) % q

class FiatShamirProver:
    def __init__(self, p: int, q: int, g: int, x: int, *, context: str = "FiatShamirDemo2025") -> None:
        self.p, self.q, self.g, self.x = p, q, g, x
        self.context = context
        self.y = pow(g, x, p)

    def prove(self) -> Tuple[int, int]:
        s = random.randint(1, self.q - 1)
        f = pow(self.g, s, self.p)
        c = _hash_challenge(f, self.y, self.context, self.q)
        r = (s + c * self.x) % self.q
        return f, r

class FiatShamirVerifier:
    def __init__(self, p: int, q: int, g: int, y: int, *, context: str = "FiatShamirDemo2025") -> None:
        self.p, self.q, self.g, self.y = p, q, g, y
        self.context = context

    def verify(self, proof: Tuple[int, int]) -> bool:
        f, r = proof
        c = _hash_challenge(f, self.y, self.context, self.q)
        return pow(self.g, r, self.p) == (f * pow(self.y, c, self.p)) % self.p

# ---------------------------------------------------------------------------
# Phase‑2：多組挑戰 (k)
# ---------------------------------------------------------------------------

def _hash_concat(values: List[int], y: int, context: str) -> bytes:
    concat = "|".join(map(str, values + [y])) + "|" + context
    return hashlib.sha256(concat.encode()).digest()

def _derive_challenges(h_digest: bytes, k: int, q: int) -> List[int]:
    challenges: List[int] = []
    ctr = 0
    while len(challenges) < k:
        block = hashlib.sha256(h_digest + ctr.to_bytes(4, "big")).digest()
        for i in range(0, len(block), 4):
            if len(challenges) >= k:
                break
            challenges.append(int.from_bytes(block[i:i+4], "big") % q)
        ctr += 1
    return challenges

class MultiChallengeProver:
    def __init__(self, p: int, q: int, g: int, x: int, k: int = 5, *, context: str = "FiatShamirDemo2025") -> None:
        assert k >= 1
        self.p, self.q, self.g, self.x, self.k = p, q, g, x, k
        self.context = context
        self.y = pow(g, x, p)

    def prove(self) -> List[Tuple[int, int]]:
        s_list = [random.randint(1, self.q - 1) for _ in range(self.k)]
        f_list = [pow(self.g, s, self.p) for s in s_list]
        c_list = _derive_challenges(_hash_concat(f_list, self.y, self.context), self.k, self.q)
        return [(f, (s + c * self.x) % self.q) for f, s, c in zip(f_list, s_list, c_list)]

class MultiChallengeVerifier:
    def __init__(self, p: int, q: int, g: int, y: int, k: int, *, context: str = "FiatShamirDemo2025") -> None:
        self.p, self.q, self.g, self.y, self.k = p, q, g, y, k
        self.context = context

    def verify(self, proofs: List[Tuple[int, int]]) -> bool:
        if len(proofs) != self.k:
            return False
        f_list = [f for f, _ in proofs]
        c_list = _derive_challenges(_hash_concat(f_list, self.y, self.context), self.k, self.q)
        for (f, r), c in zip(proofs, c_list):
            if pow(self.g, r, self.p) != (f * pow(self.y, c, self.p)) % self.p:
                return False
        return True

# ---------------------------------------------------------------------------
# Phase‑3：安全性模擬
# ---------------------------------------------------------------------------

def simulate_forgery_success(k_values: List[int], trials: int = 10000, bits: int = 128) -> dict[int, float]:
    """返回 {k: 偽造成功率}；偽造者亂猜 (f_i,r_i)。"""
    results: dict[int, float] = {}
    for k in k_values:
        p, q = generate_safe_prime(bits)
        g = find_generator(p, q)
        x = random.randint(1, q - 1)
        y = pow(g, x, p)
        verifier = MultiChallengeVerifier(p, q, g, y, k)
        success = 0
        for _ in tqdm(range(trials), desc=f"Simulating k={k}"):
            forged = [(random.randint(2, p - 2), random.randint(2, q - 2)) for _ in range(k)]
            if verifier.verify(forged):
                success += 1
        results[k] = success / trials
    return results

# ---------------------------------------------------------------------------
# CLI / Demo / 入口點
# ---------------------------------------------------------------------------

def demo_single_multi() -> None:
    print("\n=== Single‑challenge Demo ===")
    p, q = generate_safe_prime(128)
    g = find_generator(p, q)
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    prover = FiatShamirProver(p, q, g, x)
    verifier = FiatShamirVerifier(p, q, g, y)
    honest = verifier.verify(prover.prove())
    forged = verifier.verify((random.randint(2, p - 2), random.randint(2, q - 2)))
    print(f"honest pass = {honest}\nforged pass = {forged}")

    print("\n=== Multi‑challenge Demo (k=5) ===")
    k = 5
    prover2 = MultiChallengeProver(p, q, g, x, k)
    verifier2 = MultiChallengeVerifier(p, q, g, y, k)
    honest2 = verifier2.verify(prover2.prove())
    forged2 = verifier2.verify([(random.randint(2, p - 2), random.randint(2, q - 2)) for _ in range(k)])
    print(f"honest pass = {honest2}\nforged pass = {forged2}")


def plot_results(results: dict[int, float], trials: int, out_dir: Path) -> None:
    # ks = list(results.keys())
    # ys = list(results.values())
    filtered = [(k, v) for k, v in results.items() if v > 0]
    if filtered:
        ks, ys = zip(*filtered)
    else:
        ks, ys = [], []


    plt.figure(figsize=(6, 4))
    plt.plot(ks, ys, marker="o")
    plt.yscale("log")
    plt.xlabel("Number of challenges k")
    plt.ylabel("Forgery success rate (log scale)")
    plt.title(f"Forgery success probability vs k\n({trials} trials each)")
    plt.grid(True)
    out_dir.mkdir(parents=True, exist_ok=True)
    img = out_dir / "forge_success_vs_k.png"
    plt.savefig(img, bbox_inches="tight")
    plt.close()
    print(f"圖形已存檔： {img.resolve()}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fiat–Shamir Schnorr all‑in‑one demo & simulation")
    parser.add_argument("--k", nargs="*", type=int, default=[1, 5, 10, 20], help="k list for simulation")
    parser.add_argument("--trials", type=int, default=10000, help="number of forgeries per k")
    parser.add_argument("--bits", type=int, default=128, help="bit length of prime q for simulation")
    args = parser.parse_args()

    demo_single_multi()

    print("\n=== Security Simulation ===")
    results = simulate_forgery_success(args.k, args.trials, args.bits)
    for k, rate in results.items():
        print(f"k={k:>4}  success_rate={rate:.6e}")

    log_txt = f"# trials = {args.trials}, bits = {args.bits}\n"
    log_txt += "\n".join([f"k={k}, success_rate={r:.6e}" for k, r in results.items()])
    out_dir = Path("./Fiat-Shamir Heuristic/simulation_result")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "forge_success_vs_k.txt").write_text(log_txt, encoding="utf-8")
    plot_results(results, args.trials, out_dir)


if __name__ == "__main__":
    main()
