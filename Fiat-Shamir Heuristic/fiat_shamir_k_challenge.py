# Fiat–Shamir Heuristic – Single & Multi‑challenge NIZK (Schnorr)
# Author: 林伯叡、黃杬霆
# Updated: 2025/05/24 – Phase‑1 (single) & Phase‑2 (k‑challenge) finished
#
# This module now包含：
#   • FiatShamirProver / Verifier          — 第一階段（單一挑戰）
#   • MultiChallengeProver / Verifier      — 第二階段（k 組挑戰）
#   • demo_single() / demo_multi() 範例    — 可輸出 logs 及 PNG
#
# ---------------------------------------------------------------------------

import hashlib
import random
import textwrap
from pathlib import Path
from typing import List, Tuple

try:
    import matplotlib.pyplot as plt  # only用於 demo 圖
except ImportError:
    plt = None  # type: ignore

from sympy import isprime

# === 共用工具 ===============================================================


def generate_safe_prime(bits: int = 128):
    """產生安全質數 p 與大質數因子 q."""
    while True:
        q = random.getrandbits(bits) | 1
        if not isprime(q):
            continue
        for r in range(2, 20):
            p = q * r + 1
            if isprime(p):
                return p, q


def find_generator(p: int, q: int):
    for g in range(2, p):
        if pow(g, q, p) == 1:
            return g
    raise ValueError("no generator")


# === Phase‑1: 單一挑戰版本 ==================================================


def _hash_challenge(f: int, y: int, context: str, q: int) -> int:
    data = f"{f}|{y}|{context}".encode()
    h = hashlib.sha256(data).hexdigest()
    return int(h, 16) % q


class FiatShamirProver:
    """一次性 (f, r) 證明產生器"""

    def __init__(self, p: int, q: int, g: int, x: int, *, context: str = "FiatShamirDemo2025"):
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
    def __init__(self, p: int, q: int, g: int, y: int, *, context: str = "FiatShamirDemo2025"):
        self.p, self.q, self.g, self.y = p, q, g, y
        self.context = context

    def verify(self, proof: Tuple[int, int]) -> bool:
        f, r = proof
        c = _hash_challenge(f, self.y, self.context, self.q)
        return pow(self.g, r, self.p) == (f * pow(self.y, c, self.p)) % self.p


# === Phase‑2: 多組挑戰版本 (k‑challenge) ====================================


def _hash_concat(values: List[int], y: int, context: str) -> bytes:
    """f1|f2|...|fk|y|ctx → 32‑byte digest"""
    concat = "|".join(map(str, values + [y])) + "|" + context
    return hashlib.sha256(concat.encode()).digest()


def _derive_challenges(h_digest: bytes, k: int, q: int) -> List[int]:
    """將 256‑bit 雜湊擴充為 k 個挑戰，每個再 mod q。"""
    challenges: List[int] = []
    counter = 0
    while len(challenges) < k:
        ctr_bytes = counter.to_bytes(4, "big", signed=False)
        block = hashlib.sha256(h_digest + ctr_bytes).digest()
        # split block into 4‑byte words
        for i in range(0, len(block), 4):
            if len(challenges) >= k:
                break
            word = int.from_bytes(block[i:i + 4], "big")
            challenges.append(word % q)
        counter += 1
    return challenges


class MultiChallengeProver:
    """產生 k‑tuple 證明 [(f_i, r_i)]"""

    def __init__(self, p: int, q: int, g: int, x: int, k: int = 5, *, context: str = "FiatShamirDemo2025"):
        assert k >= 1
        self.p, self.q, self.g, self.x, self.k = p, q, g, x, k
        self.context = context
        self.y = pow(g, x, p)

    def prove(self) -> List[Tuple[int, int]]:
        s_list = [random.randint(1, self.q - 1) for _ in range(self.k)]
        f_list = [pow(self.g, s, self.p) for s in s_list]

        h_digest = _hash_concat(f_list, self.y, self.context)
        c_list = _derive_challenges(h_digest, self.k, self.q)

        proofs = []
        for s, c in zip(s_list, c_list):
            r = (s + c * self.x) % self.q
            proofs.append((pow(self.g, s, self.p), r))
        return proofs


class MultiChallengeVerifier:
    def __init__(self, p: int, q: int, g: int, y: int, k: int, *, context: str = "FiatShamirDemo2025"):
        self.p, self.q, self.g, self.y, self.k = p, q, g, y, k
        self.context = context

    def verify(self, proofs: List[Tuple[int, int]]) -> bool:
        if len(proofs) != self.k:
            return False
        f_list = [f for f, _ in proofs]
        h_digest = _hash_concat(f_list, self.y, self.context)
        c_list = _derive_challenges(h_digest, self.k, self.q)
        for (f, r), c in zip(proofs, c_list):
            if pow(self.g, r, self.p) != (f * pow(self.y, c, self.p)) % self.p:
                return False
        return True


# === Demo functions =========================================================


def _save_log_png(log: str, out_dir: Path, fname: str):
    if plt is None:
        return
    fig = plt.figure(figsize=(10, 12))
    plt.axis("off")
    plt.text(0.01, 0.99, log, va="top", ha="left", family="monospace")
    img_path = out_dir / f"{fname}.png"
    fig.savefig(img_path, bbox_inches="tight")
    plt.close(fig)


def demo_single(out_dir: str | Path = "./Fiat-Shamir Heuristic/result"):
    print("\n=== Single‑challenge Demo ===")
    p, q = generate_safe_prime(128)
    g = find_generator(p, q)
    x = random.randint(1, q - 1)
    y = pow(g, x, p)

    prover = FiatShamirProver(p, q, g, x)
    verifier = FiatShamirVerifier(p, q, g, y)

    proof = prover.prove()
    honest_ok = verifier.verify(proof)

    forged = (random.randint(2, p - 2), random.randint(2, q - 2))
    forged_ok = verifier.verify(forged)

    log = textwrap.dedent(f"""
        Single‑challenge (k=1) result
        honest pass = {honest_ok}
        forged pass = {forged_ok}
    """).strip()
    print(log)


def demo_multi(k: int = 5, out_dir: str | Path = "./Fiat-Shamir Heuristic/result"):
    print(f"\n=== Multi‑challenge Demo (k={k}) ===")
    p, q = generate_safe_prime(128)
    g = find_generator(p, q)
    x = random.randint(1, q - 1)
    y = pow(g, x, p)

    prover = MultiChallengeProver(p, q, g, x, k)
    verifier = MultiChallengeVerifier(p, q, g, y, k)

    proofs = prover.prove()
    honest_ok = verifier.verify(proofs)

    # 偽造：隨機 r_i
    forged = [(random.randint(2, p - 2), random.randint(2, q - 2)) for _ in range(k)]
    forged_ok = verifier.verify(forged)

    log = textwrap.dedent(f"""
        Multi‑challenge (k={k}) result
        honest pass = {honest_ok}
        forged pass = {forged_ok}
    """).strip()
    print(log)


if __name__ == "__main__":
    demo_single()
    demo_multi(k=5)
    demo_multi(k=10)
    demo_multi(k=500)
