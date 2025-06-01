# -*- coding: utf-8 -*-
"""
Fiat–Shamir Schnorr：經典群 + 橢圓曲線、批次驗證 All‑in‑One
=================================================================
* Phase‑1  傳統有限域單挑戰 / 多挑戰
* Phase‑2  ECC‑Schnorr（secp256k1）單挑戰 / 多挑戰
* Phase‑3  批次驗證 (Batch) 與偽造率模擬

CLI 範例
--------
# 傳統有限域 + 批次驗證 + 模擬
python3 fs_all.py --k 1 5 10 20 --trials 10000

# 只展示 ECC 示範（不跑模擬）
python3 fs_all.py --ecc --no-sim

相依：sympy（必需）、tqdm（progress bar，可選）、matplotlib（繪圖，可選）、ecdsa（ECC，可裝）
"""
from __future__ import annotations
import argparse, hashlib, random, textwrap, sys
from pathlib import Path
from typing import List, Tuple
import matplotlib.pyplot as plt
from tqdm import tqdm
from ecdsa import curves, ellipticcurve, numbertheory
from sympy import isprime

# ----------------------------------------------------------------------------
# 共用工具：有限域安全質數 + 生成元
# ----------------------------------------------------------------------------

def generate_safe_prime(bits: int = 128) -> Tuple[int, int]:
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
    raise ValueError("找不到生成元，請重試參數建構")

# ----------------------------------------------------------------------------
# 有限域 Schnorr（單挑戰 / k 挑戰）
# ----------------------------------------------------------------------------

def _hash_challenge(f: int, y: int, ctx: str, q: int) -> int:
    return int(hashlib.sha256(f"{f}|{y}|{ctx}".encode()).hexdigest(), 16) % q

class SchnorrProver:
    def __init__(self, p: int, q: int, g: int, x: int, ctx: str):
        self.p, self.q, self.g, self.x, self.ctx = p, q, g, x, ctx
        self.y = pow(g, x, p)
    def prove(self) -> Tuple[int, int]:
        s = random.randint(1, self.q - 1)
        f = pow(self.g, s, self.p)
        c = _hash_challenge(f, self.y, self.ctx, self.q)
        r = (s + c * self.x) % self.q
        return f, r
class SchnorrVerifier:
    def __init__(self, p: int, q: int, g: int, y: int, ctx: str):
        self.p, self.q, self.g, self.y, self.ctx = p, q, g, y, ctx
    def verify(self, proof: Tuple[int, int]) -> bool:
        f, r = proof
        c = _hash_challenge(f, self.y, self.ctx, self.q)
        return pow(self.g, r, self.p) == (f * pow(self.y, c, self.p)) % self.p

# k‑challenge

def _hash_concat(vals: List[int], y: int, ctx: str) -> bytes:
    return hashlib.sha256(("|".join(map(str, vals + [y])) + "|" + ctx).encode()).digest()

def _derive_cs(hd: bytes, k: int, q: int) -> List[int]:
    cs: List[int] = []
    ctr = 0
    while len(cs) < k:
        block = hashlib.sha256(hd + ctr.to_bytes(4, "big")).digest()
        for i in range(0, len(block), 4):
            if len(cs) >= k:
                break
            cs.append(int.from_bytes(block[i:i+4], "big") % q)
        ctr += 1
    return cs
class SchnorrKProver:
    def __init__(self, p, q, g, x, k, ctx):
        self.p, self.q, self.g, self.x, self.k, self.ctx = p, q, g, x, k, ctx
        self.y = pow(g, x, p)
    def prove(self) -> List[Tuple[int, int]]:
        s = [random.randint(1, self.q - 1) for _ in range(self.k)]
        f = [pow(self.g, si, self.p) for si in s]
        c = _derive_cs(_hash_concat(f, self.y, self.ctx), self.k, self.q)
        return [(fi, (si + ci * self.x) % self.q) for fi, si, ci in zip(f, s, c)]
class SchnorrKVerifier:
    def __init__(self, p, q, g, y, k, ctx):
        self.p, self.q, self.g, self.y, self.k, self.ctx = p, q, g, y, k, ctx
    def verify(self, proofs: List[Tuple[int, int]]) -> bool:
        if len(proofs) != self.k:
            return False
        f = [fi for fi, _ in proofs]
        c = _derive_cs(_hash_concat(f, self.y, self.ctx), self.k, self.q)
        for (fi, ri), ci in zip(proofs, c):
            if pow(self.g, ri, self.p) != (fi * pow(self.y, ci, self.p)) % self.p:
                return False
        return True

# 批次驗證（有限域）

def batch_verify(proofs: List[Tuple[int, int]], y_list: List[int], p: int, q: int, g: int, ctx: str) -> bool:
    if len(proofs) != len(y_list):
        return False
    left = 1
    right = 1
    for (f, r), y in zip(proofs, y_list):
        c = _hash_challenge(f, y, ctx, q)
        left = (left * pow(g, r, p)) % p
        right = (right * f * pow(y, c, p)) % p
    return left == right

# ----------------------------------------------------------------------------
# ECC‑Schnorr（secp256k1）
# ----------------------------------------------------------------------------
_curve = curves.SECP256k1
_G = _curve.generator
_n = _curve.order
def _h_ec(fx, fy, yx, yy, ctx):
    h = hashlib.sha256(f"{fx}|{fy}|{yx}|{yy}|{ctx}".encode()).digest()
    return int.from_bytes(h, "big") % _n

class ECCProver:
    def __init__(self, x: int, ctx: str):
        self.x, self.ctx = x, ctx
        self.Y = self.x * _G  # public
    def prove(self):
        k = random.randrange(1, _n)
        F = k * _G
        c = _h_ec(F.x(), F.y(), self.Y.x(), self.Y.y(), self.ctx)
        r = (k + c * self.x) % _n
        return (F, r)
class ECCVerifier:
    def __init__(self, Y, ctx: str):
        self.Y, self.ctx = Y, ctx
    def verify(self, proof):
        F, r = proof
        c = _h_ec(F.x(), F.y(), self.Y.x(), self.Y.y(), self.ctx)
        left = r * _G
        right = F + c * self.Y
        return left == right
# 批次驗證 ECC
def batch_verify_ecc(proofs, Y_list, ctx):
    left = ellipticcurve.INFINITY
    right = ellipticcurve.INFINITY
    for (F, r), Y in zip(proofs, Y_list):
        c = _h_ec(F.x(), F.y(), Y.x(), Y.y(), ctx)
        left = left + r * _G if left else r * _G
        right = right + (F + c * Y) if right else F + c * Y
    return left == right

# ----------------------------------------------------------------------------
# 模擬與 CLI
# ----------------------------------------------------------------------------

def simulate_forgery(k_vals, trials=10000, bits=128):
    res = {}
    for k in k_vals:
        p, q = generate_safe_prime(bits)
        g = find_generator(p, q)
        x = random.randint(1, q - 1)
        y = pow(g, x, p)
        verifier = SchnorrKVerifier(p, q, g, y, k, "CTX")
        succ = 0
        for _ in tqdm(range(trials), desc=f"k={k}"):
            forged = [(random.randint(2, p - 2), random.randint(2, q - 2)) for _ in range(k)]
            if verifier.verify(forged):
                succ += 1
        res[k] = succ / trials
    return res

# Plot helper

def _plot(res, trials, out_dir):
    ks, ys = zip(*[(k, max(r, 1/trials)) for k, r in res.items()])
    plt.figure(figsize=(6,4))
    plt.plot(ks, ys, marker="o")
    plt.yscale("log")
    plt.xlabel("k")
    plt.ylabel("forgery rate (log)")
    plt.title(f"Forgery probability vs k ({trials} trials)")
    plt.grid(True)
    out_dir.mkdir(exist_ok=True)
    fn = out_dir / "forge_prob.png"
    plt.savefig(fn, bbox_inches="tight")
    plt.close()
    print("圖存檔至", fn.resolve())

# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", nargs="*", type=int, default=[1,5,10,20])
    ap.add_argument("--trials", type=int, default=10000)
    ap.add_argument("--bits", type=int, default=128)
    ap.add_argument("--ecc", action="store_true", help="demo ECC‑Schnorr")
    ap.add_argument("--no-sim", action="store_true", help="skip simulation")
    args = ap.parse_args()

    print("\n[有限域單/多挑戰 Demo]")
    p, q = generate_safe_prime(args.bits)
    g = find_generator(p, q)
    x = random.randint(1, q-1)
    prov = SchnorrProver(p,q,g,x,"CTX")
    ver  = SchnorrVerifier(p,q,g,prov.y,"CTX")
    print("single pass:", ver.verify(prov.prove()))

    k=5
    provk = SchnorrKProver(p,q,g,x,k,"CTX")
    verk  = SchnorrKVerifier(p,q,g,provk.y,k,"CTX")
    print(f"k={k} pass:", verk.verify(provk.prove()))

    if args.ecc:
        print("\n[ECC‑Schnorr Demo]")
        x_ec = random.randrange(1, _n)
        prov_ec = ECCProver(x_ec, "CTX")
        ver_ec  = ECCVerifier(prov_ec.Y, "CTX")
        print("ecc single pass:", ver_ec.verify(prov_ec.prove()))

    if not args.no_sim:
        print("\n[偽造成功率模擬]")
        res = simulate_forgery(args.k, args.trials, args.bits)
        for k,v in res.items():
            print(f"k={k:<3} rate={v:.6e}")
        _plot(res,args.trials,Path("sim_out"))

if __name__ == "__main__":
    main()
    # import time, random
    # p,q = generate_safe_prime(128); g=find_generator(p,q)
    # proofs, ys = [], []
    # batches = 1000000
    # for _ in tqdm(range(batches)):
    #     x=random.randint(1,q-1); prover=SchnorrProver(p,q,g,x,'CTX')
    #     proofs.append(prover.prove()); ys.append(prover.y)
    # t1=time.time();  
    # for pr,y in tqdm(zip(proofs,ys)): SchnorrVerifier(p,q,g,y,'CTX').verify(pr)
    # solo=time.time()-t1
    # t2=time.time(); batch_verify(proofs,ys,p,q,g,'CTX'); batch=time.time()-t2
    # print(f"time for solo: {solo} s")
    # print(f"time for batch ({batches}): {batch} s")

