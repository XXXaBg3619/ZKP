# ecc_vs_ff_benchmark.py  –  Compare finite‑field Schnorr vs. ECC‑Schnorr
# ----------------------------------------------------------------------
# * Generates N honest proofs for each scheme (default 50_000)
# * Measures verification time per scheme (pure Python)
# * Reports average proof size (bytes)
#
# Dependencies: sympy, ecdsa (pip install sympy ecdsa)
# ----------------------------------------------------------------------

import hashlib, random, time, argparse, sys
from typing import List, Tuple

from sympy import isprime
from ecdsa import curves, ellipticcurve

# ------------------------------------------------------------------
# Finite‑field parameters – 2048‑bit safe prime (RFC 3526 group 14)
# ------------------------------------------------------------------
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"  # 256 chars → 2048 bits
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374"  # continued
    "FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A"  # continue
    "899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"  # finish
)
P = int(P_HEX, 16)
Q = (P - 1) // 2  # safe prime subgroup
G = 2

# ------------------------------------------------------------------
# ECC parameters (secp256k1)
# ------------------------------------------------------------------
curve = curves.SECP256k1
G_EC = curve.generator
N_EC = curve.order

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def int_to_bytes(i: int, length: int | None = None) -> bytes:
    if length is None:
        length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, "big")


def sha256_int(*msgs: bytes, mod: int) -> int:
    h = hashlib.sha256(b"".join(msgs)).digest()
    return int.from_bytes(h, "big") % mod

# ------------------------------------------------------------------
# Finite‑field Schnorr proof / verify
# ------------------------------------------------------------------

def ff_keypair():
    x = random.randint(1, Q - 1)
    y = pow(G, x, P)
    return x, y


def ff_prove(x: int, y: int) -> Tuple[int, int]:
    s = random.randint(1, Q - 1)
    f = pow(G, s, P)
    c = sha256_int(int_to_bytes(f), int_to_bytes(y), mod=Q)
    r = (s + c * x) % Q
    return f, r


def ff_verify(y: int, proof: Tuple[int, int]) -> bool:
    f, r = proof
    c = sha256_int(int_to_bytes(f), int_to_bytes(y), mod=Q)
    return pow(G, r, P) == (f * pow(y, c, P)) % P

# ------------------------------------------------------------------
# ECC‑Schnorr proof / verify (secp256k1)
# ------------------------------------------------------------------

def point_compressed(pt: ellipticcurve.Point) -> bytes:
    x_bytes = int_to_bytes(pt.x(), 32)
    prefix = b"\x02" if pt.y() % 2 == 0 else b"\x03"
    return prefix + x_bytes


def ec_keypair():
    x = random.randrange(1, N_EC)
    Y = x * G_EC
    return x, Y


def ec_prove(x: int, Y) -> Tuple[ellipticcurve.Point, int]:
    k = random.randrange(1, N_EC)
    F = k * G_EC
    c = sha256_int(point_compressed(F), point_compressed(Y), mod=N_EC)
    r = (k + c * x) % N_EC
    return F, r


def ec_verify(Y, proof) -> bool:
    F, r = proof
    c = sha256_int(point_compressed(F), point_compressed(Y), mod=N_EC)
    left = r * G_EC
    right = F + c * Y
    return left == right

# ------------------------------------------------------------------
# Benchmark
# ------------------------------------------------------------------

def benchmark(n: int):
    print(f"\n=== Generating {n} proofs each scheme ===")

    # Finite‑field
    x_ff, y_ff = ff_keypair()
    ff_proofs: List[Tuple[int, int]] = [ff_prove(x_ff, y_ff) for _ in range(n)]

    # ECC
    x_ec, Y_ec = ec_keypair()
    ec_proofs = [ec_prove(x_ec, Y_ec) for _ in range(n)]

    # ---- size ----
    f_len = (P.bit_length() + 7) // 8  # 256 bytes
    r_ff_len = (Q.bit_length() + 7) // 8  # 32 bytes
    ff_size = (f_len + r_ff_len) * n

    ec_size = (33 + 32) * n  # compressed F + r 32 bytes

    print(f"[size] FF total {ff_size/1024:.1f} KB   | ECC total {ec_size/1024:.1f} KB")

    # ---- verify timing ----
    t0 = time.perf_counter()
    for fpr in ff_proofs:
        ff_verify(y_ff, fpr)
    t1 = time.perf_counter()
    for epr in ec_proofs:
        ec_verify(Y_ec, epr)
    t2 = time.perf_counter()

    ff_time = t1 - t0
    ec_time = t2 - t1
    print(f"[verify] FF  {ff_time:.4f} s   | ECC {ec_time:.4f} s")
    print(f"          ECC speed‑up ≈ {ff_time/ec_time:.1f}×")

# ------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--N", type=int, default=50000, help="number of proofs per scheme")
    args = parser.parse_args()

    benchmark(args.N)
