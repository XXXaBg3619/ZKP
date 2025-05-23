# Fiat–Shamir Heuristic – Non‑interactive Zero‑Knowledge Proof (Schnorr)
# Author: 林伯叡、黃杬霆
# Date: 2025/05/24
#
# This module implements a non‑interactive Schnorr identification protocol
# using the Fiat–Shamir heuristic.  The prover produces a one‑shot proof
# (f, r).  The verifier re‑computes the challenge with SHA‑256 and checks
#     g^r == f * y^c  (mod p)
#
# The code retains the safe‑prime parameter generation from schnorr.py for
# consistency, but removes all interactive elements such as timestamps or
# external randomness in the challenge stage.
#
# Usage (see the __main__ block):
#   1. Honest prover generates a proof – verification succeeds.
#   2. Forged proof (no knowledge of secret key) – verification fails.
#
# Dependencies: sympy, hashlib, random
#
# ------------------------------------------------------------

import hashlib
import random
from sympy import isprime


# === Parameter generation ===================================================

def generate_safe_prime(bits: int = 128):
    """Generate a safe prime p with prime divisor q = (p‑1)//r.
    For demo purposes the bit‑length defaults to 128.  Increase to 256+
    in production.
    """
    while True:
        q = random.getrandbits(bits)
        q |= 1  # make sure q is odd
        if not isprime(q):
            continue
        # try small r (2 … 20) so that p = q * r + 1 is prime
        for r in range(2, 20):
            p = q * r + 1
            if isprime(p):
                return p, q


def find_generator(p: int, q: int):
    """Find a generator g of the q‑order subgroup of Z_p^✱."""
    for g in range(2, p):
        if pow(g, q, p) == 1:
            return g
    raise ValueError("No generator found – bad parameters")


# === Fiat–Shamir Schnorr classes ===========================================

def _hash_challenge(f: int, y: int, context: str, q: int) -> int:
    """Compute challenge c = H(f || y || context)  mod q."""
    data = f"{f}|{y}|{context}".encode()
    h = hashlib.sha256(data).hexdigest()
    return int(h, 16) % q


class FiatShamirProver:
    """Prover holding secret key x; produces non‑interactive proof."""

    def __init__(self, p: int, q: int, g: int, x: int,
                 context: str = "FiatShamirDemo2025"):
        self.p, self.q, self.g, self.x = p, q, g, x
        self.context = context
        self.y = pow(g, x, p)  # public key

    def prove(self):
        """Return proof (f, r)."""
        s = random.randint(1, self.q - 1)
        f = pow(self.g, s, self.p)
        c = _hash_challenge(f, self.y, self.context, self.q)
        r = (s + c * self.x) % self.q
        return f, r


class FiatShamirVerifier:
    """Verifier who knows only the public key."""

    def __init__(self, p: int, q: int, g: int, y: int,
                 context: str = "FiatShamirDemo2025"):
        self.p, self.q, self.g, self.y = p, q, g, y
        self.context = context

    def verify(self, proof):
        f, r = proof
        # recompute challenge
        c = _hash_challenge(f, self.y, self.context, self.q)
        left = pow(self.g, r, self.p)
        right = (f * pow(self.y, c, self.p)) % self.p
        return left == right


# === Stand‑alone demo =======================================================

def demo():
    print("=== Fiat–Shamir Schnorr Demo ===")
    # 1. Generate common parameters
    p, q = generate_safe_prime(bits=128)
    g = find_generator(p, q)

    # 2. Key generation
    x = random.randint(1, q - 1)  # secret
    y = pow(g, x, p)              # public
    context = "FiatShamirDemo2025"

    # 3. Honest proof
    prover = FiatShamirProver(p, q, g, x, context)
    verifier = FiatShamirVerifier(p, q, g, y, context)

    proof = prover.prove()
    ok = verifier.verify(proof)
    print("[Honest] Verification passed?", ok)

    # 4. Forged proof (attacker guesses)
    fake_f = random.randint(2, p - 2)
    fake_r = random.randint(2, q - 2)
    forged_ok = verifier.verify((fake_f, fake_r))
    print("[Forge ] Verification passed?", forged_ok)

    if ok and not forged_ok:
        print("Demo successful: honest proof accepted, forgery rejected.")


if __name__ == "__main__":
    demo()
