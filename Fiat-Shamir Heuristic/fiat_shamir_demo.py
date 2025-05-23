# Fiat–Shamir Heuristic – Non-interactive Zero-Knowledge Proof (Schnorr)
# Author: 林伯叡、黃杬霆
# Updated: 2025/05/24 – added logging & image export
#
# This module implements a non-interactive Schnorr identification protocol
# using the Fiat–Shamir heuristic.  Besides the original Prover / Verifier
# API, *demo()* can now save a full execution log to a text file and render
# it as a PNG image, making it convenient to embed in reports or slides.
#
# ---------------------------------------------------------------------------

import hashlib
import random
import textwrap
from pathlib import Path
from sympy import isprime  # noqa: F401

# === Parameter generation ==================================================


def generate_safe_prime(bits: int = 128):
    """Generate a safe prime *p* and its large prime factor *q*.

    *bits* is the bit-length of *q*; use ≥256 in real deployments.
    """
    from sympy import isprime

    while True:
        q = random.getrandbits(bits) | 1  # ensure odd
        if not isprime(q):
            continue
        for r in range(2, 20):  # small co-factor keeps search fast
            p = q * r + 1
            if isprime(p):
                return p, q


def find_generator(p: int, q: int):
    """Return a generator g of the prime-order subgroup of Z_p^×."""
    for g in range(2, p):
        if pow(g, q, p) == 1:
            return g
    raise ValueError("No subgroup generator found – bad (p, q)")


# === Fiat–Shamir Schnorr ====================================================


def _hash_challenge(f: int, y: int, context: str, q: int) -> int:
    data = f"{f}|{y}|{context}".encode()
    h = hashlib.sha256(data).hexdigest()
    return int(h, 16) % q


class FiatShamirProver:
    def __init__(self, p: int, q: int, g: int, x: int, *,
                 context: str = "FiatShamirDemo2025"):
        self.p, self.q, self.g, self.x = p, q, g, x
        self.context = context
        self.y = pow(g, x, p)  # public key

    # ------------------------------------------------------------------
    def prove(self):
        """Return a one-shot proof (f, r)."""
        s = random.randint(1, self.q - 1)
        f = pow(self.g, s, self.p)
        c = _hash_challenge(f, self.y, self.context, self.q)
        r = (s + c * self.x) % self.q
        return f, r


class FiatShamirVerifier:
    def __init__(self, p: int, q: int, g: int, y: int, *,
                 context: str = "FiatShamirDemo2025"):
        self.p, self.q, self.g, self.y = p, q, g, y
        self.context = context

    # ------------------------------------------------------------------
    def verify(self, proof):
        f, r = proof
        c = _hash_challenge(f, self.y, self.context, self.q)
        left = pow(self.g, r, self.p)
        right = (f * pow(self.y, c, self.p)) % self.p
        return left == right


# === Utilities ==============================================================


def _generate_log(p, q, g, x, y, proof, forged, context):
    f, r = proof
    fake_f, fake_r = forged
    c = _hash_challenge(f, y, context, q)
    c_forge = _hash_challenge(fake_f, y, context, q)

    honest_pass = pow(g, r, p) == (f * pow(y, c, p)) % p
    forge_pass = pow(g, fake_r, p) == (fake_f * pow(y, c_forge, p)) % p

    return textwrap.dedent(f"""
        === Fiat–Shamir Schnorr Detailed Log ===
        Parameters:
          p = {p}
          q = {q}
          g = {g}

        Key pair:
          secret x = {x}
          public y = {y}

        --- Honest Prover ---
          commitment f = {f}
          challenge  c = {c}
          response   r = {r}
          pass? {honest_pass}

        --- Forged Attempt ---
          fake_f = {fake_f}
          fake_r = {fake_r}
          challenge  c' = {c_forge}
          pass? {forge_pass}
    """).strip()


# === Demo / script entry-point =============================================


def demo(save_txt: bool = True, save_fig: bool = True,
         out_dir: str | Path = "."):
    """Run an honest proof / forged attempt and (optionally) export logs."""
    print("=== Fiat–Shamir Schnorr Demo ===")

    # 1. set-up
    context = "FiatShamirDemo2025"
    p, q = generate_safe_prime(128)
    g = find_generator(p, q)
    x = random.randint(1, q - 1)
    y = pow(g, x, p)

    prover = FiatShamirProver(p, q, g, x, context=context)
    verifier = FiatShamirVerifier(p, q, g, y, context=context)

    proof = prover.prove()
    honest_ok = verifier.verify(proof)

    fake_f = random.randint(2, p - 2)
    fake_r = random.randint(2, q - 2)
    forged_ok = verifier.verify((fake_f, fake_r))

    print("[Honest] Verification passed?", honest_ok)
    print("[Forge ] Verification passed?", forged_ok)

    # 2. optional artefacts
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    log = _generate_log(p, q, g, x, y, proof, (fake_f, fake_r), context)

    if save_txt:
        txt_path = out_dir / "./Fiat-Shamir Heuristic/fiat_shamir_log.txt"
        txt_path.write_text(log, encoding="utf-8")
        print("Log saved to", txt_path)

    if honest_ok and not forged_ok:
        print("Demo successful: honest proof accepted, forgery rejected.")


if __name__ == "__main__":
    # Run with default export to current directory
    demo()
