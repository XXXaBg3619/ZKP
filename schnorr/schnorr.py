#ZKP with Schnorr
#Author: 林伯叡、黃杬霆
#Date: 2025/05/08

from sympy import isprime
import random
import os

# ===== 公開參數設定 =====

def generate_safe_prime(bits=8):
    """
    產生一組安全質數 p, q，使得 p = q * r + 1，且 q, p 都是質數
    bits: q 的位元長度
    """
    while True:
        q = random.getrandbits(bits)
        q |= 1  # 確保是奇數
        if isprime(q):
            for r in range(2, 20):
                p = q * r + 1
                if isprime(p):
                    return p, q

# 產生參數 p, q
# 5 → p為2~3位數、8 → p為3~4位數、16 → p為5~6位數、32+ → 高安全性測試用
p, q = generate_safe_prime(bits=16)  

def find_generator(p, q):
    """找一個生成元 g，使得 g^q ≡ 1 mod p"""
    for g in range(2, p):
        if pow(g, q, p) == 1:
            return g
    raise Exception("找不到生成元")

g = find_generator(p, q)
x = random.randint(1, q - 1)
y = pow(g, x, p)

# ===== Schnorr 協定主程式 =====

def schnorr_proof(rounds=100):
    """執行 Schnorr 協定共 rounds 回合，顯示每輪資訊與統計成功次數"""
    logs = []
    success_count = 0

    for i in range(1, rounds + 1):
        s = random.randint(1, q - 1)
        f = pow(g, s, p)
        c = random.randint(1, q - 1)
        r = (s + c * x) % q

        left = pow(g, r, p)
        right = (f * pow(y, c, p)) % p
        passed = left == right
        if passed:
            success_count += 1

        logs.append(f"Round {i}: s={s}, f={f}, c={c}, r={r}, g^r={left}, f*y^c={right}, pass={passed}")

    logs.append(f"\nTotal successful rounds: {success_count}/{rounds}")
    return logs

def write_result(logs, filename="result.txt"):
    """將結果寫入與此 .py 程式同一個資料夾"""
    script_dir = os.path.dirname(os.path.abspath(__file__))  # 此 .py 檔案的所在資料夾
    filepath = os.path.join(script_dir, filename)
    with open(filepath, "w") as f:
        f.write("\n".join(logs))
    print(f"結果已寫入：{filepath}")

# ===== 主程式執行區塊 =====

if __name__ == "__main__":
    result_logs = schnorr_proof(100)
    write_result(result_logs)
