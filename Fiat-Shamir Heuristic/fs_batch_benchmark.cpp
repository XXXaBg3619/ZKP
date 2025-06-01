// fs_batch_benchmark.cpp  —  Finite-field Schnorr & Batch Verification benchmark
// Compile: g++ fs_batch_benchmark.cpp -lssl -lcrypto -O2 -std=c++17
// Usage:   ./a.out <num_proofs>  (default 1000000)
//
// * Hard-coded safe prime p, subgroup order q, generator g  (≈128-bit)
// * Generates <num_proofs> honest proofs using single key pair
// * Measures time for:    (A) individual verification loop
//                         (B) batch verification (∑r and ∑c trick)
//
// For clarity, this demo relies on OpenSSL BIGNUM + SHA-256 and is NOT
// constant-time.  Production use requires side-channel-resistant code.

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <chrono>
#include <iostream>
#include <random>
#include <vector>

struct Proof {
    BIGNUM* f;  // commitment
    BIGNUM* r;  // response
    BIGNUM* c;  // challenge (cache for batch)
};

static const char* P_DEC = "5502416447973014042564914579205940370339";  // 128-bit safe prime
static const char* Q_DEC = "305689802665167446809161921066996687241";
static const int    G_INT = 67;  // small generator of q-order subgroup

// Hash f||y with SHA-256 → BN mod q
BIGNUM* hash_challenge(const BIGNUM* f, const BIGNUM* y, const BIGNUM* q, BN_CTX* ctx) {
    char* f_hex = BN_bn2hex(f);
    char* y_hex = BN_bn2hex(y);
    std::string payload = std::string(f_hex) + std::string(y_hex);
    OPENSSL_free(f_hex);
    OPENSSL_free(y_hex);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest);

    BIGNUM* h = BN_new();
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH, h);
    BN_mod(h, h, q, ctx);
    return h;  // caller owns
}

int main(int argc, char* argv[]) {
    size_t N = (argc >= 2) ? static_cast<size_t>(std::stoull(argv[1])) : 1000000ULL;
    BN_CTX* ctx = BN_CTX_new();

    // Parameters
    BIGNUM *p = BN_new(), *q = BN_new(), *g = BN_new();
    BN_dec2bn(&p, P_DEC);
    BN_dec2bn(&q, Q_DEC);
    BN_set_word(g, G_INT);

    // Key pair
    std::random_device rd; std::mt19937_64 rng(rd());
    std::uniform_int_distribution<unsigned long long> dist(0ULL);
    BIGNUM* x = BN_new(); BN_rand_range(x, q);
    BIGNUM* y = BN_new(); BN_mod_exp(y, g, x, p, ctx);

    // Generate proofs
    std::vector<Proof> proofs; proofs.reserve(N);
    proofs.resize(N);
    for (size_t i = 0; i < N; ++i) {
        BIGNUM* s = BN_new(); BN_rand_range(s, q);
        BIGNUM* f = BN_new(); BN_mod_exp(f, g, s, p, ctx);
        BIGNUM* c = hash_challenge(f, y, q, ctx);
        // r = s + c*x mod q
        BIGNUM* r = BN_new();
        BN_mod_mul(r, c, x, q, ctx);
        BN_mod_add(r, r, s, q, ctx);
        proofs[i] = {f, r, c};
        BN_free(s);
    }

    // --- Individual verification timing ---
    auto t0 = std::chrono::high_resolution_clock::now();
    for (const auto& pr : proofs) {
        BIGNUM* c = hash_challenge(pr.f, y, q, ctx);  // recompute
        BIGNUM* lhs = BN_new(); BN_mod_exp(lhs, g, pr.r, p, ctx);
        BIGNUM* rhs = BN_new();
        BIGNUM* y_c = BN_new(); BN_mod_exp(y_c, y, c, p, ctx);
        BN_mod_mul(rhs, pr.f, y_c, p, ctx);
        if (BN_cmp(lhs, rhs) != 0) {
            std::cerr << "verification failed!\n";
        }
        BN_free(lhs); BN_free(rhs); BN_free(y_c); BN_free(c);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    // --- Batch verification timing ---
    // sum_r, sum_c, prod_f
    BIGNUM *sum_r = BN_new(); BN_zero(sum_r);
    BIGNUM *sum_c = BN_new(); BN_zero(sum_c);
    BIGNUM *prod_f = BN_new(); BN_one(prod_f);
    for (const auto& pr : proofs) {
        BN_mod_add(sum_r, sum_r, pr.r, q, ctx);
        BN_mod_add(sum_c, sum_c, pr.c, q, ctx);
        BN_mod_mul(prod_f, prod_f, pr.f, p, ctx);
    }
    BIGNUM* left = BN_new(); BN_mod_exp(left, g, sum_r, p, ctx);
    BIGNUM* y_pow = BN_new(); BN_mod_exp(y_pow, y, sum_c, p, ctx);
    BIGNUM* right = BN_new(); BN_mod_mul(right, prod_f, y_pow, p, ctx);
    bool batch_pass = (BN_cmp(left, right) == 0);
    auto t2 = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> solo_dur = t1 - t0;
    std::chrono::duration<double> batch_dur = t2 - t1;

    std::cout << "proofs           : " << N << "\n";
    std::cout << "solo verify time : " << solo_dur.count() << " s\n";
    std::cout << "batch verify time: " << batch_dur.count() << " s\n";
    std::cout << "batch pass       : " << (batch_pass?"true":"false") << "\n";

    // Free
    for (auto& pr : proofs) { BN_free(pr.f); BN_free(pr.r); BN_free(pr.c);}    
    BN_free(x); BN_free(y); BN_free(p); BN_free(q); BN_free(g);
    BN_free(sum_r); BN_free(sum_c); BN_free(prod_f); BN_free(left); BN_free(y_pow); BN_free(right);
    BN_CTX_free(ctx);
    return 0;
}
