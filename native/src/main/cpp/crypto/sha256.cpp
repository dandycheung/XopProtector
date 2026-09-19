/**
 * Minimal SHA-256 + HMAC-SHA-256 implementation.
 * Optimised for ARM64; no malloc, no external deps.
 */
#include "crypto/sha256.h"
#include <cstring>
#include <string.h>

namespace protector::crypto {

// ── SHA-256 core ────────────────────────────────────────────────────

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t big32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8)  |
           static_cast<uint32_t>(p[3]);
}

static inline void put_big32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = big32(block + i * 4);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256_init(sha256_ctx* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(sha256_ctx* ctx, const void* data, size_t len) {
    auto* p = static_cast<const uint8_t*>(data);
    size_t idx = static_cast<size_t>(ctx->count & 63);
    ctx->count += static_cast<uint64_t>(len);
    while (len > 0) {
        size_t n = 64 - idx;
        if (n > len) n = len;
        memcpy(ctx->buf + idx, p, n);
        idx += n;
        p += n;
        len -= n;
        if (idx == 64) {
            sha256_transform(ctx->state, ctx->buf);
            idx = 0;
        }
    }
}

void sha256_final(sha256_ctx* ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->count * 8;
    size_t idx = static_cast<size_t>(ctx->count & 63);
    // Padding
    ctx->buf[idx++] = 0x80;
    if (idx > 56) {
        memset(ctx->buf + idx, 0, 64 - idx);
        sha256_transform(ctx->state, ctx->buf);
        idx = 0;
    }
    memset(ctx->buf + idx, 0, 56 - idx);
    put_big32(ctx->buf + 56, static_cast<uint32_t>(bits >> 32));
    put_big32(ctx->buf + 60, static_cast<uint32_t>(bits));
    sha256_transform(ctx->state, ctx->buf);
    for (int i = 0; i < 8; i++) put_big32(digest + i * 4, ctx->state[i]);
}

// ── HMAC-SHA-256 ────────────────────────────────────────────────────

void hmac_sha256_parts(const uint8_t* key, size_t key_len,
                       const void* const* parts, const size_t* lens, size_t nparts,
                       uint8_t mac_out[32]) {
    uint8_t key_block[64] = {0};
    const size_t block_sz = 64;

    if (key_len > block_sz) {
        sha256_ctx ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, key_block);
    } else if (key != nullptr && key_len > 0) {
        memcpy(key_block, key, key_len);
    }

    uint8_t inner_key[64];
    for (int i = 0; i < 64; i++) inner_key[i] = key_block[i] ^ 0x36;

    sha256_ctx inner;
    sha256_init(&inner);
    sha256_update(&inner, inner_key, 64);
    for (size_t i = 0; i < nparts; i++) {
        if (lens[i] == 0) continue;
        sha256_update(&inner, parts[i], lens[i]);
    }
    uint8_t inner_hash[32];
    sha256_final(&inner, inner_hash);

    uint8_t outer_key[64];
    for (int i = 0; i < 64; i++) outer_key[i] = key_block[i] ^ 0x5c;

    sha256_ctx outer;
    sha256_init(&outer);
    sha256_update(&outer, outer_key, 64);
    sha256_update(&outer, inner_hash, 32);
    sha256_final(&outer, mac_out);

    memset(key_block, 0, sizeof(key_block));
    memset(inner_key, 0, sizeof(inner_key));
    memset(outer_key, 0, sizeof(outer_key));
    memset(inner_hash, 0, sizeof(inner_hash));
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const void* data, size_t data_len,
                 uint8_t mac_out[32]) {
    const void* parts[1] = {data};
    size_t lens[1] = {data_len};
    hmac_sha256_parts(key, key_len, parts, lens, 1, mac_out);
}

// ── HKDF-SHA256 (RFC 5869) ──────────────────────────────────────────

static bool hkdf_expand(const uint8_t prk[32],
                        const uint8_t* info, size_t info_len,
                        uint8_t* out, size_t out_len) {
    if (info_len > 4096u) {
        return false;
    }
    uint8_t t[32] = {0};
    size_t t_len = 0;
    size_t filled = 0;
    uint8_t block[32 + 4096 + 1];
    uint8_t n = static_cast<uint8_t>((out_len + 31u) / 32u);
    for (uint8_t i = 1; i <= n; i++) {
        size_t blen = t_len + info_len + 1;
        if (t_len > 0) {
            memcpy(block, t, t_len);
        }
        if (info_len > 0 && info != nullptr) {
            memcpy(block + t_len, info, info_len);
        }
        block[t_len + info_len] = i;
        hmac_sha256(prk, 32, block, blen, t);
        t_len = 32;
        size_t copy = out_len - filled;
        if (copy > 32) copy = 32;
        memcpy(out + filled, t, copy);
        filled += copy;
    }
    memset(t, 0, sizeof(t));
    memset(block, 0, sizeof(block));
    return true;
}

bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len) {
    if (ikm == nullptr && ikm_len != 0) return false;
    if (out == nullptr || out_len == 0 || out_len > HKDF_MAX_OUT_LEN) return false;
    if (salt == nullptr && salt_len != 0) return false;
    if (info == nullptr && info_len != 0) return false;

    uint8_t zero_salt[SHA256_LEN] = {0};
    const uint8_t* salt_ptr = salt;
    size_t salt_n = salt_len;
    if (salt_n == 0) {
        salt_ptr = zero_salt;
        salt_n = SHA256_LEN;
    }

    uint8_t prk[32];
    hmac_sha256(salt_ptr, salt_n, ikm_len == 0 ? nullptr : ikm, ikm_len, prk);

    bool ok = hkdf_expand(prk, info, info_len, out, out_len);
    memset(prk, 0, sizeof(prk));
    memset(zero_salt, 0, sizeof(zero_salt));
    return ok;
}

#define PROT_RODATA __attribute__((section(".rodata.prot"), used))

bool hkdf_self_test() {
    // RFC 5869 A.1
    static const uint8_t kIkm1[22] PROT_RODATA = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t kSalt1[13] PROT_RODATA = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    static const uint8_t kInfo1[10] PROT_RODATA = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    static const uint8_t kOkm1[42] PROT_RODATA = {
        0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,0x2f,0x2a,
        0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,0xec,0xc4,0xc5,0xbf,
        0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65
    };
    uint8_t out1[42];
    if (!hkdf_sha256(kIkm1, sizeof(kIkm1), kSalt1, sizeof(kSalt1),
                     kInfo1, sizeof(kInfo1), out1, sizeof(out1))) {
        return false;
    }
    if (memcmp(out1, kOkm1, sizeof(kOkm1)) != 0) return false;

    // RFC 5869 A.3 — empty salt and info
    static const uint8_t kOkm3[42] PROT_RODATA = {
        0x8d,0xa4,0xe7,0x75,0xa5,0x63,0xc1,0x8f,0x71,0x5f,0x80,0x2a,0x06,0x3c,0x5a,0x31,
        0xb8,0xa1,0x1f,0x5c,0x5e,0xe1,0x87,0x9e,0xc3,0x45,0x4e,0x5f,0x3c,0x73,0x8d,0x2d,
        0x9d,0x20,0x13,0x95,0xfa,0xa4,0xb6,0x1a,0x96,0xc8
    };
    uint8_t out3[42];
    if (!hkdf_sha256(kIkm1, sizeof(kIkm1), nullptr, 0, nullptr, 0, out3, sizeof(out3))) {
        return false;
    }
    if (memcmp(out3, kOkm3, sizeof(kOkm3)) != 0) return false;

    // XopProtector domain-separation fixture (must match HkdfSha256Test)
    uint8_t master[32];
    uint8_t cert[32];
    for (int i = 0; i < 32; i++) {
        master[i] = static_cast<uint8_t>(i);
        cert[i] = static_cast<uint8_t>(0x20 + i);
    }
    static const uint8_t kInfoDex[] PROT_RODATA = {
        // "xop-dex-v1" || "com.yqsh.protectordemo"
        0x78,0x6f,0x70,0x2d,0x64,0x65,0x78,0x2d,0x76,0x31,
        0x63,0x6f,0x6d,0x2e,0x79,0x71,0x73,0x68,0x2e,0x70,
        0x72,0x6f,0x74,0x65,0x63,0x74,0x6f,0x72,0x64,0x65,0x6d,0x6f
    };
    static const uint8_t kDex16[16] PROT_RODATA = {
        0x37,0x7c,0xe3,0xca,0x1c,0xeb,0x73,0xaa,0x03,0x18,0x64,0x37,0x21,0xa0,0xa8,0x4a
    };
    uint8_t dex[16];
    if (!hkdf_sha256(master, 32, cert, 32, kInfoDex, sizeof(kInfoDex), dex, 16)) {
        return false;
    }
    if (memcmp(dex, kDex16, sizeof(kDex16)) != 0) return false;

    static const uint8_t kInfoSo[] PROT_RODATA = {
        // "xop-so-v1" || "com.yqsh.protectordemo"
        0x78,0x6f,0x70,0x2d,0x73,0x6f,0x2d,0x76,0x31,
        0x63,0x6f,0x6d,0x2e,0x79,0x71,0x73,0x68,0x2e,0x70,
        0x72,0x6f,0x74,0x65,0x63,0x74,0x6f,0x72,0x64,0x65,0x6d,0x6f
    };
    static const uint8_t kSo16[16] PROT_RODATA = {
        0x54,0x42,0xb8,0xe8,0xc5,0xac,0x63,0xa1,0x3a,0xdf,0xab,0x1c,0xb0,0x38,0x57,0x85
    };
    uint8_t so[16];
    if (!hkdf_sha256(master, 32, cert, 32, kInfoSo, sizeof(kInfoSo), so, 16)) {
        return false;
    }
    if (memcmp(so, kSo16, sizeof(kSo16)) != 0) return false;

    static const uint8_t kInfoHmac[] PROT_RODATA = {
        // "xop-hmac-v1" || "com.yqsh.protectordemo"
        0x78,0x6f,0x70,0x2d,0x68,0x6d,0x61,0x63,0x2d,0x76,0x31,
        0x63,0x6f,0x6d,0x2e,0x79,0x71,0x73,0x68,0x2e,0x70,
        0x72,0x6f,0x74,0x65,0x63,0x74,0x6f,0x72,0x64,0x65,0x6d,0x6f
    };
    static const uint8_t kHmac32[32] PROT_RODATA = {
        0x91,0x76,0x68,0x23,0xd4,0xae,0x9f,0xea,0xa9,0xd3,0xf8,0xab,0x39,0x0a,0x2e,0x3d,
        0x50,0x4f,0xad,0xe7,0xaf,0xee,0x6b,0x9f,0xfb,0x11,0xec,0x7e,0xae,0x5d,0xe6,0x88
    };
    uint8_t hmac[32];
    if (!hkdf_sha256(master, 32, cert, 32, kInfoHmac, sizeof(kInfoHmac), hmac, 32)) {
        return false;
    }
    if (memcmp(hmac, kHmac32, sizeof(kHmac32)) != 0) return false;

    memset(master, 0, sizeof(master));
    memset(cert, 0, sizeof(cert));
    memset(dex, 0, sizeof(dex));
    memset(so, 0, sizeof(so));
    memset(hmac, 0, sizeof(hmac));
    return true;
}

} // namespace protector::crypto
