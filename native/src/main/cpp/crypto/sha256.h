/**
 * Minimal SHA-256 + HMAC-SHA-256 + HKDF-SHA256 (RFC 5869).
 * HKDF must match Java {@code CryptoUtils.hkdfSha256}.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

namespace protector::crypto {

struct sha256_ctx {
    uint8_t buf[64];
    uint32_t state[8];
    uint64_t count;
};

void sha256_init(sha256_ctx* ctx);
void sha256_update(sha256_ctx* ctx, const void* data, size_t len);
void sha256_final(sha256_ctx* ctx, uint8_t digest[32]);

/** One-shot SHA-256. */
inline void sha256(const void* data, size_t len, uint8_t digest[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

/**
 * HMAC-SHA-256.
 * @param key      secret key
 * @param key_len  key length in bytes
 * @param data     message (may be nullptr when data_len == 0)
 * @param data_len message length
 * @param mac_out  32-byte output MAC
 */
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const void* data, size_t data_len,
                 uint8_t mac_out[32]);

/** HMAC-SHA256 over concatenated parts (empty / nullptr parts with len 0 skipped). */
void hmac_sha256_parts(const uint8_t* key, size_t key_len,
                       const void* const* parts, const size_t* lens, size_t nparts,
                       uint8_t mac_out[32]);

/** SHA-256 / HMAC-SHA256 digest length. */
constexpr size_t SHA256_LEN = 32;
/** RFC 5869: N = ceil(L / HashLen) must be <= 255. */
constexpr size_t HKDF_MAX_OUT_LEN = 255 * SHA256_LEN;

/**
 * HKDF-SHA256 (RFC 5869 Extract-then-Expand).
 * Must match Java {@code CryptoUtils.hkdfSha256}.
 * {@code salt == nullptr || salt_len == 0} → HashLen zero bytes.
 * {@code info == nullptr || info_len == 0} → empty info.
 * @return false if args invalid or out_len is 0 / too large.
 */
bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);

/** RFC 5869 + XopProtector domain-separation vectors (matches Java tests). */
bool hkdf_self_test();

} // namespace protector::crypto
