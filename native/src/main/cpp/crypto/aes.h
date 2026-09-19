#pragma once

#include <cstddef>
#include <cstdint>

namespace protector::crypto {

constexpr size_t AES_BLOCK = 16;
constexpr size_t AES_KEY_LEN = 16;
constexpr size_t GCM_NONCE_LEN = 12;
constexpr size_t GCM_TAG_LEN = 16;

/** AES-128 encrypt one 16-byte block (big-endian state layout as NIST). */
void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

/**
 * AES-128-CTR with all-zero IV (matches Java AES/CTR/NoPadding + zero IvParameterSpec).
 * In-place OK when in == out.
 */
void aes128_ctr_crypt(const uint8_t key[16], const uint8_t* in, uint8_t* out, size_t len);

/**
 * Decrypt AES-128-GCM package: nonce(12) || ciphertext || tag(16).
 * Returns false on auth failure. plain_len must equal enc_len - 12 - 16.
 */
bool aes128_gcm_decrypt(const uint8_t key[16],
                        const uint8_t* enc, size_t enc_len,
                        uint8_t* plain, size_t plain_len);

/**
 * Encrypt AES-128-GCM package into {@code out}: nonce(12) || ciphertext || tag(16).
 * {@code nonce} must be 12 random bytes (caller-supplied).
 * {@code out_cap} must be &gt;= plain_len + 12 + 16; {@code *out_len} receives package size.
 */
bool aes128_gcm_encrypt(const uint8_t key[16],
                        const uint8_t nonce[12],
                        const uint8_t* plain, size_t plain_len,
                        uint8_t* out, size_t out_cap, size_t* out_len);

/** Verify AES-CTR/GCM against Java javax.crypto + NIST block vector. */
bool aes_self_test();

} // namespace protector::crypto
