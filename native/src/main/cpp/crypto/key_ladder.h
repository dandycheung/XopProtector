/**
 * Key ladder: K_master (in .bitcode) + cert SHA-256 + package → domain keys.
 * Must match Java {@code KeyLadder}.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace protector::crypto {

struct DerivedKeys {
    uint8_t dex[16];
    uint8_t insn[16];
    uint8_t so[16];
    /** Encrypted so_warm/ cache wrap (label xop-sowarm-v1). */
    uint8_t sowarm[16];
    uint8_t assets[16];
    uint8_t hmac[32];
};

/**
 * HKDF-Expand labels concatenated with package (no separator).
 * {@code cert_sha256} is the 32-byte v2/v3 first-signer digest (salt).
 */
bool derive_app_keys(const uint8_t master[32], const uint8_t cert_sha256[32],
                     const char* package_name, DerivedKeys* out);

/** Copy K_master from the .bitcode slot, XOR pad, then wipe the slot. */
bool recover_k_master(uint8_t out[32]);

/** Zero the in-section master slot (RX→RW→RX). */
void wipe_k_master_slot();

/** Fixture vectors matching Java {@code KeyLadderTest}. */
bool key_ladder_self_test();

} // namespace protector::crypto
