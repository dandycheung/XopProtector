#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace protector::risk {

/**
 * Capture .bitcode after decrypt, apply MADV_DONTDUMP, and remember
 * libprotector load bias for later integrity / anti-dump checks.
 * Call once from init_protector after decrypt_bitcode().
 * HMAC expected value is bound later from config (not an SO-local CRC).
 */
void so_guard_init();

/**
 * Bind {@code config.bitcode_hmac.<abi>} and {@code K_hmac}.
 * If .bitcode is mapped, verifies immediately (false = mismatch, fail closed).
 * If the section address is not resolved yet, stores the expected MAC and
 * returns true (deferred — not a mismatch).
 */
bool so_guard_bind_hmac(const uint8_t* hmac_key, size_t key_len, const std::string& expected_hex);

/** Packed ABI name matching packer {@code lib/<abi>/} (e.g. arm64-v8a). */
const char* so_guard_abi();

/** Sticky fail from bitcode HMAC mismatch (VMP must refuse). */
bool so_guard_integrity_failed();

/**
 * Re-check in-memory .bitcode HMAC against config and scan maps for
 * suspicious RWX / dump tooling touching libprotector.so.
 */
void so_guard_check();

} // namespace protector::risk
