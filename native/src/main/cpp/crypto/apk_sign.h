#pragma once

#include <cstddef>
#include <cstdint>

namespace protector::crypto {

/**
 * SHA-256 of the first APK Signature Scheme v3 (preferred) or v2 signer
 * certificate (X.509 DER). Must match Java {@code ApkSignerCert.sha256Hex}.
 * Opens the APK via {@code openat}/{@code read}/{@code lseek} syscalls
 * (not libc fopen/pread).
 *
 * @return false if the file cannot be read or has no parseable v2/v3 cert
 */
bool apk_first_signer_cert_sha256(const char* apk_path, uint8_t out_digest[32]);

/** Synthetic v2/v3 APKs matching Java {@code ApkSignerCertTest}. */
bool apk_sign_self_test();

} // namespace protector::crypto
