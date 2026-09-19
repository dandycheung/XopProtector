#pragma once

#include "common/runtime_state.h"

#include <string>

namespace protector::so {

/**
 * Load assets/protector/sokeys.bin (PSOK) using {@code K_so}.
 * @return false on corrupt/decrypt failure; true if absent (no protect-so) or loaded OK.
 */
bool load_sokeys(const std::string& path, const uint8_t* so_wrap_key);

/** Protector cache dir + optional ApplicationInfo.nativeLibraryDir for pre-decrypt. */
void set_runtime_dirs(const std::string& protector_dir, const std::string& native_lib_dir);

/**
 * From config.json {@code so_decrypt_mode}. Default Eager.
 * Lazy: skip full cold-start materialize; dlopen path decrypts keyed DT_NEEDED closure.
 */
void set_so_decrypt_mode(protector::SoDecryptMode mode);

/** Current mode (default Eager until config is applied). */
protector::SoDecryptMode so_decrypt_mode();

/**
 * Eager: copy each keyed SO into protectorDir/so_plain and decrypt.
 * Lazy: mkdir only on cold start; dlopen path decrypts keyed DT_NEEDED closure.
 * Both modes reuse {@code so_plain/} + {@code so_plain_ready} across launches
 * (plaintext warm). APK stamp invalidation clears the cache on update.
 */
void materialize_decrypted_sos();

/**
 * Eager: preload all keyed so_plain modules (DT_NEEDED order) so linker
 * internal resolves never hit packaged ciphertext.
 * Lazy: only preload mirrors already present in so_plain this process; then
 * schedule background fill of remaining keyed SOs (writes so_plain_ready).
 * Idempotent per process. Call after NativeLibDirRedirect (so_plain fallback).
 */
void preload_so_plain();

/** Install dlopen / android_dlopen_ext hooks to decrypt .text on first load. */
void install_business_so_hooks();

/** True if any business SO keys were loaded. */
bool has_sokeys();

/**
 * Optional AES-128 key for legacy so_warm/ PSW1 (unused when plaintext warm is on).
 */
void set_so_warm_key(const uint8_t key[16]);

/**
 * Decrypt .text of business SOs already mapped into this process.
 * Prefer calling after ClassLoader merge (or on a background thread) so cold
 * start is not blocked; dlopen hooks still cover subsequent loads.
 */
void decrypt_already_loaded_async();

/**
 * Explicit decrypt for a basename (e.g. "libdemo_biz.so") after System.loadLibrary.
 * Needed when linker symbols bypass hooked dlopen/android_dlopen_ext.
 * @return true if the SO is not in the key table, or .text is decrypted successfully;
 *         false if a key exists but decrypt failed / still encrypted.
 */
bool ensure_decrypted(const char* so_basename);

} // namespace protector::so
