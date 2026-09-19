#pragma once

#include <jni.h>
#include <cstdint>

namespace protector::vm {

/**
 * Interpret a prepared TRUE_VMP method.
 * @param args Java Object[] matching static parameters (boxed).
 * @return boxed result, or null for void (caller treats as null).
 */
jobject interpret(JNIEnv* env, int dex_index, uint32_t method_idx, jobjectArray args);

/**
 * Startup no-op besides indexing checks. TRUE_VMP GCM decrypt happens on first
 * {@link interpret} (LRU plaintext window).
 */
bool prepare_true_vmp_images();

/** Wipe decrypted TRUE_VMP images (environment_degraded / re-init). */
void clear_true_vmp_lru();

} // namespace protector::vm
