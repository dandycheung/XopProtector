#pragma once

#include "crypto/aes.h"
#include "common/runtime_state.h"
#include "vm/vm_codec.h"
#include "common/log.h"

#include <cstring>
#include <vector>

namespace protector::crypto {

/**
 * Decrypt one code.bin method payload (nonce||ct||tag) into plain Dalvik bytes.
 * If flags&VMP (PVM1), GCM plaintext is a PVM1 image and is unpacked after GCM.
 * TRUE_VMP payloads are decrypted on interpret (LRU), not here.
 */
inline bool decrypt_insns(const uint8_t* enc, size_t enc_len,
                          uint8_t* plain, size_t plain_len,
                          uint32_t method_idx, uint32_t flags,
                          const ShellConfig& cfg) {
    if (enc == nullptr || plain == nullptr || plain_len == 0 || enc_len == 0) {
        return false;
    }
    if (cfg.insns_aes_key.size() != AES_KEY_LEN) {
        return false;
    }
    if ((flags & vm::FLAG_TRUE_VMP) != 0) {
        PLOGE("decrypt_insns called for TRUE_VMP method=%u", method_idx);
        return false;
    }

    if ((flags & vm::FLAG_VMP) == 0) {
        return aes128_gcm_decrypt(cfg.insns_aes_key.data(), enc, enc_len, plain, plain_len);
    }

    // PVM1 packing: GCM plaintext length is 4 + plain_len.
    size_t packed_len = 4 + plain_len;
    if (enc_len < GCM_NONCE_LEN + GCM_TAG_LEN + packed_len) {
        PLOGE("PVM1 GCM package too short method=%u enc=%zu need=%zu",
              method_idx, enc_len, GCM_NONCE_LEN + GCM_TAG_LEN + packed_len);
        return false;
    }
    size_t ct_len = enc_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    if (ct_len != packed_len) {
        PLOGE("PVM1 GCM size mismatch method=%u ct=%zu expect=%zu",
              method_idx, ct_len, packed_len);
        return false;
    }
    std::vector<uint8_t> packed(packed_len);
    if (!aes128_gcm_decrypt(cfg.insns_aes_key.data(), enc, enc_len,
                            packed.data(), packed_len)) {
        return false;
    }
    bool ok = vm::unpack_pvm1(method_idx, packed.data(), packed_len, plain, plain_len);
    memset(packed.data(), 0, packed.size());
    return ok;
}

} // namespace protector::crypto
