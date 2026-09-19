/**
 * Key ladder: recover K_master from .bitcode slot, HKDF domain keys.
 * Layout matches packer KeyLadder.java / SoSectionEncryptor.
 */
#include "crypto/key_ladder.h"
#include "common/protector_macro.h"
#include "crypto/sha256.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/mman.h>

namespace protector::crypto {

namespace {

struct __attribute__((packed)) XopMasterSlot {
    uint8_t magic[16];
    uint8_t wrapped[32];
};

/* Marker XOPKMASTER + 6 zero bytes. Packer scans .bitcode for this blob.
 * Must be const: a writable object in .bitcode makes LLD emit a WX PT_LOAD
 * (W+E load segments are rejected by Android 10+). Runtime still mprotects
 * the page to wipe the slot after recover. */
PROTECTOR_ENCRYPT __attribute__((used))
static const volatile XopMasterSlot g_xop_master = {
        {0x58, 0x4f, 0x50, 0x4b, 0x4d, 0x41, 0x53, 0x54, 0x45, 0x52, 0, 0, 0, 0, 0, 0},
        {0}
};

PROTECTOR_ENCRYPT __attribute__((used))
static const volatile uint8_t g_xop_master_pad[32] = {
        0x91, 0x2e, 0x6b, 0xd4, 0x08, 0x57, 0xc3, 0x1a,
        0xfe, 0x44, 0x80, 0x3d, 0xb9, 0x65, 0x12, 0xac,
        0x37, 0xea, 0x09, 0x7c, 0x51, 0x96, 0x2b, 0xf0,
        0x4d, 0x83, 0x18, 0xce, 0x60, 0xa5, 0x3f, 0x77
};

static bool hkdf_labeled(const uint8_t master[32], const uint8_t cert[32],
                         const char* label, const char* package,
                         uint8_t* out, size_t out_len) {
    if (label == nullptr || package == nullptr || package[0] == 0) {
        return false;
    }
    std::string info;
    info.append(label);
    info.append(package);
    bool ok = hkdf_sha256(master, 32, cert, 32,
                          reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                          out, out_len);
    for (char& c : info) {
        c = 0;
    }
    return ok;
}

} // namespace

bool derive_app_keys(const uint8_t master[32], const uint8_t cert_sha256[32],
                                       const char* package_name, DerivedKeys* out) {
    if (master == nullptr || cert_sha256 == nullptr || out == nullptr || package_name == nullptr
            || package_name[0] == 0) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!hkdf_labeled(master, cert_sha256, "xop-dex-v1", package_name, out->dex, 16)) {
        return false;
    }
    if (!hkdf_labeled(master, cert_sha256, "xop-insn-v1", package_name, out->insn, 16)) {
        return false;
    }
    if (!hkdf_labeled(master, cert_sha256, "xop-so-v1", package_name, out->so, 16)) {
        return false;
    }
    if (!hkdf_labeled(master, cert_sha256, "xop-sowarm-v1", package_name, out->sowarm, 16)) {
        return false;
    }
    if (!hkdf_labeled(master, cert_sha256, "xop-assets-v1", package_name, out->assets, 16)) {
        return false;
    }
    if (!hkdf_labeled(master, cert_sha256, "xop-hmac-v1", package_name, out->hmac, 32)) {
        return false;
    }
    return true;
}

void wipe_k_master_slot() {
    /* Destination must stay volatile: the object is const (so .bitcode stays
     * AX / no WX PT_LOAD). A non-volatile memset through const_cast is UB and
     * Clang/NDK Release will delete it, leaving K_master in the HMAC window. */
    volatile uint8_t* slot = const_cast<uint8_t*>(g_xop_master.wrapped);
    uintptr_t start = PROTECTOR_PAGE_START(reinterpret_cast<uintptr_t>(
            const_cast<uint8_t*>(g_xop_master.wrapped)));
    uintptr_t end = PROTECTOR_PAGE_START(reinterpret_cast<uintptr_t>(
            const_cast<uint8_t*>(g_xop_master.wrapped) + 32) - 1)
            + static_cast<uintptr_t>(get_cache_page_size());
    size_t size = end - start;
    void* page = reinterpret_cast<void*>(start);
    if (mprotect(page, size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        (void)mprotect(page, size, PROT_READ | PROT_WRITE);
    }
    for (int i = 0; i < 32; i++) {
        slot[i] = 0;
    }
    mprotect(page, size, PROT_READ | PROT_EXEC);
    __builtin___clear_cache(reinterpret_cast<char*>(const_cast<uint8_t*>(slot)),
                            reinterpret_cast<char*>(const_cast<uint8_t*>(slot) + 32));
}

bool recover_k_master(uint8_t out[32]) {
    if (out == nullptr) {
        return false;
    }
    bool any = false;
    for (int i = 0; i < 32; i++) {
        uint8_t v = static_cast<uint8_t>(g_xop_master.wrapped[i])
                ^ static_cast<uint8_t>(g_xop_master_pad[i]);
        out[i] = v;
        any = any || (v != 0);
    }
    wipe_k_master_slot();
    return any;
}

bool key_ladder_self_test() {
    uint8_t master[32];
    uint8_t cert[32];
    for (int i = 0; i < 32; i++) {
        master[i] = static_cast<uint8_t>(i);
        cert[i] = static_cast<uint8_t>(0x20 + i);
    }
    DerivedKeys keys{};
    if (!derive_app_keys(master, cert, "com.yqsh.protectordemo", &keys)) {
        return false;
    }
    static const uint8_t kDex[16] = {
            0x37, 0x7c, 0xe3, 0xca, 0x1c, 0xeb, 0x73, 0xaa,
            0x03, 0x18, 0x64, 0x37, 0x21, 0xa0, 0xa8, 0x4a
    };
    static const uint8_t kInsn[16] = {
            0x38, 0xe9, 0xfa, 0xce, 0x9f, 0x71, 0xe9, 0x08,
            0xb8, 0x5c, 0x1e, 0x56, 0x4e, 0xfb, 0x4a, 0x89
    };
    static const uint8_t kSo[16] = {
            0x54, 0x42, 0xb8, 0xe8, 0xc5, 0xac, 0x63, 0xa1,
            0x3a, 0xdf, 0xab, 0x1c, 0xb0, 0x38, 0x57, 0x85
    };
    static const uint8_t kSowarm[16] = {
            0x3e, 0x81, 0x14, 0xe0, 0x44, 0x8f, 0x16, 0x2d,
            0x29, 0x02, 0x63, 0xd2, 0x5c, 0x39, 0xfe, 0xef
    };
    static const uint8_t kAssets[16] = {
            0x86, 0x30, 0x5d, 0x5b, 0x38, 0x7e, 0x54, 0x31,
            0xa8, 0x00, 0x4e, 0x3c, 0x7b, 0xdf, 0xc6, 0x45
    };
    static const uint8_t kHmac[32] = {
            0x91, 0x76, 0x68, 0x23, 0xd4, 0xae, 0x9f, 0xea,
            0xa9, 0xd3, 0xf8, 0xab, 0x39, 0x0a, 0x2e, 0x3d,
            0x50, 0x4f, 0xad, 0xe7, 0xaf, 0xee, 0x6b, 0x9f,
            0xfb, 0x11, 0xec, 0x7e, 0xae, 0x5d, 0xe6, 0x88
    };
    if (memcmp(keys.dex, kDex, 16) != 0) return false;
    if (memcmp(keys.insn, kInsn, 16) != 0) return false;
    if (memcmp(keys.so, kSo, 16) != 0) return false;
    if (memcmp(keys.sowarm, kSowarm, 16) != 0) return false;
    if (memcmp(keys.assets, kAssets, 16) != 0) return false;
    if (memcmp(keys.hmac, kHmac, 32) != 0) return false;
    memset(&keys, 0, sizeof(keys));
    memset(master, 0, sizeof(master));
    return true;
}

} // namespace protector::crypto
