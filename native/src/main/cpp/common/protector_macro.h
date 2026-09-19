#pragma once

#include <unistd.h>
#include <cstdint>
#include <cstring>

// ── Compile-time string obfuscation (Phase 4) ──────────────────────
// Rolling XOR — not crypto; defeats trivial `strings` / fixed-key scans.
// Encode: c[i] = p[i] ^ OBSC_ROLL(i)   where OBSC_ROLL(i) = 0x5A ^ ((i*0x1B)&0xFF)
// Legacy fixed-0x5A blobs still decode if every byte used the old key (i==0 only
// matches); regenerate with scripts/obsc_encode.py after upgrading.

constexpr uint8_t OBSC_ROLL(size_t i) {
    return static_cast<uint8_t>(0x5A ^ ((i * 0x1Bu) & 0xFFu));
}

/** Stack-based rolling XOR decoder.
 *  Rotating thread-local slots so consecutive OBSC_DECODE calls stay valid. */
inline const char* unobsc(const char* obs, size_t len) {
    static thread_local char bufs[8][256];
    static thread_local int slot = 0;
    if (len >= 256) return obs;
    char* buf = bufs[slot++ & 7];
    for (size_t i = 0; i < len; i++) {
        buf[i] = static_cast<char>(static_cast<uint8_t>(obs[i]) ^ OBSC_ROLL(i));
    }
    buf[len] = 0;
    return buf;
}

#define OBSC_LEN(s) (sizeof(s) - 1)
#define OBSC_DECODE(s) unobsc(s, OBSC_LEN(s))

// Encrypted code section — avoid ".rodata.cst*" names: LLD merges those into
// .rodata (SHF_MERGE) and the packer can no longer find a dedicated segment.
#define SECTION_NAME_BITCODE ".bitcode"
#define SECTION_NAME_DATA ".data"
// Writable K_wrap slot. Unique name so LLD will not merge it into .data.
#define SECTION_NAME_PROTWRAP ".protwrap"

#define SECTION(name) __attribute__((section(name)))
#define KEEP_SYMBOL __attribute__((visibility("default")))
#define INIT_ARRAY_SECTION __attribute__((constructor))
#define PROTECTOR_ENCRYPT SECTION(SECTION_NAME_BITCODE)
#define PROTECTOR_DATA_SECTION SECTION(SECTION_NAME_DATA)

inline int get_cache_page_size() {
    static int pagesize = getpagesize();
    return pagesize;
}

#define PROTECTOR_PAGE_MASK (~((get_cache_page_size()) - 1))
#define PROTECTOR_PAGE_START(addr) ((addr) & (uintptr_t)PROTECTOR_PAGE_MASK)

/** Encrypted dexes.zip magic: 'P''D''X''1' */
#define PROTECTOR_DEX_MAGIC0 'P'
#define PROTECTOR_DEX_MAGIC1 'D'
#define PROTECTOR_DEX_MAGIC2 'X'
#define PROTECTOR_DEX_MAGIC3 '1'

/** Encrypted asset blob magic: 'P''A''S''1' */
#define PROTECTOR_ASSET_MAGIC0 'P'
#define PROTECTOR_ASSET_MAGIC1 'A'
#define PROTECTOR_ASSET_MAGIC2 'S'
#define PROTECTOR_ASSET_MAGIC3 '1'

/** HMAC-SHA256 key size for config.json integrity. */
#define PROTECTOR_HMAC_KEY_SIZE 32
