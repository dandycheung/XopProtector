#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace protector::dex {

constexpr size_t kMaxMethodsPerClass = 65536;
constexpr size_t kCodeItemFixedSize = 16; // registers..insns_size fields

struct ClassDef {
    uint32_t class_idx_;
    uint32_t access_flags_;
    uint32_t superclass_idx_;
    uint32_t interfaces_off_;
    uint32_t source_file_idx_;
    uint32_t annotations_off_;
    uint32_t class_data_off_;
    uint32_t static_values_off_;
};

struct ClassDataMethod {
    uint32_t method_idx; // absolute after delta accumulate
    uint32_t access_flags;
    uint32_t code_off;
};

struct CodeItemHeader {
    uint16_t registers_size_;
    uint16_t ins_size_;
    uint16_t outs_size_;
    uint16_t tries_size_;
    uint32_t debug_info_off_;
    uint32_t insns_size_; // in 16-bit code units
    uint16_t insns_[];
};

namespace V21 {
struct DexFile {
    void* vtable;
    const uint8_t* begin_;
    size_t size_;
    std::string location_;
    uint32_t location_checksum_;
    void* mem_map_;
    const void* header_;
};
}

namespace V28 {
struct DexFile {
    void* vtable;
    const uint8_t* begin_;
    size_t size_;
    const uint8_t* data_begin_;
    size_t data_size_;
    std::string location_;
    uint32_t location_checksum_;
    const void* header_;
};
}

namespace V35 {
template <typename T>
struct ArrayRef {
    T* array_;
    size_t size_;
};
struct DexFile {
    void* vtable;
    const uint8_t* begin_;
    size_t unused_size_;
    ArrayRef<const uint8_t> data_;
    std::string location_;
    uint32_t location_checksum_;
    const void* header_;
};
}

struct DexView {
    const uint8_t* begin = nullptr;
    size_t size = 0;
    std::string location;
    bool valid = false;
};

/** Probe DexFile by API layout. Uses process_vm_readv so OEM/API 36 mismatch
 *  does not SIGSEGV on std::string copy. Prefers sdk-matched layout; only
 *  falls back on kInvalidLayout (never on kUnsafe). */
DexView probe_dex_file(const void* dex_file, int sdk_level);

/**
 * Read uleb128 with remaining-buffer bound.
 * @return bytes consumed, or 0 on failure (sets *ok=false).
 */
size_t read_uleb128(const uint8_t* data, size_t max_len, uint64_t* val, bool* ok);
size_t skip_fields(const uint8_t* data, size_t max_len, uint64_t count, bool* ok);
size_t read_methods(const uint8_t* data, size_t max_len, ClassDataMethod* out,
                    uint64_t count, bool* ok);

int parse_dex_number(const std::string& location);

/**
 * Integrity v2: every {@code code.bin} (dex, method_idx) must exist as a
 * concrete method ({@code code_off != 0}) in the matching extracted
 * {@code classes*.dex} under {@code protector_dir}. Empty code.bin is OK.
 */
bool verify_code_methods_in_extracted_dexes(const char* protector_dir);

/** Patch all methods of a class (idempotent).
 *  P0: decrypts off the mprotect path, then one RW window per class;
 *  DEX stays RW for a short startup hold before deferred RO. */
void patch_class(const char* descriptor, const void* dex_file, const void* dex_class_def);

/**
 * P1: restore all hollow methods into extracted classes*.dex files under
 * {@code protectorDir} (parallel per file) BEFORE ART maps them.
 * Requires {@link runtime::init_app} already parsed code.bin.
 */
void prepatch_extracted_dexes(const char* protector_dir);

} // namespace protector::dex
