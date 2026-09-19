#include "so/business_so.h"
#include "common/elf_util.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "crypto/aes.h"
#include "crypto/rc4.h"

#include "bytehook.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <mutex>
#include <string>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(__ANDROID__)
#include <android/api-level.h>
#include <android/dlext.h>
#include <sys/sendfile.h>
#endif

namespace protector::so {

struct SoKey {
    std::string name;
    uint8_t key[16]{};
    bool decrypted = false;
    bool in_flight = false;
};

static std::mutex g_mu;
static std::condition_variable g_cv;
static std::vector<SoKey> g_keys;
/** Basenames observed via dlopen before sokeys were available. */
static std::vector<std::string> g_pending;
static std::atomic_bool g_hooks_installed{false};
/** True if at least one of dlopen / android_dlopen_ext / __loader_* hooked. */
static std::atomic_bool g_dlopen_hooks_ok{false};
/** Process-local: full keyed materialize already completed successfully. */
static std::atomic_bool g_full_materialize_done{false};
/** Dropped leftover so_plain_ready / keyed mirrors from a previous process. */
static std::atomic_bool g_dropped_stale_mirrors{false};

static bool dlopen_hooks_ok() {
    return g_dlopen_hooks_ok.load(std::memory_order_acquire);
}

/** True after L1/L2 mapped plaintext for this keyed basename (skip in-memory RC4). */
static bool keyed_mapped_plain(const std::string& base);

/** Full keyed materialize into so_plain (eager path). Used by eager mode and as
 *  lazy fallback when dlopen hooks are unavailable (e.g. bytehook INITERR_SIG). */
static void materialize_all_keyed_sos();
static std::atomic_bool g_preload_done{false};
static std::atomic_bool g_fill_started{false};
static std::string g_protector_dir;
static std::string g_native_lib_dir;
/** Default Eager until config.json is applied (Phase 0 wiring). */
static std::atomic<int> g_so_decrypt_mode{static_cast<int>(SoDecryptMode::Eager)};

static constexpr const char* kSoPlainReady = "so_plain_ready";
static constexpr const char* kSoWarmDir = "so_warm";
static constexpr const char* kSoWarmReady = "so_warm_ready";
static constexpr uint8_t kPsw1Magic[4] = {'P', 'S', 'W', '1'};
/** Skip encrypting / hydrating blobs larger than this (avoid peak RAM). */
static constexpr off_t kWarmMaxPlainBytes = 64 * 1024 * 1024;

static uint8_t g_so_warm_key[16]{};
static std::atomic_bool g_so_warm_key_set{false};

void set_so_warm_key(const uint8_t key[16]) {
    if (key == nullptr) {
        g_so_warm_key_set.store(false, std::memory_order_release);
        memset(g_so_warm_key, 0, sizeof(g_so_warm_key));
        return;
    }
    memcpy(g_so_warm_key, key, 16);
    g_so_warm_key_set.store(true, std::memory_order_release);
}

static bool so_warm_key_ok() {
    return g_so_warm_key_set.load(std::memory_order_acquire);
}

void set_runtime_dirs(const std::string& protector_dir, const std::string& native_lib_dir) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!protector_dir.empty()) {
        g_protector_dir = protector_dir;
    }
    if (!native_lib_dir.empty()) {
        g_native_lib_dir = native_lib_dir;
    }
}

void set_so_decrypt_mode(SoDecryptMode mode) {
    g_so_decrypt_mode.store(static_cast<int>(mode), std::memory_order_relaxed);
    PLOGI("business so: so_decrypt_mode=%s",
          mode == SoDecryptMode::Lazy ? "lazy" : "eager");
}

SoDecryptMode so_decrypt_mode() {
    int v = g_so_decrypt_mode.load(std::memory_order_relaxed);
    return v == static_cast<int>(SoDecryptMode::Lazy) ? SoDecryptMode::Lazy
                                                      : SoDecryptMode::Eager;
}

static void maybe_decrypt_by_name(const std::string& base);
static void decrypt_already_loaded();
PROTECTOR_ENCRYPT static bool decrypt_text_on_disk(const std::string& path, const std::string& base);
static SoKey* find_key_unlocked(const std::string& base);
static void ensure_plain_closure_for(const std::string& base);

static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    ifs.seekg(0, std::ios::end);
    auto sz = ifs.tellg();
    if (sz <= 0) return false;
    ifs.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    return static_cast<bool>(ifs.read(reinterpret_cast<char*>(out.data()), sz));
}

static uint16_t ru16(const uint8_t* p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static uint32_t ru32(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static std::string basename_of(const char* path) {
    if (path == nullptr || path[0] == 0) return {};
    const char* base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return std::string(base);
}

bool load_sokeys(const std::string& path, const uint8_t* so_wrap_key) {
    if (so_wrap_key == nullptr) return false;
    std::vector<uint8_t> buf;
    if (!read_file(path, buf) || buf.size() < 4) {
        PLOGI("sokeys.bin absent — business SO protect off");
        return true;
    }
    if (buf[0] != 'P' || buf[1] != 'S' || buf[2] != 'O' || buf[3] != 'K') {
        PLOGE("sokeys bad magic");
        return false;
    }
    const uint8_t* enc = buf.data() + 4;
    size_t enc_len = buf.size() - 4;
    if (enc_len < crypto::GCM_NONCE_LEN + crypto::GCM_TAG_LEN) return false;
    size_t plain_len = enc_len - crypto::GCM_NONCE_LEN - crypto::GCM_TAG_LEN;
    std::vector<uint8_t> plain(plain_len);
    if (!crypto::aes128_gcm_decrypt(so_wrap_key, enc, enc_len, plain.data(), plain_len)) {
        PLOGE("sokeys AES-GCM decrypt failed");
        return false;
    }
    if (plain_len < 4) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    uint32_t count = ru32(plain.data());
    // Bound by remaining bytes (min entry = 2-byte name len + 0 name + 16 key).
    size_t max_by_size = (plain_len - 4) / 18;
    if (count > max_by_size || count > 4096u) {
        PLOGE("sokeys count out of range: %u max=%zu", count, max_by_size);
        memset(plain.data(), 0, plain.size());
        return false;
    }
    size_t cursor = 4;
    std::vector<SoKey> loaded;
    loaded.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        if (cursor + 2 > plain_len) {
            loaded.clear();
            memset(plain.data(), 0, plain.size());
            return false;
        }
        uint16_t nlen = ru16(plain.data() + cursor);
        cursor += 2;
        if (cursor + nlen + 16 > plain_len) {
            loaded.clear();
            memset(plain.data(), 0, plain.size());
            return false;
        }
        SoKey sk;
        sk.name.assign(reinterpret_cast<const char*>(plain.data() + cursor), nlen);
        cursor += nlen;
        memcpy(sk.key, plain.data() + cursor, 16);
        cursor += 16;
        loaded.push_back(std::move(sk));
    }
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_keys.swap(loaded);
    }
    g_cv.notify_all();
    memset(plain.data(), 0, plain.size());
    memset(buf.data(), 0, buf.size());
    PLOGI("sokeys loaded count=%zu", g_keys.size());

    // Flush dlopen observations that happened before keys were ready.
    std::vector<std::string> pending;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        pending.swap(g_pending);
    }
    for (const auto& name : pending) {
        // Closure materialize is for lazy cold start; eager still full-materializes next.
        if (so_decrypt_mode() == SoDecryptMode::Lazy) {
            ensure_plain_closure_for(name);
        }
        maybe_decrypt_by_name(name);
    }
    // Do not block cold start on scanning all already-mapped SOs — caller
    // schedules decrypt_already_loaded_async() after hooks / DexMerger.
    return true;
}

bool has_sokeys() {
    std::lock_guard<std::mutex> lock(g_mu);
    return !g_keys.empty();
}

static SoKey* find_key_unlocked(const std::string& base) {
    for (auto& k : g_keys) {
        if (k.name == base) return &k;
    }
    return nullptr;
}

static int page_mprotect(void* start, size_t size, int prot) {
    int ps = getpagesize();
    uintptr_t s = reinterpret_cast<uintptr_t>(start) & ~static_cast<uintptr_t>(ps - 1);
    uintptr_t e = (reinterpret_cast<uintptr_t>(start) + size + ps - 1)
                  & ~static_cast<uintptr_t>(ps - 1);
    return mprotect(reinterpret_cast<void*>(s), e - s, prot);
}

enum class ClaimResult {
    /** Copied key; caller must decrypt then commit_key. */
    Claimed,
    /** Already decrypted — nothing to do. */
    AlreadyDone,
    /** Not in key table (SO not protected). */
    NotProtected,
};

/**
 * Claim a key for decrypt, or wait until an in-flight decrypt finishes.
 * Copies key material; no SoKey* escapes the lock.
 */
static ClaimResult claim_key(const std::string& base, uint8_t out_key[16]) {
    std::unique_lock<std::mutex> lock(g_mu);
    for (;;) {
        SoKey* key = find_key_unlocked(base);
        if (key == nullptr) return ClaimResult::NotProtected;
        if (key->decrypted) return ClaimResult::AlreadyDone;
        if (!key->in_flight) {
            key->in_flight = true;
            memcpy(out_key, key->key, 16);
            return ClaimResult::Claimed;
        }
        g_cv.wait(lock);
    }
}

static void commit_key(const std::string& base, bool success) {
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(base);
        if (key != nullptr) {
            key->in_flight = false;
            if (success) {
                key->decrypted = true;
            }
        }
    }
    g_cv.notify_all();
}

static bool is_decrypted_unlocked(const std::string& base) {
    SoKey* key = find_key_unlocked(base);
    return key != nullptr && key->decrypted;
}

PROTECTOR_ENCRYPT static bool decrypt_loaded_text(const std::string& so_name) {
    if (so_name.empty()) return true;

    uint8_t key_bytes[16];
    ClaimResult claim = claim_key(so_name, key_bytes);
    if (claim == ClaimResult::NotProtected) return true;

    // L1 / L2-memfd / L2-fd already mapped plaintext — never RC4 the image again.
    if (claim == ClaimResult::AlreadyDone && keyed_mapped_plain(so_name)) {
        return true;
    }

    // Prefer packaged extract mapping when present: so_plain may also appear in
    // maps while the JNI entry still points at ciphertext (API≤23 L2/L3 fallback).
    std::string path;
    bool mapped_plain = false;
    {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp != nullptr) {
            char line[512];
            std::string plain_hit;
            std::string pkg_hit;
            while (fgets(line, sizeof(line), fp) != nullptr) {
                if (strstr(line, "r-xp") == nullptr && strstr(line, "rwxp") == nullptr) {
                    continue;
                }
                char map_path[256] = {0};
#ifdef __LP64__
                if (sscanf(line, "%*llx-%*llx %*s %*llx %*s %*s %255s", map_path) != 1) continue;
#else
                if (sscanf(line, "%*x-%*x %*s %*x %*s %*s %255s", map_path) != 1) continue;
#endif
                const bool memfd = strstr(map_path, "/memfd:") != nullptr;
                const char* base = strrchr(map_path, '/');
                base = base ? base + 1 : map_path;
                bool name_hit = strcmp(base, so_name.c_str()) == 0;
                if (!name_hit && memfd && strncmp(base, "memfd:", 6) == 0) {
                    name_hit = strcmp(base + 6, so_name.c_str()) == 0;
                }
                if (!name_hit) continue;
                if (memfd || strstr(map_path, "/so_plain/") != nullptr) {
                    if (plain_hit.empty()) plain_hit = map_path;
                } else if (pkg_hit.empty()) {
                    pkg_hit = map_path;
                }
            }
            fclose(fp);
            if (!pkg_hit.empty()) {
                path = std::move(pkg_hit);
                mapped_plain = false;
            } else if (!plain_hit.empty()) {
                path = std::move(plain_hit);
                mapped_plain = true;
            }
        }
    }
    if (path.empty()) {
        path = find_so_path(so_name.c_str());
        mapped_plain = path.find("/so_plain/") != std::string::npos;
    }
    if (path.empty()) {
        if (claim == ClaimResult::Claimed) {
            memset(key_bytes, 0, sizeof(key_bytes));
            commit_key(so_name, false);
        }
        PLOGW("business so path missing: %s", so_name.c_str());
        return false;
    }

    if (claim == ClaimResult::AlreadyDone) {
        // Disk mirror is plaintext; if THIS mapping is also so_plain, skip.
        // If linker still mapped packaged ciphertext, force in-memory RC4.
        if (mapped_plain) {
            return true;
        }
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(so_name);
        if (key == nullptr) return true;
        memcpy(key_bytes, key->key, 16);
    }

    bool ok = false;
    uintptr_t bias = 0;
    // Bias from the same path we will decrypt (packaged vs so_plain).
    {
        FILE* fp = fopen("/proc/self/maps", "r");
        if (fp == nullptr) {
            memset(key_bytes, 0, sizeof(key_bytes));
            if (claim == ClaimResult::Claimed) commit_key(so_name, false);
            return false;
        }
        uintptr_t map_start = 0;
        bool found_map = false;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, path.c_str()) == nullptr) continue;
            unsigned long start = 0;
            if (sscanf(line, "%lx-", &start) == 1) {
                map_start = static_cast<uintptr_t>(start);
                found_map = true;
                break;
            }
        }
        fclose(fp);
        if (!found_map) {
            PLOGW("business so load bias missing: %s path=%s", so_name.c_str(), path.c_str());
            memset(key_bytes, 0, sizeof(key_bytes));
            if (claim == ClaimResult::Claimed) commit_key(so_name, false);
            return false;
        }
        uint64_t p_vaddr = 0;
        if (!get_first_pt_load_vaddr(path.c_str(), &p_vaddr)) {
            bias = map_start;
        } else {
            bias = map_start - static_cast<uintptr_t>(p_vaddr);
        }
    }

    // Section headers from the same file that is mapped when possible.
    Elf_Shdr shdr{};
    get_elf_section(&shdr, path.c_str(), ".text");
    if (shdr.sh_size == 0) {
        memset(key_bytes, 0, sizeof(key_bytes));
        if (claim == ClaimResult::Claimed) {
            commit_key(so_name, false);
        }
        return false;
    }
    auto* text = reinterpret_cast<uint8_t*>(bias + shdr.sh_addr);
    if (page_mprotect(text, shdr.sh_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        PLOGW("mprotect RWX failed for %s", so_name.c_str());
        memset(key_bytes, 0, sizeof(key_bytes));
        if (claim == ClaimResult::Claimed) {
            commit_key(so_name, false);
        }
        return false;
    }
    std::vector<uint8_t> tmp(shdr.sh_size);
    struct rc4_state st {};
    rc4_init(&st, key_bytes, 16);
    memset(key_bytes, 0, sizeof(key_bytes));
    rc4_crypt(&st, text, tmp.data(), static_cast<int>(shdr.sh_size));
    memcpy(text, tmp.data(), shdr.sh_size);
    memset(tmp.data(), 0, tmp.size());
    __builtin___clear_cache(reinterpret_cast<char*>(text),
                            reinterpret_cast<char*>(text + shdr.sh_size));
    page_mprotect(text, shdr.sh_size, PROT_READ | PROT_EXEC);
    ok = true;
    PLOGI("decrypted business SO .text: %s bias=0x%zx mapped=%s",
          so_name.c_str(), (size_t)bias, mapped_plain ? "so_plain" : "packaged");
    if (claim == ClaimResult::Claimed) {
        commit_key(so_name, ok);
    }
    return ok;
}

static void maybe_decrypt_by_name(const std::string& base) {
    if (base.empty()) return;
    (void)decrypt_loaded_text(base);
}

/**
 * Android 6 (API≤23) linker rejects app-dir SOs that carry DT_VERNEED against
 * libc ("cannot find libc.so from verneed[0]…"). Clear VERNEEDNUM on so_plain
 * only — higher APIs keep symbol versions unchanged.
 */
static void strip_verneed_if_old_android(const std::string& path) {
#if defined(__ANDROID__)
    if (android_get_device_api_level() > 24) return;
    FILE* fp = fopen(path.c_str(), "r+b");
    if (fp == nullptr) return;
    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
        || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0
        || ehdr.e_phoff == 0
        || ehdr.e_phentsize != sizeof(Elf_Phdr)
        || ehdr.e_phnum == 0) {
        fclose(fp);
        return;
    }
    if (fseek(fp, static_cast<long>(ehdr.e_phoff), SEEK_SET) != 0) {
        fclose(fp);
        return;
    }
#ifdef __LP64__
    using Dyn = Elf64_Dyn;
#else
    using Dyn = Elf32_Dyn;
#endif
    Elf_Off dyn_off = 0;
    size_t dyn_bytes = 0;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        Elf_Phdr ph{};
        if (fread(&ph, 1, sizeof(ph), fp) != sizeof(ph)) break;
        if (ph.p_type == PT_DYNAMIC) {
            dyn_off = ph.p_offset;
            dyn_bytes = static_cast<size_t>(ph.p_filesz);
            break;
        }
    }
    if (dyn_off == 0 || dyn_bytes < sizeof(Dyn)) {
        fclose(fp);
        return;
    }
    const size_t n = dyn_bytes / sizeof(Dyn);
    std::vector<Dyn> dyns(n);
    if (fseek(fp, static_cast<long>(dyn_off), SEEK_SET) != 0
        || fread(dyns.data(), sizeof(Dyn), n, fp) != n) {
        fclose(fp);
        return;
    }
    bool changed = false;
    for (size_t i = 0; i < n; i++) {
        if (dyns[i].d_tag == DT_NULL) break;
        // DT_VERNEEDNUM — zero count disables version-requirement walk.
        if (dyns[i].d_tag == DT_VERNEEDNUM && dyns[i].d_un.d_val != 0) {
            dyns[i].d_un.d_val = 0;
            changed = true;
        }
    }
    if (changed) {
        if (fseek(fp, static_cast<long>(dyn_off), SEEK_SET) == 0
            && fwrite(dyns.data(), sizeof(Dyn), n, fp) == n) {
            fflush(fp);
            PLOGI("business so: stripped DT_VERNEEDNUM for API≤24 %s", path.c_str());
        }
    }
    fclose(fp);
#else
    (void)path;
#endif
}

/**
 * Decrypt .text in the on-disk ELF before the real dlopen runs constructors
 * (DT_INIT / JNI_OnLoad). Post-dlopen memory decrypt is too late for init code.
 * Caller must have Claimed the key (in_flight); this commits on success/failure.
 */
PROTECTOR_ENCRYPT static bool rc4_text_on_disk_claimed(const std::string& path,
                                                       const std::string& base,
                                                       uint8_t key_bytes[16]) {
    Elf_Shdr shdr{};
    get_elf_section(&shdr, path.c_str(), ".text");
    if (shdr.sh_size == 0 || shdr.sh_offset == 0) {
        memset(key_bytes, 0, 16);
        commit_key(base, false);
        return false;
    }

    FILE* fp = fopen(path.c_str(), "r+b");
    if (!fp) {
        PLOGW("pre-decrypt open failed: %s", path.c_str());
        memset(key_bytes, 0, 16);
        commit_key(base, false);
        return false;
    }
    if (fseek(fp, static_cast<long>(shdr.sh_offset), SEEK_SET) != 0) {
        fclose(fp);
        memset(key_bytes, 0, 16);
        commit_key(base, false);
        return false;
    }
    std::vector<uint8_t> buf(static_cast<size_t>(shdr.sh_size));
    if (fread(buf.data(), 1, buf.size(), fp) != buf.size()) {
        fclose(fp);
        memset(key_bytes, 0, 16);
        memset(buf.data(), 0, buf.size());
        commit_key(base, false);
        return false;
    }
    std::vector<uint8_t> plain(buf.size());
    struct rc4_state st {};
    rc4_init(&st, key_bytes, 16);
    memset(key_bytes, 0, 16);
    rc4_crypt(&st, buf.data(), plain.data(), static_cast<int>(plain.size()));
    memset(buf.data(), 0, buf.size());
    if (fseek(fp, static_cast<long>(shdr.sh_offset), SEEK_SET) != 0
        || fwrite(plain.data(), 1, plain.size(), fp) != plain.size()) {
        fclose(fp);
        memset(plain.data(), 0, plain.size());
        commit_key(base, false);
        return false;
    }
    fflush(fp);
    fclose(fp);
    memset(plain.data(), 0, plain.size());
    strip_verneed_if_old_android(path);
    commit_key(base, true);
    PLOGI("pre-decrypted business SO .text on disk: %s", base.c_str());
    return true;
}

PROTECTOR_ENCRYPT static bool decrypt_text_on_disk(const std::string& path,
                                                   const std::string& base) {
    if (path.empty() || path[0] != '/' || base.empty()) return false;

    uint8_t key_bytes[16];
    ClaimResult claim = claim_key(base, key_bytes);
    if (claim == ClaimResult::NotProtected) return true;
    if (claim == ClaimResult::AlreadyDone) {
        // Warm so_plain from an older build may still carry DT_VERNEED.
        strip_verneed_if_old_android(path);
        return true;
    }
    return rc4_text_on_disk_claimed(path, base, key_bytes);
}

static bool file_exists_path(const std::string& path);
static bool copy_file_bytes(const std::string& src, const std::string& dst, bool force = false);
static bool is_system_soname(const std::string& need);
static int scrub_forbidden_from_so_plain(const std::string& out_dir);

/**
 * L1/L2/L3 keyed open plan (docs/so-load-contract.md).
 * L2: linker filename = extract path (dladdr); content = memfd (optional) or
 * so_plain via LIBRARY_FD. L3 keeps the so_plain path as fallback.
 */
struct KeyedOpenPlan {
    std::string base;
    std::string linker_name;
    std::string content_path;
    std::string so_plain_path;
    bool use_library_fd = false;
};

static int g_extract_writable = -1; // -1 unknown, 0 no, 1 yes

/** L2b: stable extract paths for dladdr rewrite (keyed basename → extract abs). */
static std::mutex g_dladdr_mu;
static std::unordered_map<std::string, std::string> g_dladdr_extract;
/** Keyed SOs already mapped from plaintext (L1 / L2 fd / memfd) — skip in-memory RC4. */
static std::unordered_set<std::string> g_fd_mapped_plain;

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
/** Skip memfd copy for huge SOs (path-sensitive megacores); L2 file fd still applies. */
static constexpr off_t kMemfdMaxBytes = 16 * 1024 * 1024;

/**
 * Copy {@code path} into an anonymous memfd. Returns -1 if unsupported, too
 * large, or copy failed — caller then opens so_plain as the L2 fd.
 */
static int create_memfd_from_path(const std::string& path, const char* name) {
#if defined(__ANDROID__) && defined(__NR_memfd_create)
    int src = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (src < 0) return -1;
    struct stat st {};
    if (fstat(src, &st) != 0 || st.st_size <= 0 || st.st_size > kMemfdMaxBytes) {
        close(src);
        return -1;
    }
    const char* tag = (name != nullptr && name[0] != '\0') ? name : "xopso";
    int mfd = static_cast<int>(syscall(__NR_memfd_create, tag, MFD_CLOEXEC));
    if (mfd < 0) {
        close(src);
        return -1;
    }
    off_t copied = 0;
    while (copied < st.st_size) {
        off_t off = copied;
        ssize_t n = sendfile(mfd, src, &off, static_cast<size_t>(st.st_size - copied));
        if (n <= 0) break;
        copied = off;
    }
    if (copied != st.st_size) {
        if (lseek(src, copied, SEEK_SET) < 0 || lseek(mfd, copied, SEEK_SET) < 0) {
            close(src);
            close(mfd);
            return -1;
        }
        char buf[256 * 1024];
        off_t left = st.st_size - copied;
        while (left > 0) {
            size_t want = sizeof(buf) < static_cast<size_t>(left)
                    ? sizeof(buf) : static_cast<size_t>(left);
            ssize_t r = read(src, buf, want);
            if (r <= 0) {
                close(src);
                close(mfd);
                return -1;
            }
            ssize_t w = 0;
            while (w < r) {
                ssize_t k = write(mfd, buf + w, static_cast<size_t>(r - w));
                if (k <= 0) {
                    close(src);
                    close(mfd);
                    return -1;
                }
                w += k;
            }
            left -= r;
        }
    }
    close(src);
    if (lseek(mfd, 0, SEEK_SET) != 0) {
        close(mfd);
        return -1;
    }
    return mfd;
#else
    (void)path;
    (void)name;
    return -1;
#endif
}

static void mark_keyed_mapped_plain(const std::string& base) {
    if (base.empty()) return;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    g_fd_mapped_plain.insert(base);
}

static void unmark_keyed_mapped_plain(const std::string& base) {
    if (base.empty()) return;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    g_fd_mapped_plain.erase(base);
}

static bool keyed_mapped_plain(const std::string& base) {
    if (base.empty()) return false;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    return g_fd_mapped_plain.count(base) != 0;
}

/**
 * Intentionally a no-op under plaintext warm reuse: so_plain mirrors must
 * survive L1/L2 maps so the next process can skip RC4 via so_plain_ready.
 * (PR12 in-process unlink conflicted with cross-launch warm; product chose speed.)
 */
static void maybe_drop_so_plain_mirror(const KeyedOpenPlan& plan) {
    (void)plan;
}

static std::string keyed_soname_from_fname(const char* fname) {
    if (fname == nullptr || fname[0] == '\0') return {};
    const char* memfd = strstr(fname, "/memfd:");
    if (memfd != nullptr) {
        memfd += 7;
        const char* end = memfd;
        while (*end != '\0' && *end != ' ' && *end != ')') {
            ++end;
        }
        return std::string(memfd, static_cast<size_t>(end - memfd));
    }
    return basename_of(fname);
}

static bool extract_dir_writable(const std::string& nld) {
    if (nld.empty()) return false;
    if (g_extract_writable >= 0) return g_extract_writable == 1;
    std::string probe = nld + "/.xop_write_probe";
    FILE* fp = fopen(probe.c_str(), "wb");
    if (fp == nullptr) {
        g_extract_writable = 0;
        return false;
    }
    fclose(fp);
    unlink(probe.c_str());
    g_extract_writable = 1;
    return true;
}

/** Prefer archived packaged bytes (survives L1 extract overwrite) over live nld. */
static std::string keyed_packaged_src(const std::string& name, const std::string& nld) {
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
    }
    if (!cache_root.empty()) {
        std::string cipher = cache_root + "/so_cipher/" + name;
        if (file_exists_path(cipher)) return cipher;
    }
    return nld + "/" + name;
}

static KeyedOpenPlan plan_keyed_open(const std::string& base, const std::string& plain_path) {
    KeyedOpenPlan plan;
    plan.base = base;
    plan.content_path = plain_path;
    plan.linker_name = plain_path;
    plan.so_plain_path = plain_path;
    plan.use_library_fd = false;
    if (base.empty() || plain_path.empty() || !file_exists_path(plain_path)) {
        return plan;
    }
    std::string nld;
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
    }
    if (nld.empty()) {
        PLOGI("business so: load L3 so_plain (no nld) %s", base.c_str());
        return plan;
    }
    std::string extract = nld + "/" + base;
    // L1: publish plaintext onto extract path so dlopen(extract) sees plain +
    // correct path. Archive packaged bytes first so rematerialize still has cipher.
    if (extract_dir_writable(nld) && file_exists_path(extract) && !cache_root.empty()) {
        std::string cipher_dir = cache_root + "/so_cipher";
        mkdir(cipher_dir.c_str(), 0700);
        std::string cipher = cipher_dir + "/" + base;
        bool archived = file_exists_path(cipher)
                || copy_file_bytes(extract, cipher, /*force=*/true);
        if (!archived) {
            PLOGW("business so: L1 cipher archive failed %s — trying L2", base.c_str());
        } else if (copy_file_bytes(plain_path, extract, /*force=*/true)) {
            plan.linker_name = extract;
            plan.content_path = extract;
            plan.use_library_fd = false;
            {
                std::lock_guard<std::mutex> lock(g_dladdr_mu);
                g_dladdr_extract[base] = extract;
            }
            PLOGI("business so: load L1 extract plain %s", base.c_str());
            return plan;
        } else {
            PLOGW("business so: L1 publish failed %s — trying L2", base.c_str());
        }
    }
    // L2: name=extract (dladdr), content=memfd (optional) or so_plain via LIBRARY_FD.
    plan.linker_name = extract;
    plan.content_path = plain_path;
    plan.use_library_fd = true;
    {
        std::lock_guard<std::mutex> lock(g_dladdr_mu);
        g_dladdr_extract[base] = extract;
    }
    PLOGI("business so: load L2 extract-name + LIBRARY_FD %s", base.c_str());
    return plan;
}

#if defined(__ANDROID__)
using AndroidDlopenExtFn = void* (*)(const char*, int, const android_dlextinfo*);

static AndroidDlopenExtFn resolve_android_dlopen_ext() {
    static AndroidDlopenExtFn fn = nullptr;
    static std::once_flag once;
    std::call_once(once, []() {
        // Prefer the linker export — PLT hooks may shadow libc's android_dlopen_ext.
        fn = reinterpret_cast<AndroidDlopenExtFn>(
                dlsym(RTLD_DEFAULT, "__loader_android_dlopen_ext"));
        if (fn == nullptr) {
            fn = reinterpret_cast<AndroidDlopenExtFn>(
                    dlsym(RTLD_NEXT, "android_dlopen_ext"));
        }
        if (fn == nullptr) {
            fn = reinterpret_cast<AndroidDlopenExtFn>(
                    dlsym(RTLD_DEFAULT, "android_dlopen_ext"));
        }
    });
    return fn;
}
#endif

/** Open keyed SO per L1/L2/L3. Does not go through bytehook stubs (avoids recursion). */
static void* dlopen_keyed_plan(const KeyedOpenPlan& plan, int flags,
                               const void* caller_extinfo) {
    if (plan.content_path.empty()) return nullptr;
#if defined(__ANDROID__)
    if (plan.use_library_fd) {
        AndroidDlopenExtFn ext = resolve_android_dlopen_ext();
        if (ext != nullptr) {
            bool used_memfd = false;
            int fd = create_memfd_from_path(plan.content_path, plan.base.c_str());
            if (fd >= 0) {
                used_memfd = true;
            } else {
                fd = open(plan.content_path.c_str(), O_RDONLY | O_CLOEXEC);
            }
            if (fd >= 0) {
                android_dlextinfo info{};
                // Preserve only namespace from caller. Do NOT copy USE_LIBRARY_FD(_OFFSET)
                // — ClassLoader often passes an APK zip fd+offset; mixing that with our
                // so_plain fd makes L2 fail and fall back to L3 (so_plain path → TTIN).
                if (caller_extinfo != nullptr) {
                    const auto* c = reinterpret_cast<const android_dlextinfo*>(caller_extinfo);
                    if ((c->flags & ANDROID_DLEXT_USE_NAMESPACE) != 0 &&
                        c->library_namespace != nullptr) {
                        info.flags |= ANDROID_DLEXT_USE_NAMESPACE;
                        info.library_namespace = c->library_namespace;
                    }
                }
                info.flags |= ANDROID_DLEXT_USE_LIBRARY_FD;
                info.library_fd = fd;
                info.library_fd_offset = 0;
                // Mark before ext() so .init_array / JNI_OnLoad skip in-memory RC4.
                mark_keyed_mapped_plain(plan.base);
                void* h = ext(plan.linker_name.c_str(), flags, &info);
                close(fd);
                if (h != nullptr) {
                    maybe_drop_so_plain_mirror(plan);
                    if (used_memfd) {
                        PLOGI("business so: L2 content=memfd %s", plan.base.c_str());
                    }
                    return h;
                }
                unmark_keyed_mapped_plain(plan.base);
                __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                        "L2 fail %s err=%s — L3", plan.linker_name.c_str(),
                        dlerror());
            } else {
                __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                        "L2 open fd fail %s errno=%d", plan.content_path.c_str(), errno);
            }
        } else {
            __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                    "L2 no android_dlopen_ext — L3");
        }
        // Fall through to L3 direct so_plain dlopen — keep the file.
        return dlopen(plan.content_path.c_str(), flags);
    }
#else
    (void)caller_extinfo;
#endif
    mark_keyed_mapped_plain(plan.base);
    void* h = dlopen(plan.content_path.c_str(), flags);
    if (h != nullptr) {
        // L1: extract holds plaintext; drop the so_plain duplicate. L3 (no nld): keep.
        if (plan.content_path != plan.so_plain_path) {
            maybe_drop_so_plain_mirror(plan);
        }
        return h;
    }
    unmark_keyed_mapped_plain(plan.base);
    return nullptr;
}

static bool file_exists_path(const std::string& path);
static std::vector<std::string> read_dt_needed(const std::string& path);
static void copy_plain_deps(const std::string& out_dir, const std::string& nld);
static bool symlink_plain_dep(const std::string& src, const std::string& dst);

static off_t file_size_path(const std::string& path) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) return -1;
    return st.st_size;
}

static void drop_so_plain_ready(const std::string& out_dir) {
    unlink((out_dir + "/" + kSoPlainReady).c_str());
}

static bool write_so_plain_ready(const std::string& out_dir, size_t count) {
    std::string path = out_dir + "/" + kSoPlainReady;
    FILE* fp = fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        PLOGE("business so: write %s failed errno=%d", kSoPlainReady, errno);
        return false;
    }
    fprintf(fp, "%zu\n", count);
    fflush(fp);
    fclose(fp);
    return true;
}

/** True when so_plain_ready exists and every keyed SO that exists in nld is mirrored. */
static bool so_plain_ready_ok(const std::string& out_dir,
                              const std::string& nld,
                              const std::vector<std::string>& names) {
    if (!file_exists_path(out_dir + "/" + kSoPlainReady)) return false;
    if (names.empty()) return false;
    for (const auto& name : names) {
        std::string src = keyed_packaged_src(name, nld);
        if (!file_exists_path(src)) continue; // other-ABI-only key
        std::string dst = out_dir + "/" + name;
        off_t ds = file_size_path(dst);
        off_t ss = file_size_path(src);
        if (ds <= 0 || ss <= 0 || ds != ss) return false;
    }
    return true;
}

/**
 * Discard leftover keyed mirrors was used when product refused cross-launch
 * plaintext. Plaintext warm restores reuse instead — keep this helper unused
 * (APK stamp still deletes so_plain/ on update).
 */
static void drop_cross_launch_so_plain(const std::string& out_dir,
                                       const std::vector<std::string>& names) {
    (void)out_dir;
    (void)names;
    // no-op: plaintext warm keeps so_plain across launches
}

static std::string so_warm_dir(const std::string& cache_root) {
    return cache_root + "/" + kSoWarmDir;
}

static std::string so_warm_blob_path(const std::string& warm_dir, const std::string& name) {
    return warm_dir + "/" + name + ".w1";
}

static bool read_all_file(const std::string& path, std::vector<uint8_t>* out) {
    if (out == nullptr) return false;
    out->clear();
    FILE* fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) return false;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return false;
    }
    long sz = ftell(fp);
    if (sz < 0 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return false;
    }
    out->resize(static_cast<size_t>(sz));
    size_t n = out->empty() ? 0 : fread(out->data(), 1, out->size(), fp);
    fclose(fp);
    if (n != out->size()) {
        out->clear();
        return false;
    }
    return true;
}

static bool write_all_file_atomic(const std::string& path, const uint8_t* data, size_t len) {
    if (data == nullptr && len != 0) return false;
    std::string tmp = path + ".tmp";
    unlink(tmp.c_str());
    FILE* fp = fopen(tmp.c_str(), "wb");
    if (fp == nullptr) return false;
    bool ok = len == 0 || fwrite(data, 1, len, fp) == len;
    if (ok) {
        fflush(fp);
#if defined(__ANDROID__)
        fsync(fileno(fp));
#endif
    }
    fclose(fp);
    if (!ok) {
        unlink(tmp.c_str());
        return false;
    }
    chmod(tmp.c_str(), 0600);
    unlink(path.c_str());
    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

static bool random_nonce12(uint8_t out[12]) {
    if (out == nullptr) return false;
#if defined(__ANDROID__)
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < 12) {
        ssize_t n = read(fd, out + got, 12 - got);
        if (n <= 0) {
            close(fd);
            return false;
        }
        got += static_cast<size_t>(n);
    }
    close(fd);
    return true;
#else
    for (int i = 0; i < 12; i++) out[i] = static_cast<uint8_t>(i + 1);
    return true;
#endif
}

/**
 * Decrypt PSW1 blob → so_plain/name (ephemeral plaintext for this process).
 * @return true on success or SO not present in warm (caller falls back).
 *         false only when blob exists but is corrupt / auth fails.
 */
static bool try_hydrate_one_from_warm(const std::string& name,
                                      const std::string& warm_dir,
                                      const std::string& plain_dir,
                                      const std::string& nld) {
    if (!so_warm_key_ok() || name.empty() || is_system_soname(name)) return true;
    std::string src = keyed_packaged_src(name, nld);
    if (!file_exists_path(src)) {
        // Other-ABI-only entry.
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key != nullptr) {
            key->decrypted = true;
            key->in_flight = false;
            g_cv.notify_all();
        }
        return true;
    }
    off_t expect = file_size_path(src);
    if (expect <= 0 || expect > kWarmMaxPlainBytes) return true;

    std::string blob = so_warm_blob_path(warm_dir, name);
    std::vector<uint8_t> pkg;
    if (!read_all_file(blob, &pkg)) return true; // miss → cold path
    if (pkg.size() < 4 + 4 + crypto::GCM_NONCE_LEN + crypto::GCM_TAG_LEN) {
        unlink(blob.c_str());
        return false;
    }
    if (memcmp(pkg.data(), kPsw1Magic, 4) != 0) {
        unlink(blob.c_str());
        return false;
    }
    uint32_t plain_size = static_cast<uint32_t>(pkg[4])
            | (static_cast<uint32_t>(pkg[5]) << 8)
            | (static_cast<uint32_t>(pkg[6]) << 16)
            | (static_cast<uint32_t>(pkg[7]) << 24);
    if (static_cast<off_t>(plain_size) != expect
            || pkg.size() != 8 + crypto::GCM_NONCE_LEN + plain_size + crypto::GCM_TAG_LEN) {
        unlink(blob.c_str());
        return false;
    }
    std::vector<uint8_t> plain(plain_size);
    const uint8_t* gcm = pkg.data() + 8;
    size_t gcm_len = pkg.size() - 8;
    if (!crypto::aes128_gcm_decrypt(g_so_warm_key, gcm, gcm_len, plain.data(), plain.size())) {
        PLOGW("business so: so_warm auth fail %s — drop blob", name.c_str());
        unlink(blob.c_str());
        return false;
    }
    mkdir(plain_dir.c_str(), 0700);
    std::string dst = plain_dir + "/" + name;
    if (!write_all_file_atomic(dst, plain.data(), plain.size())) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    chmod(dst.c_str(), 0700);
    memset(plain.data(), 0, plain.size());
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key != nullptr) {
            key->decrypted = true;
            key->in_flight = false;
        }
    }
    g_cv.notify_all();
    return true;
}

/** True when every keyed SO present on this ABI has a valid warm hydrate. */
static bool try_hydrate_all_from_warm(const std::string& cache_root,
                                      const std::string& nld,
                                      const std::vector<std::string>& names) {
    if (!so_warm_key_ok() || cache_root.empty()) return false;
    std::string warm = so_warm_dir(cache_root);
    std::string ready = warm + "/" + kSoWarmReady;
    if (!file_exists_path(ready)) return false;
    std::string plain = cache_root + "/so_plain";
    mkdir(plain.c_str(), 0700);
    int need = 0;
    int ok = 0;
    for (const auto& name : names) {
        if (name.empty() || is_system_soname(name)) continue;
        std::string src = keyed_packaged_src(name, nld);
        if (!file_exists_path(src)) continue;
        off_t ss = file_size_path(src);
        // Oversized blobs are never cached; leave for RC4 / on-demand.
        if (ss <= 0 || ss > kWarmMaxPlainBytes) continue;
        need++;
        std::string blob = so_warm_blob_path(warm, name);
        if (!file_exists_path(blob)) return false;
        if (!try_hydrate_one_from_warm(name, warm, plain, nld)) return false;
        // After hydrate, decrypted flag set only on success path that wrote file.
        {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            if (key != nullptr && key->decrypted) ok++;
        }
    }
    if (need == 0 || ok != need) return false;
    PLOGI("business so: so_warm hydrate ok count=%d", ok);
    return true;
}

static bool persist_one_to_warm(const std::string& name,
                                const std::string& warm_dir,
                                const std::string& plain_path,
                                off_t expect_size) {
    if (!so_warm_key_ok() || name.empty() || is_system_soname(name)) return false;
    if (expect_size <= 0 || expect_size > kWarmMaxPlainBytes) return false;
    if (file_size_path(plain_path) != expect_size) return false;
    std::vector<uint8_t> plain;
    if (!read_all_file(plain_path, &plain) || static_cast<off_t>(plain.size()) != expect_size) {
        return false;
    }
    uint8_t nonce[12];
    if (!random_nonce12(nonce)) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    size_t gcm_cap = crypto::GCM_NONCE_LEN + plain.size() + crypto::GCM_TAG_LEN;
    std::vector<uint8_t> gcm(gcm_cap);
    size_t gcm_len = 0;
    if (!crypto::aes128_gcm_encrypt(g_so_warm_key, nonce, plain.data(), plain.size(),
                                    gcm.data(), gcm.size(), &gcm_len)) {
        memset(plain.data(), 0, plain.size());
        return false;
    }
    memset(plain.data(), 0, plain.size());
    std::vector<uint8_t> pkg(8 + gcm_len);
    memcpy(pkg.data(), kPsw1Magic, 4);
    uint32_t ps = static_cast<uint32_t>(expect_size);
    pkg[4] = static_cast<uint8_t>(ps);
    pkg[5] = static_cast<uint8_t>(ps >> 8);
    pkg[6] = static_cast<uint8_t>(ps >> 16);
    pkg[7] = static_cast<uint8_t>(ps >> 24);
    memcpy(pkg.data() + 8, gcm.data(), gcm_len);
    mkdir(warm_dir.c_str(), 0700);
    std::string blob = so_warm_blob_path(warm_dir, name);
    bool ok = write_all_file_atomic(blob, pkg.data(), pkg.size());
    memset(pkg.data(), 0, pkg.size());
    memset(gcm.data(), 0, gcm.size());
    return ok;
}

static void persist_all_to_warm(const std::string& cache_root,
                                const std::string& nld,
                                const std::vector<std::string>& names) {
    if (!so_warm_key_ok() || cache_root.empty()) return;
    std::string warm = so_warm_dir(cache_root);
    std::string plain = cache_root + "/so_plain";
    mkdir(warm.c_str(), 0700);
    int wrote = 0;
    int skip = 0;
    for (const auto& name : names) {
        if (name.empty() || is_system_soname(name)) continue;
        std::string src = keyed_packaged_src(name, nld);
        if (!file_exists_path(src)) continue;
        off_t ss = file_size_path(src);
        std::string dst = plain + "/" + name;
        bool dec = false;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            dec = key != nullptr && key->decrypted;
        }
        if (!dec || ss <= 0 || ss > kWarmMaxPlainBytes) {
            skip++;
            continue;
        }
        if (persist_one_to_warm(name, warm, dst, ss)) wrote++;
        else skip++;
    }
    // Ready mark only when every on-ABI keyed SO has a blob.
    bool complete = true;
    for (const auto& name : names) {
        if (name.empty() || is_system_soname(name)) continue;
        if (!file_exists_path(keyed_packaged_src(name, nld))) continue;
        off_t ss = file_size_path(keyed_packaged_src(name, nld));
        if (ss <= 0 || ss > kWarmMaxPlainBytes) continue; // optional skip not required
        if (!file_exists_path(so_warm_blob_path(warm, name))) {
            complete = false;
            break;
        }
    }
    if (complete && wrote > 0) {
        char body[32];
        int n = snprintf(body, sizeof(body), "%d\n", wrote);
        if (n > 0) {
            write_all_file_atomic(warm + "/" + kSoWarmReady,
                                  reinterpret_cast<const uint8_t*>(body),
                                  static_cast<size_t>(n));
        }
        PLOGI("business so: so_warm persist wrote=%d skip=%d ready=1", wrote, skip);
    } else {
        unlink((warm + "/" + kSoWarmReady).c_str());
        PLOGI("business so: so_warm persist wrote=%d skip=%d ready=0", wrote, skip);
    }
}

/** Stream-copy src→dst via temp+rename. When force=false, skip if sizes already match. */
static bool copy_file_bytes(const std::string& src, const std::string& dst, bool force) {
    off_t ss = file_size_path(src);
    if (ss <= 0) return false;
    // Already a complete mirror — skip rewrite (plain deps only).
    if (!force && file_size_path(dst) == ss) {
        return true;
    }

    std::string tmp = dst + ".tmp";
    unlink(tmp.c_str());
    FILE* in = fopen(src.c_str(), "rb");
    if (in == nullptr) return false;
    FILE* out = fopen(tmp.c_str(), "wb");
    if (out == nullptr) {
        fclose(in);
        return false;
    }

    char buf[256 * 1024];
    off_t written = 0;
    bool ok = true;
    while (written < ss) {
        size_t want = static_cast<size_t>(std::min<off_t>(sizeof(buf), ss - written));
        size_t n = fread(buf, 1, want, in);
        if (n == 0) {
            ok = false;
            break;
        }
        if (fwrite(buf, 1, n, out) != n) {
            ok = false;
            break;
        }
        written += static_cast<off_t>(n);
    }
    if (ok) {
        fflush(out);
#if defined(__ANDROID__)
        fsync(fileno(out));
#endif
    }
    fclose(out);
    fclose(in);
    if (!ok || written != ss) {
        unlink(tmp.c_str());
        return false;
    }
    chmod(tmp.c_str(), 0700);
    unlink(dst.c_str());
    if (rename(tmp.c_str(), dst.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return file_size_path(dst) == ss;
}

static bool materialize_one_keyed(const std::string& name,
                                  const std::string& out_dir,
                                  const std::string& nld);

/**
 * Copy+RC4 one keyed basename into so_plain if needed.
 * Serializes via claim_key so on-demand and background fill cannot force-copy
 * over each other (or over an already-mapped mirror).
 * @return false only when the SO is keyed, present in nld, and decrypt failed.
 */
static bool materialize_one_keyed(const std::string& name,
                                  const std::string& out_dir,
                                  const std::string& nld) {
    if (name.empty()) return true;
    // Class S: never mirror into so_plain (Conscrypt / GLES collision).
    if (is_system_soname(name)) {
        unlink((out_dir + "/" + name).c_str());
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key != nullptr) {
            key->decrypted = true;
            key->in_flight = false;
            g_cv.notify_all();
        }
        return true;
    }
    if (nld.empty()) {
        PLOGW("business so: materialize_one nld unset for %s", name.c_str());
        return false;
    }
    std::string src = keyed_packaged_src(name, nld);
    std::string dst = out_dir + "/" + name;

    // Other-ABI-only key: nothing on this device.
    if (!file_exists_path(src)) {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(name);
        if (key == nullptr) return true;
        key->decrypted = true;
        key->in_flight = false;
        g_cv.notify_all();
        return true;
    }

    for (int attempt = 0; attempt < 2; attempt++) {
        uint8_t key_bytes[16];
        ClaimResult claim = claim_key(name, key_bytes);
        if (claim == ClaimResult::NotProtected) return true;
        if (claim == ClaimResult::AlreadyDone) {
            if (file_exists_path(dst) && file_size_path(dst) == file_size_path(src)) {
                return true;
            }
            // Marked done but mirror missing/truncated — reclaim and rebuild.
            {
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = false;
                    key->in_flight = false;
                }
            }
            g_cv.notify_all();
            memset(key_bytes, 0, sizeof(key_bytes));
            continue;
        }

        // Claimed: exclusive owner for copy + decrypt.
        mkdir(out_dir.c_str(), 0700);
        const off_t ss = file_size_path(src);
        const off_t ds = file_size_path(dst);
        // Only rewrite when missing or size mismatch — never force-clobber a
        // same-sized file that may already be mmap'd as plaintext (warm reuse).
        const bool need_copy = ds <= 0 || ss <= 0 || ds != ss;
        if (need_copy) {
            if (!copy_file_bytes(src, dst, /*force=*/true)) {
                PLOGW("business so: on-demand copy failed %s", name.c_str());
                memset(key_bytes, 0, sizeof(key_bytes));
                commit_key(name, false);
                return false;
            }
            return rc4_text_on_disk_claimed(dst, name, key_bytes);
        }
        // Same-sized leftover from a prior launch — treat as plaintext warm.
        memset(key_bytes, 0, sizeof(key_bytes));
        commit_key(name, true);
        strip_verneed_if_old_android(dst);
        return true;
    }
    PLOGW("business so: materialize_one give up %s", name.c_str());
    return false;
}

/**
 * Depth-first: materialize keyed DT_NEEDED deps, then the root if keyed.
 * ELF headers are read from packaged nld (ciphertext .text is fine for DYNAMIC).
 * Prevents linker from resolving encrypted deps when a parent loads from /data/app.
 */
static bool materialize_keyed_closure(const std::string& root,
                                      const std::string& out_dir,
                                      const std::string& nld,
                                      std::unordered_set<std::string>& visiting) {
    if (root.empty()) return true;
    if (visiting.count(root)) return true; // cycle
    visiting.insert(root);

    std::string elf_path;
    if (!nld.empty() && file_exists_path(nld + "/" + root)) {
        elf_path = nld + "/" + root;
    } else if (file_exists_path(out_dir + "/" + root)) {
        elf_path = out_dir + "/" + root;
    }

    bool ok = true;
    if (!elf_path.empty()) {
        for (const auto& need : read_dt_needed(elf_path)) {
            bool need_keyed = false;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                need_keyed = find_key_unlocked(need) != nullptr;
            }
            if (!need_keyed) continue;
            if (!materialize_keyed_closure(need, out_dir, nld, visiting)) {
                ok = false;
            }
        }
    }
    visiting.erase(root);

    bool self_keyed = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        self_keyed = find_key_unlocked(root) != nullptr;
    }
    if (self_keyed && !materialize_one_keyed(root, out_dir, nld)) {
        ok = false;
    }
    return ok;
}

/**
 * Lazy path: ensure so_plain has plaintext for {@code base} (if keyed) and all
 * keyed DT_NEEDED deps before the real dlopen/linker resolve.
 */
static void ensure_plain_closure_for(const std::string& base) {
    if (base.empty() || !has_sokeys()) return;
    std::string nld;
    std::string cache_root;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
    }
    if (cache_root.empty()) return;
    std::string out_dir = cache_root + "/so_plain";
    mkdir(out_dir.c_str(), 0700);
    std::unordered_set<std::string> visiting;
    if (!materialize_keyed_closure(base, out_dir, nld, visiting)) {
        PLOGW("business so: keyed closure incomplete for %s", base.c_str());
    }
    if (!nld.empty()) {
        copy_plain_deps(out_dir, nld);
    }
}

/** Create so_plain/name -> nld/name symlink; replace regular-file duplicates. */
static bool symlink_plain_dep(const std::string& src, const std::string& dst) {
    char buf[4096];
    ssize_t n = readlink(dst.c_str(), buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        if (src == buf) return false; // already correct
    }
    struct stat st {};
    if (lstat(dst.c_str(), &st) == 0) {
        unlink(dst.c_str());
    }
    if (symlink(src.c_str(), dst.c_str()) != 0) {
        PLOGW("business so: symlink plain dep failed %s -> %s errno=%d",
              dst.c_str(), src.c_str(), errno);
        return false;
    }
    return true;
}

/**
 * Class S — never plant under so_plain (system/OpenSSL/GLES collision).
 * Keep in sync with packer BusinessSoProtector SYSTEM_SONAME_* lists.
 */
static bool is_system_soname(const std::string& need) {
    if (need.empty()) return false;
    static const char* kExact[] = {
            "libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so",
            "libc++.so", "libstdc++.so",
            "libandroid.so", "libjnigraphics.so",
            "libEGL.so", "libGLESv1_CM.so", "libGLESv2.so", "libGLESv3.so",
            "libOpenSLES.so", "libOpenMAXAL.so",
            "libvulkan.so", "libcamera2ndk.so",
    };
    for (const char* e : kExact) {
        if (need == e) return true;
    }
    if (need.compare(0, 9, "libcrypto") == 0) return true;
    if (need.compare(0, 6, "libssl") == 0) return true;
    if (need.compare(0, 7, "libGLESv") == 0) return true;
    return false;
}

/** Remove Class S leftovers from so_plain (old encrypt-all packages / bad deps). */
static int scrub_forbidden_from_so_plain(const std::string& out_dir) {
    if (out_dir.empty()) return 0;
    DIR* dir = opendir(out_dir.c_str());
    if (dir == nullptr) return 0;
    int n = 0;
    while (dirent* ent = readdir(dir)) {
        if (ent->d_name[0] == '.') continue;
        std::string name = ent->d_name;
        if (name.size() <= 3 || name.compare(name.size() - 3, 3, ".so") != 0) continue;
        if (!is_system_soname(name)) continue;
        std::string path = out_dir + "/" + name;
        if (unlink(path.c_str()) == 0) {
            n++;
            __android_log_print(ANDROID_LOG_WARN, "protector.SoLoad",
                    "scrub Class S from so_plain: %s", name.c_str());
        }
    }
    closedir(dir);
    return n;
}

/**
 * Ensure non-keyed DT_NEEDED deps are visible beside keyed so_plain mirrors as
 * <b>symlinks</b> to the packaged extract (same inode → no dual libc++).
 * Never plant Class S (crypto/GLES/…). Call before keyed dlopen/preload.
 */
static void copy_plain_deps(const std::string& out_dir, const std::string& nld) {
    if (nld.empty() || out_dir.empty()) return;
    scrub_forbidden_from_so_plain(out_dir);
    bool progress = true;
    int linked = 0;
    int refreshed = 0;
    int skipped_sys = 0;
    while (progress) {
        progress = false;
        DIR* dir = opendir(out_dir.c_str());
        if (dir == nullptr) return;
        std::vector<std::string> bases;
        while (dirent* ent = readdir(dir)) {
            if (ent->d_name[0] == '.') continue;
            std::string n = ent->d_name;
            if (n.size() > 3 && n.compare(n.size() - 3, 3, ".so") == 0) {
                bases.push_back(std::move(n));
            }
        }
        closedir(dir);
        for (const auto& base : bases) {
            std::string base_path = out_dir + "/" + base;
            struct stat st {};
            if (lstat(base_path.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
                continue;
            }
            for (const auto& need : read_dt_needed(base_path)) {
                {
                    std::lock_guard<std::mutex> lock(g_mu);
                    if (find_key_unlocked(need) != nullptr) continue;
                }
                if (is_system_soname(need)) {
                    std::string dst = out_dir + "/" + need;
                    if (unlink(dst.c_str()) == 0) skipped_sys++;
                    continue;
                }
                std::string src = nld + "/" + need;
                if (!file_exists_path(src)) continue;
                std::string dst = out_dir + "/" + need;
                if (symlink_plain_dep(src, dst)) {
                    linked++;
                    progress = true;
                }
            }
        }
    }
    DIR* dir = opendir(out_dir.c_str());
    if (dir != nullptr) {
        while (dirent* ent = readdir(dir)) {
            if (ent->d_name[0] == '.') continue;
            std::string n = ent->d_name;
            if (n.size() <= 3 || n.compare(n.size() - 3, 3, ".so") != 0) continue;
            if (is_system_soname(n)) {
                if (unlink((out_dir + "/" + n).c_str()) == 0) skipped_sys++;
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(g_mu);
                if (find_key_unlocked(n) != nullptr) continue;
            }
            std::string src = nld + "/" + n;
            if (!file_exists_path(src)) continue;
            std::string dst = out_dir + "/" + n;
            struct stat lst {};
            if (lstat(dst.c_str(), &lst) == 0 && S_ISREG(lst.st_mode)) {
                if (symlink_plain_dep(src, dst)) refreshed++;
            } else if (lstat(dst.c_str(), &lst) != 0) {
                if (symlink_plain_dep(src, dst)) linked++;
            }
        }
        closedir(dir);
    }
    if (linked > 0 || refreshed > 0 || skipped_sys > 0) {
        PLOGI("business so: plain deps symlink linked=%d refreshed=%d scrub_sys=%d",
              linked, refreshed, skipped_sys);
    }
}

static void materialize_all_keyed_sos() {
    if (!has_sokeys()) return;
    if (g_full_materialize_done.load(std::memory_order_acquire)) {
        PLOGI("business so: full materialize already done this process");
        // Still refresh dep symlinks (GLES blacklist / libc++ links).
        std::string nld;
        std::string cache_root;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            nld = g_native_lib_dir;
            cache_root = g_protector_dir;
        }
        if (!nld.empty() && !cache_root.empty()) {
            copy_plain_deps(cache_root + "/so_plain", nld);
        }
        return;
    }
    auto t0 = std::chrono::steady_clock::now();
    std::string nld;
    std::string cache_root;
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    if (nld.empty() || cache_root.empty()) {
        PLOGW("business so: dirs unset — skip full materialize (nld=%d cache=%d)",
              nld.empty() ? 0 : 1, cache_root.empty() ? 0 : 1);
        return;
    }
    std::string out_dir = cache_root + "/so_plain";
    mkdir(out_dir.c_str(), 0700);
    scrub_forbidden_from_so_plain(out_dir);

    // Warm reuse: prior launch left decrypted mirrors + ready mark.
    if (so_plain_ready_ok(out_dir, nld, names)) {
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (auto& k : g_keys) k.decrypted = true;
        }
        g_cv.notify_all();
        copy_plain_deps(out_dir, nld);
        g_full_materialize_done.store(true, std::memory_order_release);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        PLOGI("business so: reuse so_plain count=%zu cost_ms=%lld", names.size(),
              static_cast<long long>(ms));
        return;
    }

    std::atomic<int> ok{0};
    std::atomic<int> fail{0};
    unsigned hw = std::thread::hardware_concurrency();
    unsigned workers = hw == 0 ? 2u : std::min(2u, hw);
    if (names.size() < workers) workers = static_cast<unsigned>(std::max<size_t>(1, names.size()));

    auto worker = [&](size_t begin, size_t end) {
        for (size_t i = begin; i < end; i++) {
            const std::string& name = names[i];
            if (is_system_soname(name)) {
                unlink((out_dir + "/" + name).c_str());
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = true;
                    key->in_flight = false;
                }
                ok.fetch_add(1);
                continue;
            }
            std::string src = keyed_packaged_src(name, nld);
            std::string dst = out_dir + "/" + name;
            if (!file_exists_path(src)) {
                // Basename in sokeys from another ABI only — nothing to decrypt here.
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = true;
                    key->in_flight = false;
                }
                ok.fetch_add(1);
                continue;
            }
            // Skip when this process already decrypted and mirror size matches.
            // Cross-launch warm hits so_plain_ready_ok before the worker pool.
            // Cold start without ready: always recopy from packaged ciphertext
            // so leftover plaintext is never RC4'd a second time.
            const off_t ss = file_size_path(src);
            bool already = false;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                already = key != nullptr && key->decrypted;
            }
            if (already && ss > 0 && file_size_path(dst) == ss) {
                ok.fetch_add(1);
                continue;
            }
            if (!copy_file_bytes(src, dst, /*force=*/true)) {
                fail.fetch_add(1);
                PLOGW("business so: materialize copy failed %s", name.c_str());
                continue;
            }
            {
                std::lock_guard<std::mutex> lock(g_mu);
                SoKey* key = find_key_unlocked(name);
                if (key != nullptr) {
                    key->decrypted = false;
                    key->in_flight = false;
                }
            }
            g_cv.notify_all();
            if (decrypt_text_on_disk(dst, name)) {
                ok.fetch_add(1);
            } else {
                fail.fetch_add(1);
                PLOGW("business so: materialize decrypt failed %s", name.c_str());
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(workers);
    size_t chunk = (names.size() + workers - 1) / workers;
    for (unsigned w = 0; w < workers; w++) {
        size_t begin = static_cast<size_t>(w) * chunk;
        if (begin >= names.size()) break;
        size_t end = std::min(names.size(), begin + chunk);
        threads.emplace_back(worker, begin, end);
    }
    for (auto& th : threads) th.join();

    // Retry any keyed SO that did not decrypt (parallel IO can flake on some devices).
    std::vector<std::string> retry;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (const auto& k : g_keys) {
            if (!k.decrypted) retry.push_back(k.name);
        }
    }
    for (const auto& name : retry) {
        std::string src = keyed_packaged_src(name, nld);
        std::string dst = out_dir + "/" + name;
        if (!file_exists_path(src)) {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            if (key != nullptr) {
                key->decrypted = true;
                key->in_flight = false;
            }
            continue;
        }
        if (!copy_file_bytes(src, dst, /*force=*/true)) {
            PLOGE("business so: materialize retry copy failed %s", name.c_str());
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(g_mu);
            SoKey* key = find_key_unlocked(name);
            if (key != nullptr) {
                key->decrypted = false;
                key->in_flight = false;
            }
        }
        g_cv.notify_all();
        if (!decrypt_text_on_disk(dst, name)) {
            PLOGE("business so: materialize retry failed %s", name.c_str());
        }
    }

    int ok_n = 0;
    int fail_n = 0;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (const auto& k : g_keys) {
            if (k.decrypted) ok_n++;
            else fail_n++;
        }
    }
    // Persist reuse mark whenever every keyed SO was decrypted (ignore plain-dep extras).
    if (fail_n == 0 && ok_n > 0) {
        if (!write_so_plain_ready(out_dir, static_cast<size_t>(ok_n))) {
            PLOGE("business so: so_plain_ready not written (warm reuse disabled)");
        } else {
            g_full_materialize_done.store(true, std::memory_order_release);
        }
    } else {
        drop_so_plain_ready(out_dir);
        if (fail_n > 0) {
            PLOGE("business so: materialize incomplete ok=%d fail=%d (no warm reuse)",
                  ok_n, fail_n);
        }
    }
    // Copy plaintext DT_NEEDED deps into so_plain so ClassLoader-only dir still resolves.
    copy_plain_deps(out_dir, nld);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
    PLOGI("business so: materialize so_plain ok=%d fail=%d workers=%u cost_ms=%lld",
          ok_n, fail_n, workers, static_cast<long long>(ms));
}

void materialize_decrypted_sos() {
    if (!has_sokeys()) return;
    auto t0 = std::chrono::steady_clock::now();
    const bool lazy = so_decrypt_mode() == SoDecryptMode::Lazy;
    PLOGI("business so: materialize begin mode=%s", lazy ? "lazy" : "eager");
    std::string nld;
    std::string cache_root;
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    if (nld.empty() || cache_root.empty()) {
        PLOGW("business so: dirs unset — skip materialize (nld=%d cache=%d)",
              nld.empty() ? 0 : 1, cache_root.empty() ? 0 : 1);
        return;
    }
    std::string out_dir = cache_root + "/so_plain";
    mkdir(out_dir.c_str(), 0700);

    // Warm reuse: prior launch left decrypted mirrors + ready mark
    // (eager cold start, or Phase 3 background fill under lazy).
    if (so_plain_ready_ok(out_dir, nld, names)) {
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (auto& k : g_keys) k.decrypted = true;
        }
        g_cv.notify_all();
        copy_plain_deps(out_dir, nld);
        g_full_materialize_done.store(true, std::memory_order_release);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        PLOGI("business so: reuse so_plain count=%zu cost_ms=%lld", names.size(),
              static_cast<long long>(ms));
        return;
    }

    // Lazy cold start: do not RC4 the full keyed set; dlopen path materializes
    // a keyed DT_NEEDED closure on demand. Never write so_plain_ready here.
    // If dlopen hooks failed (see install_business_so_hooks / preload), we force
    // materialize_all_keyed_sos() as a fallback so ClassLoader never maps ciphertext.
    if (lazy) {
        drop_so_plain_ready(out_dir);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        PLOGI("business so: lazy skip full materialize keyed=%zu hooks_ok=%d cost_ms=%lld",
              names.size(), dlopen_hooks_ok() ? 1 : 0, static_cast<long long>(ms));
        return;
    }

    materialize_all_keyed_sos();
}

/** Read DT_NEEDED basenames from an on-disk ELF (empty on parse failure).
 *  Streams headers only — must not mmap/slurp multi-100MB SOs (e.g. libd3). */
static std::vector<std::string> read_dt_needed(const std::string& path) {
    std::vector<std::string> out;
    FILE* fp = fopen(path.c_str(), "rb");
    if (fp == nullptr) return out;

    Elf_Ehdr eh{};
    if (fread(&eh, 1, sizeof(eh), fp) != sizeof(eh)
        || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0
        || eh.e_phoff == 0 || eh.e_phnum == 0
        || eh.e_phentsize != sizeof(Elf_Phdr)) {
        fclose(fp);
        return out;
    }

    std::vector<Elf_Phdr> ph(eh.e_phnum);
    if (fseek(fp, static_cast<long>(eh.e_phoff), SEEK_SET) != 0
        || fread(ph.data(), sizeof(Elf_Phdr), eh.e_phnum, fp) != eh.e_phnum) {
        fclose(fp);
        return out;
    }

    const Elf_Phdr* dyn = nullptr;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = &ph[i];
            break;
        }
    }
    if (dyn == nullptr || dyn->p_filesz == 0 || dyn->p_filesz > 16 * 1024 * 1024) {
        fclose(fp);
        return out;
    }

#ifdef __LP64__
    using Dyn = Elf64_Dyn;
#else
    using Dyn = Elf32_Dyn;
#endif
    std::vector<Dyn> dyns(dyn->p_filesz / sizeof(Dyn));
    if (dyns.empty()
        || fseek(fp, static_cast<long>(dyn->p_offset), SEEK_SET) != 0
        || fread(dyns.data(), sizeof(Dyn), dyns.size(), fp) != dyns.size()) {
        fclose(fp);
        return out;
    }

    uint64_t strtab_vaddr = 0;
    for (const auto& d : dyns) {
        if (d.d_tag == DT_NULL) break;
        if (d.d_tag == DT_STRTAB) {
            strtab_vaddr = d.d_un.d_ptr;
            break;
        }
    }
    if (strtab_vaddr == 0) {
        fclose(fp);
        return out;
    }

    uint64_t strtab_off = 0;
    bool mapped = false;
    for (uint16_t i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;
        uint64_t v0 = ph[i].p_vaddr;
        uint64_t v1 = v0 + ph[i].p_filesz;
        if (strtab_vaddr >= v0 && strtab_vaddr < v1) {
            strtab_off = ph[i].p_offset + (strtab_vaddr - v0);
            mapped = true;
            break;
        }
    }
    if (!mapped) {
        fclose(fp);
        return out;
    }

    for (const auto& d : dyns) {
        if (d.d_tag == DT_NULL) break;
        if (d.d_tag != DT_NEEDED) continue;
        uint64_t off = strtab_off + d.d_un.d_val;
        if (fseek(fp, static_cast<long>(off), SEEK_SET) != 0) continue;
        char name[256];
        size_t len = 0;
        while (len + 1 < sizeof(name)) {
            int c = fgetc(fp);
            if (c == EOF || c == 0) break;
            name[len++] = static_cast<char>(c);
        }
        name[len] = 0;
        if (len > 0) {
            out.emplace_back(name, len);
        }
    }
    fclose(fp);
    return out;
}

static bool file_exists_path(const std::string& path) {
    struct stat st {};
    return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

/**
 * Depth-first load so DT_NEEDED never falls through to encrypted extract
 * copies (linker internal resolve bypasses dlopen hooks). Keyed SOs use L1/L2/L3.
 */
static void preload_one(const std::string& plain_dir,
                        const std::string& base,
                        std::unordered_set<std::string>& visiting,
                        std::unordered_set<std::string>& loaded,
                        int& ok,
                        int& fail) {
    if (base.empty() || loaded.count(base)) return;
    if (visiting.count(base)) return; // cycle
    if (is_system_soname(base)) return; // Class S — never pin from so_plain
    std::string path = plain_dir + "/" + base;
    if (!file_exists_path(path)) return; // system / absent dep — let linker resolve

    visiting.insert(base);
    for (const auto& need : read_dt_needed(path)) {
        preload_one(plain_dir, need, visiting, loaded, ok, fail);
    }
    bool keyed = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        keyed = find_key_unlocked(base) != nullptr;
    }
    void* h = nullptr;
    if (keyed) {
        KeyedOpenPlan plan = plan_keyed_open(base, path);
        h = dlopen_keyed_plan(plan, RTLD_NOW | RTLD_GLOBAL, nullptr);
    } else {
        h = dlopen(path.c_str(), RTLD_NOW | RTLD_GLOBAL);
    }
    visiting.erase(base);
    if (h != nullptr) {
        loaded.insert(base);
        ok++;
    } else {
        fail++;
        PLOGW("business so: preload failed %s: %s", base.c_str(), dlerror());
    }
}

/**
 * Phase 3 (lazy only): after bootstrap, fill remaining keyed SOs into so_plain
 * on a low-priority thread. On full success writes so_plain_ready for warm reuse.
 * Idempotent per process; no-op when already ready or mode is eager.
 */
static void fill_so_plain_async() {
    if (so_decrypt_mode() != SoDecryptMode::Lazy) return;
    if (!has_sokeys()) return;

    std::string nld;
    std::string cache_root;
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
        cache_root = g_protector_dir;
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    if (nld.empty() || cache_root.empty() || names.empty()) {
        PLOGW("business so: background fill skipped (dirs/keys unset)");
        return;
    }
    std::string out_dir = cache_root + "/so_plain";
    if (so_plain_ready_ok(out_dir, nld, names)) {
        PLOGI("business so: background fill skip — so_plain_ready already ok");
        return;
    }

    bool expected = false;
    if (!g_fill_started.compare_exchange_strong(expected, true)) return;

    std::thread([nld, names, out_dir]() {
#if defined(__ANDROID__)
        // Lower *this thread* only — PRIO_PROCESS with who=0 would renice the app.
        const pid_t tid = static_cast<pid_t>(syscall(__NR_gettid));
        if (tid > 0) {
            setpriority(PRIO_PROCESS, tid, 10);
        }
#endif
        auto t0 = std::chrono::steady_clock::now();
        mkdir(out_dir.c_str(), 0700);

        // Snapshot which still need work (on-demand may have finished some).
        std::vector<std::string> pending;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (const auto& k : g_keys) {
                if (!k.decrypted) pending.push_back(k.name);
            }
        }

        std::atomic<int> ok{0};
        std::atomic<int> fail{0};
        if (!pending.empty()) {
            unsigned hw = std::thread::hardware_concurrency();
            unsigned workers = hw == 0 ? 2u : std::min(2u, hw);
            if (pending.size() < workers) {
                workers = static_cast<unsigned>(std::max<size_t>(1, pending.size()));
            }
            auto worker = [&](size_t begin, size_t end) {
                for (size_t i = begin; i < end; i++) {
                    if (materialize_one_keyed(pending[i], out_dir, nld)) {
                        ok.fetch_add(1);
                    } else {
                        fail.fetch_add(1);
                    }
                }
            };
            std::vector<std::thread> threads;
            threads.reserve(workers);
            size_t chunk = (pending.size() + workers - 1) / workers;
            for (unsigned w = 0; w < workers; w++) {
                size_t begin = static_cast<size_t>(w) * chunk;
                if (begin >= pending.size()) break;
                size_t end = std::min(pending.size(), begin + chunk);
                threads.emplace_back(worker, begin, end);
            }
            for (auto& th : threads) th.join();
        }

        // Retry failures once (flaky IO).
        std::vector<std::string> retry;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (const auto& k : g_keys) {
                if (!k.decrypted) retry.push_back(k.name);
            }
        }
        for (const auto& name : retry) {
            (void)materialize_one_keyed(name, out_dir, nld);
        }

        copy_plain_deps(out_dir, nld);

        int ok_n = 0;
        int fail_n = 0;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            for (const auto& k : g_keys) {
                if (k.decrypted) ok_n++;
                else fail_n++;
            }
        }

        bool mirrors_ok = fail_n == 0 && ok_n > 0;
        if (mirrors_ok) {
            for (const auto& name : names) {
                std::string src = keyed_packaged_src(name, nld);
                if (!file_exists_path(src)) continue; // other-ABI-only key
                off_t ds = file_size_path(out_dir + "/" + name);
                off_t ss = file_size_path(src);
                if (ds <= 0 || ss <= 0 || ds != ss) {
                    mirrors_ok = false;
                    break;
                }
            }
        }

        if (mirrors_ok) {
            if (!write_so_plain_ready(out_dir, static_cast<size_t>(ok_n))) {
                PLOGE("business so: background fill so_plain_ready write failed");
            } else {
                PLOGI("business so: background fill ready ok=%d", ok_n);
            }
        } else {
            drop_so_plain_ready(out_dir);
            PLOGW("business so: background fill incomplete ok=%d fail=%d (no ready)",
                  ok_n, fail_n);
        }

        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        PLOGI("business so: background fill done pending=%zu workers_ok=%d "
              "workers_fail=%d final_ok=%d final_fail=%d cost_ms=%lld",
              pending.size(), ok.load(), fail.load(), ok_n, fail_n,
              static_cast<long long>(ms));
    }).detach();
}

void preload_so_plain() {
    bool expected = false;
    if (!g_preload_done.compare_exchange_strong(expected, true)) {
        return; // already done this process
    }
    if (!has_sokeys()) return;
    const bool lazy = so_decrypt_mode() == SoDecryptMode::Lazy;
    const bool hooks = dlopen_hooks_ok();
    PLOGI("business so: preload begin mode=%s hooks_ok=%d",
          lazy ? "lazy" : "eager", hooks ? 1 : 0);
    auto t0 = std::chrono::steady_clock::now();
    std::string cache_root;
    std::vector<std::string> keyed;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
        keyed.reserve(g_keys.size());
        for (const auto& k : g_keys) keyed.push_back(k.name);
    }
    if (cache_root.empty()) return;
    std::string plain_dir = cache_root + "/so_plain";
    std::string nld;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        nld = g_native_lib_dir;
    }

    std::unordered_set<std::string> visiting;
    std::unordered_set<std::string> loaded;
    int ok = 0;
    int fail = 0;
    int skipped_missing = 0;

    // Lazy without working dlopen hooks cannot decrypt on demand — ClassLoader
    // falls through to packaged ciphertext and SIGILL (seen on Hi-MC/libcpbase).
    if (lazy && !hooks) {
        PLOGW("business so: lazy preload — dlopen hooks missing, force full materialize");
        materialize_all_keyed_sos();
        // Continue with eager-style pin below.
    } else if (lazy) {
        // Dep symlinks / GLES scrub before any pin.
        copy_plain_deps(plain_dir, nld);
        // Phase 2: do not force-dlopen every keyed SO. Only pin mirrors already
        // materialized this process (on-demand). Missing libs decrypt on first
        // hooked dlopen via keyed DT_NEEDED closure.
        for (const auto& name : keyed) {
            if (!file_exists_path(plain_dir + "/" + name)) {
                skipped_missing++;
                continue;
            }
            preload_one(plain_dir, name, visiting, loaded, ok, fail);
        }
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - t0)
                          .count();
        PLOGI("business so: lazy preload existing ok=%d fail=%d present=%d "
              "skipped_missing=%d keyed=%zu cost_ms=%lld",
              ok, fail, ok + fail, skipped_missing, keyed.size(),
              static_cast<long long>(ms));
        // Phase 3: finish remaining keyed SOs off the critical path this process.
        fill_so_plain_async();
        return;
    }

    // Dep symlinks must exist before keyed dlopen (avoid dual GLES / missing libc++).
    copy_plain_deps(plain_dir, nld);

    // Eager (or lazy fallback): pin every encrypted SO from so_plain.
    for (const auto& name : keyed) {
        preload_one(plain_dir, name, visiting, loaded, ok, fail);
    }
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
    PLOGI("business so: preload keyed ok=%d fail=%d keyed=%zu cost_ms=%lld",
          ok, fail, keyed.size(), static_cast<long long>(ms));
}

/**
 * Return path that real dlopen should use. Protected SOs are always mirrored into
 * a writable protector cache and decrypted there — avoids read-only /data/app lib
 * trees and stale page-cache issues so JNI_OnLoad / .init_array see plaintext.
 */
static std::string path_for_dlopen(const char* filename) {
    if (filename == nullptr || filename[0] == '\0') return {};
    if (!has_sokeys()) return filename;
    std::string base = basename_of(filename);
    if (base.empty()) return filename;

    // Class S: never rewrite to so_plain; let linker use system/Apex/extract.
    if (is_system_soname(base)) {
        std::string cache_root;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            cache_root = g_protector_dir;
            SoKey* key = find_key_unlocked(base);
            if (key != nullptr) {
                key->decrypted = true;
                key->in_flight = false;
            }
        }
        g_cv.notify_all();
        if (!cache_root.empty()) {
            unlink((cache_root + "/so_plain/" + base).c_str());
        }
        return filename;
    }

    const bool lazy = so_decrypt_mode() == SoDecryptMode::Lazy;
    // Lazy: materialize keyed self + DT_NEEDED closure even when the parent SO
    // itself is not encrypted (linker resolves deps without hooked dlopen).
    if (lazy) {
        ensure_plain_closure_for(base);
    }

    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (find_key_unlocked(base) == nullptr) {
            return filename; // not protected (deps already handled when lazy)
        }
    }

    std::string cache_root;
    std::string nld;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        cache_root = g_protector_dir;
        nld = g_native_lib_dir;
    }
    std::string plain_dir = cache_root.empty() ? std::string() : (cache_root + "/so_plain");
    std::string cache = plain_dir.empty() ? std::string() : (plain_dir + "/" + base);

    // Already pointing at the decrypted mirror — never RC4 twice (RC4 is involution).
    if (!cache.empty() && filename[0] == '/' && std::string(filename) == cache) {
        bool done = false;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            done = is_decrypted_unlocked(base);
        }
        if (done || decrypt_text_on_disk(cache, base)) {
            return cache;
        }
        PLOGE("business so: refuse ciphertext dlopen (so_plain decrypt failed) %s",
              base.c_str());
        return {};
    }
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (!cache.empty() && is_decrypted_unlocked(base)) {
            // file_exists checked outside — path stable after materialize
        } else {
            goto need_mirror;
        }
    }
    if (file_exists_path(cache)) {
        return cache;
    }
need_mirror:

    // Lazy: exclusive materialize (claim + conditional copy) — avoid racing a
    // force rewrite against background fill / an already-mapped so_plain file.
    if (lazy && !cache_root.empty() && !nld.empty() && !plain_dir.empty()) {
        if (materialize_one_keyed(base, plain_dir, nld)) {
            if (file_exists_path(cache)) return cache;
        }
        // Never fall back to packaged ciphertext — that SIGILL's in .init_array.
        PLOGE("business so: refuse ciphertext dlopen (lazy materialize failed) %s",
              base.c_str());
        return {};
    }

    // Source must be the packaged (possibly encrypted) extract — not so_plain.
    std::string abs;
    if (filename[0] == '/' && (plain_dir.empty()
                                || std::string(filename).compare(0, plain_dir.size(), plain_dir) != 0)) {
        abs = filename;
    } else if (!nld.empty()) {
        abs = keyed_packaged_src(base, nld);
    } else if (filename[0] == '/') {
        abs = filename;
    }
    if (abs.empty()) {
        PLOGE("business so: refuse dlopen — no source for keyed %s", base.c_str());
        return {};
    }

    if (cache_root.empty()) {
        // No writable mirror dir — decrypt in place only if path is writable.
        if (decrypt_text_on_disk(abs, base)) return abs;
        PLOGE("business so: refuse ciphertext dlopen (no cache) %s", base.c_str());
        return {};
    }
    mkdir(plain_dir.c_str(), 0700);

    if (!copy_file_bytes(abs, cache, /*force=*/true)) {
        PLOGE("business so: refuse ciphertext dlopen (copy failed) %s", base.c_str());
        return {};
    }

    // Fresh mirror from packaged lib — allow decrypt even if a prior attempt marked done.
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(base);
        if (key != nullptr) {
            key->decrypted = false;
            key->in_flight = false;
        }
    }
    g_cv.notify_all();

    if (decrypt_text_on_disk(cache, base)) {
        return cache;
    }
    PLOGE("business so: refuse ciphertext dlopen (decrypt failed) %s", base.c_str());
    return {};
}

static void note_or_decrypt(const char* filename) {
    std::string base = basename_of(filename);
    if (base.empty()) return;
    bool have_keys = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        have_keys = !g_keys.empty();
        if (!have_keys) {
            // Remember for flush when sokeys arrive (early dlopen before initApp).
            for (const auto& p : g_pending) {
                if (p == base) return;
            }
            g_pending.push_back(base);
            return;
        }
    }
    maybe_decrypt_by_name(base);
}

static bool is_keyed_basename(const std::string& base) {
    if (base.empty()) return false;
    std::lock_guard<std::mutex> lock(g_mu);
    return find_key_unlocked(base) != nullptr;
}

static void* fake_dlopen(const char* filename, int flags) {
    BYTEHOOK_STACK_SCOPE();
    std::string path = path_for_dlopen(filename);
    if (path.empty()) {
        if (filename != nullptr && filename[0] != '\0'
            && is_keyed_basename(basename_of(filename))) {
            PLOGE("business so: dlopen blocked for keyed SO %s", filename);
            return nullptr;
        }
        void* h = BYTEHOOK_CALL_PREV(fake_dlopen, filename, flags);
        if (h) note_or_decrypt(filename);
        return h;
    }
    std::string base = basename_of(filename);
    if (base.empty()) base = basename_of(path.c_str());
    if (is_keyed_basename(base)) {
        KeyedOpenPlan plan = plan_keyed_open(base, path);
        void* h = dlopen_keyed_plan(plan, flags, nullptr);
        if (h) note_or_decrypt(plan.content_path.c_str());
        return h;
    }
    void* h = BYTEHOOK_CALL_PREV(fake_dlopen, path.c_str(), flags);
    if (h) note_or_decrypt(path.c_str());
    return h;
}

static void* fake_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    BYTEHOOK_STACK_SCOPE();
    std::string path = path_for_dlopen(filename);
    if (path.empty()) {
        if (filename != nullptr && filename[0] != '\0'
            && is_keyed_basename(basename_of(filename))) {
            PLOGE("business so: android_dlopen_ext blocked for keyed SO %s", filename);
            return nullptr;
        }
        void* h = BYTEHOOK_CALL_PREV(fake_android_dlopen_ext, filename, flags, extinfo);
        if (h) note_or_decrypt(filename);
        return h;
    }
    std::string base = basename_of(filename);
    if (base.empty()) base = basename_of(path.c_str());
    if (is_keyed_basename(base)) {
        KeyedOpenPlan plan = plan_keyed_open(base, path);
        void* h = dlopen_keyed_plan(plan, flags, extinfo);
        if (h) note_or_decrypt(plan.content_path.c_str());
        return h;
    }
    void* h = BYTEHOOK_CALL_PREV(fake_android_dlopen_ext, path.c_str(), flags, extinfo);
    if (h) note_or_decrypt(path.c_str());
    return h;
}

/**
 * L2b: LIBRARY_FD may map so_plain or memfd; rewrite dli_fname to the extract
 * path recorded at L2 open so OSG/path-sensitive code matches.
 */
static int fake_dladdr(const void* addr, Dl_info* info) {
    BYTEHOOK_STACK_SCOPE();
    int r = BYTEHOOK_CALL_PREV(fake_dladdr, addr, info);
    if (r == 0 || info == nullptr || info->dli_fname == nullptr) return r;
    const char* fname = info->dli_fname;
    const bool memfd_name = strstr(fname, "/memfd:") != nullptr;
    if (strstr(fname, "/so_plain/") == nullptr && !memfd_name) return r;
    std::string base = keyed_soname_from_fname(fname);
    if (base.empty() || !is_keyed_basename(base)) return r;

    std::string extract;
    {
        std::lock_guard<std::mutex> lock(g_dladdr_mu);
        auto it = g_dladdr_extract.find(base);
        if (it != g_dladdr_extract.end()) {
            info->dli_fname = it->second.c_str();
            return r;
        }
    }
    {
        std::lock_guard<std::mutex> glock(g_mu);
        if (!g_native_lib_dir.empty()) {
            extract = g_native_lib_dir + "/" + base;
        }
    }
    if (extract.empty()) return r;
    std::lock_guard<std::mutex> lock(g_dladdr_mu);
    auto it = g_dladdr_extract.emplace(base, std::move(extract)).first;
    info->dli_fname = it->second.c_str();
    return r;
}

static void decrypt_already_loaded() {
    // Copy names under lock — never hold SoKey* across unlock (load_sokeys swap).
    std::vector<std::string> names;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        names.reserve(g_keys.size());
        for (const auto& k : g_keys) names.push_back(k.name);
    }
    for (const auto& name : names) {
        if (find_so_path(name.c_str()).empty()) continue;
        (void)decrypt_loaded_text(name);
    }
}

void decrypt_already_loaded_async() {
    if (!has_sokeys()) return;
    static std::atomic_bool started{false};
    bool expected = false;
    if (!started.compare_exchange_strong(expected, true)) return;
    std::thread([]() {
        decrypt_already_loaded();
        PLOGI("business so: decrypt_already_loaded (async) done");
    }).detach();
}

void install_business_so_hooks() {
    bool expected = false;
    if (!g_hooks_installed.compare_exchange_strong(expected, true)) {
        // Already installed — if keys just arrived, flush pending / loaded.
        if (has_sokeys()) {
            std::vector<std::string> pending;
            {
                std::lock_guard<std::mutex> lock(g_mu);
                pending.swap(g_pending);
            }
            for (const auto& name : pending) maybe_decrypt_by_name(name);
            // Lazy on-demand needs working dlopen hooks. Without them, ClassLoader
            // resolves keyed SOs from /data/app ciphertext → SIGILL (libcpbase).
            if (so_decrypt_mode() == SoDecryptMode::Lazy && !dlopen_hooks_ok()) {
                PLOGW("business so: lazy + no dlopen hooks — force full materialize");
                materialize_all_keyed_sos();
            }
            decrypt_already_loaded_async();
        }
        return;
    }

    bytehook_stub_t s1 = bytehook_hook_all(
            nullptr, "dlopen", reinterpret_cast<void*>(fake_dlopen), nullptr, nullptr);
    if (s1) PLOGI("business so: dlopen hooked (early-capable)");
    else PLOGW("business so: dlopen hook failed");

    bytehook_stub_t s2 = bytehook_hook_all(
            nullptr, "android_dlopen_ext",
            reinterpret_cast<void*>(fake_android_dlopen_ext), nullptr, nullptr);
    if (s2) PLOGI("business so: android_dlopen_ext hooked");
    else PLOGW("business so: android_dlopen_ext hook failed");

    // Android 10+ libnativeloader often exposes this instead of android_dlopen_ext.
    bytehook_stub_t s3 = bytehook_hook_all(
            nullptr, "__loader_android_dlopen_ext",
            reinterpret_cast<void*>(fake_android_dlopen_ext), nullptr, nullptr);
    if (s3) PLOGI("business so: __loader_android_dlopen_ext hooked");
    else PLOGW("business so: __loader_android_dlopen_ext hook failed");

    bytehook_stub_t s4 = bytehook_hook_all(
            nullptr, "dladdr", reinterpret_cast<void*>(fake_dladdr), nullptr, nullptr);
    if (s4) PLOGI("business so: dladdr hooked (L2b path rewrite)");
    else PLOGW("business so: dladdr hook failed");

    const bool any = (s1 != nullptr) || (s2 != nullptr) || (s3 != nullptr);
    g_dlopen_hooks_ok.store(any, std::memory_order_release);
    if (!any) {
        PLOGW("business so: all dlopen-family hooks failed (bytehook init?)");
        if (has_sokeys() && so_decrypt_mode() == SoDecryptMode::Lazy) {
            PLOGW("business so: lazy + no dlopen hooks — force full materialize");
            materialize_all_keyed_sos();
        }
    }

    // Eager scan deferred — see decrypt_already_loaded_async from init_app.
}

/**
 * True when /proc/self/maps has an executable mapping of {@code base} whose
 * path is <b>not</b> so_plain (typically packaged extract ciphertext).
 * Android 6 often fails L2/L3 dlopen(so_plain) (verneed) and falls back to the
 * encrypted extract while disk materialize already marked the key decrypted.
 */
static bool packaged_so_mapped(const std::string& base) {
    if (base.empty()) return false;
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp == nullptr) return false;
    char line[512];
    bool hit = false;
    while (fgets(line, sizeof(line), fp) != nullptr) {
        // r-xp / rwxp — skip non-executable (file read caches).
        if (strstr(line, "r-xp") == nullptr && strstr(line, "rwxp") == nullptr) {
            continue;
        }
        if (strstr(line, "/so_plain/") != nullptr) continue;
        const char* slash = strrchr(line, '/');
        const char* name = slash != nullptr ? slash + 1 : line;
        // maps line ends with "path\n" — compare basename prefix
        size_t n = base.size();
        if (strncmp(name, base.c_str(), n) == 0
            && (name[n] == '\0' || name[n] == '\n' || name[n] == ' ')) {
            hit = true;
            break;
        }
    }
    fclose(fp);
    return hit;
}

bool ensure_decrypted(const char* so_basename) {
    if (so_basename == nullptr || so_basename[0] == '\0') return true;
    std::string base = basename_of(so_basename);
    if (base.empty()) base = so_basename;

    bool tracked = false;
    bool disk_done = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        SoKey* key = find_key_unlocked(base);
        if (key == nullptr) return true; // not protected
        disk_done = key->decrypted;
        tracked = true;
    }

    // Disk so_plain may already be plaintext (key.decrypted) while the linker
    // still mapped packaged ciphertext — common on API≤23 when L2/L3 verneed
    // fails. Only skip when no packaged executable mapping remains.
    if (disk_done && !packaged_so_mapped(base)) {
        return true;
    }

    // Lazy cold start skipped full materialize — ensure so_plain + keyed deps first.
    if (so_decrypt_mode() == SoDecryptMode::Lazy) {
        ensure_plain_closure_for(base);
    }

    if (!decrypt_loaded_text(base)) {
        PLOGE("ensure_decrypted failed: %s", base.c_str());
        return false;
    }

    std::lock_guard<std::mutex> lock(g_mu);
    bool ok = is_decrypted_unlocked(base);
    if (!ok && tracked) {
        PLOGE("ensure_decrypted: still encrypted after claim: %s", base.c_str());
    }
    return ok;
}

} // namespace protector::so
