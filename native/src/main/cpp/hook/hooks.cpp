#include "hook/hooks.h"
#include "common/log.h"
#include "common/runtime_state.h"
#include "common/protector_macro.h"
#include "dex/dex_file.h"
#include "risk/risk.h"
#include "report/threat_report.h"

#include <unistd.h>
#include <cstdio>
#include <cerrno>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <android/api-level.h>
#include <cstring>
#include <string>
#include <cstddef>
#include <sys/mman.h>
#include <sys/types.h>
#include <elf.h>
#include <link.h>

#include "dobby.h"
#include "bytehook.h"

#include <atomic>
#include <android/log.h>

namespace protector::hook {

/** Pre-AOSP16: DefineClass(Thread*, char const*, size_t hash, Handle, DexFile, ClassDef). */
static void* (*g_origin_define_class_v22)(void*, void*, const char*, size_t, void*, const void*,
                                          const void*) = nullptr;
/** AOSP16+: DefineClass(..., size_t descriptor_length, size_t hash, ...). */
static void* (*g_origin_define_class_v36)(void*, void*, const char*, size_t, size_t, void*,
                                          const void*, const void*) = nullptr;
static void* (*g_origin_define_class_v21)(void*, const char*, void*, const void*, const void*) = nullptr;
// LoadClass(Thread*, DexFile&, ClassDef&, Handle<Class>) — last arg is Handle, not char*.
static void (*g_origin_load_class_v23)(void*, const void*, const void*, const void*, void*) = nullptr;

struct ArtLibInfo {
    uintptr_t load_bias = 0;
    char path[512]{};
};

static int art_lib_phdr_cb(struct dl_phdr_info* info, size_t, void* data) {
    auto* out = static_cast<ArtLibInfo*>(data);
    if (info == nullptr || info->dlpi_name == nullptr) return 0;
    const char* name = info->dlpi_name;
    // Match libart.so but not libartbase / libartpalette / etc.
    const char* base = strrchr(name, '/');
    base = base ? base + 1 : name;
    if (strcmp(base, "libart.so") != 0) return 0;
    out->load_bias = static_cast<uintptr_t>(info->dlpi_addr);
    strncpy(out->path, name, sizeof(out->path) - 1);
    return 1;
}

static bool find_loaded_art(ArtLibInfo* out) {
    out->load_bias = 0;
    out->path[0] = 0;
    dl_iterate_phdr(art_lib_phdr_cb, out);
    return out->path[0] != 0;
}

static const char* art_lib_path_fallback() {
    int sdk = runtime_state().sdk_level;
    if (sdk < 29) {
#ifdef __LP64__
        return "/system/lib64/libart.so";
#else
        return "/system/lib/libart.so";
#endif
    } else if (sdk == 29) {
#ifdef __LP64__
        return "/apex/com.android.runtime/lib64/libart.so";
#else
        return "/apex/com.android.runtime/lib/libart.so";
#endif
    }
    // Prefer Xiaomi / some OEM "compatible" APEX, then stock ART APEX.
    static const char* kCandidates[] = {
#ifdef __LP64__
        "/apex/com.android.art.compatible/lib64/libart.so",
        "/apex/com.android.art/lib64/libart.so",
#else
        "/apex/com.android.art.compatible/lib/libart.so",
        "/apex/com.android.art/lib/libart.so",
#endif
    };
    for (const char* p : kCandidates) {
        if (access(p, R_OK) == 0) return p;
    }
#ifdef __LP64__
    return "/apex/com.android.art/lib64/libart.so";
#else
    return "/apex/com.android.art/lib/libart.so";
#endif
}

static const char* art_lib_path() {
    static ArtLibInfo cached{};
    static bool inited = false;
    if (!inited) {
        inited = true;
        if (!find_loaded_art(&cached) || cached.path[0] == 0) {
            strncpy(cached.path, art_lib_path_fallback(), sizeof(cached.path) - 1);
        }
    }
    return cached.path;
}

#ifdef __LP64__
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Shdr = Elf64_Shdr;
using Elf_Sym = Elf64_Sym;
#else
using Elf_Ehdr = Elf32_Ehdr;
using Elf_Shdr = Elf32_Shdr;
using Elf_Sym = Elf32_Sym;
#endif

/** Resolve a (possibly local) symbol without DobbySymbolResolver — it SEGV on
 *  some Android 14 / APEX libart layouts inside elf_ctx_init. */
static void* resolve_elf_symbol(const char* elf_path, uintptr_t load_bias, const char* sym) {
    FILE* fp = fopen(elf_path, "rb");
    if (!fp) return nullptr;
    Elf_Ehdr ehdr{};
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)
        || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(fp);
        return nullptr;
    }
    if (ehdr.e_shoff == 0 || ehdr.e_shentsize != sizeof(Elf_Shdr) || ehdr.e_shnum == 0) {
        fclose(fp);
        return nullptr;
    }
    std::vector<Elf_Shdr> shdrs(ehdr.e_shnum);
    if (fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET) != 0
        || fread(shdrs.data(), sizeof(Elf_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) {
        fclose(fp);
        return nullptr;
    }

    auto lookup_in = [&](const Elf_Shdr& symtab, const Elf_Shdr& strtab) -> void* {
        if (symtab.sh_entsize != sizeof(Elf_Sym) || symtab.sh_size == 0) return nullptr;
        size_t count = static_cast<size_t>(symtab.sh_size / sizeof(Elf_Sym));
        if (count > 2 * 1024 * 1024) return nullptr;
        std::vector<Elf_Sym> syms(count);
        std::vector<char> strs(static_cast<size_t>(strtab.sh_size));
        if (fseek(fp, static_cast<long>(symtab.sh_offset), SEEK_SET) != 0
            || fread(syms.data(), sizeof(Elf_Sym), count, fp) != count) {
            return nullptr;
        }
        if (fseek(fp, static_cast<long>(strtab.sh_offset), SEEK_SET) != 0
            || fread(strs.data(), 1, strs.size(), fp) != strs.size()) {
            return nullptr;
        }
        for (const auto& s : syms) {
            if (s.st_name == 0 || s.st_name >= strs.size()) continue;
            if (strcmp(strs.data() + s.st_name, sym) != 0) continue;
            if (s.st_shndx == SHN_UNDEF || s.st_value == 0) continue;
            return reinterpret_cast<void*>(load_bias + static_cast<uintptr_t>(s.st_value));
        }
        return nullptr;
    };

    void* found = nullptr;
    for (const auto& sh : shdrs) {
        if (sh.sh_type != SHT_SYMTAB && sh.sh_type != SHT_DYNSYM) continue;
        if (sh.sh_link >= shdrs.size()) continue;
        const Elf_Shdr& strtab = shdrs[sh.sh_link];
        if (strtab.sh_type != SHT_STRTAB) continue;
        found = lookup_in(sh, strtab);
        if (found) break;
    }
    fclose(fp);
    return found;
}

static void* resolve_art_symbol(const char* sym) {
    ArtLibInfo art{};
    if (!find_loaded_art(&art)) {
        strncpy(art.path, art_lib_path_fallback(), sizeof(art.path) - 1);
        // Without load bias we cannot safely relocate — try bias 0 only for ET_EXEC (never).
        __android_log_print(ANDROID_LOG_ERROR, "protector",
                            "libart.so not in dl_iterate_phdr; path=%s", art.path);
        return nullptr;
    }
    void* addr = resolve_elf_symbol(art.path, art.load_bias, sym);
    if (!addr) {
        __android_log_print(ANDROID_LOG_ERROR, "protector",
                            "symbol %s not in %s bias=0x%zx", sym, art.path,
                            (size_t)art.load_bias);
    }
    return addr;
}

static const char* art_caller_lib_name() {
    // bytehook matches by basename in caller's GOT
    if (runtime_state().sdk_level >= 29) {
        return "libartbase.so";
    }
    return "libart.so";
}

static bool scan_strtab_buffer(const char* data, size_t size, const char* k1, const char* k2,
                               char* out, size_t out_len) {
    if (data == nullptr || size == 0) return false;
    size_t i = 0;
    while (i < size) {
        const char* s = data + i;
        size_t remain = size - i;
        size_t len = strnlen(s, remain);
        if (len == 0) {
            i++;
            continue;
        }
        if (len >= 8 && len < out_len && s[0] == '_' && s[1] == 'Z'
            && strstr(s, k1) != nullptr && strstr(s, k2) != nullptr) {
            memcpy(out, s, len);
            out[len] = 0;
            return true;
        }
        i += len + 1;
    }
    return false;
}

/** Prefer scanning ELF SHT_STRTAB sections only (avoid loading entire libart). */
static bool find_symbol_in_strtab(FILE* fp, const char* k1, const char* k2,
                                  char* out, size_t out_len) {
    Elf_Ehdr ehdr{};
    if (fseek(fp, 0, SEEK_SET) != 0) return false;
    if (fread(&ehdr, 1, sizeof(ehdr), fp) != sizeof(ehdr)) return false;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return false;
    if (ehdr.e_shoff == 0 || ehdr.e_shentsize != sizeof(Elf_Shdr) || ehdr.e_shnum == 0) {
        return false;
    }

    std::vector<Elf_Shdr> shdrs(ehdr.e_shnum);
    if (fseek(fp, static_cast<long>(ehdr.e_shoff), SEEK_SET) != 0) return false;
    if (fread(shdrs.data(), sizeof(Elf_Shdr), ehdr.e_shnum, fp) != ehdr.e_shnum) return false;

    for (const auto& sh : shdrs) {
        if (sh.sh_type != SHT_STRTAB || sh.sh_size == 0) continue;
        // Cap absurd sizes
        if (sh.sh_size > 64 * 1024 * 1024) continue;
        std::vector<char> buf(static_cast<size_t>(sh.sh_size));
        if (fseek(fp, static_cast<long>(sh.sh_offset), SEEK_SET) != 0) continue;
        if (fread(buf.data(), 1, buf.size(), fp) != buf.size()) continue;
        if (scan_strtab_buffer(buf.data(), buf.size(), k1, k2, out, out_len)) {
            return true;
        }
    }
    return false;
}

/** Fallback: sliding window scan without holding the whole file. */
static bool find_symbol_chunked(FILE* fp, const char* k1, const char* k2,
                                char* out, size_t out_len) {
    constexpr size_t kChunk = 1024 * 1024;
    constexpr size_t kOverlap = 512;
    if (fseek(fp, 0, SEEK_END) != 0) return false;
    long file_sz = ftell(fp);
    if (file_sz <= 0) return false;
    if (fseek(fp, 0, SEEK_SET) != 0) return false;

    std::vector<char> buf(kChunk + kOverlap);
    size_t carry = 0;
    long pos = 0;
    while (pos < file_sz) {
        size_t to_read = static_cast<size_t>(
                (std::min)(static_cast<long>(kChunk), file_sz - pos));
        if (fread(buf.data() + carry, 1, to_read, fp) != to_read) return false;
        size_t total = carry + to_read;
        for (size_t i = 0; i + 16 < total; i++) {
            if (buf[i] != '_' || buf[i + 1] != 'Z') continue;
            size_t len = strnlen(buf.data() + i, total - i);
            if (len < 8 || len >= out_len) continue;
            // Skip incomplete string at chunk end
            if (i + len >= total && pos + static_cast<long>(to_read) < file_sz) continue;
            if (strstr(buf.data() + i, k1) && strstr(buf.data() + i, k2)) {
                memcpy(out, buf.data() + i, len);
                out[len] = 0;
                return true;
            }
            i += len;
        }
        if (total > kOverlap) {
            memmove(buf.data(), buf.data() + total - kOverlap, kOverlap);
            carry = kOverlap;
        } else {
            carry = total;
        }
        pos += static_cast<long>(to_read);
    }
    return false;
}

static bool find_symbol_contains(const char* elf_path, const char* k1, const char* k2,
                                char* out, size_t out_len) {
    FILE* fp = fopen(elf_path, "rb");
    if (!fp) return false;
    bool ok = find_symbol_in_strtab(fp, k1, k2, out, out_len);
    if (!ok) {
        PLOGW("strtab scan miss, fallback chunked: %s", elf_path);
        ok = find_symbol_chunked(fp, k1, k2, out, out_len);
    }
    fclose(fp);
    return ok;
}

struct ArtRxCheck {
    uintptr_t addr = 0;
    bool ok = false;
};

static int art_rx_phdr_cb(struct dl_phdr_info* info, size_t, void* data) {
    auto* c = static_cast<ArtRxCheck*>(data);
    if (info == nullptr || info->dlpi_name == nullptr || c == nullptr) return 0;
    const char* name = info->dlpi_name;
    const char* base = strrchr(name, '/');
    base = base ? base + 1 : name;
    if (strcmp(base, "libart.so") != 0) return 0;
    const uintptr_t bias = static_cast<uintptr_t>(info->dlpi_addr);
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || (ph->p_flags & PF_X) == 0) continue;
        const uintptr_t start = bias + static_cast<uintptr_t>(ph->p_vaddr);
        const uintptr_t end = start + static_cast<uintptr_t>(ph->p_memsz);
        if (c->addr >= start && c->addr < end) {
            c->ok = true;
            return 1;
        }
    }
    return 1;
}

static bool art_symbol_in_rx(void* addr) {
    if (addr == nullptr) return false;
    ArtRxCheck c{};
    c.addr = reinterpret_cast<uintptr_t>(addr);
    dl_iterate_phdr(art_rx_phdr_cb, &c);
    return c.ok;
}

static bool descriptor_starts_with(const char* descriptor, const char* prefix) {
    if (descriptor == nullptr || prefix == nullptr) return false;
    return strncmp(descriptor, prefix, strlen(prefix)) == 0;
}

static bool is_system_class_descriptor(const char* descriptor) {
    if (descriptor == nullptr || descriptor[0] == '\0') return false;
    static const char* kPrefixes[] = {
            "Landroid/",
            "Ljava/",
            "Ldalvik/",
            "Lcom/android/",
            "Lcom/huawei/",
            "Lcom/hihonor/",
            "Lcom/harmony/",
            "Lcom/harmonyos/",
            "Lohos/",
            "Llibcore/",
            "Lsun/",
            "Lorg/apache/harmony/",
    };
    for (const char* pfx : kPrefixes) {
        if (descriptor_starts_with(descriptor, pfx)) return true;
    }
    return false;
}

static void* DefineClassV22(void* thiz, void* self, const char* descriptor, size_t hash,
                            void* class_loader, const void* dex_file, const void* dex_class_def) {
    if (g_origin_define_class_v22 == nullptr) {
        return nullptr;
    }
    if (!is_system_class_descriptor(descriptor)) {
        protector::dex::patch_class(descriptor, dex_file, dex_class_def);
    }
    return g_origin_define_class_v22(thiz, self, descriptor, hash, class_loader, dex_file, dex_class_def);
}

/** Android 16 / AOSP ART: extra descriptor_length before hash. Wrong ABI → SEGV in origin. */
static void* DefineClassV36(void* thiz, void* self, const char* descriptor, size_t descriptor_length,
                            size_t hash, void* class_loader, const void* dex_file,
                            const void* dex_class_def) {
    if (g_origin_define_class_v36 == nullptr) {
        return nullptr;
    }
    if (!is_system_class_descriptor(descriptor)) {
        protector::dex::patch_class(descriptor, dex_file, dex_class_def);
    }
    return g_origin_define_class_v36(thiz, self, descriptor, descriptor_length, hash, class_loader,
                                     dex_file, dex_class_def);
}

static void* DefineClassV21(void* thiz, const char* descriptor, void* class_loader,
                            const void* dex_file, const void* dex_class_def) {
    if (g_origin_define_class_v21 == nullptr) {
        return nullptr;
    }
    if (!is_system_class_descriptor(descriptor)) {
        protector::dex::patch_class(descriptor, dex_file, dex_class_def);
    }
    return g_origin_define_class_v21(thiz, descriptor, class_loader, dex_file, dex_class_def);
}

/** True when mangled DefineClass has descriptor_length + hash (EPKcmm / EPKcjj). */
static bool define_class_sym_is_v36(const char* sym) {
    if (sym == nullptr) return false;
    return strstr(sym, "EPKcmm") != nullptr || strstr(sym, "EPKcjj") != nullptr;
}

/** True for classic V22 mangling (EPKcm / EPKcj) — not V36's EPKcmm / EPKcjj. */
static bool define_class_sym_is_v22(const char* sym) {
    if (sym == nullptr || define_class_sym_is_v36(sym)) return false;
    return strstr(sym, "EPKcm") != nullptr || strstr(sym, "EPKcj") != nullptr;
}

static void LoadClassV23(void* thiz, const void* self, const void* dex_file,
                         const void* dex_class_def, void* klass) {
    if (g_origin_load_class_v23 == nullptr) {
        return;
    }
    protector::dex::patch_class(nullptr, dex_file, dex_class_def);
    g_origin_load_class_v23(thiz, self, dex_file, dex_class_def, klass);
}

static bool hook_define_class() {
    // Android 10 (API 29) x86: Dobby replace of DefineClass scrambles the
    // ClassDef& such that ART aborts in GetIndexForClassDef
    // (&class_def < class_defs_). Arm64/11+ keep DefineClass; API<=29 uses
    // LoadClass first (see install_hooks).
    if (runtime_state().sdk_level <= 29) {
#if defined(__i386__) || defined(__x86_64__)
        PLOGE("sdk=%d x86: skip DefineClass Dobby hook", runtime_state().sdk_level);
        return false;
#endif
    }
    char sym[512] = {0};
    void* addr = nullptr;
    bool use_v36 = false;
    const int sdk = runtime_state().sdk_level;

    // AOSP 16+ DefineClass(Thread*, char const*, size_t descriptor_length, size_t hash, ...).
    // On sdk>=35 try exact V36 mangling first, then V22; ABI choice follows symbol only.
    if (sdk >= 35) {
#ifdef __LP64__
        static const char* kExactV36[] = {
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE",
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_7DexFile8ClassDefE",
        };
        static const char* kExactV22[] = {
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE",
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_7DexFile8ClassDefE",
        };
#else
        static const char* kExactV36[] = {
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE",
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_7DexFile8ClassDefE",
        };
        static const char* kExactV22[] = {
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_3dex8ClassDefE",
                "_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS_7DexFile8ClassDefE",
        };
#endif
        for (const char* cand : kExactV36) {
            void* p = resolve_art_symbol(cand);
            if (p != nullptr && art_symbol_in_rx(p)) {
                addr = p;
                strncpy(sym, cand, sizeof(sym) - 1);
                use_v36 = true;
                break;
            }
        }
        if (addr == nullptr) {
            for (const char* cand : kExactV22) {
                void* p = resolve_art_symbol(cand);
                if (p != nullptr && art_symbol_in_rx(p)) {
                    addr = p;
                    strncpy(sym, cand, sizeof(sym) - 1);
                    break;
                }
            }
        }
    }
    if (addr == nullptr) {
        const char* path = art_lib_path();
        if (!find_symbol_contains(path, "ClassLinker", "DefineClass", sym, sizeof(sym))) {
            PLOGW("DefineClass symbol not found in %s", path);
            return false;
        }
        addr = resolve_art_symbol(sym);
        use_v36 = define_class_sym_is_v36(sym);
    }
    if (!addr) {
        PLOGE("resolve_art_symbol failed for DefineClass");
        return false;
    }
    if (!art_symbol_in_rx(addr)) {
        PLOGE("DefineClass not in libart RX sdk=%d", sdk);
        return false;
    }
    // ABI from mangling only: EPKcmm/EPKcjj → V36; clear EPKcm/EPKcj (not mm) → V22.
    // Do not force V36 solely because sdk>=36 (fuzzy/unknown stays V22).
    if (!use_v36) {
        use_v36 = define_class_sym_is_v36(sym);
    }
    if (!use_v36 && define_class_sym_is_v22(sym)) {
        PLOGI("DefineClass V22 mangling sdk=%d sym=%s", sdk, sym);
    }

    int rc;
    if (sdk < 22) {
        rc = DobbyHook(addr, (dobby_dummy_func_t)DefineClassV21,
                       (dobby_dummy_func_t*)&g_origin_define_class_v21);
    } else if (use_v36) {
        rc = DobbyHook(addr, (dobby_dummy_func_t)DefineClassV36,
                       (dobby_dummy_func_t*)&g_origin_define_class_v36);
    } else {
        rc = DobbyHook(addr, (dobby_dummy_func_t)DefineClassV22,
                       (dobby_dummy_func_t*)&g_origin_define_class_v22);
    }
    PLOGI("DefineClass hook rc=%d v36=%d sdk=%d sym=%s", rc, use_v36 ? 1 : 0, sdk, sym);
    return rc == 0;
}

static bool hook_load_class() {
    if (runtime_state().sdk_level < 23) return false;
    char sym[512] = {0};
    const char* path = art_lib_path();
    // Prefer exact LoadClass(Thread*, DexFile&, ClassDef&, Handle) — avoid matching
    // LoadClassMembers / similar helpers that also contain "LoadClass".
    if (!find_symbol_contains(path, "ClassLinker9LoadClass", "ClassDef", sym, sizeof(sym))) {
        if (!find_symbol_contains(path, "ClassLinker", "LoadClassEPNS", sym, sizeof(sym))) {
            PLOGW("LoadClass symbol not found");
            return false;
        }
    }
    void* addr = resolve_art_symbol(sym);
    if (!addr) return false;
    if (!art_symbol_in_rx(addr)) {
        PLOGE("LoadClass not in libart RX sdk=%d", runtime_state().sdk_level);
        return false;
    }
    int rc = DobbyHook(addr, (dobby_dummy_func_t)LoadClassV23,
                       (dobby_dummy_func_t*)&g_origin_load_class_v23);
    PLOGI("LoadClass hook rc=%d sym=%s", rc, sym);
    return rc == 0;
}

static bool path_needs_writable_dex(const char* path) {
    if (path == nullptr || path[0] == '\0') return false;
    if (strstr(path, "code_cache/protector") != nullptr) return true;
    if (strstr(path, "dexes.zip") != nullptr) return true;
    if (strstr(path, "/protector/") != nullptr && strstr(path, ".dex") != nullptr) return true;
    return false;
}

static int maybe_add_write_prot(int fd, int prot) {
    if (fd < 0) return prot;
    char link_path[1024] = {0};
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(fd_path, link_path, sizeof(link_path) - 1);
    if (n <= 0) return prot;
    link_path[n] = 0;
    if (path_needs_writable_dex(link_path)) {
        if ((prot & PROT_READ) && !(prot & PROT_WRITE)) {
            PLOGD("mmap +PROT_WRITE for %s", link_path);
            return prot | PROT_WRITE;
        }
    }
    return prot;
}

static void* fake_mmap(void* addr, size_t size, int prot, int flags, int fd, off_t offset) {
    BYTEHOOK_STACK_SCOPE();
    int new_prot = maybe_add_write_prot(fd, prot);
    return BYTEHOOK_CALL_PREV(fake_mmap, addr, size, new_prot, flags, fd, offset);
}

static void* fake_mmap64(void* addr, size_t size, int prot, int flags, int fd, off64_t offset) {
    BYTEHOOK_STACK_SCOPE();
    int new_prot = maybe_add_write_prot(fd, prot);
    return BYTEHOOK_CALL_PREV(fake_mmap64, addr, size, new_prot, flags, fd, offset);
}

static int fake_execve(const char* pathname, char* const argv[], char* const envp[]) {
    BYTEHOOK_STACK_SCOPE();
    if (pathname != nullptr && strstr(pathname, "dex2oat") != nullptr) {
        PLOGD("execve blocked: %s", pathname);
        errno = EACCES;
        return -1;
    }
    return BYTEHOOK_CALL_PREV(fake_execve, pathname, argv, envp);
}

static void hook_one(const char* sym, void* fake) {
    bytehook_stub_t stub = bytehook_hook_single(
            art_caller_lib_name(),
            "libc.so",
            sym,
            fake,
            nullptr,
            nullptr);
    if (stub != nullptr) {
        PLOGI("%s bytehook ok caller=%s", sym, art_caller_lib_name());
    } else {
        PLOGW("%s bytehook fail", sym);
    }
}

static void hook_mmap() {
    hook_one("mmap", (void*)fake_mmap);
    hook_one("mmap64", (void*)fake_mmap64);
}

static void hook_execve() {
    hook_one("execve", (void*)fake_execve);
}

PROTECTOR_ENCRYPT void ensure_bytehook() {
    static std::atomic_bool done{false};
    bool expected = false;
    if (!done.compare_exchange_strong(expected, true)) {
        return;
    }
    const int bh = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    if (bh != 0) {
        PLOGW("bytehook_init failed rc=%d", bh);
        done.store(false);
    } else {
        PLOGI("bytehook_init ok");
    }
}

PROTECTOR_ENCRYPT void install_hooks() {
    static std::atomic_bool done{false};
    bool expected = false;
    if (!done.compare_exchange_strong(expected, true)) {
        return;
    }
    runtime_state().sdk_level = android_get_device_api_level();
    ensure_bytehook();
    hook_execve();
    hook_mmap();
    // API 24 (Android 7) x86_64: Dobby LoadClass/DefineClass leads to ART
    // AllocObject SIGSEGV right after makeApplication. Prefer no class hook —
    // hollow restore relies on prepatch (API≥25) or stays on stubs / TRUE_VMP.
    bool ok = false;
#if defined(__x86_64__) || defined(__i386__)
    if (runtime_state().sdk_level <= 24) {
        PLOGE("sdk=%d x86: skip ART class hooks (Dobby unstable)", runtime_state().sdk_level);
        ok = true; // do not treat as fatal — TRUE_VMP + optional prepatch still work
    } else
#endif
    if (runtime_state().sdk_level <= 29) {
        ok = hook_load_class();
        if (!ok) {
            ok = hook_define_class();
        }
    } else {
        ok = hook_define_class();
        if (!ok) {
            ok = hook_load_class();
        }
    }
    if (!ok) {
        // Hollow restore depends on DefineClass/LoadClass hooks. Honour rasp_action
        // instead of always SIGILL — Alert/Degrade keep the process alive for diagnosis.
        int action = runtime_state().config.rasp_action.load(std::memory_order_relaxed);
        PLOGE("ART class hooks failed; rasp_action=%d", action);
        if (action == static_cast<int>(RaspAction::Alert)) {
            protector::risk::mark_environment_degraded();
            protector::report::report_threat("art_hooks_failed", action);
        } else if (action == static_cast<int>(RaspAction::Degrade)) {
            protector::risk::mark_environment_degraded();
            protector::report::report_threat("art_hooks_failed", action);
            protector::risk::schedule_delayed_crash();
        } else {
            protector::risk::crash_sigill();
        }
    }
}

} // namespace protector::hook
