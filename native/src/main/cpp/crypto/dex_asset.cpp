#include "crypto/dex_asset.h"
#include "crypto/aes.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "common/sys_io.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <zlib.h>

namespace protector::crypto {

namespace {

constexpr size_t kIoBuf = 256 * 1024;

static bool read_all(const std::string& path, std::vector<uint8_t>& out) {
    return protector::sys_read_file(path.c_str(), out);
}

static bool write_all(const std::string& path, const uint8_t* data, size_t len) {
    // Buffer must outlive the ofstream: pubsetbuf does not copy; destroying the
    // vector before ofstream::~ofstream flush is UAF. On Android 6 that zeroed
    // the last 256KiB of classes.dex (map_list / class_data) → "Map is missing header".
    std::vector<char> buf(kIoBuf);
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.rdbuf()->pubsetbuf(buf.data(), static_cast<std::streamsize>(buf.size()));
    ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len));
    ofs.flush();
    bool ok = static_cast<bool>(ofs);
    ofs.close();
    return ok;
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

struct ZipLocal {
    std::string base_name;
    uint16_t method = 0;
    uint32_t crc32 = 0;
    uint32_t comp_size = 0;
    uint32_t uncomp_size = 0;
    size_t data_off = 0;
};

static std::string basename_of_zip_path(const std::string& name) {
    size_t slash = name.find_last_of("/\\");
    return slash == std::string::npos ? name : name.substr(slash + 1);
}

/** Collect local-file .dex entries (zip4j writes sizes in the local header). */
static bool parse_dex_locals(const uint8_t* zip, size_t zip_len, std::vector<ZipLocal>& out) {
    out.clear();
    size_t off = 0;
    while (off + 30 <= zip_len) {
        if (ru32(zip + off) != 0x04034b50u) {
            break; // central directory / EOCD
        }
        uint16_t flags = ru16(zip + off + 6);
        uint16_t method = ru16(zip + off + 8);
        uint32_t crc = ru32(zip + off + 14);
        uint32_t comp = ru32(zip + off + 18);
        uint32_t uncomp = ru32(zip + off + 22);
        uint16_t nlen = ru16(zip + off + 26);
        uint16_t elen = ru16(zip + off + 28);
        if (off + 30 + nlen + elen > zip_len) {
            PLOGE("zip local header truncated");
            return false;
        }
        if ((flags & 0x8) != 0) {
            // Data descriptor: sizes not in local header — fall back to Java ZipFile path.
            PLOGW("zip entry uses data descriptor — native extract unsupported");
            return false;
        }
        std::string name(reinterpret_cast<const char*>(zip + off + 30), nlen);
        size_t data_off = off + 30 + nlen + elen;
        if (data_off + comp > zip_len) {
            PLOGE("zip entry data OOB");
            return false;
        }
        std::string base = basename_of_zip_path(name);
        if (base.size() > 4 && base.compare(base.size() - 4, 4, ".dex") == 0) {
            ZipLocal e;
            e.base_name = std::move(base);
            e.method = method;
            e.crc32 = crc;
            e.comp_size = comp;
            e.uncomp_size = uncomp;
            e.data_off = data_off;
            out.push_back(std::move(e));
        }
        off = data_off + comp;
    }
    return true;
}

static bool inflate_raw(const uint8_t* src, size_t src_len,
                        uint8_t* dst, size_t dst_len) {
    z_stream strm{};
    // -MAX_WBITS = raw DEFLATE (ZIP), not zlib wrapper.
    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
        return false;
    }
    strm.next_in = const_cast<Bytef*>(src);
    strm.avail_in = static_cast<uInt>(src_len);
    strm.next_out = dst;
    strm.avail_out = static_cast<uInt>(dst_len);
    int rc = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    return rc == Z_STREAM_END && strm.total_out == dst_len;
}

static bool write_one_dex(const uint8_t* zip, const ZipLocal& e, const std::string& out_dir) {
    std::string path = out_dir + "/" + e.base_name;
    // Previous run may have setReadOnly — remove before rewrite.
    std::remove(path.c_str());
    std::vector<uint8_t> plain;
    if (e.method == 0) {
        if (e.comp_size != e.uncomp_size) return false;
        if (e.comp_size >= 4) {
            const uint8_t* p = zip + e.data_off;
            if (!(p[0] == 'd' && p[1] == 'e' && p[2] == 'x' && p[3] == '\n')) {
                PLOGE("stored %s missing dex magic", e.base_name.c_str());
                return false;
            }
        }
        plain.assign(zip + e.data_off, zip + e.data_off + e.comp_size);
    } else if (e.method == 8) {
        if (e.uncomp_size == 0 || e.uncomp_size > 512u * 1024u * 1024u) {
            PLOGE("bad uncomp size for %s", e.base_name.c_str());
            return false;
        }
        plain.resize(e.uncomp_size);
        if (!inflate_raw(zip + e.data_off, e.comp_size, plain.data(), plain.size())) {
            PLOGE("inflate failed for %s", e.base_name.c_str());
            return false;
        }
        if (plain.size() >= 4
            && !(plain[0] == 'd' && plain[1] == 'e' && plain[2] == 'x' && plain[3] == '\n')) {
            PLOGE("extracted %s missing dex magic", e.base_name.c_str());
            return false;
        }
    } else {
        PLOGE("unsupported zip method %u for %s", e.method, e.base_name.c_str());
        return false;
    }
    // ZIP local CRC must match — catches truncated/corrupt inflate.
    uint32_t got = static_cast<uint32_t>(::crc32(0L, plain.data(), static_cast<uInt>(plain.size())));
    if (got != e.crc32) {
        PLOGE("CRC mismatch for %s expect=0x%x got=0x%x", e.base_name.c_str(), e.crc32, got);
        memset(plain.data(), 0, plain.size());
        return false;
    }
    bool ok = write_all(path, plain.data(), plain.size());
    memset(plain.data(), 0, plain.size());
    return ok;
}

static bool extract_dexes_parallel(const uint8_t* zip, size_t zip_len,
                                   const std::string& out_dir) {
    std::vector<ZipLocal> entries;
    if (!parse_dex_locals(zip, zip_len, entries)) {
        return false;
    }
    if (entries.empty()) {
        PLOGI("zip has no .dex entries");
        return true;
    }

    // Sequential extract: zlib is fine multi-threaded, but large multidex packs
    // were observed with corrupt outputs under memory pressure; CRC gates below.
    for (const auto& e : entries) {
        if (!write_one_dex(zip, e, out_dir)) {
            PLOGE("extract failed: %s", e.base_name.c_str());
            return false;
        }
        PLOGI("extracted %s (%u bytes)", e.base_name.c_str(), e.uncomp_size);
    }
    return true;
}

static bool decrypt_pdx1_to_plain(std::vector<uint8_t>& buf, const uint8_t key[16],
                                  std::vector<uint8_t>& plain) {
    if (key == nullptr) return false;
    if (buf.size() < 4) return false;
    if (buf[0] != PROTECTOR_DEX_MAGIC0 || buf[1] != PROTECTOR_DEX_MAGIC1
        || buf[2] != PROTECTOR_DEX_MAGIC2 || buf[3] != PROTECTOR_DEX_MAGIC3) {
        return false;
    }
    const uint8_t* enc = buf.data() + 4;
    size_t enc_len = buf.size() - 4;
    if (enc_len < GCM_NONCE_LEN + GCM_TAG_LEN) return false;
    size_t plain_len = enc_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    plain.resize(plain_len);
    if (!aes128_gcm_decrypt(key, enc, enc_len, plain.data(), plain_len)) {
        plain.clear();
        return false;
    }
    if (plain_len < 4 || plain[0] != 'P' || plain[1] != 'K') {
        memset(plain.data(), 0, plain.size());
        plain.clear();
        return false;
    }
    return true;
}

} // namespace

bool decrypt_dexes_zip_file(const std::string& path, const uint8_t key[16]) {
    if (key == nullptr) return false;
    std::vector<uint8_t> buf;
    if (!read_all(path, buf) || buf.size() < 4) {
        PLOGE("dexes.zip read failed: %s", path.c_str());
        return false;
    }

    // Legacy plaintext ZIP
    if (buf[0] == 'P' && buf[1] == 'K') {
        PLOGI("dexes.zip is plaintext ZIP (legacy)");
        return true;
    }

    std::vector<uint8_t> plain;
    if (!decrypt_pdx1_to_plain(buf, key, plain)) {
        PLOGE("dexes.zip PDX1 decrypt failed");
        memset(buf.data(), 0, buf.size());
        return false;
    }

    std::string tmp = path + ".dec";
    if (!write_all(tmp, plain.data(), plain.size())) {
        PLOGE("dexes.zip write temp failed");
        memset(plain.data(), 0, plain.size());
        memset(buf.data(), 0, buf.size());
        return false;
    }
    memset(plain.data(), 0, plain.size());
    memset(buf.data(), 0, buf.size());

    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(path.c_str());
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            PLOGE("dexes.zip replace failed");
            std::remove(tmp.c_str());
            return false;
        }
    }
    PLOGI("dexes.zip PDX1 decrypted (%zu bytes)", plain.size());
    return true;
}

bool decrypt_and_extract_dexes(const std::string& zip_path,
                               const uint8_t key[16],
                               const std::string& out_dir) {
    auto t0 = std::chrono::steady_clock::now();
    std::vector<uint8_t> buf;
    if (!read_all(zip_path, buf) || buf.size() < 4) {
        PLOGE("dexes.zip read failed: %s", zip_path.c_str());
        return false;
    }

    std::vector<uint8_t> plain;
    const uint8_t* zip_data = nullptr;
    size_t zip_len = 0;
    bool own_plain = false;

    if (buf[0] == 'P' && buf[1] == 'K') {
        zip_data = buf.data();
        zip_len = buf.size();
        PLOGI("dexes.zip plaintext ZIP (legacy extract)");
    } else {
        if (key == nullptr || !decrypt_pdx1_to_plain(buf, key, plain)) {
            PLOGE("PDX1 decrypt for extract failed");
            memset(buf.data(), 0, buf.size());
            return false;
        }
        memset(buf.data(), 0, buf.size());
        buf.clear();
        buf.shrink_to_fit();
        zip_data = plain.data();
        zip_len = plain.size();
        own_plain = true;
    }

    bool ok = extract_dexes_parallel(zip_data, zip_len, out_dir);
    if (own_plain) {
        memset(plain.data(), 0, plain.size());
        plain.clear();
    } else {
        memset(buf.data(), 0, buf.size());
        buf.clear();
    }

    if (!ok) {
        // This process only: write plaintext zip so Java DexMerger can unzip.
        // Next launch force-extracts PDX1 from the APK (must not HMAC this leftover).
        PLOGW("native dex extract failed — falling back to plaintext zip path");
        return decrypt_dexes_zip_file(zip_path, key);
    }

    // Drop ciphertext (and any leftover) — DexMerger will use classes*.dex.
    std::remove(zip_path.c_str());
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
    PLOGI("decrypt+extract dexes done cost_ms=%lld", static_cast<long long>(ms));
    return true;
}

} // namespace protector::crypto
