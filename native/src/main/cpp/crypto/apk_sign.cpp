/**
 * Parse APK Signing Block (v2/v3) and SHA-256 the first signer certificate.
 * Layout matches packer ApkSignerCert.java.
 */
#include "crypto/apk_sign.h"
#include "crypto/sha256.h"
#include "common/sys_io.h"

#include <cstring>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <vector>

namespace protector::crypto {

namespace {

constexpr int kApkSigBlockMin = 32;
constexpr uint64_t kMagicLo = 0x20676953204b5041ULL;
constexpr uint64_t kMagicHi = 0x3234206b636f6c42ULL;
constexpr uint32_t kEocdSig = 0x06054b50u;
constexpr int kEocdMin = 22;
constexpr int kEocdCommentOff = 20;
constexpr uint32_t kV2Id = 0x7109871au;
constexpr uint32_t kV3Id = 0xf05368c0u;
constexpr uint64_t kMaxSigningBlock = 32ull * 1024 * 1024;
constexpr uint32_t kMaxCert = 64u * 1024;

static uint32_t ru32(const uint8_t* p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t ru64(const uint8_t* p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static int open_apk(const char* path) {
    return protector::sys_open_ro(path);
}

static bool read_at(int fd, uint64_t off, void* buf, size_t n) {
    return protector::sys_pread_all(fd, off, buf, n);
}

struct Cur {
    const uint8_t* p = nullptr;
    size_t n = 0;
    size_t off = 0;

    bool prefixed(Cur* sub) {
        if (off + 4 > n) {
            return false;
        }
        uint32_t len = ru32(p + off);
        off += 4;
        if (len > n - off) {
            return false;
        }
        sub->p = p + off;
        sub->n = len;
        sub->off = 0;
        off += len;
        return true;
    }
};

static bool first_cert_in_scheme(const uint8_t* value, size_t value_len,
                                 const uint8_t** cert, uint32_t* cert_len) {
    Cur scheme{value, value_len, 0};
    Cur signers{};
    if (!scheme.prefixed(&signers)) {
        return false;
    }
    Cur signer{};
    if (!signers.prefixed(&signer)) {
        return false;
    }
    Cur signed_data{};
    if (!signer.prefixed(&signed_data)) {
        return false;
    }
    Cur digests{};
    if (!signed_data.prefixed(&digests)) {
        return false;
    }
    Cur certs{};
    if (!signed_data.prefixed(&certs)) {
        return false;
    }
    Cur one{};
    if (!certs.prefixed(&one) || one.n == 0 || one.n > kMaxCert) {
        return false;
    }
    *cert = one.p;
    *cert_len = static_cast<uint32_t>(one.n);
    return true;
}

static bool find_cd_offset(const uint8_t* tail, size_t tail_len, uint64_t file_size,
                           uint64_t* cd_out) {
    if (file_size < kEocdMin || tail_len < kEocdMin) {
        return false;
    }
    uint64_t max_comment = file_size - kEocdMin;
    if (max_comment > 0xffffu) {
        max_comment = 0xffffu;
    }
    for (uint64_t comment = 0; comment <= max_comment; comment++) {
        if (kEocdMin + comment > tail_len) {
            break;
        }
        size_t eocd_pos = tail_len - kEocdMin - static_cast<size_t>(comment);
        if (ru32(tail + eocd_pos) != kEocdSig) {
            continue;
        }
        uint32_t actual = static_cast<uint32_t>(tail[eocd_pos + kEocdCommentOff])
                | (static_cast<uint32_t>(tail[eocd_pos + kEocdCommentOff + 1]) << 8);
        if (actual != comment) {
            continue;
        }
        uint32_t cd = ru32(tail + eocd_pos + 16);
        if (cd == 0xffffffffu) {
            return false; // ZIP64
        }
        *cd_out = cd;
        return true;
    }
    return false;
}

static bool parse_id_values(const uint8_t* block, size_t total,
                            const uint8_t** v3, size_t* v3_len,
                            const uint8_t** v2, size_t* v2_len) {
    *v3 = nullptr;
    *v3_len = 0;
    *v2 = nullptr;
    *v2_len = 0;
    if (total < 8 + 24) {
        return false;
    }
    size_t pairs_end = total - 24;
    size_t off = 8;
    while (off + 8 <= pairs_end) {
        uint64_t len_long = ru64(block + off);
        off += 8;
        if (len_long < 4 || len_long > pairs_end - off) {
            break;
        }
        uint32_t len = static_cast<uint32_t>(len_long);
        uint32_t id = ru32(block + off);
        const uint8_t* val = block + off + 4;
        size_t val_len = static_cast<size_t>(len - 4);
        off += len;
        if (id == kV3Id) {
            *v3 = val;
            *v3_len = val_len;
        } else if (id == kV2Id) {
            *v2 = val;
            *v2_len = val_len;
        }
    }
    return *v3_len > 0 || *v2_len > 0;
}

using ReadAtFn = bool (*)(void* ctx, uint64_t off, void* buf, size_t n);

static bool parse_apk(void* ctx, ReadAtFn read_fn, uint64_t file_size, uint8_t out_digest[32]) {
    if (file_size < static_cast<uint64_t>(kEocdMin + kApkSigBlockMin) || out_digest == nullptr) {
        return false;
    }
    uint64_t max_comment = file_size - kEocdMin;
    if (max_comment > 0xffffu) {
        max_comment = 0xffffu;
    }
    size_t tail_len = static_cast<size_t>(kEocdMin + max_comment);
    if (static_cast<uint64_t>(tail_len) > file_size) {
        tail_len = static_cast<size_t>(file_size);
    }
    std::vector<uint8_t> tail(tail_len);
    if (!read_fn(ctx, file_size - tail_len, tail.data(), tail_len)) {
        return false;
    }
    uint64_t cd_off = 0;
    if (!find_cd_offset(tail.data(), tail_len, file_size, &cd_off)
            || cd_off < kApkSigBlockMin || cd_off > file_size) {
        return false;
    }
    uint8_t footer[24];
    if (!read_fn(ctx, cd_off - 24, footer, 24)) {
        return false;
    }
    if (ru64(footer + 8) != kMagicLo || ru64(footer + 16) != kMagicHi) {
        return false;
    }
    uint64_t block_size = ru64(footer);
    if (block_size < 24 || block_size > kMaxSigningBlock - 8) {
        return false;
    }
    uint64_t total = block_size + 8;
    if (total > cd_off) {
        return false;
    }
    uint64_t block_off = cd_off - total;
    std::vector<uint8_t> block(static_cast<size_t>(total));
    if (!read_fn(ctx, block_off, block.data(), static_cast<size_t>(total))) {
        return false;
    }
    if (ru64(block.data()) != block_size) {
        return false;
    }

    const uint8_t* v3 = nullptr;
    const uint8_t* v2 = nullptr;
    size_t v3_len = 0;
    size_t v2_len = 0;
    parse_id_values(block.data(), static_cast<size_t>(total), &v3, &v3_len, &v2, &v2_len);

    const uint8_t* cert = nullptr;
    uint32_t cert_len = 0;
    if (v3_len > 0 && first_cert_in_scheme(v3, v3_len, &cert, &cert_len)) {
        sha256(cert, cert_len, out_digest);
        return true;
    }
    if (v2_len > 0 && first_cert_in_scheme(v2, v2_len, &cert, &cert_len)) {
        sha256(cert, cert_len, out_digest);
        return true;
    }
    return false;
}

static bool read_fd(void* ctx, uint64_t off, void* buf, size_t n) {
    return read_at(*static_cast<int*>(ctx), off, buf, n);
}

struct MemApk {
    const uint8_t* p;
    size_t n;
};

static bool read_mem(void* ctx, uint64_t off, void* buf, size_t n) {
    auto* m = static_cast<MemApk*>(ctx);
    if (m == nullptr || m->p == nullptr || off > m->n || n > m->n - off) {
        return false;
    }
    memcpy(buf, m->p + off, n);
    return true;
}

static void append_bytes(std::vector<uint8_t>& out, const uint8_t* p, size_t n) {
    out.insert(out.end(), p, p + n);
}

static void append_u32(std::vector<uint8_t>& out, uint32_t v) {
    uint8_t b[4];
    memcpy(b, &v, 4);
    append_bytes(out, b, 4);
}

static void append_u64(std::vector<uint8_t>& out, uint64_t v) {
    uint8_t b[8];
    memcpy(b, &v, 8);
    append_bytes(out, b, 8);
}

static std::vector<uint8_t> prefixed(const std::vector<uint8_t>& inner) {
    std::vector<uint8_t> o;
    append_u32(o, static_cast<uint32_t>(inner.size()));
    append_bytes(o, inner.data(), inner.size());
    return o;
}

static std::vector<uint8_t> concat2(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    std::vector<uint8_t> o = a;
    append_bytes(o, b.data(), b.size());
    return o;
}

static std::vector<uint8_t> scheme_value(const std::vector<uint8_t>& cert) {
    auto empty = prefixed({});
    auto certs = prefixed(prefixed(cert));
    auto signed_data = concat2(concat2(empty, certs), empty);
    auto signer = concat2(concat2(prefixed(signed_data), prefixed({})), prefixed({}));
    return prefixed(prefixed(signer));
}

static std::vector<uint8_t> signing_block_pairs(const uint32_t* ids, const std::vector<uint8_t>* values,
                                               size_t n) {
    uint64_t pairs_len = 0;
    for (size_t i = 0; i < n; i++) {
        pairs_len += 8 + 4 + values[i].size();
    }
    uint64_t block_size = pairs_len + 8 + 16;
    std::vector<uint8_t> b;
    append_u64(b, block_size);
    for (size_t i = 0; i < n; i++) {
        append_u64(b, 4ull + values[i].size());
        append_u32(b, ids[i]);
        append_bytes(b, values[i].data(), values[i].size());
    }
    append_u64(b, block_size);
    append_u64(b, kMagicLo);
    append_u64(b, kMagicHi);
    return b;
}

static std::vector<uint8_t> eocd(uint32_t cd_offset, uint32_t cd_size) {
    std::vector<uint8_t> b;
    append_u32(b, kEocdSig);
    for (int i = 0; i < 4; i++) {
        b.push_back(0);
        b.push_back(0);
    }
    append_u32(b, cd_size);
    append_u32(b, cd_offset);
    b.push_back(0);
    b.push_back(0);
    return b;
}

static std::vector<uint8_t> make_apk(const std::vector<uint8_t>& prefix,
                                    const std::vector<uint8_t>& block) {
    std::vector<uint8_t> apk = prefix;
    append_bytes(apk, block.data(), block.size());
    auto rec = eocd(static_cast<uint32_t>(prefix.size() + block.size()), 0);
    append_bytes(apk, rec.data(), rec.size());
    return apk;
}

static bool digest_mem(const std::vector<uint8_t>& apk, uint8_t out[32]) {
    MemApk mem{apk.data(), apk.size()};
    return parse_apk(&mem, read_mem, apk.size(), out);
}

static std::vector<uint8_t> sequential(uint8_t start, size_t len) {
    std::vector<uint8_t> o(len);
    for (size_t i = 0; i < len; i++) {
        o[i] = static_cast<uint8_t>(start + i);
    }
    return o;
}

} // namespace

bool apk_first_signer_cert_sha256(const char* apk_path, uint8_t out_digest[32]) {
    if (apk_path == nullptr || apk_path[0] == 0 || out_digest == nullptr) {
        return false;
    }
    int fd = open_apk(apk_path);
    if (fd < 0) {
        return false;
    }
    uint64_t file_size = 0;
    if (!protector::sys_fd_size(fd, &file_size)
            || file_size < static_cast<uint64_t>(kEocdMin + kApkSigBlockMin)) {
        protector::sys_close_fd(fd);
        return false;
    }
    bool ok = parse_apk(&fd, read_fd, file_size, out_digest);
    protector::sys_close_fd(fd);
    return ok;
}

bool apk_sign_self_test() {
    auto cert_v2 = sequential(0x30, 48);
    uint32_t id_v2 = kV2Id;
    auto val_v2 = scheme_value(cert_v2);
    auto block_v2 = signing_block_pairs(&id_v2, &val_v2, 1);
    uint8_t prefix_v2[] = {0x50, 0x4b};
    auto apk_v2 = make_apk(std::vector<uint8_t>(prefix_v2, prefix_v2 + 2), block_v2);
    uint8_t got[32];
    uint8_t expect[32];
    if (!digest_mem(apk_v2, got)) {
        return false;
    }
    sha256(cert_v2.data(), cert_v2.size(), expect);
    if (memcmp(got, expect, 32) != 0) {
        return false;
    }

    auto cert_a = sequential(0x11, 16);
    auto cert_b = sequential(0x22, 16);
    uint32_t ids[2] = {kV2Id, kV3Id};
    std::vector<uint8_t> vals[2] = {scheme_value(cert_a), scheme_value(cert_b)};
    auto block_both = signing_block_pairs(ids, vals, 2);
    auto apk_both = make_apk(std::vector<uint8_t>(8, 0), block_both);
    if (!digest_mem(apk_both, got)) {
        return false;
    }
    sha256(cert_b.data(), cert_b.size(), expect);
    if (memcmp(got, expect, 32) != 0) {
        return false;
    }

    auto unsigned_apk = eocd(0, 0);
    if (digest_mem(unsigned_apk, got)) {
        return false;
    }

    uint32_t unknown = 0x12345678u;
    std::vector<uint8_t> junk{1, 2, 3, 4};
    auto unknown_block = signing_block_pairs(&unknown, &junk, 1);
    auto apk_unknown = make_apk(std::vector<uint8_t>(1, 0), unknown_block);
    if (digest_mem(apk_unknown, got)) {
        return false;
    }
    return true;
}

} // namespace protector::crypto
