#include "vm/pvm2_format.h"
#include "common/log.h"

#include <cstring>

namespace protector::vm {

static uint16_t read_u16(const uint8_t* p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static bool read_string_pool(const uint8_t* data, size_t size, size_t* cursor,
                             uint16_t count, std::vector<std::string>* out) {
    out->clear();
    out->reserve(count);
    for (uint16_t i = 0; i < count; i++) {
        if (*cursor + 2 > size) {
            return false;
        }
        uint16_t len = read_u16(data + *cursor);
        *cursor += 2;
        if (*cursor + len > size) {
            return false;
        }
        out->emplace_back(reinterpret_cast<const char*>(data + *cursor), len);
        *cursor += len;
    }
    return true;
}

static bool read_index_pool(const uint8_t* data, size_t size, size_t* cursor,
                            uint16_t count, const std::vector<std::string>& strings,
                            std::vector<std::string>* out) {
    out->clear();
    out->reserve(count);
    for (uint16_t i = 0; i < count; i++) {
        if (*cursor + 2 > size) {
            return false;
        }
        uint16_t idx = read_u16(data + *cursor);
        *cursor += 2;
        if (idx >= strings.size()) {
            PLOGE("PVM2 pool idx OOB %u >= %zu", idx, strings.size());
            return false;
        }
        out->push_back(strings[idx]);
    }
    return true;
}

static void set_identity_map(Pvm2Image* out) {
    out->has_morph = false;
    out->isa_id = 0;
    out->imm_key = 0;
    out->scratch_extra = 1;
    for (int i = 0; i < 256; i++) {
        out->inv_map[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    }
}

bool parse_pvm2(const uint8_t* data, size_t size, Pvm2Image* out) {
    if (out == nullptr || data == nullptr || size < 18) {
        return false;
    }
    out->valid = false;
    out->strings.clear();
    out->methods.clear();
    out->fields.clear();
    out->types.clear();
    out->handlers.clear();
    out->code.clear();
    set_identity_map(out);

    if (memcmp(data, "PVM2", 4) != 0) {
        PLOGE("PVM2 bad magic");
        return false;
    }

    out->version = read_u16(data + 4);
    out->reg_count = read_u16(data + 6);
    out->ins_size = read_u16(data + 8);
    out->handler_count = read_u16(data + 10);
    out->code_size = read_u16(data + 12);
    out->ret_kind = data[14];
    out->isa_id = data[15];
    uint16_t str_count = read_u16(data + 16);

    if (out->version != PVM2_VERSION_V1 && out->version != PVM2_VERSION_V2
            && out->version != PVM2_VERSION_V3 && out->version != PVM2_VERSION_V4
            && out->version != PVM2_VERSION_V5) {
        PLOGE("PVM2 unsupported version %u", out->version);
        return false;
    }
    if (out->reg_count == 0 || out->reg_count > 256) {
        PLOGE("PVM2 bad reg_count %u", out->reg_count);
        return false;
    }
    if (out->version >= PVM2_VERSION_V3 && out->isa_id >= PVM2_ISA_COUNT) {
        PLOGE("PVM2 bad isa_id %u", out->isa_id);
        return false;
    }
    if (out->version < PVM2_VERSION_V2) {
        out->scratch_extra = 0;
    } else if (out->version < PVM2_VERSION_V5) {
        out->scratch_extra = 1;
    }

    size_t cursor = 18;
    if (!read_string_pool(data, size, &cursor, str_count, &out->strings)) {
        PLOGE("PVM2 strings truncated");
        return false;
    }

    if (out->version >= PVM2_VERSION_V2) {
        if (cursor + 2 > size) {
            return false;
        }
        uint16_t method_count = read_u16(data + cursor);
        cursor += 2;
        if (!read_index_pool(data, size, &cursor, method_count, out->strings, &out->methods)) {
            PLOGE("PVM2 method pool truncated");
            return false;
        }

        if (cursor + 2 > size) {
            return false;
        }
        uint16_t field_count = read_u16(data + cursor);
        cursor += 2;
        if (!read_index_pool(data, size, &cursor, field_count, out->strings, &out->fields)) {
            PLOGE("PVM2 field pool truncated");
            return false;
        }

        if (cursor + 2 > size) {
            return false;
        }
        uint16_t type_count = read_u16(data + cursor);
        cursor += 2;
        if (!read_index_pool(data, size, &cursor, type_count, out->strings, &out->types)) {
            PLOGE("PVM2 type pool truncated");
            return false;
        }

        if (out->version >= PVM2_VERSION_V3) {
            if (cursor + 1 > size) {
                return false;
            }
            uint8_t op_count = data[cursor++];
            // v3 morph tables are 40 ops; v4+ use PVM2_OP_COUNT (50).
            bool op_count_ok = (op_count == PVM2_OP_COUNT_V3 || op_count == PVM2_OP_COUNT);
            if (!op_count_ok || cursor + op_count > size) {
                PLOGE("PVM2 bad morph table op_count=%u", op_count);
                return false;
            }
            for (int i = 0; i < 256; i++) {
                out->inv_map[static_cast<size_t>(i)] = 0xFF;
            }
            for (uint8_t canonical = 0; canonical < op_count; canonical++) {
                uint8_t wire = data[cursor + canonical];
                if (out->inv_map[wire] != 0xFF) {
                    PLOGE("PVM2 morph collision wire=%u", wire);
                    return false;
                }
                out->inv_map[wire] = canonical;
            }
            cursor += op_count;
            out->has_morph = true;
            if (out->version >= PVM2_VERSION_V5) {
                if (cursor + 5 > size) {
                    PLOGE("PVM2 v5 morph extras truncated");
                    return false;
                }
                out->scratch_extra = data[cursor++];
                if (out->scratch_extra < 1 || out->scratch_extra > 3) {
                    PLOGE("PVM2 bad scratch_extra %u", out->scratch_extra);
                    return false;
                }
                int32_t key;
                memcpy(&key, data + cursor, 4);
                cursor += 4;
                out->imm_key = key;
            }
        }

        out->handlers.reserve(out->handler_count);
        for (uint16_t i = 0; i < out->handler_count; i++) {
            if (cursor + 8 > size) {
                PLOGE("PVM2 handlers truncated");
                return false;
            }
            Pvm2Handler h;
            h.start = read_u16(data + cursor);
            h.end = read_u16(data + cursor + 2);
            h.handler_pc = read_u16(data + cursor + 4);
            h.catch_type_idx = read_u16(data + cursor + 6);
            cursor += 8;
            out->handlers.push_back(h);
        }
    } else if (out->handler_count != 0) {
        PLOGE("PVM2 v1 unexpected handler_count %u", out->handler_count);
        return false;
    }

    if (cursor + out->code_size > size) {
        PLOGE("PVM2 code truncated");
        return false;
    }
    out->code.assign(data + cursor, data + cursor + out->code_size);
    out->valid = true;
    return true;
}

} // namespace protector::vm
