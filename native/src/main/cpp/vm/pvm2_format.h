#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <array>

namespace protector::vm {

/** bit0 = legacy PVM1; bit1 = true PVM2 interpreter. */
constexpr uint32_t FLAG_VMP = 1u;
constexpr uint32_t FLAG_TRUE_VMP = 2u;

constexpr uint16_t PVM2_VERSION_V1 = 1;
constexpr uint16_t PVM2_VERSION_V2 = 2;
constexpr uint16_t PVM2_VERSION_V3 = 3;
constexpr uint16_t PVM2_VERSION_V4 = 4;
constexpr uint16_t PVM2_VERSION_V5 = 5;

/** Morph table size for v3 images. */
constexpr uint8_t PVM2_OP_COUNT_V3 = 40;
/** Morph table size for v4+ (float/double/monitor). */
constexpr uint8_t PVM2_OP_COUNT = 50;
constexpr uint8_t PVM2_ISA_COUNT = 3;

enum RetKind : uint8_t {
    RET_V = 0,
    RET_I = 1,
    RET_J = 2,
    RET_L = 3,
    RET_Z = 4,
    RET_F = 5,
    RET_D = 6,
};

enum Op : uint8_t {
    OP_NOP = 0,
    OP_CONST = 1,
    OP_CONST_WIDE = 2,
    OP_CONST_STR = 3,
    OP_MOVE = 4,
    OP_MOVE_WIDE = 5,
    OP_MOVE_OBJ = 6,
    OP_GOTO = 7,
    OP_IF_CMP = 8,
    OP_IF_Z = 9,
    OP_RETURN_VOID = 10,
    OP_RETURN = 11,
    OP_RETURN_WIDE = 12,
    OP_RETURN_OBJ = 13,
    OP_BINOP = 14,
    OP_BINOP_2ADDR = 15,
    // Phase 2
    OP_INVOKE_STATIC = 16,
    OP_INVOKE_VIRTUAL = 17,
    OP_INVOKE_DIRECT = 18,
    OP_INVOKE_INTERFACE = 19,
    OP_INVOKE_SUPER = 20,
    OP_MOVE_RESULT = 21,
    OP_MOVE_RESULT_WIDE = 22,
    OP_MOVE_RESULT_OBJ = 23,
    OP_SGET = 24,
    OP_SPUT = 25,
    OP_IGET = 26,
    OP_IPUT = 27,
    OP_NEW_INSTANCE = 28,
    OP_NEW_ARRAY = 29,
    OP_ARRAY_LENGTH = 30,
    OP_AGET = 31,
    OP_APUT = 32,
    OP_CHECK_CAST = 33,
    OP_INSTANCE_OF = 34,
    OP_THROW = 35,
    OP_MOVE_EXCEPTION = 36,
    OP_CONST_CLASS = 37,
    OP_NEG = 38,
    OP_FILLED_NEW_ARRAY = 39,
    // Phase 5 (v4)
    OP_BINOP_WIDE = 40,
    OP_BINOP_2ADDR_WIDE = 41,
    OP_BINOP_FLOAT = 42,
    OP_BINOP_2ADDR_FLOAT = 43,
    OP_BINOP_DOUBLE = 44,
    OP_BINOP_2ADDR_DOUBLE = 45,
    OP_UNOP = 46,
    OP_CMP = 47,
    OP_MONITOR_ENTER = 48,
    OP_MONITOR_EXIT = 49,
};

enum Kind : uint8_t {
    KIND_I = 0,
    KIND_J = 1,
    KIND_L = 2,
    KIND_Z = 3,
    KIND_B = 4,
    KIND_S = 5,
    KIND_C = 6,
};

enum Cond : uint8_t {
    COND_EQ = 0,
    COND_NE = 1,
    COND_LT = 2,
    COND_GE = 3,
    COND_GT = 4,
    COND_LE = 5,
};

enum BinOp : uint8_t {
    BIN_ADD = 0,
    BIN_SUB = 1,
    BIN_MUL = 2,
    BIN_AND = 3,
    BIN_OR = 4,
    BIN_XOR = 5,
    BIN_SHL = 6,
    BIN_SHR = 7,
    BIN_USHR = 8,
    BIN_DIV = 9,
    BIN_REM = 10,
};

enum UnOp : uint8_t {
    UN_NEG_LONG = 0,
    UN_NEG_FLOAT = 1,
    UN_NEG_DOUBLE = 2,
    UN_NOT_INT = 3,
    UN_NOT_LONG = 4,
    UN_INT_TO_LONG = 5,
    UN_INT_TO_FLOAT = 6,
    UN_INT_TO_DOUBLE = 7,
    UN_LONG_TO_INT = 8,
    UN_LONG_TO_FLOAT = 9,
    UN_LONG_TO_DOUBLE = 10,
    UN_FLOAT_TO_INT = 11,
    UN_FLOAT_TO_LONG = 12,
    UN_FLOAT_TO_DOUBLE = 13,
    UN_DOUBLE_TO_INT = 14,
    UN_DOUBLE_TO_LONG = 15,
    UN_DOUBLE_TO_FLOAT = 16,
    UN_INT_TO_BYTE = 17,
    UN_INT_TO_CHAR = 18,
    UN_INT_TO_SHORT = 19,
};

enum CmpKind : uint8_t {
    CMP_FLOAT_L = 0,
    CMP_FLOAT_G = 1,
    CMP_DOUBLE_L = 2,
    CMP_DOUBLE_G = 3,
    CMP_LONG = 4,
};

constexpr uint16_t PVM2_CATCH_ALL = 0xFFFF;

struct Pvm2Handler {
    uint16_t start = 0;
    uint16_t end = 0;
    uint16_t handler_pc = 0;
    uint16_t catch_type_idx = PVM2_CATCH_ALL;
};

struct Pvm2Image {
    uint16_t version = 0;
    uint16_t reg_count = 0;
    uint16_t ins_size = 0;
    uint16_t handler_count = 0;
    uint16_t code_size = 0;
    uint8_t ret_kind = RET_V;
    uint8_t isa_id = 0;
    /** inverse[wire] = canonical; identity for v1/v2. */
    std::array<uint8_t, 256> inv_map{};
    bool has_morph = false;
    /** v5+: XOR key for CONST / CONST_WIDE immediates. v1–v4 = 0. */
    int32_t imm_key = 0;
    /** Extra compiler scratch regs after the Dalvik frame. v2–v4 = 1; v1 = 0. */
    uint8_t scratch_extra = 1;
    std::vector<std::string> strings;
    std::vector<std::string> methods;
    std::vector<std::string> fields;
    std::vector<std::string> types;
    std::vector<Pvm2Handler> handlers;
    std::vector<uint8_t> code;
    bool valid = false;
};

bool parse_pvm2(const uint8_t* data, size_t size, Pvm2Image* out);

inline uint8_t demorph_op(const Pvm2Image& img, uint8_t wire) {
    if (!img.has_morph) {
        return wire;
    }
    return img.inv_map[wire];
}

} // namespace protector::vm
