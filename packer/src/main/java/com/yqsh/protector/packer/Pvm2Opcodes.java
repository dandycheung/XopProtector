package com.yqsh.protector.packer;

/** PVM2 ISA — keep in sync with native/vm/pvm2_format.h */
public final class Pvm2Opcodes {
    private Pvm2Opcodes() {
    }

    /** Phase 5 ISA + PR11 imm XOR morph (v5). */
    public static final int VERSION = 5;

    public static final int RET_V = 0;
    public static final int RET_I = 1;
    public static final int RET_J = 2;
    public static final int RET_L = 3;
    public static final int RET_Z = 4;
    public static final int RET_F = 5;
    public static final int RET_D = 6;

    public static final int OP_NOP = 0;
    public static final int OP_CONST = 1;
    public static final int OP_CONST_WIDE = 2;
    public static final int OP_CONST_STR = 3;
    public static final int OP_MOVE = 4;
    public static final int OP_MOVE_WIDE = 5;
    public static final int OP_MOVE_OBJ = 6;
    public static final int OP_GOTO = 7;
    public static final int OP_IF_CMP = 8;
    public static final int OP_IF_Z = 9;
    public static final int OP_RETURN_VOID = 10;
    public static final int OP_RETURN = 11;
    public static final int OP_RETURN_WIDE = 12;
    public static final int OP_RETURN_OBJ = 13;
    public static final int OP_BINOP = 14;
    public static final int OP_BINOP_2ADDR = 15;

    // Phase 2
    public static final int OP_INVOKE_STATIC = 16;    // u16 mid, u8 argc, u8 regs[argc]
    public static final int OP_INVOKE_VIRTUAL = 17;
    public static final int OP_INVOKE_DIRECT = 18;
    public static final int OP_INVOKE_INTERFACE = 19;
    public static final int OP_INVOKE_SUPER = 20;
    public static final int OP_MOVE_RESULT = 21;      // u8 dst
    public static final int OP_MOVE_RESULT_WIDE = 22;
    public static final int OP_MOVE_RESULT_OBJ = 23;
    public static final int OP_SGET = 24;             // u8 dst, u16 fid, u8 kind
    public static final int OP_SPUT = 25;             // u8 src, u16 fid, u8 kind
    public static final int OP_IGET = 26;             // u8 dst, u8 obj, u16 fid, u8 kind
    public static final int OP_IPUT = 27;             // u8 src, u8 obj, u16 fid, u8 kind
    public static final int OP_NEW_INSTANCE = 28;     // u8 dst, u16 type_idx
    public static final int OP_NEW_ARRAY = 29;        // u8 dst, u8 size, u16 type_idx
    public static final int OP_ARRAY_LENGTH = 30;     // u8 dst, u8 arr
    public static final int OP_AGET = 31;             // u8 dst, u8 arr, u8 idx, u8 kind
    public static final int OP_APUT = 32;             // u8 src, u8 arr, u8 idx, u8 kind
    public static final int OP_CHECK_CAST = 33;       // u8 obj, u16 type_idx
    public static final int OP_INSTANCE_OF = 34;      // u8 dst, u8 obj, u16 type_idx
    public static final int OP_THROW = 35;            // u8 src
    public static final int OP_MOVE_EXCEPTION = 36;   // u8 dst
    public static final int OP_CONST_CLASS = 37;      // u8 dst, u16 type_idx
    public static final int OP_NEG = 38;              // u8 dst, u8 src (int)
    public static final int OP_FILLED_NEW_ARRAY = 39; // u16 type_idx, u8 argc, u8 regs[argc] → pending obj

    // Phase 5 (v4)
    public static final int OP_BINOP_WIDE = 40;       // long: bin, dst, b, c
    public static final int OP_BINOP_2ADDR_WIDE = 41;
    public static final int OP_BINOP_FLOAT = 42;      // float: bin, dst, b, c
    public static final int OP_BINOP_2ADDR_FLOAT = 43;
    public static final int OP_BINOP_DOUBLE = 44;     // double: bin, dst, b, c (wide regs)
    public static final int OP_BINOP_2ADDR_DOUBLE = 45;
    public static final int OP_UNOP = 46;             // u8 unop, u8 dst, u8 src
    public static final int OP_CMP = 47;              // u8 cmp_kind, u8 dst, u8 b, u8 c
    public static final int OP_MONITOR_ENTER = 48;    // u8 obj
    public static final int OP_MONITOR_EXIT = 49;     // u8 obj

    public static final int KIND_I = 0;
    public static final int KIND_J = 1;
    public static final int KIND_L = 2;
    public static final int KIND_Z = 3;
    public static final int KIND_B = 4;
    public static final int KIND_S = 5;
    public static final int KIND_C = 6;

    public static final int COND_EQ = 0;
    public static final int COND_NE = 1;
    public static final int COND_LT = 2;
    public static final int COND_GE = 3;
    public static final int COND_GT = 4;
    public static final int COND_LE = 5;

    public static final int BIN_ADD = 0;
    public static final int BIN_SUB = 1;
    public static final int BIN_MUL = 2;
    public static final int BIN_AND = 3;
    public static final int BIN_OR = 4;
    public static final int BIN_XOR = 5;
    public static final int BIN_SHL = 6;
    public static final int BIN_SHR = 7;
    public static final int BIN_USHR = 8;
    public static final int BIN_DIV = 9;
    public static final int BIN_REM = 10;

    public static final int UN_NEG_LONG = 0;
    public static final int UN_NEG_FLOAT = 1;
    public static final int UN_NEG_DOUBLE = 2;
    public static final int UN_NOT_INT = 3;
    public static final int UN_NOT_LONG = 4;
    public static final int UN_INT_TO_LONG = 5;
    public static final int UN_INT_TO_FLOAT = 6;
    public static final int UN_INT_TO_DOUBLE = 7;
    public static final int UN_LONG_TO_INT = 8;
    public static final int UN_LONG_TO_FLOAT = 9;
    public static final int UN_LONG_TO_DOUBLE = 10;
    public static final int UN_FLOAT_TO_INT = 11;
    public static final int UN_FLOAT_TO_LONG = 12;
    public static final int UN_FLOAT_TO_DOUBLE = 13;
    public static final int UN_DOUBLE_TO_INT = 14;
    public static final int UN_DOUBLE_TO_LONG = 15;
    public static final int UN_DOUBLE_TO_FLOAT = 16;
    public static final int UN_INT_TO_BYTE = 17;
    public static final int UN_INT_TO_CHAR = 18;
    public static final int UN_INT_TO_SHORT = 19;

    public static final int CMP_FLOAT_L = 0;
    public static final int CMP_FLOAT_G = 1;
    public static final int CMP_DOUBLE_L = 2;
    public static final int CMP_DOUBLE_G = 3;
    public static final int CMP_LONG = 4;
}
