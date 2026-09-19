package com.yqsh.protector.packer;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Per-APK PVM2 opcode morphing (Phase 3). Canonical ops 0..OP_COUNT-1 map to wire bytes.
 */
public final class Pvm2Morph {
    /** NOP..MONITOR_EXIT inclusive (v4). Keep in sync with {@link Pvm2Opcodes}. */
    public static final int OP_COUNT = 50;
    public static final int ISA_COUNT = 3;

    /** Profile id written into PVM2 v3 header (0..2). */
    public final int isaId;
    /** Per-build XOR for CONST / CONST_WIDE immediates (v5). */
    public final int immKey;
    /** forward[canonical] = wire */
    public final byte[] forward;
    /** inverse[wire & 0xff] = canonical, or -1 if unused */
    public final int[] inverse;

    private Pvm2Morph(int isaId, int immKey, byte[] forward, int[] inverse) {
        this.isaId = isaId;
        this.immKey = immKey;
        this.forward = forward;
        this.inverse = inverse;
    }

    public byte wire(int canonical) {
        if (canonical < 0 || canonical >= OP_COUNT) {
            throw new IllegalArgumentException("bad op " + canonical);
        }
        return forward[canonical];
    }

    /** Random isa profile + salted Fisher–Yates shuffle of the opcode space. */
    public static Pvm2Morph random(SecureRandom rng) {
        int isa = rng.nextInt(ISA_COUNT);
        return fromIsa(isa, rng);
    }

    public static Pvm2Morph fromIsa(int isaId, SecureRandom rng) {
        if (isaId < 0 || isaId >= ISA_COUNT) {
            throw new IllegalArgumentException("isaId");
        }
        List<Integer> ops = new ArrayList<>(OP_COUNT);
        for (int i = 0; i < OP_COUNT; i++) {
            ops.add(i);
        }
        // Profile-specific pre-rotate so the three ISAs differ even with same RNG stream.
        Collections.rotate(ops, (isaId + 1) * 7);
        for (int i = OP_COUNT - 1; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            Collections.swap(ops, i, j);
        }
        byte[] forward = new byte[OP_COUNT];
        int[] inverse = new int[256];
        for (int i = 0; i < 256; i++) {
            inverse[i] = -1;
        }
        for (int canonical = 0; canonical < OP_COUNT; canonical++) {
            int wire = ops.get(canonical);
            forward[canonical] = (byte) wire;
            inverse[wire] = canonical;
        }
        int immKey = rng.nextInt();
        if (immKey == 0) {
            immKey = 0xA5A5A5A5;
        }
        return new Pvm2Morph(isaId, immKey, forward, inverse);
    }

    /** Instruction length in bytes for a canonical opcode at {@code code[pc]}. */
    public static int insnSize(byte[] code, int pc) {
        int op = code[pc] & 0xff;
        switch (op) {
            case Pvm2Opcodes.OP_NOP:
            case Pvm2Opcodes.OP_RETURN_VOID:
                return 1;
            case Pvm2Opcodes.OP_RETURN:
            case Pvm2Opcodes.OP_RETURN_WIDE:
            case Pvm2Opcodes.OP_RETURN_OBJ:
            case Pvm2Opcodes.OP_MOVE_RESULT:
            case Pvm2Opcodes.OP_MOVE_RESULT_WIDE:
            case Pvm2Opcodes.OP_MOVE_RESULT_OBJ:
            case Pvm2Opcodes.OP_THROW:
            case Pvm2Opcodes.OP_MOVE_EXCEPTION:
            case Pvm2Opcodes.OP_MONITOR_ENTER:
            case Pvm2Opcodes.OP_MONITOR_EXIT:
                return 2;
            case Pvm2Opcodes.OP_MOVE:
            case Pvm2Opcodes.OP_MOVE_WIDE:
            case Pvm2Opcodes.OP_MOVE_OBJ:
            case Pvm2Opcodes.OP_GOTO:
            case Pvm2Opcodes.OP_ARRAY_LENGTH:
            case Pvm2Opcodes.OP_NEG:
                return 3;
            case Pvm2Opcodes.OP_CONST_STR:
            case Pvm2Opcodes.OP_BINOP_2ADDR:
            case Pvm2Opcodes.OP_BINOP_2ADDR_WIDE:
            case Pvm2Opcodes.OP_BINOP_2ADDR_FLOAT:
            case Pvm2Opcodes.OP_BINOP_2ADDR_DOUBLE:
            case Pvm2Opcodes.OP_NEW_INSTANCE:
            case Pvm2Opcodes.OP_CHECK_CAST:
            case Pvm2Opcodes.OP_CONST_CLASS:
            case Pvm2Opcodes.OP_UNOP:
                return 4;
            case Pvm2Opcodes.OP_BINOP:
            case Pvm2Opcodes.OP_BINOP_WIDE:
            case Pvm2Opcodes.OP_BINOP_FLOAT:
            case Pvm2Opcodes.OP_BINOP_DOUBLE:
            case Pvm2Opcodes.OP_CMP:
            case Pvm2Opcodes.OP_SGET:
            case Pvm2Opcodes.OP_SPUT:
            case Pvm2Opcodes.OP_NEW_ARRAY:
            case Pvm2Opcodes.OP_AGET:
            case Pvm2Opcodes.OP_APUT:
            case Pvm2Opcodes.OP_INSTANCE_OF:
            case Pvm2Opcodes.OP_IF_Z:
                return 5;
            case Pvm2Opcodes.OP_CONST:
            case Pvm2Opcodes.OP_IF_CMP:
            case Pvm2Opcodes.OP_IGET:
            case Pvm2Opcodes.OP_IPUT:
                return 6;
            case Pvm2Opcodes.OP_CONST_WIDE:
                return 10;
            case Pvm2Opcodes.OP_INVOKE_STATIC:
            case Pvm2Opcodes.OP_INVOKE_VIRTUAL:
            case Pvm2Opcodes.OP_INVOKE_DIRECT:
            case Pvm2Opcodes.OP_INVOKE_INTERFACE:
            case Pvm2Opcodes.OP_INVOKE_SUPER:
            case Pvm2Opcodes.OP_FILLED_NEW_ARRAY: {
                // op + u16 + u8 argc + regs[argc]
                if (pc + 4 > code.length) {
                    throw new IllegalArgumentException("truncated invoke at " + pc);
                }
                int argc = code[pc + 3] & 0xff;
                return 4 + argc;
            }
            default:
                throw new IllegalArgumentException("unknown op 0x" + Integer.toHexString(op));
        }
    }

    /** Rewrite opcode bytes canonical → wire and XOR CONST immediates (in place). */
    public void morphCodeInPlace(byte[] code) {
        int pc = 0;
        while (pc < code.length) {
            int canon = code[pc] & 0xff;
            int size = insnSize(code, pc);
            if (canon == Pvm2Opcodes.OP_CONST) {
                xorI32Le(code, pc + 2, immKey);
            } else if (canon == Pvm2Opcodes.OP_CONST_WIDE) {
                xorI32Le(code, pc + 2, immKey);
                xorI32Le(code, pc + 6, immKey);
            }
            code[pc] = wire(canon);
            pc += size;
        }
    }

    static void xorI32Le(byte[] code, int off, int key) {
        if (off < 0 || off + 4 > code.length) {
            throw new IllegalArgumentException("imm xor truncated at " + off);
        }
        int v = (code[off] & 0xff)
                | ((code[off + 1] & 0xff) << 8)
                | ((code[off + 2] & 0xff) << 16)
                | ((code[off + 3] & 0xff) << 24);
        v ^= key;
        code[off] = (byte) v;
        code[off + 1] = (byte) (v >> 8);
        code[off + 2] = (byte) (v >> 16);
        code[off + 3] = (byte) (v >> 24);
    }
}
