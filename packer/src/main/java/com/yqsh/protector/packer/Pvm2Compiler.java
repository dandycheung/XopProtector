package com.yqsh.protector.packer;

import com.android.dex.Code;
import com.android.dex.Dex;
import com.android.dex.MethodId;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Compiles Dalvik method bodies into PVM2 v4 images (float/double/monitor ISA).
 */
public final class Pvm2Compiler {
    private static final int MAX_REGS = 32;
    private static final int MAX_CODE_UNITS = 512;
    private static final int PACKED_SWITCH_IDENT = 0x0100;
    private static final int SPARSE_SWITCH_IDENT = 0x0200;
    private static final int FILL_ARRAY_DATA_IDENT = 0x0300;

    public static final class Result {
        public final byte[] image;
        public final String failReason;

        private Result(byte[] image, String failReason) {
            this.image = image;
            this.failReason = failReason;
        }

        public static Result ok(byte[] image) {
            return new Result(image, null);
        }

        public static Result fail(String reason) {
            return new Result(null, reason);
        }

        public boolean isOk() {
            return image != null;
        }
    }

    private Pvm2Compiler() {
    }

    public static Result tryCompile(Dex dex, Code code, String returnType, boolean isStatic) {
        return tryCompile(dex, code, returnType, isStatic, null);
    }

    public static Result tryCompile(Dex dex, Code code, String returnType, boolean isStatic,
                                    Pvm2Morph morph) {
        if (code == null) return Result.fail("no code");
        if (code.getRegistersSize() > MAX_REGS) return Result.fail("too many regs");
        short[] units = code.getInstructions();
        if (units == null || units.length == 0) return Result.fail("empty");
        if (units.length > MAX_CODE_UNITS) return Result.fail("too large");

        int retKind = retKindOf(returnType);
        if (retKind < 0) return Result.fail("unsupported return " + returnType);

        // Extra scratch: lit* / packed-switch use +1; fill-array-data needs +2 (index+value),
        // or +3 when element_width is 8 (wide value pair).
        int dalvikRegs = code.getRegistersSize();
        int extra = extraRegsForUnits(units);
        int scratchReg = dalvikRegs;
        int totalRegs = dalvikRegs + extra;
        if (totalRegs > MAX_REGS) return Result.fail("too many regs (+scratch)");

        if (morph == null) {
            morph = Pvm2Morph.fromIsa(0, new java.security.SecureRandom());
        }

        List<String> strings = new ArrayList<>();
        List<Integer> methodPool = new ArrayList<>(); // indices into strings
        List<Integer> fieldPool = new ArrayList<>();
        List<Integer> typePool = new ArrayList<>();
        Map<Integer, Integer> dalvikPcToEmitIndex = new HashMap<>();
        List<Emit> emits = new ArrayList<>();
        List<Fixup> fixups = new ArrayList<>();

        int pc = 0;
        while (pc < units.length) {
            dalvikPcToEmitIndex.put(pc, emits.size());
            int op = units[pc] & 0xff;
            try {
                int advance = translateOne(dex, units, pc, op, scratchReg, totalRegs, strings,
                        methodPool, fieldPool, typePool, emits, fixups);
                if (advance <= 0) {
                    return Result.fail("bad advance at pc=" + pc + " op=0x" + Integer.toHexString(op));
                }
                pc += advance;
            } catch (UnsupportedOperationException ex) {
                return Result.fail(ex.getMessage());
            } catch (RuntimeException ex) {
                return Result.fail("pc=" + pc + " op=0x" + Integer.toHexString(op) + ": " + ex.getMessage());
            }
        }

        ByteArrayOutputStream codeBuf = new ByteArrayOutputStream();
        int[] emitOffsets = new int[emits.size()];
        try {
            for (int i = 0; i < emits.size(); i++) {
                emitOffsets[i] = codeBuf.size();
                emits.get(i).write(codeBuf);
            }
        } catch (IOException e) {
            return Result.fail(e.getMessage());
        }
        byte[] codeBytes = codeBuf.toByteArray();

        for (Fixup f : fixups) {
            Integer targetEmit = dalvikPcToEmitIndex.get(f.targetDalvikPc);
            if (targetEmit == null) return Result.fail("bad branch target " + f.targetDalvikPc);
            int from = emitOffsets[f.emitIndex] + f.relFieldOffsetInEmit;
            int afterInsn = emitOffsets[f.emitIndex] + emits.get(f.emitIndex).size();
            int rel = emitOffsets[targetEmit] - afterInsn;
            if (rel < Short.MIN_VALUE || rel > Short.MAX_VALUE) {
                return Result.fail("branch too far");
            }
            codeBytes[from] = (byte) (rel & 0xff);
            codeBytes[from + 1] = (byte) ((rel >> 8) & 0xff);
        }

        List<Handler> handlers = new ArrayList<>();
        try {
            buildHandlers(dex, code, dalvikPcToEmitIndex, emitOffsets, strings, typePool, handlers);
        } catch (UnsupportedOperationException ex) {
            return Result.fail(ex.getMessage());
        }

        try {
            morph.morphCodeInPlace(codeBytes);
            return Result.ok(buildImageV3(totalRegs, extra, code.getInsSize(), retKind, morph,
                    strings, methodPool, fieldPool, typePool, handlers, codeBytes));
        } catch (IOException e) {
            return Result.fail(e.getMessage());
        } catch (RuntimeException e) {
            return Result.fail("morph: " + e.getMessage());
        }
    }

    private static void buildHandlers(Dex dex, Code code,
                                      Map<Integer, Integer> dalvikPcToEmitIndex,
                                      int[] emitOffsets,
                                      List<String> strings,
                                      List<Integer> typePool,
                                      List<Handler> out) {
        Code.Try[] tries = code.getTries();
        if (tries == null || tries.length == 0) return;
        Code.CatchHandler[] catches = code.getCatchHandlers();
        if (catches == null) throw new UnsupportedOperationException("tries without handlers");

        for (Code.Try t : tries) {
            int startPc = t.getStartAddress();
            int endPc = startPc + t.getInstructionCount();
            Integer startEmit = dalvikPcToEmitIndex.get(startPc);
            if (startEmit == null) {
                throw new UnsupportedOperationException("try start not mapped " + startPc);
            }
            int startOff = emitOffsets[startEmit];
            int endOff = codeEndOffset(dalvikPcToEmitIndex, emitOffsets, endPc);

            Code.CatchHandler ch = catches[t.getCatchHandlerIndex()];
            int[] typeIdxs = ch.getTypeIndexes();
            int[] addrs = ch.getAddresses();
            if (typeIdxs != null && addrs != null) {
                for (int i = 0; i < typeIdxs.length && i < addrs.length; i++) {
                    addHandler(dex, startOff, endOff, addrs[i], typeIdxs[i],
                            dalvikPcToEmitIndex, emitOffsets, strings, typePool, out);
                }
            }
            int catchAll = ch.getCatchAllAddress();
            if (catchAll >= 0) {
                addHandler(dex, startOff, endOff, catchAll, -1,
                        dalvikPcToEmitIndex, emitOffsets, strings, typePool, out);
            }
        }
    }

    /**
     * Half-open try end in PVM2 code bytes for Dalvik {@code endPc}.
     * {@code dalvikPcToEmitIndex} records only the <em>first</em> emit of each Dalvik insn;
     * lit* lowering emits CONST+BINOP, so {@code bestEmit+1} is wrong — use the first emit of
     * the next Dalvik insn (or {@link Integer#MAX_VALUE} when the try covers the method end).
     */
    private static int codeEndOffset(Map<Integer, Integer> map, int[] emitOffsets, int endPc) {
        Integer exact = map.get(endPc);
        if (exact != null) return emitOffsets[exact];
        int bestPc = -1;
        for (Map.Entry<Integer, Integer> e : map.entrySet()) {
            int pc = e.getKey();
            if (pc < endPc && pc > bestPc) bestPc = pc;
        }
        if (bestPc < 0) throw new UnsupportedOperationException("try end unmapped");
        int nextPc = Integer.MAX_VALUE;
        Integer nextEmit = null;
        for (Map.Entry<Integer, Integer> e : map.entrySet()) {
            int pc = e.getKey();
            if (pc > bestPc && pc < nextPc) {
                nextPc = pc;
                nextEmit = e.getValue();
            }
        }
        if (nextEmit != null) return emitOffsets[nextEmit];
        return Integer.MAX_VALUE;
    }

    private static void addHandler(Dex dex, int startOff, int endOff, int handlerPc,
                                   int typeIdx, Map<Integer, Integer> map, int[] emitOffsets,
                                   List<String> strings, List<Integer> typePool,
                                   List<Handler> out) {
        Integer he = map.get(handlerPc);
        if (he == null) throw new UnsupportedOperationException("handler pc unmapped " + handlerPc);
        int handlerOff = emitOffsets[he];
        int catchTypePoolIdx = 0xFFFF;
        if (typeIdx >= 0) {
            catchTypePoolIdx = internType(typePool, strings, dex.typeNames().get(typeIdx));
        }
        out.add(new Handler(startOff, endOff, handlerOff, catchTypePoolIdx));
    }

    private static int retKindOf(String returnType) {
        if (returnType == null) return -1;
        switch (returnType) {
            case "V":
                return Pvm2Opcodes.RET_V;
            case "I":
            case "B":
            case "S":
            case "C":
                return Pvm2Opcodes.RET_I;
            case "F":
                return Pvm2Opcodes.RET_F;
            case "Z":
                return Pvm2Opcodes.RET_Z;
            case "J":
                return Pvm2Opcodes.RET_J;
            case "D":
                return Pvm2Opcodes.RET_D;
            default:
                if (returnType.startsWith("L") || returnType.startsWith("[")) {
                    return Pvm2Opcodes.RET_L;
                }
                return -1;
        }
    }

    private static int kindOfType(String type) {
        if (type == null) return Pvm2Opcodes.KIND_L;
        switch (type) {
            case "I":
            case "F":
                return Pvm2Opcodes.KIND_I;
            case "J":
            case "D":
                return Pvm2Opcodes.KIND_J;
            case "Z":
                return Pvm2Opcodes.KIND_Z;
            case "B":
                return Pvm2Opcodes.KIND_B;
            case "S":
                return Pvm2Opcodes.KIND_S;
            case "C":
                return Pvm2Opcodes.KIND_C;
            default:
                return Pvm2Opcodes.KIND_L;
        }
    }

    private static int translateOne(Dex dex, short[] units, int pc, int op,
                                    int scratchReg, int totalRegs,
                                    List<String> strings,
                                    List<Integer> methodPool,
                                    List<Integer> fieldPool,
                                    List<Integer> typePool,
                                    List<Emit> emits, List<Fixup> fixups) {
        int u0 = units[pc] & 0xffff;
        switch (op) {
            case 0x00: {
                int ident = u0;
                if (ident == PACKED_SWITCH_IDENT
                        || ident == SPARSE_SWITCH_IDENT
                        || ident == FILL_ARRAY_DATA_IDENT) {
                    return payloadWidth(units, pc);
                }
                emits.add(Emit.of(Pvm2Opcodes.OP_NOP));
                return 1;
            }
            case 0x01: {
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x02: {
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE, (u0 >> 8) & 0xff, units[pc + 1] & 0xffff));
                return 2;
            }
            case 0x04: {
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_WIDE, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x05: {
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_WIDE, (u0 >> 8) & 0xff, units[pc + 1] & 0xffff));
                return 2;
            }
            case 0x07: {
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_OBJ, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x08: {
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_OBJ, (u0 >> 8) & 0xff, units[pc + 1] & 0xffff));
                return 2;
            }
            case 0x0a:
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_RESULT, (u0 >> 8) & 0xff));
                return 1;
            case 0x0b:
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_RESULT_WIDE, (u0 >> 8) & 0xff));
                return 1;
            case 0x0c:
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_RESULT_OBJ, (u0 >> 8) & 0xff));
                return 1;
            case 0x0d:
                emits.add(Emit.of(Pvm2Opcodes.OP_MOVE_EXCEPTION, (u0 >> 8) & 0xff));
                return 1;
            case 0x0e:
                emits.add(Emit.of(Pvm2Opcodes.OP_RETURN_VOID));
                return 1;
            case 0x0f:
                emits.add(Emit.of(Pvm2Opcodes.OP_RETURN, (u0 >> 8) & 0xff));
                return 1;
            case 0x10:
                emits.add(Emit.of(Pvm2Opcodes.OP_RETURN_WIDE, (u0 >> 8) & 0xff));
                return 1;
            case 0x11:
                emits.add(Emit.of(Pvm2Opcodes.OP_RETURN_OBJ, (u0 >> 8) & 0xff));
                return 1;
            case 0x12: {
                int a = (u0 >> 8) & 0x0f;
                int b = (u0 << 16) >> 28;
                emits.add(Emit.const32(a, b));
                return 1;
            }
            case 0x13: {
                emits.add(Emit.const32((u0 >> 8) & 0xff, units[pc + 1]));
                return 2;
            }
            case 0x14: {
                int imm = (units[pc + 1] & 0xffff) | ((units[pc + 2] & 0xffff) << 16);
                emits.add(Emit.const32((u0 >> 8) & 0xff, imm));
                return 3;
            }
            case 0x15: {
                emits.add(Emit.const32((u0 >> 8) & 0xff, (units[pc + 1] & 0xffff) << 16));
                return 2;
            }
            case 0x16: {
                emits.add(Emit.const64((u0 >> 8) & 0xff, units[pc + 1]));
                return 2;
            }
            case 0x17: {
                long imm = (units[pc + 1] & 0xffffL) | ((units[pc + 2] & 0xffffL) << 16);
                emits.add(Emit.const64((u0 >> 8) & 0xff, imm));
                return 3;
            }
            case 0x18: { // const-wide
                long imm = (units[pc + 1] & 0xffffL)
                        | ((units[pc + 2] & 0xffffL) << 16)
                        | ((units[pc + 3] & 0xffffL) << 32)
                        | ((units[pc + 4] & 0xffffL) << 48);
                emits.add(Emit.const64((u0 >> 8) & 0xff, imm));
                return 5;
            }
            case 0x19: { // const-wide/high16
                emits.add(Emit.const64((u0 >> 8) & 0xff, ((long) (units[pc + 1] & 0xffff)) << 48));
                return 2;
            }
            case 0x1a: {
                String s = dex.strings().get(units[pc + 1] & 0xffff);
                emits.add(Emit.constStr((u0 >> 8) & 0xff, intern(strings, s)));
                return 2;
            }
            case 0x1b: {
                int strIdx = (units[pc + 1] & 0xffff) | ((units[pc + 2] & 0xffff) << 16);
                emits.add(Emit.constStr((u0 >> 8) & 0xff, intern(strings, dex.strings().get(strIdx))));
                return 3;
            }
            case 0x1c: { // const-class
                String t = dex.typeNames().get(units[pc + 1] & 0xffff);
                emits.add(Emit.u8u16(Pvm2Opcodes.OP_CONST_CLASS, (u0 >> 8) & 0xff,
                        internType(typePool, strings, t)));
                return 2;
            }
            case 0x1d: { // monitor-enter
                emits.add(Emit.of(Pvm2Opcodes.OP_MONITOR_ENTER, (u0 >> 8) & 0xff));
                return 1;
            }
            case 0x1e: { // monitor-exit
                emits.add(Emit.of(Pvm2Opcodes.OP_MONITOR_EXIT, (u0 >> 8) & 0xff));
                return 1;
            }
            case 0x1f: { // check-cast
                String t = dex.typeNames().get(units[pc + 1] & 0xffff);
                emits.add(Emit.u8u16(Pvm2Opcodes.OP_CHECK_CAST, (u0 >> 8) & 0xff,
                        internType(typePool, strings, t)));
                return 2;
            }
            case 0x20: { // instance-of
                int a = (u0 >> 8) & 0x0f;
                int b = (u0 >> 12) & 0x0f;
                String t = dex.typeNames().get(units[pc + 1] & 0xffff);
                emits.add(Emit.instanceOf(a, b, internType(typePool, strings, t)));
                return 2;
            }
            case 0x21: { // array-length
                emits.add(Emit.of(Pvm2Opcodes.OP_ARRAY_LENGTH, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x22: { // new-instance
                String t = dex.typeNames().get(units[pc + 1] & 0xffff);
                emits.add(Emit.u8u16(Pvm2Opcodes.OP_NEW_INSTANCE, (u0 >> 8) & 0xff,
                        internType(typePool, strings, t)));
                return 2;
            }
            case 0x23: { // new-array
                int a = (u0 >> 8) & 0x0f;
                int b = (u0 >> 12) & 0x0f;
                String t = dex.typeNames().get(units[pc + 1] & 0xffff);
                emits.add(Emit.newArray(a, b, internType(typePool, strings, t)));
                return 2;
            }
            case 0x24: { // filled-new-array
                return translateFilledNewArray(dex, units, pc, false, strings, typePool, emits);
            }
            case 0x25: { // filled-new-array/range
                return translateFilledNewArray(dex, units, pc, true, strings, typePool, emits);
            }
            case 0x26: { // fill-array-data → CONST index/value + APUT (no new PVM2 op)
                return translateFillArrayData(units, pc, scratchReg, scratchReg + 1, totalRegs,
                        emits);
            }
            case 0x27: { // throw
                emits.add(Emit.of(Pvm2Opcodes.OP_THROW, (u0 >> 8) & 0xff));
                return 1;
            }
            case 0x2b: { // packed-switch → CONST + IF_EQ chain (no new PVM2 op)
                return translatePackedSwitch(units, pc, scratchReg, emits, fixups);
            }
            case 0x28: {
                int emitIndex = emits.size();
                emits.add(Emit.gotoPlaceholder());
                fixups.add(new Fixup(emitIndex, 1, pc + (byte) ((u0 >> 8) & 0xff)));
                return 1;
            }
            case 0x29: {
                int emitIndex = emits.size();
                emits.add(Emit.gotoPlaceholder());
                fixups.add(new Fixup(emitIndex, 1, pc + units[pc + 1]));
                return 2;
            }
            case 0x2d: case 0x2e: { // cmpl-float / cmpg-float
                int kind = (op == 0x2d) ? Pvm2Opcodes.CMP_FLOAT_L : Pvm2Opcodes.CMP_FLOAT_G;
                int aa = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.cmp(kind, aa, bc & 0xff, (bc >> 8) & 0xff));
                return 2;
            }
            case 0x2f: case 0x30: { // cmpl-double / cmpg-double
                int kind = (op == 0x2f) ? Pvm2Opcodes.CMP_DOUBLE_L : Pvm2Opcodes.CMP_DOUBLE_G;
                int aa = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.cmp(kind, aa, bc & 0xff, (bc >> 8) & 0xff));
                return 2;
            }
            case 0x31: { // cmp-long
                int aa = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.cmp(Pvm2Opcodes.CMP_LONG, aa, bc & 0xff, (bc >> 8) & 0xff));
                return 2;
            }
            case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37: {
                int cond = op - 0x32;
                int emitIndex = emits.size();
                emits.add(Emit.ifCmpPlaceholder(cond, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                fixups.add(new Fixup(emitIndex, 4, pc + units[pc + 1]));
                return 2;
            }
            case 0x38: case 0x39: case 0x3a: case 0x3b: case 0x3c: case 0x3d: {
                int cond = op - 0x38;
                int emitIndex = emits.size();
                emits.add(Emit.ifZPlaceholder(cond, (u0 >> 8) & 0xff));
                fixups.add(new Fixup(emitIndex, 3, pc + units[pc + 1]));
                return 2;
            }
            case 0x44: case 0x45: case 0x46: case 0x47: case 0x48: case 0x49: case 0x4a: {
                // aget-*
                int kind = agetKindFixed(op);
                int aa = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.aget(aa, bc & 0xff, (bc >> 8) & 0xff, kind));
                return 2;
            }
            case 0x4b: case 0x4c: case 0x4d: case 0x4e: case 0x4f: case 0x50: case 0x51: {
                int kind = aputKind(op);
                int aa = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.aput(aa, bc & 0xff, (bc >> 8) & 0xff, kind));
                return 2;
            }
            case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58: {
                // iget
                int kind = igetKind(op);
                int a = (u0 >> 8) & 0x0f;
                int b = (u0 >> 12) & 0x0f;
                int fid = internField(dex, fieldPool, strings, units[pc + 1] & 0xffff);
                emits.add(Emit.iget(a, b, fid, kind));
                return 2;
            }
            case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f: {
                int kind = iputKind(op);
                int a = (u0 >> 8) & 0x0f;
                int b = (u0 >> 12) & 0x0f;
                int fid = internField(dex, fieldPool, strings, units[pc + 1] & 0xffff);
                emits.add(Emit.iput(a, b, fid, kind));
                return 2;
            }
            case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: {
                int kind = sgetKind(op);
                int fid = internField(dex, fieldPool, strings, units[pc + 1] & 0xffff);
                emits.add(Emit.sget((u0 >> 8) & 0xff, fid, kind));
                return 2;
            }
            case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d: {
                int kind = sputKind(op);
                int fid = internField(dex, fieldPool, strings, units[pc + 1] & 0xffff);
                emits.add(Emit.sput((u0 >> 8) & 0xff, fid, kind));
                return 2;
            }
            case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72: {
                return translateInvoke35(dex, units, pc, op, strings, methodPool, emits);
            }
            case 0x74: case 0x75: case 0x76: case 0x77: case 0x78: {
                return translateInvoke3r(dex, units, pc, op, strings, methodPool, emits);
            }
            case 0x7b: { // neg-int
                emits.add(Emit.of(Pvm2Opcodes.OP_NEG, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x7c: { // not-int
                emits.add(Emit.unop(Pvm2Opcodes.UN_NOT_INT, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x7d: { // neg-long
                emits.add(Emit.unop(Pvm2Opcodes.UN_NEG_LONG, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x7e: { // not-long
                emits.add(Emit.unop(Pvm2Opcodes.UN_NOT_LONG, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x7f: { // neg-float
                emits.add(Emit.unop(Pvm2Opcodes.UN_NEG_FLOAT, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x80: { // neg-double
                emits.add(Emit.unop(Pvm2Opcodes.UN_NEG_DOUBLE, (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x81: case 0x82: case 0x83: case 0x84: case 0x85: case 0x86:
            case 0x87: case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c:
            case 0x8d: case 0x8e: case 0x8f: {
                emits.add(Emit.unop(mapUnop(op), (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99: case 0x9a: {
                int bin = mapBinop(op);
                int a = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.binop(bin, a, bc & 0xff, (bc >> 8) & 0xff));
                return 2;
            }
            case 0x9b: case 0x9c: case 0x9d: case 0x9e: case 0x9f: case 0xa0: case 0xa1:
            case 0xa2: case 0xa3: case 0xa4: case 0xa5: {
                int bin = mapBinopLong(op);
                int a = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.binopWide(bin, a, bc & 0xff, (bc >> 8) & 0xff));
                return 2;
            }
            case 0xa6: case 0xa7: case 0xa8: case 0xa9: case 0xaa: {
                int bin = mapBinopFloat(op);
                int a = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.binopFloat(bin, a, bc & 0xff, (bc >> 8) & 0xff));
                return 2;
            }
            case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf: {
                int bin = mapBinopDouble(op);
                int a = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                emits.add(Emit.binopDouble(bin, a, bc & 0xff, (bc >> 8) & 0xff));
                return 2;
            }
            case 0xb0: case 0xb1: case 0xb2: case 0xb3: case 0xb4: case 0xb5: case 0xb6: case 0xb7:
            case 0xb8: case 0xb9: case 0xba: {
                emits.add(Emit.binop2addr(mapBinop2addr(op), (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0xbb: case 0xbc: case 0xbd: case 0xbe: case 0xbf: case 0xc0: case 0xc1:
            case 0xc2: case 0xc3: case 0xc4: case 0xc5: {
                emits.add(Emit.binop2addrWide(mapBinop2addrLong(op),
                        (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0xc6: case 0xc7: case 0xc8: case 0xc9: case 0xca: {
                emits.add(Emit.binop2addrFloat(mapBinop2addrFloat(op),
                        (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0xcb: case 0xcc: case 0xcd: case 0xce: case 0xcf: {
                emits.add(Emit.binop2addrDouble(mapBinop2addrDouble(op),
                        (u0 >> 8) & 0x0f, (u0 >> 12) & 0x0f));
                return 1;
            }
            case 0xd0: case 0xd1: case 0xd2: case 0xd3: case 0xd4: case 0xd5: case 0xd6: case 0xd7: {
                // binop/lit16 — a = b OP lit; rsub-int is a = lit - b
                int a = (u0 >> 8) & 0x0f;
                int b = (u0 >> 12) & 0x0f;
                short lit = units[pc + 1];
                if (op == 0xd1) {
                    emits.add(Emit.const32(scratchReg, lit));
                    emits.add(Emit.binop(Pvm2Opcodes.BIN_SUB, a, scratchReg, b));
                } else {
                    emits.add(Emit.const32(scratchReg, lit));
                    emits.add(Emit.binop(mapBinopLit16(op), a, b, scratchReg));
                }
                return 2;
            }
            case 0xd8: case 0xd9: case 0xda: case 0xdb: case 0xdc: case 0xdd: case 0xde: case 0xdf:
            case 0xe0: case 0xe1: case 0xe2: {
                int bin = mapBinopLit8(op);
                int a = (u0 >> 8) & 0xff;
                int bc = units[pc + 1] & 0xffff;
                int b = bc & 0xff;
                int lit = (byte) ((bc >> 8) & 0xff);
                emits.add(Emit.const32(scratchReg, lit));
                emits.add(Emit.binop(bin, a, b, scratchReg));
                return 2;
            }
            default:
                throw new UnsupportedOperationException("unsupported opcode 0x" + Integer.toHexString(op));
        }
    }

    /**
     * packed-switch vAA, +BBBBBBBB. Payload ident 0x0100.
     * Lowered to {@code CONST scratch, key} + {@code IF_EQ vAA, scratch, target} per case;
     * default is fall-through. Does not add a PVM2 opcode (morph table stays 50).
     */
    private static int translatePackedSwitch(short[] units, int pc, int scratchReg,
                                            List<Emit> emits, List<Fixup> fixups) {
        if (pc + 3 > units.length) {
            throw new UnsupportedOperationException("truncated packed-switch");
        }
        int vAA = (units[pc] >> 8) & 0xff;
        int payloadPc = pc + readI32Units(units, pc + 1);
        if (payloadPc < 0 || payloadPc + 4 > units.length) {
            throw new UnsupportedOperationException("bad packed-switch payload");
        }
        if ((units[payloadPc] & 0xffff) != PACKED_SWITCH_IDENT) {
            throw new UnsupportedOperationException("bad packed-switch ident");
        }
        int size = units[payloadPc + 1] & 0xffff;
        int firstKey = readI32Units(units, payloadPc + 2);
        int width = 4 + size * 2;
        if (payloadPc + width > units.length) {
            throw new UnsupportedOperationException("truncated packed-switch payload");
        }
        for (int i = 0; i < size; i++) {
            int targetRel = readI32Units(units, payloadPc + 4 + i * 2);
            int targetPc = pc + targetRel;
            if (targetPc < 0 || targetPc >= units.length) {
                throw new UnsupportedOperationException("bad packed-switch target");
            }
            int key = firstKey + i;
            emits.add(Emit.const32(scratchReg, key));
            int emitIndex = emits.size();
            emits.add(Emit.ifCmpPlaceholder(Pvm2Opcodes.COND_EQ, vAA, scratchReg));
            fixups.add(new Fixup(emitIndex, 4, targetPc));
        }
        return 3;
    }

    /**
     * fill-array-data vAA, +BBBBBBBB. Payload ident 0x0300.
     * Lowered to {@code CONST idx} + {@code CONST val} + {@code APUT} per element.
     * Width 1/2/4/8 → byte/short/int/long kinds; interpreter discriminates
     * boolean/char/float/double by runtime array type. No new PVM2 opcode.
     */
    private static int translateFillArrayData(short[] units, int pc, int scratchIdx,
                                              int scratchVal, int totalRegs, List<Emit> emits) {
        if (pc + 3 > units.length) {
            throw new UnsupportedOperationException("truncated fill-array-data");
        }
        int vAA = (units[pc] >> 8) & 0xff;
        int payloadPc = pc + readI32Units(units, pc + 1);
        if (payloadPc < 0 || payloadPc + 4 > units.length) {
            throw new UnsupportedOperationException("bad fill-array-data payload");
        }
        if ((units[payloadPc] & 0xffff) != FILL_ARRAY_DATA_IDENT) {
            throw new UnsupportedOperationException("bad fill-array-data ident");
        }
        int elemWidth = units[payloadPc + 1] & 0xffff;
        int size = readI32Units(units, payloadPc + 2);
        if (size < 0) {
            throw new UnsupportedOperationException("bad fill-array-data size");
        }
        int kind;
        boolean wide;
        switch (elemWidth) {
            case 1:
                kind = Pvm2Opcodes.KIND_B;
                wide = false;
                break;
            case 2:
                kind = Pvm2Opcodes.KIND_S;
                wide = false;
                break;
            case 4:
                kind = Pvm2Opcodes.KIND_I;
                wide = false;
                break;
            case 8:
                kind = Pvm2Opcodes.KIND_J;
                wide = true;
                break;
            default:
                throw new UnsupportedOperationException("bad fill-array-data width " + elemWidth);
        }
        int need = wide ? scratchVal + 2 : scratchVal + 1;
        if (need > totalRegs) {
            throw new UnsupportedOperationException("too many regs (+scratch)");
        }
        long dataBytes = (long) size * (long) elemWidth;
        int dataUnits = (int) ((dataBytes + 1) / 2);
        if (payloadPc + 4 + dataUnits > units.length) {
            throw new UnsupportedOperationException("truncated fill-array-data payload");
        }
        for (int i = 0; i < size; i++) {
            emits.add(Emit.const32(scratchIdx, i));
            int byteOff = i * elemWidth;
            if (wide) {
                emits.add(Emit.const64(scratchVal, readPayloadLong(units, payloadPc, byteOff)));
            } else {
                int val;
                if (elemWidth == 1) {
                    val = (byte) readPayloadByte(units, payloadPc, byteOff);
                } else if (elemWidth == 2) {
                    val = (short) (readPayloadByte(units, payloadPc, byteOff)
                            | (readPayloadByte(units, payloadPc, byteOff + 1) << 8));
                } else {
                    val = readPayloadByte(units, payloadPc, byteOff)
                            | (readPayloadByte(units, payloadPc, byteOff + 1) << 8)
                            | (readPayloadByte(units, payloadPc, byteOff + 2) << 16)
                            | (readPayloadByte(units, payloadPc, byteOff + 3) << 24);
                }
                emits.add(Emit.const32(scratchVal, val));
            }
            emits.add(Emit.aput(scratchVal, vAA, scratchIdx, kind));
        }
        return 3;
    }

    private static int extraRegsForUnits(short[] units) {
        int extra = 1;
        int pc = 0;
        while (pc < units.length) {
            int u0 = units[pc] & 0xffff;
            int op = u0 & 0xff;
            if (op == 0x00 && (u0 == PACKED_SWITCH_IDENT
                    || u0 == SPARSE_SWITCH_IDENT
                    || u0 == FILL_ARRAY_DATA_IDENT)) {
                try {
                    int w = payloadWidth(units, pc);
                    pc += Math.max(w, 1);
                } catch (RuntimeException e) {
                    pc += 1;
                }
                continue;
            }
            if (op == 0x26 && pc + 3 <= units.length) {
                int payloadPc = pc + readI32Units(units, pc + 1);
                if (payloadPc >= 0 && payloadPc + 4 <= units.length
                        && (units[payloadPc] & 0xffff) == FILL_ARRAY_DATA_IDENT) {
                    int elemWidth = units[payloadPc + 1] & 0xffff;
                    extra = Math.max(extra, elemWidth >= 8 ? 3 : 2);
                }
                pc += 3;
                continue;
            }
            int n = dalvikCodeUnits(op);
            if (pc + n > units.length) {
                break;
            }
            pc += n;
        }
        return extra;
    }

    /**
     * Dalvik instruction size in code units (payloads handled separately).
     * Matches the dex instruction list used by ART / smali.
     */
    private static int dalvikCodeUnits(int op) {
        switch (op) {
            case 0x03: case 0x06: case 0x09: // move/16 family
            case 0x14: // const
            case 0x17: // const-wide/32
            case 0x1b: // const-string/jumbo
            case 0x2a: // goto/32
            case 0x24: case 0x25: // filled-new-array
            case 0x26: case 0x2b: case 0x2c: // fill/switch
            case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72:
            case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:
            case 0x79: case 0x7a:
            case 0xfc: case 0xfd: // invoke-custom
                return 3;
            case 0x18: // const-wide
                return 5;
            case 0xfa: case 0xfb: // invoke-polymorphic
                return 4;
            case 0x01: case 0x04: case 0x07:
            case 0x0a: case 0x0b: case 0x0c: case 0x0d:
            case 0x0e: case 0x0f: case 0x10: case 0x11:
            case 0x12: case 0x1d: case 0x1e: case 0x21: case 0x27: case 0x28:
                return 1;
            case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f:
            case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
            case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
            case 0x8a: case 0x8b: case 0x8c: case 0x8d: case 0x8e: case 0x8f:
                return 1;
            default:
                if (op >= 0xb0 && op <= 0xcf) {
                    return 1;
                }
                if (op <= 0x00) {
                    return 1;
                }
                return 2;
        }
    }

    private static int readPayloadByte(short[] units, int payloadPc, int byteIndex) {
        int unit = units[payloadPc + 4 + (byteIndex / 2)] & 0xffff;
        if ((byteIndex & 1) == 0) {
            return unit & 0xff;
        }
        return (unit >> 8) & 0xff;
    }

    private static long readPayloadLong(short[] units, int payloadPc, int byteOff) {
        long v = 0;
        for (int b = 0; b < 8; b++) {
            v |= ((long) readPayloadByte(units, payloadPc, byteOff + b)) << (8 * b);
        }
        return v;
    }

    private static int payloadWidth(short[] units, int pc) {
        int ident = units[pc] & 0xffff;
        if (ident == PACKED_SWITCH_IDENT) {
            if (pc + 2 > units.length) {
                throw new UnsupportedOperationException("truncated packed-switch payload");
            }
            int size = units[pc + 1] & 0xffff;
            int width = 4 + size * 2;
            if (pc + width > units.length) {
                throw new UnsupportedOperationException("truncated packed-switch payload");
            }
            return width;
        }
        if (ident == SPARSE_SWITCH_IDENT) {
            if (pc + 2 > units.length) {
                throw new UnsupportedOperationException("truncated sparse-switch payload");
            }
            int size = units[pc + 1] & 0xffff;
            int width = 2 + size * 4;
            if (pc + width > units.length) {
                throw new UnsupportedOperationException("truncated sparse-switch payload");
            }
            return width;
        }
        if (ident == FILL_ARRAY_DATA_IDENT) {
            if (pc + 4 > units.length) {
                throw new UnsupportedOperationException("truncated fill-array-data payload");
            }
            int elemWidth = units[pc + 1] & 0xffff;
            long size = readI32Units(units, pc + 2) & 0xffffffffL;
            long dataBytes = size * (long) elemWidth;
            if (elemWidth == 0 || dataBytes > (long) Integer.MAX_VALUE - 8) {
                throw new UnsupportedOperationException("bad fill-array-data payload");
            }
            int dataUnits = (int) ((dataBytes + 1) / 2);
            int width = 4 + dataUnits;
            if (pc + width > units.length) {
                throw new UnsupportedOperationException("truncated fill-array-data payload");
            }
            return width;
        }
        throw new UnsupportedOperationException("not a payload");
    }

    private static int readI32Units(short[] units, int index) {
        return (units[index] & 0xffff) | ((units[index + 1] & 0xffff) << 16);
    }

    private static int translateInvoke35(Dex dex, short[] units, int pc, int op,
                                         List<String> strings, List<Integer> methodPool,
                                         List<Emit> emits) {
        int pvmOp = invokeOp(op);
        int u0 = units[pc] & 0xffff;
        int argCount = (u0 >> 12) & 0x0f;
        int methodIdx = units[pc + 1] & 0xffff;
        int c = units[pc + 2] & 0xffff;
        int f = (c >> 12) & 0x0f;
        int e = (c >> 8) & 0x0f;
        int d = (c >> 4) & 0x0f;
        int cc = c & 0x0f;
        int mid = internMethod(dex, methodPool, strings, methodIdx);
        int[] regs = new int[argCount];
        if (argCount > 0) regs[0] = cc;
        if (argCount > 1) regs[1] = d;
        if (argCount > 2) regs[2] = e;
        if (argCount > 3) regs[3] = f;
        if (argCount > 4) regs[4] = (u0 >> 8) & 0x0f;
        emits.add(Emit.invoke(pvmOp, mid, regs));
        return 3;
    }

    private static int translateInvoke3r(Dex dex, short[] units, int pc, int op,
                                         List<String> strings, List<Integer> methodPool,
                                         List<Emit> emits) {
        int pvmOp = invokeOpRange(op);
        int u0 = units[pc] & 0xffff;
        int argCount = (u0 >> 8) & 0xff;
        int methodIdx = units[pc + 1] & 0xffff;
        int first = units[pc + 2] & 0xffff;
        int mid = internMethod(dex, methodPool, strings, methodIdx);
        int[] regs = new int[argCount];
        for (int i = 0; i < argCount; i++) regs[i] = first + i;
        emits.add(Emit.invoke(pvmOp, mid, regs));
        return 3;
    }

    private static int translateFilledNewArray(Dex dex, short[] units, int pc, boolean range,
                                               List<String> strings, List<Integer> typePool,
                                               List<Emit> emits) {
        int u0 = units[pc] & 0xffff;
        int typeIdx = units[pc + 1] & 0xffff;
        String t = dex.typeNames().get(typeIdx);
        int tid = internType(typePool, strings, t);
        int[] regs;
        if (range) {
            int argCount = (u0 >> 8) & 0xff;
            int first = units[pc + 2] & 0xffff;
            regs = new int[argCount];
            for (int i = 0; i < argCount; i++) regs[i] = first + i;
        } else {
            int argCount = (u0 >> 12) & 0x0f;
            int c = units[pc + 2] & 0xffff;
            int f = (c >> 12) & 0x0f;
            int e = (c >> 8) & 0x0f;
            int d = (c >> 4) & 0x0f;
            int cc = c & 0x0f;
            regs = new int[argCount];
            if (argCount > 0) regs[0] = cc;
            if (argCount > 1) regs[1] = d;
            if (argCount > 2) regs[2] = e;
            if (argCount > 3) regs[3] = f;
            if (argCount > 4) regs[4] = (u0 >> 8) & 0x0f;
        }
        emits.add(Emit.filledNewArray(tid, regs));
        return 3;
    }

    private static int invokeOp(int dalvikOp) {
        switch (dalvikOp) {
            case 0x6e: return Pvm2Opcodes.OP_INVOKE_VIRTUAL;
            case 0x6f: return Pvm2Opcodes.OP_INVOKE_SUPER;
            case 0x70: return Pvm2Opcodes.OP_INVOKE_DIRECT;
            case 0x71: return Pvm2Opcodes.OP_INVOKE_STATIC;
            case 0x72: return Pvm2Opcodes.OP_INVOKE_INTERFACE;
            default: throw new UnsupportedOperationException("invoke");
        }
    }

    private static int invokeOpRange(int dalvikOp) {
        switch (dalvikOp) {
            case 0x74: return Pvm2Opcodes.OP_INVOKE_VIRTUAL;
            case 0x75: return Pvm2Opcodes.OP_INVOKE_SUPER;
            case 0x76: return Pvm2Opcodes.OP_INVOKE_DIRECT;
            case 0x77: return Pvm2Opcodes.OP_INVOKE_STATIC;
            case 0x78: return Pvm2Opcodes.OP_INVOKE_INTERFACE;
            default: throw new UnsupportedOperationException("invoke/range");
        }
    }

    private static int agetKindFixed(int op) {
        switch (op) {
            case 0x44: return Pvm2Opcodes.KIND_I;
            case 0x45: return Pvm2Opcodes.KIND_J;
            case 0x46: return Pvm2Opcodes.KIND_L;
            case 0x47: return Pvm2Opcodes.KIND_Z;
            case 0x48: return Pvm2Opcodes.KIND_B;
            case 0x49: return Pvm2Opcodes.KIND_C;
            case 0x4a: return Pvm2Opcodes.KIND_S;
            default: return Pvm2Opcodes.KIND_I;
        }
    }

    private static int aputKind(int op) {
        switch (op) {
            case 0x4b: return Pvm2Opcodes.KIND_I;
            case 0x4c: return Pvm2Opcodes.KIND_J;
            case 0x4d: return Pvm2Opcodes.KIND_L;
            case 0x4e: return Pvm2Opcodes.KIND_Z;
            case 0x4f: return Pvm2Opcodes.KIND_B;
            case 0x50: return Pvm2Opcodes.KIND_C;
            case 0x51: return Pvm2Opcodes.KIND_S;
            default: return Pvm2Opcodes.KIND_I;
        }
    }

    private static int igetKind(int op) {
        switch (op) {
            case 0x52: return Pvm2Opcodes.KIND_I;
            case 0x53: return Pvm2Opcodes.KIND_J;
            case 0x54: return Pvm2Opcodes.KIND_L;
            case 0x55: return Pvm2Opcodes.KIND_Z;
            case 0x56: return Pvm2Opcodes.KIND_B;
            case 0x57: return Pvm2Opcodes.KIND_C;
            case 0x58: return Pvm2Opcodes.KIND_S;
            default: return Pvm2Opcodes.KIND_I;
        }
    }

    private static int iputKind(int op) {
        switch (op) {
            case 0x59: return Pvm2Opcodes.KIND_I;
            case 0x5a: return Pvm2Opcodes.KIND_J;
            case 0x5b: return Pvm2Opcodes.KIND_L;
            case 0x5c: return Pvm2Opcodes.KIND_Z;
            case 0x5d: return Pvm2Opcodes.KIND_B;
            case 0x5e: return Pvm2Opcodes.KIND_C;
            case 0x5f: return Pvm2Opcodes.KIND_S;
            default: return Pvm2Opcodes.KIND_I;
        }
    }

    private static int sgetKind(int op) {
        switch (op) {
            case 0x60: return Pvm2Opcodes.KIND_I;
            case 0x61: return Pvm2Opcodes.KIND_J;
            case 0x62: return Pvm2Opcodes.KIND_L;
            case 0x63: return Pvm2Opcodes.KIND_Z;
            case 0x64: return Pvm2Opcodes.KIND_B;
            case 0x65: return Pvm2Opcodes.KIND_C;
            case 0x66: return Pvm2Opcodes.KIND_S;
            default: return Pvm2Opcodes.KIND_I;
        }
    }

    private static int sputKind(int op) {
        switch (op) {
            case 0x67: return Pvm2Opcodes.KIND_I;
            case 0x68: return Pvm2Opcodes.KIND_J;
            case 0x69: return Pvm2Opcodes.KIND_L;
            case 0x6a: return Pvm2Opcodes.KIND_Z;
            case 0x6b: return Pvm2Opcodes.KIND_B;
            case 0x6c: return Pvm2Opcodes.KIND_C;
            case 0x6d: return Pvm2Opcodes.KIND_S;
            default: return Pvm2Opcodes.KIND_I;
        }
    }

    private static int mapBinop(int op) {
        switch (op) {
            case 0x90: return Pvm2Opcodes.BIN_ADD;
            case 0x91: return Pvm2Opcodes.BIN_SUB;
            case 0x92: return Pvm2Opcodes.BIN_MUL;
            case 0x93: return Pvm2Opcodes.BIN_DIV;
            case 0x94: return Pvm2Opcodes.BIN_REM;
            case 0x95: return Pvm2Opcodes.BIN_AND;
            case 0x96: return Pvm2Opcodes.BIN_OR;
            case 0x97: return Pvm2Opcodes.BIN_XOR;
            case 0x98: return Pvm2Opcodes.BIN_SHL;
            case 0x99: return Pvm2Opcodes.BIN_SHR;
            case 0x9a: return Pvm2Opcodes.BIN_USHR;
            default: return -1;
        }
    }

    private static int mapBinop2addr(int op) {
        switch (op) {
            case 0xb0: return Pvm2Opcodes.BIN_ADD;
            case 0xb1: return Pvm2Opcodes.BIN_SUB;
            case 0xb2: return Pvm2Opcodes.BIN_MUL;
            case 0xb3: return Pvm2Opcodes.BIN_DIV;
            case 0xb4: return Pvm2Opcodes.BIN_REM;
            case 0xb5: return Pvm2Opcodes.BIN_AND;
            case 0xb6: return Pvm2Opcodes.BIN_OR;
            case 0xb7: return Pvm2Opcodes.BIN_XOR;
            case 0xb8: return Pvm2Opcodes.BIN_SHL;
            case 0xb9: return Pvm2Opcodes.BIN_SHR;
            case 0xba: return Pvm2Opcodes.BIN_USHR;
            default: return -1;
        }
    }

    private static int mapBinopLong(int op) {
        switch (op) {
            case 0x9b: return Pvm2Opcodes.BIN_ADD;
            case 0x9c: return Pvm2Opcodes.BIN_SUB;
            case 0x9d: return Pvm2Opcodes.BIN_MUL;
            case 0x9e: return Pvm2Opcodes.BIN_DIV;
            case 0x9f: return Pvm2Opcodes.BIN_REM;
            case 0xa0: return Pvm2Opcodes.BIN_AND;
            case 0xa1: return Pvm2Opcodes.BIN_OR;
            case 0xa2: return Pvm2Opcodes.BIN_XOR;
            case 0xa3: return Pvm2Opcodes.BIN_SHL;
            case 0xa4: return Pvm2Opcodes.BIN_SHR;
            case 0xa5: return Pvm2Opcodes.BIN_USHR;
            default: return -1;
        }
    }

    private static int mapBinop2addrLong(int op) {
        switch (op) {
            case 0xbb: return Pvm2Opcodes.BIN_ADD;
            case 0xbc: return Pvm2Opcodes.BIN_SUB;
            case 0xbd: return Pvm2Opcodes.BIN_MUL;
            case 0xbe: return Pvm2Opcodes.BIN_DIV;
            case 0xbf: return Pvm2Opcodes.BIN_REM;
            case 0xc0: return Pvm2Opcodes.BIN_AND;
            case 0xc1: return Pvm2Opcodes.BIN_OR;
            case 0xc2: return Pvm2Opcodes.BIN_XOR;
            case 0xc3: return Pvm2Opcodes.BIN_SHL;
            case 0xc4: return Pvm2Opcodes.BIN_SHR;
            case 0xc5: return Pvm2Opcodes.BIN_USHR;
            default: return -1;
        }
    }

    private static int mapBinopFloat(int op) {
        switch (op) {
            case 0xa6: return Pvm2Opcodes.BIN_ADD;
            case 0xa7: return Pvm2Opcodes.BIN_SUB;
            case 0xa8: return Pvm2Opcodes.BIN_MUL;
            case 0xa9: return Pvm2Opcodes.BIN_DIV;
            case 0xaa: return Pvm2Opcodes.BIN_REM;
            default: return -1;
        }
    }

    private static int mapBinop2addrFloat(int op) {
        switch (op) {
            case 0xc6: return Pvm2Opcodes.BIN_ADD;
            case 0xc7: return Pvm2Opcodes.BIN_SUB;
            case 0xc8: return Pvm2Opcodes.BIN_MUL;
            case 0xc9: return Pvm2Opcodes.BIN_DIV;
            case 0xca: return Pvm2Opcodes.BIN_REM;
            default: return -1;
        }
    }

    private static int mapBinopDouble(int op) {
        switch (op) {
            case 0xab: return Pvm2Opcodes.BIN_ADD;
            case 0xac: return Pvm2Opcodes.BIN_SUB;
            case 0xad: return Pvm2Opcodes.BIN_MUL;
            case 0xae: return Pvm2Opcodes.BIN_DIV;
            case 0xaf: return Pvm2Opcodes.BIN_REM;
            default: return -1;
        }
    }

    private static int mapBinop2addrDouble(int op) {
        switch (op) {
            case 0xcb: return Pvm2Opcodes.BIN_ADD;
            case 0xcc: return Pvm2Opcodes.BIN_SUB;
            case 0xcd: return Pvm2Opcodes.BIN_MUL;
            case 0xce: return Pvm2Opcodes.BIN_DIV;
            case 0xcf: return Pvm2Opcodes.BIN_REM;
            default: return -1;
        }
    }

    private static int mapUnop(int op) {
        switch (op) {
            case 0x81: return Pvm2Opcodes.UN_INT_TO_LONG;
            case 0x82: return Pvm2Opcodes.UN_INT_TO_FLOAT;
            case 0x83: return Pvm2Opcodes.UN_INT_TO_DOUBLE;
            case 0x84: return Pvm2Opcodes.UN_LONG_TO_INT;
            case 0x85: return Pvm2Opcodes.UN_LONG_TO_FLOAT;
            case 0x86: return Pvm2Opcodes.UN_LONG_TO_DOUBLE;
            case 0x87: return Pvm2Opcodes.UN_FLOAT_TO_INT;
            case 0x88: return Pvm2Opcodes.UN_FLOAT_TO_LONG;
            case 0x89: return Pvm2Opcodes.UN_FLOAT_TO_DOUBLE;
            case 0x8a: return Pvm2Opcodes.UN_DOUBLE_TO_INT;
            case 0x8b: return Pvm2Opcodes.UN_DOUBLE_TO_LONG;
            case 0x8c: return Pvm2Opcodes.UN_DOUBLE_TO_FLOAT;
            case 0x8d: return Pvm2Opcodes.UN_INT_TO_BYTE;
            case 0x8e: return Pvm2Opcodes.UN_INT_TO_CHAR;
            case 0x8f: return Pvm2Opcodes.UN_INT_TO_SHORT;
            default: return -1;
        }
    }

    private static int mapBinopLit8(int op) {
        switch (op) {
            case 0xd8: return Pvm2Opcodes.BIN_ADD;
            case 0xd9: return Pvm2Opcodes.BIN_SUB;
            case 0xda: return Pvm2Opcodes.BIN_MUL;
            case 0xdb: return Pvm2Opcodes.BIN_DIV;
            case 0xdc: return Pvm2Opcodes.BIN_REM;
            case 0xdd: return Pvm2Opcodes.BIN_AND;
            case 0xde: return Pvm2Opcodes.BIN_OR;
            case 0xdf: return Pvm2Opcodes.BIN_XOR;
            case 0xe0: return Pvm2Opcodes.BIN_SHL;
            case 0xe1: return Pvm2Opcodes.BIN_SHR;
            case 0xe2: return Pvm2Opcodes.BIN_USHR;
            default: return -1;
        }
    }

    private static int mapBinopLit16(int op) {
        switch (op) {
            case 0xd0: return Pvm2Opcodes.BIN_ADD;
            case 0xd2: return Pvm2Opcodes.BIN_MUL;
            case 0xd3: return Pvm2Opcodes.BIN_DIV;
            case 0xd4: return Pvm2Opcodes.BIN_REM;
            case 0xd5: return Pvm2Opcodes.BIN_AND;
            case 0xd6: return Pvm2Opcodes.BIN_OR;
            case 0xd7: return Pvm2Opcodes.BIN_XOR;
            default: return -1;
        }
    }

    private static int intern(List<String> strings, String s) {
        for (int i = 0; i < strings.size(); i++) {
            if (strings.get(i).equals(s)) return i;
        }
        strings.add(s);
        return strings.size() - 1;
    }

    private static int internType(List<Integer> typePool, List<String> strings, String type) {
        int sidx = intern(strings, type);
        for (int i = 0; i < typePool.size(); i++) {
            if (typePool.get(i) == sidx) return i;
        }
        typePool.add(sidx);
        return typePool.size() - 1;
    }

    private static int internMethod(Dex dex, List<Integer> methodPool, List<String> strings, int methodIdx) {
        MethodId mid = dex.methodIds().get(methodIdx);
        String owner = dex.typeNames().get(mid.getDeclaringClassIndex());
        String name = dex.strings().get(mid.getNameIndex());
        com.android.dex.ProtoId proto = dex.protoIds().get(mid.getProtoIndex());
        String ret = dex.typeNames().get(proto.getReturnTypeIndex());
        StringBuilder sb = new StringBuilder();
        sb.append(owner).append("->").append(name).append('(');
        if (proto.getParametersOffset() != 0) {
            short[] types = dex.readTypeList(proto.getParametersOffset()).getTypes();
            for (short t : types) {
                sb.append(dex.typeNames().get(t & 0xffff));
            }
        }
        sb.append(')').append(ret);
        int sidx = intern(strings, sb.toString());
        for (int i = 0; i < methodPool.size(); i++) {
            if (methodPool.get(i) == sidx) return i;
        }
        methodPool.add(sidx);
        return methodPool.size() - 1;
    }

    private static int internField(Dex dex, List<Integer> fieldPool, List<String> strings, int fieldIdx) {
        com.android.dex.FieldId fid = dex.fieldIds().get(fieldIdx);
        String owner = dex.typeNames().get(fid.getDeclaringClassIndex());
        String name = dex.strings().get(fid.getNameIndex());
        String type = dex.typeNames().get(fid.getTypeIndex());
        String desc = owner + "->" + name + ":" + type;
        int sidx = intern(strings, desc);
        for (int i = 0; i < fieldPool.size(); i++) {
            if (fieldPool.get(i) == sidx) return i;
        }
        fieldPool.add(sidx);
        return fieldPool.size() - 1;
    }

    private static byte[] buildImageV3(int regCount, int extraScratch, int insSize, int retKind,
                                       Pvm2Morph morph,
                                       List<String> strings,
                                       List<Integer> methodPool,
                                       List<Integer> fieldPool,
                                       List<Integer> typePool,
                                       List<Handler> handlers,
                                       byte[] code) throws IOException {
        // Fix handler end offsets that used sentinel
        for (Handler h : handlers) {
            if (h.end < 0) {
                h.end = code.length;
            } else if (h.end > code.length) {
                h.end = code.length;
            }
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bos);
        out.writeBytes("PVM2");
        writeU16(out, Pvm2Opcodes.VERSION);
        writeU16(out, regCount);
        writeU16(out, insSize);
        writeU16(out, handlers.size());
        writeU16(out, code.length);
        out.writeByte(retKind);
        out.writeByte(morph.isaId & 0xff);
        writeU16(out, strings.size());
        for (String s : strings) {
            byte[] utf = s.getBytes(StandardCharsets.UTF_8);
            if (utf.length > 0xffff) throw new IOException("string too long");
            writeU16(out, utf.length);
            out.write(utf);
        }
        writeU16(out, methodPool.size());
        for (int idx : methodPool) writeU16(out, idx);
        writeU16(out, fieldPool.size());
        for (int idx : fieldPool) writeU16(out, idx);
        writeU16(out, typePool.size());
        for (int idx : typePool) writeU16(out, idx);
        out.writeByte(Pvm2Morph.OP_COUNT);
        out.write(morph.forward);
        if (extraScratch < 1 || extraScratch > 3) {
            throw new IOException("bad extraScratch " + extraScratch);
        }
        out.writeByte(extraScratch);
        writeU32(out, morph.immKey);
        for (Handler h : handlers) {
            writeU16(out, h.start);
            writeU16(out, h.end);
            writeU16(out, h.handler);
            writeU16(out, h.catchType);
        }
        out.write(code);
        out.flush();
        return bos.toByteArray();
    }

    private static void writeU16(DataOutputStream out, int v) throws IOException {
        out.writeByte(v & 0xff);
        out.writeByte((v >> 8) & 0xff);
    }

    private static void writeU32(DataOutputStream out, int v) throws IOException {
        out.writeByte(v & 0xff);
        out.writeByte((v >> 8) & 0xff);
        out.writeByte((v >> 16) & 0xff);
        out.writeByte((v >> 24) & 0xff);
    }

    private static final class Handler {
        int start;
        int end;
        final int handler;
        final int catchType;

        Handler(int start, int end, int handler, int catchType) {
            this.start = start;
            this.end = end;
            this.handler = handler;
            this.catchType = catchType;
        }
    }

    private static final class Fixup {
        final int emitIndex;
        final int relFieldOffsetInEmit;
        final int targetDalvikPc;

        Fixup(int emitIndex, int relFieldOffsetInEmit, int targetDalvikPc) {
            this.emitIndex = emitIndex;
            this.relFieldOffsetInEmit = relFieldOffsetInEmit;
            this.targetDalvikPc = targetDalvikPc;
        }
    }

    private static final class Emit {
        final byte[] data;

        Emit(byte[] data) {
            this.data = data;
        }

        int size() {
            return data.length;
        }

        void write(ByteArrayOutputStream out) throws IOException {
            out.write(data);
        }

        static Emit of(int op) {
            return new Emit(new byte[]{(byte) op});
        }

        static Emit of(int op, int a) {
            return new Emit(new byte[]{(byte) op, (byte) a});
        }

        static Emit of(int op, int a, int b) {
            return new Emit(new byte[]{(byte) op, (byte) a, (byte) b});
        }

        static Emit const32(int dst, int imm) {
            ByteBuffer bb = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_CONST);
            bb.put((byte) dst);
            bb.putInt(imm);
            return new Emit(bb.array());
        }

        static Emit const64(int dst, long imm) {
            ByteBuffer bb = ByteBuffer.allocate(10).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_CONST_WIDE);
            bb.put((byte) dst);
            bb.putLong(imm);
            return new Emit(bb.array());
        }

        static Emit constStr(int dst, int idx) {
            ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_CONST_STR);
            bb.put((byte) dst);
            bb.putShort((short) idx);
            return new Emit(bb.array());
        }

        static Emit u8u16(int op, int a, int idx) {
            ByteBuffer bb = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) op);
            bb.put((byte) a);
            bb.putShort((short) idx);
            return new Emit(bb.array());
        }

        static Emit gotoPlaceholder() {
            return new Emit(new byte[]{(byte) Pvm2Opcodes.OP_GOTO, 0, 0});
        }

        static Emit ifCmpPlaceholder(int cond, int a, int b) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_IF_CMP, (byte) cond, (byte) a, (byte) b, 0, 0
            });
        }

        static Emit ifZPlaceholder(int cond, int a) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_IF_Z, (byte) cond, (byte) a, 0, 0
            });
        }

        static Emit binop(int bin, int dst, int b, int c) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP, (byte) bin, (byte) dst, (byte) b, (byte) c
            });
        }

        static Emit binop2addr(int bin, int dst, int src) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP_2ADDR, (byte) bin, (byte) dst, (byte) src
            });
        }

        static Emit binopWide(int bin, int dst, int b, int c) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP_WIDE, (byte) bin, (byte) dst, (byte) b, (byte) c
            });
        }

        static Emit binop2addrWide(int bin, int dst, int src) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP_2ADDR_WIDE, (byte) bin, (byte) dst, (byte) src
            });
        }

        static Emit binopFloat(int bin, int dst, int b, int c) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP_FLOAT, (byte) bin, (byte) dst, (byte) b, (byte) c
            });
        }

        static Emit binop2addrFloat(int bin, int dst, int src) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP_2ADDR_FLOAT, (byte) bin, (byte) dst, (byte) src
            });
        }

        static Emit binopDouble(int bin, int dst, int b, int c) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP_DOUBLE, (byte) bin, (byte) dst, (byte) b, (byte) c
            });
        }

        static Emit binop2addrDouble(int bin, int dst, int src) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_BINOP_2ADDR_DOUBLE, (byte) bin, (byte) dst, (byte) src
            });
        }

        static Emit unop(int kind, int dst, int src) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_UNOP, (byte) kind, (byte) dst, (byte) src
            });
        }

        static Emit cmp(int kind, int dst, int b, int c) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_CMP, (byte) kind, (byte) dst, (byte) b, (byte) c
            });
        }

        static Emit invoke(int op, int mid, int[] regs) {
            ByteBuffer bb = ByteBuffer.allocate(4 + regs.length).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) op);
            bb.putShort((short) mid);
            bb.put((byte) regs.length);
            for (int r : regs) bb.put((byte) r);
            return new Emit(bb.array());
        }

        static Emit filledNewArray(int typeIdx, int[] regs) {
            ByteBuffer bb = ByteBuffer.allocate(4 + regs.length).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_FILLED_NEW_ARRAY);
            bb.putShort((short) typeIdx);
            bb.put((byte) regs.length);
            for (int r : regs) bb.put((byte) r);
            return new Emit(bb.array());
        }

        static Emit sget(int dst, int fid, int kind) {
            ByteBuffer bb = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_SGET);
            bb.put((byte) dst);
            bb.putShort((short) fid);
            bb.put((byte) kind);
            return new Emit(bb.array());
        }

        static Emit sput(int src, int fid, int kind) {
            ByteBuffer bb = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_SPUT);
            bb.put((byte) src);
            bb.putShort((short) fid);
            bb.put((byte) kind);
            return new Emit(bb.array());
        }

        static Emit iget(int dst, int obj, int fid, int kind) {
            ByteBuffer bb = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_IGET);
            bb.put((byte) dst);
            bb.put((byte) obj);
            bb.putShort((short) fid);
            bb.put((byte) kind);
            return new Emit(bb.array());
        }

        static Emit iput(int src, int obj, int fid, int kind) {
            ByteBuffer bb = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_IPUT);
            bb.put((byte) src);
            bb.put((byte) obj);
            bb.putShort((short) fid);
            bb.put((byte) kind);
            return new Emit(bb.array());
        }

        static Emit newArray(int dst, int size, int typeIdx) {
            ByteBuffer bb = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_NEW_ARRAY);
            bb.put((byte) dst);
            bb.put((byte) size);
            bb.putShort((short) typeIdx);
            return new Emit(bb.array());
        }

        static Emit instanceOf(int dst, int obj, int typeIdx) {
            ByteBuffer bb = ByteBuffer.allocate(5).order(ByteOrder.LITTLE_ENDIAN);
            bb.put((byte) Pvm2Opcodes.OP_INSTANCE_OF);
            bb.put((byte) dst);
            bb.put((byte) obj);
            bb.putShort((short) typeIdx);
            return new Emit(bb.array());
        }

        static Emit aget(int dst, int arr, int idx, int kind) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_AGET, (byte) dst, (byte) arr, (byte) idx, (byte) kind
            });
        }

        static Emit aput(int src, int arr, int idx, int kind) {
            return new Emit(new byte[]{
                    (byte) Pvm2Opcodes.OP_APUT, (byte) src, (byte) arr, (byte) idx, (byte) kind
            });
        }
    }
}
