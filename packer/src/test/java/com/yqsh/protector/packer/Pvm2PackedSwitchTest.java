package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.android.dex.ClassData;
import com.android.dex.ClassDef;
import com.android.dex.Code;
import com.android.dex.Dex;
import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder;
import com.android.tools.smali.dexlib2.builder.SwitchLabelElement;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderPackedSwitchPayload;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderSparseSwitchPayload;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

class Pvm2PackedSwitchTest {

    @Test
    void packedSwitchCompiles() throws Exception {
        byte[] dexBytes = assemblePackedSwitchDex();
        Pvm2Compiler.Result r = compileFirstStaticIntMethod(dexBytes);
        assertTrue(r.isOk(), () -> "compile failed: " + r.failReason);
        assertNotNull(r.image);
    }

    @Test
    void sparseSwitchStillUnsupported() throws Exception {
        byte[] dexBytes = assembleSparseSwitchDex();
        Pvm2Compiler.Result r = compileFirstStaticIntMethod(dexBytes);
        assertTrue(!r.isOk());
        assertTrue(r.failReason.contains("unsupported opcode 0x2c"),
                () -> "expected 0x2c skip, got: " + r.failReason);
    }

    private static Pvm2Compiler.Result compileFirstStaticIntMethod(byte[] dexBytes)
            throws java.io.IOException {
        Dex dex = new Dex(dexBytes);
        for (ClassDef classDef : dex.classDefs()) {
            if (classDef.getClassDataOffset() == 0) {
                continue;
            }
            ClassData classData = dex.readClassData(classDef);
            for (ClassData.Method method : classData.getDirectMethods()) {
                if (method.getCodeOffset() == 0) {
                    continue;
                }
                String name = dex.strings().get(
                        dex.methodIds().get(method.getMethodIndex()).getNameIndex());
                if ("<init>".equals(name) || "<clinit>".equals(name)) {
                    continue;
                }
                Code code = dex.readCode(method);
                return Pvm2Compiler.tryCompile(dex, code, "I", true);
            }
        }
        throw new IllegalStateException("no static method with code");
    }

    private static byte[] assemblePackedSwitchDex() throws Exception {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Label payload = b.getLabel("payload");
        Label c0 = b.getLabel("c0");
        Label c1 = b.getLabel("c1");
        b.addInstruction(new BuilderInstruction31t(Opcode.PACKED_SWITCH, 0, payload));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, -1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("c0");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 10));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("c1");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 20));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("payload");
        b.addInstruction(new BuilderPackedSwitchPayload(0, List.of(c0, c1)));
        return writeDex("packedSwitch", b.getMethodImplementation());
    }

    private static byte[] assembleSparseSwitchDex() throws Exception {
        MethodImplementationBuilder b = new MethodImplementationBuilder(1);
        Label payload = b.getLabel("payload");
        Label c0 = b.getLabel("c0");
        Label c10 = b.getLabel("c10");
        b.addInstruction(new BuilderInstruction31t(Opcode.SPARSE_SWITCH, 0, payload));
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 0, -1));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("c0");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 10));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("c10");
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 20));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        b.addLabel("payload");
        b.addInstruction(new BuilderSparseSwitchPayload(List.of(
                new SwitchLabelElement(0, c0),
                new SwitchLabelElement(10, c10))));
        return writeDex("sparseSwitch", b.getMethodImplementation());
    }

    private static byte[] writeDex(String methodName, MethodImplementation impl) throws Exception {
        ImmutableMethod method = new ImmutableMethod(
                "LProbe;",
                methodName,
                List.of(new ImmutableMethodParameter("I", null, null)),
                "I",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(),
                null,
                impl);
        ImmutableClassDef cls = new ImmutableClassDef(
                "LProbe;",
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                null,
                Collections.emptySet(),
                Collections.emptySet(),
                Collections.emptySet(),
                List.of(method),
                Collections.emptyList());
        DexPool pool = new DexPool(Opcodes.getDefault());
        pool.internClass(cls);
        MemoryDataStore store = new MemoryDataStore();
        pool.writeTo(store);
        return store.getData();
    }
}
