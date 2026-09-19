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
import com.android.tools.smali.dexlib2.builder.instruction.BuilderArrayPayload;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11n;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction31t;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

class Pvm2FillArrayDataTest {

    @Test
    void fillIntArrayCompiles() throws Exception {
        byte[] dexBytes = assembleFillArrayDex("[I", 4, List.of(10, 20, 30, 40));
        Pvm2Compiler.Result r = compileFirstStatic(dexBytes, "[I");
        assertTrue(r.isOk(), () -> "compile failed: " + r.failReason);
        assertNotNull(r.image);
    }

    @Test
    void fillByteArrayCompiles() throws Exception {
        byte[] dexBytes = assembleFillArrayDex("[B", 1, List.of(1, 2, 3, 4, 5));
        Pvm2Compiler.Result r = compileFirstStatic(dexBytes, "[B");
        assertTrue(r.isOk(), () -> "compile failed: " + r.failReason);
        assertNotNull(r.image);
    }

    /** 31 Dalvik regs + 1 scratch = 32. A const/16 0x26 must not be scanned as fill-array. */
    @Test
    void thirtyOneRegsWithConst26StillCompiles() throws Exception {
        MethodImplementationBuilder b = new MethodImplementationBuilder(31);
        b.addInstruction(new BuilderInstruction21s(Opcode.CONST_16, 0, 0x26));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN, 0));
        ImmutableMethod method = new ImmutableMethod(
                "LProbe;",
                "wideFrame",
                Collections.emptyList(),
                "I",
                AccessFlags.PUBLIC.getValue() | AccessFlags.STATIC.getValue(),
                Collections.emptySet(),
                null,
                b.getMethodImplementation());
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
        Pvm2Compiler.Result r = compileFirstStatic(store.getData(), "I");
        assertTrue(r.isOk(), () -> "31-reg frame rejected: " + r.failReason);
    }

    private static Pvm2Compiler.Result compileFirstStatic(byte[] dexBytes, String returnType)
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
                return Pvm2Compiler.tryCompile(dex, code, returnType, true);
            }
        }
        throw new IllegalStateException("no static method with code");
    }

    private static byte[] assembleFillArrayDex(String arrayType, int elemWidth, List<Number> values)
            throws Exception {
        MethodImplementationBuilder b = new MethodImplementationBuilder(2);
        Label payload = b.getLabel("payload");
        b.addInstruction(new BuilderInstruction11n(Opcode.CONST_4, 1, values.size()));
        b.addInstruction(new BuilderInstruction22c(
                Opcode.NEW_ARRAY, 0, 1, new ImmutableTypeReference(arrayType)));
        b.addInstruction(new BuilderInstruction31t(Opcode.FILL_ARRAY_DATA, 0, payload));
        b.addInstruction(new BuilderInstruction11x(Opcode.RETURN_OBJECT, 0));
        b.addLabel("payload");
        b.addInstruction(new BuilderArrayPayload(elemWidth, values));
        return writeDex("fillArray", arrayType, b.getMethodImplementation());
    }

    private static byte[] writeDex(String methodName, String returnType, MethodImplementation impl)
            throws Exception {
        ImmutableMethod method = new ImmutableMethod(
                "LProbe;",
                methodName,
                Collections.emptyList(),
                returnType,
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
