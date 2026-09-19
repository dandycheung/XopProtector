package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

class Pvm2MorphTest {

    @Test
    void xorI32LeRoundTrip() {
        byte[] b = new byte[]{1, 2, 3, 4, 5, 6};
        int key = 0x12345678;
        Pvm2Morph.xorI32Le(b, 2, key);
        assertNotEquals(3, b[2] & 0xff);
        Pvm2Morph.xorI32Le(b, 2, key);
        assertEquals(3, b[2] & 0xff);
        assertEquals(4, b[3] & 0xff);
        assertEquals(5, b[4] & 0xff);
        assertEquals(6, b[5] & 0xff);
    }

    @Test
    void morphCodeXorsConstImmediate() {
        int imm = 42;
        ByteBuffer bb = ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN);
        bb.put((byte) Pvm2Opcodes.OP_CONST);
        bb.put((byte) 0);
        bb.putInt(imm);
        byte[] code = bb.array();

        Pvm2Morph morph = Pvm2Morph.fromIsa(1, new SecureRandom());
        assertTrue(morph.immKey != 0);
        morph.morphCodeInPlace(code);

        assertEquals(morph.wire(Pvm2Opcodes.OP_CONST), code[0]);
        int stored = (code[2] & 0xff)
                | ((code[3] & 0xff) << 8)
                | ((code[4] & 0xff) << 16)
                | ((code[5] & 0xff) << 24);
        assertEquals(imm ^ morph.immKey, stored);
        Pvm2Morph.xorI32Le(code, 2, morph.immKey);
        int restored = (code[2] & 0xff)
                | ((code[3] & 0xff) << 8)
                | ((code[4] & 0xff) << 16)
                | ((code[5] & 0xff) << 24);
        assertEquals(imm, restored);
    }
}
