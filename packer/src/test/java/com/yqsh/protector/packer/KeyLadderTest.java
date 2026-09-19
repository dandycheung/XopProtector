package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.yqsh.protector.packer.util.CryptoUtils;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Domain-separated HKDF vectors shared with native {@code key_ladder_self_test}.
 */
class KeyLadderTest {

    @Test
    void fixtureMatchesNativeGoldens() {
        byte[] master = sequential((byte) 0x00, 32);
        byte[] cert = sequential((byte) 0x20, 32);
        KeyLadder.Derived d = KeyLadder.derive(master, cert, "com.yqsh.protectordemo");
        assertEquals("377ce3ca1ceb73aa0318643721a0a84a", CryptoUtils.toHex(d.dex));
        assertEquals("38e9face9f71e908b85c1e564efb4a89", CryptoUtils.toHex(d.insn));
        assertEquals("5442b8e8c5ac63a13adfab1cb0385785", CryptoUtils.toHex(d.so));
        assertEquals("3e8114e0448f162d290263d25c39feef", CryptoUtils.toHex(d.sowarm));
        assertEquals("86305d5b387e5431a8004e3c7bdfc645", CryptoUtils.toHex(d.assets));
        assertFalse(Arrays.equals(d.so, d.sowarm));
        assertEquals(
                "91766823d4ae9feaa9d3f8ab390a2e3d"
                        + "504fade7afee6b9ffb11ec7eae5de688",
                CryptoUtils.toHex(d.hmac));
        assertFalse(Arrays.equals(d.dex, d.so));
        assertFalse(Arrays.equals(d.dex, d.insn));
        assertFalse(Arrays.equals(d.dex, d.assets));
        assertEquals(16, d.dex.length);
        assertEquals(32, d.hmac.length);
    }

    @Test
    void sokeysWrapKeyIsNotDexKey() {
        KeyLadder.Derived d = KeyLadder.derive(
                sequential((byte) 0x00, 32),
                sequential((byte) 0x20, 32),
                "com.yqsh.protectordemo");
        // PSOK must be GCM-wrapped with K_so; K_dex decrypt would fail.
        assertFalse(Arrays.equals(d.so, d.dex));
    }

    @Test
    void wrapMasterRoundTrip() {
        byte[] master = sequential((byte) 0xA0, 32);
        byte[] wrapped = KeyLadder.wrapMaster(master);
        byte[] back = new byte[32];
        for (int i = 0; i < 32; i++) {
            back[i] = (byte) (wrapped[i] ^ KeyLadder.MASTER_PAD[i]);
        }
        assertArrayEquals(master, back);
        assertEquals(16, KeyLadder.MASTER_MAGIC.length);
    }

    @Test
    void wrapWrapKeyRoundTrip() {
        byte[] wrap = sequential((byte) 0xB0, 16);
        byte[] wrapped = KeyLadder.wrapWrapKey(wrap);
        byte[] back = new byte[16];
        for (int i = 0; i < 16; i++) {
            back[i] = (byte) (wrapped[i] ^ KeyLadder.WRAP_PAD[i]);
        }
        assertArrayEquals(wrap, back);
        assertEquals(16, KeyLadder.WRAP_MAGIC.length);
        assertEquals(".protwrap", KeyLadder.PROTWRAP_SECTION);
        assertThrows(IllegalArgumentException.class, () -> KeyLadder.wrapWrapKey(new byte[8]));
    }

    @Test
    void masterMagicIsUniqueInSyntheticBitcode() {
        byte[] buf = new byte[80];
        System.arraycopy(KeyLadder.MASTER_MAGIC, 0, buf, 8, KeyLadder.MASTER_MAGIC.length);
        assertEquals(8, SoSectionEncryptor.findUniqueMagic(buf));
        assertThrows(IllegalStateException.class, () -> SoSectionEncryptor.findUniqueMagic(new byte[64]));
    }

    @Test
    void wrapMagicIsUniqueInSyntheticProtwrap() {
        byte[] buf = new byte[48];
        System.arraycopy(KeyLadder.WRAP_MAGIC, 0, buf, 4, KeyLadder.WRAP_MAGIC.length);
        assertEquals(4, SoSectionEncryptor.findUniqueMagic(
                buf, KeyLadder.WRAP_MAGIC, KeyLadder.WRAP_LEN, "XOPKWRAP"));
        assertThrows(IllegalStateException.class, () -> SoSectionEncryptor.findUniqueMagic(
                new byte[32], KeyLadder.WRAP_MAGIC, KeyLadder.WRAP_LEN, "XOPKWRAP"));
    }

    @Test
    void fromHexRejectsBadInput() {
        assertThrows(IllegalArgumentException.class, () -> KeyLadder.fromHex("ab"));
        assertThrows(IllegalArgumentException.class, () -> KeyLadder.derive(new byte[16], new byte[32], "p"));
        assertThrows(IllegalArgumentException.class,
                () -> KeyLadder.derive(new byte[32], new byte[32], ""));
    }

    private static byte[] sequential(byte start, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (start + i);
        }
        return out;
    }
}
