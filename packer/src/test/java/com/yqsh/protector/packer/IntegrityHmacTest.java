package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.yqsh.protector.packer.util.CryptoUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.junit.jupiter.api.Test;

/**
 * Integrity v1: file HMAC and post-wipe .bitcode HMAC match native checks.
 * Integrity v2: code.bin method-set HMAC (sorted dex/method_idx/flags).
 */
class IntegrityHmacTest {

    @Test
    void fileHmacChangesWhenOneByteFlips() {
        byte[] key = sequential((byte) 0x11, 32);
        byte[] pdx1 = "PDX1-fixture-bytes".getBytes(StandardCharsets.US_ASCII);
        String a = CryptoUtils.toHex(CryptoUtils.hmacSha256(key, pdx1));
        pdx1[pdx1.length - 1] ^= 1;
        String b = CryptoUtils.toHex(CryptoUtils.hmacSha256(key, pdx1));
        assertEquals(64, a.length());
        assertNotEquals(a, b);
    }

    @Test
    void bitcodePostWipeIgnoresMasterSlot() {
        byte[] key = sequential((byte) 0x22, 32);
        byte[] plain = new byte[96];
        System.arraycopy(KeyLadder.MASTER_MAGIC, 0, plain, 16, KeyLadder.MASTER_MAGIC.length);
        Arrays.fill(plain, 16 + KeyLadder.MASTER_MAGIC.length,
                16 + KeyLadder.MASTER_MAGIC.length + KeyLadder.MASTER_LEN, (byte) 0x5a);
        String withMaster = SoSectionEncryptor.hmacBitcodePostWipe(plain, key);

        byte[] zeroed = Arrays.copyOf(plain, plain.length);
        Arrays.fill(zeroed, 16 + KeyLadder.MASTER_MAGIC.length,
                16 + KeyLadder.MASTER_MAGIC.length + KeyLadder.MASTER_LEN, (byte) 0);
        String alreadyZero = SoSectionEncryptor.hmacBitcodePostWipe(zeroed, key);
        assertEquals(withMaster, alreadyZero);
        assertEquals(64, withMaster.length());
    }

    @Test
    void bitcodeHmacJsonStableOrder() {
        Map<String, String> m = new TreeMap<>();
        m.put("armeabi-v7a", sequentialHex(1));
        m.put("arm64-v8a", sequentialHex(2));
        String json = PackerMain.formatBitcodeHmacJson(m);
        assertEquals("{\"arm64-v8a\":\"" + sequentialHex(2)
                + "\",\"armeabi-v7a\":\"" + sequentialHex(1) + "\"}", json);
        assertThrows(IllegalArgumentException.class, () -> PackerMain.formatBitcodeHmacJson(Map.of()));
    }

    @Test
    void codeMethodsHmacStableAndSensitive() {
        byte[] key = sequential((byte) 0x33, 32);
        PackerMain.InsnRecord a = rec(7, 2);
        PackerMain.InsnRecord b = rec(3, 0);
        Map<Integer, List<PackerMain.InsnRecord>> map = new HashMap<>();
        map.put(1, List.of(a));
        map.put(0, List.of(b));
        String mac = CodeMethodsIntegrity.hmacHex(key, map);

        Map<Integer, List<PackerMain.InsnRecord>> swapped = new HashMap<>();
        swapped.put(0, List.of(b));
        swapped.put(1, List.of(a));
        assertEquals(mac, CodeMethodsIntegrity.hmacHex(key, swapped));

        byte[] enc = CodeMethodsIntegrity.encode(map);
        assertEquals(4 + 2 * 12, enc.length);
        // LE count = 2
        assertEquals(2, enc[0] & 0xff);
        assertEquals(0, enc[1]);
        // first row is dex=0 (sorted)
        assertEquals(0, enc[4]);

        PackerMain.InsnRecord flipped = rec(3, 0);
        flipped.methodIndex = 4;
        Map<Integer, List<PackerMain.InsnRecord>> other = new HashMap<>();
        other.put(0, List.of(flipped));
        other.put(1, List.of(a));
        assertNotEquals(mac, CodeMethodsIntegrity.hmacHex(key, other));
        assertEquals(64, mac.length());
    }

    @Test
    void codeMethodsHmacEmptySet() {
        byte[] key = sequential((byte) 0x44, 32);
        String empty = CodeMethodsIntegrity.hmacHex(key, Map.of());
        Map<Integer, List<PackerMain.InsnRecord>> blanks = new HashMap<>();
        blanks.put(0, List.of());
        assertEquals(empty, CodeMethodsIntegrity.hmacHex(key, blanks));
        byte[] enc = CodeMethodsIntegrity.encode(Map.of());
        assertEquals(4, enc.length);
        assertEquals(0, enc[0]);
    }

    private static PackerMain.InsnRecord rec(int methodIndex, int flags) {
        PackerMain.InsnRecord r = new PackerMain.InsnRecord();
        r.methodIndex = methodIndex;
        r.flags = flags;
        return r;
    }

    private static byte[] sequential(byte start, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (start + i);
        }
        return out;
    }

    private static String sequentialHex(int seed) {
        byte[] b = new byte[32];
        for (int i = 0; i < 32; i++) {
            b[i] = (byte) (seed + i);
        }
        return CryptoUtils.toHex(b);
    }
}
