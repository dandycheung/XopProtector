package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.yqsh.protector.packer.util.CryptoUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * HKDF-SHA256 vectors shared with native {@code protector::crypto::hkdf_self_test}.
 */
class HkdfSha256Test {

    /** RFC 5869 Appendix A.1 */
    @Test
    void rfc5869Case1() {
        byte[] ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] okm = CryptoUtils.hkdfSha256(ikm, salt, info, 42);
        assertEquals(
                "3cb25f25faacd57a90434f64d0362f2a"
                        + "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                        + "34007208d5b887185865",
                CryptoUtils.toHex(okm));
    }

    /** RFC 5869 Appendix A.3 — empty salt and info (salt defaults to HashLen zeros). */
    @Test
    void rfc5869Case3EmptySaltAndInfo() {
        byte[] ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] okm = CryptoUtils.hkdfSha256(ikm, null, null, 42);
        assertEquals(
                "8da4e775a563c18f715f802a063c5a31"
                        + "b8a11f5c5ee1879ec3454e5f3c738d2d"
                        + "9d201395faa4b61a96c8",
                CryptoUtils.toHex(okm));
        byte[] okmEmptyArr = CryptoUtils.hkdfSha256(ikm, new byte[0], new byte[0], 42);
        assertArrayEquals(okm, okmEmptyArr);
    }

    /**
     * Future key-ladder fixture: IKM=K_master 00..1f, salt=cert 20..3f,
     * info = "xop-dex-v1" || "com.yqsh.protectordemo", L=16
     * and "xop-hmac-v1" || package, L=32.
     * Must match native {@code hkdf_self_test}.
     */
    @Test
    void xopDomainSeparationFixture() {
        byte[] master = sequential((byte) 0x00, 32);
        byte[] cert = sequential((byte) 0x20, 32);
        String pkg = "com.yqsh.protectordemo";
        byte[] dexInfo = concat("xop-dex-v1".getBytes(StandardCharsets.US_ASCII),
                pkg.getBytes(StandardCharsets.US_ASCII));
        byte[] hmacInfo = concat("xop-hmac-v1".getBytes(StandardCharsets.US_ASCII),
                pkg.getBytes(StandardCharsets.US_ASCII));

        byte[] kDex = CryptoUtils.hkdfSha256(master, cert, dexInfo, 16);
        byte[] kHmac = CryptoUtils.hkdfSha256(master, cert, hmacInfo, 32);
        byte[] kSo = CryptoUtils.hkdfSha256(master, cert,
                concat("xop-so-v1".getBytes(StandardCharsets.US_ASCII),
                        pkg.getBytes(StandardCharsets.US_ASCII)),
                16);

        // Golden values from this implementation (RFC 5869); native hkdf_self_test uses the same bytes.
        assertEquals("377ce3ca1ceb73aa0318643721a0a84a", CryptoUtils.toHex(kDex));
        assertEquals(
                "91766823d4ae9feaa9d3f8ab390a2e3d"
                        + "504fade7afee6b9ffb11ec7eae5de688",
                CryptoUtils.toHex(kHmac));
        assertEquals("5442b8e8c5ac63a13adfab1cb0385785", CryptoUtils.toHex(kSo));
        // Domain separation: different info → different keys.
        assertEquals(16, kDex.length);
        assertEquals(16, kSo.length);
        assertFalse(Arrays.equals(kDex, kSo));
    }

    @Test
    void rejectsNullIkmAndBadLength() {
        byte[] ikm = {1, 2, 3};
        assertThrows(IllegalArgumentException.class,
                () -> CryptoUtils.hkdfSha256(null, new byte[32], new byte[0], 16));
        assertThrows(IllegalArgumentException.class,
                () -> CryptoUtils.hkdfSha256(ikm, new byte[32], new byte[0], 0));
        assertThrows(IllegalArgumentException.class,
                () -> CryptoUtils.hkdfSha256(ikm, new byte[32], new byte[0],
                        CryptoUtils.HKDF_MAX_OUT_LEN + 1));
    }

    private static byte[] sequential(byte start, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (start + i);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
