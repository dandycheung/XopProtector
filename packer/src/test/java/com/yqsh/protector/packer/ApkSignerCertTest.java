package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

class ApkSignerCertTest {

    private static final long MAGIC_LO = 0x20676953204b5041L;
    private static final long MAGIC_HI = 0x3234206b636f6c42L;

    @Test
    void v2FirstCertSha256() throws Exception {
        byte[] cert = sequential((byte) 0x30, 48);
        File apk = writeApk(new byte[]{0x50, 0x4b},
                signingBlock(ApkSignerCert.V2_ID, schemeValue(cert)));
        try {
            assertEquals(sha256Hex(cert), ApkSignerCert.sha256Hex(apk));
            assertTrue(Arrays.equals(cert, ApkSignerCert.firstCertificateDer(apk)));
        } finally {
            //noinspection ResultOfMethodCallIgnored
            apk.delete();
        }
    }

    @Test
    void v3PreferredOverV2() throws Exception {
        byte[] certV2 = sequential((byte) 0x11, 16);
        byte[] certV3 = sequential((byte) 0x22, 16);
        byte[] block = signingBlockTwoSchemes(
                ApkSignerCert.V2_ID, schemeValue(certV2),
                ApkSignerCert.V3_ID, schemeValue(certV3));
        File apk = writeApk(new byte[8], block);
        try {
            assertEquals(sha256Hex(certV3), ApkSignerCert.sha256Hex(apk));
        } finally {
            //noinspection ResultOfMethodCallIgnored
            apk.delete();
        }
    }

    @Test
    void v3Only() throws Exception {
        byte[] cert = sequential((byte) 0x41, 24);
        File apk = writeApk(new byte[4],
                signingBlock(ApkSignerCert.V3_ID, schemeValue(cert)));
        try {
            assertEquals(sha256Hex(cert), ApkSignerCert.sha256Hex(apk));
        } finally {
            //noinspection ResultOfMethodCallIgnored
            apk.delete();
        }
    }

    @Test
    void unsignedZipHasNoSigningBlock() throws Exception {
        File apk = File.createTempFile("unsigned-", ".apk");
        try (FileOutputStream fos = new FileOutputStream(apk)) {
            fos.write(eocd(0, 0));
        }
        try {
            assertThrows(Exception.class, () -> ApkSignerCert.sha256Hex(apk));
        } finally {
            //noinspection ResultOfMethodCallIgnored
            apk.delete();
        }
    }

    @Test
    void missingSchemeReturnsNullCert() throws Exception {
        // Signing block present but only an unknown ID — no v2/v3.
        byte[] block = signingBlock(0x12345678, new byte[]{1, 2, 3, 4});
        File apk = writeApk(new byte[1], block);
        try {
            assertNull(ApkSignerCert.firstCertificateDer(apk));
            assertNull(ApkSignerCert.sha256Hex(apk));
        } finally {
            //noinspection ResultOfMethodCallIgnored
            apk.delete();
        }
    }

    @Test
    void firstCertInSchemeParsesLengthPrefixedBlob() {
        byte[] cert = {0x30, 0x01, 0x00};
        byte[] value = schemeValue(cert);
        ByteBuffer buf = ByteBuffer.wrap(value).order(ByteOrder.LITTLE_ENDIAN);
        byte[] got = ApkSignerCert.firstCertInScheme(buf);
        assertNotNull(got);
        assertTrue(Arrays.equals(cert, got));
    }

    private static String sha256Hex(byte[] data) throws Exception {
        return ApkSignerCert.toHexLower(MessageDigest.getInstance("SHA-256").digest(data));
    }

    private static byte[] sequential(byte start, int len) {
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            out[i] = (byte) (start + i);
        }
        return out;
    }

    /** v2/v3 scheme value: signers → signer → signed-data → digests, certs, attrs. */
    static byte[] schemeValue(byte[] certDer) {
        byte[] emptySeq = prefixed(new byte[0]);
        byte[] certsSeq = prefixed(prefixed(certDer));
        byte[] signedData = concat(emptySeq, certsSeq, emptySeq);
        byte[] signer = concat(prefixed(signedData), prefixed(new byte[0]), prefixed(new byte[0]));
        return prefixed(prefixed(signer));
    }

    static byte[] signingBlock(int id, byte[] value) {
        return signingBlockPairs(new int[]{id}, new byte[][]{value});
    }

    static byte[] signingBlockTwoSchemes(int id1, byte[] v1, int id2, byte[] v2) {
        return signingBlockPairs(new int[]{id1, id2}, new byte[][]{v1, v2});
    }

    private static byte[] signingBlockPairs(int[] ids, byte[][] values) {
        long pairsLen = 0;
        for (byte[] value : values) {
            pairsLen += 8 + 4 + value.length;
        }
        long blockSize = pairsLen + 8 + 16;
        int total = (int) (blockSize + 8);
        ByteBuffer b = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        b.putLong(blockSize);
        for (int i = 0; i < ids.length; i++) {
            b.putLong(4L + values[i].length);
            b.putInt(ids[i]);
            b.put(values[i]);
        }
        b.putLong(blockSize);
        b.putLong(MAGIC_LO);
        b.putLong(MAGIC_HI);
        return b.array();
    }

    static File writeApk(byte[] prefix, byte[] signingBlock) throws Exception {
        long cdOffset = prefix.length + signingBlock.length;
        byte[] eocd = eocd(cdOffset, 0);
        File f = File.createTempFile("apk-sign-test-", ".apk");
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(prefix);
            fos.write(signingBlock);
            fos.write(eocd);
        }
        return f;
    }

    static byte[] eocd(long cdOffset, long cdSize) {
        ByteBuffer b = ByteBuffer.allocate(22).order(ByteOrder.LITTLE_ENDIAN);
        b.putInt(0x06054b50);
        b.putShort((short) 0);
        b.putShort((short) 0);
        b.putShort((short) 0);
        b.putShort((short) 0);
        b.putInt((int) cdSize);
        b.putInt((int) cdOffset);
        b.putShort((short) 0);
        return b.array();
    }

    static byte[] prefixed(byte[] inner) {
        byte[] out = new byte[4 + inner.length];
        ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN).putInt(inner.length);
        System.arraycopy(inner, 0, out, 4, inner.length);
        return out;
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }
}
