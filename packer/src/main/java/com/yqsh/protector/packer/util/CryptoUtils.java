package com.yqsh.protector.packer.util;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Crypto helpers shared by packer and matching native crypto/aes.* / sha256.*.
 * AES-128-GCM for code.bin method bodies; AES-128-CTR (zero IV) for SO sections;
 * HKDF-SHA256 (RFC 5869) for the key ladder (must match native
 * {@code protector::crypto::hkdf_sha256}).
 */
public final class CryptoUtils {
    public static final int AES_KEY_LEN = 16;
    public static final int GCM_NONCE_LEN = 12;
    public static final int GCM_TAG_LEN = 16;
    /** SHA-256 / HMAC-SHA256 output length. */
    public static final int SHA256_LEN = 32;
    /** RFC 5869: N = ceil(L / HashLen) must be &lt;= 255. */
    public static final int HKDF_MAX_OUT_LEN = 255 * SHA256_LEN;

    private CryptoUtils() {
    }

    /**
     * AES-128-GCM encrypt. Returns {@code nonce(12) || ciphertext || tag(16)}.
     */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] plain) throws Exception {
        if (key == null || key.length != AES_KEY_LEN || plain == null) {
            throw new IllegalArgumentException("invalid AES-GCM args");
        }
        byte[] nonce = new byte[GCM_NONCE_LEN];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_LEN * 8, nonce));
        byte[] ctAndTag = cipher.doFinal(plain);
        byte[] out = new byte[GCM_NONCE_LEN + ctAndTag.length];
        System.arraycopy(nonce, 0, out, 0, GCM_NONCE_LEN);
        System.arraycopy(ctAndTag, 0, out, GCM_NONCE_LEN, ctAndTag.length);
        return out;
    }

    /**
     * AES-128-CTR with all-zero IV (size-preserving). Same key+IV on decrypt.
     */
    public static byte[] aesCtrCrypt(byte[] key, byte[] data) throws Exception {
        if (key == null || key.length != AES_KEY_LEN || data == null) {
            throw new IllegalArgumentException("invalid AES-CTR args");
        }
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(new byte[16]));
        return cipher.doFinal(data);
    }

    /** RC4 matching FreeBSD/native rc4.c (SO .bitcode size-preserving encrypt). */
    public static byte[] rc4Crypt(byte[] key, byte[] in) {
        if (key == null || key.length == 0 || in == null) {
            return null;
        }
        byte[] perm = new byte[256];
        for (int i = 0; i < 256; i++) {
            perm[i] = (byte) i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + (perm[i] & 0xff) + (key[i % key.length] & 0xff)) & 0xff;
            byte tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
        byte[] out = new byte[in.length];
        int i = 0;
        j = 0;
        for (int n = 0; n < in.length; n++) {
            i = (i + 1) & 0xff;
            j = (j + (perm[i] & 0xff)) & 0xff;
            byte tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
            int k = ((perm[i] & 0xff) + (perm[j] & 0xff)) & 0xff;
            out[n] = (byte) (in[n] ^ perm[k]);
        }
        return out;
    }

    public static String toHex(byte[] data) {
        if (data == null) return "";
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    /**
     * HMAC-SHA256. Empty {@code data} is allowed (RFC 2104).
     */
    public static byte[] hmacSha256(byte[] key, byte[] data) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("HMAC key required");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data != null ? data : new byte[0]);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /**
     * HKDF-SHA256 (RFC 5869 Extract-then-Expand).
     * {@code salt == null} or empty → HashLen zero bytes (RFC default).
     * {@code info == null} → empty info.
     */
    public static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int outLen) {
        if (ikm == null) {
            throw new IllegalArgumentException("HKDF IKM required");
        }
        if (outLen <= 0 || outLen > HKDF_MAX_OUT_LEN) {
            throw new IllegalArgumentException("HKDF outLen out of range: " + outLen);
        }
        byte[] saltKey = (salt == null || salt.length == 0)
                ? new byte[SHA256_LEN]
                : salt;
        byte[] prk = hmacSha256(saltKey, ikm);
        try {
            return hkdfExpand(prk, info != null ? info : new byte[0], outLen);
        } finally {
            Arrays.fill(prk, (byte) 0);
            if (salt == null || salt.length == 0) {
                Arrays.fill(saltKey, (byte) 0);
            }
        }
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int outLen) {
        int n = (outLen + SHA256_LEN - 1) / SHA256_LEN;
        byte[] okm = new byte[outLen];
        byte[] t = new byte[0];
        int filled = 0;
        try {
            for (int i = 1; i <= n; i++) {
                byte[] block = new byte[t.length + info.length + 1];
                System.arraycopy(t, 0, block, 0, t.length);
                System.arraycopy(info, 0, block, t.length, info.length);
                block[block.length - 1] = (byte) i;
                t = hmacSha256(prk, block);
                Arrays.fill(block, (byte) 0);
                int copy = Math.min(SHA256_LEN, outLen - filled);
                System.arraycopy(t, 0, okm, filled, copy);
                filled += copy;
            }
            return okm;
        } finally {
            Arrays.fill(t, (byte) 0);
        }
    }
}
