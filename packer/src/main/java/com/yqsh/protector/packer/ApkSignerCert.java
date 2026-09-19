package com.yqsh.protector.packer;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * SHA-256 of the first APK Signature Scheme v2/v3 signer certificate (X.509 DER).
 * Must match native {@code protector::crypto::apk_first_signer_cert_sha256}.
 * Does not use {@code PackageManager}; reads the APK Signing Block from the file.
 */
public final class ApkSignerCert {
    /** APK Signature Scheme v2 block ID. */
    public static final int V2_ID = 0x7109871a;
    /** APK Signature Scheme v3 block ID. */
    public static final int V3_ID = 0xf05368c0;

    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;
    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    private static final int ZIP_EOCD_REC_MIN_SIZE = 22;
    private static final int ZIP_EOCD_REC_SIG = 0x06054b50;
    private static final int UINT16_MAX = 0xffff;
    private static final int ZIP_EOCD_COMMENT_LENGTH_OFFSET = 20;
    private static final long MAX_SIGNING_BLOCK = 32L * 1024 * 1024;

    private ApkSignerCert() {
    }

    /**
     * Lowercase hex SHA-256 of the first signer certificate.
     *
     * @return 64 hex chars, or {@code null} if the APK has no parseable v2/v3 block
     */
    public static String sha256Hex(File apk) throws IOException {
        byte[] cert = firstCertificateDer(apk);
        if (cert == null || cert.length == 0) {
            return null;
        }
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(cert);
            return toHexLower(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }

    /**
     * First signer X.509 DER from v3 (preferred) then v2. {@code null} if absent.
     */
    public static byte[] firstCertificateDer(File apk) throws IOException {
        if (apk == null || !apk.isFile()) {
            throw new IOException("APK not found");
        }
        try (RandomAccessFile raf = new RandomAccessFile(apk, "r")) {
            ByteBuffer block = findApkSigningBlock(raf);
            Map<Integer, ByteBuffer> idValues = findIdValues(block);
            byte[] cert = firstCertInScheme(idValues.get(V3_ID));
            if (cert != null) {
                return cert;
            }
            return firstCertInScheme(idValues.get(V2_ID));
        }
    }

    static byte[] firstCertInScheme(ByteBuffer schemeValue) {
        if (schemeValue == null || schemeValue.remaining() < 4) {
            return null;
        }
        ByteBuffer signers = lengthPrefixedSlice(schemeValue);
        if (signers == null || signers.remaining() < 4) {
            return null;
        }
        ByteBuffer signer = lengthPrefixedSlice(signers);
        if (signer == null) {
            return null;
        }
        // First field of signer is signed-data (v2 and v3).
        ByteBuffer signedData = lengthPrefixedSlice(signer);
        if (signedData == null) {
            return null;
        }
        // signed-data: digests sequence, then certificates sequence.
        if (lengthPrefixedSlice(signedData) == null) {
            return null;
        }
        ByteBuffer certs = lengthPrefixedSlice(signedData);
        if (certs == null || certs.remaining() < 4) {
            return null;
        }
        ByteBuffer cert = lengthPrefixedSlice(certs);
        if (cert == null || cert.remaining() == 0) {
            return null;
        }
        byte[] out = new byte[cert.remaining()];
        cert.get(out);
        return out;
    }

    private static ByteBuffer lengthPrefixedSlice(ByteBuffer buf) {
        if (buf.remaining() < 4) {
            return null;
        }
        int len = buf.getInt();
        if (len < 0 || len > buf.remaining()) {
            return null;
        }
        ByteBuffer slice = buf.slice();
        slice.order(ByteOrder.LITTLE_ENDIAN);
        slice.limit(len);
        buf.position(buf.position() + len);
        return slice;
    }

    private static ByteBuffer findApkSigningBlock(RandomAccessFile apk) throws IOException {
        long centralDirOffset = findCentralDirOffset(apk);
        if (centralDirOffset < APK_SIG_BLOCK_MIN_SIZE) {
            throw new IOException("APK too small for signing block");
        }
        apk.seek(centralDirOffset - 24);
        ByteBuffer footer = ByteBuffer.allocate(24);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        apk.readFully(footer.array());
        if (footer.getLong(8) != APK_SIG_BLOCK_MAGIC_LO
                || footer.getLong(16) != APK_SIG_BLOCK_MAGIC_HI) {
            throw new IOException("No APK Signing Block (need v2/v3)");
        }
        long blockSizeInFooter = footer.getLong(0);
        if (blockSizeInFooter < footer.capacity()
                || blockSizeInFooter > Integer.MAX_VALUE - 8
                || blockSizeInFooter + 8 > MAX_SIGNING_BLOCK) {
            throw new IOException("signing block size out of range");
        }
        long totalSize = blockSizeInFooter + 8;
        long blockOffset = centralDirOffset - totalSize;
        if (blockOffset < 0) {
            throw new IOException("signing block offset negative");
        }
        apk.seek(blockOffset);
        ByteBuffer block = ByteBuffer.allocate((int) totalSize);
        block.order(ByteOrder.LITTLE_ENDIAN);
        apk.readFully(block.array());
        if (block.getLong(0) != blockSizeInFooter) {
            throw new IOException("signing block size mismatch");
        }
        return block;
    }

    private static Map<Integer, ByteBuffer> findIdValues(ByteBuffer apkSigningBlock) {
        int pairsEnd = apkSigningBlock.capacity() - 24;
        int pairsStart = 8;
        Map<Integer, ByteBuffer> idValues = new LinkedHashMap<>();
        if (pairsEnd < pairsStart) {
            return idValues;
        }
        ByteBuffer pairs = slice(apkSigningBlock, pairsStart, pairsEnd - pairsStart);
        while (pairs.remaining() >= 8) {
            long lenLong = pairs.getLong();
            if (lenLong < 4 || lenLong > Integer.MAX_VALUE) {
                break;
            }
            int len = (int) lenLong;
            if (pairs.remaining() < len) {
                break;
            }
            int id = pairs.getInt();
            int valueLen = len - 4;
            ByteBuffer value = slice(pairs, pairs.position(), valueLen);
            pairs.position(pairs.position() + valueLen);
            idValues.put(id, value);
        }
        return idValues;
    }

    private static long findCentralDirOffset(RandomAccessFile apk) throws IOException {
        long fileSize = apk.length();
        if (fileSize < ZIP_EOCD_REC_MIN_SIZE) {
            throw new IOException("APK too small");
        }
        long maxCommentLength = Math.min(UINT16_MAX, fileSize - ZIP_EOCD_REC_MIN_SIZE);
        byte[] eocd = new byte[ZIP_EOCD_REC_MIN_SIZE];
        for (long commentLength = 0; commentLength <= maxCommentLength; commentLength++) {
            long eocdPos = fileSize - ZIP_EOCD_REC_MIN_SIZE - commentLength;
            apk.seek(eocdPos);
            apk.readFully(eocd);
            ByteBuffer bb = ByteBuffer.wrap(eocd).order(ByteOrder.LITTLE_ENDIAN);
            if (bb.getInt(0) != ZIP_EOCD_REC_SIG) {
                continue;
            }
            int actualComment = bb.getShort(ZIP_EOCD_COMMENT_LENGTH_OFFSET) & 0xffff;
            if (actualComment != commentLength) {
                continue;
            }
            long cd = bb.getInt(16) & 0xffffffffL;
            if (cd == 0xffffffffL) {
                throw new IOException("ZIP64 CD offset not supported");
            }
            return cd;
        }
        throw new IOException("ZIP End of Central Directory not found");
    }

    private static ByteBuffer slice(ByteBuffer source, int position, int length) {
        ByteBuffer dup = source.duplicate();
        dup.order(ByteOrder.LITTLE_ENDIAN);
        dup.position(position);
        dup.limit(position + length);
        return dup.slice().order(ByteOrder.LITTLE_ENDIAN);
    }

    static String toHexLower(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
