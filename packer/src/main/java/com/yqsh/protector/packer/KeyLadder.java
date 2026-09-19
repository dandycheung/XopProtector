package com.yqsh.protector.packer;

import com.yqsh.protector.packer.util.CryptoUtils;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

/**
 * HKDF-SHA256 key ladder. {@code K_master} is the secret; cert SHA-256 and
 * package name are binding only. Must match native {@code key_ladder.cpp}.
 */
public final class KeyLadder {
    public static final int MASTER_LEN = 32;
    public static final int WRAP_LEN = 16;
    public static final int AES_LEN = 16;
    public static final int HMAC_LEN = 32;

    /** 16-byte marker in plaintext {@code .bitcode} (then RC4). */
    public static final byte[] MASTER_MAGIC = {
            'X', 'O', 'P', 'K', 'M', 'A', 'S', 'T', 'E', 'R', 0, 0, 0, 0, 0, 0
    };

    /** XOR pad for the 32-byte master slot; must match native recover pad. */
    public static final byte[] MASTER_PAD = {
            (byte) 0x91, 0x2e, 0x6b, (byte) 0xd4, 0x08, 0x57, (byte) 0xc3, 0x1a,
            (byte) 0xfe, 0x44, (byte) 0x80, 0x3d, (byte) 0xb9, 0x65, 0x12, (byte) 0xac,
            0x37, (byte) 0xea, 0x09, 0x7c, 0x51, (byte) 0x96, 0x2b, (byte) 0xf0,
            0x4d, (byte) 0x83, 0x18, (byte) 0xce, 0x60, (byte) 0xa5, 0x3f, 0x77
    };

    /** Writable ALLOC section holding XOR-padded {@code K_wrap}. */
    public static final String PROTWRAP_SECTION = ".protwrap";

    /** 16-byte marker in plaintext {@code .protwrap}. */
    public static final byte[] WRAP_MAGIC = {
            'X', 'O', 'P', 'K', 'W', 'R', 'A', 'P', 0, 0, 0, 0, 0, 0, 0, 0
    };

    /** XOR pad for the 16-byte wrap slot; must match native recover split literals. */
    public static final byte[] WRAP_PAD = {
            (byte) 0x3b, 0x7c, 0x19, 0x5e, (byte) 0xa2, (byte) 0xdf, 0x48, 0x31,
            0x6c, (byte) 0x85, (byte) 0xea, 0x27, 0x54, (byte) 0x9b, 0x0f, (byte) 0xd6
    };

    public static final String LABEL_DEX = "xop-dex-v1";
    public static final String LABEL_INSN = "xop-insn-v1";
    public static final String LABEL_SO = "xop-so-v1";
    public static final String LABEL_SOWARM = "xop-sowarm-v1";
    public static final String LABEL_ASSETS = "xop-assets-v1";
    public static final String LABEL_HMAC = "xop-hmac-v1";

    private KeyLadder() {
    }

    public static final class Derived {
        public final byte[] dex;
        public final byte[] insn;
        public final byte[] so;
        /** AES-128 wrap for encrypted so_warm/ cross-launch cache (PSW1). */
        public final byte[] sowarm;
        public final byte[] assets;
        public final byte[] hmac;

        Derived(byte[] dex, byte[] insn, byte[] so, byte[] sowarm, byte[] assets, byte[] hmac) {
            this.dex = dex;
            this.insn = insn;
            this.so = so;
            this.sowarm = sowarm;
            this.assets = assets;
            this.hmac = hmac;
        }
    }

    /**
     * {@code HKDF-Extract(salt=cert, IKM=master)} then Expand per label||package.
     */
    public static Derived derive(byte[] master, byte[] certSha256, String packageName) {
        if (master == null || master.length != MASTER_LEN) {
            throw new IllegalArgumentException("K_master must be 32 bytes");
        }
        if (certSha256 == null || certSha256.length != MASTER_LEN) {
            throw new IllegalArgumentException("cert SHA-256 must be 32 bytes");
        }
        if (packageName == null || packageName.isEmpty()) {
            throw new IllegalArgumentException("package name required for HKDF info");
        }
        byte[] pkg = packageName.getBytes(StandardCharsets.UTF_8);
        return new Derived(
                expand(master, certSha256, LABEL_DEX, pkg, AES_LEN),
                expand(master, certSha256, LABEL_INSN, pkg, AES_LEN),
                expand(master, certSha256, LABEL_SO, pkg, AES_LEN),
                expand(master, certSha256, LABEL_SOWARM, pkg, AES_LEN),
                expand(master, certSha256, LABEL_ASSETS, pkg, AES_LEN),
                expand(master, certSha256, LABEL_HMAC, pkg, HMAC_LEN));
    }

    /** {@code K_master XOR pad} written into the .bitcode slot before RC4. */
    public static byte[] wrapMaster(byte[] master) {
        if (master == null || master.length != MASTER_LEN) {
            throw new IllegalArgumentException("K_master must be 32 bytes");
        }
        byte[] out = new byte[MASTER_LEN];
        for (int i = 0; i < MASTER_LEN; i++) {
            out[i] = (byte) (master[i] ^ MASTER_PAD[i]);
        }
        return out;
    }

    /** {@code K_wrap XOR pad} written into the {@code .protwrap} slot. */
    public static byte[] wrapWrapKey(byte[] kWrap) {
        if (kWrap == null || kWrap.length != WRAP_LEN) {
            throw new IllegalArgumentException("K_wrap must be 16 bytes");
        }
        byte[] out = new byte[WRAP_LEN];
        for (int i = 0; i < WRAP_LEN; i++) {
            out[i] = (byte) (kWrap[i] ^ WRAP_PAD[i]);
        }
        return out;
    }

    public static byte[] fromHex(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex required");
        }
        String h = hex.trim().toLowerCase(Locale.US).replace(":", "");
        if (h.length() != 64 || !h.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("expected 64 hex chars, got: " + hex);
        }
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static byte[] expand(byte[] master, byte[] cert, String label, byte[] pkg, int len) {
        byte[] lab = label.getBytes(StandardCharsets.US_ASCII);
        byte[] info = new byte[lab.length + pkg.length];
        System.arraycopy(lab, 0, info, 0, lab.length);
        System.arraycopy(pkg, 0, info, lab.length, pkg.length);
        try {
            return CryptoUtils.hkdfSha256(master, cert, info, len);
        } finally {
            Arrays.fill(info, (byte) 0);
        }
    }
}
