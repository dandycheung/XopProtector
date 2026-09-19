package com.yqsh.protector.packer;

import com.yqsh.protector.packer.elf.ReadElf;
import com.yqsh.protector.packer.util.CryptoUtils;

import java.io.File;
import java.io.RandomAccessFile;
import java.util.Arrays;
import java.util.List;

/**
 * RC4-encrypts {@code .bitcode} with {@code K_wrap} and writes XOR-padded
 * {@code K_master} into the {@code XOPKMASTER} slot before encrypt.
 * {@code K_wrap} is written into the {@code .protwrap} section by magic,
 * not via a dynamic symbol.
 */
public final class SoSectionEncryptor {
    private static final String BITCODE = ".bitcode";
    private static final long SHF_WRITE = 0x1L;
    private static final long SHF_ALLOC = 0x2L;

    private SoSectionEncryptor() {
    }

    /**
     * Embed the same {@code K_master} (and {@code K_wrap}) into one ABI's
     * {@code libprotector.so}. All ABIs must receive identical master bytes.
     *
     * @return lowercase hex HMAC-SHA256 of the post-wipe plaintext {@code .bitcode}
     *         (K_master slot zeroed), matching runtime after {@code recover_k_master}.
     */
    public static String encrypt(File soFile, byte[] kWrap, byte[] kMaster, byte[] kHmac)
            throws Exception {
        if (soFile == null || !soFile.isFile() || kWrap == null || kWrap.length != KeyLadder.WRAP_LEN) {
            throw new IllegalArgumentException("invalid so or K_wrap");
        }
        if (kMaster == null || kMaster.length != KeyLadder.MASTER_LEN) {
            throw new IllegalArgumentException("invalid K_master");
        }
        if (kHmac == null || kHmac.length != KeyLadder.HMAC_LEN) {
            throw new IllegalArgumentException("invalid K_hmac");
        }
        String hmacHex = encryptBitcodeWithMaster(soFile, kWrap, KeyLadder.wrapMaster(kMaster), kHmac);
        writeWrapSlot(soFile, KeyLadder.wrapWrapKey(kWrap));
        return hmacHex;
    }

    /**
     * HMAC-SHA256 of decrypted {@code .bitcode} as the process sees it after
     * wiping the K_master slot (magic remains, 32-byte payload is zeros).
     */
    static String hmacBitcodePostWipe(byte[] plainWithMaster, byte[] kHmac) {
        if (plainWithMaster == null || kHmac == null || kHmac.length != KeyLadder.HMAC_LEN) {
            throw new IllegalArgumentException("bitcode HMAC requires plaintext and K_hmac");
        }
        int magicAt = findUniqueMagic(plainWithMaster);
        byte[] forMac = Arrays.copyOf(plainWithMaster, plainWithMaster.length);
        int slot = magicAt + KeyLadder.MASTER_MAGIC.length;
        Arrays.fill(forMac, slot, slot + KeyLadder.MASTER_LEN, (byte) 0);
        try {
            return CryptoUtils.toHex(CryptoUtils.hmacSha256(kHmac, forMac));
        } finally {
            Arrays.fill(forMac, (byte) 0);
        }
    }

    private static String encryptBitcodeWithMaster(File soFile, byte[] kWrap, byte[] wrappedMaster,
                                                   byte[] kHmac)
            throws Exception {
        try (ReadElf readElf = new ReadElf(soFile)) {
            List<ReadElf.SectionHeader> headers = readElf.getSectionHeaders();
            for (ReadElf.SectionHeader sh : headers) {
                if (!BITCODE.equals(sh.getName())) continue;
                long offset = sh.getOffset();
                int size = (int) sh.getSize();
                if (size <= 0) {
                    throw new IllegalStateException("empty .bitcode in " + soFile.getName());
                }
                byte[] plain = readAt(soFile, offset, size);
                int magicAt = findUniqueMagic(plain);
                System.arraycopy(wrappedMaster, 0, plain, magicAt + KeyLadder.MASTER_MAGIC.length,
                        wrappedMaster.length);
                String hmacHex = hmacBitcodePostWipe(plain, kHmac);
                byte[] enc = CryptoUtils.rc4Crypt(kWrap, plain);
                Arrays.fill(plain, (byte) 0);
                if (enc == null || enc.length != size) {
                    throw new IllegalStateException("RC4 encrypt .bitcode failed");
                }
                writeAt(soFile, offset, enc);
                System.out.println("Encrypted .bitcode (RC4) + K_master slot in " + soFile.getName()
                        + " offset=0x" + Long.toHexString(offset) + " size=" + size);
                return hmacHex;
            }
        }
        throw new IllegalStateException("no .bitcode section in " + soFile.getName());
    }

    static int findUniqueMagic(byte[] haystack) {
        return findUniqueMagic(haystack, KeyLadder.MASTER_MAGIC, KeyLadder.MASTER_LEN, "XOPKMASTER");
    }

    static int findUniqueMagic(byte[] haystack, byte[] magic, int payloadLen, String label) {
        if (haystack == null || magic == null || label == null) {
            throw new IllegalArgumentException("magic search requires haystack, magic, label");
        }
        int found = -1;
        int count = 0;
        int need = magic.length + payloadLen;
        for (int i = 0; i + need <= haystack.length; i++) {
            boolean match = true;
            for (int j = 0; j < magic.length; j++) {
                if (haystack[i + j] != magic[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                count++;
                found = i;
            }
        }
        if (count != 1) {
            throw new IllegalStateException(
                    "expected one " + label + " slot, found " + count);
        }
        return found;
    }

    private static void writeWrapSlot(File soFile, byte[] wrappedKey) throws Exception {
        if (wrappedKey == null || wrappedKey.length != KeyLadder.WRAP_LEN) {
            throw new IllegalArgumentException("invalid wrapped K_wrap");
        }
        try (ReadElf readElf = new ReadElf(soFile)) {
            ReadElf.SectionHeader sh = readElf.getSectionHeader(KeyLadder.PROTWRAP_SECTION);
            if (sh == null) {
                throw new IllegalStateException("no .protwrap section in " + soFile.getName());
            }
            if ((sh.getFlags() & SHF_ALLOC) == 0 || (sh.getFlags() & SHF_WRITE) == 0) {
                throw new IllegalStateException(".protwrap is not ALLOC|WRITE in " + soFile.getName());
            }
            int size = (int) sh.getSize();
            int need = KeyLadder.WRAP_MAGIC.length + KeyLadder.WRAP_LEN;
            if (size < need) {
                throw new IllegalStateException(".protwrap too small in " + soFile.getName());
            }
            byte[] plain = readAt(soFile, sh.getOffset(), size);
            int magicAt = findUniqueMagic(plain, KeyLadder.WRAP_MAGIC, KeyLadder.WRAP_LEN, "XOPKWRAP");
            System.arraycopy(wrappedKey, 0, plain, magicAt + KeyLadder.WRAP_MAGIC.length, wrappedKey.length);
            writeAt(soFile, sh.getOffset(), plain);
            System.out.println("Wrote K_wrap slot in " + soFile.getName()
                    + " .protwrap offset=0x" + Long.toHexString(sh.getOffset()));
        }
    }

    private static byte[] readAt(File file, long offset, int len) throws Exception {
        byte[] buf = new byte[len];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(offset);
            raf.readFully(buf);
        }
        return buf;
    }

    private static void writeAt(File file, long offset, byte[] data) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
            raf.seek(offset);
            raf.write(data);
        }
    }
}
