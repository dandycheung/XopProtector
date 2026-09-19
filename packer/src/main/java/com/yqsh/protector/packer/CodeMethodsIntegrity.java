package com.yqsh.protector.packer;

import com.yqsh.protector.packer.util.CryptoUtils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Integrity v2: HMAC of the hollow/VMP method set in {@code code.bin}.
 * Encoding must match native {@code encode_code_methods} (LE u32 count, then
 * sorted {@code dex, method_idx, flags} triples).
 */
public final class CodeMethodsIntegrity {
    private CodeMethodsIntegrity() {
    }

    public static byte[] encode(Map<Integer, List<PackerMain.InsnRecord>> map) {
        Map<Long, Integer> unique = new TreeMap<>();
        if (map != null) {
            for (Map.Entry<Integer, List<PackerMain.InsnRecord>> e : map.entrySet()) {
                if (e.getKey() == null || e.getValue() == null) {
                    continue;
                }
                int dex = e.getKey();
                for (PackerMain.InsnRecord r : e.getValue()) {
                    if (r == null) {
                        continue;
                    }
                    long key = ((dex & 0xffffffffL) << 32) | (r.methodIndex & 0xffffffffL);
                    unique.put(key, r.flags);
                }
            }
        }
        ByteBuffer buf = ByteBuffer.allocate(4 + unique.size() * 12)
                .order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(unique.size());
        for (Map.Entry<Long, Integer> e : unique.entrySet()) {
            long key = e.getKey();
            buf.putInt((int) (key >>> 32));
            buf.putInt((int) key);
            buf.putInt(e.getValue());
        }
        return buf.array();
    }

    public static String hmacHex(byte[] hmacKey, Map<Integer, List<PackerMain.InsnRecord>> map) {
        if (hmacKey == null || hmacKey.length != KeyLadder.HMAC_LEN) {
            throw new IllegalArgumentException("code_methods_hmac requires K_hmac");
        }
        return CryptoUtils.toHex(CryptoUtils.hmacSha256(hmacKey, encode(map)));
    }
}
