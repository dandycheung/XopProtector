package com.yqsh.protector.packer;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * True-VMP compile telemetry. Does not change admission policy.
 */
public final class Pvm2Admission {
    public enum SkipReason {
        unsupported_opcode("unsupported_opcode"),
        too_many_regs("too_many_regs"),
        try_catch("try_catch"),
        branch("branch"),
        type("type"),
        other("other");

        public final String wire;

        SkipReason(String wire) {
            this.wire = wire;
        }
    }

    public int candidates;
    public int attempted;
    public int success;
    public int fallback;
    public final EnumMap<SkipReason, Integer> reasons = new EnumMap<>(SkipReason.class);
    public final Map<Integer, Integer> unsupportedOpcodes = new LinkedHashMap<>();

    public void reset() {
        candidates = 0;
        attempted = 0;
        success = 0;
        fallback = 0;
        reasons.clear();
        unsupportedOpcodes.clear();
    }

    public void noteCandidate() {
        candidates++;
    }

    public void noteSuccess() {
        attempted++;
        success++;
    }

    public void noteFail(String failReason) {
        attempted++;
        fallback++;
        SkipReason reason = classify(failReason);
        reasons.merge(reason, 1, Integer::sum);
        Integer opcode = parseUnsupportedOpcode(failReason);
        if (opcode != null) {
            unsupportedOpcodes.merge(opcode, 1, Integer::sum);
        }
    }

    public String admissionLine() {
        double rate = attempted == 0 ? 0.0 : (100.0 * success / attempted);
        return String.format(Locale.US,
                "PVM2 admission: candidates=%d attempted=%d success=%d fallback=%d rate=%.1f%%",
                candidates, attempted, success, fallback, rate);
    }

    public String skipReasonsLine() {
        StringBuilder sb = new StringBuilder("PVM2 skip reasons:");
        for (SkipReason r : SkipReason.values()) {
            sb.append(' ').append(r.wire).append('=').append(count(r));
        }
        return sb.toString();
    }

    /** Always emitted so empty harvests are still grep-able. Keys are hex opcodes. */
    public String unsupportedOpcodesLine() {
        StringBuilder sb = new StringBuilder("TRUE_VMP unsupported opcodes (count): {");
        boolean first = true;
        for (Map.Entry<Integer, Integer> e : unsupportedOpcodes.entrySet()) {
            if (!first) {
                sb.append(", ");
            }
            first = false;
            sb.append(String.format(Locale.US, "0x%x=%d", e.getKey(), e.getValue()));
        }
        sb.append('}');
        return sb.toString();
    }

    public int count(SkipReason reason) {
        Integer n = reasons.get(reason);
        return n == null ? 0 : n;
    }

    public static SkipReason classify(String failReason) {
        if (failReason == null || failReason.isEmpty()) {
            return SkipReason.other;
        }
        String r = failReason.toLowerCase(Locale.US);
        if (r.contains("unsupported opcode 0x")) {
            return SkipReason.unsupported_opcode;
        }
        if (r.contains("too many regs")) {
            return SkipReason.too_many_regs;
        }
        if (r.contains("unsupported return")) {
            return SkipReason.type;
        }
        if (r.contains("branch")) {
            return SkipReason.branch;
        }
        if (r.contains("try ") || r.contains("tries") || r.contains("handler")) {
            return SkipReason.try_catch;
        }
        return SkipReason.other;
    }

    public static Integer parseUnsupportedOpcode(String failReason) {
        if (failReason == null) {
            return null;
        }
        final String marker = "unsupported opcode 0x";
        int idx = failReason.indexOf(marker);
        if (idx < 0) {
            return null;
        }
        int start = idx + marker.length();
        int end = start;
        while (end < failReason.length()) {
            char c = failReason.charAt(end);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                end++;
            } else {
                break;
            }
        }
        if (end == start) {
            return null;
        }
        try {
            return Integer.parseInt(failReason.substring(start, end), 16);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }
}
