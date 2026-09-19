package com.yqsh.protector.packer;

import java.util.Locale;

/**
 * Commercial auto True-VMP markers — no customer package names required.
 * Matches Dalvik type descriptors for well-known payment SDK / callback tokens.
 *
 * <ul>
 *   <li>{@code alipay} — all Alipay-related types (pay hot-path denylist cleared
 *       after PVM2 Alipay matrix: {@code sdk/m/*}, {@code sdk/app}, {@code android/app})</li>
 *   <li>{@code /wxapi/} — WeChat callback package segment only (e.g. {@code .../wxapi/WXPayHelper;}),
 *       not OpenSDK class names like {@code WXApiImpl}</li>
 * </ul>
 */
public final class PaymentVmpRules {

    /**
     * Formerly Alipay pay hot-path denylist. Empty after full reopen (0.6.39).
     * Kept as a hook if a future SDK surface needs temporary exclusion.
     */
    static final String[] ALIPAY_PAY_HOT_PATH_PREFIXES = {};

    private PaymentVmpRules() {
    }

    /**
     * @param typeDescriptor e.g. {@code Lcom/alipay/apmobilesecuritysdk/face/APSecuritySdk;}
     *                       or {@code Lcom/foo/wxapi/WXPayHelper;}
     */
    public static boolean matches(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 3) {
            return false;
        }
        // Never True-VMP Android components: DexPool rewrite of their host DEX has
        // broken sibling classes (annotation/type resolve failures → “数据异常”).
        if (ProtectPolicy.isAndroidComponent(typeDescriptor)) {
            return false;
        }
        String lower = typeDescriptor.toLowerCase(Locale.US);
        if (lower.contains("alipay")) {
            return !isAlipayPayHotPath(typeDescriptor);
        }
        // Package segment only — avoids Lcom/tencent/mm/opensdk/openapi/BaseWXApiImplV10;
        return lower.contains("/wxapi/");
    }

    /** Visible for tests. Descriptor compared with ASCII case-fold on prefixes. */
    static boolean isAlipayPayHotPath(String typeDescriptor) {
        if (typeDescriptor == null || ALIPAY_PAY_HOT_PATH_PREFIXES.length == 0) {
            return false;
        }
        String folded = typeDescriptor.toLowerCase(Locale.US);
        for (String prefix : ALIPAY_PAY_HOT_PATH_PREFIXES) {
            if (folded.startsWith(prefix.toLowerCase(Locale.US))) {
                return true;
            }
        }
        return false;
    }
}
