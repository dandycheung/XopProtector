package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PaymentVmpRulesTest {

    @Test
    void matchesWxapiNonComponent() {
        assertTrue(PaymentVmpRules.matches("Lcom/foo/wxapi/WXPayHelper;"));
    }

    @Test
    void rejectsWxapiAndroidComponents() {
        assertFalse(PaymentVmpRules.matches(
                "Lcom/togeter/play/wxapi/WXPayEntryActivity;"));
    }

    @Test
    void matchesAlipayAndroidAppBinderSurface() {
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/android/app/IAlixPay$Stub;"));
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/android/app/IAlixPay;"));
        assertFalse(PaymentVmpRules.isAlipayPayHotPath("Lcom/alipay/android/app/IAlixPay;"));
    }

    @Test
    void matchesAlipaySdkAppPayTask() {
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/app/PayTask;"));
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/app/PayTask$1;"));
        assertFalse(PaymentVmpRules.isAlipayPayHotPath("Lcom/alipay/sdk/app/PayTask;"));
    }

    @Test
    void matchesAlipayExpandedMspAndSecurity() {
        assertTrue(PaymentVmpRules.matches(
                "Lcom/alipay/apmobilesecuritysdk/face/APSecuritySdk;"));
        assertTrue(PaymentVmpRules.matches(
                "Lcom/alipay/android/phone/mrpc/core/HttpException;"));
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/m/u/n;"));
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/m/u/h$e;"));
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/m/s/a;"));
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/m/x/d;"));
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/m/e/b;"));
    }

    @Test
    void rejectsWxApiClassNameWithoutSegment() {
        assertFalse(PaymentVmpRules.matches(
                "Lcom/tencent/mm/opensdk/openapi/BaseWXApiImplV10;"));
    }
}
