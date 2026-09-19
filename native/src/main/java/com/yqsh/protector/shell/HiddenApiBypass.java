package com.yqsh.protector.shell;

import android.util.Log;

import androidx.annotation.Keep;

import java.lang.reflect.Method;

/**
 * Best-effort exemption so Proxy→real Application callback migration can read
 * greylist/blacklist fields such as {@code Application.mCallbacksController}
 * (API 34+). Failures are ignored — public paths still work.
 */
@Keep
final class HiddenApiBypass {
    private static final String TAG = "protector.HiddenApi";
    private static boolean attempted;

    private HiddenApiBypass() {
    }

    static void exemptAll() {
        if (attempted) {
            return;
        }
        attempted = true;
        try {
            Method forName = Class.class.getDeclaredMethod("forName", String.class);
            Method getDeclaredMethod = Class.class.getDeclaredMethod(
                    "getDeclaredMethod", String.class, Class[].class);
            Class<?> vmRuntime = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
            Method getRuntime = (Method) getDeclaredMethod.invoke(vmRuntime, "getRuntime", null);
            Method setHiddenApiExemptions = (Method) getDeclaredMethod.invoke(
                    vmRuntime, "setHiddenApiExemptions", new Class<?>[]{String[].class});
            Object runtime = getRuntime.invoke(null);
            setHiddenApiExemptions.invoke(runtime, (Object) new String[]{"L"});
            Log.i(TAG, "setHiddenApiExemptions(L) ok");
        } catch (Throwable t) {
            Log.w(TAG, "setHiddenApiExemptions skipped", t);
        }
    }
}
