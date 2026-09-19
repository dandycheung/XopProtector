package com.yqsh.protector.shell;

import android.util.Log;

import androidx.annotation.Keep;

/**
 * Phase 5 — chain {@link Thread.UncaughtExceptionHandler} without replacing the
 * app's handler. Reports a soft threat then delegates.
 * <p>
 * Uses an explicit nested class (not a lambda): the shell DEX is re-d8'd from the
 * R8 jar in {@code exportShellFiles}, and lambda synthetics have been observed to
 * throw {@link NoSuchMethodError} at runtime ({@code shell/a.<init>(Handler)}).
 */
@Keep
public final class CrashGuard {
    private static final String TAG = "protector.CrashGuard";
    private static volatile boolean installed;

    private CrashGuard() {
    }

    public static void install() {
        if (installed) {
            return;
        }
        installed = true;
        Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(new ChainedHandler(prev));
    }

    private static String sanitize(String s) {
        if (s == null || s.isEmpty()) {
            return "unknown";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        return sb.toString();
    }

    /** Explicit handler — avoids R8/d8 lambda re-desugar breakage in shell DEX. */
    @Keep
    private static final class ChainedHandler implements Thread.UncaughtExceptionHandler {
        private final Thread.UncaughtExceptionHandler prev;

        ChainedHandler(Thread.UncaughtExceptionHandler prev) {
            this.prev = prev;
        }

        @Override
        public void uncaughtException(Thread t, Throwable e) {
            try {
                String name = e != null ? e.getClass().getSimpleName() : "Throwable";
                JniBridge.reportThreat("uncaught_" + sanitize(name));
            } catch (Throwable ignored) {
            }
            if (prev != null) {
                prev.uncaughtException(t, e);
            } else {
                Log.e(TAG, "uncaught", e);
            }
        }
    }
}
