package com.yqsh.protectordemo

import android.app.Application
import android.util.Log

/**
 * Real application used before packing / restored after shell init.
 */
class DemoApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "DemoApplication.onCreate native=" + safeNativeVersion()
                + " this=" + javaClass.name)
        // Register on the real Application after shell replace — mirrors customer
        // ProcessLifecycleOwner / ActivityLifecycleCallbacks usage.
        LifecycleProbe.installAppActivityCallbacks(this)
        LifecycleProbe.installProcess(this)
    }

    private fun safeNativeVersion(): String {
        if (!isProtectorPacked()) {
            return "unpacked"
        }
        return try {
            ProtectorShell.nativeVersion()
        } catch (t: Throwable) {
            "unavailable: ${t.message}"
        }
    }

    companion object {
        private const val TAG = "protector.DemoApp"
    }
}
