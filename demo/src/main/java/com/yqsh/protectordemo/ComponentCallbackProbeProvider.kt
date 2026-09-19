package com.yqsh.protectordemo

import android.content.ComponentCallbacks
import android.content.ContentProvider
import android.content.ContentValues
import android.content.res.Configuration
import android.database.Cursor
import android.net.Uri
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Runs during ContentProvider install (often still on ProxyApplication) and
 * registers a ComponentCallbacks so shell reattach migration can be verified.
 */
class ComponentCallbackProbeProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        val ctx = context ?: return false
        val appCtx = ctx.applicationContext
        Log.i(TAG, "provider onCreate application=${appCtx.javaClass.name}")
        appCtx.registerComponentCallbacks(object : ComponentCallbacks {
            override fun onConfigurationChanged(newConfig: Configuration) {
                configEvents.incrementAndGet()
                Log.i(TAG, "onConfigurationChanged density=${newConfig.densityDpi}")
            }

            override fun onLowMemory() {
                Log.i(TAG, "onLowMemory")
            }
        })
        registered.set(true)
        return true
    }

    override fun query(u: Uri, p: Array<out String>?, s: String?, a: Array<out String>?, o: String?): Cursor? = null
    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    companion object {
        private const val TAG = "protector.CompCb"
        val registered = AtomicBoolean(false)
        val configEvents = AtomicInteger(0)
    }
}
