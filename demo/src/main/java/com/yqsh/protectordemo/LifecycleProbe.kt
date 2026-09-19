package com.yqsh.protectordemo

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.util.Log
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Self-test for Lifecycle after shell Application replace.
 * Process observer must see ON_START/ON_RESUME once the Activity is shown;
 * Activity observer must see ON_CREATE/ON_START/ON_RESUME for MainActivity.
 */
object LifecycleProbe {
    private const val TAG = "protector.Lifecycle"

    private val processEvents = CopyOnWriteArrayList<String>()
    private val activityEvents = CopyOnWriteArrayList<String>()
    private val appCallbackEvents = CopyOnWriteArrayList<String>()
    private val processInstalled = AtomicBoolean(false)
    private val appCallbacksInstalled = AtomicBoolean(false)

    @Volatile
    var appClassAtProcessRegister: String = "?"
        private set

    @Volatile
    var applicationClassSeenByActivity: String = "?"
        private set

    fun installProcess(app: Application) {
        if (!processInstalled.compareAndSet(false, true)) return
        appClassAtProcessRegister = app.javaClass.name
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onCreate(owner: LifecycleOwner) = recordProcess("ON_CREATE")
            override fun onStart(owner: LifecycleOwner) = recordProcess("ON_START")
            override fun onResume(owner: LifecycleOwner) = recordProcess("ON_RESUME")
            override fun onPause(owner: LifecycleOwner) = recordProcess("ON_PAUSE")
            override fun onStop(owner: LifecycleOwner) = recordProcess("ON_STOP")
        })
        Log.i(TAG, "ProcessLifecycleOwner observer attached on ${app.javaClass.name}")
    }

    /** Raw Application callbacks — independent of AndroidX ProcessLifecycleOwner. */
    fun installAppActivityCallbacks(app: Application) {
        if (!appCallbacksInstalled.compareAndSet(false, true)) return
        app.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityCreated(a: Activity, b: Bundle?) = recordAppCb("CREATED:${a.javaClass.simpleName}")
            override fun onActivityStarted(a: Activity) = recordAppCb("STARTED:${a.javaClass.simpleName}")
            override fun onActivityResumed(a: Activity) = recordAppCb("RESUMED:${a.javaClass.simpleName}")
            override fun onActivityPaused(a: Activity) = recordAppCb("PAUSED:${a.javaClass.simpleName}")
            override fun onActivityStopped(a: Activity) = recordAppCb("STOPPED:${a.javaClass.simpleName}")
            override fun onActivitySaveInstanceState(a: Activity, b: Bundle) {}
            override fun onActivityDestroyed(a: Activity) = recordAppCb("DESTROYED:${a.javaClass.simpleName}")
        })
        Log.i(TAG, "Application.ActivityLifecycleCallbacks attached on ${app.javaClass.name}")
    }

    fun installActivity(owner: LifecycleOwner, application: Application) {
        applicationClassSeenByActivity = application.javaClass.name
        owner.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onCreate(owner: LifecycleOwner) = recordActivity("ON_CREATE")
            override fun onStart(owner: LifecycleOwner) = recordActivity("ON_START")
            override fun onResume(owner: LifecycleOwner) = recordActivity("ON_RESUME")
            override fun onPause(owner: LifecycleOwner) = recordActivity("ON_PAUSE")
            override fun onStop(owner: LifecycleOwner) = recordActivity("ON_STOP")
            override fun onDestroy(owner: LifecycleOwner) = recordActivity("ON_DESTROY")
        })
        Log.i(TAG, "Activity LifecycleObserver attached; application=${application.javaClass.name}")
    }

    fun processOk(): Boolean =
        processEvents.contains("ON_START") && processEvents.contains("ON_RESUME")

    fun activityOk(): Boolean =
        activityEvents.contains("ON_CREATE") &&
            activityEvents.contains("ON_START") &&
            activityEvents.contains("ON_RESUME")

    fun appCallbacksOk(): Boolean =
        appCallbackEvents.any { it.startsWith("STARTED:") } &&
            appCallbackEvents.any { it.startsWith("RESUMED:") }

    fun applicationIdentityOk(): Boolean =
        applicationClassSeenByActivity == DemoApplication::class.java.name &&
            (appClassAtProcessRegister == DemoApplication::class.java.name ||
                appClassAtProcessRegister == "?")

    fun overallOk(): Boolean = processOk() && activityOk() && appCallbacksOk() && applicationIdentityOk()

    /** Activity + raw Application callbacks OK, but ProcessLifecycleOwner stuck (typical after shell replace). */
    fun processOnlyBroken(): Boolean =
        !processOk() && activityOk() && appCallbacksOk() && applicationIdentityOk()

    fun verdict(): String = when {
        overallOk() -> "PASS"
        processOnlyBroken() -> "PARTIAL(process_broken)"
        else -> "FAIL"
    }

    fun statusLine(): String {
        val proc = if (processOk()) "PASS" else "FAIL"
        val act = if (activityOk()) "PASS" else "FAIL"
        val raw = if (appCallbacksOk()) "PASS" else "FAIL"
        val id = if (applicationIdentityOk()) "PASS" else "FAIL"
        return "lifecycle verdict=${verdict()} process=$proc activity=$act appCb=$raw appId=$id" +
            "\napp@register=$appClassAtProcessRegister" +
            "\napp@activity=$applicationClassSeenByActivity" +
            "\nprocessEvents=${processEvents.joinToString(",")}" +
            "\nactivityEvents=${activityEvents.joinToString(",")}" +
            "\nappCbEvents=${appCallbackEvents.takeLast(8).joinToString(",")}"
    }

    private fun recordProcess(ev: String) {
        processEvents.add(ev)
        Log.i(TAG, "process $ev")
    }

    private fun recordActivity(ev: String) {
        activityEvents.add(ev)
        Log.i(TAG, "activity $ev")
    }

    private fun recordAppCb(ev: String) {
        appCallbackEvents.add(ev)
        Log.i(TAG, "appCb $ev")
    }
}
