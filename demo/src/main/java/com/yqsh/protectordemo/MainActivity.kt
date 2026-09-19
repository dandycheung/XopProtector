package com.yqsh.protectordemo

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var tv: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tv = TextView(this)
        tv.textSize = 14f
        tv.setPadding(48, 48, 48, 48)
        setContentView(tv)

        LifecycleProbe.installActivity(this, application)

        val packed = isProtectorPacked()
        try {
            // Shell must re-pin Application so getApplication() is DemoApplication, not Proxy.
            val app = application
            if (app !is DemoApplication) {
                throw ClassCastException(
                    "getApplication() is ${app.javaClass.name}, expected DemoApplication"
                )
            }
            Business.stamp = 1 // triggers loadLibrary("demo_biz")
            if (packed) {
                // Linker may bypass hooked dlopen; force .text decrypt after load.
                ProtectorShell.ensureBusinessSo("libdemo_biz.so")
            }
            val secret = Business.secret()
            val sum = Business.add(40, 2)
            val score = Business.licenseScore(7, 11)
            val inv = Business.invokeProbe(20, 1)
            val field = Business.fieldProbe(41)
            val arr = Business.arrayProbe(10)
            val caught = Business.catchProbe(0)
            val okPath = Business.catchProbe(5)
            val so = Business.soProbe(40, 2)
            val f = Business.floatProbe(2.0f, 3.0f)
            val d = Business.doubleProbe(8.0, 2.0)
            val fcmp = Business.floatCmpProbe(1.0f, 2.0f)
            val sync = Business.syncProbe(20)
            val lsh = Business.longShiftProbe(8L, 2)
            val fcast = Business.floatCastProbe(Float.NaN)
            val psw = Business.packedSwitchProbe(2)
            val pswDef = Business.packedSwitchProbe(99)
            val fill = Business.fillArrayProbe(1)

            // Assets / res-protect / NetGuard / pin-certs: off in protectDemo + desktop.
            // CLI only; --encrypt-assets needs ProtectorAssets (not AssetManager.open).

            var expectScore = (7 + 11) * 3
            if (expectScore < 0) expectScore *= -1
            val expectArr = 10 + 3 + 2
            val bizOk = secret == "protector-ok-42"
                    && sum == 42
                    && score == expectScore
                    && inv == 42
                    && field == 42
                    && arr == expectArr
                    && caught == -7
                    && okPath == 10
                    && so == 42
                    && f == 7.5f
                    && d == 3.75
                    && fcmp == -1
                    && sync == 82
                    && lsh == 34L
                    && fcast == 0
                    && psw == 30
                    && pswDef == -1
                    && fill == 20
            val status = when {
                !packed -> getString(R.string.status_unpacked)
                bizOk -> getString(R.string.status_pass)
                else -> getString(R.string.status_fail)
            }
            val bizMsg = "secret=$secret add=$sum score=$score inv=$inv field=$field arr=$arr " +
                    "catch=$caught/$okPath so=$so f=$f d=$d fcmp=$fcmp sync=$sync lsh=$lsh fcast=$fcast " +
                    "psw=$psw/$pswDef fill=$fill " +
                    "status=$status"
            tv.tag = bizMsg.replace(' ', '\n')
            refreshUi("pending")
            Log.i("protector-demo", bizMsg)
        } catch (t: Throwable) {
            tv.tag = getString(R.string.status_error, t.message ?: "")
            refreshUi("error")
            Log.e("protector-demo", "business failed", t)
        }

        // ProcessLifecycleOwner dispatches ON_START/ON_RESUME after first frame.
        Handler(Looper.getMainLooper()).post {
            refreshUi("post")
            Handler(Looper.getMainLooper()).postDelayed({ refreshUi("delayed") }, 500)
        }
    }

    private fun refreshUi(phase: String) {
        val biz = (tv.tag as? String).orEmpty()
        val life = LifecycleProbe.statusLine()
        val lifeStatus = when {
            LifecycleProbe.overallOk() -> getString(R.string.lifecycle_pass)
            LifecycleProbe.processOnlyBroken() -> getString(R.string.lifecycle_partial)
            else -> getString(R.string.lifecycle_fail)
        }
        tv.text = "$biz\n\n--- lifecycle ($phase) ---\n$lifeStatus\n$life"
        Log.i("protector.Lifecycle", "ui[$phase] $lifeStatus ${LifecycleProbe.statusLine().replace('\n', ' ')}")
    }
}
