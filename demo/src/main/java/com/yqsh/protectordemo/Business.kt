package com.yqsh.protectordemo

import androidx.annotation.Keep

/**
 * Business logic for protector demo (TRUE_VMP / PVM2).
 * Keep bytecode simple so PVM2 compiler can cover invoke/field/array/exception/float/monitor.
 */
@Keep
object Business {
    init {
        System.loadLibrary("demo_biz")
        // Packed builds: MainActivity calls ProtectorShell.ensureBusinessSo after
        // confirming assets/protector/config.json (unpacked must not load libprotector).
    }

    /** Static field for sget/sput coverage. */
    @JvmField
    var stamp: Int = 1

    /** Simple string return — PVM2 CONST_STR + RETURN_OBJ. */
    @JvmStatic
    fun secret(): String {
        return "protector-ok-42"
    }

    /** Pure int arithmetic — PVM2 BINOP + RETURN. */
    @JvmStatic
    fun add(a: Int, b: Int): Int {
        return a + b
    }

    /** Phase-1 opcode friendly: add + mul + if-ltz + mul-by-minus-one. */
    @JvmStatic
    fun licenseScore(seed: Int, factor: Int): Int {
        var x = seed + factor
        x = x * 3
        if (x < 0) {
            x = x * -1
        }
        return x
    }

    /** Phase-2: invoke-static + binop. */
    @JvmStatic
    fun invokeProbe(a: Int, b: Int): Int {
        return add(a, b) * 2
    }

    /** Phase-2: sget/sput on stamp. */
    @JvmStatic
    fun fieldProbe(delta: Int): Int {
        stamp = stamp + delta
        return stamp
    }

    /** Phase-2: new-array / aput / aget / array-length. */
    @JvmStatic
    fun arrayProbe(n: Int): Int {
        val a = IntArray(2)
        a[0] = n
        a[1] = 3
        return a[0] + a[1] + a.size
    }

    /**
     * Phase-2: throw + typed catch + move-exception.
     * flag==0 throws; otherwise returns flag*2.
     */
    @JvmStatic
    fun catchProbe(flag: Int): Int {
        return try {
            if (flag == 0) {
                throw RuntimeException()
            }
            flag * 2
        } catch (e: RuntimeException) {
            -7
        }
    }

    /** Phase-5: float ALU (mul + add). */
    @JvmStatic
    fun floatProbe(a: Float, b: Float): Float {
        return a * b + 1.5f
    }

    /** Phase-5: double ALU (div + sub). */
    @JvmStatic
    fun doubleProbe(a: Double, b: Double): Double {
        return a / b - 0.25
    }

    /** Phase-5: float compare → cmpl/cmpg. */
    @JvmStatic
    fun floatCmpProbe(a: Float, b: Float): Int {
        return if (a < b) -1 else if (a > b) 1 else 0
    }

    /** Phase-5: monitor-enter/exit via synchronized. */
    @JvmStatic
    fun syncProbe(n: Int): Int {
        synchronized(Business::class.java) {
            return n * 2 + stamp
        }
    }

    /** Regression: shl-long must use 32-bit shift count (not Reg.j). */
    @JvmStatic
    fun longShiftProbe(v: Long, n: Int): Long {
        return (v shl n) or (v ushr n)
    }

    /** Regression: float→int NaN / clamp semantics (ART). */
    @JvmStatic
    fun floatCastProbe(f: Float): Int {
        return f.toInt()
    }

    /** PR10: packed-switch (Dalvik 0x2b) coverage for True-VMP. */
    @JvmStatic
    fun packedSwitchProbe(x: Int): Int {
        return when (x) {
            0 -> 10
            1 -> 20
            2 -> 30
            3 -> 40
            else -> -1
        }
    }

    /** fill-array-data (Dalvik 0x26) coverage for True-VMP. */
    @JvmStatic
    fun fillArrayProbe(i: Int): Int {
        val a = intArrayOf(10, 20, 30, 40)
        return a[i and 3]
    }

    /** JNI into libdemo_biz.so (Phase 4 --protect-so smoke). */
    @JvmStatic
    external fun nativeAddRaw(a: Int, b: Int): Int

    /** Phase-4: VMP wrapper that invokes the protected business SO. */
    @JvmStatic
    fun soProbe(a: Int, b: Int): Int {
        return nativeAddRaw(a, b)
    }
}
