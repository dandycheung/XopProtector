# Keep Android entry points; allow R8 to obfuscate Business and other app code.
-keepclassmembers class * extends android.app.Activity {
    public void *(android.view.View);
}

# Keep TRUE_VMP demo targets so packer can compile them to PVM2
# (R8 would otherwise inline them into MainActivity).
-keep class com.yqsh.protectordemo.Business {
    public static *** *(...);
    public static int stamp;
    public static native int nativeAddRaw(int, int);
}

# Lifecycle self-test (DefaultLifecycleObserver bridge methods)
-keep class com.yqsh.protectordemo.LifecycleProbe { *; }
-keep class com.yqsh.protectordemo.ComponentCallbackProbeProvider { *; }
-keepclassmembers class * implements androidx.lifecycle.DefaultLifecycleObserver {
    <methods>;
}
