# Shell entry points must survive R8 (manifest + JNI + reflection).
-keep class com.yqsh.protector.shell.ProxyApplication { *; }
-keep class com.yqsh.protector.shell.ProxyComponentFactory { *; }
-keep class com.yqsh.protector.shell.JniBridge { *; }
-keepclassmembers class com.yqsh.protector.shell.JniBridge {
    native <methods>;
}
# DexMerger / ApplicationReplacer are called from kept shell classes; allow shrinking of unused helpers.
-keep class com.yqsh.protector.shell.DexMerger { *; }
-keep class com.yqsh.protector.shell.ApplicationReplacer { *; }
-keep class com.yqsh.protector.shell.StrEnc { *; }
# CrashGuard + nested handler (shell DEX re-d8; no lambda synthetics).
-keep class com.yqsh.protector.shell.CrashGuard { *; }
-keep class com.yqsh.protector.shell.CrashGuard$* { *; }
