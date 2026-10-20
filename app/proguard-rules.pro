# ============================================================
# QQEnhancedBypass R8 / ProGuard 规则
#
# 修复说明：原规则里的包名是 io.github.qqenhanced.bypass，
# 而项目实际包名是 io.github.xalsace.qqbypass，包名整体对不上
# 导致所有 keep 规则全部失效。R8 full mode 于是把 XposedEntry
# 连同整套 hook 代码当作不可达死代码删除，安装后必然
# ClassNotFoundException: io.github.xalsace.qqbypass.XposedEntry
# ============================================================

# ---- 1. Xposed 入口（LSPosed 反射实例化，必须完整保留） ----
-keep class io.github.xalsace.qqbypass.XposedEntry {
    public <init>();
    public *;
}

# 入口实现的 Xposed 回调接口
-keep class * implements de.robv.android.xposed.IXposedHookLoadPackage
-keep class * implements de.robv.android.xposed.IXposedHookZygoteInit
-keep class * implements de.robv.android.xposed.IXposedHookInitPackageResources

# ---- 2. 整个模块代码树全量保留 ----
# hook 逻辑彼此通过静态方法互调，且可能被 native 层反向依赖，
# 任何一处被 shrink 都会造成运行期行为缺失，故整包保留。
-keep class io.github.xalsace.qqbypass.** { *; }
-keepclassmembers class io.github.xalsace.qqbypass.** { *; }
-keepnames class io.github.xalsace.qqbypass.** { *; }

# ---- 3. 配置类字段保护 ----
# HookConfig 的静态字段会被 hook 回调按名读写，保留字段名与 setter。
-keepclassmembers class io.github.xalsace.qqbypass.config.HookConfig {
    public static <fields>;
    public static <methods>;
}

# ---- 4. JNI 绑定 ----
# native 方法名必须与 Java 侧一一对应，重命名或移除都会
# 造成 UnsatisfiedLinkError。
-keepclasseswithmembernames class * {
    native <methods>;
}

# ---- 5. 注解 ----
# 原规则引用的 KeepForHook 注解类实际不存在，此处保留声明以防后续补充。
-keep @interface io.github.xalsace.qqbypass.annotation.KeepForHook

# ---- 6. 屏蔽第三方依赖告警 ----
-dontwarn de.robv.android.xposed.**
-dontwarn com.bytedance.android.bytehook.**
-dontwarn org.luckypray.dexkit.**

# ---- 6b. DexKit 自身保护 ----
# 原规则只加了 -dontwarn，但 DexKit 2.0.0 内部是 kotlin 实现，
# 通过反射构造 matcher 链 + 读 dex 条目，R8 full mode 下这些
# 内部类/构造器会被 shrink 或改名，运行期报
# NoSuchMethodException / ClassNotFoundException。
# 只 keep 它自己的包（org.luckypray.**），不动我们的代码树。
-keep class org.luckypray.dexkit.** { *; }
-keepclassmembers class org.luckypray.dexkit.** { *; }
# DexKit 依赖 kotlin-reflect 的元数据
-dontwarn kotlin.**
-dontwarn kotlinx.**

# ---- 7. 保留行号与源文件名，便于崩溃日志定位 ----
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ---- 8. 通用属性 ----
-keepattributes *Annotation*,InnerClasses,EnclosingMethod,Signature
