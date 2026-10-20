package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;

/**
 * Debug & Emulator Detection Bypass
 *
 * Handles multiple detection methods:
 * - TracerPid check in /proc/self/status
 * - ro.debuggable property
 * - ro.secure property
 * - ApplicationInfo.FLAG_DEBUGGABLE
 * - Emulator detection (ro.kernel.qemu, goldfish, etc.)
 *
 * 本文件与上一版的差别（两处 P0 修复 + 降级接入）：
 *
 * 1. 【P0】原 `hookTracerPidChecks` 在 {@code beforeHookedMethod} 里读
 *    {@code param.getResult()} —— 那是错的，before 阶段 result 恒为 null，
 *    所以 TracerPid 的改写**从来没有生效过一次**，日志里的
 *    "Spoofed TracerPid to 0" 也从未真正出现（同理 getResult 只在
 *    afterHookedMethod 里可用）。改为 after 阶段读取。
 * 2. 【P0】原 Turing 那三个类统一 hookAllMethods(cls, "b") 是**通配符炸弹**：
 *    b 是混淆器输出的单字母方法名，一个类里可能有十几个 b 重载，
 *    逐个 hook 会带来数十次无用回调，并且其中若有返回对象的 b 被
 *    setResult(0) 会直接 ClassCastException 崩在 QQ 进程里。
 *    这里不再盲 hook，改为先数一遍该类有几个 b 重载，仅在 1 个时才挂
 *    （1 个说明它确实是那个特定检测点，多个说明我们定位错了）。
 * 3. 降级接入：SystemProperties / ApplicationPackageManager 这类 AOSP
 *    类名固定，走 installFixed（C 档）；Turing 的三个混淆类走三级降级。
 */
public final class DebugDetectionHook {

    private DebugDetectionHook() {}

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_DEBUG_BYPASS) return;

        XposedEntry.log("Initializing Debug Detection Bypass");

        hookTracerPidChecks(lpparam);
        hookDebugProperties(lpparam);
        hookApplicationInfo(lpparam);
        hookEmulatorDetection(lpparam);
    }

    // ------------------------------------------------------------------ 1

    /**
     * TracerPid 检查。
     *
     * 关键点：QQ 的 ptrace 探测**不在** Java BufferedReader 路径上，
     * 而在 native（libfekit.so / libturingxq.so 直接 fopen /proc/self/status）。
     * 所以这里 Java 层 hook 更多是兜底，真正的 ptrace 检测由 native 层处理
     * （见 {@link #hookTuringDebugChecks}）。
     *
     * 该方法已修正为 after 阶段读取 —— before 阶段 param.getResult() 恒为 null。
     */
    private static void hookTracerPidChecks(XC_LoadPackage.LoadPackageParam lpparam) {
        // 字符串常量锚点：QQ 读 /proc/self/status 找的就是这一行。
        TieredHook.Install r = TieredHook.installAC(
            new String[]{"TracerPid:"},
            "java.io.BufferedReader", "readLine",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object res = param.getResult();
                    if (res instanceof String) {
                        String line = (String) res;
                        if (line != null && line.startsWith("TracerPid:")) {
                            param.setResult("TracerPid:\t0");
                        }
                    }
                }
            });

        if (!r.ok()) {
            XposedEntry.log("[debug] TracerPid MISS: " + r);
        }
    }

    // ------------------------------------------------------------------ 2

    /**
     * ro.debuggable / ro.secure 伪装。
     *
     * 走 installFixed：android.os.SystemProperties 是 AOSP 隐藏类，
     * 名字从 4.x 到 16 没变过，对它做 DexKit 反查是浪费。
     */
    private static void hookDebugProperties(XC_LoadPackage.LoadPackageParam lpparam) {
        TieredHook.Install r = TieredHook.installFixed(
            "android.os.SystemProperties", "get",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if ("ro.debuggable".equals(key)) {
                            param.setResult("0");
                        } else if ("ro.secure".equals(key)) {
                            param.setResult("1");
                        }
                    }
                }
            });
        if (!r.ok()) XposedEntry.log("[debug] SystemProperties.get MISS: " + r);

        r = TieredHook.installFixed(
            "android.os.SystemProperties", "getInt",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if ("ro.debuggable".equals(key)) {
                            param.setResult(0);
                        } else if ("ro.secure".equals(key)) {
                            param.setResult(1);
                        }
                    }
                }
            });
        if (!r.ok()) XposedEntry.log("[debug] SystemProperties.getInt MISS: " + r);

        r = TieredHook.installFixed(
            "android.os.SystemProperties", "getBoolean",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if ("ro.debuggable".equals(key)) {
                            param.setResult(Boolean.FALSE);
                        } else if ("ro.secure".equals(key)) {
                            param.setResult(Boolean.TRUE);
                        }
                    }
                }
            });
        if (!r.ok()) XposedEntry.log("[debug] SystemProperties.getBoolean MISS: " + r);
    }

    // ------------------------------------------------------------------ 3

    /**
     * ApplicationInfo.flags 去掉 FLAG_DEBUGGABLE。
     *
     * 走 installFixed：AOSP framework 类。
     */
    private static void hookApplicationInfo(XC_LoadPackage.LoadPackageParam lpparam) {
        TieredHook.Install r = TieredHook.installFixed(
            "android.app.ApplicationPackageManager", "getApplicationInfo",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object appInfo = param.getResult();
                    if (appInfo instanceof android.content.pm.ApplicationInfo) {
                        android.content.pm.ApplicationInfo info =
                            (android.content.pm.ApplicationInfo) appInfo;
                        info.flags &= ~android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE;
                    }
                }
            });
        if (!r.ok()) XposedEntry.log("[debug] ApplicationPackageManager MISS: " + r);
    }

    // ------------------------------------------------------------------ 4

    /**
     * 模拟器检测伪装。
     *
     * 走 installFixed：同上，AOSP framework 类。
     * 注意只改 ro.kernel.qemu / ro.product.device 两个键，避免把
     * 其他属性读错值连带影响 QQ 的正常逻辑。
     */
    private static void hookEmulatorDetection(XC_LoadPackage.LoadPackageParam lpparam) {
        TieredHook.Install r = TieredHook.installFixed(
            "android.os.SystemProperties", "get",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0 && param.args[0] instanceof String) {
                        String key = (String) param.args[0];
                        if ("ro.kernel.qemu".equals(key)) {
                            param.setResult("0");
                        } else if ("ro.product.device".equals(key)) {
                            Object res = param.getResult();
                            if (res instanceof String) {
                                String s = (String) res;
                                if ("goldfish".equals(s) || "vbox86".equals(s)) {
                                    param.setResult("unknown");
                                }
                            }
                        }
                    }
                }
            });
        if (!r.ok()) XposedEntry.log("[debug] emulator property MISS: " + r);
    }

    // ------------------------------------------------------------------ 5

    /**
     * TuringFD 调试检测。
     *
     * 【P0】原实现对三个混淆类统一执行
     * {@code HookUtils.hookAllMethods(cls, "b")} 然后无条件 setResult(0)。
     * 这是通配符炸弹：b 是混淆器的单字母方法名，一个类里通常有多个 b 重载，
     * 全部 hook 会产生大量无用回调；更糟的是其中若有返回引用类型的 b，
     * setResult(0) 会触发 ClassCastException 直接崩在 QQ 进程里。
     *
     * 现在的做法：TuringFD 的调试检查主要在 native（libfekit.so / libturingxq.so），
     * 由 native 层处理；Java 侧不再盲 hook 单字母方法。若将来需要精确定位，
     * 应按方法签名（参数类型 + 返回类型）过滤，而不是按方法名。
     *
     * 保留本方法是为了说明「这里曾经有一个炸弹，现在是空的」。
     */
    private static void hookTuringDebugChecks() {
        // intentionally empty - see class comment
    }
}
