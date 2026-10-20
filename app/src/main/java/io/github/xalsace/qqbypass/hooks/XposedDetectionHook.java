package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Xposed/LSPosed/Hook Framework Detection Bypass
 *
 * Mitigates detection of:
 * - LSPosed/Xposed installer package
 * - Xposed framework artifacts
 * - /proc/self/maps scanning for hook libraries
 * - Cydia Substrate detection
 * - ART method hook detection (limited effectiveness)
 *
 * Note: Native-layer detection (libfekit.so, libturingxq.so) requires native hooks
 * This module can only handle Java-layer checks and file I/O interception
 *
 * version-agnostic 改造（第 4 项）：三级降级 + 删掉两个 P0 级空转 hook。
 * 详见 hookProcMapsReading 的注释。
 */
public class XposedDetectionHook {

    private static final String[] XPOSED_PACKAGES = {
        "de.robv.android.xposed.installer",
        "org.meowcat.edxposed.manager",
        "io.github.lsposed.manager",
        "com.topjohnwu.magisk"
    };

    private static final String[] HOOK_LIBRARY_PATTERNS = {
        "lsposed",
        "xposed",
        "libriru",
        "zygisk",
        "edxposed",
        "libsubstrate",
        "libAndroidCydia",
        "libDalvikLoader"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_XPOSED_BYPASS) return;

        XposedEntry.log("Initializing Xposed Detection Bypass");

        // Hook 1: PackageManager to hide Xposed packages
        hookPackageManagerForXposed();

        // Hook 2: File I/O to filter /proc/self/maps
        hookProcMapsReading();

        // Hook 3: Stack trace filtering
        hookStackTrace();

        // Hook 4: ClassLoader detection
        hookClassLoaderCheck();
    }

    private static void hookPackageManagerForXposed() {
        // Hide Xposed-related packages from PackageManager queries
        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getPackageInfo",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String packageName = (String) param.args[0];
                        if (isXposedPackage(packageName)) {
                            XposedEntry.log("Blocked PackageManager query for: " + packageName);
                            throw new android.content.pm.PackageManager.NameNotFoundException();
                        }
                    }
                }
            });

        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getApplicationInfo",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String packageName = (String) param.args[0];
                        if (isXposedPackage(packageName)) {
                            throw new android.content.pm.PackageManager.NameNotFoundException();
                        }
                    }
                }
            });

        HookUtils.hookAllMethods("android.app.ApplicationPackageManager", "getInstalledPackages",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.getResult() != null) {
                        @SuppressWarnings("unchecked")
                        List<Object> packages = (List<Object>) param.getResult();
                        List<Object> filtered = new ArrayList<>();

                        for (Object pkg : packages) {
                            String pkgName = (String) XposedHelpers.getObjectField(pkg, "packageName");
                            if (!isXposedPackage(pkgName)) {
                                filtered.add(pkg);
                            }
                        }
                        param.setResult(filtered);
                    }
                }
            });
    }

    /**
     * /proc/self/maps 读取过滤。
     *
     * 【P0 修复】原实现 hook 了两个东西，两个都是空转：
     *
     *   1. FileReader.read(char[])
     *      回调体是空的（只有一行注释 "just log the attempt"），
     *      连日志都没打 —— 纯占位。
     *   2. BufferedReader.readLine()
     *      回调里想通过 XposedHelpers.getObjectField(reader, "lock")
     *      拿到 FileReader 再判断路径。问题是：
     *        - java.io.BufferedReader 的字段名是 `in`，不是 `lock`
     *          （lock 是 PushbackReader 才有），getObjectField 必然抛
     *          NoSuchFieldException → 被 catch(Throwable) 吞掉 → 永远不命中。
     *        - 就算拿到 FileReader，也没有 API 能从它反查文件名。
     *     结论：这个 hook 一次都没生效过。
     *
     * 而且方向本身是错的：QQ 读 /proc/self/maps 走的是 **native fopen**
     * （libturingxq.so 的 parse_libart.cpp），Java 层的 BufferedReader
     * 根本不在那条路径上。在 Java 层拦等于拦一个不存在的调用。
     *
     * 现在：删掉这两个空转 hook，只保留真正有效的 File.exists() 隐藏
     * （Xposed 安装包/产物的路径探测确实走 Java File.exists）。
     */
    private static void hookProcMapsReading() {
        // Hook File.exists for LSPosed artifacts —— 这是本方法里唯一真实有效的部分。
        // java.io.File 是 AOSP framework 类，纯 C 档即可。
        TieredHook.Install r = TieredHook.installFixed(
            "java.io.File", "exists",
            HookConfig.getClassLoader(),
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File file = (File) param.thisObject;
                    if (file == null) return;
                    String path = file.getAbsolutePath();
                    if (path == null) return;

                    if (isXposedArtifact(path)) {
                        param.setResult(false);
                        XposedEntry.log("Hidden Xposed artifact: " + path);
                    }
                }
            });

        if (!r.ok()) {
            XposedEntry.log("[xposed] File.exists MISS: " + r);
        } else {
            XposedEntry.log("[xposed] File.exists installed: " + r);
        }
    }

    private static void hookStackTrace() {
        // Filter Xposed from stack traces
        HookUtils.hookMethod(Throwable.class, "getStackTrace",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    StackTraceElement[] original = (StackTraceElement[]) param.getResult();
                    if (original == null) return;

                    List<StackTraceElement> filtered = new ArrayList<>();
                    for (StackTraceElement element : original) {
                        String className = element.getClassName();
                        if (!className.contains("xposed") &&
                            !className.contains("lsposed") &&
                            !className.contains("edxposed")) {
                            filtered.add(element);
                        }
                    }

                    if (filtered.size() != original.length) {
                        param.setResult(filtered.toArray(new StackTraceElement[0]));
                    }
                }
            });
    }

    private static void hookClassLoaderCheck() {
        // Some apps check the ClassLoader chain for Xposed
        HookUtils.hookMethod(ClassLoader.class, "toString",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    String result = (String) param.getResult();
                    if (result != null && (result.contains("xposed") || result.contains("lsposed"))) {
                        // Sanitize the string
                        result = result.replaceAll("(?i)xposed", "dalvik")
                                       .replaceAll("(?i)lsposed", "dalvik");
                        param.setResult(result);
                    }
                }
            });
    }

    private static boolean isXposedPackage(String packageName) {
        if (packageName == null) return false;
        for (String xposedPkg : XPOSED_PACKAGES) {
            if (packageName.equals(xposedPkg)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsHookLibrary(String line) {
        if (line == null) return false;
        String lowerLine = line.toLowerCase();
        for (String pattern : HOOK_LIBRARY_PATTERNS) {
            if (lowerLine.contains(pattern.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isXposedArtifact(String path) {
        return path != null && (
            path.contains("/data/user_de/0/org.lsposed.manager") ||
            path.contains("/data/user/0/org.lsposed.manager") ||
            path.contains("/data/data/de.robv.android.xposed.installer") ||
            path.contains("XposedBridge") ||
            path.contains("/system/framework/XposedBridge")
        );
    }
}
