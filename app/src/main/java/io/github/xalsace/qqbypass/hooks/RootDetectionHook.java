package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.io.File;

/**
 * Root Detection Bypass Hook
 *
 * Bypasses Java-layer root detection implementations:
 * 1. oicq.wlogin_sdk.request.w.h() - Wlogin SDK
 * 2. org.light.device.LightDeviceUtils.isRooted()
 * 3. com.tenpay.charge.v2.util.ChargeV2Utils.isDeviceRooted()
 *
 * Note: Native-layer detection (libfekit.so) requires native hooks
 * QQ 9.3.50 removed: gathererga.UserInfoImpl, bugly.proguard.cp, camerasdk.avreport.DeviceInfo
 *
 * version-agnostic 改造（第 4 项）：每个 hook 点都走 TieredHook 三级降级。
 * 同时修掉一个 P0 级崩溃源（见 hookRuntimeExec 的注释）。
 */
public class RootDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_ROOT_BYPASS) return;

        XposedEntry.log("Initializing Root Detection Bypass");

        // Hook 1: Wlogin SDK root check
        hookWloginRoot();

        // Hook 2: Light Device Utils
        hookLightDeviceRoot();

        // Hook 3: Tenpay charge utils
        hookTenpayRoot();

        // Generic file existence checks for su binaries
        hookFileExists();

        // Hook Runtime.exec to prevent su detection
        hookRuntimeExec();

        // Hook PackageManager to hide root apps
        hookPackageManager();
    }

    private static void hookWloginRoot() {
        final String cls = "oicq.wlogin_sdk.request.w";
        final String classRegex = "oicq\\.wlogin_sdk\\..*";

        TieredHook.Install r = TieredHook.install(
            null, classRegex, "h", cls, "h",
            HookConfig.getClassLoader(),
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // This method collects device info including root status
                    // We let it run but will block the network report
                    XposedEntry.log("Wlogin root check intercepted");
                }
            });
        if (!r.ok()) XposedEntry.log("[root] wlogin MISS: " + r);
    }

    /**
     * Light Device Utils：isRooted() 返回 boolean。
     *
     * 降级：B 档正则 org\.light\.device\..* 防 SDK 内类名调整，
     * C 档写死 org.light.device.LightDeviceUtils#isRooted。
     * 返回值是原始类型 boolean，setResult(false) 类型安全。
     */
    private static void hookLightDeviceRoot() {
        final String cls = "org.light.device.LightDeviceUtils";
        final String classRegex = "org\\.light\\.device\\..*";

        TieredHook.Install r = TieredHook.install(
            null, classRegex, "isRooted", cls, "isRooted",
            HookConfig.getClassLoader(),
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                    XposedEntry.log("LightDevice isRooted: false");
                }
            });
        if (!r.ok()) XposedEntry.log("[root] light device MISS: " + r);
    }

    /**
     * Tenpay charge utils：isDeviceRooted() 返回 boolean，同上。
     */
    private static void hookTenpayRoot() {
        final String cls = "com.tenpay.charge.v2.util.ChargeV2Utils";
        final String classRegex = "com\\.tenpay\\.charge\\..*";

        TieredHook.Install r = TieredHook.install(
            null, classRegex, "isDeviceRooted", cls, "isDeviceRooted",
            HookConfig.getClassLoader(),
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                    XposedEntry.log("Tenpay isDeviceRooted: false");
                }
            });
        if (!r.ok()) XposedEntry.log("[root] tenpay MISS: " + r);
    }

    private static void hookFileExists() {
        // Hook File.exists() to hide su binaries and root manager apps
        HookUtils.hookMethod(File.class, "exists",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File file = (File) param.thisObject;
                    String path = file.getAbsolutePath();

                    // Common su paths
                    if (isSuspiciousPath(path)) {
                        param.setResult(false);
                    }
                }
            });
    }

    /**
     * Hook Runtime.exec to prevent command-based detection.
     *
     * 【P0 修复】原实现在 hook 回调内直接
     *     param.setResult(new ProcessBuilder("echo").start());
     * 这是错的，两个原因：
     *   1. 递归：ProcessBuilder.start() 本身又被本模块的
     *      RuntimeMonitorHook.hookProcessBuilder hook 着，会在回调里再次进入
     *      hook 逻辑，极端情况下栈溢出。
     *   2. 主线程阻塞：exec 的调用方常在主线程，new ProcessBuilder().start()
     *      是重量级系统调用（fork+exec+pipe），在 hook 回调里同步做会卡 UI，
     *      QQ 的 ANR 监控会记录到。
     *
     * 现在改成「只观察 + 交给 RuntimeMonitorHook 统一中性化」：
     * RuntimeMonitorHook.hookProcessBuilder 已经把 `type su` / `which su` 等
     * root 探针在**原地**改写成 `sh -c exit 1`，那才是正确的 choke point
     * （Runtime.exec 和 Pandora RuntimeMonitor.exec 都汇聚到它）。
     * 这里不再重复拦截，只打日志说明流量经过了哪个入口。
     */
    private static void hookRuntimeExec() {
        final String cls = "java.lang.Runtime";
        final String classRegex = "java\\.lang\\.Runtime";

        TieredHook.Install r = TieredHook.install(
            null, classRegex, "exec", cls, "exec",
            HookConfig.getClassLoader(),
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length == 0 || param.args[0] == null) return;
                    String command = param.args[0].toString();
                    if (command == null) return;

                    if (command.contains("su") || command.contains("magisk")
                            || command.contains("/system/xbin/which")
                            || (command.contains("mount") && command.contains("grep"))) {
                        // 不在这里拦：由 RuntimeMonitorHook 在 ProcessBuilder.start
                        // 原地改写命令。这里只记一笔，便于确认探针确实流经 Runtime.exec。
                        XposedEntry.log("[root] root probe via Runtime.exec (handled by "
                            + "ProcessBuilder neutralizer): " + command);
                    }
                }
            });
        if (!r.ok()) XposedEntry.log("[root] Runtime.exec MISS: " + r);
    }

    /**
     * Hook PackageManager to hide root management apps.
     *
     * 降级：ApplicationPackageManager 是 AOSP framework 类，名字不变，
     * 走纯 C 档（installFixed）即可，做 A/B 是浪费。
     * 行为保持原样：只 hook 不改写（改写有连锁崩溃风险）。
     */
    private static void hookPackageManager() {
        String[] methods = {"getPackageInfo", "getApplicationInfo", "getInstalledPackages", "getInstalledApplications"};

        for (String method : methods) {
            final String m = method;
            TieredHook.Install r = TieredHook.installFixed(
                "android.app.ApplicationPackageManager", m,
                HookConfig.getClassLoader(),
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        // Filter out root management apps from results
                        // Implementation depends on return type
                    }
                });
            if (!r.ok()) {
                XposedEntry.log("[root] PackageManager#" + m + " MISS: " + r);
            }
        }
    }

    private static boolean isSuspiciousPath(String path) {
        // Comprehensive list of root-related paths
        String[] suspiciousPaths = {
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/bin/su",
            "/system/bin/.ext/.su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/system/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu",
            // Magisk
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/magisk.log",
            "/data/magisk.img",
            "/data/adb/magisk.img",
            // KernelSU
            "/data/adb/ksu",
            "/data/adb/ksud"
        };

        for (String suspicious : suspiciousPaths) {
            if (path.contains(suspicious)) {
                return true;
            }
        }
        return false;
    }
}
