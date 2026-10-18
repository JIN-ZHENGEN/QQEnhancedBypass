package io.github.xalsace.qqbypass.hooks;

import android.os.Build;
import android.os.Process;
import android.telephony.TelephonyManager;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.Fingerprint;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.config.ModuleConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Device Info Hook - Consistency Protection
 *
 * Handles Pandora's multi-path cross-validation:
 * - Ensures consistent values across different API calls
 * - Prevents detection of single-API hooks
 * - Maintains device fingerprint consistency
 *
 * Pandora DeviceInfoMonitor uses 6+ different methods to get the same info:
 * - TelephonyManager.getImei()
 * - TelephonyManager.getDeviceId()
 * - Build.SERIAL (field)
 * - Build.getSerial() (method)
 * - SystemProperties.get()
 * - SubscriptionManager APIs
 */
public class DeviceInfoHook {

    /**
     * 当前进程的指纹快照。
     *
     * 改造前这里是 4 个独立 static 字段，两个问题：
     *  - 跨 user 串号（XSpace 下 u0/u999 共用一套，放大风控）
     *  - 跨进程可能不一致（各进程各自初始化）
     *
     * 现在换成单个 {@link Fingerprint}：它由 (设备种子, userId) **确定性派生**，
     * 不保存状态。同一 user 在任何进程任何时刻算出的值必定相同，
     * 这正好满足 Pandora 多路径交叉校验的要求。
     *
     * 为 null 表示不伪造（真值透传），保持改造前的默认行为。
     */
    private static volatile Fingerprint fingerprint = null;

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_DEVICE_SPOOF) return;

        XposedEntry.log("Initializing Device Info Hook");

        // Initialize cached values from config or real device
        initCachedValues();

        // Hook all device ID retrieval methods with consistent values
        hookTelephonyManager();
        hookBuildSerial();
        hookSystemProperties();
        hookAndroidId();

        // Hook Pandora monitoring framework
        hookPandoraMonitor();
    }

    private static void initCachedValues() {
        Fingerprint fp = null;
        try {
            ModuleConfig cfg = ModuleConfig.get();
            if (cfg.isSpoofFingerprintEnabled()) {
                fp = cfg.fingerprintForUser(currentUserId());
                XposedEntry.log("[device] spoofing enabled: " + fp);
            } else {
                XposedEntry.log("[device] spoofing disabled - passing through real values");
            }
        } catch (Throwable t) {
            // 指纹构造绝不允许打断注入：出错就退回真值透传。
            XposedEntry.log("[device] fingerprint init failed, pass-through: " + t.getMessage());
            fp = null;
        }
        fingerprint = fp;
    }

    /**
     * 当前进程所属 user id。
     *
     * 用 Process.myUid()/100000 推导（Android 的 uid = userId * 100000 + appId），
     * 而不是直接用 myUid()：后者是 app 级 uid，同一 user 内不同 app 不同值，
     * 不能作为指纹分桶键。
     */
    private static int currentUserId() {
        try {
            return Process.myUid() / 100000;
        } catch (Throwable t) {
            return 0;
        }
    }

    private static String cachedImei() {
        Fingerprint fp = fingerprint;
        return fp == null ? null : fp.imei();
    }

    private static String cachedSerial() {
        Fingerprint fp = fingerprint;
        return fp == null ? null : fp.serial();
    }

    private static String cachedAndroidId() {
        Fingerprint fp = fingerprint;
        return fp == null ? null : fp.androidId();
    }

    private static void hookTelephonyManager() {
        // Hook all IMEI/DeviceId retrieval methods
        String[] methods = {"getImei", "getDeviceId", "getMeid"};

        for (String method : methods) {
            HookUtils.hookAllMethods("android.telephony.TelephonyManager", method,
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (cachedImei() != null) {
                            param.setResult(cachedImei());
                        }
                        // If null, let real value pass through for consistency
                    }
                });
        }

        // Hook getSimSerialNumber
        HookUtils.hookAllMethods("android.telephony.TelephonyManager", "getSimSerialNumber",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (cachedSerial() != null) {
                        param.setResult(cachedSerial());
                    }
                }
            });
    }

    private static void hookBuildSerial() {
        // Hook Build.SERIAL field access (difficult to hook directly)
        // Hook Build.getSerial() method instead
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            HookUtils.hookMethod(Build.class, "getSerial",
                new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        if (cachedSerial() != null) {
                            param.setResult(cachedSerial());
                        }
                    }
                });
        }
    }

    private static void hookSystemProperties() {
        // Hook SystemProperties.get() to return consistent values
        HookUtils.hookAllMethods("android.os.SystemProperties", "get",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String key = (String) param.args[0];

                        // Override specific properties
                        if ("ro.boot.serialno".equals(key) && cachedSerial() != null) {
                            param.setResult(cachedSerial());
                        } else if ("gsm.serial".equals(key) && cachedSerial() != null) {
                            param.setResult(cachedSerial());
                        }
                    }
                }
            });
    }

    private static void hookAndroidId() {
        // Hook Settings.Secure.getString for android_id
        HookUtils.hookAllMethods("android.provider.Settings.Secure", "getString",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length >= 2) {
                        String key = (String) param.args[1];
                        if ("android_id".equals(key) && cachedAndroidId() != null) {
                            param.setResult(cachedAndroidId());
                        }
                    }
                }
            });
    }

    private static void hookPandoraMonitor() {
        // Hook Pandora's DeviceInfoMonitor to prevent cross-validation
        HookUtils.hookAllMethods("com.tencent.qmethod.pandoraex.monitor.DeviceInfoMonitor", "getImei",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    if (cachedImei() != null) {
                        param.setResult(cachedImei());
                    }
                }
            });

        // Hook MonitorReporter.report (void method) to suppress anomaly reports.
        // report() returns void, so setResult(null) is type-safe.
        HookUtils.hookAllMethods("com.tencent.qmethod.pandoraex.core.MonitorReporter", "report",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    // Block all monitoring reports
                    param.setResult(null);
                }
            });

        // NOTE: Do NOT hook getStrategyAndReport().
        // It sits on the NORMAL data-retrieval path (DeviceInfoMonitor.getModel,
        // InstalledAppListMonitor.getRunningAppProcesses) and returns a typed
        // strategy object. Forcing setResult(0) triggers a ClassCastException
        // ("Return value's type from hook callback does not match the hooked method")
        // thrown by Xposed during proceed() - impossible to catch - which crashes
        // QQ's startup tasks and blocks entry to the main UI (QQ 9.3.50).
    }
}
