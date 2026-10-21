package io.github.xalsace.qqbypass;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.config.ModuleConfig;
import io.github.xalsace.qqbypass.hooks.*;
import io.github.xalsace.qqbypass.resolve.TargetResolver;

import java.util.List;

/**
 * QQ Enhanced Bypass - Comprehensive Detection Bypass Module
 *
 * This module provides multi-layered protection against QQ's environment detection:
 * - Java Layer: Root/Xposed/Debug detection bypass (30%)
 * - Native Layer: libc/libfekit/libturingxq hooks (70%)
 * - Network reporting interception
 * - Device info spoofing with cross-validation protection
 *
 * 执行模型（改造后）：handleLoadPackage 只做三件事 ——
 *   1. 初始化 HookConfig（classLoader 等全局状态，各 hook 类仍依赖它）
 *   2. 建注册表并逐模块隔离执行
 *   3. 汇总自检报告
 * 具体 hook 的调用不再写死在本类里，见 {@link HookRegistry}。
 */
public class XposedEntry implements IXposedHookLoadPackage {

    private static final String TAG = "QQEnhancedBypass";
    private static final String TARGET_PACKAGE = "com.tencent.mobileqq";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }

        log("=== QQ Enhanced Bypass v2.0 ===");
        log("Package: " + lpparam.packageName);
        log("Process: " + lpparam.processName);
        // Initialize configuration
        // 各既有 hook 类仍从 HookConfig 取 classLoader / lpparam，必须先初始化。
        // 唯一一处 banner 之前、尚未被 try/catch 覆盖的步骤：若这里抛异常，
        // handleLoadPackage 会整段 abort，LSPosed 只打一条无 QQEnhancedBypass
        // TAG 的 "Exception in hooker"，表现就是「注入了但日志全无」。
        // 显式包住并打 error，避免这种静默失败。
        try {
            HookConfig.init(lpparam);
        } catch (Throwable t) {
            logError("[fatal] HookConfig.init failed, abort injection", t);
            return;
        }

        // === DexKit 后台预解析（version-agnostic 改造第 4/5 项）===
        // 必须尽早启动：DexKit 解析上百 MB 的 dex 要数秒，而各 hook 类的
        // Tier A 只有在它 ready 后才可能命中。放在这里（HookConfig.init 之后、
        // 任何 hook 安装之前）是为了给后台线程争取最长的解析窗口，
        // 让同一次注入的 Tier A 就有机会生效，而不是每次都要等下一次重启。
        //
        // 非阻塞：本方法只起一条 MIN_PRIORITY 线程然后立刻返回，
        // handleLoadPackage 不会被拖慢。
        try {
            TargetResolver.initAsync(lpparam.appInfo.sourceDir);
        } catch (Throwable t) {
            // 起线程失败只意味着 Tier A 全程不可用，B/C 档照常工作。
            logError("TargetResolver init failed", t);
        }


        // === 运行时配置（路线图第 6 项）===
        ModuleConfig cfg;
        try {
            cfg = ModuleConfig.get();
            log("[config] " + cfg.describe());
        } catch (Throwable t) {
            // 配置读取绝不允许拖垮注入：读不到就全默认继续跑。
            cfg = ModuleConfig.defaults();
            log("[config] load failed, using defaults: " + t.getMessage());
        }

        // 把逐条 hook 日志的开关接到配置上（自检报告不受它影响，永远打印）。
        try {
            HookConfig.applyVerbose(cfg.isVerbose());
        } catch (Throwable ignored) {
        }

        // === Native 层（路线图第 2 项）===
        // 默认开启：CI 会产出 libnative-bypass.so 并打进 APK；
        // UnifiedHookCoordinator 在 .so 缺失时自动走纯 Java 降级，不会崩。
        // 要临时关掉，在 qqbypass.json 写 "nativeHooks": false 后重启 QQ。
        boolean nativeEnabled = cfg.isNativeHooksEnabled();
        if (nativeEnabled) {
            try {
                UnifiedHookCoordinator.initialize(lpparam);
            } catch (Throwable t) {
                // 这里抓不到 native crash（那是信号级的），只能抓 Java 侧异常。
                // 所以下面这条 [native] 日志是判断 library load 是否成功的唯一依据。
                logError("UnifiedHookCoordinator init failed", t);
            }
            // loadLibrary 是否成功，直接决定了保护等级是 80% 还是 30%
            log("[native] enabled=" + io.github.xalsace.qqbypass.NativeBypass.isLibraryLoaded()
                + " (true=+so+loaded, false=lib missing, falling back to Java only)");
        } else {
            log("[native] disabled by config (nativeHooks=false in qqbypass.json)");
        }

        // === Java 层多模块执行（路线图第 1 项）===
        List<HookResult> results;
        try {
            results = HookRegistry.createDefault().runAll(lpparam);
        } catch (Throwable t) {
            // runAll 自身已逐模块兜底，走到这里说明注册表构造阶段就炸了。
            logError("HookRegistry failed to run", t);
            results = null;
        }

        // === 自检报告 ===
        if (results != null) {
            log("=== Java Hooks: " + HookRegistry.summarize(results) + " ===");
            for (HookResult r : results) {
                log("  " + r.describe());
            }
        }

        // === 版本适配检测（路线图第 6 项）===
        // hook 目标写死在各 hook 类里，QQ 改版改名会静默失效。
        // 这里扫一遍关键符号，失效的直接报出来，不用靠猜。
        try {
            VersionCompat.logReport();
        } catch (Throwable t) {
            logError("version compat scan failed", t);
        }

        // Native 层在后台线程异步安装，稍后报告最终等级
        if (nativeEnabled) {
            try {
                log("Initial Protection Level: " + UnifiedHookCoordinator.getProtectionLevel());
                UnifiedHookCoordinator.reportFinalProtectionLevelAsync();
            } catch (Throwable t) {
                logError("protection level report failed", t);
            }
        }
    }

    /**
     * Initialize native layer hooks (deprecated - now handled by UnifiedHookCoordinator)
     */
    @Deprecated
    private void initNativeHooks() {
        // This method is kept for compatibility but functionality moved to UnifiedHookCoordinator
    }

    public static void log(String message) {
        Log.i(TAG, message);
    }

    public static void logError(String message, Throwable t) {
        Log.e(TAG, message, t);
    }
}
