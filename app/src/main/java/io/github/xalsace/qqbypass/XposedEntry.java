package io.github.xalsace.qqbypass;

import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.config.ModuleConfig;
import io.github.xalsace.qqbypass.hooks.*;

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
        HookConfig.init(lpparam);

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
        // 默认关闭。native hook 未经真机验证，且由配置文件控制，
        // 不再读 HookConfig 的编译期常量。
        boolean nativeEnabled = cfg.isNativeHooksEnabled();
        if (nativeEnabled) {
            try {
                UnifiedHookCoordinator.initialize(lpparam);
            } catch (Throwable t) {
                logError("UnifiedHookCoordinator init failed", t);
            }
        } else {
            log("[native] disabled by config (default off - untested on device)");
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
