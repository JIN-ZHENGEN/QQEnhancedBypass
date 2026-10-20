package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * QQ 9.3.50 detection/report completion hooks.
 *
 * Targets the real risk-control data sources that the legacy hooks missed
 * (the legacy onExec/process/sendSsoMsg targets either did not exist on 9.3.50
 * or were on the wrong path). Every class/method below was verified to exist by
 * directly parsing QQ 9.3.50's dex class_data (not trusting the written reports,
 * which contained several fabricated method names).
 *
 * Return types were also verified. setResult(null) is only used where the method
 * returns void (V) or an Object (never a primitive) to avoid the uncatchable
 * ClassCastException class of crash. Object-returning blocks carry an NPE caveat
 * (caller may deref null) and are grouped separately so they can be toggled.
 *
 * Everything is gated by HookConfig.ENABLE_QQ950_PATCH and classExists() so a
 * missing class can never crash module init.
 */
public class QQ950PatchHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_QQ950_PATCH) return;

        XposedEntry.log("Initializing QQ 9.3.50 detection-point patch");

        // Tier 1: void-return, crash-safe backstops (kick + telemetry + switches)
        hookKickBackstop();
        hookMsfTelemetry();
        hookTuringWrapper();
        hookChannelReport();

        // Tier 2: object-return risk-detection blocks (type-safe, NPE-caveat)
        hookTuringRiskDetect();
        hookTuringDID();
    }

    // ==================== Tier 1: void-return, crash-safe ====================

    /**
     * Kick backstop: the method that actually clears the login state on a server
     * kick. Blocking it prevents the forced logout.
     * NOTE: if the server has already invalidated the session token this may
     * leave a non-functional session; kept as a backstop, observe behavior.
     *
     * 三级降级（version-agnostic 改造）：
     *   A 按 "mqq.intent.action.KICK_TO_LOGIN" 字符串反查引用它的方法
     *   B 类名正则 com\.tencent\.mobileqq\.kick\..* + 方法名 [a-z]
     *   C 写死的 com.tencent.mobileqq.kick.NTKickProcessor#b（9.3.50 实测值）
     *
     * 为什么必须降级：9.3.50 的类名是 ...mobileqq.kick.NTKickProcessor，
     * 9.3.60 起搬到 login.ntlogin 下并改名（Issue #2 列出的 ao#f 即其中之一），
     * 到 9.3.75 C 档大概率已经失效。C 档失效时旧代码只会静默跳过 ——
     * 现在会显式报 MISS，由 ActivityLaunchHook 从 Intent 层面兜底。
     */
    private static void hookKickBackstop() {
        final String[] kickStrings = {"mqq.intent.action.KICK_TO_LOGIN"};
        final String cls = "com.tencent.mobileqq.kick.NTKickProcessor";
        final String classRegex = "com\\.tencent\\.mobileqq\\.(kick|login)\\..*";

        TieredHook.Install r = TieredHook.install(
            kickStrings,
            classRegex, "[a-z]",
            cls, "b",
            HookConfig.getClassLoader(),
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null); // void return - crash-safe
                    // 刻意不在回调里读 r.tier：r 的赋值发生在 install() 返回之后，
                    // 而本回调可能在 install() 内部挂上 hook 的瞬间就被触发。
                    // 在匿名内部类里引用尚未完成赋值的局部变量，javac 直接报
                    // "variable r might not have been initialized"。
                    // 档位信息由外层 !r.ok() 分支统一输出。
                    XposedEntry.log("[QQ950] blocked kick backstop");
                }
            });

        if (!r.ok()) {
            XposedEntry.log("[QQ950] kick backstop MISS (" + r
                + ") - 依赖 ActivityLaunchHook 的 Intent 层兜底");
        } else {
            XposedEntry.log("[QQ950] kick backstop installed: " + r);
        }
    }

    /**
     * MSF telemetry: all void, pure reporting. sendAllMsg is intentionally
     * EXCLUDED (name implies message flushing, blocking could break send/recv).
     *
     * 降级说明：MsfCore 是 msf 核心类，包名 com.tencent.mobileqq.msf.core
     * 从 QQ 5.x 起没变过，C 档可靠性高；A 档用 "MsfCore" 这个类名字符串
     * 不好使（重名太多），所以只给 B 档正则 + C 档写死。
     */
    private static void hookMsfTelemetry() {
        final String cls = "com.tencent.mobileqq.msf.core.MsfCore";
        final String classRegex = "com\\.tencent\\.mobileqq\\.msf\\.core\\..*";
        String[] reportMethods = {
            "doReportOnInitComplete", "reportMsfCoreInit",
            "tryReportJobAlive", "tryReportLoadCfgTempFile",
            "tryReportMSFAlive", "tryReportSoLoadUseTxlib"
        };
        for (String m : reportMethods) {
            TieredHook.Install r = TieredHook.install(
                null, classRegex, m, cls, m,
                HookConfig.getClassLoader(),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        p.setResult(null); // all void - crash-safe
                    }
                });
            if (!r.ok()) {
                // 单方法 MISS 不致命（6 个里少几个不影响主体），记一行即可
                XposedEntry.log("[QQ950] msf telemetry MISS: " + r);
            }
        }
    }

    /**
     * Turing switches: TuringWrapper.b()/c() : void. a() returns AtomicBoolean
     * (state), left untouched to avoid NPE.
     *
     * 降级：B 档正则覆盖 com.tencent.mobileqq.dt.model.* 整包，
     * 因为 TuringWrapper 这个名字在 9.3.60 之后有变动记录。
     */
    private static void hookTuringWrapper() {
        final String cls = "com.tencent.mobileqq.dt.model.TuringWrapper";
        final String classRegex = "com\\.tencent\\.mobileqq\\.dt\\.model\\..*";
        for (String m : new String[]{"b", "c"}) {
            TieredHook.Install r = TieredHook.install(
                null, classRegex, m, cls, m,
                HookConfig.getClassLoader(),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        p.setResult(null); // void - crash-safe
                    }
                });
            if (!r.ok()) {
                XposedEntry.log("[QQ950] turing wrapper MISS: " + r);
            }
        }
    }

    /**
     * ChannelManager.checkMethod() : void - the Java-side entry that arms the
     * report channel (initReport is private native, cannot be hooked directly).
     *
     * 降级：ChannelManager 是 QQ 自有类，包名 com.tencent.mobileqq.channel
     * 稳定；B 档正则覆盖整包防类名内层级调整。
     */
    private static void hookChannelReport() {
        final String cls = "com.tencent.mobileqq.channel.ChannelManager";
        final String classRegex = "com\\.tencent\\.mobileqq\\.channel\\..*";

        TieredHook.Install r = TieredHook.install(
            null, classRegex, "checkMethod", cls, "checkMethod",
            HookConfig.getClassLoader(),
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                    p.setResult(null); // void - crash-safe
                    // 不在回调里读 r.tier，原因同 hookKickBackstop：
                    // javac 明确赋值分析会报 "variable r might not have been initialized"。
                    XposedEntry.log("[QQ950] blocked ChannelManager.checkMethod");
                }
            });

        if (!r.ok()) {
            XposedEntry.log("[QQ950] channel report MISS: " + r);
        }
    }

    // ============ Tier 2: object-return risk detection (NPE-caveat) ============
    // These return Objects, so setResult(null) is TYPE-safe (no ClassCastException),
    // but a caller that dereferences the null result without a guard could NPE.
    // Turing SDKs generally null-check risk responses defensively. Gated so they
    // can be disabled independently if an NPE appears in logs.

    /**
     * TuringRiskService.reqRiskDetectV2(...) : RiskDetectResp - the core risk
     * detection call whose result feeds the server's cheat/anomaly judgment.
     * Both the wxa and xq SDK variants, 3 overloads each.
     *
     * 降级：这两条类名属于腾讯 Turing SDK，版本间 package 有过 wxa/xq 互换；
     * B 档用宽正则 com\.tencent\.(turingfd|turingcam|tfd)\..* 一并覆盖。
     */
    private static void hookTuringRiskDetect() {
        if (!HookConfig.ENABLE_QQ950_RISK_BLOCK) return;
        String[] classes = {
            "com.tencent.tfd.sdk.wxa.TuringRiskService",
            "com.tencent.turingfd.sdk.xq.TuringRiskService"
        };
        final String classRegex = "com\\.tencent\\.(turingfd|turingcam|tfd)\\.sdk\\..*";
        for (final String cls : classes) {
            TieredHook.Install r = TieredHook.install(
                null, classRegex, "reqRiskDetectV2", cls, "reqRiskDetectV2",
                HookConfig.getClassLoader(),
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                        p.setResult(null); // RiskDetectResp (Object) - type-safe
                        // 不在回调里读 r.tier，原因同 hookKickBackstop。
                        XposedEntry.log("[QQ950] blocked reqRiskDetectV2");
                    }
                });
            if (!r.ok()) {
                XposedEntry.log("[QQ950] risk detect MISS: " + r);
            }
        }
    }

    /**
     * TuringIDService.getTuringDID/getTuringDIDCached : ITuringDID (Object);
     * getTuringDIDAsync : void. The Turing device id is a fingerprint source.
     *
     * 降级：同上，宽正则覆盖三个可能的 SDK 包前缀。
     */
    private static void hookTuringDID() {
        if (!HookConfig.ENABLE_QQ950_RISK_BLOCK) return;
        String[] classes = {
            "com.tencent.tfd.sdk.wxa.TuringIDService",
            "com.tencent.turingfd.sdk.xq.TuringIDService"
        };
        final String classRegex = "com\\.tencent\\.(turingfd|turingcam|tfd)\\.sdk\\..*";
        for (final String cls : classes) {
            for (String m : new String[]{"getTuringDID", "getTuringDIDAsync", "getTuringDIDCached"}) {
                TieredHook.Install r = TieredHook.install(
                    null, classRegex, m, cls, m,
                    HookConfig.getClassLoader(),
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam p) throws Throwable {
                            p.setResult(null); // Object or void - type-safe
                        }
                    });
                if (!r.ok()) {
                    XposedEntry.log("[QQ950] turing DID MISS: " + r);
                }
            }
        }
    }
}
