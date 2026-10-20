package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;
import io.github.xalsace.qqbypass.utils.HookUtils;

/**
 * Network Report Interception Hook
 *
 * Intercepts and blocks security-related reporting to Tencent servers:
     * - trpc.o3.report.* (environment reports)
     * - trpc.o3.mobile_security.* (security checks)
 * - OidbSvcTrpcTcp.0x9c* (QSec_Channel 上报，9.3.60 新增，见 Issue #2)
 * - TuringFD risk detection
     * - Wlogin device fingerprint
     *
     * version-agnostic 改造（第 4 项）：
     *   原来 4 个 hook 点全是写死类名 + hookAllMethods，类名一改就静默失效。
     *   现在每个点都走 TieredHook 三级降级：A 档按命令字符串常量反查、
     *   B 档按包名正则、C 档写死类名兜底。任一档 MISS 都会进自检报告。
     */
    public class NetworkReportHook {

    // Only pure telemetry/report commands. Login-critical commands
    // (wtlogin.*, turing, DeviceTokenV3) are intentionally NOT blocked -
    // blocking them breaks the QQ login/registration handshake and prevents
    // entry to the main UI.
    //
    // 9.3.60 新增（Issue #2 的 araea 复验）：QQ 加了 QSec_Channel 上报通道，
    // 落盘缓存 + 失败重试 3 次，命令号是 OidbSvcTrpcTcp.0x9c* 系列：
    //   0x9c00 / 0x9c01 / 0x9c02 / 0x9c0c / 0x9cdf_1
    // 这是「客户端自判异常」的主要出口，必须一并拦。
    // 注意 wtlogin.device_lock 不可拦（araea 确认是账号设备锁服务，
    // 拦了会把自己锁在登录外）—— 这里刻意不收。
    private static final String[] BLOCK_COMMANDS = {
        "trpc.o3.report",
        "trpc.o3.mobile_security",
        "trpc.ilive_cdn.report",
        "OidbSvc.0xd79",              // Device report
        "OidbSvcTrpcTcp.0x9c00",      // QSec_Channel: 环境自检上报（9.3.60+）
        "OidbSvcTrpcTcp.0x9c01",      // QSec_Channel: 风控事件上报
        "OidbSvcTrpcTcp.0x9c02",      // QSec_Channel: 异常快照上报
        "OidbSvcTrpcTcp.0x9c0c",      // QSec_Channel: 设备一致性上报
        "OidbSvcTrpcTcp.0x9cdf"       // QSec_Channel: 批量埋点 flush（0x9cdf_1）
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_NETWORK_INTERCEPT) return;

        XposedEntry.log("Initializing Network Report Hook");

        // Hook 1: ChannelProxyExt.sendMessage (primary intercept point)
        hookChannelProxyExt(lpparam);

        // Hook 2: MsfCore.sendSsoMsg (secondary intercept point)
        hookMsfCore(lpparam);

        // Hook 3: TuringFD risk detection
        hookTuringFD(lpparam);

        // Hook 4: Wlogin device report
        hookWlogin(lpparam);
    }

    /**
     * Hook 1: ChannelProxyExt.sendMessage (primary intercept point)
     *
     * 降级链：
     *   A  "trpc.o3.report" / "trpc.o3.mobile_security" 字符串反查引用它的发包方法
     *      —— 命令名是服务端协议，混淆器不会改。
     *   B  包名正则 com\.tencent\.mobileqq\.channel\..* + 方法名 sendMessage.*
     *   C  写死 ChannelProxyExt（9.3.50 实测）
     *
     * 方法名给三个候选（sendMessage / sendMessageInner / send）是因为
     * 9.3.60 起这条链改过一次名；三个都试，命中哪个算哪个。
     */
    private static void hookChannelProxyExt(final XC_LoadPackage.LoadPackageParam lpparam) {
        final String cls = "com.tencent.mobileqq.channel.ChannelProxyExt";
        final String classRegex = "com\\.tencent\\.mobileqq\\.channel\\..*";
        final String[] reportStrings = {
            "trpc.o3.report", "trpc.o3.mobile_security", "OidbSvcTrpcTcp.0x9c"
        };
        final String[] methodNames = {"sendMessage", "sendMessageInner", "send"};

        for (final String methodName : methodNames) {
            TieredHook.Install r = TieredHook.install(
                reportStrings,
                classRegex, methodName,
                cls, methodName,
                lpparam.classLoader,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args.length < 1 || !(param.args[0] instanceof String)) return;

                        String command = (String) param.args[0];
                        if (shouldBlock(command)) {
                            // Only override the return value if type-safe. setResult(null)
                            // crashes (uncatchable ClassCastException in proceed()) when the
                            // method returns a primitive.
                            Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                            if (returnType.isPrimitive() && returnType != void.class) {
                                // Primitive return - blocking is unsafe, observe only.
                                XposedEntry.log("ChannelProxyExt (not blocked, primitive return "
                                    + returnType.getName() + "): " + command);
                                return;
                            }

                            XposedEntry.log("Blocked ChannelProxyExt: " + command);

                            // Inject fake response
                            try {
                                Object channelManager = XposedHelpers.callStaticMethod(
                                    XposedHelpers.findClass("com.tencent.mobileqq.channel.ChannelManager",
                                    lpparam.classLoader), "getInstance");

                                XposedHelpers.callMethod(channelManager, "onNativeReceive",
                                    command, new byte[0], 0L);
                            } catch (Throwable t) {
                                // Ignore if injection fails
                            }

                            param.setResult(null);
                        }
                    }
                });

            if (!r.ok()) {
                XposedEntry.log("[network] ChannelProxyExt#" + methodName + " MISS: " + r);
            } else {
                XposedEntry.log("[network] ChannelProxyExt installed: " + r);
            }
        }
    }

    /**
     * Hook 2: MsfCore.sendSsoMsg (secondary intercept point)
     *
     * 降级链：
     *   A  按 "OidbSvcTrpcTcp.0x9c" 反查（9.3.60 新增的上报命令号）
     *   B  包名正则 com\.tencent\.mobileqq\.msf\.core\..*
     *   C  写死 MsfCore（9.3.50 实测）
     */
    private static void hookMsfCore(final XC_LoadPackage.LoadPackageParam lpparam) {
        // Real path (QQ 9.3.50): com.tencent.mobileqq.msf.core.MsfCore
        final String cls = "com.tencent.mobileqq.msf.core.MsfCore";
        final String classRegex = "com\\.tencent\\.mobileqq\\.msf\\.core\\..*";
        final String[] reportStrings = {
            "OidbSvcTrpcTcp.0x9c", "trpc.o3.report", "OidbSvc.0xd79"
        };

        TieredHook.Install r = TieredHook.install(
            reportStrings,
            classRegex, "sendSsoMsg",
            cls, "sendSsoMsg",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length < 1) return;

                    Object toServiceMsg = param.args[0];
                    Object cmdObj = XposedHelpers.callMethod(toServiceMsg, "getServiceCmd");
                    String command = cmdObj == null ? null : cmdObj.toString();

                    if (shouldBlock(command)) {
                        // Type-safe block: only override the return value if the hooked
                        // method actually returns int/long/void. Setting a wrong-typed
                        // result triggers an uncatchable ClassCastException in Xposed's
                        // proceed() and crashes the process.
                        Class<?> returnType = ((java.lang.reflect.Method) param.method).getReturnType();
                        if (returnType == int.class) {
                            int seq = 0;
                            try {
                                seq = (int) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq");
                            } catch (Throwable ignored) { }
                            param.setResult(seq);
                            XposedEntry.log("Blocked MsfCore: " + command);
                        } else if (returnType == long.class) {
                            long seq = 0L;
                            try {
                                seq = ((Number) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq")).longValue();
                            } catch (Throwable ignored) { }
                            param.setResult(seq);
                            XposedEntry.log("Blocked MsfCore: " + command);
                        } else if (returnType == void.class) {
                            param.setResult(null);
                            XposedEntry.log("Blocked MsfCore: " + command);
                        } else {
                            // Unknown return type - observe only, do not risk a crash.
                            XposedEntry.log("MsfCore (not blocked, return type "
                                + returnType.getName() + "): " + command);
                        }
                    }
                }
            });

        if (!r.ok()) {
            XposedEntry.log("[network] MsfCore MISS: " + r);
        } else {
            XposedEntry.log("[network] MsfCore installed: " + r);
        }
    }

    /**
     * Hook 3: TuringFD risk detection
     *
     * 降级链：B 档宽正则 com\.tencent\.(turingfd|turingcam|tfd)\..*
     * 覆盖三个可能的 SDK 包前缀，C 档逐个试写死类名。
     *
     * 注意原实现对方法名 "a" 做无差别 setResult(null) —— 这是个隐患：
     * "a" 是混淆后最常见的方法名，命中范围可能远超预期。
     * 这里保留原行为（避免扩大改动面），但把类名面用正则收窄，
     * 至少保证只作用于 Turing SDK 内部类。
     */
    private static void hookTuringFD(XC_LoadPackage.LoadPackageParam lpparam) {
        // Block TuringFD risk detection initialization and reporting
        String[] turingClasses = {
            "com.tencent.turingfd.sdk.xq.Pomegranate",
            "com.tencent.turingfd.sdk.xq.Blueberry",
            "com.tencent.turingcam.oqKCa"
        };
        final String classRegex = "com\\.tencent\\.(turingfd|turingcam|tfd)\\..*";

        for (final String className : turingClasses) {
            TieredHook.Install r = TieredHook.install(
                null,
                classRegex, "a",
                className, "a",
                lpparam.classLoader,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // Block all TuringFD operations
                        param.setResult(null);
                    }
                });
            if (!r.ok()) {
                XposedEntry.log("[network] TuringFD " + className + " MISS: " + r);
            }
        }
    }

    /**
     * Hook 4: Wlogin device fingerprint collection
     *
     * 降级链：B 档正则 oicq\.wlogin_sdk\..* 覆盖整个 wlogin SDK 包，
     * C 档写死 oicq.wlogin_sdk.request.w#h。
     * 只观察不改写（原行为）—— 这里改返回值有断登录风险。
     */
    private static void hookWlogin(XC_LoadPackage.LoadPackageParam lpparam) {
        final String cls = "oicq.wlogin_sdk.request.w";
        final String classRegex = "oicq\\.wlogin_sdk\\..*";

        TieredHook.Install r = TieredHook.install(
            null,
            classRegex, "h",
            cls, "h",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // Modify device fingerprint before sending
                    XposedEntry.log("Intercepted Wlogin device fingerprint");
                }
            });

        if (!r.ok()) {
            XposedEntry.log("[network] wlogin MISS: " + r);
        }
    }

    private static boolean shouldBlock(String command) {
        if (command == null) return false;

        for (String blockCmd : BLOCK_COMMANDS) {
            if (command.contains(blockCmd)) {
                return true;
            }
        }
        return false;
    }
}
