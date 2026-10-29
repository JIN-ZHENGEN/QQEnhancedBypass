package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.ModuleConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;

/**
 * IntChkBypassHook —— 针对 QQ「intchk（内存完整性检查 + 特征码扫描）」体系的对抗模块。
 *
 * ★ 本模块每一条依据都来自对 CattaFish/qqDecoder 反编译产物（QQ v9.3.80.42670）
 *   与本地 qq9380.apk / 真机 so 的实证，逐条可查，不是推测。
 *
 * ============ 一、被对抗的真实链路（源码级实证）============
 *
 * ① 触发（服务端主动，不是客户端定时自检）
 *    com/tencent/mobileqq/app/dj.java（日志 tag = SafeCenterPushHandler）
 *      收 SSO push：msgtype0x210 / submsgtype0x4a，按 uint32_sec_cmd 分派
 *        sec_cmd = 1 → com.tencent.ctsz.m  （重打包/签名，见 RepackCheckBypassHook）
 *        sec_cmd = 2 → intchk              （本模块主目标）
 *
 * ② 执行引擎（源码全文已读，422 行）
 *    com/tencent/mqpsdk/secsrv/b.java，intchk$ReqBody.uint32_subcmd 单一通道：
 *        subcmd=1 FetchCheckConfigReq  → g(String) 发起拉配置
 *        subcmd=2 ReportCheckResultReq → d(RspBody) 执行检查并上报
 *        subcmd=3 ReportStrikeResultReq→ f(String) 报打击结果
 *    回包 rpt_msg_check_item[] 由【服务端下发】，每项 intchk$CheckItem：
 *        uint32_check_type   1=memchk（比对特征码）/ 2=memreport（dump 原始字节）
 *        bytes_module_name / uint32_start_offset / uint32_end_offset
 *        bytes_match_pattern 期望字节 hex，经 HexUtil.hexStr2Bytes 转 byte[]
 *    执行（b.java:175 / :194 实证）：
 *        type=1 → MQPSecUtil.memchk(module,start,end,pattern) → 命中1 未命中2
 *        type=2 → MQPSecUtil.memreport(module,start,end) → hex 回传服务端
 *
 * ③ native 门面（源码全文已读）
 *    com/tencent/mqp/app/sec/MQPSecUtil.java：
 *        static native boolean memchk(String, int, int, byte[])
 *        static native byte[]  memreport(String, int, int)
 *        native void antitrace(String)
 *        static void do_report(String) → ReportController, tag "Safe_MQPSecUtil"
 *
 * ④ 打击（b.java e() 实证，XML 由服务端下发）
 *    type=1 不可取消窗 / type=2 exec(null) 退出 / type=3 拉起指定 package
 *
 * ============ 二、★ 关键实证：arm64 上该检测器当前加载失败 ============
 *
 * MQPSecUtil 静态块加载链（源码 32-72 行）：
 *     1. 查 filesDir.getParent()/txlib/libmqpintchk.so，不存在 → a(context,str)
 *     2. a() 里 open("lib/" + str + "/libmqpintchk.so")
 *        str 推导：CPU_ABI="arm64-v8a" 不含 x86/mip → str="armeabi"
 *        → 实际去开 assets/lib/armeabi/libmqpintchk.so
 *     3. 仍不存在 → 试 filesDir.getParent()/lib/libmqpintchk.so
 *     4. 都不存在 → System.loadLibrary("mqpintchk") → UnsatisfiedLinkError 被吞
 *
 * APK 实证：assets/lib/ 下【只有 x86_64 三个 so】
 *     （libqq_patch.so / libmsfbootV2.so / libcodecwrapperV2.so），无 armeabi。
 * 真机实证：find /data -name '*mqpintchk*'、-type d -name txlib 均零命中。
 *
 * → intchk 在当前 arm64 设备上处于【系统性空转】。
 * → 但 MQPSecUtil / b 均接了 QQ 的 qfix 热补丁（PatchRedirectCenter.getRedirector），
 *   腾讯随时可远程补上 arm64 so 或改加载逻辑。本模块属【预防性】部署。
 *
 * ============ 三、策略：为什么「修改」优于「拦截」============
 *
 * 拦截 = 沉默。正常 QQ 必定响应 intchk 并上报结果；
 *   不上报等于向服务端宣告「该客户端被做了手脚」——沉默是最强的异常信号。
 * 修改 = 伪装成正常。服务端看到「客户端正常响应了检查，结果正常」。
 *
 * 且更优的是【在源头改】而非在出口改 pb：
 *   - memchk/memreport 是 Java 层可 hook 的 native 方法，ART 里有 ArtMethod
 *   - setResult 后原生实现根本不执行，QQ 走自己的正常调用链，内部状态自洽
 *   - 对所有上报通道统一生效（无需针对 MsfCore / ChannelProxyExt 各做一遍）
 *
 * memreport 必须返回 null，绝不能伪造字节：
 *   服务端掌握官方 so 原文，假字节一比对即自证。
 *   返回 null 时 QQ 走 HexUtil.bytes2HexStr(null) → set("")，
 *   这正是【native 库缺失时真实会发生的路径】，属于完美伪装。
 *
 * ============ 四、层级（A 最干净 → E 兜底）============
 *   A. 拦触发：SafeCenterPushHandler 收不到 sec_cmd=2
 *   B. 拦引擎：b.g() 不发起拉配置（等价于本次未触发）
 *   C. ★主策略★：memchk → true，memreport → null，antitrace 吞掉
 *   D. 拦落地：System.load 含 mqpintchk 抛 UnsatisfiedLinkError（默认关）
 *   E. 保登录：拦打击执行，避免 logout + 关自动登录
 *
 * ★ D 默认关闭的理由（本轮更正）：
 *   arm64 上 so 本来就加载失败，再拦 System.load 属重复且无收益。
 *   更关键：MQPSecUtil 加载失败是【常态】，强行阻止反而会改变
 *   "library not found" 这一自然状态。待腾讯补上 arm64 so 后再开。
 */
public class IntChkBypassHook {

    private static final String TAG = "QQBypass.IntChk";

    /** 模块 id，用于 qqbypass.json 的 modules 段开关。 */
    private static final String MODULE_ID = "intchk";

    private static final String PUSH_HANDLER = "com.tencent.mobileqq.app.dj";
    private static final String ENGINE_REAL  = "com.tencent.mqpsdk.secsrv.b";
    private static final String SEC_UTIL     = "com.tencent.mqp.app.sec.MQPSecUtil";
    private static final String STRIKE       = "com.tencent.mobileqq.app.MSFIntChkStrike";

    /** A 档依据：SafeCenterPushHandler 是类内硬编码日志 tag，不参与混淆。 */
    private static final String[] STR_PUSH = {"SafeCenterPushHandler"};

    /** C 档依据：MQPSecUtil 的日志 tag（源码 56/70 行实证）。 */
    private static final String[] STR_SECUTIL = {"cannot load library"};

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            if (!ModuleConfig.get().isModuleEnabled(MODULE_ID)) {
                XposedEntry.log("[intchk] disabled by config, skip");
                return;
            }
        } catch (Throwable t) {
            // 配置读取失败按启用处理：宁可多保护，不可静默掉一层
        }

        final ClassLoader cl = lpparam.classLoader;
        tryC(cl);   // ★ 主策略，最先装
        tryB(cl);
        tryA(cl);
        tryD(cl);
        tryE(cl);
    }

    /**
     * ★ C（主策略）：成对处理 memchk / memreport / antitrace。
     *
     * 这是本模块核心，最先安装 —— 它是唯一能对所有上报通道统一生效、
     * 且不依赖触发点是否被旁路的一层。
     *
     * 关于 memchk 返回 true 的安全性：
     *   返回类型是 primitive boolean，param.setResult(Boolean.TRUE) 由 Xposed
     *   自动 unbox，不存在 NetworkReportHook 里担心的 ClassCastException
     *   （那种风险出现在返回类型是 primitive 却塞了错误包装类型时，
     *   而 boolean↔Boolean 是唯一确定的映射）。
     */
    private static void tryC(final ClassLoader cl) {
        try {
            final Class<?> c = XposedHelpers.findClass(SEC_UTIL, cl);

            // memchk → true：「在本区间匹配到了期望字节」= 未被改写。
            TieredHook.Install r1 = TieredHook.installAC(
                STR_SECUTIL, SEC_UTIL, "memchk", cl,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        logOnce("memchk -> true (module=" + safeArg(param.args, 0) + ")");
                        param.setResult(Boolean.TRUE);
                    }
                });

            // memreport → null：不返回真实字节，也不伪造字节。
            // 返回类型 byte[] 是引用类型，setResult(null) 安全。
            TieredHook.Install r2 = TieredHook.installAC(
                STR_SECUTIL, SEC_UTIL, "memreport", cl,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        logOnce("memreport -> null (refuse dump)");
                        param.setResult(null);
                    }
                });

            // antitrace：反调试追踪通道。返回 void，setResult(null) 安全。
            TieredHook.Install r3 = TieredHook.installAC(
                STR_SECUTIL, SEC_UTIL, "antitrace", cl,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        logOnce("antitrace swallowed");
                        param.setResult(null);
                    }
                });

            report("C.memchk", r1);
            report("C.memreport", r2);
            report("C.antitrace", r3);
        } catch (Throwable t) {
            XposedEntry.logError("[intchk] C failed (non-fatal)", t);
        }
    }

    /**
     * B：拦执行引擎的发起入口 g(String)。
     * 不拉配置 → 无 check item → 无 memchk/memreport → 无结果上报。
     * 与「服务端本次未要求检查」完全等价。
     */
    private static void tryB(final ClassLoader cl) {
        try {
            TieredHook.Install r = TieredHook.installAC(
                null, ENGINE_REAL, "g", cl,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        logOnce("B: block check start (b.g)");
                        param.setResult(null);
                    }
                });
            report("B.g", r);
        } catch (Throwable t) {
            XposedEntry.logError("[intchk] B failed (non-fatal)", t);
        }
    }

    /**
     * A：拦触发点。
     * ★ 这里【不做无差别 setResult(null)】—— dj 是 push 处理器，
     *   "a" 是混淆后最常见的方法名，无差别拦截会误伤同一方法处理的
     *   sec_cmd=1（重打包）与 sec_cmd=4（安全横幅）分支，
     *   甚至吞掉无关 push。只在能确认是 sec_cmd=2 时才拦。
     */
    private static void tryA(final ClassLoader cl) {
        try {
            TieredHook.Install r = TieredHook.installAC(
                STR_PUSH, PUSH_HANDLER, "a", cl,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Integer cmd = findIntArg(param.args, 2);
                        if (cmd != null && cmd.intValue() == 2) {
                            logOnce("A: block sec_cmd=2 (intchk) at push handler");
                            param.setResult(null);
                        }
                    }
                });
            report("A.push", r);
        } catch (Throwable t) {
            XposedEntry.logError("[intchk] A failed (non-fatal)", t);
        }
    }

    /**
     * D：阻止 libmqpintchk.so 落地。默认关闭 —— 见类注释第四节。
     */
    private static void tryD(final ClassLoader cl) {
        boolean enabled;
        try {
            enabled = ModuleConfig.get().isModuleEnabled("intchk.blockSo");
        } catch (Throwable t) {
            return; // 读不到配置 = 不启用
        }
        if (!enabled) return;

        try {
            XposedBridge.hookAllMethods(Runtime.class, "load", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String p = findStringArg(param.args, "mqpintchk");
                    if (p != null) {
                        logOnce("D: block System.load " + p);
                        param.setThrowable(new UnsatisfiedLinkError("blocked"));
                    }
                }
            });
            XposedEntry.log("[intchk] D: System.load guard installed");
        } catch (Throwable t) {
            XposedEntry.logError("[intchk] D failed (non-fatal)", t);
        }
    }

    /**
     * E：保住登录态。只在能确认是关闭自动登录时才拦。
     */
    private static void tryE(final ClassLoader cl) {
        try {
            Class<?> strike = null;
            try {
                strike = XposedHelpers.findClass(STRIKE, cl);
            } catch (Throwable ignored) {
                // 类名可能随版本变化，找不到就跳过
            }
            if (strike != null) {
                XposedBridge.hookAllMethods(strike, "a", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        logOnce("E: strike suppressed");
                        param.setResult(null);
                    }
                });
                XposedEntry.log("[intchk] E: strike hooked");
            }
        } catch (Throwable t) {
            XposedEntry.logError("[intchk] E failed (non-fatal)", t);
        }
    }

    // ------------------------------------------------------------------ util

    /** 按“值相等”找 Integer 参数。不假设参数位置（混淆后签名可能变）。 */
    private static Integer findIntArg(Object[] args, int value) {
        if (args == null) return null;
        for (Object a : args) {
            if (a instanceof Integer && ((Integer) a).intValue() == value) {
                return (Integer) a;
            }
        }
        return null;
    }

    private static String findStringArg(Object[] args, String needle) {
        if (args == null) return null;
        for (Object a : args) {
            if (a instanceof String && ((String) a).contains(needle)) {
                return (String) a;
            }
        }
        return null;
    }

    private static String safeArg(Object[] args, int idx) {
        if (args == null || idx >= args.length || args[idx] == null) return "?";
        return String.valueOf(args[idx]);
    }

    private static void report(String tier, TieredHook.Install r) {
        if (r == null) return;
        if (r.ok()) {
            XposedEntry.log("[intchk] " + tier + " installed: " + r);
        } else {
            XposedEntry.log("[intchk] " + tier + " MISS: " + r);
        }
    }

    /**
     * 按需日志：与项目 VERBOSE_LOGGING=false 的默认一致，
     * 需要排查时在 qqbypass.json 里打开 verbose 即可，无需重编译。
     */
    private static void logOnce(String msg) {
        try {
            if (ModuleConfig.get().isVerbose()) {
                XposedEntry.log("[intchk] " + msg);
            }
        } catch (Throwable ignored) {
        }
    }
}