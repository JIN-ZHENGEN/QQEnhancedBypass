package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.ModuleConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;

/**
 * RepackCheckBypassHook —— 针对 sec_cmd=1 分支（重打包 / 签名检测）的对抗模块。
 *
 * 逆向出处：com/tencent/ctsz/m.java
 *   - com/tencent/ctsz/ 全包仅此 1 个文件，DEX 中仅 2 处字符串引用
 *     （Lcom/tencent/ctsz/m; 与 m$1），高度可疑的安全组件，已确认。
 *   - 整个类的常量用 c(byte[]) 逐字节 XOR 51 (0x33) 混淆。
 *     key=51 的坐实方式：混淆串 f102722g 解出 "sig_check"，
 *     与同文件第 281 行明文 getCodec("sig_check") 完全吻合（交叉验证）。
 *
 * 它采集什么：
 *   1. APK 整体 MD5
 *   2. 是否重打包（遍历 JarFile entry 查重名 → u32_is_repack）
 *   3. 签名 MD5（getPackageInfo(pkg,64).signatures[0] + MessageDigest("MD5")）
 *   4. versionName —— ★关键点：不是问 PackageManager，而是
 *      getPackageArchiveInfo(sourceDir, 1).versionName
 *      【直接从 APK 文件读】，专门防 hook PackageManager 返回假版本号。
 *
 * 上报：signature$SignatureReport（含 u32_is_repack / str_md5 / str_signature），
 *       出网前 codec.encode。
 *
 * ============ 对抗要点 ============
 * 这条分支【不检测 hook】，它检测的是「APK 文件本身是不是官方的」。
 * 因此对 LSPosed 注入型模块而言，本分支天然不会命中 ——
 * LSPosed 不改 APK、不重签名、不重打包。
 *
 * 但它仍值得拦：
 *   1. 若用户装的是改包/去广告版 QQ，或用了会改 APK 的模块，会被这里抓到。
 *   2. u32_is_repack 一旦为真，是【服务端可长期留存】的黑记录。
 *   3. versionName 从 APK 文件读是强反 hook 设计，
 *      只 hook PackageManager 无效，必须拦在上报出口。
 *
 * ★ 与旧版一致但需强调：不伪造 str_md5。
 *   伪造 MD5 与服务端持有的官方 APK 摘要不符，等于自证改包。
 *   正确做法是【不让它上报这条】，而不是【上报假的】。
 */
public class RepackCheckBypassHook {

    private static final String TAG = "QQBypass.Repack";

    /** 模块 id，用于 qqbypass.json 的 modules 段开关。 */
    private static final String MODULE_ID = "repack";

    /** com.tencent.ctsz 包下唯一的类。 */
    private static final String CTSZ_M = "com.tencent.ctsz.m";

    /** A 档依据：SignatureReport / sig_check 是该分支的协议名与 codec 名，混淆器不改。 */
    private static final String[] STR_REPACK = {"sig_check", "UI_ROUTER_NOTIFICATION"};

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            if (!ModuleConfig.get().isModuleEnabled(MODULE_ID)) {
                XposedEntry.log("[repack] disabled by config, skip");
                return;
            }
        } catch (Throwable t) {
            // 配置读取失败按启用处理
        }

        final ClassLoader cl = lpparam.classLoader;
        tryCollect(cl);
        tryDialog(cl);
    }

    /**
     * 拦采集/上报出口。
     *
     * 方法名被混淆，不写死。走 TieredHook：
     *   A  按 "sig_check" / "UI_ROUTER_NOTIFICATION" 字符串常量反查引用它的方法
     *   C  写死类名 com.tencent.ctsz.m 兜底
     */
    private static void tryCollect(final ClassLoader cl) {
        try {
            TieredHook.Install r = TieredHook.installAC(
                STR_REPACK, CTSZ_M, "a", cl,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        logOnce("collect: neutralize SignatureReport path");
                        // 不伪造 MD5/签名值，只是不让它把判定结果交出去。
                        // 返回 void 的方法 setResult(null) 是安全的。
                        if (isVoidMethod(param.method)) {
                            param.setResult(null);
                        }
                    }
                });
            report("collect", r);
        } catch (Throwable t) {
            XposedEntry.logError("[repack] collect failed (non-fatal)", t);
        }
    }

    /**
     * 拦 result=2 时构造的强制弹窗（UI_ROUTER_NOTIFICATION）。
     * 只拦弹窗，不改服务端判定 —— 判定改不了，但至少不被本机弹窗骚扰。
     */
    private static void tryDialog(final ClassLoader cl) {
        try {
            Class<?> act = XposedHelpers.findClass("android.app.Activity", cl);
            XposedBridge.hookAllMethods(act, "startActivity", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String route = findStringArg(param.args, "UI_ROUTER_NOTIFICATION");
                    if (route != null) {
                        logOnce("suppress repack notification dialog");
                        param.setResult(null);
                    }
                }
            });
            XposedEntry.log("[repack] dialog guard installed");
        } catch (Throwable t) {
            XposedEntry.logError("[repack] dialog failed (non-fatal)", t);
        }
    }

    // ------------------------------------------------------------------ util

    /**
     * 只放行 void 返回。
     *
     * 这是从 NetworkReportHook 学来的教训：对返回 primitive（int/long）的方法
     * 直接 setResult(null) 会在 Xposed 的 proceed() 里触发不可捕获的
     * ClassCastException，直接崩进程。这里保守处理 —— 只处理 void。
     */
    private static boolean isVoidMethod(Object method) {
        if (method instanceof java.lang.reflect.Method) {
            return ((java.lang.reflect.Method) method).getReturnType() == void.class;
        }
        return false;
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

    private static void report(String tier, TieredHook.Install r) {
        if (r == null) return;
        if (r.ok()) {
            XposedEntry.log("[repack] " + tier + " installed: " + r);
        } else {
            XposedEntry.log("[repack] " + tier + " MISS: " + r);
        }
    }

    private static void logOnce(String msg) {
        try {
            if (ModuleConfig.get().isVerbose()) {
                XposedEntry.log("[repack] " + msg);
            }
        } catch (Throwable ignored) {
        }
    }
}