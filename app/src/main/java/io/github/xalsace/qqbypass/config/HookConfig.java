package io.github.xalsace.qqbypass.config;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Central configuration for hook modules
 */
public class HookConfig {

    public static XC_LoadPackage.LoadPackageParam loadPackageParam;
    public static ClassLoader classLoader;

    // Feature toggles
    //
    // 【已改造】这些字段原先是唯一的开关来源，但因为它们是编译期常量，
    // 要关掉任何一个都必须改源码重新编译装 APK —— 不符合「配置文件支持」的要求。
    //
    // 现在真正的开关在 ModuleConfig（读 /sdcard/Download/qqbypass.json），
    // 由 HookRegistry 在调用每个 hook 之前判断。这里这批字段降级为「内部保险」：
    // 保持 true 不动，各 hook 类里的 `if (!ENABLE_XXX) return;` 留作最后一道闸门，
    // 用于某模块出现问题时可以在源码层面快速拉闸，而不需要改注册表逻辑。
    //
    // 注意它们**不是**运行时可写的 —— applyVerbose() 之外没有任何地方改它们。
    public static boolean ENABLE_NATIVE_HOOKS = true;        // Native layer hooks (70% coverage)
    public static boolean ENABLE_ROOT_BYPASS = true;
    public static boolean ENABLE_XPOSED_BYPASS = true;
    public static boolean ENABLE_DEBUG_BYPASS = true;
    public static boolean ENABLE_DEVICE_SPOOF = true;
    public static boolean ENABLE_NETWORK_INTERCEPT = true;
    public static boolean ENABLE_RUNTIME_BYPASS = true;
    public static boolean ENABLE_QQ950_PATCH = true;        // QQ 9.3.50 detection-point completion
    public static boolean ENABLE_QQ950_RISK_BLOCK = true;   // Tier 2: object-return risk blocks (NPE-caveat; disable if NPE appears)

    // Verbose logging
    //
    // 默认值由 true 改为 false。开启时每条 hook 都会打日志，QQ 每次冷启动
    // 会产生几十上百行 —— 既是噪音，也让模块的行为特征更明显。
    // 需要排查时通过配置文件的 verbose:true 打开即可，不必重编译。
    // 自检报告（模块汇总 + 版本适配结论）不受此开关影响，始终打印。
    public static boolean VERBOSE_LOGGING = false;

    // Fake device info (used when spoofing is enabled)
    //
    // 【已弃用】这三个字段已被 config/Fingerprint 取代。
    // 原因：它们不区分 user，XSpace 双开下 u0/u999 会拿到同一套假值，
    // 服务端据此判定「同一设备绑定两个账号」—— 与绕过检测的目标相反。
    // 新的实现按 userId 分桶且确定性派生（见 Fingerprint 类注释），
    // 由 ModuleConfig.spoofFingerprint 控制是否启用。
    //
    // 保留字段只为编译兼容，运行时不再读取。
    @Deprecated
    public static String FAKE_IMEI = null;
    @Deprecated
    public static String FAKE_ANDROID_ID = null;
    @Deprecated
    public static String FAKE_SERIAL = null;

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        loadPackageParam = lpparam;
        classLoader = lpparam.classLoader;
    }

    /**
     * 把日志开关接到运行时配置上。
     *
     * 只影响 {@code HookUtils} 里逐条打印的 "Hooked: xxx / Failed to hook: xxx"。
     * XposedEntry 的自检报告（模块汇总 + 版本适配结论）走的是 XposedEntry.log，
     * 不受这个开关影响 —— 也就是说关掉 verbose 只是不再刷屏，
     * 「到底生效了没有」的答案永远都打在日志里。
     *
     * 默认 false：QQ 每次冷启动都会重新注入，7 个模块几十条 hook 全部打印
     * 会造成明显的日志噪音，也让模块自身更容易被行为分析发现。
     */
    public static void applyVerbose(boolean verbose) {
        VERBOSE_LOGGING = verbose;
    }

    public static ClassLoader getClassLoader() {
        return classLoader;
    }
}
