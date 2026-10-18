package io.github.xalsace.qqbypass;

import android.util.Log;

import de.robv.android.xposed.XposedHelpers;

import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * QQ 版本适配检测（路线图第 6 项）。
 *
 * 存在的理由：本模块的 7 个 hook 类里写满了硬编码的 QQ 类名/方法名
 * （RootDetectionHook 有 25 条 su 路径、QQ950PatchHook 锁死 NTKickProcessor 等）。
 * QQ 一改版，这些符号就会消失 —— 表现是「模块还是显示已激活，但保护悄悄掉了」，
 * 没有任何东西告诉你哪里失效了。
 *
 * 本工具在每次注入后做一次批量探针，把失效的 hook 目标列出来，
 * 让「该适配了」变成一个可以从日志里读出来的结论，而不是靠猜。
 */
public final class VersionCompat {

    private static final String TAG = "QQEnhancedBypass";

    /** 探针项：一个 hook 目标 + 它属于哪个模块。 */
    public static final class Probe {
        public final String moduleId;
        public final String target;
        /** 类缺失 = 符号不存在；方法缺失 = 类在但方法改名了。 */
        public final String kind;

        private Probe(String moduleId, String target, String kind) {
            this.moduleId = moduleId;
            this.target = target;
            this.kind = kind;
        }

        static Probe clazz(String moduleId, String className) {
            return new Probe(moduleId, className, "class");
        }

        static Probe method(String moduleId, String className, String methodName) {
            return new Probe(moduleId, className + "#" + methodName, "method");
        }
    }

    /**
     * 各 hook 类的关键目标清单。
     *
     * 刻意只列**最关键**的那些，而不是把 7 个类里的全部 hook 点抄一遍：
     * 探针会逐个 findClass，是真实的类加载开销，在 handleLoadPackage 里
     * 做上百次会明显拖慢 QQ 启动。挑每个模块最具代表性的 2-3 个即可 ——
     * 它们一旦消失，说明该模块的覆盖面已经出问题了。
     */
    private static final Probe[] PROBES = {
        // Root 检测：QQ 判断 root 的核心入口
        Probe.clazz("root_detection", "java.io.File"),
        Probe.clazz("root_detection", "android.app.ApplicationPackageManager"),

        // Xposed 检测：StackTrace 遍历 + 类加载器枚举
        Probe.clazz("xposed_detection", "java.lang.StackTraceElement"),
        Probe.clazz("xposed_detection", "dalvik.system.PathClassLoader"),

        // 设备信息：Pandora 监控是 QQ 的设备指纹采集入口
        Probe.clazz("device_info", "com.tencent.qmethod.pandoraex.monitor.DeviceInfoMonitor"),
        Probe.clazz("device_info", "android.telephony.TelephonyManager"),

        // 网络上报：QQ 的风控上报通道
        Probe.clazz("network_report", "com.tencent.mobileqq.msf.core.MsfCore"),

        // QQ 9.3.50 专项：图灵风控 SDK 的三个入口
        Probe.clazz("qq950_patch", "com.tencent.mobileqq.ntkick.NTKickProcessor"),
        Probe.clazz("qq950_patch", "com.tencent.turingcam.TuringRiskService"),

        // Runtime 监控：进程/包信息枚举
        Probe.clazz("runtime_monitor", "android.app.ActivityManager"),
    };

    private VersionCompat() {
    }

    /** 对全部探针执行一次检测，返回缺失项列表（空 = 全部适配良好）。 */
    public static List<String> scan() {
        List<String> missing = new ArrayList<String>();
        for (Probe p : PROBES) {
            if (!exists(p)) {
                missing.add(p.moduleId + ":" + p.target + "(" + p.kind + ")");
            }
        }
        return missing;
    }

    /** 生成一行人读的自检结论。 */
    public static String report() {
        List<String> missing = scan();
        if (missing.isEmpty()) {
            return "compat=OK (" + PROBES.length + "/" + PROBES.length + " probes present)";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("compat=STALE missing=").append(missing.size())
          .append('/').append(PROBES.length).append(" [");
        for (int i = 0; i < missing.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(missing.get(i));
        }
        sb.append(']');
        return sb.toString();
    }

    private static boolean exists(Probe p) {
        try {
            if ("class".equals(p.kind)) {
                return HookUtils.classExists(p.target);
            }
            // method 形态：target 是 "类名#方法名"
            int hash = p.target.indexOf('#');
            if (hash <= 0) return false;
            String cn = p.target.substring(0, hash);
            String mn = p.target.substring(hash + 1);
            Class<?> c = XposedHelpers.findClass(cn, HookConfig.getClassLoader());
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                if (m.getName().equals(mn)) {
                    return true;
                }
            }
            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 在注入末尾调用，把结论写进日志。
     *
     * 只在有缺失时才打完整清单：QQ 每次冷启动都会走这里，
     * 正常情况下不该刷屏。
     */
    public static void logReport() {
        List<String> missing = scan();
        if (missing.isEmpty()) {
            Log.i(TAG, "[compat] OK - all " + PROBES.length + " probe targets present");
            return;
        }
        Log.w(TAG, "[compat] STALE - " + missing.size() + "/" + PROBES.length
            + " probe targets missing, QQ may have changed:");
        for (String m : missing) {
            Log.w(TAG, "[compat]   missing " + m);
        }
    }
}