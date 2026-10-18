package io.github.xalsace.qqbypass.hooks;

import android.util.Log;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.config.ModuleConfig;
import io.github.xalsace.qqbypass.utils.HookCounters;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * hook 模块注册表（路线图第 1 项：Java 层多模块 hook 框架）。
 *
 * 改造前 XposedEntry.handleLoadPackage 长这样：
 *
 *   try {
 *       NetworkReportHook.hook(lpparam);
 *       RootDetectionHook.hook(lpparam);
 *       ... 共 8 次硬编码静态调用
 *   } catch (Throwable t) { log(...); }
 *
 * 三个真实问题：
 *  1. 一个 try 包全部 —— 第 3 个 hook 抛异常，后面 5 个全部静默跳过，
 *     日志只有一行，表现为「模块装了但保护等级莫名其妙只有 30%」。
 *  2. 无法单独关闭某个模块 —— HookConfig 里那批 ENABLE_* 是编译期常量，
 *     要关一个必须改代码重新编译装 APK。
 *  3. 完全没有执行结果 —— 谁成功、谁跳过、跳过了几个，只能人肉翻 logcat。
 *
 * 本类逐模块隔离执行 + 逐个记录结果，任一模块炸掉不影响其余。
 *
 * 注意：本类刻意不引用 HookUtils。HookUtils 依赖 Xposed/android 类型，
 * 而 Xposed 是 compileOnly，纯 JVM 单测里触碰会 NoClassDefFoundError。
 * 计数只走 {@link HookCounters}（无任何外部依赖）。
 */
public final class HookRegistry {

    private static final String TAG = "QQEnhancedBypass";

    private final Map<String, HookModule> modules = new LinkedHashMap<String, HookModule>();

    public HookRegistry() {
    }

    /**
     * 注册一个模块。重复 id 覆盖旧的（后注册者优先），便于测试替换。
     * 返回 this 以支持链式注册。
     */
    public HookRegistry register(HookModule m) {
        if (m != null && m.id() != null) {
            modules.put(m.id(), m);
        }
        return this;
    }

    /** 已注册的模块数。 */
    public int size() {
        return modules.size();
    }

    /** 按 id 取模块，没有则返回 null。 */
    public HookModule get(String id) {
        return id == null ? null : modules.get(id);
    }

    /**
     * 按注册顺序执行所有模块，返回逐模块结果。
     *
     * 契约：本方法自身不抛异常。任何模块的任何 Throwable 都被捕获成
     * {@link HookResult.Status#FAILED}，其余模块照常执行。
     */
    public List<HookResult> runAll(XC_LoadPackage.LoadPackageParam lpparam) {
        ModuleConfig cfg;
        try {
            cfg = ModuleConfig.get();
        } catch (Throwable t) {
            // 配置读取本身绝不允许拖垮注入：读不到就用默认值继续跑。
            cfg = ModuleConfig.defaults();
        }

        List<HookResult> results = new ArrayList<HookResult>(modules.size());
        for (HookModule m : modules.values()) {
            results.add(runOne(m, lpparam, cfg));
        }
        return results;
    }

    private HookResult runOne(HookModule m, XC_LoadPackage.LoadPackageParam lpparam, ModuleConfig cfg) {
        String id = m.id();

        boolean enabled;
        try {
            enabled = m.isEnabled(cfg);
        } catch (Throwable t) {
            // 开关判断出错按「启用」处理：宁可多 hook，不可静默失保护。
            enabled = true;
        }
        if (!enabled) {
            Log.i(TAG, "[registry] " + id + " disabled by config");
            return HookResult.disabled(id);
        }

        long h0 = HookCounters.snapshotHooked();
        long s0 = HookCounters.snapshotSkipped();
        long t0 = System.currentTimeMillis();

        try {
            m.hook(lpparam);
            long ms = System.currentTimeMillis() - t0;
            HookResult r = HookResult.ok(id,
                HookCounters.deltaHooked(h0),
                HookCounters.deltaSkipped(s0),
                ms);
            Log.i(TAG, "[registry] " + r.describe() + " in " + ms + "ms");
            return r;
        } catch (Throwable t) {
            long ms = System.currentTimeMillis() - t0;
            Log.e(TAG, "[registry] " + id + " FAILED after " + ms + "ms", t);
            return HookResult.failed(id, t, ms);
        }
    }

    /** 汇总：总成功数 / 总跳过数 / 失败模块名列表。供自检报告使用。 */
    public static String summarize(List<HookResult> results) {
        if (results == null || results.isEmpty()) return "no-modules";
        int hooked = 0, skipped = 0, failed = 0, disabled = 0;
        StringBuilder bad = new StringBuilder();
        for (HookResult r : results) {
            hooked += r.hooked();
            skipped += r.skipped();
            if (r.status() == HookResult.Status.FAILED) {
                failed++;
                if (bad.length() > 0) bad.append(',');
                bad.append(r.moduleId());
            } else if (r.status() == HookResult.Status.DISABLED) {
                disabled++;
            }
        }
        StringBuilder sb = new StringBuilder();
        sb.append("modules=").append(results.size())
          .append(" hooked=").append(hooked)
          .append(" skipped=").append(skipped)
          .append(" failed=").append(failed)
          .append(" disabled=").append(disabled);
        if (bad.length() > 0) sb.append(" failedIds=[").append(bad).append(']');
        return sb.toString();
    }

    /**
     * 构造默认注册表：把改造前的 8 次硬编码调用逐条包成 {@link HookModule}。
     *
     * 每个适配器都把「开关」接到 {@link ModuleConfig} 的对应 id 上，
     * 从而取代 HookConfig 里那批编译期常量（路线图第 6 项）。
     * 原有 hook 类本身零改动 —— 它们仍然是 `public static void hook(lpparam)`。
     */
    public static HookRegistry createDefault() {
        HookRegistry r = new HookRegistry();
        r.register(adapter("network_report", "Network Report Intercept", NetworkReportHook.class));
        r.register(adapter("root_detection", "Root Detection Bypass", RootDetectionHook.class));
        r.register(adapter("xposed_detection", "Xposed Detection Bypass", XposedDetectionHook.class));
        r.register(adapter("device_info", "Device Info Consistency", DeviceInfoHook.class));
        r.register(adapter("debug_detection", "Debug/Emulator Bypass", DebugDetectionHook.class));
        r.register(adapter("runtime_monitor", "Runtime Monitor Bypass", RuntimeMonitorHook.class));
        r.register(adapter("qq950_patch", "QQ 9.3.50 Detection Patch", QQ950PatchHook.class));
        return r;
    }

    /**
     * 把一个形如 `public static void hook(LoadPackageParam)` 的既有 hook 类
     * 反射包装成 HookModule。
     *
     * 用反射而不是为每个类手写适配器，是为了让「以后新增 hook 类」只需在
     * createDefault 里加一行；代价是编译期检查不到方法签名，所以下面做一次
     * 启动期自检，签名不对就记日志而不是等到运行时才崩。
     */
    private static HookModule adapter(final String id, final String name, final Class<?> clazz) {
        // 启动期自检：确认 hook(LoadPackageParam) 存在，避免运行时才炸。
        boolean sane = false;
        try {
            clazz.getDeclaredMethod("hook", XC_LoadPackage.LoadPackageParam.class);
            sane = true;
        } catch (Throwable ignored) {
        }
        if (!sane) {
            Log.e(TAG, "[registry] adapter sanity check failed for " + id
                + " -> " + clazz.getName());
        }

        return new HookModule() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public String displayName() {
                return name;
            }

            @Override
            public boolean isEnabled(ModuleConfig cfg) {
                return cfg == null || cfg.isModuleEnabled(id);
            }

            @Override
            public void hook(XC_LoadPackage.LoadPackageParam lpparam) {
                // 原 hook 类内部会自己读 HookConfig 的 classLoader 等状态，
                // 这里只负责把 lpparam 透传过去。
                invokeStatic(clazz, lpparam);
            }
        };
    }

    private static void invokeStatic(Class<?> clazz, XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            java.lang.reflect.Method m =
                clazz.getDeclaredMethod("hook", XC_LoadPackage.LoadPackageParam.class);
            m.setAccessible(true);
            m.invoke(null, lpparam);
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            throw new RuntimeException(cause == null ? e : cause);
        } catch (Throwable t) {
            if (t instanceof RuntimeException) throw (RuntimeException) t;
            throw new RuntimeException(t);
        }
    }

    /** 已注册模块的 id 列表（顺序即执行顺序），自检/测试用。 */
    public List<String> ids() {
        return Collections.unmodifiableList(new ArrayList<String>(modules.keySet()));
    }
}