package io.github.xalsace.qqbypass.utils;

import android.util.Log;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import io.github.xalsace.qqbypass.config.HookConfig;

import java.lang.reflect.Method;

/**
 * Utility class for common Xposed hook operations
 *
 * 计数说明：成功/跳过计数统一记在 {@link HookCounters} 里，本类所有 hook 入口
 * 只负责 record。之所以用全局计数 + 差值而不是让每个 hook 模块自己上报，是因为
 * 现有 7 个 hook 类全是 `void hook(lpparam)` 形态，改成返回值要动所有调用点；
 * 差值法让它们零改动接入。
 *
 * 计数器之所以不放在本类：本类 import 了 Xposed / android 类型，而 Xposed API
 * 在 Gradle 里是 compileOnly（运行时由框架提供）。一旦注册表在纯 JVM 单测里
 * 触碰到本类，就会 NoClassDefFoundError。见 HookCounters 的类注释。
 */
public class HookUtils {

    private static final String TAG = "QQEnhancedBypass";

    // 快照/差值 API 全部委托给 HookCounters，保留在此处仅为兼容既有调用点。
    /** 取当前成功计数快照（配合 {@link #deltaHooked} 做区间统计）。 */
    public static long snapshotHooked() { return HookCounters.snapshotHooked(); }

    /** 取当前跳过计数快照。 */
    public static long snapshotSkipped() { return HookCounters.snapshotSkipped(); }

    /** 与快照的差值：这段区间内成功 hook 了多少。 */
    public static int deltaHooked(long snapshot) { return HookCounters.deltaHooked(snapshot); }

    /** 与快照的差值：这段区间内跳过了多少。 */
    public static int deltaSkipped(long snapshot) { return HookCounters.deltaSkipped(snapshot); }

    /**
     * Safe hook with error handling
     */
    public static void hookMethod(String className, String methodName, Object... parameterTypesAndCallback) {
        try {
            Class<?> clazz = XposedHelpers.findClass(className, HookConfig.getClassLoader());
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
            HookCounters.recordHooked();
            log("Hooked: " + className + "." + methodName);
        } catch (Throwable t) {
            HookCounters.recordSkipped();
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook: " + className + "." + methodName + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook method with class object
     */
    public static void hookMethod(Class<?> clazz, String methodName, Object... parameterTypesAndCallback) {
        try {
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
            HookCounters.recordHooked();
            log("Hooked: " + clazz.getName() + "." + methodName);
        } catch (Throwable t) {
            HookCounters.recordSkipped();
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook: " + clazz.getName() + "." + methodName + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook all methods with specific name
     */
    public static void hookAllMethods(String className, String methodName, XC_MethodHook callback) {
        try {
            Class<?> clazz = XposedHelpers.findClass(className, HookConfig.getClassLoader());
            XposedBridge.hookAllMethods(clazz, methodName, callback);
            HookCounters.recordHooked();
            log("Hooked all methods: " + className + "." + methodName);
        } catch (Throwable t) {
            HookCounters.recordSkipped();
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook all methods: " + className + "." + methodName + " - " + t.getMessage());
            }
        }
    }

    /**
     * Hook constructor
     */
    public static void hookConstructor(String className, Object... parameterTypesAndCallback) {
        try {
            Class<?> clazz = XposedHelpers.findClass(className, HookConfig.getClassLoader());
            XposedHelpers.findAndHookConstructor(clazz, parameterTypesAndCallback);
            HookCounters.recordHooked();
            log("Hooked constructor: " + className);
        } catch (Throwable t) {
            HookCounters.recordSkipped();
            if (HookConfig.VERBOSE_LOGGING) {
                log("Failed to hook constructor: " + className + " - " + t.getMessage());
            }
        }
    }

    /**
     * Check if class exists
     */
    public static boolean classExists(String className) {
        try {
            XposedHelpers.findClass(className, HookConfig.getClassLoader());
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    public static void log(String message) {
        if (HookConfig.VERBOSE_LOGGING) {
            Log.i(TAG, message);
        }
    }
}
