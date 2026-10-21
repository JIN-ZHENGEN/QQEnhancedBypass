package io.github.xalsace.qqbypass.resolve;

import android.util.Log;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import java.lang.reflect.Method;

/**
 * 三级降级安装器（version-agnostic 改造第 4 项）。
 *
 * 改造前各 hook 类的形态是：
 *
 *   HookUtils.hookAllMethods("com.tencent.mobileqq.kick.NTKickProcessor", "b", cb);
 *
 * 一句话，没有降级。类名一旦被混淆器改掉，表现是 hookAllMethods 内部
 * catch 住 ClassNotFound → recordSkipped() → 日志一行 "Failed to hook"
 * （而且 VERBOSE_LOGGING 默认 false，连这行都没有）。
 * 结果就是**模块显示已激活，保护悄悄掉了一层**，无任何提示。
 *
 * 三级降级的含义：同一个 hook 目标，按可靠性从高到低准备三条安装路径，
 * 依次尝试，第一条成功就不再往下走：
 *
 *   Tier A  DexKit 按字符串常量反查。混淆器不改方法体里的字符串常量，
 *            所以类名/方法名怎么改都能找到。约 90% 覆盖。
 *            需要 TargetResolver 已 ready（后台线程解析完 base.apk）。
 *   Tier B  DexKit 按类名正则 + 方法名正则。前缀通配，类名从 ao 改成 ap
 *            仍命中。同样需要 ready。
 *   Tier C  写死的真实类名（兜底）。不依赖 DexKit，A 未就绪时唯一能立刻
 *            生效的一层；也是 A 解析完成后字符串常量改写时的备份。
 *
 * 三者不互斥：A 未命中不代表目标失效（可能只是 DexKit 还没解析完），
 * 此时 B 或 C 顶上。任一层成功即返回对应档位，调用方据此判断是否要在
 * 自检报告里记 MISS。
 *
 * 线程约束：本类只在 handleLoadPackage 所在线程调用（不跨线程），
 * 内部不做任何阻塞等待。DexKit 的初始化是另一条后台线程
 * （见 {@link TargetResolver#initAsync}），两者通过 volatile bridge 字段同步。
 */
public final class TieredHook {

    private static final String TAG = "QQEnhancedBypass";

    private TieredHook() {}

    /** 安装结果：最终生效的档位 + 挂上的 hook 数。 */
    public static final class Install {
        /** A/B/C/MISS。 */
        public final String tier;
        /** 实际挂上的 hook 数量（0 = 没挂上）。 */
        public final int hooked;
        /** 命中的目标描述（真实类名或正则本身）。 */
        public final String target;

        Install(String tier, int hooked, String target) {
            this.tier = tier;
            this.hooked = hooked;
            this.target = target;
        }

        public boolean ok() {
            return hooked > 0;
        }

        @Override
        public String toString() {
            return tier + " " + target + " x" + hooked;
        }
    }

    /**
     * 三级降级安装一个 hook。
     *
     * @param strings     A 档依据：目标方法引用的字符串常量（可多个以缩小范围）
     * @param classRegex  B 档依据：类名正则，例如 "com\\.tencent\\.mobileqq\\.kick\\.[a-zA-Z]+"
     * @param methodRegex B 档依据：方法名正则，例如 "[a-z]" 或 "b|onKick"
     * @param className   C 档依据：写死的真实类名
     * @param methodName  C 档依据：写死的真实方法名
     * @param cl          类加载器（QQ 的）
     * @param cb          hook 回调
     * @return 安装结果；调用方用 {@link Install#ok()} 判断是否生效
     */
    public static Install install(String[] strings,
                                  String classRegex, String methodRegex,
                                  String className, String methodName,
                                  ClassLoader cl,
                                  XC_MethodHook cb) {
        String cLabel = className != null ? className : classRegex;
        String mLabel = methodName != null ? methodName : methodRegex;

        // ---- Tier A: DexKit 字符串常量 ----
        if (strings != null && strings.length > 0 && TargetResolver.ready()) {
            try {
                MethodRef ref = TargetResolver.findByStrings(strings);
                if (ref != null) {
                    int n = TargetResolver.hook(ref, cl, cb);
                    if (n > 0) {
                        return new Install("A", n, ref.toString());
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "[tier] A failed for " + cLabel + "#" + mLabel + ": " + t);
            }
        }

        // ---- Tier B: DexKit 类名正则 + 方法名正则 ----
        if (classRegex != null && methodRegex != null && TargetResolver.ready()) {
            try {
                MethodRef ref = TargetResolver.findByRegex(classRegex, methodRegex);
                if (ref != null) {
                    int n = TargetResolver.hook(ref, cl, cb);
                    if (n > 0) {
                        return new Install("B", n, ref.toString());
                    }
                }
            } catch (Throwable t) {
                Log.w(TAG, "[tier] B failed for " + classRegex + "/" + methodRegex + ": " + t);
            }
        }

        // ---- Tier C: 写死的真实类名（兜底，不依赖 DexKit） ----
        if (className != null && methodName != null) {
            try {
                Class<?> c = XposedHelpers.findClass(className, cl);
                int before = countMethods(c, methodName);
                XposedBridge.hookAllMethods(c, methodName, cb);
                if (before > 0) {
                    return new Install("C", before, className + "#" + methodName);
                }
                // hookAllMethods 对「类在但方法不在」是静默成功（0 个方法），
                // 必须自己数一次，否则会把 MISS 误报成 C。
            } catch (Throwable t) {
                Log.w(TAG, "[tier] C failed for " + className + "#" + methodName + ": " + t);
            }
        }

        // ---- MISS：登记「DexKit ready 后回查升级」 ----
        // 若本目标本带有字符串常量（A 档依据），但调用瞬间 DexKit 还没 ready
        // （TieredHook 在 handleLoadPackage 同步执行，而 DexKit 在后台线程解析 dex，
        // 正常要 1~4s 才就绪），则把它排队，等 TargetResolver.setReady() 时
        // 统一回查 DexKit 补挂 Tier A/B hook，避免「首次注入只有 C、必须重启才生效 A」。
        // 无 strings 的目标（纯 C 档，如 AOSP 框架类）升级无意义，直接 MISS。
        if (strings != null && strings.length > 0) {
            TargetResolver.enqueueUpgrade(strings, classRegex, methodRegex,
                className, methodName, cl, cb);
        }
        return new Install("MISS", 0, cLabel + "#" + mLabel);
    }

    /**
     * 便捷重载：只给写死类名/方法名（C 档单层）。
     *
     * 用于那些本来就没有更好定位手段的目标 —— 最典型的是 AOSP 框架类本身，
     * android.app.Instrumentation 这个名字从 4.x 到 16 没变过，
     * 对它做 A/B 档是纯浪费。
     */
    public static Install installFixed(String className, String methodName,
                                       ClassLoader cl, XC_MethodHook cb) {
        return install(null, null, null, className, methodName, cl, cb);
    }

    /** 便捷重载：A 档 + C 档两级（字符串常量命中最好，否则退回写死类名）。 */
    public static Install installAC(String[] strings,
                                    String className, String methodName,
                                    ClassLoader cl, XC_MethodHook cb) {
        return install(strings, null, null, className, methodName, cl, cb);
    }

    private static int countMethods(Class<?> c, String methodName) {
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            if (m.getName().equals(methodName)) n++;
        }
        return n;
    }
}