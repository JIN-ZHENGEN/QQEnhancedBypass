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
                // ★ 修复（2026-10-30 code review）：原先用 countMethods(c, methodName)
                //   只数 c.getDeclaredMethods()，与 hookAllMethods 的真实口径
                //   【不一致】——后者会 hook 继承自父类的同名方法，而
                //   getDeclaredMethods() 不含继承成员。
                //
                //   后果（双向都会错）：
                //     1) 方法只存在于父类时：declaredCount=0，但 hookAllMethods
                //        实际挂上了 N 个 → 本应报 C，却误报 MISS，
                //        并把它塞进 enqueueUpgrade 队列等 DexKit 补挂；
                //        表现为日志里一堆假 MISS，让人误判保护掉了。
                //     2) 子类覆写时：declaredCount 只数子类那份，
                //        与 hookAllMethods 实际挂的数量对不上，报告数字失真。
                //
                //   正确做法：遍历整条继承链计数，与 hookAllMethods 口径对齐。
                //   （仍保留「类在但方法不在 → 报 MISS 不报 C」的初衷，
                //     即 hookAllMethods 静默返回 0 这个坑照旧被挡住。）
                int before = countMethodsInHierarchy(c, methodName);
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

    /**
     * 遍历整条继承链统计同名方法数，与 {@link XposedBridge#hookAllMethods} 口径对齐。
     *
     * hookAllMethods 内部用的是「本类 + 所有父类」的同名方法集合
     * （Xposed 的 findMethodsExact 语义），因此这里必须同样沿
     * getSuperclass() 向上走完，否则计数会偏小。
     *
     * 逐层用 getDeclaredMethods() 并自行判重：子类覆写父类方法时，
     * 两者都被 hookAllMethods 计入（方法签名相同的覆写只算一次），
     * 这里用「类名#方法名#参数签名」去重，与覆写语义一致。
     */
    private static int countMethodsInHierarchy(Class<?> c, String methodName) {
        java.util.Set<String> seen = new java.util.HashSet<String>();
        Class<?> cur = c;
        // 防御：继承链异常长/循环（理论不可能，但 ROM 改过 ART 也说不准），
        // 用深度上限兜住，避免死循环卡死 handleLoadPackage。
        int depth = 0;
        while (cur != null && depth < 64) {
            try {
                for (Method m : cur.getDeclaredMethods()) {
                    if (!m.getName().equals(methodName)) continue;
                    StringBuilder sig = new StringBuilder();
                    sig.append(cur.getName()).append('#').append(methodName).append('(');
                    for (Class<?> p : m.getParameterTypes()) {
                        sig.append(p.getName()).append(';');
                    }
                    sig.append(')');
                    seen.add(sig.toString());
                }
            } catch (Throwable ignored) {
                // 某些 ART 版本对 getDeclaredMethods 可能抛（如代理类），跳过该层
            }
            cur = cur.getSuperclass();
            depth++;
        }
        return seen.size();
    }

    /**
     * 仅统计本类声明的方法（不含继承）。
     *
     * 保留它是因为语义明确、个别场景可能有用；但 Tier C 判定请一律用
     * {@link #countMethodsInHierarchy} —— 那才是与 hookAllMethods 对齐的口径。
     */
    private static int countMethods(Class<?> c, String methodName) {
        int n = 0;
        for (Method m : c.getDeclaredMethods()) {
            if (m.getName().equals(methodName)) n++;
        }
        return n;
    }
}
