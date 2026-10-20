package io.github.xalsace.qqbypass.resolve;

import android.util.Log;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;

import org.luckypray.dexkit.DexKitBridge;
import org.luckypray.dexkit.query.FindClass;
import org.luckypray.dexkit.query.FindMethod;
import org.luckypray.dexkit.query.matchers.ClassMatcher;
import org.luckypray.dexkit.query.matchers.MethodMatcher;
import org.luckypray.dexkit.result.ClassData;
import org.luckypray.dexkit.result.MethodData;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 按「字符串常量」定位 QQ 的 hook 目标 —— 抗版本更新的核心手段。
 *
 * 前提认知：混淆器会改类名、方法名、字段名，但**方法体里引用的字符串常量
 * 基本不动**。Intent action、路径前缀、协议命令名、错误码、日志 tag
 * 都是有语义的，改了服务端就不认。
 *
 * 对照：改造前各 hook 类里写死的是
 *   com.tencent.mobileqq.kick.NTKickProcessor#b
 *   com.tencent.mobileqq.login.ntlogin.ao#f
 * 这两条在 9.3.60 就被改过一轮，9.3.75 大概率再次失效，
 * 且失效时表现为「模块显示已激活，但保护悄悄掉了」，无任何提示。
 *
 * 换成按 mqq.intent.action.KICK_TO_LOGIN 这个字符串反查引用它的方法，
 * 类名怎么改都能找到。
 *
 * 线程模型：DexKit 解析上百 MB 的 dex 要数秒，绝不能在
 * handleLoadPackage 里同步调用（会拖慢 QQ 冷启动）。因此：
 *   - initAsync() 在后台线程建 bridge
 *   - 各 hook 类在 Tier A 处先查一次，未 ready 就跳过，走 Tier B/C
 *   - 后台线程解析完成后不主动 hook（时机太晚），只把结果缓存供下次注入使用
 * 也就是说「首次启动可能只有 B/C 生效，重启后 A 生效」—— 这是可接受的：
 * A 是精确打击，B/C 是覆盖面，两者不互斥。
 */
public final class TargetResolver {

    private static final String TAG = "QQEnhancedBypass";

    private static volatile DexKitBridge bridge;
    private static final AtomicBoolean initing = new AtomicBoolean(false);
    private static volatile boolean initFailed = false;

    private TargetResolver() {}

    /** 是否已就绪。供 VersionCompat 判定 A 档是否可用。 */
    public static boolean ready() {
        return bridge != null;
    }

    public static boolean initFailed() {
        return initFailed;
    }

    /**
     * 异步初始化。幂等，可重复调用。
     *
     * @param apkPath QQ 的 base.apk 路径，从 lpparam.appInfo.sourceDir 取
     */
    public static void initAsync(final String apkPath) {
        if (apkPath == null || apkPath.length() == 0) return;
        if (bridge != null || initFailed) return;
        if (!initing.compareAndSet(false, true)) return;

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    long t0 = System.currentTimeMillis();
                    DexKitBridge b = DexKitBridge.create(apkPath);
                    bridge = b;
                    Log.i(TAG, "[resolve] DexKit ready in "
                        + (System.currentTimeMillis() - t0) + "ms: " + apkPath);
                } catch (Throwable e) {
                    initFailed = true;
                    Log.e(TAG, "[resolve] DexKit init failed, Tier A disabled", e);
                } finally {
                    initing.set(false);
                }
            }
        }, "QQBypass-Resolver");
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();
    }

    // ------------------------------------------------------------ Tier A

    /**
     * 按字符串常量定位唯一方法，返回与 DexKit 解耦的 {@link MethodRef}。
     *
     * 这是整个方案里最抗版本更新的一招：混淆器会改类名方法名，
     * 但方法体里引用的字符串常量基本不动 —— Intent action、协议命令名、
     * 错误码、日志 tag 都是服务端语义，改了服务端就不认。
     *
     * @param strings 该方法引用的字符串常量，可给多个以缩小范围
     * @return 定位到的方法；未就绪或未命中返回 null
     */
    public static MethodRef findByStrings(String... strings) {
        MethodData md = byStrings(strings);
        return md == null ? null : toRef(md);
    }

    /**
     * 按字符串常量定位唯一方法。整个方案里最抗版本更新的一招。
     *
     * @param strings 该方法引用的字符串常量，可给多个以缩小范围
     * @return 定位到的方法；未就绪或未命中返回 null
     */
    public static MethodData byStrings(String... strings) {
        DexKitBridge b = bridge;
        if (b == null || strings == null || strings.length == 0) return null;
        try {
            List<MethodData> r = b.findMethod(
                FindMethod.create()
                    .matcher(MethodMatcher.create().usingStrings(strings)));
            return r.isEmpty() ? null : r.get(0);
        } catch (Throwable t) {
            Log.w(TAG, "[resolve] byStrings failed: " + t);
            return null;
        }
    }

    // ------------------------------------------------------------ Tier B

    /**
     * 按类名正则 + 方法名正则定位，返回与 DexKit 解耦的 {@link MethodRef}。
     *
     * 用于字符串常量不好使的场景（比如目标方法引用的字符串太常见，
     * usingStrings 会命中几十个方法）。正则写成前缀通配，例如
     *   com\.tencent\.mobileqq\.login\.ntlogin\.[a-z]+
     * 这样类名从 ao 改成 ap 也照样命中。
     *
     * 注意：本方法只在 DexKit ready 时有效 —— 正则枚举必须读 dex，
     * 没有不依赖 DexKit 的类枚举 API（Xposed 不提供）。
     * 因此 Tier B 在实践中主要服务于「A 档 ready 但字符串没命中」。
     */
    public static MethodRef findByRegex(String classRegex, String methodRegex) {
        MethodData md = byRegex(classRegex, methodRegex);
        return md == null ? null : toRef(md);
    }

    /**
     * 按类名正则 + 方法名正则定位。
     *
     * 用于字符串常量不好使的场景（比如目标方法引用的字符串太常见）。
     * 正则写成前缀通配，例如
     *   com\.tencent\.mobileqq\.login\.ntlogin\.[a-z]+
     * 这样类名从 ao 改成 ap 也照样命中。
     */
    public static MethodData byRegex(String classRegex, String methodRegex) {
        DexKitBridge b = bridge;
        if (b == null) return null;
        try {
            List<ClassData> cs = b.findClass(
                FindClass.create()
                    .matcher(ClassMatcher.create().className(classRegex)));
            if (cs.isEmpty()) return null;
            for (MethodData m : cs.get(0).getMethods()) {
                if (m.getName().matches(methodRegex)) return m;
            }
            return null;
        } catch (Throwable t) {
            Log.w(TAG, "[resolve] byRegex failed: " + t);
            return null;
        }
    }

    /**
     * MethodData -&gt; MethodRef。
     *
     * 注意方法名取 {@code getName()} 而不是 {@code getMethodName()}：
     * 两者在 DexKit 2.0.0 里都返回同一个值（getMethodName 内部转委托
     * getDexMethod().getName()），取 getName() 少一跳。
     */
    private static MethodRef toRef(MethodData md) {
        return new MethodRef(md.getClassName(), md.getName(), md.getMethodSign());
    }

    // ------------------------------------------------------------ 安装

    /**
     * 把 DexKit 定位到的方法真正 hook 上（MethodData 版本）。
     *
     * 转成 {@link MethodRef} 后委托给同名重载，内部只有一份实现。
     */
    public static int hook(MethodData md, ClassLoader cl, XC_MethodHook cb) {
        if (md == null) return 0;
        return hook(toRef(md), cl, cb);
    }

    /**
     * 把定位到的方法真正 hook 上。
     *
     * 刻意不走 XposedHelpers.findAndHookMethod(className, ...)：
     * 那个 API 内部要按参数类型 findClass，目标方法的参数类型此刻可能还没加载，
     * 会直接抛 ClassNotFoundError 导致 hook 失败。
     * 这里只反射目标类自身（它一定已加载，否则 DexKit 也定位不到运行期的它），
     * 再按 名称 + 参数签名 精确匹配后 XposedBridge.hookMethod。
     *
     * @return 实际挂上的 hook 数量，0 表示没挂上
     */
    public static int hook(MethodRef ref, ClassLoader cl, XC_MethodHook cb) {
        if (ref == null) return 0;
        try {
            Class<?> c = XposedHelpers.findClass(ref.className, cl);
            String wantSign = ref.paramSign;
            int hit = 0;
            for (Method m : c.getDeclaredMethods()) {
                if (!m.getName().equals(ref.methodName)) continue;
                if (!methodSign(m).equals(wantSign)) continue;
                XposedBridge.hookMethod(m, cb);
                hit++;
            }
            Log.i(TAG, "[resolve] hooked " + ref + " x" + hit);
            return hit;
        } catch (Throwable t) {
            Log.w(TAG, "[resolve] hook failed " + ref.className + ": " + t);
            return 0;
        }
    }

    /** 供 VersionCompat 探活用：只判断能不能定位到，不 hook。 */
    public static boolean canResolve(String... strings) {
        return byStrings(strings) != null;
    }

    // ------------------------------------------------------------ 签名工具

    /**
     * 生成 DexKit {@code getMethodSign()} 形式的方法签名：
     * {@code (java.lang.String,int)void} —— 参数与返回类型都是 **Java 全限定名**，
     * 不是 dex 形式的 {@code (Ljava/lang/String;I)V}。
     *
     * 为什么必须对齐到这个形式：DexKit 2.0.0 的 MethodData 没有 getParamSign()，
     * 只有 getMethodSign()，其内部实现是
     *   "(" + paramTypeNames.join(",") + ")" + returnTypeName
     * 而 paramTypeNames / returnTypeName 都是 Java 全限定名。
     * 早期版本按 dex 形式生成签名去比对，结果永远不相等，
     * 表现为「DexKit 定位到了目标，但 hook 挂不上，hit 恒为 0」——
     * 而且因为 beforeHookedMethod 里没有任何日志，这个失败是完全静默的。
     */
    public static String methodSign(Method m) {
        StringBuilder sb = new StringBuilder("(");
        Class<?>[] pts = m.getParameterTypes();
        for (int i = 0; i < pts.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(typeName(pts[i]));
        }
        return sb.append(')').append(typeName(m.getReturnType())).toString();
    }

    /**
     * Java 全限定类型名。与 DexKit 的 DexSignUtil.getTypeName 语义一致：
     * 原始类型用名字（int / boolean），数组用 "[]" 后缀，类用全限定名。
     */
    private static String typeName(Class<?> c) {
        if (c == int.class)     return "int";
        if (c == long.class)    return "long";
        if (c == boolean.class) return "boolean";
        if (c == byte.class)    return "byte";
        if (c == char.class)    return "char";
        if (c == short.class)   return "short";
        if (c == float.class)   return "float";
        if (c == double.class)  return "double";
        if (c == void.class)    return "void";
        if (c.isArray())        return typeName(c.getComponentType()) + "[]";
        return c.getName();
    }
}