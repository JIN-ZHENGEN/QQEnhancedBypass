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
import java.util.Set;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
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
 *   - 若目标带有字符串常量，同时登记进 PENDING 队列（见
 *     {@link #enqueueUpgrade}），等 bridge 建好后由 {@link #setReady}
 *     在同进程内回查补挂，无需等下次注入
 * 也就是说「首次注入只有 B/C，同进程毫秒级后 A 补上」——
 * 真机实测 DexKit ready 耗时 624ms ~ 9949ms（受设备负载影响），
 * 补挂后即出现 {@code [resolve] Tier A upgraded} 日志。
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

    // ------------------------------------------------------------ Tier A 回查升级

    /**
     * 一个待「DexKit ready 后回查升级」的 hook 目标。
     *
     * 成因：{@link TieredHook#install} 在调用瞬间若 DexKit 还没 ready（后台线程
     * 还在解析上百 MB 的 dex），A/B 两档的前置条件不满足，只能落 C 档甚至 MISS。
     * 此时若目标本带有字符串常量（strings 非空），就把它登记到这里；等
     * {@link #setReady} 被调用时统一回查 DexKit，命中则补挂 Tier A hook，
     * 让「首次注入只有 C、重启才生效 A」的延迟从「跨进程重启」缩到「同进程毫秒级」。
     *
     * 线程安全：bridge 就绪后 {@code ready()} 即返回 true，队列只会被消费一次，
     * 故用轻量并发容器即可，无需额外锁。
     */
    private static final class PendingUpgrade {
        final String[] strings;
        final String classRegex;
        final String methodRegex;
        final String className;
        final String methodName;
        final ClassLoader cl;
        final XC_MethodHook cb;

        PendingUpgrade(String[] strings, String classRegex, String methodRegex,
                       String className, String methodName, ClassLoader cl, XC_MethodHook cb) {
            this.strings = strings;
            this.classRegex = classRegex;
            this.methodRegex = methodRegex;
            this.className = className;
            this.methodName = methodName;
            this.cl = cl;
            this.cb = cb;
        }
    }

    /** 等待 DexKit ready 后回查升级的 hook 目标队列。 */
    private static final List<PendingUpgrade> PENDING =
        new CopyOnWriteArrayList<PendingUpgrade>();

    /** 已按 ref 去重挂上的 Tier A hook，避免回查重复挂载。 */
    private static final Set<String> UPGRADED = Collections.newSetFromMap(
        new ConcurrentHashMap<String, Boolean>());

    /**
     * 登记一个待回查升级的目标（由 {@link TieredHook} 在 MISS 且带 strings 时调用）。
     *
     * @return 是否成功登记（false 表示已是 MISS 不带 strings，或已 ready 无需排队）
     */
    public static boolean enqueueUpgrade(String[] strings, String classRegex, String methodRegex,
                                        String className, String methodName,
                                        ClassLoader cl, XC_MethodHook cb) {
        if (strings == null || strings.length == 0) return false; // 无 A 档依据，升级无意义
        if (bridge != null) {
            // 已经 ready 了，直接尝试升级（不排队）。
            tryUpgradeNow(strings, classRegex, methodRegex, className, methodName, cl, cb);
            return true;
        }
        PENDING.add(new PendingUpgrade(strings, classRegex, methodRegex,
            className, methodName, cl, cb));
        return true;
    }

    /**
     * 由 {@link #initAsync} 在 bridge 建好、把 ready() 置 true 之后调用，
     * 触发所有待回查目标的 Tier A 升级。幂等。
     */
    static void setReady() {
        if (PENDING.isEmpty()) return;
        Log.i(TAG, "[resolve] DexKit ready -> upgrading " + PENDING.size() + " pending Tier A target(s)");
        for (PendingUpgrade p : PENDING) {
            tryUpgradeNow(p.strings, p.classRegex, p.methodRegex,
                p.className, p.methodName, p.cl, p.cb);
        }
        PENDING.clear();
    }

    private static void tryUpgradeNow(String[] strings, String classRegex, String methodRegex,
                                      String className, String methodName,
                                      ClassLoader cl, XC_MethodHook cb) {
        if (strings == null || strings.length == 0) return;
        if (!TargetResolver.ready()) return;
        // 去重键 = strings + 目标类方法，避免同一目标重复挂载；
        // 同时允许「共串但 hook 不同方法」的两个调用点各自升级（如网络/踢线）。
        StringBuilder key = new StringBuilder();
        for (String s : strings) { key.append(s).append('|'); }
        key.append(className).append('#').append(methodName);
        if (UPGRADED.contains(key.toString())) return;
        UPGRADED.add(key.toString());
        try {
            MethodRef ref = TargetResolver.findByStrings(strings);
            if (ref != null) {
                int n = TargetResolver.hook(ref, cl, cb);
                if (n > 0) {
                    Log.i(TAG, "[resolve] Tier A upgraded -> " + ref + " x" + n);
                } else {
                    Log.w(TAG, "[resolve] Tier A upgrade miss (hooked=0): " + ref);
                }
            } else {
                // 字符串常量没命中 —— 可能该版本已改协议，回退到 B 档正则。
                if (classRegex != null && methodRegex != null) {
                    MethodRef br = TargetResolver.findByRegex(classRegex, methodRegex);
                    if (br != null) {
                        int n = TargetResolver.hook(br, cl, cb);
                        if (n > 0) {
                            Log.i(TAG, "[resolve] Tier B upgraded -> " + br + " x" + n);
                        }
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "[resolve] upgrade failed for " + java.util.Arrays.toString(strings) + ": " + t);
        }
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
                    // DexKit 2.0.0 的 DexKitBridge.create() 内部会懒加载
                    // libdexkit.so；在部分 ROM / Android 版本上，若 APK 未把
                    // so 解压到 /data/app/.../lib/（extractNativeLibs=false
                    // 且 zip 内 so 未 4K 对齐），ART 无法 mmap，会抛
                    // UnsatisfiedLinkError: No implementation found for
                    // nativeInitDexKit。这里在 create() 之前显式 preload 一次，
                    // 让失败更早暴露，并把根因明确区分「so 缺失/未解压」与
                    // 「so 已就位但符号异常」，供 [compat] 报告。
                    try {
                        System.loadLibrary("dexkit");
                    } catch (Throwable le) {
                        Log.e(TAG, "[resolve] System.loadLibrary(\"dexkit\") failed "
                            + "before DexKitBridge.create(); native lib not loadable "
                            + "(check extractNativeLibs / 4K alignment): " + le, le);
                    }
                    DexKitBridge b = DexKitBridge.create(apkPath);
                    bridge = b;
                    Log.i(TAG, "[resolve] DexKit ready in "
                        + (System.currentTimeMillis() - t0) + "ms: " + apkPath);
                    // 关键：bridge 就绪后立即触发「DexKit ready 后回查升级」，
                    // 让本应在下一次函数注入才生效的 Tier A 在第时间挂上。
                    // 这把「首次注入只有 C、重启才生效 A」的延迟从跨进程重启
                    // 缩到同进程毫秒级（见 enqueueUpgrade / setReady）。
                    setReady();
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
        String sign = md.getMethodSign();
        // DexKit getMethodSign() 在不同版本/调用下可能返回两种形式：
        //   - dex 短码形 (...)V / (Ljava/lang/String;I)V
        //   - 或 Java 全限定形 (...)void / (java.lang.String,int)void
        // 而本类 methodSign(Method) 统一产出 Java 全限定形。
        // 若直接存 dex 形，hook() 里 methodSign(m).equals(ref.paramSign)
        // 永远不相等（例如 "()V" != "()void"），导致 hook 挂上却 hit=0 的静默失败。
        // 因此这里把 dex 形规范成 Java 全限定形，与反射侧对齐。
        String orig = sign;
        // 注意：不能拿「含 ';'」当 dex 形判据——()V / (I)V 这类无参或纯原始类型签名
        // 根本不含 ';'，会被误判成「已是 Java 形」而跳过转换，
        // 最终 hook() 里 "()V" != "()void" 恒不相等，hit 永远是 0。
        // 必须用字符集判别：整串只由 dex 类型描述符字符构成才算 dex 形。
        if (looksDexForm(sign)) {
            sign = dexSignToJava(sign);
        }
        MethodRef r = new MethodRef(md.getClassName(), md.getName(), sign);
        Log.i(TAG, "[resolve] toRef " + md.getClassName() + "#" + md.getName()
            + " rawSign='" + orig + "' normalized='" + sign + "'");
        return r;
    }

    /**
     * 判断签名是否为 dex 短码形，例如 {@code ()V} / {@code (I)V} / {@code (Ljava/lang/String;I)V}。
     * 判别方式：整串只允许出现 dex 类型描述符字符（VZBCSIJFD、L、[、;、/），
     * 一旦出现 'j'、'a'、'.'、',' 等 Java 全限定名/分隔符字符即判定为 Java 形，
     * 例如 {@code (java.lang.String,int)void} 含 '.' 与 ','，不会被误判。
     */
    private static boolean looksDexForm(String s) {
        if (s == null || s.length() < 3) return false;
        int close = s.indexOf(')');
        if (close != s.lastIndexOf(')')) return false;
        if (s.charAt(0) != '(' || close < 0) return false;
        for (int i = 1; i < close; i++) {
            if (!isDexSignChar(s.charAt(i))) return false;
        }
        if (close + 1 >= s.length()) return false;
        for (int i = close + 1; i < s.length(); i++) {
            if (!isDexSignChar(s.charAt(i))) return false;
        }
        return true;
    }

    private static boolean isDexSignChar(char c) {
        switch (c) {
            case 'V': case 'Z': case 'B': case 'C': case 'S':
            case 'I': case 'J': case 'F': case 'D':
            case 'L': case '[': case ';': case '/':
                return true;
            default:
                return false;
        }
    }

    /**
     * 把 DexKit 的 dex 短码方法签名规范成本模块使用的 Java 全限定形。
     * 例：()V -> ()void；(Ljava/lang/String;I)V -> (java.lang.String,int)void
     * 仅当输入含 ';'（dex 形标志）时调用；已是 Java 形则不动。
     */
    private static String dexSignToJava(String dex) {
        int close = dex.indexOf(')');
        if (close < 0) return dex;
        String params = dex.substring(1, close);
        String ret = dex.substring(close + 1);
        StringBuilder sb = new StringBuilder("(");
        int i = 0;
        boolean first = true;
        while (i < params.length()) {
            if (!first) sb.append(',');
            first = false;
            char c = params.charAt(i);
            if (c == '[') {
                int j = i;
                while (j < params.length() && params.charAt(j) == '[') j++;
                String base = typeWord(params, j);
                sb.append(base);
                for (int k = i; k < j; k++) sb.append("[]");
                i = j + 1;
            } else if (c == 'L') {
                int end = params.indexOf(';', i);
                if (end < 0) end = params.length();
                sb.append(params.substring(i + 1, end).replace('/', '.'));
                i = end + 1;
            } else {
                sb.append(primWord(c));
                i++;
            }
        }
        sb.append(')');
        sb.append(typeWord(ret, 0));
        return sb.toString();
    }

    private static String typeWord(String s, int idx) {
        if (idx >= s.length()) return s;
        char c = s.charAt(idx);
        if (c == 'L') {
            int end = s.indexOf(';', idx);
            if (end < 0) end = s.length();
            return s.substring(idx + 1, end).replace('/', '.');
        }
        return primWord(c);
    }

    private static String primWord(char c) {
        switch (c) {
            case 'V': return "void";
            case 'I': return "int";
            case 'J': return "long";
            case 'Z': return "boolean";
            case 'B': return "byte";
            case 'C': return "char";
            case 'S': return "short";
            case 'F': return "float";
            case 'D': return "double";
            default:  return String.valueOf(c);
        }
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
            StringBuilder diag = null;
            for (Method m : c.getDeclaredMethods()) {
                String ms = methodSign(m);
                if (!m.getName().equals(ref.methodName)) continue;
                if (diag == null) diag = new StringBuilder();
                diag.append(ms).append(' ');
                // 双保险：即使 toRef 的规范化漏网，这里再按去空格形式比一次。
                // DexKit 的签名可能带空格 "(int, java.lang.String)"，反射侧不带，
                // 去掉空白后比对可吸收这类差异。
                if (!ms.equals(wantSign) && !norm(ms).equals(norm(wantSign))) continue;
                XposedBridge.hookMethod(m, cb);
                hit++;
            }
            Log.i(TAG, "[resolve] hooked " + ref + " x" + hit);
            if (hit == 0) {
                // hit=0 的诊断：把该类里所有同名方法的真实反射签名打出来，
                // 与 wantSign 直接对比，一眼看出是「签名形式不匹配」还是「方法不存在」。
                Log.w(TAG, "[resolve] hook diag wantSign='" + wantSign + "' actual="
                    + (diag == null ? "<no method named " + ref.methodName + ">" : diag.toString()));
            }
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

    /** 去掉签名里的所有空白，用于容错比对。 */
    private static String norm(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') sb.append(c);
        }
        return sb.toString();
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