package io.github.xalsace.qqbypass.config;

import java.util.Locale;

/**
 * 设备指纹生成器（路线图第 3 项：设备指纹一致性增强）。
 *
 * 解决原有 DeviceInfoHook 的三个真实缺陷：
 *
 * 1. **跨 user 串号**。原来是 4 个 `private static String cachedXxx`，进程内单例。
 *    在 XSpace 多开下 u0 和 u999 跑在同一台机器上，共用一套假指纹会让服务端
 *    判定「同一设备绑定两个账号」，这与绕过检测的目标完全相反 —— 直接放大风控。
 *    → 本类按 userId 分桶，不同 user 得到不同指纹。
 *
 * 2. **跨进程不一致**。QQ 有主进程和 :MSF 等多个进程，各自有一份 static，
 *    各自生成就会得到不同值，Pandora 的多路径交叉校验（同一信息用 6 种 API 取，
 *    比对是否一致）立刻就能发现破绽。
 *    → 本类所有值都由 seed **确定性派生**，不保存状态、不依赖进程内缓存。
 *      只要 seed 相同，任何进程任何时刻算出的指纹都完全一致。
 *
 * 3. **格式不合法**。随便造一串数字当 IMEI，会被 Luhn 校验位检查一眼识破。
 *    → IMEI 走标准 Luhn 校验位；MEID/Android ID 用合法字符集与长度。
 *
 * 不伪造时（默认）本类不被使用，真值原样透传 —— 保持改造前的默认行为不变。
 */
public final class Fingerprint {

    private final int userId;
    private final String seed;
    private final String imei;
    private final String meid;
    private final String serial;
    private final String androidId;

    private Fingerprint(int userId, String seed) {
        this.userId = userId;
        this.seed = seed;
        // 所有字段都由 (seed, userId) 确定性派生 —— 见类注释第 2 点。
        String base = seed + "#u" + userId;
        this.imei = deriveImei(base + "#imei");
        this.meid = deriveHex(base + "#meid", 14).toUpperCase(Locale.US);
        this.serial = deriveAlnum(base + "#serial", 10).toUpperCase(Locale.US);
        this.androidId = deriveHex(base + "#aid", 16).toLowerCase(Locale.US);
    }

    /**
     * 取指定 user 的指纹。
     *
     * @param userId      Android 多用户 id（0 = 机主，999 = XSpace 双开）
     * @param configSeed  配置文件里为该 user 指定的种子；null 表示由设备稳定属性派生
     */
    public static Fingerprint forUser(int userId, String configSeed) {
        String seed = (configSeed != null && configSeed.length() > 0)
            ? configSeed
            : deviceSeed();
        return new Fingerprint(userId, seed);
    }

    public int userId() { return userId; }
    public String imei() { return imei; }
    public String meid() { return meid; }
    public String serial() { return serial; }
    public String androidId() { return androidId; }

    @Override
    public String toString() {
        return "Fingerprint{u=" + userId
            + " imei=" + imei
            + " meid=" + meid
            + " serial=" + serial
            + " aid=" + androidId + "}";
    }

    // ------------------------------------------------------------- seed 来源

    /**
     * 设备级种子：从稳定的构建属性派生，保证同一台设备上所有进程算出同一个值。
     *
     * 刻意**不读**任何被本模块 hook 过的属性（Build.SERIAL / getImei /
     * SystemProperties 的 serialno）—— 否则会读回自己伪造的值，构成循环。
     * 这里只用 Build 里的常规字段，它们不在 DeviceInfoHook 的覆盖范围内。
     *
     * 用反射读取而不是直接 `import android.os.Build`：这样本类在纯 JVM 单元测试
     * 里也能加载（android.jar 的这些字段在 JVM 上会抛异常，反射 + try/catch 可回落）。
     */
    private static String deviceSeed() {
        StringBuilder sb = new StringBuilder();
        sb.append(readBuildField("FINGERPRINT"));
        sb.append('|').append(readBuildField("BOARD"));
        sb.append('|').append(readBuildField("BRAND"));
        sb.append('|').append(readBuildField("DEVICE"));
        sb.append('|').append(readBuildField("HARDWARE"));
        return sb.toString();
    }

    private static String readBuildField(String name) {
        try {
            Class<?> c = Class.forName("android.os.Build");
            java.lang.reflect.Field f = c.getField(name);
            Object v = f.get(null);
            return v == null ? "" : String.valueOf(v);
        } catch (Throwable t) {
            // 不在 Android 上（单元测试）读不到就是空串，仍然确定性可用。
            return "";
        }
    }

    // --------------------------------------------------------------- 派生算法

    /**
     * 派生 IMEI：15 位数字，最后一位是标准 Luhn 校验位。
     *
     * TAC（前 8 位）里前两位固定用 86（中国）使其看起来像真实号段，
     * 其余位由 hash 填充。
     */
    private static String deriveImei(String base) {
        long h = hash(base);
        StringBuilder sb = new StringBuilder(15);
        sb.append("86");                                  // TAC 前两位：中国
        long v = h;
        for (int i = 0; i < 12; i++) {                    // 再填 12 位 -> 共 14 位
            sb.append((char) ('0' + (int) Math.abs(v % 10)));
            v /= 10;
            if (v == 0) v = hash(base + "#" + i);         // 防止提前耗尽变全 0
        }
        sb.append(luhnCheck(sb.toString()));
        return sb.toString();
    }

    /**
     * 计算 14 位数字的 Luhn 校验位。
     * 从右往左，第 2、4、6... 位（即 0-based 的奇数下标）翻倍后按位求和。
     *
     * public 是为了让单测能直接钉死这个算法（见 FingerprintTest.luhnCheckMatchesKnownValues）。
     * 它是纯函数、无副作用，暴露不影响模块行为。
     */
    public static char luhnCheck(String first14) {
        int sum = 0;
        for (int i = 0; i < first14.length(); i++) {
            int d = first14.charAt(i) - '0';
            if (d < 0 || d > 9) d = 0;
            if (i % 2 == 1) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
        }
        int check = (10 - (sum % 10)) % 10;
        return (char) ('0' + check);
    }

    private static String deriveHex(String base, int len) {
        StringBuilder sb = new StringBuilder(len);
        long v = hash(base);
        for (int i = 0; i < len; i++) {
            sb.append(HEX[(int) Math.abs(v % 16)]);
            v = (v / 16) ^ hash(base + "#" + i);
            if (v == 0) v = hash(base + "#x" + i);
        }
        return sb.toString();
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private static String deriveAlnum(String base, int len) {
        StringBuilder sb = new StringBuilder(len);
        long v = hash(base);
        for (int i = 0; i < len; i++) {
            int idx = (int) Math.abs(v % 36);
            sb.append(idx < 10 ? (char) ('0' + idx) : (char) ('A' + (idx - 10)));
            v = (v / 36) ^ hash(base + "#" + i);
            if (v == 0) v = hash(base + "#a" + i);
        }
        return sb.toString();
    }

    /**
     * FNV-1a 64 位变体。自己实现而不是用 String.hashCode()，是因为
     * hashCode 在不同 JDK/ART 版本上语义虽稳定但分布较差；FNV 分布更均匀，
     * 能避免派生出的指纹出现明显规律（比如连续多位相同）。
     */
    private static long hash(String s) {
        long h = 0xcbf29ce484222325L;
        for (int i = 0; i < s.length(); i++) {
            h ^= (long) s.charAt(i);
            h *= 0x100000001b3L;
        }
        // 折叠到 63 位避免后续取模时出现负数边界问题
        return h == Long.MIN_VALUE ? 0 : h;
    }
}