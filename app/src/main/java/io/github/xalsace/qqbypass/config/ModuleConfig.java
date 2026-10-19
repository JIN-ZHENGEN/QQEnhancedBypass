package io.github.xalsace.qqbypass.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 运行时配置（路线图第 6 项：配置文件支持，无需重新编译）。
 *
 * 取代原先 {@link HookConfig} 里那批 `public static boolean` 编译期常量。
 * 设计约束（每一条都对应一个真实踩过的坑）：
 *
 * 1. **必须零异常外溢**。本类的 get() 会在 handleLoadPackage 的最早期被调用，
 *    任何抛错都会打断整个注入流程，导致所有 hook 静默失效。所以每个读取点
 *    都用 try/catch 包住并回落到 DEFAULT。
 * 2. **必须能在两个进程里读到同一份**。QQ 有主进程和 :MSF 两个进程，各自有
 *    各自的 static。配置文件放外部存储就是为了让两边读到同一份内容。
 * 3. **读不到 = 全默认**，绝不因为配置文件缺失就关闭保护。
 * 4. **指纹 seed 按 user 分桶**。XSpace 多开下 u0 与 u999 是同一设备上两个账号，
 *    共用一套假指纹会让服务端判定「同一设备多账号」，反而放大风控 —— 这与
 *    绕过的目标是相反的。
 */
public final class ModuleConfig {

    // 候选路径按优先级排列。第一个存在的用它的内容；都不存在则全默认。
    // /data/local/tmp 是 fallback：Android 11+ 上 QQ 进程读 /sdcard 可能被
    // 分区存储限制拒绝，而 /data/local/tmp 对所有 uid 可读。
    private static final String[] CANDIDATES = {
        "/sdcard/Download/qqbypass.json",
        "/data/local/tmp/qqbypass.json"
    };

    private static volatile ModuleConfig cached;

    /** 各 hook 模块开关；缺失的键 = 启用（与改造前的默认行为一致）。 */
    private final Map<String, Boolean> modules;
    /** userId -> 指纹种子。缺失则由 Fingerprint 自行生成并持久化。 */
    private final Map<Integer, String> fingerprintSeeds;
    private final boolean verbose;
    private final boolean nativeHooks;
    /** 是否伪造设备指纹。默认 false —— 见 {@link Fingerprint} 类注释里的风险说明。 */
    private final boolean spoofFingerprint;

    private ModuleConfig(Map<String, Boolean> modules,
                         Map<Integer, String> fingerprintSeeds,
                         boolean verbose,
                         boolean nativeHooks,
                         boolean spoofFingerprint) {
        this.modules = Collections.unmodifiableMap(modules);
        this.fingerprintSeeds = Collections.unmodifiableMap(fingerprintSeeds);
        this.verbose = verbose;
        this.nativeHooks = nativeHooks;
        this.spoofFingerprint = spoofFingerprint;
    }

    /** 全默认：所有模块开、不伪造指纹、静默日志、native 开。 */
    public static ModuleConfig defaults() {
        return new ModuleConfig(
            Collections.<String, Boolean>emptyMap(),
            Collections.<Integer, String>emptyMap(),
            false,
            true,
            false);
    }

    /**
     * 读取配置。只在进程生命周期内解析一次，之后返回缓存。
     * 改配置文件必须重启 QQ 才生效 —— 这是 Xposed 模块的固有约束。
     */
    public static ModuleConfig get() {
        ModuleConfig c = cached;
        if (c != null) return c;
        synchronized (ModuleConfig.class) {
            if (cached != null) return cached;
            cached = load();
            return cached;
        }
    }

    /** 仅供测试：注入一份配置，绕过文件读取。 */
    static void setForTest(ModuleConfig c) {
        cached = c;
    }

    static ModuleConfig load() {
        for (String path : CANDIDATES) {
            try {
                File f = new File(path);
                if (!f.exists() || !f.isFile()) continue;
                String text = readAll(f);
                if (text == null || text.length() == 0) continue;
                return fromJson(text);
            } catch (Throwable t) {
                // 单个候选失败（权限/损坏），继续试下一个，绝不外溢
            }
        }
        return defaults();
    }

    /** 从 JSON 文本构造。任何结构异常都回落到该项的默认值，而不是整个配置作废。
 *  public 以便单测直接喂畸形输入（见 ModuleConfigTest.garbageNeverThrows）。 */
    public static ModuleConfig fromJson(String text) {
        Map<String, Boolean> mods = new LinkedHashMap<String, Boolean>();
        Map<Integer, String> seeds = new LinkedHashMap<Integer, String>();
        boolean verbose = false;
        boolean nativeHooks = true;
        boolean spoofFingerprint = false;

        Map<String, Object> root;
        try {
            root = Json.asObject(Json.parse(text));
        } catch (Throwable t) {
            return defaults();
        }
        if (root == null) return defaults();

        Map<String, Object> modsRaw = Json.asObject(root.get("modules"));
        if (modsRaw != null) {
            for (Map.Entry<String, Object> e : modsRaw.entrySet()) {
                Boolean b = Json.asBoolean(e.getValue(), null);
                if (b != null && e.getKey() != null) {
                    mods.put(e.getKey(), b);
                }
            }
        }

        Map<String, Object> fpRaw = Json.asObject(root.get("fingerprint"));
        if (fpRaw != null) {
            for (Map.Entry<String, Object> e : fpRaw.entrySet()) {
                String seed = Json.asString(e.getValue(), null);
                if (seed == null || seed.length() == 0) continue;
                try {
                    int uid = Integer.parseInt(e.getKey());
                    seeds.put(uid, seed);
                } catch (NumberFormatException ignored) {
                    // key 不是数字 = 配置写错，忽略该项
                }
            }
        }

        verbose = Json.asBoolean(root.get("verbose"), false);
        // native 默认开：CI 侧 CMake 已能产出 libnative-bypass.so 并随 APK 打包，
        // 且 UnifiedHookCoordinator 在库缺失时会走纯 Java 降级路径（不会崩）。
        // 想在真机关掉请在 qqbypass.json 里写 "nativeHooks": false。
        nativeHooks = Json.asBoolean(root.get("nativeHooks"), true);
        // 伪造指纹默认关：做错有负收益（共用指纹会让服务端判定同设备多账号），
        // 且这是本模块最容易被识别的一层。默认保持真值透传。
        spoofFingerprint = Json.asBoolean(root.get("spoofFingerprint"), false);

        return new ModuleConfig(mods, seeds, verbose, nativeHooks, spoofFingerprint);
    }

    /** 查询模块开关。未配置的模块默认开启。 */
    public boolean isModuleEnabled(String id) {
        Boolean v = modules.get(id);
        return v == null || v;
    }

    public String seedForUser(int userId) {
        return fingerprintSeeds.get(userId);
    }

    public boolean isVerbose() {
        return verbose;
    }

    public boolean isNativeHooksEnabled() {
        return nativeHooks;
    }

    public boolean isSpoofFingerprintEnabled() {
        return spoofFingerprint;
    }

    /**
     * 取当前 user 的指纹。
     *
     * 只在 spoofFingerprint 打开时才是「假」的 —— 这是刻意的设计：
     * 伪造指纹是最容易被服务端识别的一层，且做错会放大风控
     * （见 {@link Fingerprint} 类注释），所以默认不启用。
     */
    public Fingerprint fingerprintForUser(int userId) {
        return Fingerprint.forUser(userId, seedForUser(userId));
    }

    /** 供自检报告输出：当前实际生效的配置摘要。 */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("verbose=").append(verbose)
          .append(" nativeHooks=").append(nativeHooks)
          .append(" spoofFingerprint=").append(spoofFingerprint)
          .append(" modules={");
        boolean first = true;
        // 只列出被显式关闭的，保持日志简短；全开时输出 modules={all-default-on}
        for (Map.Entry<String, Boolean> e : modules.entrySet()) {
            if (!e.getValue()) {
                if (!first) sb.append(',');
                sb.append(e.getKey()).append("=off");
                first = false;
            }
        }
        if (first) sb.append("all-default-on");
        sb.append("} seeds=").append(fingerprintSeeds.size());
        return sb.toString();
    }

    /** 列出所有被显式配置的模块 id（自检用）。 */
    public java.util.Set<String> configuredModuleIds() {
        return modules.keySet();
    }

    // ------------------------------------------------------------------ io

    private static String readAll(File f) {
        InputStream in = null;
        try {
            in = new FileInputStream(f);
            // 配置文件最多几十字节，但上限保护防止误指到大文件把内存吃光
            long len = f.length();
            if (len > 64 * 1024) return null;
            byte[] buf = new byte[(int) len];
            int off = 0;
            while (off < buf.length) {
                int n = in.read(buf, off, buf.length - off);
                if (n < 0) break;
                off += n;
            }
            return new String(buf, 0, off, "UTF-8");
        } catch (Throwable t) {
            return null;
        } finally {
            if (in != null) {
                try { in.close(); } catch (Throwable ignored) { }
            }
        }
    }

    /** 便于测试：直接给出候选路径列表。
 *  public 是测试可见性需要；它只返回常量数组副本，无副作用。 */
    public static List<String> candidatePaths() {
        java.util.List<String> out = new java.util.ArrayList<String>();
        Collections.addAll(out, CANDIDATES);
        return out;
    }
}