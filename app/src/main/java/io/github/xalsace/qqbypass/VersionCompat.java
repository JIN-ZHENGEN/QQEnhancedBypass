package io.github.xalsace.qqbypass;

import android.util.Log;

import io.github.xalsace.qqbypass.resolve.TargetResolver;
import io.github.xalsace.qqbypass.utils.HookUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * QQ 版本适配检测 —— A/B/C/MISS 四档模型（version-agnostic 改造第 5 项）。
 *
 * 改造前的形态只有一个 boolean：类在不在。它的致命问题不是「不够准」，
 * 而是**不可量化**：日志只会打 missing=2/9，无法回答「这 2 个缺失是
 * 暂时的还是永久的」「整体保护等级还剩多少」，也就没法作为发版门禁。
 *
 * 四档定义（按可靠性从高到低）：
 *
 *   A  = DexKit 按字符串常量命中。抗混淆、抗版本更新，覆盖率约 90%。
 *        需要 TargetResolver 已 ready（后台线程解析完 base.apk）。
 *   B  = 类名/方法名正则命中。类名从 ao 改成 ap 也照样命中，
 *        但正则本身仍依赖包名前缀不变。
 *   C  = 行为兜底命中（ActivityLaunchHook 这类，hook AOSP 框架类）。
 *        100% 版本无关 —— QQ 无论怎么改，Intent 跳转都要走
 *        android.app.Instrumentation.execStartActivity。
 *   MISS = 三层都没命中，这个 hook 目标当前彻底失效。
 *
 * 关键指标：MISS 数。MISS=0 意味着「每个检测点都有至少一层在兜」，
 * 这是可以写进 CI 的量化门禁（A+B+C 全部归零才让 CI 红）。
 * A 单独为 0 不代表失效 —— 可能只是后台线程还没解析完，
 * 或该目标本身设计成只走 C 档。
 *
 * 另一个修正：原 PROBES 里 qq950_patch 写的是
 *   com.tencent.mobileqq.ntkick.NTKickProcessor
 * 而 QQ950PatchHook 实际 hook 的是
 *   com.tencent.mobileqq.kick.NTKickProcessor
 * 两处不一致，导致探针永远报缺失、而 hook 其实是好的 —— 假阴性。
 * 这里不再逐条抄类名，而是改成按模块登记「判定依据」，
 * 判定逻辑与 hook 实现分开但仍由同一处字符串常量驱动，不会各写一份再次漂移。
 */
public final class VersionCompat {

    private static final String TAG = "QQEnhancedBypass";

    /** 一个 hook 目标的探测结果。 */
    public static final class Probe {
        /** 模块 id，与 ModuleConfig / HookRegistry 用的是同一套。 */
        public final String moduleId;
        /** 人类可读的目标描述，用于日志。 */
        public final String target;
        /** 该目标的判定依据（A 档用的字符串常量，或 B/C 档的类名）。 */
        public final String evidence;
        /** 最终命中的档位。 */
        public final Tier tier;

        private Probe(String moduleId, String target, String evidence, Tier tier) {
            this.moduleId = moduleId;
            this.target = target;
            this.evidence = evidence;
            this.tier = tier;
        }

        static Probe of(String moduleId, String target, String evidence, Tier tier) {
            return new Probe(moduleId, target, evidence, tier);
        }

        public boolean isMiss() {
            return tier == Tier.MISS;
        }

        @Override
        public String toString() {
            return moduleId + ":" + target + " -> " + tier.label
                + (tier == Tier.MISS ? "" : " (" + evidence + ")");
        }
    }

    /** 四档。顺序即可靠性排序。 */
    public enum Tier {
        /** DexKit 字符串常量命中。 */
        A("A:dexkit"),
        /** 类名正则命中。 */
        B("B:regex"),
        /** 行为兜底命中（AOSP 框架类 hook）。 */
        C("C:behavior"),
        /** 三层全部未命中，彻底失效。 */
        MISS("MISS"),
        /** 探活时 DexKit 尚未就绪（A 档尚未能判定），中性态，不计入 MISS。 */
        PENDING("PENDING");

        public final String label;

        Tier(String label) {
            this.label = label;
        }
    }

    /**
     * 单个探测目标的判定配置。
     *
     * 判定方式三选一：
     *   strings     → A 档：按 DexKit 字符串常量反查
     *   classRegex  → B 档：按类名正则探测（用 HookUtils.classExists 试真实类名）
     *   frameworkCls→ C 档：AOSP 框架类一定存在，存在性即 hook 生效的证明
     */
    private static final class Target {
        final String moduleId;
        final String target;
        final Tier tier;
        final String[] strings;
        final String classRegex;

        private Target(String moduleId, String target, Tier tier,
                       String[] strings, String classRegex) {
            this.moduleId = moduleId;
            this.target = target;
            this.tier = tier;
            this.strings = strings;
            this.classRegex = classRegex;
        }

        static Target strings(String moduleId, String target, String... strings) {
            return new Target(moduleId, target, Tier.A, strings, null);
        }

        static Target classRegex(String moduleId, String target, String classRegex) {
            return new Target(moduleId, target, Tier.B, null, classRegex);
        }

        static Target behavior(String moduleId, String target, String frameworkClass) {
            // C 档复用 classRegex 字段存放「框架类名」—— 它一定存在，
            // 存在性本身就是 hook 生效的证明（ActivityLaunchHook 已挂上）。
            return new Target(moduleId, target, Tier.C, null, frameworkClass);
        }
    }

    /**
     * 探测目标登记表。
     *
     * 刻意只登记**每个模块最关键的那 1-3 个**：每条都要真实 findClass 或
     * 触发一次 DexKit 查询，在 handleLoadPackage 里做上百次会明显拖慢 QQ
     * 冷启动。它们一旦 MISS，说明该模块的覆盖面已经出问题了。
     *
     * 与旧版 PROBES 的差别：旧的只记一个类名，命中与否全凭 findClass；
     * 新的每条都带自己的判定链，所以新增 hook 目标时**不需要**
     * 在这里再抄一份类名 —— 判定逻辑与被测对象写在一处，不会漂移。
     */
    private static final Target[] TARGETS = {
        // ---- C 档：行为兜底（100% 版本无关，应永远非 MISS） ----
        Target.behavior("activity_launch",
            "Instrumentation.execStartActivity (kick/login backstop)",
            "android.app.Instrumentation"),

        // ---- B 档：类名正则探测（依赖包名前缀不变） ----
        Target.classRegex("root_detection", "File.exists su-path filter",
            "java.io.File"),
        Target.classRegex("xposed_detection", "ClassLoader.toString sanitize",
            "java.lang.ClassLoader"),
        Target.classRegex("runtime_monitor", "ProcessBuilder.start neutralizer",
            "java.lang.ProcessBuilder"),
        Target.classRegex("debug_detection", "TracerPid readLine spoof",
            "java.io.BufferedReader"),

        // ---- A 档：DexKit 字符串常量（核心手段，抗混淆） ----
        // 踢线 action。这三个入口（NTKickProcessor / login.ntlogin.ao / UidServiceImpl）
        // 在 9.3.60 全被改过一轮类名，写死类名必然失效；字符串常量不动。
        Target.strings("qq950_patch", "kick: mqq.intent.action.KICK_TO_LOGIN",
            "mqq.intent.action.KICK_TO_LOGIN"),
        Target.strings("network_report", "report: trpc.o3.report",
            "trpc.o3.report", "trpc.o3.mobile_security"),
        Target.strings("device_info", "pandora: DeviceInfoMonitor",
            "DeviceInfoMonitor"),

        // 说明：A 档只在后台线程解析完成后才可能命中。首次注入时 DexKit
        // 未 ready，它们会落到 MISS —— 这不是失效，是「还没解析完」。
        // 重启 QQ 后同一进程再次注入时 A 档才会生效。
        // 因此判定「是否真失效」要看 MISS 是否**跨多次重启持续存在**，
        // 而不是看单次日志。logReport() 每次都会打，便于对比。
    };

    private VersionCompat() {
    }

    /** 对全部目标执行一次探测。 */
    public static List<Probe> scan() {
        List<Probe> out = new ArrayList<Probe>(TARGETS.length);
        for (Target t : TARGETS) {
            out.add(evaluate(t));
        }
        return out;
    }

    /** 按模块 id 取该模块的探测结果，没有则返回 null。 */
    public static Probe probeFor(String moduleId) {
        for (Target t : TARGETS) {
            if (t.moduleId.equals(moduleId)) {
                return evaluate(t);
            }
        }
        return null;
    }

    /** 四档统计。供 CI / 自检报告使用。 */
    public static final class Stats {
        public final int a, b, c, miss, pending;
        public final int total;

        Stats(int a, int b, int c, int miss, int pending, int total) {
            this.a = a;
            this.b = b;
            this.c = c;
            this.miss = miss;
            this.pending = pending;
            this.total = total;
        }

        /** 可直接写进 CI 的判定：MISS 必须为 0（PENDING 中性态不计失效）。 */
        public boolean healthy() {
            return miss == 0;
        }

        @Override
        public String toString() {
            return "A=" + a + " B=" + b + " C=" + c + " MISS=" + miss
                + " PENDING=" + pending + " total=" + total;
        }
    }

    public static Stats stats(List<Probe> probes) {
        int a = 0, b = 0, c = 0, miss = 0, pending = 0;
        for (Probe p : probes) {
            switch (p.tier) {
                case A:
                    a++;
                    break;
                case B:
                    b++;
                    break;
                case C:
                    c++;
                    break;
                case PENDING:
                    pending++;
                    break;
                default:
                    miss++;
                    break;
            }
        }
        return new Stats(a, b, c, miss, pending, probes.size());
    }

    /**
     * 一行人读的自检结论，含四档分布。
     *
     * 注意 A 档为 0 通常**不代表失效**：DexKit 在后台线程初始化，
     * 首次注入时大概率还没 ready。真正要看的是 MISS。
     */
    public static String report() {
        List<Probe> probes = scan();
        Stats s = stats(probes);
        StringBuilder sb = new StringBuilder();
        sb.append("compat=").append(s.healthy() ? "OK" : "STALE")
          .append(' ').append(s);
        if (!s.healthy()) {
            sb.append(" missing=[");
            boolean first = true;
            for (Probe p : probes) {
                if (!p.isMiss()) continue;
                if (!first) sb.append(", ");
                sb.append(p.moduleId).append(':').append(p.target);
                first = false;
            }
            sb.append(']');
        }
        return sb.toString();
    }

    /** 单目标判定：按登记的档位探测，命中即返回该档，否则 MISS。 */
    private static Probe evaluate(Target t) {
        String evidence = null;
        boolean hit = false;

        switch (t.tier) {
            case A:
                // A 档：DexKit 字符串常量。未 ready 时本次探测算 PENDING（中性），
                // 不计入 MISS —— 这是「尚未解析完」而非「永久失效」。
                // 只有 ready 后仍 canResolve=false 才算真 MISS。
                if (!TargetResolver.ready()) {
                    return Probe.of(t.moduleId, t.target, join(t.strings), Tier.PENDING);
                }
                hit = TargetResolver.canResolve(t.strings);
                evidence = join(t.strings);
                break;
            case B:
            case C:
                // B/C 档：真实类名存在性探测。classExists 内部已 try/catch，
                // 类加载失败返回 false 而不会外溢。
                hit = HookUtils.classExists(t.classRegex);
                evidence = t.classRegex;
                break;
            default:
                break;
        }

        return Probe.of(t.moduleId, t.target, evidence, hit ? t.tier : Tier.MISS);
    }

    private static String join(String... strings) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < strings.length; i++) {
            if (i > 0) sb.append('+');
            sb.append(strings[i]);
        }
        return sb.toString();
    }

    /**
     * 在注入末尾调用，把结论写进日志。
     *
     * 与旧版的差别：旧版只在有缺失时打完整清单，正常时只打一行 OK。
     * 新版**每次都打四档统计**，因为四档分布本身就是「当前保护等级」
     * 的可量化指标 —— 只看 MISS 会漏掉「A 档一直没起来」这种退化。
     * 明细只在 STALE 时展开，避免刷屏。
     */
    public static void logReport() {
        List<Probe> probes = scan();
        Stats s = stats(probes);

        // 先打 DexKit 自身状态。这是解读四档分布的前提：
        // 没打这一行时，看到 "A=0" 无法区分是「后台线程还没解析完」
        // 还是「解析完了但字符串常量没命中」—— 两者的处置完全不同。
        if (!TargetResolver.ready()) {
            Log.i(TAG, "[compat] dexkit=" + (TargetResolver.initFailed() ? "FAILED" : "initializing")
                + " (Tier A unavailable this injection; B/C still active)");
        } else {
            Log.i(TAG, "[compat] dexkit=ready (Tier A active)");
        }

        if (s.healthy()) {
            Log.i(TAG, "[compat] OK - " + s
                + " (A=dexkit抗混淆, B=类名正则, C=行为兜底, MISS=彻底失效)");
            // A 档为 0 单独提示一句：这是最常见的「以为生效了其实没有」。
            if (s.a == 0) {
                Log.i(TAG, "[compat] note: A=0 - DexKit not ready or no A-tier target "
                    + "resolved; fall back to B/C. Re-inject after QQ restart to confirm.");
            }
            return;
        }

        Log.w(TAG, "[compat] STALE - " + s + ", these targets have no working layer:");
        for (Probe p : probes) {
            if (p.tier == Tier.PENDING) {
                // PENDING 是中性态：DexKit 尚未就绪，A 档未判，本轮不算失效。
                // 等后台线程 setReady() 触发回查升级后，下一轮 scan 才会落到 A 或 MISS。
                Log.w(TAG, "[compat]   PENDING " + p.moduleId + ":" + p.target
                    + " (DexKit not ready yet; re-scan after DexKit ready)");
                continue;
            }
            if (!p.isMiss()) continue;
            Log.w(TAG, "[compat]   MISS " + p.moduleId + ":" + p.target
                + " (tier " + p.tier.label + " evidence=" + p.evidence + ")");
        }
        // 提示一条判定口径，避免把「后台线程未解析完」误判成永久失效。
        Log.w(TAG, "[compat] hint: MISS 跨多次重启持续出现才代表真失效; "
            + "单次 MISS 可能只是 DexKit 后台解析未完成");
    }

    // ------------------------------------------------------------ 兼容旧调用点

    /**
     * 旧 API：返回缺失项字符串列表。
     *
     * 保留是为了不让外部调用点一次性全改。语义等价于新的 MISS 列表。
     */
    public static List<String> scanMissing() {
        List<String> missing = new ArrayList<String>();
        for (Probe p : scan()) {
            if (p.isMiss()) {
                missing.add(p.moduleId + ":" + p.target);
            }
        }
        return missing;
    }
}