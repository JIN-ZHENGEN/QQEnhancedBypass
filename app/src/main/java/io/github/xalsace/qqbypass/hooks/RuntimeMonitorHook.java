package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.config.HookConfig;
import io.github.xalsace.qqbypass.resolve.TieredHook;

/**
 * Runtime Monitor Bypass
 *
 * Handles Pandora RuntimeMonitor which monitors:
 * - Runtime.exec() calls for suspicious commands (ip, pm, getprop, sh)
 * - Command outputs via ProcessBuilder
 * - System command execution patterns
 *
 * Also handles various command processors:
 * - IPProcessor
 * - PackageManagerProcessor
 * - PropProcessor
 *
 * 本文件与上一版的差别：
 *  1. 降级接入：ProcessBuilder.start 是 AOSP 框架类（installFixed，C 档）；
 *     Pandora 的 RuntimeMonitor 与三个 Processor 是业务类，走三级降级
 *     （A 档按方法体里的字符串常量反查，B 档类名正则，C 档写死类名）。
 *  2. 通配符收敛：原实现用 hookAllMethods(cls, "exec") —— exec 在
 *     RuntimeMonitor 里有 6 个重载，全部 hook 会产生 6 倍无用回调。
 *     现在由 TieredHook.install 统一处理，C 档同样 hookAllMethods
 *     （重载数量少且签名统一，可接受），但 A/B 档会按 DexKit 精确定位
 *     到具体某一个重载，不再盲目全挂。
 *  3. MISS 显式化：任一层都没挂上时打日志，不再静默 recordSkipped。
 */
public final class RuntimeMonitorHook {

    private static final String[] MONITORED_COMMANDS = {
        "ip", "pm", "getprop", "sh", "/system/bin/sh",
        "ps", "cat", "mount", "which", "su"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_RUNTIME_BYPASS) return;

        XposedEntry.log("Initializing Runtime Monitor Bypass");

        hookPandoraRuntimeMonitor(lpparam);
        hookCommandProcessors(lpparam);
        hookProcessBuilder(lpparam);
    }

    // ------------------------------------------------------------------ 1

    /**
     * Pandora RuntimeMonitor 的 exec / execute 观察。
     *
     * CORRECTED for QQ 9.3.50 (verified by parsing the dex class_data):
     * RuntimeMonitor has NO monitor()/onExec(). Its real methods are:
     *   exec (x6 overloads), execute, isInspect.
     * The previous monitor/onExec hooks matched ZERO methods (silent no-op:
     * XposedBridge.hookAllMethods logs success even when it hooks nothing).
     *
     * exec() internally delegates to Runtime.exec, which we ALREADY hook at the
     * framework level (and safely fake output there). So we do NOT override exec's
     * return value here (it returns a Process - wrong-typed setResult would crash,
     * same class of bug as getStrategyAndReport). We OBSERVE only, to surface what
     * commands actually flow through Pandora's monitor - key diagnostics for the
     * delayed risk-control detection.
     *
     * A 档依据：exec/execute 方法体里引用了这些命令名字符串常量。
     */
    private static void hookPandoraRuntimeMonitor(XC_LoadPackage.LoadPackageParam lpparam) {
        final String cls = "com.tencent.qmethod.pandoraex.monitor.RuntimeMonitor";

        TieredHook.Install r = TieredHook.installAC(
            new String[]{"RuntimeMonitor"},
            cls, "exec",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    logCommandArgs("RuntimeMonitor.exec", param.args);
                }
            });
        if (!r.ok()) XposedEntry.log("[runtime] RuntimeMonitor.exec MISS: " + r);

        r = TieredHook.installAC(
            new String[]{"RuntimeMonitor"},
            cls, "execute",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    logCommandArgs("RuntimeMonitor.execute", param.args);
                }
            });
        if (!r.ok()) XposedEntry.log("[runtime] RuntimeMonitor.execute MISS: " + r);
    }

    // ------------------------------------------------------------------ 2

    /**
     * 三个命令处理器的 transform 观察。
     *
     * CORRECTED for QQ 9.3.50: the three RuntimeMonitor$XxxProcessor classes have
     * NO process() method. They implement RuntimeProcessor with transform() + getType().
     * The previous .process hooks were silent no-ops (0 methods matched).
     * transform() returns processed command output QQ consumes, so OBSERVE only
     * (no setResult - no ClassCastException / breakage).
     */
    private static void hookCommandProcessors(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] processors = {
            "com.tencent.qmethod.pandoraex.monitor.RuntimeMonitor$IPProcessor",
            "com.tencent.qmethod.pandoraex.monitor.RuntimeMonitor$PackageManagerProcessor",
            "com.tencent.qmethod.pandoraex.monitor.RuntimeMonitor$PropProcessor"
        };
        for (String processor : processors) {
            final String shortName = processor.substring(processor.lastIndexOf('$') + 1);
            TieredHook.Install r = TieredHook.installAC(
                new String[]{"RuntimeMonitor"},
                processor, "transform",
                lpparam.classLoader,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        logCommandArgs(shortName + ".transform", param.args);
                    }
                });
            if (!r.ok()) XposedEntry.log("[runtime] " + shortName + ".transform MISS: " + r);
        }
    }

    private static void logCommandArgs(String tag, Object[] args) {
        if (args == null) return;
        for (Object arg : args) {
            if (arg == null) continue;
            String s;
            if (arg instanceof String[]) {
                s = java.util.Arrays.toString((String[]) arg);
            } else {
                s = arg.toString();
            }
            if (isMonitoredCommand(s)) {
                XposedEntry.log(tag + " observed monitored command: " + s);
            }
        }
    }

    // ------------------------------------------------------------------ 3

    /**
     * ProcessBuilder.start() 原地中性化。
     *
     * 这是整个模块里唯一真正**阻断**检测的一层，其余都是观察。
     *
     * ProcessBuilder.start() is the UNIVERSAL choke point for command execution:
     * Runtime.exec() and Pandora RuntimeMonitor.exec() both funnel through it
     * (verified in runtime logs - every `type su` probe passes here).
     *
     * EVIDENCE (kick log 22_08-18-33-32): QQ ran `/system/bin/sh -c type su`
     * 130+ times over ~97 min. It was only OBSERVED, never blocked, so `type su`
     * returned the real result (su found) every time - root reported - server
     * force-logout. This neutralizes those probes.
     *
     * 实现要点（这是正确解法，上一版已对，本版保留并补降级）：
     * 把命令**原地改写**成一个无害的 `exit 1`，让真实的 start() 继续跑。
     * 这样返回的是一个真的 Process 对象，stdout 为空、退出码非零 ——
     * 正好就是未 root 设备上 `type su` / `which su` 的真实表现。
     * 不 fake Process 对象（避免递归进本 hook），也不 setResult 假值。
     */
    private static void hookProcessBuilder(XC_LoadPackage.LoadPackageParam lpparam) {
        // AOSP 框架类，名字从 4.x 到 16 没变过，走纯 C 档。
        TieredHook.Install r = TieredHook.installFixed(
            "java.lang.ProcessBuilder", "start",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    ProcessBuilder pb = (ProcessBuilder) param.thisObject;
                    java.util.List<String> command = pb.command();
                    if (command == null || command.isEmpty()) return;

                    String joined = joinCommand(command);

                    if (isRootProbe(joined)) {
                        pb.command("/system/bin/sh", "-c", "exit 1");
                        XposedEntry.log("Neutralized ProcessBuilder root probe: " + joined);
                    } else if (isMonitoredCommand(joined)) {
                        XposedEntry.log("ProcessBuilder command intercepted: " + joined);
                    }
                }
            });

        if (!r.ok()) {
            // 连 java.lang.ProcessBuilder 都挂不上，说明模块自身出了问题
            // （ProGuard 裁掉了引用），必须显式报出来。
            XposedEntry.logError("[runtime] ProcessBuilder.start FAILED: " + r, null);
        } else {
            XposedEntry.log("[runtime] ProcessBuilder.start installed via tier " + r);
        }
    }

    private static String joinCommand(java.util.List<String> command) {
        StringBuilder sb = new StringBuilder();
        for (String part : command) {
            if (part == null) continue;
            if (sb.length() > 0) sb.append(' ');
            sb.append(part);
        }
        return sb.toString();
    }

    /**
     * Unambiguous root / root-manager probes that are safe to neutralize.
     * Kept narrow (token-level "su" + known root-manager names) so legitimate
     * shell commands QQ needs are never rewritten.
     */
    private static boolean isRootProbe(String joined) {
        if (joined == null) return false;
        String s = joined.toLowerCase();
        // Known root-manager names + explicit su binary paths (verified present in
        // QQ 9.3.50 dex: /system/bin/su, /system/xbin/su, /sbin/su, /su/bin/su).
        if (s.contains("magisk") || s.contains("supersu") || s.contains("superuser")
                || s.contains("busybox") || s.contains("ksud")
                || s.contains("which su") || s.contains("type su") || s.contains("command -v su")
                || s.contains("/system/bin/su") || s.contains("/system/xbin/su")
                || s.contains("/sbin/su") || s.contains("/su/bin")
                || s.contains("/data/local/su")) {
            return true;
        }
        // standalone "su" token (matches `su`, `type su`, `sh -c su`; not `sudo`, `pull`,
        // and not benign paths that merely contain the substring "su").
        for (String tok : s.split("\\s+")) {
            if (tok.equals("su")) return true;
        }
        return false;
    }

    private static boolean isMonitoredCommand(String command) {
        if (command == null) return false;

        for (String monitored : MONITORED_COMMANDS) {
            if (command.contains(monitored)) {
                return true;
            }
        }
        return false;
    }
}