package io.github.xalsace.qqbypass.utils;

/**
 * 进程内的 hook 成功/跳过计数器。
 *
 * 为什么单独成一个类、且刻意不 import 任何 Xposed / android 类型：
 * 计数器要被 {@link io.github.xalsace.qqbypass.hooks.HookRegistry} 在纯 JVM
 * 单元测试里读写。Xposed API 在 Gradle 工程里是 compileOnly（由框架在运行时
 * 提供），不会出现在 test classpath 上 —— 只要注册表间接引用到它，单测就会
 * 以 NoClassDefFoundError 崩掉。把它隔离出来，注册表和单测就都干净了。
 *
 * 计数语义（对应路线图第 1 项「多模块 hook 框架」的可观测性要求）：
 * hooked   = 确实 hook 住的方法数
 * skipped  = 因类/方法不存在而跳过的数量（QQ 改版改名时这个数会涨，是适配信号）
 */
public final class HookCounters {

    private static volatile long hooked = 0L;
    private static volatile long skipped = 0L;

    private HookCounters() {
    }

    public static void recordHooked() {
        hooked++;
    }

    public static void recordSkipped() {
        skipped++;
    }

    public static long snapshotHooked() {
        return hooked;
    }

    public static long snapshotSkipped() {
        return skipped;
    }

    public static int deltaHooked(long snapshot) {
        long d = hooked - snapshot;
        return d < 0L ? 0 : (d > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) d);
    }

    public static int deltaSkipped(long snapshot) {
        long d = skipped - snapshot;
        return d < 0L ? 0 : (d > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) d);
    }
}
