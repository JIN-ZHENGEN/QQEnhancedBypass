package io.github.xalsace.qqbypass.hooks;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.config.ModuleConfig;

/**
 * 一个可插拔的 hook 模块（路线图第 1 项：Java 层多模块 hook）。
 *
 * 改造前 XposedEntry.handleLoadPackage 里是 8 次硬编码的静态调用，
 * 被一个 try 整体包住 —— 任意一个 hook 抛异常，后面所有 hook 全部跳过，
 * 只留一行日志，表现为「模块装了但保护等级静默掉到 30%」。
 *
 * 这个接口把「注册 / 开关 / 执行 / 结果」四件事分离，由 {@link HookRegistry}
 * 统一驱动，单模块失败不再影响其他模块。
 */
public interface HookModule {

    /** 稳定 id，用于配置文件里的开关键，以及自检报告。 */
    String id();

    /** 人类可读名，只用于日志。 */
    String displayName();

    /** 是否启用。默认实现读配置；未配置的模块默认启用。 */
    boolean isEnabled(ModuleConfig cfg);

    /**
     * 执行 hook。
     *
     * 实现类应当「尽力而为」：某个具体方法找不到（QQ 改版改名）不应该抛异常，
     * 而应该由 {@link io.github.xalsace.qqbypass.utils.HookUtils} 内部记一笔
     * 并继续下一个 —— 这样 {@code skipped} 计数才有意义。
     */
    void hook(XC_LoadPackage.LoadPackageParam lpparam);
}