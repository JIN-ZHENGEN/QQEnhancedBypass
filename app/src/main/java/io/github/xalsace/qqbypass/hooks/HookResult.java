package io.github.xalsace.qqbypass.hooks;

/**
 * 单个 hook 模块的执行结果。
 *
 * 存在的意义是让「保护到底生效没有」变成可观测的量，而不是靠人肉翻 logcat。
 * 每次注入结束后由 SelfTestReport 汇总落盘。
 */
public final class HookResult {

    public enum Status {
        /** 按预期执行完毕，没有致命异常。 */
        OK,
        /** 被配置文件显式关闭。 */
        DISABLED,
        /** 模块自身抛出了未预期异常（被注册表捕获隔离）。 */
        FAILED
    }

    private final String moduleId;
    private final Status status;
    /** 实际成功 hook 住的方法数。 */
    private final int hooked;
    /** 因为类/方法不存在而跳过的数量 —— QQ 改版时这个数会涨。 */
    private final int skipped;
    private final Throwable error;
    private final long durationMs;

    HookResult(String moduleId, Status status, int hooked, int skipped, Throwable error, long durationMs) {
        this.moduleId = moduleId;
        this.status = status;
        this.hooked = hooked;
        this.skipped = skipped;
        this.error = error;
        this.durationMs = durationMs;
    }

    static HookResult ok(String id, int hooked, int skipped, long ms) {
        return new HookResult(id, Status.OK, hooked, skipped, null, ms);
    }

    static HookResult disabled(String id) {
        return new HookResult(id, Status.DISABLED, 0, 0, null, 0L);
    }

    static HookResult failed(String id, Throwable t, long ms) {
        return new HookResult(id, Status.FAILED, 0, 0, t, ms);
    }

    public String moduleId() { return moduleId; }
    public Status status() { return status; }
    public int hooked() { return hooked; }
    public int skipped() { return skipped; }
    public Throwable error() { return error; }
    public long durationMs() { return durationMs; }

    public boolean isOk() { return status == Status.OK; }

    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append(moduleId).append('=').append(status.name().toLowerCase());
        if (status == Status.OK) {
            sb.append("(hooked=").append(hooked).append(",skipped=").append(skipped).append(')');
        }
        if (error != null) {
            String m = error.getMessage();
            sb.append(" err=").append(m == null ? error.getClass().getSimpleName() : m);
        }
        return sb.toString();
    }
}