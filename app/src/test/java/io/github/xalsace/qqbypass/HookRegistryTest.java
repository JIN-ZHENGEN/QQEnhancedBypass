package io.github.xalsace.qqbypass;

import org.junit.Test;

import java.util.List;

import io.github.xalsace.qqbypass.config.ModuleConfig;
import io.github.xalsace.qqbypass.hooks.HookModule;
import io.github.xalsace.qqbypass.hooks.HookRegistry;
import io.github.xalsace.qqbypass.hooks.HookResult;
import io.github.xalsace.qqbypass.utils.HookCounters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * 注册表的行为测试。
 *
 * 重点验的是改造前那个最致命的缺陷：**一个 hook 抛异常会带走后面所有 hook**。
 * 原实现把 8 次调用包在同一个 try 里，第 3 个炸了后 5 个静默跳过，
 * 日志只有一行 —— 这正是「模块装了但保护等级莫名其妙掉到 30%」的成因。
 */
public class HookRegistryTest {

    /** 测试替身：可配置是否抛异常、是否记 hook 计数。 */
    private static class FakeModule implements HookModule {
        final String id;
        final boolean enabled;
        final boolean throwOnHook;
        final int hooksToRecord;
        boolean ran = false;

        FakeModule(String id, boolean enabled, boolean throwOnHook, int hooksToRecord) {
            this.id = id;
            this.enabled = enabled;
            this.throwOnHook = throwOnHook;
            this.hooksToRecord = hooksToRecord;
        }

        @Override public String id() { return id; }
        @Override public String displayName() { return "fake:" + id; }

        @Override
        public boolean isEnabled(ModuleConfig cfg) { return enabled; }

        @Override
        public void hook(de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam lpparam) {
            ran = true;
            for (int i = 0; i < hooksToRecord; i++) {
                HookCounters.recordHooked();
            }
            if (throwOnHook) {
                throw new RuntimeException("boom from " + id);
            }
        }
    }

    /**
     * 核心用例：中间模块炸掉，前后模块必须照常执行。
     * 改造前这条会失败（b、c 被静默跳过）。
     */
    @Test
    public void failureIsIsolated() {
        FakeModule a = new FakeModule("a", true, false, 2);
        FakeModule b = new FakeModule("b", true, true, 0);   // 抛异常
        FakeModule c = new FakeModule("c", true, false, 3);

        HookRegistry r = new HookRegistry();
        r.register(a).register(b).register(c);

        List<HookResult> rs = r.runAll(null);

        assertEquals(3, rs.size());
        assertTrue("a 应该执行过", a.ran);
        assertTrue("b 应该执行过（在抛异常前）", b.ran);
        assertTrue("c 必须执行 —— 这正是改造要修的核心问题", c.ran);

        assertEquals(HookResult.Status.OK, rs.get(0).status());
        assertEquals(HookResult.Status.FAILED, rs.get(1).status());
        assertEquals(HookResult.Status.OK, rs.get(2).status());

        // 计数差值：a 记了 2 个 hook，c 记了 3 个
        assertEquals(2, rs.get(0).hooked());
        assertEquals(3, rs.get(2).hooked());
    }

    /** 关闭的模块不执行，且状态是 DISABLED。 */
    @Test
    public void disabledModuleIsSkipped() {
        FakeModule off = new FakeModule("off", false, false, 5);
        HookRegistry r = new HookRegistry();
        r.register(off);

        List<HookResult> rs = r.runAll(null);
        assertEquals(1, rs.size());
        assertEquals(HookResult.Status.DISABLED, rs.get(0).status());
        assertFalse("关闭的模块不应执行", off.ran);
        assertEquals(0, rs.get(0).hooked());
    }

    /** isEnabled 自身抛异常时按「启用」处理 —— 宁可多 hook 不可失保护。 */
    @Test
    public void enabledCheckFailureFailsOpen() {
        HookModule m = new HookModule() {
            @Override public String id() { return "weird"; }
            @Override public String displayName() { return "weird"; }
            @Override public boolean isEnabled(ModuleConfig cfg) { throw new RuntimeException("nope"); }
            @Override
            public void hook(de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam p) { }
        };
        HookRegistry r = new HookRegistry();
        r.register(m);
        List<HookResult> rs = r.runAll(null);
        assertEquals("开关判断出错应视为启用", HookResult.Status.OK, rs.get(0).status());
    }

    /** 重复 id 覆盖：后注册者生效。 */
    @Test
    public void duplicateIdOverwrites() {
        HookRegistry r = new HookRegistry();
        FakeModule first = new FakeModule("dup", true, false, 0);
        FakeModule second = new FakeModule("dup", true, false, 0);
        r.register(first).register(second);

        assertEquals(1, r.size());
        assertFalse(first.ran);
        r.runAll(null);
        assertFalse("被覆盖的模块不应执行", first.ran);
        assertTrue(second.ran);
    }

    /** 空注册表不炸，summarize 有兜底文案。 */
    @Test
    public void emptyRegistryIsSafe() {
        HookRegistry r = new HookRegistry();
        List<HookResult> rs = r.runAll(null);
        assertTrue(rs.isEmpty());
        assertEquals(0, r.size());
        assertNull(r.get("nothing"));
        assertEquals("no-modules", HookRegistry.summarize(rs));
    }

    /** summarize 统计各状态数量。 */
    @Test
    public void summarizeCounts() {
        HookRegistry r = new HookRegistry();
        r.register(new FakeModule("ok1", true, false, 4));
        r.register(new FakeModule("bad", true, true, 0));
        r.register(new FakeModule("off", false, false, 0));

        List<HookResult> rs = r.runAll(null);
        String s = HookRegistry.summarize(rs);
        assertTrue(s.contains("modules=3"));
        assertTrue(s.contains("hooked=4"));
        assertTrue(s.contains("failed=1"));
        assertTrue(s.contains("disabled=1"));
        assertTrue(s.contains("failedIds=[bad]"));
    }

    /** 默认注册表包含全部 hook 类（含 version-agnostic 改造新增的 activity_launch），且 id 唯一。 */
    @Test
    public void defaultRegistryContainsLegacyHooks() {
        HookRegistry r = HookRegistry.createDefault();
        List<String> ids = r.ids();
        assertEquals(8, ids.size());
        assertTrue(ids.contains("network_report"));
        assertTrue(ids.contains("root_detection"));
        assertTrue(ids.contains("xposed_detection"));
        assertTrue(ids.contains("device_info"));
        assertTrue(ids.contains("debug_detection"));
        assertTrue(ids.contains("runtime_monitor"));
        assertTrue(ids.contains("qq950_patch"));
        assertTrue(ids.contains("activity_launch"));
        assertEquals("id 应唯一", ids.size(), new java.util.HashSet<String>(ids).size());
        for (String id : ids) {
            assertNotNull(r.get(id));
        }
    }
}