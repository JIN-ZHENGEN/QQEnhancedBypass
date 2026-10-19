package io.github.xalsace.qqbypass;

import org.junit.Test;

import io.github.xalsace.qqbypass.config.ModuleConfig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * 运行时配置的健壮性测试。
 *
 * 最重要的性质是：**任何畸形输入都不能抛异常**。
 * ModuleConfig.get() 在 handleLoadPackage 的最早期被调用，一次抛错就会
 * 打断整个注入流程、让所有 hook 静默失效 —— 这是比配置没生效严重得多的故障。
 */
public class ModuleConfigTest {

    /**
     * 全默认：所有模块开、不伪造、安静、native 关。
     *
     * native 这里断言为 false 是有意的，它把「默认行为」钉在测试里。
     * 曾短暂改为 true（v1.0.8），真机随即被判定异常：ByteHook 的 GOT hook
     * 改写了反欺诈库自身的 GOT 表项，而它们的自检正是扫这一项。
     * 若哪天要重新开启，必须同时改这里和 ModuleConfig.defaults()，
     * 否则测试会立刻提醒你两处不一致。
     */
    @Test
    public void defaultsAreSafe() {
        ModuleConfig c = ModuleConfig.defaults();
        assertTrue("未配置的模块默认启用", c.isModuleEnabled("anything"));
        assertFalse("默认不伪造指纹", c.isSpoofFingerprintEnabled());
        assertFalse("默认关 native（GOT hook 会触发反欺诈库自检）", c.isNativeHooksEnabled());
        assertFalse("默认不打印冗余日志", c.isVerbose());
        assertNull(c.seedForUser(0));
        assertNotNull(c.describe());
    }

    /** native 可以被配置文件显式关掉 —— 真机上出问题的退路。 */
    @Test
    public void nativeCanBeDisabledByConfig() {
        ModuleConfig c = ModuleConfig.fromJson("{\"nativeHooks\": false}");
        assertFalse("配置显式关闭时必须真的关掉", c.isNativeHooksEnabled());
        // 关掉 native 不应该顺手把别的默认值也影响掉
        assertTrue(c.isModuleEnabled("root_detection"));
        assertFalse(c.isSpoofFingerprintEnabled());
    }

    /** native 也可以被配置文件显式打开 —— 与上一条互为镜像，保证开关双向有效。 */
    @Test
    public void nativeCanBeEnabledByConfig() {
        ModuleConfig c = ModuleConfig.fromJson("{\"nativeHooks\": true}");
        assertTrue("配置显式开启时必须真的打开", c.isNativeHooksEnabled());
        assertTrue(c.isModuleEnabled("root_detection"));
        assertFalse(c.isSpoofFingerprintEnabled());
    }

    /** 空 JSON 对象 = 全默认，不抛异常。 */
    @Test
    public void emptyObjectIsDefaults() {
        ModuleConfig c = ModuleConfig.fromJson("{}");
        assertTrue(c.isModuleEnabled("x"));
        assertFalse(c.isSpoofFingerprintEnabled());
        assertFalse("空配置必须与 defaults() 一致（native 关）", c.isNativeHooksEnabled());
    }

    /** 完全不是 JSON —— 必须回落到默认，绝不抛出。 */
    @Test
    public void garbageNeverThrows() {
        String[] bad = {
            "",
            "   ",
            "not json at all",
            "{",
            "}",
            "[1,2,3]",
            "null",
            "{\"modules\":",
            "<<<>>>",
            "\\u0000\\u0001"
        };
        for (String s : bad) {
            ModuleConfig c = ModuleConfig.fromJson(s);
            assertNotNull("输入 [" + s + "] 应得到非 null 配置", c);
            assertTrue("输入 [" + s + "] 应保持模块默认启用", c.isModuleEnabled("whatever"));
        }
    }

    /** 单项关掉某个模块，其余保持默认启用。 */
    @Test
    public void moduleCanBeDisabledIndividually() {
        ModuleConfig c = ModuleConfig.fromJson(
            "{\"modules\":{\"root_detection\":false,\"network_report\":true}}");
        assertFalse(c.isModuleEnabled("root_detection"));
        assertTrue(c.isModuleEnabled("network_report"));
        assertTrue("未提及的模块仍默认启用", c.isModuleEnabled("device_info"));
    }

    /** modules 里的非布尔值被忽略（不崩、也不误关闭）。 */
    @Test
    public void nonBooleanModuleValueIsIgnored() {
        ModuleConfig c = ModuleConfig.fromJson(
            "{\"modules\":{\"a\":\"yes\",\"b\":1,\"c\":null,\"d\":false}}");
        assertTrue("字符串true以外的取值不应被当成 true/false 误判，" +
                   "该项应回落到默认启用", c.isModuleEnabled("a"));
        assertTrue(c.isModuleEnabled("b"));
        assertTrue(c.isModuleEnabled("c"));
        assertFalse("明确的 false 应当生效", c.isModuleEnabled("d"));
    }

    /** fingerprint seed 按 user 读取。 */
    @Test
    public void seedIsReadPerUser() {
        ModuleConfig c = ModuleConfig.fromJson(
            "{\"fingerprint\":{\"0\":\"aaa\",\"999\":\"bbb\"}}");
        assertEquals("aaa", c.seedForUser(0));
        assertEquals("bbb", c.seedForUser(999));
        assertNull("未配置的 user 没有 seed", c.seedForUser(5));
    }

    /** fingerprint 的 key 不是数字时忽略该项，不影响其他 key。 */
    @Test
    public void nonNumericSeedKeyIsIgnored() {
        ModuleConfig c = ModuleConfig.fromJson(
            "{\"fingerprint\":{\"abc\":\"x\",\"0\":\"real\"}}");
        assertEquals("real", c.seedForUser(0));
    }

    /** 顶层开关生效。 */
    @Test
    public void topLevelFlagsApply() {
        ModuleConfig c = ModuleConfig.fromJson(
            "{\"verbose\":true,\"nativeHooks\":true,\"spoofFingerprint\":true}");
        assertTrue(c.isVerbose());
        assertTrue(c.isNativeHooksEnabled());
        assertTrue(c.isSpoofFingerprintEnabled());
    }

    /** 部分字段损坏时，其余字段仍然生效（不是整体作废）。 */
    @Test
    public void partialDamageKeepsRestWorking() {
        ModuleConfig c = ModuleConfig.fromJson(
            "{\"modules\":{\"a\":false},\"verbose\":\"notabool\"," +
            "\"nativeHooks\":true,\"unknownKey\":{\"deep\":[1,2]}}");
        assertFalse(c.isModuleEnabled("a"));
        assertFalse("坏掉的 verbose 回落到默认 false", c.isVerbose());
        assertTrue("其余开关照常生效", c.isNativeHooksEnabled());
    }

    /** describe() 摘要包含关键开关状态，供自检日志使用。 */
    @Test
    public void describeSummarizesState() {
        ModuleConfig def = ModuleConfig.defaults();
        String d = def.describe();
        assertTrue(d.contains("verbose="));
        assertTrue(d.contains("nativeHooks="));
        assertTrue(d.contains("spoofFingerprint="));
        assertTrue("全默认时应显示 all-default-on", d.contains("all-default-on"));

        String d2 = ModuleConfig.fromJson("{\"modules\":{\"a\":false}}").describe();
        assertTrue("被关闭的模块应出现在摘要里", d2.contains("a=off"));
        assertFalse(d2.contains("all-default-on"));
    }

    /** 配置的 listUnixDatagrams —— 候选路径至少有一个，且都非空。 */
    @Test
    public void candidatePathsAreSane() {
        java.util.List<String> paths = ModuleConfig.candidatePaths();
        assertNotNull(paths);
        assertFalse(paths.isEmpty());
        for (String p : paths) {
            assertNotNull(p);
            assertTrue(p.length() > 0);
        }
    }
}