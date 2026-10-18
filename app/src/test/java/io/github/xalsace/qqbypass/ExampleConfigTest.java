package io.github.xalsace.qqbypass;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

import io.github.xalsace.qqbypass.config.Json;
import io.github.xalsace.qqbypass.config.ModuleConfig;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * 校验随仓库分发的配置示例本身是合法的。
 *
 * 这条测试防的是一件很具体的事：我们写了一份带注释的 qqbypass.json.example
 * 给用户照抄，但如果里面有个手滑的逗号或引号，用户复制过去就得到一个
 * 完全无效的配置文件 —— 而 ModuleConfig 出于「绝不因配置问题打断注入」的设计
 * 会静默回落到默认值，用户完全不会知道自己的配置没生效。
 *
 * 所以示例必须在 CI 里被真正解析一遍。
 */
public class ExampleConfigTest {

    private static final String[] CANDIDATES = {
        "docs/qqbypass.json.example",
        "../docs/qqbypass.json.example",
        "app/../docs/qqbypass.json.example"
    };

    @Test
    public void exampleConfigParses() throws Exception {
        File f = findExample();
        assertNotNull("应能在仓库里找到 docs/qqbypass.json.example", f);

        String text = readAll(f);
        // 1. 必须是合法 JSON
        Object parsed = Json.parse(text);
        assertNotNull("示例配置应能解析出对象", Json.asObject(parsed));

        // 2. 必须能被 ModuleConfig 正确读取（不因结构问题整体作废）
        ModuleConfig cfg = ModuleConfig.fromJson(text);
        assertNotNull(cfg);

        // 3. 示例里的默认值意图必须成立：默认不动指纹、不默认开 native。
        //    这两项是安全相关默认值，示例一旦写成 true 就是误导用户。
        assertFalse("示例不应默认开启指纹伪造", cfg.isSpoofFingerprintEnabled());
        assertFalse("示例不应默认开启未验证的 native hook", cfg.isNativeHooksEnabled());

        // 4. 示例里列出的 7 个模块 id 都应与注册表实际 id 一致 ——
        //    改了 HookRegistry 的 id 却忘了改示例，用户照抄就会配了个不存在
        //    的键（静默无效）。这条把两者钉在一起。
        java.util.Map<String, Object> mods =
            Json.asObject(Json.asObject(parsed).get("modules"));
        assertNotNull("示例应含 modules 段", mods);
        java.util.List<String> registryIds =
            io.github.xalsace.qqbypass.hooks.HookRegistry.createDefault().ids();
        for (String key : mods.keySet()) {
            if (key.startsWith("_")) continue;   // 跳过 _comment 之类
            assertTrue("示例里的模块 id [" + key + "] 在注册表中不存在",
                registryIds.contains(key));
        }
        // 反向：注册表里每个模块都应在示例中出现（保证文档完整）
        for (String id : registryIds) {
            assertTrue("注册表模块 [" + id + "] 未在配置示例中列出", mods.containsKey(id));
        }

        // 5. 指纹示例必须给不同 user 不同 seed —— 这正是双开串号反模式的反面教材
        java.util.Map<String, Object> fp =
            Json.asObject(Json.asObject(parsed).get("fingerprint"));
        assertNotNull("示例应含 fingerprint 段", fp);
        String s0 = Json.asString(fp.get("0"), null);
        String s999 = Json.asString(fp.get("999"), null);
        assertNotNull(s0);
        assertNotNull(s999);
        assertFalse("示例必须给 u0 与 u999 不同的 seed", s0.equals(s999));

        // 6. 两个 user 的派生 IMEI 确实不同（端到端验证分桶生效）
        ModuleConfig real = cfg;
        io.github.xalsace.qqbypass.config.Fingerprint f0 = real.fingerprintForUser(0);
        io.github.xalsace.qqbypass.config.Fingerprint f999 = real.fingerprintForUser(999);
        assertFalse("按示例配置，u0 与 u999 的 IMEI 必须不同",
            f0.imei().equals(f999.imei()));
        assertEquals(15, f0.imei().length());
        assertEquals(15, f999.imei().length());
    }

    // ------------------------------------------------------------------ 辅助

    /** Gradle 单测的工作目录是 app/，仓库根在其上一级；两种都试。 */
    private static File findExample() {
        for (String p : CANDIDATES) {
            File f = new File(p);
            if (f.exists() && f.isFile()) return f;
        }
        return null;
    }

    private static String readAll(File f) throws Exception {
        BufferedReader r = new BufferedReader(new FileReader(f));
        try {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        } finally {
            r.close();
        }
    }
}