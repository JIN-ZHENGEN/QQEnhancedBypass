package io.github.xalsace.qqbypass;

import org.junit.Test;

import java.util.List;
import java.util.Map;

import io.github.xalsace.qqbypass.config.Json;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * 零依赖 JSON 解析器的测试。
 *
 * 存在的意义：本模块是 Xposed 模块，宿主是 QQ。引入 Gson/Jackson/Moshi 会
 * (a) 增大 APK 体积 (b) 把可能与宿主冲突的类带进宿主 ClassLoader。
 * 自己写 250 行的代价，换来零依赖。代价是必须自己保证健壮性 —— 这就是本测试。
 */
public class JsonTest {

    // ------------------------------------------------------------ 正常解析

    @Test
    public void parsesFlatObject() {
        Object o = Json.parse("{\"a\":1,\"b\":\"two\",\"c\":true,\"d\":null}");
        Map<String, Object> m = Json.asObject(o);
        assertNotNull(m);
        // 4 个键都保留：显式的 null 与「键不存在」是两回事（标准 JSON 语义），
        // 保留键才能让调用方区分「配置写了 null」和「压根没配」。
        assertEquals(4, m.size());
        assertEquals(Long.valueOf(1), Json.asLong(m.get("a"), -1L));
        assertEquals("two", Json.asString(m.get("b"), null));
        assertEquals(Boolean.TRUE, Json.asBoolean(m.get("c"), false));
        assertTrue("显式的 null 必须保留键", m.containsKey("d"));
        assertNull(m.get("d"));
    }

    @Test
    public void parsesNestedStructures() {
        Object o = Json.parse("{\"m\":{\"k\":[1,2,3]}}");
        Map<String, Object> root = Json.asObject(o);
        Map<String, Object> inner = Json.asObject(root.get("m"));
        assertNotNull(inner);
        List<Object> arr = Json.asArray(inner.get("k"));
        assertNotNull(arr);
        assertEquals(3, arr.size());
        assertEquals(Long.valueOf(2), Json.asLong(arr.get(1), -1L));
    }

    @Test
    public void parsesTopLevelArray() {
        Object o = Json.parse("[1,\"x\",false]");
        List<Object> arr = Json.asArray(o);
        assertNotNull(arr);
        assertEquals(3, arr.size());
        assertEquals("x", Json.asString(arr.get(1), null));
        assertEquals(Boolean.FALSE, Json.asBoolean(arr.get(2), true));
    }

    @Test
    public void parsesEscapesAndUnicode() {
        Map<String, Object> m = Json.asObject(
            Json.parse("{\"s\":\"a\\\"b\\\\c\\n\\t\\u0041\"}"));
        assertEquals("a\"b\\c\n\tA", Json.asString(m.get("s"), null));
    }

    @Test
    public void parsesNegativeAndFractionalNumbers() {
        Map<String, Object> m = Json.asObject(
            Json.parse("{\"a\":-12,\"b\":1.5}"));
        assertEquals(Long.valueOf(-12), Json.asLong(m.get("a"), 0L));
        // 小数按整数解析（本模块只需要整数开关），不应抛异常
        assertNotNull(Json.asLong(m.get("b"), 0L));
    }

    @Test
    public void ignoresWhitespace() {
        Map<String, Object> m = Json.asObject(
            Json.parse("  {  \"a\" :  1  ,  \"b\" : [ 2 ]  }  "));
        assertEquals(Long.valueOf(1), Json.asLong(m.get("a"), -1L));
        assertNotNull(Json.asArray(m.get("b")));
    }

    // ------------------------------------------------------------ 类型访问器

    /** 访问器在类型不符时返回默认值，绝不抛出。 */
    @Test
    public void accessorsFallBackToDefaults() {
        Object obj = Json.parse("{\"s\":\"x\",\"n\":7,\"b\":true,\"a\":[]}");
        Map<String, Object> m = Json.asObject(obj);

        // 类型不符 -> 默认值
        assertEquals(-1L, Json.asLong(m.get("s"), -1L).longValue());
        assertEquals("dflt", Json.asString(m.get("n"), "dflt"));
        assertEquals(Boolean.FALSE, Json.asBoolean(m.get("s"), false));

        // 缺失的键 -> 默认值
        assertEquals(99L, Json.asLong(m.get("missing"), 99L).longValue());
        assertEquals("none", Json.asString(m.get("missing"), "none"));

        // asObject/asArray 类型不符 -> null
        assertNull(Json.asObject(m.get("s")));
        assertNull(Json.asArray(m.get("s")));
    }

    @Test
    public void accessorsHandleNullInput() {
        assertEquals("d", Json.asString(null, "d"));
        assertEquals(5L, Json.asLong(null, 5L).longValue());
        assertEquals(Boolean.TRUE, Json.asBoolean(null, true));
        assertNull(Json.asObject(null));
        assertNull(Json.asArray(null));
    }

    // ------------------------------------------------------------ 畸形输入

    /** 所有畸形输入都要抛出 JsonException（可预测的类型），而不是任意异常。 */
    @Test
    public void malformedInputThrowsJsonException() {
        String[] bad = {
            "",
            "   ",
            "{",
            "}",
            "[",
            "{\"a\"}",
            "{\"a\":}",
            "{,}",
            "[1,]",
            "{\"a\":1,}",
            "tru",
            "\"unterminated",
            "{\"a\":01}",
            "nope"
        };
        for (String s : bad) {
            try {
                Json.parse(s);
                fail("输入 [" + s + "] 本应抛出 JsonException");
            } catch (Json.JsonException expected) {
                // 期望的行为：可预测的类型，调用方 catch Throwable 即可兜住
            }
        }
    }

    /** 尾随垃圾也要报错 —— 防止配置文件被截断后静默读到半截内容。 */
    @Test
    public void trailingGarbageIsRejected() {
        try {
            Json.parse("{\"a\":1} garbage");
            fail("尾随垃圾本应被拒绝");
        } catch (Json.JsonException expected) {
        }
    }

    /** 空容器是合法的。 */
    @Test
    public void emptyContainersAreValid() {
        assertNotNull(Json.asObject(Json.parse("{}")));
        assertNotNull(Json.asArray(Json.parse("[]")));
        assertEquals(0, Json.asObject(Json.parse("{}")).size());
    }

    /** 深层嵌套不炸栈（配置文件不会很深，但要防止恶意输入）。 */
    @Test
    public void deeplyNestedDoesNotExplode() {
        StringBuilder sb = new StringBuilder();
        int depth = 200;
        for (int i = 0; i < depth; i++) sb.append("{\"a\":");
        sb.append("1");
        for (int i = 0; i < depth; i++) sb.append('}');
        // 能解析或能抛出异常都算过关，关键是不要 StackOverflowError 逃逸
        try {
            Json.parse(sb.toString());
        } catch (Json.JsonException e) {
            // 深度限制生效亦可
        } catch (StackOverflowError e) {
            fail("不应发生栈溢出: " + e);
        }
    }

    /** 大数字不抛异常（退化处理即可）。 */
    @Test
    public void hugeNumbersDoNotThrow() {
        Map<String, Object> m = Json.asObject(
            Json.parse("{\"a\":99999999999999999999999}"));
        assertNotNull(Json.asLong(m.get("a"), 0L));
    }

    /** 布尔字面量大小写敏感。 */
    @Test
    public void booleanLiteralsAreCaseSensitive() {
        Map<String, Object> m = Json.asObject(Json.parse("{\"a\":true,\"b\":false}"));
        assertEquals(Boolean.TRUE, Json.asBoolean(m.get("a"), false));
        assertEquals(Boolean.FALSE, Json.asBoolean(m.get("b"), true));
        // "True" 不是合法 JSON 字面量
        try {
            Json.parse("{\"a\":True}");
            fail("True 不是合法 JSON 字面量");
        } catch (Json.JsonException expected) {
        }
    }

    @Test
    public void jsonExceptionIsRuntimeException() {
        assertTrue(RuntimeException.class.isAssignableFrom(Json.JsonException.class));
        assertFalse("JsonException 应是 RuntimeException，调用方无需显式捕获",
            Exception.class.isAssignableFrom(Json.JsonException.class)
                && !RuntimeException.class.isAssignableFrom(Json.JsonException.class));
    }
}