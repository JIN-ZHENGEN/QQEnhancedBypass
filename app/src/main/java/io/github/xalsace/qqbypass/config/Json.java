package io.github.xalsace.qqbypass.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 零依赖的极简 JSON 读取器。
 *
 * 存在的理由：本模块是纯 Java Xposed 模块，宿主进程是 QQ，任何第三方 JSON 库
 * （Gson/Jackson/Moshi）都会 (a) 增加 APK 体积 (b) 带进宿主 ClassLoader 可能冲突的类。
 * 而配置文件只有几十字节的扁平结构，一个递归下降解析器足够。
 *
 * 只支持读取（parse），不支持序列化 —— 模块运行时不需要写 JSON。
 * 只支持 RFC 8259 的子集：object / array / string / number / true / false / null。
 * 解析失败抛 {@link JsonException}，由调用方决定是否降级到默认值。
 */
public final class Json {

    private final String src;
    private int pos;

    private Json(String src) {
        this.src = src;
    }

    /** 解析 JSON 文本；返回 Map/List/String/Double/Boolean/null。 */
    public static Object parse(String text) {
        // 空输入不是合法的 JSON 文本（RFC 8259：JSON text 必须是一个完整的值）。
        // 这里刻意抛异常而不是返回 null：配置文件被截断成 0 字节是真实会发生的
        // （写到一半断电、adb push 中断），静默返回 null 会让它被当成「没配置」
        // 而继续用默认值 —— 那是错的，应当被识别为损坏。
        if (text == null || text.length() == 0) {
            throw new JsonException("empty input");
        }
        Json p = new Json(text);
        p.skipWs();
        Object v = p.readValue();
        p.skipWs();
        if (p.pos < p.src.length()) {
            throw new JsonException("trailing content at " + p.pos);
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asObject(Object v) {
        return (v instanceof Map) ? (Map<String, Object>) v : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asArray(Object v) {
        return (v instanceof List) ? (List<Object>) v : null;
    }

    public static String asString(Object v, String def) {
        return (v instanceof String) ? (String) v : def;
    }

    public static Boolean asBoolean(Object v, Boolean def) {
        return (v instanceof Boolean) ? (Boolean) v : def;
    }

    /** 数字转 long；布尔不算数字，字符串不尝试解析（避免 "1" 被当成 1 造成困惑）。 */
    public static Long asLong(Object v, Long def) {
        if (v instanceof Double) {
            return ((Double) v).longValue();
        }
        if (v instanceof Long) {
            return (Long) v;
        }
        return def;
    }

    // ---------------------------------------------------------------- parse

    private Object readValue() {
        if (pos >= src.length()) {
            throw new JsonException("unexpected end of input");
        }
        char c = src.charAt(pos);
        switch (c) {
            case '{': return readObject();
            case '[': return readArray();
            case '"': return readString();
            case 't': expect("true");  return Boolean.TRUE;
            case 'f': expect("false"); return Boolean.FALSE;
            case 'n': expect("null");  return null;
            default:  return readNumber();
        }
    }

    private Map<String, Object> readObject() {
        Map<String, Object> out = new LinkedHashMap<>();
        expectChar('{');
        skipWs();
        if (peek() == '}') {
            pos++;
            return out;
        }
        while (true) {
            skipWs();
            if (peek() != '"') {
                throw new JsonException("expected key at " + pos);
            }
            String key = readString();
            skipWs();
            expectChar(':');
            skipWs();
            out.put(key, readValue());
            skipWs();
            char c = peek();
            pos++;
            if (c == '}') {
                return out;
            }
            if (c != ',') {
                throw new JsonException("expected ',' or '}' at " + (pos - 1));
            }
        }
    }

    private List<Object> readArray() {
        List<Object> out = new ArrayList<>();
        expectChar('[');
        skipWs();
        if (peek() == ']') {
            pos++;
            return out;
        }
        while (true) {
            skipWs();
            out.add(readValue());
            skipWs();
            char c = peek();
            pos++;
            if (c == ']') {
                return out;
            }
            if (c != ',') {
                throw new JsonException("expected ',' or ']' at " + (pos - 1));
            }
        }
    }

    private String readString() {
        expectChar('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            if (pos >= src.length()) {
                throw new JsonException("unterminated string");
            }
            char c = src.charAt(pos++);
            if (c == '"') {
                return sb.toString();
            }
            if (c == '\\') {
                if (pos >= src.length()) {
                    throw new JsonException("unterminated escape");
                }
                char e = src.charAt(pos++);
                switch (e) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case '/':  sb.append('/');  break;
                    case 'b':  sb.append('\b'); break;
                    case 'f':  sb.append('\f'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    case 'u':
                        if (pos + 4 > src.length()) {
                            throw new JsonException("bad \\u escape");
                        }
                        sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                        pos += 4;
                        break;
                    default:
                        throw new JsonException("bad escape \\" + e);
                }
            } else {
                sb.append(c);
            }
        }
    }

    private Object readNumber() {
        int start = pos;
        // 严格按 RFC 8259 的语法扫描，而不是「把所有看起来像数字的字符吞掉」。
        // 宽松扫描会接受 01 / +5 / 1e / --1 这类非法字面量，让被截断或写错的
        // 配置文件静默通过 —— 配置是安全相关输入，宁可报错走默认值。
        boolean negative = false;
        if (peek() == '-') {
            negative = true;
            pos++;
        }
        // int 部分：必须有至少一位数字
        int intStart = pos;
        while (pos < src.length() && isDigit(src.charAt(pos))) {
            pos++;
        }
        if (pos == intStart) {
            throw new JsonException("expected digit at " + pos);
        }
        // 前导零非法：0 后面不能直接跟数字（"01" 错，"0" 和 "0.5" 对）
        if (pos - intStart > 1 && src.charAt(intStart) == '0') {
            throw new JsonException("leading zero in number at " + intStart);
        }

        boolean fractional = false;
        // frac 部分
        if (pos < src.length() && src.charAt(pos) == '.') {
            fractional = true;
            pos++;
            int fracStart = pos;
            while (pos < src.length() && isDigit(src.charAt(pos))) {
                pos++;
            }
            if (pos == fracStart) {
                throw new JsonException("expected digit after '.' at " + pos);
            }
        }
        // exp 部分
        if (pos < src.length() && (src.charAt(pos) == 'e' || src.charAt(pos) == 'E')) {
            fractional = true;
            pos++;
            if (pos < src.length() && (src.charAt(pos) == '-' || src.charAt(pos) == '+')) {
                pos++;
            }
            int expStart = pos;
            while (pos < src.length() && isDigit(src.charAt(pos))) {
                pos++;
            }
            if (pos == expStart) {
                throw new JsonException("expected digit in exponent at " + pos);
            }
        }

        String lit = src.substring(start, pos);
        try {
            if (!fractional && lit.length() <= 18) {
                return Long.valueOf(lit);
            }
            return Double.valueOf(lit);
        } catch (NumberFormatException e) {
            throw new JsonException("bad number '" + lit + "'");
        }
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    // ---------------------------------------------------------------- helpers

    private char peek() {
        if (pos >= src.length()) {
            throw new JsonException("unexpected end of input");
        }
        return src.charAt(pos);
    }

    private void expectChar(char c) {
        if (pos >= src.length() || src.charAt(pos) != c) {
            throw new JsonException("expected '" + c + "' at " + pos);
        }
        pos++;
    }

    private void expect(String lit) {
        if (!src.startsWith(lit, pos)) {
            throw new JsonException("expected '" + lit + "' at " + pos);
        }
        pos += lit.length();
    }

    private void skipWs() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f') {
                pos++;
            } else {
                break;
            }
        }
    }

    /** 解析失败信号。故意做成 RuntimeException 的子类，让调用方用一个 catch 兜住。 */
    public static class JsonException extends RuntimeException {
        public JsonException(String msg) {
            super(msg);
        }
    }
}
