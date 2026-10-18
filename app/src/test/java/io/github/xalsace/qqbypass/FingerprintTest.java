package io.github.xalsace.qqbypass;

import org.junit.Test;

import io.github.xalsace.qqbypass.config.Fingerprint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * 指纹生成器的性质测试。
 *
 * 这里验的不是具体数值（那是实现细节），而是三条**性质** —— 它们直接对应
 * DeviceInfoHook 原来那 4 个 static 单例字段的缺陷：
 *   1. 跨 user 必须不同（否则 XSpace 双开 = 同设备多账号，放大风控）
 *   2. 跨进程必须一致（否则 Pandora 多路径交叉校验立刻抓到）
 *   3. 格式必须合法（IMEI 过 Luhn，否则一眼假）
 */
public class FingerprintTest {

    /** 性质 1：不同 user 得到不同指纹。这是路线 3 的核心诉求。 */
    @Test
    public void differentUsersGetDifferentFingerprints() {
        Fingerprint u0 = Fingerprint.forUser(0, "seed");
        Fingerprint u999 = Fingerprint.forUser(999, "seed");

        assertFalse("u0 与 u999 的 IMEI 必须不同", u0.imei().equals(u999.imei()));
        assertFalse("u0 与 u999 的 serial 必须不同", u0.serial().equals(u999.serial()));
        assertFalse("u0 与 u999 的 androidId 必须不同", u0.androidId().equals(u999.androidId()));
        assertFalse("u0 与 u999 的 meid 必须不同", u0.meid().equals(u999.meid()));
    }

    /** 性质 2：同一 (seed,user) 反复生成必须完全一致 —— 跨进程一致性的前提。 */
    @Test
    public void sameSeedAndUserIsDeterministic() {
        Fingerprint a = Fingerprint.forUser(0, "seed");
        Fingerprint b = Fingerprint.forUser(0, "seed");
        assertEquals(a.imei(), b.imei());
        assertEquals(a.meid(), b.meid());
        assertEquals(a.serial(), b.serial());
        assertEquals(a.androidId(), b.androidId());
        assertEquals(a.toString(), b.toString());
    }

    /** 性质 2 的延伸：不同 seed 得到不同指纹。 */
    @Test
    public void differentSeedsDiverge() {
        Fingerprint a = Fingerprint.forUser(0, "seed-a");
        Fingerprint b = Fingerprint.forUser(0, "seed-b");
        assertFalse(a.imei().equals(b.imei()));
    }

    /** 性质 3：IMEI 必须是 15 位数字，且末位是合法 Luhn 校验位。 */
    @Test
    public void imeiIs15DigitsAndPassesLuhn() {
        for (int u = 0; u < 20; u++) {
            String imei = Fingerprint.forUser(u, "seed").imei();
            assertEquals("user " + u + " 的 IMEI 长度", 15, imei.length());
            assertTrue("IMEI 应全为数字: " + imei, imei.matches("\\d{15}"));
            assertTrue("IMEI 应过 Luhn: " + imei, passesLuhn(imei));
        }
    }

    /** 各字段长度与字符集符合真实设备的形态。 */
    @Test
    public void fieldShapesAreValid() {
        Fingerprint fp = Fingerprint.forUser(0, "seed");
        assertEquals("MEID 应为 14 位十六进制", 14, fp.meid().length());
        assertTrue(fp.meid().matches("[0-9A-F]{14}"));
        assertTrue("serial 应只含大写字母数字", fp.serial().matches("[0-9A-Z]+"));
        assertEquals("serial 长度", 10, fp.serial().length());
        assertEquals("androidId 应为 16 位十六进制", 16, fp.androidId().length());
        assertTrue(fp.androidId().matches("[0-9a-f]{16}"));
    }

    /** seed 为 null 时回落到设备种子，不抛异常。 */
    @Test
    public void nullSeedFallsBackToDeviceSeed() {
        Fingerprint fp = Fingerprint.forUser(0, null);
        assertNotNull(fp.imei());
        assertEquals(15, fp.imei().length());
    }

    /** 空 seed 同样回落，不抛异常。 */
    @Test
    public void emptySeedFallsBackToDeviceSeed() {
        Fingerprint fp = Fingerprint.forUser(3, "");
        assertNotNull(fp.imei());
        assertEquals(15, fp.imei().length());
    }

    /** 大量 user 下不出现重复 IMEI —— 排除 hash 碰撞导致串号。 */
    @Test
    public void noCollisionsAcrossManyUsers() {
        java.util.Set<String> seen = new java.util.HashSet<String>();
        for (int u = 0; u < 500; u++) {
            assertTrue("user " + u + " 的 IMEI 撞车", seen.add(Fingerprint.forUser(u, "s").imei()));
        }
    }

    /** Luhn 校验位算法的直接验证：用一组已知答案钉死实现。 */
    @Test
    public void luhnCheckMatchesKnownValues() {
        // 电信行业通用测试用例：前 14 位 "79927398710980" 的校验位是 6
        assertEquals('6', Fingerprint.luhnCheck("79927398710980"));
        // 短一些的经典用例："7992739871" 的校验位是 3
        assertEquals('3', Fingerprint.luhnCheck("7992739871"));
        // 全 0 的校验位是 0
        assertEquals('0', Fingerprint.luhnCheck("00000000000000"));
    }

    // ------------------------------------------------------------------ 辅助

    /** 独立实现的 Luhn 校验，用来交叉验证（不复用被测代码）。 */
    private static boolean passesLuhn(String imei) {
        int sum = 0;
        boolean doubleIt = false;
        for (int i = imei.length() - 1; i >= 0; i--) {
            int d = imei.charAt(i) - '0';
            if (doubleIt) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }
}