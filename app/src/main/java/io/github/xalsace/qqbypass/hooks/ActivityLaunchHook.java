package io.github.xalsace.qqbypass.hooks;

import android.content.Intent;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.xalsace.qqbypass.XposedEntry;
import io.github.xalsace.qqbypass.resolve.TieredHook;

/**
 * 踢线（kick to login page）的行为兜底。
 *
 * 为什么需要这一类：所有按 QQ 类名定位的 hook 都会随版本失效。
 * 9.3.50 的入口是 com.tencent.mobileqq.kick.NTKickProcessor#b，
 * 9.3.60 多出 com.tencent.mobileqq.login.ntlogin.ao#f 与
 * com.tencent.mobileqq.login.api.impl.UidServiceImpl#kickToLoginPage 两条，
 * 到 9.3.75 大概率又改名。三个入口殊途同归：
 * 最终都是发一个 action 为 {@link #ACTION_KICK} 的 Intent 跳登录页。
 *
 * 而 startActivity 的所有重载，在 AOSP 里最终都汇聚到
 * {@code android.app.Instrumentation.execStartActivity} ——
 * 这是 framework 类的固定路径，Android 4.x ~ 16 签名只有增减没有更名。
 * 所以 hook 它 = 100% 版本无关地覆盖全部踢线入口。
 *
 * 代价：比 hook NTKickProcessor 稍晚一步（已经走到启动 Activity 了），
 * 但换来的是不需要知道任何一个 QQ 类名。
 * 两种 hook 同时存在，谁先命中谁先拦，互为备份。
 */
public final class ActivityLaunchHook {

    /** 服务端踢线 / 票据失效 / UID 取不到，最终都是这个 action。 */
    private static final String ACTION_KICK = "mqq.intent.action.KICK_TO_LOGIN";

    /** 登录页所在的组件，用于兜底识别（部分版本 action 被改写）。 */
    private static final String[] LOGIN_COMPONENT_HINTS = {
        "LoginActivity", "login.LoginActivity", "/base/login"
    };

    private ActivityLaunchHook() {}

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        XposedEntry.log("[activity] installing execStartActivity kick interceptor");

        // 目标类是 AOSP framework 类，名字从 Android 4.x 到 16 没变过，
        // 因此走 installFixed（纯 C 档）—— 对它做 DexKit 字符串反查是浪费。
        TieredHook.Install r = TieredHook.installFixed(
            "android.app.Instrumentation", "execStartActivity",
            lpparam.classLoader,
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Intent intent = findIntent(param.args);
                    if (intent == null) return;
                    if (!isKick(intent)) return;

                    XposedEntry.log("[activity] KICK_TO_LOGIN intercepted (action="
                        + intent.getAction() + ")");

                    // 返回值类型安全判定。
                    // 注意 param.method 的静态类型是 java.lang.reflect.Member，
                    // 没有 getReturnType()；必须强转成 Method 才能取。
                    // Instrumentation.execStartActivity 在 Android 12+ 返回
                    // ActivityResult（对象），更早的版本是 void，
                    // 两种情况 setResult(null) 都安全。
                    Class<?> rt = null;
                    if (param.method instanceof java.lang.reflect.Method) {
                        rt = ((java.lang.reflect.Method) param.method).getReturnType();
                    }
                    if (rt == null || rt == void.class || !rt.isPrimitive()) {
                        param.setResult(null);
                    } else {
                        // 原始类型返回值：不能 setResult(null)，只能放过。
                        XposedEntry.log("[activity] primitive return "
                            + rt.getName() + ", not blocking");
                    }
                }
            });

        if (!r.ok()) {
            // 走到这里说明连 AOSP 框架类都找不到 —— 那只可能是模块自身出了问题
            // （比如 ProGuard 裁掉了 Instrumentation 的引用），必须显式报出来。
            XposedEntry.logError("[activity] FAILED to install: " + r, null);
        } else {
            XposedEntry.log("[activity] installed via tier " + r);
        }
    }

    /** 各重载里 Intent 参数位置不同，扫一遍最稳。 */
    private static Intent findIntent(Object[] args) {
        if (args == null) return null;
        for (Object a : args) {
            if (a instanceof Intent) return (Intent) a;
        }
        return null;
    }

    private static boolean isKick(Intent intent) {
        if (intent == null) return false;
        String action = intent.getAction();
        if (action != null && action.contains("KICK_TO_LOGIN")) return true;

        // action 被改写时的兜底：看组件名。QQ 的登录页类名在 9.x 系列一直稳定。
        android.content.ComponentName cn = intent.getComponent();
        if (cn != null) {
            String s = cn.getClassName();
            for (String hint : LOGIN_COMPONENT_HINTS) {
                if (s != null && s.contains(hint)) return true;
            }
        }
        return false;
    }
}
