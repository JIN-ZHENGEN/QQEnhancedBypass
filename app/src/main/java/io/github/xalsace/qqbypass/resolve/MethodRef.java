package io.github.xalsace.qqbypass.resolve;

/**
 * 目标方法引用。
 *
 * 存在的理由：DexKit 的 MethodData 是第三方类型，让 hook 类直接依赖它
 * 会把 DexKit 的 API 变更传导到所有调用点。这里抽出一个只带
 * className / methodName / paramSign 三个字段的不可变值对象，
 * hook 类与 TieredHook 都只面对它。
 *
 * 单独成文件的理由：Java 规定一个 public 顶层类必须放在同名文件里。
 * 早期把它塞在 TargetResolver.java 头部，javac 直接报
 * "class MethodRef is public, should be declared in a file named MethodRef.java"。
 */
public final class MethodRef {
    public final String className;
    public final String methodName;
    /**
     * DexKit getMethodSign() 形式的方法签名：
     * {@code (java.lang.String,int)void}（Java 全限定名，逗号分隔，含返回类型）。
     */
    public final String paramSign;

    public MethodRef(String className, String methodName, String paramSign) {
        this.className = className;
        this.methodName = methodName;
        this.paramSign = paramSign;
    }

    @Override
    public String toString() {
        return className + "#" + methodName + paramSign;
    }
}
