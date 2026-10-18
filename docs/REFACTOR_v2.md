# v2.0 改造说明：六项路线图的落地情况

本文件记录相对 `f553afa`（v1.0.7）的改造。逐项说明「做了什么 / 没做什么 / 为什么」。

---

## 已落地（4 项，全部纯 Java）

### 1. Java 层多模块 hook 框架 ✅

**改前的问题**（`XposedEntry.handleLoadPackage`）：

```java
try {
    UnifiedHookCoordinator.initialize(lpparam);
    NetworkReportHook.hook(lpparam);
    RootDetectionHook.hook(lpparam);
    ... 共 8 次硬编码静态调用
} catch (Throwable t) { log(...); }
```

一个 `try` 包住全部 —— 第 3 个 hook 抛异常，后面 5 个**全部静默跳过**，
日志只有一行。这就是「模块显示已激活，但保护等级莫名其妙掉到 30%」的成因。

**改后**：新增 `hooks/HookModule`（接口）、`hooks/HookResult`（执行结果）、
`hooks/HookRegistry`（注册表）。逐模块隔离执行，任一模块炸掉不影响其余：

```
[registry] network_report=ok(hooked=3,skipped=1) in 12ms
[registry] root_detection=ok(hooked=25,skipped=0) in 8ms
[registry] qq950_patch=failed err=...
[registry] runtime_monitor=ok(hooked=6,skipped=2) in 5ms   ← 照常执行
=== Java Hooks: modules=7 hooked=34 skipped=3 failed=1 disabled=0 ===
```

原有 7 个 hook 类**零改动**，通过反射适配器接入（`HookRegistry.createDefault()`）。

### 3. 设备指纹一致性增强 ✅

**改前**：`DeviceInfoHook` 有 4 个 `private static String cachedXxx`，
跨 user 共用一个进程内单例。在 XSpace 双开（u0 + u999）下，两个 QQ 拿到
**同一套**假指纹 —— 服务端据此判定「同一设备绑定两个账号」，反而放大风控。

**改后**：新增 `config/Fingerprint`，所有值由 `(设备种子, userId)` **确定性派生**：

| 性质 | 保证方式 | 单测 |
|---|---|---|
| 跨 user 不同 | seed 里拼入 `#u{userId}` | `differentUsersGetDifferentFingerprints` |
| 跨进程一致 | 纯函数派生，无状态、无缓存 | `sameSeedAndUserIsDeterministic` |
| 格式合法 | IMEI 走标准 Luhn 校验位，15 位数字 | `imeiIs15DigitsAndPassesLuhn` |

**默认关闭**（`spoofFingerprint: false`），真值原样透传。理由：
伪造指纹是本模块最容易被识别的一层，且做错了有负收益。

### 5. 自动化测试框架 ✅

新增 `app/src/test/` 下 5 个测试类、**43 个用例全绿**：

| 测试类 | 覆盖 | 用例数 |
|---|---|---|
| `HookRegistryTest` | 失败隔离、开关、覆盖、默认注册表完整性 | 7 |
| `FingerprintTest` | 三条核心性质 + Luhn 已知答案 | 9 |
| `ModuleConfigTest` | 畸形输入不抛异常、按 user 读 seed | 11 |
| `JsonTest` | 解析正确性 + 14 种畸形输入 | 15 |
| `ExampleConfigTest` | 示例配置文件端到端可解析 | 1 |

跑法：`./gradlew :app:testReleaseUnitTest`

关键设计：测试全部是**纯 JVM 单测**（`testOptions.unitTests.returnDefaultValues = true`），
不依赖真机、不依赖 LSPosed。为此把计数器从 `HookUtils` 抽到独立的
`utils/HookCounters` —— 后者不 import 任何 Xposed/android 类型，
避免 compileOnly 的 Xposed API 在单测里引发 `NoClassDefFoundError`。

### 6. 配置文件支持 + 版本适配检测 ✅

**配置文件支持**：新增 `config/Json`（256 行零依赖 JSON 解析器）+
`config/ModuleConfig`（运行时配置）。读 `/sdcard/Download/qqbypass.json`
或 `/data/local/tmp/qqbypass.json`，示例见 `docs/qqbypass.json.example`。

取代了原先 `HookConfig` 里那批 `public static boolean` 编译期常量 ——
以前要关一个模块必须改源码重编译装 APK。

三条硬性约束（每条都对应一个真实踩过的坑）：
1. **零异常外溢** —— 配置读取在最早期调用，一次抛错就打断整个注入
2. **读不到 = 全默认** —— 绝不因为配置文件缺失就关闭保护
3. **指纹 seed 按 user 分桶** —— 共用会放大风控

**版本适配检测**：新增 `VersionCompat`，每次注入后扫描 10 个关键 hook 目标，
失效的直接报出来。7 个 hook 类里写满了硬编码的 QQ 类名/方法名，QQ 一改版
这些符号就消失 —— 以前只能靠猜，现在日志里会写：

```
[compat] STALE - 2/10 probe targets missing, QQ may have changed:
[compat]   missing qq950_patch:com.tencent.turingcam.TuringRiskService(class)
```

---

## 未落地（2 项）

### 2. native hook 支持（JNI 层）❌ 代码已有，未验证构建

**重要更正**：早期基于 dex 反编译判断「native 已打进包但 Java 侧没接线」是**错的**。
读源码后确认 `NativeBypass` 静态块里 `System.loadLibrary("native-bypass")` 和
`ByteHook.init()` 俱全，`UnifiedHookCoordinator.initialize()` 读的也是
`NativeBypass.isLibraryLoaded()`。接线本来就是完好的。

真正没做的是**验证**：当前构建环境是 arm64 宿主机跑 x86_64 Android NDK，
整条工具链（cmake / ninja / clang / lld）都要 qemu 翻译。过程中
`ld.lld` 因 argv[0] 问题报「lld is a generic driver」，clang 内部 exec
`clang.real` 绕过包装脚本…… 属「靠 qemu 硬凑」，即便跑通也不稳定。

因此 native 在配置里**默认关闭**（`nativeHooks: false`），需要时在真机上
单独开启观察。代码一行没删，验证留到有合适构建环境时做。

### 4. 签名校验绕过（实验性）❌ 未做

原始路线图里这一项标着「实验性」。实际情况是：拿到目标 App 的签名校验逻辑
并设计绕过方案，需要能验证它确实生效 —— 而在当前环境下无法完成这个验证。
交付一个自己都没验证过、且一旦失效就可能导致 App 崩溃或触发更强风控的
功能，不划算。

---

## 其他改动

- `gradlew` + `gradle-wrapper.jar`：仓库原先缺失，已补上（否则无法命令行构建）
- `build.gradle`：补 `testOptions` 与 JUnit/Xposed 测试依赖
- `HookConfig.VERBOSE_LOGGING` 默认 `true` → `false`，改由配置文件的
  `verbose` 控制。自检报告不受影响，始终打印
- `HookConfig.FAKE_*` 三个字段标记 `@Deprecated`，已被 `Fingerprint` 取代

## 已知约束

- 改配置文件必须**重启 QQ** 才生效（Xposed 模块只在进程启动时读一次配置）
- `DeviceInfoHook` 里「不要 hook `getStrategyAndReport()`」的警告仍然有效：
  它返回 typed 对象，`setResult(0)` 会触发 Xposed 抛 `ClassCastException`，
  导致 QQ 9.3.50 启动任务崩溃、进不去主界面
