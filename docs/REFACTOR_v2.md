# v2.0 改造说明：六项路线图的落地情况

本文件记录相对 `f553afa`（v1.0.7）的改造。逐项说明「做了什么 / 没做什么 / 为什么」。

---

## 已落地（5 项）

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

## 未落地（1 项）

### 2. native hook 支持（JNI 层）✅ 已构建验证通过

**重要更正**：早期基于 dex 反编译判断「native 已打进包但 Java 侧没接线」是**错的**。
读源码后确认 `NativeBypass` 静态块里 `System.loadLibrary("native-bypass")` 和
`ByteHook.init()` 俱全，`UnifiedHookCoordinator.initialize()` 读的也是
`NativeBypass.isLibraryLoaded()`。接线本来就是完好的。

**再更正（本次）**：上一版写的「无法验证构建」也已被推翻。native 库现在**构建成功**：

```
9 个源文件全部编译通过，链接产出 libnative-bypass.so (3.4 MB)
ELF: class=64 type=SHARED machine=0xb7 (AArch64)
导出 JNI 符号 7 个：initNativeHooksNative / isHooksInstalledNative /
  isHookActiveNative / getHookStatusNative / getHookStatisticsNative /
  notifyDetectionNative / JNI_OnLoad
NEEDED: libbytehook.so, liblog.so, libandroid.so, libc++_shared.so
```

关键突破：不需要 qemu，也不需要 NDK 的 x86_64 工具链。构建脚本见仓库根目录
`build-native.sh`。

**为什么之前跑不通**：宿主是 aarch64，而 NDK 25.1 只带 `linux-x86_64` 预编译
工具链，其 clang 是 x86_64 ELF（`3e00`），直接执行 = SIGILL (exit 132)，
且 `binfmt_misc` 未注册（无法透明执行），只剩 qemu 一条路 —— 而 qemu 下
`ld.lld` 报 argv[0] 问题、clang 内部 exec `clang.real` 绕过包装脚本，不可靠。

**解法**：装 Ubuntu arm64 原生 clang 做交叉编译。clang 本身是交叉编译器，
宿主架构只决定「谁跑编译器」，不影响 `--target=aarch64-linux-android24`
的产出。唯一的坑是 **NDK 25 不带 `libgcc.a`**（改用 compiler-rt），
需要显式 `--rtlib=compiler-rt` + `-resource-dir` 指向 NDK 的
`lib64/clang/14.0.6`，让链接器找到 `libclang_rt.builtins-aarch64-android.a`。

**运行时 Switch 已打开**：native 现在默认启用（`nativeHooks: true`）。
理由有三条：
1. CI 是 x86_64 原生环境，CMake 路径通畅，`libnative-bypass.so` 会随 APK 打包；
2. `UnifiedHookCoordinator` 在 `.so` 缺失时走纯 Java 降级路径，不会崩；
3. `ModuleConfigTest.nativeCanBeDisabledByConfig` 保证真机上一键关闭的退路有效。

**退路**：真机出问题就写配置，重启 QQ 即回到纯 Java：
```json
{ "nativeHooks": false }
```

**重要前提**：此前那些 `-unsigned.apk` / `-signed.apk` 里 **`.so` 数量为 0** ——
它们是在你这台 x86_64-SDK 的 proot 里构建的，NDK 工具链跑不起来，native
从来就没被打包进去。所以「native 无效」此前是双重原因：既默认关闭，
包里也根本没有库。后者只有在 CI 出包时才真正成立。

**仍未变的**：构建已验证 ≠ 运行时已验证。ByteHook 的 PLT hook 本身是可检测面，
native 层出错是 native crash 而非 Java 异常（try/catch 抓不到信号级崩溃）。
判断依据看 logcat 里这条：

```
[native] enabled=true   (库加载成功，保护等级 80%)
[native] enabled=false  (.so 缺失，回落 Java only 30%)
```

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
