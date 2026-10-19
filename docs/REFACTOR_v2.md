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

**再再更正（真机实测，v1.0.9）——默认值已改回 `false`**：
v1.0.8 曾短暂把默认翻成 `true`，真机装上后**立即被判定异常**。根因不是配置，
而是 ByteHook 的机制：它是 **GOT/PLT hook**，而 `bytehook_hook_all` 会改写
**所有已加载库**的 GOT 表项 —— 包括 `libturingxq.so` / `libturingmfa.so` /
`libQSec.so` / `libMSFKernel.so` 这四个腾讯反欺诈库自身。它们的自检逻辑正是
扫描自身 GOT 里有没有指向库外地址的项（`send` 本该指向 `libc.so`，改成了
跳板），一查即中。

Java 层那 64 个 hook 全是 ART 方法级（改 entry point），不走 GOT，所以扫不到 ——
这就是「native 关着一直没事，一开就出事」的原因。

被 hook 的全局符号清单（`hook_all` = 全进程）：

| 文件 | 符号 |
|---|---|
| `hook_libc.cpp` | `fopen` `fgets` `readlink` `access` |
| `hook_libfekit.cpp` | `system` `popen` |
| `hook_libturingxq.cpp` | `send` `sendto` |

另有几处放大问题：`hook_libqsec.cpp` 把任何含 `hook` 子串的符号一律返回
`nullptr`（会误伤 QQ 自身的合法符号）；`hook_libturingxq.cpp` 的 `fake_send`
把风控上报吞掉并伪装发送成功（服务端静默本身即是风控画像）；
`send` 被 turingxq（全局）和 turingmfa（单库）**hook 了两次**，嵌套跳板纯增风险。

**当前默认值**：`false`。`ModuleConfig.defaults()` / `fromJson()` 初值 /
`Json.asBoolean` 回退值三处已同步，`defaultsAreSafe` 与 `emptyObjectIsDefaults`
两条断言钉死新值，并新增 `nativeCanBeEnabledByConfig` 保证开关双向有效。

**开启方式（后果自负）**：在 `qqbypass.json` 里写 `{"nativeHooks": true}`，
重启 QQ。日志会打 `[native] enabled=true`。

**未来要安全启用 native 的前提**：删掉全部 `hook_all`，只保留限定调用方的
`bytehook_hook_single`（目前唯一相对安全的是 `hook_libfekit.cpp` 里那条
只拦 `libfekit.so` 的 `strstr`）；`hook_libmsfkernel.cpp` 只记录后放行、
零收益却改了 libMSFKernel 的 GOT，`hook_libmsf.cpp` 源码自述「默认不做任何 hook」，
这两个应当直接移除。

**仍未变的**：构建已验证 ≠ 运行时已验证。ByteHook 的 PLT hook 本身是可检测面，
native 层出错是 native crash 而非 Java 异常（try/catch 抓不到信号级崩溃）。
判断依据看 logcat 里这条：

```
[native] enabled=true   (库加载成功，保护等级 80%)
[native] enabled=false  (.so 缺失或配置关闭，回落 Java only 30%)
[disabled by config]    (nativeHooks=false，库压根不加载)
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
