#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build-native.sh - 构建 Android native 库（绕过 x86_64-only NDK 工具链）
#
# 为什么需要这个脚本
# ------------------
# 本机宿主是 aarch64 (Ubuntu 24.04 arm64)，而 Android NDK 25.1 只提供
# linux-x86_64 预编译工具链。NDK 自带的 clang/ld.lld 是 x86_64 ELF：
#
#     $ ndk/.../prebuilt/linux-x86_64/bin/clang --version
#     -> SIGILL (exit 132)     # CPU 不认识
#     $ qemu-x86_64-static ... # 能跑但不可靠：ld.lld argv[0]、clang 内部
#                              # exec clang.real 绕过包装脚本等问题
#
# 解法：用 Ubuntu 自己的 arm64 clang 做交叉编译。clang 本来就是交叉编译器，
# 宿主架构只决定"谁跑编译器"，不影响产出 --target=aarch64-linux-android24
# 的产物。这样完全绕开 qemu。
#
# 唯一坑：NDK 25 不带 libgcc.a（改用 compiler-rt），所以要显式指定
# --rtlib=compiler-rt 并把 resource-dir 指到 NDK 的 clang/14.0.6，
# 让链接器找到 libclang_rt.builtins-aarch64-android.a。
#
# 用法：./build-native.sh
# ---------------------------------------------------------------------------
set -u

NDKROOT="${ANDROID_NDK_HOME:-/opt/android-sdk/ndk/25.1.8937393}"
NDKPRE="$NDKROOT/toolchains/llvm/prebuilt/linux-x86_64"
SYS="$NDKPRE/sysroot"
# compiler-rt builtins 所在目录（NDK 自带 clang 版本 14.0.6）
CLANGRES="$NDKPRE/lib64/clang/14.0.6"

SRC="$(cd "$(dirname "$0")" && pwd)/app/src/main/cpp"
OUT="${OUT:-/tmp/nbuild}"
ABI="${ABI:-arm64-v8a}"

# bytehook prefab：从 AAR 解压出来的目录
BH="${BH:-/tmp/bhx/prefab/modules/bytehook}"

CXX=clang++
TARGET=aarch64-linux-android24

mkdir -p "$OUT"
rm -f "$OUT"/*.o "$OUT"/*.so "$OUT"/err.txt 2>/dev/null

if [ ! -d "$SRC" ]; then echo "FATAL: source dir not found: $SRC"; exit 1; fi
if [ ! -f "$BH/libs/android.$ABI/libbytehook.so" ]; then
  echo "FATAL: bytehook prefab missing at $BH"
  echo "  fetch it with:  mkdir -p /tmp/bh && cd /tmp/bh && \\"
  echo "    curl -sL -o bh.aar https://repo1.maven.org/maven2/com/bytedance/bytehook/1.0.2/bytehook-1.0.2.aar && \\"
  echo "    python3 -c \"import zipfile;zipfile.ZipFile('bh.aar').extractall('/tmp/bhx')\""
  exit 1
fi

SOURCES="native-bypass.cpp \
 hooks/hook_libc.cpp \
 hooks/hook_libfekit.cpp \
 hooks/hook_libturingxq.cpp \
 hooks/hook_libmsf.cpp \
 hooks/hook_libqsec.cpp \
 hooks/hook_libmsfkernel.cpp \
 hooks/hook_libturingmfa.cpp \
 utils/log.cpp"

cd "$SRC" || exit 1

ok=0; fail=0
echo "=== compiling ($ABI) ==="
for f in $SOURCES; do
  o="$OUT/$(echo "$f" | tr '/' '_').o"
  if $CXX --target=$TARGET --sysroot="$SYS" -std=c++17 -fPIC \
      -I"$SRC" -I"$BH/include" -c "$f" -o "$o" 2>>"$OUT/err.txt"; then
    echo "  OK   $f"; ok=$((ok+1))
  else
    echo "  FAIL $f"; fail=$((fail+1))
  fi
done
echo "  compiled_ok=$ok failed=$fail"
if [ "$fail" -gt 0 ]; then echo "--- errors ---"; cat "$OUT/err.txt"; exit 1; fi

echo "=== linking ==="
$CXX --target=$TARGET --sysroot="$SYS" -fuse-ld=lld -shared \
  --rtlib=compiler-rt -resource-dir="$CLANGRES" \
  -o "$OUT/libnative-bypass.so" \
  "$OUT"/*.o \
  -L"$BH/libs/android.$ABI" -lbytehook \
  -L"$SYS/usr/lib/aarch64-linux-android" -llog -landroid 2>&1 | head -20

if [ -f "$OUT/libnative-bypass.so" ]; then
  echo "=== result ==="
  ls -la "$OUT/libnative-bypass.so"
  # 校验产出架构：ELF machine 字段必须是 b7 00 (AArch64)
  magic=$(od -A n -t x1 -N 20 "$OUT/libnative-bypass.so" | head -2 | tr -s ' ' | tail -1)
  echo "  ELF machine bytes: $magic  (expect 03 00 b7 00)"
  echo "SUCCESS: $OUT/libnative-bypass.so"
  echo "Copy into APK tree with:"
  echo "  mkdir -p app/src/main/jniLibs/$ABI"
  echo "  cp $OUT/libnative-bypass.so app/src/main/jniLibs/$ABI/"
  echo "  cp $BH/libs/android.$ABI/libbytehook.so app/src/main/jniLibs/$ABI/"
else
  echo "FAILED: linker produced no output"; exit 1
fi