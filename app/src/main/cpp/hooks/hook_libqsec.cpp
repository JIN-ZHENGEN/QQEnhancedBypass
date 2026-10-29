#include <jni.h>
#include <dlfcn.h>
#include <string>
#include <cstring>
#include "../utils/log.h"
#include "bytehook.h"

/**
 * hook_libqsec.cpp —— 修正版
 *
 * ★ 修正说明（基于 libQSec.so 的 ELF 手工逆向，readelf + od 逐字节解析）：
 *
 *   原实现对 libQSec.so 调 bytehook_hook_single("libQSec.so", nullptr, "dlopen", ...)。
 *   这是【无效的】。ELF 实证：
 *     - libQSec.so 类型 DYN / aarch64，Entry 0x1f40，仅 4 个 section header（被 strip）
 *     - 动态符号共 41 个，其中【唯一导出函数是 JNI_OnLoad（值 0x5e14）】
 *     - dlopen / dlsym / dladdr / dlclose 出现在这 41 个符号里，但它们的身份是
 *       【导入符号（UND）】，即 libQSec.so 去调用【别的库】的 dlopen，
 *       而不是它自己导出一个叫 dlopen 的函数。
 *     - 23 个 R_AARCH64_GLOB_DAT 重定位正是指向这些导入符号。
 *   → 按 "libQSec.so" + "dlopen" 去查符号，查的是 libQSec.so 的导出表，必然落空。
 *
 *   正确做法：dlopen/dlsym/dladdr 应由 linker 提供，要拦就【全局拦】，
 *   即把库名传 nullptr（ByteHook 语义：匹配所有库），符号名给 dlopen/dlsym/dladdr。
 *
 * ★ 附加的实证结论（写在这里供后续维护者参考）：
 *   - JNI_OnLoad @0x5e14 处的 256 字节是【高熵随机字节】
 *     （b8 f4 ae 4f ef f8 17 de ...，256 字节中 140 个唯一值），
 *     而 entry 0x1f40 是合法 ARM64（f3 03 00 aa / e0 03 13 aa / c0 03 5f d6，
 *     附近有明文串 "aa1234567_"）。
 *     → 核心段加壳、运行时自解密。静态看不到它装了什么定时器回调。
 *   - 23 个重定位构成 JNI_OnLoad 的完整调用面：
 *     sleep / open / pthread_once / timer_create / chmod / pthread_mutex_init /
 *     __cxa_guard_acquire / __errno / _ZdlPv / write / timer_delete /
 *     __stack_chk_fail / _Znwm / dlclose / timer_settime / __cxa_guard_release /
 *     dlsym / strcmp / sprintf / sigaction / pthread_mutex_lock / strdup
 *     → 定时器定频自检 + 信号自保护 + dl* 遍历模块 + 文件探测。
 *   - 它【没有任何 Java_ 导出】，不向 Java 层提供接口，
 *     在 JNI_OnLoad 阶段自行启动，是典型的自保护型注入。
 */

static void* (*original_dlopen)(const char*, int) = nullptr;
static void* (*original_dlsym)(void*, const char*) = nullptr;
static int   (*original_dladdr)(const void*, Dl_info*) = nullptr;

// 命中即计数的统计（供 getHookStatisticsNative 展示）
static int g_dlopen_blocked = 0;
static int g_dlsym_blocked  = 0;
static int g_dladdr_spoofed = 0;

/** 是否是可疑的 hook 框架名字。集中一处，便于维护。 */
static bool is_hook_framework(const char* s) {
    if (!s) return false;
    return std::string(s).find("bytehook")  != std::string::npos
        || std::string(s).find("xhook")     != std::string::npos
        || std::string(s).find("shadowhook")!= std::string::npos
        || std::string(s).find("dobby")     != std::string::npos
        || std::string(s).find("xposed")    != std::string::npos
        || std::string(s).find("substrate") != std::string::npos
        || std::string(s).find("lspd")      != std::string::npos;
}

/**
 * 全局 hook dlopen。
 * 注意：这里拦的是【别人】调用 dlopen，不是 libQSec.so 导出的 dlopen。
 */
static void* hooked_dlopen(const char* filename, int flag) {
    if (filename && is_hook_framework(filename)) {
        __sync_fetch_and_add(&g_dlopen_blocked, 1);
        LOGI("dlopen blocked: %s", filename);
        return nullptr;
    }
    return original_dlopen ? original_dlopen(filename, flag)
                           : dlopen(filename, flag);
}

static void* hooked_dlsym(void* handle, const char* symbol) {
    if (symbol && is_hook_framework(symbol)) {
        __sync_fetch_and_add(&g_dlsym_blocked, 1);
        LOGI("dlsym blocked: %s", symbol);
        return nullptr;
    }
    return original_dlsym ? original_dlsym(handle, symbol)
                          : dlsym(handle, symbol);
}

static int hooked_dladdr(const void* addr, Dl_info* info) {
    int ret = original_dladdr ? original_dladdr(addr, info) : dladdr(addr, info);
    if (ret != 0 && info && info->dli_fname && is_hook_framework(info->dli_fname)) {
        __sync_fetch_and_add(&g_dladdr_spoofed, 1);
        LOGI("dladdr spoofed: %s -> /system/lib64/libc.so", info->dli_fname);
        // 伪装成系统库。注意 dli_fname 是 const char*，这里直接改写指针本身。
        info->dli_fname = "/system/lib64/libc.so";
        info->dli_fbase = nullptr;
        info->dli_sname = nullptr;
        info->dli_saddr = nullptr;
    }
    return ret;
}

static void install_one(const char* sym, void* hooked, void** orig) {
    bytehook_stub_t stub = bytehook_hook_single(
        nullptr, nullptr, sym, hooked, nullptr, orig);
    if (stub == nullptr) {
        LOGE("Failed to hook global %s", sym);
    } else {
        LOGI("hooked global %s (orig=%p)", sym, *orig);
    }
}

void install_qsec_hooks() {
    LOGI("Installing QSec hooks (GLOBAL dl*) ...");

    // ★ 库名传 nullptr = 全局匹配，而不是 "libQSec.so"。见文件头修正说明。
    install_one("dlopen", (void*)hooked_dlopen,  (void**)&original_dlopen);
    install_one("dlsym",  (void*)hooked_dlsym,   (void**)&original_dlsym);
    install_one("dladdr", (void*)hooked_dladdr,  (void**)&original_dladdr);

    LOGI("QSec hooks installed (dlopen=%d dlsym=%d dladdr=%d)",
         g_dlopen_blocked, g_dlsym_blocked, g_dladdr_spoofed);
}

/** 供 native-bypass.cpp 的统计接口取用 */
int qsec_get_dlopen_blocked()  { return g_dlopen_blocked; }
int qsec_get_dlsym_blocked()   { return g_dlsym_blocked; }
int qsec_get_dladdr_spoofed()  { return g_dladdr_spoofed; }