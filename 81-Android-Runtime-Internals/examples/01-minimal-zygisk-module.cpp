/*
 * 01-minimal-zygisk-module.cpp — the smallest useful Zygisk module.
 *
 * WHAT IT DOES
 *   Logs the lifecycle callbacks and the process UID. It does not hook
 *   anything. Its purpose is to prove that the loader reached the child and
 *   that pre-specialize runs before the UID drop.
 *
 * HOW TO BUILD
 *   curl -L -o zygisk.hpp \
 *     https://raw.githubusercontent.com/topjohnwu/zygisk-module-sample/master/module/jni/zygisk.hpp
 *   "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang++" \
 *     -shared -fPIC -std=c++17 -fno-exceptions -fno-rtti -fvisibility=hidden \
 *     -o arm64-v8a.so 01-minimal-zygisk-module.cpp -I. -llog
 *
 * HOW TO PACKAGE
 *   module.prop at the module root, and the library at zygisk/arm64-v8a.so.
 *   See Lab 03 for the full layout and the install steps.
 *
 * WHAT TO EXPECT
 *   adb logcat -s RuntimeLab
 *     onLoad
 *     pre-specialize uid=0
 *     post-specialize uid=<app uid>
 */

#include <jni.h>
#include <unistd.h>
#include <android/log.h>

#include "zygisk.hpp"

#define LOG_TAG "RuntimeLab"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

class RuntimeLabModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        api_ = api;
        env_ = env;
        LOGI("onLoad uid=%d", getuid());
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // Still root, still zygote's SELinux domain. Do privileged setup here.
        LOGI("pre-specialize uid=%d", getuid());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // The app's UID and SELinux domain. Do per-app work here.
        LOGI("post-specialize uid=%d", getuid());
    }

private:
    zygisk::Api *api_ = nullptr;
    JNIEnv *env_ = nullptr;
};

REGISTER_ZYGISK_MODULE(RuntimeLabModule)
