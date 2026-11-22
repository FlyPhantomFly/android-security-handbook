/*
 * 03-lsplant-hook-sketch.cpp — the shape of an LSPlant integration.
 *
 * WHAT IT DOES
 *   Shows the three separate concerns: Init (resolve ART symbols and the
 *   inline hooker), Hook (replace the target entrypoint and keep a backup),
 *   and Deoptimize (handle callers that inlined the target).
 *
 * THIS IS A SKETCH, NOT A STANDALONE BUILD.
 *   The InitInfo field names and the Dobby return codes vary between LSPlant
 *   and Dobby versions. Pin the commits from the framework you are using and
 *   check the headers. See Vector's .gitmodules for the pinned forks.
 *
 * HOW TO USE
 *   Read it beside LSPlant's lsplant.hpp and lsplant.cc. The point is the
 *   separation of concerns, not the exact syntax.
 */

#include <jni.h>
#include <dlfcn.h>
#include <lsplant.hpp>

namespace {

// LSPlant needs three things from the host: a way to install an inline hook,
// a way to remove it, and a way to resolve libart.so symbols.
lsplant::InitInfo make_init_info() {
    lsplant::InitInfo info{};
    info.inline_hooker = [](void *target, void *hooker, void **backup) {
        // Dobby is one possible inline hooker; LSPlant does not require it.
        return DobbyHook(target, hooker, backup) == RS_SUCCESS;
    };
    info.inline_unhooker = [](void *target) {
        return DobbyDestroy(target) == RT_SUCCESS;
    };
    info.art_symbol_resolver = [](const char *symbol) {
        return dlsym(RTLD_DEFAULT, symbol);
    };
    info.art_symbol_prefix_resolver = [](const char *prefix) {
        return dlsym(RTLD_DEFAULT, prefix);
    };
    return info;
}

}  // namespace

// Returns the backup method on success, or nullptr on failure.
jobject install_hook(JNIEnv *env, jobject target, jobject hooker, jobject callback) {
    static const lsplant::InitInfo info = make_init_info();
    if (!lsplant::Init(env, info)) {
        return nullptr;
    }
    return lsplant::Hook(env, target, hooker, callback);
}

// Use this when the target was inlined into a caller and the hook never fires.
// The caller set usually has to be identified separately.
bool fix_inlined_caller(JNIEnv *env, jobject caller) {
    return lsplant::Deoptimize(env, caller);
}
