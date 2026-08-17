// art_method_reference.cpp — annotated reference for the ART structures that
// matter to a security researcher, plus a working native self-inspection
// routine you can compile into a test app.
//
// WHAT IT DEMONSTRATES
//   1. The ArtMethod layout described in ../README.md section 3.15, annotated
//      with what each field means to an attacker.
//   2. The object header from section 3.18.
//   3. A JNI function that locates its own ArtMethod entry point and reports
//      the execution state — the native equivalent of scripts/artmethod-inspect.js.
//   4. A demonstration of why native integrity checks resist Java-level hooking
//      (section 5.2 and ../../38-TamperDetection/README.md).
//
// HOW TO BUILD
//   Add to an NDK project's CMakeLists.txt:
//
//     add_library(artref SHARED art_method_reference.cpp)
//     find_library(log-lib log)
//     target_link_libraries(artref ${log-lib})
//
//   Then from Java/Kotlin:
//
//     static { System.loadLibrary("artref"); }
//     public static native String probeSelf();
//     public static native long   entryPointOf(Class<?> cls, String method);
//
// ⚠️ CRITICAL CAVEAT
//   The field offsets below are NOT stable. ART ships as a Mainline module, so
//   two devices reporting the same Android release can have different ArtMethod
//   layouts (README section 3.26). This file therefore DERIVES the offset at
//   runtime rather than hard-coding it. Never ship hard-coded offsets; that is
//   the single biggest cause of "works on my phone" breakage in ART tooling.
//
// AUTHORISED TESTING AND EDUCATION ONLY.

#include <jni.h>
#include <android/log.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <dlfcn.h>
#include <unistd.h>

#define LOG_TAG "ARTREF"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

namespace artref {

// ---------------------------------------------------------------------------
// 1. REFERENCE LAYOUTS
//
// These mirror art/runtime/art_method.h and art/runtime/mirror/object.h.
// They are documentation, not something to cast a real pointer to blindly.
// ---------------------------------------------------------------------------

/**
 * ArtMethod — the most security-relevant structure in Android.
 *
 * Key properties:
 *   - It is a plain C++ struct, NOT a managed object.
 *   - It does NOT live on the Java heap.
 *   - The garbage collector therefore NEVER moves it.
 *
 * That last point is what makes it a stable target to patch, and it is why
 * every Java hooking framework on Android converges on the same technique.
 */
struct ArtMethodReference {
    // The owning class. A GC root, so it keeps the class alive.
    // Compressed to 32 bits on 64-bit builds.
    uint32_t declaring_class_;

    // Java access flags in the low bits (ACC_PUBLIC, ACC_STATIC, ACC_NATIVE...)
    // PLUS ART-internal bits in the high range, including:
    //   kAccFastNative, kAccCompileDontBother, kAccPreviouslyWarm
    //   and — importantly for attackers — the HIDDEN API access bits that
    //   implement non-SDK interface restrictions. Clearing those is one route
    //   to bypassing hidden-API enforcement.
    uint32_t access_flags_;

    // Index into the declaring DEX file's method_ids table. This is how you
    // map a runtime method back to a name.
    uint32_t dex_method_index_;

    // Slot in the declaring class's vtable (virtual dispatch) or the
    // interface method table (interface dispatch). See README section 3.19.
    uint16_t method_index_;

    // JIT invocation counter. When it crosses dalvik.vm.jitthreshold the
    // method is queued for compilation. Doubles as imt_index_ for interfaces.
    uint16_t hotness_count_;

    struct PtrSizedFields {
        // For a NATIVE method this is the JNI function pointer. Overwrite it
        // and you have redirected a native method without touching its code —
        // a quieter alternative to inline hooking.
        void* data_;

        // *** THE FIELD THAT MATTERS ***
        //
        // Where execution goes when this method is called. Its value encodes
        // the method's execution state:
        //
        //   address in OAT oatexec         -> AOT compiled
        //   address in JIT code cache      -> JIT compiled
        //   art_quick_to_interpreter_bridge-> interpreted
        //   art_quick_resolution_trampoline-> not yet resolved
        //   art_quick_generic_jni_trampoline-> native, generic stub
        //   art_quick_instrumentation_entry-> instrumented / deoptimized
        //
        // Frida, Xposed and LSPosed all hook by overwriting this pointer.
        // So does ART itself, every time the JIT compiles a method.
        void* entry_point_from_quick_compiled_code_;
    } ptr_sized_fields_;
};

/**
 * The managed object header (README section 3.18).
 *
 * The monitor word is genuinely multi-purpose: identity hash, thin-lock state,
 * fat-monitor pointer, or — during a concurrent copying GC — the FORWARDING
 * ADDRESS the object is being moved to.
 *
 * That last use is why a raw object address is not stable across a GC, and why
 * Frida hands you handles rather than pointers.
 */
struct ObjectHeaderReference {
    uint32_t klass_;     // mirror::Class* (compressed)
    uint32_t monitor_;   // hash / lock / forwarding address
    // instance fields follow
};

// ---------------------------------------------------------------------------
// 2. RUNTIME OFFSET DERIVATION
//
// Because the layout is not stable, find the entry-point offset by looking for
// a pointer that is either a known ART trampoline or lies in executable memory.
// ---------------------------------------------------------------------------

struct MemRange {
    uintptr_t start;
    uintptr_t end;
    bool      executable;
    char      path[256];
};

static std::vector<MemRange> ReadMaps() {
    std::vector<MemRange> ranges;
    FILE* f = fopen("/proc/self/maps", "r");
    if (f == nullptr) return ranges;

    char line[512];
    while (fgets(line, sizeof(line), f) != nullptr) {
        MemRange r{};
        char perms[8] = {0};
        r.path[0] = '\0';
        // Format: start-end perms offset dev inode path
        int n = sscanf(line, "%lx-%lx %7s %*s %*s %*s %255[^\n]",
                       &r.start, &r.end, perms, r.path);
        if (n >= 3) {
            r.executable = (strchr(perms, 'x') != nullptr);
            ranges.push_back(r);
        }
    }
    fclose(f);
    return ranges;
}

static bool IsExecutable(const std::vector<MemRange>& ranges, uintptr_t addr,
                         const char** pathOut) {
    for (const auto& r : ranges) {
        if (addr >= r.start && addr < r.end) {
            if (pathOut != nullptr) *pathOut = r.path;
            return r.executable;
        }
    }
    return false;
}

/**
 * Resolve a known ART trampoline. Not all builds export these, so callers must
 * tolerate nullptr. This is exactly the portability problem described in
 * README section 3.26.
 */
static void* FindArtSymbol(const char* name) {
    void* handle = dlopen("libart.so", RTLD_NOW | RTLD_NOLOAD);
    if (handle == nullptr) {
        handle = dlopen("libart.so", RTLD_NOW);
    }
    if (handle == nullptr) return nullptr;
    void* sym = dlsym(handle, name);
    return sym;
}

/**
 * Derive the byte offset of entry_point_from_quick_compiled_code_ within
 * ArtMethod, by scanning for a pointer that lands in executable memory.
 *
 * Returns -1 on failure. Callers MUST handle that rather than assuming a value.
 */
static int DeriveEntryPointOffset(void* artMethod,
                                  const std::vector<MemRange>& ranges) {
    if (artMethod == nullptr) return -1;

    auto* base = reinterpret_cast<uint8_t*>(artMethod);
    const int kPtr = static_cast<int>(sizeof(void*));
    int best = -1;

    // The entry point is conventionally the last pointer-sized field, so we
    // scan forwards and keep the LAST qualifying offset.
    for (int off = 0; off <= 64; off += kPtr) {
        uintptr_t value = 0;
        memcpy(&value, base + off, sizeof(value));
        if (value == 0) continue;
        if (IsExecutable(ranges, value, nullptr)) {
            best = off;
        }
    }
    return best;
}

// ---------------------------------------------------------------------------
// 3. SELF-INSPECTION
// ---------------------------------------------------------------------------

static std::string ClassifyEntryPoint(uintptr_t ep,
                                      const std::vector<MemRange>& ranges) {
    struct { const char* sym; const char* meaning; } known[] = {
        {"art_quick_to_interpreter_bridge",  "INTERPRETED"},
        {"art_quick_generic_jni_trampoline", "NATIVE (generic JNI stub)"},
        {"art_quick_resolution_trampoline",  "UNRESOLVED (first call resolves)"},
        {"art_quick_imt_conflict_trampoline","IMT CONFLICT"},
        {"art_quick_instrumentation_entry",  "INSTRUMENTED (deoptimized/hooked)"},
    };

    for (const auto& k : known) {
        void* addr = FindArtSymbol(k.sym);
        if (addr != nullptr && reinterpret_cast<uintptr_t>(addr) == ep) {
            return std::string(k.meaning) + "  [" + k.sym + "]";
        }
    }

    const char* path = nullptr;
    if (IsExecutable(ranges, ep, &path)) {
        if (path != nullptr && path[0] != '\0') {
            // File-backed executable memory: AOT code from the OAT file.
            return std::string("AOT compiled  [") + path + "]";
        }
        // Anonymous executable memory: the JIT code cache.
        return "JIT compiled  [anonymous — JIT code cache]";
    }
    return "UNKNOWN";
}

}  // namespace artref

// ---------------------------------------------------------------------------
// 4. JNI ENTRY POINTS
// ---------------------------------------------------------------------------

extern "C" JNIEXPORT jstring JNICALL
Java_com_artlab_probe_NativeProbe_probeSelf(JNIEnv* env, jclass /*clazz*/) {
    std::string out;
    char buf[512];

    snprintf(buf, sizeof(buf), "pid=%d  pointerSize=%zu\n",
             getpid(), sizeof(void*));
    out += buf;

    auto ranges = artref::ReadMaps();
    snprintf(buf, sizeof(buf), "mapped ranges: %zu\n", ranges.size());
    out += buf;

    // Report whether the interpreter bridge symbol is available. Its absence
    // is informative: it tells you this ART build strips those symbols, and
    // therefore that symbol-based tooling will need a fallback.
    void* bridge = artref::FindArtSymbol("art_quick_to_interpreter_bridge");
    snprintf(buf, sizeof(buf), "art_quick_to_interpreter_bridge = %p%s\n",
             bridge, bridge == nullptr ? "  (NOT EXPORTED on this build)" : "");
    out += buf;

    // Count executable anonymous ranges. These are the JIT code cache — and
    // the reason naive "executable anonymous memory means injected code"
    // anti-Frida checks produce false positives on every app.
    size_t anonExec = 0;
    for (const auto& r : ranges) {
        if (r.executable && r.path[0] == '\0') anonExec++;
    }
    snprintf(buf, sizeof(buf),
             "executable anonymous ranges: %zu  (JIT code cache — legitimate)\n",
             anonExec);
    out += buf;

    LOGI("%s", out.c_str());
    return env->NewStringUTF(out.c_str());
}

/**
 * Report the entry point and execution state of an arbitrary Java method.
 *
 * This is the native equivalent of scripts/artmethod-inspect.js. It works even
 * when Java-level tooling is blocked, and it demonstrates why native integrity
 * checks are harder to defeat than Java ones: none of this calls into the
 * framework, so hooking PackageManager or any Java API achieves nothing.
 */
extern "C" JNIEXPORT jstring JNICALL
Java_com_artlab_probe_NativeProbe_inspectMethod(JNIEnv* env, jclass /*clazz*/,
                                                jclass target, jstring jname,
                                                jstring jsig) {
    const char* name = env->GetStringUTFChars(jname, nullptr);
    const char* sig  = env->GetStringUTFChars(jsig,  nullptr);

    std::string out;
    char buf[512];

    // GetMethodID returns a jmethodID, which in ART IS an ArtMethod pointer.
    // This is an implementation detail, not a contract — but it is stable in
    // practice and is what makes native introspection possible.
    jmethodID mid = env->GetMethodID(target, name, sig);
    if (mid == nullptr) {
        env->ExceptionClear();
        mid = env->GetStaticMethodID(target, name, sig);
    }

    if (mid == nullptr) {
        env->ExceptionClear();
        out = "method not found: ";
        out += name;
        out += sig;
    } else {
        void* artMethod = reinterpret_cast<void*>(mid);
        auto ranges = artref::ReadMaps();

        snprintf(buf, sizeof(buf), "method   : %s%s\nArtMethod: %p\n",
                 name, sig, artMethod);
        out += buf;

        int off = artref::DeriveEntryPointOffset(artMethod, ranges);
        if (off < 0) {
            out += "entry point offset: could not derive on this build\n";
        } else {
            uintptr_t ep = 0;
            memcpy(&ep, reinterpret_cast<uint8_t*>(artMethod) + off, sizeof(ep));

            snprintf(buf, sizeof(buf),
                     "offset   : +0x%x (derived, NOT hard-coded)\n"
                     "entry    : 0x%lx\n"
                     "state    : %s\n",
                     off, static_cast<unsigned long>(ep),
                     artref::ClassifyEntryPoint(ep, ranges).c_str());
            out += buf;

            // Decode the low access flags for context.
            uint32_t af = 0;
            memcpy(&af, reinterpret_cast<uint8_t*>(artMethod) + 4, sizeof(af));
            snprintf(buf, sizeof(buf), "flags    : 0x%08x  ", af);
            out += buf;
            if (af & 0x0001) out += "PUBLIC ";
            if (af & 0x0002) out += "PRIVATE ";
            if (af & 0x0008) out += "STATIC ";
            if (af & 0x0010) out += "FINAL ";
            if (af & 0x0100) out += "NATIVE ";
            if (af & 0x0400) out += "ABSTRACT ";
            out += "\n(upper bits carry ART-internal and hidden-API state)\n";
        }
    }

    env->ReleaseStringUTFChars(jname, name);
    env->ReleaseStringUTFChars(jsig,  sig);

    LOGI("%s", out.c_str());
    return env->NewStringUTF(out.c_str());
}

/*
 * WHY THIS MATTERS FOR DEFENCE
 *
 * An integrity check written in Java is defeated by one entry-point patch,
 * because the checking method is itself an ArtMethod. A check written here is
 * not: the attacker must locate the native function in Ghidra and either hook
 * it with Interceptor.attach or patch its instructions.
 *
 * That is a real increase in cost — but it is NOT a security boundary. Native
 * code runs in a process the attacker controls, so given enough time the check
 * falls too. See README section 5 and ../../38-TamperDetection/README.md.
 *
 * The only control that escapes this is one whose verdict is produced by
 * hardware the attacker does not control and evaluated by a server they do not
 * control. Everything on the client buys time, not security.
 */
