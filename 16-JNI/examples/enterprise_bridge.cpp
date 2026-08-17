/*
 * examples/enterprise_bridge.cpp
 *
 * Example 9.5b -- the C++ half of a JNI layer someone senior owns.
 *
 * WHAT THIS SHOWS
 *     Every technique from README section 3, applied together, in the shape
 *     a large codebase actually uses:
 *
 *       - C++, so the compiler enforces the jstring / jbyteArray / jobject
 *         distinction that plain C erases into void*
 *       - RAII wrappers, so every acquisition is released on EVERY path
 *         including the error paths -- the universal cause of JNI leaks is
 *         an early return that skips a Release call
 *       - IDs cached exactly once, each behind a GLOBAL jclass reference,
 *         because an ID's validity is tied to its class staying loaded
 *       - one throwJava helper, so error handling is uniform
 *       - a session registry keyed by an opaque token with a generation
 *         counter, so a forged or stale token is rejected by an integer
 *         comparison instead of being dereferenced (README 5.5 fix (c))
 *       - dynamic registration from JNI_OnLoad, written out in full
 *       - an explicit thread-attachment helper with a pthread_key
 *         destructor, so a worker thread that dies without detaching cannot
 *         abort the process (README 3.19)
 *       - exception discipline: check after every fallible call, and decide
 *         deliberately between propagating and clearing
 *
 * WHAT IT IS NOT
 *     A cryptography example. `seal` here is a placeholder XOR so the file
 *     stays about the boundary. Real sealing belongs in a reviewed library
 *     -- see ../../34-Cryptography/README.md.
 *
 * BUILD (host, requires the Android NDK)
 *     Verified: compiles clean with -Wall -Wextra under
 *     aarch64-linux-android21-clang from NDK 25.2.9519653. ./build.sh in
 *     this directory reproduces it, out of tree.
 *     See examples/README.md. In CMake:
 *         add_library(enterprise SHARED enterprise_bridge.cpp)
 *         target_compile_options(enterprise PRIVATE
 *             -fvisibility=hidden -fstack-protector-strong -D_FORTIFY_SOURCE=2)
 *         target_link_options(enterprise PRIVATE -Wl,-z,relro,-z,now)
 *
 *     -fvisibility=hidden is deliberate: with dynamic registration nothing
 *     but JNI_OnLoad needs to be exported, and hiding the rest is free.
 *
 * NOTE ON libnativehelper
 *     AOSP's own native code uses ScopedLocalRef, ScopedUtfChars and
 *     ScopedByteArrayRO from libnativehelper, which do exactly what the
 *     wrappers below do. They are not available to app code, which is why
 *     this file writes its own -- but if you are recommending a remediation
 *     for platform code, name theirs.
 */

#include <jni.h>
#include <pthread.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

/* ================================================================== */
/* Cached runtime state                                                */
/* ================================================================== */

JavaVM*   gVm            = nullptr;   /* process-wide: safe to cache      */
jclass    gBridgeClass   = nullptr;   /* GLOBAL ref, keeps the IDs alive  */
jclass    gListenerClass = nullptr;   /* GLOBAL ref                       */
jmethodID gOnResult      = nullptr;   /* ResultListener.onResult(I[B)V    */
pthread_key_t gDetachKey;             /* see AttachedEnv below            */

constexpr const char* kBridgeClassName   = "com/example/bridge/EnterpriseBridge";
constexpr const char* kListenerClassName = "com/example/bridge/EnterpriseBridge$ResultListener";

/* Note the '$' in the listener's name. In a DESCRIPTOR and in a FindClass
 * argument, '$' stays a literal '$'. It becomes _00024 only in a mangled
 * SYMBOL name -- and since this library registers dynamically, no mangled
 * symbol exists at all. Confusing the two encodings is the most common
 * mangling error; see README section 3.5. */

/* ================================================================== */
/* RAII wrappers. The whole point: release happens on EVERY path.      */
/* ================================================================== */

/* A scoped local reference. Deletes on destruction, so an early return
 * cannot leak it and the local reference table cannot creep. */
template <typename T>
class ScopedLocal {
public:
    ScopedLocal(JNIEnv* env, T ref) : env_(env), ref_(ref) {}
    ~ScopedLocal() { if (ref_ != nullptr) env_->DeleteLocalRef(ref_); }
    ScopedLocal(const ScopedLocal&) = delete;
    ScopedLocal& operator=(const ScopedLocal&) = delete;
    T get() const { return ref_; }
    explicit operator bool() const { return ref_ != nullptr; }
private:
    JNIEnv* env_;
    T ref_;
};

/* GetStringUTFChars / ReleaseStringUTFChars, paired by the destructor.
 * c_str() is nullptr when the acquisition failed, in which case an
 * OutOfMemoryError is already pending. */
class ScopedUtf {
public:
    ScopedUtf(JNIEnv* env, jstring s) : env_(env), s_(s), p_(nullptr) {
        if (s != nullptr) p_ = env->GetStringUTFChars(s, nullptr);
    }
    ~ScopedUtf() { if (p_ != nullptr) env_->ReleaseStringUTFChars(s_, p_); }
    ScopedUtf(const ScopedUtf&) = delete;
    ScopedUtf& operator=(const ScopedUtf&) = delete;
    const char* c_str() const { return p_; }
private:
    JNIEnv* env_;
    jstring s_;
    const char* p_;
};

/* Copy a jbyteArray into owned memory. Deliberately a COPY rather than a
 * pinned pointer: it closes the time-of-check/time-of-use window in which
 * another Java thread mutates the array between our length read and our
 * use of the contents. See UnsafeDemo.java's closing note. */
class OwnedBytes {
public:
    OwnedBytes(JNIEnv* env, jbyteArray arr) : ok_(false) {
        if (arr == nullptr) return;
        const jsize n = env->GetArrayLength(arr);
        if (n < 0) return;
        buf_.resize(static_cast<size_t>(n));
        if (n > 0) {
            env->GetByteArrayRegion(arr, 0, n, reinterpret_cast<jbyte*>(buf_.data()));
            if (env->ExceptionCheck()) return;      /* bounds threw; leave ok_ false */
        }
        ok_ = true;
    }
    bool ok() const { return ok_; }
    uint8_t* data() { return buf_.data(); }
    size_t size() const { return buf_.size(); }
private:
    std::vector<uint8_t> buf_;
    bool ok_;
};

/* Attach the calling thread if it is not already attached, and arrange for
 * DetachCurrentThread to run when the thread exits. ART ABORTS THE PROCESS
 * if an attached thread dies without detaching, so this is not optional for
 * a library that creates its own threads. */
void detachOnThreadExit(void*) {
    if (gVm != nullptr) gVm->DetachCurrentThread();
}

class AttachedEnv {
public:
    AttachedEnv() : env_(nullptr) {
        if (gVm == nullptr) return;
        const jint rc = gVm->GetEnv(reinterpret_cast<void**>(&env_), JNI_VERSION_1_6);
        if (rc == JNI_EDETACHED) {
            JavaVMAttachArgs args{JNI_VERSION_1_6, "enterprise-worker", nullptr};
            if (gVm->AttachCurrentThreadAsDaemon(&env_, &args) != JNI_OK) {
                env_ = nullptr;
                return;
            }
            /* Register the destructor exactly once per thread. Setting a
             * non-null value is what arms it. */
            pthread_setspecific(gDetachKey, reinterpret_cast<void*>(1));
        } else if (rc != JNI_OK) {
            env_ = nullptr;
        }
        /* If rc was JNI_OK we did NOT attach, so we must not detach. */
    }
    JNIEnv* get() const { return env_; }
    explicit operator bool() const { return env_ != nullptr; }
private:
    JNIEnv* env_;
};

/* ================================================================== */
/* Errors -- one helper, so every path reports the same way            */
/* ================================================================== */

void throwJava(JNIEnv* env, const char* clsName, const char* msg) {
    /* Do not call this while an exception is already pending: FindClass is
     * not legal in that state. Callers clear first if they are recovering. */
    if (env->ExceptionCheck()) return;
    ScopedLocal<jclass> cls(env, env->FindClass(clsName));
    if (cls) env->ThrowNew(cls.get(), msg);
    /* If FindClass failed, its own exception is pending, which is still a
     * correct outcome. */
}

void throwIse(JNIEnv* env, const char* msg) {
    throwJava(env, "java/lang/IllegalStateException", msg);
}

void throwIae(JNIEnv* env, const char* msg) {
    throwJava(env, "java/lang/IllegalArgumentException", msg);
}

/* ================================================================== */
/* The session registry -- an opaque token, never an address            */
/*                                                                      */
/* token = (generation << 32) | slot                                    */
/*                                                                      */
/* A forged token fails an integer comparison. A stale token fails the   */
/* generation check. Neither is ever dereferenced, which is the whole    */
/* difference from unsafe_jni.c's VULN 4.                                */
/* ================================================================== */

struct Session {
    uint32_t generation = 0;
    bool     live       = false;
    std::string config;
    uint8_t  key        = 0x37;
};

std::mutex gSessionsMu;
std::unordered_map<uint32_t, Session> gSessions;
uint32_t gNextSlot = 1;
uint32_t gNextGeneration = 1;

jlong sessionCreate(const std::string& config) {
    std::lock_guard<std::mutex> lock(gSessionsMu);
    const uint32_t slot = gNextSlot++;
    const uint32_t gen  = gNextGeneration++;
    Session s;
    s.generation = gen;
    s.live = true;
    s.config = config;
    gSessions[slot] = std::move(s);
    return (static_cast<jlong>(gen) << 32) | static_cast<jlong>(slot);
}

/* Returns a COPY of what the caller needs, under the lock, rather than a
 * pointer that could be freed by another thread mid-use. */
bool sessionLookup(jlong token, Session* out) {
    if (token == 0) return false;
    const uint32_t slot = static_cast<uint32_t>(token & 0xFFFFFFFFu);
    const uint32_t gen  = static_cast<uint32_t>((static_cast<uint64_t>(token) >> 32) & 0xFFFFFFFFu);
    std::lock_guard<std::mutex> lock(gSessionsMu);
    auto it = gSessions.find(slot);
    if (it == gSessions.end()) return false;
    if (!it->second.live) return false;
    if (it->second.generation != gen) return false;   /* stale token */
    *out = it->second;
    return true;
}

bool sessionDestroy(jlong token) {
    if (token == 0) return false;
    const uint32_t slot = static_cast<uint32_t>(token & 0xFFFFFFFFu);
    const uint32_t gen  = static_cast<uint32_t>((static_cast<uint64_t>(token) >> 32) & 0xFFFFFFFFu);
    std::lock_guard<std::mutex> lock(gSessionsMu);
    auto it = gSessions.find(slot);
    if (it == gSessions.end() || !it->second.live || it->second.generation != gen) {
        return false;                                  /* double close, or forged */
    }
    gSessions.erase(it);
    return true;
}

/* ================================================================== */
/* The implementations. All static: nothing but JNI_OnLoad is exported. */
/*                                                                      */
/* Every one is a STATIC Java method, so the second parameter is a      */
/* jclass. The real arguments still start at the third parameter --     */
/* args[2] in a Frida hook.                                             */
/* ================================================================== */

jlong nativeOpen(JNIEnv* env, jclass, jstring configJson) {
    ScopedUtf cfg(env, configJson);
    if (cfg.c_str() == nullptr) {
        /* Either configJson was null, or the acquisition OOMed and an
         * exception is already pending. Distinguish, so the caller gets a
         * useful error rather than a confusing one. */
        if (!env->ExceptionCheck()) throwIae(env, "config is null");
        return 0;
    }
    return sessionCreate(std::string(cfg.c_str()));
}

void nativeClose(JNIEnv* env, jclass, jlong token) {
    if (!sessionDestroy(token)) {
        /* A clean exception, not a double free. The Java side's
         * AtomicLong.getAndSet(0) should make this unreachable; this is the
         * defence in depth that assumes it is reachable anyway. */
        throwIse(env, "invalid or already-closed session");
    }
}

jbyteArray sealImpl(JNIEnv* env, jlong token, jbyteArray payload, bool /*unseal*/) {
    Session s;
    if (!sessionLookup(token, &s)) { throwIse(env, "invalid or closed session"); return nullptr; }

    OwnedBytes bytes(env, payload);
    if (!bytes.ok()) {
        if (!env->ExceptionCheck()) throwIae(env, "payload is null or unreadable");
        return nullptr;
    }
    if (bytes.size() > (1u << 22)) { throwIae(env, "payload too large"); return nullptr; }

    /* Placeholder transform. The security content of this file is the
     * boundary, not this loop. */
    for (size_t i = 0; i < bytes.size(); ++i) bytes.data()[i] ^= s.key;

    const jsize n = static_cast<jsize>(bytes.size());
    jbyteArray out = env->NewByteArray(n);
    if (out == nullptr) return nullptr;                /* OutOfMemoryError pending */
    ScopedLocal<jbyteArray> guard(env, out);

    env->SetByteArrayRegion(out, 0, n, reinterpret_cast<const jbyte*>(bytes.data()));
    if (env->ExceptionCheck()) return nullptr;

    /* We are returning this reference, so do NOT let the guard delete it.
     * NewLocalRef gives us a second reference; the guard deletes one and we
     * return the other. (Alternatively, restructure so the guard is not
     * constructed on the success path -- either is fine; silently returning
     * a reference a destructor is about to delete is not.) */
    return static_cast<jbyteArray>(env->NewLocalRef(out));
}

jbyteArray nativeSeal(JNIEnv* env, jclass, jlong token, jbyteArray payload) {
    return sealImpl(env, token, payload, false);
}

jbyteArray nativeUnseal(JNIEnv* env, jclass, jlong token, jbyteArray sealed) {
    return sealImpl(env, token, sealed, true);
}

/* The async path exists to exercise the thread rules. In a real product the
 * work would go to a pool; the JNI-relevant part is identical. */
struct AsyncJob {
    jlong token;
    std::vector<uint8_t> payload;
    jobject listener;     /* a GLOBAL reference: it must outlive this call */
};

void* asyncWorker(void* raw) {
    AsyncJob* job = static_cast<AsyncJob*>(raw);

    AttachedEnv attached;                     /* attaches if needed; detaches at exit */
    JNIEnv* env = attached.get();
    if (env == nullptr) { delete job; return nullptr; }

    Session s;
    const bool ok = sessionLookup(job->token, &s);
    if (ok) {
        for (size_t i = 0; i < job->payload.size(); ++i) job->payload[i] ^= s.key;
    }

    const jsize n = static_cast<jsize>(job->payload.size());
    jbyteArray out = env->NewByteArray(n);
    if (out != nullptr) {
        ScopedLocal<jbyteArray> guard(env, out);
        env->SetByteArrayRegion(out, 0, n,
                                reinterpret_cast<const jbyte*>(job->payload.data()));
        if (!env->ExceptionCheck()) {
            env->CallVoidMethod(job->listener, gOnResult, ok ? 0 : -1, out);
            /* The Java listener may have thrown. There is no Java caller on
             * this thread to propagate to, so we must clear -- and log,
             * because a silently swallowed callback exception is its own
             * bug class. */
            if (env->ExceptionCheck()) {
                env->ExceptionDescribe();     /* logs AND clears */
                env->ExceptionClear();        /* harmless if already cleared */
            }
        } else {
            env->ExceptionClear();
        }
    } else {
        env->ExceptionClear();                /* NewByteArray OOM */
    }

    env->DeleteGlobalRef(job->listener);      /* the global ref's owner is us */
    delete job;
    return nullptr;
}

void nativeSealAsync(JNIEnv* env, jclass, jlong token, jbyteArray payload,
                     jobject listener) {
    if (listener == nullptr) { throwIae(env, "listener is null"); return; }

    OwnedBytes bytes(env, payload);
    if (!bytes.ok()) {
        if (!env->ExceptionCheck()) throwIae(env, "payload is null");
        return;
    }

    /* A LOCAL reference dies when this method returns, and is valid only on
     * this thread. The worker needs neither of those properties, so promote
     * to a global. Forgetting this is one of the most common JNI crashes,
     * and it fails far from the mistake. */
    jobject globalListener = env->NewGlobalRef(listener);
    if (globalListener == nullptr) { throwIse(env, "NewGlobalRef failed"); return; }

    AsyncJob* job = new AsyncJob();
    job->token = token;
    job->payload.assign(bytes.data(), bytes.data() + bytes.size());
    job->listener = globalListener;

    pthread_t t;
    if (pthread_create(&t, nullptr, asyncWorker, job) != 0) {
        env->DeleteGlobalRef(globalListener);
        delete job;
        throwIse(env, "pthread_create failed");
        return;
    }
    pthread_detach(t);
}

/* ================================================================== */
/* Registration                                                        */
/* ================================================================== */

const JNINativeMethod kMethods[] = {
    { "nativeOpen",      "(Ljava/lang/String;)J",  reinterpret_cast<void*>(nativeOpen) },
    { "nativeClose",     "(J)V",                   reinterpret_cast<void*>(nativeClose) },
    { "nativeSeal",      "(J[B)[B",                reinterpret_cast<void*>(nativeSeal) },
    { "nativeUnseal",    "(J[B)[B",                reinterpret_cast<void*>(nativeUnseal) },
    { "nativeSealAsync",
      "(J[BLcom/example/bridge/EnterpriseBridge$ResultListener;)V",
      reinterpret_cast<void*>(nativeSealAsync) },
};

/* Signature matching in RegisterNatives is EXACT STRING COMPARISON against
 * the method's descriptor. One wrong character -- a missing ';', a '.' where
 * a '/' belongs, the wrong return type -- and RegisterNatives returns a
 * negative value with NoSuchMethodError pending. That is the single most
 * common cause of "RegisterNatives fails and I cannot see why". */

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    gVm = vm;

    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    if (pthread_key_create(&gDetachKey, detachOnThreadExit) != 0) return JNI_ERR;

    /* FindClass here resolves against the app's ClassLoader because ART set
     * that up for the duration of JNI_OnLoad. The same call from a worker
     * thread later would resolve against the system ClassLoader and fail --
     * which is exactly why all FindClass work happens here and the results
     * are cached as global references. README section 4.2. */
    jclass localBridge = env->FindClass(kBridgeClassName);
    if (localBridge == nullptr) return JNI_ERR;

    if (env->RegisterNatives(localBridge, kMethods,
                             static_cast<jint>(sizeof(kMethods) / sizeof(kMethods[0])))
        != JNI_OK) {
        env->DeleteLocalRef(localBridge);
        return JNI_ERR;
    }

    gBridgeClass = static_cast<jclass>(env->NewGlobalRef(localBridge));
    env->DeleteLocalRef(localBridge);
    if (gBridgeClass == nullptr) return JNI_ERR;

    jclass localListener = env->FindClass(kListenerClassName);
    if (localListener == nullptr) return JNI_ERR;
    gListenerClass = static_cast<jclass>(env->NewGlobalRef(localListener));
    env->DeleteLocalRef(localListener);
    if (gListenerClass == nullptr) return JNI_ERR;

    /* Cache the ID behind the GLOBAL class reference. Caching an ID while
     * letting its class be unloaded is a use-after-free waiting to happen. */
    gOnResult = env->GetMethodID(gListenerClass, "onResult", "(I[B)V");
    if (gOnResult == nullptr) return JNI_ERR;      /* NoSuchMethodError pending */

    /* The return value is a JNI VERSION, not a status. */
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return;
    if (gBridgeClass != nullptr)   { env->DeleteGlobalRef(gBridgeClass);   gBridgeClass = nullptr; }
    if (gListenerClass != nullptr) { env->DeleteGlobalRef(gListenerClass); gListenerClass = nullptr; }
}
