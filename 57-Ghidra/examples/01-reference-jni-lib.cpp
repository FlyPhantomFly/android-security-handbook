/*
 * 01-reference-jni-lib.cpp — a reference library that exercises every pattern
 *                            this chapter teaches you to recognise.
 *
 * WHAT IT IS
 *   A single native library containing, deliberately, one clean example of each
 *   construct you will meet in real Android binaries. Build it, open it in
 *   Ghidra, and use it as a Rosetta stone: you know the source, so you can see
 *   exactly what the compiler and the decompiler did to it.
 *
 *   That is the fastest way to build recognition. Reading a stranger's stripped
 *   binary teaches you slowly; reading YOUR OWN stripped binary teaches you
 *   quickly, because you can check every guess.
 *
 * WHAT IT DEMONSTRATES
 *   1.  A statically registered JNI method            -> Java_* export
 *   2.  An OVERLOADED static method                   -> mangled __ suffix
 *   3.  A method with an underscore in the package    -> _1 escaping
 *   4.  Dynamically registered methods                -> JNI_OnLoad + table
 *   5.  A .init_array constructor                     -> runs before everything
 *   6.  Reading and writing Java strings              -> GetStringUTFChars
 *   7.  Reading and writing Java byte arrays          -> GetByteArrayElements
 *   8.  Calling back into Java                        -> GetMethodID + Call*
 *   9.  Throwing a Java exception from native code    -> ThrowNew
 *  10.  Caching a jclass as a global reference        -> NewGlobalRef
 *  11.  A custom struct with mixed field sizes        -> offset arithmetic
 *  12.  A switch statement                            -> jump table
 *  13.  A string comparison                           -> strcmp idiom
 *  14.  An FNV-1a hash                                -> recognisable constants
 *  15.  A stack buffer with strcpy                    -> the bug class you hunt
 *  16.  Debug logging with format strings             -> free documentation
 *
 * HOW TO BUILD
 *
 *   Fastest route -- no Gradle, no Android Studio. ./build.sh in this directory
 *   builds both the stripped and the unstripped .so with the NDK, out of tree.
 *
 *   Full app route: place in app/src/main/cpp/ alongside the CMakeLists.txt
 *   below, then:
 *     ./gradlew assembleRelease
 *     unzip -o -d raw app/build/outputs/apk/release/app-release.apk lib/\*
 *
 *   (The glob is backslash-escaped rather than single-quoted. A quoted glob
 *    would put a slash directly against an asterisk inside this C block
 *    comment, which opens a nested comment as far as clang is concerned and
 *    is reported as -Wcomment. The escaped form means the same thing to the
 *    shell and keeps this file warning-free -- and the same trap will bite you
 *    the first time you paste a path glob into a C comment of your own.)
 *
 *   CMakeLists.txt:
 *     cmake_minimum_required(VERSION 3.22)
 *     project(reference)
 *     add_library(reference SHARED 01-reference-jni-lib.cpp)
 *     find_library(log-lib log)
 *     target_link_libraries(reference ${log-lib})
 *     # Build BOTH ways and compare:
 *     #   stripped   -> what you will actually be given
 *     #   unstripped -> the answer key
 *     set_target_properties(reference PROPERTIES LINK_FLAGS "-Wl,--strip-all")
 *
 * HOW TO USE IT
 *   Build twice, once with --strip-all and once without. Import both into the
 *   same Ghidra project. Analyse the stripped one; check your answers against
 *   the unstripped one. Every FUN_... in the first has a name in the second.
 *
 * AUTHORISED TESTING ONLY - though this is your own code, so go ahead.
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>

#define TAG "REFLIB"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)

/* ==========================================================================
 * 11. A custom struct with mixed field sizes.
 *
 * In Ghidra this appears as offset arithmetic on an untyped pointer until you
 * define the struct. Note the padding: `flags` at +0x04 is followed by four
 * bytes of padding so that `created` at +0x08 is 8-byte aligned. Getting the
 * padding wrong is the usual reason a recovered struct does not total the
 * size you see in the malloc/calloc call.
 * ========================================================================== */

typedef struct {
    unsigned int       magic;      /* +0x00, 4 bytes  */
    unsigned int       flags;      /* +0x04, 4 bytes  */
    unsigned long long created;    /* +0x08, 8 bytes  */
    char               name[24];   /* +0x10, 24 bytes */
    unsigned char      digest[16]; /* +0x28, 16 bytes */
    unsigned int       counter;    /* +0x38, 4 bytes  */
                                   /* +0x3c, 4 bytes tail padding */
} Record;                          /* sizeof == 0x40  */

#define RECORD_MAGIC   0x52454331u   /* "REC1" - recognisable in a hexdump */
#define FLAG_VERIFIED  0x0001u
#define FLAG_SEALED    0x0002u
#define FLAG_READONLY  0x0004u

static Record *g_record = NULL;

/* ==========================================================================
 * 10. A cached global reference.
 *
 * Real libraries cache jclass and jmethodID values because looking them up is
 * expensive. In Ghidra these appear as writes to .bss globals from JNI_OnLoad
 * or from an initialisation function, and reads everywhere else.
 * ========================================================================== */

static jclass    g_callbackClass  = NULL;
static jmethodID g_callbackMethod = NULL;

/* ==========================================================================
 * 14. FNV-1a. The two constants below are worth memorising: 0x811C9DC5 is the
 *     32-bit offset basis and 0x01000193 is the prime. Seeing them together in
 *     a loop identifies the algorithm instantly, without reading the loop.
 *
 *     Other constants worth recognising on sight:
 *       0x67452301, 0xEFCDAB89   -> MD5 / SHA-1 initial state
 *       0x6A09E667, 0xBB67AE85   -> SHA-256 initial state
 *       0x9E3779B9               -> golden-ratio constant (TEA, xxHash)
 *       0xEDB88320               -> reversed CRC-32 polynomial
 *       0x63, 0x7C, 0x77, 0x7B   -> the first bytes of the AES S-box
 * ========================================================================== */

static unsigned int fnv1a(const unsigned char *data, size_t n,
                          unsigned int basis) {
    unsigned int h = basis;
    for (size_t i = 0; i < n; i++) {
        h = (h ^ data[i]) * 0x01000193u;
    }
    return h;
}

/* ==========================================================================
 * 5. A constructor.
 *
 * __attribute__((constructor)) puts a pointer to this function in .init_array.
 * The dynamic linker calls it during dlopen - BEFORE JNI_OnLoad, and long
 * before any Java code touches the library.
 *
 * That earliness is why anti-analysis and unpacking logic is placed here. It
 * is also why ../README.md section 11 tells you to read .init_array first.
 * ========================================================================== */

__attribute__((constructor))
static void library_init(void) {
    LOGI("constructor: library loaded, this runs before JNI_OnLoad");
}

/* ==========================================================================
 * 1. A statically registered JNI method.
 *
 * The symbol name is derived mechanically from the Java method:
 *   package com.example.ref, class Reference, method plainMethod
 *   -> Java_com_example_ref_Reference_plainMethod
 *
 * Find it in Ghidra under Symbol Tree -> Exports.
 * ========================================================================== */

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_ref_Reference_plainMethod(JNIEnv *env, jobject /* thiz */) {
    /* 6. NewStringUTF: native code producing a Java string. Offset 0x538. */
    return env->NewStringUTF("plain static registration");
}

/* ==========================================================================
 * 2. An OVERLOADED static method.
 *
 * When a Java method is overloaded, the mangled symbol gains "__" followed by
 * the encoded argument signature, because the plain name would be ambiguous.
 *
 *   process(String)      -> Java_..._process__Ljava_lang_String_2
 *   process(String, int) -> Java_..._process__Ljava_lang_String_2I
 *
 * In the suffix, _2 encodes ';' and _3 encodes '['.
 * ========================================================================== */

extern "C" JNIEXPORT jint JNICALL
Java_com_example_ref_Reference_process__Ljava_lang_String_2(
        JNIEnv *env, jobject /* thiz */, jstring input) {
    /* 6. GetStringUTFChars: native code consuming a Java string. Offset 0x548. */
    const char *s = env->GetStringUTFChars(input, NULL);
    if (s == NULL) return -1;

    unsigned int h = fnv1a((const unsigned char *) s, strlen(s), 0x811C9DC5u);

    /* Always release. A missing release is a leak, and in ART's checked JNI
     * mode it is a fatal error - which is itself a useful hint that a library
     * was never tested with CheckJNI enabled. */
    env->ReleaseStringUTFChars(input, s);

    /* 16. Debug logging. The format string survives stripping and tells the
     * analyst the return type and its meaning for free. */
    LOGI("process(String) -> 0x%08x", h);
    return (jint) h;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_ref_Reference_process__Ljava_lang_String_2I(
        JNIEnv *env, jobject /* thiz */, jstring input, jint seed) {
    const char *s = env->GetStringUTFChars(input, NULL);
    if (s == NULL) return -1;
    unsigned int h = fnv1a((const unsigned char *) s, strlen(s),
                           (unsigned int) seed);
    env->ReleaseStringUTFChars(input, s);
    return (jint) h;
}

/* ==========================================================================
 * 3. A package name containing an underscore.
 *
 * Java package com.example.my_pkg, class C, method m
 *   -> Java_com_example_my_1pkg_C_m
 *
 * The literal underscore in "my_pkg" becomes _1, so that it is distinguishable
 * from the _ that separates package components. Decoding this by hand is a
 * skill worth having; see ../README.md section 3.9.
 * ========================================================================== */

extern "C" JNIEXPORT jint JNICALL
Java_com_example_my_1pkg_Helper_compute(JNIEnv * /* env */,
                                        jobject /* thiz */, jint x) {
    return x * 31 + 7;
}

/* ==========================================================================
 * 7. Byte arrays: the crypto input/output path.
 *
 * GetByteArrayElements (0x5c0) gives you a pointer to the elements;
 * ReleaseByteArrayElements (0x600) hands it back. JNI_ABORT as the mode means
 * "discard any changes", which is the common case for read-only access.
 *
 * A function that calls both, with work in between, is almost always the
 * transform you are looking for.
 * ========================================================================== */

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_ref_Reference_transform(JNIEnv *env, jobject /* thiz */,
                                         jbyteArray input) {
    jsize n = env->GetArrayLength(input);
    if (n <= 0 || n > 4096) {
        return NULL;
    }

    jbyte *in = env->GetByteArrayElements(input, NULL);
    if (in == NULL) return NULL;

    jbyte *out = (jbyte *) malloc((size_t) n);
    if (out == NULL) {
        env->ReleaseByteArrayElements(input, in, JNI_ABORT);
        return NULL;
    }

    /* A trivially reversible transform, so you can verify your reading. */
    for (jsize i = 0; i < n; i++) {
        out[i] = (jbyte) (in[i] ^ (0x5A + (i & 0x0F)));
    }

    env->ReleaseByteArrayElements(input, in, JNI_ABORT);

    jbyteArray result = env->NewByteArray(n);
    env->SetByteArrayRegion(result, 0, n, out);
    free(out);
    return result;
}

/* ==========================================================================
 * 8. Calling BACK into Java.
 *
 * FindClass (0x30) -> GetMethodID (0x108) -> CallVoidMethod.
 * The GetMethodID call takes a name and a signature as literal strings, which
 * is a gift: those two strings tell you exactly which Java method is about to
 * be invoked, and therefore which Java class to open in JADX.
 *
 * Whenever you see a string like "(Ljava/lang/String;)V" in .rodata, look for
 * the GetMethodID that references it.
 * ========================================================================== */

extern "C" JNIEXPORT void JNICALL
Java_com_example_ref_Reference_notify(JNIEnv *env, jobject thiz,
                                      jstring message) {
    /* The cached-then-lazy shape, exactly as production libraries write it: a
     * read of the .bss global first, and the expensive lookup only if it is
     * still NULL. In Ghidra this decompiles to `if (DAT_... == 0) { ... }`
     * around the FindClass/GetMethodID pair, and that `DAT_` is the same
     * address JNI_OnLoad wrote. Cross-referencing the two is how you tie a
     * nameless global to a Java method name. */
    jmethodID mid = g_callbackMethod;

    if (mid == NULL) {
        jclass cls = env->GetObjectClass(thiz);
        if (cls == NULL) return;
        mid = env->GetMethodID(cls, "onNativeEvent", "(Ljava/lang/String;)V");
    }

    if (mid == NULL) {
        /* 9. Throwing a Java exception from native code. In Ghidra this is a
         * FindClass for the exception class followed by ThrowNew. */
        jclass ise = env->FindClass("java/lang/IllegalStateException");
        if (ise != NULL) {
            env->ThrowNew(ise, "onNativeEvent not found");
        }
        return;
    }

    env->CallVoidMethod(thiz, mid, message);
}

/* ==========================================================================
 * 12. A switch statement -> a jump table in .rodata.
 *
 * Ghidra usually recovers this correctly and renders it as a switch. When it
 * does not, you get a computed branch and a table of offsets, and the
 * decompilation looks broken. Recognising the shape saves you the confusion.
 * ========================================================================== */

extern "C" JNIEXPORT jint JNICALL
Java_com_example_ref_Reference_dispatch(JNIEnv * /* env */,
                                        jobject /* thiz */, jint op) {
    switch (op) {
        case 0:  return 100;
        case 1:  return 200;
        case 2:  return 300;
        case 3:  return 400;
        case 4:  return 500;
        case 5:  return 600;
        case 6:  return 700;
        case 7:  return 800;
        default: return -1;
    }
}

/* ==========================================================================
 * 13 + 15. String comparison, and the bug class.
 *
 * strcmp returning 0 means EQUAL, which reads backwards the first few times.
 * In decompiled C you will see `if (iVar1 == 0)` where the source said
 * `if (strcmp(a, b) == 0)`.
 *
 * The strcpy below into a 16-byte stack buffer is the classic stack overflow.
 * Finding this shape - an unbounded copy into a fixed buffer - is a large part
 * of what native-code vulnerability research consists of.
 * See ../../70-VulnerabilityResearch/README.md.
 * ========================================================================== */

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_ref_Reference_checkName(JNIEnv *env, jobject /* thiz */,
                                         jstring name) {
    const char *s = env->GetStringUTFChars(name, NULL);
    if (s == NULL) return JNI_FALSE;

    char buf[16];
    /* DELIBERATE BUG: no length check. This is what you are hunting. */
    strcpy(buf, s);

    jboolean result = (strcmp(buf, "administrator") == 0) ? JNI_TRUE : JNI_FALSE;

    env->ReleaseStringUTFChars(name, s);
    LOGW("checkName(%s) -> %d", buf, result);
    return result;
}

/* ==========================================================================
 * 11 (continued). Building the struct.
 * ========================================================================== */

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_ref_Reference_createRecord(JNIEnv *env, jobject /* thiz */,
                                            jstring name) {
    const char *s = env->GetStringUTFChars(name, NULL);
    if (s == NULL) return JNI_FALSE;

    Record *r = (Record *) calloc(1, sizeof(Record));
    if (r == NULL) {
        env->ReleaseStringUTFChars(name, s);
        return JNI_FALSE;
    }

    r->magic   = RECORD_MAGIC;
    r->flags   = FLAG_VERIFIED;
    r->created = 0x1234567800000000ULL;      /* a recognisable constant */
    strncpy(r->name, s, sizeof(r->name) - 1);
    r->counter = 1;

    unsigned int h = fnv1a((const unsigned char *) r->name,
                           strlen(r->name), 0x811C9DC5u);
    memcpy(r->digest, &h, sizeof(h));

    if (strcmp(r->name, "root") == 0) {
        r->flags |= FLAG_SEALED | FLAG_READONLY;
    }

    env->ReleaseStringUTFChars(name, s);

    free(g_record);
    g_record = r;
    return JNI_TRUE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_ref_Reference_describeRecord(JNIEnv *env, jobject /* thiz */) {
    char buf[128];
    if (g_record == NULL) {
        return env->NewStringUTF("no record");
    }
    /* 16. snprintf with a format string gives the analyst every field type. */
    snprintf(buf, sizeof(buf), "magic=%08x flags=%04x name=%s counter=%u",
             g_record->magic, g_record->flags, g_record->name,
             g_record->counter);
    return env->NewStringUTF(buf);
}

/* ==========================================================================
 * 4. Dynamically registered methods.
 *
 * These implementations are `static`, so after stripping they have no symbol
 * at all and appear only as FUN_... The mapping from Java name to address
 * exists solely in the kMethods table below.
 *
 * This is what defeats `readelf --dyn-syms | grep Java_`, and it is why
 * ../scripts/RecoverRegisterNatives.py exists.
 * ========================================================================== */

static jint impl_hidden_add(JNIEnv * /* env */, jobject /* thiz */,
                            jint a, jint b) {
    return a + b;
}

static jstring impl_hidden_secret(JNIEnv *env, jobject /* thiz */) {
    /* No plaintext constant: the value is assembled at runtime. */
    char buf[32];
    unsigned int k = fnv1a((const unsigned char *) "reference-seed", 14,
                           0x811C9DC5u);
    snprintf(buf, sizeof(buf), "S-%08x", k);
    return env->NewStringUTF(buf);
}

static jboolean impl_hidden_verify(JNIEnv *env, jobject /* thiz */,
                                   jstring token) {
    const char *s = env->GetStringUTFChars(token, NULL);
    if (s == NULL) return JNI_FALSE;
    unsigned int h = fnv1a((const unsigned char *) s, strlen(s), 0x811C9DC5u);
    env->ReleaseStringUTFChars(token, s);
    return (h == 0x7A3C11B4u) ? JNI_TRUE : JNI_FALSE;
}

/*
 * The table. Three pointers per entry:
 *   const char *name;       -> .rodata
 *   const char *signature;  -> .rodata
 *   void       *fnPtr;      -> .text
 *
 * That shape is exactly what a structural scan looks for.
 */
static JNINativeMethod kMethods[] = {
    { "hiddenAdd",    "(II)I",                 (void *) impl_hidden_add    },
    { "hiddenSecret", "()Ljava/lang/String;",  (void *) impl_hidden_secret },
    { "hiddenVerify", "(Ljava/lang/String;)Z", (void *) impl_hidden_verify }
};

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void * /* reserved */) {
    JNIEnv *env = NULL;

    /* GetEnv on the JavaVM, at offset 0x30 in the JNIInvokeInterface table.
     * Do not confuse it with FindClass, which is offset 0x30 in the JNIEnv
     * table - the receiver tells you which is which. */
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass c = env->FindClass("com/example/ref/Reference");
    if (c == NULL) return JNI_ERR;

    /* 10. Cache a global reference. A local reference would be invalid after
     * JNI_OnLoad returns; NewGlobalRef makes it survive. In Ghidra this is a
     * write to a .bss global. */
    g_callbackClass = (jclass) env->NewGlobalRef(c);

    /* A jmethodID is NOT a reference and needs no NewGlobalRef -- it stays
     * valid as long as the class is not unloaded, which is why the class is
     * pinned above and the ID is simply stored. Caching it here is what the
     * comment at the top of this file describes: a .bss write from JNI_OnLoad,
     * paired with reads from every method that fires the callback. Look for
     * that shape in Ghidra -- a global that is written once near
     * RegisterNatives and read from a dozen places is almost always a cached
     * jclass or jmethodID, and the string literals feeding the GetMethodID
     * call name the exact Java method to open in JADX. */
    g_callbackMethod = env->GetMethodID(c, "onNativeEvent",
                                        "(Ljava/lang/String;)V");
    if (g_callbackMethod == NULL) {
        /* Not fatal: Java_..._notify falls back to a per-call lookup. Clear the
         * pending NoSuchMethodError so the caller is not left with an exception
         * queued on the thread. */
        env->ExceptionClear();
    }

    /* RegisterNatives - offset 0x6b8 on a 64-bit target. THE call to find. */
    if (env->RegisterNatives(c, kMethods,
                             sizeof(kMethods) / sizeof(kMethods[0])) != JNI_OK) {
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad: registered %zu dynamic methods",
         sizeof(kMethods) / sizeof(kMethods[0]));
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM *vm, void * /* reserved */) {
    JNIEnv *env = NULL;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_OK) {
        if (g_callbackClass != NULL) {
            env->DeleteGlobalRef(g_callbackClass);
            g_callbackClass = NULL;
        }
    }
    free(g_record);
    g_record = NULL;
}

/*
 * The matching Java class, for reference:
 *
 *   package com.example.ref;
 *
 *   public class Reference {
 *       static { System.loadLibrary("reference"); }
 *
 *       public native String  plainMethod();
 *       public native int     process(String input);
 *       public native int     process(String input, int seed);
 *       public native byte[]  transform(byte[] input);
 *       public native void    notify(String message);
 *       public native int     dispatch(int op);
 *       public native boolean checkName(String name);
 *       public native boolean createRecord(String name);
 *       public native String  describeRecord();
 *
 *       // dynamically registered
 *       public native int     hiddenAdd(int a, int b);
 *       public native String  hiddenSecret();
 *       public native boolean hiddenVerify(String token);
 *
 *       // called FROM native code
 *       public void onNativeEvent(String message) {
 *           android.util.Log.i("REFLIB", "callback: " + message);
 *       }
 *   }
 *
 *   package com.example.my_pkg;
 *
 *   public class Helper {
 *       public native int compute(int x);
 *   }
 */
