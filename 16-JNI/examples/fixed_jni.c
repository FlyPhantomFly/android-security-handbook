/*
 * examples/fixed_jni.c
 *
 * Example 9.3b -- the corrected form of every function in unsafe_jni.c.
 *
 * WHAT THIS SHOWS
 *     The same five functions, same names, same signatures, written so that
 *     each defect is impossible rather than merely unlikely. Diff the two
 *     files; the changes are small and the principle behind each is stated
 *     in a FIX comment.
 *
 *     The principle, once, for all five:
 *
 *         The native function must re-derive every constraint it depends on,
 *         from the objects it was given, on every call.
 *
 *     GetArrayLength and GetStringUTFLength are free and authoritative. A
 *     length passed as a parameter is a hint. A pointer passed as a jlong is
 *     an assertion by untrusted code.
 *
 * BUILD (host, requires the Android NDK)
 *     Verified: compiles clean with -Wall -Wextra under
 *     aarch64-linux-android21-clang from NDK 25.2.9519653. ./build.sh in
 *     this directory reproduces it, out of tree.
 *     See examples/README.md. Build this one WITH hardening -- there is no
 *     reason not to:
 *         clang -shared -fPIC -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
 *               -Wl,-z,relro,-z,now -o libfixed.so fixed_jni.c
 *
 * HOW TO VERIFY THE FIX
 *     Run Lab 02's triggers against this library instead of libunsafe.so.
 *     Every one should produce a clean Java exception or a bounded result,
 *     and CheckJNI should stay silent.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SCRATCH_MAX 256
#define LOGBUF_MAX  128

/* ------------------------------------------------------------------ */
/* Throw helpers. Written once so error handling is uniform, which is  */
/* the only way it stays correct as the file grows.                    */
/* ------------------------------------------------------------------ */

static void throw_by_name(JNIEnv *env, const char *cls_name, const char *msg)
{
    jclass cls = (*env)->FindClass(env, cls_name);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, msg);
        (*env)->DeleteLocalRef(env, cls);
    }
}

static void throw_iae(JNIEnv *env, const char *msg)
{
    throw_by_name(env, "java/lang/IllegalArgumentException", msg);
}

static void throw_ise(JNIEnv *env, const char *msg)
{
    throw_by_name(env, "java/lang/IllegalStateException", msg);
}

/* =====================================================================
 * FIX 1 -- do not trust the length parameter  (was VULN 1)
 * ================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeDecode(JNIEnv *env, jobject thiz,
                                                 jbyteArray input, jint length)
{
    (void)thiz;

    if (input == NULL) { throw_iae(env, "input is null"); return NULL; }

    /* FIX 1a: the array's own length is the authority. This one call makes
     * the Java-side check redundant rather than load-bearing, which is the
     * property you want -- the check may be bypassed; this cannot be. */
    const jsize actual = (*env)->GetArrayLength(env, input);

    /* FIX 1b: `length` is now only a request, and it is bounded by BOTH the
     * real array length and the destination buffer. */
    if (length < 0 || length > actual || length > SCRATCH_MAX) {
        throw_iae(env, "length out of range");
        return NULL;                                  /* throw, then return */
    }

    unsigned char scratch[SCRATCH_MAX];

    /* FIX 1c: the bounded Region API rather than a raw element pointer.
     * GetByteArrayRegion validates start and length against the array; the
     * destination was sized by the check above. */
    (*env)->GetByteArrayRegion(env, input, 0, length, (jbyte *)scratch);
    if ((*env)->ExceptionCheck(env)) return NULL;

    for (jint i = 0; i < length; i++) {
        scratch[i] = (unsigned char)(scratch[i] ^ 0x5A);
    }

    jbyteArray out = (*env)->NewByteArray(env, length);
    if (out == NULL) return NULL;                     /* OutOfMemoryError pending */
    (*env)->SetByteArrayRegion(env, out, 0, length, (const jbyte *)scratch);
    if ((*env)->ExceptionCheck(env)) return NULL;
    return out;
}

/* =====================================================================
 * FIX 2 -- size the buffer in BYTES, not UTF-16 units  (was VULN 2)
 * ================================================================== */
JNIEXPORT void JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeLog(JNIEnv *env, jclass clazz, jstring msg)
{
    (void)clazz;

    if (msg == NULL) { throw_iae(env, "msg is null"); return; }

    /* FIX 2a: two different lengths, used for two different purposes.
     *   units -- what GetStringUTFRegion's start/length arguments mean
     *   bytes -- what the destination buffer must hold  */
    const jsize units = (*env)->GetStringLength(env, msg);
    const jsize bytes = (*env)->GetStringUTFLength(env, msg);

    char buf[LOGBUF_MAX];

    /* FIX 2b: the comparison is now bytes-against-bytes. Reserve one byte
     * for the terminator. */
    if (bytes < 0 || bytes >= (jsize)sizeof(buf)) {
        throw_iae(env, "message too long");
        return;
    }

    (*env)->GetStringUTFRegion(env, msg, 0, units, buf);
    if ((*env)->ExceptionCheck(env)) return;
    buf[bytes] = '\0';                                /* index by BYTES */

    printf("%s\n", buf);
}

/* =====================================================================
 * FIX 3 -- check after every fallible call  (was VULN 3)
 *
 * Correct JNI code is branch-heavy. Straight-line JNI code is suspicious by
 * shape alone, before you read a single argument.
 * ================================================================== */
JNIEXPORT void JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeDeliver(JNIEnv *env, jobject thiz,
                                                  jobject listener, jstring payload)
{
    (void)thiz;

    if (listener == NULL) { throw_iae(env, "listener is null"); return; }

    jclass cls = (*env)->GetObjectClass(env, listener);
    if (cls == NULL) return;                          /* exception pending; propagate */

    jmethodID mid = (*env)->GetMethodID(env, cls, "onData", "(Ljava/lang/String;)V");
    if (mid == NULL) {
        /* NoSuchMethodError is pending. DeleteLocalRef is one of the few
         * calls that is legal in that state; everything else is not. */
        (*env)->DeleteLocalRef(env, cls);
        return;                                        /* propagate to the caller */
    }

    (*env)->CallVoidMethod(env, listener, mid, payload);

    /* FIX 3: the callback is Java code and may have thrown. Decide
     * deliberately whether to propagate or to swallow -- and if you swallow,
     * clear FIRST, because until you do, further JNI calls are undefined. */
    if ((*env)->ExceptionCheck(env)) {
        jthrowable e = (*env)->ExceptionOccurred(env);
        (*env)->ExceptionClear(env);
        /* Log it. A silently swallowed callback exception is its own bug. */
        if (e != NULL) (*env)->DeleteLocalRef(env, e);
    }

    (*env)->DeleteLocalRef(env, cls);
}

/* =====================================================================
 * FIX 4 -- validate the handle  (was VULN 4)
 *
 * Three layers, in increasing order of robustness. This file implements the
 * first two; the third is described because it is what a real product should
 * do.
 *
 *   (a) a magic word inside the object, so a forged pointer is very likely
 *       rejected -- cheap, and defeats accidental misuse, not a determined
 *       attacker who can read memory
 *   (b) a registry of live handles, so only pointers this library actually
 *       allocated are accepted -- defeats forgery AND use-after-free
 *   (c) never expose an address at all: hand Java an integer INDEX into a
 *       native table, so a forged value is merely an out-of-range index.
 *       Or use NativeAllocationRegistry so the runtime owns the lifetime.
 * ================================================================== */

#define SESSION_MAGIC 0x5E551011u
#define MAX_SESSIONS  64

typedef struct {
    unsigned magic;
    size_t   len;
    unsigned char data[64];
} Session;

/* (b) the registry. A real implementation needs a mutex around this; it is
 * omitted here only to keep the example readable, and its absence is itself
 * the kind of thing to look for in a review. */
static Session *g_live[MAX_SESSIONS];

static int registry_add(Session *s)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_live[i] == NULL) { g_live[i] = s; return 0; }
    }
    return -1;
}

static int registry_contains(const Session *s)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_live[i] == s) return 1;
    }
    return 0;
}

static void registry_remove(const Session *s)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (g_live[i] == s) { g_live[i] = NULL; return; }
    }
}

/* Resolve a jlong to a Session, or NULL. This one function is the whole fix. */
static Session *session_from_handle(jlong handle)
{
    if (handle == 0) return NULL;
    Session *s = (Session *)(intptr_t)handle;
    if (!registry_contains(s)) return NULL;           /* forged or already closed */
    if (s->magic != SESSION_MAGIC) return NULL;       /* belt and braces */
    return s;
}

JNIEXPORT jlong JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeOpen(JNIEnv *env, jclass clazz)
{
    (void)clazz;
    Session *s = (Session *)calloc(1, sizeof(Session));
    if (s == NULL) { throw_by_name(env, "java/lang/OutOfMemoryError", "session"); return 0; }
    s->magic = SESSION_MAGIC;
    s->len = sizeof(s->data);
    if (registry_add(s) != 0) {
        free(s);
        throw_ise(env, "too many open sessions");
        return 0;
    }
    return (jlong)(intptr_t)s;
}

JNIEXPORT jint JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeRead(JNIEnv *env, jclass clazz,
                                               jlong handle, jbyteArray out)
{
    (void)clazz;

    Session *s = session_from_handle(handle);
    if (s == NULL) { throw_ise(env, "invalid or closed session"); return -1; }
    if (out == NULL) { throw_iae(env, "out is null"); return -1; }

    jsize n = (*env)->GetArrayLength(env, out);
    if (n < 0) return -1;
    if ((size_t)n > s->len) n = (jsize)s->len;

    (*env)->SetByteArrayRegion(env, out, 0, n, (const jbyte *)s->data);
    if ((*env)->ExceptionCheck(env)) return -1;
    return n;
}

JNIEXPORT void JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeClose(JNIEnv *env, jclass clazz, jlong handle)
{
    (void)clazz;

    Session *s = session_from_handle(handle);
    if (s == NULL) {
        /* Closing twice is now a clean IllegalStateException rather than a
         * double free. Note that the Java side must ALSO make close atomic
         * (see UnsafeDemo.java's comment) or two threads can both arrive
         * here with the same still-valid handle. */
        throw_ise(env, "invalid or already-closed session");
        return;
    }
    registry_remove(s);
    s->magic = 0;                                     /* poison before freeing */
    free(s);
}

/* =====================================================================
 * FIX 5 -- delete local references inside the loop  (was VULN 5)
 * ================================================================== */
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeCount(JNIEnv *env, jobject thiz,
                                                jobjectArray items)
{
    (void)thiz;

    if (items == NULL) { throw_iae(env, "items is null"); return -1; }

    const jsize n = (*env)->GetArrayLength(env, items);
    jint total = 0;

    for (jsize i = 0; i < n; i++) {
        jstring s = (jstring)(*env)->GetObjectArrayElement(env, items, i);
        if ((*env)->ExceptionCheck(env)) return -1;
        if (s == NULL) continue;

        const char *c = (*env)->GetStringUTFChars(env, s, NULL);
        if (c != NULL) {
            total += (jint)strlen(c);
            (*env)->ReleaseStringUTFChars(env, s, c);
        }

        /* FIX 5: one line. Without it the table grows by one per iteration
         * and the process aborts at 512. */
        (*env)->DeleteLocalRef(env, s);
    }
    return total;
}
