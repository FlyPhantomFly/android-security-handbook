/*
 * examples/safe_jni.c
 *
 * Example 9.2 -- strings and arrays handled correctly.
 *
 * WHAT THIS SHOWS
 *     The disciplined pattern, in full, on every path:
 *
 *       - lengths derived from the OBJECT via GetArrayLength /
 *         GetStringUTFLength, never from a passed parameter
 *       - the bounded ...Region APIs rather than raw element pointers
 *       - an exception check after every fallible call
 *       - no leak on any path, including the error paths
 *       - local references deleted inside loops
 *
 *     Read this file, then read unsafe_jni.c, then read fixed_jni.c. This
 *     one is what correct looks like when nobody is under time pressure.
 *
 * BUILD (host, requires the Android NDK)
 *     Verified: compiles clean with -Wall -Wextra under
 *     aarch64-linux-android21-clang from NDK 25.2.9519653. ./build.sh in
 *     this directory reproduces it, out of tree.
 *     See examples/README.md.
 *
 * WHAT TO NOTICE
 *     Every function is shaped the same way: validate, size from the object,
 *     acquire, check, use, release, check, return. When you review someone
 *     else's JNI code, look for that shape. Its absence is the finding.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT 65536

/* ------------------------------------------------------------------ */
/* Small helpers. Every real JNI layer has these; write them once.     */
/* ------------------------------------------------------------------ */

static void throw_by_name(JNIEnv *env, const char *cls_name, const char *msg)
{
    /* Do not call this while an exception is already pending: FindClass is
     * not one of the calls that is legal in that state. Clear first if you
     * are recovering from something. */
    jclass cls = (*env)->FindClass(env, cls_name);
    if (cls != NULL) {
        (*env)->ThrowNew(env, cls, msg);
        (*env)->DeleteLocalRef(env, cls);
    }
    /* If FindClass itself failed, its own exception is pending, which is
     * still a correct outcome: the caller sees an exception either way. */
}

static void throw_iae(JNIEnv *env, const char *msg)
{
    throw_by_name(env, "java/lang/IllegalArgumentException", msg);
}

static void throw_oom(JNIEnv *env)
{
    throw_by_name(env, "java/lang/OutOfMemoryError", "native allocation failed");
}

/* ------------------------------------------------------------------ */
/* 1. byte[] in, byte[] out                                            */
/*    Java: public native byte[] transform(byte[] in);                 */
/*    Sig:  ([B)[B                                                     */
/* ------------------------------------------------------------------ */
JNIEXPORT jbyteArray JNICALL
Java_com_example_jnidemo_SafeCodec_transform(JNIEnv *env, jobject thiz, jbyteArray in)
{
    (void)thiz;

    if (in == NULL) {
        throw_iae(env, "input is null");
        return NULL;                       /* throw, then return, immediately */
    }

    /* The array's own length is the only authority. A separately passed
     * length would be a hint, and hints do not bound memcpy. */
    const jsize n = (*env)->GetArrayLength(env, in);
    if (n < 0 || n > MAX_INPUT) {
        throw_iae(env, "input too large");
        return NULL;
    }

    /* malloc(0) is allowed to return NULL, which we would misread as an
     * allocation failure. Ask for at least one byte. */
    jbyte *tmp = (jbyte *)malloc((size_t)(n > 0 ? n : 1));
    if (tmp == NULL) {
        throw_oom(env);
        return NULL;
    }

    /* GetByteArrayRegion validates start and length against the ARRAY and
     * throws ArrayIndexOutOfBoundsException if they are wrong. It cannot
     * validate `tmp`, which is why we sized `tmp` from `n` above. */
    (*env)->GetByteArrayRegion(env, in, 0, n, tmp);
    if ((*env)->ExceptionCheck(env)) { free(tmp); return NULL; }

    for (jsize i = 0; i < n; i++) {
        tmp[i] = (jbyte)(tmp[i] ^ 0x5A);
    }

    jbyteArray out = (*env)->NewByteArray(env, n);
    if (out == NULL) { free(tmp); return NULL; }   /* OutOfMemoryError pending */

    (*env)->SetByteArrayRegion(env, out, 0, n, tmp);
    free(tmp);
    if ((*env)->ExceptionCheck(env)) return NULL;

    return out;
}

/* ------------------------------------------------------------------ */
/* 2. String in, String out                                            */
/*    Java: public native String normalise(String s);                  */
/*    Sig:  (Ljava/lang/String;)Ljava/lang/String;                     */
/* ------------------------------------------------------------------ */
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_SafeCodec_normalise(JNIEnv *env, jobject thiz, jstring s)
{
    (void)thiz;

    if (s == NULL) { throw_iae(env, "s is null"); return NULL; }

    /* THE LENGTH TRAP, avoided.
     *   GetStringLength     -> UTF-16 CODE UNITS
     *   GetStringUTFLength  -> MODIFIED UTF-8 BYTES
     * A buffer holds bytes, so it must be sized from the second one.
     * Using the first is the bug in unsafe_jni.c, function 2. */
    const jsize units = (*env)->GetStringLength(env, s);
    const jsize bytes = (*env)->GetStringUTFLength(env, s);
    if (bytes < 0 || bytes > MAX_INPUT) { throw_iae(env, "string too long"); return NULL; }

    char *buf = (char *)malloc((size_t)bytes + 1);
    if (buf == NULL) { throw_oom(env); return NULL; }

    /* GetStringUTFRegion takes a start and length in UTF-16 UNITS but writes
     * BYTES. That mismatch is the whole trap; the destination was sized in
     * bytes above, so it is safe here. */
    (*env)->GetStringUTFRegion(env, s, 0, units, buf);
    if ((*env)->ExceptionCheck(env)) { free(buf); return NULL; }
    buf[bytes] = '\0';

    /* Modified UTF-8 never contains a zero byte, so C string functions are
     * safe on it -- but it is NOT valid standard UTF-8 when the string holds
     * U+0000 or an astral character. Do not hand it to a strict parser. */
    for (jsize i = 0; i < bytes; i++) {
        if (buf[i] >= 'A' && buf[i] <= 'Z') buf[i] = (char)(buf[i] - 'A' + 'a');
    }

    jstring out = (*env)->NewStringUTF(env, buf);   /* NULL on OOM or bad MUTF-8 */
    free(buf);
    return out;
}

/* ------------------------------------------------------------------ */
/* 3. Iterating a String[] without leaking local references            */
/*    Java: public native int countNonEmpty(String[] items);           */
/*    Sig:  ([Ljava/lang/String;)I                                     */
/* ------------------------------------------------------------------ */
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_SafeCodec_countNonEmpty(JNIEnv *env, jobject thiz,
                                                 jobjectArray items)
{
    (void)thiz;

    if (items == NULL) { throw_iae(env, "items is null"); return -1; }

    const jsize n = (*env)->GetArrayLength(env, items);
    jint count = 0;

    for (jsize i = 0; i < n; i++) {
        /* GetObjectArrayElement creates a LOCAL REFERENCE. Local references
         * are freed only when this native method returns -- not at the end
         * of the loop iteration. With n in the hundreds and no delete, the
         * table overflows and the PROCESS ABORTS:
         *     JNI ERROR (app bug): local reference table overflow (max=512)
         * That is a denial of service whenever `n` is attacker-controlled.
         * See README section 5.4. */
        jstring s = (jstring)(*env)->GetObjectArrayElement(env, items, i);
        if ((*env)->ExceptionCheck(env)) return -1;

        if (s != NULL) {
            if ((*env)->GetStringLength(env, s) > 0) count++;
            (*env)->DeleteLocalRef(env, s);        /* THE FIX, one line */
        }
    }
    return count;

    /* The alternative, when the body creates several references:
     *
     *   for (jsize i = 0; i < n; i++) {
     *       if ((*env)->PushLocalFrame(env, 16) != JNI_OK) return -1;
     *       ... anything ...
     *       (*env)->PopLocalFrame(env, NULL);
     *   }
     */
}

/* ------------------------------------------------------------------ */
/* 4. Calling back into Java, with full exception discipline           */
/*    Java: public native void deliver(Callback cb, byte[] payload);   */
/*    Sig:  (Lcom/example/jnidemo/Callback;[B)V                        */
/* ------------------------------------------------------------------ */
JNIEXPORT void JNICALL
Java_com_example_jnidemo_SafeCodec_deliver(JNIEnv *env, jobject thiz,
                                           jobject cb, jbyteArray payload)
{
    (void)thiz;

    if (cb == NULL) { throw_iae(env, "callback is null"); return; }

    jclass cls = (*env)->GetObjectClass(env, cb);
    if (cls == NULL) return;                       /* exception pending */

    jmethodID mid = (*env)->GetMethodID(env, cls, "onData", "([B)V");
    if (mid == NULL) {
        /* NoSuchMethodError is pending. We choose to propagate it, so we do
         * NOT clear it -- but we must still release what we hold, and
         * DeleteLocalRef is one of the few calls legal in this state. */
        (*env)->DeleteLocalRef(env, cls);
        return;
    }

    (*env)->CallVoidMethod(env, cb, mid, payload);

    /* The Java callback may have thrown. Until this is cleared, almost every
     * JNI call is undefined behaviour -- including the DeleteLocalRef below?
     * No: Delete*Ref IS legal with a pending exception. Anything else is not. */
    if ((*env)->ExceptionCheck(env)) {
        /* Choose deliberately: propagate, or swallow. Swallowing an error
         * silently is its own bug class, so if you clear it, log it. */
        jthrowable e = (*env)->ExceptionOccurred(env);
        (*env)->ExceptionClear(env);               /* clear BEFORE anything else */
        if (e != NULL) (*env)->DeleteLocalRef(env, e);
    }

    (*env)->DeleteLocalRef(env, cls);
}
