/*
 * examples/hello_jni.c
 *
 * Example 9.1 -- the C side of HelloJni.java, statically registered.
 *
 * WHAT THIS SHOWS
 *     The minimum correct shape of a JNI function: the two synthetic
 *     parameters, a NULL check on every fallible call, and a paired release
 *     for everything acquired. Nothing here is clever; everything here is
 *     the part people leave out.
 *
 * BUILD (host, requires the Android NDK)
 *     Verified: compiles clean with -Wall -Wextra under
 *     aarch64-linux-android21-clang from NDK 25.2.9519653. ./build.sh in
 *     this directory reproduces it, out of tree.
 *     See examples/README.md for the full CMakeLists.txt and ndk-build
 *     recipes. The short version:
 *
 *       $NDK/toolchains/llvm/prebuilt/<host>/bin/aarch64-linux-android21-clang \
 *           -shared -fPIC -o libhellojni.so hello_jni.c
 *
 *     Then confirm the symbols are exported and match what ART will look for:
 *       nm -D --defined-only libhellojni.so | grep ' T Java_'
 *
 * WHAT TO NOTICE
 *     - JNIEXPORT forces default visibility, so the symbol lands in .dynsym
 *       and survives `strip`. JNICALL is empty on ARM and ARM64.
 *     - Every JNI function that can fail is checked. This file is
 *       deliberately branch-heavy: correct JNI code looks like this, and
 *       straight-line JNI code is suspicious by shape alone.
 *     - GetStringUTFChars gives MODIFIED UTF-8, which never contains a zero
 *       byte, which is why handing it to snprintf is safe.
 *     - The returned jstring is a local reference created in this frame.
 *       Returning it is correct; returning a stale one from an earlier call
 *       is undefined behaviour.
 */

#include <jni.h>
#include <stdio.h>
#include <string.h>

/* ---------------------------------------------------------------------
 * Java: public native String greeting(String name);
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 * Symbol:    Java_com_example_jnidemo_HelloJni_greeting
 * ------------------------------------------------------------------ */
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_HelloJni_greeting(JNIEnv *env, jobject thiz, jstring name)
{
    (void)thiz;                       /* the receiver; unused here */

    if (name == NULL) {
        /* A null argument is not an error the runtime catches for you.
         * Throw a Java exception and return IMMEDIATELY -- ThrowNew does
         * not stop this function. */
        jclass ex = (*env)->FindClass(env, "java/lang/NullPointerException");
        if (ex != NULL) {
            (*env)->ThrowNew(env, ex, "name is null");
            (*env)->DeleteLocalRef(env, ex);
        }
        return NULL;
    }

    const char *n = (*env)->GetStringUTFChars(env, name, NULL);
    if (n == NULL) {
        /* Allocation failed. An OutOfMemoryError is already pending; just
         * return and let it surface in the Java caller. */
        return NULL;
    }

    char buf[128];
    /* snprintf, not sprintf: the input length is not ours to trust, and the
     * whole point of chapter 16 is that nothing upstream bounded it. */
    snprintf(buf, sizeof(buf), "hello, %s", n);

    (*env)->ReleaseStringUTFChars(env, name, n);   /* pair the get, always */

    jstring out = (*env)->NewStringUTF(env, buf);  /* may return NULL on OOM */
    return out;                                     /* a local ref: correct */
}

/* ---------------------------------------------------------------------
 * The overloaded pair. Because two native methods share the name
 * "describe", ART's short-name lookup is ambiguous and it falls back to
 * the LONG name, which appends "__" plus the mangled parameter
 * descriptors -- and no return type.
 *
 *   describe(int)     -> ..._describe__I
 *   describe(byte[])  -> ..._describe___3B    (note: three underscores)
 * ------------------------------------------------------------------ */
JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_HelloJni_describe__I(JNIEnv *env, jobject thiz, jint value)
{
    (void)thiz;
    char buf[64];
    snprintf(buf, sizeof(buf), "int %d", (int)value);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jstring JNICALL
Java_com_example_jnidemo_HelloJni_describe___3B(JNIEnv *env, jobject thiz, jbyteArray value)
{
    (void)thiz;

    if (value == NULL) return (*env)->NewStringUTF(env, "null array");

    /* GetArrayLength is the ONLY authoritative source for how big this is.
     * There is no separate length parameter here precisely so that the
     * question cannot arise. */
    const jsize len = (*env)->GetArrayLength(env, value);

    /* jbyte is SIGNED. Cast before printing, or 0xFF renders as -1. */
    jbyte first = 0;
    if (len > 0) {
        (*env)->GetByteArrayRegion(env, value, 0, 1, &first);
        if ((*env)->ExceptionCheck(env)) return NULL;   /* region call can throw */
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "byte[%d], first=0x%02x",
             (int)len, (unsigned)(first & 0xFF));
    return (*env)->NewStringUTF(env, buf);
}

/* ---------------------------------------------------------------------
 * A STATIC native method. Note the second parameter is a jclass, not a
 * jobject. In a Frida hook, args[1] is still the synthetic slot -- the
 * real arguments still start at args[2].
 *
 * Signature: ()I
 * ------------------------------------------------------------------ */
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_HelloJni_version(JNIEnv *env, jclass clazz)
{
    (void)env;
    (void)clazz;
    return 1;
}
