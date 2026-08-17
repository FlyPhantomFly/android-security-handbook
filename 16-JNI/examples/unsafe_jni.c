/*
 * examples/unsafe_jni.c
 *
 * Example 9.3a -- DELIBERATELY VULNERABLE. Read with fixed_jni.c open beside it.
 *
 * *** WARNING ***
 *     Every function in this file contains an intentional memory-safety
 *     defect, marked with a VULN: comment naming the trigger. Build it only
 *     inside a throwaway test app on a device you control. Do not copy any
 *     function from this file into real code -- copy from fixed_jni.c.
 *
 * WHAT THIS SHOWS
 *     The chapter's security thesis, made concrete:
 *
 *         A bounds check written in Java protects nothing once the value
 *         crosses into C.
 *
 *     Four defects, each from a different section of README section 5:
 *
 *       VULN 1  (README 5.2)  trusts a caller-supplied length against a
 *                             fixed-size stack buffer. The Java wrapper
 *                             validates it; reflection skips the wrapper.
 *       VULN 2  (README 5.6)  sizes a byte buffer from the UTF-16 unit
 *                             count. One emoji overflows it.
 *       VULN 3  (README 5.3)  never checks for a pending exception, so it
 *                             continues with a NULL jmethodID.
 *       VULN 4  (README 5.5)  casts a jlong straight to a pointer with no
 *                             validation, handing Java an arbitrary
 *                             dereference primitive.
 *
 *     A fifth, VULN 5 (README 5.4), leaks a local reference per loop
 *     iteration, which aborts the process when the count is large enough.
 *
 * BUILD (host, requires the Android NDK)
 *     Verified: compiles clean with -Wall -Wextra under
 *     aarch64-linux-android21-clang from NDK 25.2.9519653. ./build.sh in
 *     this directory reproduces it, out of tree.
 *     See examples/README.md. Build WITHOUT hardening if you want the
 *     overflows to be visible rather than caught by a canary:
 *         clang -shared -fPIC -fno-stack-protector -U_FORTIFY_SOURCE \
 *               -o libunsafe.so unsafe_jni.c
 *     Keeping the hardening on is the more realistic test; it turns most of
 *     these from corruption into a crash, which is exactly the severity
 *     conversation README section 5.2 tells you to have.
 *
 * HOW TO DEMONSTRATE
 *     Lab 02 walks each one. The short version, from Frida:
 *         Java.perform(function () {
 *           const C = Java.use('com.example.jnidemo.UnsafeDemo');
 *           const big = Java.array('byte', new Array(4096).fill(0x41));
 *           C.$new().nativeDecode(big, 4096);      // VULN 1
 *         });
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* =====================================================================
 * VULN 1 -- the trusted length  (README 5.2)
 *
 * Java side (see UnsafeDemo.java):
 *
 *     public byte[] decode(byte[] input) {
 *         if (input.length > 256) throw new IllegalArgumentException();
 *         return nativeDecode(input, input.length);      // "validated"
 *     }
 *     native byte[] nativeDecode(byte[] input, int length);
 *
 * The check is real, and it is in the wrong language. nativeDecode is a
 * method: reflection reaches it, Frida's Java.use reaches it, and a
 * repackaged APK with the check deleted reaches it.
 * ================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeDecode(JNIEnv *env, jobject thiz,
                                                 jbyteArray input, jint length)
{
    (void)thiz;

    unsigned char scratch[256];                  /* fixed size, mirrors "MAX" in Java */

    jbyte *p = (*env)->GetByteArrayElements(env, input, NULL);
    if (p == NULL) return NULL;

    /* VULN 1: `length` is an int in a register. Nothing checked it on THIS
     * side of the boundary. GetArrayLength was available and free, and was
     * not called. A 4096-byte input with length=4096 writes 3840 bytes past
     * the end of `scratch`.
     *
     * Trigger:  nativeDecode(new byte[4096], 4096) by reflection.
     * Effect:   stack smash. With a canary, a controlled abort; without one,
     *           saved-register and return-address corruption. */
    memcpy(scratch, p, (size_t)length);

    (*env)->ReleaseByteArrayElements(env, input, p, JNI_ABORT);

    for (jint i = 0; i < length && i < (jint)sizeof(scratch); i++) {
        scratch[i] = (unsigned char)(scratch[i] ^ 0x5A);
    }

    jbyteArray out = (*env)->NewByteArray(env, length);
    if (out == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, out, 0, length, (jbyte *)scratch);
    return out;
}

/* =====================================================================
 * VULN 2 -- UTF-16 units counted against a byte buffer  (README 5.6)
 *
 * Java side:
 *     native void nativeLog(String msg);
 * ================================================================== */
JNIEXPORT void JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeLog(JNIEnv *env, jclass clazz, jstring msg)
{
    (void)clazz;

    char buf[128];

    /* GetStringLength returns UTF-16 CODE UNITS. */
    jsize n = (*env)->GetStringLength(env, msg);

    /* VULN 2: this looks exactly like a bounds check and is not one. The
     * comparison is units-against-bytes. GetStringUTFRegion below takes a
     * start and length in UNITS but writes modified-UTF-8 BYTES: up to 3
     * bytes per BMP character, and 6 for an astral character encoded as a
     * surrogate pair.
     *
     * Trigger:  nativeLog("<127 copies of any emoji>")
     * Effect:   up to 762 bytes written into a 128-byte stack buffer. */
    if (n >= (jsize)sizeof(buf)) return;

    (*env)->GetStringUTFRegion(env, msg, 0, n, buf);
    buf[n] = '\0';                                /* and this indexes by units too */

    printf("%s\n", buf);
}

/* =====================================================================
 * VULN 3 -- no exception check, so execution continues on NULL
 *           (README 5.3)
 *
 * JNI does NOT unwind. A failed call sets a pending exception on the thread
 * and RETURNS NORMALLY. The next C statement runs.
 * ================================================================== */
JNIEXPORT void JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeDeliver(JNIEnv *env, jobject thiz,
                                                  jobject listener, jstring payload)
{
    (void)thiz;

    /* VULN 3a: if `listener` is null, GetObjectClass leaves an exception
     * pending and returns NULL. */
    jclass cls = (*env)->GetObjectClass(env, listener);

    /* VULN 3b: if the listener does not declare onData with EXACTLY this
     * signature -- for example after an app update changed it to take a
     * CharSequence -- GetMethodID returns NULL and leaves NoSuchMethodError
     * pending. Calling ANY other JNI function in that state is undefined
     * behaviour, and `mid` is NULL besides. */
    jmethodID mid = (*env)->GetMethodID(env, cls, "onData", "(Ljava/lang/String;)V");

    /* VULN 3c: and now we call through a NULL jmethodID with an exception
     * already pending.
     *
     * Trigger:  hook the Java callback to throw, or pass an object whose
     *           onData signature does not match, or force an OOM.
     * Effect:   crash at a low address, or worse -- ART is entitled to do
     *           anything at all here. */
    (*env)->CallVoidMethod(env, listener, mid, payload);

    (*env)->DeleteLocalRef(env, cls);
}

/* =====================================================================
 * VULN 4 -- a raw pointer in a Java long  (README 5.5)
 *
 * Java side:
 *     private long nativeHandle;
 *     private static native long  nativeOpen();
 *     private static native int   nativeRead(long handle, byte[] out);
 *     private static native void  nativeClose(long handle);
 * ================================================================== */
typedef struct {
    unsigned magic;
    size_t   len;
    unsigned char data[64];
} Session;

JNIEXPORT jlong JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeOpen(JNIEnv *env, jclass clazz)
{
    (void)env; (void)clazz;
    Session *s = (Session *)calloc(1, sizeof(Session));
    if (s == NULL) return 0;
    s->magic = 0x5E551011u;
    s->len = sizeof(s->data);
    /* The address of a heap allocation, returned to Java as a number. */
    return (jlong)(intptr_t)s;
}

JNIEXPORT jint JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeRead(JNIEnv *env, jclass clazz,
                                               jlong handle, jbyteArray out)
{
    (void)clazz;

    /* VULN 4: `handle` is an arbitrary 64-bit integer chosen by Java code.
     * There is no validation of any kind -- not even a NULL check, let alone
     * a check that this is a Session we allocated.
     *
     * Trigger:  nativeRead(0x4141414141414141, new byte[16]) by reflection.
     * Effect:   controlled-address read. The crash address in the tombstone
     *           is your proof. Combined with nativeClose, this is also a
     *           double-free and a use-after-free. */
    Session *s = (Session *)(intptr_t)handle;

    jsize n = (*env)->GetArrayLength(env, out);
    if ((size_t)n > s->len) n = (jsize)s->len;
    (*env)->SetByteArrayRegion(env, out, 0, n, (const jbyte *)s->data);
    return n;
}

JNIEXPORT void JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeClose(JNIEnv *env, jclass clazz, jlong handle)
{
    (void)env; (void)clazz;
    /* VULN 4b: free() on an attacker-chosen pointer, and no guard against
     * being called twice. The Java-side `nativeHandle = 0` after this is not
     * atomic with it, so two threads can both reach here with the same
     * value. */
    free((void *)(intptr_t)handle);
}

/* =====================================================================
 * VULN 5 -- local reference exhaustion  (README 5.4)
 *
 * Java side:
 *     native int nativeCount(String[] items);
 * ================================================================== */
JNIEXPORT jint JNICALL
Java_com_example_jnidemo_UnsafeDemo_nativeCount(JNIEnv *env, jobject thiz,
                                                jobjectArray items)
{
    (void)thiz;

    jsize n = (*env)->GetArrayLength(env, items);
    jint total = 0;

    for (jsize i = 0; i < n; i++) {
        /* VULN 5: each GetObjectArrayElement creates a local reference that
         * lives until this method RETURNS. None are deleted. The default
         * capacity on ART is 512 per thread, and exceeding it is an
         * unconditional process abort -- not a catchable exception:
         *
         *     JNI ERROR (app bug): local reference table overflow (max=512)
         *
         * Trigger:  nativeCount(new String[600])
         * Effect:   the app dies. If `n` comes from a network response, an
         *           intent extra or a parsed file, that is a remote or
         *           cross-app denial of service. */
        jstring s = (jstring)(*env)->GetObjectArrayElement(env, items, i);
        if (s != NULL) {
            const char *c = (*env)->GetStringUTFChars(env, s, NULL);
            if (c != NULL) {
                total += (jint)strlen(c);
                (*env)->ReleaseStringUTFChars(env, s, c);
            }
            /* the missing line:  (*env)->DeleteLocalRef(env, s); */
        }
    }
    return total;
}
