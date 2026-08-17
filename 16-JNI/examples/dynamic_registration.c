/*
 * examples/dynamic_registration.c
 *
 * Example 9.4 -- a library that exports ONLY JNI_OnLoad.
 *
 * WHAT THIS SHOWS
 *     Dynamic registration written the way a protection vendor writes it,
 *     so that Lab 03 has something realistic to recover:
 *
 *       - every implementation function is `static`, so it has internal
 *         linkage and never reaches .dynsym -- `nm -D` shows nothing
 *       - the class name is assembled at runtime from a byte array rather
 *         than sitting in the binary as a literal, so `strings` misses it
 *       - the method names and signatures are lightly obscured for the same
 *         reason, and reconstructed just before RegisterNatives is called
 *       - registration happens inside JNI_OnLoad, which ART calls during
 *         System.loadLibrary, before any app code runs
 *
 *     The result: the Java class is free to be renamed to a.b.c by R8,
 *     there is no Java_* symbol anywhere, and pure static analysis of the
 *     .so recovers nothing useful.
 *
 * AND WHY IT DOES NOT WORK
 *     ART must be handed the name, the signature and the address in
 *     PLAINTEXT, because it looks the method up on the class by exact string
 *     comparison. RegisterNatives is a mandatory chokepoint. Hook it and the
 *     whole table falls out:
 *
 *         frida -U -f com.example.app --no-pause \
 *               -l ../scripts/dump-registernatives.js
 *
 *     Obfuscation can hide where the code is and what it is called. It
 *     cannot hide the moment the code talks to the runtime.
 *
 * BUILD (host, requires the Android NDK)
 *     Verified: compiles clean with -Wall -Wextra under
 *     aarch64-linux-android21-clang from NDK 25.2.9519653. ./build.sh in
 *     this directory reproduces it, out of tree.
 *     See examples/README.md.
 *
 *     Then prove the point to yourself:
 *         llvm-nm -D --defined-only libguard.so | grep ' T '
 *         # -> only JNI_OnLoad and JNI_OnUnload
 *
 * *** THE XOR BELOW DOES NOT SURVIVE -O2. MEASURED. ***
 *     This header used to promise that
 *         strings -a libguard.so | grep -i 'com/example'
 *     prints nothing, because kClassEnc is XORed with 0x5A. It prints nothing
 *     at -O0, -O1, -Os and -Oz. At -O2 -- the level examples/README.md tells
 *     you to build with -- it prints:
 *
 *         com/example/jnidemo/Guar([B)[B
 *
 *     clang evaluates unxor() at COMPILE TIME, because kClassEnc and XK are
 *     both constants and the loop has no side effects, and then emits the
 *     answer: a 16-byte and an 8-byte load from .rodata for the first 24
 *     characters, plus `mov w8, #100` -- the letter 'd' as an immediate -- for
 *     the 25th. Hence "Guar", one character short, running straight into the
 *     adjacent "([B)[B" because there is no NUL between them.
 *
 *     Nothing below is buggy; FindClass still receives the complete name at
 *     runtime. The obfuscation is simply gone from the artefact. That is the
 *     more useful lesson, and it is why this file is still written this way:
 *       - a de-obfuscation the optimiser can fold is not a de-obfuscation;
 *       - a plaintext string missing its LAST character is the fingerprint of
 *         exactly this transformation, and worth recognising on sight;
 *       - and you cannot learn either fact by reading source. Run ./build.sh,
 *         which prints the five-optimisation-level table, and read the binary.
 *
 * RELATED
 *     ../../37-RootDetection/examples/native_root_check.c applies the same
 *     technique to a root check. Read both; neither is "the" canonical
 *     version, and the differences are instructive.
 *
 * *** NOTE ON INTENT ***
 *     This is a teaching artefact for an analyst. The obscuring here is
 *     deliberately weak -- a single XOR -- because the lesson is that the
 *     STRENGTH of the obscuring is irrelevant to the recovery technique.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Cached state. Set up once in JNI_OnLoad, used for the process life.  */
/* ------------------------------------------------------------------ */

static JavaVM  *g_vm         = NULL;   /* process-wide; safe to cache      */
static jclass   g_guardClass = NULL;   /* GLOBAL ref, or the IDs go stale  */
static jmethodID g_onVerdict = NULL;   /* cached callback                  */

/* ------------------------------------------------------------------ */
/* Trivial string obscuring. Real protectors use something stronger;    */
/* the recovery technique is identical either way.                      */
/* ------------------------------------------------------------------ */

#define XK 0x5A

/* "com/example/jnidemo/Guard" XORed with 0x5A, so the plaintext is not a
 * string literal anywhere in this file. Written as an explicit initialiser
 * list rather than a string so that it is a byte array to the compiler, not
 * character data -- `strings` skips it either way, since none of the encoded
 * bytes form a printable run.
 *
 * It is `const`, so it lands in .rodata, not .data. At -O2 it does not land
 * anywhere: the whole decode is constant-folded and the array is dead. Read
 * the "THE XOR BELOW DOES NOT SURVIVE -O2" block in this file's header before
 * you trust this scheme to hide anything. */
static const unsigned char kClassEnc[] = {
    0x39, 0x35, 0x37, 0x75, 0x3f, 0x22, 0x3b, 0x37, 0x2a, 0x36, 0x3f, 0x75,
    0x30, 0x34, 0x33, 0x3e, 0x3f, 0x37, 0x35, 0x75, 0x1d, 0x2f, 0x3b, 0x28,
    0x3e, 0x00
};
/* Regenerate that table with:
 *   python3 -c "print(', '.join('0x%02x'%(ord(c)^0x5A) \
 *       for c in 'com/example/jnidemo/Guard'))"
 * and remember FindClass wants slashes and no L/; -- that form is
 * 'com/example/jnidemo/Guard', not 'Lcom/example/jnidemo/Guard;'. */

/* Decode in place into a caller-supplied buffer. Returns buf. */
static char *unxor(const unsigned char *enc, char *buf, size_t cap)
{
    size_t i = 0;
    for (; i + 1 < cap && enc[i] != 0x00; i++) {
        buf[i] = (char)(enc[i] ^ XK);
    }
    buf[i] = '\0';
    return buf;
}

/* ------------------------------------------------------------------ */
/* The implementations. NOTE: every one is `static`.                    */
/*                                                                      */
/* Internal linkage means these never appear in .dynsym, never appear   */
/* in `nm -D`, and in a stripped library have no name anywhere at all.  */
/* Their addresses exist only inside kMethods below.                    */
/* ------------------------------------------------------------------ */

/* Java: private native boolean check(String tag);
 * Sig:  (Ljava/lang/String;)Z
 *
 * Remember the convention: env, then the receiver, then the declared
 * parameters. In a Frida hook that is args[0], args[1], args[2]. */
static jboolean guard_check(JNIEnv *env, jobject thiz, jstring tag)
{
    (void)thiz;

    if (tag == NULL) return JNI_FALSE;

    const char *t = (*env)->GetStringUTFChars(env, tag, NULL);
    if (t == NULL) return JNI_FALSE;                  /* OOM pending */

    /* Whatever the "protection" actually is. The point for the analyst is
     * that `t` is plaintext right here, on the stack, at a known offset in
     * a known function -- which is why hooking the boundary beats defeating
     * the obfuscation. */
    jboolean ok = (jboolean)(strcmp(t, "release") == 0);

    (*env)->ReleaseStringUTFChars(env, tag, t);
    return ok;
}

/* Java: private native byte[] seal(byte[] payload);
 * Sig:  ([B)[B */
static jbyteArray guard_seal(JNIEnv *env, jobject thiz, jbyteArray payload)
{
    (void)thiz;

    if (payload == NULL) return NULL;

    const jsize n = (*env)->GetArrayLength(env, payload);   /* authoritative */
    if (n < 0 || n > 1 << 20) return NULL;

    jbyte *buf = (jbyte *)malloc((size_t)(n > 0 ? n : 1));
    if (buf == NULL) return NULL;

    (*env)->GetByteArrayRegion(env, payload, 0, n, buf);
    if ((*env)->ExceptionCheck(env)) { free(buf); return NULL; }

    for (jsize i = 0; i < n; i++) buf[i] = (jbyte)(buf[i] ^ 0x37);

    jbyteArray out = (*env)->NewByteArray(env, n);
    if (out != NULL) (*env)->SetByteArrayRegion(env, out, 0, n, buf);
    free(buf);
    return out;
}

/* Java: private static native long nativeInit();
 * Sig:  ()J
 *
 * A static native: args[1] is a jclass rather than a jobject. The real
 * arguments -- there are none here -- would still start at args[2]. */
static jlong guard_init(JNIEnv *env, jclass clazz)
{
    (void)env; (void)clazz;
    return (jlong)0x1234ABCD;
}

/* ------------------------------------------------------------------ */
/* The registration table.                                              */
/*                                                                      */
/* struct JNINativeMethod { const char* name; const char* signature;    */
/*                          void* fnPtr; }                              */
/*                                                                      */
/* Three pointers: 24 bytes per entry on 64-bit, 12 on 32-bit. In a hex */
/* view of .data.rel.ro this is a run of pointer triples where the      */
/* first two point at short strings and the third points into .text.    */
/* See README section 6.5.                                              */
/*                                                                      */
/* This table is NOT a static initialiser here: it is filled in at       */
/* runtime from the decoded strings, so that even the method names do    */
/* not appear as literals. That is the last thing a static analyst can   */
/* take away, and it costs the runtime analyst nothing.                  */
/* ------------------------------------------------------------------ */

static char g_n1[16], g_s1[64];
static char g_n2[16], g_s2[64];
static char g_n3[16], g_s3[64];

static JNINativeMethod kMethods[3];

static void build_table(void)
{
    /* Names and signatures, assembled rather than written. A real protector
     * would derive these from an encrypted blob; the shape is the same. */
    snprintf(g_n1, sizeof(g_n1), "%s%s", "ch", "eck");
    snprintf(g_s1, sizeof(g_s1), "(L%s/%s/String;)Z", "java", "lang");

    snprintf(g_n2, sizeof(g_n2), "%s%s", "se", "al");
    snprintf(g_s2, sizeof(g_s2), "([B)[B");

    snprintf(g_n3, sizeof(g_n3), "%s%s", "native", "Init");
    snprintf(g_s3, sizeof(g_s3), "()J");

    kMethods[0].name = g_n1; kMethods[0].signature = g_s1;
    kMethods[0].fnPtr = (void *)guard_check;

    kMethods[1].name = g_n2; kMethods[1].signature = g_s2;
    kMethods[1].fnPtr = (void *)guard_seal;

    kMethods[2].name = g_n3; kMethods[2].signature = g_s3;
    kMethods[2].fnPtr = (void *)guard_init;
}

/* ------------------------------------------------------------------ */
/* JNI_OnLoad -- the one exported symbol, and the one ART calls.        */
/*                                                                      */
/* ART calls this during System.loadLibrary, BEFORE that call returns.  */
/* Anything the library wants to do before the app can use it happens   */
/* here: decrypting itself, checking for a debugger, and -- as here --  */
/* registering its natives.                                             */
/*                                                                      */
/* This is why you must SPAWN the process to observe it. Attaching to a */
/* running app is far too late.                                         */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;

    JNIEnv *env = NULL;
    g_vm = vm;                                  /* process-wide: correct to cache */

    /* GetEnv, not AttachCurrentThread: we are already on an attached thread,
     * the one that called System.loadLibrary. */
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;                         /* -1: refuses the load */
    }

    char cls_name[64];
    unxor(kClassEnc, cls_name, sizeof(cls_name));   /* "com/example/jnidemo/Guard" */

    /* FindClass here resolves against the app's ClassLoader, because ART set
     * that up before calling us. The same call from a thread the library
     * creates later would resolve against the system ClassLoader and fail --
     * which is exactly why libraries do all their FindClass work in
     * JNI_OnLoad and cache the results. See README section 4.2. */
    jclass local = (*env)->FindClass(env, cls_name);
    if (local == NULL) {
        return JNI_ERR;                         /* ClassNotFoundException pending */
    }

    build_table();

    if ((*env)->RegisterNatives(env, local, kMethods,
                                (jint)(sizeof(kMethods) / sizeof(kMethods[0]))) != JNI_OK) {
        /* NoSuchMethodError is pending: a name or a signature did not match
         * a `native` method on that class, byte for byte. This is the single
         * most common cause of "RegisterNatives returns -1". */
        (*env)->DeleteLocalRef(env, local);
        return JNI_ERR;
    }

    /* Promote to a global reference so the cached jmethodID below stays
     * valid: an ID's lifetime is tied to the class remaining loaded. */
    g_guardClass = (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    if (g_guardClass == NULL) return JNI_ERR;

    /* Cache the callback ID once. Note this can fail, and the failure leaves
     * an exception pending that we must clear before returning a success
     * version -- returning with an exception pending is a bug. */
    g_onVerdict = (*env)->GetMethodID(env, g_guardClass, "onVerdict", "(Z)V");
    if (g_onVerdict == NULL) {
        (*env)->ExceptionClear(env);            /* optional callback; not fatal */
    }

    /* The return value is a JNI VERSION, not a status code. Returning
     * JNI_ERR or an unsupported version fails the load with
     * UnsatisfiedLinkError. */
    return JNI_VERSION_1_6;                     /* 0x00010006 */
}

/* Android does not unload app libraries in practice, so this is a curiosity
 * rather than a hook point. Its presence in a library is worth noticing;
 * its absence means nothing. */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return;
    if (g_guardClass != NULL) {
        (*env)->DeleteGlobalRef(env, g_guardClass);
        g_guardClass = NULL;
    }
}
