/*
 * jni-surface.c -- a library whose EXPORT TABLE is the interesting part.
 *
 * PURPOSE
 *     Chapter 15 is about the file, not the bridge. This example exists for
 *     exactly one reason: to give you a .so whose .dynsym contains the three
 *     shapes you will meet in real applications, so you can see how each one
 *     looks from the ELF side.
 *
 *       1. STATICALLY REGISTERED   Java_com_example_Native_addNumbers
 *                                  The name encodes the class and method, so
 *                                  the export table alone tells you the Java
 *                                  side. `readelf --dyn-syms | grep Java_`
 *                                  is a complete inventory.
 *
 *       2. DYNAMICALLY REGISTERED  registerNatives() below hands the runtime a
 *                                  table of {name, signature, pointer} from
 *                                  JNI_OnLoad. Nothing in .dynsym mentions
 *                                  Java at all. This is what an app does when
 *                                  it does not want its native entry points
 *                                  listed, and it is the common case in
 *                                  hardened apps.
 *
 *       3. NOT EXPORTED AT ALL     the static helpers. Present in .text, in
 *                                  .symtab until stripped, never in .dynsym.
 *
 *     Build it, strip it, and run:
 *         python3 ../scripts/elf-inspect.py libjnisurface.so --dynsyms
 *     Count how many of the five native methods you can see. The answer is
 *     two, and understanding why is the point of the file.
 *
 * HOW TO BUILD
 *     NDK=$ANDROID_HOME/ndk/<version>/toolchains/llvm/prebuilt/<host>/bin
 *     $NDK/aarch64-linux-android21-clang -shared -fPIC -O2 \
 *         -Wl,-z,max-page-size=16384 -o libjnisurface.so jni-surface.c
 *     $NDK/llvm-strip libjnisurface.so
 *
 *     No JNI headers are needed. The few JNI types used here are declared
 *     locally, deliberately, so the file compiles with nothing but a C
 *     compiler and a sysroot -- and so it is obvious that from the ELF's point
 *     of view JNIEnv is just "a pointer".
 *
 *     Loading it into a real app, and the meaning of JNIEnv, jclass, the
 *     signature strings and the calling convention, are chapter 16's subject.
 *     Do not learn JNI from this file; it is a fixture, not a tutorial.
 *
 * WHAT THIS FILE WILL *NOT* SHOW YOU
 *     - Correct JNI. The local type declarations are the minimum that compiles;
 *       real code includes <jni.h> and gets real types.
 *     - How to recover the dynamic registration table from a compiled library.
 *       That is a runtime job -- 57-Ghidra section 7.2, and 53-Frida.
 *     - Any security control. Nothing here checks anything.
 */

#include <stdlib.h>
#include <string.h>

/* ---- the smallest JNI shim that compiles. Real code uses <jni.h>. ---- */
typedef int             jint;
typedef long long       jlong;
typedef unsigned char   jboolean;
typedef void           *jobject;
typedef void           *jclass;
typedef void           *jstring;
typedef void           *JavaVM;

/* JNIEnv is a pointer to a table of function pointers. From ELF's point of
 * view it is one pointer-sized argument like any other; that it is the runtime
 * interface is a fact about chapter 16, not about this file. */
typedef void           *JNIEnv;

typedef struct {
    const char *name;
    const char *signature;
    void       *fnPtr;
} JNINativeMethod;

#define JNI_VERSION_1_6 0x00010006

/* ------------------------------------------------------------------------
 * Shape 1: static registration. The runtime finds these by NAME, derived from
 * the fully-qualified Java method. Underscores in a package name become _1,
 * which is why real symbols look mangled even without any obfuscation.
 * ------------------------------------------------------------------------ */
jint Java_com_example_native_1demo_Native_addNumbers(JNIEnv *env, jclass cls,
                                                    jint a, jint b)
{
    (void)env; (void)cls;
    return a + b;
}

jboolean Java_com_example_native_1demo_Native_isDeviceRooted(JNIEnv *env,
                                                             jclass cls)
{
    (void)env; (void)cls;
    /* A real check would stat /system/bin/su and friends -- 37-RootDetection.
     * The point here is only that the name is visible in .dynsym. */
    return 0;
}

/* ------------------------------------------------------------------------
 * Shape 2: dynamic registration. These four functions are static, so they are
 * not exported. The runtime learns about them only from the table below, at
 * run time, from inside JNI_OnLoad.
 *
 * From the outside, a `readelf --dyn-syms | grep Java_` returns nothing for
 * these, and an analyst who stops there concludes the library has no JNI
 * surface. It has four methods.
 * ------------------------------------------------------------------------ */
static jstring native_decrypt(JNIEnv *env, jobject self, jstring in)
{
    (void)env; (void)self;
    return in;
}

static jlong native_sign(JNIEnv *env, jobject self, jlong payload)
{
    (void)env; (void)self;
    return payload ^ 0x5A5A5A5A5A5A5A5ALL;
}

static jboolean native_verify_integrity(JNIEnv *env, jobject self)
{
    (void)env; (void)self;
    return 1;
}

static jint native_config_flags(JNIEnv *env, jobject self)
{
    (void)env; (void)self;
    return 0x2F;
}

/* The table an analyst wants. In a stripped release build it sits in .rodata
 * as three pointers per entry, and finding it is a recognisable pattern: a run
 * of {pointer-to-string, pointer-to-string, pointer-into-.text}. */
/* __attribute__((used)) matters here. Without it the optimiser sees that
 * nothing outside this file reads kMethods and deletes the whole table, taking
 * the four static functions with it -- and the fixture stops demonstrating
 * anything. Real code keeps it because RegisterNatives genuinely reads it. */
__attribute__((used))
static const JNINativeMethod kMethods[] = {
    { "decrypt",         "(Ljava/lang/String;)Ljava/lang/String;",
      (void *)native_decrypt },
    { "sign",            "(J)J",
      (void *)native_sign },
    { "verifyIntegrity", "()Z",
      (void *)native_verify_integrity },
    { "configFlags",     "()I",
      (void *)native_config_flags },
};

/* ------------------------------------------------------------------------
 * JNI_OnLoad is exported, always. It is the linker-visible entry point the
 * runtime calls immediately after System.loadLibrary maps the library. If a
 * library exports JNI_OnLoad and nothing matching Java_*, registration is
 * dynamic and the mapping exists only in memory.
 * ------------------------------------------------------------------------ */
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)vm; (void)reserved;
    /* Real code: FindClass("com/example/native_demo/Native"), then
     * (*env)->RegisterNatives(env, clazz, kMethods, 4). The reference below
     * stands in for that call so the table is genuinely reachable. */
    if (kMethods[0].fnPtr == NULL) {
        return -1;
    }
    return JNI_VERSION_1_6;
}

/* ------------------------------------------------------------------------
 * Shape 3: a constructor, which runs BEFORE JNI_OnLoad. If an app wants a
 * check to happen before any instrumentation is attached, this is where it
 * goes. Its address is in .init_array, and on AArch64 the slot in the file is
 * zero -- the address is in the relocation addend.
 * ------------------------------------------------------------------------ */
static volatile int g_ready;

__attribute__((constructor))
static void earliest(void)
{
    g_ready = 1;
}
