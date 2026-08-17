/*
 * 01-r2-target.c -- the reference target for chapter 59 (radare2).
 *
 * PURPOSE
 *   A small, deliberately-structured Android native library used by every lab in this
 *   chapter. It is written to exhibit, in as few lines as possible, the five things you
 *   actually have to recognise in a real Android .so:
 *
 *     1. A statically registered JNI entry point   -> appears in .dynsym, findable with `iE`
 *     2. A dynamically registered one via          -> does NOT appear in .dynsym at all;
 *        JNI_OnLoad + RegisterNatives                 you must find the JNINativeMethod table
 *     3. An "obfuscated" string                    -> and the measured way that obfuscation
 *                                                     fails at -O2 (see the WARNING below)
 *     4. A magic-constant comparison               -> the mov/movk + cmp + cset shape
 *     5. A short-circuiting gate                   -> the reason patching the obvious
 *                                                     function does nothing
 *
 * BUILD
 *   Do not build this by hand and do not build it inside the repository.
 *   Use the chapter's build script, which builds out of tree:
 *
 *       cd 59-radare2/examples && ./build.sh
 *
 *   It produces, in $HOME/ch59-build (or the directory you pass as $1):
 *       libr2target.so        shared library, -O2   (the main lab target)
 *       libr2target-O0.so     shared library, -O0   (for the string-folding comparison)
 *       r2gate                AArch64 executable    (for the patching labs)
 *
 * USAGE OF THE EXECUTABLE
 *       ./r2gate <licence-key>          prints "gate=N", exits 0 if N==1 else 1
 *   The accepted key is FNV-1a(key) == 0xBF8272B8. Working it out is lab 04's job.
 *
 * MEASURED WARNING -- this file's most important lesson
 *   lt_probe_paths() XOR-encrypts "/system/xbin/su" so that `strings` will not find it.
 *   At -O2 THIS DOES NOT WORK. Both the ciphertext and the key are compile-time
 *   constants, so clang evaluates the whole decode loop during compilation and stores the
 *   PLAINTEXT in .rodata. Verified with NDK 25.2.9519653:
 *
 *       llvm-strings -n 4 libr2target.so    | grep xbin   ->  /system/xbin/su
 *       llvm-strings -n 4 libr2target-O0.so | grep xbin   ->  (nothing)
 *
 *   Higher optimisation made the secret MORE visible. See 02-r2-target-hardened.c for the
 *   fix and README.md section 5.3 for why it works. This file keeps the broken version on
 *   purpose -- it is the finding, not a bug.
 *
 * ETHICS
 *   This is a target you compile yourself. Use the techniques in this chapter only against
 *   binaries you built, applications you own, or deliberately-vulnerable training apps.
 *
 * Compiles clean with -Wall -Wextra under aarch64-linux-android21-clang (NDK 25.2.9519653).
 */

#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

/* "/system/xbin/su" XOR 0xA7.
 * The key was chosen so that no ciphertext byte lands in printable ASCII and none is
 * zero -- otherwise the ciphertext itself shows up in `strings` output, which defeats
 * the point of the exercise before the optimiser ever gets a chance to. */
static const unsigned char k_enc_path[] = {
    0x88, 0xd4, 0xde, 0xd4, 0xd3, 0xc2, 0xca, 0x88,
    0xdf, 0xc5, 0xce, 0xc9, 0x88, 0xd4, 0xd2
};

#define XOR_KEY 0xA7

static void xor_decode(const unsigned char *in, size_t n, char *out)
{
    size_t i;
    for (i = 0; i < n; i++) {
        out[i] = (char)(in[i] ^ XOR_KEY);
    }
    out[n] = '\0';
}

/*
 * The "is this device rooted" probe.
 *
 * noinline is deliberate: without it the compiler folds this into lt_gate and the labs
 * lose the call site they are supposed to find with `axt`. Real libraries are inlined
 * constantly, which is exactly the failure mode 18-ARM section 5.4 measured -- see
 * README.md section 5.4 for both mechanisms side by side.
 */
__attribute__((noinline))
int lt_probe_paths(void)
{
    char buf[64];
    xor_decode(k_enc_path, sizeof(k_enc_path), buf);
    return access(buf, F_OK) == 0 ? 1 : 0;
}

/*
 * The licence check: FNV-1a over the key, compared against a magic constant.
 *
 * In the disassembly this is the classic shape --
 *     mov  w9, #40389 ; movk w9, #33052, lsl #16   -> 0x811C9DC5, the FNV-1a basis
 *     mov  w11, #403  ; movk w11, #256,  lsl #16   -> 0x01000193, the FNV-1a prime
 *     mov  w8, #29368 ; movk w8, #49026, lsl #16   -> 0xBF8272B8, the target hash
 *     cmp  w9, w8 ; cset w0, eq
 * Recognising published algorithm constants identifies the algorithm without reading the
 * loop. See README.md section 6.4.
 */
__attribute__((noinline))
int lt_verify_license(const char *key)
{
    uint32_t acc = 0x811c9dc5u;
    size_t i;

    if (key == NULL) {
        return 0;
    }
    for (i = 0; key[i] != '\0'; i++) {
        acc ^= (unsigned char)key[i];
        acc *= 0x01000193u;
    }
    return acc == 0xbf8272b8u;
}

/*
 * The gate -- and the whole point of lab 03.
 *
 * Note the ORDER. The root probe runs FIRST and returns early. On a device where the
 * probe fires, lt_verify_license is never called, so patching lt_verify_license to
 * return 1 changes precisely nothing. This was measured on the AVD sdk_gphone16k_x86_64,
 * which ships /system/xbin/su; the four-variant truth table is in README.md section 5.4.
 */
__attribute__((noinline))
int lt_gate(const char *key)
{
    if (lt_probe_paths()) {
        return 0;
    }
    if (!lt_verify_license(key)) {
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------------------------
 * JNI surface
 * ---------------------------------------------------------------------------------- */

/*
 * Statically registered. The name mangling is Java_ + fully-qualified class with '.'
 * replaced by '_', then '_', then the method name. It lands in .dynsym, so `iE` finds it.
 *
 * MEASURED: at -O2 this compiles to a single instruction --
 *     b <lt_probe_paths@plt>
 * a tail call. If you disassemble the export and find one branch, you have not found the
 * code; follow the branch. README.md section 6.3.
 */
JNIEXPORT jint JNICALL
Java_com_pentest_ch59_Native_staticCheck(JNIEnv *env, jobject thiz)
{
    (void)env;
    (void)thiz;
    return (jint)lt_probe_paths();
}

/*
 * Dynamically registered. `static` means this symbol never reaches .dynsym, so no amount
 * of `iE` / `is` / `nm -D` will name it. The only static route to it is the
 * JNINativeMethod table below. README.md sections 4.3 and 9.3.
 */
static jint dyn_gate(JNIEnv *env, jobject thiz, jstring key)
{
    const char *utf;
    jint result;

    (void)thiz;
    utf = (*env)->GetStringUTFChars(env, key, NULL);
    result = (jint)lt_gate(utf);
    (*env)->ReleaseStringUTFChars(env, key, utf);
    return result;
}

/*
 * Three pointers per record: name, signature, function. 24 bytes on a 64-bit target.
 * MEASURED: this array lands in .data.rel.ro, and JNI_OnLoad materialises its address
 * with `adrp x2, 0x2000` + `add x2, x2, #2968`.
 */
static const JNINativeMethod k_methods[] = {
    { "dynGate", "(Ljava/lang/String;)I", (void *)dyn_gate }
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env = NULL;
    jclass cls;

    (void)reserved;

    /* GetEnv is index 6 in JNIInvokeInterface -> offset 0x30. In the disassembly this is
     * `ldr x8, [x0]` ; `ldr x8, [x8, #48]` ; `blr x8`. */
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    /* FindClass is also at offset 0x30, but in JNINativeInterface. */
    cls = (*env)->FindClass(env, "com/pentest/ch59/Native");
    if (cls == NULL) {
        return JNI_ERR;
    }

    /* RegisterNatives is index 215 -> offset 215*8 = 1720 = 0x6b8.
     * MEASURED in the disassembly as `ldr x8, [x8, #1720]` ; `blr x8`. */
    if ((*env)->RegisterNatives(env, cls, k_methods, 1) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

/* ------------------------------------------------------------------------------------
 * Standalone entry point, so the same source also builds the `r2gate` executable used by
 * labs 03 and 04. A shared library ignores main(); an executable uses it.
 * ---------------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    const char *key = (argc > 1) ? argv[1] : "";
    int ok = lt_gate(key);

    printf("gate=%d\n", ok);
    return ok ? 0 : 1;
}
