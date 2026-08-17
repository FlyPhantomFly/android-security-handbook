/*
 * licence-check.c -- a deliberately patchable native check, in the exact shape
 *                    real Android apps use it.
 *
 * PURPOSE
 *     Chapter 18's labs need a real compiled AArch64 binary whose behaviour you
 *     can change by editing four bytes and then PROVE you changed. This is that
 *     binary. It contains four functions of escalating patch difficulty:
 *
 *       lc_is_licensed()      one comparison. The one-instruction patch.
 *       lc_verify_signature() several checks feeding one boolean. The
 *                             "make the whole function return 1" patch.
 *       lc_is_device_rooted() a loop over a path list. Patching the RESULT is
 *                             easy; patching the LOOP is instructive.
 *       lc_decrypt_flag()     the check gates a computation, so returning the
 *                             right boolean is NOT enough -- you have to make
 *                             the real code path run. This is the case that
 *                             separates a bypass from a break.
 *
 *     It also ships a `main` (built as a separate executable by the build
 *     script) so that "the behaviour changed" is something you observe by
 *     running the program, not something you infer from a disassembly.
 *
 * HOW TO BUILD
 *     # host, with the Android NDK installed
 *     ./build-arm-fixtures.sh /tmp/ch18
 *
 *     Produces /tmp/ch18/liblicence.so (the patch target) and
 *     /tmp/ch18/licence-host (the same logic built for your own machine, so
 *     you can run it without a device or emulator).
 *
 * HOW TO RUN THE HOST BUILD
 *     /tmp/ch18/licence-host                  # prints every check's verdict
 *     /tmp/ch18/licence-host WRONGKEY         # supply your own token
 *
 * REQUIREMENTS
 *     Android NDK r21+ for the .so. Any C compiler for the host build --
 *     clang, gcc, or the NDK's own clang targeting your host.
 *
 * WHAT THIS FILE IS *NOT*
 *     - Not a licence check anybody should ship. There is no server, no
 *       signature, no key derivation, and the "secret" is a string constant.
 *       Real anti-tamper is chapter 38's subject and it is much harder to
 *       write than to read.
 *     - Not obfuscated. Chapter 40 covers what obfuscation does to these
 *       shapes; the point here is to read the SHAPES first, cleanly.
 *     - Not safe C. lc_verify_signature deliberately uses a fixed stack buffer
 *       so that -fstack-protector-strong has something to protect, and so the
 *       canary prologue appears in the listing. Do not copy the pattern.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef LC_EXPORT
#define LC_EXPORT __attribute__((visibility("default")))
#endif

/* ------------------------------------------------------------------ */
/* Target 1 -- the single comparison.                                   */
/*                                                                      */
/* At -O2 this becomes cmp + cset: three instructions and a ret. The     */
/* one-instruction patch is to replace the cset with `mov w0, #1`.       */
/* ------------------------------------------------------------------ */
LC_EXPORT int lc_is_licensed(int tier)
{
    return tier >= 2;
}

/* ------------------------------------------------------------------ */
/* Target 2 -- several checks feeding one boolean, with a stack buffer   */
/* so the canary appears.                                               */
/*                                                                      */
/* The expected token is "ARM64-IS-NOT-HARD" (17 characters). Every       */
/* failing path returns 0; the single success path returns 1.            */
/* ------------------------------------------------------------------ */
LC_EXPORT int lc_verify_signature(const char *token)
{
    char scratch[48];
    size_t n;

    if (token == NULL) {
        return 0;
    }
    n = strlen(token);
    if (n != 17) {
        return 0;
    }
    memcpy(scratch, token, n);
    scratch[n] = '\0';

    if (scratch[0] != 'A' || scratch[1] != 'R' || scratch[2] != 'M') {
        return 0;
    }
    if (strcmp(scratch, "ARM64-IS-NOT-HARD") != 0) {
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Target 3 -- a loop over a table of paths. This is the shape almost    */
/* every native root check has (see 37-RootDetection), reduced to its    */
/* skeleton. The paths are checked with access(); on a host build with   */
/* none of them present it returns 0.                                    */
/* ------------------------------------------------------------------ */
static const char *const kSuspectPaths[] = {
    "/system/bin/su",
    "/system/xbin/su",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/data/local/tmp/frida-server",
};

LC_EXPORT int lc_is_device_rooted(void)
{
    unsigned i;
    for (i = 0; i < sizeof(kSuspectPaths) / sizeof(kSuspectPaths[0]); i++) {
        FILE *f = fopen(kSuspectPaths[i], "r");
        if (f != NULL) {
            fclose(f);
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Target 4 -- the check GATES A COMPUTATION.                            */
/*                                                                      */
/* Forcing lc_verify_signature to return 1 gets you past the branch, but */
/* the flag is derived from the token itself, so a wrong token still     */
/* produces garbage. This is the difference between bypassing an         */
/* authorisation decision and actually obtaining the protected value --  */
/* and it is why "I patched the check" is sometimes not the end of the   */
/* job. README section 5.4 uses this function as its worked example.      */
/* ------------------------------------------------------------------ */
LC_EXPORT int lc_decrypt_flag(const char *token, char *out, size_t outlen)
{
    /* "ANDROID-ARM64-FLAG" XORed byte-by-byte with the key below.
       Written as an explicit byte array so the constant is visible in
       .rodata and you can find it with a strings-style search -- which is
       itself the lesson: the ciphertext is right there in the file. */
    static const unsigned char ct[] = {
        0x00, 0x1c, 0x09, 0x64, 0x7b, 0x64, 0x0d, 0x7e, 0x6c,
        0x1c, 0x02, 0x62, 0x19, 0x65, 0x07, 0x1e, 0x05, 0x06
    };
    size_t i;

    if (!lc_verify_signature(token)) {
        return -1;
    }
    if (outlen < sizeof(ct) + 1) {
        return -2;
    }
    for (i = 0; i < sizeof(ct); i++) {
        out[i] = (char)(ct[i] ^ (unsigned char)token[i % 17]);
    }
    out[sizeof(ct)] = '\0';
    return (int)sizeof(ct);
}

/* ------------------------------------------------------------------ */
/* A JNI-shaped entry point, so the library has a Java_* export whose    */
/* prologue you can read. The calling convention above the ABI level     */
/* belongs to 16-JNI; what is HERE is that JNIEnv* arrives in x0 and     */
/* jobject in x1, which pushes the first real argument to x2.            */
/* Declared with plain pointers so that <jni.h> is not required to       */
/* build this file outside an Android project.                           */
/* ------------------------------------------------------------------ */
LC_EXPORT int Java_com_example_arm_Native_isLicensed(void *env, void *thiz,
                                                     int tier)
{
    (void)env;
    (void)thiz;
    return lc_is_licensed(tier);
}

/* ------------------------------------------------------------------ */
/* Host driver. Compiled only when LC_MAIN is defined, so the .so does   */
/* not carry a main().                                                   */
/* ------------------------------------------------------------------ */
#ifdef LC_MAIN
int main(int argc, char **argv)
{
    const char *token = (argc > 1) ? argv[1] : "WRONG-TOKEN-HERE!";
    char flag[64];
    int rc;

    printf("token              : %s\n", token);
    printf("lc_is_licensed(0)  : %d\n", lc_is_licensed(0));
    printf("lc_is_licensed(1)  : %d\n", lc_is_licensed(1));
    printf("lc_is_licensed(2)  : %d\n", lc_is_licensed(2));
    printf("lc_verify_signature: %d\n", lc_verify_signature(token));
    printf("lc_is_device_rooted: %d\n", lc_is_device_rooted());

    rc = lc_decrypt_flag(token, flag, sizeof(flag));
    if (rc < 0) {
        printf("lc_decrypt_flag    : refused (%d)\n", rc);
    } else {
        printf("lc_decrypt_flag    : %s\n", flag);
    }
    return 0;
}
#endif
