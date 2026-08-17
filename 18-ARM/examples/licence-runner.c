/*
 * licence-runner.c -- load liblicence.so and call every export, so that
 *                     "the patch changed the behaviour" is something you
 *                     WATCH HAPPEN rather than something you infer from a
 *                     disassembly.
 *
 * PURPOSE
 *     A disassembly diff proves the bytes changed. It does not prove the
 *     program now does something different -- you could have patched a
 *     function nothing calls, or patched a copy, or patched a path that was
 *     already dead. This runner closes that gap. It is an ordinary Android
 *     command-line executable: it dlopen()s the library by path, resolves
 *     each export with dlsym(), calls it, and prints the answer.
 *
 *     The library is loaded BY PATH, which is deliberate: you can point it at
 *     the pristine copy and the patched copy in turn, without reinstalling
 *     anything and without an app.
 *
 * HOW TO BUILD
 *     # host, with the Android NDK installed
 *     ./build-arm-fixtures.sh /tmp/ch18
 *     # -> /tmp/ch18/licence-runner   (an arm64 Android ELF executable)
 *
 * HOW TO RUN
 *     # host
 *     adb push /tmp/ch18/licence-runner /tmp/ch18/liblicence.so /data/local/tmp/
 *     adb shell chmod 755 /data/local/tmp/licence-runner
 *     adb shell /data/local/tmp/licence-runner /data/local/tmp/liblicence.so
 *     adb shell /data/local/tmp/licence-runner /data/local/tmp/liblicence.so ARM64-IS-NOT-HARD
 *
 *     No root is needed. /data/local/tmp is writable and executable by the
 *     shell user on every ordinary device.
 *
 * REQUIREMENTS
 *     An arm64-v8a Android device or emulator with adb, API 21 or newer. The
 *     NDK to build. Nothing else -- no app, no Gradle, no root, no Frida.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *     - Whether the same patch works inside a real app. An app may verify its
 *       own libraries (38-TamperDetection), may load a different ABI, or may
 *       reach the function by a path this runner does not exercise.
 *     - Whether the patch is correct in every input case. It calls each
 *       function a handful of times with fixed inputs. A patch that returns 1
 *       unconditionally will look identical to a correct bypass here, which is
 *       exactly the confusion README section 5.4 is about.
 *     - Anything about the JNI entry point beyond the fact that it exists.
 *       Calling Java_* from C by hand needs a JNIEnv; that is 16-JNI.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef int (*fn_is_licensed_t)(int);
typedef int (*fn_verify_t)(const char *);
typedef int (*fn_rooted_t)(void);
typedef int (*fn_decrypt_t)(const char *, char *, size_t);

static void *must_sym(void *h, const char *name)
{
    void *p = dlsym(h, name);
    if (p == NULL) {
        fprintf(stderr, "dlsym(%s) failed: %s\n", name, dlerror());
    }
    return p;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "./liblicence.so";
    const char *token = (argc > 2) ? argv[2] : "WRONG-TOKEN-HERE";
    char flag[64];
    void *h;
    fn_is_licensed_t is_licensed;
    fn_verify_t verify;
    fn_rooted_t rooted;
    fn_decrypt_t decrypt;
    int rc;

    h = dlopen(path, RTLD_NOW);
    if (h == NULL) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", path, dlerror());
        return 1;
    }

    is_licensed = (fn_is_licensed_t)must_sym(h, "lc_is_licensed");
    verify      = (fn_verify_t)must_sym(h, "lc_verify_signature");
    rooted      = (fn_rooted_t)must_sym(h, "lc_is_device_rooted");
    decrypt     = (fn_decrypt_t)must_sym(h, "lc_decrypt_flag");

    if (!is_licensed || !verify || !rooted || !decrypt) {
        dlclose(h);
        return 2;
    }

    printf("library            : %s\n", path);
    printf("token              : %s\n", token);
    printf("lc_is_licensed(0)  : %d\n", is_licensed(0));
    printf("lc_is_licensed(1)  : %d\n", is_licensed(1));
    printf("lc_is_licensed(2)  : %d\n", is_licensed(2));
    printf("lc_verify_signature: %d\n", verify(token));
    printf("lc_is_device_rooted: %d\n", rooted());

    memset(flag, 0, sizeof(flag));
    rc = decrypt(token, flag, sizeof(flag));
    if (rc < 0) {
        printf("lc_decrypt_flag    : refused (%d)\n", rc);
    } else {
        printf("lc_decrypt_flag    : %s\n", flag);
    }

    dlclose(h);
    return 0;
}
