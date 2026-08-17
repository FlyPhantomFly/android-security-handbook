/*
 * vault-runner.c — the harness you are given for the CTF in
 *                  lab-04-ctf-the-honest-trampoline.md.
 *
 * WHAT IT DOES
 *   Loads libvault.so, calls vault_open() with whatever pin you pass on the
 *   command line, and prints the result. That is all it does. It contains no
 *   hooks and no hints.
 *
 *   Your job is to write a second program — or extend this one — that installs
 *   a hook and gets vault_open() to return 0.
 *
 * HOW TO RUN
 *   ./build-ctf.sh
 *   adb push $OUT/vault-runner $OUT/libvault.so /data/local/tmp/
 *   adb shell chmod 755 /data/local/tmp/vault-runner
 *   adb shell /system/bin/linker64 /data/local/tmp/vault-runner 0000
 *
 * RETURN CODES FROM vault_open — you will meet all four
 *    0   success, and `out` holds the flag
 *   -1   wrong pin
 *   -2   TAMPERED. vault_open noticed its own first eight instruction words
 *        no longer sum to what they summed to at load time.
 *   -3   output buffer too small (you will not hit this; the runner sizes it)
 *
 * REQUIREMENTS
 *   Android NDK, arm64 device, adb. No root. No frida-server. The whole
 *   challenge is solvable as the unprivileged shell user.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - The pin. Do not brute force it; there are better than a trillion
 *     candidates and that is not the exercise.
 *   - Which hook type to use. Four are on the table and exactly one of them
 *     walks past all three defences. Read ../README.md section 3, run
 *     ../scripts/hook-surface.sh against libvault.so, and choose deliberately.
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <dlfcn.h>

typedef int (*vault_open_fn)(const char *, char *, size_t);

int main(int argc, char **argv) {
    char out[128];
    const char *pin = (argc > 1) ? argv[1] : "0000";

    setvbuf(stdout, NULL, _IONBF, 0);

    void *h = dlopen("/data/local/tmp/libvault.so", RTLD_NOW);
    if (!h) { printf("dlopen failed: %s\n", dlerror()); return 1; }

    vault_open_fn vault_open = (vault_open_fn)dlsym(h, "vault_open");
    if (!vault_open) { printf("dlsym failed: %s\n", dlerror()); return 1; }
    printf("vault_open @ %p\n", (void *)vault_open);

    memset(out, 0, sizeof(out));
    int rc = vault_open(pin, out, sizeof(out));

    printf("vault_open(\"%s\") = %d", pin, rc);
    switch (rc) {
    case  0: printf("  FLAG: %s\n", out); break;
    case -1: printf("  (wrong pin)\n"); break;
    case -2: printf("  (TAMPERED - vault_open's own prologue changed)\n"); break;
    case -3: printf("  (buffer too small)\n"); break;
    default: printf("  (unexpected)\n"); break;
    }
    return rc == 0 ? 0 : 1;
}
