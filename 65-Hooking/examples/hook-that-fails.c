/*
 * hook-that-fails.c — installs a CORRECT inline hook on a function that is
 *                     never called, and prints the proof that both statements
 *                     are true at the same time.
 *
 * WHAT IT DOES
 *   Loads libinline.so and hooks `lic_is_valid` so that it unconditionally
 *   returns 1. Then it calls, in order:
 *
 *     lic_is_valid("bad")        -> 1     the hook works
 *     lic_open_feature("bad")    -> -1    the hook is irrelevant
 *
 *   Both lines are printed in the same run. The hook is not broken. The
 *   function is not the one making the decision, because clang inlined its
 *   body into lic_open_feature at -O2. See libinline.c for the disassembly.
 *
 *   It then hooks `lic_open_feature` — the caller — and shows that reaching
 *   for the consumer of the decision rather than its producer fixes it.
 *
 * WHY THIS IS THE MOST IMPORTANT EXAMPLE IN THE DIRECTORY
 *   The failure mode it demonstrates is silent. Your hook fires. Your log line
 *   prints. Your return value is honoured. And the application still refuses,
 *   because the code path you instrumented is dead. Testers lose hours here,
 *   and the usual reaction — "my hook is not working" — sends them to debug the
 *   hooking engine, which is the one thing that is behaving correctly.
 *
 *   The diagnostic is one command, and it is static:
 *       llvm-objdump -d libinline.so | grep "bl.*<lic_is_valid>"
 *   No output means nothing calls it, and no hook on it will ever matter.
 *
 * HOW TO RUN
 *   ./build-hook-fixtures.sh
 *   adb push $OUT/hook-that-fails $OUT/libinline.so /data/local/tmp/
 *   adb shell chmod 755 /data/local/tmp/hook-that-fails
 *   adb shell /system/bin/linker64 /data/local/tmp/hook-that-fails
 *
 * REQUIREMENTS
 *   Android NDK, arm64 device, adb. No root, no frida-server.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether hooking the caller is always the answer. It is not. If the caller
 *     was itself inlined into ITS caller you are one level further up the same
 *     problem, and at some point the honest move is to patch the constant the
 *     compiler folded rather than hook anything.
 *   - Anything about Java inlining. ART inlines too, and the fix there is
 *     different — force the method back to the interpreter. That belongs to
 *     ../../13-ART/README.md, which owns the managed layer.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>

static long PAGE;

typedef int (*lic_fn)(const char *);

/*
 * The simplest possible inline hook: overwrite the first two instructions with
 * `mov w0, #1 ; ret`. No trampoline, because we do not want to call through.
 *
 * Both encodings are round-trip verified — see ../cheatsheet.md.
 *   52800020   mov w0, #1
 *   d65f03c0   ret
 */
static int force_return_1(void *fn) {
    void *pg = (void *)((uintptr_t)fn & ~(uintptr_t)(PAGE - 1));
    size_t span = ((uintptr_t)fn + 8) - (uintptr_t)pg;
    if (mprotect(pg, span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("mprotect"); return -1;
    }
    ((uint32_t *)fn)[0] = 0x52800020u;   /* mov w0, #1 */
    ((uint32_t *)fn)[1] = 0xd65f03c0u;   /* ret        */
    mprotect(pg, span, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *)fn, (char *)fn + 8);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    PAGE = sysconf(_SC_PAGESIZE);

    void *h = dlopen("/data/local/tmp/libinline.so", RTLD_NOW);
    if (!h) { printf("dlopen failed: %s\n", dlerror()); return 1; }
    lic_fn is_valid    = (lic_fn)dlsym(h, "lic_is_valid");
    lic_fn open_feature = (lic_fn)dlsym(h, "lic_open_feature");
    if (!is_valid || !open_feature) { printf("dlsym failed\n"); return 1; }

    printf("lic_is_valid      @ %p\n", (void *)is_valid);
    printf("lic_open_feature  @ %p\n\n", (void *)open_feature);

    printf("== BEFORE ANY HOOK ==\n");
    printf("  lic_is_valid(\"bad\")       = %d\n", is_valid("bad"));
    printf("  lic_is_valid(\"PRO-1234\")  = %d\n", is_valid("PRO-1234"));
    printf("  lic_open_feature(\"bad\")   = %d\n", open_feature("bad"));
    printf("  lic_open_feature(\"PRO-1234\") = %d\n", open_feature("PRO-1234"));

    printf("\n== HOOK lic_is_valid -> always 1 ==\n");
    if (force_return_1((void *)is_valid) != 0) return 1;
    printf("  lic_is_valid(\"bad\")       = %d   <- the hook demonstrably works\n",
           is_valid("bad"));
    printf("  lic_open_feature(\"bad\")   = %d  <- and it changed NOTHING\n",
           open_feature("bad"));
    printf("\n  The hook is correct. The function is dead code from the caller's\n"
           "  point of view: clang inlined its body into lic_open_feature, so no\n"
           "  `bl lic_is_valid` exists to intercept. Confirm it statically with\n"
           "      llvm-objdump -d libinline.so | grep \"bl.*<lic_is_valid>\"\n"
           "  which prints nothing at all.\n");

    printf("\n== HOOK THE CALLER INSTEAD ==\n");
    if (force_return_1((void *)open_feature) != 0) return 1;
    printf("  lic_open_feature(\"bad\")   = %d  <- now the decision changed\n",
           open_feature("bad"));
    printf("\n  Hook where the decision is CONSUMED, not where it is computed.\n"
           "  (Here the caller returns 1 rather than 42, because the patch forces\n"
           "  a return value of 1 without knowing what the function means. A real\n"
           "  hook would use a trampoline and rewrite only the refusal path.)\n");
    return 0;
}
