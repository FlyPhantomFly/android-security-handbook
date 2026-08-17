/*
 * libinline.c — a target whose check function is BOTH exported AND inlined.
 *
 * WHY THIS FILE EXISTS
 *   Every hooking tutorial shows a hook that works. This one shows a hook that
 *   fails, for the single most common real reason, and lets you see the reason
 *   in the disassembly rather than take it on trust.
 *
 *   `lic_is_valid` has external linkage, so it appears in .dynsym, so dlsym
 *   finds it, so you can hook it. Hooking it changes nothing, because clang
 *   also INLINED its body into `lic_open_feature`. The caller does not call it.
 *   There is no `bl lic_is_valid` anywhere in the library.
 *
 *   This is not a contrived flag combination. It is plain `-O2`, which is what
 *   every release build uses. The compiler is allowed to do both things at once:
 *   emit the standalone copy because something outside this translation unit
 *   might call it, and inline the body because it can see it.
 *
 * MEASURED OUTPUT — NDK 25.2.9519653, clang 14.0.7, -shared -O2 -fPIC, aarch64
 *
 *   000000000000164c <lic_is_valid>:
 *       164c: cbz  x0, 0x1670
 *       1650: stp  x29, x30, [sp, #-16]!
 *       1654: mov  x29, sp
 *       1658: adrp x1, ...
 *       165c: add  x1, x1, #1240
 *       1660: bl   0x16f0 <strcmp@plt>
 *       1664: cmp  w0, #0
 *       1668: cset w0, eq
 *       166c: ldp  x29, x30, [sp], #16
 *       1670: ret
 *
 *   0000000000001674 <lic_open_feature>:
 *       1674: cbz  x0, 0x1694
 *       1678: stp  x29, x30, [sp, #-16]!
 *       167c: mov  x29, sp
 *       1680: adrp x1, ...            <-- the SAME body, inlined
 *       1684: add  x1, x1, #1240
 *       1688: bl   0x16f0 <strcmp@plt>
 *       168c: ldp  x29, x30, [sp], #16
 *       1690: cbz  w0, 0x169c
 *       1694: mov  w0, #-1            <-- refused
 *       1698: ret
 *       169c: mov  w0, #42            <-- allowed
 *       16a0: ret
 *
 *   Read the second listing and look for a call to the first. There is none.
 *   Chapter 18 recorded exactly this outcome for a byte patch
 *   (../../18-ARM/README.md section 5.4: "a patch that provably works, against
 *   a function that provably no longer matters"). Hooking inherits the problem
 *   unchanged, because a hook is a patch with better ergonomics.
 *
 * WHAT TO DO ABOUT IT — in order of preference
 *   1. Hook the CALLER (`lic_open_feature`) instead. The decision is still made
 *      somewhere; find where it is consumed rather than where it is computed.
 *   2. Hook what the inlined copy still calls out to. Here the inlined body
 *      still goes through the PLT to `strcmp`, so a PLT/GOT hook DOES reach it
 *      even though an inline hook on lic_is_valid does not — see plt-got-hook.c.
 *   3. Patch the inlined copy directly, at its address inside the caller. This
 *      works and does not scale: the compiler may have inlined it into six
 *      callers, each with different register allocation.
 *
 * BUILD
 *   $NDK/aarch64-linux-android21-clang -shared -O2 -fPIC -o libinline.so libinline.c
 *   (or run ./build-hook-fixtures.sh)
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether YOUR target is inlined. Compiler versions, optimisation levels
 *     and inlining budgets differ. Read the caller's disassembly; do not assume
 *     this file's outcome transfers.
 *   - How to force the compiler not to inline. `__attribute__((noinline))`
 *     exists, but you do not control the build of the thing you are testing.
 */

#include <string.h>

/* External linkage: exported, hookable — and inlined anyway. */
int lic_is_valid(const char *key) {
    return key && strcmp(key, "PRO-1234") == 0;
}

/* The caller. Its body contains a COPY of lic_is_valid, not a call to it. */
int lic_open_feature(const char *key) {
    if (!lic_is_valid(key)) return -1;
    return 42;
}
