/*
 * libguard.c — the hook target used by every example, script and lab in this
 *              chapter. Build it, do not download it. It is deliberately tiny
 *              so that its disassembly fits on one screen and you can hold the
 *              whole thing in your head while you patch it.
 *
 * WHY THESE THREE FUNCTIONS
 *
 *   guard_check()  is the interesting one. Its prologue, as clang -O2 emits it
 *                  for aarch64, is four instructions long and the THIRD of them
 *                  is `adrp` — a PC-relative instruction. That single fact is
 *                  what makes this file a teaching artefact rather than a toy:
 *                  a 16-byte absolute-jump patch displaces four instructions,
 *                  one of which cannot simply be copied elsewhere. It must be
 *                  RE-ENCODED for its new address. See ../README.md section 3.7
 *                  and labs/lab-02.
 *
 *   guard_level()  starts with `adrp` at instruction ZERO. Even a 4-byte branch
 *                  patch displaces a PC-relative instruction here. It exists so
 *                  you can see that "just use a short branch" does not make the
 *                  relocation problem go away.
 *
 *   guard_name()   returns a pointer into .rodata. It is here so the hook-point
 *                  analyser has a third shape to report on.
 *
 *   guard_counter  is exported deliberately. After an inline hook that calls
 *                  through to the original, this counter proves the ORIGINAL
 *                  BODY still ran. Without it you cannot distinguish "my
 *                  replacement called the trampoline" from "my replacement
 *                  returned a constant and the original never executed".
 *
 * BUILD (host, outside the repository — never commit the .so)
 *
 *   NDK=$HOME/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/<host>/bin
 *   $NDK/aarch64-linux-android21-clang -shared -O2 -fPIC -o libguard.so libguard.c
 *
 *   Or just run ./build-hook-fixtures.sh, which builds every fixture in this
 *   directory into a scratch tree outside the repo.
 *
 * WHAT THIS FILE WILL *NOT* SHOW YOU
 *   - Anything about Java. This is the native layer only.
 *   - A realistic authentication routine. `strcmp` against a hard-coded string
 *     is not how anyone should check a token; it is here because it produces a
 *     `bl strcmp` through the PLT, which is the third hook layer the chapter
 *     compares. Do not copy this pattern into anything real.
 */

#include <string.h>

/* Not `static const char *` — an array, so the bytes land in .rodata and the
   compiler forms their address with adrp/add rather than loading a pointer. */
static const char SECRET[] = "s3cr3t-token";

/* Exported so a hook can prove the original body executed. */
int guard_counter = 0;

/*
 * Returns 1 when `token` matches the built-in secret, 0 otherwise.
 *
 * Measured prologue, NDK 25.2.9519653 clang 14.0.7, -O2 -fPIC, aarch64:
 *
 *   +0   a9bf7bfd    stp  x29, x30, [sp, #-16]!     position independent
 *   +4   910003fd    mov  x29, sp                   position independent
 *   +8   b0000008    adrp x8, <page of guard_counter GOT entry>   PC-RELATIVE
 *   +12  f944ad08    ldr  x8, [x8, #2392]           position independent
 *
 * The `adrp` at +8 is the whole point. Copy it verbatim to a trampoline and it
 * computes the wrong page.
 */
int guard_check(const char *token) {
    guard_counter++;
    if (!token) return 0;
    return strcmp(token, SECRET) == 0;
}

/*
 * Returns twice the number of times guard_check has been called.
 *
 * Measured prologue: `adrp` is instruction ZERO.
 *
 *   +0   b0000008    adrp x8, ...                   PC-RELATIVE at offset 0
 *   +4   f944ad08    ldr  x8, [x8, #2392]
 *   +8   b9400108    ldr  w8, [x8]
 *   +12  531f7900    lsl  w0, w8, #1
 */
int guard_level(void) {
    return guard_counter * 2;
}

/* Returns a pointer to the secret. A third prologue shape for the analyser. */
const char *guard_name(void) {
    return SECRET;
}
