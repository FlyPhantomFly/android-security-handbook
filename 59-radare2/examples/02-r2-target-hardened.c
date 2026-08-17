/*
 * 02-r2-target-hardened.c -- the fix for the measured failure in 01-r2-target.c.
 *
 * PURPOSE
 *   01-r2-target.c XOR-encrypts a sensitive path so that `strings` will not find it, and
 *   at -O2 that protection is DELETED BY THE COMPILER. This file shows the minimal change
 *   that makes it actually hold, and exists so you can diff the two binaries and see the
 *   difference in the disassembly rather than taking it on faith.
 *
 * BUILD
 *       cd 59-radare2/examples && ./build.sh
 *   produces libr2hardened.so in the out-of-tree build directory.
 *
 * THE MEASUREMENT (NDK 25.2.9519653, aarch64-linux-android21-clang, -O2 -Wall -Wextra)
 *
 *   Naive version (01-r2-target.c), constant key:
 *       llvm-strings -n 4 libr2target.so | grep xbin   ->  /system/xbin/su      LEAKED
 *   Hardened version (this file), volatile key:
 *       llvm-strings -n 4 libr2hardened.so | grep xbin ->  (nothing)            HELD
 *
 *   And in the disassembly, the reason. In the naive -O2 build the decode loop does not
 *   exist at all; clang folded it and left a single vector load of the finished plaintext:
 *
 *       adrp  x8, 0x0
 *       ldr   q0, [x8, #1680]      ; 1680 = 0x690 = .rodata -- already decoded
 *       str   q0, [sp]
 *       bl    <access@plt>
 *
 *   In this hardened build the loop survives (vectorised, but real) and operates on
 *   ciphertext that is still ciphertext on disk:
 *
 *       ldrb  w8, [x8, #...]       ; load the volatile key -- compiler may not assume it
 *       dup   v0.8b, w8
 *       eor   v0.8b, v0.8b, v1.8b  ; the XOR actually happens at run time
 *
 * WHY volatile WORKS
 *   `volatile` tells the compiler it may not assume that a load returns the value it last
 *   stored -- the object may change by means outside the program's control. That single
 *   assumption is what constant folding depends on, so removing it breaks the fold chain
 *   and the loop must be emitted.
 *
 *   This is the same reasoning 19-Memory applies to scrubbing secrets with a volatile
 *   loop, and it is the same class of problem: a standard defensive idiom that the
 *   optimiser is entitled to delete.
 *
 * WHAT THIS DOES *NOT* BUY YOU
 *   The string is now absent from the file, and it is present in memory for as long as
 *   `buf` is live at run time. Any attacker with Frida, r2frida, or a core dump reads it
 *   trivially -- see README.md section 7.3. This raises the cost of a `strings` sweep from
 *   zero to "attach a debugger". It is a rate limiter, not a boundary. Do not ship a
 *   secret to a device and call it protected.
 *
 * Compiles clean with -Wall -Wextra under aarch64-linux-android21-clang (NDK 25.2.9519653).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

/* Identical ciphertext to 01-r2-target.c: "/system/xbin/su" XOR 0xA7. */
static const unsigned char k_enc_path[] = {
    0x88, 0xd4, 0xde, 0xd4, 0xd3, 0xc2, 0xca, 0x88,
    0xdf, 0xc5, 0xce, 0xc9, 0x88, 0xd4, 0xd2
};

/*
 * THE ONE LINE THAT MATTERS.
 *
 * In 01-r2-target.c this was `#define XOR_KEY 0xA7` -- a compile-time constant, which is
 * what lets clang evaluate the decode at compile time. Declaring it `volatile` makes the
 * key opaque to the optimiser and the fold becomes illegal.
 */
static volatile unsigned char g_xor_key = 0xA7;

__attribute__((noinline))
int lt_probe_paths_hardened(void)
{
    char buf[64];
    unsigned char key = g_xor_key;   /* one volatile read, then ordinary arithmetic */
    size_t i;

    for (i = 0; i < sizeof(k_enc_path); i++) {
        buf[i] = (char)(k_enc_path[i] ^ key);
    }
    buf[sizeof(k_enc_path)] = '\0';

    return access(buf, F_OK) == 0 ? 1 : 0;
}

/*
 * A NOTE ON CLEVERER SCHEMES, AND WHY THIS FILE DOES NOT SHIP ONE
 *
 * The obvious next step is to "derive" the key from something the compiler cannot know,
 * so that an analyst cannot simply read the one-byte key sitting next to the ciphertext.
 * Be careful: most hand-rolled attempts at this are folded away just as thoroughly as the
 * naive version was, and for the same reason.
 *
 * A concrete example of one that does NOT work:
 *
 *     uintptr_t anchor = (uintptr_t)k_enc_path;
 *     unsigned char key = 0xA7u ^ (anchor & 0xFF) ^ (anchor & 0xFF);   // BROKEN
 *
 * It looks address-dependent. It is not: `x ^ y ^ y` is `x`, clang simplifies it during
 * instruction combining, recovers the constant 0xA7, and then the whole decode loop is
 * constant-foldable again -- exactly the failure this file exists to fix.
 *
 * The rule this illustrates is more useful than any particular scheme:
 *
 *     If a sufficiently smart compiler could compute your key, assume it did.
 *
 * Verify, do not assume. Build the library, run `strings` on the RELEASE artefact, and
 * check that the thing you were protecting is absent. That check takes five seconds and is
 * the only evidence that counts. Lab 02 walks through it.
 */

int main(void)
{
    printf("hardened=%d\n", lt_probe_paths_hardened());
    return 0;
}
