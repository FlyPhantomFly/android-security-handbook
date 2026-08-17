/*
 * examples/fold.c -- the independent fixture for chapter 74, case C.
 *
 * WHAT THIS DEMONSTRATES
 *   A string "obfuscated" by XOR-ing it against a compile-time constant key is
 *   not obfuscated at all once the optimiser is allowed to run. Build this file
 *   twice from IDENTICAL SOURCE, at -O0 and at -O2, and the -O2 build ships the
 *   plaintext that the -O0 build hid.
 *
 *   Note the __attribute__((noinline)) on decode(). It is deliberate, and it is
 *   the point: 58-IDA records noinline as the fix for this class, and it does
 *   not work here. noinline constrains the INLINER. The transformation that
 *   leaks the string is interprocedural constant propagation followed by
 *   function specialisation, which noinline does not restrain at all.
 *
 * WHY A SEPARATE FIXTURE
 *   59-radare2/examples/01-r2-target.c already demonstrates the leak. This file
 *   exists so that the reproduction in chapter 74 is INDEPENDENT evidence rather
 *   than a re-execution of the same source. It was written from scratch and is
 *   deliberately as small as the effect allows.
 *
 * BUILD (host; writes OUTSIDE the repository -- do not commit .so files)
 *
 *   NOTE the host tag below is spelled out rather than globbed. A glob of the
 *   form prebuilt/<star>/bin cannot be written inside a C block comment: the
 *   star-slash closes the comment early and the rest of this header becomes
 *   code. That is not hypothetical -- it is how the first version of this file
 *   failed to compile, and 37-RootDetection shipped the same bug once with
 *   /proc/<star>/mounts inside a comment. Substitute your own host tag:
 *   windows-x86_64, linux-x86_64 or darwin-x86_64.
 *
 *   NDK=$HOME/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/bin
 *   OUT=$HOME/ch74-build && mkdir -p "$OUT"
 *   "$NDK"/aarch64-linux-android21-clang -Wall -Wextra -O0 -fPIC -shared \
 *        -o "$OUT/fold-O0.so" examples/fold.c
 *   "$NDK"/aarch64-linux-android21-clang -Wall -Wextra -O2 -fPIC -shared \
 *        -o "$OUT/fold-O2.so" examples/fold.c
 *
 * OBSERVE
 *   "$NDK"/llvm-strings -n 4 "$OUT/fold-O0.so" | grep xbin    # expect: nothing
 *   "$NDK"/llvm-strings -n 4 "$OUT/fold-O2.so" | grep xbin    # expect: /system/xbin/su
 *
 *   "$NDK"/llvm-objdump -s -j .rodata "$OUT/fold-O0.so"       # the ciphertext
 *   "$NDK"/llvm-objdump -s -j .rodata "$OUT/fold-O2.so"       # the PLAINTEXT, no ciphertext
 *
 *   "$NDK"/llvm-objdump -d --disassemble-symbols=decode "$OUT/fold-O0.so"   # 31 instructions
 *   "$NDK"/llvm-objdump -d --disassemble-symbols=decode "$OUT/fold-O2.so"   #  4 instructions
 *
 * EXECUTED?
 *   YES. Built with NDK 25.2.9519653 on the host (Windows 11, Git Bash) while
 *   writing chapter 74, and every output quoted in README.md section 3.3.3 and
 *   in examples/reproduction-log.md came from that build. Both builds compile
 *   clean under -Wall -Wextra.
 *
 * TARGET-CHECK
 *   This is an ARM64 shared object built for Android. It is never executed --
 *   the whole demonstration is static, on the file. That matters: the leak is
 *   visible to anyone holding the APK, with no device involved.
 */

#include <stdio.h>

/*
 * "/system/xbin/su" XOR 0xa7, fifteen bytes.
 *
 * Reproduce this array with:
 *   python3 -c "s='/system/xbin/su'; print(','.join('0x%02x'%(ord(c)^0xa7) for c in s))"
 *
 * Both this array and the key below are `static const`, which is exactly the
 * property that lets the optimiser evaluate the decode at compile time. That is
 * not a mistake in the fixture -- it is the mistake the fixture is about, and it
 * is what almost every hand-rolled string obfuscation in the wild looks like.
 */
static const unsigned char ct[] = {
    0x88, 0xd4, 0xde, 0xd4, 0xd3, 0xc2, 0xca, 0x88,
    0xdf, 0xc5, 0xce, 0xc9, 0x88, 0xd4, 0xd2
};

static const unsigned char key = 0xa7;

/*
 * The decoder. noinline is requested, granted, and useless.
 *
 * At -O2 this function still exists and main() still calls it -- you can see the
 * `bl` in the disassembly. What changed is its BODY: every call site passes
 * compile-time constants, so clang specialised the function against them and the
 * fifteen-iteration XOR loop became a single 16-byte vector load of the finished
 * plaintext:
 *
 *     0000000000001640 <decode>:
 *         1640: adrp  x8, ...
 *         1644: ldr   q0, [x8, #1184]     <-- the plaintext, already decoded
 *         1648: str   q0, [x0]
 *         164c: ret
 *
 * The `ldr q0` shape is worth memorising. A 16-byte vector load feeding a store
 * into a caller-supplied buffer, inside a function that is supposed to be
 * decrypting something, means the decryption already happened at build time.
 */
__attribute__((noinline))
static void decode(char *out, const unsigned char *in, unsigned n, unsigned char k)
{
    for (unsigned i = 0; i < n; i++) {
        out[i] = (char)(in[i] ^ k);
    }
    out[n] = '\0';
}

int main(void)
{
    char buf[32];

    decode(buf, ct, (unsigned)sizeof ct, key);
    printf("%s\n", buf);

    return 0;
}

/*
 * WHAT ACTUALLY FIXES THIS
 *
 * Not noinline. The remedy measured in 59-radare2 is to make a value the
 * compiler cannot prove:
 *
 *     static volatile unsigned char key = 0xa7;
 *
 * `volatile` forbids the optimiser from assuming it knows the value, so the loop
 * survives -- at -O2 it vectorises into `dup` / `eor` rather than disappearing --
 * and the plaintext is absent from the built object.
 *
 * But treat that as a demonstration, not as security advice. It defeats the
 * OPTIMISER, not an analyst: the ciphertext and the key are both still in the
 * file, and recovering the string is a two-line script. The only durable answer
 * is for the value not to be in the binary at all -- derived from a runtime input,
 * a server response, or a key the user supplies.
 *
 * The transferable rule, which is larger than this file:
 *
 *     If the optimiser can prove your secret, it will store your secret.
 *
 * And the audit that catches it, which needs BOTH lines:
 *
 *     llvm-strings -n 4 lib.so | grep -F "$SECRET"        # expect nothing
 *     llvm-objdump -s -j .rodata lib.so | grep -iF "$CT"  # expect SOMETHING
 *
 * The first line alone passes when the obfuscation worked AND when the compiler
 * deleted the whole construct. That is 58-IDA's "passed for exactly the wrong
 * reason", and it is why the second line is not optional.
 */
