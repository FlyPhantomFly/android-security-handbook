/*
 * patterns.c -- one small C function per recurring AArch64 instruction shape.
 *
 * PURPOSE
 *     Chapter 18's pattern catalogue (README section 3.10) claims that twenty
 *     shapes cover almost everything you will ever read in an Android native
 *     library. This file is the proof: every listing printed in that catalogue
 *     was produced by compiling THIS file with the NDK and disassembling the
 *     result with llvm-objdump. Nothing in the chapter was written from memory.
 *
 *     Each function is deliberately tiny and deliberately does something
 *     slightly artificial, because the goal is to force the compiler to emit
 *     one specific instruction shape with as little surrounding noise as
 *     possible.
 *
 * HOW TO BUILD
 *     # host, Git Bash / WSL / Linux / macOS, with the Android NDK installed
 *     ./build-arm-fixtures.sh /tmp/ch18
 *
 *     or by hand:
 *     $NDK/aarch64-linux-android21-clang -shared -fPIC -O2 \
 *         -o /tmp/libpatterns64.so patterns.c
 *     $NDK/llvm-objdump -d --no-show-raw-insn /tmp/libpatterns64.so
 *
 * REQUIREMENTS
 *     Android NDK r21 or newer. Nothing else -- no libc beyond Bionic's own
 *     headers, no Android project, no Gradle, no device.
 *
 * WHAT THIS FILE WILL *NOT* SHOW YOU
 *     - Byte-for-byte identical output to the chapter on a different NDK.
 *       Register allocation, instruction scheduling and inlining all change
 *       between clang releases. The SHAPES are stable; the exact registers and
 *       offsets are not. The chapter states the compiler version for this
 *       reason and you should check yours before comparing.
 *     - Anything about C++ (name mangling, vtables, exceptions). Those shapes
 *       are real and common but they belong with the decompiler workflow in
 *       57-Ghidra rather than with the instruction set.
 *     - Real cryptography, a real licence check, or anything you should copy
 *       into production. licence-check.c next door is the deliberately
 *       patchable target; this file is a reference specimen.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* 1. Leaf function: no stack frame at all.                            */
/*    Nothing is called, nothing outlives a register, so the compiler   */
/*    emits no prologue and no epilogue -- just the work and `ret`.     */
/* ------------------------------------------------------------------ */
int pat_leaf_add(int a, int b)
{
    return a + b;
}

/* ------------------------------------------------------------------ */
/* 2. Non-leaf function: needs a frame because it calls something, so   */
/*    x30 (the return address) must be spilled somewhere.               */
/* ------------------------------------------------------------------ */
int pat_nonleaf(int a)
{
    return pat_leaf_add(a, 7) * 2;
}

/* ------------------------------------------------------------------ */
/* 3. Callee-saved registers: enough live values across a call that the */
/*    compiler has to use x19..x28 and therefore has to save them.      */
/* ------------------------------------------------------------------ */
extern int pat_opaque(int);

int pat_callee_saved(int a, int b, int c)
{
    int x = pat_opaque(a);
    int y = pat_opaque(b);
    int z = pat_opaque(c);
    return x + y + z;
}

/* ------------------------------------------------------------------ */
/* 4. cbz / cbnz: compare-and-branch against zero, no flags involved.   */
/* ------------------------------------------------------------------ */
int pat_cbz(const char *s)
{
    if (s == NULL) {
        return -1;
    }
    return (int)s[0];
}

/* ------------------------------------------------------------------ */
/* 5. cmp + b.cond: comparison against a non-zero constant.             */
/* ------------------------------------------------------------------ */
int pat_cmp_branch(int v)
{
    if (v == 42) {
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 6. cset / csel: branchless conditional. This is the shape that turns */
/*    a boolean check into two instructions with no jump at all, and it */
/*    is the single most common way a "return true/false" check is      */
/*    compiled at -O2.                                                  */
/* ------------------------------------------------------------------ */
int pat_cset(int v)
{
    return v > 100;
}

int pat_csel(int a, int b)
{
    return a < b ? a : b;
}

/* ------------------------------------------------------------------ */
/* 7. tbz / tbnz: test one bit and branch. Flag words compile to this.  */
/* ------------------------------------------------------------------ */
int pat_tbz(uint32_t flags)
{
    if (flags & 0x40u) {
        return 100;
    }
    return 200;
}

/* ------------------------------------------------------------------ */
/* 8. adrp + add: forming the address of a string literal in .rodata.   */
/*    THE most important pattern in the whole catalogue -- it is how    */
/*    every constant address in position-independent code is built.     */
/* ------------------------------------------------------------------ */
const char *pat_string_literal(void)
{
    return "/system/bin/su";
}

/* ------------------------------------------------------------------ */
/* 9. adrp + ldr: reading a global variable. Same first instruction,    */
/*    different second one -- `add` gives you the ADDRESS, `ldr` gives  */
/*    you the CONTENTS.                                                 */
/* ------------------------------------------------------------------ */
int g_counter = 0;

int pat_global_read(void)
{
    return g_counter;
}

void pat_global_write(int v)
{
    g_counter = v;
}

/* ------------------------------------------------------------------ */
/* 10. Building a large immediate with movz + movk.                     */
/*     AArch64 instructions are 32 bits wide, so a 64-bit constant      */
/*     cannot fit in one. It is assembled 16 bits at a time.            */
/* ------------------------------------------------------------------ */
uint64_t pat_big_constant(void)
{
    return 0x1122334455667788ULL;
}

uint32_t pat_medium_constant(void)
{
    return 0xDEADBEEFu;
}

/* ------------------------------------------------------------------ */
/* 11. Calling an imported function -- goes through the PLT.            */
/* ------------------------------------------------------------------ */
size_t pat_calls_import(const char *s)
{
    return strlen(s);
}

/* ------------------------------------------------------------------ */
/* 12. Tail call: the last thing the function does is call something    */
/*     else and return its result, so the compiler branches instead of  */
/*     calling. No `bl`, no `ret` -- just `b`.                          */
/* ------------------------------------------------------------------ */
int pat_tail_call(const char *s)
{
    return puts(s);
}

/* ------------------------------------------------------------------ */
/* 13. Indirect call through a function pointer: `blr`.                 */
/* ------------------------------------------------------------------ */
typedef int (*handler_t)(int);

int pat_indirect_call(handler_t fn, int arg)
{
    /* The `+ 1` matters: without it this is a TAIL call and the compiler
       emits `br` with no frame at all. With it, the result has to come
       back here, so you get the true `blr` shape. */
    return fn(arg) + 1;
}

/* ------------------------------------------------------------------ */
/* 14. Switch statement dense enough for a jump table.                  */
/*     The return values are deliberately NOT an arithmetic progression: */
/*     given 11, 22, 33 ... clang notices the pattern and emits a        */
/*     multiply instead of a table, which is a real and instructive      */
/*     compiler behaviour but not the shape we are cataloguing here.     */
/* ------------------------------------------------------------------ */
int pat_switch(int op)
{
    switch (op) {
    case 0:  return 0x41;
    case 1:  return 0x9c;
    case 2:  return 0x17;
    case 3:  return 0xff;
    case 4:  return 0x02;
    case 5:  return 0xbe;
    case 6:  return 0x3d;
    case 7:  return 0x70;
    default: return -1;
    }
}

/* ------------------------------------------------------------------ */
/* 15. A fixed-size copy the compiler inlines instead of calling memcpy */
/* ------------------------------------------------------------------ */
void pat_inline_memcpy(char *dst, const char *src)
{
    memcpy(dst, src, 32);
}

/* ------------------------------------------------------------------ */
/* 16. Loads of different widths, signed and unsigned.                  */
/*     ldrb zero-extends, ldrsb sign-extends. Getting this backwards is */
/*     how you misread a comparison against a negative constant.        */
/* ------------------------------------------------------------------ */
int pat_load_widths(const uint8_t *p)
{
    int a = p[0];                       /* ldrb  -> zero-extend */
    int b = (int)(int8_t)p[1];          /* ldrsb -> sign-extend */
    int c = *(const uint16_t *)(p + 2); /* ldrh */
    int d = *(const int32_t *)(p + 4);  /* ldr w */
    return a + b + c + d;
}

/* ------------------------------------------------------------------ */
/* 17. Stack canary: a local array big enough to trigger               */
/*     -fstack-protector-strong. Build this file WITH the flag to see   */
/*     the guard load; build it without to see the same function with   */
/*     no guard at all.                                                 */
/* ------------------------------------------------------------------ */
int pat_stack_canary(const char *name)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "user=%s", name);
    return (int)strlen(buf);
}

/* ------------------------------------------------------------------ */
/* 18. Floating point arguments and return: v/d/s registers, a whole    */
/*     separate register file with its own AAPCS64 rules.               */
/* ------------------------------------------------------------------ */
double pat_float_args(double a, float b, int c)
{
    return a * (double)b + (double)c;
}

/* ------------------------------------------------------------------ */
/* 19. Nine integer arguments: the ninth does not fit in x0..x7 and     */
/*     goes on the stack. This is the single most useful AAPCS64 fact   */
/*     to see with your own eyes.                                       */
/* ------------------------------------------------------------------ */
__attribute__((noinline))
int pat_nine_args(int a1, int a2, int a3, int a4,
                  int a5, int a6, int a7, int a8, int a9)
{
    return a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9;
}

/* The arguments come out of an array so that the compiler cannot constant-fold
   the whole call away. Written with literals it becomes `mov w0, #45`, which
   is correct, impressive, and useless as a teaching listing. */
int pat_nine_args_caller(const int *p)
{
    return pat_nine_args(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8]);
}

/* ------------------------------------------------------------------ */
/* 20. Large struct return: does not fit in x0/x1, so the CALLER passes */
/*     a hidden pointer in x8 and the callee writes through it.         */
/* ------------------------------------------------------------------ */
struct big { long a, b, c, d; };

struct big pat_big_return(long seed)
{
    struct big r;
    r.a = seed;
    r.b = seed + 1;
    r.c = seed + 2;
    r.d = seed + 3;
    return r;
}

/* Small struct: 16 bytes or less comes back in x0 and x1 instead. */
struct pair { long lo, hi; };

struct pair pat_small_return(long seed)
{
    struct pair p;
    p.lo = seed;
    p.hi = ~seed;
    return p;
}

/* ------------------------------------------------------------------ */
/* 21. A raw syscall: `svc #0` with the number in x8. Native code can   */
/*     reach the kernel without going anywhere near libc, which is why  */
/*     hooking libc is not the same as blocking a behaviour.            */
/* ------------------------------------------------------------------ */
long pat_raw_syscall(void)
{
#if defined(__aarch64__)
    /* SYS_getpid on AArch64 Linux is 172. Written as a literal so the
       instruction sequence is visible rather than hidden behind a macro. */
    register long x8 __asm__("x8") = 172;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
#elif defined(__arm__)
    /* The 32-bit EABI puts the syscall number in r7 and uses `svc #0` too.
       getpid is 20 in the ARM EABI table -- a different number from the
       AArch64 one, which is exactly the sort of thing that catches people
       out when they carry knowledge across the ABI boundary.

       r7 has to be saved and restored by hand here: in Thumb mode with
       frame pointers enabled (the NDK default) r7 IS the frame pointer, and
       clang refuses to let a `register` variable bind to it. That refusal is
       correct, and working around it with an explicit push/pop is exactly
       what Bionic's own syscall stubs do. */
    long ret;
    __asm__ volatile(
        "push {r7}\n\t"
        "mov  r7, #20\n\t"
        "svc  #0\n\t"
        "pop  {r7}"
        : "=r"(ret) : : "memory");
    return ret;
#else
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/* 22. Reading a system register. On AArch64 that is `mrs`, and         */
/*     TPIDR_EL0 is the thread pointer -- how Bionic reaches            */
/*     thread-local storage, including the stack guard value.           */
/*     On ARM32 the equivalent is a coprocessor read, `mrc p15, ...`,   */
/*     which is why the two look nothing alike in a disassembly.        */
/* ------------------------------------------------------------------ */
uint64_t pat_read_thread_pointer(void)
{
#if defined(__aarch64__)
    uint64_t v;
    __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(v));
    return v;
#elif defined(__arm__)
    uint32_t v;
    __asm__ volatile("mrc p15, 0, %0, c13, c0, 3" : "=r"(v));
    return v;
#else
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* 23. A loop. Counted, with the increment and the compare visible.     */
/* ------------------------------------------------------------------ */
int pat_loop_sum(const int *a, int n)
{
    int s = 0;
    for (int i = 0; i < n; i++) {
        s += a[i];
    }
    return s;
}

/* ------------------------------------------------------------------ */
/* 24. The shape a "return true/false" security check compiles to, and  */
/*     the one every patching lab in this chapter attacks.              */
/* ------------------------------------------------------------------ */
int pat_boolean_check(const char *token)
{
    if (token == NULL) {
        return 0;
    }
    if (strlen(token) != 16) {
        return 0;
    }
    if (token[0] != 'A') {
        return 0;
    }
    return 1;
}
