/*
 * sum_demo.c — the chapter's reference program, at a LOW level of abstraction.
 *
 * PURPOSE
 *   Version 2 of 4. Compare against sum_demo.py, SumDemo.java and sum_demo.s.
 *   Same program. Completely different clothes.
 *
 * BUILD AND RUN
 *   host $ gcc -O0 -g sum_demo.c -o sum_demo && ./sum_demo
 *   host $ ./sum_demo 100 1000
 *
 * SEE WHAT IT BECOMES
 *   host $ gcc -O0 -S sum_demo.c -o sum_demo_real.s   # assembly
 *   host $ objdump -d sum_demo | less                 # machine code
 *   host $ readelf -h sum_demo                        # the ELF header
 *   host $ xxd sum_demo | head                        # the raw bytes
 *
 * COMPARE OPTIMISATION LEVELS — this is the most instructive experiment in the file
 *   host $ gcc -O0 -S sum_demo.c -o /tmp/O0.s
 *   host $ gcc -O2 -S sum_demo.c -o /tmp/O2.s
 *   host $ diff /tmp/O0.s /tmp/O2.s
 *   At -O2 the compiler may unroll the loop, or replace it entirely with the closed-form
 *   n*(n+1)/2. The source did not change. This is why decompiled code often looks nothing
 *   like the original, and why you must never assume the structure you see was written.
 *
 * WHAT TO NOTICE
 *   * Every variable has a declared type and therefore a fixed size in bytes.
 *   * `int` is 32 bits and signed. It WRAPS silently. See the experiments at the bottom.
 *   * After building, the source is no longer needed. Delete it and ./sum_demo still runs.
 *     Compare with sum_demo.py, where deleting the file destroys the program.
 *
 * Chapter 03 — Programming Fundamentals, sections 2.3, 3.4 and 9.1
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

/*
 * Sum 1..n, returning -1 if the running total ever exceeds `limit`.
 *
 * Four things here have no equivalent in the Python version:
 *   1. `int` return type — the function can only ever produce a 32-bit signed integer.
 *   2. `int n, int limit` — the parameters have fixed sizes, decided at compile time.
 *   3. `int total` — four bytes of stack space, reserved on entry, gone on return.
 *   4. Silent overflow — if `total` exceeds INT_MAX it wraps to a negative number and the
 *      `total > limit` test becomes false, so the loop keeps going. Try it.
 */
int bounded_sum(int n, int limit) {
    int total = 0;                       /* 4 bytes on the stack */
    for (int i = 1; i <= n; i++) {       /* i also lives on the stack */
        total = total + i;               /* THIS LINE CAN OVERFLOW SILENTLY */
        if (total > limit) {
            return -1;
        }
    }
    return total;
}

/*
 * The same function written to be safe. Compare the two in the disassembly: the checked
 * version costs one extra branch per iteration, which is the entire price of correctness here.
 */
int bounded_sum_checked(int n, int limit) {
    int total = 0;
    for (int i = 1; i <= n; i++) {
        /* Check BEFORE the addition, not after — checking afterwards means inspecting a value
           that has already wrapped, and undefined behaviour has already happened. */
        if (total > INT_MAX - i) {
            return -2;                   /* would overflow */
        }
        total = total + i;
        if (total > limit) {
            return -1;
        }
    }
    return total;
}

int main(int argc, char **argv) {
    int n     = (argc > 1) ? atoi(argv[1]) : 10;
    int limit = (argc > 2) ? atoi(argv[2]) : 1000;

    printf("%d\n", bounded_sum(n, limit));

    if (argc > 3) {                      /* any third argument switches on the comparison */
        printf("checked: %d\n", bounded_sum_checked(n, limit));
        printf("INT_MAX = %d  (%zu bytes)\n", INT_MAX, sizeof(int));
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------
 * EXPERIMENTS
 *
 * 1. THE OVERFLOW. Run:
 *        ./sum_demo 100000 2147483647
 *    The true sum of 1..100000 is 5,000,050,000, which does not fit in a signed 32-bit int.
 *    The result wraps. The program does not warn you, does not crash, and returns a number
 *    that looks plausible. Now run the Python version with the same arguments and compare.
 *
 * 2. LET THE COMPILER FIND IT. Rebuild with:
 *        gcc -fsanitize=undefined -O0 -g sum_demo.c -o sum_demo_san && ./sum_demo_san 100000 2147483647
 *    It names the exact file, line and column, in under a second. This is chapter 03 section 9.2.
 *
 * 3. FIND THE LOOP IN THE ASSEMBLY.
 *        gcc -O0 -S sum_demo.c -o - | sed -n '/bounded_sum:/,/ret/p'
 *    There is no `for` instruction. Find the compare, the forward conditional branch (the exit)
 *    and the backward unconditional branch (the repeat). Every loop you will ever reverse is
 *    that shape.
 *
 * 4. FIND YOUR `if` IN THE FILE.
 *        objdump -d sum_demo | grep -A2 -B2 cmp
 *    Pick one instruction, note its address, convert to a file offset with
 *    `readelf -S sum_demo`, then `xxd -s <offset> -l 16 sum_demo`. Those bytes ARE your
 *    comparison. See labs/lab-01.
 *
 * 5. WHAT SURVIVED?
 *        strings sum_demo | grep -i bound
 *    The function name is present because -g kept the symbols. Now strip it:
 *        strip sum_demo -o sum_demo_stripped && strings sum_demo_stripped | grep -i bound
 *    Nothing. Compare with `strings SumDemo.class`, where the names cannot be removed because
 *    the runtime needs them. That difference is why Android Java decompiles well and .so files
 *    do not.
 * ------------------------------------------------------------------------------------------ */
