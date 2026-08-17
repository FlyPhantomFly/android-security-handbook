/*
 * overflow_demo.c — integer overflow as a vulnerability class, in code that looks reasonable.
 *
 * PURPOSE
 *   Four shapes of the same bug, each in a form seen repeatedly in real parsers, each with:
 *       * why a developer writes it
 *       * how you detect it
 *       * how it is exploited
 *       * the secure fix, as code
 *
 *   Nothing here is contrived. Every function below is the shape of code that ships.
 *
 * BUILD AND RUN
 *   host $ gcc -O0 -g overflow_demo.c -o overflow_demo
 *   host $ ./overflow_demo                       # the guided tour
 *   host $ ./overflow_demo 1 200000000           # run one case with a chosen value
 *
 * LET THE COMPILER FIND THEM — do this second, and notice how long it takes
 *   host $ gcc -fsanitize=undefined,address -g overflow_demo.c -o overflow_san
 *   host $ ./overflow_san 1 200000000
 *
 * WHY IT MATTERS ON ANDROID
 *   Java's `int` wraps too — the Java Language Specification requires it. What Java adds is a
 *   bounds check on the ARRAY ACCESS, so a wrapped length becomes NegativeArraySizeException or
 *   ArrayIndexOutOfBoundsException rather than memory corruption. That is a denial of service
 *   instead of code execution, which is a genuine improvement and is NOT the same as safety.
 *   And the moment the data crosses into a .so through JNI, all of this is back on the table.
 *
 * Chapter 03 — Programming Fundamentals, sections 3.4 and 9.2; labs/lab-03 bug 2
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#define RECORD_SIZE 16
#define MAX_REASONABLE_RECORDS 100000


/* =================================================================================================
 * SHAPE 1 — the allocation size overflow. The classic, and still the most common.
 *
 * WHY A DEVELOPER WRITES IT
 *   Every individual step is defensible. Sixteen bytes per record times `count` records is
 *   obviously the right size. The allocation is checked for failure. memcpy is given exactly the
 *   number of bytes that were allocated. The code reads as careful, and it is — about everything
 *   except the type of `size`.
 *
 * WHAT ACTUALLY HAPPENS
 *   `int` is 32 bits signed, maximum 2 147 483 647. With count = 200 000 000 the true product is
 *   3 200 000 000, which does not fit, so it wraps to -1 094 967 296. That negative value is then
 *   passed to malloc, whose parameter is size_t — unsigned, 64 bits — so it becomes an enormous
 *   positive number and the allocation fails. Change count slightly and the wrapped value is
 *   SMALL AND POSITIVE: a tiny buffer is allocated, memcpy writes gigabytes into it, and the
 *   attacker controls the length. That is a controlled heap overflow.
 *
 * DETECTION
 *   grep -rn 'malloc(\|calloc(\|new byte\[' src/ | grep -E '\*|\+'
 *   Then read each one. Most are fine. Ten minutes, and one of them is this.
 *
 * SEVERITY
 *   Critical IF count is attacker-controlled and the wrapped value lands small-and-positive.
 *   Low if count is bounded upstream by a protocol field of eight bits. You cannot rate it
 *   without following `count` backwards to its source.
 * ============================================================================================== */

char *load_records_BUGGY(const char *src, int count) {
    int size = count * RECORD_SIZE;          /* <-- THE BUG IS ON THIS LINE */
    char *buf = malloc(size);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, src, count * RECORD_SIZE);   /* may write far past `size` bytes */
    return buf;
}

char *load_records_FIXED(const char *src, int count) {
    /* 1. Reject nonsense before doing arithmetic on it. A record count is bounded by the
          protocol, and stating that bound explicitly is worth more than any later check. */
    if (count < 0 || count > MAX_REASONABLE_RECORDS) {
        return NULL;
    }

    /* 2. Do the multiplication in a checked helper, so the check cannot be forgotten. */
    size_t size;
    if (__builtin_mul_overflow((size_t)count, (size_t)RECORD_SIZE, &size)) {
        return NULL;                          /* the multiplication would have overflowed */
    }

    /* 3. calloc performs the same count*size check internally. Prefer it whenever the
          allocation is naturally "n things of size m". */
    char *buf = calloc((size_t)count, RECORD_SIZE);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, src, size);
    return buf;
}


/* =================================================================================================
 * SHAPE 2 — the length check that the overflow walks straight through.
 *
 * WHY A DEVELOPER WRITES IT
 *   The check IS there. It looks like defensive programming. `offset + length <= buffer_size`
 *   is exactly the right inequality — it is just evaluated in a type that cannot hold the sum.
 *
 * WHAT HAPPENS
 *   With offset near INT_MAX and a positive length, `offset + length` wraps to a NEGATIVE number,
 *   which is comfortably <= buffer_size, so the check passes and the read goes wherever the
 *   attacker pointed it. The check did not merely fail to help; it actively authorised the read.
 * ============================================================================================== */

int read_slice_BUGGY(const char *buf, int buffer_size, int offset, int length, char *out) {
    if (offset + length > buffer_size) {     /* offset + length can WRAP to negative */
        return -1;                            /* "rejected" — except it was not */
    }
    memcpy(out, buf + offset, length);
    return 0;
}

int read_slice_FIXED(const char *buf, size_t buffer_size, size_t offset, size_t length,
                     char *out) {
    /* Check each operand separately, and subtract rather than add, so nothing can wrap.
       This is the standard idiom and it is worth memorising:
           offset <= size   AND   length <= size - offset
       Both sides are non-negative at every step. */
    if (offset > buffer_size) {
        return -1;
    }
    if (length > buffer_size - offset) {
        return -1;
    }
    memcpy(out, buf + offset, length);
    return 0;
}


/* =================================================================================================
 * SHAPE 3 — the subtraction that goes negative and is then treated as unsigned.
 *
 * WHY A DEVELOPER WRITES IT
 *   "Remaining bytes" is an obvious quantity, and in the developer's mental model `consumed` is
 *   never greater than `total` because the parser only ever moves forwards. Then a malformed
 *   input makes the parser over-consume once, and the invariant is gone.
 *
 * WHAT HAPPENS
 *   total - consumed is -8. Assigning it to size_t (unsigned, 64-bit) gives
 *   18 446 744 073 709 551 608. Every subsequent bounds check against `remaining` passes.
 * ============================================================================================== */

size_t remaining_BUGGY(int total, int consumed) {
    return total - consumed;                  /* negative -> enormous when read as size_t */
}

int remaining_FIXED(int total, int consumed, size_t *out) {
    if (total < 0 || consumed < 0 || consumed > total) {
        return -1;                            /* the invariant was violated — say so */
    }
    *out = (size_t)(total - consumed);
    return 0;
}


/* =================================================================================================
 * SHAPE 4 — the loop counter that wraps and never terminates.
 *
 * WHY A DEVELOPER WRITES IT
 *   `short` was chosen because the field in the file format is sixteen bits, which is careful,
 *   type-accurate thinking. The loop then compares a `short` against an `int`.
 *
 * WHAT HAPPENS
 *   Once i reaches 32 767 the next increment wraps to -32 768, so `i < count` stays true forever.
 *   The loop never ends, and every iteration writes to arr[i] with a NEGATIVE index.
 * ============================================================================================== */

void fill_BUGGY(int *arr, int count) {
    for (short i = 0; i < count; i++) {       /* wraps at 32767 and runs forever */
        arr[i] = i;
    }
}

void fill_FIXED(int *arr, size_t count) {
    /* Use a counter type that can represent every value the bound can take. size_t is the
       right choice for anything that indexes memory. */
    for (size_t i = 0; i < count; i++) {
        arr[i] = (int)i;
    }
}


/* =================================================================================================
 * The guided tour.
 * ============================================================================================== */

static void banner(const char *title) {
    printf("\n================================================================\n");
    printf("  %s\n", title);
    printf("================================================================\n");
}

static void demo_shape1(int count) {
    banner("SHAPE 1 — allocation size overflow");
    printf("  RECORD_SIZE = %d, count = %d\n", RECORD_SIZE, count);

    /* Compute the true product in 64-bit arithmetic so we can show the difference. */
    long long truth = (long long)count * RECORD_SIZE;
    int wrapped = count * RECORD_SIZE;

    printf("  true product (64-bit) : %lld\n", truth);
    printf("  as computed (32-bit)  : %d\n", wrapped);
    printf("  as malloc sees it     : %zu\n", (size_t)wrapped);
    if (truth != (long long)wrapped) {
        printf("  >>> THE VALUES DISAGREE. The multiplication overflowed.\n");
        printf("  >>> This comparison is exactly what scripts/watch-alloc.js does at runtime.\n");
    } else {
        printf("  (no overflow at this value — try 200000000, or 134217729)\n");
    }
}

static void demo_shape2(void) {
    banner("SHAPE 2 — length check bypassed by overflow");
    int buffer_size = 1024;
    int offset = INT_MAX - 10;
    int length = 100;

    printf("  buffer_size=%d  offset=%d  length=%d\n", buffer_size, offset, length);
    printf("  offset + length (32-bit) = %d\n", offset + length);
    printf("  the check `offset + length > buffer_size` evaluates to %s\n",
           (offset + length > buffer_size) ? "TRUE (rejected)" : "FALSE (ACCEPTED)");
    printf("  >>> The sum wrapped negative, so the guard authorised an out-of-bounds read.\n");
    printf("  >>> The fix is to SUBTRACT: `length > buffer_size - offset`.\n");
}

static void demo_shape3(void) {
    banner("SHAPE 3 — negative subtraction read as unsigned");
    int total = 100, consumed = 108;
    size_t r = remaining_BUGGY(total, consumed);
    printf("  total=%d consumed=%d\n", total, consumed);
    printf("  total - consumed as int    : %d\n", total - consumed);
    printf("  the same value as size_t   : %zu\n", r);
    printf("  >>> Every subsequent bounds check against this value passes.\n");
}

static void demo_shape4(void) {
    banner("SHAPE 4 — loop counter wraps and never terminates");
    printf("  for (short i = 0; i < 40000; i++)\n");
    printf("  short holds -32768..32767. At 32767 the increment wraps to -32768,\n");
    printf("  so `i < 40000` remains true forever and arr[i] is indexed NEGATIVELY.\n");
    printf("  (Not executed here — it would hang and then corrupt memory.)\n");
}

int main(int argc, char **argv) {
    if (argc > 2) {
        int which = atoi(argv[1]);
        int value = atoi(argv[2]);
        if (which == 1) { demo_shape1(value); return 0; }
    }

    demo_shape1(4);
    demo_shape1(200000000);
    demo_shape2();
    demo_shape3();
    demo_shape4();

    banner("HOW TO FIND THESE FOR REAL");
    printf("  1. Sanitiser — names the file, line and column in under a second:\n");
    printf("       gcc -fsanitize=undefined,address -g overflow_demo.c -o san && ./san 1 200000000\n\n");
    printf("  2. Debugger — watch the value change:\n");
    printf("       gdb ./overflow_demo ; break load_records_BUGGY ; run ; print size\n\n");
    printf("  3. Reading, with a pattern rather than a hunch:\n");
    printf("       grep -rn 'malloc(\\|calloc(\\|new byte\\[' src/ | grep -E '\\*|\\+'\n\n");
    printf("  4. At runtime on Android, without any source:\n");
    printf("       frida -U -f <pkg> -l scripts/watch-alloc.js\n");
    printf("       It hooks the allocator and compares each size against the 64-bit product.\n\n");
    printf("  Note that (1) takes one second and (3) takes ten minutes. Turn the sanitiser on.\n");
    return 0;
}
