/*
 * bug2.c — Debugging challenge 2: integer overflow in an allocation size.
 * Difficulty: * * - - -
 *
 * BUILD AND RUN
 *   host $ gcc -O0 -g bug2.c -o bug2
 *   host $ ./bug2 4
 *   host $ ./bug2 200000000
 *   host $ ./bug2 134217729
 *
 * WITH A DEBUGGER
 *   host $ gdb ./bug2
 *   (gdb) break load_records
 *   (gdb) run 200000000
 *   (gdb) next
 *   (gdb) print size
 *   (gdb) print (unsigned long)size
 *
 * WITH SANITISERS
 *   host $ gcc -fsanitize=undefined,address -g bug2.c -o bug2_san && ./bug2_san 200000000
 *
 * See labs/lab-03-debugging-challenge.md and examples/overflow_demo.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECORD_SIZE 16

/* Allocates space for `count` records and copies them in.
   Every individual step here is defensible. That is what makes it a good bug. */
char *load_records(const char *src, int count) {
    int size = count * RECORD_SIZE;
    char *buf = malloc(size);
    if (!buf) {
        return NULL;
    }
    memcpy(buf, src, count * RECORD_SIZE);
    return buf;
}

int main(int argc, char **argv) {
    int count = (argc > 1) ? atoi(argv[1]) : 4;

    char src[8192];
    memset(src, 'A', sizeof(src));

    printf("count = %d\n", count);
    printf("  true product (64-bit) : %lld\n", (long long)count * RECORD_SIZE);
    printf("  as computed (32-bit)  : %d\n", count * RECORD_SIZE);

    char *r = load_records(src, count);
    printf("  load_records returned %p\n", (void *)r);
    free(r);
    return 0;
}

/*
 * QUESTIONS
 *   1. What is `size` when count is 200000000? What does malloc actually receive?
 *   2. Try 134217729. Why is that value more dangerous than 200000000?
 *      (Hint: 134217729 * 16 = 2147483664, which wraps to 16.)
 *   3. Which line and column did the sanitiser name?
 *   4. Write the fix. Then write your severity assessment, and say what ONE additional fact you
 *      would need before you could put a number on it in a real report.
 *
 * THE FIX — see examples/overflow_demo.c, load_records_FIXED()
 *   Reject implausible counts first; do the multiplication with __builtin_mul_overflow or use
 *   calloc, which performs the same check internally.
 */
