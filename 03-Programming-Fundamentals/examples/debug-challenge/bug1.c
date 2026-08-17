/*
 * bug1.c — Debugging challenge 1: off by one.
 * Difficulty: * - - - -
 *
 * BUILD AND RUN
 *   host $ gcc -O0 -g bug1.c -o bug1 && ./bug1
 *   Run it ten times. Is the output stable?
 *
 * THEN LET THE TOOL FIND IT
 *   host $ gcc -fsanitize=address -g bug1.c -o bug1_asan && ./bug1_asan
 *
 * The symptom is "the answer is wrong, sometimes". Find the mechanism, not just the symptom.
 * See labs/lab-03-debugging-challenge.md.
 */

#include <stdio.h>

int sum_array(const int *arr, int len) {
    int total = 0;
    for (int i = 0; i <= len; i++) {      /* the whole bug is one character */
        total += arr[i];
    }
    return total;
}

int main(void) {
    int data[5] = {1, 2, 3, 4, 5};
    printf("sum = %d  (expected 15)\n", sum_array(data, 5));
    return 0;
}

/*
 * QUESTIONS
 *   1. What is read on the final iteration? Who owns that memory?
 *   2. Why is the output sometimes correct and sometimes not? What would make it deterministic?
 *   3. Why is this a SECURITY bug and not merely a correctness bug? Consider what sits immediately
 *      after a stack buffer, and re-read chapter 03 section 3.8.3.
 *   4. Write the regression test that catches it. Hint: put a guard value after the array.
 *
 * THE FIX
 *   for (int i = 0; i < len; i++)
 *
 *   The general rule from the cheat sheet: `<` not `<=` against a length. A length is a count,
 *   and the last valid index is always one less than the count.
 */
