/*
 * bug3.c — Debugging challenge 3: use after free, escalating to a privilege bug.
 * Difficulty: * * * - -
 *
 * BUILD AND RUN
 *   host $ gcc -O0 -g bug3.c -o bug3 && ./bug3
 *
 * WITH THE SANITISER — note that it names BOTH the free and the original allocation
 *   host $ gcc -fsanitize=address -g bug3.c -o bug3_asan && ./bug3_asan
 *
 * This is not a crash. It is a privilege escalation, and the difference matters.
 * See labs/lab-03-debugging-challenge.md.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[32];
    int  admin;
} session_t;

session_t *make_session(const char *name, int admin) {
    session_t *s = malloc(sizeof(session_t));
    if (!s) return NULL;
    strncpy(s->name, name, sizeof(s->name) - 1);
    s->name[sizeof(s->name) - 1] = '\0';
    s->admin = admin;
    return s;
}

void logout(session_t *s) {
    printf("logging out %s\n", s->name);
    free(s);
    /* Note what does NOT happen here. */
}

int main(void) {
    session_t *s = make_session("alice", 0);
    printf("alice admin flag: %d\n", s->admin);

    logout(s);

    /* Something else allocates. The allocator, being efficient, hands back the block it just
       reclaimed — which is exactly the behaviour that makes this exploitable rather than random. */
    session_t *attacker = make_session("mallory", 1);
    (void)attacker;

    /* And the stale pointer is still used, one function call later, by code that has no idea
       any of the above happened. */
    printf("after logout, s->name = %s, s->admin = %d\n", s->name, s->admin);

    if (s->admin) {
        printf(">>> PRIVILEGE ESCALATION: a logged-out session is now administrative.\n");
    }
    return 0;
}

/*
 * QUESTIONS
 *   1. What does the final line print? Explain WHY the second malloc returned the same address.
 *   2. ASan names two source locations: "freed by thread T0 here" and "previously allocated by
 *      thread T0 here". Why are BOTH needed to understand the bug?
 *   3. This is not a crash. Explain how an attacker who controls what gets allocated after the
 *      free turns it into "become admin". This technique is called heap grooming.
 *   4. There are three defensible one-line fixes. Name them, pick one, and defend it.
 *
 * THE FIXES, and the trade-offs
 *   a. `logout(&s)` taking a session_t** and setting *s = NULL after the free.
 *      Turns the use-after-free into a null dereference: a crash instead of an escalation.
 *      A crash is a much better failure mode than silent privilege escalation.
 *   b. Reference counting, so the block is only freed when the last holder releases it.
 *      Correct, and adds bookkeeping every caller must get right.
 *   c. Do not free at all — pool the sessions and mark them invalid.
 *      Eliminates the class entirely at the cost of memory.
 *
 * WHAT JAVA WOULD HAVE DONE
 *   This bug cannot exist in managed code: the object is not collected while a reference exists.
 *   That is chapter 03 section 3.14 in one sentence — and it stops being true the moment the same
 *   data crosses into a .so through JNI.
 */
