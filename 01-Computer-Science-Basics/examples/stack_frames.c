/* =============================================================================
 * stack_frames.c — watching the stack grow, one frame at a time
 * Chapter 01 — Computer Science Basics
 * Companion to labs/lab-03-stack-frames-and-overflow.md
 * =============================================================================
 *
 * WHAT THIS PROGRAM DEMONSTRATES
 *
 *   1. That every function call allocates a fresh block of stack memory -- a
 *      "stack frame" -- and that the frames are laid out at DECREASING
 *      addresses. The stack grows DOWNWARD on x86-64, on AArch64, and on
 *      every architecture Android supports.
 *   2. That the distance between consecutive frames is the frame size, which
 *      the compiler decides and which you can read straight out of the
 *      `sub rsp, N` (x86-64) or `stp x29, x30, [sp, #-N]!` (AArch64)
 *      instruction in the prologue.
 *   3. That a local variable's address is not a fixed property of the source
 *      code: the SAME line of C produces a different address on every call,
 *      because the frame moves.
 *   4. That recursion consumes stack linearly and that the stack is finite,
 *      so unbounded recursion terminates the process by touching a guard page.
 *   5. That the saved frame pointer chain links every live frame together,
 *      which is precisely how a debugger, a crash handler, and Android's
 *      tombstone generator produce a backtrace.
 *   6. That arrays are indexed UPWARD while the stack grows DOWNWARD, which
 *      is the structural reason a buffer overflow reaches the return address.
 *
 * HOW TO COMPILE AND RUN
 *
 *   The flags matter. Compile it exactly like this or the demonstration is
 *   destroyed by the optimiser:
 *
 *       gcc -O0 -g -fno-omit-frame-pointer -Wall -Wextra -o stack_frames stack_frames.c
 *       ./stack_frames
 *
 *     -O0                      keeps locals in memory instead of registers, so
 *                              they have addresses you can print
 *     -fno-omit-frame-pointer  keeps rbp / x29 as a genuine frame pointer, so
 *                              the frame chain in SECTION 5 is walkable
 *     -g                       lets gdb line up source with assembly
 *
 *   Compare against an OPTIMISED build to see the demonstration collapse:
 *
 *       gcc -O2 -o stack_frames_O2 stack_frames.c && ./stack_frames_O2
 *
 *     At -O2 the compiler inlines the small functions, so several "frames"
 *     vanish entirely and the addresses stop marching downward in neat steps.
 *     That is not a bug in this program; it is the reason release builds are
 *     harder to reverse engineer than debug builds.
 *
 *   Cross-compile for AArch64 and run under QEMU:
 *
 *       aarch64-linux-gnu-gcc -O0 -g -static -fno-omit-frame-pointer \
 *           -o stack_frames_arm64 stack_frames.c
 *       qemu-aarch64 ./stack_frames_arm64
 *
 *   Build for a real Android device with the NDK:
 *
 *       $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/\
 *           aarch64-linux-android30-clang -O0 -g -fno-omit-frame-pointer \
 *           -o stack_frames_android stack_frames.c
 *       adb push stack_frames_android /data/local/tmp/
 *       adb shell chmod 755 /data/local/tmp/stack_frames_android
 *       adb shell /data/local/tmp/stack_frames_android
 *
 * WHAT TO OBSERVE
 *
 *   - SECTION 2: the three printed addresses DECREASE as you go deeper. The
 *     difference between them is the caller's frame size in bytes. Write those
 *     numbers down; they are the same numbers you will read out of the
 *     disassembly in Lab 03 Part B.
 *   - SECTION 3: after returning, calling a different function at the same
 *     depth reuses the same addresses. Stack memory is recycled, not cleared.
 *     That is why uninitialised locals contain the previous call's data, and
 *     why "stack garbage" is a real information-disclosure primitive.
 *   - SECTION 4: recursion marches downward by a constant step. Multiply the
 *     step by the depth limit and you have the stack requirement of the
 *     algorithm. Compare with `ulimit -s` (8 MB by default on Linux) and with
 *     Android's 1 MB default for non-main threads.
 *   - SECTION 5: the frame-pointer chain reaches main. Compare its output
 *     with `bt` in gdb -- they describe the same structure.
 *   - SECTION 6: &buf[0] is LOWER than &canary_like, so writing past the end
 *     of buf moves toward the guard value and then toward the return address.
 *
 * SEE ALSO
 *   labs/lab-02-processes-memory-maps.md  — finding [stack] in /proc/<pid>/maps
 *   labs/lab-03-stack-frames-and-overflow.md — taking one frame apart in gdb
 *   ../../18-ARM/README.md                — AArch64 prologues and the link register
 * =============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Track the deepest address reached, so SECTION 4 can report total usage. */
static uintptr_t g_deepest_address = UINTPTR_MAX;
static int       g_max_depth_reached = 0;

/* Helper: print an address and how far it is from a reference address. */
static void report(const char *who, const void *addr, const void *reference)
{
    long delta = (long)((const char *)addr - (const char *)reference);
    if (reference == NULL)
        printf("  %-22s local at %p\n", who, addr);
    else
        printf("  %-22s local at %p   (%+ld bytes from the caller's local)\n",
               who, addr, delta);
}

/* =========================================================================
 * SECTION 2 support — a chain of three nested functions.
 *
 * Each one declares a local, prints its address, and calls the next. Because
 * level_one has not returned when level_two runs, both frames are live at the
 * same time and occupy different memory. The addresses therefore decrease.
 * ====================================================================== */

static void level_three(const void *caller_local)
{
    volatile int local_three = 3;   /* volatile stops the optimiser from
                                     * eliminating a variable that is only
                                     * ever taken the address of */
    report("level_three()", (const void *)&local_three, caller_local);
    printf("      -> level_three is the deepest frame in this chain. When it\n");
    printf("         returns, its 'local_three' becomes stale memory that the\n");
    printf("         next call at this depth will silently reuse.\n");
}

static void level_two(const void *caller_local)
{
    volatile int local_two = 2;
    report("level_two()", (const void *)&local_two, caller_local);
    level_three((const void *)&local_two);
}

static void level_one(const void *caller_local)
{
    volatile int local_one = 1;
    report("level_one()", (const void *)&local_one, caller_local);
    level_two((const void *)&local_one);
}

/* =========================================================================
 * SECTION 3 support — two sibling functions with identical frame shapes.
 *
 * Called one after the other from the same place, they receive the same stack
 * memory, because the first one's frame was released before the second was
 * allocated. `sibling_b` deliberately reads an UNINITIALISED local to show
 * that the bytes left behind by `sibling_a` are still there.
 * ====================================================================== */

static void sibling_a(void)
{
    int marker = 0x41414141;   /* 'AAAA' -- easy to spot */
    printf("  sibling_a()            wrote  0x%08x at %p\n",
           marker, (void *)&marker);
}

static void sibling_b(void)
{
    int leftover;              /* deliberately NOT initialised */

    /* Reading an uninitialised local is undefined behaviour in C. It is done
     * here, once, on purpose, to make a security point. Never do this in real
     * code -- and when you SEE it in decompiled code, treat it as a finding.
     *
     * The read goes through a `volatile` pointer rather than naming `leftover`
     * directly. Both forms read the same never-written stack slot, but the
     * direct form is one clang can PROVE is uninitialised, so it fires
     * -Wuninitialized and this file would no longer compile clean under the
     * -Wall -Wextra promised in the header. That difference is itself the
     * lesson: the compiler only warns about the uninitialised reads it can see
     * locally. Route the value through a pointer, a helper function, or a
     * partially-filled struct -- as real parsers do -- and the diagnostic goes
     * silent while the bug stays exactly as dangerous. Never read "no compiler
     * warning" as "no uninitialised memory". */
    const volatile int *slot = &leftover;

    printf("  sibling_b()            reads  0x%08x at %p  <-- same address\n",
           *slot, (void *)&leftover);
    printf("      -> If that value is 0x41414141, you are looking at sibling_a's\n");
    printf("         data. This is 'stack garbage'. A struct partially filled by\n");
    printf("         a parser and then copied out to an attacker leaks whatever\n");
    printf("         the previous call left in the uncopied bytes. Real kernel\n");
    printf("         and native-library information disclosures work exactly so.\n");
}

/* =========================================================================
 * SECTION 4 support — recursion, one frame per call.
 *
 * Each recursive call allocates a frame of the same size, so the addresses
 * step downward by a constant amount. That constant is the frame size, and
 * multiplying it by the recursion depth gives you the algorithm's stack cost.
 * ====================================================================== */

static void recurse(int depth, int limit, uintptr_t first_address)
{
    /* A local array makes each frame comfortably large and easy to measure. */
    volatile char frame_filler[64];
    frame_filler[0] = (char)depth;

    uintptr_t here = (uintptr_t)&frame_filler[0];

    if ((uintptr_t)here < g_deepest_address)
        g_deepest_address = here;
    if (depth > g_max_depth_reached)
        g_max_depth_reached = depth;

    if (depth <= 5 || depth == limit) {
        printf("  depth %4d : frame at %p", depth, (void *)here);
        if (depth > 1)
            printf("   (%ld bytes below the first frame)",
                   (long)(first_address - here));
        printf("\n");
    } else if (depth == 6) {
        printf("  ... (frames 6 to %d omitted) ...\n", limit - 1);
    }

    if (depth < limit)
        recurse(depth + 1, limit, first_address);
}

/* =========================================================================
 * SECTION 5 support — walking the saved frame-pointer chain.
 *
 * With -fno-omit-frame-pointer, every frame stores the caller's frame pointer
 * at a known location, forming a linked list that terminates at main. A
 * debugger's `bt`, a crash handler's backtrace, and Android's tombstone
 * generator all walk exactly this list (or the equivalent DWARF unwind tables
 * when the frame pointer has been omitted).
 *
 * __builtin_frame_address(N) is a GCC/Clang extension that returns the frame
 * address N levels up. It is the portable-enough way to demonstrate the chain
 * without writing architecture-specific assembly.
 *
 * A NONZERO argument is not free, and clang says so: -Wframe-address (on by
 * default in -Wall) warns that __builtin_frame_address(1) "is unsafe". The
 * reason is worth understanding rather than suppressing blindly. Asking for
 * frame N > 0 requires the compiler to emit a walk of the saved frame-pointer
 * chain, and that chain only exists if the CALLER also kept a frame pointer.
 * If the caller was compiled with -fomit-frame-pointer, was inlined, or is the
 * outermost frame in the thread, the walk reads whatever happens to sit at that
 * offset -- a wrong pointer, or a fault. That is exactly why this file insists
 * on -fno-omit-frame-pointer, and exactly why a production backtracer uses
 * DWARF unwind tables (.eh_frame) instead of trusting the frame pointer.
 *
 * The warning is therefore correct and is accepted DELIBERATELY, scoped to the
 * two lines that need it, with the reason recorded here. A blanket
 * -Wno-frame-address in a build file would hide the next occurrence too.
 * ====================================================================== */

static void show_frame_chain_inner(void)
{
    printf("  frame of this function      : %p\n", __builtin_frame_address(0));
#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wframe-address"
#elif defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wframe-address"
#endif
    /* Valid here ONLY because this file mandates -fno-omit-frame-pointer and
     * show_frame_chain_outer() is a real, non-inlined caller. See the note
     * above before copying this line into anything you care about. */
    printf("  frame of its caller         : %p\n", __builtin_frame_address(1));
#if defined(__clang__)
#  pragma clang diagnostic pop
#elif defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif
    printf("  return address of this frame: %p\n", __builtin_return_address(0));
    printf("      -> Each frame address is HIGHER than the one below it, and each\n");
    printf("         return address points back into the caller's code. Those two\n");
    printf("         facts together are the entire backtrace algorithm.\n");
    printf("      -> In gdb, `bt` prints this list. On Android, a native crash\n");
    printf("         writes it into /data/tombstones/tombstone_NN.\n");
}

static void show_frame_chain_outer(void)
{
    show_frame_chain_inner();
}

/* =========================================================================
 * SECTION 6 support — array indexing direction versus stack growth direction.
 *
 * This function does NOT overflow anything. It only prints the addresses that
 * make the danger obvious, so that Lab 03 has something concrete to build on.
 * ====================================================================== */

static void show_overflow_geometry(void)
{
    char buf[32];
    volatile unsigned long canary_like = 0xCAFEBABEDEADBEEFul;

    memset(buf, 'X', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    printf("  &buf[0]                = %p\n", (void *)&buf[0]);
    printf("  &buf[31]               = %p   (indexing moves UP)\n", (void *)&buf[31]);
    printf("  &canary_like           = %p\n", (void *)&canary_like);
    printf("  frame pointer here     = %p\n", __builtin_frame_address(0));
    printf("  return address here    = %p\n", __builtin_return_address(0));
    printf("  distance buf[0] -> canary_like = %ld bytes\n",
           (long)((const char *)&canary_like - &buf[0]));
    printf("      -> If that distance is POSITIVE, writing more than that many\n");
    printf("         bytes into buf reaches canary_like. Beyond it lie the saved\n");
    printf("         frame pointer and the saved return address. Nothing in the\n");
    printf("         machine prevents the write; strcpy simply keeps going until\n");
    printf("         it meets a NUL byte in the SOURCE.\n");
    printf("      -> If the distance is NEGATIVE, your compiler placed the scalar\n");
    printf("         BELOW the array. Compilers may reorder locals, and some\n");
    printf("         hardening modes deliberately sort arrays closest to the\n");
    printf("         canary. Always measure; never assume.\n");
}

int main(void)
{
    printf("=====================================================================\n");
    printf(" stack_frames.c -- watching the stack grow, one frame at a time\n");
    printf("=====================================================================\n\n");

    /* --------------------------------------------------------------- */
    printf("SECTION 1 — where main's frame is\n");
    {
        int main_local = 0;
        printf("  &main_local            = %p\n", (void *)&main_local);
        printf("  main's frame address   = %p\n", __builtin_frame_address(0));
        printf("  --> Compare this with the [stack] line in /proc/self/maps.\n");
        printf("      In another terminal, while a long-running build of this\n");
        printf("      program is paused, run:  grep stack /proc/<pid>/maps\n\n");
    }

    /* --------------------------------------------------------------- */
    printf("SECTION 2 — three nested calls, three live frames\n");
    {
        volatile int main_marker = 0;
        report("main()", (const void *)&main_marker, NULL);
        level_one((const void *)&main_marker);
        printf("  --> Every step is NEGATIVE. The stack grows toward LOWER\n");
        printf("      addresses. The magnitude of each step is the caller's frame\n");
        printf("      size, which is the immediate in `sub rsp, N` on x86-64 or in\n");
        printf("      `stp x29, x30, [sp, #-N]!` on AArch64.\n\n");
    }

    /* --------------------------------------------------------------- */
    printf("SECTION 3 — stack memory is recycled, not erased\n");
    sibling_a();
    sibling_b();
    printf("\n");

    /* --------------------------------------------------------------- */
    printf("SECTION 4 — recursion consumes stack linearly\n");
    {
        volatile char here;
        uintptr_t start = (uintptr_t)&here;
        int limit = 40;

        recurse(1, limit, start);
        printf("  deepest frame reached  : %p\n", (void *)g_deepest_address);
        printf("  total stack consumed   : %lu bytes over %d frames\n",
               (unsigned long)(start - g_deepest_address), g_max_depth_reached);
        printf("  average per frame      : %lu bytes\n",
               (unsigned long)((start - g_deepest_address) /
                               (g_max_depth_reached ? g_max_depth_reached : 1)));
        printf("      -> Check your shell's limit with:  ulimit -s   (KB)\n");
        printf("      -> Divide the limit by the per-frame cost to get the maximum\n");
        printf("         safe recursion depth. Exceeding it touches the guard page\n");
        printf("         below [stack] and the kernel delivers SIGSEGV. On Android,\n");
        printf("         non-main threads default to about 1 MB, so the safe depth\n");
        printf("         is roughly eight times smaller than on a desktop thread.\n");
        printf("      -> To see the crash for yourself, rebuild with a much larger\n");
        printf("         limit (for example 10000000) and run under gdb. The fault\n");
        printf("         address will sit just below the low end of [stack] that\n");
        printf("         you found in Lab 02.\n\n");
    }

    /* --------------------------------------------------------------- */
    printf("SECTION 5 — the frame-pointer chain is the backtrace\n");
    show_frame_chain_outer();
    printf("\n");

    /* --------------------------------------------------------------- */
    printf("SECTION 6 — why overflows reach the return address\n");
    show_overflow_geometry();

    printf("\n=====================================================================\n");
    printf(" Next: open this binary in gdb and reproduce SECTION 6 by hand:\n");
    printf("   gdb -q ./stack_frames\n");
    printf("   (gdb) break show_overflow_geometry\n");
    printf("   (gdb) run\n");
    printf("   (gdb) x/16gx $sp\n");
    printf("   (gdb) x/2gx $rbp        # saved rbp, then saved return address\n");
    printf(" Then work through labs/lab-03-stack-frames-and-overflow.md.\n");
    printf("=====================================================================\n");
    return 0;
}
