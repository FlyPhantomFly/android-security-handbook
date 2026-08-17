/*
 * heap-bugs.c -- six native memory-safety behaviours, one per mode, small
 *                enough that you can hold the whole program in your head.
 *
 * PURPOSE
 *     Chapter 19 claims that a heap-buffer-overflow, a use-after-free and a
 *     double-free are three different defects with three different detection
 *     signatures. This program is how you check that claim yourself instead of
 *     believing it. Build it once per sanitiser configuration with
 *     build-memory-fixtures.sh, run the same mode against each build, and
 *     compare what the process prints and how it dies.
 *
 *     Mode "layout" contains no bug at all. It exists because the single most
 *     useful thing a beginner can do with an allocator is watch where it puts
 *     things, and the second most useful is watch what it does with a block
 *     you just gave back.
 *
 * USAGE
 *     # on the device, after `adb push`
 *     ./heap-bugs layout          # no bug: allocator behaviour, addresses, deltas
 *     ./heap-bugs overflow [n]    # write n bytes past a 32-byte allocation (default 1)
 *     ./heap-bugs uaf             # read and write memory after free()
 *     ./heap-bugs dfree           # free() the same pointer twice
 *     ./heap-bugs invfree         # free() a pointer into the middle of a block
 *     ./heap-bugs stack           # write past the end of a stack array
 *
 *     Every mode prints what it is about to do BEFORE doing it, so that when
 *     the process dies you know which line killed it. Output is unbuffered for
 *     the same reason -- a crash must not eat the last printf.
 *
 * REQUIREMENTS
 *     A C compiler targeting Android. The NDK's aarch64-linux-android<API>-clang
 *     is the only one that produces a binary an Android device will run; see
 *     build-memory-fixtures.sh. It also builds and runs unchanged on desktop
 *     Linux, which is a legitimate way to learn the concepts when you have no
 *     device, as long as you remember that the allocator there is glibc's, not
 *     Scudo's, and the layout numbers will differ.
 *
 * WHAT THIS PROGRAM WILL *NOT* TELL YOU
 *     - Whether any of these bugs is EXPLOITABLE. It is a demonstration of
 *       detection, not of exploitation. Turning an overflow into control of the
 *       process needs a target worth corrupting, a way to reach it, and a way
 *       to survive the corruption; none of that is here and none of it is in
 *       the chapter either. See README section 5.6 for why "reachable" is the
 *       word that belongs in your report and "exploitable" usually is not.
 *     - Anything about the Java heap. Every allocation here is native. ART's
 *       managed heap is 13-ART's subject.
 *     - Whether YOUR app has these bugs. It has no relationship to any real
 *       application; it is a fixture for the labs.
 *     - What the addresses "mean" on your device. They are randomised. Two runs
 *       give two answers, and that is the point of the ASLR discussion.
 *
 * SAFETY
 *     Modes other than "layout" deliberately corrupt memory. Run this on a test
 *     device or an emulator you are willing to reboot. It cannot damage
 *     anything outside its own process, but a process that dies inside malloc
 *     can leave confusing logcat entries behind.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * A volatile sink. Every value the program computes is stored here so that the
 * optimiser cannot decide the buggy access is dead code and delete it. This is
 * not paranoia: at -O2, clang will happily remove a read whose result is never
 * used, and you will spend an hour wondering why the sanitiser is silent.
 */
static volatile unsigned char g_sink;
static volatile void *g_ptr_sink;

/* ------------------------------------------------------------------------ */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Strip Android's heap pointer tag.
 *
 * On a 64-bit Android 11 or newer process whose app targets API 30 or higher,
 * every malloc() return value carries a tag in its TOP BYTE -- you will see
 * addresses like 0xb40000765b7562b0 where the 0xb4 is not part of the address.
 * The CPU ignores that byte when it dereferences the pointer (Arm calls the
 * feature Top-Byte-Ignore), so the program works; but /proc/<pid>/maps prints
 * UNTAGGED addresses, so a naive numeric comparison against maps matches
 * nothing at all.
 *
 * This function is four lines long and it is the single most common reason a
 * beginner's "find the region containing this pointer" code silently reports
 * that no region contains it. See README section 3.7.
 */
static unsigned long untag(const void *p)
{
    uintptr_t v = (uintptr_t)p;

#if UINTPTR_MAX > 0xffffffffU
    /*
     * 64-bit: clear the top byte.
     *
     * Note the ULL suffix. Writing 0x00ffffffffffffffUL here compiles on
     * arm64 and SILENTLY TRUNCATES on armeabi-v7a, where `unsigned long` is
     * 32 bits. That is not a hypothetical: building this file for 32-bit with
     * -Wall -Wextra is what caught it. Android's 64-bit and 32-bit ABIs differ
     * in the width of `long`, and memory code is exactly where that bites.
     */
    v &= (uintptr_t)0x00ffffffffffffffULL;
#else
    /*
     * 32-bit: there is no spare top byte, so there is no pointer tagging, no
     * HWASan and no MTE. Untagging is the identity function. This is a real
     * security difference between the two ABIs, not a detail -- see
     * build-memory-fixtures.sh fixture 7.
     */
#endif
    return (unsigned long)v;
}

/* The tag byte itself, or 0 on a 32-bit build where there is no such thing. */
static unsigned int tag_of(const void *p)
{
    return (unsigned int)(((unsigned long long)(uintptr_t)p >> 56) & 0xffU);
}

/*
 * Print the /proc/self/maps line whose address range contains `addr`.
 *
 * This is the whole of the chapter's "find the runtime base" technique in
 * twenty lines: parse "START-END perms offset dev inode path", compare, print.
 * Doing it by hand once is worth more than reading about it three times.
 */
static void describe_address(const char *label, const void *addr)
{
    unsigned long target = untag(addr);
    char line[512];
    FILE *f = fopen("/proc/self/maps", "r");

    if (f == NULL) {
        printf("  %-14s %p   (cannot open /proc/self/maps: %s)\n",
               label, addr, strerror(errno));
        return;
    }

    if (target != (unsigned long)(uintptr_t)addr) {
        printf("  %-14s %p  tagged; searching maps for %012lx\n",
               label, addr, target);
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long lo = 0, hi = 0;
        char perms[8];
        char rest[400];

        perms[0] = '\0';
        rest[0] = '\0';

        /*
         * "%lx-%lx %7s %*s %*s %*s %399[^\n]" -- the four fields we skip with
         * %*s are file offset, device, inode. The last conversion takes the
         * path, which may be absent (anonymous memory) or contain spaces
         * (a deleted file, or a path with a space in it), so it is read to
         * end-of-line rather than as a word.
         */
        if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %399[^\n]",
                   &lo, &hi, perms, rest) >= 3) {
            if (target >= lo && target < hi) {
                printf("  %-14s %p  in %012lx-%012lx %s %s\n",
                       label, addr, lo, hi, perms,
                       rest[0] ? rest : "(anonymous)");
                fclose(f);
                return;
            }
        }
    }

    fclose(f);
    printf("  %-14s %p  (no mapping contains this address)\n", label, addr);
}

/* Print the first `n` bytes of `p` as hex, with a caller-supplied label. */
static void hexdump(const char *label, const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    size_t i;

    printf("  %-14s", label);
    for (i = 0; i < n; i++) {
        printf(" %02x", b[i]);
    }
    printf("\n");
}

/*
 * Difference between two pointers, as a signed byte count, computed on the
 * UNTAGGED values. Subtracting two tagged pointers gives a number in the
 * quintillions and tells you nothing; this is the second place a tag-unaware
 * tool silently produces garbage instead of an error.
 */
static long delta(const void *a, const void *b)
{
    return (long)((long)untag(b) - (long)untag(a));
}

/* ------------------------------------------------------------------------ */
/* Mode: layout -- no bug. Watch the allocator work.                         */
/* ------------------------------------------------------------------------ */

static int mode_layout(void)
{
    void *small[8];
    void *big;
    void *huge;
    void *reused;
    int i;
    int stack_local = 0;

    printf("== layout: where does this allocator put things ==\n\n");

    printf("Address-space landmarks for this process (pid %d):\n", (int)getpid());
    describe_address("code", (const void *)(uintptr_t)&mode_layout);
    describe_address("stack", (const void *)&stack_local);
    describe_address("libc", (const void *)(uintptr_t)&printf);
    printf("\n");

    /*
     * Eight identical small allocations. On a bump-style or free-list-style
     * allocator these land at a fixed stride; on Scudo the stride is the size
     * class rounded up, but the ORDER is randomised, so the deltas are not
     * monotonic. That difference is visible right here, with no tooling.
     */
    printf("Eight 32-byte allocations, in order:\n");
    for (i = 0; i < 8; i++) {
        small[i] = malloc(32);
        if (small[i] == NULL) {
            printf("  malloc failed\n");
            return 1;
        }
        memset(small[i], 0x41 + i, 32);
        if (i == 0) {
            printf("  [%d] %p\n", i, small[i]);
        } else {
            printf("  [%d] %p   delta from previous: %+ld bytes\n",
                   i, small[i], delta(small[i - 1], small[i]));
        }
    }
    printf("\n");
    describe_address("small[0]", small[0]);
    printf("\n");

    /*
     * Free the middle one and immediately ask for the same size again.
     *
     * The textbook answer is "a quarantine stops you getting it back". Measure
     * it rather than believing it: on a stock Android 13 arm64 device this
     * prints SAME ADDRESS, because Scudo's quarantine is configurable and
     * Android ships it OFF by default -- QuarantineSizeKb is not free, and
     * Android chose the memory. On a build with SCUDO_OPTIONS containing a
     * non-zero QuarantineSizeKb, the same line prints a different address.
     *
     * Immediate LIFO reuse is exactly the property heap grooming depends on,
     * and it is present on the device in your hand.
     */
    printf("Free small[3] (%p), then malloc(32) again:\n", small[3]);
    free(small[3]);
    reused = malloc(32);
    /*
     * Compare the UNTAGGED addresses. Under HWASan the block really is handed
     * straight back, but with a fresh tag in the top byte, so a naive `==`
     * between the two pointer values says "different" when the underlying
     * memory is identical. Getting this wrong is how you conclude that a
     * sanitiser build "does not reuse memory" when in fact it reuses it
     * eagerly and relies on the tag to catch you.
     */
    printf("  new allocation: %p  %s\n", reused,
           untag(reused) == untag(small[3])
               ? "SAME ADDRESS (immediate reuse)"
               : "different address (delayed reuse / quarantine)");
    if (untag(reused) == untag(small[3]) && reused != small[3]) {
        printf("                  same memory, DIFFERENT TAG "
               "(%02x -> %02x) -- this is HWASan or MTE at work\n",
               tag_of(small[3]), tag_of(reused));
    }
    printf("\n");

    /*
     * Small versus large. Every allocator has a threshold above which it stops
     * carving from its own pool and asks the kernel directly with mmap. Crossing
     * that threshold changes the address by a lot, and changes what a
     * neighbouring overflow can reach.
     */
    big = malloc(64 * 1024);
    huge = malloc(4 * 1024 * 1024);
    printf("Size classes:\n");
    printf("  malloc(32)        %p\n", small[0]);
    printf("  malloc(65536)     %p   delta from the 32-byte block: %+ld\n",
           big, delta(small[0], big));
    printf("  malloc(4194304)   %p   delta from the 32-byte block: %+ld\n",
           huge, delta(small[0], huge));
    printf("\n");
    describe_address("64 KiB", big);
    describe_address("4 MiB", huge);
    printf("\n");

    /*
     * What is IN a fresh allocation, and what is in it after free?
     *
     * Again: measure, do not assume. Scudo has a ZeroContents option, and on a
     * stock Android 13 arm64 device the sixteen bytes below come back
     * IDENTICAL after free() -- the old contents are still sitting in the page.
     * That is the mechanism behind every "we found the session token in a heap
     * dump" finding, and you are looking at it directly, in four lines of C.
     *
     * The remediation is not "hope the allocator zeroes it". It is: overwrite
     * the secret yourself before you free it, with something the compiler is
     * not allowed to elide. See heap-bugs-fixed.c.
     */
    printf("Contents, before and after:\n");
    hexdump("small[0] now", small[0], 16);
    free(small[0]);
    /*
     * Reading freed memory is itself a use-after-free. We do it here, on
     * purpose, in the one mode that is otherwise clean, because seeing the
     * residue is the whole lesson -- and because it lets you check that your
     * sanitiser build catches even this benign-looking read. Under HWASan or
     * MTE sync this line is where the process dies, which is the correct
     * outcome and not a bug in the demo.
     */
    hexdump("after free", small[0], 16);
    printf("\n");

    printf("If you got here, no checker objected to the read above.\n");
    printf("Run the HWASan build of this same binary and compare.\n");

    g_ptr_sink = reused;
    g_ptr_sink = big;
    g_ptr_sink = huge;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Mode: overflow -- heap-buffer-overflow                                     */
/* ------------------------------------------------------------------------ */

static int mode_overflow(int past_end)
{
    unsigned char *buf = (unsigned char *)malloc(32);
    int i;

    if (buf == NULL) {
        return 1;
    }

    printf("== overflow: write %d byte(s) past a 32-byte allocation ==\n\n", past_end);
    printf("  allocation: %p .. %p (32 bytes)\n", buf, buf + 32);
    printf("  about to write to %p .. %p\n", buf, buf + 32 + past_end - 1);
    printf("  the last %d byte(s) are out of bounds\n\n", past_end);
    fflush(stdout);

    /*
     * The classic off-by-one, written as an obvious loop so there is no doubt
     * about which iteration is the bad one. In real code this arrives as a
     * `<=` where a `<` belonged, or as memcpy with a length the caller
     * controls -- see README section 3.9.
     */
    for (i = 0; i < 32 + past_end; i++) {
        buf[i] = (unsigned char)(0x61 + (i & 0x0f));
        if (i == 32) {
            printf("  wrote index 32 -- first byte past the end\n");
            fflush(stdout);
        }
    }

    printf("\n  survived the write.\n");
    printf("  An unsanitised build usually survives a small overflow: the bytes\n");
    printf("  after a 32-byte block are allocator padding or another block's\n");
    printf("  header, and nothing has looked at them YET. The crash, if it comes,\n");
    printf("  comes later and somewhere else. That delay is the entire reason\n");
    printf("  sanitisers exist.\n\n");
    fflush(stdout);

    printf("  now calling free() -- an allocator that validates its header may\n");
    printf("  abort here rather than at the corrupting write:\n");
    fflush(stdout);
    free(buf);
    printf("  free() returned without complaint.\n");
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Mode: uaf -- use-after-free                                                */
/* ------------------------------------------------------------------------ */

static int mode_uaf(void)
{
    unsigned char *buf = (unsigned char *)malloc(64);
    unsigned char *other;

    if (buf == NULL) {
        return 1;
    }

    printf("== uaf: read and write through a pointer after free() ==\n\n");

    memset(buf, 0x53, 64);
    memcpy(buf, "SESSION=deadbeefcafebabe", 24);
    printf("  allocated %p and filled it with a fake secret\n", buf);
    hexdump("contents", buf, 24);
    fflush(stdout);

    free(buf);
    printf("\n  free(%p) done. `buf` is now a DANGLING POINTER: the value is\n", (void *)buf);
    printf("  unchanged, the memory it names is no longer ours.\n\n");
    fflush(stdout);

    printf("  reading through the dangling pointer:\n");
    fflush(stdout);
    hexdump("after free", buf, 24);

    /*
     * The step that makes a use-after-free interesting rather than merely
     * wrong: something else takes the memory, and now two pieces of code
     * disagree about what lives there. This is the shape of every real UAF --
     * an object is freed, a different object is allocated into the hole, and
     * the stale pointer writes into the new object's fields.
     */
    other = (unsigned char *)malloc(64);
    printf("\n  malloc(64) again -> %p %s\n", other,
           untag(other) == untag(buf)
               ? "== the freed block. The hole has been reclaimed."
               : "!= the freed block (quarantine, or a different bin)");
    if (other != NULL) {
        memset(other, 0x77, 64);
    }

    printf("\n  writing through the dangling pointer:\n");
    fflush(stdout);
    buf[0] = 0x41;
    printf("  wrote 0x41 to %p\n", (void *)buf);

    if (other != NULL) {
        hexdump("other[0..15]", other, 16);
        printf("\n  If the two pointers are equal, look at byte 0 of `other`.\n");
        printf("  It is 0x41, not 0x77. A write through a pointer its owner\n");
        printf("  believes it still owns has just changed a different object's\n");
        printf("  first field. Replace `other` with something holding a function\n");
        printf("  pointer and you have the classic primitive.\n");
        free(other);
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Mode: dfree -- double free                                                 */
/* ------------------------------------------------------------------------ */

static int mode_dfree(void)
{
    void *buf = malloc(48);

    if (buf == NULL) {
        return 1;
    }

    printf("== dfree: free() the same pointer twice ==\n\n");
    printf("  allocated %p\n", buf);
    fflush(stdout);

    free(buf);
    printf("  first free() ok\n");
    fflush(stdout);

    printf("  second free() -- this is where a checking allocator aborts:\n");
    fflush(stdout);
    free(buf);

    printf("\n  second free() returned. This build's allocator did not notice.\n");
    printf("  That does not mean nothing happened: the block is now on the\n");
    printf("  free list twice, so two future malloc() calls can be handed the\n");
    printf("  same address. See README section 3.10.\n");
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Mode: invfree -- free of an interior pointer                               */
/* ------------------------------------------------------------------------ */

static int mode_invfree(void)
{
    unsigned char *buf = (unsigned char *)malloc(64);

    if (buf == NULL) {
        return 1;
    }

    printf("== invfree: free() a pointer into the middle of a block ==\n\n");
    printf("  allocated %p, freeing %p (16 bytes in)\n", buf, buf + 16);
    printf("  The allocator looks for its bookkeeping just before the pointer\n");
    printf("  it is given. Sixteen bytes in, that bookkeeping is your data.\n\n");
    fflush(stdout);

    free(buf + 16);

    printf("  returned without aborting -- which is worse news than aborting.\n");
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Mode: stack -- stack-buffer-overflow                                       */
/* ------------------------------------------------------------------------ */

static int mode_stack(void)
{
    unsigned char buf[16];
    /*
     * unsigned long long, not unsigned long. On armeabi-v7a `unsigned long` is
     * 32 bits and this constant would be silently truncated to 0x55667788 --
     * which -Wconstant-conversion catches, and which nothing catches if you do
     * not build for both ABIs.
     */
    volatile unsigned long long guard_me = 0x1122334455667788ULL;
    int i;

    printf("== stack: write past the end of a 16-byte stack array ==\n\n");
    printf("  buf at %p, a neighbouring local at %p (delta %+ld)\n",
           (void *)buf, (void *)&guard_me, delta(buf, (const void *)&guard_me));
    describe_address("buf", (const void *)buf);
    printf("\n  writing 40 bytes into a 16-byte array:\n");
    fflush(stdout);

    for (i = 0; i < 40; i++) {
        buf[i] = 0x42;
    }

    printf("  neighbouring local is now 0x%016llx (was 0x1122334455667788)\n",
           (unsigned long long)guard_me);
    printf("\n  Note what this mode does NOT demonstrate: it does not overwrite\n");
    printf("  the return address in a way you should try to control. It shows\n");
    printf("  that an out-of-bounds stack write reaches a neighbour, which is\n");
    printf("  the reachability question a tester actually has to answer.\n");
    printf("\n  Returning now. A -fstack-protector build checks its canary here.\n");
    fflush(stdout);

    g_sink = buf[0];
    return 0;
}

/* ------------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s <mode> [arg]\n"
            "\n"
            "  layout          no bug -- allocator behaviour and address-space landmarks\n"
            "  overflow [n]    write n bytes past a 32-byte allocation (default 1)\n"
            "  uaf             read and write after free()\n"
            "  dfree           free() the same pointer twice\n"
            "  invfree         free() a pointer 16 bytes into a block\n"
            "  stack           write 40 bytes into a 16-byte stack array\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *mode;

    /*
     * Unbuffered stdout. When the process is about to be killed by a sanitiser
     * or by SIGSEGV, a buffered printf is a printf you never see, and you lose
     * the one line that says which access was the fatal one.
     */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    mode = argv[1];

    if (strcmp(mode, "layout") == 0) {
        return mode_layout();
    }
    if (strcmp(mode, "overflow") == 0) {
        int n = (argc > 2) ? atoi(argv[2]) : 1;
        if (n < 1) {
            n = 1;
        }
        if (n > 4096) {
            n = 4096;
        }
        return mode_overflow(n);
    }
    if (strcmp(mode, "uaf") == 0) {
        return mode_uaf();
    }
    if (strcmp(mode, "dfree") == 0) {
        return mode_dfree();
    }
    if (strcmp(mode, "invfree") == 0) {
        return mode_invfree();
    }
    if (strcmp(mode, "stack") == 0) {
        return mode_stack();
    }

    usage(argv[0]);
    return 2;
}
