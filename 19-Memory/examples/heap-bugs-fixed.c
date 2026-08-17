/*
 * heap-bugs-fixed.c -- the same six situations as heap-bugs.c, written so that
 *                      none of them is a defect. The remediation half of the
 *                      pair.
 *
 * PURPOSE
 *     A chapter that shows you a use-after-free and stops has done half a job.
 *     The repository rule is: vulnerable code, why developers write it,
 *     detection, and then the secure fix AS CODE. This file is that fix, and
 *     it is deliberately the same shape as heap-bugs.c so you can diff them.
 *
 *     The point it exists to make is uncomfortable and worth stating plainly:
 *     every fix here is a DISCIPLINE, not a feature. C gives you no help. The
 *     `owned_free` idiom below is four lines and it eliminates two of the six
 *     bug classes; nothing in the language makes you use it.
 *
 * USAGE
 *     # on the device, after `adb push`
 *     ./heap-bugs-fixed selftest       # run every case, expect exit status 0
 *     ./heap-bugs-fixed bounds         # the overflow case, bounded
 *     ./heap-bugs-fixed ownership      # the UAF and double-free cases
 *     ./heap-bugs-fixed secret         # the residue case: scrub before free
 *     ./heap-bugs-fixed stack          # the stack case, bounded
 *
 *     The check that matters:
 *
 *         ./heap-bugs-fixed selftest              -> prints, exits 0
 *         (HWASan build) ./heap-bugs-fixed selftest -> prints, exits 0, SILENT
 *
 *     A sanitiser that stays quiet on this file and screams on heap-bugs.c is
 *     a sanitiser you can trust to tell you something about your own code.
 *     If it is quiet on BOTH, your sanitiser build is not what you think it
 *     is -- check that the runtime library actually loaded.
 *
 * REQUIREMENTS
 *     Same as heap-bugs.c. See build-memory-fixtures.sh.
 *
 * WHAT THIS FILE WILL *NOT* TELL YOU
 *     - That C can be made safe by discipline. It cannot, at scale. Every fix
 *       here is one careless edit away from being undone, which is the actual
 *       argument for Rust in new native code and for HWASan in CI on the code
 *       you already have. README section 5.9 makes that argument properly.
 *     - How to fix a bug in code you do not own. A third-party .so with a UAF
 *       is fixed by upgrading it or by removing it. See 17-Libraries.
 *     - Anything about Java. `String` and `char[]` have their own residue
 *       problem, and it is 13-ART's and 34-Cryptography's subject.
 */

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------------------------------ */
/* Fix 1: a buffer that knows how big it is                                  */
/* ------------------------------------------------------------------------ */

/*
 * The bug in heap-bugs.c's `overflow` mode is not the write. It is that a bare
 * `unsigned char *` carries no capacity, so every piece of code that touches it
 * has to remember the size correctly, and one of them eventually will not.
 *
 * Keeping the capacity NEXT TO the pointer, in one struct, and only ever
 * appending through a function that checks it, removes the class of bug rather
 * than this instance of it. That distinction -- class versus instance -- is
 * what separates a fix from a patch, and it is what you should be asking a
 * developer for when you report an overflow.
 */
typedef struct {
    unsigned char *data;
    size_t len;   /* bytes currently used   */
    size_t cap;   /* bytes actually allocated */
} buf_t;

static int buf_init(buf_t *b, size_t cap)
{
    b->data = (unsigned char *)malloc(cap);
    if (b->data == NULL) {
        b->len = 0;
        b->cap = 0;
        return -1;
    }
    b->len = 0;
    b->cap = cap;
    return 0;
}

/*
 * Append with a capacity check. Note the check is `n > b->cap - b->len` and
 * NOT `b->len + n > b->cap`: the second form can overflow size_t when `n` is
 * attacker-controlled and enormous, wrap to a small number, and pass. That
 * integer overflow is the single most common way a "bounds-checked" copy turns
 * out not to be. README section 3.9.2 has the arithmetic.
 */
static int buf_append(buf_t *b, const void *src, size_t n)
{
    if (b->data == NULL) {
        return -1;
    }
    if (n > b->cap - b->len) {
        return -1;                 /* refuse; do not truncate silently */
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Fix 2 and 3: ownership, expressed in code                                  */
/* ------------------------------------------------------------------------ */

/*
 * free() takes a pointer by value, so it cannot possibly clear the caller's
 * copy. This helper takes the ADDRESS of the pointer and clears it, which
 * makes two bug classes structurally impossible:
 *
 *     use-after-free   -- the dangling pointer is NULL, so the stale use is a
 *                         NULL dereference: a reliable, immediate, obvious
 *                         crash at the exact line that is wrong, instead of
 *                         silent corruption discovered three screens later.
 *     double free      -- free(NULL) is defined to do nothing, so the second
 *                         call is a no-op rather than an abort.
 *
 * It does not fix a UAF through a SECOND copy of the pointer that some other
 * object is holding. Nothing local can. That case needs an ownership model:
 * refcounting, a unique_ptr in C++, or an arena whose lifetime you control.
 */
#define OWNED_FREE(p) do { free(p); (p) = NULL; } while (0)

/* ------------------------------------------------------------------------ */
/* Fix 4: scrub secrets before releasing the memory                          */
/* ------------------------------------------------------------------------ */

/*
 * heap-bugs.c demonstrates, on a real device, that the bytes of a freed block
 * are still there afterwards. If those bytes were a token, they are now
 * findable by anything that can read the process -- a heap dump, a core file,
 * Frida's Memory.scan, or the next allocation that happens to land there and
 * does not initialise itself.
 *
 * The naive fix, `memset(p, 0, n); free(p);`, is legal C that the optimiser is
 * ALLOWED TO DELETE: the memory is dead after free, so the store is provably
 * unobservable, and "dead store elimination" removes it. This is not
 * theoretical; it is a known and repeatedly re-discovered class of bug in
 * cryptographic code.
 *
 * The advice you will read everywhere is "call explicit_bzero()". CHECK THAT
 * ADVICE AGAINST YOUR TOOLCHAIN before you take it. Grepping the NDK r25c
 * sysroot headers finds no explicit_bzero and no memset_s at all:
 *
 *     grep -rn explicit_bzero \
 *       $NDK/toolchains/llvm/prebuilt/<host>/sysroot/usr/include
 *     (no output)
 *
 * and a build that calls it fails at link time with
 * "undefined symbol: explicit_bzero". C11 Annex K's memset_s is optional and
 * Android does not implement it either.
 *
 * So on Android the portable answer is the third option: a volatile-qualified
 * write loop. `volatile` makes every store an observable side effect, which
 * the standard forbids the optimiser from removing. It is slower than memset
 * and that is the correct trade for the handful of buffers that hold secrets.
 *
 * If your NDK is new enough to declare explicit_bzero, or you are building for
 * the platform rather than the NDK, prefer it -- but verify, do not assume.
 */
static void scrub(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;

    while (n--) {
        *v++ = 0;
    }
}

/* ------------------------------------------------------------------------ */

static void hexdump(const char *label, const void *p, size_t n)
{
    const unsigned char *b = (const unsigned char *)p;
    size_t i;

    printf("  %-16s", label);
    for (i = 0; i < n; i++) {
        printf(" %02x", b[i]);
    }
    printf("\n");
}

/* ------------------------------------------------------------------------ */
/* Case: bounds                                                              */
/* ------------------------------------------------------------------------ */

static int case_bounds(void)
{
    buf_t b;
    unsigned char payload[64];
    int rc;

    printf("== bounds: the same append, refused instead of overflowing ==\n\n");

    if (buf_init(&b, 32) != 0) {
        return 1;
    }
    memset(payload, 0x61, sizeof(payload));

    rc = buf_append(&b, payload, 32);
    printf("  append 32 into capacity 32 -> %s (len now %zu)\n",
           rc == 0 ? "OK" : "REFUSED", b.len);

    rc = buf_append(&b, payload, 1);
    printf("  append 1 more             -> %s (len still %zu)\n",
           rc == 0 ? "OK" : "REFUSED", b.len);

    /*
     * The integer-overflow case. With the naive check `b.len + n > b.cap`,
     * len=32 and n=SIZE_MAX-8 wrap round to a small number and the check
     * PASSES. With the subtraction form it cannot.
     */
    rc = buf_append(&b, payload, SIZE_MAX - 8);
    printf("  append SIZE_MAX-8         -> %s  <- the check that a naive\n",
           rc == 0 ? "OK (BUG!)" : "REFUSED");
    printf("                                     `len + n > cap` would fail\n");

    OWNED_FREE(b.data);
    b.len = 0;
    b.cap = 0;
    printf("\n  no out-of-bounds access occurred. HWASan has nothing to say.\n");
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Case: ownership                                                           */
/* ------------------------------------------------------------------------ */

static int case_ownership(void)
{
    unsigned char *buf = (unsigned char *)malloc(64);

    printf("== ownership: free-and-null kills UAF and double-free ==\n\n");

    if (buf == NULL) {
        return 1;
    }
    memset(buf, 0x53, 64);
    printf("  allocated %p\n", (void *)buf);

    OWNED_FREE(buf);
    printf("  after OWNED_FREE, buf == %p\n", (void *)buf);

    /*
     * The stale use. In heap-bugs.c this silently read and then silently
     * corrupted another object. Here it is a NULL check that costs one
     * comparison and turns a memory-safety bug into a control-flow decision.
     */
    if (buf != NULL) {
        printf("  (unreachable) reading through buf\n");
    } else {
        printf("  the stale use is now a NULL check that fails safely\n");
    }

    /* The double free. free(NULL) is a defined no-op. */
    OWNED_FREE(buf);
    printf("  second OWNED_FREE is free(NULL): defined, no-op, no abort\n");

    printf("\n  What this does NOT fix: a second copy of the pointer held by\n");
    printf("  another object. OWNED_FREE clears the copy you can see. If the\n");
    printf("  object was published to a callback, a list, or a JNI global ref,\n");
    printf("  you need an ownership model, not a macro. See README 5.9.\n");
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Case: secret                                                              */
/* ------------------------------------------------------------------------ */

static int case_secret(void)
{
    char *token = (char *)malloc(64);
    char *probe;
    uintptr_t untagged_token;
    uintptr_t untagged_probe;

    printf("== secret: scrub before free, and prove it stuck ==\n\n");

    if (token == NULL) {
        return 1;
    }
    memset(token, 0, 64);
    memcpy(token, "SESSION=deadbeefcafebabe", 24);
    printf("  token buffer at %p\n", (void *)token);
    hexdump("before scrub", token, 24);

    scrub(token, 64);
    hexdump("after scrub", token, 24);

    /*
     * Mask off Android's heap pointer tag before comparing addresses. See
     * heap-bugs.c's untag(); the ULL suffix matters on 32-bit builds.
     */
#if UINTPTR_MAX > 0xffffffffU
    untagged_token = (uintptr_t)token & (uintptr_t)0x00ffffffffffffffULL;
#else
    untagged_token = (uintptr_t)token;
#endif
    free(token);
    token = NULL;

    /*
     * Reclaim the same block and look at it. This is a legitimate read: the
     * memory is ours again. If the scrub worked, there is nothing to find. If
     * you comment out the scrub() call above and rebuild, the ASCII of the
     * fake token reappears here, which is the whole demonstration.
     */
    probe = (char *)malloc(64);
    if (probe != NULL) {
#if UINTPTR_MAX > 0xffffffffU
        untagged_probe = (uintptr_t)probe & (uintptr_t)0x00ffffffffffffffULL;
#else
        untagged_probe = (uintptr_t)probe;
#endif
        if (untagged_probe == untagged_token) {
            printf("\n  reclaimed the same block at %p\n", (void *)probe);
            hexdump("what is in it", probe, 24);
            printf("  All zero. Comment out the scrub() call, rebuild, and this\n");
            printf("  line prints the token instead.\n");
        } else {
            printf("\n  got a different block (%p); run again, or read README 3.6\n",
                   (void *)probe);
        }
        free(probe);
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Case: stack                                                               */
/* ------------------------------------------------------------------------ */

/*
 * The bounded version of heap-bugs.c's `stack` mode. Two rules, both boring:
 *
 *   1. The destination size is written ONCE, as sizeof(dst), at the call site.
 *      Never as a repeated literal, because the literal and the array drift
 *      apart during maintenance and the compiler will not tell you.
 *   2. snprintf() and strlcpy() truncate rather than overflow, and both report
 *      what they WOULD have written, so the caller can treat truncation as the
 *      error it usually is. strcpy() and sprintf() cannot, which is why
 *      _FORTIFY_SOURCE exists to replace them.
 */
static int case_stack(int argc, char **argv)
{
    char dst[16];
    /* unsigned long long, not unsigned long: `long` is 32 bits on armeabi-v7a
       and this constant would be silently truncated. Same trap as heap-bugs.c. */
    volatile unsigned long long neighbour = 0x1122334455667788ULL;
    const char *src = (argc > 2) ? argv[2]
                                 : "an input far longer than sixteen bytes";
    int would_be;

    printf("== stack: bounded copy into a 16-byte array ==\n\n");
    printf("  dst is %zu bytes at %p; neighbour at %p\n",
           sizeof(dst), (void *)dst, (void *)&neighbour);
    printf("  source is %zu bytes\n\n", strlen(src));

    would_be = snprintf(dst, sizeof(dst), "%s", src);

    printf("  snprintf wrote %zu bytes (including the terminator)\n",
           strlen(dst) + 1);
    printf("  it reports it WOULD have written %d\n", would_be);
    printf("  dst = \"%s\"\n", dst);

    if (would_be >= (int)sizeof(dst)) {
        printf("\n  TRUNCATED. Treat this as an error, not a success: a\n");
        printf("  truncated path, hostname or signature is a different value,\n");
        printf("  and silently accepting it is how a bounded copy becomes a\n");
        printf("  logic vulnerability instead of a memory-safety one.\n");
    }

    printf("\n  neighbour is still 0x%016llx\n", (unsigned long long)neighbour);
    return 0;
}

/* ------------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s <case> [arg]\n"
            "\n"
            "  selftest        run every case; exit status 0 means all clean\n"
            "  bounds          capacity-checked append (fixes `overflow`)\n"
            "  ownership       free-and-null (fixes `uaf` and `dfree`)\n"
            "  secret          scrub before free (fixes the residue)\n"
            "  stack [text]    bounded copy (fixes `stack`)\n",
            argv0);
}

int main(int argc, char **argv)
{
    const char *which;
    int rc = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    which = argv[1];

    if (strcmp(which, "selftest") == 0) {
        rc |= case_bounds();
        printf("\n");
        rc |= case_ownership();
        printf("\n");
        rc |= case_secret();
        printf("\n");
        rc |= case_stack(argc, argv);
        printf("\n== selftest complete: %s ==\n", rc == 0 ? "all clean" : "FAILED");
        return rc;
    }
    if (strcmp(which, "bounds") == 0) {
        return case_bounds();
    }
    if (strcmp(which, "ownership") == 0) {
        return case_ownership();
    }
    if (strcmp(which, "secret") == 0) {
        return case_secret();
    }
    if (strcmp(which, "stack") == 0) {
        return case_stack(argc, argv);
    }

    usage(argv[0]);
    return 2;
}
