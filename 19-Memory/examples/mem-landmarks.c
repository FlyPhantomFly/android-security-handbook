/*
 * mem-landmarks.c -- the address space, from the inside: where the loader put
 *                    things, how big a page is, and what page protections
 *                    actually do when you violate them.
 *
 * PURPOSE
 *     /proc/<pid>/maps is a report about a process. This program is the process
 *     writing that report about itself, which is the only way to be certain you
 *     are reading it correctly. It answers four questions with measurements
 *     rather than assertions:
 *
 *       landmarks  Where are my code, my stack, my heap, libc and the linker?
 *                  Printed as a single parseable line so a shell loop can run
 *                  it fifty times and you can SEE the ASLR entropy instead of
 *                  reading a number someone else measured.
 *       pagesize   How big is a page on THIS device? Since Android 15 the
 *                  answer is not always 4096, and code that assumes it is
 *                  breaks in ways that look like memory corruption.
 *       wx         Make a page writable AND executable, watch it appear in
 *                  /proc/self/maps as `rwxp`, then remove the write permission
 *                  and prove the removal is enforced by the hardware.
 *       guard      Put an unmapped page between two mapped ones and prove that
 *                  a linear overflow across it faults immediately. This is the
 *                  mechanism behind guard pages, and behind why an overflow of
 *                  a 4 MiB allocation is often more detectable than an
 *                  overflow of a 32-byte one.
 *
 * USAGE
 *     # on the device, after `adb push`
 *     ./mem-landmarks landmarks
 *     ./mem-landmarks pagesize
 *     ./mem-landmarks wx
 *     ./mem-landmarks guard
 *
 *     # measure ASLR entropy: fifty runs, count distinct libc bases
 *     # adb shell
 *     for i in $(seq 1 50); do
 *       /system/bin/linker64 /data/local/tmp/ch19/mem-landmarks landmarks
 *     done | tr ' ' '\n' | grep '^libc=' | sort -u | wc -l
 *
 *     Fifty runs giving fifty distinct bases means ASLR is doing its job for
 *     exec'd processes. Fifty runs giving ONE base would mean it is not, and
 *     is worth a second look before you conclude anything else.
 *
 * REQUIREMENTS
 *     Same as heap-bugs.c. See build-memory-fixtures.sh.
 *
 * WHAT THIS PROGRAM WILL *NOT* TELL YOU
 *     - The ASLR entropy of an APP process. This is a command-line executable,
 *       which the kernel execs and therefore randomises freshly. An Android app
 *       is FORKED from the Zygote and never execs, so its library layout is
 *       inherited, identical across apps, and fixed until reboot. That is the
 *       single most important sentence in this chapter's ASLR section and this
 *       program deliberately cannot demonstrate it -- see README section 3.5
 *       and labs/lab-01 for the way to observe the real thing.
 *     - Anything about another process. Everything here is /proc/self.
 *     - Whether an RWX page in a real app is malicious. It usually is not: ART
 *       and every JIT need one. README section 5.4 is about telling them apart.
 *     - Kernel addresses. kptr_restrict hides them and this program does not
 *       try; kernel memory is out of scope for the whole chapter.
 */

#define _GNU_SOURCE

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Android tags heap pointers in the top byte; maps does not. See heap-bugs.c. */
static unsigned long untag(const void *p)
{
    uintptr_t v = (uintptr_t)p;

#if UINTPTR_MAX > 0xffffffffU
    v &= (uintptr_t)0x00ffffffffffffffULL;   /* ULL, not UL -- see heap-bugs.c */
#endif
    return (unsigned long)v;
}

/* ------------------------------------------------------------------------ */
/* Reading our own maps                                                      */
/* ------------------------------------------------------------------------ */

/*
 * Return the START address of the mapping that contains `addr`, or 0.
 *
 * "The start of the mapping" is not the same thing as "the load base of the
 * library". A shared object has several PT_LOAD segments and therefore several
 * consecutive mappings -- typically r--p, r-xp, r--p, rw-p -- and the load base
 * is the start of the FIRST of them, the one whose file offset is 0. Confusing
 * the two is the most common reason a computed function address is wrong by
 * exactly one segment. find_base() below gets it right; this one does not try.
 */
static unsigned long containing_start(unsigned long addr)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long lo, hi;

    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && addr >= lo && addr < hi) {
            fclose(f);
            return lo;
        }
    }
    fclose(f);
    return 0;
}

/*
 * Return the load base of the mapped file whose path CONTAINS `needle`.
 *
 * The rule the dynamic linker itself uses: the load base is the lowest mapping
 * of that file, and its file offset field is 00000000. Scanning for the first
 * line whose path matches AND whose offset is zero is exactly the computation
 * Frida's Module.findBaseAddress performs, and doing it once by hand is what
 * makes that API stop being magic.
 */
static unsigned long find_base(const char *needle)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];

    if (f == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        unsigned long lo, hi, off;
        char perms[8], path[400];

        path[0] = '\0';
        if (sscanf(line, "%lx-%lx %7s %lx %*s %*s %399[^\n]",
                   &lo, &hi, perms, &off, path) >= 4) {
            if (off == 0 && path[0] != '\0' && strstr(path, needle) != NULL) {
                fclose(f);
                return lo;
            }
        }
    }
    fclose(f);
    return 0;
}

/* Print the maps lines whose path or name contains `needle`. */
static void print_maps_matching(const char *needle)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];

    if (f == NULL) {
        printf("  (cannot read /proc/self/maps)\n");
        return;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strstr(line, needle) != NULL) {
            printf("    %s", line);
        }
    }
    fclose(f);
}

/* Print the single maps line containing `addr`, with a label. */
static void print_maps_line_for(unsigned long addr)
{
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long lo, hi;

    if (f == NULL) {
        return;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 && addr >= lo && addr < hi) {
            printf("    %s", line);
            break;
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------------ */
/* Mode: landmarks                                                            */
/* ------------------------------------------------------------------------ */

static int mode_landmarks(int verbose)
{
    int stack_local = 0;
    void *heap = malloc(64);
    unsigned long exe_base, libc_base, linker_base;
    unsigned long stack_start, heap_start;

    exe_base = find_base("mem-landmarks");
    libc_base = find_base("libc.so");
    linker_base = find_base("linker64");
    if (linker_base == 0) {
        linker_base = find_base("linker");
    }
    stack_start = containing_start((unsigned long)(uintptr_t)&stack_local);
    heap_start = containing_start(untag(heap));

    /*
     * One line, all hex, no 0x prefixes, stable field order. This format is not
     * pretty on purpose: it is meant to be fed to sed, sort and uniq by the
     * entropy loop in the header comment, and a format that a shell can chop up
     * without a parser is worth more here than an aligned table.
     */
    printf("pid=%d exe=%lx libc=%lx linker=%lx stack=%lx heap=%lx page=%ld\n",
           (int)getpid(), exe_base, libc_base, linker_base,
           stack_start, heap_start, sysconf(_SC_PAGESIZE));

    if (verbose) {
        printf("\nThe mappings those numbers came from:\n");
        printf("\n  the executable itself (note the four segments):\n");
        print_maps_matching("mem-landmarks");
        printf("\n  libc:\n");
        print_maps_matching("libc.so");
        printf("\n  the stack:\n");
        print_maps_matching("[stack]");
        printf("\n  the mapping holding a fresh malloc(64) at %p:\n", heap);
        print_maps_line_for(untag(heap));
        printf("\n");
        printf("  Read the permission column. The executable and libc each\n");
        printf("  appear several times with DIFFERENT permissions, because a\n");
        printf("  shared object is loaded segment by segment: read-only data,\n");
        printf("  then read+execute code, then read-only-after-relocation, then\n");
        printf("  read+write data. One file, four mappings, one load base --\n");
        printf("  the lowest one, the one whose file offset is 00000000.\n");
    }

    free(heap);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Mode: pagesize                                                             */
/* ------------------------------------------------------------------------ */

static int mode_pagesize(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    void *p;

    printf("== pagesize ==\n\n");
    printf("  sysconf(_SC_PAGESIZE) = %ld bytes (%ld KiB)\n", ps, ps / 1024);
    printf("  getpagesize()         = %d bytes\n", getpagesize());

    /*
     * Page granularity is not an abstraction: ask for one byte with mmap and
     * the kernel gives you a whole page, and /proc/self/maps proves it.
     */
    p = mmap(NULL, 1, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("  mmap failed\n");
        return 1;
    }
    printf("\n  mmap of ONE byte returned %p. Its mapping:\n", p);
    print_maps_line_for((unsigned long)(uintptr_t)p);
    printf("\n  That mapping is a whole page wide. Every protection decision\n");
    printf("  the kernel makes is per page, so \"make this one variable\n");
    printf("  read-only\" is not a thing you can ask for -- you can only ask\n");
    printf("  about the page it happens to live in, along with whatever else\n");
    printf("  shares that page.\n\n");

    printf("  Why this number matters beyond trivia: since Android 15, AOSP\n");
    printf("  supports devices configured with 16 KiB pages. A native library\n");
    printf("  whose PT_LOAD segments are aligned to 4 KiB will not load at all\n");
    printf("  on such a device, and code that hard-codes 4096 -- to round an\n");
    printf("  mmap length, or to compute a page base for mprotect -- is wrong\n");
    printf("  in a way that presents as memory corruption. Always ask the\n");
    printf("  system, as the two calls above do. See README section 3.3.\n");

    munmap(p, (size_t)ps);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Fault-surviving plumbing for the wx and guard modes                        */
/* ------------------------------------------------------------------------ */

static sigjmp_buf g_jump;
static volatile sig_atomic_t g_caught;
static volatile sig_atomic_t g_code;

static void fault_handler(int sig, siginfo_t *info, void *ctx)
{
    (void)ctx;
    g_caught = sig;
    g_code = (info != NULL) ? info->si_code : 0;
    siglongjmp(g_jump, 1);
}

/*
 * Install a SIGSEGV/SIGBUS handler that jumps back rather than dying, so the
 * program can perform a deliberately illegal access, survive it, and carry on
 * to the next demonstration.
 *
 * This is a teaching device and NOT a technique to copy into production. A
 * process that catches SIGSEGV and continues has, by definition, continued past
 * memory corruption it does not understand. Real code should let it die: a
 * crash is a security control, and "handle the segfault and retry" is how a
 * memory-safety bug becomes an exploitable one that nobody notices.
 */
static int install_fault_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        return -1;
    }
    return sigaction(SIGBUS, &sa, NULL);
}

/* ------------------------------------------------------------------------ */
/* Mode: wx                                                                   */
/* ------------------------------------------------------------------------ */

static int mode_wx(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    unsigned char *p;

    printf("== wx: a page that is writable and executable at the same time ==\n\n");

    if (install_fault_handler() != 0) {
        printf("  cannot install signal handler\n");
        return 1;
    }

    /*
     * PROT_WRITE|PROT_EXEC together. This is what W^X ("write xor execute")
     * forbids as a policy, and what a JIT needs as a mechanism. On Android the
     * request usually succeeds for an app's own anonymous memory; SELinux
     * policy is what stops it for file-backed mappings and for some domains.
     */
    p = (unsigned char *)mmap(NULL, (size_t)ps,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("  mmap(PROT_READ|PROT_WRITE|PROT_EXEC) FAILED.\n");
        printf("  That is a good sign, and it means this device or domain\n");
        printf("  refuses RWX anonymous memory outright.\n");
        return 0;
    }

    printf("  mmap(PROT_READ|PROT_WRITE|PROT_EXEC) -> %p\n", (void *)p);
    printf("  and here is how it looks in /proc/self/maps:\n");
    print_maps_line_for((unsigned long)(uintptr_t)p);
    printf("\n  The permission column reads rwxp. THAT is the string a triage\n");
    printf("  script greps for, and scripts/maps-analyse.py flags it. It is not\n");
    printf("  automatically a finding: ART's JIT legitimately holds pages like\n");
    printf("  this. It is a question -- who created it, and does the code that\n");
    printf("  writes into it ever handle attacker-controlled bytes?\n\n");

    p[0] = 0xc0;
    printf("  wrote one byte into it: p[0] = 0xc0. No fault.\n\n");

    /*
     * Now take PROT_WRITE away. The page keeps its contents and its execute
     * permission; only the write permission goes. The next store to it must
     * fault, and the fault is delivered by the MMU, not by any check the
     * program performs. This is the difference between a mitigation that is
     * ENFORCED and a check that is merely PRESENT.
     */
    if (mprotect(p, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        printf("  mprotect to R+X failed\n");
        munmap(p, (size_t)ps);
        return 1;
    }
    printf("  mprotect(PROT_READ|PROT_EXEC) done. Now:\n");
    print_maps_line_for((unsigned long)(uintptr_t)p);
    printf("\n  the same byte is still readable: p[0] = 0x%02x\n", p[0]);

    printf("\n  now writing to it again, which must fault:\n");
    g_caught = 0;
    if (sigsetjmp(g_jump, 1) == 0) {
        p[0] = 0x41;
        printf("  NO FAULT. Write permission was not actually removed -- that\n");
        printf("  would be a broken kernel or a broken emulator, and worth\n");
        printf("  investigating before you trust any other result here.\n");
    } else {
        printf("  faulted with signal %d (si_code %d) -- exactly as intended.\n",
               (int)g_caught, (int)g_code);
        printf("  Nothing in this program checked anything. The page table\n");
        printf("  entry lost its write bit and the MMU refused the store.\n");
    }

    munmap(p, (size_t)ps);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Mode: guard                                                                */
/* ------------------------------------------------------------------------ */

static int mode_guard(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    unsigned char *region;
    unsigned char *data;
    unsigned char *guard;
    size_t i;

    printf("== guard: an unmapped page turns a silent overflow into a crash ==\n\n");

    if (install_fault_handler() != 0) {
        printf("  cannot install signal handler\n");
        return 1;
    }

    region = (unsigned char *)mmap(NULL, (size_t)ps * 3,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        printf("  mmap failed\n");
        return 1;
    }
    data = region;
    guard = region + ps;

    /*
     * PROT_NONE: mapped, but with no access of any kind. Reading it, writing it
     * or executing it all fault. This is what a "guard page" is -- there is no
     * special kernel feature involved, just a page with no permissions placed
     * where you want an overflow to stop.
     */
    if (mprotect(guard, (size_t)ps, PROT_NONE) != 0) {
        printf("  mprotect(PROT_NONE) failed\n");
        munmap(region, (size_t)ps * 3);
        return 1;
    }

    printf("  three pages at %p, middle one set to PROT_NONE:\n", (void *)region);
    print_maps_line_for((unsigned long)(uintptr_t)data);
    print_maps_line_for((unsigned long)(uintptr_t)guard);
    print_maps_line_for((unsigned long)(uintptr_t)(guard + ps));
    printf("\n  The middle line's permissions read ---p. Nothing may touch it.\n");
    printf("  Note that all three still appear in maps: PROT_NONE memory is\n");
    printf("  MAPPED, it simply has no permissions. A region that is genuinely\n");
    printf("  unmapped does not appear at all.\n\n");

    printf("  now writing forward from the first page, one byte at a time:\n");
    g_caught = 0;
    if (sigsetjmp(g_jump, 1) == 0) {
        for (i = 0; i < (size_t)ps * 2; i++) {
            data[i] = 0x41;
        }
        printf("  wrote %zu bytes with no fault -- unexpected.\n", i);
    } else {
        printf("  faulted with signal %d (si_code %d)\n",
               (int)g_caught, (int)g_code);
        printf("\n  The overflow stopped at the page boundary, immediately,\n");
        printf("  at the first out-of-bounds byte rather than thousands of\n");
        printf("  bytes later. That immediacy is the entire value of a guard\n");
        printf("  page, and it is how GWP-ASan catches overflows on a sampled\n");
        printf("  fraction of allocations with almost no runtime cost: place\n");
        printf("  the allocation right up against a PROT_NONE page and let the\n");
        printf("  MMU do the checking. README section 3.12.\n");
    }

    munmap(region, (size_t)ps * 3);
    return 0;
}

/* ------------------------------------------------------------------------ */

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s <mode>\n"
            "\n"
            "  landmarks       one parseable line: exe, libc, linker, stack, heap bases\n"
            "  landmarks -v    the same, plus the maps lines they came from\n"
            "  pagesize        page size, and proof that mapping is page-granular\n"
            "  wx              create an rwxp page, then prove mprotect is enforced\n"
            "  guard           a PROT_NONE page stopping a linear overflow\n",
            argv0);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "landmarks") == 0) {
        int verbose = (argc > 2 && strcmp(argv[2], "-v") == 0);
        return mode_landmarks(verbose);
    }
    if (strcmp(argv[1], "pagesize") == 0) {
        return mode_pagesize();
    }
    if (strcmp(argv[1], "wx") == 0) {
        return mode_wx();
    }
    if (strcmp(argv[1], "guard") == 0) {
        return mode_guard();
    }
    usage(argv[0]);
    return 2;
}
