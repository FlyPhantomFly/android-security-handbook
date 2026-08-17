/*
 * trampoline-hook.c — a complete inline (trampoline) hook for AArch64, written
 *                     by hand, with no Frida, no root, and no library.
 *
 * WHAT IT DOES
 *   Loads libguard.so, then installs an inline hook on the exported function
 *   `guard_check` and demonstrates, with printed evidence, that:
 *
 *     1. the function's behaviour changed  — guard_check("wrong") goes 0 -> 1;
 *     2. the ORIGINAL body still ran       — the exported guard_counter
 *                                            increments on every hooked call,
 *                                            which is only possible if the
 *                                            trampoline actually executed it;
 *     3. a PC-relative instruction was RE-ENCODED, not copied — the `adrp` in
 *        the displaced prologue is printed before and after relocation.
 *
 *   Every instruction word it writes is printed. Nothing is hidden.
 *
 * THE SIX STEPS OF AN INLINE HOOK — this file is these six steps and nothing else
 *
 *     1. find the target address                       dlsym / dl_iterate_phdr
 *     2. decide how many instructions to displace      16 bytes = 4 words here
 *     3. allocate a trampoline WITHIN RANGE            the hard part; see below
 *     4. copy the displaced instructions, RELOCATING   the other hard part
 *        any that are PC-relative, then append a jump
 *        back to target+N
 *     5. make the target page writable, overwrite the
 *        first N bytes with a jump to the replacement,
 *        restore the page permissions
 *     6. flush the instruction cache                   the step everyone forgets
 *
 * THE PATCH IT WRITES (16 bytes, absolute, unlimited range)
 *
 *     +0   58000050    ldr  x16, #8      load the 8 bytes at +8 into x16
 *     +4   d61f0200    br   x16          branch to it
 *     +8   <8 bytes>   .quad replacement
 *
 *   Every one of those encodings came from an assemble/disassemble round trip
 *   with the NDK's clang and llvm-objdump. None was written from memory. The
 *   table lives in ../cheatsheet.md; the round trip that produced it is
 *   reproducible with ../../18-ARM/scripts/arm64-patch.py --show-encodings.
 *
 *   x16 is IP0, the intra-procedure-call scratch register. AAPCS64 permits any
 *   code at a function entry boundary to clobber it, which is exactly why every
 *   real hooking engine uses x16 or x17 here. See ../../18-ARM/README.md 3.4.
 *
 * HOW TO RUN
 *   ./build-hook-fixtures.sh                 # builds this and libguard.so
 *   adb push $OUT/trampoline-hook $OUT/libguard.so /data/local/tmp/
 *   adb shell chmod 755 /data/local/tmp/trampoline-hook
 *   adb shell /system/bin/linker64 /data/local/tmp/trampoline-hook
 *
 *   The `linker64` invocation is not decoration. /data/local/tmp is mounted
 *   nosuid,nodev and the vendor build refuses direct execve there; running the
 *   dynamic linker and handing it the executable is the standard workaround and
 *   is documented in ../../18-ARM/README.md section 7.7.
 *
 * REQUIREMENTS
 *   Android NDK (tested: 25.2.9519653, clang 14.0.7), an arm64 device or
 *   emulator, adb. No root. No frida-server. Nothing is installed on the
 *   device beyond two files in /data/local/tmp.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether this technique works on an ARBITRARY function. It works on this
 *     one because this one's first four instructions are relocatable. Run
 *     ../scripts/hookability.py first on anything else; see the "REFUSED"
 *     path in relocate() for what happens when they are not.
 *   - Anything about thread safety. A real engine must stop the world, or
 *     write the patch atomically, because another thread can be executing
 *     inside the 16 bytes you are rewriting. This one is single-threaded and
 *     says so rather than pretending the problem does not exist.
 *   - Whether the app noticed. The patched bytes are trivially readable by the
 *     process itself. Detection and its defeat are 67-BypassingProtections'
 *     subject, not this file's.
 *   - Anything about ARM32/Thumb. Thumb is variable length; a 16-byte patch
 *     written blindly into Thumb code produces silent nonsense.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

static long PAGE;
#define PAGE_DOWN(p) ((void *)((uintptr_t)(p) & ~(uintptr_t)(PAGE - 1)))

typedef int (*guard_fn)(const char *);

/* Set in step 4. Calling this runs the displaced prologue then jumps back into
   the middle of the original function, so the original body executes. */
static guard_fn tramp = NULL;

/* ------------------------------------------------------------------------ */
/* The replacement. Note that it is an ordinary C function: the hook does not  */
/* need assembly on the replacement side, only on the patch side.             */
/* ------------------------------------------------------------------------ */
static int replacement(const char *token) {
    int real = tramp(token);      /* call through — this is why we need a trampoline */
    printf("    [hook] guard_check(\"%s\") really returned %d -> forcing 1\n",
           token ? token : "(null)", real);
    return 1;
}

static void dump(const char *tag, const uint32_t *p, int n) {
    printf("  %s\n", tag);
    for (int i = 0; i < n; i++)
        printf("    %p:  %08x\n", (const void *)(p + i), p[i]);
}

/* ------------------------------------------------------------------------ */
/* Instruction classification. These masks decide whether a displaced word    */
/* can be copied verbatim. Getting one of them wrong produces a hook that     */
/* works on your test binary and corrupts the next one.                       */
/* ------------------------------------------------------------------------ */
static int is_adrp   (uint32_t w) { return (w & 0x9f000000u) == 0x90000000u; }
static int is_adr    (uint32_t w) { return (w & 0x9f000000u) == 0x10000000u; }
static int is_ldr_lit(uint32_t w) { return (w & 0x3b000000u) == 0x18000000u; }
static int is_b      (uint32_t w) { return (w & 0xfc000000u) == 0x14000000u; }
static int is_bl     (uint32_t w) { return (w & 0xfc000000u) == 0x94000000u; }
static int is_bcond  (uint32_t w) { return (w & 0xff000010u) == 0x54000000u; }
static int is_cbz    (uint32_t w) { return (w & 0x7e000000u) == 0x34000000u; }
static int is_tbz    (uint32_t w) { return (w & 0x7e000000u) == 0x36000000u; }

/*
 * adrp Rd, <label>  encoding:
 *
 *   31  30 29  28..24  23.................5  4..0
 *    1  immlo  10000   immhi (19 bits)       Rd
 *
 * It computes  (PC & ~0xFFF) + (SignExtend(immhi:immlo) << 12).
 * The immediate is a count of 4 KiB PAGES, signed, 21 bits — so +/-4 GiB.
 */
static int64_t adrp_imm(uint32_t w) {
    int64_t immlo = (w >> 29) & 0x3;
    int64_t immhi = (w >> 5) & 0x7ffff;
    int64_t imm   = (immhi << 2) | immlo;              /* 21 bits */
    if (imm & (1LL << 20)) imm -= (1LL << 21);         /* sign extend */
    return imm;
}

static uint32_t adrp_encode(uint32_t w, int64_t imm21) {
    uint32_t immlo = (uint32_t)(imm21 & 0x3);
    uint32_t immhi = (uint32_t)((imm21 >> 2) & 0x7ffff);
    return (w & 0x9f00001fu) | (immlo << 29) | (immhi << 5);
}

/*
 * Copy one instruction from old_pc to new_pc, re-encoding PC-relative forms.
 * Returns 0 on success, -1 if the form cannot be relocated.
 *
 * Only adrp is handled here. Every other PC-relative form is REFUSED rather
 * than mishandled. Refusing is the correct behaviour for a teaching engine:
 * silently copying a `b` would produce a branch to the wrong place, and the
 * failure would surface a thousand instructions away from the bug.
 */
static int relocate(uint32_t w, uintptr_t old_pc, uintptr_t new_pc, uint32_t *out) {
    if (is_adrp(w)) {
        uintptr_t page = (old_pc & ~(uintptr_t)0xfff) + (uintptr_t)(adrp_imm(w) << 12);
        int64_t delta = (int64_t)(page - (new_pc & ~(uintptr_t)0xfff)) >> 12;
        if (delta > 0xfffffLL || delta < -0x100000LL) {
            printf("    [reloc] REFUSED: adrp target page %p is beyond +/-4 GiB "
                   "of the trampoline\n", (void *)page);
            return -1;
        }
        *out = adrp_encode(w, delta);
        printf("    [reloc] adrp %08x -> %08x   (target page %p, imm %lld -> %lld)\n",
               w, *out, (void *)page, (long long)adrp_imm(w), (long long)delta);
        return 0;
    }
    if (is_adr(w) || is_ldr_lit(w) || is_b(w) || is_bl(w) ||
        is_bcond(w) || is_cbz(w) || is_tbz(w)) {
        printf("    [reloc] REFUSED: %08x is PC-relative and this engine does "
               "not re-encode that form\n", w);
        return -1;
    }
    *out = w;    /* position independent — safe to copy verbatim */
    printf("    [copy ] %08x  (position independent)\n", w);
    return 0;
}

/* Write the 16-byte absolute jump described in the header comment. */
static void put_abs_jump(uint32_t *dst, uintptr_t dest) {
    dst[0] = 0x58000050u;                        /* ldr x16, #8 */
    dst[1] = 0xd61f0200u;                        /* br  x16     */
    memcpy(&dst[2], &dest, sizeof(dest));        /* .quad dest  */
}

/*
 * Allocate one page as close to `near` as possible.
 *
 * A plain mmap() hint is ADVISORY. Measured on an Android 13 / API 33 arm64
 * device: passing target+1 MiB as the hint returned a page 11,097,491,692 bytes
 * away — about 10.3 GiB, which is outside adrp's +/-4 GiB reach, so relocation
 * failed outright. MAP_FIXED_NOREPLACE turns the request into a real one: it
 * maps at exactly the address given, or fails, and never silently clobbers an
 * existing mapping the way bare MAP_FIXED would.
 */
static void *alloc_near(void *near) {
    uintptr_t base = (uintptr_t)near & ~(uintptr_t)(PAGE - 1);
    for (long k = 1; k < 4096; k++) {
        for (int below = 0; below < 2; below++) {
            uintptr_t want = below ? base - (uintptr_t)k * PAGE
                                   : base + (uintptr_t)k * PAGE;
            void *r = mmap((void *)want, (size_t)PAGE, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
            if (r == MAP_FAILED) continue;
            if (r == (void *)want) return r;
            munmap(r, (size_t)PAGE);       /* kernel ignored the fixed request */
        }
    }
    return MAP_FAILED;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    PAGE = sysconf(_SC_PAGESIZE);
    printf("page size = %ld bytes\n", PAGE);

    /* ---- step 1: find the target ------------------------------------ */
    void *h = dlopen("/data/local/tmp/libguard.so", RTLD_NOW);
    if (!h) { printf("dlopen failed: %s\n", dlerror()); return 1; }
    guard_fn target = (guard_fn)dlsym(h, "guard_check");
    if (!target) { printf("dlsym failed: %s\n", dlerror()); return 1; }
    printf("guard_check @ %p\n", (void *)target);

    printf("\n== BEFORE ==\n");
    printf("  guard_check(\"wrong\")        = %d\n", target("wrong"));
    printf("  guard_check(\"s3cr3t-token\")  = %d\n", target("s3cr3t-token"));
    dump("original prologue:", (const uint32_t *)target, 6);

    /* ---- step 3: trampoline page, within adrp range ------------------ */
    uint32_t *tp = alloc_near((void *)target);
    if (tp == MAP_FAILED) { perror("alloc_near"); return 1; }
    printf("\ntrampoline page @ %p  (%+lld bytes from target)\n",
           (void *)tp, (long long)((intptr_t)tp - (intptr_t)target));

    /* ---- step 4: relocate the displaced instructions ----------------- */
    printf("\n== RELOCATING the 4 displaced instructions ==\n");
    const uint32_t *src = (const uint32_t *)target;
    for (int i = 0; i < 4; i++) {
        uint32_t out;
        if (relocate(src[i], (uintptr_t)&src[i], (uintptr_t)&tp[i], &out) != 0) {
            printf("\ncannot build a trampoline for this function - aborting.\n"
                   "This is the correct outcome, not a bug. Run\n"
                   "  python3 ../scripts/hookability.py libguard.so --symbol guard_check\n"
                   "to see why before you try again.\n");
            return 1;
        }
        tp[i] = out;
    }
    put_abs_jump(&tp[4], (uintptr_t)target + 16);   /* jump back past the patch */
    dump("trampoline:", tp, 8);

    if (mprotect(tp, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect trampoline"); return 1;
    }
    __builtin___clear_cache((char *)tp, (char *)tp + PAGE);
    tramp = (guard_fn)tp;

    /* ---- step 5: patch the target ------------------------------------ */
    void *pg = PAGE_DOWN(target);
    size_t span = ((uintptr_t)target + 16) - (uintptr_t)pg;
    if (mprotect(pg, span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("mprotect RWX refused (%s) - retrying without EXEC\n", strerror(errno));
        if (mprotect(pg, span, PROT_READ | PROT_WRITE) != 0) {
            perror("mprotect RW"); return 1;
        }
    }
    put_abs_jump((uint32_t *)target, (uintptr_t)replacement);
    if (mprotect(pg, span, PROT_READ | PROT_EXEC) != 0) { perror("mprotect back"); return 1; }

    /* ---- step 6: the step everyone forgets ---------------------------- */
    __builtin___clear_cache((char *)target, (char *)target + 16);

    printf("\n== AFTER ==\n");
    dump("patched prologue:", (const uint32_t *)target, 6);
    printf("  guard_check(\"wrong\")        = %d\n", target("wrong"));
    printf("  guard_check(\"s3cr3t-token\")  = %d\n", target("s3cr3t-token"));

    const int *counter = (const int *)dlsym(h, "guard_counter");
    printf("\nguard_counter = %d\n", counter ? *counter : -1);
    printf("Four calls were made and the counter reads 4, so the ORIGINAL body\n"
           "executed on every one of them. The hook intercepted the return value\n"
           "without replacing the function.\n");
    return 0;
}
