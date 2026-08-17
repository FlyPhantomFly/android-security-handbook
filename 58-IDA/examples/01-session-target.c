/*
 * examples/01-session-target.c
 *
 * PURPOSE
 *   The reversing target for chapter 58. It is built twice by
 *   examples/build.sh -- once unstripped (the answer key) and once stripped
 *   (what you actually work on) -- and it is deliberately built out of
 *   constructs that separate a good interactive disassembler from a mediocre
 *   one:
 *
 *     1. A context STRUCT passed by pointer through six functions. Recovering
 *        it is the single highest-value action in this binary, and it is the
 *        thing Hex-Rays' "Create new struct type" does in one keystroke and
 *        every other tool makes you do by hand. Section 3.6.
 *
 *     2. A dense SWITCH over twelve opcodes, which compiles to a jump table in
 *        .rodata. Whether your tool recovers the table decides whether you see
 *        twelve cases or one indirect branch into nowhere. Section 3.5.
 *
 *     3. An INDIRECT CALL through a function-pointer table that the optimiser
 *        cannot fold away, because an exported setter can rewrite it. No
 *        static tool resolves this without help. Section 3.5 and section 11.
 *
 *        The first version of this file made the table `static const`, and
 *        clang devirtualised every call: the indirect branch simply was not
 *        in the output. That failure is recorded in section 11 because it is
 *        the more useful half of the lesson -- a fixture that does not
 *        reproduce the construct it claims to teach is worse than no fixture.
 *
 *     4. A predicate small enough that clang INLINES it at -O2, leaving an
 *        exported symbol that nothing calls. Chapter 18 section 5.4 measured
 *        exactly this and patched a function that no longer mattered; this
 *        fixture reproduces it so you can see it before it costs you an hour.
 *
 *     5. A TAIL CALL, which turns a `bl` into a `b` and makes the callee look
 *        like it belongs to the caller. It needs __attribute__((noinline)) to
 *        survive -- see session_slow_path below, and section 11 for what
 *        happened when it did not have one.
 *
 *     6. A NORETURN error path, which decides where your tool stops
 *        disassembling.
 *
 *     7. XOR-OBFUSCATED strings, so `strings` on the file finds nothing and
 *        the interesting text only exists after the function has run.
 *
 *     8. Three functions linked in from a STATIC ARCHIVE (02-crcutil.c), so
 *        the finished binary mixes application logic with library code and
 *        nothing marks the boundary. That is what FLIRT is for. Section 3.7.
 *
 * WHAT IT IS NOT
 *   It is not a JNI tutorial. Chapter 57 owns JNIEnv retyping and dynamic
 *   registration recovery, and repeating that here would waste your time and
 *   the fixture's. There is exactly ONE JNI entry point, present only so the
 *   library is recognisably Android rather than generic Linux, and it uses
 *   hand-declared JNI types so this file compiles with no jni.h at all --
 *   the same trick 15-Native-Code/examples/jni-surface.c uses.
 *
 * BUILD
 *   # host
 *   ./build.sh                       # arm64-v8a, into $TMPDIR/ch58-build
 *   OUTDIR=/tmp/ch58 ./build.sh      # choose where
 *   ABI=armeabi-v7a ./build.sh       # 32-bit, for the ARM/Thumb comparison
 *
 *   Verified clean with -Wall -Wextra under NDK 25.2.9519653 (clang 14.0.7),
 *   target aarch64-unknown-linux-android21.
 *
 * NOTHING IS WRITTEN INTO THE REPOSITORY. build.sh builds out of tree; `.so`,
 * `.o` and `.a` are on this repository's artefact blocklist.
 *
 * AUTHORISED TESTING ONLY. This is your own code, so analyse it freely. Do not
 * point the techniques in this chapter at software you have no permission to
 * examine.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "02-crcutil.h"

/* ================================================================== *
 * Minimal JNI declarations.
 *
 * Declared by hand so this file needs no jni.h and no NDK sysroot header
 * search. The machine code generated for the one JNI function below is
 * identical either way: x0 is the JNIEnv*, x1 the jobject, and the first real
 * argument arrives in x2 (chapter 18, AAPCS64).
 * ================================================================== */

typedef void *JNIEnv;
typedef void *jobject;
typedef int32_t jint;

#define CH58_EXPORT __attribute__((visibility("default")))

/* ================================================================== *
 * 1. The structure you are here to recover.
 *
 * Every offset below is a number you will meet in the disassembly as
 * `[x0, #N]` and nowhere else. The whole of lab 02 is turning those numbers
 * back into these names.
 *
 * Layout on arm64 (LP64, natural alignment), stated here as the answer key:
 *
 *   +0x00  uint32_t magic
 *   +0x04  uint32_t flags
 *   +0x08  uint64_t issued_at
 *   +0x10  uint8_t  key[16]
 *   +0x20  char     user[32]
 *   +0x40  uint32_t crc
 *   +0x44  int32_t  state
 *   +0x48  uint32_t step_count
 *   +0x4c  uint32_t reserved
 *   ----   total 0x50 bytes
 *
 * Note there is no padding anywhere. That is deliberate and it is a small
 * lie about real code: genuine structs usually have holes, and a hole is the
 * thing that most often makes a recovered struct one field short. Lab 02 asks
 * you to add a field that creates one and re-derive the layout.
 * ================================================================== */

typedef struct {
    uint32_t magic;
    uint32_t flags;
    uint64_t issued_at;
    uint8_t  key[16];
    char     user[32];
    uint32_t crc;
    int32_t  state;
    uint32_t step_count;
    uint32_t reserved;
} session_ctx;

#define SESSION_MAGIC     0x5345534Eu    /* "NSES" little-endian */
#define FLAG_SEALED       0x00000001u
#define FLAG_PRIVILEGED   0x00000002u
#define FLAG_EXPIRED      0x00000004u
#define FLAG_DEBUG        0x00000008u

enum session_state {
    ST_INVALID = -1,
    ST_FRESH   = 0,
    ST_OPEN    = 1,
    ST_SEALED  = 2,
    ST_DEAD    = 3
};

/* ================================================================== *
 * 2. The noreturn error path.
 *
 * __attribute__((noreturn)) tells the compiler nothing follows a call to
 * this function. The compiler then omits any code after the call site,
 * and a disassembler that does not know the function never returns will
 * keep decoding whatever bytes come next -- usually producing a page of
 * plausible nonsense. Both IDA and Ghidra discover non-returning functions
 * automatically; watching where they stop is how you check they did.
 * ================================================================== */

static void session_fatal(int code) __attribute__((noreturn));

static void session_fatal(int code)
{
    /* abort() is itself noreturn, so this is a tail call to a noreturn
     * import: the tightest possible version of the pattern. */
    (void)code;
    abort();
}

/* ================================================================== *
 * 3. The predicate that will be inlined.
 *
 * At -O2 clang inlines this into every caller. The symbol survives in the
 * unstripped build because it is referenced by the exported wrapper below,
 * but the copies that actually execute are inside the callers. Patching the
 * standalone body therefore changes nothing -- which is exactly the result
 * chapter 18 measured on a different fixture, and the single most common
 * reason a beginner concludes their patch "did not work".
 * ================================================================== */

static int session_magic_ok(const session_ctx *s)
{
    return s != NULL && s->magic == SESSION_MAGIC;
}

/* Exported wrapper, so the symbol has a reason to exist in .dynsym.
 * Compare the two: the wrapper is three instructions; the inlined copies
 * inside session_step are two, with no call at all. */
CH58_EXPORT int session_check_magic(const session_ctx *s)
{
    return session_magic_ok(s);
}

/* ================================================================== *
 * 4. XOR-obfuscated strings.
 *
 * The plaintext never appears in the file. `strings` finds nothing, and a
 * signature scan for the plaintext finds nothing. The strings exist only on
 * the stack, only after session_reveal has run, which is the entire argument
 * for pairing a disassembler with a debugger rather than choosing between
 * them.
 *
 * Encoded with key 0x5A. The build script prints the decoded values so you
 * can check your work without running anything.
 * ================================================================== */

#define OBF_KEY 0x5A

/* "/system/bin/su"  XOR 0x5A */
static const uint8_t obf_su_path[] = {
    0x75, 0x29, 0x23, 0x29, 0x2e, 0x3f, 0x37, 0x75, 0x38, 0x33, 0x34, 0x75,
    0x29, 0x2f, 0x00
};

/* "ro.debuggable"   XOR 0x5A */
static const uint8_t obf_debuggable[] = {
    0x28, 0x35, 0x74, 0x3e, 0x3f, 0x38, 0x2f, 0x3d, 0x3d, 0x3b, 0x38, 0x36,
    0x3f, 0x00
};

/* "CH58{...}" is NOT here. The flag for lab 04 is assembled at runtime. */

/*
 * noinline is LOAD-BEARING and was added after measurement.
 *
 * Without it, clang inlined this function, constant-folded the XOR at compile
 * time, proved that the comparison in session_seal is always true, and then
 * deleted BOTH encoded arrays and the entire decode path as dead. The measured
 * result was a .rodata containing neither the encoded strings nor the
 * plaintexts -- a fixture that claimed to teach string obfuscation and
 * contained no obfuscated strings.
 *
 * With noinline, the compiler cannot know what this function writes through
 * `out`, so the arrays must survive and the decode must actually run.
 *
 * The general lesson is in the README's section 11.4: a fixture is a claim,
 * and the only way to check a claim about a binary is to disassemble it.
 */
__attribute__((noinline))
static void session_reveal(char *out, const uint8_t *src, size_t n)
{
    size_t i;
    for (i = 0; i + 1 < n; i++) {
        out[i] = (char)(src[i] ^ OBF_KEY);
    }
    out[n - 1] = '\0';
}

/* ================================================================== *
 * 5. The function-pointer table -- an indirect call no static tool
 *    can resolve on its own.
 *
 * The table lives in .data (writable) rather than .data.rel.ro, because
 * session_set_digest below can rewrite it. That one exported setter is what
 * makes the indirect call survive -O2: with a `static const` table clang
 * proves the contents and replaces every `blr` with a direct `bl`, and the
 * construct you came to study is not in the binary at all. Measured, and
 * written up in section 11.
 *
 * The slots still read as ZERO in a plain hexdump, because their initial
 * values are load-time relocations (R_AARCH64_RELATIVE), not literals. A tool
 * that applies relocations shows you three pointers; a tool that does not
 * shows you twenty-four zero bytes. Check yours.
 * ================================================================== */

typedef uint32_t (*digest_fn)(const uint8_t *, size_t);

static uint32_t digest_crc(const uint8_t *p, size_t n)
{
    return ch58_crc32(p, n);
}

static uint32_t digest_fnv(const uint8_t *p, size_t n)
{
    return (uint32_t)(ch58_fnv1a64(p, n) & 0xFFFFFFFFu);
}

static uint32_t digest_sum(const uint8_t *p, size_t n)
{
    uint32_t acc = 0;
    size_t   i;
    for (i = 0; i < n; i++) {
        acc = (acc << 3) ^ (acc >> 29) ^ p[i];
    }
    return acc;
}

/* NOT const, and reachable from outside. Both properties are required. */
static digest_fn digest_table[3] = {
    digest_crc,
    digest_fnv,
    digest_sum
};

/*
 * The reason the table cannot be folded. In real code this is a plugin hook,
 * a test seam, or a "pluggable crypto backend" -- the shape is extremely
 * common, and it is why so many real libraries contain indirect calls that
 * no static tool can follow.
 */
CH58_EXPORT int session_set_digest(int idx, digest_fn fn)
{
    if (idx < 0 || idx > 2 || fn == NULL) {
        return -1;
    }
    digest_table[idx] = fn;
    return 0;
}

/* ================================================================== *
 * 6. Initialisation.
 * ================================================================== */

CH58_EXPORT int session_init(session_ctx *s, const char *user, uint64_t now)
{
    size_t n;

    if (s == NULL || user == NULL) {
        return -1;
    }

    memset(s, 0, sizeof(*s));
    s->magic     = SESSION_MAGIC;
    s->issued_at = now;
    s->state     = ST_FRESH;

    n = strlen(user);
    if (n >= sizeof(s->user)) {
        n = sizeof(s->user) - 1;
    }
    memcpy(s->user, user, n);
    s->user[n] = '\0';

    /* A key derived from the user name and the timestamp. Device-bound in
     * appearance, worthless in practice: everything it depends on is
     * readable by whoever holds the device. Chapter 57's key-source table
     * rates this MEDIUM; the point of putting it here is that recovering it
     * requires the struct, and nothing else. */
    {
        uint64_t h = ch58_fnv1a64((const uint8_t *)s->user, n);
        int      i;
        h ^= now;
        for (i = 0; i < 16; i++) {
            s->key[i] = (uint8_t)((h >> ((i % 8) * 8)) & 0xFFu);
            h = h * 0x100000001B3ull + (uint64_t)i;
        }
    }

    return 0;
}

/* ================================================================== *
 * 7. The dense switch -- a jump table in .rodata.
 *
 * Twelve consecutive cases with no gaps is exactly the shape clang turns
 * into a table of offsets plus an indirect branch. On AArch64 the emitted
 * idiom is roughly:
 *
 *     adrp x8, <table>          ; page address of the jump table
 *     add  x8, x8, #:lo12:<table>
 *     ldrsw x9, [x8, x9, lsl #2] ; sign-extended 32-bit offset from the table
 *     add  x9, x8, x9
 *     br   x9                    ; branch to the case body
 *
 * The exact instructions your build produces are printed by build.sh; read
 * them there rather than trusting this comment, because the shape depends on
 * the clang version and the case count.
 * ================================================================== */

CH58_EXPORT int session_step(session_ctx *s, int opcode,
                             const uint8_t *in, size_t n)
{
    uint32_t d;

    /* The inlined predicate. At -O2 there is no `bl session_magic_ok` here;
     * the two-instruction body is spliced in. */
    if (!session_magic_ok(s)) {
        return -1;
    }
    if (s->state == ST_DEAD) {
        return -1;
    }

    s->step_count++;

    switch (opcode) {
    case 0:  /* OPEN */
        s->state = ST_OPEN;
        return 0;

    case 1:  /* CLOSE */
        s->state = ST_DEAD;
        return 0;

    case 2:  /* TOUCH */
        s->issued_at++;
        return 0;

    case 3:  /* MARK PRIVILEGED -- the interesting one */
        s->flags |= FLAG_PRIVILEGED;
        return 0;

    case 4:  /* CLEAR PRIVILEGED */
        s->flags &= ~FLAG_PRIVILEGED;
        return 0;

    case 5:  /* MARK EXPIRED */
        s->flags |= FLAG_EXPIRED;
        return 0;

    case 6:  /* DIGEST WITH CRC */
    case 7:  /* DIGEST WITH FNV */
    case 8:  /* DIGEST WITH THE ROLLING SUM */
        /* The index is computed from the opcode, so the call target is not
         * a compile-time constant and clang must emit a `blr`. This is the
         * one branch in the library that no static tool can follow on its
         * own -- section 3.5 covers what each tool lets you do about it. */
        if (in == NULL) { return -1; }
        d = digest_table[opcode - 6](in, n);
        s->crc = d;
        return 0;

    case 9:  /* MIX THE KEY */
        if (in == NULL || n == 0) { return -1; }
        {
            size_t i;
            for (i = 0; i < 16; i++) {
                s->key[i] ^= in[i % n];
            }
        }
        return 0;

    case 10: /* DEBUG FLAG */
        s->flags |= FLAG_DEBUG;
        return 0;

    case 11: /* SUICIDE -- the noreturn path */
        session_fatal(11);

    default:
        s->state = ST_INVALID;
        return -1;
    }
}

/* ================================================================== *
 * 8. The tail call, and the specialised inline.
 *
 * TWO constructs live here and they are easy to confuse.
 *
 * session_slow_path is marked noinline, so `return session_slow_path(...)`
 * in tail position compiles to a `b` rather than a `bl` plus `ret`. In a
 * listing the caller appears to simply end; in a call graph the edge is a
 * jump. Section 6 covers how each tool renders it.
 *
 * session_dispatch then calls session_step, which clang DOES inline -- and
 * because `in` is provably NULL at that call site, the inlined copy is a
 * SPECIALISED copy: cases 6 to 9 collapse into the shared error return and
 * the second jump table points four of its twelve entries at the same
 * address. Measured; the byte tables are printed by build.sh. Two functions
 * with near-identical source therefore disassemble to visibly different
 * code, which is the cheapest available demonstration that "the decompiler
 * shows the source" is false.
 * ================================================================== */

__attribute__((noinline))
static int session_slow_path(session_ctx *s, int opcode)
{
    if (s == NULL) {
        return -1;
    }
    s->reserved++;
    return session_step(s, opcode, NULL, 0);
}

CH58_EXPORT int session_dispatch(session_ctx *s, int opcode)
{
    if (opcode < 0) {
        return -1;
    }
    /* Tail position: expect `b session_slow_path`, not `bl` + `ret`. */
    return session_slow_path(s, opcode);
}

/* ================================================================== *
 * 9. Sealing -- where the struct, the archive code and the obfuscated
 *    strings all meet.
 * ================================================================== */

CH58_EXPORT int session_seal(session_ctx *s)
{
    char su_path[16];
    char prop[16];

    if (!session_magic_ok(s)) {
        return -1;
    }
    if (s->state != ST_OPEN) {
        return -2;
    }

    /* The two strings exist here and only here. Break on this function and
     * read the stack, and you have both; read the file with `strings` and you
     * have neither. */
    session_reveal(su_path, obf_su_path, sizeof(obf_su_path));
    session_reveal(prop, obf_debuggable, sizeof(obf_debuggable));

    /* Deliberately NOT a root check. It compares the decoded strings against
     * themselves so the fixture has no behaviour that depends on the device
     * it runs on -- a fixture whose result changes per device is useless as
     * an answer key. The strings are here to be recovered, not obeyed. */
    if (su_path[0] == '/' && prop[0] == 'r') {
        s->flags |= FLAG_SEALED;
    }

    s->crc   = ch58_crc32((const uint8_t *)s, offsetof(session_ctx, crc));
    s->state = ST_SEALED;
    return 0;
}

/* ================================================================== *
 * 10. A reader for the sealed state, so the labs have something to
 *     interrogate.
 * ================================================================== */

CH58_EXPORT int session_report(const session_ctx *s, char *out, size_t cap)
{
    char hex[2 * 16 + 1];

    if (s == NULL || out == NULL || cap < 96) {
        return -1;
    }
    if (!(s->flags & FLAG_SEALED)) {
        out[0] = '\0';
        return -2;
    }

    ch58_hex(hex, s->key, sizeof(s->key));

    /* Assembled by hand rather than with snprintf, so that the format string
     * is not sitting in .rodata announcing the field order. */
    {
        size_t p = 0;
        size_t i;
        const char *u = s->user;

        for (i = 0; u[i] != '\0' && p + 1 < cap; i++) { out[p++] = u[i]; }
        if (p + 1 < cap) { out[p++] = ':'; }
        for (i = 0; hex[i] != '\0' && p + 1 < cap; i++) { out[p++] = hex[i]; }
        out[p] = '\0';
        return (int)p;
    }
}

/* ================================================================== *
 * 11. The single JNI entry point.
 *
 * Statically registered, so the symbol is in .dynsym and survives stripping.
 * It exists so the library is recognisably an Android library; chapter 57
 * owns everything else about JNI.
 * ================================================================== */

CH58_EXPORT jint
Java_com_pentest_ch58_Session_nativeSelfTest(JNIEnv *env, jobject thiz)
{
    session_ctx s;
    char        report[128];
    int         rc;

    (void)env;
    (void)thiz;

    if (session_init(&s, "tester", 1700000000ull) != 0) { return -1; }
    if (session_dispatch(&s, 0) != 0)                   { return -2; }
    if (session_step(&s, 3, NULL, 0) != 0)              { return -3; }
    if (session_seal(&s) != 0)                          { return -4; }

    rc = session_report(&s, report, sizeof(report));
    return (jint)rc;
}
