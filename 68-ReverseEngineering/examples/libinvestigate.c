/*
 * libinvestigate.c -- the purpose-built target for chapter 68's labs.
 *
 * PURPOSE
 *   This library exists to be reverse engineered. It is not a demonstration of
 *   a vulnerability and it is not a realistic app. It is a *fixture*: every
 *   structure in it was placed to make one specific investigative mistake
 *   attractive, so that the lab can walk you into the mistake and back out of
 *   it with the ground truth in hand.
 *
 *   You own this binary. You compiled it. That means every claim you make
 *   about it is checkable against the source -- which is the only setting in
 *   which you can honestly grade your own reverse engineering.
 *
 * BUILD
 *   ./build.sh          (see build.sh -- builds OUT OF TREE, into $TMPDIR)
 *
 *   Or by hand, from this directory:
 *     NDK=$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin
 *     $NDK/aarch64-linux-android21-clang -Wall -Wextra -O2 -fPIC -shared \
 *         -o /tmp/ch68/libinvestigate.so libinvestigate.c
 *
 * THE FOUR TRAPS, STATED HONESTLY
 *   Read this list AFTER you have done lab 02, not before. It is the answer key.
 *
 *   TRAP 1 -- The obvious function is dead.
 *       `iv_check_license` is exported, is named exactly what you would grep
 *       for, contains a comparison against a plausible key, and is called by
 *       nothing. Patching it, hooking it, or reading it carefully all produce
 *       confident, correct-looking, useless results.
 *
 *   TRAP 2 -- The real decision is inlined.
 *       The gate that actually runs lives inside `iv_open_vault`, written as
 *       a `static inline` helper the compiler folds into its caller at -O2.
 *       There is no symbol for it and no `bl` targeting it.
 *
 *   TRAP 3 -- The value is produced far from where it is consumed.
 *       `iv_derive_seed` computes a byte and stores it in a struct field. The
 *       consumer reads it hundreds of instructions later, in another function.
 *       Control-flow tracking does not connect them; data-flow tracking does.
 *       This is the case chapter 37's lab 04 defers here.
 *
 *   TRAP 4 -- The visible string is not the answer.
 *       `.rodata` contains a decoy that matches every flag-shaped regex you
 *       own. The real output is assembled at runtime and never exists in the
 *       file. `strings` finds the decoy in under a second and it is wrong.
 *
 * ETHICS
 *   Purpose-built lab target. Reverse engineer this, apps you own, and
 *   deliberately-vulnerable training apps. Nothing else without written
 *   authorisation -- see the chapter's section 1.6.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* TRAP 4: the decoy. This is the string `strings` will hand you.       */
/* ------------------------------------------------------------------ */
static const char kDecoy[] = "CH68{n0t_th3_r3al_0ne_keep_going}";

/*
 * The real answer is never stored. These are the XOR-masked bytes; the
 * plaintext appears only in a stack buffer, only while the gate is open.
 *
 * WHY THE MASK IS THE SEED AND NOT A CONSTANT -- this is a measurement, not a
 * design preference. The first version of this file masked with a literal
 * `#define MASK 0xc7`. Built at -O2, clang constant-folded the entire
 * decode loop and deposited the finished plaintext in `.rodata`, where
 * `strings` printed it immediately. The obfuscation was defeated by the
 * compiler before any attacker arrived.
 *
 * Masking with `g_state.seed` -- a mutable global written at runtime -- is
 * not foldable, so the plaintext genuinely does not exist in the file. The
 * chapter's section 3.9 uses this as its worked example of an artefact that
 * disagrees with the source it was built from, because it is one that
 * happened here rather than one that was invented for the page.
 */
static const uint8_t kMasked[] = {
    0xfe, 0xf5, 0x8b, 0x85, 0xc6, 0xd8, 0xcb, 0x8c,
    0xd9, 0xd8, 0xd3, 0xde, 0xd8, 0xe2, 0xdf, 0x8e,
    0xdc, 0xc9, 0xce, 0xe2, 0xdc, 0xe2, 0xda, 0xd2,
    0xd2, 0xd9, 0xe2, 0xce, 0xc9, 0xd2, 0xcf, 0xc4,
    0xc0
};

/* ------------------------------------------------------------------ */
/* TRAP 3: producer and consumer, deliberately far apart.              */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t magic;      /* 0: never changes, pure noise                    */
    uint8_t  seed;       /* 1: THE value -- produced here, consumed in the  */
                         /*    vault gate, with no call edge between them   */
    uint8_t  attempts;   /* 2: incremented, read by nothing that matters    */
    uint16_t pad;        /* 3: alignment                                    */
} iv_state_t;

static iv_state_t g_state = { 0x5647494Eu, 0u, 0u, 0u };

/*
 * Produces the seed. Note what this function does NOT do: it does not decide
 * anything, it does not return the seed, and it does not name it. It writes a
 * byte into a global and returns a status nobody checks. A reader following
 * call edges out of main will walk straight past it.
 */
int iv_derive_seed(const char *key)
{
    size_t i;
    uint8_t acc = 0x3fu;

    if (key == NULL)
        return -1;

    for (i = 0; key[i] != '\0'; i++)
        acc = (uint8_t)((acc << 1) ^ (uint8_t)key[i]);

    g_state.seed = acc;
    g_state.attempts++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* TRAP 1: the dead function. Exported, obvious, and called by nothing. */
/* ------------------------------------------------------------------ */
/*
 * Everything about this function says "I am the check". It is exported so it
 * shows up in `llvm-nm -D`. It is named so it shows up in your grep. It
 * compares against a literal so it shows up in `strings`. It returns the
 * boolean you were hoping to find.
 *
 * It is called by nothing. Confirm that yourself:
 *     llvm-objdump -d libinvestigate.so | grep -c 'bl.*<iv_check_license>'
 * The answer is 0, and the chapter's whole method is built around the habit
 * that produced that command instead of a conclusion.
 */
int iv_check_license(const char *license)
{
    if (license == NULL)
        return 0;
    return strcmp(license, "PREMIUM-2024-VALID") == 0;
}

/* ------------------------------------------------------------------ */
/* TRAP 2: the real gate, inlined into its only caller.                */
/* ------------------------------------------------------------------ */
/*
 * `static inline` plus -O2 means clang folds this into iv_open_vault. After
 * compilation there is no `gate_is_open` symbol, no call site, and no single
 * branch you can point at and call "the check" -- its condition is fused into
 * the caller's control flow. The source has a function; the binary does not.
 */
static inline int gate_is_open(uint8_t seed)
{
    return seed == 0xbdu;
}

/*
 * The only entry point that matters.
 *
 * `out` receives the answer on success and is left untouched on failure.
 * Returns 1 when the vault opened, 0 when it did not.
 */
int iv_open_vault(const char *key, char *out, size_t outlen)
{
    size_t i, n;

    if (key == NULL || out == NULL || outlen == 0)
        return 0;

    if (iv_derive_seed(key) != 0)
        return 0;

    /* The consumer. g_state.seed was written by another function, and the
     * only thing connecting the two is the memory location. */
    if (!gate_is_open(g_state.seed))
        return 0;

    n = sizeof(kMasked);
    if (outlen < n + 1)
        return 0;

    /*
     * The mask is the runtime seed, read through a `volatile` lvalue. Both
     * halves of that sentence were forced by measurement -- see the comment on
     * kMasked, and read this one before you decide the `volatile` is cargo
     * cult, because it is the more interesting of the two:
     *
     * Masking with `g_state.seed` alone was STILL folded away. The reason is
     * worth sitting with. Control flow only reaches this line when
     * `gate_is_open(g_state.seed)` was true, and that function is `seed ==
     * 0xbd`. So on this path the compiler has *proved* the seed's value, and
     * it happily substitutes the constant it just proved and folds the loop.
     *
     * The check that guards the secret is what told the compiler the secret.
     *
     * A `volatile` read is defined as observable behaviour, so the optimiser
     * must actually load it and cannot propagate the proven value into it.
     * This is the same reason 19-Memory's scrubbing example uses a `volatile`
     * loop rather than a plain one.
     */
    {
        volatile uint8_t mask = g_state.seed;
        for (i = 0; i < n; i++)
            out[i] = (char)(kMasked[i] ^ mask);
    }
    out[n] = '\0';
    return 1;
}

/*
 * Returns the decoy. Exists so that a `strings`-first workflow finds something
 * and stops. Referenced so the string is not dead-stripped.
 */
const char *iv_banner(void)
{
    return kDecoy;
}

/* Reports how many times the seed was derived. Present only so that
 * g_state.attempts has a reader and is not optimised away. */
unsigned iv_attempts(void)
{
    return (unsigned)g_state.attempts;
}
