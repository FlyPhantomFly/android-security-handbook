/*
 * 03-ctf-vault.c -- the target for chapter 59, lab 04 (CTF).
 *
 * PURPOSE
 *   A deliberately-vulnerable crackme built to punish one specific bad habit: patching
 *   the function whose name sounds like the security boundary.
 *
 *   It is designed so that PATCHING IS NOT ENOUGH. The flag is encrypted with a keystream
 *   derived from the licence key itself, so an attacker who patches the verifier to
 *   return success gets past the gate and receives GARBAGE, because no patch can
 *   manufacture key material that was never in the binary.
 *
 *   That is the lesson: a bypass defeats a CHECK; it cannot conjure a SECRET. Recovering
 *   the flag requires actually recovering the key.
 *
 * BUILD
 *       cd 59-radare2/examples && ./build.sh
 *   produces `ctfvault` (AArch64 PIE, 16 KiB-page safe) in the out-of-tree build dir.
 *
 * USAGE
 *       ./ctfvault <licence-key>
 *
 * SPOILER WARNING
 *   Solving lab 04 means recovering the key from the BINARY. This source file obviously
 *   contains the answer in structure if not in literal text. If you want the challenge,
 *   build it and do not read past this comment block.
 *
 * DESIGN NOTES (for the instructor, not the solver)
 *   - vault_probe_environment() is an upstream short-circuit guard, exactly as in
 *     01-r2-target.c. It fires on any device where /system/xbin/su exists -- which
 *     includes stock Google AVDs, measured on sdk_gphone16k_x86_64 (API 35).
 *   - vault_verify_token() is the tempting target. Patching it to return 1 opens the gate
 *     and produces a corrupt flag, because vault_reveal() re-derives the keystream from
 *     the SUPPLIED key rather than from the verifier's verdict.
 *   - The key is five lowercase letters, so exhaustive search is 26^5 = 11,881,376
 *     candidates -- a few seconds in C, well under a minute in Python. The hint string
 *     in the binary tells the solver the length and alphabet, so the search is bounded
 *     and fair.
 *   - FNV-1a is not invertible, which is the point: the solver must brute force, or
 *     notice the algorithm's published constants and reason about it.
 *
 * ETHICS
 *   This is a target you compile yourself. Nothing here should be pointed at software you
 *   do not own.
 *
 * Compiles clean with -Wall -Wextra under aarch64-linux-android21-clang (NDK 25.2.9519653).
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* "/system/xbin/su" XOR 0xA7 -- see 01-r2-target.c for why this leaks at -O2 anyway. */
static const unsigned char k_enc_path[] = {
    0x88, 0xd4, 0xde, 0xd4, 0xd3, 0xc2, 0xca, 0x88,
    0xdf, 0xc5, 0xce, 0xc9, 0x88, 0xd4, 0xd2
};

/* The flag, XOR-ed with an xorshift32 keystream seeded by FNV-1a(correct key).
 * Recovering this requires the KEY, not merely a bypass. */
static const unsigned char k_enc_flag[] = {
    0x69, 0x7d, 0x0d, 0xb2, 0x06, 0x77, 0x2a, 0x0f,
    0x73, 0x99, 0xac, 0x9a, 0x70, 0x1c, 0x29, 0x60,
    0xa9, 0xb2, 0x1d, 0x31, 0x06, 0x35, 0x3f, 0x7f,
    0x94, 0x18, 0x34, 0x43, 0x5d, 0x47, 0x25, 0x9d,
    0x62, 0x3f, 0xff, 0x14, 0x60, 0x17, 0xa5, 0x40,
    0xcd, 0x07
};

/* Deliberate, fair hint -- bounds the search space so the challenge is solvable. */
static const char k_hint[] = "licence keys are five lowercase letters";

/* ---------------------------------------------------------------------------------- */

static uint32_t fnv1a(const char *s)
{
    uint32_t h = 0x811c9dc5u;
    size_t i;

    if (s == NULL) {
        return 0;
    }
    for (i = 0; s[i] != '\0'; i++) {
        h ^= (unsigned char)s[i];
        h *= 0x01000193u;
    }
    return h;
}

/* xorshift32 -- a tiny PRNG. Its three shift constants (13, 17, 5) are as recognisable
 * in disassembly as FNV-1a's multiplier, and identifying it is part of the puzzle. */
static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;

    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/*
 * The upstream guard. Runs FIRST and short-circuits everything below it.
 * This is the function that actually decides, and it is not the one with the
 * security-sounding name.
 */
__attribute__((noinline))
int vault_probe_environment(void)
{
    char buf[64];
    size_t i;

    for (i = 0; i < sizeof(k_enc_path); i++) {
        buf[i] = (char)(k_enc_path[i] ^ 0xA7);
    }
    buf[sizeof(k_enc_path)] = '\0';

    return access(buf, F_OK) == 0 ? 1 : 0;
}

/*
 * The tempting target. Patch this to `mov w0,#1; ret` and the gate opens -- and the flag
 * is still garbage, because vault_reveal() does not consult this function's verdict.
 */
__attribute__((noinline))
int vault_verify_token(const char *key)
{
    return fnv1a(key) == 0x6dc666d5u;
}

/*
 * The part a patch cannot help with: the keystream is re-derived from the SUPPLIED key.
 * Wrong key in, wrong flag out, regardless of what the verifier was patched to say.
 */
__attribute__((noinline))
void vault_reveal(const char *key, char *out, size_t outsz)
{
    uint32_t state = fnv1a(key);
    size_t n = sizeof(k_enc_flag);
    size_t i;

    if (outsz < n + 1) {
        n = (outsz > 0) ? outsz - 1 : 0;
    }
    for (i = 0; i < n; i++) {
        out[i] = (char)(k_enc_flag[i] ^ (unsigned char)(xorshift32(&state) & 0xFF));
    }
    out[n] = '\0';
}

__attribute__((noinline))
int vault_open(const char *key)
{
    if (vault_probe_environment()) {
        return 0;
    }
    if (!vault_verify_token(key)) {
        return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    char flag[64];
    const char *key;

    if (argc < 2) {
        printf("usage: %s <licence-key>\n", argv[0]);
        printf("hint: %s\n", k_hint);
        return 2;
    }
    key = argv[1];

    if (!vault_open(key)) {
        printf("vault sealed\n");
        return 1;
    }

    vault_reveal(key, flag, sizeof(flag));
    printf("vault open: %s\n", flag);
    return 0;
}
