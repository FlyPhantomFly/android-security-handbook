/*
 * libvault.c — the CTF target for labs/lab-04-ctf-the-honest-trampoline.md.
 *
 * INSTRUCTOR NOTE — read this only after attempting the lab, or you will spoil
 * it for yourself. Everything a solver needs is in the lab file.
 *
 * WHAT IT IS
 *   A single exported function, vault_open(pin, out, outlen), which returns:
 *        0  success, and writes the flag into `out`
 *       -1  wrong pin
 *       -2  TAMPERED — the function noticed that its own prologue changed
 *
 *   Three defences, layered so that the obvious attack fails and the
 *   understanding-based attack succeeds:
 *
 *   1. The PIN IS NOT IN THE BINARY IN CLEARTEXT. It is stored XORed with a
 *      one-byte key and decoded onto the stack immediately before the
 *      comparison. `strings` finds nothing. That closes the lazy path and
 *      forces the solver to observe runtime data rather than read the file.
 *
 *   2. THE CHECK FUNCTION IS INLINED. vault_pin_ok() has external linkage, so
 *      it is exported and dlsym finds it — and clang at -O2 also inlines its
 *      body into vault_open, so nothing calls the standalone copy. A hook on
 *      vault_pin_ok installs perfectly and changes nothing. This is the same
 *      failure ../examples/libinline.c isolates, restaged as a trap.
 *
 *   3. VAULT_OPEN CHECKSUMS ITS OWN PROLOGUE. A constructor records the sum of
 *      the first eight instruction words at load time. Every call recomputes it.
 *      An inline hook on vault_open — the natural next move once (2) has failed
 *      — overwrites those words and is caught, returning -2.
 *
 * THE INTENDED SOLUTION, and why it is the lesson
 *   The inlined copy of the comparison still calls strcmp, and strcmp is an
 *   IMPORT, reached through this library's PLT. A PLT/GOT hook replaces one
 *   pointer in a data table. It modifies NO INSTRUCTIONS, so the prologue
 *   checksum is unchanged and defence 3 never fires.
 *
 *   And the hook does better than bypass: strcmp's second argument is the
 *   decoded pin, in cleartext, at the moment of comparison. The solver can read
 *   the real pin out of the hook, remove the hook entirely, and open the vault
 *   legitimately. That two-stage arc — hook to OBSERVE, then act on what you
 *   learned — is the honest use of the technique and the point of the exercise.
 *
 *   A tamper check that guards code is blind to a hook that only touches data.
 *
 * BUILD
 *   $NDK/aarch64-linux-android21-clang -shared -O2 -fPIC -o libvault.so libvault.c
 *   $NDK/aarch64-linux-android21-clang -O1 -o vault-runner vault-runner.c -ldl
 *   (or run ./build-ctf.sh in this directory)
 *
 * WHAT THIS FILE IS NOT
 *   It is not a model of how to protect anything. A self-checksum over eight
 *   words, with the baseline stored in writable memory in the same process, is
 *   defeated by writing to that baseline. It is here to be understood and
 *   walked around, and the lab says so.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* The PIN, and its NUL terminator, with every byte XORed by 0x5A. Not
   cryptography — just enough that `strings libvault.so` shows nothing useful,
   which is the point: the solver must observe the runtime, not read the file. */
static const unsigned char PIN_ENC[] = {
    0x6b, 0x69, 0x6d, 0x63, 0x77, 0x3b, 0x36, 0x2a, 0x32, 0x3b, 0x5a
};

/* The flag, and its NUL terminator, XORed byte-wise with 0x3C. */
static const unsigned char FLAG_ENC[] = {
    0x7f, 0x74, 0x0a, 0x09, 0x47, 0x5b, 0x53, 0x48, 0x63, 0x4f, 0x50, 0x53,
    0x48, 0x63, 0x5e, 0x59, 0x5d, 0x48, 0x4f, 0x63, 0x48, 0x59, 0x44, 0x48,
    0x63, 0x5f, 0x54, 0x59, 0x5f, 0x57, 0x4f, 0x49, 0x51, 0x41, 0x3c
};

/*
 * THE KEYS MUST BE `volatile`, AND THE REASON IS A LESSON IN ITSELF.
 *
 * The first version of this file wrote them as `#define PIN_KEY 0x5A`. clang at
 * -O2 then saw a constant array XORed with a constant key, evaluated the whole
 * loop at compile time, and emitted the DECODED strings straight into .rodata.
 * `strings libvault.so` printed "1379-alp" and "CH65{got_slot_beats_text_checksu"
 * and the challenge was over before it began.
 *
 * `volatile` forbids the compiler from assuming the value it just stored is the
 * value it will read back, so the fold cannot happen and the decode really does
 * run at runtime. Verify it yourself after building:
 *
 *     strings libvault.so | grep -Ei 'CH65|1379'      # must print nothing
 *
 * The same constant-folding effect is why so much real "string obfuscation" is
 * useless: if the key is a compile-time constant, the optimiser is a
 * deobfuscator that ships with your toolchain.
 */
static volatile unsigned char g_pin_key  = 0x5A;
static volatile unsigned char g_flag_key = 0x3C;

/* Baseline prologue checksum, captured at load time by the constructor. */
static uint32_t g_baseline = 0;
static int      g_armed    = 0;

int vault_open(const char *pin, char *out, size_t outlen);

/* Sum the first `words` instruction words of `fn`. */
static uint32_t prologue_sum(const void *fn, int words) {
    const uint32_t *p = (const uint32_t *)fn;
    uint32_t s = 0;
    for (int i = 0; i < words; i++) s = (s * 31u) + p[i];
    return s;
}

__attribute__((constructor))
static void vault_arm(void) {
    g_baseline = prologue_sum((const void *)&vault_open, 8);
    g_armed = 1;
}

/*
 * Exported, hookable — and inlined into vault_open at -O2, so hooking it here
 * accomplishes nothing. That is deliberate.
 */
int vault_pin_ok(const char *pin) {
    char real[sizeof(PIN_ENC)];
    size_t i;
    if (!pin) return 0;
    /* The terminator is encoded too, so this loop decodes it as well. */
    for (i = 0; i < sizeof(PIN_ENC); i++)
        real[i] = (char)(PIN_ENC[i] ^ g_pin_key);
    return strcmp(pin, real) == 0;      /* <- the PLT call the solution uses */
}

int vault_open(const char *pin, char *out, size_t outlen) {
    size_t i;

    if (g_armed && prologue_sum((const void *)&vault_open, 8) != g_baseline)
        return -2;                       /* my own code changed under me */

    if (!vault_pin_ok(pin)) return -1;

    if (outlen < sizeof(FLAG_ENC)) return -3;
    for (i = 0; i < sizeof(FLAG_ENC); i++)
        out[i] = (char)(FLAG_ENC[i] ^ g_flag_key);
    return 0;
}
