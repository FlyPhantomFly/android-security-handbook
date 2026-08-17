/*
 * examples/02-crcutil.c
 *
 * PURPOSE
 *   Three utility functions that stand in for "code somebody else wrote".
 *   examples/build.sh compiles this file on its own, puts the object into a
 *   static archive (libcrcutil.a), and links that archive into the target
 *   library. The result is a stripped .so in which three of the functions are
 *   library code and the rest is application logic -- and nothing in the
 *   binary says which is which.
 *
 *   That is the exact problem FLIRT solves, and you cannot practise solving it
 *   on a binary where you do not already know the answer. Here you do: these
 *   three, and only these three.
 *
 *   scripts/01-make-flirt-pat.py reads the archive this file produces and
 *   emits FLAIR .pat lines for it. Both halves of the exercise therefore come
 *   from code in this directory.
 *
 * WHY THESE THREE
 *   ch58_crc32     table-driven, so it carries a 1 KiB constant table whose
 *                  first words identify it with no code analysis at all
 *   ch58_fnv1a64   no table, two 64-bit magic constants that AArch64 cannot
 *                  encode as immediates -- a movz/movk chain instead
 *   ch58_hex       tiny, boring, and present in almost every real library;
 *                  the archetype of a function you want a signature to name
 *                  so that you never read it
 *
 * BUILD
 *   Do not compile directly. Run examples/build.sh.
 *   Verified clean with -Wall -Wextra under NDK 25.2.9519653 (clang 14.0.7).
 *
 * AUTHORISED TESTING ONLY. This is your own code.
 */

#include "02-crcutil.h"

/* ------------------------------------------------------------------ */
/* CRC-32, IEEE 802.3, reflected form, polynomial 0xEDB88320.          */
/*                                                                     */
/* The table is built once on first use rather than being a static     */
/* initialiser. That is deliberate: it means the .rodata does NOT      */
/* contain the table, and a reader looking for the classic             */
/* 00000000 77073096 EE0E612C ... signature in the file will not find  */
/* it. They will find the polynomial constant in the code instead.     */
/* Section 3.7 uses this to make a point about what a byte-pattern     */
/* signature can and cannot see.                                       */
/* ------------------------------------------------------------------ */

static uint32_t crc_table[256];
static int      crc_table_ready = 0;

static void crc32_build_table(void)
{
    uint32_t i;
    for (i = 0; i < 256u; i++) {
        uint32_t c = i;
        int k;
        for (k = 0; k < 8; k++) {
            /* 0xEDB88320 is the reflected form of 0x04C11DB7. Both appear in
             * chapter 57's fingerprint table. Neither is encryption. */
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc_table[i] = c;
    }
    crc_table_ready = 1;
}

uint32_t ch58_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t   i;

    if (!crc_table_ready) {
        crc32_build_table();
    }
    for (i = 0; i < len; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ------------------------------------------------------------------ */
/* FNV-1a, 64-bit.                                                     */
/*                                                                     */
/* Both constants are 64-bit and neither is encodable as an AArch64    */
/* immediate, so clang materialises each with a movz plus up to three  */
/* movk instructions. Chapter 18 section 3.3 covers that encoding; the */
/* consequence here is that grepping the file for the bytes of         */
/* 0xCBF29CE484222325 finds NOTHING, because the constant never exists */
/* contiguously in the binary. It exists as four 16-bit fields spread  */
/* across four instruction words.                                      */
/* ------------------------------------------------------------------ */

uint64_t ch58_fnv1a64(const uint8_t *data, size_t len)
{
    uint64_t h = 0xCBF29CE484222325ull;   /* offset basis */
    size_t   i;

    for (i = 0; i < len; i++) {
        h ^= (uint64_t)data[i];
        h *= 0x100000001B3ull;            /* FNV prime */
    }
    return h;
}

/* ------------------------------------------------------------------ */
/* Lower-case hex encode.                                              */
/*                                                                     */
/* The lookup string "0123456789abcdef" IS in .rodata, and it is one   */
/* of the most reliable tells in a stripped Android library: find that */
/* string, look at what references it, and you have found the hex      */
/* encoder without reading a single instruction.                       */
/* ------------------------------------------------------------------ */

void ch58_hex(char *out, const uint8_t *data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[2 * i]     = digits[(data[i] >> 4) & 0x0Fu];
        out[2 * i + 1] = digits[data[i] & 0x0Fu];
    }
    out[2 * len] = '\0';
}
