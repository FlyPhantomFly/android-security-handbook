/*
 * examples/02-crcutil.h
 *
 * PURPOSE
 *   The public interface of a small "third-party utility library". It exists
 *   to be compiled into a STATIC archive (libcrcutil.a) and linked into
 *   01-session-target.c, so that the finished .so contains three functions
 *   that came from somewhere else.
 *
 *   That is the situation FLIRT (chapter 58 section 3.7) exists to solve: a
 *   stripped binary in which some functions are the application's own logic
 *   and some are library code you should not waste an afternoon reading. The
 *   only way to practise telling them apart is to build a binary where you
 *   know, for certain, which is which.
 *
 * BUILD
 *   Do not compile this file directly. Run examples/build.sh, which builds
 *   the archive and the library out of tree.
 *
 * AUTHORISED TESTING ONLY. This is your own code; analyse it freely.
 */

#ifndef CH58_CRCUTIL_H
#define CH58_CRCUTIL_H

#include <stddef.h>
#include <stdint.h>

/*
 * CRC-32 (IEEE 802.3, reflected, polynomial 0xEDB88320).
 *
 * Deliberately the table-driven form. The 256-entry table is emitted into
 * .rodata and its first words are a recognisable constant sequence, which is
 * how you identify this function without any symbol at all. Chapter 57's
 * "crypto fingerprints" table lists 0xEDB88320 for exactly this reason -- and
 * warns that finding it is NOT evidence of encryption.
 */
uint32_t ch58_crc32(const uint8_t *data, size_t len);

/*
 * FNV-1a, 64-bit. Two magic constants, no table:
 *   offset basis 0xCBF29CE484222325, prime 0x100000001B3.
 * The prime does not fit an AArch64 immediate, so the compiler must
 * materialise it with a movz/movk chain -- see the ground-truth listing in
 * examples/03-ground-truth-aarch64.md.
 */
uint64_t ch58_fnv1a64(const uint8_t *data, size_t len);

/*
 * Lower-case hex encode. Writes 2*len bytes plus a NUL, so `out` must have
 * room for 2*len+1. Included because it is the single most common helper in
 * real Android native code and therefore the single most common function you
 * will identify and then ignore.
 */
void ch58_hex(char *out, const uint8_t *data, size_t len);

#endif /* CH58_CRCUTIL_H */
