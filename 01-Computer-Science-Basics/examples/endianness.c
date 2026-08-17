/* =============================================================================
 * endianness.c — how multi-byte values are actually laid out in memory
 * Chapter 01 — Computer Science Basics
 * Companion to labs/lab-01-binary-hex-endianness.md
 * =============================================================================
 *
 * WHAT THIS PROGRAM DEMONSTRATES
 *
 *   1. That a variable is nothing more than a run of bytes at an address.
 *   2. That the *order* of those bytes is a property of the machine, not of C.
 *   3. How to detect that order at runtime using a union (the classic trick)
 *      and how to detect it at compile time using the compiler's own macros.
 *   4. What an int, a short, a long and a float look like byte by byte.
 *   5. Why an IEEE-754 float that "looks like" 1.0 is really 0x3F800000.
 *   6. Where locals actually live relative to each other in the stack frame.
 *
 * WHY YOU SHOULD CARE (Android security)
 *
 *   Every binary format you will parse on Android declares an endianness:
 *   the DEX header has an explicit endian_tag field, the ELF header has
 *   EI_DATA at offset 5, ZIP is little-endian by specification. Meanwhile
 *   everything arriving over the network -- TLS record lengths, DNS packets,
 *   protobuf-over-HTTP framing, Java's DataOutputStream and the default order
 *   of java.nio.ByteBuffer -- is big-endian. A Frida script that reads a
 *   4-byte length from native memory and gets 0x78563412 instead of 0x12345678
 *   is not broken; it is reading the correct bytes in the wrong order.
 *
 * HOW TO COMPILE AND RUN
 *
 *   Host / WSL / macOS:
 *       gcc -O0 -g -Wall -Wextra -o endianness endianness.c
 *       ./endianness
 *
 *   Cross-compile for AArch64 and run under QEMU:
 *       aarch64-linux-gnu-gcc -O0 -g -static -o endianness_arm64 endianness.c
 *       qemu-aarch64 ./endianness_arm64
 *
 *   Build for a real Android device with the NDK (adjust API level / path):
 *       $ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/\
 *           aarch64-linux-android30-clang -O0 -g -o endianness_android endianness.c
 *       adb push endianness_android /data/local/tmp/
 *       adb shell chmod 755 /data/local/tmp/endianness_android
 *       adb shell /data/local/tmp/endianness_android
 *
 *   Then compare the output with the Python cross-check from the lab:
 *       python3 -c "import struct; print(struct.pack('=I', 0x12345678).hex(' '))"
 *
 * WHAT TO OBSERVE
 *
 *   - Section 2 prints 78 56 34 12 on every machine you will realistically use.
 *     x86-64 laptops, AArch64 Android phones and Apple Silicon Macs are all
 *     little-endian. AArch64 hardware is capable of big-endian data accesses
 *     (SCTLR_ELx.EE), but Android never configures it that way, which is why
 *     EI_DATA in every Android .so is 1 (ELFDATA2LSB).
 *   - Section 4 shows that the ASCII string is NOT reversed. Byte arrays and
 *     strings are stored in order; only multi-byte *numbers* are affected by
 *     endianness. The DEX header contains both kinds side by side, which is
 *     exactly why beginners get it wrong there.
 *   - Section 6 prints stack addresses that change on every run when ASLR is
 *     on, and are identical when you run under `setarch $(uname -m) -R`.
 * =============================================================================
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* -----------------------------------------------------------------------------
 * A union places every member at the SAME address. Writing through one member
 * and reading through another therefore shows you the raw bytes of the first.
 * This is the standard, portable-in-practice endianness probe.
 * -------------------------------------------------------------------------- */
union probe32 {
    uint32_t as_u32;      /* four bytes, interpreted as one number   */
    uint8_t  as_bytes[4]; /* the same four bytes, one at a time      */
};

/* Print `len` bytes starting at `p`, low address first, as hex. */
static void dump_bytes(const char *label, const void *p, size_t len)
{
    const unsigned char *b = (const unsigned char *)p;
    printf("  %-24s @ %p : ", label, p);
    for (size_t i = 0; i < len; i++)
        printf("%02x ", b[i]);
    printf("\n");
}

/* Print `len` bytes as binary, so you can see individual bits. */
static void dump_bits(const char *label, const void *p, size_t len)
{
    const unsigned char *b = (const unsigned char *)p;
    printf("  %-24s        : ", label);
    for (size_t i = 0; i < len; i++) {
        for (int bit = 7; bit >= 0; bit--)
            putchar((b[i] & (1u << bit)) ? '1' : '0');
        putchar(' ');
    }
    printf("\n");
}

/* Runtime endianness detection. Returns 1 for little-endian, 0 for big. */
static int is_little_endian(void)
{
    union probe32 u;
    u.as_u32 = 0x01020304u;
    /* If the LEAST significant byte (0x04) sits at the LOWEST address,
     * the machine is little-endian. */
    return u.as_bytes[0] == 0x04;
}

int main(void)
{
    printf("=====================================================================\n");
    printf(" endianness.c  --  what a variable really looks like in memory\n");
    printf("=====================================================================\n\n");

    /* ---------------------------------------------------------------------
     * SECTION 1 — how big is everything on THIS machine and ABI?
     *
     * The C standard guarantees only relative sizes (sizeof(char) == 1 and
     * char <= short <= int <= long <= long long). The exact widths come from
     * the ABI. Android's arm64-v8a and x86_64 ABIs are both LP64: long and
     * pointers are 64-bit, int stays 32-bit. Android's 32-bit ABIs
     * (armeabi-v7a, x86) are ILP32: long and pointers are 32-bit.
     * ------------------------------------------------------------------ */
    printf("SECTION 1 — type sizes on this machine (in bytes)\n");
    printf("  char        %2zu      short       %2zu\n", sizeof(char), sizeof(short));
    printf("  int         %2zu      long        %2zu\n", sizeof(int), sizeof(long));
    printf("  long long   %2zu      float       %2zu\n", sizeof(long long), sizeof(float));
    printf("  double      %2zu      void *      %2zu\n", sizeof(double), sizeof(void *));
    printf("  size_t      %2zu      uintptr_t   %2zu\n", sizeof(size_t), sizeof(uintptr_t));
    printf("  --> this is an %s ABI\n\n",
           (sizeof(void *) == 8 && sizeof(long) == 8) ? "LP64 (64-bit)" : "ILP32 (32-bit)");

    /* ---------------------------------------------------------------------
     * SECTION 2 — the union probe, the classic endianness test
     * ------------------------------------------------------------------ */
    printf("SECTION 2 — union probe with the value 0x12345678\n");
    {
        union probe32 u;
        u.as_u32 = 0x12345678u;

        printf("  value written : 0x%08x\n", u.as_u32);
        dump_bytes("bytes in memory", u.as_bytes, 4);
        printf("  as_bytes[0] = 0x%02x  (byte at the LOWEST address)\n", u.as_bytes[0]);
        printf("  as_bytes[3] = 0x%02x  (byte at the HIGHEST address)\n", u.as_bytes[3]);

        if (u.as_bytes[0] == 0x78) {
            printf("  --> LITTLE-ENDIAN: least significant byte first.\n");
            printf("      This is x86, x86-64, and every Android ABI.\n");
        } else if (u.as_bytes[0] == 0x12) {
            printf("  --> BIG-ENDIAN: most significant byte first.\n");
            printf("      This is 'network byte order' and some legacy CPUs.\n");
        } else {
            printf("  --> MIXED / MIDDLE-ENDIAN. Historically real (PDP-11), "
                   "practically extinct.\n");
        }
        printf("  helper function is_little_endian() says: %d\n\n", is_little_endian());
    }

    /* ---------------------------------------------------------------------
     * SECTION 3 — the same value seen through pointer casts
     *
     * A pointer cast changes only the INTERPRETATION applied to the bytes.
     * The bytes themselves never move. This is the single most important
     * idea in the whole file.
     * ------------------------------------------------------------------ */
    printf("SECTION 3 — one 32-bit value, four interpretations\n");
    {
        uint32_t value = 0xDEADBEEFu;
        uint8_t  *as_u8  = (uint8_t *)&value;
        uint16_t *as_u16 = (uint16_t *)&value;
        int32_t  *as_i32 = (int32_t *)&value;

        printf("  uint32_t value      = 0x%08x  (%u unsigned)\n", value, value);
        printf("  read as int32_t     = %d        <-- SAME BITS, signed reading\n", *as_i32);
        printf("  read as two uint16  = 0x%04x 0x%04x\n", as_u16[0], as_u16[1]);
        printf("  read as four uint8  = 0x%02x 0x%02x 0x%02x 0x%02x\n",
               as_u8[0], as_u8[1], as_u8[2], as_u8[3]);
        dump_bits("bit pattern", &value, 4);
        printf("  NOTE: 0xDEADBEEF as a signed 32-bit int is negative because the\n");
        printf("        top bit is set. Two's complement: %d == %u - 2^32.\n\n",
               *as_i32, value);
    }

    /* ---------------------------------------------------------------------
     * SECTION 4 — short, int, long, and a STRING side by side
     *
     * Watch carefully: the numbers are byte-reversed, the string is not.
     * ------------------------------------------------------------------ */
    printf("SECTION 4 — numbers are reordered, byte arrays are not\n");
    {
        uint16_t s   = 0x1234;
        uint32_t i   = 0x12345678u;
        uint64_t l   = 0x1122334455667788ull;
        char     str[9] = "dex\n035";   /* the real DEX magic, minus its NUL */

        dump_bytes("uint16_t 0x1234", &s, sizeof(s));
        dump_bytes("uint32_t 0x12345678", &i, sizeof(i));
        dump_bytes("uint64_t 0x1122...88", &l, sizeof(l));
        dump_bytes("char[] \"dex\\n035\"", str, 8);
        printf("  --> The string reads 64 65 78 0a 30 33 35 00 in order: 'd','e','x',\n");
        printf("      newline, '0','3','5', NUL. That is the DEX magic exactly as it\n");
        printf("      appears in `xxd -l 8 classes.dex`. Strings are byte arrays and\n");
        printf("      byte arrays are never byte-swapped.\n\n");
    }

    /* ---------------------------------------------------------------------
     * SECTION 5 — IEEE-754 floating point
     *
     * A float is 1 sign bit, 8 exponent bits (biased by 127), and 23 mantissa
     * bits. It is not a number in the sense an int is; it is a packed
     * structure. Reading it with the wrong type produces spectacular garbage,
     * which is why Frida scripts must call readFloat() and not readU32().
     * ------------------------------------------------------------------ */
    printf("SECTION 5 — floats are packed structures, not plain numbers\n");
    {
        float    f = 1.0f;
        uint32_t f_bits;
        memcpy(&f_bits, &f, sizeof(f_bits));   /* memcpy is the strictly-correct
                                                * way to reinterpret; it avoids
                                                * strict-aliasing undefined behaviour */

        dump_bytes("float 1.0f", &f, sizeof(f));
        dump_bits("float 1.0f bits", &f, sizeof(f));
        printf("  as uint32_t         = 0x%08x\n", f_bits);
        printf("  sign bit            = %u\n", (f_bits >> 31) & 1u);
        printf("  exponent (biased)   = %u  -> real exponent %d\n",
               (f_bits >> 23) & 0xFFu, (int)((f_bits >> 23) & 0xFFu) - 127);
        printf("  mantissa            = 0x%06x\n", f_bits & 0x7FFFFFu);
        printf("  --> 1.0 = +1 x 2^0 x 1.0, so exponent field = 127 = 0x7F and the\n");
        printf("      mantissa is all zeros, giving the famous 0x3F800000.\n");

        float g = 0.1f;
        memcpy(&f_bits, &g, sizeof(f_bits));
        dump_bytes("float 0.1f", &g, sizeof(g));
        printf("  0.1f as uint32_t    = 0x%08x\n", f_bits);
        printf("  0.1f printed to 20dp: %.20f\n", (double)g);
        printf("  --> 0.1 is not representable in binary, exactly as 1/3 is not\n");
        printf("      representable in decimal. This is why money is never stored\n");
        printf("      in a float, and why comparing floats with == is a bug.\n\n");

        double d = 1.0;
        dump_bytes("double 1.0", &d, sizeof(d));
        printf("  --> A double is 1 sign + 11 exponent (bias 1023) + 52 mantissa bits,\n");
        printf("      so 1.0 is 0x3FF0000000000000.\n\n");
    }

    /* ---------------------------------------------------------------------
     * SECTION 6 — where do variables actually live?
     *
     * Compare the addresses printed here against /proc/self/maps from Lab 02.
     * The stack address is high, the heap address is much lower, and the
     * address of a string literal is lower still and inside a read-only
     * mapping of the executable itself.
     * ------------------------------------------------------------------ */
    printf("SECTION 6 — addresses: stack vs heap vs code vs rodata\n");
    {
        int              stack_var    = 42;
        static int       static_var   = 43;      /* .data  */
        static int       bss_var;                /* .bss   */
        const char      *literal      = "I live in .rodata";
        void            *heap_var     = malloc(64);

        printf("  &stack_var (stack)   = %p\n", (void *)&stack_var);
        printf("  heap_var   (heap)    = %p\n", heap_var);
        printf("  &static_var (.data)  = %p\n", (void *)&static_var);
        printf("  &bss_var    (.bss)   = %p   (value %d, zero-initialised for free)\n",
               (void *)&bss_var, bss_var);
        printf("  literal     (.rodata)= %p   \"%s\"\n", (const void *)literal, literal);
        printf("  &main       (.text)  = %p\n", (void *)(uintptr_t)main);

        printf("\n  Sorted low to high, you will normally see:\n");
        printf("    .text  <  .rodata  <  .data  <  .bss  <  heap  <<  stack\n");
        printf("  Run this twice. With ASLR enabled every address changes. Run it as\n");
        printf("    setarch $(uname -m) -R ./endianness\n");
        printf("  and they stop changing. That is Lab 02's ASLR demonstration, from\n");
        printf("  inside the process instead of from /proc.\n");

        free(heap_var);
    }

    /* ---------------------------------------------------------------------
     * SECTION 7 — compile-time detection
     *
     * GCC and Clang both define __BYTE_ORDER__. Use this in real code rather
     * than the runtime union probe, because the compiler can then fold the
     * branch away entirely.
     * ------------------------------------------------------------------ */
    printf("\nSECTION 7 — what the COMPILER thinks, decided at build time\n");
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__)
  #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    printf("  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__\n");
  #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    printf("  __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__\n");
  #else
    printf("  __BYTE_ORDER__ is something unusual\n");
  #endif
#else
    printf("  __BYTE_ORDER__ is not defined by this compiler; "
           "fall back to the runtime probe.\n");
#endif
    printf("  runtime probe agrees: %s\n",
           is_little_endian() ? "little-endian" : "big-endian");

    /* ---------------------------------------------------------------------
     * SECTION 8 — manual byte swapping
     *
     * This is what ntohl()/htonl() do, and what you must do by hand in a
     * Frida script when a native buffer holds big-endian network data.
     * ------------------------------------------------------------------ */
    printf("\nSECTION 8 — swapping byte order by hand\n");
    {
        uint32_t host_value = 0x12345678u;
        uint32_t swapped =
              ((host_value & 0x000000FFu) << 24)
            | ((host_value & 0x0000FF00u) <<  8)
            | ((host_value & 0x00FF0000u) >>  8)
            | ((host_value & 0xFF000000u) >> 24);

        printf("  original 0x%08x -> swapped 0x%08x\n", host_value, swapped);
        dump_bytes("original in memory", &host_value, 4);
        dump_bytes("swapped in memory ", &swapped, 4);
        printf("  --> On a little-endian machine, writing the SWAPPED value produces\n");
        printf("      the byte sequence a big-endian reader expects. That is exactly\n");
        printf("      what htonl() is, and why TLS record lengths, DNS headers and\n");
        printf("      Java's DataOutputStream all need it.\n");
    }

    printf("\n=====================================================================\n");
    printf(" Next: examples/stack_frames.c, then labs/lab-03-stack-frames-and-overflow.md\n");
    printf("=====================================================================\n");
    return 0;
}
