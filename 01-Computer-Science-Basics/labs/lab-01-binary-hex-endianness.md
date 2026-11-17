# Lab 01 — Binary, Hexadecimal, Two's Complement and Endianness

> After this lab you will be able to look at a raw hex dump of an APK's `classes.dex` or a native
> `.so` library and say, without tooling, what the first sixteen bytes mean.

**Chapter:** [01 — Computer Science Basics](../README.md)
**Difficulty:** Beginner
**Estimated time:** 90 minutes (45 minutes of it with a pen and paper, no computer)

---

## Objective

Every file you will ever reverse engineer on Android is a sequence of bytes. The APK is a ZIP, the
ZIP contains a DEX, the DEX contains bytecode, the APK also contains ELF shared objects, and every
one of those formats begins with a fixed *magic number* that identifies it. A tool such as `jadx` or
`file` reads those bytes for you, but a tool can only tell you what it was written to recognise. When
an app deliberately corrupts its DEX header to break automated analysis — a real and common
anti-analysis technique — the only way forward is to read the bytes yourself and know which ones are
lies.

That skill rests on four small pieces of arithmetic that must become automatic:

1. Converting between decimal, binary and hexadecimal without a calculator.
2. Reading a negative number written in two's complement.
3. Knowing what a byte, a word and a dword are, and how many of each fit where.
4. Knowing which end of a multi-byte number comes first in memory — its *endianness*.

By the end you will have converted numbers by hand, verified your answers against a program you
wrote, determined the endianness of your own machine experimentally, and annotated the header bytes
of a real DEX file and a real ELF file.

> **Definition**
> A **byte** is eight binary digits (bits), so it can hold 256 distinct values: 0 to 255 if you
> interpret it as unsigned, or −128 to 127 if you interpret it as signed. The bits themselves carry
> no interpretation; *interpretation is something the reader applies*, and choosing the wrong
> interpretation is the root of an enormous number of bugs and vulnerabilities.

---

## Prerequisites

| Requirement | Why you need it | How to check |
|---|---|---|
| A Linux shell — native Linux, WSL2 on Windows, or macOS | `xxd`, `od` and a C compiler live there | Run `uname -a` |
| `xxd` (ships with `vim-common`) | Produces the hex dumps you will read | Run `which xxd` |
| Python 3.8 or newer | Endianness detection and cross-checking your arithmetic | Run `python3 --version` |
| A C compiler (`gcc` or `clang`) — optional but recommended | The union trick for endianness | Run `gcc --version` |
| Any APK file | Source of a real DEX and a real ELF | See Setup below |
| Pen and paper | Non-negotiable for the first section | — |

No Android device is required for this lab. Everything runs on your computer.

---

## Setup

### 1. Create a working directory

```bash
# host / WSL
mkdir -p ~/android-lab/lab01 && cd ~/android-lab/lab01
```

**Every command in this lab runs from `~/android-lab/lab01`** unless a comment says otherwise. If you
open a new terminal part-way through, `cd ~/android-lab/lab01` again before continuing.

That directory is deliberately *not* inside this repository, so a relative path like `../scripts/`
will not find the chapter's scripts. Record where you cloned the repository, in the same shell:

```bash
# host / WSL — point REPO at your clone of Android-Security-Handbook
export REPO=~/Android-Security-Handbook

# Verify: this must print the script's path, not an error
ls "$REPO/01-Computer-Science-Basics/scripts/hexdump-header.py"
```

Part F uses `$REPO`. If you close the terminal, re-run the `export` as well as the `cd`.

### 2. Obtain an APK

Any APK works. If you have a device connected you can pull one; otherwise download a small
open-source APK from F-Droid. To pull one from a device:

```bash
# host — find the on-device path of an installed package, then copy it out
adb shell pm path com.android.chrome
adb pull /data/app/~~AbCdEf==/com.android.chrome-XyZ==/base.apk ./base.apk
```

The exact path printed by `pm path` will differ on your device; copy the line it prints. If you have
no device, any `.apk` downloaded to your machine is fine.

### 3. Extract a DEX and an ELF from it

An APK is a ZIP archive. `classes.dex` sits at the archive root; native libraries sit under
`lib/<abi>/`.

```bash
# host / WSL
unzip -o base.apk 'classes.dex' 'lib/arm64-v8a/*' -d extracted/
ls -l extracted/
ls -l extracted/lib/arm64-v8a/ | head
```

If the APK you chose has no native libraries, use any Linux binary instead — `/bin/ls` is an ELF and
serves the same purpose for the ELF portion of this lab.

> **Warning**
> Only unpack APKs you are permitted to analyse. Pulling an APK off your own device for study is
> normal practice; redistributing a proprietary APK is not. Nothing in this lab modifies the APK.

---

## Steps

### Part A — Positional number systems, by hand

Put the computer away for this part. You are going to build the intuition that makes hex dumps
readable at a glance.

**A1. Understand what a base actually is.** The decimal number 4096 means
`4×1000 + 0×100 + 9×10 + 6×1`. Each column is a power of ten. Binary is the same idea with powers of
two, and hexadecimal is the same idea with powers of sixteen. Nothing else changes. The digits above
9 in hex are written `A`=10, `B`=11, `C`=12, `D`=13, `E`=14, `F`=15.

**A2. Memorise the powers of two up to 2^16.** Write this table out by hand once; you will use it
for the rest of your career.

| Power | Value | Power | Value |
|---|---|---|---|
| 2^0 | 1 | 2^8 | 256 |
| 2^1 | 2 | 2^9 | 512 |
| 2^2 | 4 | 2^10 | 1024 |
| 2^3 | 8 | 2^11 | 2048 |
| 2^4 | 16 | 2^12 | 4096 |
| 2^5 | 32 | 2^13 | 8192 |
| 2^6 | 64 | 2^14 | 16384 |
| 2^7 | 128 | 2^15 | 32768 |

**A3. Convert decimal to binary by repeated division by two.** Divide the number by 2, write down the
remainder, repeat with the quotient until the quotient is zero, then read the remainders bottom to
top.

**A4. Convert binary to hex by grouping into nibbles.** A *nibble* is four bits, and four bits is
exactly one hex digit. Split the binary number into groups of four from the right, padding the
leftmost group with zeros, and translate each group independently. This is why hexadecimal is used
for memory dumps and binary is not: one hex digit is one nibble, two hex digits are exactly one byte,
and the mapping is local — changing a hex digit changes exactly four bits and no others.

Now convert every row of this table by hand. Fill in the blanks. The worked answers are in the
Solution section — do not look at them yet.

| Decimal | Binary | Hexadecimal |
|---|---|---|
| 13 | ? | ? |
| 64 | ? | ? |
| 200 | ? | ? |
| 255 | ? | ? |
| 256 | ? | ? |
| 1024 | ? | ? |
| 4096 | ? | ? |
| 65535 | ? | ? |
| ? | ? | 0x70 |
| ? | ? | 0x7F |
| ? | ? | 0xDEADBEEF |

**A5. Two's complement.** Computers do not store a sign bit and a magnitude; they store negative
numbers in *two's complement*, which is defined as: invert every bit of the positive value, then add
one. The reason is not aesthetic. It is that with two's complement, the same addition circuit works
for signed and unsigned operands, and `x + (−x)` naturally overflows to zero.

> **Mental Model**
> Think of an 8-bit value as a car odometer with 256 positions arranged in a circle. Counting up
> from 255 wraps to 0. Counting *down* from 0 wraps to 255. Two's complement declares that
> the top half of the circle (128–255) is read as the negatives (−128 to −1). The bits did not
> change; only the label on the dial did.

Compute these by hand, as 8-bit values:

| Decimal | 8-bit two's complement binary | Hex |
|---|---|---|
| −1 | ? | ? |
| −5 | ? | ? |
| −100 | ? | ? |
| −128 | ? | ? |
| 127 | ? | ? |

Then answer, in one sentence each:

- Why can 8-bit two's complement represent −128 but not +128?
- If a 32-bit signed integer holds `0xFFFFFFFF`, what decimal value is that? What if the same bits
  are read as unsigned?

**A6. Words and sizes.** Fill in this table from memory once you have read it twice.

| Name | Bits | Bytes | Unsigned range | C type on AArch64 Linux |
|---|---|---|---|---|
| Bit | 1 | — | 0–1 | — |
| Nibble | 4 | ½ | 0–15 | — |
| Byte | 8 | 1 | 0–255 | `unsigned char`, `uint8_t` |
| Half-word / short | 16 | 2 | 0–65535 | `unsigned short`, `uint16_t` |
| Word / dword | 32 | 4 | 0–4294967295 | `unsigned int`, `uint32_t` |
| Double word / qword | 64 | 8 | 0–18446744073709551615 | `unsigned long`, `uint64_t` |

> **Warning**
> The word "word" is ambiguous and you must always ask whose definition is in use. In Intel
> documentation a *word* is 16 bits. In ARM documentation a *word* is 32 bits and a *doubleword* is
> 64 bits. In DEX documentation values are described by explicit width (`uint`, `ushort`). When you
> read a specification, find its definition of "word" before you trust any size arithmetic.

---

### Part B — Determine your machine's endianness

**B1. Understand the question.** The value `0x12345678` needs four bytes of memory. There are two
sensible orders to place them in ascending addresses:

| Scheme | Byte at addr+0 | addr+1 | addr+2 | addr+3 | Used by |
|---|---|---|---|---|---|
| Little-endian | `0x78` | `0x56` | `0x34` | `0x12` | x86, x86-64, ARM/AArch64 as configured by Android and Linux |
| Big-endian | `0x12` | `0x34` | `0x56` | `0x78` | Network protocols (`htons`), some legacy MIPS/PowerPC systems |

Little-endian stores the *least significant* byte at the lowest address. Big-endian stores the *most
significant* byte first, which is the order humans write numbers in — hence "network byte order" is
big-endian, because protocol designers wanted dumps to be human-readable.

**B2. Write the detector in Python.**

```python
# host / WSL — save as endian.py, run: python3 endian.py
import sys, struct

print("sys.byteorder reports:", sys.byteorder)

value = 0x12345678
little = struct.pack("<I", value)   # '<' = little-endian, 'I' = unsigned 32-bit
big    = struct.pack(">I", value)   # '>' = big-endian
native = struct.pack("=I", value)   # '=' = whatever this machine uses

print("little-endian bytes:", little.hex(" "))
print("big-endian bytes:   ", big.hex(" "))
print("native bytes:       ", native.hex(" "))
print("This machine is little-endian:", native == little)
```

Run it and record the output. Predict the three lines before you run it.

**B3. Write the detector in C using a union.** A `union` in C places all its members at the *same*
address, so writing the `int` member and reading the `char` array member shows you the raw byte
order. The full, commented program is provided as
[`../examples/endianness.c`](../examples/endianness.c). Compile and run it:

```bash
# host / WSL
gcc -O0 -g -Wall -o endianness ../examples/endianness.c
./endianness
```

Confirm that the C program and the Python program agree.

**B4. Cross-check with `xxd`.** Create a file containing a known 32-bit value in native order and
look at it.

```bash
# host / WSL
python3 -c "import struct,sys; sys.stdout.buffer.write(struct.pack('=I', 0x12345678))" > val.bin
xxd val.bin
```

You should see `78563412` on a little-endian machine. Confirm that this matches what your C program
predicted.

---

### Part C — Read a hex dump

**C1. Learn the `xxd` output format.** Run:

```bash
# host / WSL
printf 'Hello, Android!\n' > hello.txt
xxd hello.txt
```

The output has three columns. The left column is the *offset* of the first byte on that line, always
in hex. The middle column is sixteen bytes shown as thirty-two hex digits, grouped in pairs of bytes
by default. The right column, between pipes, is the ASCII rendering, with a dot substituted for any
byte outside the printable range 0x20–0x7E.

**C2. Prove to yourself that ASCII is just numbers.** Look up the byte values for `H`, `e`, `A` and
the newline in your dump.`0x41` is `A`, `0x61` is `a`, and the difference between an
uppercase and lowercase ASCII letter is exactly bit 5 (`0x20`).

**C3. Practise offsets.** Answer from the dump alone: what is the byte at offset `0x07`? At what
offset does the newline sit? How many bytes long is the file? Verify with `wc -c hello.txt`.

Useful `xxd` flags:

| Flag | Effect |
|---|---|
| `-l N` | Dump only the first N bytes |
| `-s N` | Start at offset N (accepts `0x` prefix) |
| `-g N` | Group output into N-byte columns; `-g 1` is easiest to read for header work |
| `-c N` | N bytes per line |
| `-b` | Binary dump instead of hex — useful once, then never again |

---

### Part D — Annotate a real DEX header

**D1. Dump the first 64 bytes of `classes.dex`.**

```bash
# host / WSL
xxd -g 1 -l 64 extracted/classes.dex
```

**D2. Map the bytes onto the header structure.** The DEX header is specified by the Dalvik executable
format documentation. Its first fields are:

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0x00 | 8 | `magic` | Always the ASCII bytes `dex`, a newline, three version digits, and a NUL |
| 0x08 | 4 | `checksum` | Adler-32 of the whole file after this field |
| 0x0C | 20 | `signature` | SHA-1 of the whole file after this field |
| 0x20 | 4 | `file_size` | Total size of the DEX file in bytes |
| 0x24 | 4 | `header_size` | Size of this header — `0x70`, i.e. 112 bytes |
| 0x28 | 4 | `endian_tag` | `0x12345678` for little-endian; `0x78563412` signals byte-swapped |
| 0x2C | 4 | `link_size` | Unused in practice, normally zero |
| 0x30 | 4 | `link_off` | Unused in practice, normally zero |
| 0x34 | 4 | `map_off` | Offset of the map list |
| 0x38 | 4 | `string_ids_size` | Number of entries in the string identifier list |
| 0x3C | 4 | `string_ids_off` | Offset of the string identifier list |

**D3. Decode the magic.** The eight magic bytes for a version 035 DEX are:

```
64 65 78 0a 30 33 35 00
 d  e  x \n  0  3  5 NUL
```

Write down the eight bytes your file actually has and translate each to its ASCII character. Modern
tooling emits `035`, `037`, `038` or `039` depending on the language features used; record which
version yours is.the version digits are ASCII characters, not a binary number — `035` is
the three bytes `0x30 0x33 0x35`, not the value 35.

**D4. Decode `header_size` and `endian_tag` as an endianness exercise.** Read the four bytes at
offset `0x24`. On a normal DEX you will see `70 00 00 00`. Because DEX is little-endian, those bytes
are the value `0x00000070` = 112 decimal, not `0x70000000`. Then read offset `0x28`: you will see
`78 56 34 12`, which read little-endian is the value `0x12345678`. This is the whole point of the
field — a parser reads it, and if it gets `0x78563412` instead, it knows the file was written by a
big-endian producer and every multi-byte field must be swapped.

**D5. Decode `file_size` and check it.** Read the four bytes at offset `0x20`, reverse them, convert
to decimal, and compare with the real size:

```bash
# host / WSL
xxd -g 1 -s 0x20 -l 4 extracted/classes.dex
stat -c %s extracted/classes.dex
```

If they match, you have just validated a DEX header by hand, which is exactly what ART's verifier
does before it will load the file.

> **Pentester's Note**
> Apps that want to frustrate static analysis frequently ship a `classes.dex` whose `checksum`,
> `signature` or `file_size` fields are deliberately wrong, or whose `header_size` points past the
> real header. Many desktop parsers refuse the file; the Android runtime, historically more
> permissive in some code paths, may still load it. When `jadx` says "not a valid dex file" and the
> app runs happily on a device, the first thing to do is dump the header by hand and compare it
> against this table. What you are looking for is a field the runtime ignores but the parser
> trusts.

---

### Part E — Annotate a real ELF header

**E1. Dump the first 64 bytes of a native library.**

```bash
# host / WSL
xxd -g 1 -l 64 extracted/lib/arm64-v8a/libnative-lib.so
```

Substitute whatever `.so` your APK actually contains, or use `/bin/ls`.

**E2. Map the bytes.** The first sixteen bytes are the `e_ident` array; everything after depends on
whether the file is 32-bit or 64-bit.

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0x00 | 4 | `EI_MAG0..3` | `0x7F` then ASCII `E`, `L`, `F` |
| 0x04 | 1 | `EI_CLASS` | `1` = ELFCLASS32, `2` = ELFCLASS64 |
| 0x05 | 1 | `EI_DATA` | `1` = little-endian (LSB), `2` = big-endian (MSB) |
| 0x06 | 1 | `EI_VERSION` | Always `1` |
| 0x07 | 1 | `EI_OSABI` | `0` = System V, `3` = Linux |
| 0x08 | 1 | `EI_ABIVERSION` | Normally `0` |
| 0x09 | 7 | padding | Reserved, zero |
| 0x10 | 2 | `e_type` | `1` REL, `2` EXEC, `3` DYN (shared object or PIE), `4` CORE |
| 0x12 | 2 | `e_machine` | `0x28` ARM (32-bit), `0xB7` AArch64, `0x03` i386, `0x3E` x86-64 |
| 0x14 | 4 | `e_version` | Always `1` |
| 0x18 | 8 (ELF64) | `e_entry` | Virtual address of the entry point; often `0` in a shared library |
| 0x20 | 8 (ELF64) | `e_phoff` | File offset of the program header table |
| 0x28 | 8 (ELF64) | `e_shoff` | File offset of the section header table |

On a 32-bit ELF, `e_entry`, `e_phoff` and `e_shoff` are four bytes each rather than eight, so every
offset from `0x18` onward shifts.

**E3. Answer these from your dump.** Is the file 32-bit or 64-bit? Is it little-endian or
big-endian? What machine does `e_machine` say it targets, and does that match the `lib/<abi>/`
directory it came from? Is `e_type` equal to 3, and if so, why would every Android native library
and every Android executable be `DYN` rather than `EXEC`?

**E4. Check yourself with tooling — but only after you have answered by hand.**

```bash
# host / WSL
readelf -h extracted/lib/arm64-v8a/libnative-lib.so
file extracted/lib/arm64-v8a/libnative-lib.so
```

**E5. Repeat for the APK itself.** An APK begins with a ZIP local file header whose magic is
`50 4B 03 04`, ASCII `PK` followed by `0x03 0x04`. The `PK` is the initials of Phil Katz, who wrote
the original PKZIP.

```bash
# host / WSL
xxd -g 1 -l 32 base.apk
```

---

### Part F — Automate what you just did by hand

Run the chapter's annotated dumper against all three files and compare its output with your
hand-written notes.

```bash
# host / WSL — from ~/android-lab/lab01, with $REPO set in Setup step 1
cd ~/android-lab/lab01
DUMP="$REPO/01-Computer-Science-Basics/scripts/hexdump-header.py"

python3 "$DUMP" extracted/classes.dex
python3 "$DUMP" extracted/lib/arm64-v8a/libnative-lib.so
python3 "$DUMP" base.apk
python3 "$DUMP" --length 128 /bin/ls
```

> **Warning**
> `python3: can't open file '.../hexdump-header.py'` means `$REPO` is unset or wrong — the working
> directory `~/android-lab/lab01` is outside the repository, so `../scripts/` does **not** resolve to
> the chapter's `scripts/` directory. Re-run the `export REPO=...` and the `ls` check from Setup
> step 1.

If the script's field decoding disagrees with yours anywhere, work out which of you is wrong before
moving on. That reconciliation is the actual learning.

---

## Hints

<details>
<summary>Hint 1 — I keep making mistakes converting decimal to binary</summary>

Do not divide repeatedly if you know your powers of two. Instead subtract the largest power of two
that fits, write a `1` in that column, and repeat with the remainder. For 200: the largest power of
two below 200 is 128, leaving 72; then 64, leaving 8; then 8, leaving 0. So bits 7, 6 and 3 are set,
which is `1100 1000`.
</details>

<details>
<summary>Hint 2 — Hex to decimal for two digits</summary>

Multiply the first digit by 16 and add the second. `0x9C` is `9×16 + 12` = `144 + 12` = 156. For four
hex digits, take the first two as one byte, multiply by 256, and add the value of the last two.
</details>

<details>
<summary>Hint 3 — I cannot tell whether to reverse the bytes</summary>

Ask what the bytes *are*. If they are a multi-byte **number** (a size, an offset, a checksum), they
are stored little-endian and you reverse them before reading. If they are a **string or byte array**
(the DEX magic, the ELF magic, the SHA-1 signature), they are stored in order and you do not reverse
anything. The DEX header conveniently contains both kinds side by side.
</details>

<details>
<summary>Hint 4 — `xxd` output is hard to count</summary>

Use `xxd -g 1 -c 16`. With `-g 1` each byte is a separate two-character column, so counting to the
byte at offset `0x24` means counting four bytes past the start of the line labelled `00000020`.
</details>

<details>
<summary>Hint 5 — My APK has no `lib/` directory</summary>

That is normal for a pure-Java or pure-Kotlin app. Use `/bin/ls`, `/bin/cat`, or any binary under
`/usr/bin` — they are all ELF files and the header layout is identical. If you want an AArch64
example, pull one off a device: `adb pull /system/lib64/libc.so`.
</details>

---

## Solution

### A4 — Conversion table, worked

| Decimal | Binary | Hexadecimal | Working |
|---|---|---|---|
| 13 | `0000 1101` | `0x0D` | 8 + 4 + 1 |
| 64 | `0100 0000` | `0x40` | 2^6 |
| 200 | `1100 1000` | `0xC8` | 128 + 64 + 8; nibbles `1100`=C, `1000`=8 |
| 255 | `1111 1111` | `0xFF` | All eight bits set — the largest single byte |
| 256 | `0000 0001 0000 0000` | `0x0100` | 2^8; needs a ninth bit, so two bytes |
| 1024 | `0000 0100 0000 0000` | `0x0400` | 2^10 |
| 4096 | `0001 0000 0000 0000` | `0x1000` | 2^12 — also the standard page size |
| 65535 | `1111 1111 1111 1111` | `0xFFFF` | Largest 16-bit unsigned value |
| 112 | `0111 0000` | `0x70` | The DEX `header_size` |
| 127 | `0111 1111` | `0x7F` | Largest 8-bit signed value; also ELF's first magic byte |
| 3735928559 | `1101 1110 1010 1101 1011 1110 1110 1111` | `0xDEADBEEF` | The classic joke pointer sentinel |

### A5 — Two's complement, worked

| Decimal | Steps | 8-bit binary | Hex | Check |
|---|---|---|---|---|
| −1 | `1` = `0000 0001`; invert → `1111 1110`; +1 → `1111 1111` | `1111 1111` | `0xFF` | 256 − 1 = 255 |
| −5 | `5` = `0000 0101`; invert → `1111 1010`; +1 → `1111 1011` | `1111 1011` | `0xFB` | 256 − 5 = 251 |
| −100 | `100` = `0110 0100`; invert → `1001 1011`; +1 → `1001 1100` | `1001 1100` | `0x9C` | 256 − 100 = 156 |
| −128 | `128` does not fit as positive; the bit pattern `1000 0000` is defined as −128 | `1000 0000` | `0x80` | 256 − 128 = 128 |
| 127 | Positive, no conversion | `0111 1111` | `0x7F` | — |

The shortcut visible in the "Check" column is that an 8-bit two's complement negative `−n` has the
same bit pattern as the unsigned value `256 − n`. For 32 bits the constant is 2^32 = 4294967296.

**Why −128 but not +128.** Eight bits give 256 patterns. Zero consumes one of them. That leaves 255
patterns to split between positives and negatives, and the split is not symmetric: 127 positives, 128
negatives. The asymmetry is not an accident, it falls out of the definition — `0000 0000` is zero and
`1000 0000` has no positive counterpart, so it is assigned to −128.

**`0xFFFFFFFF` in 32 bits.** Read as signed it is −1. Read as unsigned it is 4294967295. This single
ambiguity is the origin of an entire vulnerability class: a length field is read as a signed `int`,
compared against a maximum with `if (len > MAX) reject;`, passes the check because it is negative,
and is then handed to a function that takes a `size_t` (unsigned) and sees 4294967295. The check
passed and the allocation is enormous or the copy runs off the end of the buffer.

### B — Endianness

`sys.byteorder` prints `little` on every device you will realistically test: x86-64 laptops, AArch64
phones running Android, and Apple Silicon Macs. The three `struct.pack` lines print
`78 56 34 12`, `12 34 56 78`, and `78 56 34 12` respectively, and the equality test prints `True`.
The `xxd val.bin` output is `78563412`.

AArch64 hardware is *bi-endian* — the `SCTLR_ELx.EE` and `SPSR.E` control bits can select big-endian
data accesses. Android never does this. Every Android ABI (`armeabi-v7a`, `arm64-v8a`, `x86`,
`x86_64`) is little-endian, which is why `EI_DATA` in an Android `.so` is always `1`. You will
nonetheless meet big-endian data *inside* little-endian Android processes, because network protocols,
TLS records, DNS packets, Java's `DataOutputStream`, and Java's `ByteBuffer` default all use
big-endian. Confusing the two is a routine source of "my Frida script prints garbage" moments.

### D — DEX header, worked example

A concrete dump from a real file, with annotations:

```
00000000: 64 65 78 0a 30 33 35 00  |dex.035.|   magic: "dex\n035\0" → DEX version 035
00000008: 3f a1 2c 5b              |          checksum = 0x5b2ca13f (Adler-32, little-endian)
0000000c: 1a 2b ... (20 bytes)     |          signature = SHA-1 of everything after it
00000020: 4c 8f 0a 00              |          file_size = 0x000a8f4c = 691,532 bytes
00000024: 70 00 00 00              |          header_size = 0x00000070 = 112
00000028: 78 56 34 12              |          endian_tag = 0x12345678 → little-endian
0000002c: 00 00 00 00              |          link_size = 0
00000030: 00 00 00 00              |          link_off = 0
```

Your checksum, signature and `file_size` will differ; the magic, `header_size` and `endian_tag` will
not.

### E — ELF header, worked example

A dump of an `arm64-v8a` shared object:

```
00000000: 7f 45 4c 46  |  .ELF        magic
00000004: 02           |              EI_CLASS = 2 → 64-bit
00000005: 01           |              EI_DATA  = 1 → little-endian
00000006: 01           |              EI_VERSION = 1
00000007: 00           |              EI_OSABI = 0 → System V
00000008: 00 00 00 00 00 00 00 00  |  ABIVERSION + padding
00000010: 03 00        |              e_type = 3 → ET_DYN (shared object / PIE)
00000012: b7 00        |              e_machine = 0x00b7 → AArch64
00000014: 01 00 00 00  |              e_version = 1
00000018: 00 09 00 00 00 00 00 00  |  e_entry = 0x900 (offset, not absolute — this is a DYN file)
00000020: 40 00 00 00 00 00 00 00  |  e_phoff = 64
00000028: xx xx ...                 |  e_shoff
```

**Why `e_type` is always `3` on Android.** Since Android 5.0 the linker refuses to load executables
that are not position-independent, and every native library is a shared object by construction. A
position-independent executable is an `ET_DYN` file with an entry point, loaded by the dynamic
linker at a randomised base address chosen by ASLR. If `e_type` were `2` (`ET_EXEC`) the file would
demand to be loaded at one fixed address, which would defeat ASLR entirely. That single byte is the
file-format expression of a security decision, and it is why the addresses you read in a `.so`
disassembly are offsets from an unknown base rather than the addresses you will see at runtime.

> **Under the Hood**
> `e_entry` in an `ET_DYN` file is a *relative* virtual address. At load time the kernel or the
> dynamic linker picks a base address — call it `L` — maps the segments described in the program
> headers there, and the real entry point becomes `L + e_entry`. This is exactly why an address you
> noted in Ghidra (say `0x1a2b4`) never matches the address Frida reports at runtime (say
> `0x7f8c0021a2b4`). The relationship is always `runtime = module_base + file_offset_vaddr`, and
> `Module.findBaseAddress()` in Frida exists to give you `L`.

---

## Success Criteria

You have completed this lab when all of the following are true.

| # | Criterion | How to prove it |
|---|---|---|
| 1 | You converted all eleven rows of the A4 table by hand and every answer matches the solution | Your paper |
| 2 | You can state the two's complement of any small decimal in under ten seconds | Ask a friend to test you |
| 3 | You explained in your own words why `0xFFFFFFFF` is both −1 and 4294967295 | Written sentence |
| 4 | Your Python and C endianness detectors agree, and you predicted their output before running | Terminal history |
| 5 | You identified all eight DEX magic bytes and stated the version | Annotated dump |
| 6 | You read `file_size` from the DEX header by hand and it matched `stat -c %s` | Two numbers that agree |
| 7 | You read `EI_CLASS`, `EI_DATA`, `e_type` and `e_machine` from an ELF by hand, then confirmed with `readelf -h` | Side-by-side comparison |
| 8 | You explained why Android native libraries are `ET_DYN` | Written sentence |
| 9 | `hexdump-header.py` ran successfully on all three file types and agreed with your notes | Script output |

---

## Going Further

1. **Break a DEX deliberately and observe what fails.** Copy `classes.dex`, flip one byte in the
   `checksum` field with `printf` and `dd`, and run `jadx` on it. Then repeat with a byte inside the
   `signature`. Note which tools reject the file, which repair it, and which do not care. Do this
   only on a copy, and only on an APK you own.

   ```bash
   # host / WSL — corrupt byte at offset 0x08 in a COPY
   cp extracted/classes.dex broken.dex
   printf '\xff' | dd of=broken.dex bs=1 seek=8 count=1 conv=notrunc
   ```

2. **Recompute the DEX Adler-32 yourself** in Python with `zlib.adler32` over the file from offset
   `0x0C` onward, and compare with the stored checksum. Then recompute the SHA-1 over the file from
   offset `0x20` onward and compare with the stored signature. Now you know exactly which byte
   ranges each covers, which is precisely what you need to know to repair a deliberately corrupted
   DEX.

3. **Read a multi-DEX APK.** Large apps ship `classes.dex`, `classes2.dex`, `classes3.dex` and so on.
   Dump the header of each and confirm that `header_size` and `endian_tag` are identical while
   `string_ids_size` differs wildly. Explain why.

4. **Look at a 32-bit ELF.** Extract `lib/armeabi-v7a/*.so` from an APK that ships both ABIs and dump
   its header. Confirm `EI_CLASS` is `1` and that `e_phoff` is now at offset `0x1C` rather than
   `0x20`, and work out by how many bytes every subsequent field has shifted.

5. **Big-endian in a little-endian world.** Capture an HTTPS request from an app with Burp, look at
   the TLS record header in the raw bytes, and confirm the two-byte length field is big-endian. Then
   write a Frida snippet that reads a `short` from a Java `ByteBuffer` and explain why you must call
   `order(ByteOrder.LITTLE_ENDIAN)` to match native code.

6. **Float representation.** Extend [`../examples/endianness.c`](../examples/endianness.c) to print
   the bytes of `1.0f`, `-1.0f` and `0.1f`, then decode the IEEE-754 sign bit, 8-bit exponent and
   23-bit mantissa by hand. Explain in one paragraph why `0.1f + 0.2f != 0.3f`.

---

## Why this matters for Android security

Everything you did in this lab is the substrate under every tool you will ever run.

**Static analysis begins with magic bytes.** When you scan an app's `assets/` directory and find a
file called `config.dat` that begins `50 4B 03 04`, you have just discovered a hidden ZIP — a very
common way to ship a second DEX for dynamic loading, which is the standard packing technique used
both by legitimate obfuscators and by malware. When it begins `64 65 78 0a`, it is a DEX pretending
not to be one. When it begins with high-entropy bytes and no recognisable magic, it is encrypted, and
your next job is to find the key. `file` will not tell you any of this if the extension is wrong or
the header is one byte off; your eyes will.

**Dynamic analysis is arithmetic on addresses.** Every Frida script you write manipulates addresses:
`Module.findBaseAddress("libnative.so").add(0x1a2b4)`, `ptr("0x7f8c00000000").readByteArray(32)`,
`Memory.readU32()`. You cannot debug a script that reads the wrong four bytes unless you can convert
those bytes back to a number in your head, and you cannot decide whether a returned value of
`0xFFFFFFFF` is an error code, a sentinel, or −1 unless two's complement is second nature. See
[53 — Frida](../../53-Frida/README.md).

**Reading ARM disassembly is reading hex.** Immediates in AArch64 disassembly are printed in hex,
offsets in `LDR x0, [x1, #0x28]` are hex, and branch targets are hex. Chapter
[18 — ARM](../../18-ARM/README.md) assumes you can add `0x28` to a base address without
reaching for a calculator.

**Memory corruption is signedness and width.** The dominant native vulnerability classes on
Android — heap overflows in media parsers, integer overflows in length computations, off-by-one
errors in bounds checks — are all failures of exactly the arithmetic in Part A. A parser reads a
16-bit length, stores it in a signed `short`, receives `0xFFFF`, interprets it as −1, and allocates
`len + 1` = 0 bytes before copying 65535. Recognising that pattern in decompiled code requires you to
be thinking in bit-widths, not in abstract "numbers". Chapter
[19 — Memory](../../19-Memory/README.md) builds directly on this.

**Endianness decides whether your parser is right.** DEX is little-endian by definition, ELF declares
its endianness in a byte you now know how to read, ZIP is little-endian, protobuf varints are
little-endian-ish, and everything on the network is big-endian. An app that stores an encrypted token
as a big-endian length prefix followed by ciphertext will produce nonsense from a little-endian
parser, and the resulting garbage looks exactly like "the crypto is unbreakable" until you notice the
byte order.

**Next:** [Lab 02 — Processes and memory maps](lab-02-processes-memory-maps.md), where those same
hex numbers become addresses in a live process.
