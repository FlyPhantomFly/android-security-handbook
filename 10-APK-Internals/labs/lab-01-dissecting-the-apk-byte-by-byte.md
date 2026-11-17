# Lab 01 — Dissecting the APK, Byte by Byte

**Difficulty:** Beginner → Intermediate
**Time:** 60–90 minutes
**Chapter:** [10-APK-Internals](../README.md)

---

## Objective

By the end of this lab you will be able to open any APK in a hex editor and, using nothing but the
raw bytes, state where the archive begins, where its index lives, where the signature material is
hidden, and which signing schemes the file carries. You will do it twice: once by hand, so that you
understand every number, and once with a short Python program, so that you can do it at scale.

This matters because every tool you will later rely on — `apktool`, `jadx`, MobSF, `apksigner` —
is an interpretation of these bytes. When two tools disagree, the bytes are the tie-breaker. An
analyst who can only read tool output cannot resolve a disagreement; an analyst who can read the
container can.

**You will finish able to answer:**

1. What are the first four bytes of every legitimate APK, and what does it mean when they differ?
2. Where is the End Of Central Directory record, and why must it be found by searching backwards?
3. What is the single 32-bit value that the entire archive structure hangs off?
4. Where does the APK Signing Block live, and why is it invisible to a normal ZIP reader?
5. Which signature schemes does this APK carry, established without running `apksigner`?

---

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| A computer with a terminal | Everything below is command line | `echo hello` |
| Python 3.8 or later | The programmatic half of the lab | `python3 --version` |
| `xxd` or `hexdump` | Reading raw bytes | `xxd --version` or `hexdump --version` |
| `unzip` and `zipinfo` | The tool view, for comparison | `unzip -v` |
| An Android device or emulator with USB debugging | To obtain a real APK | `adb devices` |
| Android SDK build-tools on `PATH` (optional) | `apksigner` for the final cross-check | `apksigner version` |

> **Definition — hex editor / hex dump.** Computers store files as sequences of bytes, each
> being a number from 0 to 255. A hex dump prints those numbers in base 16 (two characters per
> byte) next to their textual interpretation, so you can see structure that a text editor hides.
> `xxd` is the hex dump program shipped with most Unix-like systems.

> **Definition — offset.** The position of a byte counted from the start of the file, where the
> very first byte is offset 0. Offsets are conventionally written in hexadecimal with a `0x`
> prefix, so `0x10` means "the seventeenth byte".

> **Definition — little-endian.** ZIP stores multi-byte numbers with the least significant byte
> first. The four bytes `50 4B 03 04` therefore represent the 32-bit number `0x04034B50`, not
> `0x504B0304`. Every number in this lab is little-endian. Getting this backwards is the single
> most common beginner mistake.

If you have never used a terminal, work through
[02-Linux-Basics](../../02-Linux-Basics/README.md) first; nothing here requires more than
`cd`, `ls` and running a command.

---

## Setup

### Step 0.1 — Create a working directory

```bash
# host
mkdir -p ~/apk-lab-01 && cd ~/apk-lab-01
```

### Step 0.2 — Obtain an APK from a device

Any installed app will do. A system app such as the Calculator is a good first choice because it is
small, and a Play Store app is a good second choice because it will carry more signing-block
content. First ask the package manager where the app lives.

```bash
# host
adb shell pm list packages | grep -i calculator
```

```bash
# host
adb shell pm path com.google.android.calculator
```

Expected output (paths will differ):

```
package:/product/app/CalculatorGooglePrebuilt/CalculatorGooglePrebuilt.apk
```

For a typical user-installed app you will see several lines, because modern apps ship as split
APKs:

```
package:/data/app/~~kQ1w..==/com.example.app-9Zp..==/base.apk
package:/data/app/~~kQ1w..==/com.example.app-9Zp..==/split_config.arm64_v8a.apk
package:/data/app/~~kQ1w..==/com.example.app-9Zp..==/split_config.xxhdpi.apk
```

Pull them all:

```bash
# host
for p in $(adb shell pm path com.example.app | tr -d '\r' | sed 's/^package://'); do
  adb pull "$p" .
done
ls -l *.apk
```

Work with `base.apk` for the rest of the lab. If you have no device available, any APK downloaded
to your machine works equally well — the format is identical.

```bash
# host — settle on one filename so every later command can be copy-pasted
cp base.apk target.apk
ls -l target.apk
```

> **Warning** Only pull and analyse APKs you are authorised to analyse. Your own apps, apps you
> built, and open-source apps are always fine. Commercial apps may be covered by terms of service
> that restrict reverse engineering; that is a legal question, not a technical one, and it is your
> responsibility to answer it before you start.

---

## Part 1 — The tool view (so you know what the answer should be)

### Step 1.1 — List the entries

```bash
# host
unzip -l target.apk | head -30
```

Expected output shape:

```
Archive:  target.apk
  Length      Date    Time    Name
---------  ---------- -----   ----
     4180  1981-01-01 01:01   META-INF/com/android/build/gradle/app-metadata.properties
    31112  1981-01-01 01:01   AndroidManifest.xml
  8394392  1981-01-01 01:01   classes.dex
  3117580  1981-01-01 01:01   classes2.dex
  1994208  1981-01-01 01:01   resources.arsc
   ...
```

Two things are worth noticing immediately. The dates are all `1981-01-01` because build tools zero
the timestamps for reproducible builds; a real date here means the archive was rebuilt by hand. And
`AndroidManifest.xml` has a size in the tens of kilobytes, which should already tell you it is not
text.

### Step 1.2 — Look at the per-entry detail

```bash
# host
zipinfo -v target.apk | head -60
```

`zipinfo -v` prints, for each entry, both the central directory fields and the local header fields.
Read one entry's output slowly. You are looking at exactly the structures you will decode by hand
in Part 2.

Expected fragment:

```
Central directory entry #2:
---------------------------

  AndroidManifest.xml

  offset of local header from start of archive:   4211 (00001073h) bytes
  file system or operating system of origin:      MS-DOS, OS/2 or NT FAT
  version of encoding software:                   2.0
  minimum software version required to extract:   2.0
  compression method:                             deflated
  compression sub-type (deflation):               normal
  file security status:                           not encrypted
  extended local header:                          no
  ...
  compressed size:                                8534 bytes
  uncompressed size:                              31112 bytes
  length of filename:                             19 characters
  length of extra field:                          0 bytes
  length of file comment:                         0 characters
```

### Step 1.3 — Record the answers you are about to reproduce by hand

```bash
# host
ls -l target.apk                                  # exact file size in bytes
unzip -l target.apk | tail -3                     # entry count
apksigner verify -v target.apk 2>/dev/null || echo "apksigner not installed - fine, continue"
```

Write the file size and the entry count down. In Part 2 you will derive both from raw bytes, and
they must match.

---

## Part 2 — The byte view, by hand

### Step 2.1 — The first four bytes

```bash
# host
xxd -l 64 target.apk
```

Expected output, annotated:

```
00000000: 504b 0304 1400 0800 0800 0000 2100 0000  PK..........!...
00000010: 0000 0000 0000 0000 0000 1300 0000 416e  ..............An
00000020: 6472 6f69 644d 616e 6966 6573 742e 786d  droidManifest.xm
00000030: 6c78 9cec bd07 6014 4919 8025 764a 47c1  l.....`.I..%vJG.
```

Decode the first record field by field. Everything is little-endian.

| Offset | Bytes | Value | Field | Meaning |
|---|---|---|---|---|
| `0x00` | `50 4b 03 04` | `0x04034B50` | signature | **Local File Header.** Every APK starts here. |
| `0x04` | `14 00` | 20 | version needed | 2.0 — deflate support required. |
| `0x06` | `08 00` | `0x0008` | general purpose bit flag | Bit 3 set: a data descriptor follows the entry data, so the CRC and sizes in *this* header are zero. |
| `0x08` | `08 00` | 8 | compression method | DEFLATE. |
| `0x0A` | `00 00` | 0 | last mod time | Zeroed for reproducible builds. |
| `0x0C` | `21 00` | `0x0021` | last mod date | MS-DOS date: year 1980+0, month 1, day 1. |
| `0x0E` | `00 00 00 00` | 0 | CRC-32 | Zero because bit 3 is set. |
| `0x12` | `00 00 00 00` | 0 | compressed size | Zero because bit 3 is set. |
| `0x16` | `00 00 00 00` | 0 | uncompressed size | Zero because bit 3 is set. |
| `0x1A` | `13 00` | 19 | file name length | 19 characters. |
| `0x1C` | `00 00` | 0 | extra field length | No extra field. |
| `0x1E` | `41 6e 64 …` | `AndroidManifest.xml` | file name | 19 bytes, no terminator. |
| `0x31` | `78 9c …` | — | file data | `78 9c` is a zlib/deflate header — this really is compressed data. |

> **Under the Hood** Notice that the local header's CRC and sizes are zero. That is legal and
> common: general purpose bit flag bit 3 tells the reader "I did not know the sizes when I wrote
> this header; look for a data descriptor after the data, or better, look in the central
> directory." This is precisely why the *central directory* is authoritative on Android, and why a
> reader that trusts the local header can be made to disagree with one that does not.

Take the first four bytes as a fingerprint:

```bash
# host
head -c 4 target.apk | xxd -p
```

Expected: `504b0304`.

> **Pentester's Note** If those four bytes are `6465780a` — ASCII `dex\n` — you are looking at a
> file with a DEX prepended to a ZIP. That is the Janus construction (CVE-2017-13156): the archive
> still parses, because ZIP readers work from the end of the file, but the code-loading path on
> Android 5.0–8.0 read the magic at offset 0 and executed the prepended DEX. A one-line check
> catches it. Run it on every sample you receive.

### Step 2.2 — Find the End Of Central Directory record

A ZIP reader does not read from the front. It reads the **last** record in the file — the End Of
Central Directory (EOCD) — and uses a pointer inside it to find the index. Because the EOCD ends
with a variable-length comment, a reader cannot seek to `filesize - 22`; it must scan
backwards for the signature `50 4B 05 06`.

```bash
# host — dump the last 64 bytes
xxd -s -64 target.apk
```

Expected output for an archive with no comment:

```
003f3b84: 8a01 0000 5f00 0000 0000 0000 0000 0000  ...._...........
003f3b94: 0000 0000 0000 0000 0000 0000 0000 0000  ................
003f3ba4: 504b 0506 0000 0000 9603 9603 a4c1 0000  PK..............
003f3bb4: 007a 3e00 0000                           .z>...
```

The EOCD begins at offset `0x3F3BA4`. Decode it:

| Offset | Bytes | Value | Field |
|---|---|---|---|
| `0x3F3BA4` | `50 4b 05 06` | `0x06054B50` | EOCD signature |
| `+4` | `00 00` | 0 | number of this disk |
| `+6` | `00 00` | 0 | disk where the central directory starts |
| `+8` | `96 03` | 918 | central directory records on this disk |
| `+10` | `96 03` | 918 | total central directory records |
| `+12` | `a4 c1 00 00` | `0x0000C1A4` = 49572 | size of the central directory, in bytes |
| `+16` | `00 7a 3e 00` | `0x003E7A00` = 4094464 | **offset of the start of the central directory** |
| `+20` | `00 00` | 0 | comment length |

Sanity-check the arithmetic. The file should be exactly `cdOffset + cdSize + 22 + commentLength`
bytes long:

```
4094464 + 49572 + 22 + 0 = 4144058 bytes
```

```bash
# host
stat -c%s target.apk     # Linux
stat -f%z target.apk     # macOS
```

If the numbers do not match, either you mis-decoded a field (check your endianness) or the file has
data appended after the EOCD — which is itself worth investigating.

> **Mental Model** Think of the EOCD as the back cover of a book that says "the table of
> contents starts on page 4,094,464 and is 49,572 characters long, and there are 918 chapters."
> Everything else follows from that one sentence. Corrupt or move that sentence and the whole book
> becomes unreadable — but *prepend* a hundred blank pages and a reader who only reads the back
> cover never notices, which is the Janus idea in one image.

### Step 2.3 — Walk to the central directory and read one record

```bash
# host — jump to the offset you just decoded (0x3E7A00 = 4094464)
xxd -s 4094464 -l 96 target.apk
```

Expected shape:

```
003e7a00: 504b 0102 1400 1400 0800 0800 0000 2100  PK............!.
003e7a10: 3d0e 1e2d 5410 0000 5410 0000 3a00 0000  =..-T...T...:...
003e7a20: 0000 0000 0000 0000 0000 0000 0000 4d45  ..............ME
003e7a30: 5441 2d49 4e46 2f63 6f6d 2f61 6e64 726f  TA-INF/com/andro
003e7a40: 6964 2f62 7569 6c64 2f67 7261 646c 652f  id/build/gradle/
003e7a50: 6170 702d 6d65 7461 6461 7461 2e70 726f  app-metadata.pro
```

Decode the central directory file header:

| Offset in record | Bytes | Value | Field |
|---|---|---|---|
| `+0` | `50 4b 01 02` | `0x02014B50` | Central Directory File Header signature |
| `+4` | `14 00` | 20 | version made by |
| `+6` | `14 00` | 20 | version needed to extract |
| `+8` | `08 00` | `0x0008` | general purpose bit flag |
| `+10` | `08 00` | 8 | compression method — DEFLATE |
| `+12` | `00 00` | 0 | last mod time |
| `+14` | `21 00` | `0x0021` | last mod date |
| `+16` | `3d 0e 1e 2d` | `0x2D1E0E3D` | CRC-32 of the uncompressed data |
| `+20` | `54 10 00 00` | 4180 | compressed size |
| `+24` | `54 10 00 00` | 4180 | uncompressed size (equal, so this entry is effectively stored) |
| `+28` | `3a 00` | 58 | file name length |
| `+30` | `00 00` | 0 | extra field length |
| `+32` | `00 00` | 0 | file comment length |
| `+34` | `00 00` | 0 | disk number start |
| `+36` | `00 00` | 0 | internal file attributes |
| `+38` | `00 00 00 00` | 0 | external file attributes |
| `+42` | `00 00 00 00` | 0 | **relative offset of the local file header** |
| `+46` | `4d 45 …` | `META-INF/com/android/build/gradle/app-metadata.properties` | file name |

The record is `46 + nameLen + extraLen + commentLen` bytes long, so the next record begins at
`0x3E7A00 + 46 + 58 = 0x3E7A68`. Walking 918 of these by hand is not the point — Part 3 automates
it — but decoding one gives you the vocabulary.

> **Warning** The central directory says this entry's local header is at offset 0. Compare that
> with Step 2.1, where offset 0 held `AndroidManifest.xml`. In a real APK the two agree; the
> mismatch above is an artefact of using illustrative values from two different files. When you run
> this on your own APK, the name at the local header offset **must** equal the name in the central
> directory record. A divergence there is a finding, not a typo, and `parse_apk_zip.py` in Part 3
> checks it for you.

### Step 2.4 — Find the APK Signing Block

You now know two boundaries: the entry data starts at offset 0, and the central directory starts at
`cdOffset`. In a plain ZIP those regions are adjacent. In a v2-or-later signed APK there is a block
in between that no ZIP reader ever looks at, because nothing points to it from the EOCD.

The block ends immediately before the central directory, and its last 16 bytes are the ASCII magic
`APK Sig Block 42`. Read backwards from `cdOffset`:

```bash
# host — 32 bytes ending exactly at the central directory (0x3E7A00 - 32 = 0x3E79E0)
xxd -s 4094432 -l 32 target.apk
```

Expected:

```
003e79e0: 0e00 0000 0000 0000 f839 0000 0000 0000  .........9......
003e79f0: 4150 4b20 5369 6720 426c 6f63 6b20 3432  APK Sig Block 42
```

| Region | Offset | Bytes | Meaning |
|---|---|---|---|
| Tail of the last ID-value pair | `0x3E79E0` | `0e 00 …` | Payload bytes of whatever pair came last |
| Block size (suffix) | `0x3E79E8` | `f8 39 00 00 00 00 00 00` | `0x39F8` = 14840 |
| Magic | `0x3E79F0` | `41 50 4b 20 …` | `APK Sig Block 42`, exactly 16 bytes |
| Central directory | `0x3E7A00` | `50 4b 01 02` | Where the EOCD said it would be |

The block's total length on disk is `8 + sizeOfBlock` = `8 + 14840` = 14848 bytes, so it starts at
`0x3E7A00 - 14848` = `0x3E4000`. Confirm by reading the size prefix, which must equal the suffix:

```bash
# host — 0x3E4000 = 4079616
xxd -s 4079616 -l 32 target.apk
```

Expected:

```
003e4000: f839 0000 0000 0000 5504 0000 0000 0000  .9......U.......
003e4010: 1a87 0971 3204 0000 0000 0000 2e04 0000  ...q2.......
```

| Offset | Bytes | Value | Field |
|---|---|---|---|
| `0x3E4000` | `f8 39 00 00 00 00 00 00` | 14840 | `u64 sizeOfBlock` — **must equal the suffix** |
| `0x3E4008` | `55 04 00 00 00 00 00 00` | 1109 | `u64 pairLength` for the first ID-value pair |
| `0x3E4010` | `1a 87 09 71` | `0x7109871A` | `u32 id` — **APK Signature Scheme v2** |
| `0x3E4014` | … | | 1105 bytes of v2 signer data |

The next pair starts at `0x3E4008 + 8 + 1109` = `0x3E447D`. Repeat until you reach the size suffix.

### Step 2.5 — Identify the schemes by block ID

Every pair you walk gives you a 32-bit ID. Match it against this table:

| ID | Scheme / owner |
|---|---|
| `0x7109871a` | APK Signature Scheme v2 |
| `0xf05368c0` | APK Signature Scheme v3 |
| `0x1b93ad61` | APK Signature Scheme v3.1 |
| `0x42726577` | Verity padding block — zero-filled, aligns the whole block to 4096 bytes |
| `0x2b09189e` | Source stamp, v1 layout |
| `0x6dff800d` | Source stamp, v2 layout |
| `0x504b4453` | Android Gradle Plugin dependency metadata (observed, undocumented) |
| `0x2146444e` | Google Play metadata added at serving time (observed, undocumented) |
| anything else | Unknown — dump the value and look at it |

> **Pentester's Note** The ID-value pairs are *not* covered by any signature digest. The v2/v3
> digests cover the entry data, the central directory and the EOCD — the signing block is excluded
> because it cannot contain its own hash. That makes an unknown ID-value pair a signature-safe
> hiding place for arbitrary data. On a routine assessment, enumerate the pairs; anything you cannot
> name deserves a look. [Lab 04](lab-04-ctf-the-lying-manifest.md) builds one deliberately.

### Step 2.6 — Cross-check with `apksigner`

```bash
# host
apksigner verify -v --print-certs target.apk
```

Expected:

```
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): true
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v3.1 scheme (APK Signature Scheme v3.1): false
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
Signer #1 certificate DN: CN=Example, O=Example Ltd, C=GB
Signer #1 certificate SHA-256 digest: 4a1c…
Signer #1 key algorithm: RSA
Signer #1 key size (bits): 2048
```

The `true` lines must correspond exactly to the block IDs you found by hand. If `apksigner` says v3
is present and you found no `0xf05368c0`, you made an arithmetic error — go back and re-walk the
pairs.

---

## Part 3 — The same walk, programmatically

Doing this by hand once is education. Doing it a hundred times is a script. Here is a compact,
dependency-free version you can paste into a file and run; the fuller versions with anomaly
detection live in [`../examples/parse_apk_zip.py`](../examples/parse_apk_zip.py) and
[`../examples/parse_signing_block.py`](../examples/parse_signing_block.py).

```python
#!/usr/bin/env python3
# host — save as walk_apk.py, run: python3 walk_apk.py target.apk
"""Minimal APK container walk: EOCD -> central directory -> signing block."""
import struct
import sys

EOCD_SIG = b"PK\x05\x06"          # 0x06054b50
CD_SIG = b"PK\x01\x02"            # 0x02014b50
LFH_SIG = b"PK\x03\x04"           # 0x04034b50
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

BLOCK_IDS = {
    0x7109871A: "APK Signature Scheme v2",
    0xF05368C0: "APK Signature Scheme v3",
    0x1B93AD61: "APK Signature Scheme v3.1",
    0x42726577: "verity padding",
    0x2B09189E: "source stamp (v1 layout)",
    0x6DFF800D: "source stamp (v2 layout)",
    0x504B4453: "AGP dependency metadata (observed)",
    0x2146444E: "Google Play metadata (observed)",
}


def find_eocd(data: bytes) -> int:
    """Scan backwards for the EOCD signature.

    The comment field can be up to 65535 bytes, so the EOCD may sit as far as
    65557 bytes from the end. We scan the whole tail and take the LAST match
    whose declared comment length is consistent with the file size, because the
    signature bytes can legitimately occur inside compressed data.
    """
    start = max(0, len(data) - (22 + 0xFFFF))
    best = -1
    pos = data.find(EOCD_SIG, start)
    while pos != -1:
        if pos + 22 <= len(data):
            comment_len = struct.unpack_from("<H", data, pos + 20)[0]
            if pos + 22 + comment_len == len(data):
                best = pos
        pos = data.find(EOCD_SIG, pos + 1)
    if best < 0:
        raise ValueError("no consistent EOCD found - not a ZIP?")
    return best


def main(path: str) -> None:
    data = open(path, "rb").read()
    print(f"file           : {path}")
    print(f"size           : {len(data)} bytes (0x{len(data):x})")
    verdict = "OK - local file header" if data[:4] == LFH_SIG else "SUSPICIOUS"
    print(f"first 4 bytes  : {data[:4].hex()} ({verdict})")

    eocd = find_eocd(data)
    total, cd_size, cd_off, comment_len = struct.unpack_from("<HIIH", data, eocd + 10)
    print(f"EOCD at        : 0x{eocd:x}")
    print(f"entries        : {total}")
    print(f"CD size        : {cd_size} bytes")
    print(f"CD offset      : 0x{cd_off:x}")
    print(f"comment length : {comment_len}")

    # Walk the central directory.
    off, names = cd_off, []
    while off < cd_off + cd_size and data[off:off + 4] == CD_SIG:
        method, = struct.unpack_from("<H", data, off + 10)
        csize, usize = struct.unpack_from("<II", data, off + 20)
        n, m, k = struct.unpack_from("<HHH", data, off + 28)
        lfh, = struct.unpack_from("<I", data, off + 42)
        name = data[off + 46:off + 46 + n].decode("utf-8", "replace")
        names.append(name)
        if len(names) <= 5:
            print(f"  entry {len(names):>3}: {name}  method={method} "
                  f"csize={csize} usize={usize} lfh=0x{lfh:x}")
        off += 46 + n + m + k
    print(f"walked {len(names)} central directory records "
          f"({'matches EOCD' if len(names) == total else 'MISMATCH vs EOCD'})")

    dupes = {x for x in names if names.count(x) > 1}
    print(f"duplicate names: {sorted(dupes) if dupes else 'none'}")

    # The signing block, if any, ends immediately before the central directory.
    if cd_off >= 32 and data[cd_off - 16:cd_off] == APK_SIG_BLOCK_MAGIC:
        size_suffix, = struct.unpack_from("<Q", data, cd_off - 24)
        block_start = cd_off - size_suffix - 8
        size_prefix, = struct.unpack_from("<Q", data, block_start)
        print(f"signing block  : 0x{block_start:x} .. 0x{cd_off:x} "
              f"({size_suffix + 8} bytes)")
        print(f"  size prefix/suffix agree: {size_prefix == size_suffix}")
        p = block_start + 8
        while p < cd_off - 24:
            pair_len, = struct.unpack_from("<Q", data, p)
            if pair_len < 4 or p + 8 + pair_len > cd_off - 24 + 8:
                print("  malformed pair length - stopping")
                break
            pair_id, = struct.unpack_from("<I", data, p + 8)
            name = BLOCK_IDS.get(pair_id, "UNKNOWN")
            print(f"  id=0x{pair_id:08x}  len={pair_len - 4:>8}  {name}")
            p += 8 + pair_len
    else:
        print("signing block  : absent (v1-only or unsigned)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "target.apk")
```

```bash
# host
python3 walk_apk.py target.apk
```

Expected output:

```
file           : target.apk
size           : 4144058 bytes (0x3f3bba)
first 4 bytes  : 504b0304 (OK - local file header)
EOCD at        : 0x3f3ba4
entries        : 918
CD size        : 49572 bytes
CD offset      : 0x3e7a00
comment length : 0
  entry   1: META-INF/com/android/build/gradle/app-metadata.properties  method=8 ...
  entry   2: AndroidManifest.xml  method=8 csize=8534 usize=31112 lfh=0x0
  ...
walked 918 central directory records (matches EOCD)
duplicate names: none
signing block  : 0x3e4000 .. 0x3e7a00 (14848 bytes)
  size prefix/suffix agree: True
  id=0x7109871a  len=    1105  APK Signature Scheme v2
  id=0xf05368c0  len=    1191  APK Signature Scheme v3
  id=0x42726577  len=   12512  verity padding
```

Then run the fuller parser from the chapter, which adds the checks this minimal version omits:

```bash
# host
python3 ../examples/parse_apk_zip.py target.apk
python3 ../examples/parse_signing_block.py target.apk
```

---

## Part 4 — Deliberately break it, and watch what happens

Understanding a format is easiest when you see it fail. Make a copy first.

### Step 4.1 — Append a byte and observe

```bash
# host
cp target.apk broken1.apk
printf 'A' >> broken1.apk
python3 walk_apk.py broken1.apk
```

The EOCD scan now fails its consistency test on the last match, because
`eocdOffset + 22 + commentLength` no longer equals the file size. Different ZIP implementations
handle this differently — some tolerate trailing garbage, some refuse. That variation is the whole
attack surface in miniature.

### Step 4.2 — Add an entry and re-verify

```bash
# host
cp target.apk broken2.apk
echo "hello" > note.txt && zip broken2.apk note.txt
apksigner verify -v broken2.apk
```

Expected: the v2 and v3 lines flip to failure, because the entry-content region, the central
directory and the EOCD all changed. If the APK also carried v1, the v1 line may still say `true` —
that is the pre-2016 world, and exactly why v2 exists.

### Step 4.3 — Prepend data and observe the first four bytes

```bash
# host
cp target.apk broken3.apk
printf 'dex\n035\0' | cat - target.apk > broken3.apk
head -c 4 broken3.apk | xxd -p            # 6465780a, not 504b0304
python3 walk_apk.py broken3.apk           # flags "SUSPICIOUS"
```

This is a harmless imitation of the Janus shape: a real Janus file carries a *complete, valid* DEX
before the ZIP. The point is the detection, which is a four-byte comparison.

---

## Hints

<details>
<summary>Hint 1 — my hex offsets do not line up with the tables</summary>

`xxd -s <offset>` takes a **decimal** offset unless you write it as `0x…`. Both of these work:

```bash
xxd -s 4094464 -l 96 target.apk
xxd -s 0x3e7a00 -l 96 target.apk
```

Also remember `xxd -s -64 file` (with the minus sign) means "64 bytes from the end", which is what
you want for the EOCD.
</details>

<details>
<summary>Hint 2 — my decoded numbers are enormous or negative</summary>

You are reading big-endian. ZIP is little-endian: the bytes `a4 c1 00 00` are `0x0000C1A4` = 49572,
not `0xA4C10000`. Reverse the byte order before converting. In Python, `struct.unpack('<I', b)`
does it for you — the `<` is the little-endian marker.
</details>

<details>
<summary>Hint 3 — I cannot find the signing block magic</summary>

Two possibilities. Either the APK is v1-only (check for `META-INF/*.RSA` with
`unzip -l target.apk | grep META-INF`), or you are looking in the wrong place. The magic is the 16
bytes **immediately before** the central directory offset from the EOCD, not at a fixed distance
from the end of the file. As a fallback:

```bash
grep -abo 'APK Sig Block 42' target.apk
```

The number `grep -b` prints is the byte offset of the magic; the central directory begins 16 bytes
later.
</details>

<details>
<summary>Hint 4 — my central directory walk stops early</summary>

Each record is `46 + fileNameLength + extraFieldLength + fileCommentLength` bytes. Forgetting the
extra field or the comment length is the usual cause. Print those three lengths for the record where
the walk breaks and check them against `zipinfo -v` output for the same entry.
</details>

---

## Success criteria

You have completed the lab when all of the following are true.

| # | Criterion | How you prove it |
|---|---|---|
| 1 | You can state the first four bytes of a valid APK and why they matter | `head -c 4 target.apk \| xxd -p` returns `504b0304`, and you can explain what a different value implies |
| 2 | You located the EOCD by hand | You can name its offset and show the `50 4b 05 06` bytes at it |
| 3 | You decoded the central directory offset by hand | Your value matches what `walk_apk.py` prints |
| 4 | Your arithmetic closes | `cdOffset + cdSize + 22 + commentLength` equals the file size exactly |
| 5 | You decoded at least one central directory record fully | You can name the entry, its compression method, both sizes, its CRC and its local header offset |
| 6 | You located the APK Signing Block | You can name its start and end offsets, and the size prefix equals the size suffix |
| 7 | You enumerated the block IDs | Your list of scheme block IDs matches the `true` lines from `apksigner verify -v` |
| 8 | You can do it without the manual walk | `python3 ../examples/parse_apk_zip.py target.apk` runs clean on your APK |
| 9 | You have seen it break | Steps 4.1–4.3 produced the failures described |

---

## What to take into the next lab

You can now read the container. [Lab 02](lab-02-unpack-modify-rebuild-resign.md) takes the next
step: changing what is inside it, putting it back together, and dealing with the signature you just
learned to find. [Lab 03](lab-03-write-your-own-axml-parser.md) builds the parser you need for the
formats *inside* the container, and [Lab 04](lab-04-ctf-the-lying-manifest.md) then uses everything
from all three — a manifest that lies to your tools and a payload hidden exactly where you now know
to look.

For the formats *inside* the container, continue with
[12-DEX-Internals](../../12-DEX-Internals/README.md) for `classes*.dex` and
[15-Native-Code](../../15-Native-Code/README.md) for `lib/<abi>/*.so`.
