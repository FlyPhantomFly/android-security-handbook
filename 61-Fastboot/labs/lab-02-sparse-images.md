# Lab 02 — The sparse image format, by hand

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Chapter 61 §2.2](../README.md#22-the-three-legged-transaction-that-every-fastboot-operation-is-built-from),
[§3.5](../README.md#35-sparse-images-how-a-3-gb-image-crosses-a-256-mb-buffer),
[§5.4](../README.md#54-vulnerability-classes-in-bootloaders-themselves)
**You need:** a host with `python3`. **No device, no emulator, nothing to brick.**

> This lab is entirely offline. It builds, parses, breaks and repairs files. The worst outcome is a
> corrupt file in a scratch directory.

---

## Objective

Understand the Android sparse image format well enough to:

1. **Build one by hand**, byte by byte, from `struct.pack` and nothing else.
2. **Parse an arbitrary one** and describe every chunk.
3. **Explain why it is not compression** — and demonstrate a case where it makes a file *larger*.
4. **Break one in six ways** that a careless parser accepts, and understand why each matters when the
   parser is running in the most privileged execution context on a phone.
5. **Explain the `DONT_CARE` remanence trap** and why it matters to a forensic examiner.

## Why this matters

**Practically:** every `fastboot flash` of a large partition goes through this format, and the
"Sending sparse 'super' 3/7" messages people watch scroll past are re-sparsing in action. Knowing the
format turns those messages from noise into information.

**Security-wise, and this is the real reason:** the sparse header is **entirely attacker-controlled
input containing lengths and counts**, parsed by a bootloader — freestanding C with no ASLR, no stack
protector, no NX and no memory protection. That is the canonical description of an attack surface.
Part 4 of this lab builds the malformed inputs that a correct parser must reject, which is the same
thing as building a list of the bugs an incorrect one has.

**Pedagogically:** it is the smallest complete binary format in this repository. If you have never
written a parser for a binary structure, this is the one to start with — two structs, four chunk
types, and every field matters.

---

## Setup

```bash
# host, from the chapter root
mkdir -p /tmp/lab02 && cd /tmp/lab02      # or any scratch directory
python3 -B <chapter>/scripts/sparse-tool.py selftest
```

Expect 15 passing checks and exit code 0. If that fails, stop and fix it — the rest of the lab uses
the same code paths.

> **Run Python with `-B`.** It suppresses `.pyc` writing. This repository has twice had a
> `__pycache__` directory committed by a script that was run without it, and `PYTHONDONTWRITEBYTECODE`
> does not always suffice.

---

## Part 1 — The format, from first principles

### Step 1.1 — The two structures

From AOSP at `system/core/libsparse/include/sparse/sparse_format.h`. Every field is **little-endian**
— note that this is the opposite of AVB's `vbmeta`, which is big-endian. Writing both parsers in one
sitting is how people get this wrong.

```
sparse_header (28 bytes)
  offset  size  field            value
  0       4     magic            0xED26FF3A
  4       2     major_version    1
  6       2     minor_version    0
  8       2     file_hdr_sz      28
  10      2     chunk_hdr_sz     12
  12      4     blk_sz           block size in bytes, usually 4096
  16      4     total_blks       size of the EXPANDED image, in blocks
  20      4     total_chunks     how many chunk headers follow
  24      4     image_checksum   CRC32 of the expanded image, or 0

chunk_header (12 bytes)
  offset  size  field            value
  0       2     chunk_type       0xCAC1 RAW | 0xCAC2 FILL | 0xCAC3 DONT_CARE | 0xCAC4 CRC32
  2       2     reserved1        0
  4       4     chunk_sz         size in blocks of the EXPANDED data
  8       4     total_sz         size in bytes of this chunk INCLUDING its 12-byte header
```

**The two size fields mean different things and confusing them is the most common bug.** `chunk_sz`
counts *output blocks*; `total_sz` counts *input bytes*. For a `FILL` chunk `chunk_sz` might be
1,000,000 while `total_sz` is 16.

### Step 1.2 — The four chunk types

| Type | Value | Bytes on disk | Expands to |
|---|---|---|---|
| `RAW` | `0xCAC1` | `chunk_sz × blk_sz` | those bytes verbatim |
| `FILL` | `0xCAC2` | **4** | `chunk_sz` blocks of that 4-byte pattern, repeated |
| `DONT_CARE` | `0xCAC3` | **0** | `chunk_sz` blocks the device may skip entirely |
| `CRC32` | `0xCAC4` | 4 | nothing — a running checksum, contributes no output blocks |

**Q1.** `CRC32` chunks contribute zero output blocks. Why does that matter to a parser that validates
`sum(chunk_sz) == total_blks`?

<details>
<summary>Answer</summary>

Because a `CRC32` chunk must be **excluded** from that sum, or the validation is wrong in a way that
either rejects valid images or, worse, is inconsistent between the validator and the writer.

Look at `parse()` in [`../scripts/sparse-tool.py`](../scripts/sparse-tool.py):

```python
if ctype != CHUNK_CRC32:
    blocks_seen += csz
```

A single missing conditional turns a correct check into a source of false rejections. In a bootloader,
a false rejection during a factory-image flash is a support call; the inverse mistake — accepting an
image whose chunks describe fewer blocks than the header claims — is a partially-written partition.
</details>

---

## Part 2 — Build one by hand

### Step 2.1 — Minimal image

Write this yourself. Do not copy the tool.

```python
#!/usr/bin/env python3
# /tmp/lab02/build.py -- run with: python3 -B build.py
import struct

BLK    = 4096
BLOCKS = 1024                          # 4 MiB when expanded
payload = b"FASTBOOT" * (BLK // 8)     # exactly one block of real data

header = struct.pack("<IHHHHIIII",
    0xed26ff3a,   # magic
    1, 0,         # major, minor
    28, 12,       # file_hdr_sz, chunk_hdr_sz
    BLK,          # blk_sz
    BLOCKS,       # total_blks -- the EXPANDED size
    2,            # total_chunks
    0)            # image_checksum (0 = not computed)

raw  = struct.pack("<HHII", 0xCAC1, 0, 1, 12 + BLK) + payload
fill = struct.pack("<HHII", 0xCAC2, 0, BLOCKS - 1, 12 + 4) + struct.pack("<I", 0)

open("demo.simg", "wb").write(header + raw + fill)
print("wrote demo.simg")
```

```bash
# host
python3 -B build.py
ls -l demo.simg
python3 -B <chapter>/scripts/sparse-tool.py info   demo.simg
python3 -B <chapter>/scripts/sparse-tool.py verify demo.simg
```

Measured output from exactly this script:

```
magic           0xed26ff3a
version         1.0
file_hdr_sz     28
chunk_hdr_sz    12
blk_sz          4096
total_blks      1024  (expanded size 4194304 bytes)
total_chunks    2
image_checksum  0x00000000  (0 = not computed)

idx   type       offset             blocks      on-disk  note
0     RAW        28                      1         4108
1     FILL       4136                 1023           16  pattern 00000000

on disk         4152 bytes
expands to      4194304 bytes
ratio           1010.2 : 1
```

**Q2.** Derive 4,152 by hand from the structure definitions, without running anything.

<details>
<summary>Answer</summary>

28 (file header) + [12 (chunk header) + 4,096 (RAW payload)] + [12 (chunk header) + 4 (FILL pattern)]
= 28 + 4,108 + 16 = **4,152**.

The whole saving is in the second bracket: 1,023 blocks — 4,190,208 bytes of output — described by
sixteen bytes of input. There is no algorithm doing that. It is a repeat count.
</details>

**Q3.** Expand it and verify the round trip:

```bash
python3 -B <chapter>/scripts/sparse-tool.py expand demo.simg demo.img
ls -l demo.img
head -c 32 demo.img | xxd
tail -c 32 demo.img | xxd
```

What is at the start, and what is at the end?

<details>
<summary>Answer</summary>

`demo.img` is exactly 4,194,304 bytes. The first 4,096 bytes are `FASTBOOT` repeated; the remaining
4,190,208 are zeros, because the `FILL` pattern was `00000000`.

The ratio of about 1,010:1 came entirely from being allowed to say "and then 1,023 more of these".
</details>

### Step 2.2 — Prove it is not compression

```python
#!/usr/bin/env python3
# /tmp/lab02/notcompression.py
import os, sys
sys.path.insert(0, "<chapter>/scripts")
import importlib.util
spec = importlib.util.spec_from_file_location("sp", "<chapter>/scripts/sparse-tool.py")
sp = importlib.util.module_from_spec(spec); spec.loader.exec_module(sp)

for name, raw in [
        ("all zeros    ", b"\x00" * 4096 * 256),
        ("one pattern  ", b"\xde\xad\xbe\xef" * 1024 * 256),
        ("RANDOM       ", os.urandom(4096 * 256)),
]:
    simg = sp.create(raw, 4096)
    print("%s raw=%8d sparse=%8d  ratio %8.2f : 1"
          % (name, len(raw), len(simg), len(raw) / len(simg)))
```

> **⚠️ `importlib.util.module_from_spec` writes bytecode even with `PYTHONDONTWRITEBYTECODE=1`.**
> This is a measured fact in this repository — a script using exactly this pattern left a
> `__pycache__` under `scripts/` twice. Run with `python3 -B`, and check afterwards:
> `find . -name __pycache__`.

**Q4.** Predict the third row before running it. Will the sparse form of random data be smaller,
equal, or larger than the raw data?

<details>
<summary>Answer</summary>

**Larger.** Random data has no repeated-pattern blocks, so `create()` emits a single `RAW` chunk
covering everything, and the output is the raw data plus 28 bytes of file header plus 12 bytes of
chunk header — 40 bytes bigger.

That is the whole point of the exercise: **sparse format has no dictionary and no entropy coding.**
It is a *description* of a disk image which is allowed to say "these blocks are this pattern" and "I
decline to describe those blocks". The enormous ratios come entirely from filesystem images being
mostly empty, not from any compression.

Naming it correctly matters in practice: someone who believes it is compression will expect a
guaranteed size reduction and will be confused when `fastboot` still splits the image.
</details>

---

## Part 3 — `DONT_CARE`, and a trap with real consequences

### Step 3.1 — Build one

```python
#!/usr/bin/env python3
# /tmp/lab02/dontcare.py
import struct
BLK = 4096
hdr  = struct.pack("<IHHHHIIII", 0xed26ff3a, 1, 0, 28, 12, BLK, 8, 2, 0)
dc   = struct.pack("<HHII", 0xCAC3, 0, 4, 12)                       # 4 blocks, NO payload
rawc = struct.pack("<HHII", 0xCAC1, 0, 4, 12 + 4*BLK) + (b"A" * BLK * 4)
open("dc.simg", "wb").write(hdr + dc + rawc)
print("bytes on disk:", 28 + 12 + (12 + 4*BLK))
```

```bash
python3 -B dontcare.py
python3 -B <chapter>/scripts/sparse-tool.py info dc.simg
python3 -B <chapter>/scripts/sparse-tool.py expand dc.simg dc.img
ls -l dc.img
head -c 16 dc.img | xxd
```

The `DONT_CARE` chunk costs **twelve bytes** — its header and nothing else — and accounts for four
blocks of the output.

### Step 3.2 — The trap

**Q5.** `sparse-tool.py expand` wrote zeros for the `DONT_CARE` range. Does a *device* write zeros
there when it flashes this image?

<details>
<summary>Answer</summary>

**No, and this is the trap.** `DONT_CARE` means "I decline to describe this range", not "write zeros
here". A device is entitled to skip it entirely, leaving whatever was on flash before.

`expand` has to write *something* to produce a file, and zeros are the conventional choice — which is
exactly why the tool says so in a comment at that line. **An expanded sparse image and the real
post-flash partition can differ**, precisely in the ranges the image declined to describe.

Two consequences that matter:

- **Data remanence.** Flashing a factory image over a partition does not guarantee the old contents
  are gone. For the filesystem this is fine, because its metadata says those blocks are free. For a
  forensic examiner, or anyone reasoning about whether a secret survived a reflash, it is a real and
  frequently-overlooked fact. If you need the old bytes gone, `erase` first.
- **Diffing.** Comparing an expanded factory image against a partition read back from a device will
  show spurious differences in the `DONT_CARE` ranges. Compare only the described ranges.
</details>

**Q6.** Modify `dontcare.py` so the `DONT_CARE` chunk carries a 4-byte payload (`total_sz = 16`).
Does `sparse-tool.py verify` accept it? Should it?

<details>
<summary>Answer</summary>

It rejects it: `chunk 0 DONT_CARE: payload is 4 bytes, must be 0`.

It should. A `DONT_CARE` chunk with a payload is either a writer bug or a deliberate attempt to smuggle
bytes past a parser that skips the chunk without checking its length. A parser that advances by
`total_sz` while ignoring the payload is *safe*; one that advances by `chunk_hdr_sz` while the file
actually contains more is now desynchronised from the stream, and every subsequent chunk header is
read from the wrong offset — which is a parser confusion primitive.
</details>

---

## Part 4 — Break it six ways

This is the security part. Each mutation below is a class of malformed input a privileged parser must
reject. Build them, run `verify`, and — more importantly — reason about what an unchecked parser
would do.

```python
#!/usr/bin/env python3
# /tmp/lab02/break.py -- run with python3 -B
import struct, subprocess, sys

good = open("demo.simg", "rb").read()
FH, CH = 28, 12

cases = {
  "01-bad-magic":        (0,      struct.pack("<I", 0xDEADBEEF)),
  "02-blk-sz-zero":      (12,     struct.pack("<I", 0)),
  "03-total-blks-lies":  (16,     struct.pack("<I", 999999)),
  "04-total-sz-huge":    (FH + 8, struct.pack("<I", 0x7FFFFFFF)),
  "05-total-sz-tiny":    (FH + 8, struct.pack("<I", 3)),
  "06-unknown-type":     (FH,     struct.pack("<H", 0xDEAD)),
  "07-chunk-hdr-sz-2":   (10,     struct.pack("<H", 2)),
}

for name, (off, patch) in cases.items():
    b = bytearray(good)
    b[off:off + len(patch)] = patch
    fn = name + ".simg"
    open(fn, "wb").write(bytes(b))
    r = subprocess.run([sys.executable, "-B",
                        "<chapter>/scripts/sparse-tool.py", "verify", fn],
                       capture_output=True, text=True)
    print("%-22s exit=%d  %s" % (name, r.returncode, r.stdout.strip().splitlines()[0]))
```

All seven must exit `2` with an `INVALID:` line. Now the reasoning, which is the actual exercise.

**Q7.** For each case, say what an unchecked parser running in a bootloader would do.

<details>
<summary>Answer</summary>

| Case | Unchecked behaviour | Why it is dangerous |
|---|---|---|
| **01 bad magic** | Parses whatever follows as a sparse image | Type confusion. An attacker supplies a *different* format entirely and every subsequent field is attacker-chosen |
| **02 `blk_sz` = 0** | `chunk_sz × blk_sz` is 0 for every chunk; loops that advance by that value never terminate | Denial of service at minimum. On a divide (`size / blk_sz`) it is a hardware fault in code with no exception handling |
| **03 `total_blks` lies** | Writes fewer blocks than the header claims and reports success | A **partially written partition** that the tool says flashed fine. This is the silent one, and silent is the worst kind |
| **04 `total_sz` huge** | Reads `0x7FFFFFFF` bytes from a buffer that is 4 KiB | Out-of-bounds **read** — and in a bootloader those bytes may then be written to flash, turning an info leak into persistent corruption |
| **05 `total_sz` < header** | The offset advances by less than a header, or backwards | Infinite loop, or the same chunk parsed forever, or a negative index. In C with an unsigned offset, "backwards" wraps to enormous |
| **06 unknown type** | Falls through the `switch` with no `default` | Undefined behaviour. Whatever the last case left in registers, applied to attacker-controlled sizes |
| **07 `chunk_hdr_sz` = 2** | Reads a 12-byte struct from a 2-byte region and advances by 2 | Reads adjacent chunk data as a header. Full parser desynchronisation with attacker-chosen fields |

Notice how many of these are **arithmetic**, not memory-safety in the obvious sense. `chunk_sz ×
blk_sz` in 32-bit arithmetic overflows at 4 GiB; a bootloader that allocates the product and then
copies the un-multiplied count has a textbook integer-overflow heap overflow. That is why
`sparse-tool.py` carries a `SANE_MAX_BLOCKS` ceiling and checks the running total, rather than only
checking each chunk in isolation.
</details>

**Q8.** Craft an eighth case: an integer overflow. Set `blk_sz = 0x10000` (64 KiB) and a chunk's
`chunk_sz` to `0x10000`. What is `chunk_sz × blk_sz` in 32-bit arithmetic?

<details>
<summary>Answer</summary>

`0x10000 × 0x10000 = 0x100000000`, which is `0` in 32 bits.

A parser computing `uint32_t need = chunk_sz * blk_sz;` gets **zero**, allocates nothing (or passes a
zero length to a bounds check that then trivially passes), and then copies using the *unmultiplied*
count or a separately-computed 64-bit size. That is the heap-overflow shape, and it is reachable over
USB by anyone who can plug into an unlocked device in fastboot mode.

The defences are: do the multiplication in a wider type, check the product against a plausible
maximum before using it, and never compute a length twice by two different routes. `sparse-tool.py`
gets this free from Python's arbitrary-precision integers — which is worth naming, because it means
**this lab's tool cannot demonstrate the bug it is teaching you about.** Reproducing it needs C, and
[70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) covers building that kind of
harness.
</details>

**Q9.** Chapter 70 measured something directly relevant. It fuzzed a parser and found the *same* heap
overflow presenting three ways depending on which allocation it landed in — one loud ASan crash, one
UBSan-only report with **exit code 0**, and one **completely silent, exit 0**. What does that imply
about fuzzing a sparse parser and grading on exit status?

<details>
<summary>Answer</summary>

**A campaign that grades on exit status will report a clean run against a real memory-safety bug.**

The third case in chapter 70 was silent because the overflow landed *inside the same `calloc`*, where
ASan has no redzone to trip. Nothing detected it. Exit code 0, no output, a genuine heap overflow.

For a sparse parser specifically, the chunk stream is a sequence of variable-length reads into
buffers whose sizes come from the same attacker-controlled header — so overflowing from one chunk's
region into the next chunk's region within a single allocation is exactly the shape that goes
undetected.

The practical implication is to grade on *sanitiser output* and on differential behaviour against a
reference implementation, not on whether the process died. And to keep a reference implementation
around: two parsers disagreeing about the same input is a signal that neither crashing gives you.
</details>

---

## Part 5 — Re-sparsing and the download buffer

A device reports its buffer with `getvar:max-download-size`; 256 MiB is typical. A `super` image can
be several gigabytes.

**Q10.** A 3 GiB `super.img` sparses to 900 MiB against a 256 MiB buffer. How many `download:` /
`flash:` round trips, and what must each piece after the first begin with?

<details>
<summary>Answer</summary>

**Four** (900 ÷ 256, rounded up).

Every piece after the first must begin with a **`DONT_CARE` chunk covering all the blocks the earlier
pieces already wrote**, so that this piece's real data lands at the correct offset in the partition.
The device has no memory of the previous transaction — each `flash:super` acts on whatever is
currently in the download buffer — so each piece must be a complete, self-positioning sparse image.

This is the mechanism behind `Sending sparse 'super' 2/4`, and it is why `flash:super` appears four
times for one `fastboot flash super` command. The host tool does it automatically; `-S SIZE` forces a
smaller split.
</details>

**Q11.** Implement it. Add a `split` subcommand to `sparse-tool.py` that takes a sparse image and a
maximum size and emits N sparse images, each self-positioning. Verify by expanding each piece,
overlaying them in order (later `RAW`/`FILL` data wins over earlier `DONT_CARE`), and comparing the
result byte for byte against the expansion of the original.

That final comparison is the whole test. A splitter that produces plausible-looking pieces which
reassemble incorrectly is worse than none, because the failure appears at boot rather than at flash.

---

## Part 6 — Read the real implementation

```
system/core/libsparse/sparse_format.h    the structs you have been packing
system/core/libsparse/sparse_read.c      the parser -- compare its checks to yours
system/core/libsparse/output_file.c      the writer
system/core/libsparse/sparse.c           the public API
```

**Q12.** Compare `sparse_read.c`'s validation against `parse()` in `sparse-tool.py`. Find one check
AOSP performs that this lab's tool does not, or vice versa. Which is right?

There is no answer block for this one, deliberately. It is the exercise: reading a real
security-relevant parser and forming your own view is the skill, and a supplied answer would remove
it. Write down what you find.

---

## Success criteria

- [ ] Build a valid sparse image from `struct.pack` alone, without copying the tool
- [ ] Derive its on-disk size by hand and have the number match
- [ ] Explain why sparse format is not compression, with a case where it *increases* size
- [ ] Explain what `DONT_CARE` means for data remanence after a flash
- [ ] Produce all seven malformed images and explain the danger of each
- [ ] Explain the integer-overflow case and why this lab's Python tool cannot exhibit it
- [ ] Explain why exit status is the wrong grading signal for a fuzzing campaign here
- [ ] Explain re-sparsing and what each piece after the first must begin with
- [ ] Implement `split` and verify it by byte-for-byte reassembly

## Cleanup

```bash
rm -rf /tmp/lab02
find . -name __pycache__ -type d        # must print nothing
```

## Next

[Lab 03 — vbmeta, verity, and the one byte that matters](lab-03-vbmeta-and-verity.md).
