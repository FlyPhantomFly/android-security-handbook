# Lab 01 — Parse a DEX Header by Hand

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 12 §3.1–3.8, §3.22](../README.md), `xxd`, `python3`

---

## Objective

Decode a real DEX file's header and `map_list` using nothing but a hex dump and arithmetic, then
verify your answers against `dexdump`. By the end you will never again be intimidated by a binary
format, because you will have done one the hard way.

## Why this matters

Three situations where reading bytes is the only option, all of which come up in real work.

Your tools disagree with each other — `apktool` shows one thing, `jadx` another — and you need a
tiebreaker. Your tools fail outright on a deliberately malformed file. Or you need to answer a
structural question no tool exposes, such as "is there data in this file that the map does not
account for?"

The map-coverage check you build in Step 8 is a genuine packer detector you will keep using.

---

## Setup

Get any DEX. The simplest source is an app already on your device.

```bash
# host
adb shell pm list packages -3
adb shell pm path com.example.target
adb pull <the base.apk path> target.apk
unzip -o target.apk 'classes*.dex' -d dex/
cd dex
ls -la
```

Or build a trivial app and use its DEX — smaller files are easier to walk by hand.

Confirm your tools:

```bash
# host
which xxd python3
which dexdump || echo "dexdump is in the Android SDK build-tools; add it to PATH"
```

> **Rule for this lab:** do **not** run `dexdump` until Step 9. The whole point is to derive the
> answers yourself and then check them.

---

## Steps

### Step 1 — The magic

```bash
xxd -l 8 classes.dex
```

**Record** the eight bytes.

**Q1.** What are bytes 0–3 in ASCII? What are bytes 4–6? What is byte 7?

**Q2.** What would you conclude if bytes 0–3 read `dey\n` instead? What if they read `\x7fELF`?

### Step 2 — Checksum and signature

```bash
xxd -s 8 -l 4 classes.dex      # checksum
xxd -s 12 -l 20 classes.dex    # SHA-1 signature
```

The checksum is a little-endian `uint`. Convert it.

**Q3.** Write out the checksum as a normal hex number. Remember the byte order.

Now verify it yourself:

```bash
python3 -c "
import zlib
d = open('classes.dex','rb').read()
print('computed adler32: 0x%08x' % (zlib.adler32(d[12:]) & 0xFFFFFFFF))
"
```

**Q4.** Does it match? Which byte range is the checksum computed over, and why does it start at 12?

```bash
python3 -c "
import hashlib
d = open('classes.dex','rb').read()
print('computed sha1:', hashlib.sha1(d[32:]).hexdigest())
"
```

**Q5.** Which byte range does the signature cover, and why does *it* start at 32?

**Q6.** Both fields verified. Does that tell you the file has not been tampered with? Justify your
answer in one sentence.

### Step 3 — The fixed header fields

The header is 112 bytes (`0x70`). After the 8-byte magic, 4-byte checksum and 20-byte signature comes
a run of twenty 32-bit little-endian values starting at offset `0x20`.

```bash
xxd -s 32 -l 80 classes.dex
```

Decode these by hand. Remember little-endian: the bytes `20 03 00 00` are `0x00000320` = 800.

| Offset | Field | Your value |
|---:|---|---|
| `0x20` | `file_size` | |
| `0x24` | `header_size` | |
| `0x28` | `endian_tag` | |
| `0x2C` | `link_size` | |
| `0x30` | `link_off` | |
| `0x34` | `map_off` | |
| `0x38` | `string_ids_size` | |
| `0x3C` | `string_ids_off` | |
| `0x40` | `type_ids_size` | |
| `0x44` | `type_ids_off` | |
| `0x48` | `proto_ids_size` | |
| `0x4C` | `proto_ids_off` | |
| `0x50` | `field_ids_size` | |
| `0x54` | `field_ids_off` | |
| `0x58` | `method_ids_size` | |
| `0x5C` | `method_ids_off` | |
| `0x60` | `class_defs_size` | |
| `0x64` | `class_defs_off` | |
| `0x68` | `data_size` | |
| `0x6C` | `data_off` | |

**Q7.** Is `header_size` `0x70`? Is `endian_tag` `0x12345678`? What would it mean if either were
different?

**Q8.** Does `file_size` equal the actual file length (`wc -c < classes.dex`)? What would a mismatch
suggest?

**Q9.** Is `method_ids_size` anywhere near 65,536? What happens to a build that exceeds it?

### Step 4 — Reach into the string table

`string_ids` is an array of 4-byte offsets. Each points at a `string_data_item`, which is a ULEB128
length followed by MUTF-8 bytes and a `0x00` terminator.

Read entry **0**:

```bash
# host — replace 0xNNNN with your string_ids_off
xxd -s $((0xNNNN)) -l 16 classes.dex
```

Take the first 4 bytes as a little-endian offset, then:

```bash
# host — replace 0xMMMM with the offset you just decoded
xxd -s $((0xMMMM)) -l 32 classes.dex
```

**Q10.** What is the ULEB128 length byte? What is the string? (For short strings the length is a
single byte below `0x80`, so this is easy — that is why we start with entry 0, which is usually
short.)

Now do entry **5** the same way.

**Q11.** Write a one-line description of the algorithm you just performed. That algorithm is
`string()` in [`../examples/dex_parser.py`](../examples/dex_parser.py).

### Step 5 — Decode a ULEB128 by hand

Find a string long enough that its length needs two bytes (length ≥ 128). Scan the string data region
for a byte with the high bit set:

```bash
xxd -s $((0xDATA_OFF)) -l 256 classes.dex
```

**Q12.** Take a two-byte ULEB128 and decode it manually. Show your working:
`value = (byte0 & 0x7F) | ((byte1 & 0x7F) << 7)`.

### Step 6 — The map_list

Seek to `map_off`:

```bash
# host
xxd -s $((0xMAP_OFF)) -l 64 classes.dex
```

The first 4 bytes are the entry count. Each entry is 12 bytes: `ushort type`, `ushort unused`,
`uint count`, `uint offset`.

**Q13.** How many entries are there? Decode the first three and identify their `TYPE_*` names using
the table in [§3.22](../README.md).

**Q14.** Are the entries sorted by ascending `offset`? Check at least the first five. What would
unsorted entries tell you?

### Step 7 — Cross-check the map against the header

The map should agree with the header about where each index table lives.

**Q15.** Find the `TYPE_STRING_ID_ITEM` entry in the map. Does its `offset` match `string_ids_off`
from the header? Does its `count` match `string_ids_size`?

Repeat for `TYPE_METHOD_ID_ITEM` and `TYPE_CLASS_DEF_ITEM`.

**Q16.** What would a mismatch between the header and the map mean? Which would a lenient parser
believe, and why does that matter?

### Step 8 — Map coverage: the packer detector

This is the payoff.

For each map entry, compute the byte range it occupies. For fixed-stride types, the size is
`count × item_size` (see the table in §3.22). For variable-length types, bound each by the start of
the next section.

**Q17.** Do the ranges tile the file with no gaps? Write down any uncovered region: its start, end and
size.

Now check your answer:

```bash
python3 ../examples/dex_parser.py classes.dex --map-coverage
```

**Q18.** Did you agree with the tool? If there *are* uncovered regions, dump the first 32 bytes of
each and say what you think is there.

### Step 9 — Verify everything

Only now:

```bash
dexdump -f classes.dex | head -40
python3 ../examples/dex_parser.py classes.dex --verify-header
```

**Q19.** Compare against your Step 3 table. Any field you got wrong — work out *why* before moving on.
Byte order and offset arithmetic are the usual culprits.

### Step 10 — Do it on a second file

Repeat Steps 1, 3, 6 and 8 on a DEX from a different app, ideally a much larger one. It should take
under ten minutes the second time.

**Q20.** Did the larger app have multidex? Did any of its DEX files show uncovered regions?

---

## Hints

<details>
<summary>Hint 1 — little-endian conversion keeps confusing me</summary>

The bytes `78 56 34 12` represent `0x12345678`. The *first* byte is the *least* significant. To
convert by hand, read the bytes right to left.

```bash
python3 -c "print(hex(int.from_bytes(bytes([0x78,0x56,0x34,0x12]),'little')))"
```
</details>

<details>
<summary>Hint 2 — xxd offsets</summary>

`xxd -s N` seeks to byte N. `$((0x70))` in bash converts hex to decimal, so
`xxd -s $((0x70)) -l 16 file` dumps 16 bytes starting at offset 0x70. Add `-o $((0x70))` if you want
the displayed offsets to match the file rather than starting at 0.
</details>

<details>
<summary>Hint 3 — I cannot find a multi-byte ULEB128</summary>

Most strings in a small DEX are short. Try a large app's DEX, or search programmatically:

```bash
python3 -c "
d=open('classes.dex','rb').read()
import struct
off=struct.unpack_from('<I',d,0x3C)[0]   # string_ids_off
n=struct.unpack_from('<I',d,0x38)[0]     # string_ids_size
for i in range(min(n,2000)):
    p=struct.unpack_from('<I',d,off+i*4)[0]
    if d[p] & 0x80:
        print('index',i,'at 0x%x'%p, d[p:p+4].hex(' ')); break
"
```
</details>

<details>
<summary>Hint 4 — my map coverage has overlaps, not gaps</summary>

Overlaps usually mean you used the wrong `item_size` for a fixed-stride type. Check the table in
§3.22: `proto_ids` is **12** bytes, `class_defs` is **32**, and `field_ids`/`method_ids` are **8**.
Getting `class_defs` wrong is the common error.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** Bytes 0–3 are `dex\n` (`64 65 78 0a`). Bytes 4–6 are the version, typically `035`, `037`,
`038` or `039`. Byte 7 is a NUL terminator (`0x00`).

**Q2.** `dey\n` means a Dalvik-era ODEX from Android 4.4 or earlier. `\x7fELF` means you are looking
at an **OAT** file — almost certainly a `base.odex` from `/data/app`, which despite its name is an ELF
containing compiled code. See [13-ART §3.1](../../13-ART/README.md).

**Q3.** Read the four bytes right to left. `f3 a1 2c 8b` would be `0x8b2ca1f3`.

**Q4.** It covers bytes `[12:]` — everything after the checksum field itself. It must, because a
checksum cannot cover its own storage.

**Q5.** Bytes `[32:]` — everything after the 20-byte signature field, which ends at offset 32. Same
reasoning.

**Q6.** No. Both fields are **unkeyed**, so anyone who modifies the file recomputes them —
`apktool` does it automatically. They detect corruption, not tampering. Real integrity comes from APK
signing, which is keyed. See [§5.2](../README.md) and
[10-APK-Internals](../../10-APK-Internals/README.md).

**Q7.** `header_size` must be `0x70` and `endian_tag` must be `0x12345678`. A different `header_size`
means a lenient parser might skip fields — a parser-divergence lever. A byte-swapped endian tag
(`0x78563412`) means a reverse-endian file, which the runtime rejects.

**Q8.** They should match exactly. Extra bytes beyond `file_size` mean appended data — another DEX, a
packer payload, or smuggled content.

**Q9.** The cap is 65,536 because several instruction formats encode the index in 16 bits. Exceeding
it forces multidex: `classes.dex`, `classes2.dex`, and so on. Remember the limit counts *references*,
not methods you wrote.

**Q10–Q11.** The algorithm: read a 4-byte LE offset from `string_ids_off + index*4`; seek there; read
a ULEB128 giving the UTF-16 length; the MUTF-8 bytes follow up to a `0x00`.

**Q12.** For bytes `b0 b1` with the high bit set on `b0`:
`value = (b0 & 0x7F) | ((b1 & 0x7F) << 7)`. So `0x80 0x01` = `0 | (1 << 7)` = 128.

**Q13–Q14.** Entries must be sorted by ascending `offset`. Unsorted entries mean the file was not
produced by `d8` — a strong hand-crafting signal.

**Q15–Q16.** They must agree. If they disagree, different parsers may believe different things, which
is precisely the parser-divergence evasion described in [§5.2](../README.md). Treat any disagreement
as the finding, and confirm what the *runtime* does.

**Q17–Q18.** In a legitimate `d8` output there are **no** uncovered regions. A gap means: a packer's
encrypted payload, a second DEX appended, a configuration blob, or data smuggled past a scanner that
only reads the map. If the first bytes of a gap are `dex\n`, another DEX is embedded; `PK` means a ZIP.

**Q20.** Larger apps very commonly have multidex. Always process every `classes*.dex` — analysing only
the first is how people conclude a feature is absent when it is in `classes2.dex`.

</details>

---

## Success criteria

- [ ] You decoded all twenty header fields by hand and they match `dexdump`
- [ ] You verified the checksum and signature yourself, and can explain why neither is a security control
- [ ] You resolved at least two string-table entries by hand
- [ ] You decoded a multi-byte ULEB128 showing your working
- [ ] You parsed the `map_list` and confirmed it is sorted by offset
- [ ] You cross-checked at least three map entries against the header
- [ ] You performed a map-coverage analysis and agreed with the tool
- [ ] You can explain what an uncovered region means and name three possible causes
- [ ] You repeated the exercise on a second, larger DEX in under ten minutes
- [ ] You can state, without looking it up, that `header_size` is `0x70` and `endian_tag` is `0x12345678`
