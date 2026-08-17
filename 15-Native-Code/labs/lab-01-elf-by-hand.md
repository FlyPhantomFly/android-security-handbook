# Lab 01 — Parse an ELF by hand

> **Objective:** read the first 64 bytes of a real Android native library with your own eyes, work
> out what every field means without running a single specialised tool, then write a fifty-line
> parser that proves you were right — and only then look at what the chapter's script says.

**Prerequisites:** [15-Native-Code §3.2–§3.5](../README.md#32-the-elf-header-field-by-field),
[01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) §3.2 (hexadecimal) and §3.4
(endianness)
**Difficulty:** Beginner, but do not skip it
**Time:** 90 minutes
**You will need:** a `.so` file, a hex viewer (or `od`, or Python), and Python 3

---

## Why this lab exists

There is a script three directories away that prints every answer in this lab in one command. Use it
after, not instead.

Reading the ELF specification is not the same as making the offsets work. The format only becomes
real when your own arithmetic is wrong and you have to find out why. Every reverse engineer who is
comfortable with binaries has, at some point, sat with a hex dump and counted bytes; this lab is
that afternoon, compressed.

There is also a practical payoff. When a packer produces a file that `readelf` refuses and Ghidra
loads wrongly, the only person who can say what is actually in it is the one who can read the header
by hand. Lab 05 is exactly that situation.

---

## Setup

### Option A — build the fixtures (preferred)

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"      # wherever your SDK lives
cd 15-Native-Code/examples
./build-fixtures.sh /tmp/ch15-fixtures
ls -la /tmp/ch15-fixtures
```

### Option B — no NDK

Any ELF file works for this lab. Pick one:

```bash
# host — from any APK you legitimately have
unzip -o some-app.apk 'lib/arm64-v8a/*' -d /tmp/ch15-fixtures/

# adb — from a device you own
adb pull /system/lib64/libc.so /tmp/ch15-fixtures/
```

A 32-bit library as well as a 64-bit one is ideal, because §Part 5 depends on the difference. If you
only have one width, do Part 5 by reading rather than running.

Throughout, `TARGET` is whichever file you chose:

```bash
# host
TARGET=/tmp/ch15-fixtures/libdemo-hard.so
```

---

## Part 1 — The first sixteen bytes, by eye

**Get the bytes.** Any of these works; pick whichever you have.

```bash
# host — with xxd
xxd -l 64 "$TARGET"

# host — with od, which is on far more systems
od -A x -t x1z -N 64 "$TARGET"

# host — with nothing but Python
python3 -c "
d = open('$TARGET','rb').read(64)
for i in range(0, 64, 16):
    row = d[i:i+16]
    print('%08x  %-47s  |%s|' % (
        i,
        ' '.join('%02x' % b for b in row),
        ''.join(chr(b) if 32 <= b < 127 else '.' for b in row)))
"
```

You should see something very close to this:

```text
00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
00000010  03 00 b7 00 01 00 00 00  00 00 00 00 00 00 00 00  |................|
00000020  40 00 00 00 00 00 00 00  08 12 00 00 00 00 00 00  |@...............|
00000030  00 00 00 00 40 00 38 00  0a 00 40 00 17 00 16 00  |....@.8...@.....|
```

That dump is `libdemo-hard-stripped.so` as `build-fixtures.sh` produces it with NDK r25c. Your bytes
should differ only in `e_shoff` (offset `0x28`), which depends on how big the file happens to be.

### Task 1.1 — decode `e_ident` yourself

Fill this in from your own dump before reading on.

| Offset | Field | Your byte | Meaning |
|---|---|---|---|
| `0x00`–`0x03` | `EI_MAG` | | |
| `0x04` | `EI_CLASS` | | |
| `0x05` | `EI_DATA` | | |
| `0x06` | `EI_VERSION` | | |
| `0x07` | `EI_OSABI` | | |
| `0x08` | `EI_ABIVERSION` | | |
| `0x09`–`0x0F` | `EI_PAD` | | |

<details>
<summary>Answers for the dump above</summary>

| Offset | Field | Byte | Meaning |
|---|---|---|---|
| `0x00`–`0x03` | `EI_MAG` | `7f 45 4c 46` | `\x7f` then `E`, `L`, `F`. If these are not these bytes, it is not an ELF file |
| `0x04` | `EI_CLASS` | `02` | ELF64. **Every offset after `0x10` depends on this byte** |
| `0x05` | `EI_DATA` | `01` | Little-endian. **Every multi-byte field is byte-reversed** |
| `0x06` | `EI_VERSION` | `01` | ELF version 1. It has never been anything else |
| `0x07` | `EI_OSABI` | `00` | System V. Android does *not* set the Linux value (3) |
| `0x08` | `EI_ABIVERSION` | `00` | |
| `0x09`–`0x0F` | `EI_PAD` | zeros | Reserved |

</details>

> **The two bytes that matter most are `0x04` and `0x05`.** They are the only two fields whose
> position is guaranteed regardless of anything else, and they tell you how to read every other
> field. That is why they are where they are.

### Task 1.2 — the endianness trap

At offset `0x12` the bytes are `b7 00`. What is the value of `e_machine`?

<details>
<summary>Answer</summary>

`0x00B7` = **183** = `EM_AARCH64`. Not `0xB700` = 46848.

Little-endian means the **least significant byte comes first**. Reading a multi-byte field means
reversing the bytes you see. Every field in every Android ELF works this way, and misreading it is
the single most common beginner error in binary analysis.

Practise on the harder one: at `0x28` the eight bytes are `08 12 00 00 00 00 00 00`. That is
`0x0000000000001208` = 4616.

</details>

---

## Part 2 — The rest of the header, by hand

The header from `0x10` onwards is the part whose layout depends on `EI_CLASS`. For ELF64:

| Offset | Field | Size |
|---|---|---|
| `0x10` | `e_type` | 2 |
| `0x12` | `e_machine` | 2 |
| `0x14` | `e_version` | 4 |
| `0x18` | `e_entry` | 8 |
| `0x20` | `e_phoff` | 8 |
| `0x28` | `e_shoff` | 8 |
| `0x30` | `e_flags` | 4 |
| `0x34` | `e_ehsize` | 2 |
| `0x36` | `e_phentsize` | 2 |
| `0x38` | `e_phnum` | 2 |
| `0x3A` | `e_shentsize` | 2 |
| `0x3C` | `e_shnum` | 2 |
| `0x3E` | `e_shstrndx` | 2 |

### Task 2.1 — decode all thirteen

Work them out from your own dump. Then answer these five questions:

1. Is this file position independent?
2. Which `lib/<abi>/` directory does it belong in?
3. Where does the program header table start, and how many entries does it have?
4. Where does the section header table start, and how many entries does it have?
5. Which section holds the section *names*?

(`e_shoff` and `e_shnum` will differ from the reference below if your NDK version differs. Everything
else should match exactly.)

<details>
<summary>Answers for the dump above</summary>

| Field | Bytes | Value | Reading |
|---|---|---|---|
| `e_type` | `03 00` | 3 | `ET_DYN`. **Yes, position independent** |
| `e_machine` | `b7 00` | 183 | AArch64 → `lib/arm64-v8a/` |
| `e_version` | `01 00 00 00` | 1 | |
| `e_entry` | 8 zero bytes | 0 | A plain shared library has no entry point |
| `e_phoff` | `40 00 ...` | 64 | Program headers start immediately after the header |
| `e_shoff` | `08 12 00 ...` | 4616 | Section headers near the end of the file |
| `e_flags` | `00 00 00 00` | 0 | |
| `e_ehsize` | `40 00` | 64 | Confirms ELF64 |
| `e_phentsize` | `38 00` | 56 | Each program header is 56 bytes |
| `e_phnum` | `0a 00` | 10 | Ten segments |
| `e_shentsize` | `40 00` | 64 | Each section header is 64 bytes |
| `e_shnum` | `17 00` | 23 | Twenty-three sections |
| `e_shstrndx` | `16 00` | 22 | Section 22 holds the names |

</details>

### Task 2.2 — a sanity check you can do in your head

`e_phoff` is 64 and `e_ehsize` is 64. What does that tell you about the file's layout?

<details>
<summary>Answer</summary>

The program header table starts **immediately** after the ELF header, with no gap. This is the
normal layout produced by every linker, and it is why the `PT_PHDR` segment usually says
`p_offset = 0x40`.

It is also a useful integrity check: if `e_phoff` were, say, 0x2000 in a small file, either the file
is unusual or someone has been editing it.

</details>

### Task 2.3 — verify your arithmetic

```bash
# host
python3 15-Native-Code/examples/elf_header_by_hand.py "$TARGET"
```

Compare, field by field, with what you wrote down. **If anything disagrees, find out why before
continuing** — the most likely causes are an endianness slip or reading an ELF32 layout on an ELF64
file.

---

## Part 3 — The program header table, by hand

You now know the table starts at `e_phoff` (64) and has `e_phnum` (10) entries of `e_phentsize` (56)
bytes each.

### Task 3.1 — dump the first entry

```bash
# host — 56 bytes at offset 64
python3 -c "
d = open('$TARGET','rb').read()
row = d[64:64+56]
for i in range(0, 56, 16):
    c = row[i:i+16]
    print('%04x  %s' % (64+i, ' '.join('%02x' % b for b in c)))
"
```

Decode it with the ELF64 program header layout:

| Offset within entry | Field | Size |
|---|---|---|
| `0x00` | `p_type` | 4 |
| `0x04` | `p_flags` | 4 |
| `0x08` | `p_offset` | 8 |
| `0x10` | `p_vaddr` | 8 |
| `0x18` | `p_paddr` | 8 |
| `0x20` | `p_filesz` | 8 |
| `0x28` | `p_memsz` | 8 |
| `0x30` | `p_align` | 8 |

### Task 3.2 — find the segment that decides NX

Walk all ten entries looking for `p_type == 0x6474E551` (`PT_GNU_STACK`). Read its `p_flags`.

- `PF_R` = 4, `PF_W` = 2, `PF_X` = 1.
- `p_flags == 6` means `RW-`, which is **NX in effect**.
- `p_flags == 7` means `RWE`, which is **an executable stack**.

Write down what you found.

### Task 3.3 — reconstruct the memory map

For each `PT_LOAD` entry, write a line of the form:

```text
map <p_filesz> bytes from file offset <p_offset> at base+<p_vaddr>, permissions <flags>,
then zero-fill to base+<p_vaddr + p_memsz>
```

Then answer:

1. How many `PT_LOAD` segments are there?
2. Is any of them both writable and executable?
3. Which one has `p_memsz > p_filesz`, and what is the difference called?
4. What is the smallest `p_align` across all `PT_LOAD` entries, and what does it mean for 16 KiB-page
   devices?

<details>
<summary>Answers, for the hardened fixture</summary>

1. **Four.** Read-only, read-execute, and two read-write. Modern linkers split them tightly.
2. **No.** No `PT_LOAD` has both `PF_W` and `PF_X`. If one did, that would be worth a note in any
   report — see [§3.14](../README.md#314-the-mitigation-set-in-full).
3. The read-write one. The difference is `.bss`: zero-initialised globals that occupy no bytes in
   the file.
4. `0x4000` = 16384 if the library was linked with `-Wl,-z,max-page-size=16384`, and `0x1000` = 4096
   otherwise. A 4 KiB-only library **will not load at all** on a 16 KiB-page device.

</details>

### Task 3.4 — check yourself

```bash
# host
python3 15-Native-Code/examples/elf_header_by_hand.py "$TARGET" | sed -n '/Program headers/,/^$/p'
```

---

## Part 4 — Write the parser

Now write it yourself. Aim for **fifty lines**, no imports beyond `struct` and `sys`, no
error handling. The point is the offsets, not the robustness.

### Task 4.1 — the skeleton

Create `/tmp/ch15-fixtures/myelf.py` and fill in the gaps:

```python
#!/usr/bin/env python3
# /tmp/ch15-fixtures/myelf.py -- lab 01, write this yourself
import struct, sys

data = open(sys.argv[1], 'rb').read()

assert data[:4] == b"\x7fELF", "not an ELF file"

ei_class = data[4]                  # 1 = ELF32, 2 = ELF64
ei_data  = data[5]                  # 1 = little-endian
is64   = (ei_class == 2)
endian = '<' if ei_data == 1 else '>'

# TASK: unpack the header. Hint -- one struct.unpack_from call does all of it.
#   ELF64 from offset 16: 'HHIQQQIHHHHHH'
#   ELF32 from offset 16: 'HHIIIIIHHHHHH'
# The FIELD ORDER is identical; only the widths of e_entry, e_phoff and
# e_shoff differ.

# TASK: print e_type, e_machine, e_phoff, e_phnum, e_shoff, e_shnum, e_shstrndx

# TASK: loop over the program headers.
#   ELF64 entry: 'IIQQQQQQ'  ->  type, flags, offset, vaddr, paddr, filesz, memsz, align
#   ELF32 entry: 'IIIIIIII'  ->  type, offset, vaddr, paddr, filesz, memsz, FLAGS, align
#   NOTE the flags field is in a DIFFERENT PLACE. This is the classic bug.

# TASK: for each PT_LOAD (type 1), print a one-line memory-map instruction.
# TASK: find PT_GNU_STACK (type 0x6474E551) and print whether NX is in effect.
```

### Task 4.2 — success criteria for the parser

Your parser must, for both a 64-bit and a 32-bit library:

- [ ] Print `e_type`, `e_machine` and their meanings
- [ ] Print every program header with correct permissions
- [ ] Correctly state whether the stack is executable
- [ ] Produce **identical values** to `examples/elf_header_by_hand.py`

<details>
<summary>Hint if the 32-bit permissions come out wrong</summary>

You almost certainly used the ELF64 field order for the 32-bit case. On ELF32, `p_flags` is the
**seventh** field at offset `0x18`, not the second at offset `0x04`. It is the only structure in ELF
where the field order genuinely changes between widths, and it exists because ELF32 predates the
64-bit layout and the committee reordered for alignment.

</details>

<details>
<summary>A working reference, if you are stuck for more than twenty minutes</summary>

```python
#!/usr/bin/env python3
import struct, sys

data = open(sys.argv[1], 'rb').read()
assert data[:4] == b"\x7fELF"
is64 = data[4] == 2
en = '<' if data[5] == 1 else '>'

fmt = en + ('HHIQQQIHHHHHH' if is64 else 'HHIIIIIHHHHHH')
(e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
    struct.unpack_from(fmt, data, 16)

print('e_type    ', e_type, '(3 = ET_DYN)')
print('e_machine ', e_machine, '(183 = AArch64, 40 = ARM)')
print('e_phoff   ', e_phoff, 'x', e_phnum, 'entries of', e_phentsize)
print('e_shoff   ', e_shoff, 'x', e_shnum, 'entries of', e_shentsize)

PT = {1: 'PT_LOAD', 2: 'PT_DYNAMIC', 4: 'PT_NOTE', 6: 'PT_PHDR',
      0x6474e551: 'PT_GNU_STACK', 0x6474e552: 'PT_GNU_RELRO'}

for i in range(e_phnum):
    b = e_phoff + i * e_phentsize
    if is64:
        t, fl, off, va, _pa, fsz, msz, al = struct.unpack_from(en + 'IIQQQQQQ', data, b)
    else:
        t, off, va, _pa, fsz, msz, fl, al = struct.unpack_from(en + 'IIIIIIII', data, b)
    perm = ('R' if fl & 4 else '-') + ('W' if fl & 2 else '-') + ('X' if fl & 1 else '-')
    print('%-14s off=0x%-8x vaddr=0x%-10x filesz=0x%-8x memsz=0x%-8x %s align=0x%x'
          % (PT.get(t, hex(t)), off, va, fsz, msz, perm, al))
    if t == 1:
        print('    -> map %d bytes from file 0x%x at base+0x%x as %s, zero-fill to base+0x%x'
              % (fsz, off, va, perm, va + msz))
    if t == 0x6474e551:
        print('    -> stack is', 'EXECUTABLE' if fl & 1 else 'not executable')
```

</details>

---

## Part 5 — The two widths, side by side

### Task 5.1 — run your parser on both

```bash
# host
python3 /tmp/ch15-fixtures/myelf.py /tmp/ch15-fixtures/libdemo-hard.so
python3 /tmp/ch15-fixtures/myelf.py /tmp/ch15-fixtures/libdemo-arm32.so
```

Record the differences:

| | arm64 | arm32 |
|---|---|---|
| `EI_CLASS` | | |
| `e_machine` | | |
| `e_ehsize` | | |
| `e_phentsize` | | |
| `e_shentsize` | | |
| Offset of `e_phoff` | | |

<details>
<summary>Answers</summary>

| | arm64 | arm32 |
|---|---|---|
| `EI_CLASS` | 2 | 1 |
| `e_machine` | 183 | 40 |
| `e_ehsize` | 64 | 52 |
| `e_phentsize` | 56 | 32 |
| `e_shentsize` | 64 | 40 |
| Offset of `e_phoff` | `0x20` | `0x1C` |

The 12-byte shift comes entirely from `e_entry`, `e_phoff` and `e_shoff` being 8 bytes instead of 4.
Everything from `e_flags` onwards is shifted by exactly 12.

</details>

### Task 5.2 — the one that is not just a width change

Look at the ARM32 file's program headers. You will see a segment type your table does not name:
`0x70000001`.

What is it, and why does your parser print it as a raw number?

<details>
<summary>Answer</summary>

`PT_ARM_EXIDX` — an ARM-specific segment holding the exception index table used for stack unwinding.
The value is in the processor-specific range (`PT_LOPROC` = `0x70000000` upwards), which means it is
defined by the **architecture's** ABI supplement, not by the base ELF specification.

Your parser prints it as a number because that is the honest thing to do: it does not know. So does
`examples/elf_header_by_hand.py`, and so does `scripts/elf-inspect.py`. A parser that guessed would
be worse.

This is a small but real lesson: ELF has three tiers of definition — the generic ABI, the
processor-specific supplement, and the OS-specific range (`0x6xxxxxxx`, where all the `GNU_*` and
`ANDROID_*` values live). When a tool shows you a raw constant, look for which tier it belongs to
rather than assuming the file is corrupt.

</details>

---

## Part 6 — Only now, the chapter's tools

```bash
# host — the full picture
python3 15-Native-Code/scripts/elf-inspect.py "$TARGET" --header --segments --sections

# and the checklist
python3 15-Native-Code/scripts/elf-harden-check.py "$TARGET"
```

### Task 6.1 — reconcile

For each line of the checker's output, say which field you read by hand produced it:

| Checker line | Which byte(s) you read |
|---|---|
| `Architecture ... AArch64 / arm64-v8a / 64-bit` | |
| `PIE / position independence ... yes` | |
| `NX / non-executable stack ... yes` | |
| `16 KiB page compatibility ... aligned to 0x4000` | |

<details>
<summary>Answers</summary>

| Checker line | Bytes |
|---|---|
| Architecture | `e_machine` at `0x12`, `EI_CLASS` at `0x04` |
| PIE | `e_type` at `0x10` |
| NX | `p_flags` of the `PT_GNU_STACK` program header |
| 16 KiB | the smallest `p_align` across all `PT_LOAD` program headers |

Everything the hardening checker says about those four items came from bytes you have now read
yourself. That is the point of the lab: the tool is a convenience, not an oracle.

</details>

---

## Success criteria

- [ ] You can point at any byte in the first 64 and say what it is, without a reference
- [ ] You decoded `e_machine` correctly, allowing for little-endian
- [ ] Your own parser prints the same program header table as the reference, on **both** widths
- [ ] You correctly identified whether the stack is executable, from `p_flags`
- [ ] You can explain why the ELF32 program header has `p_flags` in a different place
- [ ] You can explain what `PT_ARM_EXIDX` is and why a good parser prints it as a number
- [ ] You can name, for each of four checker output lines, which byte produced it

---

## Going further

1. **Extend your parser to section headers.** Remember it takes two passes: one to find the section
   named by `e_shstrndx`, one to name everything. Print which sections have `sh_addr == 0` and
   explain what that means.
2. **Corrupt a file deliberately.** Copy a library, set `e_shoff` to 0 with Python, and re-run both
   your parser and `readelf`. Note which tools cope and which give up. This is exactly what a packer
   does, and lab 05 depends on it.
3. **Read a real system library.** `adb pull /system/lib64/libc.so` and run your parser on it. It has
   thousands of symbols and a much richer program header table; nothing you learned stops applying.
4. **Find the ELF specification's own words** for `p_memsz` and `p_filesz`, and check that your
   one-line memory-map instruction matches. The specification is short and clear on this.

---

## Next

[Lab 02 — Run the hardening checklist](lab-02-hardening-audit.md), which uses the fields you just
read to make judgements, and then makes you write one of them up wrongly on purpose.
