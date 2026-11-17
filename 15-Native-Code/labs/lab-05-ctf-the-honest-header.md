# Lab 05 — CTF: the honest header

> **`libvault.so` is lying to you.** Its section header table says one thing; its program headers
> and dynamic array say another. Only one of them can be right, and only one of them is the one the
> dynamic linker reads. Recover four flags from a file that answers your tools confidently and
> wrongly.

**Prerequisites:** Labs [01](lab-01-elf-by-hand.md), [03](lab-03-symbols-and-linking.md);
[15-Native-Code §3.3](../README.md#33-program-headers-what-the-loader-reads),
[§3.5](../README.md#35-sections-what-tools-read-and-what-you-will-name-in-findings),
[§3.7](../README.md#37-relocations-the-blanks-the-linker-fills-in),
[§3.9](../README.md#39-the-dynamic-array-the-linkers-index)
**Difficulty:** Hard
**Time:** 2–3 hours
**You will need:** Python 3 and nothing else. **No NDK, no device, no compiler.**

---

## Brief

You have pulled a native library out of an APK during an assessment. Your triage script runs, and
the answers it gives you do not add up:

- the `.comment` section says the file was built with **GCC 4.9.2 on Debian** — on an Android
  library, in 2026;
- the export table lists **OpenSSL symbols** and nothing else, in a library the Java side calls for
  a method named `check`;
- `.rodata` is reported as **zero bytes long**, in a library that is 16 KB;
- `.text` is marked executable and **starts at the same address as `.rodata`**.

Every one of those is a section header speaking. None of them is the loader speaking.

Recover four flags. Each requires a different technique, and each corresponds to a section of the
chapter. You can verify any answer against the SHA-256 values below without being told what it is.

---

## Setup

```bash
# host
mkdir -p /tmp/ch15-ctf
python3 15-Native-Code/scripts/ctf-build-challenge.py /tmp/ch15-ctf
cd /tmp/ch15-ctf
S=~/…/15-Native-Code/scripts        # adjust
```

```text
wrote /tmp/ch15-ctf/libvault.so (16384 bytes)

This file is a PARSING target, not a runnable library: its .text
holds filler bytes rather than instructions. Do not push it to a
device expecting it to load.
```

> **This is a parsing challenge, stated plainly.** The generator synthesises a structurally valid
> ELF; `.text` contains filler, not instructions. Everything the labs and the chapter ask you to
> read is real and correctly encoded, and nothing here would execute. That honesty is deliberate: a
> CTF that pretends to be something it is not teaches the wrong habit, and this one is about
> **believing the right table**, which needs no working code.

---

## Rules

1. **Do not run `ctf-build-challenge.py --answers`** until you are done. It prints everything.
2. Every flag is `CTF{...}`. Formats are given per flag so there is no guessing about punctuation.
3. Verify with SHA-256 rather than by looking:

```bash
# host
printf '%s' 'CTF{your_answer_here}' | sha256sum
# or, without sha256sum:
python3 -c "import hashlib,sys;print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" 'CTF{...}'
```

| Flag | SHA-256 of the correct answer |
|---|---|
| 1 | `596a52f5632a637c2c15927369decf397c8392a08ee6d0239f36a6ca9c4f5da9` |
| 2 | `d036ffaddc469ed1840497ed61a737b78e0678e2dc4cbc19d43c163350acba26` |
| 3 | `a2a0124a258f923474a8fc1b56e1b011f71cd26d3b697b5053cc774ab9d1fc50` |
| 4 | `4bc58a4f66ca87f850e02388e7e13e2346c8a37721be5351f5ed1dde347044c4` |

---

## Reconnaissance — do this first, and write down what you are told

```bash
# host
python3 $S/elf-inspect.py libvault.so --header
python3 $S/elf-inspect.py libvault.so --sections
python3 $S/elf-inspect.py libvault.so --dynsyms
python3 $S/elf-harden-check.py libvault.so
```

Record the answers you are given. Several of them are false. Part of the exercise is noticing which,
and being able to say *why* you distrust each one, before you know the truth.

<details>
<summary>Four things that should already look wrong</summary>

1. **`.rodata` has `sh_size = 0`.** A 16 KB library with no read-only data at all is not a thing.
   Even a trivial library has string literals.
2. **`.text` and `.rodata` claim the same `sh_addr`.** Two sections cannot occupy the same address
   with different permissions. One of them is lying, or both are.
3. **The export table is entirely OpenSSL imports.** The library exports *nothing*, yet Java calls
   into it. A library with no exports and no `JNI_OnLoad` cannot serve a native method.
4. **`.comment` says GCC 4.9.2 on Debian.** Android native libraries are built with clang from the
   NDK. `.comment` is unmapped metadata that no loader ever reads, so it can say anything.

Point 4 is the giveaway that this is *deliberate* rather than a build accident: a corrupt file does
not usually acquire a plausible, wrong toolchain banner.

</details>

---

## Flag 1 — What is this library actually called?

**Format:** `CTF{soname_<name>}` — for example `CTF{soname_libfoo.so}`.

The file on disk is `libvault.so`, but a file name proves nothing: the dynamic linker records a
library under its `DT_SONAME`, and a `DT_NEEDED` in another library is satisfied by matching that,
not the path. Your tool's `--dynsyms` output suggests this is an OpenSSL library.

Find the name the linker would actually use.

<details>
<summary>Hint 1</summary>

Which table did `--dynsyms` read to produce those OpenSSL names? Which table would the *linker* read
to answer the same question?

</details>

<details>
<summary>Hint 2</summary>

`DT_SONAME` is tag 14 in the dynamic array. Its value is an offset into the dynamic string table,
which is located by `DT_STRTAB` (tag 5) — not by the `.dynstr` **section header**.

```bash
python3 $S/elf-inspect.py libvault.so --dynamic
```

</details>

<details>
<summary>Solution</summary>

```bash
# host
python3 $S/elf-inspect.py libvault.so --dynamic | grep -E 'SONAME|NEEDED'
```

```text
  0x1                  NEEDED               13 ("libc.so")
  0xe                  SONAME               1 ("libvault.so")
```

The dynamic array resolves `DT_SONAME` through `DT_STRTAB`, which points at the **real** string
table at file offset `0x400`. The `.dynstr` *section header* points at a decoy table at `0xA00`
containing `libinnocent.so`, `libssl.so` and the OpenSSL names.

Confirm which one the file would use with:

```bash
python3 $S/elf-inspect.py libvault.so --no-sections --dynsyms
```

```text
  ! --no-sections: section headers ignored. Every answer below comes from the
    program headers and PT_DYNAMIC, which is what the dynamic linker reads.

  UND                0        FUNC     GLOBAL     DEFAULT malloc
  UND                0        FUNC     GLOBAL     DEFAULT strcmp
  0x1040             48       FUNC     GLOBAL     DEFAULT JNI_OnLoad
  0x1080             96       FUNC     GLOBAL     DEFAULT Java_com_ctf_vault_Vault_check
  0x2118             8        OBJECT   GLOBAL     DEFAULT g_vault_state
```

A completely different library. **Flag 1: `CTF{soname_libvault.so}`**

**The lesson.** `--dynsyms` without `--no-sections` believed a section header. The section header
table is metadata; the dynamic array is load-bearing. When they disagree, the dynamic array wins,
because a file whose dynamic array is wrong does not load, and this one would.

</details>

---

## Flag 2 — What runs before `JNI_OnLoad`?

**Format:** `CTF{ctor_0x<hex>}` — lowercase hex, no leading zeros, e.g. `CTF{ctor_0x1a2b}`. Give the
**link-time virtual address** of the single `.init_array` entry.

<details>
<summary>Hint 1</summary>

`DT_INIT_ARRAY` (tag 25) gives the address of the array; `DT_INIT_ARRAYSZ` (tag 27) gives its size in
bytes. Divide by 8 for the count.

</details>

<details>
<summary>Hint 2</summary>

Read the eight bytes at that address. They are zero. That is not a bug and it does not mean there is
no constructor — see [§3.7](../README.md#37-relocations-the-blanks-the-linker-fills-in).

</details>

<details>
<summary>Hint 3</summary>

Look in `.rela.dyn` for a relocation whose `r_offset` equals the `.init_array` address.

</details>

<details>
<summary>Solution</summary>

```bash
# host
python3 $S/elf-inspect.py libvault.so --relocs
```

```text
.rela.dyn at vaddr 0x580, 24 bytes
  r_offset           type                     symbol                 addend
  0x2100             R_AARCH64_RELATIVE       -                      0x1180
```

`0x2100` is exactly where `DT_INIT_ARRAY` points. The relocation says "at `0x2100`, write
`load_base + 0x1180`". The slot in the file is zero because the value is carried in the **addend**,
which is how every `RELA` relocation works and therefore how every AArch64 build behaves.

The tool does this for you and says so:

```bash
python3 $S/elf-inspect.py libvault.so --init
```

```text
  .init_array at 0x2100, 1 entries
      [0] 0x1180   (slot is 0 in the file; the value comes from the RELATIVE relocation addend)
```

**Flag 2: `CTF{ctor_0x1180}`**

**The lesson.** Dumping `.init_array` from an arm64 library with a hex editor gives you zeros. A
reader who stops there concludes there are no constructors, and misses the first code that runs —
before `JNI_OnLoad`, before `System.loadLibrary` returns, before any instrumentation is in place. On
ARM32, which uses `REL` and has no addend, the same dump gives the real address. Two architectures,
two different correct answers.

</details>

---

## Flag 3 — How many native methods does this library really serve?

**Format:** `CTF{hidden_<name1>_<name2>}`, method names in the order they appear in the file, e.g.
`CTF{hidden_alpha_beta}`.

The export table (once you have the real one) shows exactly one `Java_*` symbol and `JNI_OnLoad`.
The Java side calls more methods than that.

<details>
<summary>Hint 1</summary>

`JNI_OnLoad` present + fewer `Java_*` exports than the Java side declares = dynamic registration.
The mapping lives in a table the code passes to `RegisterNatives` at run time, and that table's
**strings** are ordinary constants in read-only data.

</details>

<details>
<summary>Hint 2</summary>

You cannot read `.rodata` through its section header — it claims to be zero bytes long. What does
the loader use to find read-only data?

</details>

<details>
<summary>Solution</summary>

```bash
# host
python3 $S/elf-inspect.py libvault.so --strings --min 4
```

```text
  (.rodata is absent or claims zero size; reading the read-only
   PT_LOAD segment at 0x0 instead -- the loader trusts this
   and a section header cannot change it)
  ...
  0x600        vault: ready
  0x60d        signRequest
  0x619        ([BJ)[B
  0x621        verifyLicense
  0x62f        (Ljava/lang/String;)Z
  0x645        check
  0x64b        (Ljava/lang/String;)Z
  0x661        CTF{soname_libvault.so}
  ...
```

Three method names, each immediately followed by a JNI type signature — the exact shape of a
`JNINativeMethod[]` table's string constants. `check` corresponds to the visible export
`Java_com_ctf_vault_Vault_check`. The other two, `signRequest` and `verifyLicense`, appear nowhere in
the symbol table at all.

**Flag 3: `CTF{hidden_signRequest_verifyLicense}`**

flag 1 was sitting in that same dump in plaintext, and the section header's `sh_size = 0`
was the only thing stopping a section-based tool from finding it.

**The lesson.** A `Java_*` export count of zero — or of "fewer than the Java side declares" — does
not mean there is no JNI surface. Signature strings in read-only data are the cheapest possible
recovery of a dynamic registration table's *shape*, and they cost no dynamic analysis at all.
Recovering the function **pointers** from that table does need a decompiler; that is
[57-Ghidra](../../57-Ghidra/README.md) §9.2. Understanding what `RegisterNatives` is doing is
[16-JNI](../../16-JNI/README.md).

</details>

---

## Flag 4 — The blob that is not a string

**Format:** the decoded string, which is itself `CTF{...}`.

Somewhere in the read-only region there is a run of bytes that is visibly *structured* — no NULs,
consistent byte range — but is not printable. It is a single-byte XOR.

**The key is one of the values you read in the very first minute of this lab.**

<details>
<summary>Hint 1</summary>

Look at the region around file offset `0x679`, between the plaintext strings. It sits where a string
would sit and behaves like one, except that nothing in it is ASCII.

</details>

<details>
<summary>Hint 2</summary>

Single-byte XOR of ASCII text has a signature: the high bit is set consistently, and the byte
frequency mirrors English letter frequency shifted by the key. Try every key from 0 to 255 and look
for `CTF{` — 256 attempts is instant.

</details>

<details>
<summary>Hint 3 — the intended route</summary>

You do not need to brute force it. The key is `0xB7`, which is 183 — the value of `e_machine` for
AArch64, the second field you read in Part 1 of lab 01.

</details>

<details>
<summary>Solution</summary>

**Brute force, which is what you would do in reality:**

```bash
# host
python3 - <<'PY'
d = open('libvault.so', 'rb').read()
region = d[0x600:0x800]
for key in range(256):
    x = bytes(b ^ key for b in region)
    if b'CTF{' in x:
        i = x.find(b'CTF{')
        print('key 0x%02x ->' % key, x[i:x.find(b'\x00', i)].decode())
PY
```

```text
key 0xb7 -> CTF{segments_never_lie_sections_always_can}
```

(The plaintext flag 1 also appears under key `0x00`, which is a useful reminder that "key zero" is
just "no encryption".)

**The intended route**, with the key derived rather than searched:

```bash
# host
python3 - <<'PY'
import struct
d = open('libvault.so', 'rb').read()
key = struct.unpack_from('<H', d, 18)[0] & 0xFF     # e_machine low byte = 183 = 0xB7
x = bytes(b ^ key for b in d[:0xC00])
i = x.find(b'CTF{')
print('key 0x%02x, at file offset 0x%x:' % (key, i), x[i:x.find(b'\x00', i)].decode())
PY
```

**Flag 4: `CTF{segments_never_lie_sections_always_can}`**

**The lesson.** Two, actually. First, `strings` finding nothing is information, not an absence of
information: encoded data occupying the space where strings should be is a signal in itself, and
string *density* relative to file size is the number to watch. Second — and this is the point of the
whole lab — the flag says it: a section header table is a claim, and a program header table is a
contract the loader enforces.

</details>

---

## Debrief — write it up

You are on an engagement. Write the two paragraphs you would put in the report.

<details>
<summary>Reference write-up</summary>

> **[MEDIUM] `libvault.so` carries a deliberately falsified section header table**
> The section header table of `lib/arm64-v8a/libvault.so` disagrees with the program headers and the
> dynamic array in five specific ways: `.dynstr` and `.dynsym` point at decoy tables listing OpenSSL
> symbols and a `SONAME` of `libinnocent.so`; `.rodata` declares a size of zero; `.text` declares the
> same address as `.rodata`; and `.comment` names a GCC 4.9.2 Debian toolchain that could not have
> produced an Android AArch64 library. The dynamic array — which the loader does read, and which
> must be correct for the library to load at all — gives a `SONAME` of `libvault.so` and an export
> table containing `JNI_OnLoad` and `Java_com_ctf_vault_Vault_check`.
>
> **Impact.** Section headers are not read by the dynamic linker, so none of this affects execution.
> It affects *analysis*: any tool that reads section headers — including several commercial mobile
> scanners and the default configuration of common disassemblers — reports this library's symbols,
> its toolchain and its read-only data incorrectly and without warning. The most likely purpose is
> to defeat automated analysis. This is an anti-analysis measure and is rated Medium on that basis,
> not because it constitutes a memory-safety or authentication defect.
>
> **[INFO] Four native methods are registered dynamically**
> Only one `Java_*` symbol is exported. Method names `signRequest` and `verifyLicense`, with JNI
> type signatures `([BJ)[B` and `(Ljava/lang/String;)Z`, are present in read-only data in the layout
> of a `JNINativeMethod[]` table, indicating registration via `RegisterNatives` from `JNI_OnLoad`.
> An inventory based on the export table alone under-reports this library's attack surface by two
> thirds.
>
> **[INFO] One constructor executes before `JNI_OnLoad`**
> `.init_array` holds a single entry resolving to link-time address `0x1180` via an
> `R_AARCH64_RELATIVE` relocation. Code at this address executes when the dynamic linker finishes
> loading the library — before `JNI_OnLoad`, and before `System.loadLibrary` returns to Java.
> Instrumentation attached after process start will not observe it.

Note what is *not* in that write-up: no claim that the library is malicious, no severity assigned to
the missing canary, and no assertion about what the constructor does — because none of those was
established.

</details>

---

## Success criteria

- [ ] All four flags verified against their SHA-256
- [ ] You can name all five lies in the section header table
- [ ] You can explain, in one sentence, why the dynamic array cannot lie the way the section headers
      can
- [ ] You used `--no-sections` and can say exactly what it changes
- [ ] You explained why an `.init_array` slot reads as zero on AArch64 and not on ARM32
- [ ] You recovered the dynamic-registration method names without any dynamic analysis
- [ ] You wrote the debrief and assigned severities you can defend

---

## Going further

1. **Build your own liar.** Take a real library from `build-fixtures.sh` and patch its section
   headers to point `.dynsym` at `.rodata`. Then run every tool you own against it and rank them by
   how badly they cope. Anything that crashes is being honest; anything that answers confidently is
   not.
2. **Delete instead of lying.** Zero `e_shoff` and `e_shnum` on the same file and compare. Which
   failure mode is more dangerous to an analyst — a tool that says "no sections" or a tool that says
   "here are your sections" and is wrong?
3. **Write a disagreement detector.** Fifty lines: parse both tables, and report every case where a
   section header's `sh_offset`/`sh_size` describes a region that a `PT_LOAD` maps with incompatible
   permissions, or where `DT_STRTAB` and the `.dynstr` section header disagree. That check would have
   flagged this file in one line, and it is not in any tool you can download.
4. **Take it to a decompiler.** Load `libvault.so` into Ghidra and watch which of the five lies its
   loader believes. (Its `.text` is filler, so there is nothing to decompile — the interesting part
   is the loader's memory map. See [57-Ghidra](../../57-Ghidra/README.md) §4.4 for what its loader
   reads.)

---

## Where this goes next

You have finished chapter 15. You can read an ELF file by hand, audit its hardening honestly, and
tell a claim from a contract.

- [16-JNI](../../16-JNI/README.md) — the bridge itself: what `JNIEnv` is, how `RegisterNatives`
  works, and how to recover the table whose *strings* you just found.
- [57-Ghidra](../../57-Ghidra/README.md) — what the code at `0x1180` actually does.
- [53-Frida](../../53-Frida/README.md) — the same library at run time.
- [17-Libraries](../../17-Libraries/README.md) — which third-party library this is, and whether its
  version has known vulnerabilities.
