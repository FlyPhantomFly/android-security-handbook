# Ground truth — what the compiler actually emitted

This file is the answer key for every lab in chapter 58, and it is the standard against which you
judge **any** disassembler, including IDA.

> **📖 Definition**
> **Ground truth** is a fact established by a method that cannot be wrong about it. Here, the compiler
> produced the bytes, so the compiler's own object-code dump is authoritative about what the bytes
> are. A disassembler is a *reader* of those bytes and can disagree with them. When it does, the
> ground truth wins and the disassembler has found you a bug or a limitation.

**Everything below was measured**, not written from memory. Regenerate it on your own machine with:

```bash
# host
cd examples
OUTDIR=/tmp/ch58 ./build.sh          # writes /tmp/ch58/ground-truth.txt
```

| Fact | Value |
|---|---|
| Toolchain | Android NDK **25.2.9519653**, clang **14.0.7**, LLD 14.0.7 |
| Target triple | `aarch64-unknown-linux-android21` |
| Flags | `-O2 -Wall -Wextra -fPIC -shared -Wl,-z,max-page-size=16384` |
| Host | Windows 11, Git Bash |
| Warnings | **zero**, from both source files |
| Date measured | 2026-08-15 |

> **⚠️ Warning**
> The addresses below are from *one* build. Rebuild with a different NDK, a different API level, or a
> different `-O` level and every address changes, and some of the *shapes* change too. Never quote an
> address from this file at a target; quote the shape and re-derive the address. That is the whole
> reason the chapter makes you build the fixture instead of shipping it.
>
> **Addresses moved once during the writing of this chapter, for a reason worth knowing.** Adding
> `__attribute__((noinline))` to one function grew `.rodata` by 29 bytes, and because `.rodata`
> precedes `.text` in this layout, **every function address in the file shifted.** A one-word source
> change moved every number in this document. That is normal, and it is why the labs' flags are
> invariant facts rather than addresses.

---

## 1. What stripping did

```text
unstripped : 43 symbols total, 11 defined in .dynsym
stripped   : 0  symbols total, 11 defined in .dynsym
```

`--strip-all` removed the entire `.symtab` and left `.dynsym` untouched, because the dynamic linker
needs it to resolve exports at `dlopen` time. Chapter 15 establishes this; the number worth carrying
forward is the **asymmetry**: 43 names go in, 11 survive.

The rule for which 11 is **visibility, not origin**. `ch58_crc32` came from a static archive — third-
party code — and keeps its name, because it was compiled with default visibility. `session_slow_path`,
`session_fatal` and `session_reveal` are the application's own and lose theirs, because they are
`static`.

Symbols that survive the strip:

```text
0000000000005358 T Java_com_pentest_ch58_Session_nativeSelfTest
0000000000005530 T ch58_crc32
0000000000005654 T ch58_fnv1a64
000000000000568c T ch58_hex
0000000000004c34 T session_check_magic
0000000000004f90 T session_dispatch
0000000000004c78 T session_init
0000000000005244 T session_report
000000000000508c T session_seal
0000000000004c50 T session_set_digest
0000000000004e2c T session_step
```

Symbols the strip destroyed, read from the answer-key build:

```text
0000000000004f84 t session_fatal
0000000000004fa0 t session_slow_path
000000000000514c t session_reveal
00000000000054f8 t digest_crc
00000000000054fc t digest_fnv
0000000000005510 t digest_sum
```

Plus five entries the NDK's own CRT contributes — `__on_dlclose`, `__on_dlclose_late`,
`__emutls_unregister_key`, `__atexit_handler_wrapper`, `atexit`. Those five are in **every** NDK-built
library and are the cheapest possible check that a signature database is working: if your tool names
them, it has matched something.

---

## 2. The jump table — measured, and not the idiom most references print

`session_step` has a dense twelve-case `switch`. The published AArch64 jump-table idiom is usually
given as a table of 32-bit offsets read with `ldrsw`. **clang 14 did not emit that.** It emitted a
table of **single bytes**, each counting 4-byte instruction words from an `adr` anchor:

```text
# host: llvm-objdump -d --disassemble-symbols=session_step libsession-unstripped.so
    4e74: 3f 2c 00 71   cmp   w1, #11                ; the bound check
    4e78: 08 05 00 11   add   w8, w8, #1
    4e7c: 68 4a 00 b9   str   w8, [x19, #72]
    4e80: 88 02 00 54   b.hi  0x4ed0                 ; -> default
    4e84: e9 ff ff 90   adrp  x9, 0x0                ; page of the byte table
    4e88: e8 03 01 2a   mov   w8, w1
    4e8c: 29 41 21 91   add   x9, x9, #2128          ; + low 12 bits  (0x850)
    4e90: 8a 00 00 10   adr   x10, #16               ; the ANCHOR
    4e94: 2b 69 68 38   ldrb  w11, [x9, x8]          ; ONE BYTE from the table
    4e98: 4a 09 0b 8b   add   x10, x10, x11, lsl #2  ; scaled by 4 (word count)
    4e9c: 40 01 1f d6   br    x10
```

Read it as five facts:

| Instruction | What it establishes |
|---|---|
| `adrp x9, <page>` + `add x9, x9, #2128` | The table's address, split across two instructions because AArch64 cannot encode a full address in one. Chapter 18 §3.6 covers `adrp` |
| `adr x10, #16` | The **anchor**. Every table entry is an offset *from here*, not an absolute address |
| `ldrb w11, [x9, x8]` | **One byte** per case. Not four |
| `add x10, x10, x11, lsl #2` | The byte is a count of instruction words, so it is scaled by 4. Maximum reach: 255 × 4 = 1020 bytes |
| `br x10` | The indirect branch. Nothing here names any destination |

Three consequences you can act on:

1. **The table is 12 bytes, not 48.** Anyone searching a hex dump for a run of plausible addresses
   will not find it.
2. **A tool that only models word-sized tables will not recover the cases.** It will show one `br`
   into nothing and twelve orphaned basic blocks that no function claims.
3. **The bound check is separate and comes first.** `cmp w1, #11` / `b.hi <default>` is what makes the
   table safe. If you ever patch a bound check like that one, you have created an out-of-bounds
   indirect branch — a control-flow hijack primitive, in your own analysis session.

The two tables, as bytes, at `.rodata` offset `0x850`:

```text
0x00000850  0f 11 15 1a 1d 20 00 00 00 23 33 38   <- session_step
0x0000085c  10 14 18 1d 20 23 00 00 00 00 26 2b   <- session_slow_path
```

Twelve bytes each. Index 6, 7 and 8 are `00` in the first table because the source merges the three
digest cases into one body. **Index 9 is also `00` in the second table and is not in the first**, and
that single byte is the entire evidence for section 4 below.

---

## 3. The indirect call

```text
    4eac: 29 21 26 91   add   x9, x9, #2440
    4eb0: e0 03 02 aa   mov   x0, x2
    4eb4: e1 03 03 aa   mov   x1, x3
    4eb8: 28 59 68 f8   ldr   x8, [x9, w8, uxtw #3]
    4ebc: 00 01 3f d6   blr   x8
```

Exactly **one** `blr` in the whole library, in both the stripped and unstripped builds. The target is
loaded from an 8-byte-strided pointer table indexed by a value derived from the caller's `opcode`
argument, so no static analysis can name it.

The pointers are in the file as relocations, not as literals:

```text
000000000000d988  R_AARCH64_RELATIVE   54f8     <- digest_crc
000000000000d990  R_AARCH64_RELATIVE   54fc     <- digest_fnv
000000000000d998  R_AARCH64_RELATIVE   5510     <- digest_sum
```

Twenty-four bytes that read as zero in a hex dump. A tool that applies relocations at load time shows
you three function pointers; one that does not shows you nothing and you conclude the table is empty.
**Check which yours does before you conclude anything about a table.**

> **🔬 Under the Hood**
> This `blr` only exists because `digest_table` is non-`const` and an exported setter
> (`session_set_digest`) can write to it. On the first build of this fixture the table was
> `static const`, and clang proved its contents and turned every indirect call into a direct one —
> `bl ch58_crc32@plt`. The construct the fixture claimed to teach was not in the binary. That failure
> is written up in the README's §11.4 because it is the more useful half of the lesson: **a fixture
> that does not reproduce the construct it claims to teach is worse than no fixture, and the only way
> to know is to disassemble what you built.**

---

## 4. The tail call, and the specialised inline

`session_dispatch` is four instructions and has no stack frame at all:

```text
0000000000004f90 <session_dispatch>:
    4f90: 41 00 f8 37   tbnz  w1, #31, 0x4f98
    4f94: 03 00 00 14   b     0x4fa0 <session_slow_path>
    4f98: 00 00 80 12   mov   w0, #-1
    4f9c: c0 03 5f d6   ret
```

Two things to notice. `if (opcode < 0)` compiled to `tbnz w1, #31` — a **sign-bit test**, not a
comparison against zero. And `return session_slow_path(...)` compiled to `b`, not `bl` plus `ret`:
`session_slow_path` will return straight to `session_dispatch`'s caller.

In a listing that looks like the function simply stops. In a call graph it is still an edge. Tools
differ on whether they draw it, and on whether they treat the target as a separate function or as
more of this one.

`session_slow_path` then calls `session_step` with `in = NULL` — and clang inlines a copy
**specialised on that fact**:

```text
0000000000004fa0 <session_slow_path>:
    4fa0: fd 7b bf a9   stp   x29, x30, [sp, #-16]!
    4fa4: fd 03 00 91   mov   x29, sp
    4fa8: 80 01 00 b4   cbz   x0, 0x4fd8
    4fac: 08 4c 40 b9   ldr   w8, [x0, #76]        ; s->reserved -- only touched here
    4fb0: ca 69 8a 52   mov   w10, #21326
    4fb4: 09 00 40 b9   ldr   w9, [x0]
    4fb8: aa 68 aa 72   movk  w10, #21317, lsl #16 ; the inlined magic check
    ...
    4ff8: 4a 71 21 91   add   x10, x10, #2140      ; a DIFFERENT table  (0x85c)
```

`#2140` versus `#2128`: two tables, twelve bytes apart. In the specialised copy, cases 6 to 9 can
never reach the digest table, so all four collapse into the shared error return — which is the fourth
`00` in the second byte table.

> **🧠 Mental Model**
> `session_step` exists **twice** in this binary, in two different shapes, from one piece of source.
> Any statement of the form "the decompiler shows you the source" is false, and this is the cheapest
> available demonstration. What a decompiler shows you is *a* source program that would compile to
> *these* bytes — and there were two different sets of bytes here.

---

## 5. The predicate that gets patched for nothing

```text
0000000000004c34 <session_check_magic>:
    4c34: c0 00 00 b4   cbz   x0, 0x4c4c
    4c38: 08 00 40 b9   ldr   w8, [x0]
    4c3c: c9 69 8a 52   mov   w9, #21326
    4c40: a9 68 aa 72   movk  w9, #21317, lsl #16
    4c44: 1f 01 09 6b   cmp   w8, w9
    4c48: e0 17 9f 1a   cset  w0, eq
    4c4c: c0 03 5f d6   ret
```

```text
direct calls to session_check_magic anywhere in the library: 0
```

The symbol is exported, the body is correct, and **nothing calls it**. Every real check is an inlined
copy inside `session_step`, `session_slow_path`, `session_dispatch`'s callee and `session_seal` — and
you can count them by counting the `movk #21317` occurrences.

Patching this function to `mov w0, #1 ; ret` produces a function that provably returns 1 and changes
no behaviour whatsoever.

Chapter 18 §5.4 measured this on a different fixture and calls it the most useful teaching artefact in
that chapter: *a patch that provably works, against a function that provably no longer matters*.
Chapter 65 measured the same failure from the hooking side, and chapter 54 found `objection` failing
on it. It reproduces here because it is not a quirk — it is what `-O2` does to small predicates.

---

## 6. The constant that is not in the file

`SESSION_MAGIC` is `0x5345534E`. Search the binary for the bytes `4e 53 45 53` and you find nothing.
The constant is materialised in two instructions:

```text
    4c3c: c9 69 8a 52   mov   w9, #21326           ; 0x534E
    4c40: a9 68 aa 72   movk  w9, #21317, lsl #16  ; 0x5345 into bits 31:16
```

`21326` is `0x534E`; `21317` is `0x5345`. The 32-bit value exists only in a register, only at run
time. Chapter 18 §3.3 gives the encoding; the consequence here is that **byte-level constant search
is defeated by ordinary optimisation, with no obfuscation involved at all.**

The same is true of the FNV-1a constants in `ch58_fnv1a64`: `0xCBF29CE484222325` and `0x100000001B3`
are each assembled from up to four 16-bit fields, so neither appears contiguously anywhere.

---

## 7. Calls to your own exports go through the PLT

```text
    bl    <ch58_crc32@plt>
```

This library calls its own exported functions through the Procedure Linkage Table, because default
visibility makes them **interposable** — another `.so`, or `LD_PRELOAD`, is permitted to replace them,
so the compiler cannot bind the call directly.

Chapter 68 §8.3 measured that a call-site grep for `bl.*<name>` produces a **false negative** on
PLT-routed calls and must be written `bl.*<name(@plt)?>`. This build reproduces it exactly. The
relocations confirm which of the library's own functions are reached that way:

```text
0000000000009950  R_AARCH64_JUMP_SLOT  0000000000004c78  session_init
0000000000009968  R_AARCH64_JUMP_SLOT  0000000000005654  ch58_fnv1a64
0000000000009978  R_AARCH64_JUMP_SLOT  0000000000005530  ch58_crc32
0000000000009980  R_AARCH64_JUMP_SLOT  000000000000568c  ch58_hex
```

The practical consequence for hooking: a PLT-routed call can be intercepted by rewriting one GOT
entry, which is far cheaper than an inline hook. See [65-Hooking](../../65-Hooking/README.md).

---

## 8. Strings that are not strings

```text
matches for '/system/bin/su' and 'ro.debuggable': 0   (expect 0)
```

Both plaintexts are XOR-encoded with `0x5A` and live in `.rodata`; they only exist as text on the
stack inside `session_seal`, after `session_reveal` has run. `strings`, `grep`, and any signature that
searches the file find nothing.

The encoded arrays, at `.rodata` offset `0x866` and `0x875`:

```text
0x00000866  75 29 23 29 2e 3f 37 75 38 33 34 75 29 2f 00
0x00000875  28 35 74 3e 3f 38 2f 3d 3d 3b 38 36 3f 00
```

The su-path array is first. Both byte ranges sit between `0x23` and `0x75`, which is itself a tell: a
range that narrow is not random data, and it is not text either.

What *is* in the file as plain text:

```text
tester
0123456789abcdef
```

That second string is `ch58_hex`'s digit table, and finding it is the fastest route to the hex encoder
in this binary — no instruction reading required, just cross-references from the data.

> **⚠️ Warning — this construct nearly did not survive its own fixture**
> `session_reveal` carries `__attribute__((noinline))`, and it is load-bearing. Without it, clang
> inlined the decoder, constant-folded the XOR at compile time, proved the comparison in
> `session_seal` is always true, and **deleted both encoded arrays and the whole decode path as
> dead.** The measured `.rodata` contained neither the ciphertext nor the plaintext, and
> `session_seal` compiled down to an unconditional `orr w8, w8, #0x1`.
>
> A fixture that claims to teach string obfuscation and contains no obfuscated strings is worse than
> no fixture. It was caught by dumping `.rodata` and noticing the arrays were absent — which is the
> same discipline the chapter asks of you. README §11.4 records it.

> **🔍 Pentester's Note**
> The absence is itself the finding. A native library with almost no strings has encoded them, and
> that tells you something about the target before you read a line of code. The counter-technique is
> to dump strings from process memory after decoding, not from the file — see
> [53-Frida](../../53-Frida/README.md).

---

## 9. The struct — the answer key for lab 02

| Offset | Field | Type | How it appears in the listing |
|---|---|---|---|
| `+0x00` | `magic` | `uint32_t` | `ldr w8, [x0]` followed immediately by a `mov`/`movk` pair |
| `+0x04` | `flags` | `uint32_t` | `ldr w8, [x0, #4]` then `orr`/`and` with a small power of two |
| `+0x08` | `issued_at` | `uint64_t` | `ldr x8, [x0, #8]` — note `x`, not `w`: eight bytes |
| `+0x10` | `key[16]` | `uint8_t[16]` | `add x9, x19, #16` then `ldrb`/`strb` in a loop bounded by `cmp x8, #16` |
| `+0x20` | `user[32]` | `char[32]` | passed to `strlen`/`memcpy`; the bound `#31` gives the array size |
| `+0x40` | `crc` | `uint32_t` | `str w8, [x19, #64]` |
| `+0x44` | `state` | `int32_t` | `ldr w8, [x19, #68]`, compared against small constants 0–3 |
| `+0x48` | `step_count` | `uint32_t` | `ldr w8, [x19, #72]` then `add w8, w8, #1` then `str` |
| `+0x4c` | `reserved` | `uint32_t` | `ldr w8, [x0, #76]` in `session_slow_path` only |
| | | | **`sizeof` = `0x50`** |

The three tells that let you derive the type of a field without any of the above:

1. **Access width.** `ldr w` is 4 bytes, `ldr x` is 8, `ldrb` is 1, `ldrh` is 2. The instruction names
   the size; you never have to guess it.
2. **The loop bound gives the array length.** `cmp x8, #16` terminating a `strb` loop that starts at
   `+0x10` means sixteen bytes at `+0x10`.
3. **The largest offset touched, rounded up to alignment, is a lower bound on `sizeof`.** Here `+0x4c`
   plus four is `0x50`, and `memset(s, 0, sizeof(*s))` in `session_init` confirms it directly — look
   for the constant passed as the third argument to `memset`.

### Confirmed at run time

Built for `x86_64` from the same sources and run on an `sdk_gphone16k_x86_64` AVD (Android 15 /
API 35), the library's own self-test sequence — `session_init(s, "tester", 1700000000)`,
`session_dispatch(s, 0)`, `session_step(s, 3, NULL, 0)`, `session_seal(s)` — produces:

```text
rc=39 report=tester:76b457444aeb9a6c9ac1b605db125f8c
crc=841a7cce state=2 flags=00000003 step=2
```

Every one of those is a field of the structure read at its recovered offset, and every one is
plausible: `state` is 2 (`ST_SEALED`), `flags` is `0x3` (`FLAG_SEALED | FLAG_PRIVILEGED`), and
`step_count` is 2 because exactly two `session_step` calls occurred.

The key was **independently reproduced** by reimplementing the derivation in Python, on a different
architecture, and matching to the byte. The derivation is pure 64-bit integer arithmetic, so it is
architecture-independent — which is what makes it safe to publish as a fixed CTF answer.

---

## 10. Regenerating this file

```bash
# host
cd examples
OUTDIR=/tmp/ch58 ./build.sh | tee /tmp/ch58-run.log
```

If your output differs from this document, **your output is right and this document is describing a
different build.** Record the difference; a changed shape between compiler versions is exactly the
kind of thing this repository wants written down rather than smoothed over.

---

## Related

| File | Why |
|---|---|
| [`01-session-target.c`](01-session-target.c) | The source every listing above came from |
| [`02-crcutil.c`](02-crcutil.c) | The static-archive half — the FLIRT target |
| [`build.sh`](build.sh) | Regenerates everything here |
| [`../scripts/01-make-flirt-pat.py`](../scripts/01-make-flirt-pat.py) | Turns the archive into FLAIR pattern lines |
| [`../labs/lab-02-struct-recovery.md`](../labs/lab-02-struct-recovery.md) | Uses section 9 as its answer key |
| [18-ARM](../../18-ARM/README.md) | The instruction set — `adrp`, `movk`, `cset`, `tbnz`, AAPCS64 |
| [15-Native-Code](../../15-Native-Code/README.md) | ELF, symbols, relocations, `.dynsym` versus `.symtab` |
