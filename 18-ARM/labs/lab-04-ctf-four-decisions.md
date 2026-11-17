# Lab 04 — CTF: four decisions

> **`libvault.so` will not tell you anything.** It is stripped, it exports four functions and nothing
> else, its strings are meaningless, and every constant that matters is either scattered across four
> instructions or sitting in `.rodata` under a key you do not have. Recover four flags from a binary
> you cannot run, with a decompiler you are not allowed to use.

**Prerequisites:** Labs [01](lab-01-read-your-first-disassembly.md),
[02](lab-02-patch-the-licence-check.md);
[18-ARM §3.3](../README.md#33-instruction-encoding-what-a-4-byte-word-actually-contains),
[§3.6](../README.md#36-forming-addresses-adrp-and-its-partner),
[§3.9](../README.md#39-deciding-without-branching-cset-csel-csinc),
[§3.10](../README.md#310-the-pattern-catalogue),
[§6.6](../README.md#66-the-address-arithmetic-and-the-mistakes-that-come-from-it)
**Difficulty:** Hard
**Time:** 2–4 hours
**You will need:** **Python 3 and nothing else.** No NDK. No device. No emulator. No network.

---

## Brief

You have pulled a native library out of an APK during an assessment. The Java side calls four
methods on it and does not say what they do. The library is stripped: `.symtab` is gone entirely, so
every internal helper is nameless, and `.dynsym` has exactly four entries.

```text
name                                                 vaddr        size     table
v_unlock                                             0x00004704   108      .dynsym
v_reveal                                             0x00004770   268      .dynsym
v_stage3                                             0x0000487c   24       .dynsym
v_is_admin                                           0x000048e8   12       .dynsym
```

Four flags. Each needs a different technique, and each corresponds to a section of the chapter. You
can check any answer against the SHA-256 values below without being told what it is — so you will
know when you are right, and you will get no partial credit for being close.

| Flag | What it is | Chapter section | Verify against SHA-256 of your answer |
|---|---|---|---|
| **1** | The 16-character password `v_unlock` accepts | §3.10 pattern 10 and 24 | `200c9c1a18d26469e3bc754aa94a3150a886836211881c5c746ad35bb9927d8e` |
| **2** | The 19-character string `v_reveal` produces with the correct key | §3.6 | `75eb02b0b27b6ffa80cb758cf8bd4b1c217fc1148abfdfe4eb22c03986534587` |
| **3** | `v_stage3(18)`, as four lowercase hex digits with no `0x` | §3.10 pattern 23, arithmetic | `ca77d6f449f9d4b9823f25c9eb7b296b4626a9b0a81006809ce756d8525346be` |
| **4** | The **file offset** and the **four patch bytes** that make `v_is_admin` always return 1, as `offset:bytes` — offset in lowercase hex with no `0x`, bytes as eight lowercase hex digits in **file order** | §2.4, §3.3, §6.6 | `0acdbefa57171926c1e3cb545fb56a8c44e5415d404817ebb3df4c0689518640` |

**Format matters.** Flag 4's answer looks like `1234:aabbccdd`. No spaces, no `0x`, lowercase.

---

## Setup

```bash
# host -- Python 3 is the only requirement
mkdir -p /tmp/ch18-ctf
python3 18-ARM/scripts/ctf-build-vault.py /tmp/ch18-ctf
cd /tmp/ch18-ctf
```

```text
wrote /tmp/ch18-ctf/libvault.so  (4568 bytes)
sha256 5def0bcf3636583359a2602fc73180f9cabd9889066bb1b90b72a4f4904df7d1

Start here:
  python3 arm64-patch.py /tmp/ch18-ctf/libvault.so --list-symbols
  python3 find-check-shapes.py /tmp/ch18-ctf/libvault.so
```

Keep a pristine copy — you will patch one of these:

```bash
# host
cp libvault.so libvault-pristine.so
S=18-ARM/scripts        # adjust to wherever it is
```

### Checking a flag

```bash
# host
python3 - <<'PY'
import hashlib
ans = "your answer here"
print(hashlib.sha256(ans.encode()).hexdigest())
PY
```

Or as a one-liner:

```bash
# host
printf '%s' 'your answer here' | sha256sum
```

> **`echo` adds a newline** and will give you the wrong hash. Use `printf '%s'` or the Python
> form.

---

## Rules

1. **No decompiler.** No Ghidra, no IDA, no Binary Ninja, no `retdec`. That is not because they would
   fail — Ghidra would answer flag 3 in thirty seconds — but because the point of the lab is the
   instruction level, and [57-Ghidra](../../57-Ghidra/README.md) is where you are allowed to use one.
2. **No running the binary.** It is `arm64-v8a`; your host almost certainly is not. Everything here
   is static, deliberately.
3. **`llvm-objdump` is allowed if you have it**, but is not required — `arm64-patch.py` carries its
   own AArch64 decoder for exactly this reason. Every listing quoted in the hints below was produced
   by both, and they agree.
4. **Writing your own Python is expected.** Two of the four flags are much easier with fifteen lines
   of Python than by hand.

---

## Reconnaissance

Do this before opening anything.

```bash
# host
python3 "$S/arm64-patch.py" libvault.so --list-symbols
python3 "$S/find-check-shapes.py" libvault.so
python3 "$S/find-check-shapes.py" libvault.so --show --min-score 3
```

```text
libvault.so -- 2 candidate check-shaped functions (score >= 3)
Shape score only. Nothing here is a finding; it is a reading list.

========================================================================
v_unlock                                  0x00004704  108 bytes  score 7
   - cset at +0x40 (the boolean is produced here)
   - returns a literal boolean on at least one path
   - calls strlen (length check)
   calls: strlen
========================================================================
v_is_admin                                0x000048e8  12 bytes  score 7
   - cset at +0x4 (the boolean is produced here)
   - only 12 bytes -- a whole function this small is doing one thing
   - name contains 'is_'
```

**R1.** The triage found two of the four functions. Which two did it miss, and why does its scoring
model not see them? Answer this before going further — it tells you which flags will not come from a
tool.

**R2.** How would you dump the four sections you care about with no NDK at all? Write it:

```bash
# host
python3 - <<'PY'
import sys, struct
sys.path.insert(0, "18-ARM/scripts")   # adjust
import importlib.util
spec = importlib.util.spec_from_file_location("ap", "18-ARM/scripts/arm64-patch.py")
ap = importlib.util.module_from_spec(spec); spec.loader.exec_module(ap)

elf = ap.Elf(open("libvault.so", "rb").read())
print("arch", elf.arch, "ELF64" if elf.is64 else "ELF32")
for s in elf.sections:
    if s["size"] and s["name"] in (".text", ".rodata", ".dynsym", ".dynstr"):
        print("%-10s addr 0x%05x  off 0x%05x  size %d"
              % (s["name"], s["addr"], s["offset"], s["size"]))
for s in elf.segments:
    if s["type"] == 1:
        print("PT_LOAD vaddr 0x%05x off 0x%05x filesz 0x%x flags %d"
              % (s["vaddr"], s["offset"], s["filesz"], s["flags"]))
PY
```

**R3.** From that output alone, write down the `p_vaddr - p_offset` delta for **each** `PT_LOAD`. You
will need one of them for flag 4, and using the wrong one is the intended trap.

---

## Flag 1 — What does `v_unlock` accept?

`v_unlock` takes a `const char *` and returns a boolean.

```bash
# host
python3 "$S/arm64-patch.py" libvault.so --symbol v_unlock --show --context 0
```

```text
0000000000004704 <v_unlock>:
    4704: fd 7b be a9   stp     x29, x30, [sp, #-32]!
    4708: f3 0b 00 f9   str     x19, [sp, #16]
    470c: fd 03 00 91   mov     x29, sp
    4710: a0 02 00 b4   cbz     x0, 0x4764
    4714: f3 03 00 aa   mov     x19, x0
    4718: 8a 00 00 94   bl      0x4940
    471c: 1f 40 00 f1   cmp     x0, #16
    4720: 01 02 00 54   b.ne    0x4760
    4724: 68 26 40 a9   ldp     x8, x9, [x19]
    4728: 0a 2a 88 d2   mov     x10, #16720
    472c: ea a8 a8 f2   movk    x10, #17735, lsl #16
    4730: aa 25 c8 f2   movk    x10, #16685, lsl #32
    4734: 8a 29 e9 f2   movk    x10, #18764, lsl #48
    4738: 1f 01 0a eb   cmp     x8, x10
    473c: e8 c8 89 d2   mov     x8, #20039
    4740: a8 88 a8 f2   movk    x8, #17477, lsl #16
    4744: ea 17 9f 1a   cset    w10, eq
    4748: a8 65 c9 f2   movk    x8, #19245, lsl #32
    474c: a8 28 eb f2   movk    x8, #22853, lsl #48
    4750: 3f 01 08 eb   cmp     x9, x8
    4754: e8 17 9f 1a   cset    w8, eq
    4758: 40 01 08 0a   and     w0, w10, w8
    475c: 02 00 00 14   b       0x4764
    4760: e0 03 1f 2a   mov     w0, wzr
    4764: f3 0b 40 f9   ldr     x19, [sp, #16]
    4768: fd 7b c2 a8   ldp     x29, x30, [sp], #32
    476c: c0 03 5f d6   ret
```

**Q1.1.** How long must the password be? Which instruction says so?

**Q1.2.** `ldp x8, x9, [x19]` loads sixteen bytes in one instruction. What are `x8` and `x9`?

**Q1.3.** There is no `bl memcmp`. What was inlined, and what shape is it? (Note it is *not* the
`eor`/`orr` shape from README §3.10 pattern 24 — clang chose a different one here. Which, and why is
it equivalent?)

**Q1.4.** Reassemble `x10` from its four immediates. Each `movk Xd, #imm, lsl #S` places `imm` at bit
position `S`; the initial `mov` (really `movz`) places its immediate at position 0 and zeroes
everything else.

**Q1.5.** Now the step everybody gets wrong the first time: **convert the 64-bit value to bytes.**
AArch64 is little-endian, so the byte at the *lowest* address is the *lowest* byte of the value.

**Q1.6.** Do the same for `x8` and concatenate.

**Q1.7.** Confirm your reading of the comparison logic: `cset w10, eq` after the first `cmp`,
`cset w8, eq` after the second, then `and w0, w10, w8`. Why `and` rather than a branch? What does
that tell you about the compiler's treatment of `&&` here?

<details>
<summary><strong>Hint 1 — if you are stuck on the arithmetic</strong></summary>

```python
# host -- python3
def rebuild(pairs):
    """pairs: list of (imm, shift)"""
    v = 0
    for imm, sh in pairs:
        v |= (imm & 0xFFFF) << sh
    return v

x10 = rebuild([(16720, 0), (17735, 16), (16685, 32), (18764, 48)])
print(hex(x10))
print(x10.to_bytes(8, 'little'))
```

If `to_bytes(8, 'little')` gives you gibberish, try `'big'` — and then work out from
[README §3.3](../README.md#33-instruction-encoding-what-a-4-byte-word-actually-contains) why only one
of the two can be right on Android.

</details>

<details>
<summary><strong>Hint 2 — the sanity check</strong></summary>

Both halves are printable ASCII, sixteen characters total, and the string contains a hyphen. If your
answer is not printable, you have the byte order backwards. If it is printable but scrambled — for
instance `APGE-ALI` instead of something that reads as English — you have the byte order right and
the *field* order backwards inside one of the 16-bit groups. Recheck which `movk` has which `lsl`.

</details>

---

## Flag 2 — What is `v_reveal` hiding?

`v_reveal(char *out, size_t n, unsigned char key)` writes nineteen bytes and a NUL. The key is the
third argument, so it comes in `w2`.

```bash
# host
python3 "$S/arm64-patch.py" libvault.so --symbol v_reveal --show --context 0 | head -20
```

```text
0000000000004770 <v_reveal>:
    4770: 3f 50 00 f1   cmp     x1, #20
    4774: 62 00 00 54   b.hs    0x4780
    4778: 00 00 80 12   mov     w0, #-1
    477c: c0 03 5f d6   ret
    4780: e8 ff ff 90   adrp    x8, 0x0
    4784: 08 a1 14 91   add     x8, x8, #1320
    4788: 09 01 40 39   ldrb    w9, [x8]
    478c: 29 01 02 4a   eor     w9, w9, w2
    4790: 09 00 00 39   strb    w9, [x0]
    4794: 09 05 40 39   ldrb    w9, [x8, #1]
    4798: 29 01 02 4a   eor     w9, w9, w2
    479c: 09 04 00 39   strb    w9, [x0, #1]
    ...
```

**Q2.1.** What does `cmp x1, #20` / `b.hs` protect against, and what does the function return if the
buffer is too small?

**Q2.2.** `adrp x8, 0x0` then `add x8, x8, #1320`. **Compute the target address.** Remember that
`adrp` gives a page base and that objdump's `<symbol>` annotation on an `adrp` line is noise.

**Q2.3.** Which section is that address in? Use the section table you dumped in R2.

**Q2.4.** Extract the nineteen bytes at that address from the **file**. Careful: the address you
computed is a *virtual* address. Which `PT_LOAD` contains it, and what is that segment's delta?

**Q2.5.** `eor w9, w9, w2` — each byte is XORed with `w2`, the caller's key, which is the same for
every byte. **You do not have the key.** How many possibilities are there, and how long would it take
to try them all?

**Q2.6.** Recover the plaintext. What is the key, in hex?

**Q2.7.** The loop is fully unrolled — nineteen copies of `ldrb`/`eor`/`strb`. The C source had a
`for` loop. Why did the compiler unroll it rather than emit a loop, and what would have stopped it?

<details>
<summary><strong>Hint — the brute force is four lines</strong></summary>

```python
# host -- python3
ct = bytes.fromhex("1c161b1d213b3e282a052a362f29053b3e3e27")   # 19 bytes; get these yourself
for k in range(256):
    p = bytes(b ^ k for b in ct)
    if all(32 <= c < 127 for c in p):
        print(hex(k), p)
```

Only a handful of keys produce printable output, and only one produces something that reads like a
flag.

</details>

---

## Flag 3 — What does `v_stage3(18)` return?

```bash
# host
python3 "$S/arm64-patch.py" libvault.so --symbol v_stage3 --show --context 0
```

```text
000000000000487c <v_stage3>:
    487c: fd 7b bf a9   stp     x29, x30, [sp, #-16]!
    4880: fd 03 00 91   mov     x29, sp
    4884: 04 00 00 94   bl      0x4894
    4888: 00 3c 00 12   and     w0, w0, #0xffff
    488c: fd 7b c1 a8   ldp     x29, x30, [sp], #16
    4890: c0 03 5f d6   ret
    4894: 68 32 80 52   mov     w8, #403
    4898: 2a 37 8f 52   mov     w10, #31161
    489c: 08 20 a0 72   movk    w8, #256, lsl #16
    48a0: ea c6 b3 72   movk    w10, #40503, lsl #16
    48a4: 09 7c 08 1b   mul     w9, w0, w8
    48a8: 29 01 0a 4a   eor     w9, w9, w10
    48ac: 29 7d 08 1b   mul     w9, w9, w8
    48b0: 29 01 0a 4a   eor     w9, w9, w10
    ...
    48dc: 28 7d 08 1b   mul     w8, w9, w8
    48e0: 00 01 0a 4a   eor     w0, w8, w10
    48e4: c0 03 5f d6   ret
```

**Q3.1.** `v_stage3` is six instructions long and one of them is a `bl` to `0x4894` — an address
*inside* what `--list-symbols` reported as a 24-byte function. What is at `0x4894`, and why does it
have no symbol?

**Q3.2.** Reassemble `w8` and `w10` from their `movz`/`movk` pairs. Both are 32-bit; both are
well-known constants. Do you recognise either?

**Q3.3.** Count the `mul`/`eor` pairs between `0x48a4` and `0x48e0`. How many rounds?

**Q3.4.** Write the C that produced this. It is four lines.

**Q3.5.** `mul` on a `w` register is a 32-bit multiply — the result is truncated to 32 bits. Python
integers are not. Write the emulator and be careful about that:

```python
# host -- python3
def derive(seed, rounds, mult, xor):
    a = seed
    for _ in range(rounds):
        a = ((a * mult) & 0xFFFFFFFF) ^ xor
    return a
```

**Q3.6.** `and w0, w0, #0xffff` in the caller. Apply it. Format as four lowercase hex digits with no
`0x` — that is the flag.

**Q3.7.** Sanity check your emulator: what does `v_stage3(0)` return? If your answer for seed 0 is
`0` you have the loop structure wrong; re-read the order of `mul` and `eor`.

---

## Flag 4 — Where would you patch `v_is_admin`?

```bash
# host
python3 "$S/arm64-patch.py" libvault.so --symbol v_is_admin --show --context 2
```

```text
symbol   : v_is_admin  (from .dynsym)
arch     : aarch64 (ELF64)
vaddr    : 0x48e8
file off : 0x8e8   (segment vaddr 0x46b4 -> offset 0x6b4, delta -0x4000)
size     : 12 bytes (3 instructions)

BEFORE
  000048e0: 00 01 0a 4a       eor   w0, w8, w10
  000048e4: c0 03 5f d6       ret
  000048e8: 1f 18 00 71   <-- cmp   w0, #6
  000048ec: e0 d7 9f 1a       cset  w0, gt
  000048f0: c0 03 5f d6       ret
```

**The tool has just printed the file offset of the function.** That is not the answer. The answer is
about the instruction that produces the boolean, not the one that starts the function — so **work out
the offset yourself and only then use the tool to check.**

**Q4.1.** `cmp w0, #6` and `cset w0, gt`. What is the C? (Careful with the boundary.)

**Q4.2.** Which of the three instructions decides the answer? Which one would you replace?

**Q4.3.** Its virtual address is `0x48ec`. Compute its **file offset** from the program headers — not
from the tool's output for `0x48e8`, and not by assuming a delta from the first `PT_LOAD`.

**Q4.4.** What four bytes replace it? Derive `mov w0, #1` from the rule in
[README §3.3](../README.md#33-instruction-encoding-what-a-4-byte-word-actually-contains):
`mov wN, #imm` = `0x52800000 | (imm << 5) | N`. Then write the word out as it appears **in the file**,
which is little-endian.

**Q4.5.** Format: `offset:bytes`, offset in lowercase hex with no `0x`, bytes as eight lowercase hex
digits in file order, no separators. Example shape: `1234:aabbccdd`.

**Q4.6.** Now do it for real and confirm:

```bash
# host
python3 "$S/arm64-patch.py" libvault.so --symbol v_is_admin \
        --skip 1 --patch "mov w0,#1" --context 2 --write
```

Then verify the file changed at exactly the offset you predicted:

```bash
# host
cmp -l libvault-pristine.so libvault.so
```

`cmp -l` prints **1-based decimal** offsets. Convert.

**Q4.7.** Why would patching at `+0` (the `cmp`) not work? And why, in this particular library, is
there no `bti` landing pad to worry about — check the first instruction of any function and compare
against [README §3.12](../README.md#312-system-instructions-svc-and-the-hint-space).

---

## Part 5 — The questions with no hash

These are not flags. They are the reason the lab exists, and they are what you would actually write
in a report.

**5.1.** `find-check-shapes.py` scored `v_unlock` and `v_is_admin` and missed `v_reveal` and
`v_stage3`. For each miss, say precisely which scoring signal was absent and whether that is a bug or
correct behaviour.

**5.2.** You now hold flag 1 — the password `v_unlock` accepts. Suppose the application's Java side
does this:

```java
if (native.vUnlock(userInput)) { unlockPremium(); }
```

Which is the better move for an attacker: use the password you recovered, or patch `v_unlock` to
return 1? Give two reasons in each direction.

**5.3.** Flag 2's plaintext was recovered without the key. Was the key ever a secret? What would the
developer have had to do differently for the XOR to be worth anything at all?

**5.4.** `v_stage3` is a pure function of its argument with no secret in it. What is it *for*, and
what would it be used for in a real anti-tamper design? What does that imply about whether patching
it accomplishes anything?

**5.5.** You patched `v_is_admin` in Q4.6. Name three things that could make that patch useless in a
real application, drawing on [README §5.4](../README.md#54-the-worked-example-what-patching-a-check-actually-buys-you)
and [§9.5](../README.md#95-enterprise-application--a-hardened-library-and-an-honest-assessment).

**5.6.** The library is stripped, but you got four names anyway. Where did they come from, and what
would you have done if the developer had used `RegisterNatives` with non-exported implementations
instead? (See [README §6.4](../README.md#64-mapping-a-java-name-to-a-native-symbol).)

**5.7.** Write the finding. One paragraph. It must distinguish what you *recovered* (flags 1–3, all
static analysis) from what you *changed* (flag 4, a four-byte patch), and it must state honestly what
each is worth.

---

## Scoring

| Points | For |
|---|---|
| 1 | Flag 1 |
| 1 | Flag 2 |
| 1 | Flag 3 |
| 2 | Flag 4 — one point for the bytes, one for the offset. **Getting the offset from the tool without computing it does not score.** |
| 2 | Part 5, questions 5.1 and 5.5 answered well |
| **7** | **Total** |

Five out of seven is a pass. Seven means you did not use the tool as an oracle.

---

## Full solutions

Do not open this until you have four hashes matching, or you have genuinely stopped.

<details>
<summary><strong>Solution — Flag 1</strong></summary>

**Q1.1.** Sixteen. `cmp x0, #16` at `0x471c`, comparing `strlen`'s return value in `x0`.

**Q1.2.** `ldp x8, x9, [x19]` loads bytes 0–7 into `x8` and bytes 8–15 into `x9`, treating the
password as two 64-bit words.

**Q1.3.** A 16-byte `memcmp` against a constant, inlined. clang used
`cmp` / `cset` / `cmp` / `cset` / `and` rather than the `eor` / `orr` / `cmp #0` form seen in
`liblicence.so`. Both compute "are all sixteen bytes equal"; this form does two independent
comparisons and ANDs the two booleans, which is equally branchless and equally constant-time. Which
form clang picks depends on how the source expressed the comparison — here it was two `uint64_t`
equality tests joined by `&&`.

**Q1.4.**
```
x10 = 16720 | (17735 << 16) | (16685 << 32) | (18764 << 48)
    = 0x4150 | 0x4547 0000 | 0x412D 0000 0000 | 0x494C 0000 0000 0000
    = 0x494C412D45474150
```

**Q1.5.** Little-endian bytes, lowest first: `50 41 47 45 2D 41 4C 49` = `PAGE-ALI`.

**Q1.6.**
```
x8  = 20039 | (17477 << 16) | (19245 << 32) | (22853 << 48)
    = 0x4E47 | 0x4445 0000 | 0x4B2D 0000 0000 | 0x5945 0000 0000 0000
    = 0x59454B2D44454E47
```
Bytes: `47 4E 45 44 2D 4B 45 59` = `GNED-KEY`.

**Flag 1 = `PAGE-ALIGNED-KEY`**

**Q1.7.** `&&` in C short-circuits, but here both operands are cheap and side-effect-free, so the
compiler is free to evaluate both and combine them with `and`. It chose to, because two `cset`s and
an `and` are faster than a branch that might be mispredicted. This is the same reasoning as §3.9.

```python
# host -- python3, the whole thing
def rebuild(p):
    v = 0
    for imm, sh in p: v |= (imm & 0xFFFF) << sh
    return v
lo = rebuild([(16720,0),(17735,16),(16685,32),(18764,48)])
hi = rebuild([(20039,0),(17477,16),(19245,32),(22853,48)])
print((lo.to_bytes(8,'little') + hi.to_bytes(8,'little')).decode())
```

</details>

<details>
<summary><strong>Solution — Flag 2</strong></summary>

**Q2.1.** It rejects an output buffer smaller than 20 bytes and returns −1 (`mov w0, #-1`). Note the
check is `hs` — **unsigned** — which is correct for a `size_t`.

**Q2.2.** `adrp x8, 0x0` gives page base `0x0`; `add x8, x8, #1320` gives `0x0 + 0x528` = **`0x528`**.

**Q2.3.** `.rodata`, which the section table puts at address `0x528`, offset `0x528`, size 20.

**Q2.4.** `0x528` is in the **first** `PT_LOAD`, whose `p_vaddr` and `p_offset` are both `0`. Delta
zero, so the file offset is also `0x528`. **Using the `-0x4000` delta from the executable segment
would have read the wrong bytes** — that is the intended trap, and it is the same trap as
[README §2.4](../README.md#24-the-one-arithmetic-fact-everything-depends-on).

```python
# host -- python3
d = open("libvault.so","rb").read()
ct = d[0x528:0x528+19]
print(ct.hex())      # 1c161b1d213b3e282a052a362f29053b3e3e27
```

**Q2.5.** One byte, so 256 possibilities — instant. A single-byte XOR is not encryption; it is
obfuscation, and it survives only `strings`.

**Q2.6.**
```python
for k in range(256):
    p = bytes(b ^ k for b in ct)
    if all(32 <= c < 127 for c in p):
        print(hex(k), p)
```
`0x5a` gives `FLAG{adrp_plus_add}`.

**Flag 2 = `FLAG{adrp_plus_add}`, key `0x5A`**

**Q2.7.** The trip count is a compile-time constant (19), the body is tiny, and there is no
loop-carried dependency, so unrolling removes the counter, the compare and the branch at a cost of
about 150 bytes. What would have stopped it: a runtime-variable length, a much larger count, or
`-Os`. The `volatile` qualifier on the source pointer is why the compiler could not go further and
fold the whole thing into constants at compile time — which is exactly what it does if you remove it.

</details>

<details>
<summary><strong>Solution — Flag 3</strong></summary>

**Q3.1.** `0x4894` is a **non-exported helper**. The library is stripped, so it has no `.symtab`
entry, and it is `static` in the source, so it was never in `.dynsym` either. `--list-symbols`
reported `v_stage3` as 24 bytes because that is its `st_size`; the helper follows it in
`.text` with no symbol of its own. **A stripped library is full of these**, and this is why
`find-check-shapes.py` — which walks symbols — cannot see them.

**Q3.2.**
```
w8  = 403   | (256   << 16) = 0x0193 | 0x0100 0000 = 0x01000193
w10 = 31161 | (40503 << 16) = 0x79B9 | 0x9E37 0000 = 0x9E3779B9
```
Both are famous. `0x01000193` is the **FNV-1a 32-bit prime**. `0x9E3779B9` is the 32-bit
**golden-ratio constant** used in TEA, xxHash and countless mixers. Recognising these is worth real
time in practice: they identify the algorithm before you have read a line of logic.

**Q3.3.** Eight `mul`/`eor` pairs: `0x48a4`, `0x48ac`, `0x48b4`, `0x48bc`, `0x48c4`, `0x48cc`,
`0x48d4`, `0x48dc`.

**Q3.4.**
```c
uint32_t derive(uint32_t seed) {
    uint32_t a = seed;
    for (unsigned i = 0; i < 8; i++) a = (a * 0x01000193u) ^ 0x9E3779B9u;
    return a;
}
```

**Q3.5–Q3.6.**
```python
# host -- python3
def derive(seed):
    a = seed
    for _ in range(8):
        a = ((a * 0x01000193) & 0xFFFFFFFF) ^ 0x9E3779B9
    return a
print("%04x" % (derive(18) & 0xFFFF))
```

**Flag 3 = `967a`**

**Q3.7.** `v_stage3(0)` is `0xf5a8` — not zero, because the first round's `eor` injects
`0x9E3779B9` regardless of the seed. If you got `0`, you applied the `eor` before the `mul`.

</details>

<details>
<summary><strong>Solution — Flag 4</strong></summary>

**Q4.1.** `return level >= 7;`. The compiler turned `>= 7` into `> 6` because `cmp #6` with the
signed `gt` condition is exactly equivalent for integers and costs the same. Getting this backwards —
reading it as `> 6` and reporting the threshold as 6 — is the classic off-by-one in disassembly
reading.

**Q4.2.** `cset w0, gt` at `0x48ec`. It is the instruction that produces the answer. Replace it with
`mov w0, #1`.

**Q4.3.** The executable `PT_LOAD` has `p_vaddr = 0x46b4` and `p_offset = 0x6b4`, so the delta is
`-0x4000`:
```
0x48ec - 0x46b4 + 0x6b4 = 0x8ec
```

**Q4.4.**
```
mov w0, #1  =  0x52800000 | (1 << 5) | 0  =  0x52800020
in the file, little-endian:  20 00 80 52
```

**Q4.5. Flag 4 = `8ec:20008052`**

**Q4.6.** `cmp -l` should report exactly four differing bytes, at 1-based decimal offsets 2285–2288
(`0x8ec` = 2284, so 2285 is the first). If you see more than four, you patched the wrong thing.

**Q4.7.** Patching the `cmp` would leave the `cset` reading whatever flags happened to be set by the
caller — an unpredictable answer, not a forced one. And there is no `bti` in this library at all:
every function starts with real work, because these functions are reached by direct `bl` rather than
indirectly. Compare `liblicence.so`, where `__on_dlclose` and friends — which the runtime calls
through function pointers — do begin with `hint #34`.

</details>

<details>
<summary><strong>Solution — Part 5, the two scored questions</strong></summary>

**5.1.** `v_reveal` scored below the threshold because it has **no `cset`**, returns a *length* rather
than a boolean, is 268 bytes (too big for the size bonus), calls **nothing** (the whole loop is
inlined, so there is no interesting import), and its name matches none of the keywords. Every one of
those is correct behaviour: `v_reveal` genuinely is not a boolean check.

`v_stage3` scored low for a related but different reason: it is only 24 bytes, but it has no `cset`,
no literal 0/1, calls nothing recognisable, and its `bl` target is a nameless helper the script
cannot attribute. The *real* work is in the unnamed function at `0x4894`, which the script never
examines at all **because it walks symbols and that function has none.** That is the script's
documented blind spot, not a bug — but it is the one that matters most on a stripped library, and it
is why you must not treat an empty triage result as "there are no checks here".

**5.5.** Three things that would make the `v_is_admin` patch useless in a real application:

1. **The check is inlined into its callers.** The exported copy may be called by nothing. This is
   precisely the case worked through in README §5.4, where forcing `lc_verify_signature` to return 1
   demonstrably changed its return value and changed no behaviour at all. The only way to find out is
   to trace it at runtime.
2. **The decision is re-made server-side.** If the app sends the level to a backend that returns
   signed entitlements, a local boolean is decoration. Patching it produces a client that *believes*
   it is admin and a server that does not.
3. **The library is integrity-checked.** An app that hashes its own `.so` — or that ships a signature
   over `lib/` verified at startup — detects a four-byte change immediately. A memory patch
   (Lab 03 Part D) beats a file hash but not a hash over the mapped `.text`.

A fourth, worth mentioning: **the patched ABI may not be the one that loads.** If the APK ships both
`arm64-v8a` and `armeabi-v7a`, and the process started 32-bit, your AArch64 patch is inert.

</details>

---

## Success criteria

- [ ] Four hashes match.
- [ ] You computed flag 4's file offset from the program headers before checking with the tool, and
      you can say which `PT_LOAD` you used and why.
- [ ] You can explain why flag 2's data lives at a *zero* delta and flag 4's code does not.
- [ ] You derived `0x52800020` from the encoding rule rather than copying it from a table.
- [ ] You recognised `0x01000193` and `0x9E3779B9` — or, having looked them up, you will next time.
- [ ] You can state, for each of the four exports, what the triage script saw and what it missed.
- [ ] You wrote 5.7 and it distinguishes what you recovered from what you changed.

---

## Where next

You have now read AArch64 with no symbols, no source, no decompiler and no device. That is the floor,
not the ceiling — but it is the floor that everything else stands on.

- [57-Ghidra](../../57-Ghidra/README.md) — the decompiler you are finally allowed to use. Re-do this
  lab with it and time yourself. Then note which of the four flags it did *not* hand you.
- [53-Frida](../../53-Frida/README.md) — Stalker, which recompiles the instruction stream you have
  just spent four hours reading.
- [16-JNI](../../16-JNI/README.md) — the bridge whose far side you can now read fluently.
- [37-RootDetection](../../37-RootDetection/README.md) — a whole catalogue of real checks with
  exactly these shapes.
- [40-Obfuscation](../../40-Obfuscation/README.md) — what happens when somebody is actively trying to
  stop you doing this.
