# Lab 02 — Decode Instructions From Raw Bytes

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-parse-dex-by-hand.md), [Chapter 12 §3.16, §3.24–3.27](../README.md)

---

## Objective

Take the raw `insns` bytes of a method and produce the Smali by hand, then reverse the process:
hand-assemble a patch, apply it, and run it. By the end, instruction format identifiers like `21c`
and `35c` will be something you *read* rather than something you look up.

## Why this matters

Two reasons, one defensive and one offensive.

Defensively: when `baksmali` refuses a file — deliberately malformed DEX, or quickened opcodes from
an Android 8–10 device — hand-decoding is what gets you moving again.

Offensively: patching Smali correctly requires understanding the register model well enough to know
*why* a change breaks verification. Lab 03 and every bypass in
[67-BypassingProtections](../../67-BypassingProtections/README.md) depend on this.

---

## Setup

Build a tiny app so you control exactly what is in the DEX.

**`Target.java`**

```java
package com.artlab.dexlab;

import android.util.Log;

public class Target {

    private static final String TAG = "DEXLAB";

    // Simple: one string constant, one call, one return.
    public static boolean checkPin(String pin) {
        return "1337".equals(pin);
    }

    // Arithmetic: exercises binary ops and literals.
    public static int mix(int a, int b) {
        int r = a * 31;
        r = r ^ b;
        r = r + 7;
        return r;
    }

    // Wide values: long occupies TWO registers.
    public static long expiry(long base) {
        return base + 86400L;
    }

    // Array literal: becomes a fill-array-data payload.
    public static byte[] key() {
        return new byte[] {
            0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
            (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c
        };
    }

    // Branching and a switch: exercises if-* and packed-switch.
    public static String route(int code) {
        if (code < 0) return "negative";
        switch (code) {
            case 0: return "zero";
            case 1: return "one";
            case 2: return "two";
            default: return "many";
        }
    }

    // Exception table: exercises try_item and the signed handler size.
    public static int parse(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        } finally {
            Log.d(TAG, "parse done");
        }
    }
}
```

Build **release** (a debug build adds noise) and extract:

```bash
# host
./gradlew assembleRelease
unzip -o app/build/outputs/apk/release/app-release.apk 'classes*.dex' -d dex/
cd dex
```

---

## Steps

### Step 1 — Get the reference disassembly, then hide it

```bash
# host
baksmali d classes.dex -o smali/
cp smali/com/artlab/dexlab/Target.smali /tmp/answer-key.smali
```

Now **do not look at it** until told. You will check your work against it.

Get the raw bytes instead:

```bash
# host
dexdump -d classes.dex | grep -A40 "checkPin"
```

`dexdump` prints both the hex code units and its own decoding. Cover the right-hand side; work from
the hex.

### Step 2 — Decode `checkPin` by hand

You will see something close to this (indices will differ):

```text
0000: 1a00 3c05    |0000: const-string v0, "1337"
0002: 6e20 1e00 10 |0002: invoke-virtual {v0, v1}, ...
0005: 0a00         |0005: move-result v0
0006: 0f00         |0006: return v0
```

Work through each instruction from the hex only:

**Q1.** `1a00 3c05` — what is opcode `0x1A`? What is its format? Decode the register and the operand.

**Q2.** Look up the operand index in the string table (use Lab 01's method, or
`python3 ../examples/dex_parser.py classes.dex --strings | grep 1337`). Does it match?

**Q3.** `6e20 ...` — opcode `0x6E`. What format is it, and how many code units? Decode the argument
count and the register list. Remember: in `35c`, the argument count is the **high nibble** of byte 1.

**Q4.** `0a00` — what is this, and why *must* it appear here rather than two instructions later?

**Q5.** `0f00` — what does this do, and which register does it read?

### Step 3 — The register model

Find `checkPin`'s `code_item` header. `dexdump -d` prints `registers`, `ins` and `outs`:

```bash
dexdump -d classes.dex | grep -B2 -A6 "checkPin"
```

**Q6.** What are `registers_size` and `ins_size`? Compute `registers_size − ins_size`. Which `v`
number is `p0`?

**Q7.** `checkPin` is `static`. What does `p0` hold? How would the answer differ if the method were an
instance method?

### Step 4 — Decode `mix` (arithmetic)

```bash
dexdump -d classes.dex | grep -A20 "mix"
```

**Q8.** Identify each arithmetic instruction and its format. Which are `23x` (three registers), which
are `22b` (two registers plus an 8-bit literal), and which — if any — are `/2addr`?

**Q9.** Why would the compiler emit a `/2addr` form? What does it save?

### Step 5 — Decode `expiry` (wide values)

```bash
dexdump -d classes.dex | grep -A15 "expiry"
```

**Q10.** What are `registers_size` and `ins_size`? Given that `base` is a `long`, how many registers
does the parameter consume, and which ones?

**Q11.** Find the `const-wide*` instruction that loads 86400. Which variant is it, and why did the
compiler choose that one rather than the full 64-bit form?

### Step 6 — Find the array literal

**Q12.** Locate the `fill-array-data` instruction in `key()`. What format is it? What does its operand
mean?

Now find the payload:

```bash
python3 ../examples/find_array_literals.py classes.dex --keys-only
```

**Q13.** Does the tool find your 16-byte array? What does it say about the length? Explain, in one
sentence, why `strings classes.dex | grep -i key` would never have found this.

### Step 7 — Decode `route` (branches and switch)

```bash
dexdump -d classes.dex | grep -A40 "route"
```

**Q14.** Find the `if-*` instruction implementing `code < 0`. Which opcode is it, and is it comparing
two registers or against zero?

**Q15.** Find the `packed-switch` instruction and its payload. What is `first_key`? How many targets?

**Q16.** Where is the `default` case in the bytecode? (This one catches people.)

### Step 8 — Decode `parse` (exception table)

```bash
dexdump -d classes.dex | grep -A40 "parse"
```

`dexdump` prints the `catches` table after the instructions.

**Q17.** How many `try_item` entries are there? What address range does each cover?

**Q18.** The method has both a `catch` and a `finally`. Based on [§3.17](../README.md), what sign
should `encoded_catch_handler.size` have, and why?

**Q19.** Find the `move-exception` instruction. Where does it appear relative to the handler, and what
rule governs that?

### Step 9 — Check your work

Now open the answer key:

```bash
less /tmp/answer-key.smali
```

**Q20.** For every instruction you decoded wrongly, work out *why*. The usual causes are byte order,
the `35c` nibble packing, and forgetting that a `long` takes two registers.

### Step 10 — Hand-assemble a patch

Make `checkPin` always return true. Edit `smali/com/artlab/dexlab/Target.smali`:

```smali
.method public static checkPin(Ljava/lang/String;)Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method
```

**Q21.** Why `.registers 2` and not `.registers 1`? Compute `registers_size − ins_size` for both and
say what `p0` would be in each case.

Reassemble and verify:

```bash
# host
smali a smali/ -o patched-classes.dex
python3 ../examples/dex_parser.py patched-classes.dex --verify-header
dexdump -d patched-classes.dex | grep -A10 "checkPin"
```

**Q22.** Compare the patched bytes against the original. How many bytes did the method shrink by?

### Step 11 — Break it on purpose

Now produce a DEX that **fails verification**, so you recognise the symptom:

```smali
.method public static validate(Ljava/lang/String;)Z
    .registers 4
    invoke-static {p0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I
    const-string v1, "oops"          # <-- inserted between invoke and move-result
    move-result v0
    return v0
.end method
```

Add that method, reassemble, rebuild the APK, and install.

**Q23.** Does `smali a` accept it? Does the APK install? What happens when the app calls
`validate`? Capture the error:

```bash
adb logcat -s art
```

**Q24.** Explain the rule you broke in one sentence.

---

## Hints

<details>
<summary>Hint 1 — the 35c encoding defeats me</summary>

For `6e20 1e00 1000`:

- Code unit 0: `6e20` → opcode `0x6E`, then byte `0x20`. High nibble `2` = **argument count**. Low
  nibble `0` = register `G` (only used when count is 5).
- Code unit 1: `001e` little-endian = `0x001E` = the `method_ids` index.
- Code unit 2: `0010` little-endian = `0x0010`. Registers are packed as nibbles: C=`0`, D=`1`. So the
  argument list is `{v0, v1}`.

Read the nibbles right to left within each byte. This is genuinely fiddly, which is why
`invoke-*/range` exists.
</details>

<details>
<summary>Hint 2 — dexdump output is overwhelming</summary>

Narrow it:

```bash
dexdump -d classes.dex | sed -n '/checkPin/,/^$/p'
```

Or disassemble one class with baksmali and read the Smali alongside the hex.
</details>

<details>
<summary>Hint 3 — I cannot find the packed-switch payload</summary>

The `packed-switch` operand is a **signed 32-bit branch offset in code units**, relative to the
`packed-switch` instruction's own address. Add it to that address to find the payload. In Smali,
`baksmali` gives it a label like `:pswitch_data_0` and places it at the end of the method.
</details>

<details>
<summary>Hint 4 — smali rejects my register</summary>

You used a register above `v15` in a 4-bit format. Either use the `/from16` variant, or `move` the
value into a low register first. See [§3.24](../README.md).
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1.** `0x1A` is `const-string`, format `21c`: 2 code units, 1 register, constant-pool index. Byte 1
(`0x00`) is the destination register `v0`. Code unit 1 (`053c` LE = `0x053C`) is the `string_ids`
index.

**Q3.** `0x6E` is `invoke-virtual`, format `35c`: 3 code units, up to 5 registers, method index. The
high nibble of byte 1 is the argument count. See Hint 1 for the full nibble decoding.

**Q4.** `0x0A` is `move-result`. It **must** immediately follow the invoke whose result it collects,
because the result lives in a distinguished slot valid for exactly one instruction slot. Inserting
anything — even a `nop` — makes the DEX fail verification.

**Q5.** `0x0F` is `return`, format `11x`, reading `v0`.

**Q6–Q7.** For `checkPin`, `registers_size` is typically 2 and `ins_size` is 1, so `p0 == v1`. Since
the method is `static`, `p0` holds the first declared parameter (`pin`). For an instance method, `p0`
would be `this` and the first declared parameter would be `p1`.

**Q9.** `/2addr` forms use format `12x` — one code unit instead of two — by making the destination the
same as the first source. Pure size optimisation. It is also why decompiled arithmetic sometimes looks
like in-place mutation when the source did not say that.

**Q10.** A `long` occupies **two adjacent registers**. With `ins_size = 2`, the single `long`
parameter consumes both parameter registers.

**Q11.** The compiler picks the narrowest form that fits. 86400 fits in 32 bits, so `const-wide/32`
suffices and saves two code units over the full `51l` form.

**Q12–Q13.** `fill-array-data` is format `31t`: 3 code units, register plus a 32-bit signed branch
offset to the payload. `strings` misses the payload because it is raw bytes in the data section, not
text — this is exactly the point of [§3.27](../README.md).

**Q16.** The `default` case is **fall-through**. `packed-switch` branches only on a match; otherwise
execution continues at the next instruction. That is why the default body sits immediately after the
switch, which reads oddly until you know the rule.

**Q18.** The method has one typed `catch` **and** a `finally`, so a catch-all handler exists.
`encoded_catch_handler.size` must therefore be `≤ 0` — specifically `−1`, meaning one typed handler
plus a catch-all whose `catch_all_addr` follows as a `uleb128`.

**Q19.** `move-exception` is only valid as the **first instruction of a catch handler**. It moves the
thrown exception into a register. Placing it anywhere else fails verification.

**Q21.** `.registers 2` gives `registers_size − ins_size = 2 − 1 = 1`, so `p0 == v1` and `v0` is a
free local. `.registers 1` would give `p0 == v0`, so `const/4 v0, 0x1` would overwrite the incoming
parameter. In this specific method nothing reads the parameter afterwards, so it would happen to work
— but the habit is dangerous. Always compute `registers_size − ins_size`.

**Q23–Q24.** `smali a` accepts it — the assembler does not run the verifier. The APK installs fine.
The app crashes **when it first calls `validate`**, because verification happens lazily per class at
first use. `adb logcat -s art` names the method and the rejection reason. The rule broken:
`move-result` must immediately follow its invoke.

That install-then-crash-later signature is the thing to memorise. It means verification failure, not
a signing problem.

</details>

---

## Success criteria

- [ ] You decoded `checkPin` entirely from hex before looking at the answer key
- [ ] You can explain the `21c` and `35c` format identifiers without looking them up
- [ ] You computed `p0`'s register number from `registers_size − ins_size`
- [ ] You identified which arithmetic instructions used `/2addr` and why
- [ ] You correctly accounted for the `long` consuming two registers in `expiry`
- [ ] You located the array literal and can explain why `strings` misses it
- [ ] You found the `packed-switch` payload and know where the `default` case lives
- [ ] You worked out the sign of `encoded_catch_handler.size` for a `catch` + `finally`
- [ ] You hand-assembled a working patch and justified the `.registers` count
- [ ] You deliberately broke verification and recognised the install-then-crash signature
