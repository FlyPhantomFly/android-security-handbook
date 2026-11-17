# Lab 04 — CTF: The Latin VM

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-read-smali-by-hand.md), [Lab 02](lab-02-patch-and-rebuild.md), [Lab 03](lab-03-break-the-verifier.md), all of [Chapter 14 §3](../README.md)
**Needs:** a JDK, `d8`, `baksmali`, Python 3. A device is optional — the challenge runs on a desktop
JVM too.

---

## The scenario

You are handed an APK. It has one screen: a text field and a button. Type the right string, it says
**ACCEPTED**. Type anything else, **REJECTED**.

You decompile it expecting a string comparison. Instead you find a `while` loop, a `switch` on a byte
read out of an array, a hand-rolled stack, and a two-hundred-byte `fill-array-data` payload. There is
no comparison against a constant anywhere. There is no string to grep for.

The developer has implemented **a virtual machine inside the application**, and the flag check is a
program written for that VM.

## Why this challenge

Because it is real. Custom bytecode VMs are one of the strongest anti-analysis techniques in
commercial use: every serious mobile DRM product, several banking-app protection SDKs, and a good
proportion of Android malware ship one. When you meet one, the entire technique is:

1. Read the interpreter to recover the instruction set.
2. Read the program the interpreter runs.
3. Reverse the program.

Step 1 is a Smali-reading exercise, and it is exactly what this chapter has been building towards. It
is also a nice closing joke: to solve this you have to learn a second dead instruction set by reading
the Smali of a first one.

> **Why this is called the Latin VM.** Chapter 14 opens with the observation that Dalvik is Latin —
> a dead language whose notation every practitioner still has to read. This challenge adds a second
> dead language on top, invented by one developer, documented nowhere, and readable only from the code
> that interprets it. That is the situation you are actually in when you meet a commercial packer.

---

## The rules

This is a **keygen-style** challenge, and the design deliberately closes the usual shortcuts.

| Shortcut | Why it does not work |
|---|---|
| Patch the check to return `true` | The flag **is the input**. Making the app say ACCEPTED for any input tells you nothing about which input it wanted |
| `grep` for the flag | The flag never exists as a string anywhere in the APK. Only a transformation of it does |
| `strings` on the DEX | The program is a `fill-array-data` payload — raw bytes, not text |
| Brute force the whole input | 21 printable characters is about 10^40 candidates |
| Hook the comparison with Frida and read the expected value | There is no single comparison. There are 21, each against a value derived from a different key byte |

What **does** work — and what you should do — is either of:

- **Static:** recover the instruction set from the interpreter, disassemble the 190-byte program, and
  invert it on paper.
- **Dynamic:** recover the instruction set, then attack each character position independently. The
  check is per-character, so 21 positions × 95 printable characters = **1,995 tries**, not 10^40.
  Finding that decomposition is itself part of the challenge.

Both are legitimate. Doing the static one and then confirming with the dynamic one is best.

**Flag format:** `FLAG{...}`, all lowercase inside the braces plus digits and underscores. **21
characters including the braces.**

---

## Setup — build the challenge

Two files. No Android project needed; it runs on a desktop JVM, and you can also drop it into the Lab
02 app if you want it on a device.

**`Latin.java`**

```java
package com.example.latin;

/**
 * A tiny stack machine. The program it runs is in PROGRAM.
 * Nothing here is obfuscated; it is written for a machine you have
 * never seen. That is the whole difficulty.
 */
public final class Latin {

    private static final int LEN = 21;

    private static final byte[] PROGRAM = {
        0x02, 0x00, 0x01, 0x2b, 0x03, 0x07, 0x03, 0x06, 0x6b,
        0x02, 0x01, 0x01, 0x32, 0x03, 0x07, 0x03, 0x06, (byte) 0xf3,
        0x02, 0x02, 0x01, 0x39, 0x03, 0x07, 0x03, 0x06, (byte) 0xc3,
        0x02, 0x03, 0x01, 0x40, 0x03, 0x07, 0x03, 0x06, 0x38,
        0x02, 0x04, 0x01, 0x47, 0x03, 0x07, 0x03, 0x06, (byte) 0xe1,
        0x02, 0x05, 0x01, 0x4e, 0x03, 0x07, 0x03, 0x06, 0x51,
        0x02, 0x06, 0x01, 0x55, 0x03, 0x07, 0x03, 0x06, 0x0b,
        0x02, 0x07, 0x01, 0x5c, 0x03, 0x07, 0x03, 0x06, (byte) 0x81,
        0x02, 0x08, 0x01, 0x63, 0x03, 0x07, 0x03, 0x06, (byte) 0xa8,
        0x02, 0x09, 0x01, 0x6a, 0x03, 0x07, 0x03, 0x06, (byte) 0xda,
        0x02, 0x0a, 0x01, 0x71, 0x03, 0x07, 0x03, 0x06, (byte) 0xd0,
        0x02, 0x0b, 0x01, 0x78, 0x03, 0x07, 0x03, 0x06, 0x39,
        0x02, 0x0c, 0x01, 0x7f, 0x03, 0x07, 0x03, 0x06, 0x72,
        0x02, 0x0d, 0x01, (byte) 0x86, 0x03, 0x07, 0x03, 0x06, (byte) 0x9d,
        0x02, 0x0e, 0x01, (byte) 0x8d, 0x03, 0x07, 0x03, 0x06, (byte) 0x96,
        0x02, 0x0f, 0x01, (byte) 0x94, 0x03, 0x07, 0x03, 0x06, (byte) 0xc7,
        0x02, 0x10, 0x01, (byte) 0x9b, 0x03, 0x07, 0x03, 0x06, 0x7d,
        0x02, 0x11, 0x01, (byte) 0xa2, 0x03, 0x07, 0x03, 0x06, (byte) 0xb6,
        0x02, 0x12, 0x01, (byte) 0xa9, 0x03, 0x07, 0x03, 0x06, (byte) 0xc4,
        0x02, 0x13, 0x01, (byte) 0xb0, 0x03, 0x07, 0x03, 0x06, (byte) 0xf6,
        0x02, 0x14, 0x01, (byte) 0xb7, 0x03, 0x07, 0x03, 0x06, 0x56,
        0x08,
    };

    private Latin() { }

    public static boolean run(byte[] input) {
        if (input == null || input.length != LEN) {
            return false;
        }
        int[] stack = new int[32];
        int sp = 0;
        int pc = 0;
        boolean ok = true;

        while (true) {
            int op = PROGRAM[pc++] & 0xFF;
            switch (op) {
                case 0x01: {
                    stack[sp++] = PROGRAM[pc++] & 0xFF;
                    break;
                }
                case 0x02: {
                    int idx = PROGRAM[pc++] & 0xFF;
                    if (idx >= input.length) {
                        return false;
                    }
                    stack[sp++] = input[idx] & 0xFF;
                    break;
                }
                case 0x03: {
                    int b = stack[--sp];
                    int a = stack[--sp];
                    stack[sp++] = (a ^ b) & 0xFF;
                    break;
                }
                case 0x04: {
                    int b = stack[--sp];
                    int a = stack[--sp];
                    stack[sp++] = (a + b) & 0xFF;
                    break;
                }
                case 0x05: {
                    int b = stack[--sp];
                    int a = stack[--sp];
                    stack[sp++] = (a - b) & 0xFF;
                    break;
                }
                case 0x06: {
                    int want = PROGRAM[pc++] & 0xFF;
                    int got = stack[--sp];
                    if (got != want) {
                        ok = false;
                    }
                    break;
                }
                case 0x07: {
                    int n = PROGRAM[pc++] & 0xFF;
                    int a = stack[--sp];
                    stack[sp++] = ((a << n) | (a >>> (8 - n))) & 0xFF;
                    break;
                }
                case 0x08:
                    return ok;
                default:
                    return false;
            }
        }
    }
}
```

**`Challenge.java`**

```java
package com.example.latin;

import java.nio.charset.StandardCharsets;

public class Challenge {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("usage: Challenge <candidate>");
            return;
        }
        byte[] in = args[0].getBytes(StandardCharsets.UTF_8);
        System.out.println(Latin.run(in) ? "ACCEPTED" : "REJECTED");
    }
}
```

### Build it, and get the Smali

```bash
# host
mkdir -p lab04 && cd lab04
# ... save Latin.java and Challenge.java here ...
javac -d classes/ Latin.java Challenge.java

# Sanity: it should reject anything you try.
java -cp classes com.example.latin.Challenge FLAG{aaaaaaaaaaaaaaa}

# Now produce the artefact you are actually attacking.
d8 --release --output . classes/com/example/latin/*.class
baksmali d classes.dex -o smali/
wc -l smali/com/example/latin/Latin.smali
```

> **Play it properly.** From this point on, work **only** from `smali/`. Close `Latin.java`. The
> whole exercise is recovering the design from the disassembly, and if you keep the source open you
> will learn nothing.

---

## Reconnaissance

Start where you would start on any unknown APK.

```bash
# host
python3 ../scripts/smali_stats.py smali/ --top 25 --heuristics
python3 ../scripts/smali_frame.py smali/com/example/latin/Latin.smali
grep -c 'const-string' smali/com/example/latin/*.smali
grep -n 'fill-array-data\|array-data\|packed-switch\|sparse-switch' smali/com/example/latin/Latin.smali
```

**Q1.** How many `const-string` instructions are in `Latin.smali`? What does that tell you before you
read anything?

**Q2.** The profile flags a large switch and an array literal. What structure do those two facts,
together, suggest?

<details>
<summary>Answers</summary>

**A1.** Essentially none. A class with a hundred and fifty instructions and no string constants is not
doing string comparison. Whatever it compares, it compares numerically.

**A2.** A dispatch table plus a data blob. A `switch` on a value read from a byte array, inside a
loop, with a program counter — that is the shape of an **interpreter**, and the array is the program
it interprets. Recognising this shape in ten seconds is the skill; everything after it is bookkeeping.

</details>

---

## Stage 1 — Recover the instruction set

Open `smali/com/example/latin/Latin.smali` and find the `packed-switch`. Each `:pswitch_N` label is
one opcode handler.

Your task is to fill in this table **from the Smali**, not from the Java:

| Opcode | Operand bytes | Stack effect | Meaning |
|---:|---|---|---|
| `0x01` | | | |
| `0x02` | | | |
| `0x03` | | | |
| `0x04` | | | |
| `0x05` | | | |
| `0x06` | | | |
| `0x07` | | | |
| `0x08` | | | |

### How to read a handler

Take the `0x03` handler as a worked example. It will look something like:

```smali
    :pswitch_2
    add-int/lit8 v6, v3, -0x1        # sp - 1
    move v3, v6
    aget v7, v2, v3                  # b = stack[--sp]
    add-int/lit8 v6, v3, -0x1
    move v3, v6
    aget v8, v2, v3                  # a = stack[--sp]
    xor-int v9, v8, v7               # a ^ b
    and-int/lit16 v9, v9, 0xff
    aput v9, v2, v3                  # stack[sp] = result
    add-int/lit8 v3, v3, 0x1         # sp + 1
    goto :goto_dispatch
```

Every element of the chapter is in there. `aget` reads *dest, array, index*. `add-int/lit8` with a
negative literal is a decrement. `and-int/lit16 … 0xff` is a mask to a byte. `aput` reads *value,
array, index* — the reverse order. And the `goto` at the end returns to the dispatch loop.

**The three questions to ask of every handler:**

1. Does it read a byte from `PROGRAM` after the opcode? (An `aget-byte` on the program array with the
   post-incremented `pc` register — that is an **operand**.)
2. What does it pop, and what does it push? Count the `sp` decrements and increments.
3. What arithmetic sits between the pops and the push?

**Q3.** Two handlers read an operand and consume nothing from the stack. Two consume one stack value.
Three consume two. One consumes nothing and does not return to the loop. Identify them.

**Q4.** One handler contains `shl-int` and `ushr-int` on the same value, then an `or-int` and a mask.
What operation is that, and what is the operand for?

<details>
<summary>Hint for Q4</summary>

`((a << n) | (a >>> (8 - n))) & 0xFF` on an 8-bit value. Write out what happens to `0b10110011` with
`n = 3`. The bits that fall off the left reappear on the right. It is a **rotate**, not a shift — and
it is invertible, which is going to matter.

</details>

**Q5.** One handler sets a boolean register to 0 on mismatch but **does not return**. Why would a
designer write it that way rather than returning immediately?

<details>
<summary>Answer</summary>

To defeat timing and short-circuit attacks. If the VM returned at the first wrong character, an
attacker could measure how far it got and solve the input one character at a time from the outside
with no analysis at all. By running the whole program and only reporting at `HALT`, every wrong input
costs the same.

Note the irony, and note it carefully: **this defence does not actually work here**, because the
checks are still *independent*. You cannot observe which one failed from the outside, but once you
have read the program you can see that character `i` is only ever compared against a value derived
from character `i`. Independence in the program is what makes the 1,995-try attack possible, and
constant-time reporting does nothing about it.

</details>

---

## Stage 2 — Extract and disassemble the program

```bash
# host
sed -n '/\.array-data/,/end array-data/p' smali/com/example/latin/Latin.smali | head -30
```

**Q6.** What is the `.array-data` width, and how many bytes does the payload hold?

Now write a disassembler for the VM you just documented. Here is the skeleton — fill in the table:

```python
#!/usr/bin/env python3
# lab04_disasm.py -- disassemble the Latin VM program.
#
# Extract the payload from the Smali first:
#   sed -n '/\.array-data/,/end array-data/p' \
#       smali/com/example/latin/Latin.smali \
#       | grep -oE '^\s+-?0x[0-9a-f]+t?' > bytes.txt
#
# Then normalise: smali writes signed byte literals with a 't' suffix, and
# negative values as -0x.. -- so -0x52t is the byte 0xAE.

import re
import sys

OPS = {
    # opcode: (mnemonic, number_of_operand_bytes)
    0x01: ("PUSH", 1),
    0x02: ("LOAD", 1),
    # ... fill in the rest from Stage 1 ...
}

def load(path):
    out = []
    for line in open(path):
        m = re.search(r'(-?)0x([0-9a-fA-F]+)t?', line)
        if not m:
            continue
        v = int(m.group(2), 16)
        if m.group(1) == '-':
            v = (256 - v) & 0xFF
        out.append(v)
    return out

def main():
    prog = load(sys.argv[1])
    pc = 0
    while pc < len(prog):
        op = prog[pc]
        name, nops = OPS.get(op, ("???", 0))
        operands = prog[pc + 1: pc + 1 + nops]
        print("%04x: %-6s %s" % (pc, name,
                                 " ".join("0x%02x" % o for o in operands)))
        pc += 1 + nops

main()
```

Your output should be 190 bytes decoding into a perfectly regular pattern, repeated 21 times, ending
in a single `HALT`. If it is not regular, one of your operand counts is wrong — an off-by-one in
operand length desynchronises the whole stream, which is exactly what happens when you get an
instruction width wrong on a real disassembly.

**Q7.** Write out the 9-byte pattern in your own notation and say, in one English sentence, what it
checks.

<details>
<summary>Answer</summary>

```text
    LOAD  i        push input[i]
    PUSH  k_i      push a per-position key byte
    XOR            input[i] ^ k_i
    ROTL  3        rotate the result left by 3 bits
    CMP   c_i      it must equal c_i
```

In English: for each position `i`, rotating `input[i] XOR k_i` left by three bits must equal a
constant `c_i`.

</details>

---

## Stage 3 — Invert it

Every operation in the pattern is invertible, which is what makes this a keygen challenge rather than
a brute-force one.

**Q8.** `ROTL(x, 3) == c`. Solve for `x`.

**Q9.** `x ^ k == y`. Solve for `x`.

**Q10.** Compose them and write the solver.

<details>
<summary>Answers</summary>

**A8.** `x = ROTR(c, 3)`, where `ROTR(v, n) = ((v >> n) | (v << (8 - n))) & 0xFF`. A rotate is a
permutation of the bits, so it is always invertible — unlike a shift, which loses bits.

**A9.** `x = y ^ k`. XOR is its own inverse.

**A10.**

```python
#!/usr/bin/env python3
# lab04_solve.py -- recover the input the Latin VM accepts.

def rotr8(v, n):
    return ((v >> n) | (v << (8 - n))) & 0xFF

# From your disassembly: the (k_i, c_i) pairs, in order.
PAIRS = [
    (0x2b, 0x6b), (0x32, 0xf3), (0x39, 0xc3), (0x40, 0x38),
    (0x47, 0xe1), (0x4e, 0x51), (0x55, 0x0b), (0x5c, 0x81),
    (0x63, 0xa8), (0x6a, 0xda), (0x71, 0xd0), (0x78, 0x39),
    (0x7f, 0x72), (0x86, 0x9d), (0x8d, 0x96), (0x94, 0xc7),
    (0x9b, 0x7d), (0xa2, 0xb6), (0xa9, 0xc4), (0xb0, 0xf6),
    (0xb7, 0x56),
]

flag = "".join(chr(rotr8(c, 3) ^ k) for k, c in PAIRS)
print(flag)
```

</details>

**Q11.** Look at the `k_i` values in order: `0x2b`, `0x32`, `0x39`, `0x40`, … What is the pattern, and
what does noticing it save you?

<details>
<summary>Answer</summary>

They increase by 7 each time: `k_i = (0x2b + 7*i) & 0xFF`. Noticing it means you do not have to
transcribe 21 constants correctly — you can generate them, and a transcription error becomes
impossible rather than merely unlikely.

It also tells you something about the challenge author's key schedule, which on a real target is the
kind of observation that generalises: a linear key schedule usually means the same routine is used
elsewhere in the app with a different seed, and you have just learned how to attack all of them.

</details>

### Verify

```bash
# host
java -cp classes com.example.latin.Challenge "$(python3 lab04_solve.py)"
```

You want `ACCEPTED`.

---

## Stage 4 — The dynamic route

Do this **as well**, even though you already have the flag. It is the technique that works when the
transformation is *not* invertible, which is the common case in real challenges.

The key observation is from Q5: each position is checked **independently**. So instead of the whole
input space, attack one character at a time — but you cannot, because the app only reports at the
end.

Unless you make it report more often.

**Q12.** Using Lab 02's techniques, patch `Latin.smali` so the VM prints the outcome of *each* `CMP`
rather than only the final result. Which handler do you edit, and where exactly does the insertion
go?

<details>
<summary>Answer</summary>

The `0x06` (`CMP`) handler. The insertion goes immediately after the comparison, before the `goto`
back to the dispatch loop. You need three spare registers for a `Log`/`println` call, so raise
`.locals` — and because the interpreter's main method almost certainly refers to its parameters by
`pN` (check with `smali_frame.py --check` first), that raise is safe.

A minimal version, using `System.out` so it works on the desktop JVM too:

```smali
    # inside the CMP handler, after 'got' and 'want' are both in registers
    sget-object v10, Ljava/lang/System;->out:Ljava/io/PrintStream;
    invoke-static {v8}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;
    move-result-object v11
    invoke-virtual {v10, v11}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V
```

Then reassemble the single class:

```bash
# host
smali a smali/ -o patched.dex --api 34
```

and run it either on a device or by converting back — for the desktop route it is simpler to make the
same edit in the Java and rebuild, but doing it in Smali is the point of the exercise.

</details>

**Q13.** With per-comparison output, how many candidate runs do you need to recover all 21
characters? Show the arithmetic.

<details>
<summary>Answer</summary>

For each position, try every printable ASCII character (0x20–0x7E, 95 of them) and watch whether that
position's comparison passes. 21 × 95 = **1,995** runs, and you can cut it to a few hundred by trying
the plausible flag alphabet first. Compare against 95^21, which is roughly 3 × 10^41.

The reduction comes entirely from **independence**, not from the patch. The patch only lets you
*observe* the independence that was already there. That distinction is the real lesson: when you meet
a custom VM, the first question is not "how do I break the crypto" but "is each part of the secret
checked separately".

</details>

---

## Stage 5 — Write it up

Produce a short report as if this were a commercial protection SDK, covering:

1. **The mechanism.** What the developer built, described precisely enough for another engineer to
   recognise it in a different app.
2. **The instruction set.** Your table from Stage 1. This is the deliverable a colleague reuses.
3. **The break.** The two independent routes, with effort estimates.
4. **What the design got right.** Be fair: constant-time reporting, no plaintext flag, no single
   comparison to hook, and no strings to grep.
5. **What it got wrong.** Independent per-character checks; an invertible transformation; a linear
   key schedule; and the interpreter itself shipped unobfuscated in the same DEX.
6. **What would actually raise the cost.** Argue this properly rather than listing buzzwords.

<details>
<summary>Model answer for 6</summary>

- **Make the checks interdependent.** Feed each character's result into the next position's key, so a
  wrong character at position 3 corrupts every later comparison. That alone destroys the 1,995-try
  attack, because you can no longer isolate a position.
- **Use a non-invertible transformation.** Compare a hash of the whole input against one constant.
  Then there is no inversion, only search — and search is what a good password does.
- **Do not ship the interpreter in the DEX.** Put it in native code. That does not make it secret, but
  it removes the `baksmali`-readable dispatch table that made Stage 1 an afternoon rather than a week.
- **Randomise the opcode numbering per build.** Then the instruction set a colleague recovered last
  month does not transfer, and Stage 1 has to be repeated for every release.
- **And say the honest thing out loud:** none of this makes the check unbreakable, because the app
  must be able to evaluate it, so the semantics are present at run time by construction. All of it
  buys **time**. If the secret genuinely matters, it must be checked on a server. Chapter 14 §10's
  Principal-level question makes the same argument at greater length.

</details>

---

## Hints

Open them in order, and only when genuinely stuck.

<details>
<summary>Hint 1 — I do not know where to start</summary>

Do not read the file top to bottom. Run the reconnaissance commands. Find the `packed-switch`. Count
its cases. Each case is one instruction of a language you are about to document.

</details>

<details>
<summary>Hint 2 — I cannot tell which registers are the stack and the program counter</summary>

Look for the register that is incremented by 1 immediately after every `aget-byte` on the same array —
that is the program counter, and that array is the program. Look for a second array that is written
with `aput` and read with `aget` at an index that goes up and down — that is the stack, and the index
register is `sp`.

`baksmali d --no-parameter-registers` can help here: it stops hiding parameters behind `p` names, so
the register numbering is uniform and easier to track by eye.

</details>

<details>
<summary>Hint 3 — my disassembly desynchronises after a few instructions</summary>

An operand-count error. If you decode an instruction as taking zero operand bytes when it takes one,
every instruction after it is misaligned and the output turns to noise. Go back to the handler that
first produces nonsense and re-read whether it does an extra `aget-byte` on the program array.

This is not an artificial problem — it is exactly the failure mode of linear-sweep disassembly on any
architecture with variable-length instructions.

</details>

<details>
<summary>Hint 4 — I have the pattern but cannot invert the rotate</summary>

`ROTL(x, 3)` moves bit 0 to bit 3, bit 5 to bit 0, and so on. No bits are lost. The inverse is
`ROTL(x, 5)`, which is the same as `ROTR(x, 3)`, because 3 + 5 = 8.

If you had a *shift* instead of a rotate you would be stuck, because a shift discards bits. That
difference is the whole reason this challenge is solvable on paper.

</details>

<details>
<summary>Hint 5 — I have the algorithm but my output is garbage</summary>

Three usual causes:

1. You transcribed the constants by hand and made a mistake. Generate `k_i` from the pattern in Q11
   instead.
2. You are treating the smali byte literals as unsigned. `-0x52t` in an `.array-data 1` payload is the
   byte `0xAE`, not `0x52`. Normalise with `(256 - v) & 0xFF`.
3. You applied the inverse operations in the wrong order. The forward direction is XOR then ROTL, so
   the inverse is ROTR then XOR.

</details>

---

## Success criteria

- [ ] You produced the full opcode table from the Smali alone, without opening `Latin.java`.
- [ ] Your disassembler decodes all 190 bytes into a regular, self-consistent listing.
- [ ] Your solver produces a string the challenge ACCEPTs.
- [ ] You also recovered it dynamically, and can state the effort reduction with arithmetic.
- [ ] You can explain why patching the check to return `true` would have been useless here.
- [ ] Your write-up gives the design credit for what it got right.
- [ ] You can describe, from memory, the general procedure for any custom-VM protection.

---

## Instructor notes

<details>
<summary>Spoilers — flag, key schedule and solver</summary>

**Flag:** `FLAG{d4lv1k_15_l4t1n}` — 21 characters including the braces.

**Key schedule:** `k_i = (0x2B + 7*i) & 0xFF`.

**Forward transformation:** `c_i = ROTL8(flag[i] XOR k_i, 3)`.

**Instruction set:**

| Opcode | Operand | Mnemonic | Effect |
|---:|---|---|---|
| `0x01` | imm8 | `PUSH` | push imm |
| `0x02` | idx8 | `LOAD` | push `input[idx] & 0xFF`; fail if `idx >= len` |
| `0x03` | — | `XOR` | `b = pop; a = pop; push (a ^ b) & 0xFF` |
| `0x04` | — | `ADD` | `push (a + b) & 0xFF` |
| `0x05` | — | `SUB` | `push (a - b) & 0xFF` |
| `0x06` | imm8 | `CMP` | `pop`; if `!= imm` set the fail flag, **do not return** |
| `0x07` | n8 | `ROTL` | `pop a`; push `((a << n) OR (a >>> (8-n))) & 0xFF` — a bitwise-or rotate |
| `0x08` | — | `HALT` | return the flag |

`ADD` and `SUB` are never used by this program. They are there so that recovering the instruction set
requires reading every handler rather than only the ones the program happens to exercise — which is
also true of real VMs, whose interpreters always implement more than any one program uses.

**Reference generator and solver** (this produced the `PROGRAM` array above and recovers the flag
from it; both directions verified):

```python
#!/usr/bin/env python3
FLAG = "FLAG{d4lv1k_15_l4t1n}"

def rotl8(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF
def rotr8(x, n): return ((x >> n) | (x << (8 - n))) & 0xFF

# forward -- build the program
prog, pairs = [], []
for i, ch in enumerate(FLAG):
    k = (0x2B + 7 * i) & 0xFF
    c = rotl8(ord(ch) ^ k, 3)
    pairs.append((k, c))
    prog += [0x02, i, 0x01, k, 0x03, 0x07, 0x03, 0x06, c]
prog.append(0x08)
assert len(prog) == 190

# inverse -- recover the flag
recovered = "".join(chr(rotr8(c, 3) ^ k) for k, c in pairs)
assert recovered == FLAG, recovered
print("program bytes:", len(prog))
print("recovered    :", recovered)
```

**Verified behaviour of the challenge as published:**

| Input | Result |
|---|---|
| `FLAG{d4lv1k_15_l4t1n}` | ACCEPTED |
| `FLAG{aaaaaaaaaaaaaaa}` | REJECTED |
| `FLAG{}` (wrong length) | REJECTED |
| `FLAG{d4lv1k_15_l4t1N}` (one character off) | REJECTED |

**Making it harder**, if a group finishes early:

- Chain the positions: `k_i = k_{i-1} XOR input[i-1]`. This removes independence and kills the
  dynamic route entirely.
- Add opaque `ADD`/`SUB` steps that cancel out, so the pattern is no longer nine bytes and cannot be
  eyeballed.
- Interleave the per-character checks so the program is not 21 identical blocks.
- Randomise the opcode numbers and rebuild — the previous group's table stops working.

**Making it easier**, for a first attempt: shorten the flag to eight characters and drop `ROTL`, so
the pattern is `LOAD / PUSH / XOR / CMP` and the inversion is a single XOR.

</details>

---

## Where this leads

Custom bytecode VMs are the deep end of [40 — Obfuscation](../../40-Obfuscation/README.md), and this
lab is the instruction-level literacy that chapter assumes. The same procedure — read the
interpreter, recover the instruction set, disassemble the program, reverse it — applies whether the
interpreter is in Smali, in a `.so` you open with [57 — Ghidra](../../57-Ghidra/README.md), or in
JavaScript inside a WebView.

The one thing that never changes: **the interpreter has to be readable, because the machine has to
run it.**
