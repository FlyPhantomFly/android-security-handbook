# Lab 04 — CTF: the function that does not matter

> **Five flags.** Every one is recoverable by at least two independent routes, and every one is a trap
> that has cost somebody in this repository real time. There are no hidden strings, no steganography
> and no guessing: each flag is a fact about a binary you built, and each is checked against a
> published SHA-256 so you can verify yourself without an answer key.
>
> The title is flag 2. It is the most important one.

| | |
|---|---|
| **Difficulty** | Advanced |
| **Time** | 3 hours |
| **Needs an IDA licence?** | **No.** Every flag has a free-tool route |
| **Needs a device?** | **Flag 4 only, and even there a host build works.** Section 5 gives three routes |
| **You come out with** | Five verified flags and, more usefully, five habits |

---

## 0. Rules

1. **Build the target yourself.** Do not ask anyone for a binary.
2. **Do not read [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md)**
   until you have finished, or until you have used all the hints for a flag. It contains every answer.
3. **Do not read [`../examples/01-session-target.c`](../examples/01-session-target.c)'s header
   comment.** It is the design document for the traps.
4. Each flag's exact format is specified. Case and punctuation matter.
5. Verify with SHA-256. The hashes are in section 8.

```bash
# host — how to check a flag
printf '%s' 'CH58{your_answer_here}' | sha256sum
```

Note `printf` rather than `echo`: `echo` appends a newline and the hash will not match.

---

## 1. Setup

```bash
# host
cd 58-IDA/examples
OUTDIR=/tmp/ch58 ./build.sh

# hide the answer key from yourself
mkdir -p /tmp/ch58-answers
mv /tmp/ch58/ground-truth.txt /tmp/ch58-answers/

export NDKBIN="$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
```

You may use either build. `libsession.so` (stripped) is the honest challenge; `libsession-unstripped.so`
makes the listings readable while you learn. Flags 1, 2, 3 and 5 are solvable from the stripped build
alone, and doing so is worth the extra difficulty.

> **Warning**
> Every address in this lab is specific to one build. Yours will differ if you use a different NDK, a
> different API level, or a different optimisation level. **The flags are not addresses** — every one
> is an invariant fact — precisely so the challenge survives a rebuild. If a hint quotes an address,
> treat it as an example of a shape and find your own.

---

## 2. Flag 1 — the constant that is not in the file

> **The trap:** you can read a 32-bit constant in the disassembly, search the binary for its four
> bytes, and find nothing. No obfuscation is involved. This is what ordinary optimisation does, and
> people conclude the binary is packed.

**Find** the 32-bit magic value that several functions compare a loaded word against.

**Flag format:** `CH58{xxxxxxxx}` — the value in **lowercase hex, eight digits, no `0x` prefix**.
Example shape: `CH58{deadbeef}`.

### Where to start

```bash
# host — find the comparison
"$NDKBIN/llvm-objdump" -d /tmp/ch58/libsession.so | grep -B3 -A3 'movk'
```

### The trap, made concrete

Once you think you have the value, try to find it in the file:

```bash
# host — replace with your value's bytes, little-endian
"$NDKBIN/llvm-objdump" -s /tmp/ch58/libsession.so | grep -i '4e53 4553'
```

**It will not be there.** Write one sentence saying why before you move on. That sentence is the
actual deliverable; the flag is just proof you got there.

<details>
<summary><b>Hint 1</b></summary>

AArch64 cannot encode an arbitrary 32-bit immediate in a single instruction. Look for a `mov` of a
16-bit value immediately followed by a `movk` of another 16-bit value with `lsl #16`, both targeting
the same register.

</details>

<details>
<summary><b>Hint 2</b></summary>

`movk` means *move wide with keep*: it writes its immediate into the selected 16-bit field and leaves
the rest of the register alone. So `mov w9, #A` then `movk w9, #B, lsl #16` builds `(B << 16) | A`.

The immediates are printed in **decimal** by `llvm-objdump`. Convert them.

</details>

<details>
<summary><b>Hint 3</b></summary>

```bash
# host
python3 -B -c "print('%08x' % ((21317 << 16) | 21326))"
```

Substitute the two decimal immediates your build actually shows.

</details>

---

## 3. Flag 2 — the function that does not matter

> **The trap:** an exported function, correctly implemented, that does exactly what you want to
> bypass — and that nothing calls. Patch it and it will provably return whatever you made it return,
> and the program's behaviour will not change by one bit. Chapter 18 §5.4 measured this on a different
> fixture and calls it the most useful teaching artefact in that chapter. Chapter 65 hit it from the
> hooking side. Chapter 54 measured objection failing on it.

**Find** the exported function that makes a validity decision and has **zero** call sites anywhere in
the library.

**Flag format:** `CH58{name}` — the exact symbol name. Example shape: `CH58{do_the_thing}`.

### The measurement that settles it

```bash
# host — count call sites for every exported function
for f in $("$NDKBIN/llvm-nm" -D --defined-only /tmp/ch58/libsession.so | awk '{print $3}'); do
    n=$("$NDKBIN/llvm-objdump" -d /tmp/ch58/libsession.so \
        | grep -cE "bl[[:space:]]+.*<${f}(@plt)?>")
    printf '%-50s %s\n' "$f" "$n"
done
```

### The sub-trap inside the trap

**The `(@plt)?` group above is not decoration.** Chapter 68 §8.3 measured that a bare `<name>` grep
produces a **false negative** on PLT-routed calls — and this library's calls to its own exported
functions *are* PLT-routed, because default visibility makes them interposable.

Prove it for yourself before you trust any zero in that table:

```bash
# host — the library's own functions, reached through the PLT
"$NDKBIN/llvm-readelf" -r /tmp/ch58/libsession.so | grep JUMP_SLOT
```

If some of your library's own functions appear there, then a zero from the *bare* pattern would have
been meaningless. A zero from the pattern **with** the optional group is real.

### The deliverable that matters more than the flag

Answer, in writing: *why does an exported, correct, never-called function exist in this binary at all?*

<details>
<summary><b>Hint 1</b></summary>

Look at the function's size. It is small — two or three instructions of actual work. Now think about
what `-O2` does to a small function that is called from several places in the same translation unit.

</details>

<details>
<summary><b>Hint 2</b></summary>

Find the same instruction sequence elsewhere. Search for the `movk` pattern from flag 1:

```bash
# host
"$NDKBIN/llvm-objdump" -d /tmp/ch58/libsession.so | grep -c 'movk'
```

If that sequence appears in four functions and only one of them is the exported predicate, the other
three are inlined copies.

</details>

<details>
<summary><b>Hint 3</b></summary>

The exported symbol exists because the source marked it with default visibility. The compiler kept the
standalone body so that an external caller could link against it, *and* inlined the body into every
internal caller because that is faster. Both copies exist; only the inlined ones run.

The consequence for you: **check cross-references before patching.** One keystroke in IDA (`X`), one
grep otherwise.

</details>

---

## 4. Flag 3 — the strings that are not there

> **The trap:** `strings` returns nothing interesting and you conclude there is nothing to find. The
> strings exist; they just do not exist *yet*.

**Recover** the two plaintext strings that the library decodes at run time.

**Flag format:** `CH58{first|second}` — the two decoded strings **in the order the encoded arrays
appear in `.rodata`**, joined with a single pipe character, no spaces. Example shape:
`CH58{/foo/bar|baz.qux}`.

### Establish the absence first

```bash
# host
"$NDKBIN/llvm-strings" -a -n 4 /tmp/ch58/libsession.so | sort -u | head -40
```

**Journal entry.** How many human-meaningful strings does a 300-line library have? Write your
expectation, then count. The gap is the finding.

### Then find what is there instead

```bash
# host — .rodata, in full
"$NDKBIN/llvm-readelf" -x .rodata /tmp/ch58/libsession.so
```

You are looking for a run of bytes that is not ASCII, not visibly a table, and referenced by exactly
one function.

<details>
<summary><b>Hint 1</b></summary>

Look for a function containing a loop that reads a byte, applies `eor` with a constant, and stores to
a stack buffer. `eor` is exclusive-or. The constant is the key.

```bash
# host
"$NDKBIN/llvm-objdump" -d /tmp/ch58/libsession.so | grep -B4 -A4 'eor.*#'
```

</details>

<details>
<summary><b>Hint 2</b></summary>

The two encoded arrays are adjacent in `.rodata` and each ends with a `00` byte. The first is 15 bytes
including its terminator; the second is 14. Their bytes are in the range `0x23`–`0x75`, which is a tell
in itself: a byte range that narrow is not random data.

Decode:

```bash
# host — substitute your bytes and your key
python3 -B -c "
b=[0x75,0x29,0x23,0x29,0x2e]      # ... the full array
k=0x5A
print(''.join(chr(x^k) for x in b if x))"
```

</details>

<details>
<summary><b>Hint 3 — the dynamic route</b></summary>

You do not have to decode anything. Break on the function that calls the decoder, step past both
calls, and read the stack. Both plaintexts will be sitting there in clear.

That is the whole argument for pairing a disassembler with a debugger rather than choosing between
them — and it is the route that still works when the encoding is not a one-byte XOR.

</details>

### The point of this flag

The two strings look like a root check. **They are not**, and the fixture deliberately does not use
them as one — it compares them against themselves so that the library's behaviour does not depend on
the device it runs on. That is a design decision worth noticing: **a fixture whose result changes per
device is useless as an answer key.**

But you could not have known that from the strings. Finding `/system/bin/su` in a binary tells you the
string is present, not that a check exists, not that it runs, and not what happens if it passes. That
is the same discipline chapter 38 arrived at when its detector reported a self-signature check in 18 of
18 APKs and was wrong about five of them.

---

## 5. Flag 4 — the value you cannot compute by reading

> **The trap:** you can read the derivation, you can read the constants, and you still cannot state
> the answer without running something. Static analysis has a hard boundary and this is where it is.

**Recover** the 16-byte key that the library's self-test produces.

**Flag format:** `CH58{xxxx...}` — the key as **32 lowercase hex digits**, exactly as the library's own
report function formats it.

### What the self-test does

The JNI entry point runs a fixed sequence with fixed inputs. Read it to find out what they are:

```bash
# host
"$NDKBIN/llvm-objdump" -d --disassemble-symbols=Java_com_pentest_ch58_Session_nativeSelfTest \
    /tmp/ch58/libsession-unstripped.so
```

You need three things: the user name, the timestamp, and the sequence of operations.

### Route A — run it on a device

```bash
# host — build for the device's ABI and a driver to call it
cat > /tmp/ch58ctf-runner.c <<'EOF'
#include <stdio.h>
#include <string.h>
extern int session_init(void *, const char *, unsigned long long);
extern int session_dispatch(void *, int);
extern int session_step(void *, int, const unsigned char *, unsigned long);
extern int session_seal(void *);
extern int session_report(const void *, char *, unsigned long);
int main(void) {
    unsigned char s[0x50]; char out[160];
    memset(s, 0xAA, sizeof s);
    session_init(s, "tester", 1700000000ULL);
    session_dispatch(s, 0);
    session_step(s, 3, 0, 0);
    session_seal(s);
    session_report(s, out, sizeof out);
    printf("report=%s\n", out);
    return 0;
}
EOF
```

Build it against the same sources for your device's ABI, push both to a directory of your own under
`/data/local/tmp`, and run with `LD_LIBRARY_PATH=.`.

> **Warning**
> Use a directory name nobody else will pick — other chapters in this repository put workspaces under
> `/data/local/tmp` and one of them was live while this lab was written. **Remove yours when you are
> done, and remove only yours.**
>
> On Git Bash, `adb push /local/path /device/path` will silently rewrite the *device* path into a
> Windows path. `MSYS_NO_PATHCONV=1` fixes the device side and breaks the host side, so convert the
> host path with `cygpath -m` and set the variable only on the adb invocation. Chapter 68 documented
> this; it cost time here too.

### Route B — build a host driver

The key derivation is pure 64-bit integer arithmetic and is **architecture-independent**. Build the
same two sources for your own machine with your system compiler, link the driver above, and run it.
You will get the same answer.

### Route C — reimplement the derivation

Read `session_init`'s key loop and write it out in Python. This is the hardest route and the most
instructive, because it forces you to be exactly right about the arithmetic.

<details>
<summary><b>Hint 1</b></summary>

The key derivation hashes the user name with a 64-bit FNV-1a, mixes in the timestamp, and then fills
sixteen bytes with a loop. The FNV constants are the giveaway: offset basis `0xCBF29CE484222325`,
prime `0x100000001B3` — and neither is in the file contiguously, for the same reason as flag 1.

</details>

<details>
<summary><b>Hint 2</b></summary>

The loop is: take a byte out of the running hash, then advance the hash. The byte selected rotates
through the eight bytes of the hash; the advance is a multiply by the FNV prime plus the loop counter.
All arithmetic is modulo 2^64.

</details>

<details>
<summary><b>Hint 3 — the shape of route C</b></summary>

```python
M = (1 << 64) - 1
def fnv(b):
    h = 0xCBF29CE484222325
    for x in b:
        h ^= x
        h = (h * 0x100000001B3) & M
    return h

h = fnv(b'tester') ^ 1700000000
key = []
for i in range(16):
    key.append((h >> ((i % 8) * 8)) & 0xFF)
    h = (h * 0x100000001B3 + i) & M
print(''.join('%02x' % x for x in key))
```

If your reading of the loop differs from this, **trust your reading and check both against a real
run.** That is the entire point of the flag.

</details>

### The measurement, for reference

This lab's author ran route A on an `sdk_gphone16k_x86_64` AVD (Android 15 / API 35, x86_64) and
independently reproduced the same value with route C in Python. Two routes, one answer, different
architectures — which is what makes it safe to publish a fixed hash for a value that depends on
arithmetic.

The runner also reported `crc=841a7cce state=2 flags=00000003 step=2`, which is worth knowing if you
want to check the rest of your structure recovery from lab 02 at the same time.

---

## 6. Flag 5 — where static analysis stops

> **The trap:** a table of function pointers that reads as **twenty-four zero bytes** in a hex dump.
> The obvious conclusion — the table is empty, or is filled in later from somewhere unknowable — is
> wrong, and the correct answer is one command away.

**Name** the function whose address occupies the **third** slot of the library's function-pointer
table.

**Flag format:** `CH58{name}` — the exact symbol name.

### Find the table

```bash
# host — the one indirect call in the library
"$NDKBIN/llvm-objdump" -d /tmp/ch58/libsession.so | grep -B6 -E '[[:space:]]blr[[:space:]]'
```

The instruction before the `blr` loads a pointer from somewhere. Work out where.

### Look at it

```bash
# host
"$NDKBIN/llvm-readelf" -x .data /tmp/ch58/libsession.so
```

Zeroes.

<details>
<summary><b>Hint 1</b></summary>

An `ET_DYN` object does not know where it will be loaded, so it cannot store absolute addresses in
the file. It stores **relocations** instead: instructions to the loader saying "at this offset, write
`load_bias + addend`". The bytes in the file stay zero until load time.

Chapter 15 §3.7 owns relocations, and measured the same behaviour on `.init_array`, where the
constructor's address is eight zero bytes on disk.

</details>

<details>
<summary><b>Hint 2</b></summary>

```bash
# host
"$NDKBIN/llvm-readelf" -r /tmp/ch58/libsession.so | grep -i relative
```

Each `R_AARCH64_RELATIVE` line has an **offset** (where the pointer goes) and an **addend** (what
goes there). Pick the three whose offsets are consecutive and eight bytes apart, in the section your
`blr` reads from.

</details>

<details>
<summary><b>Hint 3</b></summary>

You now have three code addresses. Disassemble each:

```bash
# host — substitute your addends
"$NDKBIN/llvm-objdump" -d --start-address=0x5510 --stop-address=0x5530 \
    /tmp/ch58/libsession.so
```

The third one is short, contains a shift-and-XOR loop with no calls and no table, and is therefore not
either of the other two. Naming it requires either the unstripped build or a description of what it
computes — and the flag wants the name, so use the unstripped build once you have located it in the
stripped one.

</details>

### The deliverable that outlives the flag

Answer in writing: **how many places in this library does a purely static reading stop?** Count the
`blr` instructions and any `br <reg>` your tool did not resolve into cases. That number is a coverage
statement and it belongs in a report — chapter 68 §3.17 calls it the residue.

---

## 7. The sixth thing, which is not a flag

There is one more trap in this binary and it has no flag, because the answer is a sentence rather than
a string.

**One function in this library exists twice, in two different shapes, from one piece of source.**

Find it. Then answer:

1. Which function?
2. What is different between the two copies?
3. What single fact about the second call site caused the difference?
4. What does this do to the claim "the decompiler shows you the source"?

<details>
<summary><b>Where to look</b></summary>

Compare the two jump tables:

```bash
# host
"$NDKBIN/llvm-readelf" -x .rodata /tmp/ch58/libsession-unstripped.so | head -4
```

There are two twelve-byte tables. Count the repeated values in each. One table has three entries
pointing at the same target; the other has four.

The extra collapsed case is the answer to question 3.

</details>

<details>
<summary><b>The answer to question 4</b></summary>

A decompiler shows you *a* source program that would compile to *these* bytes. Here there are two sets
of bytes from one source, and a faithful decompilation of each would produce two different C
functions — one of which has cases the original source has and the other does not.

Any statement of the form "the function does X" can therefore be true of one copy and false of the
other. Chapter 68's evidence ladder puts decompiled code at Tier 3 for exactly this class of reason,
and chapter 56 measured the managed-code version: decompiled Java that is clean, warning-free, and
returns 100 where the bytecode returns 105.

</details>

---

## 8. Verification

```bash
# host — check each flag
printf '%s' 'CH58{...}' | sha256sum
```

| Flag | SHA-256 of the correct answer |
|---|---|
| 1 | `3165f7ef6c1c9a334749ba060ee22efeef187d5b25d63693f96911b0aa6a395e` |
| 2 | `c573c0ed283292a11b0327c3d2102387132e00aa93f64b587ff8f6c645ab49ac` |
| 3 | `da061034373945fc59cf45dadeabaa599efbb7daa97c39ba415ae2eef7d48c46` |
| 4 | `d8af5ec7ecdfe2a485f7f53a64802767e3058e22404f8ead802733f7eacaf775` |
| 5 | `cdc89c42ea566e9279b4f272d1629ff1b4ec23f3347bcd01d3e3eed0ad3570e0` |

Format reminders, because a wrong format is not a wrong answer:

| Flag | Format |
|---|---|
| 1 | `CH58{` + 8 lowercase hex digits + `}`, no `0x` |
| 2 | `CH58{` + exact symbol name + `}` |
| 3 | `CH58{` + first string + `|` + second string + `}`, no spaces, `.rodata` order |
| 4 | `CH58{` + 32 lowercase hex digits + `}` |
| 5 | `CH58{` + exact symbol name + `}` |

Use `printf`, not `echo`. A trailing newline changes the hash.

---

## 9. Success criteria

| # | Criterion |
|---|---|
| 1 | Five flags verified against the hashes |
| 2 | You can explain why a byte search for flag 1's constant fails, with no obfuscation involved |
| 3 | You proved the zero call count for flag 2 with a pattern that accounts for PLT routing |
| 4 | You can say what would have happened had you patched flag 2's function |
| 5 | You recovered flag 3 both statically and dynamically, or can describe the dynamic route precisely |
| 6 | You can say why finding `/system/bin/su` in a binary is not a finding |
| 7 | You solved flag 4 by two independent routes and got the same answer |
| 8 | You can state the boundary flag 4 illustrates: what static analysis cannot give you |
| 9 | You explained flag 5's zero bytes in terms of relocations |
| 10 | You counted the places static analysis stops, and wrote the number down |
| 11 | You found the function that exists twice, and can explain what caused the difference |
| 12 | You cleaned up anything you pushed to a device — and only your own files |

---

## 10. What each flag was really teaching

| Flag | The habit |
|---|---|
| 1 | **A byte search for a constant can fail on ordinary optimised code.** Search for the shape, not the value |
| 2 | **Check cross-references before you patch or hook.** An exported, correct function may run zero times. Measured across chapters 18, 54 and 65 |
| 3 | **Absence is evidence.** A library with no strings has encoded them — and a string's presence is not a behaviour |
| 4 | **Static analysis has a hard boundary.** Some answers require execution, and knowing which is a skill |
| 5 | **Check whether your tool applies relocations** before concluding that a table is empty |
| 6 (no flag) | **One function can exist twice.** "The decompiler shows you the source" is false, and this is the cheapest demonstration |

None of these depends on which disassembler you own. That is the chapter's argument, arriving at the
end of it: **the instrument matters less than knowing what would falsify your answer.**

---

| | |
|---|---|
| [Lab 01](lab-01-first-database.md) · [Lab 02](lab-02-struct-recovery.md) · [Lab 03](lab-03-flirt-and-typelibs.md) | The build-up |
| [Chapter README](../README.md) | §11.4 records three mistakes made building this fixture |
| [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md) | The full answer key. Read it now |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | The method these habits belong to |
