# Lab 02 — Triage a real library

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-the-command-language.md),
[15-Native-Code](../../15-Native-Code/README.md), [16-JNI](../../16-JNI/README.md),
[Chapter 59 §3.4–§3.8](../README.md#34-rabin2--the-part-you-will-use-most-and-think-about-least)

---

## Why this lab exists

Lab 01 taught you to *type*. This lab teaches you to *decide*.

The single most common way to be slow with radare2 is to run full analysis on everything by reflex.
The second most common is to open a decompiler for a question that a symbol table would have
answered. Both come from not having a cost model, and this lab builds one out of measurements you
take yourself.

You will also reproduce the chapter's most important measured finding: **a string that the source
code carefully encrypts, and that the optimiser puts back in plaintext.** That one is worth the lab
on its own, because it is a real finding you can take to a real client, and because almost everybody
believes the opposite.

> **On the state of this chapter**
> radare2 was **not installed** on the machine where this was written. Every `r2`/`rabin2` command is
> **Unverified**. Every stated fact about a binary is **Measured** with the NDK's LLVM tools and
> says so. Where a measurement was taken with `llvm-readelf`/`llvm-nm`/`llvm-objdump` rather than
> with `rabin2`, that is stated — the two read the same ELF structures, but you should know which
> produced the number in front of you.

---

## Objective

1. Answer real triage questions using only structural parsing, and know why that is cheap.
2. Measure the difference between "parse" cost and "analyse" cost, on real libraries.
3. Recognise both JNI registration mechanisms from the native side.
4. Reproduce the `-O2` string-folding finding and explain it.
5. Run a corpus scan and interpret the output.

---

## Setup

### Build the targets

```bash
# host -- out of tree
cd 59-radare2/examples
./build.sh
```

This produces, in `$HOME/ch59-build`:

| File | What it is |
|---|---|
| `libr2target.so` | `-O2` shared library — the main target |
| `libr2target-O0.so` | `-O0` build of *identical source* — for Part 4 |
| `libr2hardened.so` | `-O2` with the fix — for Part 4 |
| `r2gate` | AArch64 executable — used in lab 03 |
| `build-report.txt` | the measurements, reproduced on your machine |

### Get a corpus of real libraries

You need libraries that are big and real. An emulator or any device provides them:

```bash
# host -- pull a handful of real Android system libraries
mkdir -p ~/ch59-corpus && cd ~/ch59-corpus
adb pull /system/lib64/libsqlite.so .
adb pull /system/lib64/libcrypto.so .
adb pull /system/lib64/libandroid_runtime.so .
adb pull /system/lib64/libmedia_jni.so .
```

If your device is an x86_64 emulator, there is usually an AArch64 set as well, which is more
representative of a real phone:

```bash
# host -- AArch64 libraries on an x86_64 AVD (present when NDK translation is installed)
adb shell 'ls /system/lib64/arm64/ | head'
adb pull /system/lib64/arm64/libsqlite.so libsqlite-arm64.so
adb pull /system/lib64/arm64/libcrypto.so libcrypto-arm64.so
```

> **Measured** — the device used for this chapter was the AVD `sdk_gphone16k_x86_64`,
> Android 15 / API 35, `ro.product.cpu.abilist = x86_64,arm64-v8a`, `getconf PAGE_SIZE = 16384`.
> Both `/system/lib64/` (x86_64) and `/system/lib64/arm64/` (AArch64) exist on it.

You can also use an APK you are authorised to test:

```bash
# host
unzip -o target.apk -d ~/ch59-corpus/apk/
ls ~/ch59-corpus/apk/lib/
```

> **Warning**
> Only use APKs you own or that are published as deliberately-vulnerable training targets. See the
> ethics note in [68-ReverseEngineering](../../68-ReverseEngineering/README.md).

---

## Part 1 — Structural questions are nearly free (30 minutes)

### 1.1 — Orientation without opening a session

`rabin2` is radare2's ELF parser as a standalone program. It never analyses code.

```bash
# Unverified
rabin2 -I ~/ch59-corpus/libsqlite.so     # arch, bits, stripped, hardening
rabin2 -l ~/ch59-corpus/libsqlite.so     # DT_NEEDED
rabin2 -S ~/ch59-corpus/libsqlite.so     # sections
rabin2 -qi ~/ch59-corpus/libsqlite.so | head -30    # imports, quiet
rabin2 -qz ~/ch59-corpus/libsqlite.so | head -30    # strings, quiet
```

Time each one. They should all complete in well under a second, including on a 2 MB library.

### 1.2 — Why it is fast

The reason is in the ELF layout: parsing structure means reading a few headers and walking two or
three tables, and those tables are small relative to the code.

> **Measured** — these are the real numbers for the corpus this chapter used, obtained with
> `llvm-readelf` and `llvm-nm` from NDK 25.2.9519653. `.text bytes` is the section's size field;
> the instruction count is exact for AArch64 because instructions are four bytes.
>
> **AArch64, from `/system/lib64/arm64/`:**
>
> | Library | File bytes | `.text` bytes | Instructions | `.dynsym` | Code bytes per name |
> |---|---:|---:|---:|---:|---:|
> | `libandroid_runtime.so` | 306,880 | 36,720 | 9,180 | 1,149 | 31 |
> | `libc.so` | 1,043,784 | 510,348 | 127,587 | 1,477 | 345 |
> | `libcrypto.so` | 1,394,600 | 843,420 | 210,855 | 2,503 | 336 |
> | `libicui18n.so` | 2,799,504 | 1,590,884 | 397,721 | 6,468 | 245 |
> | **`libsqlite.so`** | 1,930,416 | **1,657,588** | **414,397** | **364** | **4,553** |
>
> **x86_64, from `/system/lib64/`:**
>
> | Library | File bytes | `.text` bytes | `.dynsym` |
> |---|---:|---:|---:|
> | `libmedia_jni.so` | 654,904 | 337,929 | 1,113 |
> | `libcrypto.so` | 1,592,592 | 1,032,872 | 2,499 |
> | `libsqlite.so` | 2,028,792 | 1,747,859 | 364 |
> | `libandroid_runtime.so` | 2,623,840 | 1,493,358 | 3,992 |
> | `libhwui.so` | 13,005,808 | 6,336,785 | 1,080 |
> | `libLLVM_android.so` | 21,465,896 | 9,712,602 | 16,241 |

Stare at `libsqlite.so` for a moment. **1.66 MB of code — 414,397 instructions — behind 364 names.**
Structural parsing reads the 364-entry table. Code analysis has to invent names for everything in
the 414,397.

`libhwui.so` on x86_64 is the same story at larger scale: 6.3 MB of code, 1,080 names.

### 1.3 — Reproduce the table yourself

```bash
# host -- the maintained version of that measurement
cd 59-radare2/scripts
./so-corpus-stats.sh ~/ch59-corpus
```

> **Measured** — this script was run against the corpus above and reproduced the table exactly.
> It prefers `rabin2` when radare2 is installed and **falls back to `llvm-readelf`** when it is not,
> which is how the chapter's numbers were produced on a machine with no radare2.

### Checkpoint 1

- Which column predicts how long full analysis will take: file size, `.text` size, or `.dynsym`
  count?
- `libhwui.so` is 6.6× larger than `libcrypto.so` (x86_64) but has *fewer* dynamic symbols. What does
  that tell you about how much of it you will have to name yourself?

<details>
<summary>Answers</summary>

- **`.text` size.** File size includes relocations, string tables, debug-ish sections and padding,
  none of which an analyser decodes. `libLLVM_android.so` is 21 MB but only 9.7 MB is code, and every
  timing tracks the 9.7.
- Almost all of it. 1,080 names for 6.3 MB of code is roughly one name per 5,900 bytes. Every
  function you care about in `libhwui.so` will arrive as `fcn.<address>`, and you will be working
  from strings and imports rather than names.

</details>

---

## Part 2 — The one measurement that anchors the cost model (20 minutes)

You cannot know what `aaa` costs until you measure it on your own machine. Do that now.

```bash
# host -- time a full analysis. -A runs aaa; -q -c q means "then quit".
time r2 -A -q -c q ~/ch59-corpus/libsqlite.so
time r2 -A -q -c q ~/ch59-corpus/libcrypto.so
```

Then measure the cheap path for comparison:

```bash
# host -- structural parsing only
time rabin2 -I ~/ch59-corpus/libsqlite.so
time rabin2 -qi ~/ch59-corpus/libsqlite.so
```

Record both numbers. The ratio is your cost model, and it is the number you should quote when someone
asks why you did not just analyse everything.

> **Measured (a floor, not `aaa`)** — this chapter could not time `aaa`, because radare2 was not
> installed. It measured instead the one step any analyser must pay — decoding every instruction in
> `.text` exactly once — using `llvm-objdump -d`, which does a linear sweep and nothing else:
>
> | Library | Arch | Disassembly lines | Time | Lines/second |
> |---|---|---:|---:|---:|
> | `libc.so` | AArch64 | 134,892 | 641 ms | ~210,000 |
> | `libcrypto.so` | AArch64 | 216,033 | 864 ms | ~250,000 |
> | `libsqlite.so` | AArch64 | 415,971 | 1,513 ms | ~275,000 |
> | `libicui18n.so` | AArch64 | 420,696 | 1,583 ms | ~266,000 |
> | `libLLVM_android.so` | x86_64 | 2,551,900 | 9,089 ms | ~281,000 |
>
> **This is a floor, not an estimate of `aaa`.** `aaa` additionally discovers function boundaries,
> builds basic blocks, computes cross-references and propagates types — strictly more work per
> instruction. Expect a multiple. What the table legitimately establishes is the *shape*: linear in
> `.text` size, a few hundred thousand instructions per second, and essentially independent of file
> size.

**Your `time r2 -A` numbers are the real thing. Write them down and compare them to the floor.**

### Checkpoint 2

Fill this in from your own measurements:

| Operation | `libsqlite.so` | Ratio vs `rabin2 -I` |
|---|---|---|
| `rabin2 -I` | ______ | 1× |
| `rabin2 -qi` | ______ | ______ |
| `r2 -A -q -c q` | ______ | ______ |

---

## Part 3 — The decision tree, applied (25 minutes)

For each question below, decide **before running anything**: does it need analysis?

| # | Question | Needs analysis? |
|---|---|---|
| 1 | Does `libcrypto.so` import `ptrace`? | |
| 2 | Which functions in `libcrypto.so` call `malloc`? | |
| 3 | What libraries does `libmedia_jni.so` depend on? | |
| 4 | Does this library have a `.init_array`? | |
| 5 | How many functions does it contain? | |
| 6 | Does it contain the string `/system/bin/su`? | |
| 7 | What does the function at `0x4000` do? | |
| 8 | Which function references the string at `0x690`? | |

<details>
<summary>Answers, with the command for each</summary>

| # | Needs analysis? | Command |
|---|---|---|
| 1 | **No** — symbol table | `rabin2 -qi libcrypto.so \| grep ptrace` |
| 2 | **Yes** — cross-references | `aa` then `axt sym.imp.malloc` |
| 3 | **No** — `DT_NEEDED` | `rabin2 -l libmedia_jni.so` |
| 4 | **No** — section header | `rabin2 -S \| grep init_array` |
| 5 | **Yes** — that is what discovery means | `aa` then `afl~?` |
| 6 | **No** — string scan | `rabin2 -qz \| grep '/system/bin/su'` |
| 7 | **Partly** — only that function | `s 0x4000; af; pdf` — seconds, not minutes |
| 8 | **Yes** — cross-references | `aa` then `axt 0x690` |

Five of eight need no analysis at all. Question 7 is the important nuance: `af` analyses **one**
function and is essentially instant, so "I need to read a function" almost never justifies `aaa`.

</details>

---

## Part 4 — The measured finding: obfuscation the compiler deleted (35 minutes)

This is the part to take away from the lab.

### 4.1 — What the source intends

Open [`../examples/01-r2-target.c`](../examples/01-r2-target.c) and read `lt_probe_paths` and
`xor_decode`. The intent is unambiguous: the path `/system/xbin/su` is stored XOR-ed with `0xA7`, so
that `strings` on the shipped library will not reveal it. The key was even chosen so that no
ciphertext byte lands in printable ASCII.

This is a standard, widely-recommended technique. It appears in countless blog posts.

### 4.2 — Test whether it works

```bash
# host -- three builds, identical source for the first two
cd ~/ch59-build
strings -n 4 libr2target.so     | grep -i xbin      # -O2
strings -n 4 libr2target-O0.so  | grep -i xbin      # -O0, same source
strings -n 4 libr2hardened.so   | grep -i xbin      # -O2, volatile key
```

Or with radare2:

```
# Unverified
$ r2 -q -c 'iz~xbin' ~/ch59-build/libr2target.so
$ r2 -q -c 'iz~xbin' ~/ch59-build/libr2target-O0.so
```

> **Measured** — with `llvm-strings` from NDK 25.2.9519653:
>
> | Build | Source | `grep xbin` |
> |---|---|---|
> | `libr2target.so` (`-O2`) | `01-r2-target.c` | **`/system/xbin/su`** — LEAKED |
> | `libr2target-O0.so` (`-O0`) | **identical source** | *(nothing)* |
> | `libr2hardened.so` (`-O2`) | `02-r2-target-hardened.c` | *(nothing)* |
>
> `examples/build.sh` prints exactly this comparison in its build report, so you can confirm it on
> your own machine in one command.

**Stop and appreciate how backwards that is.** The `-O0` debug build hides the string. The `-O2`
release build — the one that ships — publishes it. A developer who tests the protection in a debug
build sees it working and ships the plaintext.

### 4.3 — Find out why

```
# Unverified
$ r2 ~/ch59-build/libr2target.so
[0x0]> s sym.lt_probe_paths
[0x0]> af
[0x0]> pdf
```

Count the instructions in `lt_probe_paths` and look for the XOR loop.

> **Measured** — from `llvm-objdump -d libr2target.so`. The entire function:
>
> ```
> 000000000000190c <lt_probe_paths>:
>     190c: ff 43 01 d1   sub   sp, sp, #80
>     1910: fd 7b 04 a9   stp   x29, x30, [sp, #64]
>     1914: fd 03 01 91   add   x29, sp, #64
>     1918: e8 ff ff f0   adrp  x8, 0x0
>     191c: e0 03 00 91   mov   x0, sp
>     1920: e1 03 1f 2a   mov   w1, wzr
>     1924: 00 a5 c1 3d   ldr   q0, [x8, #1680]      ; 1680 = 0x690 = .rodata
>     1928: e0 03 80 3d   str   q0, [sp]
>     192c: 8d 00 00 94   bl    0x1b60 <access@plt>
>     1930: fd 7b 44 a9   ldp   x29, x30, [sp, #64]
>     1934: 1f 00 00 71   cmp   w0, #0
>     1938: e0 17 9f 1a   cset  w0, eq
>     193c: ff 43 01 91   add   sp, sp, #80
>     1940: c0 03 5f d6   ret
> ```
>
> **There is no loop.** Fourteen instructions, no branch backwards, no `eor` anywhere. The fifteen
> XOR operations were performed *by the compiler*, and `ldr q0, [x8, #1680]` is a single 16-byte NEON
> load of the finished plaintext straight out of `.rodata`.

The mechanism: both the ciphertext (`static const`) and the key (a `#define`) are compile-time
constants, so the whole decode is a constant expression. Constant folding is not a bug — it is the
optimiser doing exactly its job. It just happens to delete a security control.

### 4.4 — Confirm the fix

```
# Unverified
$ r2 ~/ch59-build/libr2hardened.so
[0x0]> s sym.lt_probe_paths_hardened
[0x0]> af
[0x0]> pdf
```

Look for `eor` instructions. Read
[`../examples/02-r2-target-hardened.c`](../examples/02-r2-target-hardened.c) — the only meaningful
change is one word:

```c
static volatile unsigned char g_xor_key = 0xA7;
```

> **Measured** — in the hardened `-O2` build the loop survives, vectorised but real:
>
> ```
>     ldrb  w8, [x8, #...]        ; load the volatile key
>     dup   v0.8b, w8
>     eor   v0.8b, v0.8b, v1.8b   ; the XOR happens at RUN time
> ```
>
> and the ciphertext stays ciphertext in `.rodata`.

`volatile` forbids the compiler from assuming a load returns the value last stored, which is
precisely the assumption constant folding needs. Removing it breaks the fold chain.

> **What this does NOT buy**
> The string is now absent from the *file*. It is present in *memory* whenever the function runs.
> Anyone with Frida, r2frida or a core dump reads it trivially. This raises the cost of a `strings`
> sweep from zero to "attach a debugger" — a rate limiter, not a boundary. Do not ship a secret to a
> device and call it protected.

### Checkpoint 4

- Why did `-O0` hide the string when `-O2` did not?
- A developer says "we tested it, `strings` finds nothing." What do you ask?
- Is this a reportable finding? On what basis?

<details>
<summary>Answers</summary>

- At `-O0` the compiler performs essentially no optimisation, so the loop is emitted literally and
  operates on ciphertext at run time. Constant folding is an optimisation and `-O0` does not do it.
- **"Which build did you test?"** Then: "run it on the release artefact that ships." Nearly always
  they tested a debug build.
- Yes. It maps to **MASVS-RESILIENCE-3** (anti-static-analysis), it has a clean one-line
  remediation, and — most importantly — it has a *severity* argument: the developer believed the
  value was protected and made downstream decisions on that belief. Report the evidence (`strings`
  output on the release artefact plus the missing loop in the disassembly), not just the conclusion.

</details>

---

## Part 5 — The JNI surface (25 minutes)

### 5.1 — Statically registered methods

```
# Unverified
$ r2 ~/ch59-build/libr2target.so
[0x0]> iE~Java_
```

> **Measured** — `llvm-nm -D --defined-only` reports exactly one:
> `Java_com_pentest_ch59_Native_staticCheck` at `0x19cc`, which decodes to class
> `com.pentest.ch59.Native`, method `staticCheck`.

Now disassemble it:

```
# Unverified
[0x0]> s sym.Java_com_pentest_ch59_Native_staticCheck
[0x0]> af
[0x0]> pdf
```

> **Measured** — the entire function is **one instruction**:
>
> ```
> 00000000000019cc <Java_com_pentest_ch59_Native_staticCheck>:
>     19cc: 61 00 00 14   b   0x1b50 <lt_probe_paths@plt>
> ```
>
> A tail call. The exported JNI entry point contains no logic at all.

**Lesson:** if you disassemble an export and find a single `b`, you have not found the code. Follow
the branch. This is extremely common in optimised builds and it wastes a lot of people's time.

### 5.2 — Dynamically registered methods

The library also registers a method at run time, and no symbol names it.

```
# Unverified
[0x0]> iE                    # is JNI_OnLoad here but Java_* missing for some methods?
[0x0]> iz~^\(                # JNI signatures all start with "("
[0x0]> iz                    # read the neighbourhood
[0x0]> iS~data.rel.ro        # where the table usually lives
```

> **Measured** — the whole of `.rodata` is fifty bytes and contains, in order:
>
> ```
> /system/xbin/su
> com/pentest/ch59/Native
> (Ljava/lang/String;)I
> dynGate
> gate=%d\n
> ```
>
> The class name, the signature and the method name sit adjacent because the compiler emitted them
> in the order the code referenced them. `.data.rel.ro` is at `0x2ba0` size `0x20`, and `JNI_OnLoad`
> materialises `0x2ba8` with `adrp x2, 0x2000` + `add x2, x2, #2984` — that is the
> `JNINativeMethod` table.
>
> The C function that implements it is called `dyn_gate`. It is `static`, so it appears **nowhere**
> in `.dynsym`. In the stripped build nothing names it at all.

### 5.3 — Find the `RegisterNatives` call

```
# Unverified
[0x0]> aa
[0x0]> pdf @ sym.JNI_OnLoad
```

Look for indirect calls: `ldr` of a constant offset from a pointer, then `blr`.

> **Measured** — from `llvm-objdump -d`:
>
> ```
>     19dc: ldr   x8, [x0]
>     19f4: ldr   x8, [x8, #48]      ; JavaVM table +0x30 -> GetEnv
>     19fc: blr   x8
>     1a18: ldr   x8, [x0]
>     1a1c: ldr   x8, [x8, #48]      ; JNIEnv table  +0x30 -> FindClass
>     1a20: blr   x8
>     1a3c: ldr   x8, [x0]
>     1a40: ldr   x8, [x8, #1720]    ; JNIEnv table  +0x6b8 -> RegisterNatives
>     1a44: blr   x8
> ```
>
> `1720 = 0x6b8`. The JNI specification fixes the table order, so **the offset is the function
> name**. These offsets independently confirm the table in
> [57-Ghidra](../../57-Ghidra/README.md) §3.8.

**This is the most transferable skill in native Android RE and it needs no tool**: see a constant
offset dereferenced from a pointer derived from parameter one, and look it up in `jni.h`.

### 5.4 — Use the inventory script

```bash
# host
cd 59-radare2/scripts
python3 -B r2-jni-inventory.py ~/ch59-build/libr2target.so
python3 -B r2-jni-inventory.py ~/ch59-build/libr2target.so --analyse
```

It reports both mechanisms and — deliberately — what it could not resolve. A static JNI scan whose
output is partly a list of gaps is an honest one.

### Checkpoint 5

- `axt` on `dyn_gate` finds nothing. Two reasons why. Which applies here?
- What is at JNIEnv offset `0x30`, and how do you know without running anything?

<details>
<summary>Answers</summary>

- The two reasons are (a) analysis has not run, and (b) the reference is an indirect call with no
  static target. **Here it is (b)** — and additionally there is no symbol named `dyn_gate` to `axt`
  in the first place. The function pointer is stored in a data table and loaded at run time; the
  `blr x8` carries no target information at all.
- `FindClass`. The `JNINativeInterface` struct in `libnativehelper/include_jni/jni.h` has a fixed,
  specification-mandated order; four reserved slots come first, so index 6 × 8 bytes = `0x30`.

</details>

---

## Part 6 — Corpus scanning (20 minutes)

```bash
# host
cd 59-radare2/scripts
python3 -B r2-triage.py ~/ch59-corpus --out corpus.csv
python3 -B r2-triage.py ~/ch59-corpus --strings --dedup --out corpus.csv
```

Then read the CSV. Sort by the `imp_*` columns.

The script runs **no code analysis** — that is the entire design point, and Part 1's measurements are
the justification. Its per-file cost is bounded by symbol-table size, so it scales to hundreds of
libraries.

### Exercise 6.1 — break it on purpose

Run it against a directory containing a text file and a truncated `.so`. Confirm that:

- Non-ELF files are skipped rather than producing a bogus row.
- A file that fails to parse produces a row with a populated `error` column, not a silent omission.

That behaviour matters more than it looks. A scanner that quietly drops files it could not read
produces a false negative that looks exactly like a clean result.

---

## Success criteria

- [ ] You measured `r2 -A` against `rabin2 -I` on the same library and can state the ratio.
- [ ] You can say which column predicts analysis cost, and why file size does not.
- [ ] You reproduced the `-O2` versus `-O0` string difference on your own machine.
- [ ] You can explain the mechanism in one sentence, using the word "constant".
- [ ] You found the JNI tail call and understood why the export contained no logic.
- [ ] You located the `RegisterNatives` call by its offset, without a symbol.
- [ ] You produced a corpus CSV and identified which libraries deserve a human.

---

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `adb pull /system/lib64/arm64/...` fails | The device has no NDK translation libs | Use `/system/lib64/`, and note the arch in your results |
| `r2 -A` seems to hang | It is analysing; large `.text` takes minutes | Let it finish once, then `Ps` to save a project |
| `iz~^\(` finds nothing | The library uses only static registration, or strings are encrypted | Check `iE~Java_`; if that is populated, registration is static |
| The corpus script prints an empty table | Tools missing | It exits non-zero with an explanation — read stderr |
| `strings` finds the path in the hardened build too | You rebuilt with different flags | Rebuild with `build.sh`; confirm `-O2` and the `volatile` key |
| Your addresses differ from this document | Different compiler version or edited source | Expected. Use `build-report.txt` from *your* build |

---

## What you learned

- Structural parsing and code analysis are different costs, differing by orders of magnitude, and
  most triage questions live in the cheap one.
- `.text` size predicts analysis cost; file size does not.
- Ten of eleven real Android libraries measured here were stripped — `libc.so` was the exception and
  kept 2,667 symbols, which is worth checking for on every platform library.
- A compile-time-constant obfuscation is not obfuscation. The optimiser is entitled to evaluate it,
  and at `-O2` it did.
- An exported JNI function can be a single branch.
- A constant offset dereferenced from `JNIEnv` is a function name.

---

## Next

[Lab 03 — Patching, and the function that did not matter](lab-03-patching-and-the-wrong-function.md)
takes the target you now understand, patches it, and shows you — by measurement on a real device —
why the obvious patch changes nothing.
