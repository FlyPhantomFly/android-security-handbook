# Lab 01 — Your first database

> **Objective.** Take a stripped Android native library you built yourself, work out what it does
> without looking at the answer key, and end with a set of named functions and one written paragraph
> saying what the library is for. Along the way, establish the habit that decides whether the rest of
> this chapter is useful: **triage before you open anything.**

| | |
|---|---|
| **Difficulty** | Beginner |
| **Time** | 90 minutes, honestly |
| **Needs an IDA licence?** | **No.** Every step has a free-tool route, and the ground truth checks both |
| **Needs a device?** | No |
| **You come out with** | A named function list, a written summary, and a number: what fraction of the library you could not resolve |

---

## 0. Before you start

Read [68-ReverseEngineering §3.1](../../68-ReverseEngineering/README.md) — *Stage 0, the question,
written down* — and then write your question at the top of a file. For this lab it is supplied:

> **Q1.** What is this library for, and which of its exported functions makes a security-relevant
> decision?

Keep that file open. Chapter 68 calls it the journal and its four fields are Hypothesis, Prediction,
Refutation, Verdict. You will use it three times in this lab, and the discipline is the point: a
hypothesis with no written refutation test is a wish.

> **Warning**
> Do not open [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md) until
> section 7 tells you to. It is the answer key, it is complete, and reading it first converts this lab
> from an exercise into a reading assignment. If you get stuck, the hints in section 6 are graduated
> for exactly that reason.

---

## 1. Setup

### 1.1 Build the target

```bash
# host
cd 58-IDA/examples
OUTDIR=/tmp/ch58 ./build.sh
```

You need an Android NDK and nothing else. The script finds it via `NDK_HOME`, `ANDROID_NDK_HOME`,
`ANDROID_NDK_ROOT`, or the newest under `$ANDROID_HOME/ndk`. It was verified with **NDK
25.2.9519653 (clang 14.0.7)** on a Windows host under Git Bash.

It builds **out of tree**. Nothing lands in the repository; `.so`, `.o` and `.a` are on the artefact
blocklist.

You should now have:

```text
/tmp/ch58/libcrcutil.a                 a static archive -- lab 03 uses this
/tmp/ch58/libsession-unstripped.so     the ANSWER KEY -- do not open it yet
/tmp/ch58/libsession.so                THE TARGET -- this is your lab
/tmp/ch58/ground-truth.txt             the answer key in text form -- also later
```

### 1.2 Put the answer key out of reach

Genuinely do this. It is the difference between a lab and a tutorial.

```bash
# host
mkdir -p /tmp/ch58-answers
mv /tmp/ch58/libsession-unstripped.so /tmp/ch58/ground-truth.txt /tmp/ch58-answers/
ls /tmp/ch58
```

You should be left with `libcrcutil.a` and `libsession.so`.

### 1.3 Point your tools at the toolchain

```bash
# host — adjust the host tag for your platform
export NDKBIN="$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
"$NDKBIN/llvm-readelf" --version | head -1
```

On Linux the host tag is `linux-x86_64`; on macOS, `darwin-x86_64`.

---

## 2. Stage 1 — prove you have the program

Chapter 68 §3.2 insists on this and it takes ten seconds. You are establishing that the file you are
about to spend ninety minutes on is the file you think it is.

```bash
# host
sha256sum /tmp/ch58/libsession.so
"$NDKBIN/llvm-readelf" -h /tmp/ch58/libsession.so | head -12
```

Write the hash in your journal. Record what `-h` tells you:

| Field | What to record | Why it matters |
|---|---|---|
| `Class` | `ELF64` | Decides which tools and which processor setting |
| `Data` | `2's complement, little endian` | Always little-endian on every Android ABI |
| `Type` | `DYN (Shared object file)` | Everything on Android is `ET_DYN` |
| `Machine` | `AArch64` | `e_machine` 183 / `0xB7` → `lib/arm64-v8a/`. Chapter 15 tabulates the rest |
| `Entry point address` | some value | Non-zero would suggest a PIE executable rather than a library |

> **Definition**
> **`ET_DYN`** is the ELF file type meaning "dynamically-relocatable object". Both shared libraries
> and position-independent executables use it, which is why the type alone does not tell you which
> you have. Android's linker has refused non-PIE executables since API 21.

**Journal entry 1.** Write down: the SHA-256, the architecture, and one sentence stating what you
therefore expect the file to be.

---

## 3. Stage 2 — triage, twenty minutes maximum

This is the section this whole chapter argues for. **You are deciding whether this file deserves an
interactive session, and what to look at first when it does.** It costs seconds and no licence.

### 3.1 Is it stripped?

```bash
# host
"$NDKBIN/llvm-readelf" -S /tmp/ch58/libsession.so | grep -E '\.symtab|\.dynsym'
"$NDKBIN/llvm-nm" /tmp/ch58/libsession.so 2>&1 | head -3
"$NDKBIN/llvm-nm" -D --defined-only /tmp/ch58/libsession.so | wc -l
```

Expect no `.symtab` section, an error or nothing from plain `nm`, and a small non-zero count from
`nm -D`.

> **Definition**
> **`.symtab`** is the full symbol table — every function and object with a name, including internal
> ones. **`.dynsym`** is the *dynamic* symbol table, holding only what the dynamic linker needs to
> resolve at load time. `--strip-all` removes `.symtab` and **cannot** remove `.dynsym`, which is why
> exported functions keep their names in a stripped library and internal ones do not. Chapter 15 owns
> this.

**Record the number.** It is the size of the list of things you get for free.

### 3.2 What does it export?

```bash
# host
"$NDKBIN/llvm-nm" -D --defined-only /tmp/ch58/libsession.so | sort -k3
```

Read the names. This is a small library so the names are informative; on a real target they would be
mangled C++ or absent entirely. Two questions to answer from this list alone:

- **Is there a `Java_*` symbol?** If yes, the library is bound to Java by static registration and the
  symbol names the class and method. If no, either binding is dynamic or the library is reached some
  other way.
- **Do any names look like they came from somewhere else?** A consistent prefix that differs from the
  rest is a strong hint of statically-linked third-party code. Lab 03 is about exactly that.

### 3.3 What does it ask the world for?

```bash
# host
"$NDKBIN/llvm-nm" -D -u /tmp/ch58/libsession.so
```

Undefined symbols are imports. Read them as a **reading order**, not a verdict:

| If you see | Look at |
|---|---|
| `memcpy`, `strlen`, `memset` | Where lengths come from. Chapter 70's territory |
| `abort`, `__stack_chk_fail` | Non-returning; §3.3 of the chapter explains why marking them matters |
| `dlopen`, `dlsym` | Something is loaded or resolved by name at run time |
| `ptrace` | Anti-debug, or a debugger. Chapter 38 measured only **1 of 18** real APKs importing it |
| `__system_property_get` | A property read. Not necessarily a root check — chapter 38 again |

> **Warning**
> An import is not a behaviour. Chapter 38's mapper first reported a self-signature check in **18 of
> 18** APKs and was lying, because `getPackageInfo` is how every SDK reads its own version string.
> Splitting patterns into strong and weak brought it to a defensible 13 of 18. **If a detector agrees
> with you about every sample, suspect the detector.**

### 3.4 What strings does it contain?

```bash
# host
"$NDKBIN/llvm-strings" -a -n 5 /tmp/ch58/libsession.so | sort -u
```

**Journal entry 2.** Before you look at the output, predict: how many human-meaningful strings do you
expect in a library with this many functions? Write the number down. Then count what you got.

The gap between those two numbers is a finding. A library with essentially no strings has encoded
them, and the absence is diagnostic. Note also which strings *are* present — a lookup table like
`0123456789abcdef` is not user-facing text, it is a hex encoder's digit table, and finding what
references it is the fastest route to that function.

### 3.5 Run the sweep instead, if you prefer

Everything above, on one line:

```bash
# host
cd 58-IDA
./scripts/03-ida-batch-triage.sh --backend llvm /tmp/ch58
```

Read the table. Then read the "READING THE TABLE" block underneath it, which is the part that turns
columns into an order of work.

**Stop and decide.** You now know: the architecture, whether it is stripped, what it exports, what it
imports, and roughly how much text it carries. Chapter 68 gives you twenty minutes for this and says
you must not open a method body inside them. Write one sentence: *is this file worth an hour, and if
so which function do you open first?*

---

## 4. Stage 3 — open it

### 4.1 If you have IDA

*File → Open*, select `libsession.so`. Check the import dialogue:

| Field | Expect |
|---|---|
| File type | `ELF64 for ARM64 (Shared object)` |
| Processor type | `ARM Little-endian [ARM]` |
| "Manual load" | leave **off** |

Let auto-analysis finish. Then, if you want the annotations done for you:

*File → Script file…* (`Alt+F7`) → [`scripts/02-ida-android-annotate.py`](../scripts/02-ida-android-annotate.py)

> **Warning**
> That script is **reviewed, not executed** — see its header, and the chapter's honesty callout. IDA
> is not installed on the machine where this chapter was written. If it fails, read the traceback,
> fix it, and consider writing down what was wrong: an untested script that a reader repairs is worth
> more than a fabricated transcript, and the repair is a contribution.

### 4.2 If you have Ghidra

*File → Import File*, confirm `AARCH64:LE:64:v8A`, run auto-analysis with **Decompiler Parameter ID**
enabled. Chapter 57 §3.5 and §3.6 cover the options that matter.

### 4.3 If you have neither

You are not blocked, and this is worth doing even if you do have a licence, because it shows you what
the GUI is doing for you.

```bash
# host — the whole library, in address order
"$NDKBIN/llvm-objdump" -d --demangle /tmp/ch58/libsession.so | less

# host — one function at a time, once you know a name from .dynsym
"$NDKBIN/llvm-objdump" -d --disassemble-symbols=session_seal /tmp/ch58/libsession.so
```

`llvm-objdump` gives you Tier 4 evidence directly — the bytes and their decoding — with no
reconstruction layer. What it does not give you is cross-references, and that is the single biggest
thing you will miss.

---

## 5. The work

Six tasks. Do them in order; each depends on the last. Write the answer to each in your journal
**before** checking it.

### Task 1 — Find the Java entry point and name the class

From `.dynsym` you have a `Java_*` symbol. Decode it by hand:

| Rule | Encoding |
|---|---|
| Package separator `.` | `_` |
| Literal `_` in a name | `_1` |
| `;` | `_2` |
| `[` | `_3` |
| Overload separator | `__` followed by the encoded argument signature |

**Deliverable.** The fully qualified Java class and method name.

### Task 2 — Follow it, and list the library's real API

The JNI entry point is a wrapper. What does it call? In IDA, the *Function calls* view; in Ghidra,
*Function Call Trees*; with `objdump`, grep for `bl` inside its body:

```bash
# host
"$NDKBIN/llvm-objdump" -d --disassemble-symbols=Java_com_pentest_ch58_Session_nativeSelfTest \
    /tmp/ch58/libsession.so | grep -E '\bbl\b'
```

**Deliverable.** The list of functions the entry point calls, in call order.

> **Pentester's Note**
> Note whether the calls go through the PLT (`@plt` in the disassembly, or a jump into a small stub).
> Chapter 68 §8.3 measured that a call-site grep for `bl.*<name>` produces a **false negative** on
> PLT-routed calls, and must be written `bl.*<name(@plt)?>`. This library reproduces that exactly,
> because default visibility makes its own exports interposable.

### Task 3 — Find the magic value

One function compares a loaded 32-bit word against a constant. Find it.

**The trap:** the constant is not in the file. It arrives in two instructions.

```bash
# host — search for the four bytes of a plausible ASCII magic. Expect nothing.
"$NDKBIN/llvm-objdump" -s -j .rodata /tmp/ch58/libsession.so | grep -i '4e53 4553'
```

Then look at how the comparison is actually built. You want a `mov` and a `movk` writing the two
halves of a 32-bit value into one register.

**Deliverable.** The 32-bit constant, and one sentence saying why a byte search for it fails.

> **Definition**
> **`movk`** — *move wide with keep* — writes a 16-bit immediate into a chosen 16-bit field of a
> register and leaves the other bits alone. AArch64 cannot encode an arbitrary 32-bit immediate in one
> instruction, so a constant like `0x5345534E` becomes `mov w9, #0x534E` followed by
> `movk w9, #0x5345, lsl #16`. Chapter 18 §3.3 covers the encoding, verified against the assembler.

### Task 4 — Find the twelve-case switch

One function has an obvious dispatch structure. Find the indirect branch and the table it reads.

**Questions to answer:**

1. What instruction ends the dispatch sequence?
2. Where is the table, and how large is each entry?
3. What bounds the index, and what happens when it is out of range?
4. Did your tool recover the twelve case bodies, or did it give you one branch and a set of orphaned
   blocks?

Question 4 is the interesting one, and it is the first place in this lab where tools genuinely differ.
Record what yours did.

> **Warning**
> If you are tempted to patch the bound check because it looks like a gate: do not, and understand
> why. Removing the bound on an indexed indirect branch converts a safe dispatch into an
> out-of-bounds branch, which is a control-flow hijack primitive. You would be introducing a
> vulnerability into a binary you are assessing.

### Task 5 — Count the places static analysis stops

```bash
# host
"$NDKBIN/llvm-objdump" -d /tmp/ch58/libsession.so | grep -cE '[[:space:]]blr[[:space:]]'
"$NDKBIN/llvm-objdump" -d /tmp/ch58/libsession.so | grep -cE '[[:space:]]br[[:space:]]+x'
```

`blr <reg>` is a call through a pointer. `br <reg>` is a computed branch — a switch, or worse.

**Deliverable.** Both counts, and for the `blr`, where the pointer came from. It is loaded from a
table; find the table and find out what is in it. (Hint: the bytes in the file are zero. That is not
the same as the table being empty. §3.5 of the chapter, and Task 6.)

### Task 6 — The table that reads as zeroes

```bash
# host
"$NDKBIN/llvm-readelf" -x .data /tmp/ch58/libsession.so
"$NDKBIN/llvm-readelf" -r /tmp/ch58/libsession.so | grep -i relativ
```

**Deliverable.** Explain, in one sentence, why the hex dump shows zeroes and the relocation table
shows addresses, and say which of the two your disassembler was showing you.

> **Definition**
> **`R_AARCH64_RELATIVE`** is a relocation meaning "at this offset, store `load_bias + addend`". The
> addend is in the relocation entry, not in the file's bytes, so the location reads as zero until the
> linker processes it at load time. Chapter 15 §3.7 owns relocations, and measured the same behaviour
> on `.init_array`, where the constructor's address lives in the addend and the slot on disk is eight
> zero bytes.

---

## 6. Hints

Graduated. Read only as far as you need.

<details>
<summary><b>Hint 1 — I cannot find where to start</b></summary>

Start from `.dynsym`. `llvm-nm -D --defined-only` gives you eleven names in a library with no other
names at all. One of them begins `Java_`. That is the door.

</details>

<details>
<summary><b>Hint 2 — the magic constant search finds nothing</b></summary>

That is the correct result and it is Task 3's whole point. Stop searching for the value and search
for the *shape*: a `mov` of a 16-bit immediate followed immediately by a `movk` with `lsl #16`
targeting the same register. Then reassemble the two halves yourself: the `movk` value is the high
16 bits.

</details>

<details>
<summary><b>Hint 3 — my tool shows a `br` and then a lot of code belonging to nothing</b></summary>

That is an unrecovered switch, and it is a legitimate outcome worth recording. Recover it by hand:
find the `adr` instruction just before the `ldrb`. That is the anchor. Each table byte, multiplied by
4 and added to the anchor's address, is one case body.

The table is in `.rodata` at the address the `adrp`/`add` pair computes. `llvm-readelf -x .rodata`
will show it to you. It is twelve bytes long. Count the distinct values: repeated values mean two
opcodes share a case body.

</details>

<details>
<summary><b>Hint 4 — how do I find the function-pointer table's contents</b></summary>

`llvm-readelf -r` lists the relocations. Look for `R_AARCH64_RELATIVE` entries whose *offset* falls
inside `.data` and whose *addend* is a code address. The addends are your three function pointers.
Then `llvm-objdump -d` at each addend to see what they are.

</details>

<details>
<summary><b>Hint 5 — I want to know what the strings say</b></summary>

There is a `.rodata` array of bytes that is not ASCII and not visibly a table. Look at what reads
it: a loop that XORs a constant into each byte and writes to the stack. Find the constant. Then decode
the array yourself:

```bash
# host — replace the bytes and the key with what you found
python3 -B -c "
b=[0x75,0x29,0x23]      # ... the array you found
print(''.join(chr(x^0x5A) for x in b))"
```

If you cannot find the loop, find the *callers* of the function containing the `.rodata` array's
cross-reference; the decoder is called from exactly one place.

</details>

---

## 7. Check your work

Now open the answer key:

```bash
# host
less /tmp/ch58-answers/ground-truth.txt
```

and read [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md), which
explains every number in it.

Score yourself honestly against this table.

| # | Success criterion | Where the answer is |
|---|---|---|
| 1 | You recorded the SHA-256 and the architecture before doing anything else | Your journal |
| 2 | You stated whether the file was stripped, with the symbol counts | Ground truth §1 |
| 3 | You demangled the JNI symbol to a fully qualified Java name | Chapter §3.10 |
| 4 | You listed the functions the entry point calls, and noticed the PLT routing | Ground truth §7 |
| 5 | You found the magic constant and can explain why a byte search fails | Ground truth §6 |
| 6 | You located the jump table and know its entry size | Ground truth §2 |
| 7 | You noticed the entries are **bytes**, not words | Ground truth §2 |
| 8 | You counted the `blr` and `br` instructions | Ground truth §3 |
| 9 | You explained the zeroed pointer table | Ground truth §3 |
| 10 | You noticed at least one exported function that nothing calls | Ground truth §5 |
| 11 | You wrote one paragraph saying what the library is for | Compare with [`../examples/01-session-target.c`](../examples/01-session-target.c)'s header |
| 12 | You wrote down what you did **not** resolve | Chapter 68 §3.17 calls this the residue |

**Criterion 10 is the one most people miss**, and it is the most valuable. There is an exported
function that is correct, well-formed, and called by nothing, because the compiler inlined its body
into every caller. **Measured: zero call sites.** If you had decided it was the security-relevant
function and spent an hour patching it, you would have produced a patch that provably works and
changes nothing — exactly what chapter 18 §5.4 measured on a different fixture.

**Criterion 12 is the one that separates a report from a summary.** Your `blr` count from Task 5 is a
coverage statement: that is one place where a purely static reading of this library stops. Say so.

---

## 8. Going further

| Variation | What it teaches |
|---|---|
| `ABI=armeabi-v7a ./build.sh` and repeat | 32-bit ARM has a different calling convention, different constant materialisation, and Thumb interworking. Chapter 18 §3.13 |
| `BOTH_OPT=1 ./build.sh` and diff the `-O0` build | Every construct in this lab exists because of `-O2`. At `-O0` nothing is inlined, nothing is specialised, and the fixture is boring — which is the lesson |
| Point the triage sweep at a real app you own | See how much of section 3 still works when the export list is 4,000 mangled C++ names |
| Pull a system library from a device and triage it | The chapter's §8.1 did this and found a library using **neither** documented JNI binding mechanism |

---

## 9. What to carry forward

- **Triage first.** Everything in section 3 cost seconds, needed no licence, and decided everything
  that came after.
- **A byte search for a constant can fail on ordinary optimised code**, with no obfuscation involved.
- **A hex dump of a pointer table can show zeroes.** Check whether your tool applies relocations.
- **An exported, correct function may be called by nothing.** Check cross-references before you spend
  an hour on it.
- **Where control flow leaves, your analysis stops.** Count those places and put the number in the
  report.

---

| Next | |
|---|---|
| [Lab 02 — Structure recovery](lab-02-struct-recovery.md) | Turn `[x0, #68]` into `s->state` |
| [Chapter README](../README.md) | §3.1–§3.5 are the sections this lab exercises |
| [`../examples/03-ground-truth-aarch64.md`](../examples/03-ground-truth-aarch64.md) | The answer key |
