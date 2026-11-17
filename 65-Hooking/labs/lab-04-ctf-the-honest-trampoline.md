# Lab 04 — CTF: The Honest Trampoline

> **Objective.** Open a vault that defends itself three ways: its PIN is not in the binary, its check
> function has been inlined out of existence, and it checksums its own prologue on every call. Two of
> the four hook types you know will fail. One walks straight past all three defences — and it does
> not modify a single instruction.

**Difficulty:** CTF — the chapter's capstone
**Time:** 2–4 hours
**Prerequisites:** Labs [01](lab-01-the-five-hook-types.md), [02](lab-02-write-an-inline-hook-by-hand.md)
and [03](lab-03-where-hooks-fail.md)
**Device used to verify this challenge:** `i9000S`, Android 13 / API 33, **unrooted, no
frida-server**. The challenge is solvable end to end as the unprivileged `shell` user. It was solved
that way while writing this lab, and the measured output is in §8.

---

## 1. The challenge

```bash
# host
cd 65-Hooking/labs
export ANDROID_NDK=$HOME/Android/Sdk/ndk/25.2.9519653
./build-ctf.sh --run
```

Measured baseline:

```
=== the pin is not in the file (this SHOULD find nothing useful) ===
  (nothing)

=== baseline: a wrong pin ===
vault_open @ 0x769ab73768
vault_open("0000") = -1  (wrong pin)
```

You are given:

| File | What it is |
|---|---|
| `libvault.so` | The target. Exports `vault_open` and `vault_pin_ok` |
| `vault-runner` | A harness that calls `vault_open(pin, out, sizeof out)` and prints the result. No hooks, no hints |

Your job: make `vault_open` return **0** and print the flag, which has the form `CH65{...}`.

### 1.1 The return codes — you will meet all of them

| Code | Meaning |
|---|---|
| `0` | Success, and `out` holds the flag |
| `-1` | Wrong PIN |
| `-2` | **TAMPERED.** `vault_open` noticed that its own first eight instruction words no longer sum to what they summed to at load time |
| `-3` | Output buffer too small (the runner sizes it correctly; you will not see this) |

### 1.2 Rules

- **No brute force.** The PIN space is far too large and guessing is not the exercise.
- **No patching the binary on disk.** Everything happens at runtime, in a process you write.
- **No root, no `frida-server`, no Frida.** The whole challenge is solvable as `shell`. If you have a
  rooted device, solving it with Frida is a legitimate second lap — but do it after, not instead.
- **Only this library.** Do not point your solver at anything else on the phone.

---

## 2. Reconnaissance — do this before writing any code

### 2.1 Is the PIN in the file?

```bash
# host
strings $OUT/libvault.so | grep -Ei 'pin|flag|CH65|[0-9]{4}'
```

Measured: nothing useful. Only symbol names (`vault_pin_ok`, `g_pin_key`, `FLAG_ENC`). The strings
are stored encoded and decoded at runtime.

> **Under the Hood.** The first version of this challenge stored the key as `#define PIN_KEY 0x5A`
> and was trivially broken: clang at `-O2` saw a constant array XORed with a constant key, folded the
> whole loop at compile time, and emitted `"1379-alp"` and `"CH65{got_slot_beats_text_checksu"`
> directly into `.rodata`. **The optimiser deobfuscated it.** The shipped version stores the keys as
> `volatile`, which forbids the fold. This is why so much real string obfuscation is worthless: if
> the key is a compile-time constant, your toolchain is a deobfuscator.

### 2.2 What is the hook surface?

```bash
# host
cd ../scripts
./hook-surface.sh $OUT/libvault.so
```

Read the output as a menu of options, not as a list of facts. Pay attention to:

- which symbols are **exported** (inline-hookable);
- which symbols are **imported** with a `JUMP_SLOT` relocation (PLT-hookable);
- the RELRO line, which tells you whether a GOT write needs an `mprotect` first.

### 2.3 What does the prologue look like?

```bash
# host
$NDK/llvm-objdump -d $OUT/libvault.so | sed -n '/<vault_open>:/,/^$/p'
```

Two questions to answer from that listing before you continue:

1. Does `vault_open` contain a `bl` to `vault_pin_ok`?
2. What does `vault_open` do **before** it does anything with the PIN?

### 2.4 The analyser's verdict

```bash
# host
python3 -B hookability.py $OUT/libvault.so --symbol vault_pin_ok
python3 -B hookability.py $OUT/libvault.so --symbol vault_open
```

The `callers in file` line for `vault_pin_ok` is worth more than everything else on the screen.

---

## 3. Hints, in escalating order

Stop reading as soon as you have enough. Each is behind a fold.

<details>
<summary>Hint 1 — where to start</summary>

Do not start by trying to make `vault_open` return 0. Start by finding out what the PIN is. You have
a whole chapter of techniques for observing a running program, and the PIN must exist in cleartext
*somewhere*, at *some* instant, or the comparison could not happen.

Where is it, and what is looking at it when it is there?

</details>

<details>
<summary>Hint 2 — the first thing you will try, and why it fails</summary>

You will hook `vault_pin_ok` to return 1. It will work — call it directly and it returns 1 — and
`vault_open` will still return `-1`.

Run the Lab 03 diagnostic:

```bash
$NDK/llvm-objdump -d $OUT/libvault.so | grep "bl.*<vault_pin_ok>"
```

Nothing. The body was inlined into `vault_open`. You hooked a function nobody calls.

</details>

<details>
<summary>Hint 3 — the second thing you will try, and why it fails</summary>

So you hook `vault_open` itself, inline, the way Lab 02 taught you. Now it returns `-2`.

Look again at what `vault_open` does *first*. It hashes its own first eight instruction words and
compares the result to a value captured at load time by a constructor. Your 16-byte patch changed
four of those eight words.

Measured, patching a single word at `+12` with a `nop`:

```
before patch:            vault_open("0000") = -1
after 1-word nop at +12: vault_open("0000") = -2   (-2 == TAMPERED)
restored:                vault_open("0000") = -1
```

One word is enough to trip it. Your hook does not need to be clumsy to be caught; it only needs to be
*in the wrong place*.

</details>

<details>
<summary>Hint 4 — the shape of the answer</summary>

Two facts you have already established:

1. The check is inlined **into** `vault_open`, so hooking the standalone copy is useless.
2. `vault_open` verifies its own **code**.

Now ask: the inlined copy of the check still has to compare two strings. How does it do that? Look at
the `bl` instructions inside `vault_open`.

A checksum over instructions cannot see a change that is not in the instructions.

</details>

<details>
<summary>Hint 5 — near-complete</summary>

`strcmp` is an **import**. The inlined comparison reaches it through this library's PLT, which loads
a pointer out of the GOT — a **data** table.

Swap that pointer for one of your own and:

- no instruction changes anywhere, so the prologue checksum is identical and defence 3 never fires;
- the inlining does not matter, because you are not hooking the check, you are hooking what the check
  calls;
- and your replacement receives **both arguments**, the second of which is the decoded PIN.

`../examples/plt-got-hook.c` already walks `DT_JMPREL` and swaps a `strcmp` slot. It is 90% of your
solver.

</details>

---

## 4. Grading rubric

Getting the flag is the entry ticket, not the score. Grade yourself on what your solution *proved*.

| Tier | What you did |
|---|---|
| **Bronze** | Got the flag by any means, including patching `g_baseline` in memory so the checksum passes |
| **Silver** | Got the flag with a PLT/GOT hook, and can explain why the checksum did not fire |
| **Gold** | Silver, plus you **read the PIN out of the hook**, removed the hook entirely, and opened the vault with the correct PIN and no instrumentation at all |
| **Platinum** | Gold, plus you can state precisely what change to `libvault.c` would defeat your solution, and what would defeat *that* |

The Gold tier is the point of the whole chapter. A hook that bypasses a check gives you one result.
A hook that **tells you what the check wanted** gives you the input, and an input is a finding you can
put in a report, hand to a developer, and reproduce without a tool.

> **Mental Model.** Hooking is an instrumentation technique. It proves behaviour; it is not itself
> a finding. "I bypassed the PIN check with a hook" is a statement about your toolkit. "The PIN is
> `1379-alpha`, hard-coded in the library, and here is the byte offset" is a statement about the
> product.

---

## 5. Platinum questions

Answer these in writing before you look at §7.

1. `vault_open` checksums eight words of its own code. **Where does the baseline live**, and what
   does that imply about the checksum's value as a control?
2. Name a change to `libvault.c` that would defeat the intended PLT/GOT solution.
3. Name a hook that would defeat *that* change.
4. The challenge decodes the PIN onto the **stack** immediately before comparing. If you could not
   hook anything at all, but could read the process's memory, would that help? What would you have to
   get right?
5. Suppose the developer replaced `strcmp` with a hand-written comparison loop inside the same
   translation unit. Which of the five hook types survive?

---

## 6. Cleanup

```bash
# host
adb shell rm -f /data/local/tmp/libvault.so /data/local/tmp/vault-runner /data/local/tmp/solver
find 65-Hooking -name '*.so' -o -name '*.o' -o -name '__pycache__'
```

The `find` must print nothing.

---

## 7. Instructor notes and solution

> **Stop here if you have not solved it.**

<details>
<summary>Full solution and measured output</summary>

### 7.1 The three defences and their intended fates

| Defence | Intended attacker experience |
|---|---|
| PIN stored XOR-encoded, decoded on the stack | `strings` finds nothing; forces runtime observation |
| `vault_pin_ok` exported **and** inlined at `-O2` | The natural first hook installs perfectly and changes nothing |
| `vault_open` checksums its own first 8 words | The natural second hook (inline, on `vault_open`) is caught, returning `-2` |

### 7.2 The solution

Walk `libvault.so`'s `DT_JMPREL` relocations, find the `R_AARCH64_JUMP_SLOT` entry for `strcmp`,
`mprotect` its GOT page writable, and overwrite the slot with your own function. Your function
records `b` — the decoded PIN — and returns 0.

The three defences fall in order:

- The **inlining** does not matter: you are hooking what the inlined copy calls, not the copy.
- The **checksum** does not fire: you changed a pointer in `.got.plt`, not an instruction in `.text`.
- The **encoding** does not matter: you are reading the string after it was decoded, at the moment of
  comparison.

### 7.3 Measured output — solved on the `i9000S`, API 33, unrooted

```
=== decoy 1: hook vault_pin_ok (the inlined check) ===
  vault_pin_ok("0000") = 1   (hook works)
  vault_open("0000")   = -1   (unchanged - it was inlined)

=== intended: PLT/GOT hook on strcmp ===
  swapped strcmp slot at 0x73cd055c40
    [plt] strcmp("0000", "1379-alpha")  <-- second argument is the PIN
  vault_open("0000") = 0  -> CH65{got_slot_beats_text_checksum}
  captured pin = "1379-alpha"
```

And the Gold lap, with **no hook installed at all**:

```
vault_open @ 0x7002b6a780
vault_open("1379-alpha") = 0  FLAG: CH65{got_slot_beats_text_checksum}
```

The flag names the lesson: `got_slot_beats_text_checksum`.

### 7.4 Answers to the Platinum questions

**1. Where does the baseline live?**
In `g_baseline`, a writable global in the library's own `.data`, in the same address space as the
attacker. Anyone who can patch code can also patch the baseline — recompute the checksum after
hooking and store the new value, and the check passes forever.

This is the structural weakness of every in-process integrity check: **the checker and the checked
share a trust domain**. The control raises cost; it does not create a boundary. Real integrity
verification needs an attestation the device cannot forge — hardware-backed attestation,
[chapter 50](../../50-HardwareBackedSecurity/README.md). Bronze-tier solutions that patch
`g_baseline` are not cheating; they are
demonstrating exactly this.

**2. What would defeat the PLT/GOT solution?**
Extend the checksum to cover the GOT. Or resolve `strcmp` once with
`dlsym(RTLD_NEXT, "strcmp")`, cache the pointer, and validate it with `dladdr` — a pointer that does
not resolve into a mapped library is a loud signal. Simplest of all: do not call `strcmp`. A
hand-written comparison loop inside the same translation unit is a direct branch with no table entry
to swap.

**3. What would defeat that?**
An inline hook on `vault_open` at an address **past** the checksum — the check runs, passes, and only
then does control reach your patch. Or an inline hook on libc's exported `strcmp` itself, which
changes no byte of `libvault.so` and so is invisible to any checksum it computes over itself. Or,
against the `dladdr` validation, place your replacement *inside* a legitimately mapped module so the
pointer resolves plausibly.

Note the shape of this exchange: each round moves the hook to a layer the defender is not checking.
That is the entire subject of [67-BypassingProtections](../../67-BypassingProtections/README.md),
which owns the arms race; this chapter owns the mechanisms it is fought with.

**4. Could you just read memory?**
Yes, and it is harder than it sounds. The decoded PIN lives in a stack buffer inside `vault_pin_ok`'s
frame, which exists only between the decode loop and the `strcmp` call — a window of a few dozen
instructions. To read it you must either be executing at that instant (which is a hook by another
name) or scan the stack of a suspended thread and know what you are looking for. Reading memory
without a hook is the *harder* technique here, not the easier one. That inversion is worth
remembering.

**5. If `strcmp` became a hand-written loop, which hook types survive?**

| Hook type | Survives? |
|---|---|
| Managed (ART entry point) | Not applicable — no Java here |
| **Inline** | **Yes** — the only one that reaches an intra-module call, at a hook point past the checksum |
| PLT/GOT | No — an intra-module call is a direct branch with no slot |
| `LD_PRELOAD` interposition | No — nothing is imported to interpose on |
| `RegisterNatives` | Not applicable |

Which is precisely the argument for why inline hooking exists at all, and why this chapter spends a
whole lab teaching you to write one by hand.

### 7.5 Why this CTF is built the way it is

Every layer maps to a section of the chapter and to a real technique:

| Layer | Chapter reference | Real-world analogue |
|---|---|---|
| Encoded strings | §2.1, the constant-folding note | String obfuscation in commercial packers |
| Inlined check | [Lab 03 §2](lab-03-where-hooks-fail.md), [18-ARM §5.4](../../18-ARM/README.md) | Every `-O2` release build |
| Prologue checksum | [38-TamperDetection](../../38-TamperDetection/README.md) | RASP SDKs that hash their own `.text` |
| PLT/GOT escape | [Lab 01 §4](lab-01-the-five-hook-types.md) | How library-scoped interception is actually done |

And the flag is not a random string. `got_slot_beats_text_checksum` is the finding.

</details>

---

## 8. Where to go next

| If you want to | Go to |
|---|---|
| Understand detection and how it is defeated systematically | [67-BypassingProtections](../../67-BypassingProtections/README.md) |
| Do all of this with one line of JavaScript instead | [53-Frida](../../53-Frida/README.md) |
| Understand the managed layer this challenge deliberately avoided | [13-ART](../../13-ART/README.md) |
| See what an integrity check can and cannot buy | [38-TamperDetection](../../38-TamperDetection/README.md) |
