# Lab 02 — The patch that changed nothing

> **Level:** Intermediate · **Time:** 2–3 hours · **Needs:** the NDK on your host. A device is
> optional for Parts 1–3 and required for Part 4.

---

## What this lab is

Everything you measure in this lab will be **true**, and you will still reach a wrong conclusion —
twice. That is the design.

Lab 01 was about a lying source. This one is about honest sources answering a question adjacent to
the one you meant. It is the harder failure, because there is nothing to catch: no contradiction
surfaces, no second source disagrees, and the wrong conclusion is fully supported by correct
evidence.

**Objective.** By the end you will be able to distinguish two mechanisms that produce the identical
symptom "my correct patch did nothing", state what a verified patch actually proves, and explain why
`__attribute__((noinline))` does not do what most people think it does.

**Prerequisites.** [18-ARM](../../18-ARM/README.md) §5 for AArch64 basics; a passing familiarity with
`objdump`. You do not need to read [59-radare2](../../59-radare2/README.md) first, and if you have
not, so much the better — you will meet its finding cold.

---

## Part 0 — Toolchain

```bash
# host -- adjust the host tag: windows-x86_64, linux-x86_64 or darwin-x86_64
export NDK_BIN="$HOME/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/linux-x86_64/bin"
export OUT="$HOME/ch74-lab02" && mkdir -p "$OUT"

"$NDK_BIN/aarch64-linux-android21-clang" --version
"$NDK_BIN/llvm-objdump" --version
```

> **⚠️ Build outside the repository.** `.so`, `.o` and executables are on this repository's artefact
> blocklist. Everything below writes to `$OUT`. If you are on Git Bash under Windows, note that
> native tools cannot open an MSYS path — use `cygpath -w` if a tool reports "No such file" for a
> path that plainly exists.

---

## Part 1 — Build a target and find the check

Save this as `$OUT/gate.c`. It is deliberately close to what real licence gating looks like.

```c
/* $OUT/gate.c */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Returns 1 if the environment looks tampered with. */
__attribute__((noinline))
int probe_paths(void)
{
    static const char *paths[] = { "/system/xbin/su", "/system/bin/su", "/sbin/su" };
    for (unsigned i = 0; i < sizeof paths / sizeof paths[0]; i++) {
        if (access(paths[i], F_OK) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Returns 1 if the key is correct. */
__attribute__((noinline))
int verify_license(const char *key)
{
    return key && strcmp(key, "lab02-valid") == 0;
}

/* The decision. */
__attribute__((noinline))
int gate(const char *key)
{
    if (probe_paths()) {
        return 0;
    }
    return verify_license(key);
}

int main(int argc, char **argv)
{
    const char *key = (argc > 1) ? argv[1] : "";
    printf("gate=%d\n", gate(key));
    return 0;
}
```

```bash
# host
"$NDK_BIN/aarch64-linux-android21-clang" -Wall -Wextra -O2 -pie \
    -Wl,-z,max-page-size=16384 -o "$OUT/gate" "$OUT/gate.c"
```

> **⚠️ The `max-page-size` flag is not optional** if you intend to run this on a 16 KiB-page
> emulator. Without it a binary as trivial as `int main(void){return 42;}` exits **139** (SIGSEGV),
> and no error message anywhere mentions page size. This repository has reproduced that twice
> independently.

Now find the check:

```bash
# host
"$NDK_BIN/llvm-objdump" -d "$OUT/gate" | grep -A2 '<verify_license>:'
"$NDK_BIN/llvm-objdump" -d "$OUT/gate" | grep -A14 '<gate>:'
```

### ⏸ STOP 1

You want the program to accept a wrong key. You have found a function called `verify_license`.

1. Write down the patch you would apply, and to which function.
2. **Write down what you expect to observe if the patch works.** Be specific — an exact expected
   output.
3. Write down what you would observe if it did **not** work.

Question 3 is the one everybody skips, and it is the one that makes the rest of the lab legible.

---

## Part 2 — Apply the patch and verify it

On AArch64 the two instructions you need are:

| Instruction | Bytes (little-endian, file order) | Word |
|---|---|---|
| `mov w0, #1` | `20 00 80 52` | `0x52800020` |
| `mov w0, #0` | `00 00 80 52` | `0x52800000` |
| `ret` | `c0 03 5f d6` | `0xd65f03c0` |

Find the virtual address of `verify_license` and convert it to a file offset. For a PIE built this
way the `.text` delta is constant across the section — derive it, do not assume it:

```bash
# host -- get .text's vaddr and file offset, then subtract
"$NDK_BIN/llvm-readelf" -S "$OUT/gate" | grep -w '.text'
```

Patch with Python so the arithmetic is visible:

```python
#!/usr/bin/env python3
# $OUT/patch.py -- write "mov w0,#1; ret" at a file offset.
import sys

path, offset = sys.argv[1], int(sys.argv[2], 0)
patch = bytes([0x20, 0x00, 0x80, 0x52,      # mov w0, #1
               0xc0, 0x03, 0x5f, 0xd6])     # ret

with open(path, 'r+b') as fh:
    fh.seek(offset)
    before = fh.read(len(patch))
    fh.seek(offset)
    fh.write(patch)

print("offset  : 0x%x" % offset)
print("before  : %s" % before.hex(' '))
print("after   : %s" % patch.hex(' '))
```

```bash
# host
cp "$OUT/gate" "$OUT/gate-patched"
python3 -B "$OUT/patch.py" "$OUT/gate-patched" <your-offset>

# VERIFY the patch is present
"$NDK_BIN/llvm-objdump" -d "$OUT/gate-patched" | grep -A3 '<verify_license>:'
```

You should see exactly:

```
<verify_license>:
    ....: 20 00 80 52   mov   w0, #1
    ....: c0 03 5f d6   ret
```

### ⏸ STOP 2

The patch is present. The bytes are verified in the file. The disassembler agrees.

**Write down: what have you just proved?** One sentence. Be precise, and resist the obvious answer.

<details>
<summary><b>Answer — and it is the whole lab</b></summary>

You have proved **that the file changed**.

You have not proved anything about the program. Those are different propositions, and the
verification step everybody performs confirms the wrong one. `objdump` reads the file. Nobody cares
about the file.

The proposition you care about is *the program behaves differently*, and nothing you have done so far
speaks to it.

</details>

---

## Part 3 — Run it

If you have a device:

```bash
# host
adb push "$OUT/gate" "$OUT/gate-patched" /data/local/tmp/
adb shell "chmod +x /data/local/tmp/gate /data/local/tmp/gate-patched"

for b in gate gate-patched; do
  for k in wrongkey lab02-valid; do
    printf '%-14s %-12s -> ' "$b" "$k"
    adb shell "/data/local/tmp/$b $k"
  done
done
```

If your device blocks `execve` under `/data/local/tmp` — some vendor builds do — run through the
linker instead:

```bash
adb shell "/system/bin/linker64 /data/local/tmp/gate wrongkey"
```

No device? Reason it out from the disassembly of `gate` and check yourself against the table below.

### ⏸ STOP 3

Fill in the four cells, then explain **every** result.

| Binary | `key=wrongkey` | `key=lab02-valid` |
|---|---|---|
| `gate` (unpatched) | | |
| `gate-patched` | | |

<details>
<summary><b>What the reference measurement showed</b></summary>

On a device that ships `/system/xbin/su` — which every `userdebug` build does, and the stock Google
emulator image is one — the result is:

| Binary | `key=wrongkey` | `key=lab02-valid` |
|---|---|---|
| `gate` (unpatched) | `gate=0` | **`gate=0`** |
| `gate-patched` | `gate=0` | **`gate=0`** |

**Four zeroes.** Read the top-right cell first: **the correct key alone does not open the gate.**
The licence check was never what stood in the way. Then the bottom row: the function named for the
protection, patched to always succeed, verified present in the bytes, changed nothing at all.

If your device has no `su` at any of those three paths, you will instead see `gate=0 / gate=1` on the
top row and `gate=1 / gate=1` on the bottom — the patch works. **That is also a finding**, and it
tells you your device does not trip `probe_paths`. Record which you saw and why; the mechanism is the
same either way.

</details>

---

## Part 4 — Diagnose it

Do not guess. Read the caller.

```bash
# host
"$NDK_BIN/llvm-objdump" -d "$OUT/gate" | grep -A14 '<gate>:'
```

### ⏸ STOP 4

1. How many `bl` instructions are in `gate`, and what do they target?
2. Under what condition is `verify_license` reached?
3. Complete the truth table by patching the *other* function and re-running. What are the four
   patch-state combinations?

<details>
<summary><b>Answer</b></summary>

`gate` calls `probe_paths` **first** and branches on its result. On a non-zero result it returns 0
immediately, and `verify_license` is never reached. The shape looks like this:

```
<gate>:
    ....: bl    <probe_paths>
    ....: cbz   w0, <continue>       ; if probe == 0, carry on
    ....: mov   w0, wzr              ; else return 0 right now
    ....: b     <exit>
<continue>:
    ....: bl    <verify_license>
```

`probe_paths` finds `/system/xbin/su` and returns 1. The gate closes before your patch is reached.
Your patch is correct, applied, and **irrelevant**.

The full matrix, which is the artefact worth producing:

| Binary | `key=wrongkey` | `key=lab02-valid` |
|---|---|---|
| Unpatched | `gate=0` | `gate=0` |
| `verify_license` -> return 1 | `gate=0` | `gate=0` |
| `probe_paths` -> return 0 | `gate=0` | **`gate=1`** |
| Both patched | **`gate=1`** | `gate=1` |

Row 3 is the correct attack, and note that it needs **both** the right patch and the right key.
Real targets stack conditions like this routinely, and a bypass that fixes one of them looks exactly
like a bypass that does not work.

</details>

---

## Part 5 — The second mechanism, same symptom

A different investigation, on a **physical arm64 device (Android 13 / API 33)**, produced this:

```
# adb shell -- lc_verify_signature patched to return 1, WRONG token supplied
lc_verify_signature: 1              <-- the patch worked, observably
lc_decrypt_flag    : refused (-1)   <-- and the thing you wanted still refuses
```

Here the patched function is **observably returning 1** — the program prints it. And the dependent
operation still refuses. There is no upstream guard in this binary at all.

### ⏸ STOP 5

1. What is the mechanism? It is not short-circuiting.
2. What single command would distinguish this case from Part 4's?

<details>
<summary><b>Answer</b></summary>

**1.** At `-O2` clang **inlined** the body of `lc_verify_signature` into `lc_decrypt_flag`. The binary
now contains two copies of the logic, and the patch landed on the standalone copy — the one nothing
calls. There is no `bl lc_verify_signature` anywhere inside `lc_decrypt_flag`. **The check was
copied, not called.**

**2.** Count the call sites:

```bash
llvm-objdump -d "$OUT/gate" | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

| Mechanism | Tell |
|---|---|
| **Inlined** | The function has few or no callers, yet the logic clearly runs |
| **Short-circuited** | The caller exists; reading it shows an earlier call and a conditional branch |

> **A trap in that command, recorded because it cost a published conclusion.** A call routed through
> the Procedure Linkage Table renders as `bl 0x1ac0 <name@plt>`. A pattern anchored on `>` right
> after the name — `grep 'bl.*<name>'` — misses it, and it misses in the direction that *feels like a
> finding*: zero call sites looks like proof the function is dead. Use `bl.*<name(@plt)?>`, or the
> `uniq -c` form above, which does not depend on getting a regex right at all.

</details>

---

## Part 6 — The bonus refutation: `noinline` does not mean what you think

Every function in `gate.c` carries `__attribute__((noinline))`. That is why Part 4 worked at all —
without it, all three functions collapse into `main` and there is nothing to patch.

Now watch the attribute fail to do its job on a different transformation. Build the chapter's
fixture, which also carries `noinline`:

```bash
# host -- from the chapter's examples directory
"$NDK_BIN/aarch64-linux-android21-clang" -Wall -Wextra -O0 -fPIC -shared \
    -o "$OUT/fold-O0.so" ../examples/fold.c
"$NDK_BIN/aarch64-linux-android21-clang" -Wall -Wextra -O2 -fPIC -shared \
    -o "$OUT/fold-O2.so" ../examples/fold.c

"$NDK_BIN/llvm-strings" -n 4 "$OUT/fold-O0.so" | grep xbin
"$NDK_BIN/llvm-strings" -n 4 "$OUT/fold-O2.so" | grep xbin
```

The file XOR-encrypts `/system/xbin/su` at compile time and decodes it at runtime, in a decoder
explicitly marked `noinline`.

### ⏸ STOP 6

1. Which build leaks the plaintext?
2. `noinline` was requested. Was it honoured? How would you check?

<details>
<summary><b>Answer</b></summary>

**1.** The `-O2` build leaks it. The `-O0` build, from **identical source**, does not. Higher
optimisation made the secret more visible.

**2.** It was honoured — and it bought nothing. Check by looking at both the section and the symbol:

```bash
"$NDK_BIN/llvm-objdump" -s -j .rodata "$OUT/fold-O2.so"
# -> 2f737973 74656d2f 7862696e 2f737500   /system/xbin/su.
#    the PLAINTEXT, and the ciphertext array is GONE

"$NDK_BIN/llvm-objdump" -d --disassemble-symbols=decode "$OUT/fold-O2.so"
# -> four instructions: adrp / ldr q0 / str q0 / ret
```

`decode` still exists as a symbol and `main` still calls it — `noinline` was obeyed to the letter.
What clang did instead was **interprocedural constant propagation and function specialisation**:
every call site passes compile-time constants, so it rewrote the body against them. Thirty-one
instructions at `-O0` become four at `-O2`, and the fifteen-iteration XOR loop becomes a single
16-byte vector load of the finished plaintext.

**`noinline` constrains the inliner. None of those passes is the inliner.**

That refutes, as a *general* remedy, the fix that [58-IDA §11.4](../../58-IDA/README.md) records
applying to this problem. It worked on 58's fixture; it does not work here. The remedy that does work
is [59's](../../59-radare2/README.md): make the key `static volatile`, so the optimiser cannot prove
its value and the loop must survive.

</details>

---

## Part 7 — Write it up

Produce a short case study of your own session, in the notation used throughout this chapter:

```
Q   <the question>
H   <hypothesis>
P   <what you predict if it holds>
R   <what would refute it -- write this BEFORE you look>
E   <the exact command>
O   <the raw observation, not a conclusion>
V   <SUPPORTED / REFUTED / INCONCLUSIVE>
```

Then audit it:

```bash
# host
python3 -B ../scripts/claim-ledger.py --strict my-lab02-writeup.md
```

It will fail you for: zero refutations, no device named, no vantage stated, or a count without a
denominator. Fix them and re-run until it exits 0.

---

## Success criteria

- [ ] You produced the four-row truth table on your own build, and can explain **every** cell —
      including why the correct key alone is not enough.
- [ ] You can state what `objdump` verification of a patch proves, in one sentence, correctly.
- [ ] You can name both mechanisms for "correct patch, no effect" and give the command that
      separates them.
- [ ] You know why `grep 'bl.*<name>'` has a false-negative mode and what to write instead.
- [ ] You can explain what `noinline` constrains and, more importantly, what it does not.
- [ ] Your write-up passes `claim-ledger.py --strict`.

---

## What to carry into Lab 03

The technique here was **check the proposition you actually care about**. Everything you measured was
true; the wrong conclusion came from measuring a proposition adjacent to the one you meant.

Lab 03 changes technique again: **change who is asking.** Same command, three different uids, three
different answers — and one of them is the only one that matters.

---

## Related

| Chapter | Why |
|---|---|
| [59-radare2](../../59-radare2/README.md) | Owns the short-circuit case and its truth table; §5.4 |
| [18-ARM](../../18-ARM/README.md) | Owns the inlining case on physical hardware; §5.4, and the encodings |
| [58-IDA](../../58-IDA/README.md) | Owns "the check that passed for the wrong reason" |
| [65-Hooking](../../65-Hooking/README.md) | The runtime analogue: a perfectly installed hook that changes nothing |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | What to do once you know which decision to move |
