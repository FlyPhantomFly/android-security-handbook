# Lab 04 — CTF: The gate that was not there

**Difficulty:** CTF
**Time:** 4–6 hours
**Prerequisites:** [Lab 01](lab-01-the-command-language.md), [Lab 02](lab-02-triage-a-real-library.md),
[Lab 03](lab-03-patching-and-the-wrong-function.md), [18-ARM](../../18-ARM/README.md),
[34-Cryptography](../../34-Cryptography/README.md),
[68-ReverseEngineering](../../68-ReverseEngineering/README.md)

---

## The challenge

You are given a single AArch64 executable, `ctfvault`. Run it with a licence key and it says:

```
vault sealed
```

It says that for every key you try. It says it on a clean device and on a rooted one. There is no
error message, no log output, and no network traffic — the program never touches the network.

**Open the vault and recover the flag.**

The flag has the form `R2CTF{...}`.

---

## Rules

1. **Recovering the flag is the objective.** Making the program print "vault open" is not, on its
   own, a solve. Read that sentence twice; it is the whole challenge.
2. You may use radare2, rizin, Cutter, Ghidra, IDA, a debugger, Frida, or a pencil.
3. You may not read [`../examples/03-ctf-vault.c`](../examples/03-ctf-vault.c). It is the source of
   the binary you are attacking and it contains the answer.
4. Target only this binary, which you compiled yourself.

---

## Setup

```bash
# host -- builds out of tree; nothing is written into the repository
cd 59-radare2/examples
./build.sh
```

`ctfvault` appears in `$HOME/ch59-build`. Run it:

```bash
# host, or on a device
adb push ~/ch59-build/ctfvault /data/local/tmp/ch59_ctfvault
adb shell chmod 755 /data/local/tmp/ch59_ctfvault
adb shell /data/local/tmp/ch59_ctfvault
adb shell /data/local/tmp/ch59_ctfvault somekey
```

> **Measured** — built with `aarch64-linux-android21-clang` (NDK 25.2.9519653) at
> `-O2 -Wall -Wextra -pie -Wl,-z,max-page-size=16384`, zero warnings, and executed on the AVD
> `sdk_gphone16k_x86_64` (Android 15 / API 35, x86_64, 16 KiB pages) through
> `libndk_translation.so`. With no arguments it prints a usage line and a hint; with any argument
> tried so far it prints `vault sealed`.

> **On the state of this chapter**
> radare2 was **not installed** on the machine where this chapter was written, so every `r2` command
> below is **Unverified**. Every stated fact about the binary and its behaviour on a device is
> **Measured** and says so. If a command behaves differently, trust the tool.

---

## Objective

Recover the flag, and be able to explain:

- Why the program refuses every key, including the correct one.
- Why patching the function with the obvious name does not solve the challenge.
- Why a **complete** bypass still does not produce the flag.
- What the difference is between defeating a check and recovering a secret.

---

## Scoring

| Level | Achievement |
|---|---|
| **Bronze** | Make the program print `vault open` at all |
| **Silver** | Explain precisely why the correct key alone is rejected |
| **Gold** | Recover the real flag |
| **Platinum** | Recover it **without patching anything** — read the key out of the binary and supply it |
| **Diamond** | Write a script that recovers the flag from the binary alone, with no device |

Bronze is easy and is a trap. Read the rules again.

---

## Hints

Open these only when stuck. Each costs you nothing but the satisfaction.

<details>
<summary>Hint 1 — where to start</summary>

Start with no analysis at all. What does the binary tell you about itself for free?

```
# Unverified
rabin2 -I ~/ch59-build/ctfvault
rabin2 -qz ~/ch59-build/ctfvault      # strings
rabin2 -qi ~/ch59-build/ctfvault      # imports
```

The binary is **not stripped**, so the function names are a gift. There are four of them and they
are named honestly. One of them tells you the search space for the key.

Also: this program calls `access()`. What is it looking for, and why would that matter?

</details>

<details>
<summary>Hint 2 — why every key fails</summary>

You found four functions. One of them sounds like the security check. It is not the one that
decides.

Disassemble the function that *calls* the others and read the order of operations:

```
# Unverified
r2 ~/ch59-build/ctfvault
[0x0]> aa
[0x0]> pdf @ sym.vault_open
```

Look for a `bl` followed by a `cbz`. What runs first? What happens if it returns non-zero?

This is exactly the structure lab 03 measured. If you skipped lab 03, go back.

</details>

<details>
<summary>Hint 3 — the environment probe</summary>

The probe checks whether a file exists. The path is XOR-encrypted in the source — and at `-O2` the
compiler folded the decode away, so `strings` shows you the plaintext anyway. This is the measured
finding from [lab 02](lab-02-triage-a-real-library.md) Part 4, reused here deliberately.

```bash
# host
strings -n 4 ~/ch59-build/ctfvault | grep -i xbin
```

Now: does that file exist on your device?

> **Measured** — on the AVD `sdk_gphone16k_x86_64`, `/system/xbin/su` **exists**:
> `-rwsr-x--- 1 root shell 51224`. The stock Google emulator image ships it. So the probe fires,
> `vault_open` returns 0 at its first branch, and the licence check is never reached.

</details>

<details>
<summary>Hint 4 — Bronze, and why it is a trap</summary>

Patch the probe to return 0 and the gate opens for the correct key. Patch *both* the probe and the
verifier and it opens for **any** key.

Do the second one and look carefully at what it prints.

> **Measured** — with both `vault_probe_environment` and `vault_verify_token` patched to return
> constants, running with the key `wrongkey` prints `vault open:` followed by **42 bytes of
> unprintable binary noise** — high-byte and control characters, not text. It is not the flag and it
> is not close to the flag. (The literal bytes are deliberately not reproduced in this document;
> pasting raw control characters into a Markdown file corrupts it.)

Why would a full bypass produce garbage? What is the flag being decrypted *with*?

</details>

<details>
<summary>Hint 5 — the reveal function</summary>

```
# Unverified
[0x0]> pdf @ sym.vault_reveal
```

Read its arguments. It is handed the key you supplied — not a boolean, and not the verifier's
verdict. It derives a keystream from that key and XORs a blob of constant data with it.

**A patch changes what a function returns. It cannot change what the key actually is.** The verifier
and the decryptor consult the key independently, so lying to the verifier does not help the
decryptor.

You need the real key.

</details>

<details>
<summary>Hint 6 — identifying the algorithms</summary>

Two published algorithms are in this binary and both are identifiable by their constants alone.

In `vault_verify_token`, look for a `mov`/`movk` pair building each 32-bit constant:

- `0x811C9DC5` — a very well-known initial value
- `0x01000193` — its companion multiplier

In `vault_reveal`, look for three shift amounts applied in sequence to one register: **13, 17, 5**.

Search for these:

```
# Unverified -- endianness matters; /v4 handles it for you
[0x0]> /v4 0x01000193
[0x0]> /v4 0x811c9dc5
```

Name both algorithms before continuing.

</details>

<details>
<summary>Hint 7 — recovering the key</summary>

FNV-1a is a hash. It is not invertible. You cannot compute the key from the target value.

But you were told the search space. Look again at the string the program prints when run with no
arguments:

> **Measured** — `rabin2 -qz` / `strings` reports the string
> `licence keys are five lowercase letters`.

Five lowercase letters is 26<sup>5</sup> = **11,881,376** candidates. That is seconds in C and well
under a minute in Python.

Find the target value in the disassembly of `vault_verify_token` — it is the constant the hash is
compared against — and brute force it.

</details>

<details>
<summary>Hint 8 — the last step</summary>

You have the key. Do not patch anything.

Run the program with the correct key on a device where the probe does **not** fire — or patch only
the probe, which does not affect the decryption at all, since `vault_reveal` never consults it.

</details>

---

## Walkthrough

Do not read this until you have solved it or genuinely given up.

<details>
<summary>Full solution</summary>

### Step 1 — orientation, no analysis

```
# Unverified
$ rabin2 -I ~/ch59-build/ctfvault
$ rabin2 -qz ~/ch59-build/ctfvault
$ rabin2 -qi ~/ch59-build/ctfvault
```

> **Measured** — the binary is **not stripped**, and `llvm-nm` reports four `vault_` functions:
>
> ```
> 0000000000004914 T vault_open
> 0000000000004804 T vault_probe_environment
> 0000000000004888 T vault_reveal
> 000000000000483c T vault_verify_token
> ```
>
> (Addresses are from one build; read yours from `build-report.txt`.)
>
> Strings include `/system/xbin/su`, `licence keys are five lowercase letters`, `vault sealed`,
> `vault open: %s`, and a usage line. `access` is imported.

The names hand you the architecture: something probes the environment, something verifies a token,
something opens, something reveals. Note immediately that **`vault_reveal` is separate from
`vault_verify_token`** — that separation is the entire challenge.

### Step 2 — why every key fails

```
# Unverified
[0x0]> aa
[0x0]> pdf @ sym.vault_open
```

The structure is the same short-circuit measured in lab 03: `vault_open` calls
`vault_probe_environment` **first**, and returns 0 immediately if it returns non-zero. Only if the
probe is clean does it call `vault_verify_token`.

The probe checks `access("/system/xbin/su", F_OK)`.

> **Measured** — that file exists on the AVD used here (`-rwsr-x--- 1 root shell 51224`), so the
> probe returns 1 and the vault is sealed regardless of the key. The correct key alone is rejected.

That is **Silver**.

### Step 3 — Bronze, and the trap

Patch both functions to return constants. Using the encodings verified in
[chapter §3.12](../README.md#312-patching-with-r2--w) — `mov w0,#1` = `20 00 80 52`,
`mov w0,#0` = `00 00 80 52`, `ret` = `c0 03 5f d6`:

```
# Unverified
$ cp ~/ch59-build/ctfvault ~/ch59-build/cv.both
$ r2 -w ~/ch59-build/cv.both
[0x0]> e io.cache=1
[0x0]> aa
[0x0]> wa mov w0, 0; ret @ sym.vault_probe_environment
[0x0]> wa mov w0, 1; ret @ sym.vault_verify_token
[0x0]> wci
```

> **Measured** — the full truth table, all variants built from the shipped source and executed on
> the AVD:
>
> | Binary | `key=wrongkey` | `key=rizin` |
> |---|---|---|
> | Unpatched | `vault sealed` | **`vault sealed`** |
> | `vault_verify_token` -> 1 | `vault sealed` | **`vault sealed`** |
> | `vault_probe_environment` -> 0 | `vault sealed` | **`vault open:` + the correct flag** |
> | Both patched | **`vault open:` + 42 bytes of binary garbage** | `vault open:` + the correct flag |
>
> Row 2 is lab 03's lesson repeated: patching the security-sounding function changes nothing,
> because it is never reached. Row 4 is this lab's lesson: a *complete* bypass opens the vault and
> produces unprintable noise, because the flag is not gated on the verdict — it is derived from the
> key.

That is **Bronze**, and it is why Bronze is not a solve.

### Step 4 — read `vault_reveal`

```
# Unverified
[0x0]> pdf @ sym.vault_reveal
```

It takes the supplied key, hashes it, uses the hash as a PRNG seed, and XORs a 42-byte constant
array with the PRNG output. It never looks at `vault_verify_token`'s result.

**This is the structural point of the whole lab.** The verifier and the decryptor consult the key
*independently*. Defeating the verifier is defeating a check. The flag is a secret, and the only
material that produces it is the key itself. No patch can invent it.

### Step 5 — identify the algorithms

In `vault_verify_token`:

- `0x811C9DC5` and `0x01000193` are the **FNV-1a 32-bit** offset basis and prime.
- The comparison target is the constant built by a `mov`/`movk` pair just before the `cmp`/`cset`.

> **Measured** — the target constant in the shipped build is **`0x6DC666D5`**.

In `vault_reveal`, the shift sequence 13 / 17 / 5 on a single 32-bit register is **xorshift32**, in
its canonical form:

```c
x ^= x << 13;  x ^= x >> 17;  x ^= x << 5;
```

Recognising both from constants alone, without reading a line of logic, is the skill
[chapter §6.4](../README.md#64-patterns-you-learn-to-recognise-in-aarch64) is teaching.

### Step 6 — brute force the key

FNV-1a is not invertible, but the search space was handed to you: five lowercase letters,
26<sup>5</sup> = 11,881,376.

```python
#!/usr/bin/env python3
# host -- recover the licence key by exhaustive search over the stated space
import itertools, string

TARGET = 0x6DC666D5          # read this from YOUR binary's disassembly

def fnv1a(s):
    h = 0x811c9dc5
    for c in s.encode():
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h

for t in itertools.product(string.ascii_lowercase, repeat=5):
    cand = "".join(t)
    if fnv1a(cand) == TARGET:
        print("key =", cand)
        break
```

> **Measured** — this recovers the key **`rizin`**.

That is **Platinum** territory: you now have the key without having patched anything.

### Step 7 — get the flag

The probe still fires on a rooted device or an AVD with `su` present. Two honest routes:

**Route A — patch only the probe.** It does not touch the decryption path at all:

```
# Unverified
[0x0]> wa mov w0, 0; ret @ sym.vault_probe_environment
```

then run with the real key.

**Route B — run it where the probe does not fire**, i.e. a device with no `su` at
`/system/xbin/su`.

> **Measured** — with the probe patched and the key `rizin`, on the AVD:
>
> ```
> vault open: R2CTF{gr4mm4r_n0t_l1st_p4tch_th3_d3c1s10n}
> ```

That is **Gold**.

### Step 8 — Diamond: no device at all

Everything needed is in the file. Extract the ciphertext, re-implement both algorithms, and decrypt
offline:

```python
#!/usr/bin/env python3
# host -- recover the flag from the binary alone, no device, no execution
import itertools, string, sys

TARGET = 0x6DC666D5

def fnv1a(s):
    h = 0x811c9dc5
    for c in s.encode():
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h

def xorshift32(x):
    x ^= (x << 13) & 0xFFFFFFFF
    x ^= (x >> 17)
    x ^= (x << 5) & 0xFFFFFFFF
    return x & 0xFFFFFFFF

# 1. recover the key
key = None
for t in itertools.product(string.ascii_lowercase, repeat=5):
    c = "".join(t)
    if fnv1a(c) == TARGET:
        key = c
        break
if key is None:
    sys.exit("key not found -- check TARGET against your binary")
print("key  =", key)

# 2. pull the 42-byte ciphertext out of .rodata.
#    Find its address with:  rabin2 -S ctfvault   (or llvm-readelf -S)
#    then read it with:      px 42 @ <addr>       (or slice the file below)
CIPHERTEXT_FILE_OFFSET = 0x0   # <-- set this from your own binary
LENGTH = 42
data = open(sys.argv[1], "rb").read()
ct = data[CIPHERTEXT_FILE_OFFSET:CIPHERTEXT_FILE_OFFSET + LENGTH]

# 3. regenerate the keystream and decrypt
state = fnv1a(key)
out = []
for b in ct:
    state = xorshift32(state)
    out.append(b ^ (state & 0xFF))
print("flag =", bytes(out).decode("ascii", "replace"))
```

Locating the ciphertext is the last piece of real work. It is a 42-byte constant array in `.rodata`
that `vault_reveal` indexes; find the `adrp`/`add` pair that materialises its address, or dump
`.rodata` and look for the 42 bytes that are not printable text.

```
# Unverified
[0x0]> iS~rodata
[0x0]> px 128 @ <rodata address>
[0x0]> axt @@ str.*                 # what references what
```

That is **Diamond**.

</details>

---

## What this challenge teaches

| Lesson | Where it bit you |
|---|---|
| The function with the security-sounding name is rarely the boundary | `vault_verify_token` patched, nothing changed |
| Read the caller before patching the callee | `vault_open`'s short-circuit explains everything |
| A bypass defeats a *check*; it cannot produce a *secret* | Full patch, garbage flag |
| Published algorithms are identifiable from their constants alone | FNV-1a and xorshift32, neither named in the binary |
| Compile-time obfuscation is not obfuscation | The XOR-ed `su` path visible in `strings` at `-O2` |
| Static analysis is enough more often than people expect | Diamond needs no device at all |
| Your test environment is part of the measurement | A stock AVD ships `/system/xbin/su` and fires the probe |

That last row is worth dwelling on. If you had tested on a device without `su`, the unpatched binary
would have accepted the correct key immediately and the entire short-circuit lesson would have been
invisible. **The environment you measure in changes what you conclude**, which is the discipline
[68-ReverseEngineering](../../68-ReverseEngineering/README.md) formalises and the reason this
repository records which device produced every number.

---

## Cleanup

```bash
# host
adb shell 'rm -f /data/local/tmp/ch59_*'
adb shell 'rm -f /data/local/tmp/ch59c_*'
adb shell 'ls /data/local/tmp/'      # confirm nothing of ours remains
```

Also remove your local build directory if you want a clean slate:

```bash
rm -rf ~/ch59-build
```

---

## Extending the challenge

If you want more, modify [`../examples/03-ctf-vault.c`](../examples/03-ctf-vault.c) and rebuild:

1. **Strip it.** `-s` at link time. Now there are no `vault_*` names and you work from strings,
   imports and `.init_array` alone. This is what a real target looks like.
2. **Move the probe into `.init_array`** so it runs before `main`, and set a global flag. Now the
   short-circuit is not even in the same function.
3. **Split the key check across three functions** so no single patch suffices.
4. **Make the probe's result perturb the keystream seed** rather than gate the branch — the
   decoupled-consequence pattern from
   [37-RootDetection lab 04](../../37-RootDetection/labs/lab-04-ctf-decoupled.md). This is the
   nastiest variant and the most realistic.
5. **Lengthen the key to seven characters** and see where Python stops being adequate.

Variant 4 is the one worth building. It produces a binary where patching *anything* yields a
plausible-looking but wrong flag, with no error, which is exactly how real anti-tamper is designed
to waste your afternoon.
