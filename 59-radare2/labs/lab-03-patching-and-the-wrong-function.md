# Lab 03 — Patching, and the function that did not matter

**Difficulty:** Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-the-command-language.md), [Lab 02](lab-02-triage-a-real-library.md),
[18-ARM](../../18-ARM/README.md), [Chapter 59 §3.12](../README.md#312-patching-with-r2--w),
[Chapter 59 §5.4](../README.md#54-the-most-important-thing-in-this-chapter-patch-the-decision-not-the-check)

---

## Why this lab exists

You will find a function called `lt_verify_license`. You will patch it to return success. You will
verify, byte by byte, that the patch is present and correct. And the program will behave **exactly as
before**.

This is not a contrived teaching scenario. It is a measurement taken on a real device, and it is the
single most common way a reverse engineer wastes an afternoon. This repository has now recorded two
independent mechanisms that produce this identical symptom:

- [18-ARM](../../18-ARM/README.md) §5.4 measured a check that was **inlined**, so the standalone
  function that was patched is called by nothing.
- This lab measures a check that is **short-circuited** by an earlier guard, so it is never reached.

Both are diagnosed the same way, and the diagnosis is one command. Learning it here costs you three
hours; learning it on an engagement costs you a day.

> **⚠️ On the state of this chapter**
> radare2 was **not installed** on the machine where this was written. Every `r2` command is
> **📘 Unverified**. The patches, the byte encodings, the file offsets and — critically — the
> behaviour of every patched binary on a real device are **✅ Measured**, and each says how.
>
> Where this lab shows you a patch applied without radare2, it is because the measurement had to be
> made with a Python byte-writer instead. The radare2 command that does the same thing is given
> alongside, marked unverified.

---

## Objective

1. Patch a binary with `r2 -w`, safely, using `io.cache` as an undo.
2. Convert a virtual address to a file offset, and explain why they differ.
3. Verify a patch at the byte level rather than by eye.
4. **Discover that a verified, correct patch changed nothing**, and diagnose why.
5. Patch the actual decision, and confirm the behaviour changed.

---

## Setup

### Build the target

```bash
# host
cd 59-radare2/examples
./build.sh
```

You want `r2gate` — an AArch64 executable built from
[`01-r2-target.c`](../examples/01-r2-target.c) with
`-O2 -pie -Wl,-z,max-page-size=16384`.

> **⚠️ The 16 KiB page trap**
> That link flag is not optional. NDK r25c binaries without it **segfault at load** on 16 KiB-page
> Android images, which includes current AVDs, and no error message points at page size. A
> three-line `int main(void){return 42;}` exits **139**. Measured independently by
> [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) and
> [39-EmulatorDetection](../../39-EmulatorDetection/README.md). `build.sh` sets it.

### Get it onto a device

```bash
# host
adb push ~/ch59-build/r2gate /data/local/tmp/ch59_r2gate
adb shell chmod 755 /data/local/tmp/ch59_r2gate
adb shell /data/local/tmp/ch59_r2gate testkey
```

> **✅ Measured** — on the AVD `sdk_gphone16k_x86_64` (Android 15 / API 35, x86_64, 16 KiB pages)
> this prints `gate=0`. An AArch64 binary runs there through `libndk_translation.so`, so an arm64
> target can be exercised without a physical phone.

> **⚠️ If `execve` is blocked**
> Some vendor builds refuse to execute from `/data/local/tmp` — the push succeeds, `chmod +x`
> succeeds, and the run fails with `No such device or address` and exit **126**
> ([65-Hooking](../../65-Hooking/README.md) measured it; [60-ADB §3.7](../../60-ADB/README.md)
> writes it up as a transport success and an execution failure). The workaround is to invoke the
> loader explicitly, which loads the binary instead of exec'ing it:
>
> ```bash
> adb shell /system/bin/linker64 /data/local/tmp/ch59_r2gate testkey
> ```

**Use a test device or an emulator.** Everything here writes only to `/data/local/tmp` and the lab
ends with a cleanup step.

---

## Part 1 — Understand before you patch (30 minutes)

### 1.1 — Find the functions

```
# 📘 Unverified
$ r2 ~/ch59-build/r2gate
[0x0]> aa
[0x0]> afl~lt_
```

> **✅ Measured** — `llvm-nm` on the shipped build reports:
>
> ```
> 00000000000048a0 T lt_gate
> 000000000000481c T lt_probe_paths
> 0000000000004854 T lt_verify_license
> ```
>
> **Read these from your own build.** `build.sh` prints them in `build-report.txt`. Editing a
> comment in the source moves every one of them.

### 1.2 — Read the licence check

```
# 📘 Unverified
[0x0]> pdf @ sym.lt_verify_license
```

> **✅ Measured** — the tail of the function, from `llvm-objdump -d` (addresses from the shared
> library build; the executable's differ by a fixed amount):
>
> ```
>     1950: a9 b8 93 52   mov    w9, #40389
>     1954: 6b 32 80 52   mov    w11, #403
>     ...
>     1974: 08 57 8e 52   mov    w8, #29368
>     1978: 48 f0 b7 72   movk   w8, #49026, lsl #16
>     197c: 3f 01 08 6b   cmp    w9, w8
>     1980: e0 17 9f 1a   cset   w0, eq
>     1984: c0 03 5f d6   ret
> ```

Decode the constants:

- `29368` = `0x72B8`, `49026` = `0xBF82`, so the target value is **`0xBF8272B8`**.
- `40389` with its `movk` partner is `0x811C9DC5` — the **FNV-1a 32-bit offset basis**.
- `403` with its partner is `0x01000193` — the **FNV-1a prime**.

So: FNV-1a hash of the key, compared against `0xBF8272B8`. Recognising published algorithm constants
identified the algorithm without reading the loop.

The shape `mov` + `movk` + `cmp` + `cset` is the most recognisable security check in AArch64:
*compare against a 32-bit magic number, return the boolean.*

### 1.3 — The step everyone skips

**Before patching anything, ask who calls it.**

```
# 📘 Unverified
[0x0]> axt sym.lt_verify_license
[0x0]> pdf @ sym.lt_gate
```

Do this now, and actually read the output. Part 3 is entirely about what happens if you do not.

---

## Part 2 — Patch it (45 minutes)

### 2.1 — Work on a copy, always

```bash
# host -- r2 -w edits in place, immediately, with no undo and no backup
cp ~/ch59-build/r2gate ~/ch59-build/r2gate.verifyonly
```

> **⚠️ Warning**
> `r2 -w` has no "save" step. `wa` writes through to disk the moment you press Enter. There is no
> confirmation and no backup. This is why the copy is step one.

### 2.2 — Patch with a safety net

```
# 📘 Unverified
$ r2 -w ~/ch59-build/r2gate.verifyonly
[0x0]> e io.cache=1                   # stage writes in memory instead of on disk
[0x0]> aa
[0x0]> s sym.lt_verify_license
[0x0]> wa mov w0, 1; ret              # assemble and write
[0x0]> pdf                            # check your work BEFORE committing
[0x0]> wci                            # commit the cache to the file
```

`e io.cache=1` is the undo that `r2 -w` otherwise lacks. Patch, inspect, patch again, and only
commit when satisfied. Turn it on before every patching session.

Three equivalent ways to write the same patch:

```
# 📘 Unverified
[0x0]> wa mov w0, 1; ret       # assemble source
[0x0]> wx 20008052c0035fd6     # raw bytes
[0x0]> wao ret1                # let r2 work out "make this return 1"
```

### 2.3 — The encodings, verified

> **✅ Measured** — assembled with `aarch64-linux-android21-clang -c -x assembler-with-cpp` from NDK
> 25.2.9519653 and read back with `llvm-objdump -d`:
>
> | Instruction | Bytes (file order) | Word |
> |---|---|---|
> | `mov w0, #1` | `20 00 80 52` | `0x52800020` |
> | `mov w0, #0` | `00 00 80 52` | `0x52800000` |
> | `ret` | `c0 03 5f d6` | `0xd65f03c0` |
> | `nop` | `1f 20 03 d5` | `0xd503201f` |
>
> The `ret` and `nop` values match those recorded independently in
> [18-ARM](../../18-ARM/README.md).

### 2.4 — Virtual address is not file offset

If you patch with anything other than radare2 — a Python script, a hex editor — you own this
arithmetic, and getting it wrong corrupts an unrelated part of the file.

```
# 📘 Unverified -- r2 prints both columns side by side
[0x0]> iS
```

> **✅ Measured** — `llvm-readelf -S ~/ch59-build/r2gate`:
>
> ```
> .text   PROGBITS   0000000000004794   000794   000288   AX
>                    ^ virtual address  ^ file offset
> ```
>
> Virtual address `0x4794`, file offset `0x794`. **Delta = `0x4000`.**
> `lt_verify_license` is at virtual address `0x4854`, so its bytes live at file offset **`0x854`**.

The general rule, computed **per section** because different sections can have different deltas:

```
file_offset = virtual_address - (section_vaddr - section_file_offset)
```

Patching at `0x4854` in a raw hex editor would write past the end of this file entirely.

### 2.5 — The patch, applied without radare2

Since radare2 was unavailable for the measurement, the patch was applied with a byte writer. This is
also the honest way to *verify* any patch, whichever tool made it:

```bash
# host -- equivalent to: r2 -w -qc 'wa mov w0,1; ret @ sym.lt_verify_license' r2gate.verifyonly
python3 -B - <<'PY'
import shutil
shutil.copy('r2gate', 'r2gate.verifyonly')
d = bytearray(open('r2gate.verifyonly','rb').read())
DELTA  = 0x4000                       # from iS / llvm-readelf -S
VERIFY = 0x4854                       # lt_verify_license, from your build report
off = VERIFY - DELTA
print('before:', ' '.join('%02x' % b for b in d[off:off+8]))
d[off:off+8] = bytes([0x20,0x00,0x80,0x52, 0xc0,0x03,0x5f,0xd6])   # mov w0,#1 ; ret
print('after :', ' '.join('%02x' % b for b in d[off:off+8]))
open('r2gate.verifyonly','wb').write(d)
PY
```

### 2.6 — Verify at the byte level

Never verify a patch by eye.

```bash
# host
llvm-objdump -d ~/ch59-build/r2gate.verifyonly --disassemble-symbols=lt_verify_license | head -6
```

> **✅ Measured** — the patch is present and exactly correct:
>
> ```
>     4854: 20 00 80 52   mov   w0, #1
>     4858: c0 03 5f d6   ret
> ```

The function now unconditionally returns 1. There is no doubt about it.

---

## Part 3 — The measurement that matters (45 minutes)

### 3.1 — Run it

```bash
# host
adb push ~/ch59-build/r2gate.verifyonly /data/local/tmp/ch59_verifyonly
adb shell chmod 755 /data/local/tmp/ch59_verifyonly
adb shell /data/local/tmp/ch59_verifyonly radare2
```

Before you run it, write down what you expect.

> **✅ Measured** — on the AVD `sdk_gphone16k_x86_64` (API 35):
>
> ```
> $ adb shell /data/local/tmp/ch59_r2gate    radare2      ->  gate=0
> $ adb shell /data/local/tmp/ch59_verifyonly radare2      ->  gate=0
> ```
>
> **The patched binary behaves identically to the unpatched one.**

The patch is correct. The patch is present. The bytes are verified. Nothing changed.

### 3.2 — Diagnose it

The diagnosis is the command you were told to run in Part 1.3 and may have skipped:

```
# 📘 Unverified
[0x0]> axt sym.lt_verify_license
[0x0]> pdf @ sym.lt_gate
```

> **✅ Measured** — `llvm-objdump -d r2gate --disassemble-symbols=lt_gate`:
>
> ```
> 00000000000048a0 <lt_gate>:
>     48a0: fd 7b be a9   stp   x29, x30, [sp, #-32]!
>     48a4: f3 0b 00 f9   str   x19, [sp, #16]
>     48a8: fd 03 00 91   mov   x29, sp
>     48ac: f3 03 00 aa   mov   x19, x0
>     48b0: db ff ff 97   bl    0x481c <lt_probe_paths>     ; <-- FIRST
>     48b4: 60 00 00 34   cbz   w0, 0x48c0                  ; probe==0 -> continue
>     48b8: e0 03 1f 2a   mov   w0, wzr                     ; else return 0 NOW
>     48bc: 05 00 00 14   b     0x48d0
>     48c0: e0 03 13 aa   mov   x0, x19
>     48c4: e4 ff ff 97   bl    0x4854 <lt_verify_license>  ; <-- only if probe==0
>     48c8: 1f 00 00 71   cmp   w0, #0
>     48cc: e0 07 9f 1a   cset  w0, ne
>     48d0: f3 0b 40 f9   ldr   x19, [sp, #16]
>     48d4: fd 7b c2 a8   ldp   x29, x30, [sp], #32
>     48d8: c0 03 5f d6   ret
> ```

There it is. `lt_gate` calls `lt_probe_paths` **first** and returns early if it fires. The call to
`lt_verify_license` at `0x48c4` is only reached when the probe returns zero.

### 3.3 — Why does the probe fire?

`lt_probe_paths` checks whether `/system/xbin/su` exists.

> **✅ Measured** — on the AVD:
>
> ```
> $ adb shell ls -l /system/xbin/su
> -rwsr-x--- 1 root shell 51224 2025-01-23 23:03 /system/xbin/su
> ```
>
> **The stock Google emulator image ships `/system/xbin/su`**, setuid root, owned `root:shell`. The
> most classic root-detection check in existence fires on an unmodified AVD.

That is a genuinely useful fact in its own right — see
[37-RootDetection](../../37-RootDetection/README.md) and
[39-EmulatorDetection](../../39-EmulatorDetection/README.md). Here it means the probe returns 1,
`lt_gate` returns 0 at `0x48b8`, and `lt_verify_license` is never called.

**The patch was correct, applied, verified — and irrelevant.**

### Checkpoint 3

- Would this patch have worked on a device with no `su` binary? What would it have proved?
- What would `axt sym.lt_verify_license` have told you *before* you patched?
- Name the other mechanism that produces this identical symptom.

<details>
<summary>Answers</summary>

- On a clean device the probe returns 0, so `lt_verify_license` **is** called, and the patch would
  have made the gate open for any key. It would have proved that the patch works *on that device* —
  and taught you nothing about the guard. Testing a bypass only on a device where the guard does not
  fire is a classic false confidence.
- It would have shown exactly one caller, `lt_gate`, at which point reading `lt_gate` — nine
  instructions — would have revealed the short-circuit before you wrote a single byte.
- **Inlining.** [18-ARM](../../18-ARM/README.md) §5.4 measured a signature check patched to return
  1, verified returning 1, and still refused — because clang had inlined the check and the patched
  standalone copy was called by nothing.

</details>

---

## Part 4 — Patch the decision (40 minutes)

Now patch what actually decides.

There are three defensible targets, and choosing between them is the skill:

| Target | Patch | Effect |
|---|---|---|
| `lt_probe_paths` | `mov w0, #0; ret` | The probe always says "clean". Most surgical. |
| The `cbz` at `0x48b4` | invert or `nop` the early return | Changes control flow only in this caller |
| `lt_gate` itself | `mov w0, #1; ret` | Opens the gate unconditionally — blunt, and destroys the key check too |

Patch the probe:

```
# 📘 Unverified
$ cp ~/ch59-build/r2gate ~/ch59-build/r2gate.probeonly
$ r2 -w ~/ch59-build/r2gate.probeonly
[0x0]> e io.cache=1
[0x0]> aa
[0x0]> s sym.lt_probe_paths
[0x0]> wa mov w0, 0; ret
[0x0]> pdf
[0x0]> wci
```

```bash
# host -- the byte-level equivalent, and how the measurement was taken
python3 -B - <<'PY'
import shutil
shutil.copy('r2gate','r2gate.probeonly')
d=bytearray(open('r2gate.probeonly','rb').read())
DELTA, PROBE = 0x4000, 0x481c          # from YOUR build report
off = PROBE - DELTA
d[off:off+8] = bytes([0x00,0x00,0x80,0x52, 0xc0,0x03,0x5f,0xd6])   # mov w0,#0 ; ret
open('r2gate.probeonly','wb').write(d)
print('patched lt_probe_paths at file offset 0x%x' % off)
PY
```

Now run the **full truth table**. Build all four variants and test each with a wrong key and the
correct key.

> **✅ Measured** — all four variants built from the shipped `examples/01-r2-target.c`, pushed to the
> AVD `sdk_gphone16k_x86_64` (API 35) and executed. The accepted key is `radare2`.
>
> | Binary | `key=wrongkey` | `key=radare2` |
> |---|---|---|
> | Unpatched | `gate=0` | **`gate=0`** |
> | `lt_verify_license` -> return 1 | `gate=0` | **`gate=0`** |
> | `lt_probe_paths` -> return 0 | `gate=0` | **`gate=1`** |
> | Both patched | `gate=1` | `gate=1` |

Read every row.

- Row 1: **the correct key alone is not enough.** On this device the guard blocks it.
- Row 2: **patching the security-sounding function does nothing.**
- Row 3: the correct attack — the right patch *and* the right key.
- Row 4: full bypass, key irrelevant.

Real targets stack conditions like this routinely, and a partial bypass looks exactly like a bypass
that does not work.

---

## Part 5 — Patching on Android is the easy half (20 minutes)

You just changed four bytes. On a real engagement that is the simplest part of the job.

| Obstacle | Why | Chapter |
|---|---|---|
| APK signature | A patched `.so` invalidates the APK signature; it will not install until re-signed | [10-APK-Internals](../../10-APK-Internals/README.md) |
| Runtime integrity checks | The app may verify its own signature or hash its libraries — and re-signing is precisely what it looks for | [38-TamperDetection](../../38-TamperDetection/README.md) |
| Multiple ABIs | You patched `arm64-v8a`; the device might load `armeabi-v7a` | [Chapter 59 §6.1](../README.md#61-getting-from-an-apk-to-the-file-radare2-opens) |
| Server-side verification | No client patch can help | [67-BypassingProtections](../../67-BypassingProtections/README.md) |
| Decoupled consequences | The check perturbs a value that fails much later, somewhere else | [37-RootDetection lab 04](../../37-RootDetection/labs/lab-04-ctf-decoupled.md) |

That last row is worth reading before lab 04.

> **🔍 Consider hooking instead**
> [Frida](../../53-Frida/README.md) changes behaviour at run time with no file modification, so
> signature checks never fire. Patching is right when you need persistence or have no injection
> path; hooking is right most other times. Knowing which to reach for is the actual skill.

---

## Cleanup

```bash
# host -- remove everything this lab pushed
adb shell 'rm -f /data/local/tmp/ch59_*'
adb shell 'ls /data/local/tmp/'      # confirm
```

Leaving artefacts on a device is how this repository accumulated residue that a later chapter had to
find and remove. Clean up even on an emulator — *especially* on an emulator, because nobody thinks of
an AVD as a device.

---

## Success criteria

- [ ] You patched a function with `r2 -w` and `io.cache`, and committed deliberately.
- [ ] You converted a virtual address to a file offset and can state the rule.
- [ ] You verified a patch at the byte level with a disassembler.
- [ ] **You observed a correct, verified patch change nothing**, and diagnosed why.
- [ ] You can name two mechanisms that produce that symptom.
- [ ] You produced the four-row truth table on a device.
- [ ] You can state the procedure that would have prevented the wasted patch.

**The procedure, in one line:** *before patching a function, run `axt` on it and read every caller;
if you cannot say what happens to the return value, you are guessing.*

---

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| Patched binary segfaults (exit 139) | Missing `-Wl,-z,max-page-size=16384` on a 16 KiB-page device | Rebuild with `build.sh` |
| `wa` says "invalid instruction" | Wrong arch assumed | `e asm.arch=arm; e asm.bits=64` |
| The patch is not in the file | You forgot `wci` after `io.cache=1`, or omitted `-w` | Both are required |
| Byte offsets look wrong | Used the virtual address as a file offset | Subtract the section delta |
| `adb shell` says "not executable" | Missing `chmod 755`, or `execve` blocked | `chmod`, or use `/system/bin/linker64` |
| Your addresses differ from this lab | Different compiler or edited source | Expected — use your `build-report.txt` |
| `gate=0` even after patching both | Wrong offsets, or you patched a stale copy | Re-verify with `llvm-objdump` |

---

## What you learned

- `r2 -w` edits in place with no undo; `e io.cache=1` supplies one.
- Virtual addresses are not file offsets, and the delta is per section.
- A patch can be provably correct and completely irrelevant.
- Short-circuiting and inlining produce the same symptom and the same diagnosis.
- Read the caller before patching the callee.
- On Android, changing the bytes is the easy half.

---

## Next

[Lab 04 — CTF: The gate that was not there](lab-04-ctf-the-gate-that-was-not-there.md) gives you a
target with no walkthrough, built to punish exactly the habit this lab just corrected.
