# Lab 01 — Reading the ART Artifacts

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Prerequisites:** [Chapter 13 §3.1–3.7](../README.md#3-deep-internal-working), a **rooted** device or
emulator, `adb`

---

## Objective

Locate every ART artifact for a real installed application, read the OAT header to determine its
compilation state, extract the DEX bytecode from the VDEX, and decompile it. By the end you will never
again be confused about which file holds what.

## Why this matters

Three situations make this the difference between working and being stuck.

The app was patched in place after installation, so the APK you can download is not what runs. The app
is a preinstalled system application whose APK is awkward to obtain. Or you need to answer "is
this app compiled or interpreted right now?" before spending an hour debugging a Frida script that was
never going to work.

All three are answered by the files in this lab.

---

## Setup

```bash
# host — confirm root and pick a target
adb shell 'su -c id'
adb shell pm list packages -3
```

Pick any third-party app. This lab uses `com.example.target` as a placeholder — substitute a real
package. A deliberately vulnerable app from [80-Appendix](../../80-Appendix/README.md) works well.

```bash
# host — set up a shell you will reuse throughout
adb shell
su
PKG=com.example.target
APK=$(pm path $PKG | head -1 | sed 's/package://')
DIR=$(dirname $APK)
echo "APK: $APK"
echo "DIR: $DIR"
```

> **Note.** The `~~<random>` component in `/data/app` was added in Android 11 so apps cannot guess each
> other's install paths. Never hard-code it — always resolve with `pm path`.

---

## Steps

### Step 1 — Find the artifacts

```bash
# device, as root
ls -la $DIR
ls -la $DIR/oat/
ls -la $DIR/oat/arm64/
```

**Record:** which of `base.odex`, `base.vdex`, `base.art` exist, and their sizes.

**Question 1.** One of these files may be absent. Which one, and what does its absence tell you about
the compiler filter? *(Hint: consult the filter table in §3.9.)*

### Step 2 — Prove `base.odex` is an ELF

```bash
# device
xxd -l 16 $DIR/oat/arm64/base.odex
```

**Expect:** `7f45 4c46` — the ELF magic `\x7fELF`.

**Question 2.** What would the first four bytes be if this were a genuine Dalvik-era ODEX? Why does the
filename still say `.odex`?

### Step 3 — Locate the OAT symbols

```bash
# device — if readelf is unavailable on-device, pull the file and run it on the host
readelf -s $DIR/oat/arm64/base.odex 2>/dev/null | grep -E "oatdata|oatexec|oatlastword"
```

If `readelf` is not present on the device:

```bash
# host
adb pull /data/app/.../oat/arm64/base.odex ./base.odex    # use your real path
readelf -s base.odex | grep -E "oatdata|oatexec|oatlastword"
readelf -h base.odex | head -10
```

**Record:** the addresses of `oatdata` and `oatexec`.

**Question 3.** What lives between `oatdata` and `oatexec`?

### Step 4 — Read the OAT header

```bash
# device, as root
oatdump --oat-file=$DIR/oat/arm64/base.odex --header-only
```

This is the most important command in the lab. Read the entire output, then extract these fields:

| Field | Your value |
|---|---|
| OAT version | |
| Instruction set | |
| Number of DEX files | |
| `compiler-filter` | |
| `dex2oat-cmdline` | |
| `bootclasspath` (first two entries) | |

**Question 4.** What does the `compiler-filter` value tell you about how easy this app will be to hook?

### Step 5 — Cross-check with dumpsys

```bash
# device
dumpsys package dexopt | grep -A5 "\[$PKG\]"
```

**Question 5.** Does this agree with the OAT header? If they ever disagree, which do you trust and why?

### Step 6 — Read the VDEX header

```bash
# device, as root
oatdump --vdex-file=$DIR/oat/arm64/base.vdex --header-only
```

**Record:** the VDEX version and the number of DEX files it contains.

### Step 7 — Extract the DEX

This is the step that matters most.

```bash
# device, as root
mkdir -p /data/local/tmp/dex_out
oatdump --vdex-file=$DIR/oat/arm64/base.vdex --export-dex-to=/data/local/tmp/dex_out
ls -la /data/local/tmp/dex_out
```

```bash
# host
adb pull /data/local/tmp/dex_out ./dex_from_vdex
ls -la ./dex_from_vdex
```

**Question 6.** Compare the extracted DEX against the DEX inside the APK:

```bash
# host
adb pull <the APK path> ./target.apk
mkdir -p apk_dex && cd apk_dex && unzip -o ../target.apk 'classes*.dex' && cd ..
sha256sum ./dex_from_vdex/*.dex ./apk_dex/*.dex
```

Do they match? Should they? What would it mean if they did not?

### Step 8 — Decompile the extracted DEX

```bash
# host
jadx -d ./decompiled ./dex_from_vdex/*.dex
ls ./decompiled/sources/
```

Confirm you get readable Java. This proves the extraction worked end to end.

### Step 9 — Dump a single method's compiled code

Pick any class from the decompiled output.

```bash
# device, as root
oatdump --oat-file=$DIR/oat/arm64/base.odex \
        --class-filter=com.example.SomeClass \
        --method-filter=someMethod
```

**Question 7.** Does the output show native ARM64 instructions, or only DEX bytecode? What does each
case tell you about whether that method was compiled?

### Step 10 — Snapshot and read the profile

```bash
# device
cmd package snapshot-profile $PKG
ls -la /data/misc/profman/ | grep $PKG
profman --dump-only --profile-file=/data/misc/profman/${PKG}-primary.prof
```

If the profile is empty, launch the app, use it for a minute, then repeat.

**Question 8.** What does a non-empty profile prove that examining the APK cannot?

### Step 11 — Change the state and observe

```bash
# device
cmd package compile -m speed -f $PKG
oatdump --oat-file=$DIR/oat/arm64/base.odex --header-only | grep -i compiler-filter
ls -la $DIR/oat/arm64/
```

```bash
# device
cmd package compile -m verify -f $PKG
oatdump --oat-file=$DIR/oat/arm64/base.odex --header-only | grep -i compiler-filter
ls -la $DIR/oat/arm64/
```

**Question 9.** How did the file sizes change between `speed` and `verify`? Did `base.art` appear or
disappear? Explain both observations.

### Step 12 — Restore

```bash
# device
cmd package compile -m speed-profile -f $PKG
```

---

## Hints

<details>
<summary>Hint 1 — oatdump is not on PATH</summary>

It lives in the ART APEX:

```bash
/apex/com.android.art/bin/oatdump --oat-file=...
```

On a 32-bit device the binary may be `oatdump32`. Check with `ls /apex/com.android.art/bin/`.
</details>

<details>
<summary>Hint 2 — the ISA directory is not arm64</summary>

Check what your device actually uses:

```bash
getprop ro.product.cpu.abi
ls $DIR/oat/
```

You may see `arm`, `x86`, or `x86_64` instead of `arm64`.
</details>

<details>
<summary>Hint 3 — oatdump output is enormous</summary>

Redirect it and read offline:

```bash
oatdump --oat-file=... > /data/local/tmp/oat.txt
```
Then `adb pull /data/local/tmp/oat.txt`. A full dump of a large app can exceed 100 MB.
</details>

<details>
<summary>Hint 4 — export-dex-to produces nothing</summary>

Confirm the output directory exists and is writable, and that you are running as root. Some builds
require an absolute path. If it still fails, your ART version may name the flag differently — check
`oatdump --help | grep -i export`.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** `base.art` may be absent. The app image is only produced by filters that actually compile —
`speed`, `speed-profile`, `space`, `space-profile` and the `everything` variants. Under `verify` or
`extract` there is nothing to pre-initialise, so no app image is written. Its absence therefore implies
a non-compiling filter.

**2.** A Dalvik ODEX began with `dey\n` (`64 65 79 0a`). The name survived because the file occupies
the same slot in the system's layout, and changing it would have broken tooling and expectations. The
contents changed completely: from optimised DEX bytecode to an ELF containing native code.

**3.** The OAT header, the key-value store, the `OatDexFile` records, the `OatClass` records with their
method bitmaps, and — from Android 8 — references into the VDEX for the DEX data itself. Everything
between the two symbols is metadata.

**4.** `verify` means nothing is compiled: every method enters the interpreter, no inlining occurs, and
Java hooks land reliably. `speed` means everything is compiled with aggressive inlining, so small
methods may have been absorbed into their callers and hooks on them will silently never fire.
`speed-profile` is in between — only profiled methods are compiled.

**5.** They should agree. `dumpsys package dexopt` reports what `PackageManagerService` believes;
the OAT header reports what `dex2oat` actually recorded when it produced the file. If they disagree,
trust the OAT header, because it is the artifact the runtime will actually load — and treat the
disagreement as interesting in its own right, since it suggests the record and the file have drifted.

**6.** They will normally match, because the VDEX's DEX section is the same bytecode taken from the
APK. They would differ if the app were patched in place after installation, if a packer rewrote the DEX
at install time, or if you are comparing against a different build than the one installed. A mismatch
is always worth investigating.

**7.** Native ARM64 instructions mean the method was AOT-compiled and is present in `oatexec`. Only
DEX bytecode with no native code means the method was not compiled and will start interpreted. Under
`speed-profile` you will see a mixture across the app, which is exactly what the `OatClass` bitmap
(§3.3) encodes.

**8.** The APK tells you what code *exists*. The profile tells you what code *actually executed on this
device*. That distinction matters enormously for triage in a large obfuscated app — it points you at
live code — and it is strong forensic evidence, since it can show that a suspicious method was really
invoked rather than merely present.

**9.** Under `speed`, `base.odex` grows substantially because it now contains compiled native code for
every method, and `base.art` appears because the app image is produced. Under `verify`, `base.odex`
shrinks to little more than metadata and `base.art` disappears, because there is nothing compiled to
pre-initialise.

</details>

---

## Success criteria

- [ ] You located `base.odex`, `base.vdex` and (conditionally) `base.art` without hard-coding a path
- [ ] You proved from its magic bytes that `base.odex` is an ELF, and can explain the misleading name
- [ ] You read the `compiler-filter` from the OAT header and can say what it implies for hooking
- [ ] You extracted DEX from the VDEX and decompiled it successfully with `jadx`
- [ ] You can explain why the VDEX — not the APK — is the authoritative source of installed bytecode
- [ ] You dumped a single method and can tell compiled from uncompiled in the output
- [ ] You snapshotted and read a profile, and can state what it proves
- [ ] You observed the artifacts change as you moved between `speed` and `verify`
- [ ] You restored the device to a sensible state afterwards
