# 73 — Labs · Cheatsheet

Dense reference. Prose lives in [README.md](README.md).
All counts measured 2026-08-16; re-run `--stats` rather than quoting them.

---

## The corpus

| Quantity | Value |
|---|---:|
| Chapters shipping labs | 79 |
| Lab markdown files | 327 |
| Beginner / Intermediate / Advanced / CTF | 61 / 120 / 66 / 74 |
| Difficulty not declared | 6 |

| Tag | Labs | Tag | Labs |
|---|---:|---|---:|
| `device` | 269 | `ndk` | 50 |
| `frida` | 128 | `ghidra` | 14 |
| `jdk` | 107 | `xposed` | 14 |
| `root` | 82 | `radare2` | 8 |
| `jadx` | 80 | `physical` | 8 |
| `apktool` | 72 | `mobsf` | 6 |
| `no-root` | 69 | `proxy` | 6 |
| `no-device` | 58 | `ida` / `aosp` | 4 / 4 |
| `objection` | 8 | `docker` | 3 |
| `python` | — | `drozer` | 0 |

---

## Commands

### Index

```bash
python3 -B scripts/build-lab-index.py                       # rebuild all four indexes
python3 -B scripts/build-lab-index.py --stats               # counts, write nothing
python3 -B scripts/build-lab-index.py --verify-links        # resolve every emitted link
python3 -B scripts/build-lab-index.py --why <relpath>       # tags + evidence for one lab
python3 -B scripts/build-lab-index.py --by chapter --out -
python3 -B scripts/build-lab-index.py --by difficulty --out -
python3 -B scripts/build-lab-index.py --by requirement --out -
python3 -B scripts/build-lab-index.py --by path --out -
python3 -B scripts/build-lab-index.py --format json --out ~/labs.json
python3 -B scripts/build-lab-index.py --format csv  --out ~/labs.csv
```

### Environment

```bash
python3 -B scripts/lab-env-probe.py                         # probe only
python3 -B scripts/lab-env-probe.py --match                 # probe + corpus match
python3 -B scripts/lab-env-probe.py --match --list runnable
python3 -B scripts/lab-env-probe.py --match --list blocked
python3 -B scripts/lab-env-probe.py --match --chapter 53
python3 -B scripts/lab-env-probe.py --match --assume frida,proxy
python3 -B scripts/lab-env-probe.py --no-device --match
python3 -B scripts/lab-env-probe.py --match --json > ~/manifest.json
```

### Triage

```bash
bash scripts/lab-doctor.sh
bash scripts/lab-doctor.sh --lab <path> --paths
bash scripts/lab-doctor.sh --no-device
```

### Target

```bash
cd examples
./build-chain-target.sh                       # build only, out of tree
./build-chain-target.sh --install
./build-chain-target.sh --target-sdk 23       # reproduce the install floor
OUTDIR=/tmp/x ./build-chain-target.sh
./build-chain-target.sh --uninstall
```

---

## Device identity — run before trusting anything

```bash
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.build.type
adb shell getenforce
adb shell getconf PAGE_SIZE
adb shell "ls /dev/block/by-name"
adb shell "mount | grep cacerts"
```

---

## The `su` form

| Device | Form | Wrong form says |
|---|---|---|
| API 35 AVD (AOSP `su`) | `su 0 <cmd>` | `su: invalid uid/gid '-c'` |
| Magisk on a handset | `adb shell "su -c 'cmd'"` | varies |
| **Any device** | `adb shell su -c 'cmd'` is **broken** | quotes stripped by the outer shell <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as a counter-example --> |

```bash
adb shell "su 0 id"     # test BOTH
adb shell "su -c id"
```

---

## Install refusals

| String | Cause | Fix |
|---|---|---|
| `INSTALL_FAILED_DEPRECATED_SDK_VERSION` | `targetSdk` below the platform floor (24) | `adb install --bypass-low-target-sdk-block` |
| `INSTALL_FAILED_USER_RESTRICTED` | OEM "Install via USB" policy. Message is untrue | root `pm install` from the device shell |
| `INSTALL_FAILED_UPDATE_INCOMPATIBLE` | Signing-key mismatch | `adb uninstall` first |

---

## Vantages

| Vantage | uid | Note |
|---|---|---|
| Third-party app | 10xxx | The only one that models an attacker app |
| `shell` | 2000 | Holds permissions no app holds. **Not an app** |
| root | 0 | Reaches what `shell` cannot |
| The app itself | its own | Via instrumentation or a hook |

```bash
adb shell id
adb shell "su 0 id"
adb shell "pm list packages -U <pkg>"
```

---

## Verdict vocabulary

| Verdict | Meaning |
|---|---|
| `HYPOTHESIS` | Read, not tested. **No claim may end here** |
| `CONFIRMED` | Observed, from a stated vantage, reproducibly |
| `REFUTED` | Tested and did not occur |
| `NOT TESTED` | Untested, and saying so |
| `DIVERGED` | Re-ran a claim, got a different result. **Not "they were wrong"** |

Divergence causes, in descending frequency:
**1** vantage · **2** device/version · **3** `su` form · **4** tool version ·
**5** a command that succeeded and did nothing · **6** the lab is wrong.

---

## Outputs that prove nothing

| Output | Prints when |
|---|---|
| `Broadcast completed: result=0` | Whether or not any receiver ran |
| `Starting: Intent { … }` | Whether or not the activity started |
| `Warning: Activity not started, intent has been delivered to currently running top-most instance` | The extra was **not** read. `onCreate` did not re-run |
| `frida --version` on the host | Says nothing about the device |
| `frida-ps -U` listing processes | Server may still fail to link on attach |
| `shutil.which()` finding a tool | It may not execute |

---

## Learning paths

| Path | Goal |
|---|---|
| `two-weeks-no-android` | 10 days, no background |
| `interview-ready` | 3 weeks of evenings |
| `emulator-only` | No phone, no bootloader, no TEE |
| `native-re` | 4–6 weeks; do not start at Ghidra |
| `no-device-at-all` | A laptop on a train |

Full contents: [`references/learning-paths.md`](references/learning-paths.md).

---

## Lab header the index parses

```markdown
**Difficulty:** Beginner | Intermediate | Advanced | CTF
**Time:** 60–90 minutes
**Prerequisites:** [Chapter NN §x](../README.md#...)
**Requires:** honest list; mark optional things optional
**Device used to verify this lab:** model, version, API, ABI, build type, root
```

Band = the level needed to **finish**. CTF is a band and goes **last** in a chapter.

---

## Writing order (not reading order)

1. Success criteria 2. Measured outputs 3. Steps 4. Setup
5. Why this matters 6. If it did not work 7. Cleanup

---

## Pre-flight checks for a new lab

```bash
python3 -B scripts/build-lab-index.py --why <lab>            # header vs derived
python3 -B scripts/build-lab-index.py --verify-links         # promised paths
python3 -B scripts/lab-env-probe.py --match --chapter NN     # can a reader run it?
python3 -B ../76-CheatSheets/scripts/lint-commands.py --path .   # target: 0 ERROR
find . \( -name '__pycache__' -o -name '*.pyc' -o -name '*.class' \
     -o -name '*.apk' -o -name '*.dex' -o -name '*.so' -o -name '*.o' \)
```

```powershell
# raw C0 control bytes -- must be zero
Get-ChildItem -LiteralPath "73-Labs" -Recurse -File | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    $n = @($b | Where-Object { ($_ -lt 0x20 -and $_ -notin 9,10,13) -or $_ -eq 0x7F }).Count
    if ($n) { "$($_.Name) $n" } }
```

```powershell
# BOM -- valid UTF-8, so a decode check will NOT catch it
Get-ChildItem -LiteralPath "73-Labs" -Recurse -File -Filter *.md | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) {
        "BOM: $($_.Name)" } }
```

---

## Link depth

| From | To another chapter |
|---|---|
| `NN-Chapter/README.md` | `../MM-Chapter/README.md` |
| `NN-Chapter/labs/x.md` | `../../MM-Chapter/README.md` |
| `NN-Chapter/references/x.md` | `../../MM-Chapter/README.md` |
| `NN-Chapter/labs/x.md` → own chapter | `../README.md` |

Verify by **resolving**, never by reading: `--verify-links`.

---

## Traps, one line each

| Trap | Reality |
|---|---|
| `adb shell su -c 'cmd'` | Quotes stripped. Use `"su -c 'cmd'"` or `su 0 cmd` <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, quoted as a counter-example --> |
| `adb shell ls /abs/path` on Git Bash | MSYS rewrites it to a host path. Quote it |
| `adb push` remote path on MSYS | Same. `MSYS_NO_PATHCONV=1` |
| `zip` / `unzip` / `apktool` on Windows | Often absent. Use Python's `zipfile`, `aapt2 dump xmltree` |
| `kotlinc` | Ships inside Android Studio, not on `PATH` |
| `javac @argfile` with a space in the path | Quote every argfile line |
| XML comment containing `--` | `aapt2` rejects the file |
| `set -o pipefail` with `head` | Spurious SIGPIPE failure. Test content, not status |
| `-Include` with `-LiteralPath` | Silently ignored. Use `Where-Object` |
| `Get-Content -Raw` + `Set-Content -Encoding UTF8` | Corrupts UTF-8 permanently |
| Python without `-B` | Writes `__pycache__` into the repo |
| App uid | Changes across reinstalls |
| 16 KiB pages | Native binaries need `-Wl,-z,max-page-size=16384` |
| Emulator | No bootloader, no TEE. 8 labs unanswerable |
