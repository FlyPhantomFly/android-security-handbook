# 74 — Case Studies · Cheatsheet

Dense reference. Full narratives in [README.md](README.md); raw evidence in
[examples/reproduction-log.md](examples/reproduction-log.md).

---

## The six cases in one table

| # | Case | Measurement | Correction | Owner |
|---|---|---|---|---|
| A | The property that lied | `getprop` = `green` / `orange` / `""` | TEE attestation; `/proc/cmdline`; bootconfig | [20](../20-Security-Architecture/README.md), [50](../50-HardwareBackedSecurity/README.md), [61](../61-Fastboot/README.md) |
| B | Patch changed nothing | Truth table, 4 rows | Read the caller; count call sites | [59](../59-radare2/README.md), [18](../18-ARM/README.md) |
| C | Compiler deleted it | `-O2` leaks, `-O0` hides | Dump `.rodata`; count decoder instructions | [59](../59-radare2/README.md), [58](../58-IDA/README.md) |
| D | Cannot detect | 3 vantages, 3 answers | `Os.stat` + `errno` | [63](../63-LSPosed/README.md), [37](../37-RootDetection/README.md) |
| E | Wrong chair | 673 / 633 / 1055 | Compare names, not counts | this chapter |
| F | 1,141 hits, 0 findings | Substring audit | Arithmetic must close | [64](../64-Xposed/README.md) |

---

## Symptom to first hypothesis

| Symptom | First hypothesis | Test |
|---|---|---|
| Detection works in test, not in production | Wrong vantage | Re-run from an app uid |
| `File.exists()` returns `false` | Cannot see it, not absent | `Os.stat`, read `errno` |
| Verified patch, no behaviour change | Inlined or short-circuited | Cross-references, then read the caller |
| `strings` finds nothing | Nothing was there to find | Dump `.rodata`, look for the **ciphertext** |
| Clean zero across every sample | Broken tool | Run it on one known-positive |
| Property disagrees with its source | Targeted forgery | Compare each field; note what was **not** forged |
| Count you cannot reproduce | Different vantage or method | Compare names, not counts |
| High-confidence band full of hits | Signature too short | Adjudicate by hand; retire tokens under ~8 chars |
| One number moved a lot, its partner did not | **Not drift** | Drift is proportional and correlated |

---

## The H/P/R/E/O/V block

```
Q   the question
H   hypothesis
P   what you predict if it holds
R   what would refute it     <-- WRITE THIS BEFORE YOU LOOK
E   the exact command
O   the raw observation, not a conclusion
V   SUPPORTED / REFUTED / INCONCLUSIVE
```

Notation owned by [68 §1.5](../68-ReverseEngineering/README.md). Reference implementation:
[68's worked journal](../68-ReverseEngineering/examples/worked-journal.md).

---

## Evidence ladder — a claim inherits its WEAKEST rung

| Rung | Evidence |
|---|---|
| 0 | Someone said so |
| 1 | A string is present |
| 2 | Code referencing it exists |
| 3 | It executes |
| 4 | **Its output changes behaviour** |
| 5 | **Reproduced by someone else, later** |

---

## Five correction techniques

| # | Technique | Case |
|---|---|---|
| 1 | Find a source with a **different trust story** | A |
| 2 | Check the **proposition you care about** | B |
| 3 | Go **one rung down** the ladder | C |
| 4 | **Change who is asking** | D, E |
| 5 | Add a **control you did not need** | E |

The one question behind all five: **"What would I expect to see if I were wrong?"**

---

## Four defects in a written case study

| Defect | Test |
|---|---|
| Tidy narrative | Zero refutations = a report, not a case study |
| Absent vantage | As which uid? Unstated means unusable |
| Unlabelled composite | Do device details change mid-narrative? |
| Count with no denominator | Out of how many? Was the top band adjudicated? |

```bash
python3 -B scripts/claim-ledger.py --strict case-study.md
```

---

## Verdicts — only three

| Verdict | Means |
|---|---|
| **REPRODUCED** | Same command, same observation |
| **DIVERGED** | It did not. **NOT a synonym for "the original was wrong"** |
| **NOT RE-RUN** | Honest state; say so rather than implying otherwise |

Before calling a divergence a mistake, rule out: different **device** / different **vantage**
(most common) / different **tool version** / different **command**.

---

## Vantage: what generalises from `run-as`

| Result | Generalises to `untrusted_app`? |
|---|---|
| **Refused** (`EACCES`) | **Yes** — a real app has no more access than `runas_app` |
| **Succeeded** | **No** — confirm with a probe APK |

---

## Measured: three-vantage file probe (AVD, API 35, Magisk 30.7)

| Path | root | `shell` | app | `File.exists()` |
|---|---|---|---|---|
| `/data/adb` | `drwx------` | EACCES | EACCES | — |
| `/data/adb/lspd` | **ENOENT** | EACCES | EACCES | `false` |
| `/data/adb/modules` | PRESENT | EACCES | EACCES | `false` |
| `/system/xbin/su` | `-rwsr-x---` | **visible** | EACCES | `false` from app |
| `/debug_ramdisk` | 0711 | stat OK, no list | stat OK, no list | `true` |
| `/debug_ramdisk/magisk` | 428,416 B | readable | **readable** | `true` |

Three `false` values, three different realities. `/data/adb` is 0700 — refusal is **above the leaf**.

---

## Measured: property visibility (same device, 2026-08-16)

| Vantage | Names | Ch.39 records |
|---|---|---|
| root | **1052** | — |
| `shell` | **670** | 1053 (as *shell*) |
| app | **633** | 634 (as *app*) |

**37 shell-only names, 0 app-only.** DIVERGED, cause not established.

| Property | root | `shell` | app |
|---|---|---|---|
| `ro.debuggable` | `1` | `1` | **(empty)** |
| `ro.secure` | `1` | `1` | **(empty)** |
| `partition.system.verified` | `2` | `2` | **(empty)** |
| `ro.serialno` | set | set | **(empty)** |
| `qemu.sf.lcd_density` | `560` | `560` | **(empty)** |
| `ro.build.tags` | `dev-keys` | `dev-keys` | `dev-keys` |
| `ro.boottime.qemu-props` | set | **(empty)** | **(empty)** |

Three standard integrity properties are unreadable by the app. Written `"1".equals(get(p))`, the
check **fails open**.

---

## Measured: `ro.boot.verifiedbootstate` — four values

| Device | Property | Truth |
|---|---|---|
| Rooted Redmi (API 30) | `green` | TEE: `Unverified`, `deviceLocked=false`, all-zero key |
| Same, at source | `/proc/cmdline` = `orange` | Three fields forged; digest + veritymode honest |
| AVD (API 35) | **`""`** | No `androidboot.verifiedbootstate` in bootconfig |

```java
// WRONG -- passes on "", "" is not "orange"
return !"orange".equals(SystemProperties.get("ro.boot.verifiedbootstate"));
// RIGHT -- allow-list; note the argument order (null-safe)
return "green".equals(SystemProperties.get("ro.boot.verifiedbootstate"));
```

Still only a mitigation. The real fix is server-validated attestation.

---

## Measured: compiler folding (NDK 25.2.9519653, AArch64)

| Build | `strings \| grep xbin` | `.rodata` | `decode` size |
|---|---|---|---|
| `-O0` | *(nothing)* | ciphertext | 31 instructions |
| `-O2` | **`/system/xbin/su`** | **plaintext, no ciphertext** | **4 instructions** |

`__attribute__((noinline))` was present in both and changed nothing — it constrains the **inliner**,
not interprocedural constant propagation or function specialisation.

```bash
# both lines are required; the first alone passes for the wrong reason
llvm-strings -n 4 lib.so | grep -F "$SECRET"          # expect nothing
llvm-objdump -s -j .rodata lib.so | grep -iF "$CT"    # expect SOMETHING
```

---

## Measured: substring signatures

```
APKs containing 'xposed'            : 58 of 237
total occurrences                   : 1141
accounted for by 'exposed'/'Exposed': 1141
unexplained                         : 0
```

Rule: **never put a token under ~8 characters in a high-confidence tier.** False-positive rate
**rises** on better-obfuscated apps — R8 generates short lowercase identifiers.

---

## "If a detector agrees with you about a lot of samples, suspect the detector"

| Chapter | Claimed | Real |
|---|---|---|
| 38 | 18/18 self-signature checks | **13/18** |
| 52 | 17 HIGH leads | **15 rejected (88%)** |
| 64 | 16 STRONG `vxp` hits | **16/16 R8 class names** |
| 48 | Graded own reference files | **Backwards, twice** |

---

## Commands

<!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the "NEVER:" line below quotes the broken form as a counter-example; the two real root lines above it are correct and stay linted for portability -->
```bash
# instrument first -- always
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk

# root convention -- try BOTH; the wrong one reads as "not rooted"
adb shell "su -c id"        # physical devices, Magisk
adb shell "su 0 id"         # AOSP emulator

# NEVER: adb shell su -c 'cmd'   <-- broken; su eats the fragments

# three vantages
./scripts/vantage-diff.sh -p <pkg> --paths paths.txt
./scripts/vantage-diff.sh -p <pkg> --props
./scripts/vantage-diff.sh --find-package

# replay the chapter's cases
./scripts/case-replay.sh -s <serial> -p <pkg> --case all

# audit a written case study
python3 -B scripts/claim-ledger.py --strict case.md
python3 -B scripts/claim-ledger.py --self-test

# find the case-A idiom, including the tell-tale negation
grep -rn --include=*.smali -A6 'ro\.boot\.verifiedbootstate' out/ | grep -B2 'xor-int/lit8'

# count call sites without a regex you can get wrong
llvm-objdump -d lib.so | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

---

## Traps

| Trap | Fix |
|---|---|
| `adb shell su -c 'cmd'` | `adb shell "su -c 'cmd'"` or `su 0 cmd` | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- trap table: the "Trap" cell IS the wrong form, the "Fix" cell is the fix -->
| `su -c` on the AVD | `su 0 <cmd>` — `-c` reads as "not rooted" |
| `adb` inside `while read` | `< /dev/null` on every `adb` call |
| `set -o pipefail` + `head`/`grep -q` | Test content, not exit status |
| `grep 'bl.*<name>'` | `bl.*<name(@plt)?>` — PLT calls have a suffix |
| Empty output on a terminal | `\| cat -A` — distinguishes empty from failed |
| `frida -U` with two devices | Pin the serial; `-U` is "first USB-type enumerated" |
| Device-side `grep` over APKs | 16 of 250 DEX entries DEFLATED, all in `/data/app` — inflate first |
| NDK binary on a 16 KiB-page AVD | `-Wl,-z,max-page-size=16384`; without it, SIGSEGV 139 |
| `*/` inside a C block comment | Closes it early. Do not write globs in comments |
| Reading a count as stable | Timestamp it. Drift is proportional across vantages |

---

## Report language

| Do not write | Write |
|---|---|
| "Root detection bypassed" | "This check returns `false` on every rooted device; it provides no detection capability" |
| "Verified boot bypass" | "Client-side integrity check reads attacker-writable data" |
| "58 apps reference X" | "58 matched; all 1,141 occurrences explained; 0 genuine" |
| "Licence enforcement defeated" | "Patch verified in the file; behavioural difference not demonstrated" |
| "Hardcoded credential" | Name the value. Severity is what leaked, not how the mechanism sounds |

---

## Quick revision

- Two conditions collapse into `exists() == false` → `ENOENT`, `EACCES`
- Fields the hiding module did **not** forge → `vbmeta.digest`, `veritymode`
- Two mechanisms for "correct patch, no effect" → inlining, short-circuiting
- `noinline` constrains → the inliner, and nothing else
- Shell-only properties on the API 35 AVD → 37, incl. `ro.debuggable`, `ro.secure`
- Three verdicts → reproduced, diverged, not re-run
- A claim inherits → its **weakest** rung
- The one saving question → *"What would I expect to see if I were wrong?"*
