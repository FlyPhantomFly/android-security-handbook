# 72 — Real World Findings: cheat sheet

Printable. Tables and commands only.

---

## The three units

| Unit | Definition | Where it goes |
|---|---|---|
| **Observation** | A demonstrable fact about the app. No judgement in it | Working notes |
| **Lead** | An observation that might indicate a problem | Triage queue |
| **Finding** | A lead that survived adjudication: attacker, path, impact, severity | The report |

---

## The three gates

| Gate | Question | Fails when |
|---|---|---|
| **1 — Real?** | Is the observation even true? | The detector is broken, not the app |
| **2 — Reachable?** | Can a *named* attacker get to it? | Wrong vantage; no attacker in the threat model |
| **3 — Impact?** | Does anything of value follow? | Nothing behind it — the Informational gate |

Record the rejection reason. Rejection reasons become the next filter.

---

## Gate 1 — how detectors manufacture false positives

| Mechanism | Measured instance | Chapter |
|---|---|---|
| Substring collision | `grep -i xposed`: 1,141 occurrences, 1,141 = "exposed", **0 findings** | 64 |
| R8-manufactured collision | `vxp` signature: **16 STRONG hits, all 16 R8 class names** | 64 |
| Ingredient mistaken for dish | Self-signature detector hit **18/18**; corrected to **13/18** | 38 |
| Surface mistaken for config | **12/14** apps have a pinning surface; **4/14** pin | 36 |
| Shape mistaken for content | **132/132** secret hits were false positives | 33 |
| Constant folded away | `FLAG_SECURE` absent from `.class` **and** DEX; true-positive rate **zero** | 47 |

**Rules:** if a detector agrees about almost every sample, suspect the detector. Explain every hit or
the signature is not evidence. **Nothing under ~8 characters in a high-confidence tier** — and short-
token false positives get *worse* on better-protected apps.

---

## Gate 2 — the vantage rule

| Vantage | Measured difference | Chapter |
|---|---|---|
| root vs `shell` vs app | **~1062** / **~678** / **~638** properties. **Shell-to-app gap ~40; root-to-shell gap ~384.** `ro.boottime.*` (111 props) is invisible to shell *and* app | 39 |
| `shell` vs app | `/system/xbin/su` visible+setuid vs `Permission denied` (`0750 root:shell`) | 37, 59 |
| `shell` vs root | `locksettings clear` as uid 2000: *"device does not support lock screen"* — a **permission** failure disguised as a **capability** failure | 48 |
| app, either way | `new File("/data/adb/lspd").exists()` is `false` whether or not it exists (`ENOENT` and `EACCES` both map to `false`) | 63 |

`adb shell` privilege comes from the **`com.android.shell` package** — 200 permissions requested,
183 at install, **16 runtime permissions pre-granted `SYSTEM_FIXED`** — not from the shell GID,
which `platform.xml` grants only `INTERNET`.

> **A probe verified from `adb shell` has not been verified.**

---

## Attacker positions — name one, or drop the finding

| Position | Controls | Typical classes |
|---|---|---|
| Malicious co-installed app, no permissions | Its own process; Intents, binds, queries | F-01, F-07 |
| Network attacker on the path | Observe/modify traffic; maybe a trusted CA | F-04 |
| Hostile device owner, root | Everything on device | F-08 **only** |
| Brief physical access, unlocked | UI, ADB if enabled | F-02, F-11 |
| Backend attacker / other tenant | Server side | F-05 — usually out of scope |

---

## The finding classes

| # | Class | Typical real severity |
|---|---|---|
| F-01 | Exposed component surface | Info → Medium; High when it mutates state or leaks user data |
| F-02 | Insecure data at rest | Info → High, determined by *what* the data is |
| F-03 | Secrets / endpoints in the artefact | Low → High; almost always over-rated |
| F-04 | Transport and trust | Info → High |
| F-05 | Authentication and session logic | Medium → Critical — where the Criticals are |
| F-06 | Cryptographic misuse | Low → High; frequently theoretical |
| F-07 | WebView and content handling | Medium → High |
| F-08 | Resilience controls | **Info unless a named adversary is in the threat model** |
| F-09 | Third-party / supply chain | Info → High; hardest to remediate |
| F-10 | Privacy and data handling | Info → High |
| F-11 | Build and release hygiene | Info → Medium; occasionally Critical by accident |
| F-12 | Platform / device posture | **Usually not a finding about the app at all** |

---

## Severity — the four inputs

| # | Input | Question |
|---|---|---|
| 1 | Attacker | Which position, and is it in the threat model? |
| 2 | Preconditions | What must be true first, how plausible? |
| 3 | Gain | Specifically what data, state change, accounts? |
| 4 | Population | How many users, repeatable at scale? |

A rating that cannot name all four is a guess. Severity is **argued from the threat model**, never
looked up from a control.

### Inflation

| Mechanism | Corrective |
|---|---|
| Inherited from the class | Rate the instance |
| Attacker assumed, not named | Name a position or drop it |
| Root assumed for free | Root is a premise, not an attacker |
| Length mistaken for weight | Length measures your effort |
| Compensating controls ignored | Preconditions cut both ways |
| Prevalence mistaken for severity | One finding, N instances |

### Deflation

| Mechanism | Corrective |
|---|---|
| Stopped at the confidence ranking | The real one sat at MEDIUM 0.50 |
| Chain rated at its weakest link | Rate the chain, remediate the cheapest link |
| Discounted what you could not prove | *Untested* ≠ *absent* |
| Lost the server-side half | Informational **plus** an explicit gap |

---

## Corpus measurement — 243 packages, API 35 (chapter §3.5)

**Denominator first: 4 of 243 are third-party. Platform corpus. Supports nothing about commercial apps.**

| Stage | Components | Apps |
|---|---:|---:|
| 1. Declared exported | 2,674 | 137 |
| 2. …not signature/dangerous/internal guarded | 1,990 | 116 |
| 3. …no `<intent-filter>` | **410** | 67 |
| 4. …is a `ContentProvider` | **83** | 38 |

**Two mechanical steps shed 84.7% of the class.**

| Application-level class | Count | Adjudication |
|---|---:|---|
| `usesCleartextTraffic` absent | 196 / 243 | **195 target API 28+ where the default is already `false`** → ~99.5% FP |
| `allowBackup` absent | 176 / 243 | Counting the default reports **205 of 243** |
| `allowBackup` explicit `true` | 29 / 243 | Lead; depends on the backup set |
| `dataExtractionRules` (API 31+) | **5** / 243 | Barely used, even by platform apps |
| `networkSecurityConfig` | 10 / 243 | — |
| `sharedUserId` | 44 / 243 | Platform design decision |
| Custom permission at `normal` | 126 / 243 | Lead only — squatting needs a declare/use mismatch |
| `debuggable="true"` | **1** / 243 | **And it was the tester's own test app** |

| Implicit export | Count |
|---|---:|
| Components with `android:exported` absent | 313 / 6,465 |
| …of those, carrying an `<intent-filter>` | **0** |
| Apps targeting API 31+ | 237 / 243 |

**The class is extinct.** API 31 made it a build error. Delete the check.

---

## Provider reachability probe — 82 authorities, shell vantage

| Outcome | Count | Meaning |
|---|---:|---|
| REACHABLE — rows | 1 | Gate 2 passes; Gate 3 opens |
| REACHABLE — empty | 36 | Gate 2 passes; Gate 3 **untested** |
| REACHED — `query()` unimplemented | 22 | App code ran. **You are inside**, wrong verb |
| REACHED — threw something else | 2 | Same conclusion |
| REFUSED — framework denial | 8 | Gate 2 fails |
| INDETERMINATE — root not a path | 13 | Not a negative result |

**61 of 82 (74.4%) reachable in some form; 8 refused.** Shell vantage — not an app result.

### Read the exception, not the exit status

| Exception | Layer | Verdict |
|---|---|---|
| `SecurityException: Permission Denial` | `ContentProvider.enforceReadPermissionInner`, **before** the app runs | Outside |
| `UnsupportedOperationException` with app frames | The **app's own code** | Inside, wrong verb — still a lead |
| `No result found.` | Query executed, table empty | Reachable; Gate 3 untested |

---

## A provider has THREE guards

| Attribute | Gates |
|---|---|
| `android:readPermission` | `query()` |
| `android:writePermission` | `insert` / `update` / `delete` |
| `android:permission` | Both, unless overridden |

**A write guard with no read guard is readable by anybody.** Folding them into one field hides
exactly the case that matters for a read probe.

---

## Static-sweep blind spots, quantified

| Blind spot | Magnitude | Chapter |
|---|---|---|
| Runtime-registered receivers | **299 of 431 actions (69%)** have no manifest receiver | 29 |
| Code in splits | One app: **zero** controls in `base.apk` | 38 |
| Compressed DEX vs raw grep | **234 STORED / 16 DEFLATED**, all 16 in `/data/app` | 64 |
| Decompiler refusals | jadx console said **61**; tree held **2,104** refused methods | 56 |
| Constant folding | `FLAG_SECURE` in neither `.class` nor DEX | 47 |
| Native behind JNI | **12.9%** of `native` methods resolve to a symbol — quote only with its denominator | 68 |

---

## Grep patterns

```bash
# WORKS -- framework signatures survive minification
grep -rn "addJavascriptInterface\|setJavaScriptEnabled\|setAllowFileAccess" ./jadx-out/
grep -rn "getParcelableExtra" ./jadx-out/

# FAILS -- constant-folded, true-positive rate ZERO
grep -rn "FLAG_SECURE" ./jadx-out/

# FAILS -- 100% false positive ("exposed" contains it)
grep -rin "xposed" ./jadx-out/

# FAILS on minified apps -- collides with R8 identifiers
grep -rn "vxp" ./jadx-out/
```

**A pattern is usable if you can name, in advance, every category of thing that could match it.**

---

## Commands

```bash
# host -- identify the device BEFORE any version-gated claim
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk

# host -- corpus sweep with the funnel and every denominator
python3 -B scripts/manifest-corpus-sweep.py --from-device --out ./sweep-out
python3 -B scripts/manifest-corpus-sweep.py --manifest-dir ./sweep-out/manifests --funnel-only
python3 -B scripts/manifest-corpus-sweep.py --from-device --exclude com.you.testapp

# host -- read-only provider reachability, classified by refusing layer
python3 -B scripts/provider-reachability-probe.py --ledger ledger.json --json out.json

# host -- the canonical manifest read, and the AUTHORITATIVE one (the device)
aapt2 dump xmltree --file AndroidManifest.xml app.apk
adb shell dumpsys package com.example.target

# host -- an independent third reading, for when the two disagree
python3 -B ../10-APK-Internals/examples/parse_axml.py --extract app.apk --json

# host -- exercise components (read ALL of -W, not the exit code)
adb shell am start -W -n com.example.target/.SomeActivity
adb shell am broadcast -n com.example.target/.SomeReceiver --es key value
adb shell content query --uri content://com.example.target.provider

# host -- liveness, before any silence means anything
adb shell "dumpsys window | grep mCurrentFocus"
adb shell pidof com.example.target

# host -- before ANY trust-store claim
adb shell "mount | grep cacerts"

# Frida, in-process, the only trustworthy vantage
frida -U -f com.example.target -l scripts/component-reachability.js
```

---

## Command traps

| Wrong | Right | Why |
|---|---|---|
| `adb shell su -c 'cmd'` | `adb shell "su -c 'cmd'"`, or `su 0 cmd` on an AVD | Outer shell strips quotes; `su` eats the flag | <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- wrong/right table: the "Wrong" cell IS the wrong form -->
| `adb shell` in a `while read` loop | Add `< /dev/null` | `adb` inherits stdin and eats the loop's input |
| `set -o pipefail` with `head` / `grep -q` | Use `grep -c`, or a shell `case` glob | Early exit → SIGPIPE → spurious failure |
| Grading a run on exit status | Test the content | A real heap overflow presented as exit 0, silently |
| `Get-Content -Raw` + `Set-Content -Encoding UTF8` | Read/write bytes explicitly | Silently double-encodes; corrupted 11 files |
| `-Include` with `-LiteralPath` | `Where-Object` | `-Include` is silently ignored |

---

## Reporting units

| Property | Rule |
|---|---|
| Title | A specific claim, not a category |
| Rows | One per **root cause**, not per instance |
| Severity | Argued, four inputs named |
| Evidence | Reproducible by the developer on their own build |
| Preconditions | In the finding, not the methodology |
| Vantage | Stated wherever a runtime result is used |
| Not-tested | Stated explicitly; *untested* ≠ *absent* |
| Remediation | Code, aimed at the mechanism |
| Confidence | Stated separately from severity where they differ |

---

## Write-up rubric (10 binary points)

| # | Criterion | Fails when |
|---|---|---|
| 1 | Title is a specific claim | It is a category |
| 2 | Attacker position named | "An attacker could…" |
| 3 | Preconditions stated | They live in the methodology |
| 4 | Severity argued | Only a control ID justifies it |
| 5 | Evidence reproducible | "See screenshot" |
| 6 | Vantage stated | Shell result as an app result |
| 7 | Impact specific | "Sensitive information" |
| 8 | Not-tested stated | Untested consequence in the indicative |
| 9 | One finding per root cause | Eleven near-identical entries |
| 10 | Remediation is code at the mechanism | "Implement proper controls" |

Criteria **6** and **8** are the two most often lost, and the two that most increase trust.

---

## Statistics discipline

| Rule | Because |
|---|---|
| Denominator in the same sentence as the numerator | "60% of apps" is not a measurement |
| Never splice two runs | 16,836→168 and 17-HIGH came from **different runs** of the same tool |
| State the corpus composition | 4 of 243 third-party bounds every conclusion |
| Publish negative results with their N | 0 findings from 1,141 hits lets a reader delete a check |
| Coverage: name the denominator's source | 67% or 50% on identical evidence, depending who counts |
| Subtract your own instrumentation | The one `debuggable` hit was the tester's app |
| A funnel step is a definition | Write it down or you cannot check it |

---

## Quick verdicts

| Situation | Verdict |
|---|---|
| Scanner emitted thousands of hits | Mechanical adjudication first: dedupe by root cause, scope out library paths, apply platform defaults |
| Detector hits N of N apps | Suspect the detector |
| Attribute absent | Look up the default at the target's `targetSdkVersion` |
| Provider returned no rows | Gate 3 *untested*, not failed |
| Backend out of scope | Informational **plus** an explicit gap. Never "not a finding", never Critical |
| "The device can be rooted" | Test-environment record, not findings table |
| Found something you cannot exploit | *Untested*, not *absent* — say which |
| Unsure of a CVE identifier | Describe the class. Cite the bulletin month or nothing |
| Naming a vendor as vulnerable | Never. Describe the class, quantify the population, anonymise the instance |
