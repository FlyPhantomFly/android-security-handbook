# Annotated triage worksheet

This is a real queue, worked. The raw tool output it starts from is in
[`sweep-output-fridathree.txt`](sweep-output-fridathree.txt); the finished ledger is
[`findings-ledger.csv`](findings-ledger.csv). Read all three together — the point of the set is
that you can check every claim here against the unedited output.

**Target.** `com.mobilehackinglab.FridaThree`, a public MobileHackingLab training APK, pulled from a
Redmi `M2101K6P` (Android 11 / API 30) on 2026-08-12.
**Artefact.** `base.apk`, 5,785,227 bytes,
SHA-256 `37299c1488934e53e316a57bd0a0d9ea8145598888c193ebdfa77971eb611d49`. One path from
`pm path` — no splits.
**Tree.** jadx 1.5.3, 2,783 classes, `finished with errors, count: 17`, 1 min 57 s.

---

## 0. How to use this worksheet

One block per lead. Each block has the same six fields, and **the last two are the ones that matter**:

| Field | What goes in it |
|---|---|
| **Lead** | Exactly as the tool printed it. Do not paraphrase; a paraphrase loses the value |
| **Score** | The tool's terms. If you disagree with the number, say which term is wrong |
| **Q1 real?** | What you read, and where. Say "Smali" if you read Smali |
| **Q2 reachable?** | Closure result, hook result, or "not applicable" — and why |
| **Q3 who?** | The actor. "Anyone with ADB", "another app", "the network", "only the app" |
| **Q4 so what?** | The asset. **This is the severity.** If you cannot name an asset, the answer is Informational |
| **Verdict** | FINDING / INFORMATIONAL / REJECTED / DEFERRED |
| **Reason** | One sentence. **Required even for FINDING** — it is what a reviewer reads first |

Work the queue **top down, including the leads you expect to reject.** Rejecting L007 takes forty
seconds and produces a line that makes the whole report more credible. Skipping it produces nothing.

---

## 1. Summary of the run

```
files scanned      3655   (app 3, third-party 2759, generated 42, resource 850, unknown 1)
raw hits           7346
killed by validators 3591
distinct leads     9
demoted as noise   4
blind-spot notices 2
aggregation ratio  816.2x
```

**Read the file classification line before anything else.** Three files out of 3,655 are the
application's own code. That single fact predicts most of what follows: any lead whose sites are all
outside those three files is about a library, not about this app.

---

## 2. The queue, worked

### L001 — `android:debuggable="true"`

```
L001  [HIGH 0.90]  DBG-01  (debug)
  what      debuggable flag in a manifest
  value     android:debuggable="true"
  sites     1 occurrence(s) in 1 file(s); 1 in app code
            resources/AndroidManifest.xml:21  [app]
  score     rule DBG-01 precision (+0.55); in the app's own package (+0.25);
            single site, in app code (+0.10)
```

| | |
|---|---|
| **Q1 real?** | Yes. `apktool` and `aapt2 dump xmltree` agree; the attribute is on `<application>` |
| **Q2 reachable?** | Not applicable — a process attribute, not code. Recorded as N/A rather than left blank |
| **Q3 who?** | Anyone with ADB access to an unlocked device: a malicious charger or kiosk, a thief, a colleague, an enterprise fleet with USB debugging enabled |
| **Q4 so what?** | The app's entire private data directory, plus process memory over JDWP. The sandbox boundary the platform exists to hold |
| **Verdict** | **FINDING** |
| **Reason** | Confirmed by the platform, not just by the file: `dumpsys package … flags=[ DEBUGGABLE … ]`. The `run-as` demonstration below is the next step and was **not** executed for this worksheet — the test device was disconnected first, and that is recorded rather than glossed |

**Evidence gathered:**

```bash
# adb shell
dumpsys package com.mobilehackinglab.FridaThree | grep 'flags='
# flags=[ DEBUGGABLE HAS_CODE ALLOW_CLEAR_USER_DATA ALLOW_BACKUP ]

# host
adb shell run-as com.mobilehackinglab.FridaThree ls -la /data/data/com.mobilehackinglab.FridaThree
```

> **Why this one took four minutes and not forty.** The next step printed by the tool named the exact
> confirming command. Leads with a next step get worked; leads without one get skipped.

---

### L002 — a base64 literal in app code

```
L002  [HIGH 0.65]  CRED-09  (credential)
  what      long base64-looking literal
  value     TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==
  sites     1 occurrence(s) in 1 file(s); 1 in app code
            sources/com/mobilehackinglab/FridaThree/MainActivity.java:50  [app]
  score     rule CRED-09 precision (+0.30); in the app's own package (+0.25);
            single site, in app code (+0.10)
```

| | |
|---|---|
| **Q1 real?** | Yes, and confirmed in bytecode, not just in decompiled Java: `dexdump -d classes3.dex` shows `const-string v0, "TUhM…" // string@002b` followed by `Base64$Decoder.decode` |
| **Q2 reachable?** | Yes, at depth 0: the holding class `MainActivity` is itself declared in the manifest and is `exported="true"` with a LAUNCHER filter |
| **Q3 who?** | Anyone who installs the app — but display is gated on `Checker.getCode() == 256` |
| **Q4 so what?** | Decodes to `MHL{MODIFIED_VARIABLE}`, a string the application displays on screen. **It protects nothing** |
| **Verdict** | **INFORMATIONAL** |
| **Reason** | Encoding is not encryption; the value is recoverable in one command, but it is a UI string rather than a credential. Reported as an observation, not a finding |

**Evidence gathered:**

```bash
echo 'TUhMe01PRElGSUVEX1ZBUklBQkxFfQ==' | base64 -d
# MHL{MODIFIED_VARIABLE}
```

> **The interesting part is the gap between Q1 and Q4.** Every automated check passes: real literal,
> app code, reachable class, high confidence. And it is still not a finding, because question four
> has no asset behind it. A report that writes this up as "hardcoded secret" is wrong in a way that
> reviewers notice immediately.
>
> Note also what static analysis *missed* here and dynamic analysis would have caught: the value is
> only displayed after a counter reaches 256. Static recovered the secret and never observed the
> gate; the intended solution to this training exercise is a Frida hook that never needs the string
> table at all. Neither method is complete.

---

### L003 — `http://schemas.android.com/apk/res/android`

```
L003  [LOW 0.30]  NET-01  (endpoint)
  sites     627 occurrence(s) in 627 file(s); 1 in app code
  score     rule NET-01 precision (+0.75); in the app's own package (+0.25);
            value appears in 627 distinct files (-0.25);
            known-noise: matches the known-constant list (schemas.android.com) (-0.45)
```

| | |
|---|---|
| **Q1 real?** | The string is present, yes |
| **Q2 reachable?** | Irrelevant — it is an XML namespace declaration, never dereferenced |
| **Q3 who?** | Nobody |
| **Q4 so what?** | Nothing |
| **Verdict** | **REJECTED** |
| **Reason** | XML namespace URI, not an endpoint. Present in 627 of 3,655 files; the app never contacts it |

> **Why it appears at all, and why that is correct.** `http://` is a format-class rule with base 0.75,
> and format rules are the ones you act on. The noise list and the file-count penalty pulled it down
> to 0.30, and `--show-suppressed` is the only reason it is visible in this run. Leaving it *visible*
> under a flag rather than deleting it is deliberate: a filter you cannot audit will one day eat a
> real finding and never tell you.

---

### L004 — legacy external storage path

```
L004  [LOW 0.10]  STO-02  (storage)
  value     <legacy external storage path>
  sites     2 occurrence(s) in 2 file(s); 0 in app code
```

| | |
|---|---|
| **Q1 real?** | Yes — two `Environment.getExternalStorage…` call sites, in `androidx/core/content/FileProvider.java:235` and `androidx/core/os/EnvironmentCompat.java:24` |
| **Q2 reachable?** | Not investigated. Stopped at Q1's location check |
| **Q3–Q4** | Not reached |
| **Verdict** | **REJECTED** |
| **Reason** | Zero sites in app code; both are AndroidX internals handling shared-storage compatibility. Would be reconsidered only if the app's own code called into that path with sensitive data |

> **Kill-list question 1 answered it and nothing else was needed.** This is the normal case, and it
> takes under a minute per lead. The temptation is to skip writing the line down because the answer
> was obvious; do not, because "obvious" is not a reason a reviewer can check.

---

### L005 — log calls with a variable message

```
L005  [LOW 0.05]  DBG-02  (debug)
  value     <log call whose message is a variable>
  sites     18 occurrence(s) in 12 file(s); 0 in app code
            sources/androidx/appcompat/app/AppLocalesStorageHelper.java:104  [third-party]
            sources/androidx/constraintlayout/motion/widget/MotionLayout.java:608  [third-party]
```

| | |
|---|---|
| **Q1 real?** | Yes, 18 call sites |
| **Q2 reachable?** | Not investigated |
| **Verdict** | **REJECTED** |
| **Reason** | All 18 sites are AndroidX and ConstraintLayout framework logging. The application's own three classes contain no `Log` calls at all |

> **This is a construct-class lead, aggregated by construct rather than by value.** Without that
> aggregation this row would have been eighteen separate leads, which is how a nine-item queue
> becomes a twenty-six-item queue that nobody finishes.

---

### L006 — `printStackTrace`

```
L006  [LOW 0.05]  DBG-04  36 occurrence(s) in 15 file(s); 0 in app code
```

| | |
|---|---|
| **Verdict** | **REJECTED** |
| **Reason** | Framework and library exception handling; zero sites in app code |

---

### L007, L008 — two more `schemas.android.com` namespaces

```
L007  [LOW 0.05]  NET-01   http://schemas.android.com/aapt          60 files, 0 in app code
L008  [LOW 0.05]  NET-01   http://schemas.android.com/apk/res-auto  40 files, 0 in app code
```

| | |
|---|---|
| **Verdict** | **REJECTED** (both) |
| **Reason** | Namespace URIs from the resource toolchain; zero sites in app code |

> Two leads, one reason, thirty seconds. Group rejections that share a reason — but keep the lead IDs
> separate in the ledger so the arithmetic still adds up.

---

### L009 — `127.0.0.1`

```
L009  [LOW 0.05]  NET-03  1 occurrence in 1 file; 0 in app code
```

| | |
|---|---|
| **Q1 real?** | Yes, in `androidx/constraintlayout/core/motion/utils/Utils.java:25` |
| **Q2 reachable?** | Library internals only |
| **Verdict** | **REJECTED** |
| **Reason** | Loopback literal inside ConstraintLayout's `Utils`; on the known-noise list, and not in app code. A loopback address is only interesting when the app *listens* on it, which would show as a `ServerSocket` — none present |

---

## 3. Blind spots recorded

```
BLIND-01  receiver registered at runtime
    12 occurrence(s) across 3 file(s); none in app code
BLIND-02  reflective dispatch
    across 313 file(s); none in app code
```

**Neither is in the application's own code.** That is an unusually good position and it is worth
saying explicitly in the report, because the usual position is the opposite:

> The application's own code does not register broadcast receivers at runtime and does not use
> reflection. Both mechanisms appear only in bundled framework libraries. Consequently, for this
> application, the usual static-analysis blind spot around runtime broadcast registration — measured
> at 69% of the broadcast surface on a comparable device — does not apply to the application's own
> logic. It does still apply to the libraries it bundles.

`BLIND-03` (runtime DEX loading), `BLIND-04` (native code), `BLIND-05` (remote config) and
`BLIND-06` (executable assets) did **not** fire. Verified independently rather than trusted:

```bash
grep -rl 'DexClassLoader' out/sources/ | wc -l     # 0
grep -rl 'loadLibrary'    out/sources/ | wc -l     # 0
unzip -l base.apk | grep -c 'lib/'                 # 0
```

---

## 4. The arithmetic

| | Count |
|---|---|
| Raw hits | 7,346 |
| Killed by rule validators before a human looked | 3,591 |
| Distinct leads presented | 9 |
| Worked by hand | 9 |
| **Findings** | **1** |
| Informational | 1 |
| Rejected | 7 |
| Deferred to dynamic analysis | 0 |

**Time:** about twenty minutes of human work after the decompile finished.

**Rejection rate: 78%.** That is a *healthy* number on a small, clean app. On the commercial
application in [README §9.4](../README.md#94-real-application--the-false-positive-arithmetic-measured)
the equivalent rate in the high-confidence band alone was 88%.

---

## 5. What this worksheet would look like if it were done badly

The same run, triaged by someone who does not distinguish leads from findings:

> **Findings: 9.** Hardcoded secret (base64 credential in `MainActivity`), debuggable application,
> **three cleartext HTTP endpoints**, external storage usage, sensitive data in logs, information
> disclosure via stack traces, hardcoded IP address.

Every one of those phrases is traceable to a line the tool printed. Seven of the nine are wrong, one
is inflated from Informational to "hardcoded secret", and one is correct. That report will be
returned by any competent reviewer, and the returned report is the *good* outcome — the bad outcome
is that it is not returned, and the client spends a sprint on three XML namespace declarations.

**The difference between that report and this worksheet is not skill or tooling. It is stage 7.**
