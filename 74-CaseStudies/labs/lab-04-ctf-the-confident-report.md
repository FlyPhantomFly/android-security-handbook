# Lab 04 — CTF: The Confident Report

> **Level:** Advanced · **Time:** 3–4 hours · **Needs:** nothing. No device, no tools, no network.
> This is pure adjudication.

---

## The premise

You have inherited a penetration test report. The tester has left the company. A client is waiting
for it, your name will go on it, and the delivery deadline is tomorrow.

The report contains **six findings**. It is well written, internally consistent, and confident. Every
measurement in it is *real* — nothing has been fabricated.

**Three of the six do not survive adjudication.**

Your job is to find which, say precisely why, and rewrite the report so that what ships is defensible.

> **⚠️ Scoring is inverted, and that is the whole exercise.**
> You gain points for **correct rejections** and lose them for **wrong ones**. There is a flag, and
> it is possible to assemble the flag and still score zero. If your instinct is to hunt for the flag
> first, notice that instinct — it is exactly the instinct that puts three bad findings in front of a
> client.

---

## Provenance — read this before anything else

**This report is COMPOSED. It is a constructed artefact, not a captured one.**

`SmartVault Retail Ltd` and `com.svr.wallet` **do not exist**. Every *measurement* in the report is
real and is drawn from this repository's own recorded work; they have been reassembled around a
fictional target and given a fictional narrator. No real vendor, application or company is described
here, and none should be inferred.

That labelling is not a disclaimer, it is the lab's first lesson. A case study composed from separate
measurements is a legitimate artefact; **one that does not say so is not.** Chapter 74 §1.5 makes this
a rule, and you are about to be shown why: the report below reads like one continuous engagement, and
part of what is wrong with it is that it was not.

---

# ═══════════════════════════════════════════════════════════
# THE REPORT
# ═══════════════════════════════════════════════════════════

**Client:** SmartVault Retail Ltd
**Target:** `com.svr.wallet` (Android), version 4.2.1
**Engagement:** Authorised mobile application assessment
**Tester:** *(departed)*

## Executive summary

The application exhibits **systemic weaknesses in its device-integrity and anti-tampering controls**,
and leaks internal infrastructure. We rate the overall posture **High risk**. Six findings are
detailed below, of which four are High severity.

---

### Finding 1 — Root detection bypass (HIGH)

The application performs root detection by probing filesystem paths. On our rooted test device we
confirmed the check can be defeated.

**Evidence.** Decompilation shows:

```java
private static final String[] R = {"/data/adb/lspd", "/data/adb/magisk",
                                   "/system/xbin/su", "/sbin/su"};
public static boolean isRooted() {
    for (String s : R) { if (new File(s).exists()) return true; }
    return false;
}
```

We ran the application on a rooted device (Magisk 30.7) and it **did not detect root**. The check is
therefore bypassable and an attacker can run the wallet on a compromised handset.

**Remediation.** Expand the path list, and add checks for the Magisk daemon and the `su` binary in
additional locations.

---

### Finding 2 — Verified boot check trivially defeated (HIGH)

The application reads `ro.boot.verifiedbootstate` and accepts any value other than `orange`.

```java
return !"orange".equals(SystemProperties.get("ro.boot.verifiedbootstate"));
```

**Evidence.** On our rooted test device the property read `green` while a TEE-signed key attestation
taken on the same device seconds later reported `verifiedBootState=Unverified`, `deviceLocked=false`
and an all-zero `verifiedBootKey`. The kernel command line for the same boot carried
`androidboot.verifiedbootstate=orange`. Separately, on an emulator the property is the empty string,
and the check passes.

**Remediation.** The property is not authenticated and the source that would reveal the rewrite
(`/proc/cmdline`) is unreadable to the application. Move the decision server-side using key
attestation and validate `rootOfTrust` there. If retained client-side, allow-list `"green"`.

---

### Finding 3 — Hooking framework in widespread use across the device estate (HIGH)

To assess the client's exposure we swept the applications present on a representative device.

**Evidence.**

```
APKs scanned                           : 237
APKs containing the substring 'xposed' : 58
```

**58 of 237 applications (24%) reference the Xposed hooking framework.** This represents a
substantial supply-chain and device-integrity risk to the client's user base.

**Remediation.** Implement Xposed detection in the wallet application and refuse to run alongside a
hooking framework.

---

### Finding 4 — Hardcoded credential path in the native library (MEDIUM)

`libsvrcrypto.so` contains an obfuscated string that decodes to a sensitive filesystem path.

**Evidence.** The library XOR-encodes strings at build time. Running `strings` on the shipped
`arm64-v8a` library returns the plaintext directly:

```
$ llvm-strings -n 4 libsvrcrypto.so | grep xbin
/system/xbin/su
```

The obfuscation is defeated by the compiler: at `-O2`, clang evaluates the decode loop at compile
time and stores the plaintext in `.rodata`. The ciphertext array is absent from the shipped binary
entirely. A build of identical source at `-O0` does not exhibit this.

**Remediation.** The value must not be a compile-time constant. Note that
`__attribute__((noinline))` on the decoder does **not** prevent this — it constrains the inliner,
while the transformation here is interprocedural constant propagation and function specialisation.
Derive the value at runtime, or accept that it ships in plaintext.

---

### Finding 5 — Licence enforcement can be removed with a four-byte patch (HIGH)

The native licence check can be neutralised.

**Evidence.** We located `svr_verify_license` in `libsvrcrypto.so` and patched it to
`mov w0, #1; ret` (`20 00 80 52 c0 03 5f d6`). We confirmed the patch in place:

```
    4854: 20 00 80 52   mov   w0, #1
    4858: c0 03 5f d6   ret
```

The patch was verified present with `llvm-objdump`. **Licence enforcement is therefore defeated** and
premium functionality can be unlocked without payment.

**Remediation.** Move licence validation server-side.

---

### Finding 6 — Non-production infrastructure enumerated in the shipped build (MEDIUM)

Static analysis of the application recovered an enumeration of internal environments.

**Evidence.** A scan produced 16,836 raw matches, which the validator reduced to 168 leads. Manual
adjudication of the 17 high-confidence leads rejected 15 of them (88%) as documentation links, UI
preview fixtures, an XML namespace and marketing URLs. **The most significant result was not in the
high-confidence band.** At confidence 0.50 the scan surfaced a `Domain` enum in application code
enumerating **thirteen environments** — production, pre-production, eight QA hosts and three staging
hosts — in the shipped production build.

**Remediation.** Strip non-production endpoints from release builds. Note that internal hostnames
disclose infrastructure naming and reduce the cost of reconnaissance against the client's estate.

---

# ═══════════════════════════════════════════════════════════
# YOUR TASK
# ═══════════════════════════════════════════════════════════

## Round 1 — Adjudicate

For **each** of the six findings, produce:

| Field | |
|---|---|
| **Verdict** | SURVIVES / REJECT / REWRITE |
| **Why** | The specific defect, or why it holds |
| **Severity** | Yours, if it survives |
| **What is missing** | The evidence you would need to make it defensible |

Do this before reading anything below. Give yourself forty minutes.

## Round 2 — The four defects

Chapter 74 §8.2 names four defects a written case study can carry. Map each to any findings it
applies to:

| Defect | Applies to finding(s)? |
|---|---|
| The tidy narrative | |
| The absent vantage | |
| The unlabelled composite | |
| The count with no denominator | |

## Round 3 — Rewrite

Rewrite the executive summary and the surviving findings so a client could act on them.

---

# ═══════════════════════════════════════════════════════════
# SCORING
# ═══════════════════════════════════════════════════════════

| | Points |
|---|---|
| Each of the three bad findings correctly rejected **with the right reason** | **+3** each |
| Correct rejection, wrong or vague reason | +1 |
| A **good** finding rejected | **−3** |
| Each of the three good findings correctly retained | +1 each |
| Correcting the executive summary's severity inflation | +2 |
| Identifying the defect that applies to the report as a whole | +2 |
| Assembling the flag | +1 |

**Maximum: 21. Passing: 14.** A perfect flag with no adjudication scores **1**.

---

# ═══════════════════════════════════════════════════════════
# THE ANSWER KEY — do not open until you have written all six verdicts
# ═══════════════════════════════════════════════════════════

<details>
<summary><b>Finding 1 — REJECT. Flag fragment: <code>CH74{n0t_a_byp4ss</code></b></summary>

**The defect: the absent vantage, and a conclusion that inverts the evidence.**

The tester ran the application on a rooted device, observed no detection, and concluded the check is
**bypassable**. The evidence supports a stronger and completely different statement: **the check
never functioned.**

`/data/adb` is mode `0700 root:root`. An application probing `/data/adb/lspd` or `/data/adb/magisk`
receives `EACCES` **at the parent directory**, above the leaf. `java.io.File.exists()` maps `ENOENT`
and `EACCES` alike to `false`. So the check returns `false` on every rooted device — the only
population it was written for. `/system/xbin/su` behaves identically for an application, because
`/system/xbin` is `0750 root:shell`: visible to `adb shell`, invisible to an app.

The report never states **which uid** the observation was made from, which is the absent-vantage
defect. And the remediation is actively harmful: *"expand the path list"* adds more paths beneath the
same unreadable parent. Every one will also return `false`. The client would spend effort and change
nothing.

**Correct finding:** *Root-detection routine is non-functional* — **Low / Informational**. There is
no control to bypass. Remediation is to remove it or replace it with signals reachable from an
application uid, such as `/proc/self/mountinfo` mount sources.

**Why this is worth 3 points:** "bypass" invites the developer to add more checks. "Non-functional"
cannot be answered that way. The difference is the entire value of the finding.

</details>

<details>
<summary><b>Finding 2 — SURVIVES. Flag fragment: <code>_th3_c0unt_w4s</code></b></summary>

Retain it, essentially as written. This is what a good finding looks like, and it is instructive to
see why:

- **Two independent sources**, one of which — a TEE-signed attestation — the attacker could not have
  produced.
- **A third source**, the kernel command line, showing the forgery directly.
- **A second device** demonstrating a distinct failure (the empty string) that the same code path
  mishandles.
- **A structural remediation**, naming why the client-side check cannot work rather than only that it
  did not.
- **It states why the cross-check is unavailable to the app**, which is what makes this a design
  finding rather than an implementation bug.

The only change worth making is severity. **High** overstates it: nothing was bypassed, and no
attacker gains anything they did not already have on a device they already control. **Medium, as a
design finding**, is defensible — the control provides no assurance, and the fix is architectural.

Rejecting this one costs you 3 points, and it is the most commonly rejected of the six by readers who
have just been told to be sceptical. **Scepticism applied uniformly is not adjudication.**

</details>

<details>
<summary><b>Finding 3 — REJECT. Flag fragment: <code>_z3r0_</code></b></summary>

**The defect: a count with no denominator and no adjudication. This is the worst finding in the
report.**

`grep -i xposed` matches the English word **"exposed"**.

The real audit over that same 237-APK corpus:

```
APKs containing the substring 'xposed' : 58
total 'xposed' occurrences             : 1141
accounted for by 'exposed'/'Exposed'   : 1141
unexplained                            : 0
```

**The arithmetic closes exactly. 1,141 hits, 1,141 explained, zero genuine.** Verified per-application
before the corpus was even swept: one browser at 4 and 4; one settings package at 113 against 15 + 98;
one Play-services package at 30 against 15 + 15.

The measured result for that corpus is that **zero of 237 applications contain Xposed-detection or
Xposed-framework code.** The single strong hit was a root manager naming a module it interoperates
with — correctly flagged, correctly dismissed.

Three further defects compound it:

1. **The corpus is wrong for the claim.** Those 237 APKs are everything installed on a stock image;
   only four are third-party. A claim about "the client's device estate" cannot rest on it.
2. **The scope is wrong.** The engagement is one application. Sweeping the device's other
   applications is not in scope and the results are not the client's to act on.
3. **The remediation contradicts the rest of the report.** It recommends adding a detection check of
   exactly the kind Finding 1 shows does not work.

**Correct handling: delete it.** Not downgrade — delete. A number wrong in every digit is not a
low-severity finding.

</details>

<details>
<summary><b>Finding 4 — SURVIVES, with one correction. Flag fragment: <code>f1nd1ngs</code></b></summary>

The **mechanism** is real, well described, and unusually well remediated — including the `noinline`
caveat, which most testers get wrong.

The problem is **severity, and what the secret actually is.**

The leaked string is `/system/xbin/su`. That is a **detection path constant**, not a credential. It
is a well-known public path that appears in every root-detection tutorial ever written. Learning that
the application probes it costs an attacker nothing — they would assume it anyway.

The finding is titled *"Hardcoded credential path"*, which implies a secret. It is not one.

**Correct handling: retain, downgrade to Informational**, and retitle to something like *"Compile-time
string obfuscation is ineffective in release builds"*. The value of the finding is the **mechanism** —
it tells the client that *every* string they think they have obfuscated is in plaintext in the shipped
binary, including any that genuinely are sensitive. Framed that way it is worth reading. Framed as a
leaked credential it is an inflated finding that will be dismissed, taking the real lesson with it.

**Severity is whatever the leaked value is worth, not whatever the mechanism sounds like.**

</details>

<details>
<summary><b>Finding 5 — REJECT. Flag fragment: <code>_but_th3_r3p0rt</code></b></summary>

**The defect: it proves the wrong proposition.**

Read the evidence again. Every word is true:

- `svr_verify_license` was patched to `mov w0, #1; ret`. **True.**
- The patch was confirmed in place with `llvm-objdump`. **True.**
- The bytes are correct. **True.**

And the conclusion — *"licence enforcement is therefore defeated"* — **does not follow from any of
it.**

`objdump` reads the **file**. What was proved is that the file changed. Nobody cares whether the file
changed. The proposition that matters is *the program behaves differently*, and **the report contains
no behavioural evidence at all.** No before-and-after output. No demonstration that premium
functionality unlocked. Nothing was run.

That gap is not pedantry. This repository has measured two separate mechanisms that make a
verified-correct patch do nothing:

| Mechanism | Tell |
|---|---|
| The check is **short-circuited** by an earlier guard | The caller exists; reading it shows an earlier call and a conditional branch. Measured: a licence gate where an upstream root probe returned first, so the patched function was never reached — and where **the correct key alone also failed** |
| The check was **inlined**, so the standalone copy is dead | The function has few or no callers, yet the logic clearly runs. Measured: a function patched to return 1, *observably* returning 1, while the dependent operation still refused |

Either would produce exactly this report.

**Correct handling: reject pending evidence.** Not "reject because it is wrong" — it may well be
right. Reject because **it is not demonstrated**, and say what would demonstrate it: a truth table
across patched and unpatched binaries with both a valid and an invalid key, showing the outputs
differ.

**A verified patch is evidence that you changed the file. Prove a behavioural difference or you have
proved nothing about the program.**

</details>

<details>
<summary><b>Finding 6 — SURVIVES. Flag fragment: <code>_sc0r3d_z3r0}</code></b></summary>

Retain it. This is the best finding in the report and the tester nearly buried it.

Notice what it does that Finding 3 does not:

- **It states the denominator** at every stage: 16,836 raw, 168 leads, 17 high-confidence.
- **It reports its own rejection rate honestly** — 15 of 17, 88% — and names the rejection reasons.
- **It says the best result was not in the high-confidence band**, which is the finding *about the
  method* and is worth as much as the finding about the application.
- **It gives concrete impact** rather than gesturing at risk.

Thirteen environments in a shipped production build is a genuine disclosure: it names internal
hosts, reveals the client's environment naming scheme, and hands a reconnaissance shortcut to anyone
who unzips the APK.

**Medium is right.** Not High — no credential leaked, no access granted. Not Low — the infrastructure
disclosure is real and actionable.

> **Confidence orders your queue; it does not rank importance.** A confidence score answers "how
> likely is this to be what my rule was looking for", which is a question about the rule. Severity
> answers "how much does this matter", which is a question about the business. Sorting by the first
> and reporting from the top is exactly how this finding gets missed.

</details>

<details>
<summary><b>The report-level defects, and the executive summary</b></summary>

**Defect: the unlabelled composite (+2).**

The report reads as one continuous engagement against one application. It is not. Finding 2's
evidence spans **a rooted phone and an emulator**. Finding 3 is a sweep of **237 unrelated
applications**. Finding 4 compares **two builds of a library**. Finding 6 is a static scan of a
decompiled tree.

None of that is illegitimate. **Not saying so is.** A reader cannot tell which device produced which
number, and therefore cannot check any of it. Every finding needs its device, its vantage, its
command and its date.

**Defect: the tidy narrative.** Six findings, six confident conclusions, not one recorded dead end,
not one rejected hypothesis, and — apart from Finding 6 — no acknowledgement that anything was ever
uncertain. Finding 6 is the only one that shows its own rejection rate, and it is the only one that
is unambiguously sound. That correlation is not a coincidence.

**The executive summary (+2).** *"Six findings, of which four are High"* becomes, after adjudication:

| Finding | Reported | Adjudicated |
|---|---|---|
| 1 Root detection | HIGH | **Low / Informational** (non-functional, not bypassed) |
| 2 Verified boot | HIGH | **Medium** (design) |
| 3 Xposed prevalence | HIGH | **Deleted** |
| 4 String obfuscation | MEDIUM | **Informational** (retitled) |
| 5 Licence patch | HIGH | **Withdrawn pending evidence** |
| 6 Non-production hosts | MEDIUM | **Medium** |

Four High becomes **zero High**. "Systemic weaknesses… High risk" is not supportable. The honest
summary is that the application's device-integrity controls **do not function**, which is a real and
worth-reporting condition — and a different one from being defeated.

</details>

<details>
<summary><b>The flag</b></summary>

```
CH74{n0t_a_byp4ss_th3_c0unt_w4s_z3r0_f1nd1ngs_but_th3_r3p0rt_sc0r3d_z3r0}
```

If you assembled it without adjudicating, you scored **1 out of 21**. That is the lab.

</details>

---

## Debrief

Three defects, one per rejected finding, and each has appeared in real published work in this
repository's own measurements:

| Finding | Defect | The one-line rule |
|---|---|---|
| 1 | Concluded "bypassed" where the evidence said "never worked" | **A non-functioning control has nothing to bypass** |
| 3 | A count with no denominator and no adjudication | **Explain every hit, or the signature is not evidence** |
| 5 | Proved the file changed, claimed the program changed | **A verified patch is not a behavioural result** |

And three about the ones that survived, which are harder to internalise:

- **Finding 2 is good and gets rejected most often**, by readers who have correctly learned to be
  sceptical and then applied scepticism uniformly. Uniform scepticism is not adjudication; it is the
  same failure as uniform credulity, with better manners.
- **Finding 4 has a real mechanism and a wrong title.** Severity attaches to the value that leaked,
  not to how impressive the mechanism sounds.
- **Finding 6 is the best work in the report and sat at confidence 0.50.** A tester who sorts by
  confidence and writes up the top band misses it entirely.

> **🧠 Mental Model — the question to ask of every finding you inherit or write.**
> *"What is the weakest rung this claim stands on?"* A claim inherits the strength of its weakest
> evidence, not its strongest. Finding 5's strongest evidence is excellent — verified bytes,
> correct encoding, clean disassembly — and its weakest rung is that **nothing was ever run.**

---

## Extension — do it to your own work

Take a report or write-up **you** produced in the last year. Run:

```bash
# host
python3 -B ../scripts/claim-ledger.py --strict your-report.md
```

Then adjudicate it yourself against the six-finding rubric above. The uncomfortable version of this
lab is the one where the report is yours.

---

## Related

| Chapter | Why |
|---|---|
| [72-RealWorldFindings](../../72-RealWorldFindings/README.md) | Finding classes, severity distributions and base rates — what a finding *should* look like |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The framework and identifiers for a real report |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Owns Finding 6's real measurement, and `lab-04-ctf-honest-report.md`, which scores the same way from the other end |
| [64-Xposed](../../64-Xposed/README.md) | Owns Finding 3's real audit |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | The evidence ladder Finding 5 falls off |
