# Lab 02 — The take-home, with the grader's rubric

> **Difficulty:** Intermediate → Senior
> **Time:** 3 hours for the exercise, capped. 1 hour for self-marking.
> **Prerequisites:** a working static and dynamic toolchain (jadx or apktool, `adb`, ideally
> Frida), and an emulator or device **you own**.
> **Constraint:** a hard three-hour cap, a fixed deliverable format, and a rubric you do not
> read until you have submitted.

---

## 1. Why this lab exists

The take-home is the only stage of a hiring process that observes your **artefact** rather
than your conversation, and it is the stage candidates practise least. It is also the stage
where the gap between what the brief says and what the grader marks is widest
([README §3.11](../README.md#311-the-take-home-what-is-graded-and-what-is-actually-graded)).

The brief will say: find and report the vulnerabilities. The grader will mark: whether your
method is stated, whether your severities are defensible, whether you distinguished a lead
from a finding, and whether a developer could act on what you wrote. Finding count is close to
uncorrelated with the outcome.

This lab gives you the exercise, the cap, the deliverable format, and — afterwards — **the
rubric the grader would have used**, so you can mark your own submission before anyone else
does.

> **⚠️ Do not read section 6 until you have submitted.**
> The rubric is the answer key. Reading it first turns this into a copying exercise and
> destroys the only measurement that matters, which is what you produce unprompted.

---

## 2. Authorisation — read this before you pick a target

**You may only test an application you are authorised to test.** For this lab that means one
of exactly two things:

1. **An intentionally vulnerable application** published by its authors for this purpose. Four
   are listed in section 3.1. Their licences and their READMEs authorise exactly this use.
2. **An application you wrote yourself**, running on a device you own.

It does **not** mean an app from the store because it is publicly downloadable. Public
availability is not authorisation, and this distinction is not academic: it is the same
distinction that makes a real hiring take-home a legal problem when it hands you a named
third-party application
([README §5.2](../README.md#52-the-take-home-that-is-unpaid-work-or-worse)).

If a real employer's take-home hands you a real third-party app, the correct move is to raise
it, and in a well-run process raising it is a passing answer. The wording that works is in
README §5.2.

**Device hygiene for this lab:**

- Use an emulator or a spare device. Not a daily driver.
- Everything you push goes under `/data/local/tmp/lab02/` so cleanup is one command.
- Uninstall the target and remove your workspace when you finish (section 8).

---

## 3. The exercise

### 3.1 Choose a target

Any one of these. They are intentionally vulnerable, published for training, and already used
elsewhere in this repository:

| Target | Character | Good for practising |
|---|---|---|
| [OVAA](https://github.com/oversecured/ovaa) — Oversecured Vulnerable Android App | broad, modern, many component-level issues | exported components, deep links, IPC |
| [InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) | a plausible banking-app shape | storage, credentials, logging, weak crypto |
| [DIVA](https://github.com/payatu/diva-android) | small, sharply scoped exercises | storage, input validation, hardcoding |
| [InjuredAndroid](https://github.com/B3nac/InjuredAndroid) | CTF-flavoured | flag-hunting, dynamic analysis |
| [OWASP MASTG crackmes](https://mas.owasp.org/crackmes/) | anti-analysis focus | resilience controls, native code |

Pick **one**. Do not sample several; part of what is being assessed is bounded work under a
cap.

### 3.2 The brief, exactly as you would receive it

> **Mobile Security Assessment — take-home exercise**
>
> Please assess the attached Android application and report your findings.
>
> Time expectation: **three hours**. Please do not exceed it; we would rather see what you can
> do in three hours than what you can do in ten.
>
> Deliverable: a single Markdown document. Format is up to you.
>
> You may use any tools you like. Please make your process reproducible.

That brief is deliberately typical, and — like a real one — it is **underspecified in exactly
the places the rubric marks**. It does not ask for scope, method, rejected leads or
limitations. The grader marks all four. Noticing that is the first thing being tested.

### 3.3 The cap is part of the exercise

Set a timer for three hours. When it fires, stop, and write down where you were. Overrunning
is not diligence; it makes your submission incomparable to everyone else's and it tells the
grader you do not manage scope — which is the same failure as
[Lab 01](lab-01-timed-mock-technical-round.md)'s, in written form.

**A suggested allocation, offered as a starting point rather than a prescription:**

| Minutes | Phase | Output |
|---:|---|---|
| 0–15 | Acquisition and triage | hashes, version, splits, ZIP listing, signature, targetSdk, native libs |
| 15–35 | Manifest and surface | exported components, permissions, `debuggable`, `allowBackup`, network security config |
| 35–75 | Static pass | decompile, **verify the decompilation worked**, targeted searches driven by the manifest |
| 75–135 | Dynamic pass | install, drive it, logcat, filesystem after use, one or two hooks |
| 135–165 | **Adjudication** | go through your leads and kill the ones that do not survive |
| 165–180 | Write-up completion | scope, limitations, rejected leads |

The 30 minutes of adjudication is the phase candidates cut when they run late, and it is the
phase the rubric weights most heavily. Cut the dynamic pass instead and say you did.

### 3.4 Commands you will want

```bash
# host — acquisition. Note pm path, because splits are normal.
adb shell pm path com.example.target
adb pull /data/app/.../base.apk ./base.apk
sha256sum base.apk

# host — triage BEFORE decompiling
unzip -l base.apk | head -40
apksigner verify --print-certs base.apk
aapt2 dump badging base.apk | grep -E 'package|sdkVersion|native-code'

# host — the platform's own manifest reader, not a re-implementation
aapt2 dump xmltree base.apk --file AndroidManifest.xml | head -80

# host — decompile, then CHECK IT WORKED
jadx -d out/ base.apk
grep -rl 'Method not decompiled' out/ | wc -l      # the number jadx's summary under-reports

# host — component surface, from the device's own resolver
adb shell "dumpsys package com.example.target | sed -n '/Activity Resolver/,/^$/p'"

# host — after driving the app
adb shell "run-as com.example.target ls -laR /data/data/com.example.target" 2>&1 | head -60
adb logcat -d | grep -i com.example.target | tail -50
```

> **⚠️ Warning — the `adb shell su -c` trap** <!-- lint:allow SU-DASH-C SU-DASH-C-BARE -- the broken form, named as the subject of this warning; covers the next line too -->
> `adb shell su -c 'a; b'` loses its quoting and runs only `a`. Write
> `adb shell "su -c 'a; b'"`. On an emulator, `su` may reject `-c` entirely — use
> `su 0 <cmd>`, which reads as "not rooted" when it fails and has caught several chapters of
> this repository out.

### 3.5 The deliverable format

One Markdown file. Save it as `submission.md` somewhere outside this repository.

Use this skeleton — it is the finding template from
[README §8.2](../README.md#82-a-finding-template-that-pre-empts-the-objections), plus the four
sections the brief did not ask for:

```markdown
# Assessment — <app> <version>

## Scope and method
What I examined, in what order, with what. What I did NOT examine.

## Findings
### F-01 — <impact in one line>
**Severity:** / **Confidence:** / **MASVS:** / **Affected:**
**Precondition.**
**What I observed.**  (the command and its real output)
**Why it happens.**   (the mechanism, one level below the API)
**Impact, and its bound.**
**Reproduction.**     (numbered, exact)
**Remediation.**      (specific, as code where possible)
**What I did not establish.**

## Leads examined and rejected
Three lines each: what it looked like, why it is not a finding.

## Limitations
Coverage, with its denominator. Tooling gaps. What three more hours would buy.
```

---

## 4. Traps deliberately present in this exercise

Not hints about the target — hints about the *exercise*. Each of these has a measurement
behind it in this repository, and each has sunk real submissions.

**Trap 1 — the decompiler lies about its own failures.** jadx prints a console error count
that under-reports refused methods by a large factor: on one real 17.5 MB application it
reported `finished with errors, count: 61` while the output tree held **2,104 refused methods
across 1,424 files**. If you do not count the tree, "I searched the decompiled output and
found nothing" is a claim about a partial decompilation.

**Trap 2 — `base.apk` is not the app.** Splits are normal. One large application showed *zero*
security controls in `base.apk` because its code ships in feature splits. `pm path` returns
every path; pull them all.

**Trap 3 — grep cannot find a constant-folded identifier.** `FLAG_SECURE` is a
`public static final int`, so javac folds it and only `0x2000` reaches the DEX. A string grep
for the name has a **true-positive rate of exactly zero**. If your report says the app does not
use `FLAG_SECURE` because you grepped for it, that is a wrong finding produced by a correct
command.

**Trap 4 — the shell is not the app, and the number everyone quotes for this is wrong.**
Anything you verify from `adb shell` has been verified from uid 2000 in the `shell` SELinux
domain. On the emulator used for this chapter the corrected property counts are **root ~1,062,
shell ~678, app ~638** — so the shell-to-app gap is about forty and the shell-to-root gap is
about four hundred. A widely-repeated figure put the shell at 1,053, and that was a **root**
measurement mislabelled. The practical consequence: a shell test is a decent proxy for app
reachability and a **terrible** proxy for root, and the expensive error is *"I tested from root
and called it shell"*. Where the gap really is total is `ro.boottime.*` — 111 properties to
root, **zero** to shell and zero to an app. Verify from the app's vantage — `run-as`, a probe,
or in-process — or label the result.

**Trap 5 — a lead is not a finding.** The published conversion rates in this repository: 16,836
raw hits → 168 leads, of which **15 of the top 17 were rejected by hand**; 132 high-confidence
hits, **132 false positives**; 1,141 keyword occurrences, **1,141 explained by an English
word**, zero findings. Your submission will be marked against that base rate whether or not
the grader states it.

**Trap 6 — a negative result needs its method.** "No hardcoded secrets found" without a stated
search method, corpus and coverage is unfalsifiable, and is therefore not a result.

---

## 5. Submitting

Before you look at section 6:

- [ ] Timer stopped at or before three hours.
- [ ] `submission.md` written and saved.
- [ ] It contains a **Scope and method** section.
- [ ] It contains a **Leads examined and rejected** section.
- [ ] It contains a **Limitations** section with a denominator in it.
- [ ] Every finding has a stated precondition.
- [ ] Every finding has real command output, not a description of output.

Now run the lint over it, which will not mark the content but will catch the shape failures:

```bash
# host — each H2/H3 graded separately; 7/12 is the pass mark
python3 -B ../scripts/answer-shape-lint.py --split --min 7 /path/to/submission.md
```

Expect some sections to score low legitimately — a "Scope and method" section has no severity
reasoning in it and should not. Read the per-axis notes rather than the totals.

---

## 6. The rubric — the grader's version

**Only read this after submitting.**

100 points. The weighting is the point: **60 of the 100 are for things the brief never asked
for.**

### 6.1 Method and scope — 25 points

| Points | Criterion |
|---:|---|
| 8 | A scope section exists and states what was examined **and what was not** |
| 6 | Acquisition is correct: `pm path` rather than assuming `base.apk`; hash and version recorded |
| 5 | The order of work is stated and defensible — triage before decompilation, manifest before searching |
| 6 | Tool output was **verified**, not trusted. Counting jadx's refused methods, or checking that the manifest reader and the platform agree, scores here |

> **0 points is the mode for the last row.** Almost nobody checks whether their decompiler
> succeeded. A submission that does stands out immediately.

### 6.2 Findings quality — 25 points

| Points | Criterion |
|---:|---|
| 8 | Each finding has a **precondition** stated (rooted? debuggable? another app installed? physical access?) |
| 7 | Reachability is argued, not assumed. "An app with root can read it" is usually not reachability |
| 5 | Real command output is included, not a paraphrase |
| 5 | Impact is bounded — what the attacker gains **and what they do not** |

### 6.3 Severity discipline — 20 points

| Points | Criterion |
|---:|---|
| 8 | Severities are argued, not asserted |
| 6 | The distribution is plausible. Everything High is a fail; everything Informational is also a fail |
| 6 | **Confidence is separated from severity.** A high-severity issue you are 60% sure of and a low-severity one you are certain of demand different actions |

### 6.4 False-positive discipline — 15 points

| Points | Criterion |
|---:|---|
| 10 | A **rejected leads** section exists, with reasons |
| 5 | No lead is presented as a finding. Each instance costs 2, to a floor of 0 |

> This is the section that most often decides the outcome. A submission with five findings and
> six rejected leads beats one with twenty-two findings and no adjudication, every time,
> because the grader has learned your false-positive rate instead of having to discover it
> later.

### 6.5 Communicability — 10 points

| Points | Criterion |
|---:|---|
| 5 | Remediation is specific, ideally as code, and is actually correct |
| 3 | A developer could reproduce from the steps without asking you a question |
| 2 | Findings are ordered by importance, not by tool section or by discovery order |

### 6.6 Limitations — 5 points

| Points | Criterion |
|---:|---|
| 3 | A limitations section exists |
| 2 | Coverage is stated **with its denominator** — "3 of 4 manifest-declared components", not "most of the app" |

### 6.7 Penalties

| Penalty | Trigger |
|---:|---|
| −10 | Scanner output pasted with light editing. Recognisable in seconds: wrong severity distribution, findings ordered by tool section, no reachability anywhere |
| −10 | A finding that is wrong *and* confidently stated |
| −5 | Overran the cap without saying so |
| −5 | "No issues found" anywhere, with no method attached |
| −5 | A negative claim about the whole app based on a string search |
| −20 | Tested a target you were not authorised to test |

### 6.8 Bands

| Score | Verdict |
|---:|---|
| 85–100 | Strong hire. Reports will not need rewriting |
| 70–84 | Hire. Method is sound; some coaching on severity or communication |
| 55–69 | Borderline. Usually correct findings with no method section — the commonest shape |
| 40–54 | No. Leads submitted as findings, or no adjudication anywhere |
| < 40 | No, and usually a scanner dump |

---

## 7. Self-marking honestly

Two instructions, both of which people ignore.

**Mark the document, not your intent.** If you meant to write a limitations section and ran
out of time, that is 0 points, exactly as it would be from a stranger. The rubric measures
what a grader receives.

**Mark the penalties first.** They are the ones you will not want to apply. In particular:
count every lead you presented as a finding, honestly. A "finding" you would not defend in a
room with the developer who wrote the code is a lead.

Then write down three things:

1. Your score, by section, out of 25/25/20/15/10/5.
2. Your **lowest-scoring section**, which is your actual weakness — it is very rarely findings
   quality.
3. One sentence of diagnosis. "I found real issues and did not adjudicate them" is a
   diagnosis. "I need more practice" is not.

**The most common self-marking error** is scoring 6.1 generously because you *know* what you
examined. The grader does not. If it is not in the document, it did not happen.

---

## 8. Cleanup

```bash
# host
adb uninstall com.example.target
adb shell rm -rf /data/local/tmp/lab02
rm -rf out/ base.apk
```

Check nothing was left behind:

```bash
# host
adb shell ls /data/local/tmp
```

You should see only tooling that was there before you started. Emulator residue survives
longer than device residue, because nobody thinks of an emulator as a device — two chapters of
this repository left files on one and neither noticed until a third went looking.

---

## 9. Success criteria

- [ ] Submission written inside a three-hour cap.
- [ ] All four unrequested sections present: scope/method, rejected leads, limitations,
      per-finding preconditions.
- [ ] Self-marked against section 6, with penalties applied honestly.
- [ ] Score ≥ 70, **or** a written diagnosis of the lowest-scoring section.
- [ ] Every finding survives the question "would I defend this in a room with the developer?"
- [ ] Device and workspace cleaned, and verified clean.

---

## 10. Extension — mark someone else's

If you can find a second person to do this lab, swap submissions and mark each other blind
against section 6, then compare scores before discussing.

The **disagreement** is the interesting output, not the scores. Two graders disagreeing
systematically about the same submission is exactly the inter-rater reliability problem in
[README §10, Staff tier](../README.md#10-common-interview-questions) — and experiencing it from
the grader's side is the fastest way to understand why hiring loops need a written signal per
question rather than a shared sense of quality.

**When you cannot reproduce something in their submission, do not correct it.** Report what you
ran and what you got, and file the difference as unresolved for them to adjudicate. That is not
politeness; it is the correct epistemic move, because you do not know what their device or their
tooling was doing and they do. This repository has a worked instance:
[README §3.7.1](../README.md#371-the-number-i-nearly-quoted-and-why-it-was-wrong) describes a
chapter that failed to reproduce another chapter's published property count and **changed
nothing** — it published its own numbers and its own command and left the adjudication to the
owner. That is what surfaced the defect. Silently overwriting the figure would have replaced one
unverified number with another; silently accepting it would have left it standing. *"I could not
reproduce your result; here is exactly what I ran"* is a senior-tier behaviour and it is worth
practising on a submission where the stakes are zero.

---

## 11. Related

- [README §3.11](../README.md#311-the-take-home-what-is-graded-and-what-is-actually-graded) — what is graded versus what is actually graded
- [README §8.1](../README.md#81-the-written-artefact-and-what-graders-mark) — the written artefact
- [README §8.2](../README.md#82-a-finding-template-that-pre-empts-the-objections) — the finding template used above
- [README §5.2](../README.md#52-the-take-home-that-is-unpaid-work-or-worse) — the authorisation question, and how to raise it
- [52-StaticAnalysis](../../52-StaticAnalysis/README.md) — the funnel, and the rejected HIGH band
- [56-JADX](../../56-JADX/README.md) — counting the tree rather than the console summary
- [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) — MASVS identifiers for the finding template
- [80-Appendix](../../80-Appendix/README.md) — report templates and the severity rubric
- [Lab 03](lab-03-live-triage-and-honest-uncertainty.md) — the same work, live and observed
