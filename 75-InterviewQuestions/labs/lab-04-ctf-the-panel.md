# Lab 04 — CTF: The Panel

> **Difficulty:** Advanced
> **Time:** 90 minutes for the gauntlet, 45 for the analysis.
> **Prerequisites:** Labs [01](lab-01-timed-mock-technical-round.md),
> [02](lab-02-take-home-with-a-rubric.md) and [03](lab-03-live-triage-and-honest-uncertainty.md).
> A device you own, `adb`, and `sha256sum` (or `Get-FileHash`).
> **Constraint:** five adversarial rounds, a **hidden scoring function**, and a flag you cannot
> guess.

---

## 1. The challenge

You are in front of a panel. They ask five questions. Each question is technically
answerable — none of them is a trick in the sense of having no answer — and yet **four of the
five will be scored zero if you answer them the way they are asked.**

The panel is not scoring what you think it is scoring.

Your task is to work out **what the scoring function actually is**, and then to satisfy it in
each round. Each round you satisfy yields one token. The five tokens, joined in round order,
form the flag.

```
Flag format:  CTF{TOKEN1-TOKEN2-TOKEN3-TOKEN4-TOKEN5}
              48 characters including the braces
              all tokens are single upper-case English words
```

**Verify without spoiling.** When you believe you have it:

```bash
# host — Git Bash / Linux / macOS
printf '%s' 'CTF{...your...guess...}' | sha256sum
```

```powershell
# host — PowerShell
$g = 'CTF{...your...guess...}'
$s = [System.Security.Cryptography.SHA256]::Create()
-join ($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($g)) | % { $_.ToString('x2') })
```

**Target digest:**

```
6657c5c7a90463a66d42921b56e8c23530a392b51c1c839ec1d6c606d0657de8
```

Per-token digests, truncated to 16 hex characters, so you can confirm one round at a time
without seeing the others. Hash the bare upper-case word, no braces, no hyphens:

| Round | First 16 hex of `sha256(TOKEN)` |
|---:|---|
| 1 | `0b997439c6f90463` |
| 2 | `e366e0adc6149908` |
| 3 | `723c7ea2458a0a11` |
| 4 | `2d1de4dbc016ea31` |
| 5 | `d3bb1e450d2f84c9` |

Do not read section 6 until you have either the flag or five failed rounds. Section 5 is a
graduated hint ladder; use as few rungs as you can stand.

---

## 2. Rules

- **Answer aloud, and record it.** A written answer lets you edit; the panel does not.
- **Four minutes per round.** Hard stop.
- **The terminal is allowed and encouraged.** A device you own, read-only commands only.
- **You may not look up the round's subject matter mid-round.** You may use the device.
- **After each round, write down one sentence**: what you think the panel scored. That sequence
  of five guesses is the actual work of this CTF; the flag is a checksum on it.

**Authorised testing only.** Every command implied by these rounds is read-only and runs
against your own device. Nothing here asks you to touch anything you do not own.

---

## 3. The five rounds

Reveal one at a time. Do not skim ahead — the rounds are ordered so that the scoring function
becomes *more* visible, and reading round 5 first destroys the puzzle.

---

### Round 1

> **The panel:** "This application uses obfuscation, root detection, emulator detection and
> integrity checking. Rate the strength of its anti-tampering protection from 1 to 10, and
> justify the number."

Four minutes.

---

### Round 2

> **The panel:** "One of our engineers claims the app cannot be run on an emulator because it
> checks `Build.FINGERPRINT` and `/dev/qemu_pipe`. Another says emulator detection is
> pointless. Who is right?"

Four minutes. You have a device in front of you.

---

### Round 3

> **The panel:** "Here is a device. Tell us whether an application's Keystore keys on it are
> hardware-backed. You have a shell."

Four minutes.

---

### Round 4

> **The panel:** "You rated 'session token readable via `run-as` on a debuggable build' as
> High. Our client's engineering lead says that is absurd — it needs a debuggable build, which
> we never ship. He wants it downgraded to Informational. He is on the call. Respond."

Four minutes.

---

### Round 5

> **The panel:** "Your report says the application contains no hardcoded credentials. Convince
> us."

Four minutes.

---

## 4. Before you look at anything else

Write down, now:

1. Your five one-sentence guesses about what each round scored.
2. Your guess at the **single** scoring function common to all five.
3. Your candidate flag, if you have one.

Then verify against the digests in section 1. If a token verifies, you have that round. If the
full flag verifies, stop — you are done, and section 6 is optional reading that will tell you
nothing you did not just demonstrate.

---

## 5. Hints

Each rung costs you something. Take them in order.

<details>
<summary><b>Hint 1 — the shape of the answer</b></summary>

Every token is a noun that names **a thing a strong answer contains**, not a thing the question
is about. None of the five tokens is `ROOT`, `EMULATOR`, `KEYSTORE`, `SEVERITY` or `SECRETS`.

If you are hunting for the subject matter, you are solving the wrong puzzle.
</details>

<details>
<summary><b>Hint 2 — what all five rounds share</b></summary>

Re-read the five questions and ask, for each one: *what does answering it directly require me
to accept without checking?*

Round 1 asks for a number on a scale nobody defined. Round 2 asks you to pick between two
people. Round 3 asks a question of a device that is a question about a key. Round 4 asks you
to defend a rating with a hostile party listening. Round 5 asks you to prove a negative.

**Not one of the five can be answered honestly as asked.** They are not badly written. They are
written that way on purpose.
</details>

<details>
<summary><b>Hint 3 — round by round, what is missing</b></summary>

| Round | The thing the question assumes, which you must not accept |
|---:|---|
| 1 | that a list of four control families can be summed into a strength |
| 2 | that one of two people must be right, and that your device agrees with either |
| 3 | that "hardware-backed" is a property of a device |
| 4 | that a rating is a negotiation rather than the output of a scale |
| 5 | that "found nothing" and "there is nothing" are the same statement |

Each token names the concept you must supply in order to refuse cleanly.
</details>

<details>
<summary><b>Hint 4 — token shapes</b></summary>

```
Round 1:  7 letters,  P _ _ _ _ _ E
Round 2:  7 letters,  V _ _ _ _ _ E
Round 3:  8 letters,  B _ _ _ _ _ _ Y
Round 4:  6 letters,  R _ _ _ _ C
Round 5: 11 letters,  D _ _ _ _ _ _ _ _ _ R
```
</details>

<details>
<summary><b>Hint 5 — the scoring function, stated plainly</b></summary>

The panel is scoring **calibration**, not correctness. In every round, the maximum score goes
to the candidate who declines to produce the confident answer the question invites, names
precisely what is missing, and then answers a smaller, defensible question instead.

This is the same property [Lab 03](lab-03-live-triage-and-honest-uncertainty.md) measures with
its four unanswerable questions, and the same one
[README §10, Principal tier](../README.md#10-common-interview-questions) argues is the most
defensible thing an interview can measure at all.
</details>

---

## 6. Solutions

**Only read this after verifying, or after five genuine attempts.**

### Round 1 — token `PREMISE`

**The trap:** producing a number. Any number. The panel does not care whether you say 4 or 7;
it cares that you accepted a scale that does not exist and summed four unrelated control
families into it.

**Full marks:** reject the premise, then rate something real.

> "I can't give you a single number for that list, and I'd want to say why rather than pick
> one. Four families of check that all terminate in one boolean is one hook — the fourth family
> bought nothing, because the cheapest place to intervene is the *verdict*, not the checks.
> So what I'd rate is the shape, not the inventory. Three questions: does the app accumulate
> evidence with provenance or collapse to a boolean; can each check actually fire from an app's
> vantage, which several published ones cannot; and does anything leave the device, because a
> score evaluated server-side is the only part an attacker cannot reach. On the first two I'd
> need the app. On the third, if the answer is no, then as a *security control* this is Low —
> it is friction with a price — and as anti-fraud friction it might be worth a great deal. The
> grading question is who owns the false positives."

**Scored:** the refusal to accept the scale, followed by a defensible substitute. A candidate
who says "it depends" and stops scores zero, the same as one who says "7".

**Chapters:** [37](../../37-RootDetection/README.md),
[38](../../38-TamperDetection/README.md), [39](../../39-EmulatorDetection/README.md),
[67](../../67-BypassingProtections/README.md), [20](../../20-Security-Architecture/README.md).

---

### Round 2 — token `VANTAGE`

**The trap:** picking a side. Both engineers are wrong, and the device in front of you settles
it in about fifteen seconds — but only if you think to use it, and only if you then state
*from where* you measured.

```bash
# adb shell — reference AVD, Android 15 / API 35
$ getprop ro.build.fingerprint
google/sdk_gphone16k_x86_64/emu64xa16k:15/AE3A.240806.043/12960925:userdebug/dev-keys
$ ls /dev/qemu_pipe
ls: /dev/qemu_pipe: No such file or directory
$ getprop ro.kernel.qemu
1
```

The first engineer's two checks both return the wrong answer here. The second engineer is
overclaiming: `ro.kernel.qemu` still reads `1`, so the property check is alive.

**Full marks** names all three of these:

1. The measurement, with the **device** attached to it.
2. The **vantage** caveat — that measurement is from `adb shell`, uid 2000, SELinux domain
   `u:r:shell:s0`, and the app that has to run the check sees a different world. Corrected
   counts on this device: **root ~1,062, shell ~678, app ~638**, with `ro.boottime.*` at 111
   for root and **zero** for both of the others. A detection probe verified from `adb shell`
   has not been verified — though note the honest version of that rule, because the widely
   quoted "shell 1,053 versus app 634" was a root measurement mislabelled: the shell-to-app gap
   is about forty, so the shell is a *fair* proxy for the app and a terrible one for root.
3. What it does **not** establish — that emulator detection in general is dead. Structural
   signals still work: the sensor population, the ABI list with a native bridge, the CPUID
   hypervisor bit on x86.

**Scored:** using the device, and then bounding the result by where you stood.

**Chapters:** [39](../../39-EmulatorDetection/README.md), [60](../../60-ADB/README.md),
[22](../../22-SELinux/README.md).

---

### Round 3 — token `BOUNDARY`

**The trap:** answering. Every version of "yes, it's Android 15, so TEE-backed" is zero, and so
is "let me check `getprop`".

Hardware backing is a property **of a key**, not of a device. The same device produces
TEE-backed keys for some parameter sets and software keys for others; one measured TEE
**accepted** RSA-1024, contradicting the expectation that it would refuse; and on an emulator
every key is `SOFTWARE` with an empty hardware-enforced list — **while the attestation chain
over it still verifies perfectly.**

**Full marks** is the four-part refusal:

> *Boundary* — "I can't answer that from a shell, and I'd push back on the framing."
> *Shape* — "Hardware backing is a property of a key, not a device. Different algorithms and
> different parameters land in different security levels on the same hardware."
> *Method* — "I'd generate a key with the exact parameters the app uses, pull its attestation,
> and read the security level out of the **hardware-enforced** list — not the software-enforced
> one, which an attacker supplies."
> *Receipt* — "And I'd expect `SOFTWARE` here, with the chain verifying anyway. That is the
> whole reason 'the chain verified' is not an answer to 'is it hardware-backed'."

**Scored:** naming the boundary of the question — device versus key, shell versus attestation,
chain versus content — before naming anything else.

**Chapters:** [49](../../49-KeyStore/README.md),
[50](../../50-HardwareBackedSecurity/README.md), [34](../../34-Cryptography/README.md).

---

### Round 4 — token `RUBRIC`

**The trap:** the hostile party on the call. There are two zero-scoring responses and they feel
like opposites:

- **Fold.** "You're right, let's call it Informational." Records as: ratings are negotiable,
  therefore not evidence.
- **Dig in.** "No, it's High." Records as: cannot be reasoned with, will lose the argument by
  winning it.

**Full marks** holds the rating and moves the conversation onto the scale:

> "I rated it High on reachability and blast radius: on a debuggable build any local process
> can read the token as the app's uid, and the token grants full account access with no
> server-side binding. If the position is that a debuggable build is a precondition you never
> ship, that is a fair argument and it is a disagreement about the **rating scale**, not about
> the finding — our scale rates on impact-if-reachable, and you're arguing likelihood. I'm
> happy to present both, or to add a likelihood column. What I'd want in the report either way
> is the check that stops a debuggable build ever shipping, because that control is what your
> argument depends on. What would change my rating is evidence that the release pipeline makes
> it impossible — if you have that, show me and I'll move it."

**Scored:** locating the disagreement in the *rubric* rather than in the finding, staying
movable by evidence and immovable by pressure, and naming in advance what would change your
mind.

**Chapters:** [71](../../71-OWASP-Mobile/README.md), [80](../../80-Appendix/README.md),
[47](../../47-Authentication/README.md).

---

### Round 5 — token `DENOMINATOR`

**The trap:** trying to prove the negative. You cannot, and the panel knows it.

**Full marks** converts an unfalsifiable claim into a bounded one, and names the mechanisms
that could have hidden a true positive:

> "I can't convince you of that, and I'd rewrite the sentence. What I can give you is the
> bounded version: I searched N of N DEX files across the base APK and both splits, with these
> patterns, and found no matches — and here is why that is weaker than it sounds.
>
> A constant-folded identifier never reaches the artefact at all: grepping for `FLAG_SECURE`
> has a **true-positive rate of exactly zero**, because javac folds `0x2000` and the name is
> gone. My decompiler under-reports its own failures — on one real app the console said 61
> errors while the output tree held **2,104 refused methods across 1,424 files**, so anything
> in those methods is invisible to a search of the output. A device-side grep over APKs is
> blind to compressed entries, and the compressed ones are disproportionately the sideloaded
> and Play-updated apps you most care about. And the secret may not be in the artefact — it may
> arrive at runtime.
>
> So the finding I'd write is: 'no hardcoded credentials were identified in the code examined;
> coverage was X of Y components and Z of the decompiled methods; a runtime-provisioned
> credential would not be visible to this method.' The denominator is the finding."

**Scored:** the denominator, plus at least two of the four mechanisms.

**Chapters:** [47](../../47-Authentication/README.md), [52](../../52-StaticAnalysis/README.md),
[56](../../56-JADX/README.md), [64](../../64-Xposed/README.md).

---

### The flag

```
CTF{PREMISE-VANTAGE-BOUNDARY-RUBRIC-DENOMINATOR}
```

```
sha256 = 6657c5c7a90463a66d42921b56e8c23530a392b51c1c839ec1d6c606d0657de8
```

### The scoring function

**Calibration.** In all five rounds the maximum score went to the answer that declined the
confident response the question invited, named exactly what was missing, and then answered a
smaller defensible question. In none of the five did the panel score the subject-matter fact.

That is not a puzzle conceit. It is the argument of
[README §1.2](../README.md#12-the-sampling-problem): with eight samples of your reasoning
extrapolated to thousands of unsupervised decisions, the property with the highest predictive
value is whether your confidence tracks your correctness. Everything else — the `su` paths, the
API levels, the flag names — is looked up in eleven seconds by a calibrated person and is
looked up wrong by an uncalibrated one.

---

## 7. The second challenge — build a round of your own

The harder half, and the one that changes how you sit on the other side of the table.

Write a **sixth round**. It must satisfy all four:

1. It asks a question that is technically answerable.
2. The obvious answer is wrong, or unsupportable, or accepts a false premise.
3. There is a smaller, defensible question underneath it.
4. It draws on a **measurement**, from this repository or your own device, that contradicts a
   widely-held belief.

Candidates that work well, each with the contradiction that powers it:

| Subject | The measurement that makes it a round |
|---|---|
| "Does this app use certificate pinning?" | 12 of 14 apps had a pinning surface; **4 actually pinned** |
| "Is `TracerPid` how you detect a debugger?" | `jdb` attached, threads enumerated, `TracerPid` read **0** throughout |
| "Has this APK been repackaged? Check the DEX CRC" | re-signing changed the signature digest and left `classes.dex` CRC **identical** |
| "Did the fuzzing campaign find anything? It exited 0" | the same heap overflow presents three ways; **two of the three exit 0**, one silently |
| "The tool said the pinning bypass succeeded" | three successful hooks reported against an app with **no network code at all** |
| "This app is signed by one certificate, so compare one hash" | **6 of 198** installed packages carry a signing lineage |

Then run your round on somebody else and see whether they fall into it. **Watching a competent
person answer confidently and wrongly is the fastest available cure for doing it yourself.**

---

## 8. Success criteria

- [ ] Five rounds attempted aloud, four minutes each, recorded.
- [ ] Five written guesses at what each round scored, made **before** section 6.
- [ ] Flag verified against the SHA-256 digest, or five genuine failures analysed.
- [ ] You can state the common scoring function in one sentence.
- [ ] You have written a sixth round meeting all four criteria in section 7.
- [ ] You ran your sixth round on someone else.

---

## 9. Debrief questions

Worth writing answers to, because they are the transferable part:

1. **Which round did you fall into hardest, and what does that say about your default under
   pressure?** Round 1 catches people who want to be helpful. Round 3 catches people who
   overestimate what a shell can tell them. Round 4 catches people who conflate being
   reasonable with being movable. Round 5 catches almost everyone.
2. **In which round would answering directly have been the *right* call in real life?** There
   is a defensible case for round 2 — sometimes a colleague needs a quick answer, not a
   seminar. Knowing when the calibrated answer is over-engineering is itself calibration.
3. **What is the cost of this behaviour when it becomes a habit?** Real. A person who refuses
   every question as under-specified is exhausting and slow, and "it depends" without a
   substitute answer is a dodge wearing rigour's clothes. Every round above ends with a
   *smaller answered question*, and that is not decoration — it is the difference between
   calibration and evasion.
4. **Would you rather hire the candidate who scored 5/5 here, or the one who knew twice as
   much and scored 1/5?** The honest answer depends on the role, and being able to say why is
   a Staff-tier answer.

---

## 10. Related

- [README §3.6](../README.md#36-cross-cutting-questions-the-ones-no-chapter-owns) — the ten cross-cutting questions these rounds are built from
- [README §3.7](../README.md#37-the-measured-contradictions-and-how-to-use-them-without-being-insufferable) — every measurement cited above, with its owning chapter
- [README §3.10](../README.md#310-severity-language-and-defending-a-rating-under-pushback) — round 4, in full
- [README §10](../README.md#10-common-interview-questions) — the same material from the panel's side of the table
- [`../examples/03-saying-i-do-not-know.md`](../examples/03-saying-i-do-not-know.md) — the six responses, transcribed
- [Lab 03](lab-03-live-triage-and-honest-uncertainty.md) — the non-adversarial version, with a published marking key
