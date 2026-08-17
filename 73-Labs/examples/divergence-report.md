# Divergence report — the short form, with a worked example

> A lab said X. You did what it said and got Y. This is what you write.
>
> Copy this file outside the repository before filling it in.

Used by [Lab 03 §7](../labs/lab-03-write-a-lab-that-survives.md). The long form, for a whole
investigation rather than a single claim, is
[74-CaseStudies/examples/reproduction-log.md](../../74-CaseStudies/examples/reproduction-log.md).

---

## 1. Why this document exists

The most common experience of running someone else's lab is that a step does not do what it says. It
is also the experience that this repository, and every other body of security writing, addresses
least. The default responses are all bad:

| Response | Why it is bad |
|---|---|
| Assume you did it wrong and keep trying | Sometimes true, but you will never find out which times |
| Assume the lab is wrong and skip it | Loses the finding, and you never tell the author |
| Edit the lab to match what you saw | **The worst one.** Converts an open question into a confident error the next reader inherits |
| Write it down and stop | Correct |

> **📖 Definition — divergence.** You re-ran a documented claim and got a different result.
> `DIVERGED` is a verdict about **the pair of observations**, not about either observer. It is
> emphatically not a synonym for "the original was wrong", and treating it as one is how a
> divergence report becomes an accusation.

---

## 2. The five causes, ranked

You usually cannot tell which one you have from a single run. Rule them out in this order, because
this is descending order of frequency in this repository's own record.

| Rank | Cause | Cheapest way to rule it out |
|---|---|---|
| 1 | **Vantage.** One of you ran as an app, the other as `shell` or root | State the identity explicitly. This is the most common cause by a wide margin |
| 2 | **Device or version difference** | Six properties: model, release, API, ABI, build type, security patch |
| 3 | **`su` form.** `su 0 <cmd>` versus `su -c <cmd>` | Run both. The wrong one reads exactly like "not rooted" |
| 4 | **Tool version.** Frida host/server especially, then build-tools, then the decompiler | `--version` on both ends |
| 5 | **One of the two measurements is wrong** | Last, not first. Includes yours |

> **⚠️ Warning.** A test blocked by your own tooling is **not** a divergence. If a command printed a
> success message and did nothing — see [Lab 02 §5.2](../labs/lab-02-the-chain-no-chapter-can-host.md)
> for a worked case where `am start` reported `Starting:` and delivered no intent — you have not
> measured anything yet. Establish that your test *could* have succeeded before you record that it
> did not.

---

## 3. The form

```
DIVERGENCE REPORT

Claim
  Source          :                 (chapter, lab, section, or an external write-up)
  Claim, verbatim :
  Claimed on      :                 (the device the original names, if it names one)

Observation
  Command, verbatim :
  Output, verbatim  :
  Repeat count      :                 (how many times you ran it, and did it vary?)

My environment
  Device          :                 (model, release, API, ABI, build type, patch level)
  Serial          :
  Root            : yes / no        working su form:
  SELinux         :
  Vantage         : app (uid ____) / shell (2000) / root / in-app
  Host tools      :                 (with versions)

Ruled out
  [ ] 1 vantage      how:
  [ ] 2 device       how:
  [ ] 3 su form      how:
  [ ] 4 tool version how:
  [ ] 5 measurement  how:

Verdict
  REPRODUCED / DIVERGED, cause established: ____ / DIVERGED, cause not established
  / NOT RUNNABLE HERE

Action taken
  (Usually: none. Say so.)
```

---

## 4. Worked example

A real divergence from this repository's record, written in the form above. It concerns a
property-visibility count in [39-EmulatorDetection](../../39-EmulatorDetection/README.md), re-run
while writing [74-CaseStudies](../../74-CaseStudies/README.md).

```
DIVERGENCE REPORT

Claim
  Source          : 39-EmulatorDetection, the shell-versus-app property visibility claim
  Claim, verbatim : shell sees 1053 properties, the app sees 634
  Claimed on      : the chapter's own device, at the time it was written

Observation
  Command, verbatim : the chapter's own documented getprop enumeration, unchanged
  Output, verbatim  : shell 673 / app 633 / root 1055
  Repeat count      : re-run; stable across runs

My environment
  Device          : as recorded in the case study's header
  Vantage         : all three measured separately, which is the point of the claim
  Host tools      : adb

Ruled out
  [x] 1 vantage      how: all three vantages measured in the same session
  [x] 3 su form      how: root vantage returned uid=0 before the enumeration
  [ ] 2 device       how: NOT ruled out. Cannot establish the original device state
  [ ] 4 tool version how: not applicable, getprop is on-device
  [ ] 5 measurement  how: NOT ruled out in either direction

Verdict
  DIVERGED, cause not established.
  Note that the APP figure reproduced almost exactly (633 against 634) while the
  SHELL figure did not (673 against 1053). A divergence in one term and not the
  other is itself evidence, and it points at the shell measurement rather than at
  the method.

Action taken
  Recorded. Chapter 39 NOT edited.
```

### 4.1 Why "chapter 39 not edited" is the right ending

Because the divergence is not resolved, and editing on an unresolved divergence would replace one
unverified number with another. The report is more useful than a correction would have been: it tells
the next reader *which* term is in doubt and hands them a narrower question than the one it started
with.

> **🧠 Mental Model.** A recorded divergence is a **question with a shape**. A divergence resolved by
> assertion is a **claim nobody will re-examine**, because it looks settled. The first compounds; the
> second rots.

---

## 5. What to do with the report

| Situation | Action |
|---|---|
| The lab is in this repository and you own the chapter | Fix it, and record what the divergence was |
| The lab is in this repository and you do not own it | File the report. **Do not edit another chapter's lab** |
| The lab is someone else's, published | Send them the report. The form above is already the message |
| You cannot tell whether your environment or theirs is the odd one | Get a third environment. One more device usually settles it |
| It is your own lab, and you cannot reproduce your own result | The most alarming case, and the most instructive. Assume your original measurement was contaminated until proven otherwise |

---

## 6. Checklist before you send it

- [ ] The claim is quoted verbatim, with a source you can point at.
- [ ] The command is quoted verbatim, including flags and quoting.
- [ ] The output is pasted, not described.
- [ ] Your vantage is stated. If you do not know it, you have not finished.
- [ ] At least one of the five causes is ruled out, with the method written down.
- [ ] The verdict uses one of the four permitted words.
- [ ] If the verdict is `DIVERGED, cause not established`, you changed nothing.
