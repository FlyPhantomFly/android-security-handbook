# Lab 01 — The timed mock technical round

> **Difficulty:** Beginner → Intermediate
> **Time:** 45 minutes for the round, 30 minutes for the self-mark. Do not split them across
> days; the marking is only useful while you remember what you said.
> **Prerequisites:** Python 3, this repository. No device required.
> **Constraint:** a clock, and no notes.

---

## 1. Why this lab exists, and why you should do it before reading chapter 75

The most common reason a candidate fails a technical phone screen is **not knowing less than
the interviewer wants**. It is spending six minutes on a ninety-second question, and then
being cut off on the one they would have answered best
([README §2.4](../README.md#24-where-candidates-are-actually-lost)).

You cannot detect that in yourself by reading, because unconstrained answers feel
appropriately long while you are giving them. The only way to find out is to put a clock on
one and look at the number afterwards.

So this lab produces a **measurement of your unprepared behaviour**, which every other piece
of preparation is then calibrated against. That is why the instruction is to do it **cold**,
before reading the rest of chapter 75. Reading first destroys the measurement, and the
measurement is the whole point.

> **Warning**
> If you have already read [README §3.9](../README.md#39-time-budgets-and-the-scoping-failure-that-costs-more-than-ignorance),
> you have been told the answer, and your baseline will be contaminated. That is not a
> disaster — run it anyway, and treat the result as a *post*-instruction measurement rather
> than a baseline. Just do not report it to yourself as a cold number.

---

## 2. Objective

By the end of this lab you will have:

1. Sat a full eight-question technical phone screen against this repository's own question
   bank, timed at 150 seconds per question.
2. A recording of yourself answering, which you will listen to once.
3. A per-question score out of 12 against a published rubric, self-marked.
4. **A number**: how many of your eight answers exceeded the budget.
5. A one-page written diagnosis naming which of the six rubric axes is your weakest.

---

## 3. Setup

### 3.1 Build the question bank

The bank is generated mechanically from every chapter's interview section, so it is always
current:

```bash
# host — from 75-InterviewQuestions/
python3 -B scripts/build-interview-index.py --format json --out /tmp/bank.json
```

Expected output on stderr:

```
wrote /tmp/bank.json (189646 bytes)
```

The byte count will differ as chapters change; anything in the 150–250 KB range is healthy. If
it is under 10 KB the parse failed — check that you are running from the chapter directory and
that `--root` resolves to the repository root.

Sanity-check the bank:

```bash
# host
python3 -B scripts/build-interview-index.py --stats | tail -8
```

Measured on 2026-08-16:

```
Beginner                            337
Intermediate                        346
Senior                              286
Staff Engineer                      187
Principal Engineer                  164
TOTAL                              1320
chapters with a section              75
```

**Your numbers will be larger.** The corpus grows every time a chapter lands — an earlier run
the same day gave 1,258 across 71 — so treat this block as a shape check, not as a target. If
your totals are within a few hundred of these and all five tiers are present, the parse worked.

### 3.2 Check the pools

```bash
# host
python3 -B scripts/mock-round.py --bank /tmp/bank.json --list-pools
```

You want to see `Technical phone screen  pool 96  8 questions x 150s`. If the pool is 0, the
bank did not build.

### 3.3 Set up recording

You need audio of yourself. A phone voice memo is fine. **This is not optional and it is the
part people skip** — you cannot mark your own shape from memory, because memory reconstructs
the answer you meant to give rather than the one you gave.

### 3.4 Rules

- **No notes, no browser, no repository open.** If you would not have it in a phone screen,
  do not have it here.
- **Answer out loud.** Not in your head, not typed. The failure mode being measured is a
  spoken one.
- **Do not stop when you go over budget.** Finish the answer. You need to know how far over
  you go, not merely that you went over.
- **Do not look anything up between questions.**

---

## 4. The round

```bash
# host — the live, timed version
python3 -B scripts/mock-round.py --bank /tmp/bank.json \
        --round "Technical phone screen" --timed
```

The script prints one question at a time with its budget, waits for you to press Enter when
you have finished speaking, and records your elapsed time. It does **not** show you the
answer — that is deliberate, and section 6 explains why.

Start recording, then start the script.

If your terminal cannot give the script an interactive stdin, use sheet mode and time yourself
with a stopwatch:

```bash
# host — printable sheet, no interaction
python3 -B scripts/mock-round.py --bank /tmp/bank.json \
        --round "Technical phone screen" --seed 7
```

`--seed 7` makes the draw reproducible, which is useful if you want to re-run the identical
round in four weeks and compare. Omit it for a fresh draw.

### What the script prints at the end

```
--------------------------------------------------------------------------
TIMING
--------------------------------------------------------------------------
Q1     212s  Beginner           OVER
Q2      94s  Beginner
Q3     301s  Intermediate       OVER
...

5 of 8 timed answers over budget.
More than half. The problem is scoping, not knowledge: decide the
last sentence BEFORE you start the first one.
```

Write the over-budget count down. **That number is the primary output of this lab.**

---

## 5. Expected results, and what they mean

Typical first-run distributions, offered as orientation rather than as a measurement — this is
a qualitative expectation, and if your numbers differ, yours are the real ones.

| Over budget | What it usually means | What to work on |
|---|---|---|
| **6–8 of 8** | You are answering every question as though it were the only one | Section 8.1. Decide the last sentence first |
| **3–5 of 8** | Scope depends on how confident you feel — you run long where you are strong | Section 8.2. The strong questions are exactly where discipline pays |
| **1–2 of 8** | Good control. The remaining work is on the rubric axes, not the clock | Section 6 |
| **0 of 8, all answers very short** | Possibly under-answering. Check your rubric scores: if shape and mechanism are low, brevity is not the reason | Section 8.3 |

The counter-intuitive result worth watching for: **people run longest on the questions they
know best.** Depth is not rewarded by the phone screen; it is rewarded by the round after it,
and spending the phone screen's clock on it is how you never get there.

---

## 6. Self-marking

Now — and not before — read the model answers. The script printed a chapter link for each
question:

```
Q1  21-App-Sandbox/README.md#10-common-interview-questions
Q2  23-Permissions/README.md#10-common-interview-questions
```

**Read them in the chapter, not as a list.** The answer sitting next to the question teaches
recall; the answer sitting inside the section that derives it teaches the derivation, which is
what the follow-up question probes.

### 6.1 The rubric

Listen to your recording once, and score each of the eight answers on all six axes. 0, 1 or 2
per axis, maximum 12.

| Axis | 0 | 1 | 2 |
|---|---|---|---|
| **Shape** | Opened with a tool or a command | Opened with a statement, but the mechanism never arrived | Plain statement → precise version → mechanism → consequence |
| **Scope** | Over budget by more than 25%, or under 35% of it | Within budget but with no planned ending — it stopped rather than landed | Inside budget with a deliberate last sentence |
| **Boundary** | Never said where the trust boundary is | Mentioned it as a slogan ("it runs on the attacker's device") | Used it to decide what the answer *is* |
| **Evidence** | Every claim equally certain | Cited something, but did not distinguish read from measured | Said which claims are measured, on what, and which are read |
| **Honesty** | Asserted through a gap, or hedged everything equally | Hedged appropriately but named no method | Named the boundary **and** how you would find out |
| **Severity** | No severity, reachability or false-positive reasoning where the question invited it | Mentioned severity without a precondition | Rated with reasoning, and named the false-positive case |

> **Definition — the Severity axis when the question is not about a finding**
> Several phone-screen questions ("what is in an APK?") do not invite severity reasoning at
> all. Score those **2 by default** and note it. Do not let a not-applicable axis drag a good
> answer down; the axis exists to catch the answers where severity *was* invited and omitted.

### 6.2 Scoring bands

| Score | Band | What it means |
|---|---|---|
| 0–4 | Recitation | The answer was facts in sequence. Read the owning chapter's §3 |
| 5–8 | Correct but shapeless | You know it. Practise the **shape**, not more facts — this is the largest population and the fastest to improve |
| 9–12 | Ready | Move up a tier and repeat |

### 6.3 Cross-check with the lint

Pick your two weakest answers, write them out as you *should* have given them, and lint them:

```bash
# host
python3 -B scripts/answer-shape-lint.py --budget 150 my-rewrite.md
```

The lint scores the same six axes mechanically. Where you and it disagree, you are probably
right — it counts word shapes and cannot read — but the disagreement is informative. It is
particularly good at catching the two things humans miss in their own work: an opening that
names a tool, and a total absence of provenance vocabulary.

**Its own calibration is published**, so you know what you are trusting: run against
[`../examples/02-weak-and-strong-at-the-same-tier.md`](../examples/02-weak-and-strong-at-the-same-tier.md)
it scores the weak answers 5, 3 and 3, and the strong answers at the same tier 11, 9 and 10.
Every pair separates in the right direction; that is the only claim being made for it.

---

## 7. Worked example — one question, marked

The question drawn on the run recorded while writing this lab:

> **Q3. Why is `apktool` output not enough?** *(Beginner,
> [52-StaticAnalysis](../../52-StaticAnalysis/README.md))*

### A real first-attempt answer, transcribed

> "So apktool gives you the Smali, and Smali is hard to read, so you'd normally use jadx as
> well because jadx gives you Java. Apktool is good for the resources though, and the
> manifest, because it decodes the binary XML. I usually run both. Actually you also want
> aapt2 sometimes. So yeah, you'd use apktool plus jadx."

**Marked:**

| Axis | Score | Why |
|---|---:|---|
| Shape | 1 | Opened with a statement rather than a command, but never reached a mechanism — "Smali is hard to read" is a preference, not a reason |
| Scope | 1 | 41 seconds, well inside budget, but it stopped rather than landed — "so yeah" is the tell |
| Boundary | 0 | Not mentioned. There *is* one here and it is the interesting part |
| Evidence | 0 | No provenance. "I usually run both" is a habit, not evidence |
| Honesty | 1 | The "actually you also want aapt2" is a real self-correction, which counts |
| Severity | 2 | Not invited by this question |
| **Total** | **5/12** | Correct but shapeless — the largest band |

### The same person's rewrite, after reading the chapter

> "Apktool gives you two things: decoded resources including the binary manifest, and Smali.
> What it does not give you is readable Java, so for anything above trivial control flow you
> want jadx alongside it.
>
> The less obvious limit is the one I actually care about. Apktool is a third-party
> re-implementation of the platform's resource parser, so it can disagree with what the
> platform itself reads — and where they disagree, the platform is what runs. That matters
> because a discrepancy between them is not a bug in apktool, it is a place someone can hide
> something: the analyst reads one manifest and the device reads another. So my habit is
> apktool for readability, `aapt2 dump xmltree` for the platform's own answer, and jadx for
> Java, and if the first two disagree I stop and find out why.
>
> What I have not established, to be clear, is how often that happens in practice — I have
> read about the class of issue rather than measured a rate."

**Marked:** Shape 2, Scope 2 (78 seconds, landed), Boundary 2 (analyst-tooling versus
platform-parser is exactly the boundary), Evidence 1 (distinguishes read from measured, but
has no measurement of its own), Honesty 2, Severity 2 (n/a). **11/12.**

**What changed:** no new fact. The rewrite contains nothing the first answer's author did not
know. It has a mechanism, a consequence, a boundary and a stated limit — the five moves from
[README §3.3](../README.md#33-the-answer-shape-and-why-it-is-this-repositorys-own-house-style).

---

## 8. Drills for each failure mode

### 8.1 If you ran over on six or more

**Drill: the last-sentence-first exercise.**

Draw ten questions in sheet mode. For each one, **write down only your final sentence** — the
conclusion you would land on — and nothing else. Ten minutes total.

```bash
# host
python3 -B scripts/mock-round.py --bank /tmp/bank.json \
        --round "Technical phone screen" --count 10
```

Then answer each aloud, aiming to arrive at that sentence. The difference is immediate and it
is not subtle: knowing where you are going converts an exploration into a route.

Repeat until eight of ten land inside budget. This usually takes two or three sessions, not
weeks — it is a planning habit, not a skill.

### 8.2 If you ran over only on your strong questions

**Drill: the offer.**

Re-run the same ten questions with one added rule: every answer must end with an explicit
offer of depth, and must not take it.

> "…and there are three failure modes underneath that if it's useful."

Three seconds. It demonstrates the depth exists, it hands the interviewer the clock they were
managing anyway, and it removes the temptation that produced your over-runs.

### 8.3 If your scores are low on Evidence

This is the most valuable axis and the slowest to fix, because you cannot talk your way into
it — you have to have measured something.

**Drill: acquire three receipts.**

```bash
# host — read-only, ~20 seconds, against a device you own
../examples/04-evidence-behind-the-answer.sh
```

That gives you receipts on emulator detection, the `/system/xbin` vantage problem, and boot
state. Then measure two things of your own, on your own device, and write down for each: the
device, the command, the output, and **what it does not establish**.

Three receipts is enough. The point is not breadth; it is that "I measured it" becomes a thing
you can say truthfully, with a device name attached, at least three times.

### 8.4 If your scores are low on Honesty

**Drill: fail on purpose.**

```bash
# host — draw questions ABOVE your level, deliberately
python3 -B scripts/mock-round.py --bank /tmp/bank.json \
        --tier "Staff Engineer" --count 6 --budget 240 --timed
```

At Intermediate, drawing Staff-tier questions guarantees you cannot answer most of them. That
is the exercise. Answer each anyway using the four-part structure — boundary, shape, method,
receipt — in twenty seconds, and only then read the chapter.

The goal is to make not-knowing *routine* rather than alarming, so that under real pressure
you default to the rehearsed behaviour instead of to whichever of bluff, retreat, deflect or
over-hedge matches your temperament.

[Lab 03](lab-03-live-triage-and-honest-uncertainty.md) is the graded version of this drill.

---

## 9. Success criteria

You have completed this lab when **all** of the following are true:

- [ ] You have an over-budget count out of 8, written down, from a **cold** run.
- [ ] You listened to the recording once, all the way through.
- [ ] You have eight scores out of 12, one per question, each with a one-line justification.
- [ ] You have identified your weakest of the six axes by total across the eight answers.
- [ ] You have rewritten your two weakest answers and linted both, and both score ≥ 7/12.
- [ ] You have run the drill in section 8 that matches your dominant failure mode, at least
      once.
- [ ] You can state, in one sentence, what your problem is. "I run 2× over budget on questions
      I know well" is a diagnosis. "I need to prepare more" is not.

---

## 10. Re-running this lab

Re-run every two to four weeks while preparing, and use `--seed` to control the comparison:

```bash
# host — the IDENTICAL round, four weeks later
python3 -B scripts/mock-round.py --bank /tmp/bank.json \
        --round "Technical phone screen" --seed 7 --timed
```

Same seed for a like-for-like comparison of *delivery*; a fresh draw to check that the
improvement generalises rather than being memorisation of eight specific answers. Do both. If
the seeded round improves and the fresh draw does not, you have learned eight answers rather
than a shape, which is exactly the failure this lab exists to detect.

Progression when you are consistently ≥ 9/12 on the phone-screen tier:

```bash
# host
python3 -B scripts/mock-round.py --bank /tmp/bank.json \
        --round "Deep technical round" --timed        # 6 x 420s, Intermediate + Senior
python3 -B scripts/mock-round.py --bank /tmp/bank.json \
        --role "Detection / Anti-Fraud Engineer" --timed
```

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `error: no bank at bank.json` | you did not pass `--bank`, and the default (a `bank.json` in the current directory) does not exist | build it first, per section 3.1, and pass `--bank /tmp/bank.json`. The default is deliberately not a path inside the repository — the bank is generated, and a committed copy would be a stale duplicate |
| `error: no chapter directories found under …` | `--root` resolved somewhere unexpected | run from `75-InterviewQuestions/`, or pass `--root` explicitly |
| bank builds but is under 10 KB | the parse found no sections | check you are pointing at the repository root, not at this chapter |
| `--list-pools` shows pool 0 for every round | same as above | as above |
| the timed mode prints `(no tty -- not timed)` | stdin is not interactive | use sheet mode plus a stopwatch, per section 4 |
| `__pycache__` appeared under `scripts/` | you ran `python3` without `-B` | delete it; always use `python3 -B` |
| every answer scores 12/12 | you are marking the answer you meant to give | listen to the recording. This is the single commonest self-marking error |

---

## 12. What this lab does not measure

Stated explicitly, because a lab that overclaims is worse than one that does less.

- **It does not measure knowledge.** A candidate who knows nothing can score 12/12 by having
  excellent shape around an empty answer. The rubric grades delivery; the other 80 chapters
  grade content.
- **It does not simulate an interviewer.** There are no follow-ups, no interruptions, and no
  reaction to what you say. Real rounds are adversarial in a way a script cannot be — that is
  [Lab 03](lab-03-live-triage-and-honest-uncertainty.md) and
  [Lab 04](lab-04-ctf-the-panel.md).
- **It cannot mark itself.** You are marking you, and you are a biased instrument. The
  recording is the control, and skipping it invalidates the exercise.
- **The 150-second budget is a convention, not a measurement.** Real phone screens vary. It is
  chosen because it is roughly what 10–15 questions in an hour implies, and because a fixed
  budget makes runs comparable.

---

## 13. Related

- [README §3.3](../README.md#33-the-answer-shape-and-why-it-is-this-repositorys-own-house-style) — the five moves the Shape axis grades
- [README §3.9](../README.md#39-time-budgets-and-the-scoping-failure-that-costs-more-than-ignorance) — why scope beats knowledge as a failure cause
- [`../examples/02-weak-and-strong-at-the-same-tier.md`](../examples/02-weak-and-strong-at-the-same-tier.md) — the lint's published calibration
- [`../scripts/mock-round.py`](../scripts/mock-round.py) · [`../scripts/answer-shape-lint.py`](../scripts/answer-shape-lint.py)
- [Lab 02](lab-02-take-home-with-a-rubric.md) — the written artefact, graded
