# Lab 02 — The method jadx gets wrong

**Difficulty:** Intermediate → Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-first-decompilation.md),
[Chapter 56 §3.5, §3.7, §3.8, §6.3–§6.6](../README.md),
and — this one is not optional — [14 — Dalvik](../../14-Dalvik/README.md) §3.1–§3.13 and §6.1.
No device, no root, no network.

---

## This is the chapter's central exercise

Every other lab teaches you to use the tool. This one teaches you where the tool stops being
trustworthy, how to tell, and what to do about it. If you do one lab from chapter 56, do this one.

The claim you are going to verify with your own hands is:

> jadx's correctness is a property of the **shape of the bytecode**, not of the semantics of the
> program — and the Java gives you no way to tell which case you are in.

That claim is why "read Java to find, read Smali to be certain" is a rule rather than a preference,
and it is why chapter 14 is a chapter you work through rather than a reference you skim.

## Objective

1. Make jadx **refuse** a method, and get the answer anyway — four different ways, without leaving
   jadx.
2. Prove that `--show-bad-code` can make a refused method *harder* to understand, not easier.
3. Find a method jadx decompiles **silently and wrongly**, notice the tell that gives it away, and
   resolve it in the bytecode.
4. **Prove the divergence by execution**, so it is a measurement and not an argument.
5. Attempt to isolate the trigger, fail to, and write up the failure honestly — including the caveat
   that must accompany any report of it.
6. Produce a one-page finding write-up that would survive being challenged.

---

## Setup

```bash
# host
cd 56-JADX/examples/02-when-jadx-is-wrong
export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"   # or leave unset if jadx is on PATH
./reproduce.sh
```

Everything in this lab needs **only jadx and a JDK**. jadx bundles a Smali assembler, so the `.smali`
files are complete self-contained inputs — no apktool, no `smali.jar`, no Android SDK. If you have
apktool or `baksmali`, Part 5 gets richer, but nothing here depends on it.

---

## Part 1 — Refusal (45 min)

`Irreducible.smali` contains a loop with two entry points.

### 1.1 Understand *why* it cannot be decompiled

Before running anything, read the Smali and draw the control-flow graph on paper. Nodes are basic
blocks; edges are branches.

Then answer:

1. Which block is the loop header? Trace the back edges — there are two paths that re-enter.
2. Java has no `goto`. Write down the shortest Java method you can that has this control-flow graph.
   (You cannot. Spend five minutes failing at it; the failure is the lesson.)
3. Define *reducible* control flow in one sentence. Chapter §3.5.
4. Why can `javac` never emit an irreducible graph from structured Java source?
5. So: is jadx's failure here a bug, a missing feature, or a property of the target language?

### 1.2 Run it and read the refusal

```bash
# host
jadx -d out-default Irreducible.smali
cat out-default/sources/com/pentest/ch56/Irr.java
```

Answer:

1. How many distinct `JADX WARN` comments are there? Group them by kind.
2. `Unsupported multi-entry loop pattern (BACK_EDGE: B:8:0x000a -> B:4:0x0003)` — map those two
   block identifiers back onto your hand-drawn graph.
3. The `code lost:` comments print actual code. Reconstruct the method from them alone. Does it match
   the instruction dump?
4. What is in the method body? Why did jadx choose *that* rather than returning a dummy value?

### 1.3 The `--show-bad-code` trap

```bash
# host
jadx --show-bad-code -d out-bad Irreducible.smali
diff out-default/sources/com/pentest/ch56/Irr.java out-bad/sources/com/pentest/ch56/Irr.java
```

1. What did you gain? What did you lose?
2. Read the `--show-bad-code` method body carefully. What does it return for `irreducible(1, 5)`?
   (Trick question — read it again.)
3. If you skimmed past the comment block, what would you conclude this method does?
4. Write the one-sentence rule for when `--show-bad-code` is the right flag and when it is not.

### 1.4 The escalation ladder

```bash
# host
jadx -m simple   -d out-simple Irreducible.smali
jadx -m fallback -d out-fb     Irreducible.smali
```

Fill in:

| Mode | Does it refuse? | Does it assert loop structure? | Would you quote it in a report? |
|---|---|---|---|
| default (`auto`) | | | |
| `--show-bad-code` | | | |
| `-m simple` | | | |
| `-m fallback` | | | |

Then: chapter §4.3 prints jadx's pass list. Find the pass in `getSimpleModePasses` that mechanically
guarantees simple mode never refuses, and name it.

**Bonus, and it matters.** Compare the last two lines of `-m simple`'s `irreducible` with the
corresponding branch targets in `-m fallback`. They are not the same. Which do you trust, and what
does that tell you about where "simple" sits on the trust ladder?

---

## Part 2 — Warned wrongness (30 min)

The second method in `Irreducible.smali`, `overlapping`, has a handler that jumps back into its own
protected region.

1. jadx does **not** refuse it. What does it print?
2. Compare with `-m fallback`. The fallback shows two separate accumulation steps inside the try
   region; the default shows one expression. Is the folded version equivalent?
3. Construct an input for which the two readings differ. (If `str` is null, both loop forever — you
   need a case where the *first* call succeeds and the *second* throws. Can `String.length()` succeed
   and `String.hashCode()` throw? What does that tell you about whether this particular method's
   divergence is *reachable*?)
4. Write down the general principle you just derived about when a folded expression inside a `try` is
   safe.

That last question is the one that sets up Part 3, where the divergence very much is reachable.

---

## Part 3 — Silence (60 min)

### 3.1 Read the bytecode first

Open `Accumulate.smali`. **Do not run jadx yet.**

By hand, trace `accumulate(new int[]{5})`:

| Step | Instruction | v0 after |
|---|---|---|
| 1 | `const/4 v0, 0x0` | |
| 2 | `aget v1, p0, 0` | |
| 3 | `add-int/2addr v0, v1` | |
| 4 | `aget v2, p0, 1` | |
| 5 | *(handler)* `add-int/lit8 v0, v0, 0x64` | |
| 6 | `return v0` | |

Write down the return value. Then trace `accumulate(new int[]{5, 7})` and write that one down too.

If you cannot do this without help, stop and read [14 §3.1–§3.4](../../14-Dalvik/README.md). This lab
does not work if you are guessing at the bytecode.

### 3.2 Now run jadx

```bash
# host
jadx -q -d out-acc Accumulate.smali
cat out-acc/sources/com/pentest/ch56/Acc.java
```

1. Does the output contain **any** `JADX WARN` comment? Any comment at all?
2. Does it compile? (Try.)
3. Does it look like something a person would write?
4. What does it return for `{5}`? Compare with your hand trace.

### 3.3 The tell

Look at the two `return` statements. Both begin `0 +`.

1. Why would a decompiler print `return 0 + 100;` instead of `return 100;`?
2. What was `0` originally?
3. State the general pattern in one sentence: **a folded expression inside a `try` whose leading
   term is a constant means ______**.
4. Now go back to the four situations in chapter §6.6's closing list ("where you are most likely to
   meet it for real") and, for each, describe the security claim that would be wrong.

### 3.4 Prove it

```bash
# host
javac -d _proof Proof.java && java -cp _proof Proof
```

Expected:

```
original(new int[]{5})    = 105
jadx output(new int[]{5}) = 100
```

1. `Proof.original` is a Java *transcription* of the Smali. How do you know the transcription is
   faithful? (Answer: compile it with `javac --release 8` + `d8 --release`, run
   `jadx -m fallback` on the result, and compare the instruction dump with
   `jadx -m fallback Accumulate.smali`. **Do this.** Do not accept the transcription on trust —
   that is the whole ethic of the lab.)
2. Having done that, you have a second, larger surprise waiting. Note what jadx does with the
   compiler-produced version of `original`. Write it down; Part 4 is about it.

---

## Part 4 — Isolate the trigger, and fail honestly (45 min)

You now know that:

- jadx mis-decompiles `Accumulate.smali`.
- jadx correctly decompiles the `javac` + `d8` build of the same program.

So the difference is not the program. It is something about the input.

### 4.1 Narrow it

`VariantV4.smali` is the same program with `javac` + `d8`'s **exact** register allocation. Run it:

```bash
# host
jadx -q -d out-v4 VariantV4.smali
jadx -q -m fallback -d out-v4-fb VariantV4.smali
```

1. Is `out-v4` correct or wrong?
2. Compare `out-v4-fb` with the fallback dump of the compiler-built version from 3.4. Identical?
3. Write your own variants. Try at least: three-address `add-int` instead of `add-int/2addr`; a
   different `.registers` count; a handler with no `move-exception`. Record each result.
4. What have you eliminated? What is left?

### 4.2 Write it up

Produce a **minimal reproducer** in the form a maintainer could act on:

- jadx version (exactly).
- The smallest input that reproduces it.
- Expected output and actual output, both quoted.
- The evidence that the expectation is right (your hand trace plus the `Proof.java` run).
- **What you did not establish.** Specifically: the input reached jadx through jadx's own
  `smali-input` assembler, so a difference introduced by the assembler rather than the decompiler has
  not been ruled out. Say so.

Read chapter §6.6's closing paragraphs and check your write-up against them. If your write-up asserts
more than you measured, cut it back.

> **This is the professional skill the lab is actually training.** Anybody can find a tool bug. What
> distinguishes a report worth reading is a precise statement of what was measured, what was
> inferred, and what remains unknown. Practise it here, where nothing is at stake.

Optional and genuinely worthwhile: search
[the jadx issue tracker](https://github.com/skylot/jadx/issues) for existing reports of
exception-edge value loss before you write anything. Finding the existing issue is a better outcome
than filing a duplicate, and searching first is part of the skill.

---

## Part 5 — Resolve it in Smali, properly (45 min)

Everything so far used jadx's own renderings. Now do it the way you would on an engagement.

### 5.1 If you have apktool or baksmali

```bash
# host — build a DEX from the smali, then disassemble it with a different tool
# (or, on a real engagement, just: apktool d -o work app.apk)
```

Compare the real Smali with `jadx -m fallback`'s rendering. List every difference in *notation*
(`v0` versus `r0`, mnemonics present or absent, offsets versus labels) and confirm there is no
difference in *meaning*.

### 5.2 If you do not

Use `scripts/jadx-vs-smali.sh`, which handles all five renderings in one command and tells you which
steps it skipped:

```bash
# host
../scripts/jadx-vs-smali.sh ../examples/02-when-jadx-is-wrong/Accumulate.smali \
                            com.pentest.ch56.Acc accumulate
```

Read its closing "How to read this" section and answer:

1. What is the difference between the script's step (1) and step (2)? Which flags produce it?
2. What is the difference between step (2) and step (3)?
3. For *this* method, at which step does the wrongness become visible?

### 5.3 The four questions

Chapter §6.3 lists four questions worth arriving in Smali with. Answer all four for `accumulate`:

1. Which registers hold what at the point you care about?
2. Where exactly does the `try` range start and end, and what is live at the handler?
3. What is the exact order of the arithmetic instructions?
4. What is the true method descriptor?

Then state which of the four the decompiled Java answered correctly, and which it did not.

---

## Part 6 — The finding write-up (30 min)

Imagine `accumulate` is a real method in a real app: a retry counter that is incremented inside a
`try`, and whose value determines whether the app locks the account. You have been asked to report on
the lockout logic.

Write the finding. One page. It must contain:

| Section | Requirement |
|---|---|
| Claim | One sentence, about the app's behaviour, that a developer could act on |
| Evidence | Quoted **Smali**, not Java. Say why |
| Reproduction | The exact commands, with tool versions |
| Impact | Honest. Not inflated |
| Remediation | As code |
| Confidence and limits | What you verified statically, what you verified at runtime, what you did not verify |

Then do the thing that makes it a real exercise: **write the same finding from the decompiled Java
alone**, as a colleague in a hurry would, and put the two side by side. Identify every sentence in
the second version that is wrong or unsupportable.

---

## Part 7 — Build the suspicion reflex (30 min)

Everything so far was on inputs someone told you were suspicious. On a real engagement nobody tells
you. This part builds the reflex that replaces being told.

### 7.1 The drill

For each of the following decompiled fragments, say in one sentence whether you would (a) read on,
(b) check `JADX WARN` comments in the file, or (c) go straight to the bytecode — and why.

```java
// A
int retries = 0;
try {
    retries = attempt(url);
    return retries + attempt(backupUrl);
} catch (IOException e) {
    return retries + 1;
}
```

```java
// B
public byte[] sign(byte[] payload) {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(KEY, "HmacSHA256"));
    return mac.doFinal(payload);
}
```

```java
// C
while (true) {
    switch (i) {
        case 0: i = 7; break;
        case 7: x = decode(a); i = 3; break;
        case 3: return x;
    }
}
```

```java
// D
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.main);
    if (isDeviceSecure()) { unlock(); }
}
```

```java
// E
public static int check(int[] flags) {
    try {
        return 0 + flags[0] + flags[1];
    } catch (Exception e) {
        return 0 + 255;
    }
}
```

<details>
<summary><b>Answers</b></summary>

- **A** — (c). An accumulator (`retries`) is updated *inside* a `try` and read in the `catch`. This is
  exactly §6.6's shape. If `attempt(url)` succeeds and `attempt(backupUrl)` throws, the two readings
  differ. Whether jadx got it right here is unknowable from the Java.
- **B** — (a). Straight-line code, no exception edge doing anything interesting, no folding of a
  mutated value. Read on. (The *finding* — a hardcoded `KEY` — is a different matter, and is
  confirmed by checking the DEX string table, not the bytecode structure.)
- **C** — (b) then (c). Control-flow flattening. The Java is probably *correct* and definitely
  useless. Check the warnings, then use `--cfg` to get the graph, and go to
  [40 — Obfuscation](../../40-Obfuscation/README.md).
- **D** — (a), with one caveat: if you care about what ran *before* `super.onCreate`, check for
  `JADX WARN: 'super' call moved to the top of the method`. That warning appeared 2,160 times in one
  ordinary app and it means the code was **reordered**.
- **E** — (c), immediately. Two leading `0 +` terms in a folded `try`. This is the §6.6 shape with the
  serial numbers filed off.

</details>

### 7.2 Write your own rule

Chapter §6.3 gives a symptom table. Add to it, in your own words, the three shapes *you* now find most
suspicious, and for each one say what one-command check settles it.

The point is not to memorise a list. It is to have a reflex that fires before you write a sentence
down.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `jadx` prints help then hangs | GUI launcher, not the CLI | `export JADX_JAR=".../lib/jadx-gui-<ver>-all.jar"`; chapter §1.3 |
| `error: no such file` on a `.smali` input | You are not in `examples/02-when-jadx-is-wrong/` | `cd` there, or pass an absolute path |
| `jadx` produces no `.java` for a `.smali` file | A syntax error in the Smali; jadx's assembler is stricter than you expect | Run without `-q` and read the error. Common causes: a label used before definition, a `.catch` range that does not enclose its instructions |
| Your hand-written variant decompiles *correctly* | You accidentally wrote reducible control flow, or the accumulator is not live on the exception edge | Check with `-m fallback` that you wrote what you meant |
| `Proof.java` prints the same number twice | You edited `jadxVersion` to match `original` | Paste jadx's output verbatim; the whole point is that it is not a paraphrase |
| `javac` refuses `Proof.java` | Nothing in it is version-sensitive; check you are not in a directory with a stale `Proof.class` | `rm -f Proof.class` |

## Success criteria

You are done when you can, without notes:

- [ ] Explain why irreducible control flow has no Java representation, using the word *reducible*
      correctly.
- [ ] Name the four decompilation modes and order them by trustworthiness.
- [ ] Explain why `--show-bad-code` can be worse than the default.
- [ ] Recognise a folded accumulator inside a `try` on sight and say why it is suspicious.
- [ ] Produce, from memory, the evidence rule from §5.4.
- [ ] State the load-bearing conclusion of §6.6 in one sentence.
- [ ] Say what your reproducer did **not** establish, without being prompted.

## What you should carry out of this lab

- jadx tells you about two of its three failure modes. The third is the one that costs you.
- The warnings are a **floor** on the error rate, not a ceiling.
- Compiler-shaped bytecode is inside jadx's tuned envelope; anything else is not — and obfuscators,
  packers, hand patches and bytecode-rewriting SDKs all produce "anything else".
- The escalation is cheap: `-m simple`, then `-m fallback`, then real Smali. Minutes, not hours.
- **Honest reporting of what you did not establish is a skill, and it is rarer than finding the bug.**

Next: [Lab 03 — Triage a real application](lab-03-triage-a-real-app.md).
