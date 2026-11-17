# Lab 04 — CTF: The Honest Decompiler

**Difficulty:** CTF
**Time:** 4–8 hours (30 minutes if you already internalised Lab 02; that is the point)
**Prerequisites:** [Lab 02](lab-02-the-method-jadx-gets-wrong.md) — genuinely required —
plus [14 — Dalvik](../../14-Dalvik/README.md) §3.1–§3.13.
Tools: **jadx and nothing else.** No device, no root, no network, no SDK.

---

## The challenge

```bash
# host
cd 56-JADX/labs/ctf-vault
jadx -d out Vault.smali
cat out/sources/com/pentest/ch56/ctf/Vault.java
```

There is exactly one flag in that class. It has the form `CTF{...}`.

**Submit it.**

That is the whole brief. Everything below is scaffolding you should try not to need.

---

## Warm-up: are you ready for this? (5 min)

Answer these three from memory. If you cannot, go back to [Lab 02](lab-02-the-method-jadx-gets-wrong.md)
— this challenge is not fun without them, it is just frustrating.

1. Name jadx's three failure modes, and say which one prints no warning.
2. What does `-m fallback` give you that the default does not, and why is it more trustworthy?
3. In `add-int/2addr v0, v1`, which register is written and what is the source of the other operand?
   (If this one stumps you: [14 §3.1–§3.4](../../14-Dalvik/README.md).)

Then check your toolchain in one command:

```bash
# host
jadx --version    # or: java -cp "$JADX_JAR" jadx.cli.JadxCLI --version
```

If that prints a version and then **hangs**, you are running the GUI launcher — chapter §1.3.

## Rules

1. **jadx is the only tool you need.** It bundles a Smali assembler, so `Vault.smali` is a complete
   self-contained input. If you have `apktool`, `baksmali` or the SDK, you may use them — they will
   not make it easier.
2. You may compute in any language. You may not need to.
3. **Do not open [`ctf-vault/SOLUTION.md`](ctf-vault/SOLUTION.md)** until you have a flag you believe
   in — and then open it, because the interesting part is *why* you believed it.

---

## What is actually being tested

Not XOR. Not Smali trivia. Three specific habits:

| Habit | Where it is tested |
|---|---|
| Not submitting the first thing that looks like a flag | Stage 0 |
| Disbelieving decompiled Java that carries no warning | Stage 1 |
| Reading an instruction dump jadx refused to structure | Stage 2 |

Each stage has a wrong answer that is *easy* and *confident*. That is deliberate. Everything about
this challenge is designed so that a competent person who trusts their tool fails it, and the same
person who checks their tool passes it in twenty minutes.

---

## Scoring yourself honestly

Before you start, write down which of these you expect to do. Afterwards, tick what you actually did.

- [ ] I grepped for `CTF{` and submitted what I found.
- [ ] I read `flag()` and reimplemented it using the values jadx printed.
- [ ] I noticed one method had no warnings and was still wrong.
- [ ] I hand-traced a method jadx refused, from its instruction dump.
- [ ] I checked my answer against a second rendering (`-m fallback` or `-m simple`) before submitting.
- [ ] I noticed that my first wrong answer was *nearly* right, and worked out why.

The last one is a gift the challenge gives you if you get partway. Watch for it.

---

## Hints

Read them one at a time, and only when you are genuinely stuck. Each costs you some of the lab.

<details>
<summary><b>Hint 1 — I ran grep and found a flag immediately.</b></summary>

You found a `String` constant. Ask yourself: does anything in the class *use* it?

`flag()` does not. It is a decoy, and the string itself tells you what mistake you just made. Read
the class, do not search it.

</details>

<details>
<summary><b>Hint 2 — I read flag() and reimplemented it, and got mojibake.</b></summary>

Good — that means you read the code rather than searching it. `flag()` decompiled correctly; it is
the only method here that did.

So the decoder is right and the *inputs* are wrong. There are exactly two inputs: `seed()` and
`rounds(...)`. Look at each one and ask which of chapter §1.4's three failure modes it is in.

</details>

<details>
<summary><b>Hint 3 — rounds() failed. jadx says so.</b></summary>

Yes, loudly: `Unsupported multi-entry loop pattern`, plus a complete instruction dump. That is jadx
being honest (chapter §6.4).

The dump is complete. Trace it by hand, on paper, for the argument `flag()` actually passes. Note
that the argument depends on `seed()`, so you need `seed()` right first.

`-m simple` and `-m fallback` give you two more renderings of the same method. Chapter §3.7 orders
them by trustworthiness. Do not skip that ordering — one of them is subtly different from the other.

</details>

<details>
<summary><b>Hint 4 — seed() looks fine. It has no warnings at all.</b></summary>

That is exactly the problem, and it is the thesis of the entire chapter.

> jadx's warnings are a **floor** on its error rate, not a ceiling. A file with no `JADX WARN`
> comments is not a file that decompiled correctly; it is a file where jadx had no doubts.

Look at `seed()`'s two `return` statements. Both start with `0 +`. Chapter §6.6 tells you exactly
what a leading constant in a folded expression inside a `try` is the residue of, and why it is
dangerous *there specifically*.

Then read the Smali, and hand-trace what the accumulator actually holds when the handler runs.

</details>

<details>
<summary><b>Hint 5 — I have a flag but it looks scrambled at the edges.</b></summary>

Then your `seed()` is right and your `rounds()` is wrong, and the challenge is telling you so. A
rotation that is off by one produces text that is *visibly* the flag with its ends swapped.

Go back to Stage 2 and re-trace. Check which argument `flag()` passes to `rounds()` — it is derived
from `seed()`, so a corrected seed changes it.

</details>

---

## Stage guide, if you want structure

You do not need this to solve it, and reading it removes some of the challenge.

<details>
<summary><b>Show the three stages</b></summary>

**Stage 0 — the decoy.** There is a `String` constant that matches `CTF{`. Nothing references it.
Submitting it is the failure mode "I searched the output instead of reading it".

**Stage 1 — the silent failure.** `seed()` decompiles into clean, warning-free, compiling Java that
returns a different number from the bytecode. This is chapter §6.6's failure mode, in the exact shape
`examples/02-when-jadx-is-wrong/Accumulate.smali` demonstrates. Read the Smali; hand-trace what the
accumulator holds when the exception fires.

**Stage 2 — the loud failure.** `rounds(int)` is refused: irreducible control flow, a multi-entry
loop, with all the warnings jadx has. The instruction dump is complete, so hand-trace it — for the
argument `flag()` actually passes, which depends on Stage 1.

`flag()` itself decompiles perfectly and is the one method here you can read and reuse.

</details>

---

## After you have the flag

Do not stop at submitting it. Answer these, in writing — this is the part that makes it a lab rather
than a puzzle.

1. **Which stage would you have failed** if you had been working quickly on a real engagement? Be
   honest. Most people fail Stage 1, because it looks correct and carries no warning.
2. For Stage 1, **what was the single visual tell** in the decompiled Java? State it as a rule you
   could apply to unfamiliar code.
3. For Stage 2, jadx gave you a warning. **Why is that the *safer* of the two failures**, even though
   it is the uglier one?
4. If `Vault` were a real app's licence check, and you wrote a finding from the decompiled Java
   alone, **what specifically would your report have got wrong?** Write the wrong sentence out.
5. Chapter §5.4 gives an evidence rule in seven words. **Which part of it did this challenge
   enforce?**
6. Now the uncomfortable one. **How would you have known to check?** There was no warning on
   `seed()`. What is the general procedure that would have caught it without you already knowing the
   answer? (There is a real answer, and it is in §6.3's symptom table and §8.5's census. Find it.)

## The reusable skill: hand-tracing an instruction dump

Stage 2 needs you to execute a method on paper. That is a skill you will use on every engagement
where jadx refuses something, so it is worth doing deliberately rather than by squinting.

The method, in five steps:

**1. Write the register file as a row of boxes.** One box per register the method declares. Label the
parameter registers — in a static method with N parameters and `.registers R`, the parameters are the
*last* N registers, so `p0` is `v(R-N)`.

**2. Number the instructions.** jadx's dump uses labels (`L5`, `La`, `Lf`); the raw bytecode uses hex
offsets. Either works; be consistent, because you will be jumping around.

**3. Make a table with one row per step**, columns: step, label, instruction, each register's value
after, and the branch taken. Do not try to hold it in your head. Loops are where people lose track,
and a loop with two entry points is where they lose track fastest.

**4. Execute one instruction at a time.** Do not skip "obvious" ones. `const/4 v0, 0x0` matters
because it is the value that survives to the handler.

**5. Stop when you reach `return`,** and write down which register you are returning and what is in
it.

For the challenge, your table for `rounds(0)` should have five rows and end at `r0 = 8`. If you got
seven rows, you entered at the wrong label — which is the mistake the challenge is designed to
produce if Stage 1 went wrong.

> **The trap specific to multi-entry loops.** Your instinct will be to read the dump top to bottom
> like source code. Do not. The entry branch at the top jumps *past* the first block, and reading
> linearly gives you the other entry point's answer. Follow the arrows, not the page order. This is
> exactly why `--show-bad-code`'s "helpful" reconstruction is dangerous here: it removes the arrows.

## Verify your answer before you submit it

A CTF flag is a claim about program behaviour, which makes it exactly the kind of claim chapter §5.4
is about. Three independent confirmations, none of which requires knowing the answer in advance:

**1. Cross-render every method you depended on.**

```bash
# host
cd 56-JADX/labs/ctf-vault
for m in restructure simple fallback; do
    jadx -m "$m" -q -d "out-$m" Vault.smali
done
```

For `seed()` and `rounds()`, do the three renderings agree with each other? Where they do not, which
one does chapter §3.7 say to trust? (`fallback` — it asserts almost nothing.)

**2. Use the chapter's comparison helper.**

```bash
# host
../../scripts/jadx-vs-smali.sh Vault.smali com.pentest.ch56.ctf.Vault seed
```

Step (1) is the Java you were reading. Step (4) is the Smali. If your answer came from step (1) and
step (4) says something different, you have your answer *and* your lesson.

**3. Check the shape of the result.**

A flag is text. If your decode produces bytes outside printable ASCII, one of your inputs is wrong —
and if it produces *nearly* readable text, one input is nearly right. Both are information. Do not
throw away a partial result; read what it is telling you.

## A note on the one legitimate shortcut

You could build `Vault` into an APK, install it, and hook `flag()` with Frida. That is not cheating —
it is chapter §5.4's third leg, "prove it at runtime", and on a real engagement it is often the
fastest correct move.

But notice what it costs here: you need a device, an install (which on the reference device needs
`su -c 'pm install'`), frida-server running, and an app that does not resist instrumentation. On a
real target the last of those is frequently false. The static path you just walked works on a file
sitting on your laptop with no infrastructure at all, and that is why it is worth being good at.

[`../scripts/jadx-blindspot.js`](../scripts/jadx-blindspot.js) is built for the dynamic version, if
you want to try it.

## Building on it

- **Write your own.** Take a method from an app you are allowed to analyse, hand-write a Smali
  variant with a shape jadx mishandles, and check whether a colleague notices. You will learn more
  from constructing one than from solving three.
- **Make Stage 1 harder.** The `0 +` tell is generous. Can you construct a divergence with no visual
  tell at all? (If you can, that is a genuinely interesting result — and chapter §6.6's caveats about
  the `smali-input` path apply to your reproducer too.)
- **Solve it with Frida instead.** Build the class into an APK, install it, and hook `flag()`. Note
  how much faster that is — and confirm that it only works because you can *run* it, which on a real
  target may require getting past everything in
  [37 — RootDetection](../../37-RootDetection/README.md) and chapter 38 (TamperDetection).
  [`../scripts/jadx-blindspot.js`](../scripts/jadx-blindspot.js) is built for exactly this.
- **Check jadx's issue tracker.** Search for reports of value loss on exception edges. Is this shape
  known? Filing a good duplicate-free report is a skill; see Lab 02 Part 4.

---

## Build your own — a template

The best way to internalise this is to construct one. Here is the recipe, and it takes about an hour.

**Step 1 — pick a divergence shape.** Two are documented and measured in
[`../examples/02-when-jadx-is-wrong/`](../examples/02-when-jadx-is-wrong/):

| Shape | jadx does | Use it for |
|---|---|---|
| Accumulator updated inside a `try`, handler adds to it | Folds the accumulator away — **silent, wrong** | A value the solver must get right |
| Loop with two entry points | Refuses, with a complete instruction dump | A value the solver must hand-trace |

**Step 2 — make the wrong value produce a *wrong but plausible* result.** This is the design work.
Options that work:

- Chain the two stages so a wrong first value feeds a wrong second (`rounds(seed & 1)` in `Vault`).
- Choose a rotation so an off-by-one produces visibly-scrambled-but-recognisable text.
- Add an unreferenced `String` constant that a `grep` finds first.

**Step 3 — verify it three ways** before you give it to anyone:

```bash
# host
jadx -q -d out Yours.smali                 # does it decompile wrongly, as intended?
jadx -q -m fallback -d out-fb Yours.smali  # is the instruction stream what you meant to write?
# then compute both readings in Python and confirm they differ
```

**Step 4 — write the solution file first, not last.** If you cannot write a clean solution, the
challenge is not solvable; it is just obscure. That distinction is worth internalising for
report-writing too.

**Step 5 — state your caveats.** If your challenge relies on jadx's `smali-input` assembler, say so
(chapter §6.6). A challenge built on a claim you have not fully isolated should say which part is
solid and which is inference — exactly as a finding would.

## Troubleshooting

| Symptom | What it means |
|---|---|
| jadx produces no `Vault.java` | Wrong directory, or you passed the `.md` file instead of the `.smali` |
| jadx prints help and hangs | GUI launcher; chapter §1.3 |
| Your decode throws `IndexError` | The array has 28 entries; your modulus is wrong |
| Every character is above 127 | Your seed is wrong by a large amount — recheck Stage 1 |
| The output is readable but starts mid-word | Your rotation is off — recheck Stage 2, and re-derive the argument from your corrected seed |
| You get the flag but cannot explain why the naive path fails | Go back and do the "After you have the flag" questions. That is the lab |

## Scoring rubric

If you are running this as a group exercise:

| Points | For |
|---|---|
| 0 | Submitted the decoy |
| 1 | Correct flag, obtained by running the code somewhere |
| 2 | Correct flag, obtained by reading the bytecode |
| 3 | …and can name which of the three failure modes each method was in |
| 4 | …and verified against a second rendering before submitting |
| 5 | …and can state, unprompted, what the reproducer would *not* establish if reported upstream |

Levels 4 and 5 are the ones that matter professionally. Level 1 is the one most people reach.

## What you should carry out of this lab

- **The failure that costs you is the one with no warning.** Loud failures are safe; you go and read
  the bytecode. Silent ones you publish.
- A decompiler is a **search accelerator with a comprehension bonus**, not an oracle.
- Escalation is cheap. `-m simple`, `-m fallback`, real Smali — minutes, not hours.
- Anything you would submit, sign, or invoice for is worth one bytecode check.

Chapter: [56 — JADX](../README.md). When jadx fails, the destination is
[14 — Dalvik](../../14-Dalvik/README.md).
