# 68 — Reverse Engineering · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. Isn't reverse engineering just "read the decompiled code until you understand it"?**

No, and that description is the reason most people are slow at it. Reading is one activity available
to you; it is neither the goal nor usually the best next move.

The goal is to answer a specific question well enough to act on. "Understand the app" is not a goal
because it has no completion condition — real applications are hundreds of thousands of lines,
mostly third-party, and nobody understands them, including the people who ship them.

Concretely: in this chapter's own worked example, the question *"does this exported licence function
gate the vault?"* was settled in forty seconds by counting call sites. Reading the function carefully
would have taken twenty minutes and told you what it *does*, which is not what was asked.

---

**2. I have an APK and no idea where to start. What is the actual first command?**

Not a decompiler. It is:

```bash
adb -s <serial> shell pm path <package>
```

Because if that returns more than one line, you have a split installation, and analysing only
`base.apk` means analysing a fraction of the program. Chrome returns seven lines. One app in this
chapter's corpus has a `base.apk` of 334 KB containing essentially nothing.

But the honest answer to your question is that the first *action* is not a command at all — it is
writing down what you are trying to find out. If you do not have a question, no command helps,
because you will have no criterion for what to do with its output.

---

**3. What is a "hypothesis" here, really? It sounds like academic dressing-up.**

It is a statement about the target that could be false, phrased so that some observation you can
actually make would show it to be false.

The test is one question: *what result would make me abandon this?* If you cannot answer, you are not
investigating — you are looking for support, and you will find it, because confirming evidence is
cheap and everywhere.

Compare:

- *"The app checks the licence"* — nothing would refute this. Not a hypothesis.
- *"The `PREMIUM` string in `LicenseManager` is compared against user input on the path that unlocks
  export"* — one breakpoint refutes it. A hypothesis.

The dressing-up objection is fair when the question is small. A five-minute question does not need a
journal entry. The machinery is a scaling technique.

---

**4. Why does it matter whether I write the refutation before or after the experiment? Same result
either way.**

It is not the same result, and this is the single highest-leverage habit in the chapter.

Run the command first and you will interpret almost any output as consistent with what you already
believed. Zero call sites becomes "it must be called through a function pointer". A hook that does
not fire becomes "my hook must be wrong". Both are *sometimes true*, which is exactly what makes them
infinitely available as excuses.

Deciding in advance which result kills the hypothesis closes off the excuse. It costs one line.

---

**5. Everyone says "static and dynamic analysis". Isn't this chapter just both of those?**

No. [52](../52-StaticAnalysis/README.md) owns the static pipeline and [51](../51-DynamicAnalysis/README.md)
owns the runtime one, and both are assumed here.

What this chapter owns is what neither can do from inside: choosing between them, correlating their
outputs, and knowing what the pair together still cannot see. The concrete artefact is the funnel in
§2.2 that runs *both* branches and diffs them into three piles — agreed, static-only, and
runtime-only. The third pile is the one beginners never generate, and it is where the most expensive
errors hide, because it means something ran that is not in the artefact you analysed.

---

**6. Why do you keep saying decompiled Java is not the code?**

Because a decompiler does not invert compilation — it synthesises plausible source that would compile
to something like the bytecode it read. Usually that is faithful. Sometimes it is not, and it does
not tell you which.

[56-JADX](../56-JADX/README.md) built the decisive case: a method that decompiles to clean,
warning-free Java returning **100**, where the bytecode returns **105**. It ships `Proof.java` which
runs both readings and prints both numbers. No warning, no marker.

That is why the evidence ladder puts decompiled output at tier 3 and disassembly or Smali at tier 4.
Read the Java to form a hypothesis; confirm in the encoding before you write a finding.

---

**7. What does "tier" actually mean, and do I really have to label everything?**

A tier is how much a piece of evidence is worth. Six of them: inference, artefact shape, decompiled
code, ground-truth encoding, observed execution, controlled experiment.

You do not have to label everything. You have to label **the evidence behind a claim you publish**,
because your reader's ability to discount it correctly depends on knowing whether it rests on a
decompiler's guess or on an experiment you ran in both directions. A finding that says "the app sends
the token in cleartext" reads identically whether you saw it on the wire or inferred it from a method
name — and those are wildly different claims.

---

**8. Two of my sources disagree. Which one do I believe?**

Neither, yet — and this is good news rather than bad. A disagreement means one of your instruments is
wrong about this target, and finding that out is usually more valuable than the original question.

Two measured examples from this repository. Chapter 50 read `ro.boot.verifiedbootstate` as `green`
and pulled a TEE-signed attestation from the same device seconds later saying
`verifiedBootState=Unverified`. **The property lies; the hardware does not.** Chapter 51 found the
manifest declaring four components and the device's resolver tables listing three — and the entire
coverage-percentage argument falls out of which one you let define the denominator.

Chase the disagreement. It is the finding.

---

**9. Why can't I just grep the decompiled output for what I am looking for?**

You can, and you should — it is cheap. What you cannot do is conclude anything from finding nothing.

"I grepped and found nothing" is a statement about your grep. [56-JADX](../56-JADX/README.md) lists
five checks that must pass before absence becomes evidence: did decompilation complete, what was
refused, is code loaded dynamically, is it native, and do you have every split APK.

And [47-Authentication](../47-Authentication/README.md) measured the sharpest version of this:
grepping an APK for `FLAG_SECURE` has a **true-positive rate of zero**, because `javac` constant-folds
`0x2000` and the identifier survives in neither the `.class` files nor the DEX. Only
`const/16 v0, #int 8192` is there. The grep is correct, the tool works, the answer is worthless.

---

**10. The function I am looking for is not in the binary. Did I do something wrong?**

Probably not — the compiler inlined it, and this is extremely common at `-O2`.

This chapter's fixture has a `static inline` gate in the source. In the optimised build there is no
symbol, no call site, and no single branch you can point at. The decision survives as three bare
instructions fused into the caller.

The move that saves you: **when the function you expect does not exist, look for its constant.**
Inlining destroys names; it does not destroy the value being compared against. `cmp w8, #0xbd` is
still there.

Build the same source at `-O0` and diff, if you can. It is the cleanest way to see how far the binary
has drifted from the source structure.

---

**11. I hooked the function and forced it to return true, and nothing changed. Is Frida broken?**

Almost certainly not. There are five ordinary explanations before you get to "broken":

1. ART inlined the method, so your hook is on something nothing calls
   ([53](../53-Frida/README.md), [65](../65-Hooking/README.md)).
2. Wrong classloader.
3. The class was not loaded when you installed the hook.
4. The method genuinely did not run.
5. **The function's return value does not gate anything** — the decoupled-control case.

Number 5 is this chapter's example, and it is more common than people expect. In the fixture, forcing
the licence check to return true changes a printed line and nothing else, because nothing calls it.
Chapter 18 measured the same shape with a patch that provably worked against a function that provably
did not matter.

Before concluding anything: run a liveness check. Does the hook fire at all, on any input?

---

**12. My scan came back with nothing. Isn't that a good result for the client?**

Only if you can say what you looked at. "No issues found" is not a result; "we looked for X in these
fourteen places, did not find it, and here are the five things this method could not have seen" is.

The blind spots are measurable and large. 87% of the managed/native boundary is invisible to symbol
lookup. 69% of broadcast actions have no manifest receiver anywhere on the device. jadx refused 2,104
methods in one real APK while reporting 61 errors. Server-side logic is never in the client at any
tier.

A report that does not mention those implies a completeness that no method delivers, and the
implication is the dishonest part — not the gap, which is unavoidable.

---

**13. How do I know when I am finished?**

Four clauses, and you fail on whichever you fail on:

1. You can state the answer in **one sentence**.
2. You can name **two independent sources** supporting it.
3. You can name **what would have changed your mind**.
4. You can say **what you did not look at**.

If you cannot do (1) you have material, not an answer. If you cannot do (2) you have a lead. If you
cannot do (3) you have a belief. If you cannot do (4) you have an unbounded claim.

Notice that "I understand the app now" is not on the list. You never will, and it was never required.

---

**14. Isn't a "bypassed control" a finding? It sounds like one.**

No, and this is worth being firm about because it is the most common inflated finding in mobile
reports.

"I disabled root detection with Frida" describes your tooling. The finding is whatever the control
was protecting, reached and demonstrated. If disabling it reached nothing, there is nothing to
report.

There is a second problem underneath. [54-Objection](../54-Objection/README.md) measured
`android sslpinning disable` reporting **three successful hooks against an app with no network code
at all** — because the hooks target platform classes, not the app. A "successful bypass" message is
evidence that a hook installed, not that the app had a control.

---

**15. When should I stop trying to understand something and just move on?**

Ask: **do I need to understand this, or only to predict it?**

If a native routine turns a request into a signature and your question is "can an attacker forge
requests", you may not need the algorithm at all. You may only need to establish that the transform
is deterministic, callable on demand, and takes attacker-controlled input. That is often an hour's
work; the algorithm can be a week's.

You need genuine understanding when you must reproduce it off-device, when the finding is *about* the
algorithm's strength, or when you must write a detection signature. Otherwise, borrow it —
[53-Frida](../53-Frida/README.md)'s `sign-oracle.js` is that answer made concrete, and its header is
explicit that a valid signature proves nothing unless an invalid one is also shown to be rejected.

---

**16. Do I really have to keep a journal? I have a good memory and shell history.**

Shell history records what you typed, never what you were trying to find out or what you concluded.
When the report is due you will reconstruct the reasoning from the commands, and that reconstruction
is always wrong in the same flattering direction.

But the stronger argument is not about reporting. Notes **externalise the frontier** — what you know,
what you have ruled out, what you have not looked at. Held in your head, that frontier shrinks at
every interruption, so you re-cover ground you already covered while never entering the region you
never entered.

Seven lines per hypothesis. Ninety seconds. The chapter ships
[`scripts/re-journal.py`](scripts/re-journal.py), which enforces the parts people skip — no
hypothesis without a refutation test, no verdict without an observation, no question closed as
answered on a single source.

---

**17. Why does `frida -U` keep being called out as dangerous? It has always worked for me.**

Because it works by accident when exactly one device is attached, and fails silently when two are.

`-U` does not mean "the phone". It means "the first USB-type device Frida enumerates". While writing
this chapter, with a phone and an emulator both attached, `frida.get_usb_device()` returned the
**emulator** — different ABI (`x86_64` vs `arm64-v8a`), different API level (35 vs 30), different page
size (16 KiB vs 4 KiB). Every runtime measurement would have been silently correlated against static
evidence from the other device.

`adb` fails loudly in the same situation, which is better behaviour. Always pass `-D <serial>`, and
record the serial next to the measurement.

---

**18. My measurement came back as a clean zero across every sample. That is a strong result, right?**

It is a strong smell. **If a detector agrees with you about every sample, suspect the detector.**

This chapter's own first boundary measurement reported zero native methods across all eighteen APKs.
Clean, uniform, plausible, and completely wrong — `dexdump.exe` cannot read a DEX from inside an APK
on Windows, and printed `Processing 'base.apk'...` while failing.

The general form: before trusting a negative, run the instrument against something you *know* is
positive. Chapter 38's mapper reported a self-signature check in 18 of 18 APKs; hardened, it reported
a defensible 13 of 18. A detector that never says no has not been shown able to.

---

**19. How is this different from chapter 67, which also talks about when to stop?**

[67](../67-BypassingProtections/README.md) owns when to stop **hooking** — when the escalation ladder
has become a treadmill and you should go static instead. Its model is that hooking rents the answer
and static analysis buys it. That is a question about technique selection inside a bypass.

This chapter owns when to stop **understanding** — whether the question you were asked is answered
well enough to write down, which is a different decision that applies even when no protection is
involved. §3.15 is the stopping rule; §3.14 is the time-boxing that forces you to apply it.

They compose: 67 tells you which instrument, this chapter tells you whether to keep going at all.

---

**20. Everything here is about being careful and slow. Doesn't that make me worse at CTFs?**

For a small CTF, yes — the ceremony costs more than it saves, and a target you can hold entirely in
your head does not need scaffolding. The chapter says so in §10's last answer.

The method is a *scaling* technique. It pays when the target is large enough that you cannot keep the
frontier in memory, when the answer has to survive someone else's scrutiny, or when being wrong is
expensive. That is most professional work and almost no CTF work.

It is also worth noticing that the discipline is not actually slower in wall-clock terms on real
targets. The forty-second call-site count that kills a hypothesis is the *fast* move; spending twenty
minutes reading the function first is the slow one. Most of what looks like care is really about
refusing to do expensive things before cheap ones.
