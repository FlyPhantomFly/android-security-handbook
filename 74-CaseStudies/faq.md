# 74 — Case Studies · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct.

---

### 1. What is actually the difference between this chapter and 72?

**72's unit is the finding class; its evidence is counts.** *"Cleartext storage of session tokens
appears in N of M applications; here is the severity distribution."*

**74's unit is the story; its evidence is a trail you can walk.** *"Here is one investigation, in
order, including the forty minutes I spent looking in the wrong file."*

The practical test: if you are tabulating a rate across many applications, you are writing 72. If you
are narrating one target in order, you are writing 74.

---

### 2. Isn't a case study just a long finding?

No, and the difference is structural rather than one of length. A finding contains the conclusion and
the evidence that supports it. A case study contains **the conclusions that turned out to be wrong,
and what killed them.**

You can test it mechanically. Run `claim-ledger.py` over the document: if there are zero refuted
hypotheses, it is a report, however long it is.

---

### 3. Why does this chapter obsess over "which uid ran the command"?

Because it silently invalidates results, and this repository has measured it independently four
times.

The short version: `adb shell` runs as uid 2000 in the `shell` SELinux domain, in the `shell` group,
with 200 permissions granted to the `com.android.shell` package. An application runs as its own uid
in `untrusted_app` with whatever it declared. They see different files and different properties.

On the reference AVD, 37 property names are visible to `shell` and invisible to an application, and
three of them — `ro.debuggable`, `ro.secure`, `partition.system.verified` — are properties that
root-detection code routinely reads.

**A detection probe verified from `adb shell` has not been verified.**

---

### 4. `File.exists()` returns a boolean. What is complicated about that?

The boolean is the problem.

Underneath, the JVM performs a `stat`-family syscall. That call can fail two interesting ways:
`ENOENT` (the file is not there) and `EACCES` (it may be there; you are not allowed to find out).
`File.exists()` has no way to express the second — it returns a `boolean` — so both become `false`.

On a rooted device, the paths that root detection probes sit under `/data/adb`, which is mode
`0700 root:root`. An application gets `EACCES` at the *parent directory*, before reaching the file.
So the check returns `false` whether the artefact is there or not.

Use `android.system.Os.stat()` and catch `ErrnoException`, which preserves `errno`.

---

### 5. If the check always returns `false`, isn't that just a bypassed check?

No, and the distinction is the most practically important one in the chapter.

**Bypassed** means a working control was defeated. **Non-functioning** means there was never a
control. Writing "root detection can be bypassed" invites the developer to reply "we'll add more
paths" — which adds more paths beneath the same unreadable parent directory, and changes nothing.

Write "this check returns `false` on every rooted device and therefore provides no detection
capability." That cannot be answered by adding paths.

---

### 6. Why is patching a function and verifying the bytes not enough?

Because `objdump` reads the **file**, and you care about the **program**.

Two measured mechanisms make a verified-correct patch do nothing:

- **Short-circuiting.** An earlier guard returns before your function is reached. Measured on a
  licence gate where an upstream root probe fired first — and where the correct key alone also failed.
- **Inlining.** At `-O2` the compiler copied the check into its caller, so the binary has two copies
  and you patched the one nothing calls. Measured on a function that *observably returned 1* while
  the dependent operation still refused.

The artefact that settles it is a truth table: patched and unpatched, valid and invalid input, four
cells.

---

### 7. How do I tell inlining from short-circuiting?

Count call sites.

```bash
llvm-objdump -d lib.so | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

Few or no callers, yet the logic demonstrably runs, means **inlined**. The caller exists and shows an
earlier call plus a conditional branch, means **short-circuited**.

Do not use `grep 'bl.*<name>'`. A call through the Procedure Linkage Table renders as
`bl 0x1ac0 <name@plt>`, so that pattern misses it — and it misses in the direction that feels like a
finding. Use `bl.*<name(@plt)?>` or the `uniq -c` form, which does not depend on a regex at all.

---

### 8. How can `-O2` leak a string that `-O0` hides, from the same source?

Because if the ciphertext and the key are both compile-time constants, the optimiser is allowed to
evaluate your decode loop at build time and store the answer. It does.

Measured on this chapter's fixture: at `-O2`, `.rodata` contains `/system/xbin/su` and **no
ciphertext at all** — the array was deleted as dead once nothing referenced it. At `-O0` it contains
the ciphertext and no plaintext.

---

### 9. I put `noinline` on my decoder. Doesn't that fix it?

No, and the fixture in this chapter carries `noinline` specifically to show that.

`noinline` constrains the **inliner**. The transformation that leaks the string is **interprocedural
constant propagation** followed by **function specialisation**: every call site passes constants, so
the compiler rewrites the function body against them. Measured: `decode` went from 31 instructions at
`-O0` to **four** at `-O2` — `adrp`, `ldr q0`, `str q0`, `ret` — while still existing as a symbol and
still being called.

`58-IDA` records `noinline` as the fix for its fixture, and it worked there. It is not a general
remedy. What works is making the value unprovable — `static volatile` on the key — and the only
durable answer is for the secret not to be a compile-time constant in the first place.

---

### 10. Why check for the ciphertext as well as the plaintext?

Because "the plaintext is absent" has **two** causes: the obfuscation worked, or the compiler deleted
the whole construct including the ciphertext.

`58-IDA` hit exactly this. Its `strings` check correctly reported zero matches for both plaintexts,
so the construct looked verified. It was not — dumping `.rodata` showed the ciphertext was missing
too, because clang had folded the XOR, proved a comparison always true, and deleted the decode path
as dead. **The test passed for exactly the wrong reason.**

Run both lines. The first alone cannot distinguish the two cases.

---

### 11. Someone published a number I can't reproduce. Should I edit their chapter?

No. Publish the divergence with its evidence and let whoever holds the original hardware settle it.

This chapter faced exactly that: a published property count of 1053 for `shell` did not reproduce —
`shell` measured 673 and **root** measured 1055. The leading explanation is that the shell leg was
taken through `su`. That was *not* asserted, and chapter 39 was not edited, because the evidence is
one device, one session, and an arithmetic coincidence.

Silently rewriting someone else's measurement destroys the record of the disagreement, which is what
a future reader needs most. **"Diverged, cause not established" is a legitimate verdict.**

---

### 12. Before I call something a divergence, what should I rule out?

In this order:

1. **A different device.** Model, API level, ABI, page size, OEM build.
2. **A different vantage.** Root, shell, or app. This is the most common cause and the hardest to
   see, because the label in a write-up is prose while the measurement was a command.
3. **A different tool version.** Compilers especially — this chapter's case C is a statement about
   NDK 25.2.9519653, not about clang in general.
4. **A different command** than the one printed.

---

### 13. Is `run-as` good enough to stand in for a real app?

Partly, and the asymmetry is what makes it usable.

`run-as` gives you the `runas_app` SELinux domain. A normally installed application gets
`untrusted_app`. They are not the same. But `runas_app` is not *more* privileged in the ways that
matter, so:

- **A refusal generalises.** If `run-as` gets `EACCES`, a real app will too.
- **A success does not.** Confirm with a purpose-built probe APK before publishing it as a signal.

Every "the app cannot see this" conclusion in this chapter is therefore sound, and those are the
conclusions the findings rest on.

---

### 14. `grep -i xposed` found 58 apps. Is that a finding?

It is a finding about the English language.

The word "exposed" contains the substring "xposed". Audited over the same corpus: 1,141 total
occurrences, **1,141 accounted for by "exposed"/"Exposed", zero unexplained.** The arithmetic closes
exactly. Zero are genuine.

The rule: **explain every hit, or the signature is not evidence.** And never put a token shorter than
about eight characters in a high-confidence tier — R8 generates short lowercase class names, so the
false-positive rate *rises* on better-obfuscated applications, which is exactly backwards from
intuition.

---

### 15. My scanner's high-confidence band is full of hits. Isn't that good?

It is the warning sign. This repository has measured the same thing four separate times: a mapper
that reported a self-signature check in 18 of 18 APKs (real answer: 13); a sweep whose 17
high-confidence leads were 15 rejected by hand; a signature that scored 16 STRONG hits all of which
were minified class names; a grader that scored its own reference files backwards.

**If a detector agrees with you about a lot of samples, suspect the detector.** Adjudicate the top
band by hand *before* you believe the bottom of it.

---

### 16. Isn't "confidence" the same as "severity"?

No, and conflating them is how good findings get missed.

**Confidence** answers *"how likely is this to be what my rule was looking for"* — a question about
the rule. **Severity** answers *"how much does this matter"* — a question about the business.

In the measured sweep, 15 of 17 high-confidence leads were rejected, and the single best result in
the entire run sat at confidence **0.50**: an enum shipping thirteen environments in a production
build. A tester who sorts by confidence and writes up the top band misses it entirely.

---

### 17. Can I write a case study about a client engagement?

Yes, with care, and the care is not optional. Remove the vendor name, version strings, hostnames and
screenshots — then check whether the *combination* of what remains still identifies the target. "A
17 MB HR application with thirteen environments in a `Domain` enum" is already fairly specific.

Ask whether the lesson survives further blurring. It almost always does, because the lesson is
usually about a mechanism rather than about a company.

---

### 18. Why does this chapter keep saying "composed, not transcribed"?

Because they are different evidentiary claims and readers cannot tell them apart without being told.

A **transcript** proves the *order* of events — that this measurement really did come before that
realisation. A **composition**, assembled from separate sessions, proves only the events.

Both are legitimate artefacts. Presenting a composition as a transcript is not, because narrative
order is doing persuasive work it has not earned.

---

### 19. This all sounds like it slows you down enormously. Does it?

Less than you would expect, and the alternative is slower.

Writing the `R` line — *what would refute this* — takes about fifteen seconds and is the single
highest-yield habit here. Recording your device and vantage is one line in your notes. The
`vantage-diff.sh` run is one command.

What actually costs time is publishing something wrong and having it come back, or spending two hours
patching a function that nothing calls. Every technique in this chapter exists because someone paid
that cost first.

---

### 20. What if my re-run finds nothing wrong? Was it wasted?

No. Reproduction is evidence in its own right — a measurement that reproduces months later, on a
rebooted device, is far stronger than one that has never been checked.

But empirically it is rarely wasted. Of three case studies re-run for this chapter, **two produced
findings the originals did not contain and one produced an entirely new case study** that corrected a
published figure. The yield on re-running published measurements is much higher than it feels like it
should be, precisely because almost nobody does it.

---

### 21. I found a bug in my own tooling while writing this up. Do I report it?

Yes, and prominently. It is often the best content you have.

While writing this chapter, the auditor script `claim-ledger.py` failed its own self-test: its
provenance detector matched the word "provenance" inside a heading that read *"Two devices, no
provenance"*, and reported the document clean. That is the chapter's own case F — a substring
matching something other than what the sentence claimed — committed by the tool written to catch it.

Two lessons came out of it, and neither would exist if the bug had been quietly fixed: **a detector
that has never failed a fixture has never been tested**, and **knowing about a trap does not exempt
you from it.**

---

### 22. Which single habit should I adopt if I only adopt one?

Before you look at the result, write down what you would expect to see **if you were wrong**.

That is the `R` line. Every case in this chapter was rescued by something that amounts to having
written one, and every case study that went wrong went wrong because nobody had.
