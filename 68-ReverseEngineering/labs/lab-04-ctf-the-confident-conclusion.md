# Lab 04 — CTF: The confident conclusion

> **The challenge.** Six claims about a target. For each one you must answer **true or false**, cite
> the evidence, and — the part that scores — **declare the tier of that evidence and state what your
> answer does not establish.**
>
> A correct answer with overstated evidence **scores negative.** A correct "I could not establish
> this" scores positive. There is a flag, and getting it is worth less than half the available
> points.
>
> **Difficulty:** CTF · **Time:** 4–8 hours
> **Root needed:** Partly — every question has a no-device route
> **Prerequisite:** labs 01–03

---

## Why this CTF is scored the way it is

Every other challenge in this repository rewards reaching the answer. This one rewards **calibration**
— knowing how much your evidence is worth — because overclaiming is the characteristic failure of
reverse-engineering reports, and no amount of tool skill fixes it.

The measurements behind that claim are in this repository, not borrowed:

| Measurement | Result |
|---|---|
| A commercial app's HIGH-confidence static band, adjudicated by hand ([52](../../52-StaticAnalysis/README.md)) | **15 of 17 rejected** — doc links, `@Preview` fixtures, an XMP namespace |
| A leak hunter against real Chrome data ([33](../../33-Storage/README.md)) | **132 high-confidence hits, 132 false positives** |
| A self-signature-check detector across 18 APKs ([38](../../38-TamperDetection/README.md)) | first reported **18 of 18**; hardened, **13 of 18** |
| Apps with a certificate-pinning surface ([36](../../36-CertificatePinning/README.md)) | 12 of 14 had it; **4 actually pinned** |
| `FLAG_SECURE` found by grepping an APK ([47](../../47-Authentication/README.md)) | **true-positive rate of zero** — `javac` constant-folds `0x2000`, so the identifier survives in neither `.class` nor DEX |

That last one is worth pausing on, because it is this chapter's thesis measured by another chapter:
the grep is *correct*, the tool is *working*, and the answer is *worthless*, because only
`const/16 v0, #int 8192` survives compilation. Someone who greps and finds nothing has learned
something about `javac`, not about the app.

> **🧠 Mental Model.** The scoring here encodes one rule: **a finding is a claim plus the strength of
> its support.** Strip the second half and you have not simplified the finding, you have removed the
> part a reader needs in order to act on it correctly.

---

## Setup

```bash
# host
cd examples && ./build.sh --both-opt
export OUT="${TMPDIR:-/tmp}/ch68-build"
export NDKBIN="$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"

cd ../labs
python3 -B ../scripts/re-journal.py --file ctf.json init \
   --target libinvestigate.so \
   --sha256 "$(sha256sum "$OUT/libinvestigate.so" | cut -d' ' -f1)" \
   --version "-O2 and -O0" --device host
```

### The rules

1. **Do not open `examples/libinvestigate.c` until you have submitted all six answers.** It is the
   answer key. Opening it early does not cheat anyone but you, and it makes the scoring meaningless.
2. Every answer needs a **journal entry**: hypothesis, refutation test, experiment, raw observation,
   verdict.
3. Every answer needs a **tier declaration** and a **limits sentence**.
4. `unproven` is an allowed answer and is frequently the correct one.

### The tier scale

| Tier | What it is |
|---|---|
| 1 | Inference — "apps like this usually". Not evidence |
| 2 | Artefact shape — a name, a string, a symbol |
| 3 | Decompiled code — a reconstruction |
| 4 | Ground-truth encoding — disassembly, Smali, raw bytes |
| 5 | Observed execution |
| 6 | Controlled experiment — changed one input, outcome changed, changed it back |

---

## The scoring rubric

Read this **before** you start. It changes how you work, which is the point.

| Outcome | Points |
|---|---:|
| Correct answer, evidence at tier 4+, limits stated | **+10** |
| Correct answer, evidence at tier 2–3, limits stated, uncertainty acknowledged | **+6** |
| `unproven`, with a correct account of *why* it could not be established | **+7** |
| Correct answer, no limits stated | **+2** |
| Correct answer, tier **overstated** | **−5** |
| Wrong answer, limits honestly stated | **−1** |
| Wrong answer, stated confidently | **−10** |
| Any answer resting only on tier 1 | **−8** |

Bonus points:

| | Points |
|---|---:|
| The flag | **+15** |
| Finding the **inconsistency** between the two builds and stating which claims it affects | **+10** |
| Correctly identifying a claim that is **true of one build and false of the other** | **+10** |
| Your journal shows a hypothesis you recorded, refuted, and abandoned | **+5** each, max +15 |

**Maximum: 125.** A perfect score on the six claims alone is 60. The flag is 15. **More than half the
points are for method.**

> **⚠️ The trap in the rubric.** "Correct answer, tier overstated" scores **−5** — worse than a wrong
> answer honestly caveated. That is deliberate and it mirrors reality: a client who finds out your
> confident claim rested on a decompiler's guess stops trusting the four findings you got right.

---

## The six claims

Answer each: **true / false / unproven**, plus evidence, tier, and limits.

---

### Claim 1

> *"The library contains a hard-coded secret in the form `CH68{...}`."*

Cheap to check. Read it very carefully before answering — the claim says **contains**, which is a
statement about the artefact and not about behaviour.

<details>
<summary>What this claim is testing</summary>

Whether you notice that the claim as worded is answerable at tier 2 and is **true**, while the claim
a careless reader substitutes — *"the library's secret is `CH68{...}`"* — is a different claim,
answerable only at tier 5, and **false**.

Answering "true, tier 2, and this establishes only that the byte sequence is present; it does not
establish that it is returned, reached, or the protected content" is worth full marks.

Answering "true — I found the flag" is the −5 case.

</details>

---

### Claim 2

> *"`iv_check_license` determines whether the vault opens."*

<details>
<summary>Hint on making this decisive cheaply</summary>

The cheapest decisive experiment is a call-site count, and it takes under a minute. **But** the
obvious pattern has a measured false-negative mode: `llvm-objdump` renders a PLT-routed call as
`bl 0x1ac0 <iv_derive_seed@plt>`, so a pattern requiring `>` immediately after the name misses it.

Use `bl.*<name(@plt)?>`, **and** corroborate any zero against the full listing:

```bash
$NDKBIN/llvm-objdump -d "$OUT/libinvestigate.so" | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

A second, independent source is available if you can run the binary. Two independent sources is the
difference between +6 and +10.

</details>

---

### Claim 3

> *"The vault's decision is made by a function called `gate_is_open`."*

This one is the reason the CTF asks you to build both optimisation levels.

<details>
<summary>Hint</summary>

Check both `libinvestigate.so` and `libinvestigate-O0.so`. Then ask which build the claim is *about*
— and notice that the claim, as worded, does not say.

If you find that the claim is true of one build and false of the other, say so explicitly: that is
worth +10 on its own, and it is the single most transferable observation in this CTF. A finding that
rests on optimiser behaviour is a finding about a compiler, an optimisation level and a build, and a
report that does not say which is making an unbounded claim from a bounded observation.

</details>

---

### Claim 4

> *"The value the gate compares against is computed from the key the user supplies."*

<details>
<summary>Hint</summary>

Control flow will not connect the producer to the consumer at `-O2`, because there are no calls at
all. Two routes:

- **Static.** Find the global the gate loads from; find what writes it; read the recurrence and
  *predict* a key. Then test the prediction — that promotes your evidence from tier 4 to tier 6.
- **Dynamic.** [`scripts/dataflow-watch.js`](../scripts/dataflow-watch.js), which hooks the producer,
  captures the address written, and backtraces the first read.

Note the script's own recorded limitation: on a device whose vendor build blocks `execve` under
`/data/local/tmp`, `frida -f` on the bare binary fails with `unable to locate Android dynamic
linker`, and the fixture-spawn path is untested there. If that is your device, the static route is
the one available — and saying so in your limits is worth points, not lost points.

</details>

---

### Claim 5

> *"An attacker who patches `iv_check_license` to return 1 obtains the vault contents."*

<details>
<summary>Hint</summary>

This is the claim most people get right for the wrong reason, and the tier declaration is where it is
won or lost.

Answering "false, because `iv_check_license` has no call sites" is correct and is tier 4. Answering
"false, and I demonstrated it" requires actually doing it — patch or hook, run, observe. That is
tier 6 and worth more.

Answering "false" with no evidence beyond claim 2's result is defensible but you must say that is
what you are doing: you are *inferring* from a related finding rather than testing this one.

</details>

---

### Claim 6

> *"The protected content never exists in the file."*

<details>
<summary>Hint</summary>

Check the shipped `-O2` build. Then consider what would have to be true for this claim to be false,
and whether you can construct that case.

There is a real and instructive answer buried here. Two earlier versions of this fixture **failed**
this claim, for two different reasons, and the second reason is the interesting one. If you can work
out what a compiler does to a decode loop whose input it can prove, you have the +10 bonus and
something you will use on real targets.

</details>

---

## The flag

The flag is the vault's contents. Obtaining it requires a key, and the key is derivable from the
recurrence in Claim 4.

```bash
# host -- once you have a candidate key
adb -s <serial> shell "LD_LIBRARY_PATH=/data/local/tmp/ch68 \
    /system/bin/linker64 /data/local/tmp/ch68/investigate <your-key>"
```

Or, with no device, solve it entirely on paper: reconstruct the recurrence, solve for the gate
constant, then decode the masked bytes yourself with the seed as the mask.

> **⚠️ The decoy.** There is a `CH68{...}` string in `.rodata` and it is **not** the flag. Submitting
> it scores **0** for the flag and **−5** on Claim 1, because it means the tier-2 observation was
> read as a tier-5 one. That is exactly the error the whole CTF is built to catch, and it is the same
> error as chapter 47's `FLAG_SECURE` grep: a correct search producing a worthless answer.

<details>
<summary>Stuck on the recurrence? A structured route</summary>

1. Disassemble `iv_derive_seed`. Find the initial constant, the loop, and the two operations inside
   it (a shift and an XOR).
2. Write it in Python. Do not trust your reading yet.
3. Get the gate constant from `iv_open_vault`'s `cmp`.
4. Brute-force short keys until one produces that constant.
5. **Test it against the program.** If it opens the vault, your reading of the loop was right; if it
   does not, your reading was wrong and the program just told you so for free.

Step 5 is the whole point. Steps 1–4 give you a tier-4 hypothesis; step 5 makes it tier 6.

</details>

---

## Submission

Write `ctf-answers.md` in this shape:

```markdown
## Claim N — <true | false | unproven>

**Evidence.**
- tier N — <the raw observation, not your interpretation>
- tier M — <second source, if you have one>

**This does not establish.** <one sentence>

**Confidence.** <high | medium | low> because <reason>
```

Then attach your journal:

```bash
# host
python3 -B ../scripts/re-journal.py --file ctf.json status
python3 -B ../scripts/re-journal.py --file ctf.json report >> ctf-answers.md
```

---

## Self-scoring

Once submitted, open [`examples/libinvestigate.c`](../examples/libinvestigate.c) — including its
"four traps, stated honestly" block — and score yourself.

<details>
<summary>THE ANSWER KEY — do not open until you have submitted all six</summary>

### Claim 1 — **TRUE**, tier 2

`strings -a` finds `CH68{n0t_th3_r3al_0ne_keep_going}`. The claim says *contains*, and it does.

**Does not establish:** that the string is returned to a caller, that it is reachable, or that it is
the protected content. It is `kDecoy`, returned by `iv_banner`, printed unconditionally on every run
including failures. Full marks require that sentence.

### Claim 2 — **FALSE**, tier 4, ideally 6

Zero call sites, under a pattern that also catches `@plt`, corroborated by the full `bl` listing:
`iv_check_license` appears in neither build's call targets. At tier 6, running the binary shows the
control **anti-correlated** with the outcome:

```
PREMIUM-2024-VALID -> license: accepted   result: refused
measure            -> license: rejected   result: CH68{ev1dence_b3ats_a_good_story}
```

This is trap 1. The function is exported, named exactly what you would grep for, contains a plausible
literal, and is called by nothing.

### Claim 3 — **TRUE of `-O0`, FALSE of `-O2`**, tier 4

At `-O0`, `gate_is_open` is a symbol and `iv_open_vault` calls it:
`bl 0x1a3c <gate_is_open>`. At `-O2` it has **no symbol and no call site** — clang inlined it, and the
decision survives as three bare instructions:

```
adrp x8, #0x104000 ; ldrb w8, [x8, #0x11] ; cmp w8, #0xbd ; b.ne <refuse>
```

Answering plain "false" is correct for the shipped build and scores +10 with limits. Identifying the
split is the +10 bonus. This is trap 2, and its general form is: **when the function you expect does
not exist, look for its constant.** Names are destroyed by inlining; constants are not.

### Claim 4 — **TRUE**, tier 4 or 6

`iv_derive_seed` computes `acc = ((acc << 1) ^ key[i]) & 0xff` starting from `0x3f`, and stores the
result in a global. The gate reads that global and compares against `0xbd`. `seed("measure") == 0xbd`.

**Does not establish** — and this is where the tier declaration matters — that the *only* input is the
key, unless you tested it. This is trap 3: producer and consumer are connected by a memory address,
not a call edge, which is why control-flow analysis will not find it and why
[37-RootDetection](../../37-RootDetection/README.md)'s lab 04 defers the technique here.

### Claim 5 — **FALSE**, tier 4 (6 if demonstrated)

Follows from Claim 2. Patching or hooking `iv_check_license` changes the printed `license` line and
nothing else, because nothing calls it and the runner does not act on its verdict.

This is the shape that produces false "successful bypass" reports.
[18-ARM](../../18-ARM/README.md) §5.4 measured a patch that provably worked against a function that
provably did not matter; [54-Objection](../../54-Objection/README.md) measured a pinning bypass
reporting three successful hooks against an app with no network code at all.

### Claim 6 — **TRUE of the shipped build**, tier 4

`strings -a` on the `-O2` build finds only the decoy. The flag is assembled at runtime into a stack
buffer.

**And this is the +10 bonus.** Two earlier versions failed this claim:

1. Masking with a literal `#define MASK 0xc7` — clang constant-folded the whole decode loop and put
   the plaintext in `.rodata`.
2. Masking with the runtime value `g_state.seed` — **still folded**, because control flow only
   reaches the loop after `gate_is_open(g_state.seed)` proved `seed == 0xbd`. The compiler
   substituted the constant it had just proved.

**The check that guards the secret is what told the compiler the secret.** Only a `volatile` read —
defined as observable behaviour, so not foldable — stopped it. Same reason
[19-Memory](../../19-Memory/README.md) uses a `volatile` loop for scrubbing.

The transferable lesson: any "validate, then decode" pattern hands the optimiser a proof of the
validated value on the decode path, and the obvious repair does not help. There is no warning, and
the source review passes.

### The flag

```
CH68{ev1dence_b3ats_a_good_story}
```

Key: `measure`. Note that the fixture's own gate constant was chosen to make that word work — which
is a small joke and also the chapter's argument.

</details>

---

## Score interpretation

| Score | Reading |
|---|---|
| **90–125** | You are calibrated. Your reports will be trusted, including the parts you hedge |
| **60–89** | Solid. Look at where you lost points — it is almost always a missing limits sentence |
| **30–59** | You are finding answers and overstating them. This is the most common professional profile and the most expensive |
| **0–29** | Re-read §2.3 and redo lab 02. The tiers are the whole skill |
| **Negative** | You answered confidently from tier 1–2 evidence. Better than it feels: you now know the failure mode by name |

> **🔍 Pentester's Note.** A negative score here is genuinely common among people who are good at
> tools. Finding things is the easy half; knowing what a finding is worth is what separates a report
> a client can act on from a list of true statements.

---

## Debrief

1. Which claim did you get **right for the wrong reason**? Everyone has one. What evidence did you
   think you had?

2. Claim 3 is true of one build and false of the other. **Name three other findings** whose truth
   depends on a compiler or build flag, and say how you would phrase each so the dependency is
   visible.

3. The rubric scores a correct answer with overstated evidence **worse** than a wrong answer honestly
   caveated. Argue against that. Then argue for it. Which argument would you make to a client?

4. Claim 6's real answer is a compiler defeating an obfuscation twice, the second time because of the
   guard. **Where else does "the check proves the value" apply?** Consider licence validation,
   feature flags, and integrity checks that decrypt after verifying.

5. You now have a journal from this CTF. Hand it to someone else. **Could they reproduce your
   conclusions from it alone?** If not, what is missing is exactly what §3.12 says a journal is for.

---

## Cleanup

```bash
# host
cd ../examples && ./build.sh --clean-device
rm -rf "${TMPDIR:-/tmp}/ch68-build"
```

Nothing built by this chapter belongs in the repository — sources only.
