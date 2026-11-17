# Lab 01 — The first twenty minutes

> **Objective.** Take a target you have never seen, and in twenty minutes produce a written question,
> a one-page shape sheet, and three ranked candidate functions — **without reading a single function
> body.** Then prove to yourself that the ranking was worth making.
>
> **Difficulty:** Beginner · **Time:** 60–90 minutes (the triage itself is timed at 20)
> **Root needed:** No · **Device needed:** No — this lab runs entirely on the host

---

## Why this lab exists

Watch anyone inexperienced open an unfamiliar binary and the sequence is the same: decompile, open
the output, start reading at the top. Two hours later they are still reading, with no written
question, no criterion for what to read next, and no way to distinguish progress from motion.

The fix is not discipline in the abstract. It is a **specific, timed activity with a deliverable**
that happens before reading is allowed. That activity is triage, and this lab is twenty minutes of
it under a rule that makes it work: **you may not read a function body.**

The rule feels arbitrary and is not. The moment you start reading, you stop triaging and start
investigating — without having decided what to investigate. Triage is the decision about where to
spend the reading; you cannot make it by reading.

> **Definition — triage.** Sorting by urgency under time pressure, with incomplete information.
> The word comes from battlefield medicine, and the analogy is exact: you are not treating anything
> yet, you are deciding what gets attention and in what order, and the decision has to be made faster
> than a full assessment would take.

---

## Setup

You need the fixture built. From the chapter directory:

```bash
# host
cd examples && ./build.sh
```

That produces `libinvestigate.so` and `investigate` under `$OUTDIR` (default
`${TMPDIR:-/tmp}/ch68-build`), out of tree. Note the path it prints; the rest of this lab calls it
`$OUT`.

```bash
# host -- set this to whatever build.sh reported
export OUT="${TMPDIR:-/tmp}/ch68-build"
ls -la "$OUT"
```

You also need the NDK's binutils on your `PATH`, or their full paths to hand:

```bash
# host -- adjust for your NDK location and host triple
export NDKBIN="$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
alias nm="$NDKBIN/llvm-nm"
alias objdump="$NDKBIN/llvm-objdump"
alias readelf="$NDKBIN/llvm-readelf"
```

### The rule that makes this lab work

**Do not open `examples/libinvestigate.c`.** You compiled it, so the answer key is on your disk —
that is the whole point of using a fixture, and it is also the thing that will ruin the exercise if
you look now. You will read it at the end of lab 02 and grade yourself against it.

If you have already read it, use the optional real-application track in Part 4 instead, where no
answer key exists.

---

## Part 1 — Stage 0: write the question (5 minutes, not timed)

Before triage, a question. You have been given this brief, which is deliberately not a question:

> *"We ship `libinvestigate.so` inside a licensed product. Confirm that the licensing works."*

That is a goal. It is unanswerable as written, unbounded, and unfalsifiable — every outcome confirms
it. Decompose it.

**Task 1.1.** Write four questions that between them cover the brief, each passing all three tests
from §3.1. Write them in a file, not in your head:

```bash
# host
python3 -B ../scripts/re-journal.py init --target libinvestigate.so \
        --sha256 "$(sha256sum "$OUT/libinvestigate.so" | cut -d' ' -f1)" \
        --version "local build" --device "host"
python3 -B ../scripts/re-journal.py ask "What decides whether the vault opens?"
```

Add three more of your own. Test each against:

| Test | Fails if |
|---|---|
| **Answerable** | No observation could settle it |
| **Bounded** | Answering it requires understanding the whole program |
| **Falsifiable** | Every outcome confirms it |

<details>
<summary>Four that pass (open only after writing your own)</summary>

1. What decides whether the vault opens?
2. Is the deciding input derived from the key the user supplies, or from something else?
3. Does the exported licence-checking function participate in that decision?
4. Is the protected content present in the file, or produced at runtime?

all four are about **one decision**. That is what "bounded" buys you: the brief mentions
licensing, and you have converted it into questions with first commands.

Notice too what is *not* in the list: "how does the library work". It is unbounded, and nobody asked.

</details>

---

## Part 2 — The twenty-minute triage (timed)

Set an actual timer. The point of the constraint is that it forces you to choose, and choosing under
constraint is the skill.

**You may run any command that does not print a function body.** Symbol tables, section headers,
sizes, strings, imports — all allowed. Disassembly of a function body — not yet.

### Task 2.1 — Fill in the shape sheet

Answer every row. "Unknown" is a legitimate answer and is more useful than a guess, because it tells
you where the cheap questions are.

| # | Question | Your answer | Command that answered it |
|---|---|---|---|
| 1 | How big is the code? | | `readelf -S`, `ls -l` |
| 2 | Stripped, or symbols present? | | `nm` versus `nm -D` |
| 3 | How many exported functions? | | `nm -D --defined-only \| grep ' T '` |
| 4 | What does it import? | | `readelf -d`, `nm -D -u` |
| 5 | Any interesting strings? | | `strings -a` |
| 6 | Any flag-shaped strings? | | `strings -a \| grep -E '\{.*\}'` |
| 7 | Constructors that run before `main`? | | `readelf -S \| grep init_array` |
| 8 | What is the *biggest* function? | | see 2.3 |

Here are the commands, ready to paste:

```bash
# host -- 01. size and sections
readelf -S "$OUT/libinvestigate.so" | grep -E 'text|rodata|data|bss|init_array'
ls -l "$OUT/libinvestigate.so"

# host -- 02/03. the map a symbol-based tool gets
nm -D --defined-only "$OUT/libinvestigate.so" | grep ' T '

# host -- 04. what it needs from outside
readelf -d "$OUT/libinvestigate.so" | grep -E 'NEEDED|SONAME'
nm -D -u "$OUT/libinvestigate.so"

# host -- 05/06. strings, and flag-shaped strings
strings -a "$OUT/libinvestigate.so" | sort -u | head -40
strings -a "$OUT/libinvestigate.so" | grep -E '\{.*\}'

# host -- 07. anything running before main?
readelf -S "$OUT/libinvestigate.so" | grep -i init_array
```

### Task 2.2 — Rank the exports by *distance to the question*

You now have five exported functions and a question: *what decides whether the vault opens?*

Rank them. The criterion is **not** which name looks most relevant — that is the weakest of the four
ranking criteria in §3.4, and the only one obfuscation destroys. Use the ladder:

| Rank | Criterion |
|---|---|
| 1 | On a path from an entry point named in the question |
| 2 | Reads or writes the state the question is about |
| 3 | Sits at a trust boundary the question crosses |
| 4 | Name matches the question's vocabulary |

**Task.** Write your top three, and next to each write *which criterion* put it there. If all three
got there by criterion 4, say so — that is a real and common outcome, and knowing it changes how much
you trust the ranking.

### Task 2.3 — Function sizes without reading bodies

Sizes are structural, not semantic, so this is still triage. `nm -S` prints them:

```bash
# host -- exported functions by size, largest first
nm -S --size-sort -D --defined-only "$OUT/libinvestigate.so" | tac
```

**Question to answer in writing:** the largest function is usually the most complex. Is it your
top-ranked candidate? If not, what does the disagreement tell you?

<details>
<summary>What the sizes are telling you</summary>

`iv_open_vault` is substantially the largest, and `iv_banner` and `iv_attempts` are tiny — a couple
of instructions each, consistent with "return a constant" and "return a field".

`iv_check_license` sits in between: big enough to do something, small enough to be a comparison.

If your name-based ranking put `iv_check_license` first and the size ranking puts `iv_open_vault`
first, you have two rankings that disagree. **That disagreement is the most useful thing triage has
produced**, and §3.7's rule applies: when two sources disagree you have a better question than the
one you started with. Which is: *does the well-named function participate at all?*

</details>

### Task 2.4 — Stop

Timer's up. Write the sheet down. Do not continue because you feel close.

---

## Part 3 — Prove the ranking was worth making

A ranking you never test is a ritual. One command tests this one, and it is the cheapest decisive
experiment available (§3.6).

**Task 3.1.** Before running anything, record a hypothesis with its refutation:

```bash
# host
python3 -B ../scripts/re-journal.py hypothesise Q1 \
   --claim   "iv_check_license participates in the vault decision" \
   --predict "at least one call site in the library targets it" \
   --refute  "zero call sites target it, under a pattern that also catches @plt"
```

The tool will refuse the hypothesis if you leave `--refute` blank or trivial. That refusal is the
lab's real content.

**Task 3.2.** Run it:

```bash
# host -- note the (@plt)? -- see the warning below
objdump -d "$OUT/libinvestigate.so" | grep -cE 'bl.*<iv_check_license(@plt)?>'
```

**Task 3.3.** Record what you *saw*, then the verdict, separately:

```bash
# host
python3 -B ../scripts/re-journal.py observe H1 \
   --experiment "objdump -d libinvestigate.so | grep -cE 'bl.*<iv_check_license(@plt)?>'" \
   --observed   "0" --tier 4
python3 -B ../scripts/re-journal.py verdict H1 refuted
```

> **Warning — why `(@plt)?` is mandatory.** `llvm-objdump` renders a call routed through the
> Procedure Linkage Table as `bl 0x1ac0 <iv_derive_seed@plt>`. A pattern anchored on `>` immediately
> after the name **misses it entirely and reports zero for a function that is definitely called.**
> Measured on this fixture built at `-O0`: `iv_derive_seed` scores 0 with the bare pattern and 1 with
> `(@plt)?`. The chapter's own §8.3 records this as a false negative in its showcase experiment. A
> zero from a regex is worth what the regex is worth.

**Task 3.4 — corroborate the zero.** Never let a single regex carry a negative result. List every
call target in the library and confirm the name is absent from the whole list:

```bash
# host -- does not depend on getting a pattern right
objdump -d "$OUT/libinvestigate.so" | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' | sort | uniq -c
```

<details>
<summary>What you should see, and what it means</summary>

At `-O2` the library contains **no `bl` instructions at all** — everything that could be called has
been inlined. At `-O0` (build with `./build.sh --both-opt`) you get exactly three:

```
      1 bl	0x1a3c <gate_is_open>
      1 bl	0x1ac0 <iv_derive_seed@plt>
      1 bl	0x1ad0 <strcmp@plt>
```

`iv_check_license` appears in neither list. It is exported, it is named exactly what you would grep
for, it contains a plausible literal — **and nothing in the library calls it.**

Your name-based ranking pointed at a function that cannot possibly be the answer. That is not a
failure of the ranking; it is what rankings are for. It cost forty seconds to find out, and it is the
single highest-value forty seconds in this chapter.

Note also `gate_is_open`, which appears at `-O0` and vanishes at `-O2`. A function in the source with
no counterpart in the optimised binary — §3.9's point, visible in one diff.

</details>

---

## Part 4 — Optional: the same twenty minutes on a real application

The fixture has five exports. A real app has twenty thousand classes, and the funnel matters more,
not less.

> **Warning — scope and ethics.** Use an application **you own**, installed on **your own device**,
> or a well-known deliberately-vulnerable training app. Reverse engineering is contractually and
> statutorily contextual (§1.6); a lab suggesting it is not authorisation.

```bash
# host -- 01. EVERY apk, not the first. Splits are the norm, not the exception
adb -s <serial> shell pm path <your.package>

# host -- 02. identity, recorded before anything else
adb -s <serial> pull <path>/base.apk .
sha256sum base.apk
aapt2 dump badging base.apk | grep -E 'package: name|versionName'

# host -- 03. shape
unzip -l base.apk | grep -cE 'classes[0-9]*\.dex'
unzip -v base.apk | grep 'lib/' | head

# host -- 04. the app's own package prefix: your best noise filter
aapt2 dump badging base.apk | sed -n 's/^package: name=.\([^.]*\.[^.]*\).*/\1/p'

# host -- 05. the native boundary, in one line
python3 -B ../scripts/boundary-map.py base.apk --summary
```

**Task 4.1.** How many APKs did `pm path` return? If more than one, your `base.apk` is a fraction of
the program, and every subsequent "I found nothing" is worthless. Record it.

**Task 4.2.** Run `boundary-map.py --summary` and read the resolved percentage. Then run
`--explain` and write down, in your own words, why that percentage is **not** a count of
`RegisterNatives` bindings.

<details>
<summary>Reference points from the chapter's own corpus</summary>

Across 18 real APKs pulled from a phone: 8,140 distinct methods declared `native`, **1,049 (12.9%)**
resolvable to an exported symbol. Individual apps ranged from 0.0% to 71.8%.

Three APKs declared 480, 618 and 331 native methods and shipped **no arm64 library at all** in
`base.apk`. For those the honest reading is not "the boundary is invisible" but "the library is
somewhere else" — a different finding with a different next step.

And `com.vendor.professionalnet`'s `base.apk` was **334 KB**, yielding zero of everything. A sweep of it
finds nothing, and nothing is not a result.

</details>

---

## Success criteria

You have finished this lab when all of the following are true:

- [ ] Four written questions, each passing the answerable/bounded/falsifiable tests.
- [ ] A completed shape sheet with all eight rows answered, including any honest "unknown".
- [ ] Three ranked candidates, each annotated with **which ranking criterion** put it there.
- [ ] A hypothesis in the journal with a refutation test written **before** the experiment.
- [ ] The call-site count run with `(@plt)?`, and **corroborated** by the full `bl`-target listing.
- [ ] A verdict recorded, and the raw observation recorded **separately** from it.
- [ ] You can state, in one sentence, why the highest-ranked name was the wrong candidate.
- [ ] You did not read a function body during the timed twenty minutes.

Check the last one honestly. It is the only one that is hard.

---

## Hints

<details>
<summary>Hint 1 — I do not know what to put in the "biggest function" row</summary>

`nm -S --size-sort` prints sizes alongside symbols. Size is a structural property of the artefact,
not a semantic one, so reading it is still triage. Anything that requires you to look at
*instructions* is not.

</details>

<details>
<summary>Hint 2 — my ranking put everything at criterion 4</summary>

That is the expected outcome for a first pass, and it is worth recording as such. Criteria 1–3 need
information you do not have twenty minutes in: call graph, state access, boundary crossings. The
lesson is that a name-based ranking is what you *start* with and is the first thing to test — which
is exactly what Part 3 does.

Now imagine the same library with every symbol stripped. Which criteria still work? All of 1–3, and
none of 4. That is §3.13's table in miniature.

</details>

<details>
<summary>Hint 3 — the flag-shaped string looks like the answer</summary>

It is tier 2 evidence: it establishes that the file contains that string. It does not establish that
anything returns it, that it is reached, or that it is the secret.

Ask the next question: *what reads it?* One command:

```bash
objdump -d "$OUT/libinvestigate.so" | sed -n '/<iv_banner>:/,/^$/p'
```

That is a function body, so save it for after the timer. When you do run it, notice how short
`iv_banner` is and what it does with the string — and then notice that the runner prints the banner
on **every** invocation, including the ones that fail.

</details>

<details>
<summary>Hint 4 — the -O2 build has no bl instructions at all and I think it is broken</summary>

It is not broken. At `-O2` clang inlined every internal call into its caller, so there is nothing
left to call. Build with `./build.sh --both-opt` and compare against `libinvestigate-O0.so`, where
the calls are visible.

That comparison is worth doing deliberately: it is the cleanest demonstration in the chapter that
**the structure of the source is not the structure of the binary**, and that a finding resting on
"the check is inlined" is a finding about a specific compiler and optimisation level.

</details>

---

## Debrief

Answer these in writing before moving to lab 02.

1. Your twenty minutes produced a shape sheet and a ranking. **Which single row of the sheet changed
   what you did next?** If none did, the sheet was a form-filling exercise rather than triage.

2. The `grep -c` in Part 3 cost forty seconds. Reading `iv_check_license` in a decompiler would have
   cost twenty minutes and told you what it *does*. **Why is the forty-second command worth more?**

3. Part 3 asked you to write the refutation before running the experiment. Suppose you had run it
   first and seen `0`. **Name two explanations you might have reached for** that would have kept the
   hypothesis alive. (This is the mechanism the ordering exists to prevent.)

4. You now know `iv_check_license` is dead. **What is your next question?** Write it down before
   opening lab 02 — and notice that it is a question you could not have asked twenty minutes ago.

---

## Where this goes next

[Lab 02](lab-02-the-hypothesis-loop.md) picks up exactly here: the obvious candidate is eliminated,
the question is still open, and the next hypothesis has to come from somewhere other than a name.
That lab is the chapter's spine — if you do only one, do that one.
