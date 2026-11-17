# Lab 02 — The hypothesis loop, run in the open

> **Objective.** Answer the question lab 01 left open — *what decides whether the vault opens?* — by
> running the loop explicitly: hypothesis, prediction, refutation, experiment, verdict. You will
> record every step, including the ones that fail, and at the end you will open the source and
> **grade yourself against ground truth**, which is something a real target never lets you do.
>
> **Difficulty:** Intermediate · **Time:** 3–5 hours
> **Root needed:** No · **Device needed:** No for parts 1–5; optional for part 6
>
> **This is the chapter's spine. If you do only one lab, do this one.**

---

## Why this lab exists

Every published methodology reads as though its author walked straight to the answer. That is the
one thing that never happens, and pretending otherwise teaches beginners that their own floundering
means they are bad at this.

So this lab is written the other way round. It walks you into three wrong answers on purpose, and
the wrong answers are the content. Each one is attractive for a specific, nameable reason, and each
is killed by a specific, cheap experiment. What you are practising is not "finding the answer" — it
is **the loop that converts a wrong idea into a better one at low cost**.

The fixture is small enough that a determined reader could brute-force it in an hour. Do not. The
value here is entirely in the method, and the method is what transfers to a target where brute force
is not available.

> **Mental Model.** In a healthy investigation **most hypotheses die.** If yours mostly survive,
> you are writing hypotheses too weak to be refuted, and you are accumulating beliefs rather than
> knowledge. This lab has four hypotheses. Three of them are wrong.

---

## Setup

```bash
# host -- build both optimisation levels; you will need the comparison
cd examples && ./build.sh --both-opt
export OUT="${TMPDIR:-/tmp}/ch68-build"

export NDKBIN="$HOME/AppData/Local/Android/Sdk/ndk/25.2.9519653/toolchains/llvm/prebuilt/windows-x86_64/bin"
alias nm="$NDKBIN/llvm-nm"; alias objdump="$NDKBIN/llvm-objdump"; alias readelf="$NDKBIN/llvm-readelf"
```

Start a journal. It is not optional in this lab — Part 7 grades it.

```bash
# host
cd labs
python3 -B ../scripts/re-journal.py --file lab02.json init \
    --target libinvestigate.so \
    --sha256 "$(sha256sum "$OUT/libinvestigate.so" | cut -d' ' -f1)" \
    --version "local -O2 build" --device host
python3 -B ../scripts/re-journal.py --file lab02.json ask \
    "What decides whether the vault opens?"
```

> **Still do not open `examples/libinvestigate.c`.** Part 7 tells you when. Reading it now converts
> a three-hour investigation into a ten-minute reading comprehension exercise, and you will not
> notice what you lost.

### What you know from lab 01

| Fact | Tier | How you know |
|---|---|---|
| Five exported functions | 2 | `nm -D` |
| `iv_check_license` has **zero** call sites | 4 | `objdump` + corroborating full `bl` listing |
| `iv_open_vault` is the largest function | 2 | `nm -S --size-sort` |
| One flag-shaped string, `CH68{n0t_th3_...}` | 2 | `strings` |
| At `-O2` the library has **no `bl` instructions at all** | 4 | full call-target listing |

---

## Part 1 — H1: the string is the secret

The cheapest possible hypothesis, and the one a `strings`-first workflow stops at.

```bash
# host
python3 -B ../scripts/re-journal.py --file lab02.json hypothesise Q1 \
  --claim   "the flag-shaped string in .rodata is the protected content" \
  --predict "some code path returns it to the caller on success" \
  --refute  "it is returned unconditionally, or returned by nothing that is gated"
```

**Task 1.1.** Find out what reads it. This needs the string's address and a cross-reference:

```bash
# host -- where does the string live?
readelf -x .rodata "$OUT/libinvestigate.so" | head -20

# host -- which function materialises that address?
objdump -d "$OUT/libinvestigate.so" | sed -n '/<iv_banner>:/,/^$/p'
```

**Task 1.2.** Now the decisive part. `iv_banner` returns it — but *when*? Run the program three ways
and compare. If you have no device, reason from the runner's source
([`examples/investigate-main.c`](../examples/investigate-main.c) is a *runner*, not the target, and
reading it is allowed):

```
banner   : CH68{n0t_th3_r3al_0ne_keep_going}     <- key = PREMIUM-2024-VALID
license  : accepted
result   : refused

banner   : CH68{n0t_th3_r3al_0ne_keep_going}     <- key = wrongkey
license  : rejected
result   : refused
```

**Task 1.3.** Record and rule.

```bash
python3 -B ../scripts/re-journal.py --file lab02.json observe H1 \
  --experiment "run with three different keys, compare the banner line" \
  --observed   "banner identical in all three runs, including both failures" --tier 5
python3 -B ../scripts/re-journal.py --file lab02.json verdict H1 refuted \
  --note "printed unconditionally; gated by nothing"
```

<details>
<summary>Why this one is worth its own part</summary>

It is refuted by a property that has nothing to do with what the string *says*: it appears on runs
that fail. A value that is identical whether you succeed or fail cannot be the thing success gives
you.

That is a general and reusable move. **When you suspect X is the protected content, check whether X
differs between a success and a failure.** If it does not, X is not it, and you did not have to
understand a single instruction to know that.

Note also which tier settled it: **5, observed execution.** Tier 2 (the string exists, and looks
exactly like a flag) pointed the wrong way, confidently.

</details>

---

## Part 2 — H2: the licence check is the gate

Lab 01 already killed this one. Re-run it here anyway, because the *reason* it stays dead matters and
because you should watch a refutation hold up under a second, independent experiment.

```bash
python3 -B ../scripts/re-journal.py --file lab02.json hypothesise Q1 \
  --claim   "iv_check_license gates the vault" \
  --predict "forcing it to return true changes the outcome" \
  --refute  "the outcome is unchanged when its verdict is inverted"
```

**Task 2.1 — the static half**, from lab 01: zero call sites under `bl.*<iv_check_license(@plt)?>`,
corroborated by the full call-target listing.

**Task 2.2 — the dynamic half.** This is the independent second source (§3.7). Run the program with
the licence-check's own literal as the key:

```bash
# host or device
investigate PREMIUM-2024-VALID
```

```
license  : accepted
result   : refused
```

**The control reports `accepted` and the vault refuses.** Now the other direction:

```bash
investigate measure
```

```
license  : rejected
result   : CH68{ev1dence_b3ats_a_good_story}
```

**Task 2.3.** Record it, and notice the strength of the result:

```bash
python3 -B ../scripts/re-journal.py --file lab02.json observe H2 \
  --experiment "run with PREMIUM-2024-VALID and with a key that opens the vault" \
  --observed   "accepted+refused, and rejected+opened" --tier 6
python3 -B ../scripts/re-journal.py --file lab02.json verdict H2 refuted \
  --note "control is anti-correlated with the outcome, not merely decoupled"
```

> **Pentester's Note.** This is the **decoupled control** from §5.3, and it is where a large
> fraction of real "successful bypasses" come from. A tester who hooks `iv_check_license` and forces
> `return 1` sees `license : accepted`, writes "licence check bypassed", and has changed a log line.
> The vault never opened. Chapter 18 measured the same failure with a patch that provably worked
> against a function that provably did not matter; chapter 54 measured a pinning bypass reporting
> three successful hooks against an app with **no network code at all**.
>
> The report sentence that is actually true is: *"the exported licence routine does not participate
> in the entitlement decision"* — which is a finding, and a more interesting one.

---

## Part 3 — H3: then the decision is inside `iv_open_vault`

Two hypotheses dead. The remaining evidence points at the largest function, which is also the one
whose name matches the outcome. Now you may read a function body.

```bash
python3 -B ../scripts/re-journal.py --file lab02.json hypothesise Q1 \
  --claim   "the deciding comparison is inside iv_open_vault" \
  --predict "its disassembly contains a conditional branch on a value, guarding the success path" \
  --refute  "it contains no such branch, or the branch is on a constant"
```

**Task 3.1.** Read it:

```bash
# host
objdump -d "$OUT/libinvestigate.so" | sed -n '/<iv_open_vault>:/,/^$/p'
```

**Task 3.2.** Find the gate. You are looking for a load followed by a compare against a constant,
followed by a conditional branch. Something very like:

```
adrp    x8, #0x104000
ldrb    w8, [x8, #0x11]        ; load one byte from a fixed global address
cmp     w8, #0xbd              ; against a constant
b.ne    <the refusal path>
```

**Task 3.3.** Record it — and note this is **supported**, not answered:

```bash
python3 -B ../scripts/re-journal.py --file lab02.json observe H3 \
  --experiment "objdump the body of iv_open_vault, look for cmp + conditional branch" \
  --observed   "ldrb from a global, cmp against #0xbd, b.ne to the refusal path" --tier 4
python3 -B ../scripts/re-journal.py --file lab02.json verdict H3 supported
```

The tool will tell you that supported is not answered. It is right: you have one source.

<details>
<summary>Three things in that disassembly worth naming</summary>

**There is no function here.** The gate is three instructions fused into the caller's control flow.
If you went looking for a `gate_is_open`-shaped symbol you would find nothing, and "there is no check
in this binary" is a conclusion people genuinely reach from that.

**The constant survived.** `#0xbd` is right there, even though whatever function it belonged to is
gone. This is §6.3's rule and the single most useful heuristic in native RE: **when the function you
expect does not exist, look for its constant.** Names are destroyed by inlining; constants are not.

**Compare the two builds.** Build with `--both-opt` and disassemble `libinvestigate-O0.so`:

```bash
objdump -d "$OUT/libinvestigate-O0.so" | sed -n '/<iv_open_vault>:/,/^$/p' | grep -E '\bbl\b'
```

```
bl	0x1ac0 <iv_derive_seed@plt>
bl	0x1a3c <gate_is_open>
```

At `-O0` both functions exist and are called. At `-O2` neither call exists. **Same source, two
different programs to reverse.** Any finding you write that rests on "the check is inlined" is a
finding about a compiler and an optimisation level, and must say so.

</details>

---

## Part 4 — H4: the deciding byte comes from the key

You have a gate. You do not have the thing that feeds it, and — this is the point of the lab —
control flow will not give it to you. At `-O2` `iv_open_vault` contains **no calls at all**, so there
is no call edge from anything to anything.

```bash
python3 -B ../scripts/re-journal.py --file lab02.json hypothesise Q1 \
  --claim   "the byte at that global is derived from the key the user supplies" \
  --predict "the byte changes when the key changes" \
  --refute  "the byte is identical across different keys"
```

### Task 4.1 — Locate the global

The `adrp`/`ldrb` pair encodes the address. `adrp` loads a 4 KiB-aligned page address; the `ldrb`
offset completes it.

```bash
# host -- which symbol lives at that address?
nm "$OUT/libinvestigate.so" | sort
readelf -S "$OUT/libinvestigate.so" | grep -E '\.data|\.bss'
```

**Question to answer in writing:** is the address in `.data` or `.bss`, and what does that tell you
about whether the value is initialised in the file or written at runtime?

### Task 4.2 — Who writes it?

There are exactly two ways to answer this, and the difference between them is the whole lesson.

**The control-flow way**, which fails: look for callers of the gate, or for a function that returns
the value. `iv_derive_seed` returns an `int` status, not the seed. Nothing passes the byte anywhere.
The call graph does not connect the producer to the consumer, because **the connection is a memory
address, not a call.**

**The data-flow way**, which works: hook the producer, capture the address it writes, watch that
address, and take a backtrace on the first read. That is
[`scripts/dataflow-watch.js`](../scripts/dataflow-watch.js), and it is the technique
[37-RootDetection](../../37-RootDetection/README.md)'s lab 04 defers to this chapter:

> *when detection is decoupled from consequence, the general tool is data-flow tracking, not
> control-flow tracking. Your instinct to look for branches is what the pattern defeats.*

The script's configuration for this target is already its worked example:

```javascript
// scripts/dataflow-watch.js -- the CONFIG block
producerModule: 'libinvestigate.so',
producerSymbol: 'iv_derive_seed',
watchModule:    'libinvestigate.so',
watchOffset:    null,          // auto-discover: snapshot, run, diff
valueSize:      1,
```

```bash
# host -- ALWAYS -D <serial>; -U picks a device for you (README section 7.5)
frida -D <serial> -n <process> -l ../scripts/dataflow-watch.js
```

> **A limitation, measured and not worked around.** On the Redmi this chapter was written against,
> the vendor build blocks `execve` under `/data/local/tmp`, so the fixture runs only via
> `/system/bin/linker64` — and `frida -f /data/local/tmp/ch68/investigate` fails with
> `unable to locate Android dynamic linker`. **The fixture-spawn path for `dataflow-watch.js` is
> therefore untested on that device.** The script's machinery (export resolution, interception,
> region snapshotting, diffing, the report) was validated against a live app process instead. If your
> device permits direct execution, this task runs as written; if not, do Task 4.3, which reaches the
> same verdict statically.

### Task 4.3 — The static route to the same answer

Read `iv_derive_seed`. It is small:

```bash
# host
objdump -d "$OUT/libinvestigate.so" | sed -n '/<iv_derive_seed>:/,/^$/p'
```

**Task.** Work out the recurrence. You are looking for a loop over the key's bytes with a shift and
an XOR, starting from a constant. Write it as Python and *test your reading against the program*:

```python
# host -- your reconstruction of the loop, from the disassembly
def seed(k, a=0x3f):
    for c in k.encode():
        a = ((a << 1) ^ c) & 0xff
    return a

print(hex(seed("wrongkey")))     # predict the byte
print(hex(seed("measure")))      # predict the byte
```

**This is the experiment.** Your reading of the disassembly makes a *prediction*; the program's
behaviour is the *observation*. If `seed("measure") == 0xbd` and the program opens the vault for
`measure` and refuses everything else you try, your reconstruction is corroborated at tier 6.

```bash
python3 -B ../scripts/re-journal.py --file lab02.json observe H4 \
  --experiment "reconstruct the seed recurrence from iv_derive_seed; solve for the gate constant; test" \
  --observed   "seed('measure')==0xbd; program opens for 'measure', refuses wrongkey and PREMIUM-2024-VALID" \
  --tier 6
python3 -B ../scripts/re-journal.py --file lab02.json verdict H4 supported
```

<details>
<summary>If you cannot read the recurrence off the disassembly</summary>

Look for these three, in a loop:

- `ldrb` — loading one byte of the key
- `lsl` or `add w8, w8, w8` — a shift left by one (clang often emits the add)
- `eor` — the XOR

and before the loop, a `mov w8, #0x3f` establishing the starting value.

If you can identify the operations but not the order, brute-force is legitimate here and is *still*
an experiment: enumerate short keys, compute candidate seeds under each ordering you consider
plausible, and see which ordering predicts the program's actual behaviour. You are using the program
as an oracle to select between readings — which is §3.15's *predict rather than understand* applied
to your own uncertainty.

</details>

---

## Part 5 — Close the question properly

You have a supported answer from one direction. Section 3.15's stopping rule needs four things.

**Task 5.1.** The second independent source. Your tier-4 reading of the disassembly and your tier-6
behavioural test are genuinely independent: an error in reading the loop would not produce a key that
opens the vault.

```bash
python3 -B ../scripts/re-journal.py --file lab02.json close Q1 answered \
  --answer "The vault opens iff a byte derived from the key by a shift-XOR recurrence equals 0xbd; the comparison is inlined into iv_open_vault and the exported licence routine is not involved" \
  --source "tier4: ldrb from .bss global, cmp #0xbd, b.ne -- inlined, no symbol" \
  --source "tier6: key 'measure' (seed 0xbd) opens it; PREMIUM-2024-VALID and wrongkey refuse; reproduced"
```

The tool refuses this close if you supply fewer than two sources. Try it with one and read what it
says.

**Task 5.2 — the residue.** Nothing is finished until you have written what you did *not* look at.

```bash
python3 -B ../scripts/re-journal.py --file lab02.json residue \
  "iv_attempts and its counter were never investigated" --kind chosen
python3 -B ../scripts/re-journal.py --file lab02.json residue \
  "only the -O2 build was analysed in depth; -O0 differs structurally" --kind structural
python3 -B ../scripts/re-journal.py --file lab02.json residue \
  "no check for whether the decoded content is verified anywhere downstream" --kind chosen
```

**Task 5.3.** Read your own ledger back:

```bash
python3 -B ../scripts/re-journal.py --file lab02.json status
python3 -B ../scripts/re-journal.py --file lab02.json report
```

**The report is your deliverable.** It should contain a claim, evidence tagged by tier, the
hypotheses that died, and the residue. Compare its shape against
[`examples/worked-journal.md`](../examples/worked-journal.md), which is the real journal from writing
this chapter — nine of its eighteen entries are failures.

---

## Part 6 — Optional: the runtime confirmation

If you have a device that permits it, close the loop at tier 5 as well.

```bash
# host -- push and run, all three keys
cd ../examples && ./build.sh --push
adb -s <serial> shell "LD_LIBRARY_PATH=/data/local/tmp/ch68 \
    /system/bin/linker64 /data/local/tmp/ch68/investigate measure"
```

**Task 6.1.** Confirm the two-directional result: a key you predict opens it does, and a key you
predict fails does. **Both directions.** One direction is a coincidence waiting to happen.

**Task 6.2.** Clean up after yourself:

```bash
cd ../examples && ./build.sh --clean-device
```

---

## Part 7 — Grade yourself against ground truth

**Now** open [`examples/libinvestigate.c`](../examples/libinvestigate.c) and read it, including the
"four traps, stated honestly" block at the top.

This is the part a real target never gives you, and it is why the fixture exists.

**Task 7.1.** Score your investigation:

| Question | Yes / No |
|---|---|
| Did you identify the real gate? | |
| Did you correctly conclude `iv_check_license` is dead? | |
| Did you find the producer/consumer split, rather than assuming a call? | |
| Did you avoid reporting the decoy string as the secret? | |
| Did any hypothesis you recorded as **supported** turn out to be wrong? | |
| Did you record a verdict you could not point at an observation for? | |

**Task 7.2 — the interesting one.** The source contains a comment explaining why the mask is read
through a `volatile`. Read it. Then answer:

> The first two attempts to hide the flag both failed, and the **second** failure is the one worth
> understanding. Masking with a runtime value was still folded away by the compiler. **Why?**

<details>
<summary>The answer, and why it generalises</summary>

Control flow only reaches the decode loop after `gate_is_open(g_state.seed)` has returned true, and
that function is `seed == 0xbd`. On that path the compiler has **proved** the seed's value, so it
substitutes the constant it just proved and folds the loop — depositing the plaintext in `.rodata`,
where `strings` finds it instantly.

**The check that guards the secret is what told the compiler the secret.**

This generalises well beyond fixtures. Any "decode after validating" pattern hands the optimiser a
proof of the validated value on the decode path. A developer who does the obvious repair — "mask with
something computed at runtime" — is still exposed, with no warning, and their code review passes
because the source genuinely contains no plaintext.

Only a `volatile` read, which is defined as observable behaviour and therefore cannot be folded,
stops it. That is the same reason [19-Memory](../../19-Memory/README.md) uses a `volatile` loop for
secret scrubbing, arrived at from the opposite direction.

</details>

**Task 7.3.** Count your refutations. If fewer than two of your four hypotheses died, re-read them:
were they falsifiable as written, or were they phrased so that any result would have fitted?

---

## Success criteria

- [ ] A journal file with four hypotheses, each carrying a refutation test written before its
      experiment.
- [ ] At least two hypotheses recorded as **refuted**.
- [ ] Every verdict has a separately recorded raw observation behind it.
- [ ] Q1 closed as `answered` with **two independent sources**, each tagged with its tier.
- [ ] At least three residue entries, including at least one `structural`.
- [ ] You can explain why the call graph does not connect `iv_derive_seed` to the gate.
- [ ] You can explain why `gate_is_open` exists in the source and not in the `-O2` binary.
- [ ] You read `libinvestigate.c` only in Part 7.

---

## Hints

<details>
<summary>Hint 1 — I cannot find where the gate's byte lives</summary>

`adrp x8, #0x104000` plus `ldrb w8, [x8, #0x11]` gives you page + offset. Compare against
`readelf -S` output to see which section that address falls in, then `nm` for a symbol at or below
it.

If the address is in `.bss`, the value is zero in the file and written at runtime — which already
tells you the producer runs before the consumer, and that the file cannot tell you the value.

</details>

<details>
<summary>Hint 2 — the -O2 disassembly of iv_open_vault contains everything at once</summary>

That is inlining, and it is why the function is the largest. Read it in three passes rather than one:

1. The **guard** pass: find the early returns (null checks, length checks).
2. The **gate** pass: find the `cmp` against a constant with a conditional branch to a return.
3. The **payload** pass: find the loop that writes to the output buffer.

Trying to read it linearly as one story is what makes inlined code feel impenetrable.

</details>

<details>
<summary>Hint 3 — how do I know the recurrence starts at 0x3f?</summary>

Look for a `mov` of a small immediate into the register the loop accumulates into, *before* the loop
body. Then test it: your Python reconstruction either predicts the program's behaviour or it does
not. If `seed("measure")` does not come out `0xbd`, your reading is wrong somewhere and the program
has just told you so for free.

That is the loop working. A prediction that fails is not a setback; it is the fastest correction you
will get.

</details>

<details>
<summary>Hint 4 — my journal keeps refusing my hypotheses</summary>

It refuses two things, deliberately:

- A hypothesis whose `--refute` is blank or shorter than eight characters. If you cannot say what
  would make you abandon the idea, you are looking for support rather than investigating.
- A verdict on a hypothesis with no recorded observation. A verdict with nothing behind it is an
  opinion.

Both refusals are the lab's content, not obstacles to it.

</details>

---

## Debrief

1. Three of your four hypotheses were wrong. **Which one would you have spent longest on** if nobody
   had told you to write a refutation test first, and what would you have been doing during that
   time?

2. H1 was killed by an observation that had nothing to do with what the string said — it appeared on
   failing runs. **State that move as a general rule** you could apply to a different target.

3. The gate is three instructions with no symbol and no call site. **Name two other situations** in
   which the thing you are looking for exists in the source and not in the binary.

4. You closed Q1 with a tier-4 and a tier-6 source. Suppose the tier-6 test had been unavailable —
   no device, no way to run it. **What would you have written instead**, and how would the report's
   limits paragraph change?

5. The residue you wrote in Task 5.2 lists things you did not do. **Pick one and estimate what it
   would have cost.** That estimate is what turns a residue entry from an apology into a decision.

---

## Where this goes next

Lab 02 stayed inside one library. [Lab 03](lab-03-across-the-boundary.md) takes a single question
*across* the managed/native boundary and back — the crossing that
[56-JADX](../../56-JADX/README.md) hands off at the `native` declaration and
[57-Ghidra](../../57-Ghidra/README.md) picks up at the `.so`, with nobody owning the walk between
them.
