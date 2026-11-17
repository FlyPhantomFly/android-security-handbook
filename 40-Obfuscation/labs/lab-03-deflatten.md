# Lab 03 — Recognise and Reverse Control-Flow Flattening

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-string-recovery.md),
[Chapter 40 §3.3](../README.md#33-control-flow-obfuscation) especially
[§3.3.2](../README.md#332-control-flow-flattening--the-important-one),
[14-Dalvik](../../14-Dalvik/README.md) for Smali, `jadx`, `apktool`, Frida

---

## Objective

Reconstruct three flattened methods back into readable source, using three different techniques of
increasing cost:

1. **By hand**, from the state-transition table — the technique you should reach for first.
2. **By tracing**, hooking the method and logging the dispatcher variable — for methods too large to
   table.
3. **By not doing it at all**, treating the method as a black box and tabulating its input/output
   behaviour — which is the right answer far more often than people expect.

Then flatten a method yourself, so you understand what the transform can and cannot preserve.

## Why this matters

Control-flow flattening is the technique that makes people give up. It produces decompiler output that
looks like a machine wrote it for other machines, and the reaction is either to close the file or to
start an open-ended fight with a forty-case switch.

Both reactions are wrong, and for the same reason: **flattening hides order, not information.** Every
basic block of the original method is still there, intact and readable. The `if`s became state
assignments. Nothing was encrypted, nothing was removed, and nothing was made ambiguous. What was
destroyed is the *sequence*, and a sequence is exactly the kind of thing you can recover with a pen
and a table in ten minutes.

The second, more important lesson is the question in
[§3.3.2's Pentester's Note](../README.md#332-control-flow-flattening--the-important-one):

> The correct first question about a flattened method is not "how do I deflatten this?" It is **"do I
> need to?"**

You are usually looking for one specific behaviour — where the token is built, whether the check
returns true, what the endpoint is for a given input. Hooking the method boundary answers that in five
minutes. Deflattening is for when you need to *reimplement* the logic, which is a much rarer
requirement than the instinct to fully understand every method suggests.

Doing this lab properly means you will never again spend an afternoon deflattening a method that
formats a date.

---

## Setup

You need variant D from [lab 01](lab-01-obfuscation-triage.md): renamed, strings encrypted, and
`Classifier.classify` flattened. Build it if you have not.

**The flattened target** — copy this verbatim into `Classifier.java`, replacing the original method:

```java
package com.obflab.target;

public class Classifier {

    // The original, kept as a comment ONLY in your build; delete it before
    // you analyse, or you will spoil the lab for yourself.
    //
    // public String classify(int score) {
    //     if (score < 0) return "invalid";
    //     String label;
    //     if (score < 50)      label = "fail";
    //     else if (score < 80) label = "pass";
    //     else                 label = "distinction";
    //     return label.toUpperCase();
    // }

    public String classify(int i) {
        String str = null;
        int state = 3;                       // entry state — NOT necessarily 0
        while (true) {
            switch (state) {
                case 0:
                    str = "distinction";
                    state = 6;
                    break;
                case 1:
                    if (i < 50) { state = 5; } else { state = 4; }
                    break;
                case 2:
                    return "invalid";
                case 3:
                    if (i < 0) { state = 2; } else { state = 1; }
                    break;
                case 4:
                    if (i < 80) { state = 7; } else { state = 0; }
                    break;
                case 5:
                    str = "fail";
                    state = 6;
                    break;
                case 6:
                    return str.toUpperCase();
                case 7:
                    str = "pass";
                    state = 6;
                    break;
            }
        }
    }
}
```

**Target 2 — a larger, nastier one.** Add this class. It uses non-sequential, randomised state values,
which is what real flatteners emit and what makes the toy example above misleadingly easy.

```java
package com.obflab.target;

public class TokenBuilder {

    /**
     * Flattened, with randomised state constants and a computed initial state.
     * Reconstruct what it does.
     */
    public String build(String user, int level, boolean trusted) {
        StringBuilder sb = new StringBuilder();
        String out = null;
        int n = 0;
        int state = 0x5F2A11;
        while (true) {
            switch (state) {
                case 0x5F2A11:
                    if (user == null || user.isEmpty()) { state = 0x1C99B4; }
                    else                                { state = 0x77AE03; }
                    break;
                case 0x1C99B4:
                    out = "";
                    state = 0x2B0D57;
                    break;
                case 0x77AE03:
                    sb.append("v1.");
                    state = 0x40E6C2;
                    break;
                case 0x40E6C2:
                    sb.append(user.length());
                    n = user.length();
                    state = (level > 0) ? 0x6A31FF : 0x0D82A9;
                    break;
                case 0x0D82A9:
                    sb.append(".guest");
                    state = 0x3E5B70;
                    break;
                case 0x6A31FF:
                    sb.append('.').append(level);
                    state = trusted ? 0x18C4E6 : 0x3E5B70;
                    break;
                case 0x18C4E6:
                    sb.append(".t");
                    n = n * 31 + level;
                    state = 0x3E5B70;
                    break;
                case 0x3E5B70:
                    sb.append('#').append(Integer.toHexString(n ^ 0x5EED));
                    state = 0x2B0D57;
                    break;
                case 0x2B0D57:
                    if (out == null) out = sb.toString();
                    return out;
                default:
                    return null;
            }
        }
    }
}
```

**Target 3 — one you will not read.** Add a method that is deliberately too large and boring to
reconstruct, so that "do I need to?" becomes a real question rather than a rhetorical one. Any
forty-case flattened method will do; generate it by flattening a string-formatting routine, or reuse
`TokenBuilder.build` with thirty junk states inserted.

Build and install:

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
apktool d -f -o D_out D.apk >/dev/null
jadx -d D_jadx --no-res D.apk >/dev/null 2>&1
```

---

## Steps

### Step 1 — Recognise it, and measure how much there is

```bash
# host — the Smali form is louder than the Java form
grep -rlc 'packed-switch\|sparse-switch' D_out/smali*/ | head
grep -rc 'goto' D_out/smali*/com/obflab/ | sort -t: -k2 -rn | head
```

**Q1.** Open three methods in `jadx`. List the recognition signs from the table in
[§3.3.2](../README.md#332-control-flow-flattening--the-important-one) that you can actually observe.
Which sign is the most reliable, and which one is present but misleading in the toy example?

**Q2.** Look at `Classifier.classify` in `jadx` and then the same method in Smali
(`D_out/smali*/com/obflab/target/Classifier.smali`). Which representation makes the flattening more
obvious, and why?

**Q3.** Why do decompilers emit `while (true) { switch }` rather than reconstructing the original
`if`/`else`? Answer in terms of dominance and structuring, not "the decompiler is not smart enough."

### Step 2 — Technique 1: the state-transition table

Do this with a pen. It takes ten minutes and it is completely reliable for a method this size.

Fill in one row per case:

| State | What the block does | Next state |
|---|---|---|
| 3 (entry) | | |
| | | |

**Q4.** Complete the table for `Classifier.classify`. What is the entry state, and why is the fact
that it is not 0 worth noticing?

**Q5.** Sort your table by reachability from the entry state and write out the original method. Does it
match the source that lab 01 told you to flatten? If it does not, where did you go wrong?

**Q6.** Which states are **unreachable** from the entry, if any? What would an unreachable case
indicate on a real target?

### Step 3 — The same technique against realistic state values

Now do `TokenBuilder.build`.

**Q7.** Build the transition table.three transitions are *conditional on a parameter* rather
than fixed. How does that change the table's shape?

**Q8.** Reconstruct the original method as source. What does it produce for
`build("alice", 3, true)`? Work it out on paper before you run anything.

**Q9.** Verify with Frida:

```javascript
// Frida REPL
Java.perform(function () {
    var T = Java.use("com.obflab.target.TokenBuilder");
    var t = T.$new();
    console.log(t.build("alice", 3, true));
    console.log(t.build("alice", 3, false));
    console.log(t.build("alice", 0, true));
    console.log(t.build("", 3, true));
});
```

Did your paper reconstruction match? If not, which state did you misread, and what does that tell you
about doing this by hand for a forty-case method?

**Q10.** The state constants are large random-looking numbers. Does that make the reconstruction
harder in any way that *matters*? What is it actually defending against?

### Step 4 — Technique 2: trace the dispatcher

For a method too large to table, let the program tell you the path.

**Approach A — instrument the Smali.** Add a log at the top of the dispatcher loop.

```smali
# In D_out/smali*/com/obflab/target/TokenBuilder.smali, at the top of the
# :goto_0 loop, before the switch:
    const-string v9, "FLAT"
    invoke-static {v9, v?}, Landroid/util/Log;->i(Ljava/lang/String;I)I
```

(You will need to adapt the register numbers and bump `.locals`. That adaptation is part of the
exercise.)

```bash
# host
apktool b -o D_patched.apk D_out
zipalign -p -f 4 D_patched.apk D_aligned.apk
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
    --out D_signed.apk D_aligned.apk
adb install -r D_signed.apk
adb logcat -s FLAT
```

**Approach B — trace from outside.** Often easier and requires no repackaging:

```javascript
// Frida REPL — you cannot see a local variable from a Java hook, but you can
// see everything that CROSSES the method boundary, and for most questions
// that is enough.
Java.perform(function () {
    var T = Java.use("com.obflab.target.TokenBuilder");
    T.build.implementation = function (u, l, t) {
        var r = this.build(u, l, t);
        console.log("build(" + u + ", " + l + ", " + t + ") = " + r);
        return r;
    };
});
```

**Q11.** Approach A gives you the exact state sequence for one input. Approach B gives you input and
output only. For which questions is A worth the repackaging cost, and for which is B sufficient?

**Q12.** You traced with one input and saw eight of forty cases execute. What have you learned, and —
precisely — what have you **not** learned? Name the specific risk of stopping here.

**Q13.** Repackaging changed the APK's signature. Which other chapter does that send you to, and what
would you have to do as well if the app checked its own signature?

### Step 5 — Technique 3: do not deflatten at all

Target 3 is the forty-case method. Before touching it, answer:

**Q14.** What is the actual question you need answered about this method? Write it as a single
sentence beginning "I need to know whether…" or "I need to know what…".

**Q15.** Can you answer that question by hooking the method boundary and tabulating input/output?
Do it. How long did it take?

**Q16.** State the distinction the chapter draws between needing to **understand** a method and needing
to **predict** it. Give one concrete task from a real engagement that requires understanding, and one
that requires only prediction.

### Step 6 — Flatten something yourself

Take `ApiClient.post` from lab 01 and flatten it by hand. Rules: no behaviour change, randomised state
constants, entry state not zero.

**Q17.** Which language constructs were awkward to flatten? What happened to the `try`/`catch`/`finally`
and to the `while` loop reading the response?

**Q18.** Now decompile your own flattened version. Is it as unreadable as the ones you were given? If
it is less so, what did you fail to do that a real flattener does?

**Q19.** Having written one, name two pieces of information that flattening **cannot** destroy, and
explain why not.

### Step 7 — Assess it

**Q20.** Using your own timings, price control-flow flattening for a developer: what does it cost the
build, and what does it buy against (a) a casual analyst, (b) an analyst who reads this chapter,
(c) an analyst who only needs to predict the method rather than understand it?

---

## Hints

<details>
<summary>Hint — Q4, finding the entry state</summary>

The entry state is whatever the state variable is initialised to before the loop begins. In Smali it
is the `const` immediately before the `:goto` label the switch sits under. Real flatteners do not use
0; some compute it from a parameter specifically so that the entry is not a visible constant.
</details>

<details>
<summary>Hint — Q7, conditional transitions</summary>

A row's "next state" column can hold two values with a condition, exactly like a branch in the
original program. That is the whole trick: `if (score < 50) state = 5; else state = 4;` **is** the
original `if`, rewritten. Your table row for it should read `1 | test i<50 | 5 if yes, 4 if no`, and
when you sort by reachability that row turns straight back into an `if`.
</details>

<details>
<summary>Hint — Q11 / Q12, what tracing does not tell you</summary>

A trace is one path through the method for one input. A method with four conditional transitions has
up to sixteen paths. Concluding "the method does X" from one trace is the same error as concluding an
app has no root detection because it did not fire on your device.
</details>

---

## Solution

<details>
<summary>Answers Q1–Q3 — recognition</summary>

**Q1.** Observable signs, in order of reliability:

| Sign | Present in the toy example? |
|---|---|
| `while (true) { switch (v) { … } }` | Yes — the canonical shape |
| A local `int` assigned in nearly every case | Yes — the state variable |
| Cases that `break` out of the switch but not the loop | Yes |
| Case labels that are large, non-sequential numbers | **No** in `Classifier`, yes in `TokenBuilder` |
| No `if` nesting despite obvious complexity | Yes |
| One enormous `packed-switch`/`sparse-switch` with a `goto` back | Yes, in Smali |
| Method is large but has almost no call depth | Partly |

Most reliable: the canonical shape plus a state variable assigned in almost every case. Those two
together have essentially no false positives — ordinary code with a `switch` in a loop (a state machine
someone wrote deliberately) is rare, and when it exists, the states have meaningful names.

Misleading in the toy example: the sequential `case 0..7` labels. Real flatteners randomise them, so
someone who learned recognition only from the toy version will look for small sequential cases and
miss the real thing. That is exactly why `TokenBuilder` exists in this lab.

**Q2.** Smali. In Java, `jadx` has already reconstructed a `switch` and given you tidy `case` labels;
in Smali you see the raw shape — a single `packed-switch` or `sparse-switch` instruction, a payload
table of branch targets, and a `goto` returning to the top. There is no structuring layer between you
and the truth.

More generally: **Smali never fails and never lies.** When the decompiler's output is confusing, going
one level down is almost always faster than arguing with it.

**Q3.** A decompiler reconstructs `if`/`while`/`for` by finding *dominance* relationships in the
control-flow graph — block A dominates block B if every path to B passes through A, and that
relationship is what a structured `if` looks like in graph form.

In a flattened CFG the dispatcher dominates every block and no block dominates any other, because
every block's only successor is the dispatcher. There is no dominance structure to find. The
decompiler is not failing; it is correctly emitting the only structure that exists, which is a switch
inside a loop. That is why "wait for a better decompiler" is not a strategy: the information the
decompiler needs was removed by construction.
</details>

<details>
<summary>Answers Q4–Q6 — the transition table</summary>

**Q4.** The table:

| State | Does | Next |
|---|---|---|
| 3 (entry) | test `i < 0` | 2 if yes, 1 if no |
| 2 | `return "invalid"` | — |
| 1 | test `i < 50` | 5 if yes, 4 if no |
| 5 | `str = "fail"` | 6 |
| 4 | test `i < 80` | 7 if yes, 0 if no |
| 7 | `str = "pass"` | 6 |
| 0 | `str = "distinction"` | 6 |
| 6 | `return str.toUpperCase()` | — |

The entry state is 3. It is worth noticing because the instinct is to start reading at `case 0`, which
here is the *last* assignment before the return and tells you nothing about the method's shape. A
flattener choosing a non-zero entry costs itself nothing and costs a careless reader several minutes.

**Q5.** Sorted by reachability, the original falls straight out:

```java
public String classify(int i) {
    if (i < 0) return "invalid";           // state 3 -> 2
    String str;
    if (i < 50)      str = "fail";         // 1 -> 5
    else if (i < 80) str = "pass";         // 4 -> 7
    else             str = "distinction";  // 4 -> 0
    return str.toUpperCase();              // 6
}
```

If it does not match, the usual error is transcribing a conditional transition backwards — writing "5
if no" where the source says "5 if yes". Check each condition against the Smali `if-ge`/`if-lt`, which
is unambiguous.

**Q6.** None here. On a real target an unreachable case usually means one of three things: the
flattener emitted junk states as decoration (bogus control flow,
[§3.3.3](../README.md#333-bogus-control-flow-and-junk-code)); the state is reached only through a path
your table missed, meaning you made an error; or the state is reached through a *computed* transition
rather than a literal assignment, which is the sophisticated variant and the one to look for when the
table does not close.
</details>

<details>
<summary>Answers Q7–Q10 — realistic state values</summary>

**Q7.** Table for `TokenBuilder.build`:

| State | Does | Next |
|---|---|---|
| `0x5F2A11` (entry) | test `user` null or empty | `0x1C99B4` if yes, `0x77AE03` if no |
| `0x1C99B4` | `out = ""` | `0x2B0D57` |
| `0x77AE03` | `sb.append("v1.")` | `0x40E6C2` |
| `0x40E6C2` | append `user.length()`, `n = user.length()` | `0x6A31FF` if `level > 0`, else `0x0D82A9` |
| `0x0D82A9` | `sb.append(".guest")` | `0x3E5B70` |
| `0x6A31FF` | append `'.'` and `level` | `0x18C4E6` if `trusted`, else `0x3E5B70` |
| `0x18C4E6` | `sb.append(".t")`, `n = n*31 + level` | `0x3E5B70` |
| `0x3E5B70` | append `'#'` and `hex(n ^ 0x5EED)` | `0x2B0D57` |
| `0x2B0D57` | if `out == null` then `out = sb.toString()`; return `out` | — |

Conditional transitions do not change the table's *shape* at all — they occupy the "next" column with
two entries and a condition, which is precisely what a branch is. That is the observation that makes
the whole technique work.

**Q8.** Reconstructed:

```java
public String build(String user, int level, boolean trusted) {
    if (user == null || user.isEmpty()) return "";
    StringBuilder sb = new StringBuilder();
    sb.append("v1.").append(user.length());
    int n = user.length();
    if (level > 0) {
        sb.append('.').append(level);
        if (trusted) {
            sb.append(".t");
            n = n * 31 + level;
        }
    } else {
        sb.append(".guest");
    }
    sb.append('#').append(Integer.toHexString(n ^ 0x5EED));
    return sb.toString();
}
```

For `build("alice", 3, true)`: `user.length()` is 5, so `n` starts at 5, becomes `5*31 + 3 = 158`
(`0x9E`), and `0x5EED ^ 0x009E = 0x5E73`. Output: `v1.5.3.t#5e73`.

Work that XOR out by hand rather than trusting it — getting a one-nibble arithmetic slip past yourself
is exactly how a reconstruction that "nearly matches" wastes an hour.

**Q9.** If it did not match, the two usual culprits are the order of the `n = n*31 + level` assignment
relative to the append, and forgetting that state `0x2B0D57` returns `out` (which is `""` on the empty
path) rather than `sb.toString()` unconditionally.

What that tells you about doing this by hand at scale: the technique is reliable but the *transcription*
is error-prone, and the error rate grows with the number of states. At around fifteen to twenty states
the probability of a mistake somewhere approaches certainty, which is the practical threshold at which
you switch to tracing.

**Q10.** No — not in any way that matters. The constants are opaque *identifiers*; you never need to
know what they mean, only that state `0x5F2A11` goes to state `0x77AE03`. Rename them to A, B, C as
you build the table and they cease to exist as a difficulty.

What they actually defend against: pattern-matching tools and scripted deflatteners that assume small
sequential states, and human readers who try to hold the numbers in their head instead of writing a
table. The second is the real target, and it works — which is a good reminder that a lot of obfuscation
is aimed at your working memory rather than at your capability.
</details>

<details>
<summary>Answers Q11–Q13 — tracing</summary>

**Q11.**

Approach A (Smali instrumentation) is worth the repackaging cost when you need the *internal path*:
which of forty cases executed, in what order, and therefore which branches are dead for the inputs you
care about. It collapses a forty-case method to the eight that matter, which is often the difference
between a readable reconstruction and an impossible one.

Approach B (boundary hook) is sufficient — and it is sufficient surprisingly often — when your question
is about behaviour rather than structure: what does this return for these inputs, is this token
deterministic, does this check ever return true. It costs thirty seconds and requires no repackaging,
no re-signing, and no risk of tripping integrity checks.

The professional habit is to try B first, always, and escalate to A only when B genuinely cannot
answer the question.

**Q12.** You have learned one path through the method for one input, and you have learned that
thirty-two of the forty cases are irrelevant *to that input*.

You have **not** learned what the method does for any other input. A method with four conditional
transitions has up to sixteen paths; you have seen one.

The specific risk of stopping here: you conclude "the method appends the level and returns" and miss
entirely that a different input reaches the branch which adds the trusted flag and changes the hash.
That is exactly the same error as concluding an app has no root detection because it did not fire on
your device — a statement about your sample presented as a statement about the program.

Mitigation: vary the inputs deliberately, and cross-check the paths you observed against the states you
found in the static table. Anything in the table you never traced is something you have not tested.

**Q13.** [38-TamperDetection](../../38-TamperDetection/README.md). Re-signing gives the APK a new
signing certificate, and any app that compares its own signature against a stored value will now fail
that check.

What you would also have to do: locate and neutralise the signature check as well — which means you are
now patching two things at once and each patch can break the other. This is why
[§7.1](../README.md#71-getting-attached-early-enough) prefers runtime instrumentation over static
patching whenever runtime is available: a Frida hook changes nothing on disk and trips nothing.
</details>

<details>
<summary>Answers Q14–Q16 — not deflattening</summary>

**Q14.** A good question is narrow and falsifiable. Examples:

- "I need to know whether this method ever returns true when `isDebuggable` is false."
- "I need to know what value this method puts in the `X-Signature` header for a known request body."
- "I need to know whether the token it builds is deterministic for a fixed input."

A bad question — and the one people implicitly start with — is "I need to understand this method",
which has no stopping condition and therefore no budget.

**Q15.** Yes, for all three of the above, and it takes about five minutes:

```javascript
Java.perform(function () {
    var C = Java.use("com.obflab.target.BigFlattened");
    C.compute.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var r = ov.apply(this, arguments);
            console.log("compute(" + Array.prototype.slice.call(arguments).join(", ") +
                        ") = " + r);
            return r;
        };
    });
});
```

Then feed it inputs and read the table. Forty cases of deliberately unreadable code, and you never read
one of them.

**Q16.** **Understanding** means you can restate the method's logic and reimplement it. **Predicting**
means you can say what it returns for a given input, without knowing why.

- Requires understanding: forging a licence token or a request signature offline, so that your
  implementation produces values the server accepts without the app running. You must reproduce the
  algorithm.
- Requires only prediction: determining whether a root check returns true, finding which endpoint is
  used for a given feature flag, confirming that a nonce is not bound to the request. A boundary hook
  answers all three.

Most engagement questions are prediction questions. Deflattening is the tool for the minority, and
reaching for it by default is the single largest source of wasted time in obfuscated-app assessment.
</details>

<details>
<summary>Answers Q17–Q20 — flattening it yourself, and pricing it</summary>

**Q17.** The awkward constructs, and what happens to them:

- **`try`/`catch`/`finally`** does not flatten cleanly, because exception handling is structural in the
  JVM/DEX: handlers are declared as ranges over the bytecode in a try/catch table, not as jumps. A
  flattener must either keep the try block intact as one case, or wrap the entire dispatcher in the
  try, which is what most do — and that is a recognition sign in itself.
- **Loops** become a state that tests the condition and transitions either back to the body state or on
  to the exit state. They flatten cleanly and become genuinely hard to see, because the loop's
  back-edge is now indistinguishable from any other transition.
- **Local variables that must survive across blocks** (here `sb`, `str`, `n`) must all be hoisted to
  method scope, which is why flattened methods have a distinctive cluster of locals declared and
  initialised to null at the top.

**Q18.** Almost certainly less unreadable. What a hand-flattening typically omits:

- Randomised, non-sequential state constants (you probably numbered them 0, 1, 2…).
- **Computed** state transitions — `state = (x * 7 + 3) & 0xFF` — instead of literal assignments, which
  is what defeats a mechanical table.
- Junk states and bogus transitions guarded by opaque predicates
  ([§3.3.3](../README.md#333-bogus-control-flow-and-junk-code)).
- Enough scale. Eight cases is a puzzle; eighty is a wall.

Noticing these omissions is the point of the exercise: you now know the difference between a
demonstration and a product.

**Q19.** Two things flattening cannot destroy:

1. **String constants.** They are in the DEX string pool regardless of what happens to the control
   flow, which is precisely why the methodology recovers strings first — string recovery is *immune*
   to flattening, and the strings then tell you which flattened method is worth the effort.
2. **The method's interface.** Its name, parameters, return type, and every framework API it calls are
   all still there and still resolvable, because the runtime needs them. That is what makes the
   boundary hook of Q15 always available.

More generally: flattening rearranges *intra-procedural* control flow. Everything inter-procedural —
call graph, signatures, framework interaction, data crossing the boundary — is untouched.

**Q20.** Honest pricing:

| Audience | Effect |
|---|---|
| Build cost | Larger methods, more locals, measurably slower on hot paths, harder crash reports (stack traces now point at a dispatcher). Non-trivial. |
| (a) Casual analyst | Effective. Many stop at the sight of a forty-case switch, and that is a real population. |
| (b) Analyst who reads this chapter | Ten minutes for a small method with a pen; longer but bounded for a large one with tracing. Delay, not prevention. |
| (c) Analyst who only needs prediction | **Approximately zero.** A boundary hook is unaffected by anything happening inside the method. |

The developer conversation that follows:

> Control-flow flattening measurably slows a reader and defeats casual analysis, at a real cost in
> performance and in the readability of your own crash reports. It provides no protection against an
> analyst who only needs to observe the method's inputs and outputs, which describes most of what an
> attacker actually does. If the concern is that a specific value can be reconstructed offline, the
> control is to make the value depend on something the client does not hold — not to make the client's
> copy harder to read.

this is the same shape of advice as everywhere else in the chapter: price it honestly, credit
what it does buy, and redirect the budget to the control that changes the outcome.
</details>

---

## Success criteria

- [ ] You listed the recognition signs you could actually observe, and identified which is misleading
      in the toy example
- [ ] You compared the Java and Smali representations and can say which is more honest
- [ ] You explained decompiler failure in terms of dominance, not competence
- [ ] You built the transition table for `Classifier.classify` and recovered the original source
- [ ] You built the table for `TokenBuilder.build` with randomised states and computed the output on
      paper before running it
- [ ] You verified with Frida and reconciled any mismatch
- [ ] You can explain why randomised state constants change nothing that matters
- [ ] You traced a method's internal path by instrumenting the dispatcher, and stated what re-signing
      costs you
- [ ] You can state precisely what a single trace does and does not establish
- [ ] You wrote your engagement question as one falsifiable sentence
- [ ] You answered that question with a boundary hook, and timed it
- [ ] You can distinguish understanding from prediction, with a concrete task for each
- [ ] You flattened a method yourself and identified what `try`/`catch` and loops do under the transform
- [ ] You named what your hand-flattening omitted that a real flattener does
- [ ] You named two things flattening cannot destroy and explained why
- [ ] You priced flattening for all three audiences and wrote the developer advice

---

## Next

[Lab 04 — Unpack a packed app](lab-04-unpack.md). You build a packer, then take its payload out of
memory.
