# Lab 01 — Your first decompilation, and what it costs

**Difficulty:** Beginner
**Time:** 1–2 hours
**Prerequisites:** [Chapter 56 §1–§3](../README.md), [04 Java](../../04-Java/README.md).
No device, no root, no network. A JDK, the Android SDK build-tools, and jadx.

---

## Objective

By the end you will have:

1. Compiled a Java class into a DEX with the same tools an Android build uses.
2. Decompiled it and compared the output with the source you wrote, line by line.
3. Named, for **every** difference, which tool caused it — `javac`, `d8`, or jadx.
4. Rebuilt it with debug information and measured what changes.
5. Found the one method where the debug build decompiles *worse* than the release build, and
   explained why.
6. Written down, in your own words, a sentence you could say to a developer about what a decompiler
   does and does not give you.

That last one is the actual deliverable. Everything before it is how you earn the right to say it.

## Why this matters

Almost everyone's first contact with jadx is pointing it at an APK they did not build, reading Java
they did not write, and quietly assuming that what they are reading is what the developer wrote.
That assumption is wrong, and it stays invisible until it produces a wrong finding, at which point it
is expensive.

The cure is to run the pipeline **in the direction you already know the answer**. You wrote the
source. You know exactly what was in it. So every difference in the output is a measurement rather
than a guess, and you learn to attribute differences to tools rather than to intent.

---

## Setup

```bash
# host
cd 56-JADX/examples/01-source-to-java

# jadx: whichever of these applies to your install
export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"   # Windows gui-only install
# or nothing at all, if `jadx` is on your PATH

export ANDROID_HOME="$HOME/AppData/Local/Android/Sdk"                # adjust for your machine

./build.sh
```

Confirm you got:

```
[1/4] javac --release 8 -g:none  (release)
[2/4] javac --release 8 -g       (debug)
[3/4] d8 --release / d8 --debug
[4/4] jadx

=== DEX sizes and string-pool counts ===========================================
dex-release     5568 bytes  string_ids_size : 121
dex-debug       6104 bytes  string_ids_size : 142
```

> **If jadx hangs and never returns**, you are running the GUI launcher. Chapter §1.3. Set `JADX_JAR`
> to `lib/jadx-gui-<ver>-all.jar` and re-run.
>
> **If `d8` says "Unsupported class file major version"**, your `javac` emitted a newer class format
> than your `d8` understands. That is why `build.sh` passes `--release 8`; if you compiled by hand
> without it, add it.

---

## Part 1 — Read the release output against the source (40 min)

Open two files side by side:

- [`AccountVault.java`](../examples/01-source-to-java/AccountVault.java) — what you compiled
- `_build/out-release/sources/com/pentest/ch56/AccountVault.java` — what came back

Work through the class **method by method**, and for each difference fill in this table. Do not read
the answers first; you will remember almost none of it if you do.

| # | What the source had | What the output has | Which tool? | Why? |
|---|---|---|---|---|
| 1 | `/** Javadoc on five methods */` | | | |
| 2 | `new HashMap<String, List<String>>()` | | | |
| 3 | `private final Map<String, List<String>> rolesByAccount` | | | |
| 4 | `List<String> roles` | | | |
| 5 | `for (String role : roles)` | | | |
| 6 | `b != '\n'` | | | |
| 7 | `try (InputStream in = ...)` | | | |
| 8 | `ENDPOINT + "?acct="` | | | |
| 9 | `i < MAX_ATTEMPTS` | | | |
| 10 | `boolean equal` / `int limit` | | | |
| 11 | `new Runnable() { ... }` | | | |
| 12 | Methods in the order you wrote them | | | |
| 13 | `case "free"` first | | | |
| 14 | *(nothing — the source has no such line)* | `str.hashCode();` | | |

### Hints, one per row, in increasing order of giving it away

1. What is the very first thing a compiler discards?
2. Does a `new` expression carry a `Signature` attribute? Does a field declaration?
3. See 2. Why are these two rows different answers to the same question?
4. Look at the *declared* type versus the *inferred* type of the local.
5. This one came back essentially intact. Why is an enhanced `for` easier than a `while`?
6. What is the numeric value of `'\n'`? What does `InputStream.read()` return?
7. Count the `close()` calls in the output. Who wrote the second one?
8. `ENDPOINT` is `static final String` with a literal initialiser. Look up "compile-time constant".
9. `MAX_ATTEMPTS` is *also* a compile-time constant, and came back as a name. Both cannot be right
   about jadx. Which one is jadx guessing? Try `--no-replace-consts`.
10. Chapter §3.6. What is `iMin` named after?
11. Try to compile the output. Really try.
12. Chapter §3.11's second-order effect.
13. Compute `"free".hashCode()`, `"plus".hashCode()`, `"enterprise".hashCode()` and sort them.
14. This is the trap. Do not guess — run `dexdump -d _build/dex-release/classes.dex` and look at the
    first two instructions of the method.

### Success criterion for Part 1

You can state, for each row, whether the cause was `javac`, `d8`, jadx, or *the compiler's language
obligations* — and for row 14 you have the bytecode open.

### Answer key

Fill in your own table first. Then check.

<details>
<summary><b>Show the answer key</b></summary>

| # | Output | Tool | Why |
|---|---|---|---|
| 1 | *(nothing)* | `javac` | Comments and formatting are discarded at parse time. Unrecoverable by anything, ever |
| 2 | `new HashMap()` | `javac` | Type erasure. A `new` expression never carried a `Signature` attribute, so there is nothing for jadx to read |
| 3 | `Map<String, List<String>> rolesByAccount` **preserved** | preserved | A *field declaration* does get a `Signature` attribute, and `d8` carries it into DEX. This is the same language feature as row 2 producing the opposite result — which is jadx being accurate, not inconsistent |
| 4 | `List<String> list` | jadx `NameGen` | The declared type came from the method's return signature; the *name* was invented |
| 5 | `for (String str2 : list)` | mostly preserved | The iterator idiom is recognisable. Only the name was lost |
| 6 | `i == 10` | `javac` + jadx `TypeInferenceVisitor` | `'\n'` is `char` 10, compared against the `int` from `read()`. The comparison forces `int` and no evidence of a character literal survives |
| 7 | `try { ... close(); } catch (Throwable th) { try { close(); } catch (Throwable th2) { th.addSuppressed(th2); } throw th; }` | `javac` | try-with-resources is syntax sugar. `javac` wrote all that machinery; jadx is showing it faithfully |
| 8 | The literal URL | `javac` | `ENDPOINT` is a `static final String` with a literal initialiser — a **compile-time constant** — so its *value* is substituted at every use site. The name never reaches the DEX there |
| 9 | `MAX_ATTEMPTS` | jadx `ConstInlineVisitor` | The bytecode holds `3`. jadx noticed the class has a `static final int MAX_ATTEMPTS = 3` and printed the name. **It is a guess** — here a correct one. `--no-replace-consts` shows the literal |
| 10 | `boolean z`, `int iMin` | jadx `NameGen` | `z` from the `Z` type descriptor for `boolean`; `iMin` from `Math.min`, the method that produced the value. The source said `equal` and `limit` |
| 11 | `new Runnable(this) { final /* synthetic */ AccountVault this$0; ... }` | `javac` + jadx | `javac` generated class `AccountVault$1` with an outer-instance constructor parameter and a synthetic `this$0` field. **`Runnable` is an interface and has no constructor, so this does not compile.** jadx chose accuracy over validity |
| 12 | Alphabetical, nested classes first | `d8` + jadx | No debug info means no line numbers, so jadx has no ordering to sort by and emits DEX order, which `d8` sorts |
| 13 | `enterprise`, `free`, `plus` | `javac` | Hash order. `"enterprise".hashCode()` is `-802737311`, `"free"` is `3151468`, `"plus"` is `3444122` |
| 14 | `str.hashCode();` on its own line | **`javac`** | **The trap.** It is genuinely in the bytecode — two `invoke-virtual hashCode` instructions, the first discarding its result. `switch` on a `null` String must throw `NullPointerException`, so the compiler needs an unconditional dereference before the lookup |

Row 14 is the one to remember. The plausible story — "jadx left it behind when folding the two-stage
string switch" — is wrong, and the first draft of chapter 56 said exactly that until `dexdump`
contradicted it. **An unexplained statement in decompiled Java has three possible authors, and
guessing between them is how confident wrong statements get written down.**

</details>

### Part 1b — prove row 14 yourself (10 min)

Do not take the answer key's word for it either.

```bash
# host
dexdump -d _build/dex-release/classes.dex | sed -n '/tierFromPlanName/,/catches/p' | head -12
```

You should see two `invoke-virtual ... hashCode` at offsets `0000` and `0003`, and a `move-result`
after only the second. Write down what that proves, and what it would have proved if there had been
only one call.

Then confirm that jadx is not adding it:

```bash
# host
jadx --no-restore-switch-over-string -q -d _build/out-raw _build/dex-release/classes.dex
grep -n "hashCode" _build/out-raw/sources/com/pentest/ch56/AccountVault.java
```

The orphan survives the flag that turns off the string-switch reconstruction. That is the second
independent confirmation, and two independent confirmations is the standard chapter §5.4 asks for.

### Part 1c — the constants trap (15 min)

Row 9 is the only row where jadx *guessed*, and guesses are worth probing.

```bash
# host
jadx --no-replace-consts -q -d _build/out-noconst _build/dex-release/classes.dex
diff _build/out-release/sources/com/pentest/ch56/AccountVault.java \
     _build/out-noconst/sources/com/pentest/ch56/AccountVault.java
```

1. Which lines changed? Was jadx's substitution correct in each case?
2. Now edit `AccountVault.java` so that `MAX_ATTEMPTS` is `0` instead of `3`, rebuild, and look at
   `unlock` and `describe`. Constant substitution on `0`, `1` and `-1` is where it goes wrong most
   often, because those values occur everywhere by coincidence.
3. Write the rule: **when does a constant name in decompiled Java carry information, and when is it
   noise?**

---

## Part 2 — Add debug information and measure (20 min)

Compare `_build/out-release/...` with `_build/out-debug/...`.

**Questions to answer, in writing:**

1. Which local variable names came back in the debug build? List five.
2. `readHeader`'s first line is `ByteArrayInputStream byteArrayInputStream = ...` in one build and
   `InputStream in = ...` in the other. Debug info supplied a *name* — where did the *type* come
   from?
3. `rolesFor` declares `new ArrayList()` in one build and `new ArrayList<>()` in the other. Explain.
4. Run:
   ```bash
   # host
   strings -a _build/dex-debug/classes.dex   | grep -x candidate
   strings -a _build/dex-release/classes.dex | grep -x candidate
   ```
   What does the difference prove about *where the names live*? Which chapter documents that
   structure? (Answer: [12 — DEX Internals](../../12-DEX-Internals/README.md), `debug_info_item`.)
5. What is the total size cost of shipping debug info, for this class?

**Then answer the question that matters on a real engagement:** given a production APK, how would you
find out in under a minute whether it shipped debug info? Write the command. Chapter §3.11 has one
answer; there is more than one.

---

## Part 3 — The result nobody expects (25 min)

Find `tierFromPlanName` in both outputs.

The **release** build gives you a clean `switch (str)`.
The **debug** build gives you `throw new UnsupportedOperationException("Method not decompiled: ...")`.

1. Read the two `JADX WARN` comments jadx prints in the debug output. Write down, in one sentence
   each, what they say.
2. The refusal comes with a complete instruction dump. Read it. Describe the two-stage structure
   `javac` emitted for a `switch` over `String`: what does the first switch dispatch on, what
   confirms the match, and what does the second switch dispatch on?
3. Now explain the paradox: **why would more information make jadx's output worse?** Hint: the
   warning says "some code will duplicate". What does a line-number table constrain?
4. Run the release build through
   ```bash
   # host
   jadx --no-restore-switch-over-string -q -d _build/out-raw _build/dex-release/classes.dex
   ```
   Does the orphan `str.hashCode();` disappear? Why not? (You answered this in Part 1 row 14.)

### Success criterion for Part 3

You can say, without hedging, why the statement "always build with debug info if you want better jadx
output" is true on average and false about this method — and why that distinction is the whole reason
this chapter exists.

---

## Part 3b — The four modes on one class (20 min)

You now have a method that refuses (`tierFromPlanName` in the debug build). Use it to walk the
escalation ladder of chapter §3.7 on a class you wrote yourself, where you know the right answer.

```bash
# host
for m in restructure simple fallback; do
    jadx -m "$m" -q -d "_build/mode-$m" _build/dex-debug/classes.dex
done
jadx --show-bad-code -q -d _build/mode-bad _build/dex-debug/classes.dex
```

Now compare `tierFromPlanName` across all five renderings and complete this table from your own
observation:

| Rendering | Does it produce a body? | Can you tell which plan maps to which Tier? | Would you quote it? |
|---|---|---|---|
| default (`auto`) | | | |
| `--show-bad-code` | | | |
| `-m restructure` | | | |
| `-m simple` | | | |
| `-m fallback` | | | |

Questions:

1. Which rendering told you the most, in the least time?
2. Which rendering would you paste into a report, and why is the answer different from (1)?
3. `-m simple` never refuses. Chapter §4.3 prints jadx's pass list — find the pass whose name explains
   why, and say what it does.
4. Do the same comparison on the **release** DEX, where `tierFromPlanName` decompiles cleanly. How do
   the five renderings differ when nothing failed? That difference is jadx's editorialising, and it is
   what `scripts/jadx-vs-smali.sh` step (1) versus step (2) is designed to surface.

## Part 3c — Draw the graph (15 min)

For a method with tangled control flow, a picture beats both the Java and the bytecode.

```bash
# host
jadx --cfg --single-class com.pentest.ch56.AccountVault -q -d _build/cfg _build/dex-debug/classes.dex
find _build/cfg -name '*.dot' | head
```

If you have Graphviz:

```bash
# host
dot -Tpng _build/cfg/**/tierFromPlanName*.dot -o switch.png
```

If you do not, read the `.dot` file directly — it is plain text, and the node labels are the basic
blocks.

1. How many basic blocks does `tierFromPlanName` have? How many edges?
2. Identify the two switches. Where do they join?
3. Compare with `unlock`'s graph. Which is more complex, and does that match your intuition from
   reading the Java?
4. State when you would reach for `--cfg` on a real engagement. (Hint: chapter §6.7's row about
   control-flow flattening.)

## Part 4 — Say it out loud (15 min)

Write two paragraphs, for two audiences.

**For a developer** who has just said "it's compiled, nobody can read it". Explain what a decompiler
gives an attacker, in plain language, without using the word "somehow". Then state precisely what
obfuscation would and would not change about your answer. Two hundred words.

**For a junior colleague** who has just pasted a decompiled method into a report as "the app's
source code". Explain what is wrong with that framing and what they should have written instead.
Give them one concrete rule they can follow. One hundred words.

If you cannot write these without going back to the chapter, that is the signal to re-read §1 and
§5.4 — not a reason to skip the exercise.

---

## Stretch goals

- **Compile the jadx output.** Take `decompiled-release.java`, strip the header comment, and run
  `javac` on it. Record every error and explain each one. There are at least two structural failures
  and they are both instructive:
  - `new Runnable(this) { ... }` — you cannot pass a constructor argument to an interface.
  - the anonymous class's `{ this.this$0 = this; }` initialiser block assigning to a `final` field
    that the compiler will insist is already definitely assigned.

  Then ask the useful question: **what would jadx have had to do to make it compile, and what would
  that have cost in accuracy?** (It would have to hide the synthetic outer reference, which means
  hiding a field that genuinely exists and that you might need to know about.)

- **Add a Kotlin file.** If you have `kotlinc`, compile a small Kotlin class into the same DEX and
  find every fingerprint from
  [05-Kotlin §6.1](../../05-Kotlin/README.md#61-the-master-fingerprint-table) in the output. Then run
  with `-Pkotlin-metadata.method-args=no` and see how much of what you found came from `@Metadata`
  rather than from the bytecode.

- **Break the checksum.** Copy `_build/dex-release/classes.dex`, flip one byte in the middle of the
  data section with a hex editor, and run jadx on it. Then run it again with
  `-Pdex-input.verify-checksum=no`. What does each do? Where does the header checksum live, and which
  chapter documents it? ([12 — DEX Internals](../../12-DEX-Internals/README.md))

- **Measure the anonymous-class flag.** Run with `--no-inline-anonymous` and compare `auditor`. Which
  version would you rather read? Which is closer to what is in the DEX?

- **Time it.** How long does jadx take on this one-class DEX? Now estimate, from that, how long a
  20,000-class app takes — then read chapter §9.4's measured figure (148 seconds for 20,091 files)
  and see how wrong your estimate was. Decompilation cost is not linear in class count, and knowing
  that stops you over-planning your first hour on an engagement.

## Common mistakes in this lab

| Mistake | Symptom | Fix |
|---|---|---|
| Running the GUI launcher as the CLI | jadx prints nothing and never exits | Set `JADX_JAR` to `lib/jadx-gui-<ver>-all.jar`; chapter §1.3 |
| Compiling without `--release 8` | `d8`: "Unsupported class file major version" | `javac --release 8` |
| Reading the answer key first | You will remember none of it | Fill in your own table, then check |
| Assuming every difference is obfuscation | You conclude the app was obfuscated when it was not | Four independent losses; only one is R8's. Chapter §2.2 |
| Attributing the orphan `hashCode()` to jadx | A confident, wrong statement | Row 14, and Part 1b |
| Concluding "debug info is always better" | Wrong about `tierFromPlanName` | Part 3 |

---

## What you should carry out of this lab

- Decompiled Java is a **reconstruction**. You have now measured exactly how much of it was invented.
- The three possible authors of any line are the developer, the compiler and the decompiler, and
  telling them apart is a skill, not an instinct.
- **Guessing which one wrote a line is how wrong findings happen.** Row 14 exists specifically to
  catch you doing it.
- One build flag changes output quality more than anything else — and not uniformly.

Next: [Lab 02 — The method jadx gets wrong](lab-02-the-method-jadx-gets-wrong.md), which is the
chapter's central exercise.
