# Lab 01 — Build it yourself, then read the mapping

> **Objective.** Run R8 by hand on a Kotlin program you can read, then read every construct in the `mapping.txt` it produces — including the ones nobody tells you about — and retrace a real stack trace both by hand and with tooling.

**Difficulty:** Beginner to intermediate
**Time:** 60–90 minutes
**Root required:** No
**Device required:** No — this lab is entirely host-side
**Chapter sections:** [§3.7](../README.md#37-the-mappingtxt-format-completely), [§3.2](../README.md#32-inlining-and-why-it-makes-methods-vanish), [§9](../README.md#9-examples)

---

## Why this lab exists

Almost everyone's first contact with `mapping.txt` is a support ticket: an obfuscated crash arrives, somebody runs `retrace`, and the readable trace comes out. That works, and it teaches nothing.

The problem is that `mapping.txt` is treated as a black box precisely when it is most useful as a white one. It is a **record of what the optimiser did to the program**, and reading it directly tells you things no retraced stack trace ever will: which classes were deleted, which methods were dissolved into their callers, which members the compiler invented, and what the original source files were called. You cannot learn that from a tool that hands you the answer.

So this lab makes you produce the file from source you wrote, and then read it. By the end you will be able to open any `mapping.txt` cold and describe the shape of the program it came from.

---

## Setup

### What you need

| Requirement | Why | How to check |
|---|---|---|
| Android SDK build-tools 34.0.0+ | R8 lives inside `lib/d8.jar` | `ls $ANDROID_HOME/build-tools/*/lib/d8.jar` |
| A platform `android.jar` | R8 needs the framework as a library | `ls $ANDROID_HOME/platforms/android-*/android.jar` |
| A JDK, version 21 or lower | **R8 8.6.x cannot read class files newer than Java 21** | `java -version` |
| Kotlin compiler jars | To compile the source | See below |
| Python 3.8+ | For the chapter's scripts | `python3 --version` |

> **The JDK trap that will cost you twenty minutes**
> If your default `java` is 22 or newer, R8 fails with `Unsupported class file major version 68` (or 67, 66…) and reports it as *"Compilation failed with an internal error"*, which sounds like an R8 bug and is not. It is R8 refusing to read class files it does not know. Android Studio ships a JDK 21 at `<studio>/jbr`; use that:
> ```bash
> export JAVA21="/c/Program Files/Android/Android Studio/jbr/bin/java.exe"
> "$JAVA21" -version    # expect 21.x
> ```

### Confirm you have R8 at all

```bash
# host
$ SDK="${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}"
$ D8="$SDK/build-tools/35.0.1/lib/d8.jar"
$ java -cp "$D8" com.android.tools.r8.R8 --version
R8 8.6.2-dev (build abaab469b5ebd4dd2bb91ba0ed6f45277faae4ca from go/r8bot ...)
```

If that prints a version, you have everything. **There is no `r8.jar` in the Android SDK** — R8 and D8 are the same code in the same jar, distinguished only by which main class you invoke. Confirm that for yourself:

```bash
# host — same jar, different compiler
$ java -cp "$D8" com.android.tools.r8.D8 --version
D8 8.6.2-dev (build abaab469b5ebd4dd2bb91ba0ed6f45277faae4ca ...)
```

Same build hash. One binary, two entry points.

### Build the sample

Everything is scripted. From the chapter's `examples/` directory:

```bash
# host — ALWAYS build outside the notes repository
$ cd 42-R8/examples
$ export JAVA21="/c/Program Files/Android/Android Studio/jbr/bin/java.exe"
$ ./build-r8-demo.sh /tmp/r8-lab01
```

The script refuses to write inside the repository, on purpose — `.dex`, `.jar` and `.class` files must never be committed. If you point it at a path under the notes tree it will tell you so and exit.

Expected tail of the output:

```
BUILD             DEX_BYTES  MAP_LINES   META_CLASSES  VERDICT
full                   5324        206              0  no-metadata
compat                13956        490              0  no-metadata
meta2-full            22804        578             14  rewritten
meta2-compat          23280        558             14  rewritten
```

> **Checkpoint 1.** You have four builds and four mapping files. If `DEX_BYTES` for `full` is dramatically smaller than for `compat`, R8 is working as expected — you are seeing full mode's more aggressive optimisation, which [§3.9](../README.md#39-full-mode-and-what-it-actually-changes) quantifies.

The source you just built is [`../examples/LicenceVault.kt`](../examples/LicenceVault.kt). Read it now, before looking at any mapping. It declares a data class, an enum, a sealed class hierarchy, a class with a companion object and an inner class, two lambdas and a top-level extension function. Eleven types in about 130 lines. Keep that number in mind.

---

## Part 1 — What survived

### Step 1.1 — Count the classes in the output

```bash
# host
$ cd /tmp/r8-lab01
$ "$SDK/build-tools/35.0.1/dexdump.exe" -f out/full/classes.dex | grep -c 'Class descriptor'
```

Then list them:

```bash
# host
$ "$SDK/build-tools/35.0.1/dexdump.exe" -f out/full/classes.dex | grep 'Class descriptor'
  Class descriptor  : 'La/a;'
  Class descriptor  : 'La/b;'
  Class descriptor  : 'La/c;'
  Class descriptor  : 'La/d;'
  Class descriptor  : 'La/e;'
  Class descriptor  : 'Lb/a;'
  Class descriptor  : 'Lc/a;'
  Class descriptor  : 'Lc/b;'
  Class descriptor  : 'Lcom/pentest/ch42/vault/VaultEntryPoint;'
```

**Nine classes**, from a source file declaring eleven types plus the whole of `kotlin-stdlib` as input.

> **Question 1.** The source declares `LicenceVault`, `LicenceRecord`, `LicenceTier`, `VerificationOutcome` and three subclasses of it, `LicenceVault.Companion`, `LicenceVault.Diagnostics`, `LicenceVaultKt` and `VaultEntryPoint`. Only one of those names appears in the DEX. Where did the others go? Write down your hypothesis before continuing — there are three distinct fates and you should be able to guess at least two.

### Step 1.2 — Ask the mapping file

```bash
# host
$ grep -n 'com.pentest' out/full/mapping.txt | grep ' -> '
```

You will see three different kinds of outcome:

```
com.pentest.ch42.vault.LicenceRecord -> a.a:
com.pentest.ch42.vault.LicenceTier$EnumUnboxingSharedUtility -> a.b:
com.pentest.ch42.vault.LicenceVault$$ExternalSyntheticLambda0 -> a.c:
com.pentest.ch42.vault.LicenceVault$$ExternalSyntheticLambda1 -> a.d:
com.pentest.ch42.vault.VerificationOutcome$Granted -> a.e:
com.pentest.ch42.vault.LicenceVault$Diagnostics -> R8$$REMOVED$$CLASS$$0:
com.pentest.ch42.vault.LicenceVaultKt -> R8$$REMOVED$$CLASS$$1:
com.pentest.ch42.vault.VaultEntryPoint -> com.pentest.ch42.vault.VaultEntryPoint:
```

**The three fates:**

| Fate | Example | What it means |
|---|---|---|
| **Renamed** | `LicenceRecord -> a.a` | Survived, with a new name |
| **Removed** | `LicenceVault$Diagnostics -> R8$$REMOVED$$CLASS$$0` | **Not in the APK at all.** The entry exists only so its members can still be retraced |
| **Kept** | `VaultEntryPoint -> VaultEntryPoint` | A keep rule forbade renaming |

And a fourth, which is the surprising one:

| **Invented** | `LicenceTier$EnumUnboxingSharedUtility -> a.b` | R8 *created* this class. It corresponds to nothing the developer wrote |

> **Checkpoint 2.** You can now explain why "count the lines in `mapping.txt` to get the class count" is wrong in *both* directions: the file contains classes that are not in the APK (removed), and the APK contains classes that were not in the source (synthetic).

Verify with the chapter's tool, which separates the categories:

```bash
# host
$ python3 -B ../42-R8/scripts/mapping-reader.py out/full/mapping.txt stats
classes total                 : 12
  renamed                     : 8
  recorded but REMOVED by R8  : 3
  synthetic (any kind)        : 4
    $$ExternalSyntheticLambda : 2
members total                 : 156
  marked r8.synthesized       : 4
  inline frames (foreign owner): 78
```

Twelve entries. Nine classes in the DEX. Three removed. Four of the nine invented by R8.

> **Question 2.** `LicenceVault` — the main class of the program — appears nowhere in that list, not even as `R8$$REMOVED$$CLASS$$n`. Search the mapping for the string `LicenceVault.` (with the dot). What do you find, and what does it tell you about where the class went?

---

## Part 2 — Reading the grammar

Open `out/full/mapping.txt` in an editor. Do not use a tool for this part.

### Step 2.1 — The header

```
# compiler: R8
# compiler_version: 8.6.2-dev
# min_api: 33
# compiler_hash: abaab469b5ebd4dd2bb91ba0ed6f45277faae4ca
# common_typos_disable
# {"id":"com.android.tools.r8.mapping","version":"2.2"}
# pg_map_id: 6627817
# pg_map_hash: SHA-256 6627817335...
```

Every line is a comment, so a naive parser ignores all of it. Do not: this block dates the build, names the toolchain exactly, tells you the `minSdkVersion` R8 compiled against, and gives you `pg_map_id` — which is how you *prove* a mapping file belongs to a particular APK.

> **Try it.** R8 can embed the same id in the DEX. Read it back:
> ```bash
> # host
> $ java -cp "$D8" com.android.tools.r8.ExtractMarker out/full/classes.dex
> ```
> Compare any `pg-map-id` you see against the `pg_map_id` header. On a real app, a match turns "I found a file on a server" into "I found the de-obfuscation key for this exact release".

### Step 2.2 — A class block, line by line

Find this block:

```
com.pentest.ch42.vault.LicenceRecord -> a.a:
# {"id":"sourceFile","fileName":"LicenceVault.kt"}
    java.lang.String subscriberId -> a
    com.pentest.ch42.vault.LicenceTier tier -> b
      # {"id":"com.android.tools.r8.residualsignature","signature":"I"}
    long expiryEpochDay -> c
    1:3:void <init>(java.lang.String,com.pentest.ch42.vault.LicenceTier,long):19:19 -> <init>
      # {"id":"com.android.tools.r8.residualsignature","signature":"()V"}
    4:7:void <init>(java.lang.String,com.pentest.ch42.vault.LicenceTier,long):20:20 -> <init>
    4:39:boolean equals(java.lang.Object):0:0 -> equals
    0:24:int hashCode():0:0 -> hashCode
    0:61:java.lang.String toString():0:0 -> toString
```

Work through it:

1. **Column zero, ends in a colon** — a class line. `LicenceRecord` is `a.a` in the APK. Read **right to left**.
2. **`sourceFile` comment** — the original file was `LicenceVault.kt`. Note this is preserved *even though* the DEX itself flattens `source_file_idx` to the constant `"SourceFile"`. The mapping restores what the APK erased.
3. **Indented, no parentheses** — a field. `subscriberId` is `a`, `tier` is `b`, `expiryEpochDay` is `c`.
4. **`residualsignature` on `tier`** — the field's original type was `LicenceTier`, but in the shipped program its type is `I`, a plain `int`. This is the enum unboxing from Step 1.2, recorded at field level. **If you searched the DEX for a field of type `LicenceTier` you would find none.**
5. **Numbers before the return type** — obfuscated line ranges. Numbers after the parentheses — source lines.
6. **`residualsignature` `()V` on the constructor** — the shipped constructor takes **no arguments**. R8 determined all three were constant or unused after inlining and removed them.

> **Checkpoint 3.** You can state, without running anything, that a Frida script hooking `a.a.$init` with three arguments will not match this class, and explain why using the residual signature.

### Step 2.3 — The line-number arithmetic

Find the two-entry method:

```
    0:23:int com.pentest.ch42.vault.LicenceVault.mixSubscriberSalt(java.lang.String):47:47 -> b
    24:36:int com.pentest.ch42.vault.LicenceVault.mixSubscriberSalt(java.lang.String):50:50 -> b
```

The rule, from [§3.7.4](../README.md#374-method-lines--the-full-grammar):

- `srcStart == srcEnd` → the original line is `srcStart`, for the whole obfuscated range.
- Otherwise → the original line is `srcStart + (L - obfStart)`.
- One trailing number only → the original line is exactly that number, and this entry is a **caller** in an inline chain.
- `0` means unknown; print no line rather than `:0`.

> **Question 3.** An obfuscated frame reports line 30 in method `b`. Which entry covers it, and what source line does it map to? Now try line 24. And line 23.

### Step 2.4 — Inline chains, the part everyone gets wrong

Find these three consecutive lines:

```
    130:146:int com.pentest.ch42.vault.LicenceVault.tierWeight(com.pentest.ch42.vault.LicenceTier):56:56 -> main
    130:146:int com.pentest.ch42.vault.LicenceVault.computeActivationCode(com.pentest.ch42.vault.LicenceRecord):70 -> main
    130:146:void main(java.lang.String[]):119 -> main
```

Three entries. Same obfuscated range `130:146`. Same target name `main`. **This is one inline chain, and it lists frames innermost first.**

How to tell which is which:
- The **first** entry has *two* trailing numbers (`:56:56`) — it is the innermost frame, the code actually executing.
- Each **subsequent** entry has *one* trailing number — it is a caller.

So an exception at obfuscated `main:140` really happened in `tierWeight` at source line 56, called from `computeActivationCode` at source line 70, called from `main` at source line 119.

**Three source frames. One runtime method.** `tierWeight` and `computeActivationCode` do not exist in the APK.

> **Question 4.** Notice that the first two entries have a *qualified* method name — `com.pentest.ch42.vault.LicenceVault.tierWeight` — while the third is bare (`main`). What does the qualifier mean, given that all three appear inside the block for `VaultEntryPoint`?

---

## Part 3 — Retracing

### Step 3.1 — Get a genuine obfuscated stack trace

The build script already produced one by running the R8-processed program and crashing it:

```bash
# host
$ cat out/cf/crash.txt
Exception in thread "main" java.lang.IllegalStateException: vault detonated
	at com.pentest.ch42.vault.VaultEntryPoint.main(SourceFile:16)
```

**One frame.** This is the frame you retrace next — it is the point of the following step.

### Step 3.2 — Retrace it by hand

Do this manually first. Find the entries for `main` whose obfuscated range covers 16, in `out/cf/mapping.txt`:

```bash
# host
$ grep -E '^\s+16:16:' out/cf/mapping.txt
    16:16:java.lang.Void com.pentest.ch42.vault.LicenceVaultKt.detonate(com.pentest.ch42.vault.LicenceVault):0:0 -> main
    16:16:void main(java.lang.String[]):0 -> main
```

Two entries, same range, same target: an inline chain. First has two trailing numbers (innermost), second has one (caller). Both source lines are `0`, meaning unknown — so print no line number.

Your hand-retraced answer:

```
Exception in thread "main" java.lang.IllegalStateException: vault detonated
	at com.pentest.ch42.vault.LicenceVaultKt.detonate(LicenceVault.kt)
	at com.pentest.ch42.vault.VaultEntryPoint.main(LicenceVault.kt)
```

### Step 3.3 — Check yourself against R8

```bash
# host
$ java -cp "$D8" com.android.tools.r8.retrace.Retrace out/cf/mapping.txt out/cf/crash.txt
Exception in thread "main" java.lang.IllegalStateException: vault detonated
	at com.pentest.ch42.vault.LicenceVaultKt.detonate(LicenceVault.kt)
	at com.pentest.ch42.vault.VaultEntryPoint.main(LicenceVault.kt)
```

> **Checkpoint 4.** Your hand-retrace matches. More importantly: **the one-frame trace was two frames.** A release stack trace's frame count tells you about the optimiser, not about the program. Any conclusion of the form "the call stack was shallow, so it must have failed early" is unfounded on an R8 build.

### Step 3.4 — Retrace with no Android tooling at all

The realistic scenario is that you have a mapping file and a stack trace on a machine with neither a JDK nor the Android SDK.

```bash
# host
$ python3 -B ../42-R8/scripts/mapping-reader.py out/cf/mapping.txt retrace out/cf/crash.txt
```

Prove it agrees with the reference implementation:

```bash
# host
$ java -cp "$D8" com.android.tools.r8.retrace.Retrace out/cf/mapping.txt out/cf/crash.txt > gt.txt
$ python3 -B ../42-R8/scripts/mapping-reader.py out/cf/mapping.txt retrace out/cf/crash.txt > mine.txt
$ diff gt.txt mine.txt && echo IDENTICAL
IDENTICAL
```

It also accepts a pipe, which is how you would actually use it against a device:

```bash
# host
$ adb logcat -d -b crash | python3 -B ../42-R8/scripts/mapping-reader.py mapping.txt retrace
```

### Step 3.5 — A harder trace

Write this to `hard.txt`, against the **full-mode** mapping:

```
java.lang.IllegalStateException: synthetic probe
	at com.pentest.ch42.vault.VaultEntryPoint.main(SourceFile:140)
	at com.pentest.ch42.vault.VaultEntryPoint.main(SourceFile:305)
	at com.pentest.ch42.vault.VaultEntryPoint.main(SourceFile:349)
	at a.d.compare(SourceFile:10)
```

Retrace it:

```bash
# host
$ python3 -B ../42-R8/scripts/mapping-reader.py out/full/mapping.txt retrace hard.txt
```

Four frames in, **twelve out**. Look particularly at these two:

```
	at com.pentest.ch42.vault.LicenceVault.access$mixSubscriberSalt(LicenceVault.java:31)
	at com.pentest.ch42.vault.LicenceVault$Diagnostics.hardwareFingerprint(LicenceVault.kt:107)
```

> **Question 5.** Two oddities here. First, the file is reported as `LicenceVault.java` on one line and `LicenceVault.kt` on the next, from a program with no Java source at all. Second, `access$mixSubscriberSalt` was never written by anyone. Explain both. (Hints: [§3.7.4](../README.md#374-method-lines--the-full-grammar) on where an inline frame's source file comes from; [§3.8](../README.md#38-synthetic-members-the-complete-naming-vocabulary) on `access$`.)

---

## Part 4 — What the file discloses before you retrace anything

This is the part that matters for a report.

```bash
# host
$ python3 -B ../42-R8/scripts/mapping-reader.py out/full/mapping.txt stats
```

Read the output as an intelligence product rather than a statistic:

| Line | What a reader learns |
|---|---|
| `recorded but REMOVED by R8 : 3` | Three classes exist in the codebase but not in this build — features present in source, absent here |
| `$$ExternalSyntheticLambda : 2` | Two lambdas were desugared, and their names disclose the enclosing class |
| `inline frames (foreign owner): 78` | 78 places where one method was dissolved into another — a partial call graph |
| `top packages disclosed` | The internal package structure, including packages flattened away in the APK |
| `sourceFile` comments | Original file names, restoring what the DEX erased |

> **Checkpoint 5.** You can now argue, concretely, why a leaked `mapping.txt` is worse than an app that was never obfuscated: the unobfuscated app discloses names; the mapping file discloses names **plus** deleted classes, original file names, the inlining record, the synthetic/authored split, and a hash tying it all to one build.

### Optional — try the lookups

```bash
# host — what is a.a?
$ python3 -B ../42-R8/scripts/mapping-reader.py out/full/mapping.txt lookup a.a

# host — where did mixSubscriberSalt end up?
$ python3 -B ../42-R8/scripts/mapping-reader.py out/full/mapping.txt reverse mixSubscriberSalt
```

The `reverse` direction is the one a pentester wants and the official `retrace` does not offer: *"I know the method is called `verifyLicence` because I read the source in a leaked repository — where is it in the binary?"*

---

## Part 5 — Compare the modes

You built four times. Compare two:

```bash
# host
$ for b in full compat; do
    printf '%-8s dex=%-7s map=%-5s classes=%s\n' "$b" \
      "$(wc -c < out/$b/classes.dex)" "$(wc -l < out/$b/mapping.txt)" \
      "$("$SDK/build-tools/35.0.1/dexdump.exe" -f out/$b/classes.dex | grep -c 'Class descriptor')"
  done
full     dex=5324    map=206   classes=9
compat   dex=13956   map=490   classes=21
```

Same source, same rules, one flag. Full mode produced output **2.6× smaller** with **fewer than half the classes**.

> **Question 6.** Look at the class list for the compat build. Several classes present there are absent from the full build. Which optimisation is responsible for most of the difference, and how could you tell from the mapping file alone?

---

## Success criteria

You have finished this lab when you can do all of the following **without referring back to the chapter**:

- [ ] Run R8 on a jar from the command line, with a keep rule, producing a DEX and a mapping file.
- [ ] Explain why there is no `r8.jar` in the Android SDK.
- [ ] Given a `mapping.txt` line, say whether it describes a class, a field or a method, and read the rename in the correct direction.
- [ ] Identify a `residualsignature` comment and explain what it changes about how you would search the DEX.
- [ ] Identify an inline chain, say which entry is the innermost frame, and justify it from the trailing line numbers.
- [ ] Compute the original source line for a given obfuscated line, for both the `srcStart == srcEnd` case and the range case.
- [ ] Explain what `R8$$REMOVED$$CLASS$$0` means and predict what searching the APK for it will find.
- [ ] Retrace a one-frame stack trace by hand and get more than one frame out.
- [ ] Name four things a `mapping.txt` discloses *besides* the identifier renames.

---

## Answers

<details>
<summary>Question 1 — where did the classes go?</summary>

Three fates, all visible in the mapping:

- `LicenceRecord`, `VerificationOutcome$Granted` — **renamed** and present.
- `LicenceVault$Diagnostics`, `LicenceVaultKt` — **removed entirely**, recorded as `R8$$REMOVED$$CLASS$$n`.
- `LicenceVault`, `LicenceVault$Companion`, the other `VerificationOutcome` subclasses — **merged and inlined away**, appearing only as inline frames inside other classes' entries.

Plus a fourth that is not a "fate" of any source type: R8 **invented** `LicenceTier$EnumUnboxingSharedUtility` and two `$$ExternalSyntheticLambda` classes.
</details>

<details>
<summary>Question 2 — where is LicenceVault?</summary>

It has no class entry of its own. Searching for `LicenceVault.` finds it as a **qualifier on method entries inside other classes' blocks**:

```
    130:146:int com.pentest.ch42.vault.LicenceVault.tierWeight(...):56:56 -> main
```

That entry sits inside the block for `VaultEntryPoint`. The qualifier says the method's true owner was `LicenceVault`, and its presence here says the method was inlined into `VaultEntryPoint.main`. The class was merged out of existence: not deleted as dead code (it was used), but dissolved, with its members redistributed into their callers.

This is why it does not even get an `R8$$REMOVED$$CLASS$$n` entry — those are for classes whose *members* still need retracing under their own class identity. `LicenceVault`'s members are all recorded as inline frames elsewhere.
</details>

<details>
<summary>Question 3 — the line arithmetic</summary>

- **Line 30** falls in `24:36`, whose source range is `50:50`. Since `srcStart == srcEnd`, the answer is **line 50** — every obfuscated line in 24–36 maps to source line 50.
- **Line 24** is the first line of the same range: also **line 50**.
- **Line 23** falls in the *first* entry, `0:23`, source range `47:47`: **line 47**.

The lesson is that the mapping is not a per-line correspondence. R8 emits ranges, and a whole range frequently collapses onto one source line because the optimiser generated many instructions from one expression.
</details>

<details>
<summary>Question 4 — what the qualifier means</summary>

An unqualified method name belongs to the class whose block it is in. A **qualified** name means the method came from a *different* class and was **inlined into** this one; the qualifier names its true owner.

So inside `VaultEntryPoint`'s block, `com.pentest.ch42.vault.LicenceVault.tierWeight` means: "this range of `VaultEntryPoint.main` is actually the body of `LicenceVault.tierWeight`". The bare `main` entry at the end of the chain is the only frame that genuinely belongs to `VaultEntryPoint`.
</details>

<details>
<summary>Question 5 — the .java file and the access$ method</summary>

**The file name.** An inlined frame's source file comes from the *owner* class's own mapping entry, not from the class it was inlined into. `LicenceVault` has no class entry at all (Question 2), so R8 has no `sourceFile` record for it and falls back to synthesising `<SimpleName>.java` — hence `LicenceVault.java`. `LicenceVault$Diagnostics` *does* have an entry (as `R8$$REMOVED$$CLASS$$0`) carrying `sourceFile: LicenceVault.kt`, so that frame gets the real `.kt` name. A single retraced trace can therefore mix `.java` and `.kt` for a pure-Kotlin program.

**`access$mixSubscriberSalt`.** A synthetic accessor. `Diagnostics` is an inner class calling the outer class's `private fun mixSubscriberSalt`, which the JVM does not permit directly, so kotlinc generated a package-private bridge. Kotlin names these `access$<originalName>` — **keeping the original private member's name** — unlike `javac`, which names them `access$000`. It is a free disclosure of a private method's name.
</details>

<details>
<summary>Question 6 — where the size difference went</summary>

Mostly **class merging and inlining**, with enum unboxing contributing. Two ways to see it from the mapping alone:

1. Count `R8$$REMOVED$$CLASS$$n` entries in each file — full mode removes more.
2. Count inline frames (entries with a foreign-owner qualifier). `mapping-reader.py stats` reports this directly; the full-mode build has far more, because more methods were dissolved into callers.

The `EnumUnboxingSharedUtility` class is present in the full build and its absence or presence in the compat build is a direct tell for whether enum unboxing ran.
</details>

---

## Where to go next

- [Lab 02 — Synthetic safari](lab-02-synthetic-safari.md) takes the naming schemes you met here and applies them to a real APK.
- [§3.8](../README.md#38-synthetic-members-the-complete-naming-vocabulary) is the full synthetic-name vocabulary.
- [56-JADX §3.10](../../56-JADX/README.md) shows what to do with a `mapping.txt` once you have one: load it into jadx and get the whole decompiled tree back with real names.
