# Lab 01 — Read a rules file

**Difficulty:** Beginner
**Time:** 60–90 minutes
**Needs:** a text editor and Python 3. No device, no Android SDK, no network.
**Chapter sections:** [§3.2–3.11](../README.md#3-deep-internal-working)

---

## Objective

Decode a ProGuard/R8 rules file by hand — every directive, every wildcard, every member
specification — and be able to say for each line **what it preserves and how much of the application
it covers**, before any tool tells you.

This lab is deliberately tool-light. The auditor script exists and you will use it, but only to mark
your own work. A person who can only read a rules file through a tool cannot read one on a client's
laptop, cannot review a pull request, and cannot tell when the tool is wrong.

By the end you will be able to:

- State the six keep directives and what each protects, from memory.
- Predict which classes a pattern matches, including the three cases everybody gets wrong.
- Look at a real rules file and separate load-bearing rules from inherited noise.
- Write the one sentence that justifies each rule: *"delete this and X breaks."*

---

## Setup

```bash
# host — from the chapter root
cd 41-ProGuard
ls examples/01-overbroad-rules.pro examples/02-tightened-rules.pro
python3 --version                     # 3.8 or newer
```

Nothing else. Open both files side by side; you will spend most of the lab in them.

---

## Part 1 — The matrix (15 minutes)

Before reading anything, build the mental model. There are exactly six keep directives, and they are
three concepts crossed with two strengths.

**Task 1.1.** Fill this in from memory, then check against
[§3.5](../README.md#35-the-keep-family--six-directives-and-the-matrix-that-explains-them).

|  | Keeps the class | Keeps only members | Keeps the class *if it has* the members |
|---|---|---|---|
| Protects from **removal and renaming** | | | |
| Protects from **renaming only** | | | |

**Task 1.2.** Answer without looking:

1. `-keepnames` is shorthand for what?
2. A class matched by `-keepclassmembers` — is the class itself protected from deletion?
3. If nothing in the program references a class matched only by `-keepclassmembers`, what happens to
   the rule's effect?
4. Which two directives are conditional on the class *possessing* the named members?

**Task 1.3 — the two-question decoder.** Practise it on these until it is automatic:

```proguard
-keep class com.example.Foo
-keepnames class com.example.Foo
-keepclassmembers class com.example.Foo { *; }
-keepclasseswithmembernames class * { native <methods>; }
-keepclassmembernames class com.example.Foo { <fields>; }
-keepclasseswithmembers class * { public static void main(java.lang.String[]); }
```

For each: **(a)** does the directive name contain `names`? If yes it cannot stop deletion.
**(b)** does it contain `classmembers`? If yes it does not protect the class. Everything else is the
class specification.

> **Hint.** Row six is the classic "keep every class that has a `main` method" rule from ProGuard's
> Java heritage. It is conditional: classes without a `main` are untouched.

---

## Part 2 — Wildcards (20 minutes)

This is the part that decides whether you can read a rules file at all.

**Task 2.1.** For each pattern, write down which of the four classes it matches. Do it on paper
before checking.

Classes:

```
com.app.MainActivity
com.app.ui.LoginActivity
com.app.ui.widget.PinKeypad
MainActivity                        (default package)
```

Patterns:

| # | Pattern | Matches? |
|---|---|---|
| 1 | `com.app.*` | |
| 2 | `com.app.**` | |
| 3 | `com.app.ui.*` | |
| 4 | `*Activity` | |
| 5 | `**Activity` | |
| 6 | `*` | |
| 7 | `com.app.**Activity` | |
| 8 | `com.app.?ain*` | |

**Task 2.2.** Two of the eight above are traps. Identify them and say why.

<details>
<summary>Answers — try first</summary>

1. `com.app.MainActivity` only. `*` does not cross `.`.
2. All three `com.app.*` classes. `**` does cross `.`.
3. `com.app.ui.LoginActivity` only.
4. **`MainActivity` in the default package only.** This is trap one: `*` cannot cross `.`, so it
   cannot reach into a package. A rule like this in a real file matches nothing and nobody notices.
5. All three `*Activity` classes, including the default-package one.
6. **Every class in the program.** This is trap two: the bare class name `*` is a documented special
   case that matches any class irrespective of package, unlike `*` used as part of a longer pattern.
7. `com.app.MainActivity` and `com.app.ui.LoginActivity`.
8. `com.app.MainActivity`. `?` is exactly one character.

</details>

**Task 2.3 — type wildcards.** `*`, `**` and `***` are name wildcards *except* in type positions.
For each member specification, say what it matches:

```proguard
-keepclassmembers class com.example.Model {
    *   getName();
    *** get*();
    %   isEnabled();
    void set*(***);
    void configure(...);
    java.lang.String[] tags;
}
```

Specifically: which of the first two would match `public String[] getTags()`, and why?

<details>
<summary>Answer</summary>

Only the second. `*` in a type position matches a type name but not an array's `[]`; `***` matches
any type including arrays of any dimension. `%` matches primitives only, so `isEnabled()` returning
`boolean` matches but returning `Boolean` does not. `(...)` matches any argument list.

</details>

---

## Part 3 — Read the bad file (25 minutes)

Open [`examples/01-overbroad-rules.pro`](../examples/01-overbroad-rules.pro). **Cover the comments**
— they give the answers away — and read only the directives.

**Task 3.1.** For each of the six directives, write down, in your own words:

| Line | Directive | What it preserves | How much of the app it covers | What breaks if you delete it |
|---|---|---|---|---|
| | | | | |

**Task 3.2.** Rank the six by damage. Justify the top two.

**Task 3.3.** One of the six disables *shrinking* as well as renaming, without using
`-dontshrink`. Which one, and by what mechanism?

**Task 3.4.** One of them is not about renaming at all — it silences diagnostics. Explain, in one
sentence a developer would accept, why silencing them is a bad trade.

**Task 3.5.** Now uncover the comments and read them. Mark every place your answer differed. The
differences are the lab.

**Task 3.6.** Run the auditor:

```bash
# host
python3 -B scripts/proguard-rules-audit.py examples/01-overbroad-rules.pro --no-colour
```

Expected shape of the output (exact counts on R8-era tooling, measured):

```
summary: CRITICAL=3, HIGH=1, MEDIUM=2, LOW=0, INFO=2
```

Compare its severity ordering with yours. Where you disagree with the tool, decide who is right —
and note that the tool's own header says it cannot tell whether a rule is *necessary*, only how
broad it is.

---

## Part 4 — Read the good file (20 minutes)

Open [`examples/02-tightened-rules.pro`](../examples/02-tightened-rules.pro). Same application, same
functionality, same three genuine reflection requirements.

**Task 4.1.** For each rule, write the sentence *"delete this and X breaks."* Do not look at the
comments until you have written all of them. If you cannot write the sentence for a rule, that is
the signal the chapter cares about: **a rule you cannot justify is a guess.**

**Task 4.2.** Run the auditor on this file too:

```bash
# host
python3 -B scripts/proguard-rules-audit.py examples/02-tightened-rules.pro --no-colour
```

Measured result: `CRITICAL=0, HIGH=0, MEDIUM=1, LOW=1, INFO=5`.

**Task 4.3.** The one MEDIUM is `-keepclassmembers enum com.pentest.ch41.** { … }`, flagged because
its class pattern uses `**`. Is the tool right to flag it? Argue both sides.

<details>
<summary>Discussion</summary>

The tool is flagging breadth, and the pattern genuinely is package-crossing. But the *member*
specification is two named methods, not `{ *; }`, and the rule is `-keepclassmembers`, which does not
protect classes at all. Its worst case is that a few enum accessor methods keep their names across a
namespace — negligible.

This is exactly the tool's documented limitation, and it is worth internalising: **a breadth score is
not a severity.** The tool ranks by how much a rule *could* cover; you rank by what it *costs*. The
correct outcome here is "acknowledged, not changing it", written down, once.

</details>

**Task 4.4.** The tightened file deliberately contains **no** `-dontwarn`. Write the two-sentence
justification a reviewer would accept for that choice, and the two-sentence justification for adding
a *scoped* one if the build warns.

---

## Part 5 — Diff the two (15 minutes)

**Task 5.1.** Produce the diff and read it as a change list:

```bash
# host
diff -u examples/01-overbroad-rules.pro examples/02-tightened-rules.pro | less
```

**Task 5.2.** For each requirement below, find the rule in `02` that satisfies it and the rule in
`01` that satisfied it, and state which is narrower and by how much:

| Requirement | Rule in `01` | Rule in `02` |
|---|---|---|
| The launcher activity must be startable by name | | |
| A class is instantiated by `Class.forName` | | |
| `Enum.valueOf("REFUND")` must work | | |
| A statically-bound JNI method must resolve | | |
| A `Serializable` class's field names must be stable across versions | | |
| Crash reports must be de-obfuscatable | | |

**Task 5.3.** `01` uses `-dontobfuscate` to make crash reports readable; `02` uses two
`-keepattributes` lines and a `-renamesourcefileattribute`. Write the paragraph you would put in a
pull request explaining why the second is better. Include what `-renamesourcefileattribute` actually
does to the DEX.

---

## Part 6 — A file you have never seen (10 minutes)

**Task 6.1.** Find a real rules file on your own machine and read it the same way:

```bash
# host — the rules your dependencies impose on every project you build
find ~/.gradle/caches/modules-2 -name '*.aar' 2>/dev/null | head -40 | while read -r a; do
    if unzip -l "$a" 2>/dev/null | grep -q 'proguard.txt'; then
        echo "=== $a"; unzip -p "$a" proguard.txt
    fi
done | head -120
```

If you have no Gradle cache, use the SDK's own defaults:

```bash
# host
cat "$ANDROID_HOME/tools/proguard/proguard-android-optimize.txt"
```

**Task 6.2.** For whichever file you found, answer:

1. How many rules use `**`?
2. How many use `{ *; }`?
3. Is there a rule that would be imposed on **your** app if you depended on this library, that you
   would object to?
4. Run the auditor on it. Does it agree with you?

---

---

## Part 7 — Rules from failures (20 minutes)

The best rules files are written backwards: a failure happens, and the narrowest rule that fixes it
is added. Practise the mapping.

**Task 7.1.** For each symptom, write the narrowest rule that fixes it. Assume the application
package is `com.acme.app`.

| Symptom at runtime | Your rule |
|---|---|
| `ClassNotFoundException: com.acme.app.plugin.CsvExporter` from a `Class.forName` | |
| `NoSuchFieldException: apiToken` on `com.acme.app.net.Session`, read with `getDeclaredField` | |
| `IllegalArgumentException: No enum constant …Kind.REFUND` | |
| `UnsatisfiedLinkError: No implementation found for int com.acme.app.crypto.Native.sign(byte[])` | |
| GSON returns a `LinkedTreeMap` where a `List<User>` was expected | |
| The JSON your app sends has keys `a`, `b`, `c` instead of `email`, `name`, `id` | |
| `android.view.InflateException: Binary XML … Error inflating class com.acme.app.ui.PinKeypad` | |
| A `Parcelable` throws `BadParcelableException: ClassNotFoundException when unmarshalling` | |

<details>
<summary>Model answers</summary>

```proguard
-keep class com.acme.app.plugin.CsvExporter { <init>(); }

-keepclassmembers class com.acme.app.net.Session {
    java.lang.String apiToken;
}

-keepclassmembers enum com.acme.app.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keepclasseswithmembernames,includedescriptorclasses class com.acme.app.crypto.Native {
    native <methods>;
}

-keepattributes Signature

# annotate the fields and keep the annotated ones -- better than keeping the class
-keepattributes RuntimeVisibleAnnotations
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# custom Views named in layouts: AGP generates this from the AAPT scan.
# If you are writing it by hand, something is wrong with your build setup --
# check build/intermediates/aapt_proguard_file/<variant>/aapt_rules.txt first.

-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}
```

Two things to notice. The GSON answer changes the **code**, not just the rules — annotating the
fields means they can be renamed safely, which is strictly better than keeping them. And the
`InflateException` answer is "do not write a rule", because AGP already generates one; a hand-written
rule there is a symptom, not a fix.

</details>

**Task 7.2.** Three of your eight rules could reasonably have been written as
`-keep class com.acme.app.** { *; }` by a developer in a hurry. Which three, and what would each
have cost beyond the immediate fix?

**Task 7.3.** Write the comment you would put above each rule. The format is fixed and it is the
whole discipline:

```proguard
# Delete this and: <the exact symptom>.
# Needed because: <what reads it by name>.
-keep ...
```

If you cannot fill in the second line for one of your own rules, that rule is a guess.

---

## Success criteria

You are done when, without notes, you can:

- [ ] Reproduce the six-directive matrix.
- [ ] Say what `-keepnames` is shorthand for.
- [ ] Explain why `-keep class *Activity` almost certainly matches nothing, and why `-keep class *`
      matches everything.
- [ ] Explain the difference between `*` and `***` in a member specification.
- [ ] Look at `-keep class com.app.** { *; }` and list **three** distinct things it disables, not one.
- [ ] Write the "delete this and X breaks" sentence for every rule in
      `examples/02-tightened-rules.pro`.
- [ ] Say what `-keepattributes SourceFile` alone leaks, and what pairs with it to fix that.

---

## Hints

<details>
<summary>I cannot see why `-keep class com.app.** { *; }` disables shrinking</summary>

`-keep` protects matched entities from **removal** as well as from renaming — that is what
distinguishes it from `-keepnames`. `{ *; }` extends the protection to every member. So every class
in the namespace, and every one of its methods and fields, is in the "do not remove" set regardless
of whether anything references it. Dead code therefore ships.

</details>

<details>
<summary>Why is `-keepattributes SourceFile` a problem on its own?</summary>

The attribute holds the original `.java`/`.kt` filename, per class. Keeping it puts your source
filenames in the DEX. jadx will then use them to *name* the classes
(`--use-source-name-as-class-name-alias`), recovering much of what renaming removed.
`-renamesourcefileattribute SourceFile` overwrites every value with one constant, so line numbers
still resolve through `mapping.txt` and the filenames do not ship.

Measured caveat, from [§3.8](../README.md#38--keepattributes--the-attribute-reference): R8 8.6.2
overwrites `SourceFile` by default anyway. The rule is still correct to write — it makes the
intention explicit and it is required under ProGuard — but verify the behaviour of your own
toolchain instead of assuming.

</details>

<details>
<summary>Task 4.4 — I cannot justify the absence of `-dontwarn`</summary>

A missing-class warning means R8 saw a reference to a class that is on no classpath. At runtime that
is `NoClassDefFoundError` on whatever path first touches it. Suppressing all of them converts a
build-time signal into a production crash. A *scoped* `-dontwarn okhttp3.internal.platform.**` says
"I know these optional platform integrations are absent and that is intended"; `-dontwarn **` says
"I do not want to know".

</details>

---

## Where to go next

[Lab 02](lab-02-build-the-diff.md) builds the two files you just read and measures what each one
actually did to the shipped artefact. Everything you predicted in Parts 3 and 4 becomes a number.
