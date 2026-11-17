# Lab 04 — CTF: the rule that lied

**Difficulty:** Advanced (CTF)
**Time:** 90 minutes to 3 hours
**Needs:** Android SDK build-tools, a JDK, Python 3. No device, no root, no network.
**Chapter sections:** all of [§3](../README.md#3-deep-internal-working), and
[§6.3](../README.md#63-recognising-each-rule-from-the-output)

---

## The brief

A developer wrote a small application and a rules file. The rules file has five rules and the
application assembles a flag from five fragments. The developer believed each rule preserved one
fragment.

Exactly one of those rules does not do what its author intended.

**Recover the flag.** It has the form:

```
CH41{XXXX-XXXX-XXXX-...}
```

**Full marks require three things:**

1. The flag, exactly as the built application would produce it.
2. The name of the rule that lied, and precisely why it does not match what its author expected.
3. A corrected rules file that preserves all five fragments *and* is narrower than the original.

---

## Rules of engagement

- **You may read the sources.** They are right there. But the sources describe *intent*, and the
  challenge is about *outcome*. A flag assembled from `Gate.java` will be wrong.
- **You do not need to run the app.** Every fragment is recoverable by static analysis of the built
  DEX and APK. Running it on a device is allowed and will confirm your answer, but the intended
  solution never leaves the host.
- **The solution is in [`ctf-vault/SOLUTION.md`](ctf-vault/SOLUTION.md).** Read it last.

---

## Setup

```bash
# host
export ANDROID_HOME=~/Android/Sdk
cd 41-ProGuard/labs/ctf-vault
ls
# AndroidManifest.xml  build.sh  java/  res/  rules.pro  SOLUTION.md
```

Build it. Everything lands outside the repository:

```bash
# host
OUTDIR=/tmp/ch41ctf ./build.sh
```

Expected output:

```
built: /tmp/ch41ctf/app.apk

Classes that reached the DEX:
  La/a;
  Lcom/pentest/ch41/ctf/Fragments;
  Lcom/pentest/ch41/ctf/Gate;
  Lcom/pentest/ch41/ctf/Holder;
  Lcom/pentest/ch41/ctf/R$string;
  Lcom/pentest/ch41/ctf/R;
  Lcom/pentest/ch41/ctf/Stage;
```

Seven classes. Six kept their names. **One did not, and that is the entire challenge in one line of
output.**

---

## Stage 0 — Predict before you measure (20 minutes)

Do this before touching the DEX. It is the part that teaches.

**Task 0.1.** Read [`rules.pro`](ctf-vault/rules.pro). There are five directives (plus the attribute
pair). For each, write down:

| # | Directive | What it preserves | Which classes it matches | Which fragment it is meant to protect |
|---|---|---|---|---|
| 1 | `-keep class …Gate { <init>(...); }` | | | |
| 2 | `-keepclassmembers enum …Stage { *; }` | | | |
| 3 | `-keepclassmembernames class …Holder { <fields>; }` | | | |
| 4 | `-keep class com.pentest.ch41.ctf.* { *; }` | | | |
| 5 | `-keepattributes SourceFile,LineNumberTable` + `-renamesourcefileattribute` | | | |

**Task 0.2.** Read `java/` and list the five fragments and where each is stored. Note the *kind* of
storage in each case — a value, a name, a resource entry — because they survive for different
reasons.

**Task 0.3.** Predict, for each fragment: **survives / does not survive**, and why.

**Task 0.4.** Now find the lie. Two of the five rules are *redundant* — something else already keeps
what they protect. One is *wrong*. Which is which?

> **Hint if you are stuck.** Look very carefully at the class listing `build.sh` printed, and at the
> package each source file declares. One source file is not in the same package as the others.

---

## Stage 1 — Fragment recovery (45 minutes)

Four commands do most of the work.

```bash
# host — from the chapter root
cd ../..
python3 -B scripts/what-survived.py /tmp/ch41ctf/app.apk --rules labs/ctf-vault/rules.pro
python3 -B scripts/proguard-rules-audit.py labs/ctf-vault/rules.pro --no-colour

BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
"$BT/dexdump" -d /tmp/ch41ctf/classes.dex | less
strings -a /tmp/ch41ctf/classes.dex | sort -u | less
```

**Task 1.1 — fragment 1** is the *name* of an enum constant. Find it:

```bash
# host
"$BT/dexdump" -d /tmp/ch41ctf/classes.dex \
    | sed -n "/Class descriptor  : 'Lcom\/pentest\/ch41\/ctf\/Stage;'/,/Direct methods/p"
```

Note what an enum constant looks like at DEX level — `PUBLIC STATIC FINAL ENUM`, of the enum's own
type, plus a synthetic `$VALUES` array.

**Task 1.2 — fragment 2** is a string constant. It is trivially findable; the point is *why* it was
never at risk. Answer in one sentence: which directive in the ProGuard language removes or alters a
string constant?

**Task 1.3 — fragment 3** is a *field name*, not a field value. The class holding it also has a
decoy value. Make sure you take the name.

**Task 1.4 — fragment 4** is a *resource name*.

```bash
# host
aapt2 dump resources /tmp/ch41ctf/app.apk | grep -oE 'string/[a-z0-9_]+'
```

Three resource names come back. One is the fragment, one is the app name, and one is a decoy placed
there specifically to catch a careless grep. Decide which is which — and note *why* you can be sure,
rather than guessing.

**Task 1.5 — fragment 5.** This is the challenge.

```bash
# host
strings -a /tmp/ch41ctf/classes.dex | grep -i e55e
```

You will get exactly one hit and it is **not** the fragment. Now find out what happened to
`Piece5`:

```bash
# host
grep -E '^[a-z].* -> ' /tmp/ch41ctf/mapping.txt
"$BT/dexdump" -d /tmp/ch41ctf/classes.dex | sed -n "/Class descriptor  : 'La\/a;'/,/^  Class descriptor/p"
"$BT/dexdump" -d /tmp/ch41ctf/classes.dex | grep -E 'const-class|getDeclaredField|forName'
```

**Task 1.6.** Answer all four:

1. Is `Piece5` in the DEX at all?
2. What is it called, and what does it contain?
3. Where did the `Class.forName("com.pentest.ch41.ctf.inner.Piece5")` call go?
4. Given (1)–(3), what happens at runtime when `Gate` calls `getDeclaredField("FIFTH")`?

**Task 1.7.** Assemble the flag. Count your fragments before you submit.

---

## Stage 2 — Name the lie (20 minutes)

**Task 2.1.** State the rule and the exact reason it does not match `Piece5`. Your answer must
include the sentence that generalises, not just the observation about this file.

**Task 2.2.** Write the one-character fix.

**Task 2.3.** The build emitted **no warning** about this. Explain why not, and name the two
diagnostic directives that would have surfaced it during development.

<details>
<summary>Hint</summary>

A rules file has no statement terminator and no symbol table. A rule that matches nothing is
syntactically indistinguishable from one that matches everything — it just adds nothing to the root
set. ProGuard emits a *note* for some of these; R8 is usually silent. The directives that would have
told the author are in [§3.10](../README.md#310-diagnostics--the-directives-that-make-rules-writable).

</details>

---

## Stage 3 — The deeper surprise (25 minutes)

`Piece5` is not in the DEX under its own name, and yet it *is* in the DEX. Reconcile that.

**Task 3.1.** From the `dexdump` output, what are `La/a;`'s access flags, and what does that tell
you about what R8 concluded about the class?

**Task 3.2.** The `Class.forName` call has vanished from `Gate`'s bytecode entirely. Explain what R8
did, and why the class had to be kept for that transformation to be legal.

**Task 3.3.** R8 modelled `Class.forName(<constant>)`. It did **not** model
`getDeclaredField(<constant>)`. Both are reflection with a constant argument. Write the sentence you
would say to a developer who concludes from Task 3.2 that "R8 handles reflection now, so we can
delete our keeps".

**Task 3.4 — cross-check.** Reproduce the same behaviour in the *other* fixture, to show it is not
an artefact of this one:

```bash
# host — delete the ReflectionEntry rule from a COPY, rebuild, and look
cp examples/02-tightened-rules.pro /tmp/exp.pro
python3 -B - <<'EOF'
t = open('/tmp/exp.pro', encoding='utf-8').read()
t = t.replace("""-keep class com.pentest.ch41.ReflectionEntry {
    <init>();
}""", "")
open('/tmp/exp.pro', 'w', encoding='utf-8').write(t)
EOF
# then rebuild build B against /tmp/exp.pro as in lab-02 Part 5 and read the mapping
```

Measured result: `com.pentest.ch41.ReflectionEntry -> a.a`, with the class, its constructor, its
field and `toString()` all intact, and `const-class La/a;` in place of the `forName` call.

**Task 3.5.** Two `Class.forName` calls, resolved identically by R8, with opposite outcomes for the
target's members. Explain the difference in one paragraph. *(The answer is not about `forName`.)*

---

## Stage 4 — Fix it properly (20 minutes)

**Task 4.1.** Write `fixed-rules.pro`: all five fragments survive, and the file is **narrower** than
the original. Narrower means: fewer classes keep their names, not more rules.

**Task 4.2.** Build with it. Write your corrected file **outside the repository** — put it in
`/tmp/ch41ctf/` — so the shipped challenge stays intact for the next person, then invoke R8 directly
exactly as in [lab 02 Part 5](lab-02-build-the-diff.md#part-5--change-one-rule-at-a-time-30-minutes),
pointing `--pg-conf` at your file.

Then check all three properties:

- All five fragments present in the DEX.
- `Fragments`, `Holder` and `Stage` **renamed** — because nothing needs their class names, and a
  correct fix makes the output *more* obfuscated, not less.
- The auditor reports no CRITICAL and no HIGH.

**Task 4.3.** Run the auditor on the original and on yours, and paste the two summary lines side by
side. The original measures `CRITICAL=0, HIGH=1, MEDIUM=1, LOW=0, INFO=4` —it does **not**
flag the rule that lied, because the auditor scores *breadth*, and a rule that is too narrow is
invisible to it.

**Task 4.4 — the meta-lesson.** Write two sentences explaining why a rules auditor structurally
cannot find the bug in this challenge, and which of the chapter's other two tools can. Then say what
that implies about relying on any single check.

<details>
<summary>Answer</summary>

`proguard-rules-audit.py` reads the rules file and nothing else. A rule that matches fewer classes
than its author intended is indistinguishable, from the text alone, from a rule that matches exactly
what it should — the file does not say what the author meant. Breadth is measurable; intent is not.

`what-survived.py` finds it, because it correlates the rules against the **built artefact** and
reports the rule as matching nothing of interest while `Piece5` is renamed. That is the general
principle: **a configuration check and an artefact check catch different classes of defect, and
neither is sufficient.** It is also why the CI gate recommended in
[§9 Example 5](../README.md#example-5-enterprise--the-deliverable) tracks a number taken from the
shipped APK, not from the rules file.

</details>

---

## Stage 4b — Optional: make the challenge harder

If you finished quickly, these variants each take a few minutes to build and each teaches one more
thing. Edit copies under `/tmp`, never the shipped sources.

**Variant 1 — move the goalposts.** Change rule 4 from `com.pentest.ch41.ctf.*` to
`com.pentest.ch41.ctf.**` and rebuild. Which classes are now unrenamed that were not before? Is the
flag complete? Is the app *better* configured than it was?

<details>
<summary>Discussion</summary>

All five fragments survive and every class in the namespace keeps its name and members — you fixed
the correctness bug by making the hardening worse. This is precisely the trade a developer makes
under time pressure, and it is why the *right* fix is a rule naming `Piece5`, not a wider wildcard.

</details>

**Variant 2 — remove the enum rule.** Delete rule 2 and rebuild. Does fragment 1 survive? Why?

**Variant 3 — remove rule 4 entirely** and keep rules 1, 2, 3 only. Predict which fragments survive
before you build. Then check — the answer is more interesting than it looks, because `Fragments`'
string constant survives even though nothing keeps the class, and the resource name survives because
nothing in the DEX controls it.

**Variant 4 — the reflection cliff.** In `Gate.java`, replace

```java
Class<?> c = Class.forName("com.pentest.ch41.ctf.inner.Piece5");
```

with

```java
String n = "com.pentest.ch41.ctf" + "." + "inner" + ".Piece5";
Class<?> c = Class.forName(n);
```

then with a version where the name is read from a resource string. Rebuild each time and record
whether R8 still resolved the call. This maps the exact boundary of R8's constant-string modelling,
and it is the most useful thing in this lab for anyone who has to advise developers.

**Variant 5 — add the decoy that fools a tool.** Add a class whose *name* is
`com.pentest.ch41.ctf.Piece5` (same simple name, different package) containing a different value.
Rebuild and run `what-survived.py`. Does the correlation output distinguish them? This is how
shaded and relocated libraries confuse a census — see
[17-Libraries](../../17-Libraries/README.md).

---

## Stage 5 — Write it up (15 minutes)

**Task 5.1.** Write the finding as if `rules.pro` were a real project's file. Two observations, at
two different severities:

1. A rule intended to preserve a reflectively-loaded class does not match it. **This is not an
   obfuscation finding** — it is a *correctness* finding, and its severity comes from the crash, not
   from the naming.
2. A package-scoped keep with `{ *; }` retains six classes that do not need it. **This is** an
   obfuscation finding, at hardening severity.

Getting those two the right way round is the point of the exercise. The rule that lied causes a
runtime failure; the rule's breadth is merely a weakened control.

**Task 5.2.** One sentence for the developer explaining how to prevent recurrence, naming a specific
directive.

---

## Scoring

| | Points |
|---|---|
| Flag correct, four fragments | 40 |
| Named the rule that lied and gave the `*` vs `**` reason | 25 |
| Explained the `const-class` rewrite and why the class survived anyway | 15 |
| Explained why `getDeclaredField` was not modelled and `forName` was | 10 |
| Produced a `fixed-rules.pro` that is both correct and narrower | 10 |

Submitting a five-fragment flag scores zero for the flag, regardless of the rest. Reading the source
and believing it is the failure mode this challenge exists to teach.

---

## Success criteria

- [ ] Flag recovered from the artefact, with the correct number of fragments.
- [ ] The lying rule named, with the wildcard reasoning stated generally.
- [ ] You can point at the `const-class` instruction and say what it replaced.
- [ ] You identified which two rules are redundant and why.
- [ ] You wrote a corrected rules file that is narrower than the original and verified both
      properties.
- [ ] You wrote the two findings at the correct relative severities.

---

## Cleanup

```bash
# host
rm -rf /tmp/ch41ctf /tmp/exp.pro
find . -name '*.dex' -o -name '*.apk' -o -name '*.class' -o -name '__pycache__'
```

---

## After the CTF

Read [`ctf-vault/SOLUTION.md`](ctf-vault/SOLUTION.md). It gives the measured output for every stage,
including the two things most people get wrong: the decoy resource name, and the assumption that a
rule which parses is a rule that matches.
