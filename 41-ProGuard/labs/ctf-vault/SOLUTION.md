# CH41 CTF — "the rule that lied" — solution

> **Spoilers.** Read [`../lab-04-ctf-the-rule-that-lied.md`](../lab-04-ctf-the-rule-that-lied.md)
> first, do the work, and come back. Everything below is measured output from
> `build.sh` on Android SDK build-tools 35.0.1 with **R8 8.6.2-dev**, JDK 24, Windows 11.
> Your R8 version may differ; where it does, the *reasoning* still holds and the
> exact strings may not. Re-measure rather than trusting this file.

---

## The flag

```
CH41{A7F2-9C10-f4b8-d31c}
```

**Four fragments, not five.** `Gate.java` assembles five. The fifth does not survive the build, so
it is not in the flag, and anyone who read the source instead of the artefact submitted a
five-fragment answer and was wrong. That is the whole exercise.

---

## What the build produced

```
$ OUTDIR=/tmp/ch41ctf ./build.sh
...
Classes that reached the DEX:
  La/a;
  Lcom/pentest/ch41/ctf/Fragments;
  Lcom/pentest/ch41/ctf/Gate;
  Lcom/pentest/ch41/ctf/Holder;
  Lcom/pentest/ch41/ctf/R$string;
  Lcom/pentest/ch41/ctf/R;
  Lcom/pentest/ch41/ctf/Stage;
```

```
$ grep -E "^[a-z].* -> " /tmp/ch41ctf/mapping.txt
com.pentest.ch41.ctf.Fragments  -> com.pentest.ch41.ctf.Fragments:
com.pentest.ch41.ctf.Gate       -> com.pentest.ch41.ctf.Gate:
com.pentest.ch41.ctf.Holder     -> com.pentest.ch41.ctf.Holder:
com.pentest.ch41.ctf.R          -> com.pentest.ch41.ctf.R:
com.pentest.ch41.ctf.R$string   -> com.pentest.ch41.ctf.R$string:
com.pentest.ch41.ctf.Stage      -> com.pentest.ch41.ctf.Stage:
com.pentest.ch41.ctf.inner.Piece5 -> a.a:
```

Six of seven classes kept their names. One did not. That one line is the answer to "which rule
lied".

---

## Fragment by fragment

### Fragment 1 — `A7F2`, an enum constant name

```
$ dexdump -d /tmp/ch41ctf/classes.dex
  Class descriptor  : 'Lcom/pentest/ch41/ctf/Stage;'
      name : '$VALUES'  type : '[Lcom/pentest/ch41/ctf/Stage;'  access : PRIVATE STATIC FINAL SYNTHETIC
      name : 'A7F2'     type : 'Lcom/pentest/ch41/ctf/Stage;'   access : PUBLIC STATIC FINAL ENUM
      name : 'FINAL'    type : 'Lcom/pentest/ch41/ctf/Stage;'   access : PUBLIC STATIC FINAL ENUM
      name : 'WARMUP'   type : 'Lcom/pentest/ch41/ctf/Stage;'   access : PUBLIC STATIC FINAL ENUM
```

An enum constant is a `public static final` field of the enum's own type, plus a synthetic
`$VALUES` array. The constants' **names** are the payload here, and they survived.

**Which rule kept them?** Two rules could have:

```proguard
-keepclassmembers enum com.pentest.ch41.ctf.Stage { *; }   # rule 2
-keep class com.pentest.ch41.ctf.* { *; }                  # rule 4 — also matches Stage
```

Rule 4 matches `com.pentest.ch41.ctf.Stage` because `Stage` is *directly* in that package. So the
fragment would have survived even without rule 2. Deleting rule 2 alone and rebuilding confirms it —
which is the point of the exercise's "which rules are inert" question: **rule 2 is redundant**, and
the auditor's rule-correlation output says as much.

Contrast this with the *standard* enum rule that almost every Android rules file carries:

```proguard
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}
```

That one keeps the two accessor methods, not `{ *; }`. Whether the constant *names* survive under it
depends on the engine and version, which is exactly why this challenge uses `{ *; }` — so the
fragment is deterministic and the lesson is about rule 4, not about enum edge cases.

### Fragment 2 — `9C10`, a string constant

```
$ strings -a /tmp/ch41ctf/classes.dex | grep -i 9c10
9C10
-9C10-
```

Two hits, and the second is more interesting than the first. R8's optimiser constant-folded the
separator characters into the literal, producing `-9C10-` as a single string in the pool. The
original `9C10` survives as well.

**No rule was needed.** There is no directive in ProGuard or R8 that removes, renames or alters a
string constant. `Fragments` kept its class name because of rule 4; had it been renamed, the string
would still have been there, byte for byte. This is section 5.5 of the chapter README, and it is the
single most important thing to be able to say to a developer.

### Fragment 3 — `f4b8`, a field name

```
$ dexdump -d /tmp/ch41ctf/classes.dex
  Class descriptor  : 'Lcom/pentest/ch41/ctf/Holder;'
      name : 'f4b8'    type : 'Ljava/lang/String;'
      name : '<init>'  type : '()V'
```

The field name survived, and note that its *value* (`value-is-not-the-flag`) is a decoy for anybody
who grabbed the first string they saw next to the field.

**Which rule kept it?** Rule 3:

```proguard
-keepclassmembernames class com.pentest.ch41.ctf.Holder { <fields>; }
```

`-keepclassmembernames` is `-keepclassmembers,allowshrinking`: it protects **names**, not presence.
Here it did not need to protect presence, because rule 4 already kept the class and all its members.
So rule 3 is also **redundant** in this build — a second inert rule, and a good illustration of how
a rules file accretes.

### Fragment 4 — `d31c`, a resource name

```
$ aapt2 dump resources /tmp/ch41ctf/app.apk | grep -oE 'string/[a-z0-9_]+'
string/app_name
string/d31c
string/decoy_e55e
```

Resource names live in `resources.arsc`. **R8 does not process `resources.arsc` at all**, so no
rule, no directive and no engine setting renames them. The name is also present in the DEX as a
literal, because `Gate` passes it to `getIdentifier("d31c", …)`.

This is why the first thing to read on an obfuscated app is its resource table: `layout/activity_pin`
and `id/pin_entry` tell you what a screen does when every class is called `a`.

### Fragment 5 — `e55e`, and why it is not in the flag

```
$ strings -a /tmp/ch41ctf/classes.dex | grep -i e55e
decoy_e55e
```

One hit, and it is the **decoy resource name**, not the fragment. The fragment's actual value is
nowhere in the DEX.

Here is what happened to `Piece5`, and it has two layers.

**Layer one — the rule that lied.**

```proguard
-keep class com.pentest.ch41.ctf.* { *; }
```

`*` **does not cross the package separator.** It matches
`com.pentest.ch41.ctf.Gate`, `…Holder`, `…Stage`, `…Fragments`, `…R` and `…R$string` — every class
*directly in* `com.pentest.ch41.ctf`. It does **not** match
`com.pentest.ch41.ctf.inner.Piece5`, which is one package deeper. The author needed `**`:

```proguard
-keep class com.pentest.ch41.ctf.** { *; }    # what they meant
```

The rule parses, the build succeeds, no warning is emitted, and `Piece5` is outside its scope.

**Layer two — what R8 did anyway, which is the part that surprises everybody.**

`Piece5` is not in the DEX under its own name, but it *is* in the DEX:

```
  Class descriptor  : 'La/a;'
  Access flags      : 0x0401 (PUBLIC ABSTRACT)
  Static fields     -
  Instance fields   -
  Direct methods    -
  Virtual methods   -
```

An empty, abstract shell. And in `Gate`:

```
004e: const-class v2, La/a;
0055: invoke-virtual {v2, v1}, Ljava/lang/Class;.getDeclaredField:(Ljava/lang/String;)…
```

The `Class.forName("com.pentest.ch41.ctf.inner.Piece5")` call **is not in the bytecode at all.** R8
recognised the constant-string `forName` idiom, resolved it at build time, kept the class so the
reference stays valid, renamed it to `a.a`, and rewrote the call site into a `const-class`.

But R8 does **not** model `getDeclaredField(String)`. Nothing reaches `FIFTH` through any edge R8
understands, so tree shaking removed the field — and with the field gone and no methods, the class
was reduced to an abstract shell.

At runtime, `Gate` therefore reaches `getDeclaredField("FIFTH")` on a class with no fields and
catches a `NoSuchFieldException`, logging `fragment 5 unavailable:`. The flag has four fragments.

> **This is the chapter's most important measured result.** The textbook model — "a shrinker reads
> bytecode edges, never strings" — is ProGuard's, and it is not quite true of R8 8.6.2. R8 models
> *some* reflection idioms and rewrites them. It models `Class.forName` with a constant argument. It
> does not model `getDeclaredField` with a constant argument. There is no warning at the boundary,
> and you cannot tell which side of it you are on by reading the source.
>
> The safe discipline does not change: **write the keep.** A redundant rule costs nothing. A missing
> one costs a `NoSuchFieldException` on a code path nobody tested.

---

## The three inert rules

Running the correlation:

```bash
python3 -B ../../scripts/what-survived.py /tmp/ch41ctf/app.apk --rules rules.pro
python3 -B ../../scripts/proguard-rules-audit.py rules.pro --no-colour
```

| Rule | Verdict |
|---|---|
| `-keep class …Gate { <init>(...); }` | **Load bearing.** Without it the launcher entry point could be renamed. In a real AGP build this rule is generated from the manifest and you would not write it |
| `-keepclassmembers enum …Stage { *; }` | **Redundant.** Rule 4 already covers `Stage` |
| `-keepclassmembernames class …Holder { <fields>; }` | **Redundant.** Rule 4 already covers `Holder`, and more strongly |
| `-keep class com.pentest.ch41.ctf.* { *; }` | **The liar.** Broad enough to make rules 2 and 3 pointless, and narrow in the one direction its author did not check |
| `-keepattributes SourceFile,LineNumberTable` + `-renamesourcefileattribute` | **Correct.** Verified: the DEX carries one constant `SourceFile` value, and no `.java` filenames |

The lesson that generalises: **a rule that is too broad and a rule that is too narrow are the same
mistake — a rule written without checking what it matches.** Rule 4 is both at once. It keeps six
classes it did not need to keep, and misses the one class it was written for.

The fix, and it is one line plus two deletions:

```proguard
# what the author should have written
-keep class com.pentest.ch41.ctf.Gate { <init>(...); }
-keepclassmembers enum com.pentest.ch41.ctf.Stage { *; }
-keepclassmembernames class com.pentest.ch41.ctf.Holder { <fields>; }
-keep class com.pentest.ch41.ctf.inner.Piece5 { public static java.lang.String FIFTH; }
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
```

Rebuild with that and all five fragments survive — and `Fragments`, `Holder` and `Stage`'s class
names are correctly renamed, because nothing needs them.

---

## Scoring

| Answer | What it means |
|---|---|
| `CH41{A7F2-9C10-f4b8-d31c}` | Correct. You read the artefact |
| `CH41{A7F2-9C10-f4b8-d31c-e55e}` | You read `Gate.java` and assumed the build honoured it |
| `CH41{A7F2-9C10-f4b8-decoy_e55e}` | You grepped for `e55e`, found the decoy resource, and did not check where it came from |
| Anything with `value-is-not-the-flag` | You took a field's value where the fragment was its name |

Full marks require the flag **and** naming the rule that lied **and** stating why `*` did not match
`com.pentest.ch41.ctf.inner.Piece5`.
