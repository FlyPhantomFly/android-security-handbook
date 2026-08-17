# Lab 02 — Build the diff: the same app, with and without rules

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Needs:** Android SDK build-tools (any recent version), a JDK, Python 3. **No device, no root, no
network, no Gradle.**
**Chapter sections:** [§2.2](../README.md#22-proguards-four-phases-and-r8s-one),
[§3.1](../README.md#31-the-four-phases-precisely), [§6](../README.md#6-reverse-engineering-perspective),
[§9 Example 2](../README.md#9-examples)

---

## Objective

Build **one application three times** — with no rules, with tightened rules, and with over-broad
rules — and measure, precisely, what survived each build.

This is the chapter's central exercise. Everything else here is commentary on the numbers you are
about to produce yourself.

By the end you will be able to:

- Demonstrate, with a diff, that `minifyEnabled true` proves nothing on its own.
- Show that an over-broad `-keep` leaves **dead code and its constants** in the APK, not just names.
- Read a `mapping.txt` and recognise a build that renamed nothing.
- Explain three toolchain behaviours that will otherwise mislead you: signing-block padding,
  R8's default `SourceFile` handling, and R8's partial reflection modelling.

---

## Setup

```bash
# host
export ANDROID_HOME=~/Android/Sdk          # or wherever your SDK lives
cd 41-ProGuard/examples/keeplab
ls java/com/pentest/ch41/                  # five .java files
ls ../01-overbroad-rules.pro ../02-tightened-rules.pro
```

**Verify the toolchain.** R8 does not ship as its own JAR in the SDK; it lives inside `d8.jar`:

```bash
# host
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
java -cp "$BT/lib/d8.jar" com.android.tools.r8.R8 --version
# R8 8.6.2-dev (build ... )
```

There is **no ProGuard binary in the Android SDK at all**. If you want to run genuine ProGuard, you
download it from Guardsquare separately. This lab uses R8, which is what your `proguard-rules.pro`
is actually fed to; the rules language is the shared part.

---

## Part 1 — Build all three (20 minutes)

```bash
# host — everything lands in $OUTDIR, outside the repository
OUTDIR=/tmp/ch41 ./build.sh
```

Expected tail of the output, measured on build-tools 35.0.1 / R8 8.6.2-dev / JDK 24:

```
a-norules      dex=   7384 B  apk=  12757 B  classes= 12  own-pkg= 12  named-members=  50
b-tightened    dex=   2920 B  apk=  12757 B  classes=  4  own-pkg=  3  named-members=  10
c-overbroad    dex=   7180 B  apk=  12757 B  classes= 12  own-pkg= 12  named-members=  49
```

**Task 1.1.** Before reading on: which of those three rows is the finding, and why?

**Task 1.2 — the first trap.** The three APKs are byte-for-byte the same size, 12,757 bytes, while
their `classes.dex` files differ by more than 2×. Work out why before reading the answer.

<details>
<summary>Answer</summary>

`apksigner` pads the **APK Signing Block** so that the ZIP central directory begins on a 4096-byte
boundary. All three DEX files fit inside the same padded span, so the total file size is identical.

The practical consequence, and it is the reason this is called out in `build.sh`'s own comments:
**comparing `ls -l *.apk` is the wrong way to check whether minification did anything.** On a small
app it will tell you nothing changed. Compare `classes.dex`.

</details>

**Task 1.3.** Confirm the padding claim yourself:

```bash
# host
python3 -B -c "
import zipfile
for v in ['a-norules','b-tightened','c-overbroad']:
    z = zipfile.ZipFile('/tmp/ch41/%s/app.apk' % v)
    print(v, [(i.filename, i.file_size, i.compress_size) for i in z.infolist() if i.filename.endswith('.dex')])
"
```

---

## Part 2 — What is in each DEX (30 minutes)

**Task 2.1.** Read the class listing the script printed. Fill in this table by hand:

| Class | A (no rules) | B (tightened) | C (over-broad) |
|---|---|---|---|
| `MainActivity` | | | |
| `LicenseValidator` | | | |
| `Transaction` | | | |
| `Transaction$Kind` | | | |
| `Transaction$WireName` | | | |
| `ReflectionEntry` | | | |
| `Analytics` | | | |
| `DeadCode` | | | |
| `R`, `R$id`, `R$layout`, `R$string` | | | |

Use three states: **present with original name**, **present renamed** (give the new name), **absent**.

**Task 2.2.** Three classes vanish entirely in build B. Name them, and for each say whether it was
*shrunk*, *inlined*, or *optimised out of existence* — they are not the same thing.

<details>
<summary>Answer</summary>

- `DeadCode` — **shrunk.** Nothing references it.
- `Analytics` — **inlined.** Its single method had one call site. `mapping.txt` records it as
  `com.pentest.ch41.Analytics -> R8$$REMOVED$$CLASS$$0`.
- `Transaction$Kind` — **enum-unboxed.** The enum was replaced by its underlying values; the class
  does not exist in the output at all.

The `R` classes are also absent from B: their integer constants were inlined at every use site, which
is what happens to `static final int` fields whenever a shrinker runs.

</details>

**Task 2.3 — the security-relevant row.** The script printed:

```
--- is the string 'staging-token-do-not-ship' still in the DEX? ---
  a-norules:   YES  (DeadCode was kept)
  b-tightened: no   (DeadCode was shrunk away)
  c-overbroad: YES  (DeadCode was kept)
```

Write the two sentences you would put in a report explaining why this row, and not the naming rows,
is what makes an over-broad `-keep` worth raising with a development team.

---

## Part 3 — Read the mappings (25 minutes)

```bash
# host
less /tmp/ch41/b-tightened/mapping.txt
less /tmp/ch41/c-overbroad/mapping.txt
```

**Task 3.1.** Build C's mapping is entirely identity mappings — `X -> X` on every line. Write the
one-liner that measures that fraction for any mapping file:

```bash
# host
awk -F' -> ' '/^[^ ].*:$/ {t++; if ($1 == substr($2,1,length($2)-1)) i++} END {printf "%d/%d identity (%.0f%%)\n", i, t, 100*i/t}' /tmp/ch41/c-overbroad/mapping.txt
awk -F' -> ' '/^[^ ].*:$/ {t++; if ($1 == substr($2,1,length($2)-1)) i++} END {printf "%d/%d identity (%.0f%%)\n", i, t, 100*i/t}' /tmp/ch41/b-tightened/mapping.txt
```

**Task 3.2.** In build B's mapping, find the entry for `Transaction`. It looks like this:

```
com.pentest.ch41.Transaction -> a.a:
    1:5:void <init>(com.pentest.ch41.Transaction$Kind,long,java.lang.String):60:60 -> <init>
      # {"id":"com.android.tools.r8.residualsignature","signature":"()V"}
```

Explain the `residualsignature` comment. What did R8 do to the constructor, and how would you verify
it from the DEX rather than from the mapping?

<details>
<summary>Answer</summary>

R8 removed all three constructor arguments — it proved they were constant at the single call site and
folded them into the constructor body. The `residualsignature` records the *actual* signature in the
output (`()V`) alongside the original, so retrace can still map a frame correctly.

Verify with `dexdump -d /tmp/ch41/b-tightened/classes.dex` and look at `La/a;.<init>`: it is `()V`,
and its body contains `const-wide/16 v0, #int 4999` and `const-string v0, "GBP"`.

</details>

**Task 3.3.** Also in build B's `Transaction`, `describe()` became `a()`. Dump its body:

```bash
# host
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
"$BT/dexdump" -d /tmp/ch41/b-tightened/classes.dex | sed -n "/a.a.a:()Ljava\/lang\/String;/,/catches/p"
```

The source called `kind.name()`. The DEX contains the literal string `"PURCHASE"`. Explain, and then
answer the question that matters: **what does an analyst learn about this app from a class called
`a.a`?**

---

## Part 4 — Run the tools (25 minutes)

**Task 4.1.** Audit both rules files:

```bash
# host — from the chapter root
cd ../..
python3 -B scripts/proguard-rules-audit.py examples/01-overbroad-rules.pro --no-colour
python3 -B scripts/proguard-rules-audit.py examples/02-tightened-rules.pro --no-colour
```

Measured summaries:

```
01-overbroad : CRITICAL=3, HIGH=1, MEDIUM=2, LOW=0, INFO=2
02-tightened : CRITICAL=0, HIGH=0, MEDIUM=1, LOW=1, INFO=5
```

**Task 4.2.** Report on each build:

```bash
# host
python3 -B scripts/what-survived.py /tmp/ch41/b-tightened/app.apk \
        --rules examples/02-tightened-rules.pro --package com.pentest.ch41
python3 -B scripts/what-survived.py /tmp/ch41/c-overbroad/app.apk \
        --rules examples/01-overbroad-rules.pro
```

**Task 4.3 — the second trap.** With `--package com.pentest.ch41`, build B reports **0% renamed**.
That is not what happened. Read the note the tool prints immediately above the verdict and explain
the trap in one sentence.

<details>
<summary>Answer</summary>

Renaming rewrites the **package** as well as the class. `Transaction` became `a.a` — it is no longer
under `com.pentest.ch41` at all, so `--package` filters it out. Scoping a census by the original
package systematically undercounts renaming, and the mistake is easy to make in the *reassuring*
direction: it makes a well-obfuscated app look unobfuscated.

Run without `--package` and compare.

</details>

**Task 4.4 — the third trap.** Look at section 6 of each report:

| Build | `SourceFile` attributes |
|---|---|
| A (no rules, D8) | **7 distinct original filenames**: `MainActivity.java`, `LicenseValidator.java`, `Transaction.java`, `Analytics.java`, `DeadCode.java`, `ReflectionEntry.java`, `R.java` |
| B (tightened, R8) | one constant value, `SourceFile` |
| C (over-broad, R8) | one constant value, `SourceFile` |

Build C sets `-keepattributes *` and `-dontobfuscate` and has **no** `-renamesourcefileattribute` —
and its filenames were still overwritten.

Confirm it directly:

```bash
# host
strings -a /tmp/ch41/a-norules/classes.dex   | grep -E '\.java$' | sort -u
strings -a /tmp/ch41/c-overbroad/classes.dex | grep -E '\.java$' | sort -u   # empty
```

Then answer: **which build leaked the developer's source filenames, and what does that do to the
usual advice about `-renamesourcefileattribute`?**

<details>
<summary>Answer</summary>

The *unminified* build leaked them. On R8 8.6.2, a minified build emits the constant `SourceFile`
regardless of the rules, so the widely-repeated warning ("keep `SourceFile` without renaming it and
your filenames ship") describes ProGuard's behaviour, not R8's default.

The advice to write `-renamesourcefileattribute SourceFile` is still correct — it makes the intent
explicit, it is required under ProGuard, and you should never depend on an unspecified default — but
the *observation* to make on someone else's APK is the reverse of what most checklists say. Measure
it; do not assert it.

</details>

---

## Part 5 — Change one rule at a time (30 minutes)

Now the experimental part. Copy the tightened rules to a scratch file so the repository copy stays
intact:

```bash
# host
cp examples/02-tightened-rules.pro /tmp/ch41/experiment.pro
```

For each experiment: edit `/tmp/ch41/experiment.pro`, rebuild with it, and record the diff.

```bash
# host — rebuild build B against your edited rules
BT=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)
AJ=$(ls -d "$ANDROID_HOME"/platforms/*/android.jar | sort -V | tail -1)
mkdir -p /tmp/ch41/exp && rm -f /tmp/ch41/exp/*.dex
java -cp "$BT/lib/d8.jar" com.android.tools.r8.R8 \
    --lib "$AJ" --min-api 21 --release \
    --pg-conf /tmp/ch41/experiment.pro \
    --pg-map-output /tmp/ch41/exp/mapping.txt \
    --output /tmp/ch41/exp \
    $(find /tmp/ch41/classes -name '*.class')
grep -E '^[a-z].* -> ' /tmp/ch41/exp/mapping.txt
```

**Experiment 5.1 — delete the native-methods rule.** Remove:

```proguard
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}
```

Measured result: `com.pentest.ch41.LicenseValidator -> a.a`. With the rule, the name is kept.

**Task.** Now dump `LicenseValidator` from the *original* build B:

```bash
# host
"$BT/dexdump" -d /tmp/ch41/b-tightened/classes.dex \
    | sed -n "/Class descriptor  : 'Lcom\/pentest\/ch41\/LicenseValidator;'/,/^  Class descriptor/p"
```

The class is **empty** — no fields, no methods. Explain how a rule conditioned on "has a native
method" kept the name of a class that has no methods at all.

<details>
<summary>Answer</summary>

Keep conditions are evaluated against the **input** program, in the root-set phase, before shrinking.
At that point `LicenseValidator` does have a `native` method, so the rule matches and puts the class
name into `noObfuscation`.

The directive is in the `names` family, which means `allowshrinking`, so it does **not** protect the
native method from removal. Shrinking then deletes `nativeCheck` (nothing calls it) and the optimiser
inlines the two real methods into `MainActivity.onCreate`. The name survives; its justification does
not.

For an analyst this is a distraction: an unrenamed class with an empty body is a wildcard
`keepclasseswithmembernames` artefact, and the code you want is in the caller.

</details>

**Experiment 5.2 — delete the reflection rule.** Remove:

```proguard
-keep class com.pentest.ch41.ReflectionEntry {
    <init>();
}
```

**Predict first.** Then measure. Under the model every guide teaches, the class is unreachable —
only a *string* names it — so it should be deleted, and `Class.forName` should throw
`ClassNotFoundException`.

Measured result on R8 8.6.2:

```
com.pentest.ch41.ReflectionEntry -> a.a:
```

```
# dexdump — the class survived intact
  Class descriptor  : 'La/a;'
  Instance fields   -   name : 'a'         type : 'Ljava/lang/String;'
  Direct methods    -   name : '<init>'    type : '()V'
  Virtual methods   -   name : 'toString'  type : '()Ljava/lang/String;'

# dexdump — MainActivity.onCreate: the forName call is GONE
005e: const-class v0, La/a;
0060: invoke-virtual {v0}, Ljava/lang/Class;.newInstance:()Ljava/lang/Object;
```

**Task.** Explain what R8 did, and then answer the question that actually matters: *does this mean
you can stop writing reflection keeps?*

<details>
<summary>Answer</summary>

R8 recognised the constant-string `Class.forName` idiom, resolved the class at build time, replaced
the whole call with a `const-class` instruction, kept the class so the reference stays valid, and
renamed it. The app works and the string is no longer in the DEX.

**No, you cannot stop writing the keeps.** The modelling is idiom matching, not analysis, and it stops
without warning. [`labs/ctf-vault`](ctf-vault/) contains the counter-example, measured in the same
session: R8 resolves `Class.forName("…Piece5")` exactly the same way *and then removes*
`Piece5.FIFTH`, because `getDeclaredField(String)` is not modelled. The class is reduced to an empty
abstract shell, the build emits no warning, and the app throws `NoSuchFieldException` at runtime.

A redundant keep rule costs nothing. A missing one costs a production crash on an untested path.

</details>

**Experiment 5.3 — widen one rule.** Replace the whole tightened file with a single line:

```proguard
-keep class com.pentest.ch41.** { *; }
```

Measure the DEX size, class count and the presence of `staging-token-do-not-ship`. You should
reproduce build C's numbers almost exactly — one line, and the entire configuration is undone.

**Experiment 5.4 — narrow the over-broad file.** Starting from
`examples/01-overbroad-rules.pro`, remove rules one at a time until the build still contains the
four classes the app genuinely needs and nothing else. Record which rules you could delete with no
effect at all.

---

## Part 6 — Write it up (20 minutes)

**Task 6.1.** Using the template in
[§9 Example 5](../README.md#example-5-enterprise--the-deliverable), write the finding for build C as
if it were a real application. Fill every measurement from your own run, not from this document.

**Task 6.2.** Your finding must survive this challenge from a developer:

> "We have `minifyEnabled true`. The build runs R8. You are telling me our obfuscation does nothing —
> prove it without showing me our source."

Write the three commands you would run in front of them, and what each one shows.

**Task 6.3.** Set the severity, and justify it in one sentence. If you wrote anything above Low
without a threat model to point at, read [§5.6](../README.md#56-honest-severity--how-to-actually-report-this)
again.

---

## Success criteria

- [ ] All three builds completed; you have the three `classes.dex` files and two `mapping.txt` files.
- [ ] You can state the DEX size, class count and named-member count for each build from your own run.
- [ ] You explained why the three APKs are the same size.
- [ ] You explained why `--package` reported 0% renamed for build B.
- [ ] You showed that build A leaked seven `.java` filenames and builds B and C leaked none.
- [ ] You reproduced the empty `LicenseValidator` and explained the rule that kept its name.
- [ ] You reproduced the `Class.forName` rewrite and can state why you would still write the rule.
- [ ] You produced a written finding with numbers from your own run and a defensible severity.

---

## Cleanup

```bash
# host — everything this lab produced lives outside the repository
rm -rf /tmp/ch41
# confirm the repo is clean
find . -name '*.dex' -o -name '*.apk' -o -name '*.class' -o -name '__pycache__'
```

---

## Where to go next

[Lab 03](lab-03-audit-an-unknown-app.md) removes the source. You get an APK and have to work out how
it was configured from the artefact alone.
