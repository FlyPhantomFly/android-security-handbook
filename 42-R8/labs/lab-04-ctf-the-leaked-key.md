# Lab 04 — CTF: The Leaked Key

> **The brief.** A vendor ships `GuardianVault`, a licensing component. During an engagement you obtain the release build *and* — from an unauthenticated CI artefact URL — a file called `mapping.txt`. Recover the flag.
>
> **Flag format:** `CH42{SEGMENT1-SEGMENT2-SEGMENT3}`
>
> Three segments. Each is recovered by a **different** technique from this chapter, and **none** of them can be found by grepping the DEX for the string `CH42` or `SEGMENT`. If you find yourself running `strings | grep -i flag`, you are on the wrong track — that is deliberate.

**Difficulty:** Advanced (capstone)
**Time:** 90–150 minutes
**Root required:** No
**Device required:** No
**Chapter sections:** all of [§3](../README.md#3-deep-internal-working), [§5.3](../README.md#53-the-mappingtxt-disclosure-and-why-it-is-different-in-kind), [§8](../README.md#8-static-analysis)

---

## Rules of engagement

1. **Do not open [`../examples/CtfVaultGuardian.kt`](../examples/CtfVaultGuardian.kt).** It is the answer key. The lab tells you when to come back and check your work.
2. You may read [`../examples/rules-ctf.pro`](../examples/rules-ctf.pro) — a pentester routinely gets the rules file, and one segment depends on noticing something in it.
3. Everything you need is in the chapter and in `../scripts/`.
4. Each segment is an ASCII token in leetspeak. When you find one you will know.

---

## Build the challenge

Binaries are never committed to this repository, so you build the target yourself.

```bash
# host — build OUTSIDE the notes repo; the script refuses otherwise
$ export JAVA21="/c/Program Files/Android/Android Studio/jbr/bin/java.exe"
$ cd 42-R8/examples
$ ./build-ctf.sh /tmp/ch42-ctf
```

Expected tail:

```
activation=-447401846
fingerprint=-1395623275
issued=1
ordered=1
mixed=1309
scaled=127
-- obfuscated stack trace (out/cf/crash.txt) --
Exception in thread "main" java.lang.IllegalStateException: guardian verification tripped
	at a.g.b(SourceFile:2)
	at a.g.a(SourceFile:3)
	at com.pentest.ch42.ctf.CtfEntryPoint.main(SourceFile:2)
```

Your artefacts:

| Path | Role in the scenario |
|---|---|
| `out/dex/classes.dex` | The shipped code you are analysing |
| `out/dex/mapping.txt` | **The leaked mapping file** |
| `out/cf/ctf-r8.jar` | A runnable build of the same program |
| `out/cf/crash.txt` | A genuine obfuscated stack trace |
| `out/cf/mapping.txt` | The mapping matching the runnable build |

> **Two mappings, and they are not interchangeable.**
> `out/dex/mapping.txt` and `out/cf/mapping.txt` come from two separate R8 invocations over the same input. Their name assignments differ, because [§3.6](../README.md#36-the-minifiers-naming-scheme) — R8 names are not stable across builds. **Retrace `crash.txt` with `out/cf/mapping.txt`.** Using the DEX one will give you a confident, wrong answer, which is exactly the failure mode the chapter warns about, and this lab will let you make it.

> **A note on names.** Your obfuscated names may differ from the transcript below. That is expected and is itself a lesson. Reason from structure, not from the literal `a.g`.

---

## Reconnaissance

Do this before hunting segments. It is the habit that matters more than the flag.

### Step R.1 — Identify the build

```bash
# host
$ cd /tmp/ch42-ctf
$ SDK="${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}"
$ D8="$SDK/build-tools/35.0.1/lib/d8.jar"
$ java -cp "$D8" com.android.tools.r8.ExtractMarker out/dex/classes.dex
```

### Step R.2 — Ask the mapping what it discloses, before using it

```bash
# host
$ python3 -B ../42-R8/scripts/mapping-reader.py out/dex/mapping.txt stats
```

Read the `top packages disclosed` block. You have just learned the application's package structure, its class count and how much of it is compiler-generated, **without decompiling anything**. That is the [§5.3](../README.md#53-the-mappingtxt-disclosure-and-why-it-is-different-in-kind) argument in practice: a leaked mapping discloses structure, not just names.

### Step R.3 — Inventory the classes

```bash
# host
$ python3 -B - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("kmr", "../42-R8/scripts/kotlin-metadata-recover.py")
kmr = importlib.util.module_from_spec(spec); spec.loader.exec_module(kmr)
for dex in kmr.load_dexes("out/dex/classes.dex"):
    for cd in dex.class_defs():
        print(dex.type_name(cd["class_idx"]))
PY
```

> **Recon question.** Most classes are one or two letters. **Two are not.** Note both — one of them is a segment, and the other is the entry point a keep rule protected. Which is which, and how would you tell them apart without knowing the answer?

---

## Segment 1 — the method that does not exist

**What you have:** an obfuscated stack trace with three frames.

```
	at a.g.b(SourceFile:2)
	at a.g.a(SourceFile:3)
	at com.pentest.ch42.ctf.CtfEntryPoint.main(SourceFile:2)
```

**What you need:** the original name of the method that actually threw.

### Try it the naive way first

```bash
# host — find a.g in the DEX and list its methods
$ "$SDK/build-tools/35.0.1/dexdump.exe" -f out/dex/classes.dex | grep -A2 "'La/g;'"
```

Whatever `a.g.b` is called in the DEX, the DEX cannot tell you what it *was*. Names are gone.

### Now use the mapping

```bash
# host — REMEMBER: crash.txt goes with out/cf/mapping.txt
$ python3 -B ../42-R8/scripts/mapping-reader.py out/cf/mapping.txt retrace out/cf/crash.txt
```

You should get **more frames out than you put in**.

> **Segment 1 checkpoint.** One of the retraced frames names a method whose name is a leetspeak token. That token is segment 1.

### Understand what you just did

Confirm the mechanism rather than accepting the answer:

```bash
# host — find the inline chain by hand
$ grep -nE '^\s+[0-9]+:[0-9]+:.*-> (a|b)$' out/cf/mapping.txt | head -20
```

> **Question 1.** The method carrying segment 1 does **not** appear anywhere in the DEX as a method. Explain precisely why, and say what R8 did with its body. Then explain why the raw trace had three frames but the retrace produced more.

> **Question 2.** Retrace `out/cf/crash.txt` against `out/dex/mapping.txt` — the *wrong* mapping. Does it error? What does it produce? What does this tell you about trusting a mapping file you found somewhere?

---

## Segment 2 — the name R8 forgot to rewrite

**What you have:** the DEX. **You may not use the mapping file for this segment** — pretend you never got it.

### Step 2.1 — Is there anything to recover?

```bash
# host
$ python3 -B ../42-R8/scripts/kotlin-metadata-recover.py out/dex/classes.dex --rewrite-check
```

You will get the verdict `rewritten`. Read the `detail` line carefully — it tells you exactly where to look next, and most people stop one line too early.

### Step 2.2 — The trap

```bash
# host
$ python3 -B ../42-R8/scripts/kotlin-metadata-recover.py out/dex/classes.dex --members | head -40
```

Look at the class and `fun` lines. They are `a`, `b`, `c`. R8's metadata rewriter did its job: **class names and function names are the obfuscated ones**.

If you conclude "nothing recoverable here", you have fallen into the trap this segment is built around — and it is the same trap [§3.10.3](../README.md#3103-the-part-r8s-rewriter-does-not-finish--and-this-is-the-recovery-path) exists to warn about.

### Step 2.3 — Look at the right lines

```bash
# host — the val lines, not the fun lines
$ python3 -B ../42-R8/scripts/kotlin-metadata-recover.py out/dex/classes.dex --members \
    | grep '^\s*val'
```

Among the recovered Kotlin property names is one leetspeak token, and one deliberate decoy that is *not* a segment.

> **Segment 2 checkpoint.** You have a property name that is plainly a flag token. Note also the JVM field beside it — a single letter. You have just reconstructed one row of `mapping.txt` from the APK alone.

> **Question 3.** Class names and function names came back obfuscated; property names came back original. Both are Kotlin-level names in the same protobuf, rewritten by the same R8 pass. Explain the difference **mechanically** — an answer that predicts the behaviour on a toolchain you have not tested.

> **Question 4.** Verify your recovery against the leaked mapping: does `mapping.txt` agree that the property's backing field was renamed to that single letter? Which command shows it?

---

## Segment 3 — the name that was never renamed

**What you have:** the DEX and [`../examples/rules-ctf.pro`](../examples/rules-ctf.pro).

Go back to your class inventory from Step R.3. Two class names are not one or two letters. One is the entry point, `com.pentest.ch42.ctf.CtfEntryPoint`. The other is segment 3, in plain text, in the shipped DEX.

### Step 3.1 — Find it

```bash
# host — long class names in a build where everything else is a single letter
$ python3 -B - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("kmr", "../42-R8/scripts/kotlin-metadata-recover.py")
kmr = importlib.util.module_from_spec(spec); spec.loader.exec_module(kmr)
for dex in kmr.load_dexes("out/dex/classes.dex"):
    for cd in dex.class_defs():
        d = dex.type_name(cd["class_idx"])
        if not d.startswith("Lcom/pentest"):
            continue
        simple = d[1:-1].rsplit("/", 1)[-1]
        print(("LONG  " if len(simple) > 3 else "short "), d)
PY
```

### Step 3.2 — Explain it

Read `rules-ctf.pro`. Every other class in the application's package is covered by rules of this shape:

```proguard
-keep,allowobfuscation class com.pentest.ch42.ctf.Guard** { *; }
```

One class is covered by a rule of this shape instead:

```proguard
-keep class com.pentest.ch42.ctf.SegmentThreeIs... { *; }
```

> **Segment 3 checkpoint.** The class name itself, minus the `SegmentThreeIs` prefix, is the token.

> **Question 5.** The two rules differ by one word. Explain exactly what `allowobfuscation` changes, and why its absence is described in [§5.4](../README.md#54-how-developers-get-this-wrong) as the most common way an app ends up unobfuscated while its build configuration claims otherwise.

> **Question 6.** This is the only segment recoverable with no tooling whatsoever. In a real engagement, why would this class in particular — the one a developer felt they had to keep by name — often be *more* interesting than the ones that got renamed?

---

## Assemble the flag

```
CH42{ <segment1> - <segment2> - <segment3> }
```

Strip the `segmentOneIs`, `segmentTwoIs` and `SegmentThreeIs` prefixes; join the three tokens with hyphens; no spaces.

### Self-check

```bash
# host — hash your answer and compare, without spoiling it in the file
$ printf '%s' 'CH42{...your answer...}' | sha256sum
```

The correct flag's SHA-256 is:

```
6ace402987929bccba536ddb9e184489696a157427c8b56fc7b38f8a2b36f17c
```

If it does not match, check for stray spaces, wrong case, or a hyphen you turned into an underscore. The tokens are uppercase leetspeak exactly as they appear in the recovered names.

Only after you have the flag — or have genuinely given up — open [`../examples/CtfVaultGuardian.kt`](../examples/CtfVaultGuardian.kt), which documents each hiding place.

---

## Part 5 — Write the engagement finding

The flag is the exercise; this is the deliverable. Using the rubric in [§5.7](../README.md#57-severity-a-rubric-you-can-defend), write up what you found.

You have three candidate findings, and they are **not** equal:

| Observation | Is it a finding? | Severity |
|---|---|---|
| `mapping.txt` served from an unauthenticated CI artefact URL | **Yes** | Medium |
| Kotlin property names recoverable from `@kotlin.Metadata` | Yes | Informational to Low |
| A class name exempted from renaming by a keep rule | Marginal | Informational |
| The app uses R8 with high obfuscation coverage | **No** | — |

> **Question 7.** Rank the three real observations by severity and justify each in one sentence. Then answer the harder question: **if the vendor fixed only one, which should it be, and why is that not "the most severe one"?**

> **Question 8.** The vendor replies: *"Obfuscation is defence in depth; the mapping file leak just removes one layer. Low severity."* Write a two-sentence rebuttal that is technically accurate and does not overstate the impact. (Careful: part of their claim is correct, and a rebuttal that denies all of it is wrong and will be dismissed.)

### Remediation, as code

Write the fix for the mapping leak. [§9](../README.md#9-examples) Example 5 has a working implementation; the important design decision is **detecting the file by content rather than by name**, because the incident version is rarely called `mapping.txt`.

---

## Success criteria

- [ ] Recover all three segments and assemble a flag matching the published hash.
- [ ] Recover segment 1 using **only** the stack trace and the mapping file.
- [ ] Recover segment 2 using **only** the DEX, with no mapping file.
- [ ] Recover segment 3 using **no tooling at all**.
- [ ] Explain why the segment-1 method does not exist in the DEX.
- [ ] Explain mechanically why property names survived metadata rewriting when function names did not.
- [ ] Explain what `allowobfuscation` changes, and why its absence leaks.
- [ ] Demonstrate what happens when the wrong mapping file is applied, and say why that is dangerous rather than merely wrong.
- [ ] Produce a severity-ranked finding list that does **not** report "the app is obfuscated" as a weakness.
- [ ] Write remediation that detects a mapping file by content.

---

## Answers

<details>
<summary>Recon question — telling the two long names apart</summary>

Both are long in a build where everything else is one or two letters, so both were exempted from renaming. Distinguish them by *why*:

- `CtfEntryPoint` is the program's entry point. Its keep rule keeps one specific method with a fixed signature (`public static void main(java.lang.String[])`) — the shape AGP generates for manifest components.
- The other is kept by a whole-class rule with all members (`{ *; }`) and no `allowobfuscation` — the shape a developer writes for reflection.

Without reading the rules file, the tell is structural: an entry point is referenced by the platform and typically has one or two well-known methods; a reflection-kept class looks like ordinary application code that has inexplicably kept its name. The second is almost always the more interesting one.
</details>

<details>
<summary>Question 1 — why the method does not exist</summary>

It was `private` and small, so R8 **inlined** it into every caller and then deleted it ([§3.2](../README.md#32-inlining-and-why-it-makes-methods-vanish)). No method with that name exists in the DEX because its body now lives, duplicated, inside its callers.

It survives in `mapping.txt` as an **inline frame**: an entry inside another method's block, with a qualified name identifying its true owner, sharing an obfuscated line range with the entries for its callers.

The raw trace had three frames because the JVM reports *runtime* frames, and after inlining there are fewer runtime frames than source frames. Retracing expands each runtime frame into the chain of source frames it represents — which is why the retrace is longer. A frame count in an R8 release trace tells you about the optimiser, not about the program.
</details>

<details>
<summary>Question 2 — the wrong mapping file</summary>

It does **not** error. It produces a fully-formed, plausible, wrong stack trace — because `a.g.b` exists in both mappings and maps to something in each.

This is the danger: the failure is silent and the output looks authoritative. It is the same reason a `mapping.txt` from app version 4.2 must never be applied to version 4.9 ([§3.6](../README.md#36-the-minifiers-naming-scheme)).

The defence is to verify the pairing before trusting it: compare the mapping's `pg_map_id` header against the `pg-map-id` in the APK's R8 marker via `ExtractMarker`. If they do not match, or either is absent, treat every retraced name as unverified.
</details>

<details>
<summary>Question 3 — why properties survived</summary>

R8 renames **JVM members**, and a Kotlin property is not one.

A Kotlin function maps one-to-one onto a JVM method. When R8 renames that method to `b`, it knows the new name and writes it into the metadata's `Function.name`, keeping the record self-consistent.

A Kotlin property is backed by up to three separate JVM members — a field, a getter and a setter — each renamed independently. There is no single new JVM name that `Property.name` could take. So R8 updates the `JvmPropertySignature` extension (which does reference concrete JVM members) and leaves the Kotlin-level `Property.name` alone.

The prediction this yields: enum entry names and companion object names *are* rewritten, because each corresponds to a JVM field R8 renamed. Check the `enum` lines in the extractor output and you will see exactly that.
</details>

<details>
<summary>Question 4 — verifying against the mapping</summary>

```bash
$ python3 -B ../42-R8/scripts/mapping-reader.py out/dex/mapping.txt reverse segmentTwo
```

It reports the class and the obfuscated field name. Compare with the `[field aI; ...]` annotation the extractor printed. When they agree, your metadata-only recovery is confirmed against R8's own record — and you have demonstrated that, for properties, the metadata channel yields the same information a leaked mapping file would.
</details>

<details>
<summary>Question 5 — what allowobfuscation changes</summary>

`-keep class X { *; }` means: X and all its members must exist in the output, **and must keep their names**. It is simultaneously a shrinking exemption and an obfuscation exemption.

`-keep,allowobfuscation class X { *; }` means: X and all its members must exist, **but R8 may rename them**. It is a shrinking exemption only.

Most keep rules exist because something is accessed reflectively. If the reflection is *by name* (`Class.forName("com.app.Foo")`), the name must survive. If it is by *annotation* or by *structure* — which is how most JSON mappers and DI containers work — the name need not survive, and `allowobfuscation` is correct.

Developers reach for the plain `-keep` form because it is shorter and always works, and each one silently exempts a class from obfuscation. Enough of them, or one with a broad wildcard like `-keep class com.app.** { *; }`, and the app is effectively unobfuscated while `minifyEnabled true` is still set — the exact failure [§8.4](../README.md#84-measuring-how-much-of-the-app-is-actually-obfuscated) is designed to measure.
</details>

<details>
<summary>Question 6 — why the kept class is more interesting</summary>

Because of *why* it was kept. A class survives renaming when something needs to find it by name at runtime — reflection, a service loader, a serialisation contract, a framework entry point, a plugin registry, a JNI binding.

Those are precisely the boundaries of the application: where it talks to the platform, to the network, or to code it did not write. They are entry points, and entry points are where an attacker starts.

So the classes a developer had to exempt are disproportionately the ones worth reading, and the exemption advertises them. The rest of the app being renamed makes them *easier* to find, not harder — they are the only long names in a sea of single letters.
</details>

<details>
<summary>Question 7 — ranking, and what to fix first</summary>

**Ranking:**

1. **Mapping file on an unauthenticated URL — Medium.** It reverses the obfuscation completely and additionally discloses removed classes, original file names, the inlining record and the package structure ([§5.3](../README.md#53-the-mappingtxt-disclosure-and-why-it-is-different-in-kind)).
2. **Kotlin property names via `@kotlin.Metadata` — Informational to Low.** Real, but narrow; here it discloses member names in library and model code, not a secret.
3. **A class name exempted by a keep rule — Informational.** Normal and often unavoidable; worth a sentence about reviewing keep rules, not a finding.

**What to fix first, and why it is not the most severe:** fix the mapping-file exposure — which *is* number one — but the reason is not its rank. It is that it is the only one with a **complete, cheap, verifiable fix**: an access control plus a build check, with no functional risk. Number two may be unfixable without breaking reflection, and number three may be required for the app to work. Remediation priority is severity *weighted by whether a safe fix exists*; recommending the removal of `kotlin.Metadata` from an app that uses Kotlin reflection trades an informational finding for a production outage.
</details>

<details>
<summary>Question 8 — the rebuttal</summary>

> "Agreed that obfuscation is defence in depth and its loss is not itself a compromise — the finding is not that the code became readable, but that a build artefact granting complete, authoritative de-obfuscation of a specific shipped release is publicly downloadable, along with the structural disclosure it carries: deleted classes, original file names and the inlining record. The severity reflects the exposure of a per-release credential from your build pipeline, which is a process control failure independent of how much the obfuscation was worth."

Why this works: it concedes the correct half of their claim immediately, which keeps the conversation technical, then relocates the finding from "obfuscation defeated" — where they have a defensible argument — to "build pipeline leaks a per-release artefact publicly", where they do not. It also names the structural disclosure, which they probably did not know was in the file.
</details>

---

## Where to go next

- [40-Obfuscation §6.1](../../40-Obfuscation/README.md) has the seven-phase deobfuscation methodology, of which this lab is the R8-specific slice.
- [56-JADX §3.10](../../56-JADX/README.md) shows what a leaked mapping does to a whole decompiled tree in one command.
- [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) for the MASVS-RESILIENCE framing the write-up should use.
