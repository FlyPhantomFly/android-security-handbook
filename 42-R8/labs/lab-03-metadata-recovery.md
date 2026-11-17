# Lab 03 — Recover original names from `kotlin.Metadata`

> **Objective.** Produce a renamed R8 build yourself, then recover the original Kotlin names from an annotation R8 left behind — and establish, by measurement rather than by repetition, exactly how far that recovery goes and where it stops.

**Difficulty:** Intermediate to advanced
**Time:** 120–150 minutes
**Root required:** No
**Device required:** Optional — only to source real APKs for Part 4
**Chapter sections:** [§3.10](../README.md#310-kotlinmetadata-the-annotation-r8-does-not-always-finish-rewriting), [§4.1](../README.md#41-the-dex-structures-r8-writes), [§5.6](../README.md#56-a-measured-correction-to-the-kotlinmetadata-folklore)

---

## Why this lab exists

[40-Obfuscation](../../40-Obfuscation/README.md) puts `kotlin.Metadata` in its table of things that survive identifier renaming, with this claim:

> *"The Kotlin reflection library reads it. It contains original names in a protobuf. Frequently not stripped. … this can hand you back original names wholesale."*

[56-JADX](../../56-JADX/README.md) states a stronger version:

> *"The `@Metadata` annotation is a de-obfuscation oracle that R8 does not remove by default."*

Both chapters point here for the detail, and neither demonstrates it. That is the gap this lab closes — and closing it properly means being willing to find that the claim is partly wrong, which is what happened.

**This lab is built around a real, reproducible experiment**, not a demonstration of a foregone conclusion. You will build the same Kotlin source four ways, measure what R8 does to the annotation in each, and discover that there are *four* distinct outcomes rather than the two the folklore describes. Then you will run the same measurement across real APKs and see how often each outcome occurs in the wild.

The finding is more useful than the folklore, and considerably more defensible in a report.

---

## Background: what you are attacking

> **Definition — `@kotlin.Metadata`**
> A runtime-visible annotation that `kotlinc` attaches to every class it compiles. It exists because the JVM class file format cannot express Kotlin's type system — nullability, `val` versus `var`, properties as distinct from fields, default parameters, `suspend`. Kotlin reflection reads it to reconstruct the original declaration.

Its elements ([05-Kotlin §8.3](../../05-Kotlin/README.md) owns the structure; this lab owns what R8 does to it):

| Element | Content |
|---|---|
| `k` | Kind: 1 = class, 2 = file facade, 3 = synthetic class, 4 = multi-file facade, 5 = multi-file part |
| `d1` | The **protobuf payload**, encoded to survive the class file's UTF-8 constraints |
| `d2` | The **string table** the protobuf indexes into — plaintext names |
| `xs`, `xi`, `pn` | Extra string, extra flags, package name |

**The reason a recovery is possible at all** is worth stating, because it is a general principle: the annotation must be readable by Kotlin reflection *at runtime*, therefore it must be readable by you *statically*. There is no encryption and no computation — just DEX structures walked by `art/runtime/dex/dex_file_annotations.cc` at runtime and by [`../scripts/kotlin-metadata-recover.py`](../scripts/kotlin-metadata-recover.py) offline.

---

## Setup

Same as [Lab 01](lab-01-build-and-read-mapping.md): Android SDK build-tools, a JDK **21 or lower**, Python 3.8+.

```bash
# host
$ export JAVA21="/c/Program Files/Android/Android Studio/jbr/bin/java.exe"
$ cd 42-R8/examples
$ ./build-r8-demo.sh /tmp/r8-lab03
```

Expected summary:

```
BUILD             DEX_BYTES  MAP_LINES   META_CLASSES  VERDICT
full                   5324        206              0  no-metadata
compat                13956        490              0  no-metadata
meta2-full            22804        578             14  rewritten
meta2-compat          23280        558             14  rewritten
```

That table **is** the experiment. The rest of Parts 1–3 explains what each row means and why.

The source is [`../examples/LicenceVault.kt`](../examples/LicenceVault.kt); the two rule files are [`../examples/rules-baseline.pro`](../examples/rules-baseline.pro) and [`../examples/rules-keep-metadata.pro`](../examples/rules-keep-metadata.pro). Read all three before continuing.

---

## Part 1 — The default: R8 strips it

### Step 1.1 — Look for the annotation in the baseline builds

```bash
# host
$ cd /tmp/r8-lab03
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py out/full/classes.dex --rewrite-check
target   : out/full/classes.dex
classes  : 0 with @kotlin.Metadata
decoded  : 0
verdict  : no-metadata
```

Zero. Confirm at the byte level, so you are not trusting one tool:

```bash
# host
$ python3 -c "
d = open('out/full/classes.dex','rb').read()
print('Lkotlin/Metadata; present:', b'Lkotlin/Metadata;' in d)"
Lkotlin/Metadata; present: False
```

The string is not even in the DEX string table. The annotation is completely gone.

### Step 1.2 — The result that contradicts the common explanation

Now the compat build. Its rules file is the same baseline, and AGP's shipped `proguard-android-optimize.txt` contains `-keepattributes *Annotation*` — the directive everyone cites as the reason metadata survives. [`rules-compat`](../examples/rules-baseline.pro) in this experiment includes it too.

```bash
# host
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py out/compat/classes.dex --rewrite-check
verdict  : no-metadata
```

**Also zero.**

> **Question 1.** `-keepattributes *Annotation*` was present, and the annotation was still removed. Why? (Hint: think about what an "attribute" is, and what would have to be true for R8 to keep an *instance* of an annotation.)

> **Checkpoint 1.** You have measured that **R8 strips `kotlin.Metadata` by default in both full and compatibility mode**, and that `-keepattributes *Annotation*` alone does not prevent it. That is already a correction to the folklore, and you produced it yourself.

---

## Part 2 — When it survives: R8 rewrites it

Something must keep the annotation *type*. The rule that does it is in [`../examples/rules-keep-metadata.pro`](../examples/rules-keep-metadata.pro):

```proguard
-keepattributes RuntimeVisibleAnnotations
-keep class kotlin.Metadata { *; }
-keep,allowobfuscation class com.pentest.ch42.vault.** { *; }
```

This is not a contrived configuration. `-keep class kotlin.Metadata` appears in the consumer rules of several widely used libraries — anything using `kotlin-reflect`, and several JSON and dependency-injection libraries — so it lands in real apps without the developer ever typing it. And `-keep,allowobfuscation` is the standard pattern for "these classes must exist with all their members, but I don't care what they're called".

### Step 2.1 — Confirm the annotation survived

```bash
# host
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py out/meta2-compat/classes.dex --rewrite-check
classes  : 14 with @kotlin.Metadata
decoded  : 13
verdict  : rewritten
detail   : 82% of recovered simple names are 1-2 characters. R8 kept kotlin.Metadata
           and rewrote its payload to match the renamed program, so class, function
           and enum-entry names are NOT the originals. Kotlin PROPERTY names are
           rewritten far less reliably -- 18 were recovered here; read them with
           --members before concluding nothing leaked.
```

### Step 2.2 — See the rewriting

```bash
# host
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py out/meta2-compat/classes.dex --members
```

Look at the class and function lines:

```
com.pentest.ch42.vault.a   ->  com.pentest.ch42.vault.a   [k=1 class]
      fun    a [jvm a()Ljava/lang/String;]
      fun    b [jvm b()Lcom/pentest/ch42/vault/b;]
      fun    c [jvm c()J]
```

The class calls itself `a`. The functions call themselves `a`, `b`, `c`. **Nothing was recovered.** R8's metadata rewriter updated the payload to describe the renamed program.

If you stopped here you would conclude the technique does not work. Almost everyone does stop here.

### Step 2.3 — The part that did not get rewritten

Look at the **`val` lines** in the same output:

```
com.pentest.ch42.vault.a   ->  com.pentest.ch42.vault.a
      val    subscriberId    [field aLjava/lang/String;; getter g()Ljava/lang/String;]
      val    tier            [field bLcom/pentest/ch42/vault/b;; getter h()Lcom/pentest/ch42/vault/b;]
      val    expiryEpochDay  [field cJ; getter f()J]
com.pentest.ch42.vault.h   ->  com.pentest.ch42.vault.h
      val    hardwareId      [field aLjava/lang/String;]
      val    issuedRecords   [field bLjava/util/List;]
      val    auditTrail      [field cLjava/util/List;]
com.pentest.ch42.vault.e   ->  com.pentest.ch42.vault.e
      val    VAULT_FORMAT_VERSION  [field VAULT_FORMAT_VERSIONI]
      val    PEPPER               [field PEPPERLjava/lang/String;]
```

Open [`../examples/LicenceVault.kt`](../examples/LicenceVault.kt) and compare. `subscriberId`, `tier`, `expiryEpochDay`, `hardwareId`, `issuedRecords`, `auditTrail`, `VAULT_FORMAT_VERSION`, `PEPPER` — **every one is the developer's original identifier**, in a build where the class is `a`, the fields are `a`/`b`/`c` and the getters are `f`/`g`/`h`.

And because the metadata records the JVM field and getter *beside* the Kotlin name, what you have recovered is not a word list. It is a **mapping table**:

| Kotlin property | JVM field | JVM getter |
|---|---|---|
| `subscriberId` | `a` | `g()` |
| `tier` | `b` | `h()` |
| `expiryEpochDay` | `c` | `f()` |

That is a fragment of `mapping.txt`, reconstructed from the APK alone, with no mapping file.

> **Checkpoint 2.** You have recovered original member names from a build you obfuscated yourself, and you can show which JVM member each corresponds to.

> **Question 2.** R8 rewrote `Function.name` but not `Property.name`. Both are Kotlin-level names in the same protobuf. Why would a compiler rewrite one and not the other? The answer is mechanical, not accidental — and getting it right is what lets you predict this behaviour on toolchains you have not tested.

### Step 2.4 — Verify against the mapping file

You have the ground truth: R8 wrote a `mapping.txt` for this build.

```bash
# host
$ python3 -B 42-R8/scripts/mapping-reader.py out/meta2-compat/mapping.txt reverse subscriberId
```

Confirm that the JVM field the metadata named (`a`) is the one the mapping says `subscriberId` became. When they agree, your recovery is verified — and you have demonstrated that the metadata channel yields, for properties, the same information a leaked mapping file would.

---

## Part 3 — Understand the decoder

You have been running a script. Now understand it, because on real targets it will hit cases the toy build does not produce.

### Step 3.1 — The two `d1` encodings

The payload is not base64. It is one of two schemes, and the **first code unit of `d1[0]` tells you which** ([§3.10.1](../README.md#3101-what-the-annotation-is-mechanically)):

| First code unit | Mode | Decode |
|---|---|---|
| `U+0000` | Modern default | Drop the marker, take the low byte of every code unit |
| `U+FFFF` | Legacy 8-to-7 | Drop the marker, add `0x7F` mod `0x7F` to every byte, unpack 7 bits into 8 |

Both are implemented in the script, ported from Kotlin's `BitEncoding.java` and `utfEncoding.kt` rather than guessed.

> **The trap that defeats most hand-rolled decoders**
> DEX strings are **Modified UTF-8**: U+0000 is encoded as the two bytes `C0 80`, and a raw `00` byte terminates the string. The modern `d1` encoding stores arbitrary payload bytes `0x00`–`0xFF` as individual UTF-16 code units, and the payload *begins* with U+0000. Decode DEX strings with a standard UTF-8 library and you destroy exactly the bytes carrying the protobuf — usually failing on the first class. The script decodes to **code units**, not to a Python `str`, for this reason.

### Step 3.2 — What is inside once decoded

```
[varint length][JvmProtoBuf.StringTableTypes][ProtoBuf.Class or ProtoBuf.Package]
```

That layout is exactly what Kotlin's `JvmProtoBufUtil.readClassDataFrom` reads. The field numbers that matter:

| Message | Field | Number |
|---|---|---|
| `Class` | `fq_name` | 3 |
| `Class` | `function` / `property` / `constructor` | 9 / 10 / 8 |
| `Function` | `name` | 2 |
| `Property` | `name` | 2 |
| `Function` (jvm ext) | `method_signature` | 100 |
| `Property` (jvm ext) | `property_signature` | 100 |

Names are **indices**, resolved through `StringTableTypes` records — which may substitute a predefined string from a fixed 44-entry list, apply a substring, replace a character, or normalise a class id. Miss any of that and names come back subtly wrong (`Lcom/foo/Bar$Baz;` instead of `com.foo.Bar.Baz`) in a way that looks like success.

### Step 3.3 — Verify the decoder on known ground truth

The `kotlin.Metadata` annotation class is itself a Kotlin class carrying its own metadata, and its property names are published:

```bash
# host
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py out/meta2-compat/classes.dex \
    --members --filter kotlin.Metadata
kotlin.Metadata  ->  kotlin.Metadata   [k=1 class]
      val    bytecodeVersion   [getter bv()[I]
      val    data1             [getter d1()[Ljava/lang/String;]
      val    data2             [getter d2()[Ljava/lang/String;]
      val    extraInt          [getter xi()I]
      val    extraString       [getter xs()Ljava/lang/String;]
      val    kind              [getter k()I]
      val    metadataVersion   [getter mv()[I]
      val    packageName       [getter pn()Ljava/lang/String;]
```

The Kotlin property is `data1`; the JVM getter is `d1()`. That is a correct decode against known ground truth, and it is the cleanest possible illustration of why Kotlin names and JVM names are different things.

> **Checkpoint 3.** You can explain the decode path end to end: DEX annotation → `d1` string array → code units → BitEncoding → length-delimited `StringTableTypes` → `ProtoBuf.Class` → name indices → resolved strings.

### Step 3.4 — Look at the raw string table

`d2` is plaintext, and [05-Kotlin §8.3](../../05-Kotlin/README.md) shows a `grep` that dumps it. Compare that crude approach with the decoded one:

```bash
# host
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py out/meta2-compat/classes.dex \
    --raw-d2 --filter kotlin.text 2>/dev/null | head -30
```

> **Question 3.** `d2` contains the original names as plain strings, so why decode `d1` at all? Give two things the decode gives you that a `d2` dump does not.

---

## Part 4 — The wild: how often does this actually work?

The toy build proves the mechanism. It says nothing about frequency. Measure that.

### Step 4.1 — Assemble a corpus

Pull whatever real APKs you can. Unrooted `adb` is enough:

```bash
# host
$ mkdir -p corpus
# The `< /dev/null` on every adb call inside the loop is load-bearing: adb
# inherits the loop's stdin and consumes the rest of the package list, so
# without it this pulls ONE apk of N and exits 0, looking like success.
$ adb shell pm list packages -3 | sed 's/package://' | while read p; do
    path=$(adb shell pm path "$p" < /dev/null | head -1 | tr -d '\r' | sed 's/package://')
    [ -n "$path" ] && adb pull "$path" "corpus/$p.apk" < /dev/null >/dev/null 2>&1 && echo "pulled $p"
  done
$ ls -la corpus/
```

### Step 4.2 — Run the census

```bash
# host
$ for f in corpus/*.apk; do
    printf '%-44s ' "$(basename "$f")"
    python3 -B 42-R8/scripts/kotlin-metadata-recover.py "$f" --rewrite-check 2>/dev/null \
      | awk '/^classes/{c=$3} /^verdict/{v=$3} END{printf "meta=%-6s %s\n", c+0, v}'
  done
```

### Step 4.3 — Compare with the chapter's measurement

The chapter ran exactly this over **19 APKs, 316,000+ classes**:

| Metadata state | APKs | Notes |
|---|---|---|
| No `@kotlin.Metadata` at all | **10** | Includes every one of the largest, most heavily obfuscated apps |
| Annotation present, payload **empty** | **1** | 1,393 empty shells |
| Present and decodable | **8** | But mostly on classes that were never renamed |
| **Wholesale recovery of an app's own renamed classes** | **0** | Not one app |

> **Question 4.** Ten of nineteen apps had no metadata at all. Does that contradict "R8 does not remove it by default"? State the most defensible version of the claim, given both this measurement and your Part 1 result.

### Step 4.4 — The fourth state: the empty shell

One corpus app produced something the toy build never does:

```bash
# host
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py corpus/<that-app>.apk --rewrite-check
classes  : 1393 with @kotlin.Metadata
decoded  : 0
verdict  : payload-stripped
detail   : 1393 classes carry an @kotlin.Metadata annotation whose elements are ALL
           absent -- no k, no d1, no d2. The annotation is a marker only. Grepping
           for 'Lkotlin/Metadata;' would have called this a leak; it is not one.
```

The annotation is present; every element is gone.

> **This is why `grep` is the wrong instrument.**
> Both [40-Obfuscation §8.2](../../40-Obfuscation/README.md) and common practice suggest `grep -rn 'Lkotlin/Metadata;' smali*/` as the detection. On this app that returns 1,393 hits and **every one is a false positive**. A string in the DEX string table proves a *reference* exists somewhere; it says nothing about whether any class carries the annotation with data. Parse the structure.

### Step 4.5 — Extract what actually leaks

On an app whose verdict is `intact` or `rewritten`, pull the property-name leaks specifically — classes that R8 renamed but whose Kotlin property names survived:

```bash
# host
$ python3 -B 42-R8/scripts/kotlin-metadata-recover.py corpus/<app>.apk --json 2>/dev/null \
  | python3 -c "
import json, sys, re
d = json.load(sys.stdin)
for c in d['classes']:
    simple = c['renamed_name'].rsplit('.',1)[-1].split('\$')[0]
    if len(simple) > 3:          # class was NOT renamed; nothing recovered
        continue
    for p in c.get('properties') or []:
        g = p.get('getter') or p.get('field') or ''
        jn = re.match(r'[^(\[L;]*', g).group()
        if len(p['name']) > 3 and jn and len(jn) <= 3:
            print('%-34s %s -> %s' % (c['renamed_name'], jn, p['name']))
"
```

In the chapter's corpus, the app with the most surviving metadata gave **87 property-name and 24 function-name recoveries** across 132 renamed classes — out of 5,315 renamed classes total. Real, useful, and nothing like "wholesale". Representative output:

```
kotlin.text.d                       a  -> value
kotlin.comparisons.f                a  -> comparator
kotlin.coroutines.jvm.internal.a$a  a  -> getModuleMethod
kotlin.coroutines.jvm.internal.a$a  b  -> getDescriptorMethod
kotlin.coroutines.jvm.internal.a$a  c  -> nameMethod
```

> **Question 5.** Every recovery above is in `kotlin-stdlib` or coroutines internals, not the app's own code. Is the technique therefore useless for understanding the app? Argue both ways, then commit to an answer.

---

## Part 5 — Write it up honestly

### Step 5.1 — Classify your target

| Verdict | What to write |
|---|---|
| `no-metadata` | No finding. R8's default behaviour removed the annotation |
| `payload-stripped` | No finding, but **record it**, so the next tester does not report the `grep` hits |
| `rewritten` | Check property names before concluding. If they leak, low-severity disclosure |
| `intact` + class names obfuscated | Genuine disclosure. Severity by what the names describe |
| `intact` + class names not obfuscated | The app was not name-obfuscated; that is the finding, not the metadata |

### Step 5.2 — The severity argument

From [§5.7](../README.md#57-severity-a-rubric-you-can-defend), metadata leakage is **Informational to Low** by default. It moves up when the recovered names describe security-relevant logic — `pinRetryCount`, `isRootedDevice`, `licenceKey`, `biometricFallbackEnabled` — because then the disclosure is not "some identifiers" but "a map of the client-side security controls". It stays at Informational when everything recovered is third-party library internals, which is the common case.

**Do not report it as "obfuscation is broken".** Report it as: *the app applies identifier renaming, and a subset of original member names remains recoverable from Kotlin metadata retained for reflection.* That is accurate, actionable, and survives a developer's pushback.

### Step 5.3 — The remediation, as code

```proguard
# Option 1 -- if the app does NOT use kotlin-reflect or any library that reads
# @Metadata at runtime. -checkdiscard makes the build FAIL if something keeps it,
# so the assumption is enforced rather than assumed.
-checkdiscard class kotlin.Metadata

# Option 2 -- if metadata IS needed (Moshi, kotlinx.serialization, Retrofit's
# Kotlin support, anything calling kotlin-reflect), you cannot remove it.
# Narrow WHERE it is needed instead of keeping it globally, and accept the
# residual property-name disclosure on those classes.
```

> **Do not recommend `-checkdiscard` blindly.** Removing metadata from an app that uses Kotlin reflection causes runtime failures that are hard to attribute — `KotlinReflectionInternalError`, or a JSON library silently failing to map a field. The correct recommendation is *"verify whether reflection is used; if not, discard it and enforce that with `-checkdiscard`"*, and the verification is the developer's to do.

---

## Success criteria

- [ ] Build the same Kotlin source with and without `kotlin.Metadata` kept, and predict the outcome of each before running the check.
- [ ] Explain why `-keepattributes *Annotation*` does not preserve the annotation on its own.
- [ ] Name the four distinct states of metadata in an R8 build, and give the detection for each.
- [ ] Recover original Kotlin property names from a build you obfuscated yourself.
- [ ] Explain mechanically why property names survive rewriting when function names do not.
- [ ] Pair a recovered Kotlin property name with its renamed JVM field and getter, and verify against `mapping.txt`.
- [ ] Describe the `d1` decode path end to end, and name the encoding marker that selects between the two schemes.
- [ ] Explain why MUTF-8 defeats a naive decoder.
- [ ] State why `grep 'Lkotlin/Metadata;'` is not a valid test, with the empty-shell case as evidence.
- [ ] Write a severity-appropriate finding, and the remediation, without overstating the impact.

---

## Answers

<details>
<summary>Question 1 — why -keepattributes did not help</summary>

`-keepattributes` controls whether *attributes* are carried through to the output — here, the `RuntimeVisibleAnnotations` attribute that holds annotation instances. It does not create a reason for the **annotation type** to exist.

`kotlin.Metadata` is an ordinary class. In the baseline build nothing reachable references it — the program never calls Kotlin reflection — so the Enqueuer never marks it live and the shrinker deletes it. An annotation whose type does not exist in the output cannot be retained on anything, so R8 drops the instances too.

Keeping the attribute is **necessary but not sufficient**. Something must also keep the type, which is what `-keep class kotlin.Metadata { *; }` does. This is why the annotation survives in real apps: some library's consumer rules keep the type, not because the app author asked for it.
</details>

<details>
<summary>Question 2 — why properties survive rewriting</summary>

Because R8 renames **JVM members**, and a Kotlin property is not one.

A Kotlin *function* corresponds one-to-one with a JVM method. When R8 renames that method to `a`, it knows the new name and can write it into the metadata's `Function.name`, keeping the record consistent.

A Kotlin *property* is a Kotlin-level construct backed by up to three separate JVM members — a backing field, a getter and a setter — each renamed independently. There is no single new JVM name that `Property.name` could be set to. So R8 updates what it *does* have mappings for — the `JvmPropertySignature` extension recording the field, getter and setter — and leaves the Kotlin-level `Property.name` untouched.

The same reasoning predicts the behaviour of the other elements you observed: enum entry names and companion object names *are* rewritten, because each corresponds to a JVM field R8 renamed.

This is why the finding generalises. It is not a bug in one R8 version; it follows from what a rename mapping can express.
</details>

<details>
<summary>Question 3 — why decode d1 when d2 is plaintext</summary>

Two things the decode gives you that a `d2` dump cannot:

1. **Association.** `d2` is an unordered bag of strings for one class. It might contain `subscriberId`, `a`, `g`, `getTier` and thirty type descriptors, with no indication of which belongs to which. Decoding `d1` tells you `subscriberId` is a *property*, backed by *field `a`*, read by *getter `g()`* — which is the difference between a word list and a mapping table.

2. **Structure and kind.** The decode tells you what each name *is*: class versus function versus property versus enum entry versus constructor, plus `k`, the companion name, the module name, sealed subclasses and nested classes. A `d2` dump gives you strings with no types.

A third, practical one: `d2` also contains type descriptors, internal markers and library names, so a raw dump has a poor signal-to-noise ratio. The decode filters to declarations.

`d2` grepping is a good ten-second triage — which is exactly how [05-Kotlin](../../05-Kotlin/README.md) presents it. The decode is what you do when the answer matters.
</details>

<details>
<summary>Question 4 — the defensible version of the claim</summary>

It does not contradict it so much as show the claim was never precise enough to be tested.

Your Part 1 result is decisive for the *default*: with ordinary rules, in both full and compat mode, R8 **removes** the annotation. So "R8 does not remove it by default" is false as stated.

The corpus result explains why the folklore exists anyway: metadata survives whenever *something* keeps the type, and that happens often in real apps because library consumer rules do it. Eight of nineteen apps had decodable metadata.

The defensible version, combining both:

> *`kotlin.Metadata` is stripped by R8's default configuration, but is preserved whenever any dependency's consumer rules keep `kotlin.Metadata` — which is common. When preserved on a class R8 renamed, R8 rewrites the class, function and enum-entry names but frequently leaves Kotlin **property** names intact, yielding a member-level mapping table. Wholesale recovery of an app's own class names was not observed in a 19-app corpus.*

The general lesson: claims of the form "tool X does not do Y by default" age badly, because defaults change and "by default" hides a configuration space. Mechanistic claims — *R8 can only rewrite what it has a rename mapping for* — stay true.
</details>

<details>
<summary>Question 5 — is library-only recovery useless?</summary>

**Against:** you did not learn one thing about the app's business logic. Knowing `kotlin.text.l` is `StringsKt` tells you nothing about how licences are validated. If the goal is understanding the app, this contributed nothing directly.

**For:** triage is mostly *elimination*. An obfuscated APK presents thousands of identical-looking classes and the expensive question is which to read. Every class you can confidently label "this is `kotlin-stdlib`" or "this is coroutines internals" is a class you never open. Recovering hundreds of library class names shrinks the search space substantially, and it does so with no mapping file and no dynamic analysis.

There is also a second-order benefit: it reveals *which* libraries the app bundles even after repackaging, which feeds dependency and supply-chain analysis.

**Commit:** the technique is genuinely useful, and it is useful for **orientation rather than comprehension**. Presenting it as "recover the original names" oversells it; presenting it as "cheaply eliminate the two-thirds of the binary that is library code, and occasionally recover a business-logic property name" is accurate. Where it does hit application code — as with the `zzd -> ClientIdentity` recovery in [§9](../README.md#9-examples) Example 4 — it is a direct hit, and it costs one command to check.
</details>

---

## Where to go next

- [Lab 04 — CTF](lab-04-ctf-the-leaked-key.md) puts this together with everything else.
- [05-Kotlin §7.5](../../05-Kotlin/README.md) has a Frida script that dumps metadata from *loaded* classes, reaching code that static analysis of the base APK never sees.
- [56-JADX §3.13](../../56-JADX/README.md) shows jadx's `kotlin-metadata` plugin, which applies this recovery automatically during decompilation.
