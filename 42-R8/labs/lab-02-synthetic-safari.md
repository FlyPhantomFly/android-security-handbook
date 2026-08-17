# Lab 02 — Synthetic safari

> **Objective.** Take a real, obfuscated APK and identify every category of compiler-generated construct in it. Extract the original developer-chosen names that those constructs leak, date the toolchain that built the app, and produce a defensible measurement of how much of the app is actually obfuscated.

**Difficulty:** Intermediate
**Time:** 90–120 minutes
**Root required:** No
**Device required:** Optional — helpful for sourcing an APK, not needed otherwise
**Chapter sections:** [§3.8](../README.md#38-synthetic-members-the-complete-naming-vocabulary), [§6.1](../README.md#61-recognising-an-r8-build-in-ten-seconds), [§8.4](../README.md#84-measuring-how-much-of-the-app-is-actually-obfuscated)

---

## Why this lab exists

There is a moment early in every APK analysis where you open the decompiled tree, see a few thousand classes called `a`, `b`, `c` and `p001a.b.c`, and have to decide where to spend the next four hours. Most people decide badly, because they treat all those classes as equivalent.

They are not. In a typical R8 build, **more than half the classes were written by a compiler, not by a person.** They implement lambdas, bridge access to private members, hold `when`-mapping tables, or replace an enum. Reading them as if they were design is a straightforward waste of time — and worse, it produces confident nonsense in reports ("the app implements a custom comparator hierarchy" when the app called `sortedBy`).

Meanwhile, those same compiler-generated classes are the richest surviving source of **original names** in an obfuscated app, because their names were *constructed* from real identifiers before the minifier ran. Learning to read them is simultaneously the fastest way to discard noise and the cheapest way to recover signal.

This lab makes both skills concrete on a real binary.

---

## Setup

### Getting a target APK

You need one real, obfuscated, Kotlin-containing APK. Any of these work:

**Option A — pull one from a device.** No root needed; a third-party `base.apk` is world-readable because the runtime must map it into every process.

```bash
# host
$ adb devices -l
$ adb shell pm list packages -3            # third-party packages
$ adb shell pm path com.example.target
package:/data/app/~~<hash>/com.example.target-<hash>/base.apk
$ adb pull /data/app/~~<hash>/com.example.target-<hash>/base.apk ./target.apk
```

> **⚠️ Record your device before you trust any version-dependent result.**
> ```bash
> $ adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk
> ```
> The device used to source the corpus for this chapter was an **`i9000S`, Android 13, API 33, unrooted, no `frida-server`**. Nothing in this lab needs root, but write down what you used.

**Option B — use a deliberately vulnerable app.** Any of the standard training APKs that are written in Kotlin and built with R8.

**Option C — build one.** Lab 01's `meta2-compat` build is a small but genuine R8 output, and every technique below works on it.

### Tools

| Tool | Needed for | Check |
|---|---|---|
| Android SDK build-tools | `ExtractMarker`, `dexdump` | `ls $ANDROID_HOME/build-tools/*/lib/d8.jar` |
| Python 3.8+ | The chapter's scripts | `python3 --version` |
| `unzip` | Reading the APK | `unzip -v` |
| jadx *(optional)* | Cross-checking visually | `jadx --version` |

---

## Part 1 — Date the build

Before looking at a single class, establish what built this APK. Everything downstream depends on it, because **synthetic naming schemes changed between D8/R8 versions** ([§3.8](../README.md#38-synthetic-members-the-complete-naming-vocabulary)).

### Step 1.1 — Read the compiler marker

```bash
# host
$ SDK="${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}"
$ D8="$SDK/build-tools/35.0.1/lib/d8.jar"
$ java -cp "$D8" com.android.tools.r8.ExtractMarker target.apk
```

Typical output:

```
~D8{"backend":"dex","compilation-mode":"release","min-api":24,"version":"8.2.47"}
~R8{"backend":"dex","compilation-mode":"release","min-api":24,"pg-map-id":"3f8a1c2","version":"8.2.47"}
```

| Field | Meaning |
|---|---|
| `~R8{...}` present | R8 ran: shrinking, optimisation and renaming were applied |
| **`~D8{...}` only, no `~R8`** | Dexed but **not minified**. This answers "is the app obfuscated" outright |
| `compilation-mode` | `release` or `debug` |
| `min-api` | How much desugaring happened. Below 26, all lambdas are desugared |
| `version` | The exact toolchain — use it to interpret naming schemes |
| `pg-map-id` | Links this build to a specific `mapping.txt`, if one ever surfaces |

> **✅ Checkpoint 1.** You can state whether the app was minified at all, and with which R8 version, in under thirty seconds and without decompiling anything.

> **Question 1.** Suppose `ExtractMarker` prints nothing at all. List three different explanations, and say how you would distinguish them.

### Step 1.2 — Record it

Start a findings file. You will fill it in as you go.

```
TARGET      : target.apk   sha256 <...>
COMPILER    : R8 <version>  /  D8 only  /  neither
MIN-API     : <n>
MODE        : release / debug
PG-MAP-ID   : <present?>
```

---

## Part 2 — The safari: find every species

Now hunt the synthetic constructs. For each one, the drill is the same: **find it, name its species, and extract the original identifier it leaks.**

### Step 2.1 — Build a class inventory

```bash
# host — dump every class descriptor from every DEX
$ python3 -B - <<'PY' > classes.txt
import importlib.util, sys
spec = importlib.util.spec_from_file_location("kmr", "42-R8/scripts/kotlin-metadata-recover.py")
kmr = importlib.util.module_from_spec(spec); spec.loader.exec_module(kmr)
for dex in kmr.load_dexes("target.apk"):
    for cd in dex.class_defs():
        print(dex.type_name(cd["class_idx"]))
PY
$ wc -l classes.txt
```

Reusing the chapter's DEX parser avoids needing `baksmali` and works identically on multi-DEX apps.

### Step 2.2 — Census by species

```bash
# host
$ for pat in 'ExternalSyntheticLambda' 'InternalSyntheticLambda' '\$r8\$lambda\$' \
             'Nest\$' 'EnumUnboxingSharedUtility' 'WhenMappings' \
             'Companion' 'DefaultImpls' 'ExternalSyntheticApiModelOutline' \
             'ExternalSyntheticBackport' 'ExternalSyntheticOutline'; do
    printf '%-38s %s\n' "$pat" "$(grep -c "$pat" classes.txt)"
  done
$ echo "TOTAL $(wc -l < classes.txt)"
```

Record the numbers. A representative shape from a real mid-sized Kotlin app:

| Species | Typical count | Generated by |
|---|---|---|
| `$$ExternalSyntheticLambda<n>` | hundreds to thousands | D8/R8 desugaring |
| `$$InternalSyntheticLambda$<n>$<hash>$<m>` | tens to hundreds | D8/R8 desugaring |
| `$$ExternalSyntheticOutline<n>` | tens to hundreds | R8 outlining |
| `$$ExternalSyntheticApiModelOutline<n>` | tens | R8 API-model outlining |
| `$$ExternalSyntheticBackport<n>` | a few | R8 backporting a newer JDK method |
| `$EnumUnboxingSharedUtility` | 0 to a few | R8 enum unboxing |
| `$WhenMappings` | tens | kotlinc, `when` over an enum |
| `$Companion`, `$DefaultImpls` | tens to hundreds | kotlinc |

> **✅ Checkpoint 2.** Add up the synthetic counts and divide by the total. If it is above 40%, you have just discovered that most of what you were about to read is not code anyone wrote.

> **Question 2.** `$$ExternalSyntheticOutline0` and `$$ExternalSyntheticLambda0` are both R8 output, but they mean opposite things about the original code. Explain the difference, and say what each tells you about the source.

### Step 2.3 — Harvest the leaked names

This is the payoff. Every `$$`-suffixed name was **constructed** by concatenating a real identifier with a scheme suffix — so the part to the left of the marker is a developer-chosen name that survived obfuscation.

```bash
# host — recover the original enclosing class names from desugared lambdas
$ grep -oE 'L[^;]*\$\$(External|Internal)SyntheticLambda' classes.txt \
  | sed -E 's/^L//; s/\$\$(External|Internal)SyntheticLambda$//' \
  | tr '/' '.' | sort -u > leaked-class-names.txt
$ wc -l leaked-class-names.txt
$ head -25 leaked-class-names.txt
```

In a heavily obfuscated app, most results will be short (`a.b.c`) — the enclosing class was itself renamed. **The interesting ones are the long ones**, which are classes a keep rule exempted:

```bash
# host — keep only names that were NOT renamed
$ awk -F. '{ n=$NF; sub(/\$.*/,"",n); if (length(n) > 3) print }' leaked-class-names.txt
```

Do the same for enum unboxing, which discloses the original enum type name outright:

```bash
# host
$ grep -oE 'L[^;]*\$EnumUnboxingSharedUtility' classes.txt \
  | sed -E 's/^L//; s/\$EnumUnboxingSharedUtility$//' | tr '/' '.' | sort -u
```

And for nestmate bridges, which disclose **both** the owner class and the private member name:

```bash
# host — $$Nest$mFoo means "private method Foo"; $$Nest$fBar means "private field Bar"
$ grep -oE '\$\$Nest\$[mf][A-Za-z0-9_]+' classes.txt | sort -u
```

> **Question 3.** Why would `$$Nest$mDecryptToken` be a more valuable find than `$$ExternalSyntheticLambda3` on the same class? What does each actually tell you?

### Step 2.4 — The `$$InternalSyntheticLambda` hash

These names contain a 64-hex-character content hash:

```
Foo$$InternalSyntheticLambda$1$1b5c58694e2ad21a64a0e1586651874577a7fec664bc478afa19ff3d47a646a4$1
```

That hash is derived from the lambda's *content*, which makes it one of the very few identifiers in an R8 build that is **stable across builds** — R8's ordinary names are not ([§3.6](../README.md#36-the-minifiers-naming-scheme)).

```bash
# host — extract the hashes as cross-version anchors
$ grep -oE '\$\$InternalSyntheticLambda\$[0-9]+\$[0-9a-f]{64}\$[0-9]+' classes.txt \
  | grep -oE '[0-9a-f]{64}' | sort -u > lambda-hashes.txt
$ wc -l lambda-hashes.txt
```

> **✅ Checkpoint 3.** You have a set of build-stable identifiers. If you ever analyse a second version of this app, intersecting these two sets tells you which lambdas are unchanged — a structural diff that survives the rename churn that makes name-based diffing useless.

---

## Part 3 — Measure the obfuscation honestly

Now produce the number that belongs in a report.

### Step 3.1 — Find the app's own package

```bash
# host
$ unzip -p target.apk AndroidManifest.xml | strings -a | grep -m1 -oE '[a-z][a-z0-9_]*(\.[a-z0-9_]+){2,}'
# or, more reliably:
$ adb shell pm list packages -3
```

The application ID is not always the code's root package, so sanity-check it against `classes.txt`.

### Step 3.2 — Measure that package specifically

```bash
# host
$ python3 -B - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("kmr", "42-R8/scripts/kotlin-metadata-recover.py")
kmr = importlib.util.module_from_spec(spec); spec.loader.exec_module(kmr)

APK = "target.apk"
PKG = "com/example/target"      # <-- edit me

short = total = 0
for dex in kmr.load_dexes(APK):
    for cd in dex.class_defs():
        d = dex.type_name(cd["class_idx"])
        if not d.startswith("L" + PKG):
            continue
        simple = d[1:-1].rsplit("/", 1)[-1].split("$")[0]
        total += 1
        if len(simple) <= 3:
            short += 1
print("classes in %s : %d" % (PKG, total))
print("short-named       : %d (%.1f%%)" % (short, 100.0*short/total if total else 0.0))
PY
```

Interpretation:

| Short-name proportion | Reading |
|---|---|
| > 80% | Obfuscation applied and effective |
| 20–80% | Partial — some packages exempted. Find out which, and why |
| < 20%, `~R8` marker present | **Finding.** Shrinking ran; renaming was neutered by over-broad keep rules |
| < 20%, no `~R8` marker | `minifyEnabled false`. Informational |

> **⚠️ Why measuring the whole APK is wrong**
> Dependencies are obfuscated by the app's own R8 run regardless of what the app exempts for itself. A whole-APK average is dominated by AndroidX and `kotlin-stdlib` and will report "well obfuscated" for an app that exempted every one of its own classes with `-keep class com.app.** { *; }`. That exact configuration is the most common way an app ends up unobfuscated while its build file claims otherwise ([§5.4](../README.md#54-how-developers-get-this-wrong)).

> **Question 4.** Your measurement returns 41%. Before writing anything down, what would you check next, and why is 41% on its own uninterpretable?

### Step 3.3 — Cross-check the heuristic

The `<= 3` threshold is a heuristic. Two checks make it defensible:

```bash
# host — 1. Is the length distribution BIMODAL? Real codebases are not.
$ sed -E 's/^L//; s/;$//' classes.txt | sed -E 's/.*\///; s/\$.*//' \
  | awk '{ print length($0) }' | sort -n | uniq -c | head -20

# host — 2. Are simple names REUSED across packages? Real codebases rarely do this.
$ sed -E 's/^L//; s/;$//' classes.txt | sed -E 's/.*\///; s/\$.*//' \
  | sort | uniq -c | sort -rn | head -10
```

An obfuscated build shows a large spike at lengths 1–2 and hundreds of packages each containing a class called `a`. A genuinely short-named real codebase shows neither.

> **⚠️ The `-obfuscationdictionary` case**
> Some builds rename into plausible-looking English words rather than `a`, `b`, `c`. Name *length* then tells you nothing. The reuse check still works — a dictionary-renamed build reuses the same small vocabulary across unrelated packages — and so does the semantic check: do the names have any relationship to what the classes do?

---

## Part 4 — Sort the wheat from the chaff

Turn the census into a triage plan.

### Step 4.1 — Build the "probably authored" list

```bash
# host — everything that is NOT obviously compiler output
$ grep -vE '\$\$(External|Internal)Synthetic|\$r8\$lambda\$|\$\$Nest\$|EnumUnboxingSharedUtility|\$WhenMappings|\$DefaultImpls' classes.txt \
  | grep "^Lcom/example/target" > authored-candidates.txt
$ wc -l authored-candidates.txt
```

Compare that with the raw class count for the package. The gap is how much reading you just avoided.

### Step 4.2 — Confirm with the synthetic access flag

Name-based filtering is a heuristic; `ACC_SYNTHETIC` is authoritative ([12-DEX-Internals §3.23](../../12-DEX-Internals/README.md)). Bit `0x1000`:

```bash
# host
$ python3 -B - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("kmr", "42-R8/scripts/kotlin-metadata-recover.py")
kmr = importlib.util.module_from_spec(spec); spec.loader.exec_module(kmr)
ACC_SYNTHETIC = 0x1000
syn = tot = 0
for dex in kmr.load_dexes("target.apk"):
    for cd in dex.class_defs():
        tot += 1
        if cd["access_flags"] & ACC_SYNTHETIC:
            syn += 1
print("classes: %d, ACC_SYNTHETIC: %d (%.1f%%)" % (syn and tot or tot, syn, 100.0*syn/tot))
PY
```

> **Question 5.** The `ACC_SYNTHETIC` count will usually be **lower** than your name-based synthetic count. That is not a contradiction. Why not? (Consider `$Companion` and `$WhenMappings`.)

### Step 4.3 — Find the entry points that had to keep their names

Some names R8 cannot touch, and they are where you start reading:

```bash
# host — manifest components must match their declared names
$ unzip -p target.apk AndroidManifest.xml | strings -a \
  | grep -oE '[a-zA-Z][a-zA-Z0-9_.]*\.(Activity|Service|Receiver|Provider)[A-Za-z0-9_]*' | sort -u

# host — JNI symbols encode the Java package, class and method name
$ unzip -o target.apk 'lib/*/*.so' -d ./libs >/dev/null 2>&1
$ strings -a libs/lib/*/*.so 2>/dev/null | grep -E '^Java_[A-Za-z0-9_]+' | sort -u | head -20
```

> **✅ Checkpoint 4.** You now have three independent lists: compiler-generated classes to ignore, authored classes to read, and unrenameable entry points to start from. That is a triage plan, and it took under an hour without decompiling anything.

---

## Part 5 — Cross-check in a decompiler (optional)

If you have jadx, confirm two of your findings visually. [56-JADX §6.1](../../56-JADX/README.md) owns the artefact table; the point here is only to see your census in context.

```bash
# host
$ jadx -d out-jadx target.apk 2>/dev/null
$ grep -rl 'ExternalSyntheticLambda' out-jadx/sources | head -5
```

Open one. You should see a small class implementing a framework interface with a single captured field, exactly as [§6.3](../README.md#63-a-smali-reading-of-an-r8-synthetic-lambda) describes. jadx marks the members it recognises with `/* synthetic */` comments.

---

## Part 6 — Write it up

Fill in your findings file:

```
TARGET        : target.apk   sha256 <...>
COMPILER      : R8 <version>, min-api <n>, release
PG-MAP-ID     : <present / absent>
CLASSES TOTAL : <n>
  synthetic by name  : <n>  (<pct>%)
  synthetic by flag  : <n>  (<pct>%)
APP PACKAGE   : com.example.target
  classes            : <n>
  short-named        : <n>  (<pct>%)
  distribution       : bimodal / not
  simple-name reuse  : <max count>
LEAKED NAMES  :
  via $$ExternalSyntheticLambda : <n> unrenamed enclosing classes
  via $EnumUnboxingSharedUtility: <list>
  via $$Nest$m / $$Nest$f       : <list>
STABLE ANCHORS: <n> $$InternalSyntheticLambda content hashes
```

**The severity discipline** from [§5.7](../README.md#57-severity-a-rubric-you-can-defend): if the short-name proportion is high, there is **no finding here** — obfuscation is present and working, and that is a hardening control functioning as intended. If it is low despite an `~R8` marker, the finding is *"obfuscation is configured but not effective, because keep rules exempt the application's own code"*, and it is **Low** unless what it exposes is itself sensitive.

Do not report leaked synthetic names as a finding on their own. They are a fact about how compilers work, not a vendor mistake, and there is no remediation a developer could apply.

---

## Success criteria

- [ ] Determine, in under a minute and without decompiling, whether an APK was processed by R8, and with which version.
- [ ] Explain what a `~D8` marker with no `~R8` marker means.
- [ ] Name at least six distinct synthetic naming schemes and say which tool generates each.
- [ ] Extract original class names from `$$ExternalSyntheticLambda` names.
- [ ] Extract an original enum type name from an `EnumUnboxingSharedUtility` class.
- [ ] Extract an original private member name from a `$$Nest$` bridge or a Kotlin `access$` bridge.
- [ ] Explain why `$$InternalSyntheticLambda` hashes are stable across builds when ordinary R8 names are not.
- [ ] Measure the obfuscated proportion of an app's *own* package and justify why the whole-APK figure is misleading.
- [ ] Give two cross-checks that defend the name-length heuristic, and one case that defeats it.
- [ ] State why leaked synthetic names are not, by themselves, a reportable finding.

---

## Answers

<details>
<summary>Question 1 — ExtractMarker prints nothing</summary>

Three explanations, distinguishable:

1. **The DEX was not produced by D8/R8 at all** — built with `dx`, with a third-party dexer, or assembled by a packer. Check the DEX version in the header and whether `string_ids` are sorted; [12-DEX-Internals §8.4](../../12-DEX-Internals/README.md) covers the structural tells.
2. **The markers were stripped post-build**, by a repackaging or protection tool. Suggestive if the APK also shows other post-processing signs, such as a stub `Application` class and an encrypted asset.
3. **The real code is not in `classes.dex`** — the visible DEX is a loader stub and the payload is decrypted at runtime. Check for large opaque assets and a small class count relative to app size.

Distinguish by looking at what *is* there: a tiny class count plus a big encrypted asset points at 3; a normal-looking app with no markers points at 2; an unusual DEX layout points at 1.
</details>

<details>
<summary>Question 2 — Outline versus Lambda</summary>

They are opposite optimisations ([§3.5](../README.md#35-outlining)):

- **`$$ExternalSyntheticLambda<n>`** is *desugaring*. The source had a lambda or method reference; DEX cannot express it as a call site (or R8 chose not to), so it became a class. It tells you **a lambda existed at that point in the named class**.
- **`$$ExternalSyntheticOutline<n>`** is *outlining*. The source had the same instruction sequence repeated in many places, and R8 extracted it into one method to save space. It tells you **nothing about a single source construct** — it is a fragment shared by many call sites, and it corresponds to no method anyone wrote.

Practical consequence: a lambda class is worth reading, because it maps to a specific piece of source. An outline is usually not, because its body is a fragment lifted out of context. Confusing the two leads to reports describing "a shared utility method" that no developer ever wrote.
</details>

<details>
<summary>Question 3 — Nest bridge versus lambda</summary>

`$$ExternalSyntheticLambda3` discloses only the **enclosing class name**, and even that is useful only if the class was not itself renamed. The `3` is a counter.

`$$Nest$mDecryptToken` discloses the **original name of a private method** — `decryptToken` — plus the fact that it is private and is accessed from a nested class. On an app where everything else is `a.b.c`, that is a semantic anchor: it names a security-relevant operation and tells you where to look. Kotlin's `access$<originalName>` bridges leak the same thing.

The general principle: schemes that embed a *member* name are far more valuable than schemes that embed only a *class* name, because member names describe behaviour.
</details>

<details>
<summary>Question 4 — 41% is uninterpretable</summary>

41% means some classes are renamed and some are not, which could arise from at least four very different situations:

1. A `-keep` rule exempting a specific subpackage — models, API DTOs, or anything reflected over by a JSON library.
2. A large body of generated code (Room, Dagger, data binding, view binding) kept by its own consumer rules.
3. The measurement's package prefix being wrong, so it is picking up a bundled third-party SDK.
4. Nested classes distorting the count, since `A$B` was split on `$` before measuring.

What to check next: **which** classes are in the un-renamed 59%. Group them by subpackage and look at the shape. If they are all `…model…`, `…dto…` or `…entity…`, it is case 1 and the reading is "the app exempts its data layer from obfuscation" — worth a sentence, not a finding. If they are the whole app, it is the over-broad-keep failure and worth reporting.

The number alone never goes in a report without the breakdown.
</details>

<details>
<summary>Question 5 — why ACC_SYNTHETIC is lower</summary>

Because `ACC_SYNTHETIC` means "not present in the source code", and several kotlinc-generated classes **are** considered part of the source-level program:

- `$Companion` is a real, declared Kotlin construct — the developer wrote `companion object`. It is a named type users can reference, so it is not synthetic.
- `$WhenMappings` and `$DefaultImpls` are generated, and whether the flag is set varies by construct and compiler version.
- Conversely, R8's own synthetics (`$$ExternalSyntheticLambda`, outlines) reliably carry the flag.

So the name-based census counts "things a compiler generated", while the flag counts "things marked as not user-visible". Both are useful; neither is a superset of the other. Use the flag when you need authority and the names when you need to know *which kind* of generated thing it is.
</details>

---

## Where to go next

- [Lab 03 — Recover original names from `kotlin.Metadata`](lab-03-metadata-recovery.md) attacks the same problem from a completely different direction, and recovers far more than names embedded in synthetic identifiers.
- [Lab 04 — CTF](lab-04-ctf-the-leaked-key.md) combines both.
- [40-Obfuscation §6.2](../../40-Obfuscation/README.md) has the technique-to-symptom table for obfuscation generally.
