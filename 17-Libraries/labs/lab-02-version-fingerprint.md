# Lab 02 — Version Fingerprinting Without Build Files

**Difficulty:** Intermediate
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-library-inventory.md),
[Chapter 17 §3](../README.md#3-deep-internal-working) — specifically §3.7, the six techniques —
[Chapter 17 §8](../README.md#8-static-analysis), `python3`, and network access to Maven Central.

---

## Objective

Determine the **exact version** of three bundled libraries in a stripped, obfuscated APK — one
managed library that reports itself, one managed library that does not, and one native library
statically linked inside a `.so` — and **defend each answer with evidence**.

The output of this lab is not three version numbers. It is three *arguments*, each of the form:

> Library **L** is version **V**, because signal **S** was observed at **artifact A**, corroborated
> by signal **T** at **artifact B**. This conclusion would be wrong if **X**, which I checked and
> ruled out because **Y**.

A version number without the signal that produced it is a guess wearing a suit.

---

## Why this matters

Chapter §3.7 opens with the sentence this lab exists to make true for you:

> "outdated OkHttp" is not a finding and "OkHttp 3.12.1, which predates the fix for the
> connection-reuse issue in 3.12.x, and here is the evidence" is.

Three concrete consequences of getting this wrong, in ascending order of career damage:

1. **You report a version that is not there.** The developer checks their `build.gradle`, finds a
   different number, and every other finding in your report is now suspect.
2. **You report a CVE that does not apply.** The vulnerable code path was stripped by R8, or the
   library is a shaded fork with the fix backported. The client spends a sprint on nothing.
3. **You report nothing, because you could not tell.** The vulnerable version was there and you had
   the evidence to find it.

There is also a defensive reason. When a scanner tells you "OkHttp 3.9.0 — CVE-XXXX", you must be
able to check it. Triangulation is how you check it, and it is how you know when the scanner is
wrong — which, on Android, it very often is (see [`../faq.md`](../faq.md)).

---

## Setup — build the target, then forget it

You need a target whose true answer exists but is not visible. Two ways:

**Option A (best).** A partner builds it and writes the versions on a piece of paper, face down.

**Option B (solo).** You build it, write the versions in a file, `sha256sum` that file, close it, and
do not open it until the end. The self-discipline is real and it works, provided you write the
answers down *before* you start analysing.

### Step 0.1 — a project with three known dependencies

Pick three real, currently published versions. **Look them up on Maven Central yourself and confirm
each artifact exists before you use it** — an invented coordinate wastes an hour later.

```groovy
// app/build.gradle — pick your own versions, then write them down and hide them
dependencies {
    implementation "com.squareup.okhttp3:okhttp:<version A>"   // reports itself in a string
    implementation "com.google.code.gson:gson:<version B>"     // reports nothing at all
}

android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),
                          'proguard-rules.pro'
        }
    }
    externalNativeBuild { cmake { path "src/main/cpp/CMakeLists.txt" } }
}
```

```properties
# gradle.properties — R8 full mode, so the obfuscation is realistic
android.enableR8.fullMode=true
```

Write some code that *uses* both libraries — a few calls each, not all of them. This matters: R8
removes what you do not call, so your APK will contain a subset of each library, which is exactly the
situation the lab is teaching you to reason about.

### Step 0.2 — a native library with a statically linked dependency

```c
/* app/src/main/cpp/core.c — a "cross-platform core" that carries its own zlib */
#include <jni.h>
#include <zlib.h>
#include <string.h>

JNIEXPORT jlong JNICALL
Java_com_liblab_fp_Core_crc(JNIEnv *env, jclass k, jbyteArray data) {
    (void) k;
    jsize n = (*env)->GetArrayLength(env, data);
    jbyte *p = (*env)->GetByteArrayElements(env, data, NULL);
    uLong c = crc32(0L, (const Bytef *) p, (uInt) n);
    (*env)->ReleaseByteArrayElements(env, data, p, JNI_ABORT);
    return (jlong) c;
}
```

```cmake
# app/src/main/cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.18.1)
project(core)
# Build zlib from source INTO libcore.so rather than linking the platform's.
# That single choice is what makes this library invisible to every build-time
# dependency scanner, and it is extremely common in real cross-platform cores.
add_subdirectory(third_party/zlib)
add_library(core SHARED core.c)
target_link_libraries(core zlibstatic)
```

Download a specific zlib release into `third_party/zlib` and, again, write the version down.

### Step 0.3 — remove the easy answers

This is what a real stripped build looks like, and it is why the lab is not five minutes long.

```bash
# host — strip the native library of everything optional
llvm-strip --strip-all app/build/.../libcore.so     # removes .symtab, KEEPS .dynsym
# and build with -Wl,--build-id=none to remove the build ID entirely

# host — delete the version stamps from the APK
zip -d app-release.apk 'META-INF/*.version'

# host — now plant a FALSE one, because real builds contain stale artefacts and
# you must learn to handle a signal that disagrees with the others
echo "3.12.1" > 'com.squareup.okhttp3_okhttp.version'
mkdir -p META-INF && mv 'com.squareup.okhttp3_okhttp.version' META-INF/
zip app-release.apk 'META-INF/com.squareup.okhttp3_okhttp.version'

# host — re-sign, because you just changed the archive
apksigner sign --ks debug.keystore app-release.apk
apksigner verify app-release.apk
```

> **Pentester's Note**
> The planted stamp is not artificial. Build pipelines copy `META-INF` forward, vendors ship AARs
> containing stamps for the versions *they* built against, and repackagers edit whatever they like.
> A stamp is a text file in a zip. Treat it as a claim, not as a fact.

---

## The Evidence Ledger

Open a file called `ledger.md` before you run a single command. Every observation goes in it, as you
make it, whether or not it turns out to matter.

| # | Library | Claim | Bound | Signal (technique) | Artifact and where in it | Confidence | What would disprove this |
|---|---|---|---|---|---|---|---|
| 1 | | | exact / min / max / presence | | | high / med / low | |

**Bound** is the discipline that makes this work. Almost no single signal gives you an exact version.
Most give you "at least this" or "at most this", and the answer is the *intersection*:

- A class that exists only from version X onward is a **lower bound**.
- A class removed in version Y is an **upper bound**.
- A compiler banner is an upper bound on *age*, never a version.
- A version string is an exact claim — and the easiest of all signals to forge.

---

## Steps

### Step 1 — Establish what you are holding

```bash
# host
bash ../scripts/lib-inventory.sh -o out app-release.apk
cat out/*/*/03-stamps.txt
cat out/*/*/05-managed.txt | head -30
```

**Q1.** Record the class counts under each library's package. Are they large or small? Why is a small
number *not* evidence that the library is small?

**Q2.** The stamp says one thing. Enter it in the ledger — with a Confidence of no better than
medium, and a "What would disprove this" cell you can actually act on.

### Step 2 — Target 1: the library that reports itself

```bash
# host — the banner, technique 1
python3 ../scripts/lib-fingerprint.py app-release.apk | sed -n '/EVIDENCE/,/SIGNALS/p'

# host — the same thing by hand, so you know what the script did
unzip -p app-release.apk classes.dex | grep -a -oE 'okhttp/[0-9]+\.[0-9]+\.[0-9]+'
for d in $(unzip -l app-release.apk | grep -oE 'classes[0-9]*\.dex'); do
  echo "== $d"; unzip -p app-release.apk "$d" | strings -a | grep -E '^okhttp/'
done
```

**Q3.** You now have two claims about the same library: the planted stamp and the banner. They
disagree. **Do not pick one.** Write both in the ledger, then design a third, independent observation
that will decide between them. What is it?

```bash
# host — the deciding observation: what does the class set say?
mkdir refs && cd refs
for v in <candidate versions>; do
  curl -sO "https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/$v/okhttp-$v.jar"
done
cd ..
python3 ../scripts/lib-fingerprint.py app-release.apk --prefix okhttp3 --refs ./refs
```

**Q4.** Read the CONTAIN column, not the Jaccard column. Why? (The script explains it, but say it in
your own words in the ledger — you will have to say it to a client one day.)

**Q5.** Several releases may contain every class your APK defines. That is a **range**, not a point.
How do you collapse a range to a point? (Hint: you are looking for one class, not a better score.)

### Step 3 — Target 2: the library that reports nothing

Gson carries no version string. There is no stamp. R8 has renamed the app's code around it and
stripped the parts you never called. Technique 1 gives you nothing; techniques 4, 5 and 6 give you
nothing. You have exactly one signal: **the class set**.

```bash
# host
python3 ../scripts/lib-fingerprint.py app-release.apk --prefix com.google.gson

cd refs
for v in <candidate versions>; do
  curl -sO "https://repo1.maven.org/maven2/com/google/code/gson/gson/$v/gson-$v.jar"
done
cd ..
python3 ../scripts/lib-fingerprint.py app-release.apk --prefix com.google.gson --refs ./refs
```

**Q6.** With only one technique available, what is the *most* you are entitled to write in a report?
Write that exact sentence into the ledger now, before you know the answer.

**Q7.** Suppose no reference contains every class in your APK. List the three explanations the script
gives, and design a check that distinguishes them.

**Q8.** R8 stripped classes. Does that make your version estimate too **high** or too **low**, and
why? Which direction should you err in, in a report?

### Step 4 — Target 3: the native library with something inside it

The `.so` is stripped, has no build ID, and its `NEEDED` list is short.

```bash
# host — symbols survive stripping, because .dynsym is not optional
readelf --dyn-syms --wide out/*/*/raw/*/lib/arm64-v8a/libcore.so | awk '{print $8}' | sort -u | head -40
readelf -d out/*/*/raw/*/lib/arm64-v8a/libcore.so | grep NEEDED

# host — or, with no binutils
python3 ../scripts/lib-fingerprint.py app-release.apk --so libcore.so
```

**Q9.** The library exports `crc32`, `inflate`, `deflate`, `inflateInit_`. Its `NEEDED` list does not
include `libz.so`. State, in one sentence, what that combination proves.

**Q10.** Now find the version. zlib puts it in a specific string:

```bash
# host
strings -a out/*/*/raw/*/lib/arm64-v8a/libcore.so | grep -E 'inflate [0-9.]+ Copyright'
strings -a out/*/*/raw/*/lib/arm64-v8a/libcore.so | grep -E '^1\.[0-9]+\.[0-9]+'
```

Which of those two greps is evidence and which is a coincidence generator? Why?

**Q11.** Suppose the banner had been stripped too. Name two remaining ways to bracket the version of
a statically linked C library from the binary alone. (Chapter §3.7 techniques 3 and 4 both apply, and
one of them still works even when the build ID is gone.)

**Q12.** Does the platform's `libz.so` matter to this app at all? What does your answer imply about
who is responsible for patching this code, and what does that do to its rating in §8.1 Phase 4?

### Step 5 — The adversarial review

Swap ledgers with a partner. If you are working alone, leave it for a day, then come back and attack
your own.

For each row, ask:

1. **Is the artifact named precisely enough that I could reproduce this observation?** "in the DEX"
   is not; "`classes2.dex`, string `okhttp/4.9.3`" is.
2. **Is the bound right?** Does that signal really give an exact version, or did the writer promote a
   lower bound to a fact because it was the only number they had?
3. **Could this signal have been forged by someone who wanted me to reach this conclusion?** Every
   string can. Which of your signals could *not* be forged without also forging the others
   consistently?
4. **What is the cheapest observation that would refute this row?** If the answer is "none", the row
   is not evidence, it is faith.

**Q13.** How many rows in your ledger survive step 5 unchanged? (Fewer than you expect. That is the
lab working.)

### Step 6 — Write the three arguments

Then, and only then, open the sealed answers.

**Q14.** For each of the three libraries: were you right? If you were right for the *wrong reason* —
your evidence did not actually support the conclusion, and you got lucky — that counts as wrong.
Which was it?

---

## Hints

<details>
<summary>Hint — Q3, deciding between the stamp and the banner</summary>

Two claims, both of them strings in a file someone else produced. You need a signal that is not a
string: **structure**.

Download both candidate releases from Maven Central and compare class sets. A version string is one
edit; a class set is hundreds of files that would all have to be edited consistently, and R8's
stripping makes the forgery harder still because the forger would have to predict which classes your
app's call graph retained.

That asymmetry — cheap to forge versus expensive to forge — is the real basis for confidence ratings.
Not how much you like the signal, but how much work faking it would have been.
</details>

<details>
<summary>Hint — Q5, collapsing a range to a point</summary>

Stop scoring and start discriminating. Take the two adjacent candidate releases at the edges of your
range and diff their class lists:

```bash
# host
unzip -l okhttp-4.9.3.jar | grep -oE 'okhttp3/[^ ]*\.class' | sort > a.txt
unzip -l okhttp-4.10.0.jar | grep -oE 'okhttp3/[^ ]*\.class' | sort > b.txt
comm -13 a.txt b.txt    # classes ADDED in the later release
comm -23 a.txt b.txt    # classes REMOVED
```

Now check your APK for exactly those classes. One class that exists in only one of the two candidates
is worth more than any similarity score, because it is a yes/no question rather than a threshold.

The catch, and you must state it in the ledger: if the discriminating class is one your app never
calls, **R8 removed it**, and its absence proves nothing. Choose a discriminator that your app's own
code path would have retained, or accept the range.
</details>

<details>
<summary>Hint — Q8, the direction of the error</summary>

R8 removes classes, so the APK's set is a **subset** of the real release. A subset is contained in
*more* releases than the full set would be — including releases that are smaller and older.

So the smallest release containing your set may be **older** than the truth. Your estimate skews low.

In a report, err toward the **wider range** and say so: "between 4.9.x and 4.11.x, evidenced by …".
An honest range is defensible. A precise wrong number is not, and it is the one the developer will
remember.
</details>

<details>
<summary>Hint — Q10, which grep is evidence</summary>

`inflate 1.2.11 Copyright` is a **structured banner**: the version sits inside a fixed sentence that
zlib's own source emits. Nothing else produces that sentence.

`^1\.[0-9]+\.[0-9]+` matches any three numbers separated by dots, anywhere in eight megabytes of
binary. It will match a date, an offset table, part of a UUID, a resource ID and a fragment of
someone else's version string. It generates candidates, not conclusions.

The general rule: prefer a match whose *surrounding context* is part of the pattern. That is why the
banner table in chapter §3.7 anchors on `OPENSSL_VERSION_TEXT`, `libcurl/`, `FFmpeg version` and
`inflate … Copyright`, and why the fingerprint script only reports a bare `3.x.y` for SQLite once
`sqlite3_*` symbols have independently proved SQLite is present.
</details>

<details>
<summary>Hint — Q11, when the banner is gone too</summary>

**Symbol-set bracketing.** Libraries add and remove exported functions between releases, exactly as
they add and remove classes. `readelf --dyn-syms` gives you the set. Compare it against symbol lists
you extract from reference builds of the same library. The chapter gives one worked example:
`av_register_all` was deprecated in FFmpeg 4.0 and later removed, so its presence brackets the build.

**Build ID correlation.** If the build ID is still there, and you can obtain the vendor's published
artifact, a match proves the binary is byte-identical to theirs — which settles the version with no
inference at all. If it was stripped, note the absence: chapter §3.7 technique 4 points out that
missing a build ID is itself a signal, since standard NDK builds emit one.

**A third one worth knowing.** Compiler and optimisation fingerprints in the code itself. Slower,
less certain, and the point at which you should ask whether the version number is worth the hour.
</details>

---

## Solution notes

<details>
<summary>The shape of a defensible answer</summary>

**Strong** — two independent techniques, one of them expensive to forge:

> OkHttp is present at version 4.9.3. Evidence: (1) the string `okhttp/4.9.3` in `classes2.dex`,
> which OkHttp emits as its `User-Agent` fragment; (2) the 84 classes the APK defines under
> `okhttp3` are fully contained in the published `okhttp-4.9.3.jar` and are *not* fully contained in
> `okhttp-4.8.1.jar`, which lacks `okhttp3/internal/connection/RealCall`. A `META-INF` stamp in the
> APK claims 3.12.1; that claim is contradicted by both observations above and by the package layout,
> which is that of the 4.x line. The stamp appears to be stale or planted.

**Weak** — one cheap signal, promoted to a fact:

> OkHttp 3.12.1 (from `META-INF`).

**Also acceptable, and better than either when it is the truth:**

> A Gson-family JSON library is present. Its class set is contained in releases 2.8.6 through 2.8.9
> and no narrower bracket could be established, because the app's call graph retains too few classes
> to discriminate between them and Gson carries no version string. If the exact version matters for
> your remediation decision, the build file will answer it in a second.

That last one names its own limitation and tells the client how to close the gap in a second. Clients
trust that far more than they trust confidence.
</details>

<details>
<summary>What the planted stamp was for</summary>

Two things.

First, so that you meet a **conflict** in a controlled setting. The fingerprint script prints
conflicts rather than averaging them, and its advice is the real advice: two disagreeing signals
usually mean two bundled copies, a stale artefact, or a deliberate lie — and each of those is worth
more in a report than the version number you were originally chasing.

Second, so that you notice the stamp was *anomalous in kind*, not just in value. OkHttp does not
normally ship a `META-INF/*.version` stamp at all; those are an AndroidX and Google-library
convention. A stamp that should not exist is a louder signal than a stamp with the wrong number in
it, and spotting that requires knowing what a normal APK looks like — which is what lab 01 built.
</details>

---

## Success criteria

- [ ] Three libraries, three version claims, each with **at least the technique named** and, where
      available, two independent techniques.
- [ ] Your ledger contains rows for signals that turned out to be wrong or useless, and they are
      still there, marked. Deleting failed observations is how you lose track of what you checked.
- [ ] You detected the conflicting stamp and resolved it with a third observation rather than by
      preference.
- [ ] For the native library, you can state whether the platform's copy is used or a private copy is
      linked in, and what that does to who is responsible for patching it.
- [ ] At least one of your three answers is a **range**, and you are comfortable with that.
- [ ] Every row survived the step 5 adversarial review, or was corrected.
- [ ] You can name, for each of your three claims, the cheapest observation that would refute it.

---

## Where to go next

| Next | Why |
|---|---|
| [Lab 03 — SDK data-collection audit](lab-03-sdk-audit.md) | Version is half of the assessment; what it *sends* is the other half |
| [Lab 05 — The library that lied](lab-05-ctf-library-that-lied.md) | Applies exactly this technique to a library whose name is a lie |
| [`../faq.md`](../faq.md) | "The version in the manifest disagrees with the code" and "is an outdated library automatically a finding" |
| [Chapter 17 §3.7](../README.md#3-deep-internal-working) | Re-read the six techniques now that you have used five of them |
| [40-Obfuscation](../../40-Obfuscation/README.md) | When the class set itself has been mangled beyond comparison |
