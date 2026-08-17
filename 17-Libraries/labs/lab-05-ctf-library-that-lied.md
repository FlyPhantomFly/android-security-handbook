# Lab 05 — CTF: The Library That Lied

**Difficulty:** Advanced
**Time:** 3–5 hours
**Prerequisites:** [Lab 01](lab-01-library-inventory.md), [Lab 02](lab-02-version-fingerprint.md),
[Lab 04](lab-04-constructor-hook.md) helps but is not required,
[Chapter 17 §3.7](../README.md#3-deep-internal-working) and [§11](../README.md#11-common-mistakes),
`python3`, network access to Maven Central, and a device or emulator.
The challenge binary is [`../examples/impostor_sdk.c`](../examples/impostor_sdk.c).

**Flag format:** `LIBLAB{...}`

---

## The challenge

You are handed `shop.apk`. The inventory looks unremarkable — a retail app with the usual set of
dependencies. One row catches your eye and then un-catches it, because the explanation is obvious:

```text
    884  okhttp3                                        OkHttp / Okio (HTTP)
```

and

```text
  lib/arm64-v8a/libokhttp_native.so
```

and

```text
  META-INF/com.squareup.okhttp3_okhttp.version           4.9.3
```

Three signals, all agreeing, all naming a library that millions of applications use and that nobody
has ever had cause to worry about.

**All three are lies.**

Your job, in order:

1. **Prove it is not what it says it is.** Not "it looks odd" — prove it, with an observation anyone
   can reproduce.
2. **Work out what it actually does**, including the part that runs before any Java code exists.
3. **Recover the flag**, and recover it **twice**: once by running it, and once from the files alone
   with no device involved.

---

## Rules

1. **Both recovery paths, or it does not count.** The dynamic path takes ten minutes once you know
   where to look. The static path is the one that proves you understood the mechanism, and it is the
   one you will need on the day the target refuses to run in your environment.
2. **No brute force.** The key is derivable, not guessable.
3. **You may — and should — download real artifacts from Maven Central.** Comparing against ground
   truth is the entire technique this lab is teaching.
4. Do not skip step 1. Recovering a flag from a library you never proved was hostile is a lucky
   afternoon, not a methodology.

---

## Building the challenge

As with the other advanced labs in this repository, you build the target. Reading the lie from the
inside is what stops you from ever writing one of these rows into a report unchecked.

### Part 1 — the application

Package **`com.liblab.shop`**. The package name is not cosmetic: the payload's key is derived from
it, so a different `applicationId` produces a blob that decrypts to noise.

```groovy
// app/build.gradle
android {
    namespace 'com.liblab.shop'
    defaultConfig {
        applicationId "com.liblab.shop"          // MUST be this
        ndk { abiFilters "arm64-v8a" }
    }
    externalNativeBuild { cmake { path "src/main/cpp/CMakeLists.txt" } }
}

dependencies {
    // Deliberately NOT com.squareup.okhttp3:okhttp. The classes below are
    // hand-written impostors. That absence is what the whole lab turns on.
}
```

### Part 2 — the impostor's Java half

Two files, both under the `okhttp3` package tree, both hand-written.

```java
// app/src/main/java/okhttp3/internal/platform/Platform.java
package okhttp3.internal.platform;

/**
 * Named after a class that really exists in OkHttp, in a package that really
 * exists, with a shape that does not. The real one has no native methods,
 * because the real OkHttp has no native code at all.
 */
public class Platform {
    static { System.loadLibrary("okhttp_native"); }

    private static final Platform PLATFORM = new Platform();
    public static Platform get() { return PLATFORM; }

    public static native int nativeInit();
    public static native String nativeVersion();

    public String toString() { return "Platform(" + nativeVersion() + ")"; }
}
```

```java
// app/src/main/java/okhttp3/OkHttpClient.java
package okhttp3;

import okhttp3.internal.platform.Platform;

/** A stub with a famous name and none of the behaviour. */
public class OkHttpClient {
    public OkHttpClient() { Platform.get(); }
    public String userAgent() { return "okhttp/4.9.3"; }
}
```

```java
// app/src/main/java/com/liblab/shop/MainActivity.java
package com.liblab.shop;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import okhttp3.OkHttpClient;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        OkHttpClient client = new OkHttpClient();
        Log.i("SHOP", "http client ready: " + client.userAgent());
    }
}
```

Add another twenty or thirty small classes under `okhttp3.*` with plausible names
(`Request`, `Response`, `Call`, `Interceptor`, `Dns`, `internal/Util`, …) so that the class count in
the inventory looks like a real library rather than a stub. **Choose names that really exist
upstream** — the challenge is only interesting if a lazy check passes.

### Part 3 — the impostor's native half

Take [`../examples/impostor_sdk.c`](../examples/impostor_sdk.c) unmodified. Its header carries the
CMake it needs. Build it as `libokhttp_native.so`.

### Part 4 — the planted stamp

```bash
# host
mkdir -p META-INF
echo "4.9.3" > META-INF/com.squareup.okhttp3_okhttp.version
zip app-release.apk META-INF/com.squareup.okhttp3_okhttp.version
apksigner sign --ks debug.keystore app-release.apk
```

Note what makes this stamp a good lie and, simultaneously, its own tell: it agrees with the
`userAgent()` string and with the `nativeVersion()` return value, so a tester who checks two signals
gets two confirmations. Whether it survives a *third* check is the lab.

### Part 5 — sanity check before you start

```bash
# host
python3 ../scripts/lib-fingerprint.py app-release.apk | sed -n '/CONCLUSIONS/,$p'
```

You should see OkHttp reported with agreeing signals. Good. Now forget how you built it.

---

## Your first attempt, which will confirm the lie

This is what a normal, competent inventory pass produces:

```bash
# host
bash ../scripts/lib-inventory.sh -o out app-release.apk
grep -i okhttp out/*/*/*.txt
```

```text
03-stamps.txt:  com.squareup.okhttp3_okhttp.version    4.9.3
05-managed.txt:    884  okhttp3        OkHttp / Okio (HTTP)
02-native.txt:  lib/arm64-v8a/libokhttp_native.so
```

Three sources, one conclusion: **OkHttp 4.9.3, bundled, no known issues for this version, rated
Informational.** Every step of that reasoning was reasonable. The row is wrong.

**Q1.** Before reading further: what is the cheapest single check that would have caught this? You
already know the answer if you did lab 01 — it is not a technique, it is a habit.

---

## Investigation

### Step 1 — Ask what the real library looks like

```bash
# host
mkdir refs && cd refs
curl -sO https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/4.9.3/okhttp-4.9.3.jar
unzip -l okhttp-4.9.3.jar | grep -c '\.class$'
unzip -l okhttp-4.9.3.jar | grep -ci '\.so$'
unzip -l okhttp-4.9.3.jar | grep -i 'META-INF' | head
cd ..
```

**Q2.** How many `.so` files does the real artifact contain? What does your answer make of
`libokhttp_native.so`?

**Q3.** Does the real artifact ship a `META-INF/*.version` stamp? Which libraries conventionally do?
What does that make of the stamp in the APK — not "wrong value", but *wrong kind*?

**Q4.** State the general rule you have just used, in one sentence. It is more valuable than this
challenge.

### Step 2 — Compare the class sets

```bash
# host
python3 ../scripts/lib-fingerprint.py app-release.apk --prefix okhttp3 --refs ./refs
```

Read the CONTAIN column and the paragraph underneath it.

**Q5.** Does any reference contain every class the APK defines? Which classes are in the APK and in
no release? What are the three explanations the tool offers, and which one applies here?

**Q6.** The APK defines a class `okhttp3.internal.platform.Platform`, and so does the real library.
Same package, same name. So this is not a made-up class. Why is it still evidence? (Look at its
*shape*, not its name.)

```bash
# host — the shape, not the name
python3 ../scripts/lib-fingerprint.py app-release.apk --list-classes | grep okhttp3 | sort > apk.txt
unzip -l refs/okhttp-4.9.3.jar | grep -oE 'okhttp3/[^ ]*\.class' \
  | sed 's#\.class$##; s#/#.#g' | sort > real.txt
comm -23 apk.txt real.txt      # in the APK, in no real release  <-- the finding
comm -13 apk.txt real.txt | wc -l    # in the real release, absent here
```

**Q7.** The second number is enormous. Is that suspicious on its own? (Careful. Lab 02 taught you the
answer, and it is not "yes".)

### Step 3 — Look at the native library properly

```bash
# host
python3 ../scripts/lib-fingerprint.py app-release.apk --so libokhttp_native.so
```

**Q8.** What does it export? What does its `NEEDED` list say? Does a networking library's dependency
list look like that?

**Q9.** How many `.init_array` entries? What does chapter §9.1 say runs there, and when?

**Q10.** The exported symbol is `Java_okhttp3_internal_platform_Platform_nativeInit`. JNI resolves by
name, so this really would bind to the Java class. Explain why a correct-looking JNI symbol name is
worth **nothing** as evidence of provenance.

### Step 4 — Read the constructor

Open the `.so` in [57-Ghidra](../../57-Ghidra/README.md), or watch it live.

```bash
# host — what does it touch, and when?
frida-trace -U -f com.liblab.shop -i "fopen" -i "fread" -i "__android_log_print"
```

**Q11.** Which file does the constructor read? Why *that* file, and why can it read it at that
moment when there is no `Context` and no application object yet?

**Q12.** There is a block of constant bytes in `.rodata` that is not a string. What is it, and what
happens to it during `dlopen`?

**Q13.** Where does the result go? Look at the *whole* argument list of the logging call, including
the tag and the priority.

### Step 5 — Recover the flag, twice

**Path A — dynamically.**

```bash
# adb shell
logcat -c
# host
adb shell am start -n com.liblab.shop/.MainActivity
adb logcat -d -s OkHttp:D
```

**Q14.** You almost certainly had this output on your screen an hour ago and read past it. Why? Name
the two design choices in `impostor_sdk.c` that made you read past it, and say what each one costs an
analyst.

**Path B — statically, no device.**

```bash
# host — the ciphertext
python3 ../scripts/lib-fingerprint.py app-release.apk --so libokhttp_native.so
# then extract the .so and find the constant array; xxd, Ghidra, or:
unzip -p app-release.apk lib/arm64-v8a/libokhttp_native.so > libokhttp_native.so
```

**Q15.** You need the key. It is not in the `.so`. Where is it, and how do you get it without running
anything?

**Q16.** Write the decryption. Six lines of Python. Then say what property of the cipher made
recovering the plaintext possible without recovering anything else.

### Step 6 — Write the finding

**Q17.** Write the paragraph you would put in the report. It must contain: what the library claims,
what it is, the evidence for both halves, what it does, and what you did *not* establish.

**Q18.** Rate it with the rubric in chapter §8.1 Phase 4. Which factor dominates, and does the total
matter?

---

## Hints

<details>
<summary>Hint — Q1, the habit</summary>

**Look at the real thing.**

The inventory said OkHttp. OkHttp is open source, it is on Maven Central, and downloading a release
takes one `curl` and eight seconds. Everything in this challenge falls apart the moment you compare
against the genuine artifact rather than reasoning about the name.

The habit generalises past this lab: whenever a signal names a library you can obtain, **obtain it**.
Compare class sets, compare file lists, compare build IDs. Chapter §3.7 technique 4 makes the same
argument for native code — if the vendor publishes the AAR, extract its `.so` and compare build IDs,
and you have *proven* rather than *inferred* provenance.
</details>

<details>
<summary>Hint — Q6, shape versus name</summary>

The real `okhttp3.internal.platform.Platform` is a Java class with Java methods. The one in the APK
declares:

```java
public static native int nativeInit();
public static native String nativeVersion();
```

`native` methods in a library that has no native code is a contradiction that no version of OkHttp
can resolve. You do not need to know OkHttp's internals to see it; you need to have looked at the
real jar and noticed there is no `.so` for those methods to bind to.

The general form: a class is not just a name, it is a name plus a set of members. Names are free to
copy. A consistent set of members that matches a real release is a great deal more work — and any
inconsistency in it is a fact you can point at.
</details>

<details>
<summary>Hint — Q7, why "hundreds of classes missing" is not the finding</summary>

Because R8 removes what the app never calls, and a real app that uses OkHttp for two requests retains
a fraction of the library. Lab 02's Q8 is exactly this: the APK's class set is a **subset** of the
real release, so absence is expected and proves nothing.

The finding is the other direction: classes present in the APK that exist in **no** release. A subset
is normal; a superset is impossible. That asymmetry is why `comm -23` is the interesting command and
`comm -13` is the boring one.
</details>

<details>
<summary>Hint — Q15, where the key lives</summary>

The constructor reads `/proc/self/cmdline` and uses what it finds as the key. `/proc/self/cmdline`
for an ordinary Android app process holds the **package name**.

Which you already have, statically, from the manifest:

```bash
# host
aapt2 dump packagename app-release.apk
# or
python3 ../../10-APK-Internals/examples/parse_axml.py --extract app-release.apk | grep -i package
```

Note what this design achieved for its author: an analyst who extracts the `.so` and carries it away
has a blob and no key. The key is a property of the *environment*, not of the file. Real malicious
SDKs bind payloads to their host for exactly this reason, and the counter is exactly this: recover
the environment fact instead of attacking the cipher.
</details>

<details>
<summary>Hint — Q14, why you read past the log line</summary>

Two choices, both deliberate:

- **The tag is `OkHttp`.** You filter logcat by the tags you expect to be interesting. Nobody greps
  for the HTTP library.
- **The label is `platform-build=`.** It reads like a build identifier, which is the single most
  ignorable thing a log line can look like.

The lesson is not "read all of logcat". It is that an impostor inherits the *attention budget* of the
identity it stole. The name is not just a disguise for a static analyst; it is a disguise for your
eyes at every stage afterwards.
</details>

---

## Solutions

<details>
<summary>Q2–Q4 — the proof, in three observations</summary>

**Q2.** Zero. The real OkHttp artifact contains no native code whatsoever — it is a pure Java/Kotlin
library. Therefore `libokhttp_native.so` is not part of OkHttp, cannot be part of OkHttp, and its
existence alone is sufficient to reject the identification. This is the cheapest and strongest of the
three observations.

**Q3.** No. `META-INF/<group>_<artifact>.version` stamps are an AndroidX and Google-library
convention; a Square artifact does not write one. So the stamp is not merely *wrong*, it is
*categorically out of place* — a file that would not exist even if the version were correct.

Wrong-value signals are ambiguous (stale build, copied artefact). Wrong-*kind* signals are not.

**Q4.** The rule:

> When a signal names a library you can obtain, obtain it and compare. Provenance is established by
> comparison with the genuine artifact, never by reading a name.
</details>

<details>
<summary>Q12 and Q16 — the payload and the decryption</summary>

**Q12.** A 42-byte array in `.rodata`. Too short to look interesting to an entropy check, no printable
run for `strings` to catch, no structure to recognise. During `dlopen` — inside the `.init_array`
constructor, before `JNI_OnLoad` — it is XORed byte-wise with the host package name repeated, and the
plaintext is left in a static buffer.

**Q16.** The decryption, with the key taken from the manifest:

```python
#!/usr/bin/env python3
# host
ct = bytes.fromhex(          # the 42 bytes from .rodata
    "2F262F622D2B190D3E0C4F07"
    "0119153C03044C331D0A0D15"
    "3D4118001B041330034B1A0C"
    "103309034A0E")
key = b"com.liblab.shop"     # from the manifest, not from the .so
print(bytes(c ^ key[i % len(key)] for i, c in enumerate(ct)).decode())
```

```text
LIBLAB{a_native_lib_that_okhttp_never_had}
```

The property that made it work: XOR with a repeating key is symmetric, so decryption *is* encryption
and you need nothing but the key. You never had to understand the constructor's control flow, only
what it consumed. That is the usual shape of these problems — find the input, not the algorithm.
</details>

<details>
<summary>Q17 — the finding, written out</summary>

> **The application bundles a native library that misrepresents itself as part of the OkHttp HTTP
> client.**
>
> The APK contains `lib/arm64-v8a/libokhttp_native.so`, 884 classes under the `okhttp3` package, and
> a `META-INF/com.squareup.okhttp3_okhttp.version` stamp reading `4.9.3`.
>
> None of these is OkHttp. Evidence: (1) the published `okhttp-4.9.3.jar` on Maven Central contains
> no native code of any kind, so no OkHttp release can account for a `.so`; (2) the APK defines
> classes under `okhttp3` that exist in no published release, including an
> `okhttp3.internal.platform.Platform` declaring `native` methods that the real class does not have;
> (3) OkHttp artifacts do not ship `META-INF/*.version` stamps, so the stamp is anomalous in kind and
> not merely in value.
>
> The library's behaviour is contained in an `.init_array` constructor, which executes inside
> `dlopen()` before `JNI_OnLoad` and before any application code. It reads `/proc/self/cmdline` to
> obtain the host package name, uses it as a key to decrypt a 42-byte blob carried in `.rodata`, and
> writes the plaintext to the system log under the tag `OkHttp` with the label `platform-build=`.
> The JNI entry points it exports are non-functional stubs.
>
> **Not established:** the provenance of the library (which supplier introduced it, and whether the
> development team is aware of it); whether the mechanism is used to carry anything beyond the test
> value observed; and whether other builds carry a different payload. Recommend obtaining the build's
> dependency provenance and comparing this `.so` against any artifact the supplier publishes.
</details>

<details>
<summary>Q18 — the rating</summary>

Using chapter §8.1 Phase 4:

| Factor | Score | Why |
|---|---|---|
| Known vulnerability in this version | 0 | There is no version. It is not the library it claims to be |
| Reachability | 3 | It runs during `dlopen`, unconditionally, at application start |
| Data sensitivity handled | 2 | It reads process metadata; the channel is capable of carrying more |
| Remote behaviour control | 0–3 | 0 for what was observed. **Investigate before you write this cell** |
| Maintenance | 3 | There is no upstream, because there is no real library |
| Provenance | 3 | Prebuilt `.so` of unknown origin, misrepresenting its identity |

The total is beside the point, and so is the CVSS score somebody will ask you for. The finding is
that **a component in this application is not what the build believes it is**, and the correct
recommendation is not "update" or "patch" but "establish how this entered the build, and audit
everything that entered by the same route".

Chapter §3.6 has the vocabulary for the conversation that follows: this is the shape of
malicious-by-design, dependency confusion, or a compromised build, and which one it is determines the
control the client needs. Do not guess between them in the report — say which evidence would
distinguish them and ask for it.
</details>

---

## Debrief

Four things this challenge exists to install.

**A name is a string the author chose.** Package prefixes, `.so` filenames, JNI symbol names, log
tags and version stamps are all free to forge, and forging all of them consistently is *still* cheap.
Chapter §11 lists "trusting a package prefix" as a reverse engineer mistake for exactly this reason.

**Corroboration means independent, not numerous.** Three agreeing signals convinced you. They agreed
because one person wrote all three. Independence is about *who could have produced the signal*, not
about how many there are. A class-set comparison against Maven Central is independent because the
attacker does not control Maven Central.

**Absence and presence are not symmetric.** Missing classes prove nothing, because R8 removes things.
Extra classes prove a great deal, because nothing adds classes to a published release. Whenever you
compare sets, ask which direction of difference is actually informative.

**Camouflage steals attention, not just identity.** You skipped the logcat line because of its tag.
You skipped the library row because of its name. The disguise did most of its work *after* you had
already inventoried it.

---

## Success criteria

- [ ] You proved the library is not OkHttp with at least **two** independent observations, at least
      one of which involved the genuine artifact from Maven Central.
- [ ] You can state which of your three original signals were forgeable and by whom.
- [ ] You identified the `.init_array` constructor and can say when it runs relative to `JNI_OnLoad`.
- [ ] You recovered `LIBLAB{a_native_lib_that_okhttp_never_had}` **dynamically**.
- [ ] You recovered it again **statically**, with no device, and can explain where the key came from
      and why it was not in the `.so`.
- [ ] You wrote the finding paragraph, and it contains an explicit "not established" sentence.
- [ ] You can explain why `comm -23` mattered and `comm -13` did not.

---

## Notes for instructors

- **The build must use `applicationId "com.liblab.shop"`.** Everything else is flexible; that is not.
- Vary the flag by changing the plaintext and re-running the XOR — the header of
  `impostor_sdk.c` shows the array format, and the generation is three lines of Python.
- **A good harder variant:** add the *real* `com.squareup.okhttp3:okhttp` dependency alongside the
  impostor classes. Now the APK contains a genuine OkHttp *and* a fake one, the class-set comparison
  returns a confusing high-containment result, and the student has to notice they are looking at two
  libraries in one namespace. That variant is closer to what shading actually looks like in the wild,
  and it is a much longer afternoon.
- **A good easier variant:** leave the `nativeVersion()` string out. Students then find the
  contradiction from the class set alone, which is a cleaner single lesson.
- The most common wrong turn is spending an hour in the disassembler on the JNI stubs. They do
  nothing. If a student is stuck there, ask them: "which function in this library is called, and by
  what?" — and let them find that nothing in the Java code ever calls `nativeInit`.

---

## Where to go next

| Next | Why |
|---|---|
| [Chapter 17 §3.6](../README.md#3-deep-internal-working) | Supply chain: name the class of attack precisely, and recommend the specific control |
| [`../faq.md`](../faq.md) | "Is a shaded library still that library" and "why does the same library appear under three names" |
| [40-Obfuscation](../../40-Obfuscation/README.md) | The same challenge, with the strings encrypted and the constructor flattened |
| [Lab 04](lab-04-constructor-hook.md) | If you have not done it: this library's constructor was friendly. The next one will not be |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Where third-party component findings map in MASVS |
