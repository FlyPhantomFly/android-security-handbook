# Lab 03 — Obfuscation blindness

**Level:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-survival-rate.md),
[42-R8](../../42-R8/README.md), [40-Obfuscation](../../40-Obfuscation/README.md),
[36-CertificatePinning](../../36-CertificatePinning/README.md).
**MobSF required:** **No.** Two fixtures ship with this chapter; the measurements below were taken
with `unzip`, `grep`, `aapt2` and `jadx`, none of which need a server.

---

## 0. The claim you are going to test

> **Anything a scanner derives from DATA survives obfuscation. Anything it derives from NAMES does
> not — and the failure is silent.**

Lab 02 measured a *survival rate*, which counts the report's mistakes. This lab measures the mistakes
the report **does not contain**: the findings that are missing, in the sections that look reassuring.

A survival rate cannot detect those. Nothing can, except going to the artefact.

---

## 1. Objective

Using two builds of one application that differ **only** in whether R8 ran:

1. Diff the two reports **section by section** and classify each section as value-derived
   (unchanged) or name-derived (degraded).
2. Find at least one **negative claim** that is false in the obfuscated build and true in the
   unobfuscated one.
3. Write the correction paragraph a client would receive.
4. Answer, in writing: *which sections of a report would you still trust on an obfuscated app?*

---

## 2. Setup

### 2.1 The two artefacts

**Option A — use the pair that ships with this chapter.** Two versions of a public,
deliberately-vulnerable training application:

| | v1.0 | v1.2 |
|---|---|---|
| Report fixture | [`synthetic-mobsf-report-v1.0.json`](../examples/synthetic-mobsf-report-v1.0.json) | [`synthetic-mobsf-report.json`](../examples/synthetic-mobsf-report.json) |
| SHA-256 | `f7daada6…f501ff` | `13718667…c39638` |
| Size | 5,646,105 B | 287,060 B |
| R8 | **no** | **yes** |

**Option B — build the pair yourself**, which is better because you control the variable. Take any
small app with a `CertificatePinner` and build it twice:

```kotlin
// app/build.gradle.kts
android {
    buildTypes {
        create("plain")     { isMinifyEnabled = false }
        create("shrunk")    { isMinifyEnabled = true
                              proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt")) }
    }
}
```

```bash
# host
./gradlew assemblePlain assembleShrunk
```

> **Build out of tree.** `.apk`, `.dex`, `.class` and `.so` are on this repository's artefact
> blocklist. Build into a scratch directory outside the repo, exactly as
> [15-Native-Code](../../15-Native-Code/README.md) does with its fixtures.

**Option C — two real releases of one real app**, from before and after the vendor enabled R8. This
is the most realistic and the least controlled: other things changed too, and your write-up must say
so.

### 2.2 Decompile both

```bash
# host
jadx -d out10 v1.0.apk 2>&1 | tail -3
jadx -d out12 v1.2.apk 2>&1 | tail -3
find out10/sources -name '*.java' | wc -l
find out12/sources -name '*.java' | wc -l
```

`MEASURED` on the shipped pair, jadx 1.5.3:

```
v1.0:  ERROR - finished with errors, count: 8        1,995 .java files, 1,757 classes
v1.2:  (clean)                                         234 .java files,   171 classes
```

**Note that already.** The *unobfuscated* build is the one the decompiler struggled with, and the
obfuscated one decompiled cleanly. "Obfuscated" and "hard to decompile" are not the same property —
R8 renames and shrinks; it does not primarily attack the decompiler. That distinction is
[40-Obfuscation](../../40-Obfuscation/README.md)'s and it matters here because people expect the
opposite.

---

## 3. Step 1 — Establish what changed, structurally

Before touching the reports, establish the ground truth yourself.

```bash
# host — are the class names gone?
find out12/sources -maxdepth 1 -type d | head -30
find out10/sources -maxdepth 1 -type d | head -30
```

`MEASURED`: v1.2's tree has single-letter package roots (`a/ b/ c/ … z/`) plus the app's own
`org/android/cmpen/`; v1.0's has `okhttp3/`, `retrofit2/`, `androidx/`, `kotlin/` intact.

```bash
# host — do the string literals survive?
for v in 10 12; do
  echo "== v1.$([ $v = 10 ] && echo 0 || echo 2)"
  mkdir -p /tmp/d$v && unzip -o -j -q v1.$([ $v = 10 ] && echo 0 || echo 2).apk 'classes*.dex' -d /tmp/d$v
  strings -a -n 8 /tmp/d$v/*.dex | grep -aoE 'https?://[A-Za-z0-9._~:/?#-]+' | sort -u
done
```

`MEASURED`: both builds contain `https://ninja.secops.group`. **The URL survived R8 completely**,
because R8 renames symbols and not data.

---

## 4. Step 2 — The pinning experiment

This is the core of the lab, and it is the case study
[36-CertificatePinning](../../36-CertificatePinning/README.md) asks this chapter to own.

### 4.1 What a name-based detector looks for

```bash
# host — the type name
for v in 10 12; do
  printf 'v1.%s CertificatePinner by NAME: ' "$([ $v = 10 ] && echo 0 || echo 2)"
  grep -a -c 'CertificatePinner' /tmp/d$v/*.dex
done
```

`MEASURED`:

| Build | `CertificatePinner` in the DEX | A name-based rule concludes |
|---|---|---|
| v1.0 | present | **"implements certificate pinning"** — correct |
| v1.2 | absent | **"does not implement certificate pinning"** — **wrong** |

### 4.2 What a value-based detector looks for

```bash
# host — the 43-character SPKI form. `grep sha256/` ALONE matches OkHttp's own
# parser constant and hits essentially every app that uses OkHttp.
for v in 10 12; do
  echo "== v1.$([ $v = 10 ] && echo 0 || echo 2)"
  grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/d$v/*.dex | sort -u
done
```

`MEASURED`:

```
== v1.0
sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=
sha256/jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=
sha256/jWseeY2GFCMiPCL39cf2IabLpYKO4uIBxLEHs7iE+00=
== v1.2
sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
```

**Both builds pin.** The value-based detector is correct on both, because a 43-character base64
string is not a symbol.

### 4.3 Find the construction site in each

```bash
# host
grep -rn 'CertificatePinner' out10/sources/ | head -3
grep -rn '+xpjwBQ7' out12/sources/ | head -3
```

`MEASURED`, v1.0 — legible:

```java
// out10/sources/org/android/cmpen/RetrofitClient.java:21
builder.certificatePinner(new CertificatePinner.Builder()
    .add("ninja.secops.group", "sha256/jWseeY2GFCMiPCL39cf2IabLpYKO4uIBxLEHs7iE+00=")
    .add("ninja.secops.group", "sha256/jQJTbIh0grw0/1TkHSumWb+Fs0Ggogr621gT3PvPKG0=")
    .add("ninja.secops.group", "sha256/C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=")
    .build());
```

`MEASURED`, v1.2 — same construction, every type renamed:

```java
// out12/sources/b/h.java:20-27
static {
    t tVar = new t();                                    // OkHttpClient.Builder
    m.d dVar = new m.d(0);                               // CertificatePinner.Builder
    dVar.f117a.add(new m.e(new String[]{                 // CertificatePinner.Pin
        "sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ="}[0]));
    m.g gVarB = dVar.b();
    tVar.f212q = gVarB;
    f19a = new u(tVar);                                  // the shared OkHttpClient
}
```

> **How to read obfuscated OkHttp quickly.** Do not try to recover names. Anchor on the **data**: the
> pin string is a literal, so grep for it, then read outward. The shape — a builder, an `add`, a
> `build`, a field assignment on another builder — is recognisable even when nothing is named. That
> is [40-Obfuscation](../../40-Obfuscation/README.md)'s "recover strings first" rule in practice.

### 4.4 Cross-check with the chapter that owns pinning

```bash
# host
python3 -B ../../36-CertificatePinning/scripts/pinning-surface.py --apk v1.2.apk
```

`MEASURED`, unedited:

```
  [1. SSLContext / X509TrustManager]
      + [MED  ] Custom X509TrustManager
      + [MED  ] SSLContext.init with own TrustManager
  [1b. X509TrustManagerExtensions]
      + [MED  ] X509TrustManagerExtensions
  [3. OkHttp CertificatePinner]
      + [HIGH ] CONFIGURED OkHttp/NSC pin value
                value: 1 distinct value(s): sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
      + [LOW  ] OkHttp pin failure message
  [4. HostnameVerifier]
      + [MED  ] Custom HostnameVerifier

  VERDICT: PIN CONFIGURED at 1 layer(s): 3. OkHttp CertificatePinner
```

**Six detections; one is the pin.** The four `MED` rows are OkHttp's own internal trust-management
classes, which ship unconditionally with the library in **every** app that uses it. That is 36's
12-of-14 measurement reproducing itself on a fresh sample: the surface is everywhere and the pin is
one line.

### 4.5 Let the validator state the contradiction

```bash
# host
python3 -B ../scripts/mobsf-validate.py \
    --report ../examples/synthetic-mobsf-report.json --apk v1.2.apk --tree ./out12 \
    | grep -A9 'certificate pinning'
```

`MEASURED`, unedited:

```
V033  [WARNING]  appsec:network
  claim     This application does not implement certificate pinning
    FOR     configured SPKI pin value(s) in the DEX: sha256/+xpjwBQ7+BLhq1r+/AU3qLNIaXPt+JgXAJ9yIQaHNkQ=
  VERDICT   REFUTED
  NEXT STEP The report is WRONG in the dangerous direction. The scanner looked
            for a class name; R8 renamed the class. Grep for the 43-character
            pin instead - see 36-CertificatePinning section 8.2.
```

---

## 5. Step 3 — The section-by-section diff

Now generalise. For each report section, decide whether it is derived from **data** or from **names**,
and check.

Fill this in from your own two runs:

| Report section | Derived from | v1.0 | v1.2 | Verdict |
|---|---|---|---|---|
| Component inventory | ? | | | |
| Permissions | ? | | | |
| Browsable activities | ? | | | |
| Manifest analysis | ? | | | |
| Certificate analysis | ? | | | |
| File / library list | ? | | | |
| URLs and domains | ? | | | |
| Secrets | ? | | | |
| Code analysis — framework API rules | ? | | | |
| Code analysis — type-name rules | ? | | | |
| Trackers | ? | | | |
| Binary analysis | ? | | | |

`MEASURED` answers on the shipped pair, for checking yourself afterwards:

<details>
<summary>The filled-in table</summary>

| Report section | Derived from | Effect of R8 | Why |
|---|---|---|---|
| Component inventory | **Data** | Unchanged | R8 cannot rename manifest-declared component names; the platform resolves them by string |
| Permissions | **Data** | Unchanged | Manifest strings |
| Browsable activities | **Data** | Unchanged | Manifest strings |
| Manifest analysis | **Data** | Unchanged | Reads the manifest |
| Certificate analysis | **Data** | Unchanged | Nothing to obfuscate |
| File / library list | **Data** | Unchanged | ZIP entries |
| URLs and domains | **Data** | Unchanged — both builds show `ninja.secops.group` | String literals survive |
| Secrets | **Data** | Unchanged | String literals |
| Code — framework API rules | **Data** | Unchanged — `Cipher.getInstance("DES")` and `("AES/ECB/…")` both found | R8 cannot rename `javax.crypto` |
| **Code — type-name rules** | **Names** | **Destroyed** | `okhttp3.CertificatePinner` → `m.e` |
| **Trackers** | **Names** | **Destroyed** | Package-prefix signatures |
| **Library identification** | **Names** | **Destroyed** | Package-prefix signatures |
| Binary analysis | **Data** | Unchanged | ELF headers; R8 does not touch `.so` |
| Readability of any cited file | **Names** | Degraded | You can still read it; it takes longer |

</details>

**The pattern, in one sentence:** everything the platform resolves by string, and everything the
developer wrote as data, survives. Everything the *compiler* was free to rename does not.

---

## 6. Step 4 — The second-order trap

There is a subtler consequence, and it is the one that causes real damage in a re-test.

> **A scanner's report on an obfuscated app is systematically shorter than its report on the same app
> unobfuscated. A reader who does not know this reads "fewer findings" as "more secure".**

`MEASURED` on the shipped pair (the item counts also reflect genuine feature differences, so this is
illustrative of direction rather than a controlled magnitude):

| | v1.0 | v1.2 |
|---|---|---|
| MobSF-style security score | 34 | 38 |
| Name-derived detections | present | absent |

Now the related trap from [42-R8](../../42-R8/README.md), because it catches people in exactly the
same situation:

> **All three of 42's test APKs were byte-identical in size (12,757 B) despite DEX sizes of
> 7,384 / 2,920 / 7,180.** `apksigner` pads the signing block to a 4 KiB boundary, so `ls -l *.apk`
> cannot tell you whether shrinking worked. **Compare the DEX, not the APK.**

```bash
# host — the comparison that is actually meaningful
for v in 10 12; do
  printf 'v1.%s  ' "$([ $v = 10 ] && echo 0 || echo 2)"
  unzip -l v1.$([ $v = 10 ] && echo 0 || echo 2).apk | awk '/classes.*\.dex/ {s+=$1} END {print s " bytes of DEX"}'
done
```

And one more, so nobody claims obfuscation was reversed:

> [42-R8](../../42-R8/README.md) scanned **19 real APKs, 316,000+ classes** for `kotlin.Metadata`:
> **zero wholesale name recovery.** Ten carried no metadata at all; one carried **1,393 empty
> shells**, so a naive `grep` reports 1,393 false positives. What *does* survive is **Kotlin property
> names** — structurally, because R8 renames JVM members and a property is not one.

---

## 7. Step 5 — Write the correction

The deliverable. A client will read the scan too, so the correction has to exist somewhere in your
report.

Template, with the shipped pair's values filled in — replace with your own:

> **N-02 — Note on automated pinning detection (Informational)**
>
> The automated scan reports that this application does not implement certificate pinning. **That is
> incorrect.** The application configures one SPKI pin for `ninja.secops.group`
> (`sha256/+xpjw…HNkQ=`) on a process-wide `OkHttpClient` constructed in a static initialiser
> (`b/h.java`). The scanner's rule matches the type name `okhttp3.CertificatePinner`; R8 renamed
> that type to `m.e`, so the rule found nothing. Version 1.0 of the same application, which ships
> unobfuscated, is detected correctly by the identical rule.
>
> **Why we are raising it.** Two reasons, and the second matters more. First, a "no pinning" line
> becomes a remediation ticket to add pinning that already exists. Second: if the scanner's negative
> claims are accepted here, they will be accepted for controls that genuinely are missing, and there
> is no way to tell those cases apart from the report alone.
>
> **What we did instead.** Mapped all four pinning layers per our standard method: one configured pin
> value, one layer. **Presence of a pin is not proof of enforcement** — that requires observing a
> handshake being rejected, recorded separately under dynamic testing.

---

## 8. Step 6 — Answer the question

In writing, in your own words:

> **Which sections of a scanner report would you still trust on an obfuscated application, and why?**

A good answer names the value/name distinction, lists at least four sections on each side, and adds
the second-order point: that the *negative* claims from the name-derived half are the dangerous
output, because nobody audits a reassurance.

A very good answer also notes what this does **not** imply — obfuscation is not a security control.
It raises an attacker's cost; it does not remove a secret. A key in `res/values/strings.xml` survives
R8 completely, so "enable obfuscation" is a **wrong remediation** for a shipped credential.

---

## 9. Hints

<details>
<summary>Hint 1 — I do not have two builds of anything</summary>

Three routes, in order of ease:

1. Use the shipped pair. Every measurement in this lab was taken on it.
2. Build any small app twice with `isMinifyEnabled` false and true. Any app with an OkHttp
   `CertificatePinner` will do; the pin can be a dummy value.
3. Two real releases of one real app from an APK mirror, from before and after the vendor enabled
   R8. Least controlled — other things changed too — and your write-up must say so.

</details>

<details>
<summary>Hint 2 — how do I recognise an obfuscated OkHttp stack at all?</summary>

Anchor on data, never on names.

- The **pin value**: `sha256/` + 43 base64 chars.
- OkHttp's own **exception strings**, which ship unconditionally:
  `grep -a -o 'Certificate pinning failure' /tmp/d12/*.dex`
- The **hostname literal** the pinner was configured with.
- `unzip -l app.apk | grep 'META-INF/.*okhttp'` — version stamps survive shrinking surprisingly often.

Then read outward from the literal. The builder shape is recognisable without names.

</details>

<details>
<summary>Hint 3 — the trackers section changed and I do not know if that is real</summary>

Tracker identification is **name-based**: it matches package prefixes against a signature database.
R8 destroys package prefixes, so the tracker count on an obfuscated build is unreliable and usually
too low.

Do **not** report "the app removed its trackers". Report that tracker identification is unreliable on
this build and say why. If it matters, confirm at runtime — the network destinations survive
obfuscation even when the class names do not.

</details>

<details>
<summary>Hint 4 — my two builds differ in more than obfuscation</summary>

Then say so, and confine your conclusions to the sections where the difference is mechanistically
explainable.

The pinning result is safe to claim even in an uncontrolled comparison, because you can show the
*same construction* in both builds — one legible, one renamed — and the same pin mechanism. That is a
mechanism argument, not a correlation.

The item-count difference is **not** safe to claim in an uncontrolled comparison. Do not.

</details>

---

## 10. Success criteria

- [ ] The section-by-section table, filled in from your own two runs, with each section classified
      value-derived or name-derived.
- [ ] A **negative claim** identified that is false on the obfuscated build, with the command that
      refutes it.
- [ ] The construction site located in **both** builds, and the correspondence between the renamed
      and original types written out.
- [ ] The DEX-size comparison, not the APK-size comparison, with a sentence on why.
- [ ] The correction paragraph, in report language.
- [ ] A written answer to §8's question naming at least four sections on each side.

---

## 11. What you should have learned

| Lesson | Evidence |
|---|---|
| Data survives R8; names do not | Your section table |
| A name-based rule fails **silently and in the reassuring direction** | The pinning claim |
| The pin *value* is the reliable detector | The 43-character grep, correct on both builds |
| Presence of a pin is still not enforcement | 36's four-layer model |
| A shorter report is not a safer app | The score comparison |
| Obfuscation is not a remediation for a shipped secret | Resource values survive completely |
| `kotlin.Metadata` does not undo it | 42's 19 APKs, 316,000 classes, zero recovery |
| Compare the DEX, not the APK | 42's byte-identical 12,757 B APKs |

---

## 12. Next

[Lab 04 — CTF: the report that lies](lab-04-ctf-the-report-that-lies.md) puts labs 01–03 together:
four flags, each recovered by disbelieving a different line of a scanner report.
