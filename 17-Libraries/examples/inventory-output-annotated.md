# An inventory output, annotated line by line — what each signal actually proves

This is real output from [`../scripts/lib-inventory.sh`](../scripts/lib-inventory.sh) and
[`../scripts/lib-fingerprint.py`](../scripts/lib-fingerprint.py), run against a composite retail
application, with every block followed by three questions answered honestly:

- **What does this prove?**
- **What does it *not* prove?**
- **What do I do next?**

The app is a composite: the shape is typical of a mid-size consumer retail app, the AndroidX and
OpenSSL versions are real releases, and the analytics vendor is fictional so that nothing here reads
as an allegation against a real company. Substitute your own target and the reasoning is unchanged.

> **Mental Model**
> An inventory is a list of *claims about a file*. A finding is a claim about *behaviour*. Almost
> every mistake in third-party assessment is made in the gap between those two sentences: a scanner
> reads a file, prints a CVE, and calls it a finding. This document is the discipline of not doing
> that.

---

## 00 — identity

```text
# 00 identity
b7e0c2...9f14  62914560  base.apk
4a1d88...02be  18874368  split_config.arm64_v8a.apk
9c30f5...771a   2097152  split_config.en.apk
```

**Proves.** Exactly which bytes were examined. Every claim below is a claim about these three
hashes and nothing else.

**Does not prove.** That these are the bytes a user gets. A Play-delivered app is assembled per
device; the splits a Pixel receives differ from the splits a low-RAM device receives.

**Next.** Record the hashes in the report. When the client says "we fixed that in the next build",
the hash is what makes the re-test a re-test rather than a new engagement.

---

## 01 — inputs and splits

```text
# 01 inputs
APKs given: 3
base.apk
split_config.arm64_v8a.apk
split_config.en.apk
```

**Proves.** All splits present in the directory were analysed.

**Does not prove.** That these are all the splits. Dynamic feature modules are downloaded *after
install* and never appear next to `base.apk`. `adb shell pm path <pkg>` after exercising the app is
the authority.

**Next.** If section 05 later shows classes referencing a feature module that has no code here, that
absence is itself a finding candidate: code arriving after install is ring 3.

> **Warning**
> The single most common way to produce a confidently wrong inventory is to analyse `base.apk`
> alone. On a bundle build it contains **no native libraries at all** — they are in
> `split_config.<abi>.apk`. Your report then says "no native code", which is not merely incomplete;
> it is false.

---

## 02 — native libraries

```text
### split_config.arm64_v8a.apk
  lib/arm64-v8a/libcore.so
  lib/arm64-v8a/libsqlcipher.so
  lib/arm64-v8a/libimagepipeline.so
  lib/arm64-v8a/librasp.so
  ABIs: lib/arm64-v8a/
```

**Proves.** Four native libraries ship, for one ABI only.

**Does not prove.** That any of them is loaded. An APK routinely carries `.so` files for code paths
that never execute.

**Next.** Confirm at runtime: `grep '\.so' /proc/<pid>/maps`. A `.so` present but never mapped is an
inventory row, not a finding.

### The per-library block, and what each line is worth

```text
### libcore.so
  size: 8918392 bytes
  -- header
    Class:                             ELF64
    Type:                              DYN (Shared object file)
    Machine:                           AArch64
  -- DT_NEEDED (what it expects the platform to provide)
    0x0000000000000001 (NEEDED)  Shared library: [liblog.so]
    0x0000000000000001 (NEEDED)  Shared library: [libz.so]
    0x0000000000000001 (NEEDED)  Shared library: [libc.so]
  -- build ID (identifies this exact build; README 3.7 T4)
    a3f19c04e77b21d5c8830fe6b9042aa17c5d1e88
  -- compiler (.comment)
    Android (7284624, based on r416183b) clang version 12.0.5
  -- hardening
    RELRO=yes
    BINDNOW=yes
    CANARY=yes
  -- constructors
    [18] .init_array       INIT_ARRAY  0000000000a41e70  00a40e70  000010
  -- statically linked third-party code (README 3.7 T3)
    OpenSSL or BoringSSL
    SQLite
    libcurl
  -- JNI shape
    JNI_OnLoad present: natives may be bound with RegisterNatives,
    so an absence of Java_* symbols does NOT mean an absence of JNI
  -- version banners (README 3.7 T1)
    OpenSSL 1.1.1k
    libcurl/7.68.0
```

| Line | Proves | Does **not** prove | Next |
|---|---|---|---|
| `Class: ELF64` / `Machine: AArch64` | The library is 64-bit ARM | That the app runs 64-bit on every device. A 32-bit split may exist and be built differently | Check for an `armeabi-v7a` split; differences between the two builds have produced real findings |
| `NEEDED: libz.so` | zlib comes from the **platform** and is therefore patched by Google/the OEM | That no *second* zlib is statically linked as well. Both happen in one binary | Look for `inflate x.y.z Copyright` in the strings; a banner plus a `NEEDED libz.so` means two copies |
| `NEEDED` does **not** list `libssl.so`/`libcrypto.so`, yet `SSL_*` symbols are exported | TLS is **statically linked into this file**. It will never receive a platform security update | Which of OpenSSL or BoringSSL it is — the symbol names are shared | The banner below settles it |
| `build ID a3f19c…` | This exact binary. Two apps carrying it ship byte-identical code | Provenance. It proves *sameness*, not *origin* | Extract the vendor's published AAR and compare. A match proves the app ships the genuine artifact; a mismatch is a finding |
| `.comment: clang 12.0.5` | The build is no older than that toolchain | The library version. A new compiler can build ancient source | Use it as an upper bound on age, never as a version |
| `RELRO/BINDNOW/CANARY = yes` | The build used standard hardening | That the code is safe. Hardening changes exploitation cost, not bug count | Note it and move on; it is a paragraph in the report, not a finding either way |
| `.init_array` size `0x10` | **Two constructor entries.** Code runs inside `dlopen`, before `JNI_OnLoad`, before any Java | What they do | This is where anti-analysis lives. See [`../labs/lab-04-constructor-hook.md`](../labs/lab-04-constructor-hook.md) |
| `JNI_OnLoad present` | Natives may be registered dynamically | That there are no JNI entry points. `RegisterNatives` binds them without exporting `Java_*` symbols | Disassemble `JNI_OnLoad` and look for the `JNINativeMethod` table; the descriptor strings are in `.rodata` |
| `OpenSSL 1.1.1k` | A string in this binary says that | That the code *is* 1.1.1k. A string is a string | Corroborate: does the symbol set match that era? Is there an `SSL_export_keying_material`? Report the version **with** the corroboration you actually did |

> **Pentester's Note**
> The three most valuable lines in that block are the ones nobody looks at: `NEEDED`, `.init_array`,
> and the absence of `libcrypto.so` alongside the presence of `SSL_*`. Together they say "this app
> carries its own TLS stack, which no update will ever reach, and it runs code before the app
> starts". That is a paragraph of report written from four lines of `readelf`.

---

## 03 — version stamps

```text
# 03 version stamps (META-INF/*.version)
## base.apk
  androidx.core_core.version                      1.9.0
  androidx.appcompat_appcompat.version            1.6.1
  androidx.fragment_fragment.version              1.5.5
  androidx.work_work-runtime.version              2.7.1
  com.google.android.material_material.version    1.6.1
```

**Proves.** The build system recorded these artifact versions. Of every signal in this document,
this is the most literal: no inference, no similarity score, a text file with a number in it.

**Does not prove.** That the code matches the number. A `.version` file is plain text inside a ZIP;
anyone who can repackage the APK can edit it, and R8 may have stripped most of the artifact it names.

**Next.** For anything that matters, corroborate with the class set:
`python3 ../scripts/lib-fingerprint.py app.apk --prefix androidx.work --refs ./refs`. If the stamp
and the class set disagree, the disagreement is worth more than either number was.

---

## 04 — extra code in assets

```text
## base.apk
  assets/rasp/config.dat
  assets/index.android.bundle
## base.apk -- cross-platform framework markers
  assets/index.android.bundle
  lib/arm64-v8a/libhermes.so
```

**Proves.** Part of this application is a React Native bundle, and something ships an opaque
configuration blob.

**Does not prove.** That the bundle is loaded from the APK. React Native supports over-the-air
bundle updates, and if this app does that, the JavaScript running on a user's device is not the
JavaScript in this file.

**Next.** Two jobs. First, unpack `index.android.bundle` and inventory the **npm** dependencies —
they are a whole second dependency tree that no Android tool will show you. Second, find out whether
the bundle can be replaced at runtime; if it can, that is ring 3 and it outranks everything else in
this document.

> **Mental Model**
> The managed class inventory of a framework app tells you the truth about the wrong layer. A React
> Native or Flutter app can show you two hundred tidy Java classes while ninety percent of its logic
> lives somewhere your DEX tooling cannot see.

---

## 05 — managed class inventory

```text
Classes defined across all inputs: 41208
Route taken: baksmali list classes

  count  package                                        vendor
  11842  androidx                                       Jetpack / AndroidX
   4915  com.google.android.gms                         Google Play services
   2201  kotlin                                         Kotlin runtime
   1980  com.facebook.react                             React Native (framework)
   1204  com.google.firebase                            Firebase
    884  okhttp3                                        OkHttp / Okio (HTTP)
    611  com.metriqa.sdk
    455  io.sentry                                      Sentry (crash reporting)
    317  com.example.shop
    212  a.a                                            
```

| Row | Proves | Does **not** prove | Next |
|---|---|---|---|
| `androidx  11842` | Jetpack is present at scale | That all of it is used. R8 keeps what is reachable, and "reachable" is generous | Nothing. Large AndroidX counts are normal and uninteresting |
| `okhttp3  884` | Classes under the OkHttp package are defined | That this **is** OkHttp. The package name is a string | Class-set comparison against real releases. This is exactly the check that catches [`impostor_sdk.c`](impostor_sdk.c) |
| `com.metriqa.sdk  611` | An SDK not in the vendor table | Anything about who publishes it or what it does | **Ten minutes here is the highest-value ten minutes in the whole inventory.** Grep its strings for endpoints, look for its provider in section 06, then search for the vendor |
| `com.example.shop  317` | The app's own code is 0.8% of the class count | That the developers wrote only 317 classes' worth of logic | State the ratio in the report. It reframes the client's conversation about third-party risk more effectively than any individual finding |
| `a.a  212` | Obfuscated classes | Which library they came from. R8 renamed them | Do not chase them by name. Identify them by *shape*: string constants, method counts, the classes they reference |

**The one that matters.** A prefix with a blank vendor column is not "nothing found". It is either
the app's own code or a library the table has never met, and the second case is where the
interesting findings are — nobody has audited an SDK nobody has heard of.

---

## 06 — manifest surface

```text
## initialisation providers -- the obfuscation-proof SDK inventory
  <provider android:name="androidx.startup.InitializationProvider"
  <provider android:name="com.google.firebase.provider.FirebaseInitProvider"
  <provider android:name="io.sentry.android.core.SentryInitProvider"
  <provider android:name="com.metriqa.sdk.MetriqaInitProvider"
  android:authorities="com.example.shop.firebaseinitprovider"
  android:authorities="com.example.shop.SentryInitProvider"
  android:authorities="com.example.shop.metriqa-init"

## permissions
  android.permission.ACCESS_NETWORK_STATE
  android.permission.ACCESS_COARSE_LOCATION
  android.permission.INTERNET
  android.permission.READ_PHONE_STATE
  com.google.android.gms.permission.AD_ID
```

**Proves.** Four SDKs start themselves before `Application.onCreate()` runs. Provider authorities are
resolved by the system as strings, so obfuscation cannot touch them — this list survives R8 intact.

**Does not prove.** That these are all the SDKs. A library that does not need early initialisation
declares no provider and does not appear here at all.

**Next.** Two questions for the permission list, and only the second one is interesting.
`ACCESS_COARSE_LOCATION` and `READ_PHONE_STATE`: does the app's own functionality need them, or did
an SDK's manifest fragment contribute them? The manifest merger silently unions permissions from
every AAR, which is how apps end up requesting things their developers never asked for.

> **Pentester's Note**
> Count the providers and say the number out loud to the client. Four here; ten to thirty is normal
> in a large consumer app. Each one is a vendor whose code runs *before the app's own code does*.
> That sentence has restructured more third-party risk conversations than any CVE I have ever
> reported.

---

## 07 — runtime code loading

```text
  base.apk!classes3.dex
      14 Ldalvik/system/DexClassLoader
       3 Ljava/lang/System;->load
```

**Proves.** The loading APIs are referenced in the DEX.

**Does not prove.** Anything at all, on its own. Play Feature Delivery, WebView, and several
perfectly ordinary libraries reference `DexClassLoader`. A reference is not a call, and a call is
not a call *with attacker-influenced bytes*.

**Next.** Find the call sites and answer one question for each: **where do the bytes come from?**
An asset decrypted at runtime, a file downloaded over HTTP, or a path in external storage are three
different severities, and only the source distinguishes them. Confirm dynamically by watching
`android_dlopen_ext` and by sweeping `/proc/<pid>/maps` for executable mappings outside `/data/app`.

---

## 08 — the fingerprint pass, and how to write the answer down

```text
  OkHttp
    version : 4.9.3
    constrains the version : T1 version banner, T2 class prefix
    confidence: high -- the version is constrained by more than one
                independent technique

  OpenSSL
    version : 1.1.1k
    constrains the version : T1 version banner
    confirms presence only : T3 symbol family
    confidence: medium -- ONE technique constrains the version.
```

The difference between those two entries is the entire discipline of this chapter.

**OkHttp** has two independent signals agreeing: a `okhttp/4.9.3` User-Agent constant in the DEX, and
a class set that is fully contained in the 4.9.3 release and in no smaller one. Two techniques that
would have to be forged consistently. Write it down as a version.

**OpenSSL** has one string. It is probably right — but "probably right" is a different sentence from
the one you are about to put your name on, and the fix costs ten minutes: check whether the symbol
set matches that era, and whether the `NEEDED` list is consistent with a static link.

### The row this all produces

| Library | Version (confidence) | Ring | Purpose | Permissions added | Endpoints | Known issues | Rating | Recommendation |
|---|---|---|---|---|---|---|---|---|
| OkHttp | 4.9.3 (high — banner + contained class set) | Bundled | HTTP client | none | app's own API | none for this version | Info | Keep current |
| Bundled OpenSSL in `libcore.so` | 1.1.1k (medium — banner only) | Bundled | TLS in the native core | none | — | Advisories published after this release apply; reachability **not confirmed** | Medium | Rebuild against a current release; prefer platform TLS |
| Metriqa SDK | unknown (analytics) | Bundled | Analytics | `ACCESS_COARSE_LOCATION`, `AD_ID` | to be determined | — | Pending | Complete the data-collection audit before rating |

Note the third row. "Pending" is an honest cell. An inventory that reports what it does not yet know
is worth more than one that guesses, because the client can act on the first and cannot trust the
second.

---

## The four sentences this document exists to teach

1. **A file is not a process.** Everything above is a claim about bytes on disk. Reachability is a
   different question and needs a running app.
2. **A name is not an identity.** Package prefixes, `.so` filenames and exported symbols are strings
   the author chose.
3. **A version is not a finding.** See [`../faq.md`](../faq.md) on why an outdated library is not
   automatically one — reachability and data sensitivity decide that.
4. **One signal is a lead; two are an answer.** Say which ones you matched, every time.

---

## Related

| File | Why |
|---|---|
| [`../scripts/lib-inventory.sh`](../scripts/lib-inventory.sh) | Produces sections 00–08 |
| [`../scripts/lib-fingerprint.py`](../scripts/lib-fingerprint.py) | Produces the evidence and conclusions blocks |
| [`../labs/lab-01-library-inventory.md`](../labs/lab-01-library-inventory.md) | Build one of these yourself, by hand first |
| [`../labs/lab-02-version-fingerprint.md`](../labs/lab-02-version-fingerprint.md) | Defend each version with its signal |
| [`../README.md`](../README.md) | Section 8.1 for the methodology, 3.7 for the six techniques |
