# 41 — ProGuard — references

Annotated. Every entry says what it is *for*, not just what it is. Ordered by how often you will
actually open it.

Where a URL is given it is a stable landing page rather than a deep link, because vendor
documentation is reorganised frequently and a broken deep link is worse than a search.

---

## The two documents you will open most

| Source | Why |
|---|---|
| **ProGuard manual — Usage** · `https://www.guardsquare.com/manual/configuration/usage` | The complete directive reference and the full class-specification grammar. This is the authority for the wildcard semantics in [cheatsheet.md §3](../cheatsheet.md), including the documented special case that the class name `*` matches every class irrespective of package. Read it once, cover to cover; it is shorter than you expect |
| **ProGuard manual — Examples** · `https://www.guardsquare.com/manual/configuration/examples` | The canonical rules for reflection, serialisation, native methods, enums, `Parcelable` and resource bundles. Most real Android rules files are descended from this page, including Google's own defaults. Reading it explains *why* your project's file looks the way it does |

---

## Android / AGP documentation

| Source | Why |
|---|---|
| **Shrink, obfuscate, and optimize your app** · `https://developer.android.com/build/shrink-code` | The AGP side: `minifyEnabled`, `shrinkResources`, `proguardFiles`, `consumerProguardFiles`, `getDefaultProguardFile`, and where the four build outputs land. Also the current statement of what R8 does by default |
| **Decode an obfuscated stack trace** · `https://developer.android.com/studio/build/shrink-code#decode-stack-trace` | `retrace`, and the Android Studio integration. The tool ships inside `build-tools/<ver>/lib/d8.jar` as `com.android.tools.r8.retrace.Retrace` |
| **AGP release notes and the R8 full-mode migration guidance** · `https://developer.android.com/build/releases/gradle-plugin` | The authoritative record of the AGP 8 default change. The behaviour that breaks builds is `-keep class Foo` no longer implying `Foo`'s default constructor |
| **`@Keep` (androidx.annotation)** · `https://developer.android.com/reference/androidx/annotation/Keep` | Worth reading alongside [faq.md #19](../faq.md): `@Keep` is implemented as a keep rule in AGP's default configuration, not as a compiler feature |

---

## Source

| Source | Why |
|---|---|
| **R8** · `https://r8.googlesource.com/r8` | The code that actually reads your `proguard-rules.pro`. Everything relevant to this chapter is in `src/main/java/com/android/tools/r8/shaking/`: the configuration parser, the keep-rule model, the root-set builder, the enqueuer, the tree pruner and the minifiers. Class names are stable across releases; line numbers are not, so do not cite them |
| **ProGuard** · `https://github.com/Guardsquare/proguard` | The original. Its architecture is a visitor pipeline over a class pool, which is why its four phases are cleanly separable and R8's are not — and why `-optimizations`, a filter over ProGuard's individual optimisation visitors, has no meaning in R8. The module layout has changed between major versions; navigate by package name rather than by path |
| **AOSP** — `build/make/core/proguard.flags`, `build/make/core/proguard_basic_keeps.flags` | The platform's own rules. `proguard_basic_keeps.flags` is the shortest defensible Android rules file in existence, written by people whose code has to survive on every device. Read it as a model |
| **AOSP** — Soong's Java support under `build/soong/java/` | Where the `optimize: { enabled, shrink, optimize, obfuscate, proguard_flags_files }` block in an `Android.bp` is handled.the platform separates the four phases explicitly where Gradle gives you one boolean — and that `obfuscate: false` is a common and correct platform choice, which is why the system apps on your device are shrunk but readable |
| **DEX format** · `https://source.android.com/docs/core/runtime/dex-format` | Needed to read `scripts/what-survived.py`, which parses the index tables directly. [12-DEX-Internals](../../12-DEX-Internals/README.md) covers it properly |

---

## OWASP

| Identifier | Why |
|---|---|
| **MASVS-RESILIENCE** | The category containing anti-reversing requirements. Its own documentation frames it as defence-in-depth, applicable only where the threat model includes a hostile user — which is the sentence to quote when a client asks why obfuscation is a Low and not a High |
| **MASVS-RESILIENCE-3** (impede comprehension) | The specific requirement that shrinking and renaming address. An over-broad keep is a partial failure of *this* control and of nothing else |
| **MASVS-CODE** | Where shipped dead code, retained debug attributes and `-ignorewarnings` masking a broken dependency belong |
| **MASTG** resilience test procedures | Cited by **name** throughout this chapter rather than by number, deliberately: the numeric MASTG identifiers have been renumbered between versions and a stale number in a report is worse than a description |

---

## Tooling

| Tool | Note |
|---|---|
| **R8 / D8** | Both live in `$ANDROID_HOME/build-tools/<ver>/lib/d8.jar`. There is **no separate `r8.jar`** in the SDK, and **no ProGuard binary at all**. `java -cp .../d8.jar com.android.tools.r8.R8 --help` is the full CLI reference |
| **`com.android.tools.r8.retrace.Retrace`** | De-obfuscates a stack trace with a mapping file. Expands inline frames, so a retraced trace can be longer than the raw one |
| **`dexdump`** | build-tools. `-d` for disassembly. The fastest way to see class descriptors, field names and method names exactly as stored |
| **`aapt2 dump resources` / `dump xmltree` / `dump packagename`** | build-tools. Resource names and the manifest — the two naming layers no shrinker setting touches |
| **jadx** | Reading the decompiled output, applying a recovered mapping (`-Prename-mappings.format=PROGUARD_FILE`), and `--use-source-name-as-class-name-alias`. Owned by [56-JADX](../../56-JADX/README.md) |
| **`strings`** | Still the highest value-per-keystroke tool against an obfuscated app, because renaming never touches a string constant |

---

## This chapter's own artefacts

| File | Purpose |
|---|---|
| [`../scripts/proguard-rules-audit.py`](../scripts/proguard-rules-audit.py) | Reads a rules file and reports, per directive, what it preserves and how broad it is; plus the whole-file findings that come from what is *absent*. Has a `--fail-on` mode for CI |
| [`../scripts/what-survived.py`](../scripts/what-survived.py) | Parses an APK's or DEX's index tables directly and reports the name census, the survivors, which keep rule explains each, the `SourceFile` state, the things renaming never touches, and any build artefact shipped inside the archive |
| [`../scripts/frida-keep-census.js`](../scripts/frida-keep-census.js) | The runtime counterpart: which classes are actually *loaded*, and a shape search for finding a class when you cannot search by name |
| [`../examples/01-overbroad-rules.pro`](../examples/01-overbroad-rules.pro) | A deliberately over-broad rules file, annotated line by line with what each rule costs |
| [`../examples/02-tightened-rules.pro`](../examples/02-tightened-rules.pro) | The same application's genuine requirements, expressed as narrowly as the language allows. Every rule carries "delete this and X breaks" |
| [`../examples/keeplab/`](../examples/keeplab/) | The fixture: five Java classes, a manifest, two resource files, and a build script that builds it **three times** and prints the diff |
| [`../labs/ctf-vault/`](../labs/ctf-vault/) | The CTF challenge: a rules file whose author believed it preserved five things |

---

## Measured on this machine — provenance for the numbers in this chapter

Recorded so that a later reader can tell what was measured from what was documented, and re-measure
rather than trusting a number whose toolchain has moved on.

| | |
|---|---|
| Host | Windows 11, Git Bash |
| SDK | Android SDK build-tools **35.0.1**, platform **android-35** |
| Shrinker | **R8 8.6.2-dev**, extracted from `build-tools/35.0.1/lib/d8.jar` |
| JDK | 24.0.2 |
| Device | **`i9000S`, Android 13 / API 33** — `ro.product.model=i9000S`, `ro.build.version.sdk=33`. **Not rooted, no frida-server** |
| Gradle | **not installed on this machine.** Every build in this chapter drives R8's CLI directly, which is why the fixtures write out the manifest keeps that AGP would generate |
| ProGuard | **not installed, and not available in the Android SDK.** No claim in this chapter about ProGuard's *runtime* behaviour was measured; ProGuard-specific statements come from its manual and are marked as such |

**Measured, not documented:** the three-build diff and every number in it; the identical APK sizes and
their cause; the `SourceFile` behaviour across the three builds; the empty `LicenseValidator` and the
rule that kept its name; the `Class.forName` rewrite and the `getDeclaredField` non-modelling; the
enum unboxing and constant folding; the two real APKs pulled from the device and every figure quoted
from them; both scripts' output on every fixture.

**Documented, not measured:** ProGuard's own behaviour; AGP's task graph and intermediate paths (no
Gradle here); R8's internal class names, which are cited from its public source tree; MASVS
category definitions.

**Written but not executed:** [`../scripts/frida-keep-census.js`](../scripts/frida-keep-census.js).
The attached device has no root and no frida-server, so it was syntax-checked and reviewed but never
run against a process. This is stated in the script's own header as well.

**Third-party apps.** Two APKs were pulled from the test device. `GoogleFeedback.apk` is named
because it is an unmodified Google system app and the observation about it (shrunk, not obfuscated)
is a property of AOSP's build configuration rather than a finding. The second, a 22.8 MB commercial
enterprise application, is **deliberately not named**, and its internal hostnames and vendor
identifiers are redacted, because this repository may be published. Only aggregate figures and the
*shape* of its JNI symbols are quoted.

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [08-Build-System](../../08-Build-System/README.md) | Where `minifyEnabled`, `proguardFiles` and `consumerProguardFiles` live, the full AGP pipeline, and the build outputs directory. Read its §3.15 before this chapter's §3.14 |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Obfuscation as a subject: string encryption, control-flow flattening, packers, native migration, and the deobfuscation methodology. Its §3.1 survivors table is the companion to this chapter's §6.2 |
| `42-R8` | R8 specifically: shrinking and optimisation internals, the `mapping.txt` format in detail, full mode, Kotlin metadata. **This chapter owns the rules language; that one owns the engine.** References to it are forward references by directory name |
| [56-JADX](../../56-JADX/README.md) | Reading the decompiled output, `--deobf` (which does not deobfuscate), `--use-source-name-as-class-name-alias`, and applying a recovered `mapping.txt` |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The DEX index tables that `what-survived.py` parses, the string pool, and the 64K method limit that made shrinking necessary in the first place |
| [10-APK-Internals](../../10-APK-Internals/README.md) | The APK as a ZIP, the signing block whose padding makes three different builds the same file size, and `resources.arsc` |
| [16-JNI](../../16-JNI/README.md) | Why a statically bound native method's symbol is derived from the post-rename class and method names, and why `RegisterNatives` is the counter |
| [17-Libraries](../../17-Libraries/README.md) | Identifying shaded and repackaged libraries — the other half of "whose code is this?" once the names are gone |
| [32-Manifest](../../32-Manifest/README.md) | The component declarations from which AGP generates its keeps |
| [04-Java](../../04-Java/README.md) | Class-file attributes, generic signatures, and reflection — the substrate `-keepattributes` operates on |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | The discipline behind "a sweep produces leads, not findings", which applies directly to the string census in §6.2 |
| [53-Frida](../../53-Frida/README.md) | The runtime side, and the source of the hooking idioms `frida-keep-census.js` builds on |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS-RESILIENCE in context, and how to place a hardening observation in a report without inflating it |
