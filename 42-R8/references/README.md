# 42 — R8 references

Annotated. Where a claim in the chapter rests on a source, the source is named here with what it was used for.

> **On citation discipline.** R8 is **not** part of AOSP — it is a separate Google project shipped as a build tool inside the Android SDK. There is no `frameworks/base` path for its algorithms, and this chapter does not invent one. AOSP paths below are cited for the *formats and runtime behaviour* R8's output must satisfy, which genuinely do live in the platform tree.

---

## 1. Primary sources — R8 itself

| Source | What it is | Used in this chapter for |
|---|---|---|
| **R8 repository** — `r8.googlesource.com/r8`, mirrored at `github.com/google/r8` | The authoritative implementation. Apache 2.0 | The phase ordering in §2.2, the `mapping.txt` writer's behaviour, `Retrace` as the reference implementation |
| `src/main/java/com/android/tools/r8/R8.java` | Compiler entry point | Confirming that shrinking, optimisation, minification and DEX writing are one pass |
| `.../shaking/Enqueuer.java` | The reachability worklist | §3.1, the root-set-and-transitive-closure model |
| `.../naming/` | Minifier and mapping writer | §3.6 naming scheme, §3.7 mapping format |
| `.../retrace/` | `Retrace` | The ground truth that `scripts/mapping-reader.py` was diffed against |
| `.../kotlin/` | The Kotlin metadata rewriter | §3.10.3 — the rewriter updates what it has rename mappings for, which is why properties survive |
| **R8 issue tracker** — `issuetracker.google.com`, component "Android Public Tracker > App Development > Shrinker (R8)" | Bug reports and behaviour clarifications | Where to check whether a behaviour you observe is intended, before reporting it as a finding |

---

## 2. Official Android documentation

| Source | Used for |
|---|---|
| **"Shrink, obfuscate, and optimize your app"** — `developer.android.com/build/shrink-code` | The `minifyEnabled` / `isMinifyEnabled` surface, `android.enableR8.fullMode`, and the documented location of `mapping.txt` and its siblings under `build/outputs/mapping/<variant>/` |
| **Android Gradle Plugin release notes** — `developer.android.com/build/releases/gradle-plugin` | Where R8 became the default shrinker (3.4.0), where the ProGuard option was removed (7.0), and where full mode became the default (8.0) |
| **"Java 8+ API desugaring support"** — `developer.android.com/studio/write/java8-support` | Why desugaring exists and what `--min-api` changes about the output |
| **"Enable multidex"** — `developer.android.com/build/multidex` | The 65,536 method-reference limit that makes shrinking load-bearing rather than cosmetic |
| **Android Studio "Retrace"/deobfuscation docs** | The intended workflow for `mapping.txt` — useful context for arguing what its *un*intended distribution means |

---

## 3. Kotlin metadata — the algorithms this chapter ports

The extractor in `scripts/kotlin-metadata-recover.py` is a **port of these files, not a guess at the format**. Each is worth citing precisely because getting any one of them slightly wrong produces plausible-looking wrong names.

| Source (in `github.com/JetBrains/kotlin`) | Defines |
|---|---|
| `.../metadata/jvm/deserialization/BitEncoding.java` | `decodeBytes`, `decode7to8`, `addModuloByte`, and the `(char) -1` 8-to-7 mode marker |
| `.../metadata/jvm/deserialization/utfEncoding.kt` | `UTF8_MODE_MARKER` (`U+0000`), `bytesToStrings`, `stringsToBytes` — the modern default encoding |
| `.../metadata/jvm/deserialization/JvmNameResolverBase.kt` | `getString`, the 44-entry `PREDEFINED_STRINGS` list, and the three record operations (`NONE`, `INTERNAL_TO_CLASS_ID`, `DESC_TO_CLASS_ID`) |
| `.../metadata/jvm/deserialization/JvmNameResolver.kt` | Record range expansion |
| `.../metadata/jvm/deserialization/JvmProtoBufUtil.kt` | `readClassDataFrom` — establishes that `d1` is a length-delimited `StringTableTypes` followed by a `Class` |
| `core/metadata/src/metadata.proto` | `Class.fq_name = 3`, `Function.name = 2`, `Property.name = 2`, `Class.enum_entry = 13` |
| `core/metadata.jvm/src/jvm_metadata.proto` | `StringTableTypes`, `JvmMethodSignature`, `JvmPropertySignature`, and extension fields 100/101 |
| **`kotlinx-metadata-jvm`** — `github.com/JetBrains/kotlin`, `libraries/kotlinx-metadata` | The supported library for reading this data on the JVM. Use it where a JVM dependency is acceptable; this chapter ships a dependency-free Python decoder because the field use case is a jump box with nothing installed |

---

## 4. DEX format and the runtime

| Source | Used for |
|---|---|
| **"Dalvik Executable format"** — `source.android.com/docs/core/runtime/dex-format` | `annotations_directory_item`, `annotation_set_item`, `annotation_item`, `encoded_annotation`, `encoded_value`, and MUTF-8 string encoding — everything the extractor walks |
| `art/libdexfile/dex/dex_file.h`, `dex_file_structs.h` | The on-disk table layouts (`ClassDef`, `MethodId`, `StringId`) that both chapter scripts parse |
| `art/libdexfile/dex/modifiers.h` | `kAccSynthetic` (`0x1000`) — the authoritative synthetic marker, as distinct from name-based heuristics |
| `art/libdexfile/dex/dex_file_verifier.cc` | Load-time structural validation — the constraints R8's writer must satisfy |
| `art/runtime/dex/dex_file_annotations.cc` | How annotations are actually retrieved at runtime; the reason `@kotlin.Metadata` is statically readable |
| `libcore/ojluni/src/main/java/java/lang/Class.java` | `getAnnotation` / `getDeclaredAnnotations`, the public API Kotlin reflection calls |

---

## 5. Standards

| Identifier | Content | Relevance |
|---|---|---|
| **MASVS-RESILIENCE-3** | Anti-tampering and obfuscation appropriate to the threat model | The control `minifyEnabled true` with reviewed rules implements |
| **MASVS-RESILIENCE-4** | Measures that impede comprehension | Identifier renaming, inlining, class merging |
| **MASVS-CODE-4** | Release-mode build with appropriate settings | `minifyEnabled`, `debuggable false`, no mapping file shipped |
| **OWASP MASTG**, resilience testing group | Procedures for determining whether and how far an app is obfuscated | The measurement discipline in §8.4 — measure the app's own package, not the APK average |
| **OWASP MASVS v2 overview** — `mas.owasp.org` | The framing that resilience controls are graduated and threat-model-dependent | The severity argument in §5.7: resilience is not pass/fail, which is why "not obfuscated" is not automatically a finding |

> No CVE is cited in this chapter. Obfuscation weaknesses and mapping-file disclosures are configuration and process failures, not memory-safety or logic vulnerabilities, and they are not assigned CVE identifiers. Inventing one would be worse than citing none.

---

## 6. Talks and background reading

| Item | Why it is worth your time |
|---|---|
| **Google I/O and Android Dev Summit sessions on R8 and app size** (Android Developers channel) | The Android tools team explaining the shrinking and optimisation model in their own terms — particularly useful for understanding *why* full mode reads rules narrowly |
| **The ProGuard manual** (Guardsquare) | Still the clearest exposition of the keep-rules language R8 inherited. Chapter 41 owns this material; read the manual when you need rule syntax rather than R8 semantics |
| **Guardsquare's DexGuard material** | Vendor documentation, so read it critically — but it is explicit about what R8 does *not* provide (string encryption, control-flow obfuscation), which is exactly the §6.4 boundary |

---

## 7. What in this chapter was measured, not cited

Recorded separately so a later reader can tell evidence from documentation. All of it is reproducible with `examples/build-r8-demo.sh` and `examples/build-ctf.sh`.

| Claim | How it was established |
|---|---|
| R8 8.6.2-dev lives in `build-tools/35.0.1/lib/d8.jar`; `D8` and `R8` share a build hash | `--version` on both main classes |
| Full mode output 5,324 bytes vs compat 13,956 from identical input | Four R8 runs over one Kotlin source |
| Full mode: 9 classes in the DEX, 4 of them R8-invented, from 11 declared source types | `dexdump -f` plus the mapping file |
| R8 strips `kotlin.Metadata` by default in **both** modes | Two builds with baseline rules; annotation absent from the DEX string table |
| `-keepattributes *Annotation*` does **not** preserve it | Compat build with that directive present; annotation still absent |
| When `kotlin.Metadata` is kept and classes are renamed, R8 **rewrites** the payload | Two builds with `-keep class kotlin.Metadata` + `-keep,allowobfuscation`; class and function names came back obfuscated |
| **Kotlin property names survive that rewriting** | Same builds: `subscriberId`, `hardwareId`, `auditTrail`, `PEPPER`, `VAULT_FORMAT_VERSION` recovered with their renamed JVM field and getter |
| Decoder correctness | Decoded `kotlin.Metadata`'s own class, recovering `data1`/`data2` behind getters `d1()`/`d2()`; then **zero decode failures across 19 APKs and 316,000+ classes** |
| `k=3` payload is a bare `ProtoBuf.Function`; `k=4` `d1` is unencoded plain part names | Both found as decode failures on real APKs and fixed |
| The empty-shell state exists | One corpus app: 1,393 classes with the annotation and every element absent |
| Corpus distribution: 10 of 19 APKs had no metadata; 0 yielded wholesale recovery | The census in §5.6 |
| Best-case real recovery: 87 property + 24 function names across 132 renamed classes | The anonymised enterprise app in §9 Example 4 |
| `scripts/mapping-reader.py` matches R8's `Retrace` byte-for-byte | `diff` against `com.android.tools.r8.retrace.Retrace` on two traces, including a 4-frame-to-12-frame inline expansion |
| An inlined frame's source file comes from the owner's entry, falling back to `<SimpleName>.java` | Derived by diffing against `Retrace`; not documented anywhere located |
| Device | `i9000S`, Android 13, API 33, **unrooted, no `frida-server`** — `adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk` |

---

## 8. Related chapters

| Chapter | Owns | This chapter's boundary with it |
|---|---|---|
| [40-Obfuscation](../../40-Obfuscation/README.md) | Obfuscation as a subject: the technique taxonomy, string encryption, control-flow flattening, packers, the deobfuscation methodology | 40 cites this chapter for `kotlin.Metadata` and for R8's synthetic artefacts. §5.6 here offers a measured refinement of 40's "frequently not stripped … wholesale" claim |
| [41-ProGuard](../../41-ProGuard/README.md) | The ProGuard lineage and the `-keep` **rules language** | This chapter uses keep rules and tabulates their *effects* on R8's phases; it does not teach the syntax. Referenced by name rather than by link because the file does not exist yet |
| [56-JADX](../../56-JADX/README.md) | Reading decompiled output; loading `mapping.txt` into jadx (`-Prename-mappings.format=PROGUARD_FILE`); the `kotlin-metadata` plugin; the artefact table in its §6.1 | 56 owns what your decompiler does with a mapping; this chapter owns the file format and what it discloses before you load it anywhere |
| [05-Kotlin](../../05-Kotlin/README.md) | Kotlin compilation artefacts and the `@Metadata` annotation's structure, including the `d1`/`d2` split and a `d2` grep; a Frida runtime dumper | 05 owns what the annotation *is*; this chapter owns **what R8 does to it** and ships a decoder for `d1` |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The DEX container, `ACC_SYNTHETIC`, `source_file_idx`, `annotations_directory_item` | 12 owns the format and the flag; this chapter owns the R8 **naming schemes** for the classes that flag marks |
| [04-Java](../../04-Java/README.md) | `javac`'s own synthetic members, including `access$000` bridges | Cited in the synthetic decoder table to separate javac's output from R8's |
| [10-APK-Internals](../../10-APK-Internals/README.md) | The APK container | The archive searched in §8.2 |
| [08-Build-System](../../08-Build-System/README.md) | Gradle and the Android build | Where AGP invokes R8, and where `build/outputs/mapping/` comes from |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Static-analysis methodology | This chapter supplies the R8-specific instruments for it |
| [53-Frida](../../53-Frida/README.md) | Frida | §7 applies it to inlined and renamed code, and explains why name-based hooks fail silently |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | Defeating runtime protections | Obfuscation is the static-analysis counterpart |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The MASVS/MASTG mapping | The framing used in §5.2 and §5.7 |
| [79-Glossary](../../79-Glossary/README.md) | Terminology | Definitions used without restating them |

---

## 9. Chapter files

| File | Contents |
|---|---|
| [`../README.md`](../README.md) | The chapter, 14 sections |
| [`../cheatsheet.md`](../cheatsheet.md) | The `mapping.txt` grammar and the synthetic-name decoder table |
| [`../mindmap.md`](../mindmap.md) | One Mermaid map of the whole chapter |
| [`../faq.md`](../faq.md) | 23 questions, including the dumb ones |
| [`../labs/lab-01-build-and-read-mapping.md`](../labs/lab-01-build-and-read-mapping.md) | Build with R8; read every `mapping.txt` construct; retrace by hand |
| [`../labs/lab-02-synthetic-safari.md`](../labs/lab-02-synthetic-safari.md) | Classify every compiler-generated construct in a real APK; measure coverage honestly |
| [`../labs/lab-03-metadata-recovery.md`](../labs/lab-03-metadata-recovery.md) | Recover original names from `kotlin.Metadata`; measure strip vs rewrite vs leak |
| [`../labs/lab-04-ctf-the-leaked-key.md`](../labs/lab-04-ctf-the-leaked-key.md) | **CTF.** Three flag segments, three techniques, one engagement write-up |
| [`../scripts/kotlin-metadata-recover.py`](../scripts/kotlin-metadata-recover.py) | Pure-Python `@kotlin.Metadata` decoder: DEX parser, BitEncoding, protobuf, name resolver, rewrite verdict |
| [`../scripts/mapping-reader.py`](../scripts/mapping-reader.py) | Pure-Python `mapping.txt` reader, retracer (inline chains included), disclosure reporter, and reverse lookup |
| [`../examples/LicenceVault.kt`](../examples/LicenceVault.kt) | The Kotlin source every measurement was made against |
| [`../examples/build-r8-demo.sh`](../examples/build-r8-demo.sh) | Builds it four ways and reproduces the chapter's central table |
| [`../examples/rules-baseline.pro`](../examples/rules-baseline.pro) · [`../examples/rules-keep-metadata.pro`](../examples/rules-keep-metadata.pro) | The two rule sets those builds compare |
| [`../examples/mapping-fullmode.txt`](../examples/mapping-fullmode.txt) · [`../examples/mapping-keepmetadata.txt`](../examples/mapping-keepmetadata.txt) | Real R8 output, not illustrations |
| [`../examples/recovered-names.txt`](../examples/recovered-names.txt) | What the extractor got back from each build |
| [`../examples/CtfVaultGuardian.kt`](../examples/CtfVaultGuardian.kt) · [`../examples/rules-ctf.pro`](../examples/rules-ctf.pro) · [`../examples/build-ctf.sh`](../examples/build-ctf.sh) | The lab-04 challenge and its build |
