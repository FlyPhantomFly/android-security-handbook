# 55 — MobSF: references

Annotated. Every entry says what it is *for*, and — where it matters — what it will not tell you.

> **⚠️ Note on provenance.** MobSF was **not run** while this chapter was written; see
> [README §1.6](../README.md#16-installation-reality--mobsf-was-not-run-here). Where this chapter
> describes MobSF's behaviour it is describing the project's own documentation and source layout,
> labelled `EXPECTED SHAPE`. Where it quotes a number, that number came from a tool that really ran
> on this machine, labelled `MEASURED`. **The most valuable reference in this file is the last one:
> your own instance's `/api_docs` page and rule catalogue.**

---

## 1. MobSF itself

| Resource | URL | What it is for | What it will not tell you |
|---|---|---|---|
| **Source repository** | <https://github.com/MobSF/Mobile-Security-Framework-MobSF> | The ground truth. Read `mobsf/StaticAnalyzer/views/android/` | Nothing about your specific version unless you check out the right tag |
| **Rule catalogue** | `mobsf/StaticAnalyzer/views/android/rules/` in the checkout | **Read this once and your interpretation of every finding changes permanently.** It is where `severity` and `cvss` are written as literals | — |
| **Documentation** | <https://mobsf.github.io/docs/> | Installation, REST API reference, dynamic-analyser device requirements | It documents the current release; older instances differ |
| **Docker image** | <https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf> | The install route to prefer. Multi-gigabyte — check disk first | — |
| **Your instance's API docs** | `http://127.0.0.1:8000/api_docs` | **The only authoritative endpoint list for the version you are actually using** | — |
| **`static_analyzer.py`** | `mobsf/StaticAnalyzer/views/android/static_analyzer.py` | The orchestrator. Shows the cache check and the fixed one-pass order that makes §5.4's join impossible | — |
| **`manifest_analysis.py`** | `mobsf/StaticAnalyzer/views/android/manifest_analysis.py` | Why manifest findings are independent, and why `component` is sometimes an attribute name | — |
| **`api_middleware.py`** | `mobsf/MobSF/views/api/api_middleware.py` | One static key, string comparison, no scopes. The basis of the operational-security section | — |

> **No line numbers are cited anywhere in this chapter**, deliberately. A line number in someone
> else's fast-moving repository is a fabrication waiting to happen; `find` and `grep` locate a symbol
> in a second and never go stale.

---

## 2. OWASP

| Resource | URL | What it is for | What it will not tell you |
|---|---|---|---|
| **MASVS** | <https://mas.owasp.org/MASVS/> | The control set MobSF tags findings against | **A MASVS tag on a finding means a rule carrying that tag matched — not that the control was tested.** A report claiming MASVS coverage from scanner tags is claiming coverage it does not have |
| **MASTG** | <https://mas.owasp.org/MASTG/> | The *procedures*. Where MobSF gives a lead, MASTG usually gives the test that settles it | It is a testing guide, not a rule set |
| **MASTG test cases** | <https://mas.owasp.org/MASTG/tests/> | The specific "how do I check this" for most categories in the cheatsheet | — |
| **Mobile Top 10** | <https://owasp.org/www-project-mobile-top-10/> | The category labels in MobSF's `owasp-mobile` metadata | It is a category taxonomy, not a severity model |

---

## 3. Tools this chapter tells you to run instead of, or alongside, MobSF

| Tool | URL | Why it is here |
|---|---|---|
| **jadx** | <https://github.com/skylot/jadx> | The decompiler underneath most of MobSF's code analysis. **Count refused methods in the output tree, not the console summary** — 56 measured a 30× gap |
| **apktool** | <https://apktool.org/> | Smali plus fully decoded resources, including `res/xml/` that MobSF summarises |
| **APKiD** | <https://github.com/rednaga/APKiD> | Packer, obfuscator and compiler fingerprints. Narrow by design and excellent within it — the fastest way to learn the report describes a stub |
| **semgrep** | <https://semgrep.dev/> | Syntax-aware rules over decompiled Java. The one tool that genuinely *reduces* false positives rather than reorganising them. Set `severity: INFO` and let stage 7 decide |
| **Frida** | <https://frida.re/> | Settles every question static analysis cannot. See [53-Frida](../../53-Frida/README.md) |
| **`aapt2`, `apksigner`** | Android build-tools | **The platform's own parser and signature verifier.** The tiebreaker whenever two tools disagree about the same bytes |
| **`readelf` / `llvm-readelf`** | binutils, or the NDK's LLVM binutils | The native-symbol check MobSF's binary section does not make: `JNI_OnLoad` present with zero `Java_` exports |

---

## 4. This repository's own tooling, used by this chapter

Nothing here is re-implemented in `55-MobSF/scripts/`. This chapter calls out to the discipline these
embody.

| Script | Chapter | What it answers |
|---|---|---|
| [`manifest-audit.py`](../../32-Manifest/scripts/manifest-audit.py) | 32 | The right validator for every manifest row MobSF emits. Resolves implicit `exported`; prints a `POSITIVE` band and marks rows `UNPROVEN` |
| [`pinning-surface.py`](../../36-CertificatePinning/scripts/pinning-surface.py) | 36 | Four-layer pinning surface with `HIGH`/`MATRL`/`MED`/`LOW` confidence classes. Refutes both directions of a scanner's pinning claim |
| [`pin-attribution.js`](../../36-CertificatePinning/scripts/pin-attribution.js) | 36 | Attributes *why* a handshake failed. "No traffic appeared" has at least six causes |
| [`lib-inventory.sh`](../../17-Libraries/scripts/lib-inventory.sh) | 17 | Dependency inventory with a `readelf → llvm-readelf → objdump → pure-Python` fallback chain that **reports which link answered** |
| [`lib-fingerprint.py`](../../17-Libraries/scripts/lib-fingerprint.py) | 17 | Library versions with confidence — what MASVS-CODE actually asks for, and what MobSF's library list is not |
| [`static-sweep.py`](../../52-StaticAnalysis/scripts/static-sweep.py) | 52 | Aggregation and confidence scoring **with every term printed**. The model this chapter's ranker is built in the image of |
| [`validate-lead.sh`](../../52-StaticAnalysis/scripts/validate-lead.sh) | 52 | Caller closure for reachability, and honest when the frontier explodes |
| [`blindspot-recorder.js`](../../52-StaticAnalysis/scripts/blindspot-recorder.js) | 52 | Records at runtime what the artefact could never show |
| [`dump-strings.py`](../../04-Java/scripts/dump-strings.py) | 04 | Exact literals from the DEX string table, MUTF-8 correct — faster and more accurate than any decompiler for a literals question |

And this chapter's own:

| Script | What it does | What it will not tell you |
|---|---|---|
| [`mobsf-triage.py`](../scripts/mobsf-triage.py) | Drives the REST API over a directory of APKs and emits a **triage ranking** with every weight and rationale printed. Works offline against saved reports | Which app is *vulnerable*. It ranks where to look |
| [`mobsf-validate.py`](../scripts/mobsf-validate.py) | Takes a report plus the artefact; gathers the evidence that would confirm or kill each finding. **Has no `FINDING` verdict** | Whether anything is reachable, or what any of it is worth |

---

## 5. The AOSP paths this chapter cites

Stable file paths. No line numbers.

| Path | Why it matters to a scanner's output |
|---|---|
| `frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java` | The manifest parse MobSF is predicting: implicit `exported`, and `parseClusterPackage` merging splits |
| `frameworks/base/core/java/android/content/pm/PackageParser.java` | The legacy parser, for pre-API-30 behaviour |
| `frameworks/base/libs/androidfw/ResourceTypes.cpp` | `ResStringPool` and `ResXMLParser` — why two tools can read the same AXML bytes differently, which is the basis of every manifest-divergence trick |
| `frameworks/base/include/androidfw/ResourceTypes.h` | The structures behind that |
| `frameworks/base/tools/aapt2/` | The compiler behind `aapt2 dump`, i.e. the platform's own reading of your manifest |
| `art/libdexfile/dex/dex_file.cc` | DEX structure |
| `art/libdexfile/dex/dex_file_verifier.cc` | `CheckHeader` — header fields are *claims* and your tools must bounds-check them too |
| `libcore/dalvik/src/main/java/dalvik/system/DexFile.java` | `openInMemoryDexFile` — where the artefact stops being the program |
| `art/runtime/jni/java_vm_ext.cc` | `JavaVMExt::RegisterNatives` — the native blind spot, in source |
| `art/runtime/class_linker.cc` | `LinkCode` consults the registered map before falling back to `dlsym` |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` | The installed truth that beats any file you decoded |

---

## 6. The measurements this chapter rests on

Each is a number produced in this repository, not a citation of someone else's claim.

| Measurement | Number | Chapter |
|---|---|---|
| Apps with a pinning **surface** vs apps that **pin** | **12 of 14** vs **4 of 14** | [36](../../36-CertificatePinning/README.md) |
| HIGH-band leads rejected on hand inspection, real 17 MB app | **15 of 17 (88%)** | [52](../../52-StaticAnalysis/README.md) |
| High-confidence secret hits against real Chrome data | **132 hits, 132 false positives** | [33](../../33-Storage/README.md) |
| A detector that agreed with its author until its patterns were split | **18/18 → 13/18** | [38](../../38-TamperDetection/README.md) |
| Broadcast surface invisible to any artefact-based tool | **299 of 431 (69%)**, corroborated at **67%** on a different device and API level | [29](../../29-BroadcastReceivers/README.md) |
| jadx under-reporting its own failures | **30×** — console `61`, tree **2,104** refused methods | [56](../../56-JADX/README.md) |
| Apps with **zero** integrity controls in `base.apk` because the code ships in splits | **1 of 18** | [38](../../38-TamperDetection/README.md) |
| Kotlin metadata yielding wholesale name recovery | **0**, across 19 APKs and 316,000+ classes | [42](../../42-R8/README.md) |
| A patched check that provably works against a function nothing calls | inlined by clang | [18](../../18-ARM/README.md) |
| **This chapter:** report items → corroborated → findings | **39 → 17 → 8**, with **2 of 8** originating outside the scan | here |
| **This chapter:** items that were the scorecard restating other sections | **11 of 39 (28%)** | here |

The generalisation all of them support, and the sentence this chapter exists to defend:

> **A sweep produces leads, not findings — and confidence ranking is not severity ranking.**

---

## 7. Related chapters

| Chapter | Relationship to this one |
|---|---|
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | **The method MobSF automates.** Owns the eight stages, triage, validation and honest severity. This chapter is "that method, applied to somebody else's stage 5" |
| [32-Manifest](../../32-Manifest/README.md) | Owns manifest semantics. Every manifest row MobSF emits is validated here — and 32 warns explicitly that automated manifest analysis must be validated |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Owns pinning. The 12-of-14 measurement is this chapter's flagship worked example, and 36 asks this chapter for *"why its 'app uses certificate pinning' finding is usually wrong, and how to say so"* |
| [10-APK-Internals](../../10-APK-Internals/README.md) | The container, the signing block, and AXML parser divergence |
| [17-Libraries](../../17-Libraries/README.md) | Dependency inventory **with versions**. MobSF's library list is a starting inventory, not MASVS-CODE compliance |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) | The runtime half. The liveness problem and the denominator problem both apply directly to MobSF's dynamic analyser |
| [56-JADX](../../56-JADX/README.md) | The decompiler underneath. Also the source of "count the tree, not the summary" |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What obfuscation does to name-based rules; packers, and why a report on a packed app describes the stub |
| [42-R8](../../42-R8/README.md) | Why type names vanish and string literals do not — the mechanism behind §5.3 |
| [43-WebView](../../43-WebView/README.md) | The bridge finding used as this chapter's worked cross-section join |
| [34-Cryptography](../../34-Cryptography/README.md) | Rates the ECB and DES rows, and owns the KDF defect no MobSF rule reports |
| [27-ContentProviders](../../27-ContentProviders/README.md) | What an exported-provider finding actually requires |
| [23-Permissions](../../23-Permissions/README.md) | Protection levels — the check MobSF explicitly declines to make |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | The 69% of the broadcast surface no artefact-based tool sees |
| [16-JNI](../../16-JNI/README.md) | `RegisterNatives`; why an empty symbol table proves nothing |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Splits, signature-lineage handling, and the self-catching detector |
| [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | The two false positives the network-security section reliably produces |
| [33-Storage](../../33-Storage/README.md) | 132/132, and what a backup finding must name |
| [35-SSL](../../35-SSL/README.md) | The trust-store posture check before any interception claim |
| [37-RootDetection](../../37-RootDetection/README.md) | Presence of a check is not enforcement |
| [53-Frida](../../53-Frida/README.md) | Settling what static analysis cannot |
| [60-ADB](../../60-ADB/README.md) | Why an `adb shell` result does not prove app reachability |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS-CODE, and what a MASVS tag does and does not mean |
| [80-Appendix](../../80-Appendix/README.md) | The report template and severity rubric this chapter deliberately does not restage |
| [79-Glossary](../../79-Glossary/README.md) | Terms used here and defined once |

Chapter 54 (Objection) wraps many of the runtime checks this chapter hands to Frida.
[39-EmulatorDetection](../../39-EmulatorDetection/README.md) and
[69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) are also referenced in the text and are now
written. `73-Labs` and `76-CheatSheets` are referenced by name and are scaffolded only.
