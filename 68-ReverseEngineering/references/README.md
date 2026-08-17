# 68 — Reverse Engineering · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

Chapter: [../README.md](../README.md)

---

## Normative specification — what "correct" means at the boundary

| Link / AOSP path | Contains |
|---|---|
| Java Native Interface Specification — "Registering Native Methods" | The `RegisterNatives` contract and the `JNINativeMethod` triple `{name, signature, fnPtr}`. The reason §3.8's measurement is possible at all |
| JNI Specification — "Resolving Native Method Names" | The mangling rules: short form, long form, and the escape set. `$` becomes `_00024` — `_0` plus **four** hex digits |
| `art/runtime/jni/jni_internal.cc` | ART's `RegisterNatives`. Hook this one function and you catch every explicit binding in the process |
| `art/runtime/jni/java_vm_ext.cc` | `JavaVMExt::FindCodeForNativeMethod` — discovery binding. The only path a symbol-based static tool can see |
| `art/runtime/art_method.h` | `ArtMethod` and its entry points. Why "what the DEX says" and "what will run if you call it now" are different facts |
| `art/runtime/native/dalvik_system_DexFile.cc` | Where DEX data — including data that was never a file — becomes a `DexFile` |
| `libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java` | The `DexPathList`. The provenance question of §7.4 |
| `libcore/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java` | A loader with no file behind it. The canonical generator of the runtime-only pile |
| Dalvik bytecode reference | Tier 4 for the managed side |
| Arm Architecture Reference Manual (A-profile) | Tier 4 for the native side. `adrp`, `ldrb`, `cmp`, `b.ne` — the four instructions §6.1's gate is made of |

> **AOSP file paths are stable and safe to cite; line numbers are not.** Name the function. Every
> path above was chosen because it survives across releases; none of them is quoted with a line
> number anywhere in this chapter.

---

## The tools, and which question each answers fastest

| Link | Reach for it when |
|---|---|
| `skylot/jadx` | You want a readable hypothesis about managed code fast — and you remember it is tier 3 |
| `smali`/`baksmali`, `dexdump` | You need tier 4 on the managed side, or jadx refused the method |
| Ghidra | You need to read native code you cannot run, or you need `JNIEnv` typed properly |
| `llvm-objdump`, `llvm-nm`, `llvm-readelf` (NDK) | Native triage in seconds: exports, sizes, call targets, sections |
| Frida | You need tier 5 or 6 — what ran, with what values, and what changes if you alter it |
| `apktool` | You need resources and the manifest as text, or you intend to rebuild |
| `aapt2` | Identity and badging in one line: package, version, ABIs |
| `apksigner` | Signer identity, before you report on an artefact you assumed was the vendor's |

> **The tracker is a first-class reference.** Every one of these tools has a public issue tracker
> documenting what it gets wrong. When your output disagrees with the binary, search there before
> concluding anything about the target — and if it is genuinely new, a minimal reproducer filed
> upstream is worth more than a blog post.

---

## Standards

| Identifier | Relevance |
|---|---|
| **MASVS-RESILIENCE-1** | Platform-integrity validation — the controls in `37-RootDetection` and `38-TamperDetection` that this activity meets |
| **MASVS-RESILIENCE-2** | Anti-tampering and anti-static-analysis. `40-Obfuscation` owns the techniques; §3.13 owns what they do to your *method* |
| **MASVS-RESILIENCE-3** | Anti-dynamic-analysis. `67-BypassingProtections` owns the response |
| **MASVS-RESILIENCE-4** | Difficulty of comprehension — the only control this chapter's activity is directly measured against |
| **MASTG** reverse-engineering procedures | The MASTG describes *procedures*; §3 is the framework for choosing among them |
| **OWASP Mobile Top 10 — M7, Insufficient Binary Protections** | Where "the app can be decompiled" belongs, and why it is not a finding on its own |
| **RFC 2606** | Reserves `.invalid`. Every endpoint in this chapter's code uses it, so nothing can resolve |

> **The resilience trap, stated once.** MASVS-RESILIENCE controls are explicitly defence in depth
> against a client-side attacker, and the standard says so. A resilience finding never substitutes
> for a MASVS-AUTH or MASVS-CRYPTO one. "The app can be reverse engineered" is a property of every
> application ever shipped. What you report is what the reverse engineering *let you do*.

---

## This chapter's own tooling

| File | Open it when |
|---|---|
| [`../scripts/re-journal.py`](../scripts/re-journal.py) | You are starting an investigation. Refuses a hypothesis with no refutation test, a verdict with no observation, and a question closed as answered on one source. `selftest` verifies all of that |
| [`../scripts/boundary-map.py`](../scripts/boundary-map.py) | You need the static managed/native map for an APK — or `--explain`, for the four causes of an unresolved method it deliberately will not choose between |
| [`../scripts/boundary-confirm.js`](../scripts/boundary-confirm.js) | You need the runtime truth: every `RegisterNatives` binding, with the module each function pointer lands in |
| [`../scripts/dataflow-watch.js`](../scripts/dataflow-watch.js) | Control flow will not connect a producer to a consumer, because the connection is a memory address |
| [`../examples/libinvestigate.c`](../examples/libinvestigate.c) | After the labs. Four deliberate traps, and an honest note on the two ways the compiler defeated its own obfuscation |
| [`../examples/investigate-main.c`](../examples/investigate-main.c) | You want to see the decoupled-control shape in twelve lines |
| [`../examples/build.sh`](../examples/build.sh) | Building the fixture out of tree. It also prints what the build *actually produced*, which is the point |
| [`../examples/worked-journal.md`](../examples/worked-journal.md) | You want to see what an investigation really looks like. Nine of its eighteen entries are failures |

---

## Tooling from other chapters that this method calls

| File | From | Called for |
|---|---|---|
| `52-StaticAnalysis/scripts/static-sweep.py` | [52](../../52-StaticAnalysis/README.md) | The hit → lead funnel §3.4 delegates to |
| `52-StaticAnalysis/scripts/validate-lead.sh` | [52](../../52-StaticAnalysis/README.md) | Stage-7 validation on a single lead |
| `51-DynamicAnalysis/scripts/blindspot-recorder.js` | [51](../../51-DynamicAnalysis/README.md) | The structural residue of §3.17, measured rather than asserted |
| `40-Obfuscation/scripts/frida-dexdump-lite.js` | [40](../../40-Obfuscation/README.md) | Recovering a DEX that was never a file. Validates candidates against header invariants instead of carving on magic bytes |
| `40-Obfuscation/scripts/frida-classloader-dump.js` | [40](../../40-Obfuscation/README.md) | Provenance: which loader holds what |
| `53-Frida/scripts/sign-oracle.js` | [53](../../53-Frida/README.md) | The prediction-level answer of §3.15 — borrow the routine instead of reproducing it |
| `12-DEX-Internals/scripts/dex-diff.py` | [12](../../12-DEX-Internals/README.md) | Comparing two builds of the same app |
| `06-Android-Architecture/scripts/device-posture.sh` | [06](../../06-Android-Architecture/README.md) | Recording the device's posture so your own rooting is methodology, not a finding |

---

## Related chapters

### Prerequisites — the instruments this chapter assumes

| Chapter | Why |
|---|---|
| [10 — APK Internals](../../10-APK-Internals/README.md) | What you are acquiring in §3.2 |
| [12 — DEX Internals](../../12-DEX-Internals/README.md) | The encoding tier 4 reads on the managed side |
| [13 — ART](../../13-ART/README.md) | **13 owns the runtime.** This chapter owns what `ArtMethod`'s mutability implies about evidence |
| [14 — Dalvik](../../14-Dalvik/README.md) | **14 owns Smali syntax.** §6.2 owns only the reading *strategy* |
| [15 — Native Code](../../15-Native-Code/README.md) · [16 — JNI](../../16-JNI/README.md) · [18 — ARM](../../18-ARM/README.md) | The native side of §3.8 and §6.1. **16 owns the mangling rules**; §3.8 owns what to do when they fail |

### The two analysis modes this chapter runs at once

| Chapter | Boundary |
|---|---|
| [51 — Dynamic Analysis](../../51-DynamicAnalysis/README.md) | **51 owns the runtime pipeline, correlation and coverage.** This chapter owns choosing which runtime experiment settles a hypothesis |
| [52 — Static Analysis](../../52-StaticAnalysis/README.md) | **52 owns the static pipeline and the hit → lead → finding funnel.** This chapter owns the funnel that runs *both* branches and diffs them into three piles |

### The tools — instruments, not method

| Chapter | Boundary |
|---|---|
| [53 — Frida](../../53-Frida/README.md) | **53 owns the engine**, and the four reasons a hook silently does not fire |
| [54 — Objection](../../54-Objection/README.md) | **54 owns the envelope of a canned tool.** Its "one of five" measurement is §3.10's scope error in the wild |
| [55 — MobSF](../../55-MobSF/README.md) | **55 owns reading a scanner report as a queue of leads** |
| [56 — JADX](../../56-JADX/README.md) | **56 owns decompilation as reconstruction, and the five checks before absence is evidence.** Cited throughout this chapter and never restated |
| [57 — Ghidra](../../57-Ghidra/README.md) | **57 owns native decompilation** and names this chapter a prerequisite. §3.6 is where its "you will read three functions" gets chosen |
| [65 — Hooking](../../65-Hooking/README.md) | **65 owns what a hook physically is** — which byte, which field, which pointer |

### What has been done to the code before you arrived

| Chapter | Boundary |
|---|---|
| [40 — Obfuscation](../../40-Obfuscation/README.md) | **40 owns the techniques and §6.1's nine-phase recovery pipeline.** This chapter is the general method 40 §6.1 specialises; §3.13 covers only what obfuscation does to your *method* |
| [41 — ProGuard](../../41-ProGuard/README.md) · [42 — R8](../../42-R8/README.md) | Why names are not evidence. 42's 19-APK, 316,000-class Kotlin-metadata measurement is what §3.13 quotes instead of the folklore |

### The controls you will meet

| Chapter | Boundary |
|---|---|
| [37 — Root Detection](../../37-RootDetection/README.md) | Its lab 04 defers **data-flow tracking** to this chapter; §7.3 and §9.3 discharge that |
| [38 — Tamper Detection](../../38-TamperDetection/README.md) | **38 owns the controls, 67 owns the bypass.** This chapter owns the investigation either one produces |
| [39 — Emulator Detection](../../39-EmulatorDetection/README.md) | Vantage matters: **~1,062 to root, ~678 to shell, ~638 to app -- properties visible to `shell`, 634 to `untrusted_app`.** Prove reachability from an app, not from the shell |
| [67 — Bypassing Protections](../../67-BypassingProtections/README.md) | **67 owns the bypass methodology, the five seams, and when to stop *hooking*.** §3.14–3.15 own when to stop *understanding* |

### Where findings go

| Chapter | Boundary |
|---|---|
| [47 — Authentication](../../47-Authentication/README.md) | Its `FLAG_SECURE` measurement — a **true-positive rate of zero** for grepping an APK, because `javac` folds `0x2000` — is this chapter's thesis proved by another chapter |
| [69 — Malware Analysis](../../69-MalwareAnalysis/README.md) | Same loop, hostile sample, disposable device. Anti-analysis is *characterised* rather than defeated |
| [70 — Vulnerability Research](../../70-VulnerabilityResearch/README.md) | Consumes §3.8's boundary map as a list of fuzzing entry points |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | Where findings are classified once they are findings |
| [19 — Memory](../../19-Memory/README.md) | Its `volatile`-loop scrubbing argument, arrived at from the opposite direction to §3.9's |

Referenced by directory name when this chapter was completed, and since written — now linked:
[58-IDA](../../58-IDA/README.md), [59-radare2](../../59-radare2/README.md),
[72-RealWorldFindings](../../72-RealWorldFindings/README.md) and
[74-CaseStudies](../../74-CaseStudies/README.md). Still named rather than linked because their
READMEs do not yet exist: `73-Labs`, `76-CheatSheets`, `78-Diagrams`.

---

## Not a link, but the highest-value reference here

The measurements this chapter rests on, with what each one licenses you to say. Quote them **with
their denominators** or not at all.

| Measurement | Figure | What it licenses |
|---|---|---|
| Native boundary, 18 real APKs | **8,140 declared, 1,049 (12.9%) symbol-resolvable** | That symbol lookup answers about one native method in eight — *in `base.apk`, for one ABI, on one device* |
| Chrome 147.0.7727.111, static vs runtime | **323 declared, 6 resolvable, 509 bound** | That the artefact you pulled is not the program. Chrome ships seven APKs |
| `RegisterNatives` trace reproducibility | **78 calls / 509 methods, three identical runs** | That the runtime figure is stable — and that Frida's `-o` file dropped 19 lines, so read the in-process counter |
| jadx refusals on a 17.5 MB APK | **console 61, tree 2,104** | That you count the tree, never the summary |
| Static HIGH band, adjudicated by hand | **15 of 17 rejected** | That confidence ranking is not severity ranking |
| Leak hunter on real Chrome data | **132 hits, 132 false positives** | That a sweep produces leads, not findings |
| Self-signature detector, before and after hardening | **18/18 → 13/18** | That a detector agreeing with every sample is a broken detector |
| Grepping an APK for `FLAG_SECURE` | **true-positive rate 0** | That a correct search can produce a worthless answer |
| Kotlin metadata, 19 APKs / 316k classes | **10 none, one 1,393 empty shells, zero wholesale recovery** | That property names survive structurally, and nothing more |
| Broadcast surface visible statically | **299 of 431 actions (69%) have no manifest receiver** | That your artefact-based tooling is blind to the majority |
| Properties by vantage | **~1,062 to root, ~678 to `shell`, ~638 to `untrusted_app`** | That you prove reachability from an app, not from the shell |
| This chapter's own hypotheses | **7 of 9 refuted** | That most hypotheses dying is what a healthy session looks like |
| This chapter's own call-site grep | **false negative on PLT calls** | That the showcase experiment needs `(@plt)?` and a corroborating listing |

The last row is the one to remember. It is a defect found in advice this chapter had already given,
by turning the chapter's own method on the chapter's own tooling — which is the only way that defect
was ever going to surface.
