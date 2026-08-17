# 56 — JADX · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

Chapter: [../README.md](../README.md)

---

## The tool itself

| Link | Open it when |
|---|---|
| https://github.com/skylot/jadx | The project. Start here for anything |
| https://github.com/skylot/jadx/releases | **You need a real CLI distribution.** The Windows `jadx-gui` bundle ships only `jadx.exe` and `lib/jadx-gui-<ver>-all.jar`; that exe answers `--version` and then opens a GUI window for any real invocation. The full distribution has `bin/jadx` and `bin/jadx.bat`. See chapter §1.3 |
| https://github.com/skylot/jadx#readme | The usage summary, and the current option list. Faster than `--help` when you are away from a terminal |
| https://github.com/skylot/jadx/wiki | Plugin documentation, the scripts API, and the `.jadx.kts` project-script format |
| https://github.com/skylot/jadx/blob/master/CHANGELOG.md | **Before you compare output from two jadx versions.** Heuristic changes mean the same input decompiles differently between releases |

## The issue tracker — the known-limitations database

| Link | Open it when |
|---|---|
| https://github.com/skylot/jadx/issues | **Before concluding that jadx is broken.** Search the symptom — "multi-entry loop", "code restructure failed", "wrong code in catch", "type inference failed" — and you will usually find the shape already characterised, often with a workaround |
| https://github.com/skylot/jadx/issues?q=is%3Aissue+label%3Adecompilation | Decompilation-correctness reports specifically. This is where the honest picture of the tool's limits lives |
| https://github.com/skylot/jadx/issues?q=is%3Aissue+is%3Aclosed | Closed issues are more useful than open ones for a limitation you are hitting today: a closed one tells you which release fixed it |

> **This is a first-class reference, not an afterthought.** Chapter §6.6 documents a measured case
> where jadx printed clean, warning-free Java that returned a different value from the bytecode. The
> professional response to a reproducible divergence is a **minimal reproducer filed here** — with an
> explicit statement of what you did *not* establish — rather than a blog post asserting the tool is
> broken. The maintainer can see internal state; you cannot.
>
> jadx's own warning text says `Please report as a decompilation issue!!!` for multi-entry loops. Take
> it literally: it is asking.

## The source, for the parts of chapter §3 and §4 you want to verify

| Path in `skylot/jadx` | Contains |
|---|---|
| `jadx-core/src/main/java/jadx/core/Jadx.java` | **The pass lists.** `getPreDecompilePassesList`, `getRegionsModePasses`, `getSimpleModePasses`, `getFallbackPassesList`. §4.3 prints all four |
| `jadx-core/src/main/java/jadx/core/dex/visitors/` | Every pass. `ConstInlineVisitor`, `AnonymousClassVisitor`, `EnumVisitor`, `InlineMethods`, `DeboxingVisitor` |
| `.../visitors/blocks/` | `BlockSplitter`, `BlockProcessor`, `DominatorTree`, **`FixMultiEntryLoops`** — the pass behind §6.4's refusal |
| `.../visitors/ssa/SSATransform.java` | Undoing `d8`'s register allocation |
| `.../visitors/typeinference/` | `TypeInferenceVisitor`, `FixTypesVisitor`, the `TypeBound*` constraints — why a `char` becomes an `int` |
| `.../visitors/regions/RegionMakerVisitor.java` | Where structure is decided, and where all three failure modes originate |
| `.../visitors/regions/SwitchOverStringVisitor.java` | The string-switch reconstruction of §9.2 |
| `.../visitors/shrink/CodeShrinkVisitor.java` | **§6.6's protagonist.** Folds a definition into its single use |
| `.../visitors/debuginfo/` | `DebugInfoAttachVisitor`, `DebugInfoApplyVisitor` — §3.11 |
| `.../codegen/NameGen.java` | Where `str2`, `cArr` and `iMin` come from |
| `jadx-core/src/main/java/jadx/api/` | `JadxDecompiler`, `JadxArgs`, `JavaClass` — the embedding API of §4.6 |
| `jadx-plugins/` | `jadx-dex-input`, `jadx-java-convert`, `jadx-smali-input`, `jadx-kotlin-metadata`, `jadx-rename-mappings` |

You can read all of it without cloning: chapter §4.1 shows how to decompile jadx's own jar **with
jadx**, which is also the fastest demonstration of the `java-convert` plugin.

## Normative specification — what "correct" means

| Link / AOSP path | Contains |
|---|---|
| https://source.android.com/docs/core/runtime/dalvik-bytecode | **The opcode reference.** Semantics of every instruction. The arbiter when your reading of the Smali and jadx's Java disagree |
| https://source.android.com/docs/core/runtime/instruction-formats | Encoding formats (`21c`, `35c`, `3rc`, `51l`…) |
| https://source.android.com/docs/core/runtime/dex-format | The DEX file format, including `debug_info_item` — the structure §3.11 is entirely about |
| `art/libdexfile/dex/dex_instruction_list.h` | The runtime's own opcode table |
| `art/libdexfile/dex/dex_file.h` | `Header`, `ClassDef`, `CodeItem`, `TryItem` |
| `art/libdexfile/dex/dex_file_verifier.cc` | What the runtime will *accept*. A DEX jadx reads happily may still be rejected here |
| `art/runtime/verifier/method_verifier.cc` | Class-load-time bytecode verification — the second gate a patched APK must pass |
| `dalvik/docs/dalvik-bytecode.html` | The historical normative document, still the one everybody cites |

> AOSP **file paths** are stable across releases and safe to cite. **Line numbers are not** — they
> move every release. Name the function instead.

## The compiler jadx models

| Link | Why it matters here |
|---|---|
| https://developer.android.com/tools/d8 | `d8`. jadx's heuristics are tuned against what it emits — which is exactly why §6.6's hand-written bytecode is where the wheels come off |
| https://developer.android.com/tools/r8 | R8: shrinking, optimisation, renaming. The source of most of what you are reading around |
| https://developer.android.com/build/shrink-code | The Gradle-facing view: `minifyEnabled`, keep rules, and **where `mapping.txt` is written** |
| https://r8.googlesource.com/r8 | R8's source, if you need to know exactly what a transformation does |
| https://docs.oracle.com/javase/specs/jls/se21/html/index.html | The JLS. Consult it when you need to know *why* the compiler emitted something — §6.2's orphan `hashCode()` is a JLS requirement, not a compiler quirk |

## Adjacent tooling

| Link | Reach for it when |
|---|---|
| https://github.com/iBotPeaches/Apktool | **You are patching.** Smali plus decoded resources plus rebuild. jadx output does not recompile; this does |
| https://github.com/google/smali | `smali`/`baksmali`. Use directly when your DEX did not come from an APK — dumped from memory, extracted from a packer, pulled from a VDEX |
| https://developer.android.com/tools/dexdump | `dexdump`. Instruction listings with file offsets. The level at which arguments end |
| https://github.com/pxb1988/dex2jar | The other route: DEX → JAR, then a Java decompiler. Worth having for a second opinion |
| https://github.com/leibnitz27/cfr | CFR — a strong independent Java decompiler. Point it at dex2jar's output when jadx and your reading disagree |
| https://github.com/Konloch/bytecode-viewer | Runs several decompilers side by side. The cheapest antidote to the correlated-blind-spot problem of §10 |
| https://github.com/skylot/jadx#gui-usage | jadx-gui's search and cross-reference features, which are the reason the GUI stays in the workflow |
| https://ghidra-sre.org/ | Where you go when §6.9's `native` declarations tell you the logic left the Java layer |
| https://frida.re/docs/javascript-api/#java | Turning a jadx class name and signature into a hook — §7.2 |

## Standards

| Identifier | Relevance |
|---|---|
| https://mas.owasp.org/MASVS/ | MASVS. **RESILIENCE-1** (impede comprehension) is measured by jadx output; **CODE-4** (no debug symbols in release builds) is §3.11 |
| https://mas.owasp.org/MASTG/ | MASTG. Many static tests begin "decompile the app". Cite the tool version alongside the test id |
| https://mas.owasp.org/MASTG/tools/android/ | MASTG's own tool listing, including jadx |
| https://owasp.org/www-project-mobile-top-10/ | The higher-level framing for the finding classes of §5.2 |

## Background — decompilation as a research problem

| Source | Why |
|---|---|
| Cifuentes, *Reverse Compilation Techniques* (PhD thesis, 1994) | The work that defined structuring algorithms for decompilers. §3.5's reducibility problem, stated formally. Read the structuring chapter and jadx's failures stop looking arbitrary |
| Hex-Rays' published notes on decompiler structuring | The commercial state of the art on the same problem, for native code. Useful for seeing which parts are universal and which are Java-specific |
| https://github.com/fesh0r/fernflower · https://github.com/mstrobel/procyon · https://github.com/Storyyeller/Krakatau | Independent Java decompilers. Running two on the same class is the cheapest way to see reconstruction as a **choice** rather than a fact |
| The `Signature` attribute in the JVM specification | Why generics survive on declarations and not on `new` expressions (§2.2) |

## Related chapters

### Prerequisites

| Chapter | Why |
|---|---|
| [04 — Java](../../04-Java/README.md) | The language jadx prints, and the compiler behaviours §6.1 attributes to `javac` |
| [05 — Kotlin](../../05-Kotlin/README.md) | **The Kotlin artefact table (§6.1 there).** This chapter points at it and does not restage it |
| [10 — APK Internals](../../10-APK-Internals/README.md) | The container jadx opens: the zip, splits, multi-DEX, signing |
| [12 — DEX Internals](../../12-DEX-Internals/README.md) | The format jadx parses. `debug_info_item`, the string pool, `code_item` |

### The destination when jadx fails

| Chapter | Why |
|---|---|
| [14 — Dalvik](../../14-Dalvik/README.md) | **Smali and the instruction set.** Everything §6.3 escalates to. 14 owns the bytecode; this chapter owns the Java |
| [11 — Android Runtime](../../11-Android-Runtime/README.md) | Class loading, and dynamically-loaded DEX that never reaches your decompiled tree |
| [13 — ART](../../13-ART/README.md) | The runtime that actually executes what you are reading about |

### What made the output look like that

| Chapter | Why |
|---|---|
| [40 — Obfuscation](../../40-Obfuscation/README.md) | The technique; this chapter reads its output. §6.2 there has the technique-to-jadx-symptom table |
| [41-ProGuard](../../41-ProGuard/README.md) · [42-R8](../../42-R8/README.md) | Where the renaming, inlining and dead-code removal came from |

### What you do with what you find

| Chapter | Why |
|---|---|
| [53 — Frida](../../53-Frida/README.md) | Where you take the class names and signatures. §7 |
| [16 — JNI](../../16-JNI/README.md) | Where §6.9's `native` declarations lead |
| [57 — Ghidra](../../57-Ghidra/README.md) | The other half of §6.9 |
| [15 — Native Code](../../15-Native-Code/README.md) | The `.so` files jadx cannot read |
| [27 — ContentProviders](../../27-ContentProviders/README.md) | Provider implementations read in decompiled form — and a worked example of the un-obfuscatable framework contract |
| [32 — Manifest](../../32-Manifest/README.md) | The manifest jadx decodes, and the parser-divergence attacks that make §8.6's cross-check necessary |
| [26 — Intent](../../26-Intent/README.md) · [29 — BroadcastReceivers](../../29-BroadcastReceivers/README.md) · [30 — Activities](../../30-Activities/README.md) | The handlers you find and read |
| [34 — Cryptography](../../34-Cryptography/README.md) · [49 — KeyStore](../../49-KeyStore/README.md) | What to do with a recovered key, and where it should have lived |
| [36 — CertificatePinning](../../36-CertificatePinning/README.md) · [44 — NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | Two of §8.3's highest-yield greps |
| [37 — RootDetection](../../37-RootDetection/README.md) | The checks you find here and neutralise elsewhere |
| [43 — WebView](../../43-WebView/README.md) | The three-line RCE chain of §5.2, all of it visible in decompiled Java |
| [33 — Storage](../../33-Storage/README.md) | Logging and storage findings |
| [23 — Permissions](../../23-Permissions/README.md) | Hidden-API and reflective-call behaviour jadx cannot predict |

### The disciplines this tool serves

| Chapter | Why |
|---|---|
| [52 — StaticAnalysis](../../52-StaticAnalysis/README.md) | The general method; this chapter is one tool inside it |
| **51-DynamicAnalysis** · **54-Objection** · **55-MobSF** | The runtime half, and the cross-checks of §7.6 |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | The standards mapping of §5.7 |
| [79 — Glossary](../../79-Glossary/README.md) · [80 — Appendix](../../80-Appendix/README.md) | Terminology and the tool matrix |

---

## Not a link, but the highest-value reference here

**How to read a jadx comment.** These appear in the output and each one is jadx telling you exactly
where it was unsure. Full table in [../cheatsheet.md](../cheatsheet.md); the five that change what
you may conclude:

| Comment | It means |
|---|---|
| `throw new UnsupportedOperationException("Method not decompiled")` | There is no Java for this method. Read the dump above it |
| `Code decompiled incorrectly, please refer to instructions dump` | The body below is **known wrong** |
| `JADX WARN: Removed duplicated region for block` | **A control-flow path is missing from the Java below.** 9,102 occurrences in one ordinary commercial app |
| `JADX WARN: 'super' call moved to the top of the method` | **Code was reordered.** Anything you conclude about initialisation order is unsafe |
| `JADX WARN: Type inference failed for: rNvM` | The declared type in the output is a guess |

And the one that is not printed anywhere: **a file with no `JADX WARN` comments is not a file that
decompiled correctly.** It is a file where jadx had no doubts. Chapter §6.6 is a measured case of the
difference.
