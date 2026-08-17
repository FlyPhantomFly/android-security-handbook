# 52 — Static Analysis · References

Annotated. Every entry says why it is here and what you would read it *for*, because a reference
list without annotations is a list of things nobody will open.

---

## AOSP source

File paths only — no line numbers are quoted anywhere in this chapter, because they move.

| Path | Read it for |
|---|---|
| `frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java` | The modern manifest parser (API 30+). Where `exported` defaults are computed, and where split manifests are merged. The ground truth your manifest reading is predicting |
| `frameworks/base/core/java/android/content/pm/PackageParser.java` | The historical parser. Still the clearest single-file description of what a manifest *is* to the platform |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` | The install path, and where the parsed package becomes the `flags=` line you read back with `dumpsys` |
| `frameworks/base/libs/androidfw/ResourceTypes.cpp` | `ResStringPool` and `ResXMLParser`. Why two tools can disagree about the same AXML bytes, and the basis of every manifest-parser divergence trick |
| `frameworks/base/include/androidfw/ResourceTypes.h` | The structure declarations, including the attribute-record size field that divergence tricks widen |
| `art/libdexfile/dex/dex_file.cc` | How the runtime walks the DEX you are parsing; `StringDataByIdx` and the MUTF-8 decode |
| `art/libdexfile/dex/dex_file_verifier.cc` | The bounds checks the runtime performs on header fields. Your tool must perform them too, because those fields are attacker-controlled claims |
| `libcore/dalvik/src/main/java/dalvik/system/DexFile.java` | `openInMemoryDexFile` — the API after which the artefact stops being the program |
| `art/runtime/jni/java_vm_ext.cc` | `JavaVMExt::RegisterNatives`. The source of the JNI blind spot: a binding with no symbol |
| `art/runtime/class_linker.cc` | `LinkCode` — registered natives are consulted before `dlsym` on the mangled name |
| `frameworks/base/tools/aapt2/` | `aapt2`'s source. Worth knowing it shares `androidfw` with the platform, which is why `aapt2 dump` is the tiebreaker |
| `external/r8` | R8 itself: renaming, inlining, class merging, and the mapping file format |

---

## Official documentation

| Source | Read it for |
|---|---|
| `source.android.com/docs/core/runtime/dex-format` | The DEX format reference. The `string_ids` table layout that `dump-strings.py` walks |
| Android Developers — *Sign your app* | Signature schemes v1–v4, and what `apksigner verify --print-certs` is telling you |
| Android Developers — *About Android App Bundles* | Why `pm path` prints more than one line, and what lives in each split |
| Android Developers — *Network security configuration* | The XML file that decides cleartext and trust; a whole finding class lives in it |
| Android Developers — *Shrink, obfuscate, and optimize your app* | R8's behaviour, the mapping file, and `-keep` semantics |
| Android Developers — *App manifest overview* | Element and attribute reference, including the `exported` requirement from API 31 |

---

## OWASP

| Item | Relationship to this chapter |
|---|---|
| **MASVS v2 — MASVS-CODE** | Asks for a dependency inventory **with versions**. Produced at stage 4; [17-Libraries](../../17-Libraries/README.md) owns the technique |
| MASVS-STORAGE, MASVS-CRYPTO, MASVS-NETWORK, MASVS-PLATFORM | The sweep finds candidates for each; the owning chapters rate them |
| MASVS-RESILIENCE | Detecting that obfuscation and anti-tamper are present is a static question; assessing their strength is not |
| **MASTG** | The static procedures assume a methodology and do not supply one. This chapter is that methodology |
| OWASP Mobile Top 10 | Useful for client-facing categorisation; not a testing method |

---

## Tools

| Tool | What it is for here | Honest limitation |
|---|---|---|
| `jadx` | Stage 3 readability | A reconstruction; reports errors that most users ignore. On Windows, the binary on `PATH` may be the GUI — run `jadx.cli.JadxCLI` from the jar |
| `apktool` | Stage 3 Smali plus decoded `res/xml/` | Not a decompiler; a re-implementation of the platform parser |
| `aapt2` | The platform's own parse | Manifest and resources only |
| `apksigner` | Stage 1 signer identity and scheme | — |
| `baksmali` / `smali` | Ground truth bytecode, and reassembly | Verbose |
| `dexdump -d` (build-tools) | Authoritative instruction listing with string indices | Hard to read at volume; excellent for one method |
| `apkid` | Packer, obfuscator and compiler identification | Narrow by design |
| `semgrep` | Syntax-aware rules over decompiled Java | Needs parseable output; silently covers less on obfuscated trees |
| MobSF | Breadth, a fast first inventory | No validation stage; one severity for every exported component |
| Android NDK LLVM binutils | `llvm-readelf` etc. when `readelf` is absent | Ships with the NDK at `toolchains/llvm/prebuilt/<host>/bin/` |

---

## This chapter's own tooling

| File | What it does |
|---|---|
| [`scripts/static-sweep.py`](../scripts/static-sweep.py) | Stages 5 and 6: the catalogue, aggregated into ranked leads with a printed score breakdown and a next step. No severity column, by design |
| [`scripts/validate-lead.sh`](../scripts/validate-lead.sh) | Stage 7: sites, holder, approximate caller closure, manifest cross-check, read-only device corroboration, and an eight-item kill list |
| [`scripts/blindspot-recorder.js`](../scripts/blindspot-recorder.js) | Stage 0, measured: hooks runtime receiver registration, reflection, DEX loading, library loading and `RegisterNatives`, and prints a delta report |
| [`examples/triage-worksheet.md`](../examples/triage-worksheet.md) | A worked queue, annotated lead by lead |
| [`examples/findings-ledger.csv`](../examples/findings-ledger.csv) | The same queue as a ledger, with a verdict and a reason against every rejection |
| [`examples/sweep-output-fridathree.txt`](../examples/sweep-output-fridathree.txt) | The real, unedited sweeper output the worked examples are built from |

---

## Tooling from other chapters that this pipeline calls

| Script | Stage | What it contributes |
|---|---|---|
| [`04-Java/scripts/dump-strings.py`](../../04-Java/scripts/dump-strings.py) | 3, 4 | The DEX string table, parsed rather than scanned, with correct MUTF-8 and table indices |
| [`17-Libraries/scripts/lib-inventory.sh`](../../17-Libraries/scripts/lib-inventory.sh) | 4 | The dependency inventory MASVS-CODE asks for, with a fallback chain that reports which tool answered |
| [`12-DEX-Internals/scripts/dex-diff.py`](../../12-DEX-Internals/scripts/dex-diff.py) | 5 (enterprise) | Index-table diffing between builds, for repackaging detection |

---

## Papers and talks

Rather than list specific talks by title and risk misattributing them, here are the *topics* worth
searching for, each with why it matters to this chapter:

- **Android manifest parser divergence** — the class of trick where the platform and third-party
  tools disagree about the same AXML. Both `32-Manifest` and `10-APK-Internals` ship CTFs built on
  different primitives within it.
- **Secret scanning precision** — the general literature on entropy- and regex-based secret
  detection, and why published precision figures are usually measured on corpora that do not look
  like decompiled Android code.
- **Call-graph construction for Android** — the academic work on reflection-aware and
  DI-aware call graphs, which exists precisely because the naive textual approach in
  `validate-lead.sh --reach` is insufficient. Read it to understand what the four holes cost.
- **Packer detection and unpacking** — the dynamic-dump literature that `40-Obfuscation` §3.7.3
  condenses.

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | The container this pipeline opens; signature and structural checks at stage 1–2 |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The bytecode format every code rule ultimately reads |
| [04-Java](../../04-Java/README.md) | `dump-strings.py`: literals when you have no decompiler, and the index that joins strings to code |
| [17-Libraries](../../17-Libraries/README.md) | Stage 4's dependency inventory; the MASVS-CODE deliverable. **This chapter does not fingerprint libraries** |
| [32-Manifest](../../32-Manifest/README.md) | Component semantics and the entry-point list. **This chapter does not audit manifests** |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What to do when the sweep returns nothing readable. **This chapter does not deobfuscate** |
| [33-Storage](../../33-Storage/README.md) | Rates storage leads; source of the 132-of-132 false-positive measurement |
| [34-Cryptography](../../34-Cryptography/README.md) | Rates crypto leads |
| [35-SSL](../../35-SSL/README.md) · [36-CertificatePinning](../../36-CertificatePinning/README.md) · [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | Rate TLS leads; source of the 12-of-14 pinning measurement and of the modified-trust-store warning |
| [43-WebView](../../43-WebView/README.md) | Rates WebView leads |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | Source of the 69% runtime-registration measurement — this chapter's central blind spot |
| [16-JNI](../../16-JNI/README.md) · [15-Native-Code](../../15-Native-Code/README.md) | `RegisterNatives`, and what to do once the sweep hits the native boundary |
| [26-Intent](../../26-Intent/README.md) · [27-ContentProviders](../../27-ContentProviders/README.md) · [28-Services](../../28-Services/README.md) · [30-Activities](../../30-Activities/README.md) | What the sinks mean once §8.5 finds attacker-controlled input reaching one |
| [53-Frida](../../53-Frida/README.md) | The dynamic half of every question stage 7 defers |
| [57-Ghidra](../../57-Ghidra/README.md) | Where the native side of a static pass continues |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS/MASTG framing; MASVS-CODE in particular |
| [80-Appendix](../../80-Appendix/README.md) | The report template and the severity rubric. **This chapter does not restage them** |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The command index; this chapter is where you validate what a sweep turns up |

[51-DynamicAnalysis](../../51-DynamicAnalysis/README.md), [55-MobSF](../../55-MobSF/README.md),
[56-JADX](../../56-JADX/README.md), [68-ReverseEngineering](../../68-ReverseEngineering/README.md)
and [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) are referenced in the chapter text as
topics rather than as links. All five are now written.
