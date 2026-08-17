# 12 — DEX Internals · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

DEX is unusual in this repository: it has a **normative written specification** as well as an
implementation. When they appear to disagree, the implementation is what runs on the device.

---

## Normative specification — start here

| Resource | Why |
|---|---|
| [Dalvik Executable format](https://source.android.com/docs/core/runtime/dex-format) | **The specification.** Every structure in §3 is defined here. Read it beside the chapter |
| [Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode) | Every opcode with its semantics |
| [Instruction formats](https://source.android.com/docs/core/runtime/instruction-formats) | The `NAx` naming scheme decoded, with bit layouts |

Those three pages are the ground truth for §3.1–§3.27. Bookmark them.

---

## AOSP source

Read on [cs.android.com](https://cs.android.com/). See [07-AOSP](../../07-AOSP/README.md) for the
navigation technique.

### The parser and the structures

| Path | Open it when |
|---|---|
| `libdexfile/dex/dex_file_structs.h` | You need the exact C++ struct for a table in §3 |
| `libdexfile/dex/dex_file.h`, `dex_file.cc` | You want the runtime's own accessor logic |
| `libdexfile/dex/dex_file_loader.cc` | Tracing how a DEX is opened and mapped (§4.1) |
| `libdexfile/dex/dex_file_verifier.cc` | The **structural** validation — bounds, sorting, sizes |
| `libdexfile/dex/leb128.h` | LEB128 encode/decode, if your implementation disagrees |
| `libdexfile/dex/modified_utf8.h`, `.cc` | MUTF-8, including the surrogate-pair handling |

### The instruction set

| Path | Open it when |
|---|---|
| **`libdexfile/dex/dex_instruction_list.h`** | **Ground truth for every opcode.** One macro-expanded table with mnemonic, format, index type and flags. Answers "does this opcode exist on this version?" in seconds |
| `libdexfile/dex/dex_instruction.h`, `.cc` | Decoding logic and operand extraction |
| `art/runtime/verifier/method_verifier.cc` | The **bytecode** data-flow verification of §3.29 |

### Tools you can read as reference implementations

| Path | Why |
|---|---|
| `art/dexdump/dexdump.cc` | A complete, readable DEX parser. When your own parser disagrees, diff against this |
| `art/dexlayout/` | Rewrites DEX for locality — a **writer** reference, useful if you need to emit DEX |
| `tools/dexter/` | An instrumentation library for modifying DEX programmatically |

### Where DEX goes next

| Path | Covers |
|---|---|
| `art/runtime/class_linker.cc` | `class_def_item` becoming a live `mirror::Class` |
| `art/runtime/vdex_file.h` | Where installed bytecode actually lives (§7.1) |

---

## The compiler that produces DEX

| Resource | Why |
|---|---|
| [R8/D8 source](https://r8.googlesource.com/r8) | The compiler. Useful when you need to know *why* a construct was emitted a particular way |
| [D8 documentation](https://developer.android.com/tools/d8) | The dexer's command line |
| [R8 documentation](https://developer.android.com/build/shrink-code) | Shrinking and optimisation — see also [42-R8](../../42-R8/README.md) |

---

## Tooling

| Tool | Use | Source |
|---|---|---|
| `dexdump` | Header (`-f`), disassembly (`-d`), positions (`-l plain`) | Android SDK build-tools |
| `baksmali` / `smali` | Disassemble and **reassemble** — the patching path | https://github.com/google/smali |
| `apktool` | Full APK decode/rebuild including resources | https://apktool.org/ |
| `jadx` | Java-level decompilation | https://github.com/skylot/jadx |
| `dex2jar` | DEX → JAR, for JVM tooling | https://github.com/pxb1988/dex2jar |
| `vdexExtractor` | **Unquickening** for Android 8–10 VDEX | https://github.com/anestisb/vdexExtractor |
| `oatdump` | Extract DEX from a device's VDEX | `/apex/com.android.art/bin/oatdump` |
| 010 Editor + DEX template | Byte-level browsing with structure overlays | commercial |
| `androguard` | Python DEX/APK analysis library | https://github.com/androguard/androguard |

### Chapter tooling

| File | Purpose |
|---|---|
| [`examples/dex_parser.py`](../examples/dex_parser.py) | Parse a DEX from first principles; **`--map-coverage` is the packer detector** |
| [`examples/find_array_literals.py`](../examples/find_array_literals.py) | Locate hardcoded byte arrays — where keys actually live |
| [`examples/PatchDemo.smali`](../examples/PatchDemo.smali) | The four patches you will make, with the pitfalls annotated |
| [`scripts/dex-audit.sh`](../scripts/dex-audit.sh) | Repeatable audit across every `classes*.dex` in an APK |

---

## Security research

| Resource | Why |
|---|---|
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Where to find real identifiers for verifier and parser vulnerabilities |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | High-quality research on runtime and format parsing bugs |
| [Android VRP rules](https://bughunters.google.com/about/rules/android-friends) | What Google treats as reportable |

> **Note on CVE citation.** This chapter describes vulnerability *classes* — parser divergence,
> verifier bypass, map inconsistency — rather than naming identifiers, because format bugs are
> numerous and version-specific and a misattributed CVE in a client report is worse than no citation.
> When you need a specific reference, pull it from the bulletin for the affected release.

---

## OWASP

| Resource | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | MASVS-CODE (hardcoded secrets, debug info in release), MASVS-CRYPTO (key material in array literals), MASVS-RESILIENCE (obfuscation quality) |
| [MASTG](https://mas.owasp.org/MASTG/) | Reverse engineering and tampering procedures |

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Internals: A Confectioner's Cookbook* — Jonathan Levin | The deepest published treatment of the format and its runtime context |
| *Android Security Internals* — Nikolay Elenkov | The security model DEX sits inside |
| *Decompiling Android* — Godfrey Nolan | Dated, but written around the format itself rather than around tools |
| *Practical Binary Analysis* — Dennis Andriesse | Not DEX-specific, but the best on-ramp to reading any binary format at byte level |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | The container DEX ships inside, and **real** (keyed) integrity via APK signing |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | The concept layer that consumes this format |
| [13-ART](../../13-ART/README.md) | OAT, VDEX, compilation, and where installed bytecode actually lives |
| [14-Dalvik](../../14-Dalvik/README.md) | The full **Smali syntax reference**, and the stack-vs-register comparison |
| [15-Native-Code](../../15-Native-Code/README.md) | Where `ACC_NATIVE` methods lead |
| [16-JNI](../../16-JNI/README.md) | The bridge those native methods cross |
| [34-Cryptography](../../34-Cryptography/README.md) | What to do with the keys you find in `fill-array-data` |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Packers, string encryption, anti-decompilation |
| [41-ProGuard](../../41-ProGuard/README.md) | What survives renaming |
| [42-R8](../../42-R8/README.md) | What the optimiser does to the bytecode you are reading |
| [56-JADX](../../56-JADX/README.md) | Decompiler limitations and when to drop to Smali |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Validating leads before they become findings |
