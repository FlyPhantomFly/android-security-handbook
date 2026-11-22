# 59 — radare2 · references

Annotated. Each entry says what it is *for*, not just what it is.

> **Note on verification.** radare2 was not installed on the machine where this chapter was written,
> so the documentation below is the authority for command behaviour, not this chapter. Where the two
> disagree, the tool wins. See [../README.md](../README.md) for the full statement.

---

## radare2 — official

| Link | What it is for |
|---|---|
| [radareorg/radare2](https://github.com/radareorg/radare2) | The source. `libr/core/cmd.c` is the command parser and the real reference for what is legal to compose with `@`, `@@`, `~` and `\|` |
| [rada.re](https://rada.re/n/) | Project home, downloads, news |
| [The radare2 book](https://book.rada.re/) | The official manual. Read the command-grammar chapters end to end; skim the rest as reference |
| [radare2-book source](https://github.com/radareorg/radare2-book) | The book's repository — useful for searching offline, and for filing corrections |
| [doc/intro.md](https://github.com/radareorg/radare2/blob/master/doc/intro.md) | The short introduction shipped in the source tree. The fastest orientation available |
| [r2pm package index](https://github.com/radareorg/radare2-pm) | What plugins exist. `r2pm -l` locally |

### Reading the source when the docs lag

| Path in the radare2 tree | Answers |
|---|---|
| `libr/core/cmd.c` | How the command language is parsed and dispatched |
| `libr/core/cmd_anal.c` | **What `aaa` actually is** — a fixed sequence of smaller commands you can run individually. Ten minutes here demystifies §3.6 of the chapter |
| `libr/bin/p/bin_elf.c`, `libr/bin/format/elf/` | The ELF loader behind every `i` command |
| `libr/bin/p/bin_dex.c`, `libr/bin/format/dex/` | The DEX loader, and the limits of it |
| `libr/anal/` | Function discovery, basic blocks, cross-references |
| `libr/esil/` | The ESIL emulator |
| `libr/arch/p/arm/`, `libr/arch/p/dalvik/` | Architecture plugins |

---

## Plugins that change what the tool can do

| Link | Why it matters |
|---|---|
| [r2ghidra](https://github.com/radareorg/r2ghidra) | Embeds **Ghidra's actual decompiler** and gives you `pdg`. This is how you get real decompiled C without a JVM. Base radare2's `pdc` is not a decompiler |
| [r2frida](https://github.com/nowsecure/r2frida) | Makes a live [Frida](../../53-Frida/README.md) session look like a file, so every radare2 command operates on process memory. The answer to packing and runtime decryption |
| [r2dec](https://github.com/wargio/r2dec-js) | A JavaScript-based pseudo-decompiler; lighter than r2ghidra, less accurate |
| [radare2-r2pipe](https://github.com/radareorg/radare2-r2pipe) | Bindings for Python, JS, Go, Rust, Ruby and more. The Python one is what this chapter's scripts use |

---

## rizin and Cutter

| Link | Notes |
|---|---|
| [rizin](https://rizin.re/) | The 2020 fork. Same command grammar, different tool names (`rz-bin`, `rz-diff`, `rzpipe`) |
| [rizinorg/rizin](https://github.com/rizinorg/rizin) | Source |
| [Cutter](https://cutter.re/) | The Qt GUI. Followed rizin at the fork. Bundles a decompiler — for many people the most pleasant way to use either project |
| [rz-ghidra](https://github.com/rizinorg/rz-ghidra) | Ghidra's decompiler for rizin/Cutter |
| [iaito](https://github.com/radareorg/iaito) | The GUI that stayed with radare2 |

---

## Learning material

| Link | Why |
|---|---|
| [Megabeets — A journey into radare2](https://www.megabeets.net/a-journey-into-radare-2-part-1/) | The introduction most people actually learn from. Worked examples rather than a command dump |
| [r2con](https://rada.re/con/) | The project's own conference. The workshop tracks are the best structured teaching material that exists for this tool |
| [radare2 explorations](https://book.rada.re/) | Community walkthroughs, CTF-flavoured |
| [Cutter documentation](https://cutter.re/docs/) | If you prefer the GUI, this is the equivalent orientation |

---

## Android, JNI and the NDK

| Link | Why it matters here |
|---|---|
| [JNI specification — function table](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html) | **The fixed order that makes an offset a function name.** This is the reference behind `ldr x8,[x8,#1720]` = `RegisterNatives` |
| [JNI design overview](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/design.html) | Name mangling rules for `Java_*` symbols, including the `_0` + **four** hex digits escape |
| [Android NDK](https://developer.android.com/ndk) | The toolchain that produced every measured binary in this chapter |
| [Android ABI management](https://developer.android.com/ndk/guides/abis) | Why `lib/` contains several directories, and why analysing the wrong one wastes a day |
| [Termux](https://termux.dev/) | On-device package manager — `pkg install radare2` puts the tool on the phone |

---

## AOSP — the structures you are actually reading

These are paths in the AOSP tree, not URLs. They define what radare2 is showing you.

| Path | Defines |
|---|---|
| `libnativehelper/include_jni/jni.h` | `JNINativeInterface` (the ~230-entry table) and `JNINativeMethod` (the three-pointer record `RegisterNatives` consumes) |
| `art/runtime/jni/jni_internal.cc` | ART's `RegisterNatives` implementation — what happens after the `blr x8` |
| `bionic/linker/linker.cpp`, `bionic/linker/linker_soinfo.cpp` | PLT/GOT resolution, which is why `sym.imp.X` is a stub and why `axt` on it is a complete local call list |
| `bionic/libc/include/elf.h` | The ELF structures `r_bin` parses |

---

## ELF and ARM

| Link | Why |
|---|---|
| [ELF specification (System V ABI)](https://refspecs.linuxfoundation.org/elf/elf.pdf) | Sections versus segments, and the `sh_addr`/`sh_offset` distinction behind the patching trap |
| [Arm Architecture Reference Manual for A-profile](https://developer.arm.com/documentation/ddi0487/latest) | Instruction encodings — the authority behind the measured `ret` = `0xd65f03c0` and `nop` = `0xd503201f` |
| [Capstone](https://www.capstone-engine.org/) | The disassembly engine radare2 can be built against, and the same one Frida's `Instruction.parse` uses |
| [Arm A64 quick reference](https://developer.arm.com/documentation/den0024/latest) | Friendlier than the ARM ARM for reading the patterns in §6.4 |

---

## OWASP

| Identifier | Relevance |
|---|---|
| [MASVS](https://mas.owasp.org/MASVS/) | **MASVS-CODE-4** (third-party/native code), **MASVS-CRYPTO-1/2** (keys, proven implementations), **MASVS-RESILIENCE-1..4** (platform integrity, anti-tampering, anti-static-analysis, anti-dynamic-analysis) |
| [MASTG](https://mas.owasp.org/MASTG/) | The testing guide. Its native-code static analysis tests are what §8 of the chapter implements |
| [MASTG — Android reverse engineering](https://mas.owasp.org/MASTG/0x05b-Android-Security-Testing/) | Tool-level techniques, including radare2 usage |

> The measured `-O2` string-folding failure in §5.3 is a **MASVS-RESILIENCE-3** finding: the
> anti-static-analysis control was present in source and absent from the shipped artefact.

---

## Tools that pair with radare2

| Tool | Role |
|---|---|
| [Frida](https://frida.re/) — [53-Frida](../../53-Frida/README.md) | The runtime half of every workflow in §7. Confirms what static analysis can only hypothesise |
| [JADX](https://github.com/skylot/jadx) — [56-JADX](../../56-JADX/README.md) | DEX and Java. Owns the territory §3.10 declines to compete in |
| [Ghidra](https://ghidra-sre.org/) — [57-Ghidra](../../57-Ghidra/README.md) | The decompiler. Its §3.16 routes batch triage and no-display work here |
| [apktool](https://apktool.org/) | Manifest and resource decoding, Smali round-tripping |
| [Unicorn Engine](https://www.unicorn-engine.org/) | Emulate a routine instead of defeating it, when what you want is the algorithm. More capable than ESIL for real work |
| [Qiling](https://qiling.io/) | Higher-level emulation with syscall support — where ESIL gives up |
| LLVM binutils (in the NDK) | `llvm-readelf`, `llvm-nm`, `llvm-objdump`, `llvm-strings`. **Every measured fact in this chapter came from these**, and `scripts/so-corpus-stats.sh` falls back to them when radare2 is absent |

---

## This chapter's own files

| File | Purpose |
|---|---|
| [`examples/01-r2-target.c`](../examples/01-r2-target.c) | The reference target: static and dynamic JNI, an obfuscated string, a magic-constant check, a short-circuiting gate |
| [`examples/02-r2-target-hardened.c`](../examples/02-r2-target-hardened.c) | The `volatile`-key fix for the measured `-O2` folding failure |
| [`examples/03-ctf-vault.c`](../examples/03-ctf-vault.c) | The lab 04 challenge. **Contains the answer — do not read it before solving** |
| [`examples/build.sh`](../examples/build.sh) | Builds everything **out of tree** and prints a report reproducing the chapter's key measurements |
| [`scripts/r2-triage.py`](../scripts/r2-triage.py) | Corpus triage via `r2pipe`, structural parsing only, CSV out. Fails loudly if the tools are missing |
| [`scripts/r2-jni-inventory.py`](../scripts/r2-jni-inventory.py) | Enumerates both JNI registration mechanisms and reports what it could **not** resolve |
| [`scripts/so-corpus-stats.sh`](../scripts/so-corpus-stats.sh) | Measures analysis workload across a directory. Uses `rabin2` when present, **falls back to `llvm-readelf`** — this produced the chapter's §2 table |

---

## Related chapters

### Prerequisites

| Chapter | Why |
|---|---|
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | Shell pipelines — every triage loop here is one |
| [15-Native-Code](../../15-Native-Code/README.md) | ELF and the NDK. This chapter reads what that one builds |
| [16-JNI](../../16-JNI/README.md) | The function table, name mangling, `RegisterNatives` |
| [17-Libraries](../../17-Libraries/README.md) | Loading, `DT_NEEDED`, library layout in an APK |
| [18-ARM](../../18-ARM/README.md) | AArch64 instructions; §6.4's patterns assume it. Also the source of the *inlining* failure mode that §5.4 pairs with its own |
| [68-ReverseEngineering](../../68-ReverseEngineering/README.md) | The investigation method. This chapter is one tool inside it |

### Companions

| Chapter | Relationship |
|---|---|
| [57-Ghidra](../../57-Ghidra/README.md) | The decompiler-centred alternative. Its §3.16 sends batch triage and no-display work here; §3.6 and §9.5 substantiate that with measurement |
| [58-IDA](../../58-IDA/README.md) | The commercial alternative, and the cases where it wins |
| [56-JADX](../../56-JADX/README.md) | Owns DEX and Java |
| [53-Frida](../../53-Frida/README.md) | The runtime half; also what r2frida drives |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The DEX format, for when a byte-level view is all that works |
| [37-RootDetection](../../37-RootDetection/README.md) | Its §8.4 commands are explained in §3.2 and consolidated in §8.4. Its lab 04 is the decoupled-consequence pattern lab 04 here points at |
| [39-EmulatorDetection](../../39-EmulatorDetection/README.md) | Source of the `axt sym.imp.__system_property_get` workflow |
| [67-BypassingProtections](../../67-BypassingProtections/README.md) | Source of the `axt sym.imp.abort` workflow |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What the graph shapes in §6.5 mean |
| [70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md) | Patch diffing with `radiff2`, and the limits of static severity claims |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | Why read-only parsing and on-device analysis matter for hostile samples |
| [34-Cryptography](../../34-Cryptography/README.md) | The algorithm-constant table that turns `/v4` into an identification tool |
| [19-Memory](../../19-Memory/README.md) | The `volatile` reasoning behind §5.3's fix |
| [10-APK-Internals](../../10-APK-Internals/README.md) | Re-signing after a patch |
| [38-TamperDetection](../../38-TamperDetection/README.md) | What notices that you patched |
