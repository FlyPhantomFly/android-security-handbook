# 15 — Native Code · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

ELF is unusual in this repository in the same way DEX is: it has a **normative written
specification** as well as several implementations. When the specification and Android's linker
appear to disagree, **the linker is what runs on the device** — and Android's own `elf.h` is the
tiebreaker for anything Android-specific.

---

## The specification — start here

| Resource | Why |
|---|---|
| [System V gABI, chapters 4 and 5](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html) | **The normative source.** Chapter 4 defines the ELF header, sections and symbols; chapter 5 defines segments, the dynamic array and relocation. Every table in README §3 traces back to these two chapters |
| [ELF specification, single PDF](https://refspecs.linuxfoundation.org/elf/elf.pdf) | The classic single-document version. Easier to read cover to cover; about 60 pages and genuinely readable |
| [`elf(5)` man page](https://man7.org/linux/man-pages/man5/elf.5.html) | The fastest possible lookup when you need one structure's field order. Bookmark it |
| [ELF Tool Chain project documentation](https://sourceforge.net/projects/elftoolchain/) | Independent implementations and specification notes; useful when two tools disagree |

**The three-tier rule**, worth internalising early: ELF constants come from three places. The
**generic ABI** (above) defines everything common. The **processor supplement** defines values in
`0x7xxxxxxx` — `PT_ARM_EXIDX` lives there. The **OS supplement** defines `0x6xxxxxxx` — every
`PT_GNU_*`, `DT_GNU_*` and `DT_ANDROID_*` lives there. A tool printing a raw constant is usually
telling you it does not have that tier's supplement, not that the file is corrupt.

---

## ARM's supplements

| Resource | Why |
|---|---|
| [ARM ABI documents (`abi-aa`)](https://github.com/ARM-software/abi-aa) | The umbrella repository. **AAELF64** defines the `R_AARCH64_*` relocation numbering used in README §3.7; **AAELF32** does the same for ARM32 and defines `PT_ARM_EXIDX` |
| [AAPCS64 (in the same repository)](https://github.com/ARM-software/abi-aa) | The calling convention. Not this chapter's subject — it belongs to 18-ARM — but it is what tells you what is in `x0` when you land on a function |
| [ARM Architecture Reference Manual](https://developer.arm.com/documentation/ddi0487/latest) | The authority when a disassembler surprises you. Enormous; use the index |

---

## Android specifics

| Resource | Why |
|---|---|
| [Android ABI Management](https://developer.android.com/ndk/guides/abis) | Which ABIs exist, how a device chooses one, what `abiFilters` does. Read this before deciding which `lib/<abi>/` to analyse |
| [Support 16 KB page sizes](https://developer.android.com/guide/practices/page-sizes) | The alignment requirement, the `-Wl,-z,max-page-size=16384` flag, and how to test. The source for README §3.11 |
| [`extractNativeLibs` in the manifest reference](https://developer.android.com/guide/topics/manifest/application-element#extractNativeLibs) | The attribute itself and its default. Short |
| [NDK guides](https://developer.android.com/ndk/guides) | The toolchain, CMake and `ndk-build` configuration — where the hardening flags in README §4.4 are actually set |
| [Android security enhancements by release](https://source.android.com/docs/security/enhancements) | Where PIE enforcement, text-relocation rejection and namespace restrictions landed. The primary source for the version matrix in README §3.18 |
| [Android Developers Blog — 16 KB page size posts](https://android-developers.googleblog.com/) | The practical migration guidance, with the reasoning behind the Play requirement |

---

## AOSP source

Read on [cs.android.com](https://cs.android.com/). [07-AOSP](../../07-AOSP/README.md) is the
navigation technique. **File paths are stable; line numbers are not, and none are cited anywhere in
this chapter.**

### The dynamic linker — the implementation of README §3.10

| Path | Open it when |
|---|---|
| `bionic/linker/linker.cpp` | You want `find_library` / `load_library` and the dependency walk |
| `bionic/linker/linker_phdr.cpp` | You want the `ElfReader` class: header verification, `ReserveAddressSpace`, `LoadSegments`, `FindPhdr`, and `phdr_table_protect_gnu_relro` — the `mprotect` that implements RELRO |
| `bionic/linker/linker_relocate.cpp` | You want to see `R_AARCH64_RELATIVE`, `GLOB_DAT` and `JUMP_SLOT` actually applied, and where the packed and RELR formats are decoded. **The single most useful file in this list** |
| `bionic/linker/linker_soinfo.cpp`, `linker_soinfo.h` | The `soinfo` bookkeeping, symbol lookup, and `call_constructors` — which runs `.init_array` |
| `bionic/linker/linker_namespaces.cpp`, `linker_config.cpp` | Why `dlopen` of a platform library fails from an app |
| `bionic/linker/dlfcn.cpp`, `bionic/libdl/libdl.cpp` | The public `dlopen` / `dlsym` entry points |
| `bionic/linker/linker_main.cpp` | How the linker bootstraps itself, which is a genuinely interesting chicken-and-egg problem |

### The constants — the tiebreaker

| Path | Why |
|---|---|
| `bionic/libc/include/elf.h` | **The authoritative Android ELF constant list.** Where `DT_ANDROID_REL`, `DT_ANDROID_RELA`, `DT_ANDROID_RELR` and `SHT_ANDROID_*` are defined, with comments on their history. Ships in every NDK sysroot as `usr/include/elf.h`, so if you have an NDK you already have it. Every Android-specific constant in this chapter was checked against it — including `DT_ANDROID_RELRENT`, which is `0x6FFFE003` and breaks the consecutive run |
| `bionic/libc/include/link.h` | `struct link_map` and `dl_iterate_phdr` — how a process enumerates its own libraries, and the list a hiding library unlinks itself from |
| `bionic/libc/include/sys/auxv.h` | `getauxval`, `AT_SECURE`, `AT_HWCAP` — how native code learns about its environment |

### The runtime's side

| Path | Why |
|---|---|
| `art/runtime/jni/java_vm_ext.cc` | `JavaVMExt::LoadNativeLibrary` — the class-loader duplicate check, the `android_dlopen_ext` call, and the `JNI_OnLoad` invocation |
| `art/runtime/native/java_lang_Runtime.cc` | The `nativeLoad` JNI glue |
| `libcore/ojluni/src/main/java/java/lang/Runtime.java`, `System.java` | `loadLibrary0` and `mapLibraryName` |
| `libcore/dalvik/src/main/java/dalvik/system/DexPathList.java`, `BaseDexClassLoader.java` | How the native library search path is built, including the `!/lib/<abi>` syntax that lets a library be mapped from inside an APK |

### Policy and build

| Path | Why |
|---|---|
| `system/core/rootdir/etc/public.libraries.android.txt` | The allowlist of platform libraries an app may load |
| `build/soong/cc/config/global.go` | Platform-side compiler and linker defaults, including hardening |
| The NDK's `build/cmake/android.toolchain.cmake` | App-side defaults. **Not the same as the compiler driver's** — README §4.4 |

---

## Tools

| Tool | Why, and the caveat |
|---|---|
| `llvm-readelf` | **Use this, not binutils, on Android targets.** Ships in every NDK at `toolchains/llvm/prebuilt/<host>/bin/`. Decodes Android's packed relocations, which binutils cannot |
| `llvm-objdump`, `llvm-nm`, `llvm-strip`, `llvm-cxxfilt` | The rest of the NDK's LLVM binutils. `llvm-cxxfilt` demangles C++ names, which you will need constantly |
| `readelf`, `objdump`, `nm`, `strings` (GNU binutils) | Fine for anything not using Android-specific formats. **Silently reports zero relocations** on a packed library |
| [`pyelftools`](https://github.com/eliben/pyelftools) | The reference Python ELF library, and a good read. This chapter's scripts deliberately avoid it so they run with nothing installed |
| [Ghidra](https://ghidra-sre.org/) | Where you go once you know *which address* matters — [57-Ghidra](../../57-Ghidra/README.md) |
| [Frida](https://frida.re/) | The run-time half — [53-Frida](../../53-Frida/README.md) |
| `zipalign` | The APK-side alignment that makes `extractNativeLibs="false"` possible |
| [LIEF](https://lief.re/) | A cross-format binary parsing and **modification** library. Worth knowing when you need to rewrite an ELF rather than read it |

---

## Reading worth the time

| Resource | Why |
|---|---|
| Ulrich Drepper, *How To Write Shared Libraries* | The definitive explanation of PLT, GOT, symbol visibility, lazy binding and why `-fvisibility=hidden` matters. Dense, opinionated, and the single best thing on this list |
| Eli Bendersky, *Position Independent Code (PIC) in shared libraries* | The clearest short explanation anywhere of why the GOT exists. Read it before Drepper if the concept is new |
| Eli Bendersky, *Load-time relocation of shared libraries* | The companion piece, on what the linker actually patches |
| Ian Lance Taylor, the twenty-part *Linkers* series (airs.com) | How linkers work, by someone who wrote `gold`. Long, and the best explanation of symbol resolution order in existence |
| *Learning Linux Binary Analysis*, Ryan O'Neill | ELF from an offensive and forensic angle: infection techniques, anti-analysis, memory forensics. Directly relevant to Lab 05 |
| MWR/other public write-ups on Android packers | Search for current ones rather than relying on a fixed link; the techniques in README §6.6 are all documented publicly |

---

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-CODE-4** | "Free security features are activated" — this chapter's checklist, almost line for line |
| MASVS-CODE-1, MASVS-CODE-2 | Third-party components kept current, and platform APIs used correctly |
| MASVS-CRYPTO-1 | The key you found in `.rodata` |
| MASVS-RESILIENCE-1 … -4 | Anti-tampering, obfuscation and integrity — the layer implemented in the `.so` |
| MASVS-STORAGE-2 | Secrets recoverable from the shipped package |
| [MASTG — Android techniques](https://mas.owasp.org/MASTG/0x05b-Android-Security-Testing/) | Procedural companions, including native reverse engineering |
| [MASTG](https://mas.owasp.org/MASTG/) | The testing guide itself |

Cite the identifier in every finding. "The library has no stack canaries" is an observation;
mapping it to MASVS-CODE-4 turns it into something a programme can track — and, just as importantly,
something a programme can decide to accept.

---

## CVEs and vulnerability history

Only identifiers verified as real are listed here. Where the class matters more than the instance,
the class is described rather than an identifier invented.

| Identifier | One line |
|---|---|
| CVE-2015-1538 | Integer overflow in Android's `libstagefright` MP4 handling, reachable by MMS. The archetypal native-parser vulnerability, and the reason Android's media stack was rearchitected |
| CVE-2016-5195 | "Dirty COW" — a Linux kernel copy-on-write race, widely used to root Android devices |
| CVE-2019-2215 | Use-after-free in the kernel Binder driver, exploited in the wild |
| *(class, not an ID)* | Repeated integer-overflow and heap-overflow findings in bundled `libpng`, `libjpeg-turbo`, FreeType, `libwebp` and OpenSSL forks. These are the highest-yield native findings on real engagements, and identifying which version is bundled is [17-Libraries](../../17-Libraries/README.md)'s subject |

> **Never cite a CVE identifier you have not checked.** One wrong number destroys the reader's trust
> in every other number in the report. Where you are unsure, describe the class: "an integer-overflow
> vulnerability of the kind found repeatedly in media parsers" is true, useful, and cannot be wrong.

---

## Related chapters

### Prerequisites

| Chapter | Why |
|---|---|
| [01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) | Memory, the stack, processes, virtual memory, endianness, hexadecimal. Its §3.23 introduces ELF; this chapter is that section's full treatment |
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | Processes, `/proc`, `ptrace`, file permissions |
| [10-APK-Internals](../../10-APK-Internals/README.md) | The ZIP structure `lib/<abi>/` sits inside, `zipalign`, and the manifest |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | The four memory-safety guarantees this chapter shows you losing |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | `ACC_NATIVE` — the flag whose methods lead here |

### Companions

| Chapter | Why |
|---|---|
| [16-JNI](../../16-JNI/README.md) | **Read next.** The bridge: `JNIEnv`, `RegisterNatives`, name mangling, the calling convention |
| [17-Libraries](../../17-Libraries/README.md) | *Which* library and *which version*. Its `lib-fingerprint.py` parses ELF the same way and for the same reason |
| [53-Frida](../../53-Frida/README.md) | The runtime half. `Module.findExportByName` is README §3.6 |
| [57-Ghidra](../../57-Ghidra/README.md) | What the code *does*, once you know where to look. Its §4.4 lists the ELF structures its loader reads |
| [37-RootDetection](../../37-RootDetection/README.md) | The most common reason a check was moved into a `.so` |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Packers, string encryption, and what degrades static analysis |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | The boundary native code sits inside, and the ones below it |
| [34-Cryptography](../../34-Cryptography/README.md) | What to do about the key you found in `.rodata` |
| [49-KeyStore](../../49-KeyStore/README.md) | Where that key should have lived |
| [13-ART](../../13-ART/README.md) | The runtime that calls `JNI_OnLoad`, itself a large body of C++ |
| [08-Build-System](../../08-Build-System/README.md) | Where the compiler and linker flags of README §4.4 are configured |
| [77-UsefulCommands](../../77-UsefulCommands/README.md) | The command index |
| [79-Glossary](../../79-Glossary/README.md) | ELF, PLT, GOT, RELRO, PIE, canary, CFI — all defined there, all owned by this chapter |

### Referenced as plain text in the chapter body, and all now written

[18-ARM](../../18-ARM/README.md) (the instruction set and AAPCS64) ·
[19-Memory](../../19-Memory/README.md) (heap layout, Scudo, grooming) ·
[22-SELinux](../../22-SELinux/README.md) ·
[38-TamperDetection](../../38-TamperDetection/README.md) ·
[51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) ·
[52-StaticAnalysis](../../52-StaticAnalysis/README.md) ·
[58-IDA](../../58-IDA/README.md) · [59-radare2](../../59-radare2/README.md) ·
[65-Hooking](../../65-Hooking/README.md) ·
[68-ReverseEngineering](../../68-ReverseEngineering/README.md) ·
[69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) ·
[70-VulnerabilityResearch](../../70-VulnerabilityResearch/README.md)

---

## This chapter's own files

| File | What it is |
|---|---|
| [`scripts/elf-harden-check.py`](../scripts/elf-harden-check.py) | The hardening checklist, stdlib-only, with per-check evidence and honest caveats. `--apk` mode also reports ZIP storage and alignment |
| [`scripts/elf-inspect.py`](../scripts/elf-inspect.py) | The `readelf` you always have. `--no-sections` answers only from `PT_DYNAMIC`, for files whose section headers cannot be trusted |
| [`scripts/so-triage.sh`](../scripts/so-triage.sh) | Ninety seconds of triage; uses `readelf` if present, falls back to the Python parsers if not |
| [`scripts/native-map.js`](../scripts/native-map.js) | Frida: module bases, live GOT state, `findExportByName` explained as it runs, `dlopen` watching |
| [`scripts/ctf-build-challenge.py`](../scripts/ctf-build-challenge.py) | Synthesises `libvault.so` for Lab 05 — an ELF whose section headers lie |
| [`examples/hardening-demo.c`](../examples/hardening-demo.c) | One source, six ELF files |
| [`examples/jni-surface.c`](../examples/jni-surface.c) | A library whose export table is the point |
| [`examples/build-fixtures.sh`](../examples/build-fixtures.sh) | Builds every fixture the labs need |
| [`examples/elf_header_by_hand.py`](../examples/elf_header_by_hand.py) | The parser Lab 01 asks you to write |
| [`labs/`](../labs/) | Five labs; the last is a CTF |
