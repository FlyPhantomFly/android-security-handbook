# 19 — Memory — References

Annotated. Each entry says what it is *for*, and where it disagrees with common belief.

> **A note on how these were used.** Every version boundary asserted in this chapter — the
> Scudo/jemalloc transition, HWASan's Android 10/11 split, MTE's Android 12/13 split, GWP-ASan's
> Android 14 default, the pointer-tag constant, the 16 KiB page timeline — was checked against the
> primary source below rather than recalled, and several of the behavioural claims were then
> *measured* on an Android 13 arm64 device with the fixtures in [`../examples/`](../examples/). Where
> the documentation and the device disagreed, the device won and the disagreement is recorded in the
> chapter. The quarantine and zero-on-free behaviour in §3.8 are both such cases.

---

## 1. AOSP source

File paths in the AOSP tree are stable and safe to cite. Line numbers are not, and none are given.

| Path | Why you would open it |
|---|---|
| `bionic/libc/bionic/malloc_tagged_pointers.h` | **The pointer-tagging implementation.** `POINTER_TAG` = `0xB4`, plus `TAG_SHIFT` (56), `CHECK_SHIFT` (48) and `UNTAG_SHIFT` (40). This is the file that explains why your `malloc` return value begins `0xb4`, and it is short enough to read in full. |
| `bionic/libc/bionic/malloc_common.cpp` | The `malloc`/`free`/`realloc` entry points, and the decision about whether to go through the dispatch table. Read it to understand why hooking `malloc` with Frida works regardless of which allocator is installed. |
| `bionic/libc/private/bionic_malloc_dispatch.h` | The dispatch table itself — a struct of function pointers. The mechanism by which malloc_debug, HWASan and the default allocator swap places. |
| `bionic/libc/bionic/heap_tagging.cpp` | How the heap tagging level is chosen at process start, which is where `targetSdkVersion` and `allowNativeHeapPointerTagging` are honoured. |
| `bionic/libc/malloc_debug/README.md` | **The authoritative malloc_debug option list**, with defaults and maxima. Do not take the option list from a blog post; take it from here. It is the source for this chapter's §3.14 table. |
| `bionic/libc/malloc_debug/README_api.md` | `malloc_iterate` and the native-heap callback API. How heap profilers walk live allocations without instrumenting the app. |
| `bionic/libc/malloc_debug/malloc_debug.cpp` | The debug allocator's implementation — read it when you want to know exactly what `free_track` or `fill_on_free` does rather than what it is documented to do. |
| `external/scudo/` | Scudo itself, imported from LLVM. The Android configuration is `scudo::AndroidConfig`, a name you will also see in real crash backtraces. |
| `bionic/linker/linker_phdr.cpp` | **`ElfReader::ReserveAddressSpace` and `ElfReader::LoadSegments`.** The two functions that explain the entire MODULES table: one `mmap(PROT_NONE)` for the whole span, then one `mmap(MAP_FIXED)` per `PT_LOAD`. This is why one library becomes four lines in `maps`. |
| `bionic/linker/linker.cpp` | `find_library`, `soinfo`, and the linker namespaces that make `dlopen` of a platform library fail even when the file is readable. |
| `bionic/libc/bionic/mmap.cpp` | The `mmap` wrapper, including the page-size handling. |
| `art/runtime/base/mem_map.cc` | **Where the `[anon:dalvik-…]` names come from.** ART builds these strings and passes them to `prctl(PR_SET_VMA_ANON_NAME)`. The whole basis of allocator and runtime fingerprinting. |
| `art/runtime/gc/heap.cc` | The ART heap and its spaces. Listed so you can see the boundary: this is [13-ART](../../13-ART/README.md)'s territory, not this chapter's. |
| `system/core/libmemunreachable/` | The unreachable-memory checker behind `check_unreachable_on_signal`. |

---

## 2. Official Android documentation

| Source | What it settles |
|---|---|
| **AOSP — Scudo** (`source.android.com/docs/security/test/scudo`) | The version boundary this chapter is cited for: *"Since the Android 11 release, scudo is used for all native code (except on low-memory devices, where jemalloc is still used)."* Also the option list (`QuarantineSizeKb`, `ZeroContents`, `DeallocationTypeMismatch`, `DeleteSizeMismatch`, the RSS limits) and the **exact error-message set** — *corrupted chunk header*, *race on chunk header*, *invalid chunk state*, *misaligned pointer*, *allocation type mismatch*, *invalid sized delete*, *RSS limit exhausted*. When one of those strings appears in a tombstone you are triaging, this is where to look it up. |
| **AOSP — HWAddressSanitizer** (`source.android.com/docs/security/test/hwasan`) | *"HWASan is only available on Android 10 and higher, and only on AArch64 hardware"*, with *"Userspace support for HWASan is available starting with Android 11."* Also `SANITIZE_TARGET := hwaddress` for platform builds, and the Android 14 `wrap.sh`/`LD_HWASAN=1` route for running HWASan apps on a non-HWASan device — which was **not supported before Android 14**. |
| **AOSP — Arm MTE** (`source.android.com/docs/security/test/memory-safety/arm-mte`) | MTE support from **Android 12**; the three modes (`sync`, `async`, `asymm`, the last on Armv8.7-A) and their signals (`SEGV_MTESERR`, `SEGV_MTEAERR`); and the enablement surface — `android:memtagMode`, `arm64.memtag.process.<basename>`, `MEMTAG_OPTIONS`, and the `NATIVE_MEMTAG_[A]SYNC` compatibility changes. |
| **AOSP — Tagged pointers** (`source.android.com/docs/security/test/tagged-pointers`) | *"Starting in Android 11, for 64-bit processes, all heap allocations have an implementation defined tag set in the top byte of the pointer"*, the `targetSdkLevel` ≥ 30 default, and `android:allowNativeHeapPointerTagging="false"` — described as not addressing "the underlying code health problem" and as something that "will disappear in future versions of Android". That last sentence is why seeing the attribute in a manifest is worth a question. |
| **AOSP — Security enhancements** (`source.android.com/docs/security/enhancements`) | The mitigation timeline used in §3.5's version matrix: hardware NX in 2.3, ASLR in 4.0, PIE support in 4.1, `FORTIFY_SOURCE` in 4.2, and Scudo listed under Android 10. |
| **AOSP — Native memory debugging** (`source.android.com/docs/core/tests/debug/native-memory`) | The entry point that points at `bionic/libc/malloc_debug/README.md`. Read the bionic file, not this page, for the option list. |
| **Android Developers — GWP-ASan** (`developer.android.com/ndk/guides/gwp-asan`) | *"GWP-ASan does not require source or recompilation (that is, works with prebuilts), and works on both 32- and 64-bit processes"*; availability for apps targeting API 30+; `android:gwpAsanMode` with `never`/`default`/`always`; and the crucial default change — *"On devices that run Android 14 (API level 34) or higher, all apps use Recoverable GWP-ASan by default"*, at roughly 1% of app launches. |
| **Android Developers — MTE** (`developer.android.com/ndk/guides/arm-mte`) | The developer-side view: the manifest example with `tools:replace`, the `adb shell am compat enable NATIVE_MEMTAG_SYNC` route, the Developer Options toggle, the stack-tagging flags (`-fsanitize=memtag`, `-fsanitize-memtag-mode=sync`, `-march=armv8-a+memtag`) which need Android 14 QPR3+, and the warning that MTE-instrumented builds are *"for debugging purposes only"*. |
| **Android Developers — Support 16 KB page sizes** (`developer.android.com/guide/practices/page-sizes`) | *"Beginning with Android 15, AOSP supports devices that are configured to use a page size of 16 KB"*; the Play requirement and its **1 February 2027** deadline; `-Wl,-z,max-page-size=16384`; the instruction to check that no `LOAD` alignment is below `2**14`; and the direct instruction to use `getpagesize()` or `sysconf(_SC_PAGESIZE)` rather than a hard-coded `4096`. |
| **Android Security Bulletins** (`source.android.com/docs/security/bulletin`) | Where to read *real* memory-safety vulnerabilities rather than invented ones. Open any month, read the "Media framework" and "System" tables, and count how many entries describe an out-of-bounds write or a use-after-free. The proportion is the useful fact, and it is one you can verify rather than one you have to trust. **This chapter deliberately cites no CVE identifier from memory.** |

---

## 3. Kernel and Linux documentation

| Source | Why |
|---|---|
| `Documentation/filesystems/proc.rst` in the Linux kernel tree | The definitive description of `/proc/<pid>/maps`, `smaps`, `smaps_rollup` and every counter and `VmFlags` code in this chapter's cheat sheet. |
| `prctl(2)` — `PR_SET_VMA`, `PR_SET_VMA_ANON_NAME` | The mechanism behind `[anon:NAME]`. Names appear in `maps` as `[anon:<name>]`; this is what makes allocator fingerprinting possible at all. |
| `mmap(2)`, `mprotect(2)`, `madvise(2)` | The three syscalls behind every region in `maps`. `mprotect` is what turns the RELRO segment from `rw-p` into `r--p` after relocation. |
| `proc(5)` | `/proc/<pid>/mem`, and the `ptrace` permission model that governs it — the answer to "why can I list the mappings but not read them". |

---

## 4. Compiler and sanitizer documentation

| Source | Why |
|---|---|
| **LLVM — Hardware-assisted AddressSanitizer Design Documentation** | The design behind the reports in §3.13.2, including the **short-granule** scheme that the "Tags for short granules around the buggy address" block in a real HWASan report refers to. Read it when a report's tag map does not look the way you expect. |
| **LLVM — AddressSanitizer** | The redzone-and-shadow design, for contrast with HWASan's tags. Useful for explaining why ASan costs roughly 3× memory and HWASan roughly 2×. |
| **LLVM — Scudo Hardened Allocator** | The upstream allocator documentation, including the option defaults that Android then overrides. The gap between the upstream `QuarantineSizeKb` default and Android's zero is exactly the kind of difference that makes measuring necessary. |
| **Clang — `-fsanitize=` documentation** | The authoritative list of what each sanitiser flag accepts. Worth checking against *your* toolchain: NDK r25c (clang 14.0.7) rejects `-fsanitize-memtag-mode=` and `-fsanitize=memtag-stack`, which is verified in this chapter and is not obvious from the general documentation. |

---

## 5. Architecture references

| Source | Why |
|---|---|
| **Arm — Memory Tagging Extension** architecture material | The hardware behind MTE: the 4-bit tag, the tagged-memory instructions, and the `SEGV_MTESERR`/`SEGV_MTEAERR` distinction. Also the source for "1 in 16 mismatches collide", which follows directly from the tag width. |
| **Arm — Top-Byte Ignore (TBI)** | The feature pointer tagging is built on. Explains why the top byte is available at all, and why none of this exists on 32-bit. |
| **Arm Architecture Reference Manual**, memory model and MMU chapters | Page tables, permission bits, and what actually happens on a permission fault. Reach for it when you need to explain *why* a mitigation cannot be bypassed in software. |

---

## 6. Research

| Source | Why |
|---|---|
| **Lee et al. — *From Zygote to Morula: Fortifying Weakened ASLR on Android*** (IEEE S&P) | The paper that quantified the Zygote ASLR consequence this chapter is cited for, and proposed replacing the model with `fork()` + `exec()`. It measured the memory cost of doing so, which is the honest counter-argument and the reason Android has not. Read it before arguing either side of §2.3. |
| Public analyses of Scudo's internals and of hardened allocators generally | Useful for the structure — primary/secondary, size classes, chunk headers, quarantine — but **check every number against your own device**. Allocator configuration varies by Android version, by OEM, by low-RAM status and by ABI, and this chapter found two documented defaults that Android does not use. |
| Android Security research on memory-safety trends (the AOSP security blog's periodic posts on the proportion of vulnerabilities that are memory-safety issues, and on Rust adoption) | The data behind §5.9's structural recommendation. When you tell a client "the fix is not better discipline, it is a memory-safe language for new code", this is the evidence. |

---

## 7. Standards and classifications

| Identifier | Name |
|---|---|
| CWE-119 | Improper restriction of operations within the bounds of a memory buffer |
| CWE-120 | Buffer copy without checking size of input (classic buffer overflow) |
| CWE-121 | Stack-based buffer overflow |
| CWE-122 | Heap-based buffer overflow |
| CWE-125 | Out-of-bounds read |
| CWE-190 | Integer overflow or wraparound |
| CWE-362 | Concurrent execution using shared resource with improper synchronisation (race condition) |
| CWE-415 | Double free |
| CWE-416 | Use after free |
| CWE-457 | Use of uninitialised variable |
| CWE-787 | Out-of-bounds write |
| CWE-843 | Access of resource using incompatible type (type confusion) |
| CWE-908 | Use of uninitialised resource |

**OWASP MASVS** — MASVS-CODE-3 (secure toolchain settings), MASVS-CODE-4 (input validation),
MASVS-STORAGE-2 (no unintended data exposure), MASVS-RESILIENCE-4 (integrity).
**OWASP MASTG** — the memory-analysis tests, which are the procedural counterpart to §7 of this
chapter.

> Check the current MASVS version in [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) before
> quoting a control identifier in a report. The identifiers were renumbered between MASVS v1 and v2
> and a stale one undermines an otherwise correct finding.

---

## 8. This chapter's own artefacts

| File | What it is, and what it is not |
|---|---|
| [`../examples/heap-bugs.c`](../examples/heap-bugs.c) | Six defects plus a no-bug `layout` mode. Built with `-Wall -Wextra` for arm64 and armeabi-v7a, and run on an Android 13 device. **Not** an exploitation demonstration. |
| [`../examples/heap-bugs-fixed.c`](../examples/heap-bugs-fixed.c) | The remediated counterpart. Runs to completion and exits 0 under HWASan with no sanitiser output — the control that makes the buggy build's report meaningful. |
| [`../examples/mem-landmarks.c`](../examples/mem-landmarks.c) | Address-space landmarks, page size, `mprotect` enforcement, guard pages. The `wx` and `guard` modes deliberately fault and survive it; the signal handler is a teaching device and is documented as one. |
| [`../examples/build-memory-fixtures.sh`](../examples/build-memory-fixtures.sh) | Builds all of the above seven ways and copies the HWASan and ASan runtimes out of the NDK. Writes nothing into the repository — binaries are build artefacts and this repository commits none. |
| [`../examples/fixture-app-maps.txt`](../examples/fixture-app-maps.txt) | **A synthetic capture**, and its own header says so at length. Structurally faithful; the addresses are invented. Do not quote an address from it as evidence about anything real. |
| [`../scripts/maps-analyse.py`](../scripts/maps-analyse.py) | Address-space triage: summary, allocator fingerprint, module table with load bases, findings. Standard library only. Prints properties, never verdicts — its header lists six things it will *not* tell you. |
| [`../scripts/enumerate-ranges.js`](../scripts/enumerate-ranges.js) | Frida: `Process.enumerateRanges()` diffed against `/proc/self/maps`, read through libc so it works on older frida-server builds. Labels Frida's own footprint rather than filtering it out. |
| [`../scripts/malloc-trace.js`](../scripts/malloc-trace.js) | Frida: measures stride, size classes and reuse. `probe()` is the controlled experiment; recording the app's own calls is expensive and off by default. |
| [`../scripts/mem-search.js`](../scripts/mem-search.js) | Frida: find a value in memory and, more importantly, classify the hit. `scrubTest()` is the before/after test that turns "the token is in memory" into a finding or an informational note. |

---

## 9. Related chapters

| Chapter | Boundary — what it owns that this one does not |
|---|---|
| [00-Introduction](../../00-Introduction/README.md) | How the repository fits together |
| [01-Computer-Science-Basics](../../01-Computer-Science-Basics/README.md) | Processes, stack frames, hex and endianness. Its lab 03 is the stack counterpart to this chapter's heap material |
| [02-Linux-Basics](../../02-Linux-Basics/README.md) | `/proc`, `adb shell`, file permissions, redirection |
| [06-Android-Architecture](../../06-Android-Architecture/README.md) | The Zygote and the boot chain — **why** it forks without `exec`. This chapter owns only the memory-layout consequence |
| [11-Android-Runtime](../../11-Android-Runtime/README.md) | The runtime as a whole |
| [13-ART](../../13-ART/README.md) | The **managed** heap, GC, `ArtMethod`, and Java heap dumps. Everything `[anon:dalvik-…]` |
| [15-Native-Code](../../15-Native-Code/README.md) | ELF format, and the **build-time** hardening checklist — NX, PIE, RELRO, canaries as properties of a *file*. This chapter owns what those cost an attacker at *run time* |
| [16-JNI](../../16-JNI/README.md) | `JNIEnv`, method registration, and the boundary where Java's bounds checking ends |
| [17-Libraries](../../17-Libraries/README.md) | *Which* third-party library is bundled, and whether that version is vulnerable |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Per-app isolation, built on the virtual memory this chapter describes |
| [40-Obfuscation](../../40-Obfuscation/README.md) | In-memory DEX carving — its sweep enumerates the regions §3.3 describes |
| [53-Frida](../../53-Frida/README.md) | Frida itself. This chapter owns what `Process.enumerateRanges` and `Memory.scan` are looking at |
| [57-Ghidra](../../57-Ghidra/README.md) | Decompilation. §6.5 here is the rebasing arithmetic it needs |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The MASVS/MASTG mapping, and the current identifier numbering |
| 18-ARM | The AArch64 instruction set and AAPCS64 — the instructions behind the addresses |
