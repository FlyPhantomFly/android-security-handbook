# 19 — Memory — Cheat Sheet

Dense reference. Explanations are in [README.md](README.md).
Deeper: [15-Native-Code](../15-Native-Code/README.md) (ELF, build-time hardening) ·
[13-ART](../13-ART/README.md) (managed heap) · [53-Frida](../53-Frida/README.md) (instrumentation)

---

## 1. `/proc/<pid>/maps` — field by field

```
7bd3ebb000-7bd3f4c000 r-xp 0003d000 fc:04 618    /apex/com.android.runtime/lib64/bionic/libc.so
[1]                   [2]  [3]      [4]   [5]    [6]
```

| # | Field | Format | Notes |
|---|---|---|---|
| 1 | address range | `START-END`, hex, no `0x` | END is **exclusive**. size = END − START |
| 2 | permissions | 4 chars | see §2 |
| 3 | file offset | hex | where in the file this mapping starts. `00000000` for anonymous |
| 4 | device | `major:minor` hex | `00:00` = no backing file |
| 5 | inode | decimal | `0` = no backing file. **Same inode = same file** |
| 6 | path | free text | see §1.1. May be empty; may contain spaces |

### 1.1 Path field — five shapes

| Shape | Example | Meaning |
|---|---|---|
| filesystem path | `/system/lib64/libc.so` | mapped from that file |
| path + `(deleted)` | `/data/.../.tmp7712 (deleted)` | file unlinked, mapping survives |
| `[bracket]` | `[stack]` `[heap]` `[vdso]` `[vvar]` | kernel-provided special region |
| `[anon:NAME]` | `[anon:scudo:primary]` | userspace named it via `prctl(PR_SET_VMA_ANON_NAME)` |
| empty | | unnamed anonymous memory |

### 1.2 `[anon:NAME]` labels — the fingerprint table

| Name contains | Means |
|---|---|
| `scudo:primary` | Scudo small/medium regions — **the native heap** |
| `scudo:secondary` | Scudo large allocations, individually mapped |
| `libc_malloc` | pre-Scudo bionic heap / generic path |
| `GWP-ASan guard`, `GWP-ASan alive slot` | GWP-ASan sampling is active |
| `SizeClassAllocator: region data` | **sanitizer_common** — HWASan or ASan is running |
| `LargeMmapAllocator` | sanitizer_common large-allocation path |
| `dalvik-main space (region space)` | **ART managed heap (Java)** |
| `dalvik-zygote space` | Zygote heap, shared copy-on-write |
| `dalvik-non moving space` | ART non-moving space |
| `dalvik-large object space allocation` | ART LOS |
| `dalvik-free list large object space` | ART LOS free list |
| `dalvik-jit-code-cache` | ART JIT output — **expect `rwxp`** |
| `dalvik-CompilerMetadata` | ART compiler metadata |
| `dalvik-indirect ref table` | JNI global / weak-global refs |
| `stack_and_tls:NNN` | a thread stack + TLS |
| `thread signal stack` | alternate signal stack |
| `linker_alloc` | dynamic linker's own allocations |
| `bionic_alloc_small_objects` | bionic internal — **not** the app heap |
| `.bss` | zero-init data beyond the file-backed segment |
| `cfi shadow` | Control Flow Integrity shadow table |
| `arc4random data` | bionic RNG state |
| `atexit handlers` | registered exit handlers |
| `System property context nodes` | property service mappings |

---

## 2. Page-protection flags

| String | `r` | `w` | `x` | share | Where you see it |
|---|---|---|---|---|---|
| `r--p` | y | | | private | `.rodata`, ELF headers, RELRO after locking |
| `r-xp` | y | | y | private | `.text` — code |
| `rw-p` | y | y | | private | `.data`, `.bss`, heap, stacks |
| `rwxp` | y | y | y | private | JIT caches. Rare elsewhere |
| `--xp` | | | y | private | **execute-only (XOM)** — hardening, not a problem |
| `---p` | | | | private | **guard page** — mapped, PROT_NONE, all access faults |
| `r--s` | y | | | shared | ashmem, `/dev/__properties__`, shared files |
| `rw-s` | y | y | | shared | shared memory — another process can change it |
| `r-xs` | y | | y | shared | shared executable mapping |

- 4th char: `p` = `MAP_PRIVATE` (copy-on-write), `s` = `MAP_SHARED`.
- Frida's `protection` string is **3 characters** and drops the share bit.
- Enforcement is by the MMU. There is no code path to hook.

### 2.1 `mprotect` / `mmap` constants

| C constant | Value | maps char |
|---|---|---|
| `PROT_NONE` | 0 | `---` |
| `PROT_READ` | 1 | `r` |
| `PROT_WRITE` | 2 | `w` |
| `PROT_EXEC` | 4 | `x` |
| `MAP_SHARED` | 0x01 | `s` |
| `MAP_PRIVATE` | 0x02 | `p` |
| `MAP_FIXED` | 0x10 | — |
| `MAP_ANONYMOUS` | 0x20 | no path |

---

## 3. `/proc/<pid>/smaps` — counters, field by field

All values in kB. `smaps` = every `maps` line + ~20 counters.

| Counter | Meaning | Use it for |
|---|---|---|
| `Size` | virtual size = END − START | nothing; it is redundant |
| `KernelPageSize` | page size the kernel uses here | 4 or 16 |
| `MMUPageSize` | page size the MMU uses here | usually equals the above |
| `Rss` | **resident** — pages in physical memory now | which regions a dump would find content in |
| `Pss` | **proportional** — shared pages ÷ sharers | fair per-process attribution |
| `Shared_Clean` | shared, unmodified | Zygote-inherited pages |
| `Shared_Dirty` | shared, modified | |
| `Private_Clean` | yours alone, unmodified | |
| `Private_Dirty` | **yours alone, modified** | **the true cost of this process** |
| `Referenced` | touched recently | |
| `Anonymous` | not file-backed | heap + stack |
| `LazyFree` | `MADV_FREE`d but not reclaimed | |
| `AnonHugePages` | transparent huge pages | |
| `ShmemPmdMapped`, `FilePmdMapped` | huge-page-mapped shmem/file | |
| `Shared_Hugetlb`, `Private_Hugetlb` | explicit huge pages | |
| `Swap` | paged out | on Android, usually zram |
| `SwapPss` | paged out, proportional | |
| `Locked` | `mlock`ed, never swappable | key material sometimes |
| `THPeligible` | 0/1 | |
| `ProtectionKey` | pkey, x86 only | |
| `VmFlags` | 2-letter flags | see below |

### 3.1 `VmFlags` two-letter codes (common ones)

| Code | Meaning | | Code | Meaning |
|---|---|---|---|---|
| `rd` | readable | | `mr` | may read |
| `wr` | writable | | `mw` | may write |
| `ex` | executable | | `me` | may execute |
| `sh` | shared | | `ms` | may share |
| `gd` | stack grows down | | `ac` | area is accountable |
| `lo` | **locked (`mlock`)** | | `nr` | swap space not reserved |
| `dd` | **do not include in core dump** | | `io` | memory-mapped I/O |
| `ht` | huge-tlb page | | `nl` | non-linear mapping |
| `mm` | mixed map area | | `sd` | soft-dirty flag |

`/proc/<pid>/smaps_rollup` — the same totals in one short block, far cheaper to read.

---

## 4. Allocator by Android version

| Android | API | Allocator | Notes |
|---|---|---|---|
| ≤ 4.x | ≤ 19 | dlmalloc | |
| 5.0 – 9 | 21–28 | jemalloc | |
| 10 | 29 | jemalloc default; **Scudo introduced** | AOSP security enhancements list Scudo in Android 10 |
| **11+** | **30+** | **Scudo** for all native code | **except low-memory devices, where jemalloc is still used** |

> Do **not** infer the allocator from the version. Read the `[anon:]` names (§1.2).

### 4.1 Scudo, measured (Android 13, arm64, non-low-RAM)

| Property | Value |
|---|---|
| Structure | primary (per-size-class regions) + secondary (individual `mmap`) |
| Chunk header | 16 bytes, immediately before the payload, **checksummed** |
| Stride, 32-byte request | **48 bytes** (32 payload + 16 header) |
| Allocation order in a class | **randomised** (anti-grooming) |
| Quarantine | **off by default on Android** — freed block returned immediately |
| Zero on free | **off by default** — old contents remain |
| 64 KiB request | still in the **primary** |
| 4 MiB request | in the **secondary** |

### 4.2 Scudo error messages (documented set)

```
Scudo ERROR: corrupted chunk header at address 0x...
Scudo ERROR: race on chunk header at address 0x...
Scudo ERROR: invalid chunk state when deallocating address 0x...
Scudo ERROR: misaligned pointer when deallocating address 0x...
Scudo ERROR: allocation type mismatch when deallocating address 0x...
Scudo ERROR: invalid sized delete when deallocating address 0x...
Scudo ERROR: RSS limit exhausted
```

### 4.3 What a stock device catches

| Defect | Caught | Where |
|---|---|---|
| double free | **yes** | `free()` — `invalid chunk state` |
| invalid / interior free | **yes** | `free()` — `corrupted chunk header` |
| heap overflow (any size) | no | — |
| use-after-free read or write | no | — |
| uninitialised read | no | — |

### 4.4 `SCUDO_OPTIONS` (environment variable, colon-separated)

| Option | Upstream default | Effect |
|---|---|---|
| `QuarantineSizeKb` | 256 (64-bit) / 64 (32-bit) | delay reuse of freed blocks |
| `ThreadLocalQuarantineSizeKb` | | per-thread quarantine |
| `ZeroContents` | | zero memory on allocation |
| `DeallocationTypeMismatch` | | abort on `new`/`free` mismatch |
| `DeleteSizeMismatch` | | abort on wrong sized delete |
| `soft_rss_limit_mb`, `hard_rss_limit_mb` | | RSS caps |

```bash
# adb shell -- a process you control; apps cannot set their own environment
SCUDO_OPTIONS=QuarantineSizeKb=256:ThreadLocalQuarantineSizeKb=64 ./binary
```

---

## 5. Pointer tagging

| Aspect | Value |
|---|---|
| Mechanism | Arm **TBI** (Top-Byte-Ignore) |
| Since | **Android 11**, 64-bit processes, kernels with TBI support |
| Default | on for `targetSdkVersion` ≥ 30; off below |
| Constant | `POINTER_TAG` = **`0xB4`** — `bionic/libc/bionic/malloc_tagged_pointers.h` |
| Shifts (same file) | `TAG_SHIFT` 56, `CHECK_SHIFT` 48, `UNTAG_SHIFT` 40 |
| Under HWASan / MTE | tag is **random per allocation**, not constant |
| 32-bit | **no tagging at all** |
| Disable | `<application android:allowNativeHeapPointerTagging="false">` (documented as temporary) |

```c
/* untag -- ULL, not UL: `unsigned long` is 32 bits on armeabi-v7a */
#if UINTPTR_MAX > 0xffffffffU
    uintptr_t clean = (uintptr_t)p & (uintptr_t)0x00ffffffffffffffULL;
#else
    uintptr_t clean = (uintptr_t)p;
#endif
```

```javascript
// Frida
function untag(p) { return Process.pointerSize === 8 ? p.and(ptr('0x00ffffffffffffff')) : p; }
```

Three places it bites: comparing with `maps`; subtracting two pointers; `==` between two pointers to
the same memory (HWASan gives the same address a new tag).

---

## 6. Detection: modes and how to enable them

### 6.1 Comparison

| | HWASan | MTE sync | MTE async | GWP-ASan | malloc_debug | ASan |
|---|---|---|---|---|---|---|
| Rebuild | **yes** | no (heap) | no (heap) | **no** | **no** | **yes** |
| Arch | AArch64 only | Armv8.5+ | Armv8.5+ | any | any | any |
| Android | 10+ (userspace 11+) | 12+ (devices 13+) | 12+ | 11+ (default 14+) | any | any |
| Alloc + free stacks | **yes** | no | no | yes | with `backtrace` | yes |
| Coverage | all instrumented accesses | all heap accesses | all heap accesses | **~1% sampled** | all heap ops | all |
| Overhead | ~2× mem, high CPU | moderate | **low** | negligible | high | ~3× mem, ~2× CPU |
| Shippable | no | marginal | **yes** | **yes** | no | no |

### 6.2 HWASan

```bash
# build
aarch64-linux-android29-clang -O1 -g -fno-omit-frame-pointer \
    -fsanitize=hwaddress -o app-hwasan app.c

# the runtime is a DT_NEEDED entry -- push it too
llvm-readelf -d app-hwasan | head -3
adb push $NDK/.../lib/linux/libclang_rt.hwasan-aarch64-android.so /data/local/tmp/

# run
adb shell 'LD_LIBRARY_PATH=/data/local/tmp /data/local/tmp/app-hwasan'

# platform-wide, on a -userdebug build
SANITIZE_TARGET := hwaddress

# app on a non-HWASan device, Android 14+: wrap.sh setting
LD_HWASAN=1
```

Report fields:

| Field | Meaning |
|---|---|
| `tag-mismatch on address 0x…` | the **untagged** address accessed |
| `at pc 0x…` | faulting instruction; subtract the module base for a decompiler |
| `READ/WRITE of size N` | the access |
| `tags: XX/YY (ptr/mem)` | pointer tag vs memory tag |
| `Cause: use-after-free` / `heap-buffer-overflow` | the classification |
| `0 bytes inside of` | offset within the allocation (UAF) |
| `0 bytes to the right of` | overflow |
| `freed by thread T… here` | **the free stack** |
| `previously allocated here` | **the allocation stack** |
| tag map | 1 byte per 16-byte granule; `00` = unallocated |

```bash
llvm-symbolizer --obj=app-hwasan 0x30d4 0x3048 0x2f84
```

### 6.3 MTE

| Mode | Behaviour | Signal |
|---|---|---|
| `off` | none | — |
| `sync` | checked at the access, precise | `SIGSEGV` / `SEGV_MTESERR` |
| `async` | deferred to kernel entry | `SIGSEGV` / `SEGV_MTEAERR` |
| `asymm` | sync reads, async writes (Armv8.7-A) | — |

```xml
<application android:memtagMode="sync" />   <!-- off | default | sync | async -->
```

```bash
adb shell am compat enable NATIVE_MEMTAG_SYNC  com.example.app
adb shell am compat enable NATIVE_MEMTAG_ASYNC com.example.app
adb shell setprop arm64.memtag.process.<basename> sync
MEMTAG_OPTIONS=sync ./native-binary        # takes precedence over the property
# Settings -> Developer options -> Memory Tagging Extension

# hardware check
adb shell grep -o mte /proc/cpuinfo | head -1
```

Stack tagging (Android 14 QPR3+, needs a newer NDK than r25c):

```
APP_CFLAGS  := -fsanitize=memtag -fno-omit-frame-pointer -march=armv8-a+memtag
APP_LDFLAGS := -fsanitize=memtag -fsanitize-memtag-mode=sync -march=armv8-a+memtag
```

> NDK r25c rejects `-fsanitize-memtag-mode=` and `-fsanitize=memtag-stack`, and `-fsanitize=memtag`
> alone emits no `.note.android.memtag`.

### 6.4 GWP-ASan

```xml
<application android:gwpAsanMode="always" />   <!-- never | default | always -->
```

| Android | Default for non-system apps |
|---|---|
| ≤ 13 | disabled |
| 14+ | **Recoverable GWP-ASan enabled**, ~1% of app launches |

Detects use-after-free and heap-buffer-overflow. Works on prebuilts, 32- and 64-bit.
Visible as `[anon:GWP-ASan …]` with `---p` guards.

### 6.5 malloc_debug

```bash
adb shell setprop libc.debug.malloc.options "guard fill free_track backtrace leak_track"
adb shell setprop libc.debug.malloc.program my-binary
adb shell setprop wrap.com.example.app '"LIBC_DEBUG_MALLOC_OPTIONS=backtrace logwrapper"'
export LIBC_DEBUG_MALLOC_OPTIONS=backtrace
```

| Option | Default | Effect |
|---|---|---|
| `front_guard[=N]` | 32 | pattern before the allocation, checked on free |
| `rear_guard[=N]` | 32 | pattern after the allocation, checked on free |
| `guard[=N]` | 32 | both |
| `backtrace[=N]` | 16 frames | record the allocation stack |
| `backtrace_enable_on_signal[=N]` | 16 | start recording on a signal |
| `backtrace_dump_on_exit` | | dump at exit |
| `backtrace_dump_prefix` | | output path prefix |
| `backtrace_min_size`, `backtrace_max_size`, `backtrace_size` | | limit by allocation size |
| `backtrace_full` | | deeper unwinding |
| `fill_on_alloc[=N]` | | fill new allocations |
| `fill_on_free[=N]` | | fill freed allocations |
| `fill[=N]` | | both |
| `expand_alloc[=N]` | 16 | enlarge every allocation |
| `free_track[=N]` | 100 | quarantine N frees and check for later writes |
| `free_track_backtrace_num_frames[=N]` | 16 | stack depth for the above |
| `leak_track` | | report live allocations at exit |
| `record_allocs[=N]` | 8,000,000 | log every allocation |
| `record_allocs_file[=PATH]`, `record_allocs_on_exit` | | where and when |
| `verify_pointers` | | check `free` gets a real allocation |
| `check_unreachable_on_signal` | | run the leak checker on demand |
| `log_allocator_stats_on_signal` | | dump allocator stats |
| `abort_on_error` | | abort instead of logging |
| `verbose` | | more logging |

---

## 7. Capturing dumps

### 7.1 Java heap dump (HPROF) — the **ART** heap

```bash
adb shell am dumpheap com.example.app /data/local/tmp/dump.hprof     # debuggable or root
adb shell am dumpheap -n com.example.app /data/local/tmp/native.txt  # native heap, if supported
adb pull /data/local/tmp/dump.hprof
hprof-conv dump.hprof dump-std.hprof        # for Eclipse MAT; Android Studio reads the raw form
```

Also: Android Studio Profiler → Memory → "Capture heap dump"; `Debug.dumpHprofData(path)` in code.

### 7.2 Native memory

```javascript
// Frida -- dump one identified region
var r = Process.findRangeByAddress(ptr('0x7300000000'));
var f = new File('/data/local/tmp/region.bin', 'wb');
f.write(Memory.readByteArray(r.base, r.size));
f.close();
```

```bash
# root -- read a region out of /proc/<pid>/mem using maps for the offsets
dd if=/proc/<pid>/mem bs=4096 skip=$((0x7300000000/4096)) count=64 of=/data/local/tmp/r.bin
```

```bash
# tombstones (root, or a debuggable app)
adb shell ls -l /data/tombstones/
adb pull /data/tombstones/tombstone_00
```

### 7.3 Which one answers which question

| Question | Tool |
|---|---|
| Which Java object holds this string, and what keeps it alive? | HPROF + MAT / Android Studio |
| What bytes are at this address? | Frida / `/proc/<pid>/mem` |
| Is my secret still in native memory after logout? | `scripts/mem-search.js` `scrubTest()` |
| Which regions have content worth dumping? | `smaps` `Rss` |
| Why did it crash? | tombstone + logcat |

---

## 8. Commands

### 8.1 Device fingerprint (run first)

```bash
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.config.low_ram          # 'true' -> jemalloc may still be in use
adb shell getconf PAGESIZE                   # 4096 or 16384
adb shell grep -o mte /proc/cpuinfo | head -1
```

### 8.2 Maps

```bash
adb shell cat /proc/self/maps                       # your shell -- works
adb shell cat /proc/<app-pid>/maps                  # DENIED by SELinux on Android 13
adb shell cat /proc/self/smaps       > s.txt
adb shell cat /proc/self/smaps_rollup

grep ' rwx' maps.txt                                # writable + executable
grep '(deleted)' maps.txt                           # unlinked but mapped
grep '/memfd:' maps.txt                             # anonymous file objects
grep -- '--xp' maps.txt                             # execute-only
grep ' rw-s ' maps.txt                              # shared + writable
grep -o '\[anon:[^]]*\]' maps.txt | sort | uniq -c | sort -rn
```

### 8.3 This chapter's tools

```bash
python3 scripts/maps-analyse.py maps.txt
python3 scripts/maps-analyse.py maps.txt --gaps --all
python3 scripts/maps-analyse.py smaps.txt --smaps
python3 scripts/maps-analyse.py maps.txt --module libc.so
python3 scripts/maps-analyse.py maps.txt --json
python3 scripts/maps-analyse.py --pid self          # Linux / WSL only
python3 scripts/maps-analyse.py maps.txt --strict   # exit 1 on any finding (CI)

frida -U -n com.example.app -l scripts/enumerate-ranges.js
frida -U -n com.example.app -l scripts/malloc-trace.js
frida -U -n com.example.app -l scripts/mem-search.js
```

### 8.4 Fixtures

```bash
cd examples && ./build-memory-fixtures.sh /tmp/ch19
adb shell mkdir -p /data/local/tmp/ch19
adb push /tmp/ch19/. /data/local/tmp/ch19/
adb shell chmod 755 /data/local/tmp/ch19/heap-bugs /data/local/tmp/ch19/mem-landmarks

adb shell /data/local/tmp/ch19/heap-bugs layout
adb shell 'LD_LIBRARY_PATH=/data/local/tmp/ch19 /data/local/tmp/ch19/heap-bugs-hwasan uaf'
adb shell /data/local/tmp/ch19/mem-landmarks wx
adb shell /data/local/tmp/ch19/mem-landmarks guard
```

> **Two traps.** Git Bash mangles `adb push` destinations — prefix `MSYS_NO_PATHCONV=1`.
> Some devices refuse to `exec` from `/data/local/tmp` (`No such device or address`) — run through
> `/system/bin/linker64 <absolute path>`.

### 8.5 Crash triage

```bash
adb logcat -d -s DEBUG,libc,scudo | tail -60
adb logcat | grep -E 'SEGV_MTESERR|SEGV_MTEAERR'
adb logcat -d | grep -E 'Scudo ERROR|Abort message|tag-mismatch'
```

| Signal / message | Means |
|---|---|
| `SIGSEGV` `SEGV_MAPERR` | access to unmapped memory |
| `SIGSEGV` `SEGV_ACCERR` | mapped, wrong permission — NX or RELRO violation |
| `SIGSEGV` `SEGV_MTESERR` / `SEGV_MTEAERR` | **MTE caught it** |
| `SIGABRT` + `Scudo ERROR: …` | the allocator caught it |
| `SIGABRT` + `stack corruption detected` | a stack canary fired |
| `SIGBUS` `BUS_ADRALN` | unaligned access, usually a corrupted pointer |
| `fault addr` made of ASCII (`0x4141…`) | data being used as a pointer |
| same stack, **different** fault addresses | signature of a **use-after-free** |

---

## 9. Manifest attributes relevant to this chapter

```bash
grep -nE 'memtagMode|gwpAsanMode|allowNativeHeapPointerTagging|extractNativeLibs' AndroidManifest.xml
```

| Attribute | Values | Reading |
|---|---|---|
| `android:memtagMode` | `off` `default` `sync` `async` | MTE. `sync` in a release build is unusual |
| `android:gwpAsanMode` | `never` `default` `always` | `never` disables a free detector — ask why |
| `android:allowNativeHeapPointerTagging` | `true` `false` | **`false` is a red flag**; documented as temporary |
| `android:extractNativeLibs` | `true` `false` | `false` → libs mapped from inside the APK, non-zero file offsets |

---

## 10. Page sizes

| | |
|---|---|
| Traditional | 4096 bytes |
| Since Android 15 | devices may be configured for **16384** |
| Play requirement | apps targeting API 35+ must support 16 KB; updates rejected from **2027-02-01** |
| Ask the system | `sysconf(_SC_PAGESIZE)` or `getpagesize()` — **never** hard-code |
| NDK r27+ | `PAGE_SIZE` is undefined in 16 KB mode, deliberately |
| Build flags (NDK ≤ r27) | `-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384` |
| Check a `.so` | `llvm-readelf -l lib.so` — no `LOAD` alignment below `2**14` |
| Symptom if wrong | the library does not load at all, or `mprotect` protects the wrong page |

---

## 11. Runtime mitigations — what each costs an attacker

| Mitigation | Stops | Does **not** stop | Runtime evidence |
|---|---|---|---|
| NX / W^X | shellcode in a data buffer | ROP/JOP; JIT needs RWX | no `rwx` except JIT |
| ASLR | hard-coded addresses | leaks; Zygote-shared layout | different bases per `exec` |
| PIE | a fixed executable base | nothing alone | `ET_DYN` executable |
| Full RELRO + BIND_NOW | GOT overwrite | a function pointer in `.data` | an `r--p` segment over the GOT |
| Stack canary | linear stack overflow to the return address | targeted writes; heap bugs | `__stack_chk_fail` |
| `_FORTIFY_SOURCE` | compile-time-sizeable overflows | runtime-computed sizes | `__memcpy_chk` imports |
| CFI | invalid indirect call targets | data-only corruption | `[anon:cfi shadow]` |
| Shadow Call Stack | return-address overwrite | forward-edge attacks | reserves `x18` |
| PAC (Armv8.3+) | using a corrupted pointer | signing gadgets | `pacia` / `autia` |
| BTI (Armv8.5+) | jumping mid-function | gadgets at valid landing pads | `bti` at entries |
| XOM | reading code to find gadgets | gadgets found from the file | `--xp` in maps |
| Pointer tagging | mismatched tag at deallocation | nothing alone | top byte `0xb4` |
| MTE | UAF and overflow at the access | ~1-in-16 tag collisions | `SEGV_MTESERR` |

Build-time detection of all of these: `python3 ../15-Native-Code/scripts/elf-harden-check.py`

---

## 12. Reachability checklist

| # | Question | Answered by |
|---|---|---|
| 1 | Does attacker-influenced input reach the bug? | source, fuzzing, or the crash stack |
| 2 | Does the bad access happen on that path? | a sanitiser report |
| 3 | What is next door? | measured stride (`malloc-trace.js` `neighbours(N)`) |
| 4 | Does the attacker control what goes next door? | source — a same-size-class allocation they fill |
| 5 | Is the corrupted value read or called? | sanitiser report, or crash registers |
| 6 | Do the mitigations stop the final step? | §11, per step |

**Unreachable ⇒ low severity. Say so plainly.**

---

## 13. CWE quick reference

| CWE | Name |
|---|---|
| 119 | improper restriction of operations within a memory buffer |
| 120 | classic buffer overflow |
| 121 | stack-based buffer overflow |
| 122 | heap-based buffer overflow |
| 125 | out-of-bounds read |
| 190 | integer overflow or wraparound |
| 362 | race condition |
| 415 | double free |
| 416 | use after free |
| 457 | use of uninitialised variable |
| 787 | out-of-bounds write |
| 843 | type confusion |
| 908 | use of uninitialised resource |

---

## 14. AOSP paths

| Path | Contents |
|---|---|
| `bionic/libc/bionic/malloc_tagged_pointers.h` | `POINTER_TAG` 0xB4, `TAG_SHIFT` 56, `CHECK_SHIFT` 48, `UNTAG_SHIFT` 40 |
| `bionic/libc/bionic/malloc_common.cpp` | `malloc`/`free` entry points, dispatch |
| `bionic/libc/private/bionic_malloc_dispatch.h` | the dispatch table |
| `bionic/libc/bionic/heap_tagging.cpp` | tagging level selection at process start |
| `bionic/libc/malloc_debug/README.md` | malloc_debug options — authoritative |
| `bionic/libc/malloc_debug/README_api.md` | `malloc_iterate` and profiler callbacks |
| `bionic/libc/malloc_debug/malloc_debug.cpp` | the debug allocator |
| `external/scudo/` | Scudo, imported from LLVM |
| `bionic/linker/linker_phdr.cpp` | `ReserveAddressSpace`, `LoadSegments` |
| `bionic/linker/linker.cpp` | `find_library`, namespaces |
| `art/runtime/base/mem_map.cc` | the `[anon:dalvik-…]` names |
| `art/runtime/gc/heap.cc` | the ART heap and its spaces (chapter 13) |
| `system/core/libmemunreachable/` | the unreachable-memory checker |
