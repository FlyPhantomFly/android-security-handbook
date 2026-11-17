# 13 — ART · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.

---

## The one command that matters

```bash
cmd package compile -m verify -f <pkg>   # everything → interpreter → hooks work
am force-stop <pkg>
```

Run this first whenever a Java hook installs but never fires.

---

## Artifacts on disk

| File | Really is |
|---|---|
| `base.odex` | **OAT file — an ELF.** Not a Dalvik ODEX |
| `base.vdex` | Verified DEX + verifier dependencies. **The bytecode lives here** |
| `base.art` | App image: pre-built object graph, mmap'd at startup |
| `boot.art` / `boot.oat` / `boot.vdex` | Boot image (framework classes) |

### Paths

```
/data/app/~~<rand>/<pkg>-<rand>/base.apk
/data/app/~~<rand>/<pkg>-<rand>/oat/arm64/{base.odex,base.vdex,base.art}
/data/misc/apexdata/com.android.art/dalvik-cache/arm64/   ← boot image (A12+)
/data/dalvik-cache/arm64/                                  ← legacy location
/data/misc/profiles/cur/<userId>/<pkg>/primary.prof        ← being written
/data/misc/profiles/ref/<pkg>/primary.prof                 ← input to dexopt
/data/misc/profman/                                        ← snapshot-profile output
/apex/com.android.art/{bin,lib64,javalib}/                 ← the ART Mainline module
```

Resolve the randomised path: `pm path <pkg>`

---

## Compiler filters

| Filter | Verifies | Compiles | Use |
|---|---|---|---|
| `assume-verified` | No | No | — |
| `extract` | No | No | Unpack only |
| `verify` | Yes | **No** | **Default for sideload. Best for hooking** |
| `quicken` | Yes | Quickens | **Removed in A11+** |
| `space-profile` | Yes | Profile, size-opt | — |
| `space` | Yes | All, size-opt | — |
| `speed-profile` | Yes | **Profile-selected** | **Normal steady state** |
| `speed` | Yes | **Everything** | **Worst for hooking — inlining** |
| `everything-profile` | Yes | Profile + skipped | Debug |
| `everything` | Yes | Absolutely all | Debug |

---

## Commands

### Compilation state

```bash
dumpsys package dexopt | grep -A5 "\[<pkg>\]"        # quick check
cmd package compile -m verify -f <pkg>               # → interpreter
cmd package compile -m speed -f <pkg>                # → full AOT
cmd package compile -m speed-profile -f <pkg>        # → profile-guided
cmd package compile --reset <pkg>                    # wipe artifacts
cmd package compile -a -m speed                      # all packages
cmd package bg-dexopt-job                            # run background dexopt now
```

| Flag | Meaning |
|---|---|
| `-m <filter>` | Compiler filter |
| `-f` | Force recompile |
| `--reset` | Delete artifacts |
| `-a` | All packages |
| `--secondary-dex` | Dynamically loaded DEX |
| `--check-prof` | Profile freshness handling |

### oatdump

```bash
oatdump --oat-file=<path>/base.odex --header-only
oatdump --oat-file=<path>/base.odex --class-filter=com.example.Auth
oatdump --oat-file=<path>/base.odex --class-filter=X --method-filter=Y
oatdump --vdex-file=<path>/base.vdex --header-only
oatdump --vdex-file=<path>/base.vdex --export-dex-to=/data/local/tmp/dex_out
oatdump --image=/data/misc/apexdata/com.android.art/dalvik-cache/arm64/boot.art
```

### Profiles

```bash
cmd package snapshot-profile <pkg>
ls -l /data/misc/profman/
profman --dump-only --profile-file=<prof>
profman --dump-only --profile-file=<prof> --apk=<apk> --dex-location=base.apk
```

### Diagnostics

```bash
logcat -s art                          # ART's own logs: GC, dexopt, verification
dumpsys meminfo <pkg>                  # dalvik vs native heap
am dumpheap <pid> /data/local/tmp/h.hprof
hprof-conv h.hprof h-std.hprof         # host: convert for MAT/Studio
am start --track-allocation <pkg>/<act>
```

---

## OAT header key-value store

| Key | Why |
|---|---|
| `compiler-filter` | **The compilation state. Check this first** |
| `dex2oat-cmdline` | Exact compiler invocation |
| `bootclasspath` | Must match at load or OAT is rejected |
| `bootclasspath-checksums` | " |
| `apex-versions` | " |
| `concurrent-copying` | GC assumed |
| `native-debuggable` | Debug info present |

### OAT symbols

```bash
readelf -s base.odex | grep -E "oatdata|oatexec|oatlastword"
xxd -l 8 base.odex     # 7f45 4c46 = ELF (correct). "dey\n" = Dalvik ODEX (ancient)
```

### OAT validation chain (any failure → fall back to interpreter)

1. OAT version matches runtime
2. Instruction set matches device
3. Boot class path string + checksums match
4. APEX versions match
5. DEX checksums match

---

## ArtMethod

```cpp
GcRoot<mirror::Class> declaring_class_;   // owning class
uint32_t              access_flags_;      // modifiers + ART bits + hidden-API bits
uint32_t              dex_method_index_;  // → DEX method_ids
uint16_t              method_index_;      // vtable / IMT slot
uint16_t              hotness_count_;     // JIT counter
void*                 data_;              // JNI fn ptr for native methods
void*                 entry_point_from_quick_compiled_code_;  // *** THE HOOK TARGET ***
```

### Entry point values → execution state

| Points at | State |
|---|---|
| Address in OAT `oatexec` | AOT compiled |
| Address in JIT code cache | JIT compiled |
| `art_quick_to_interpreter_bridge` | **Interpreted** |
| `art_quick_resolution_trampoline` | Unresolved; first call resolves |
| `art_quick_generic_jni_trampoline` | Native, generic stub |
| `art_quick_imt_conflict_trampoline` | Interface dispatch collision |
| `art_quick_instrumentation_entry` | Instrumentation active |

---

## Why a hook fails

| Symptom | Cause | Fix |
|---|---|---|
| Never fires | **Inlined** into caller | `cmd package compile -m verify -f` |
| Fires sometimes | Some sites inlined | Force deoptimization |
| Fires, old behaviour | Caller baked in result | Force interpretation |
| `ClassNotFoundException` | Wrong `ClassLoader` | `Java.enumerateClassLoaders` |
| Wrong overload | Signature mismatch | `.overload(...)` explicitly |
| Interface vs impl | Hooked declaration | Hook the concrete class |

---

## Interpreters

| Name | Era | Notes |
|---|---|---|
| Switch | Always | Portable C++; used when debugging/instrumenting. **Slow** |
| mterp | A6–A10 | Hand-written asm |
| nterp | A11+ | Template asm + inline caches. Made quickening unnecessary |

---

## JIT

| Property | Effect |
|---|---|
| `dalvik.vm.usejit` | Enable/disable JIT |
| `dalvik.vm.jitthreshold` | Invocations → compile |
| `dalvik.vm.jitwarmupthreshold` | Baseline tier |
| `dalvik.vm.jitosrthreshold` | On-stack replacement |
| `dalvik.vm.jitmaxsize` | Code cache cap |
| `dalvik.vm.usejitprofiles` | Profile recording |

JIT code cache = anonymous `r-xp`, often `[anon:jit-code-cache]` in `/proc/<pid>/maps`.
Legitimate executable anonymous memory → naive anti-Frida checks false-positive here.

---

## dalvik.vm.* properties

```bash
getprop | grep -E "dalvik\.vm|ro\.dalvik"
```

| Property | Effect |
|---|---|
| `dalvik.vm.heapstartsize` | Initial heap |
| `dalvik.vm.heapgrowthlimit` | Per-app cap (raised by `largeHeap`) |
| `dalvik.vm.heapsize` | Absolute max |
| `dalvik.vm.dex2oat-filter` | Default app filter |
| `dalvik.vm.image-dex2oat-filter` | Boot image filter |
| `dalvik.vm.checkjni` | Enable CheckJNI |
| `dalvik.vm.execution-mode` | e.g. `int:fast` |

Maximally observable device: `dalvik.vm.usejit false` + `cmd package compile -m verify -f`

---

## Manifest attributes affecting ART

| Attribute | Effect |
|---|---|
| `android:vmSafeMode="true"` | **Disables JIT + AOT optimisation.** All interpreted |
| `android:largeHeap="true"` | Raises heap cap |
| `android:debuggable="true"` | JDWP + CheckJNI + forces interpretation |
| `android:extractNativeLibs="false"` | `.so` mmap'd from APK |

---

## Heap spaces

| Space | Moves? | Contents |
|---|---|---|
| `ImageSpace` | No | Boot/app image; read-only, shared |
| `RegionSpace` | **Yes** | Main allocation; concurrent copying |
| `LargeObjectSpace` | No | Big arrays |
| `NonMovingSpace` | No | Classes, internal structures |
| `ZygoteSpace` | No | Inherited COW from Zygote |

Objects move → raw addresses invalid across GC → Frida uses handles.

---

## JNI references

| Kind | Lifetime | Table |
|---|---|---|
| Local | Until native method returns | Per-thread IRT |
| Global | Until `DeleteGlobalRef` | Process-wide |
| Weak global | Until collected | Weak table |

`jobject` = tagged index into a table, **not** an address.

```bash
setprop dalvik.vm.checkjni true    # global, next app start
setprop debug.checkjni 1           # single app
```

---

## Mainline

```bash
dumpsys package com.google.android.art | grep versionName
getprop ro.build.version.security_patch
```

Two devices, same Android version, **different ART internals**. Never hard-code `ArtMethod` offsets.

`odrefresh` regenerates the boot image after a module update → `odsign` signs it → all app OAT files
invalidated → background dexopt recompiles over the following hours.

---

## Class status ladder

```
kNotReady → kIdx → kLoaded → kResolving → kResolved → kVerifying
  → kVerified → kSuperclassValidated → kInitializing → kInitialized
  → kVisiblyInitialized
```

Error states: `kErrorResolved`, `kErrorUnresolved`, `kRetryVerificationAtRuntime`,
`kVerifiedNeedsAccessChecks`, `kRetired`

---

## Dispatch

| Instruction | Mechanism |
|---|---|
| `invoke-static` / `invoke-direct` | Resolved method, dex cache |
| `invoke-super` | Superclass vtable |
| `invoke-virtual` | `method_index_` → receiver's **vtable** |
| `invoke-interface` | **IMT** (64 slots); collision → `imt_conflict_trampoline` → `IfTable` |

---

## Extract DEX from a device

```bash
# adb shell as root
APK=$(pm path <pkg> | head -1 | sed 's/package://')
oatdump --vdex-file=$(dirname $APK)/oat/arm64/base.vdex \
        --export-dex-to=/data/local/tmp/dex_out
```
```bash
# host
adb pull /data/local/tmp/dex_out && jadx -d out ./dex_out/*.dex
```

Use this when installed bytecode may differ from the APK (in-place patch, packer, system app).

---

## Quickening (A8–A10 only)

| Generic | Quickened |
|---|---|
| `iget`/`iput` | `iget-quick`/`iput-quick` |
| `iget-object`/`iput-object` | `-object-quick` |
| `invoke-virtual` | `invoke-virtual-quick` |

Not valid standalone DEX → `baksmali` fails → needs unquickening (`vdexExtractor`).
Gone from A11+ (nterp).

---

## Rules

1. Check `compiler-filter` **before** debugging a hook.
2. `-m verify -f` isolates inlining in one command.
3. Never hard-code `ArtMethod` offsets — probe them.
4. Bytecode is in the **VDEX**, not the OAT.
5. `base.odex` is an ELF, not a Dalvik ODEX.
6. Object addresses are invalid across a GC.
7. The verifier is **not** a sandbox.
8. Record the ART module version in every report.
9. Overnight charging → background dexopt → behaviour changes.
10. Snapshot the profile before anything that triggers recompilation.
