# 65 — Hooking · Cheat sheet

Dense reference. Prose lives in [README.md](README.md).

---

## 1. The five hook types

| # | Type | Overwrites | Prerequisite | Scope | Reversible | Detectable by | Fails when |
|---|---|---|---|---|---|---|---|
| 1 | **Managed (ART)** | `ArtMethod.entry_point_from_quick_compiled_code_` | Java VM; root + injection | One method | Yes (restore pointer) | Reading the entry point back; comparing to known module ranges | Callee AOT-inlined; JIT rewrites it; non-default `ClassLoader` |
| 2 | **Inline / trampoline** | The function's first 4/8/16 bytes | Writable code page; instruction analysis | Whole process | Yes (restore bytes) | Reading the prologue; `.text` checksum | Prologue unrelocatable; no room; branch into patch region; function inlined away |
| 3 | **PLT / GOT** | One pointer in `.got.plt` | Symbol must be **imported** | **One module** | Yes (restore pointer) | `dladdr` on the slot; GOT checksum | Intra-module call; symbol inlined by compiler; resolved via `dlsym` |
| 4 | **Interposition** | Nothing — resolution *order* | Control of the `execve` environment | Whole process, from start | No (restart) | Comparing resolution to expectation | Zygote-forked app processes — i.e. almost always on Android |
| 5 | **`RegisterNatives`** | `JNINativeMethod.fnPtr` / runtime's copy | Dynamic registration; arrive at/before `JNI_OnLoad` | One native method | Yes | Comparing `fnPtr` against the module's address range | Static registration; you arrived after registration |

### Choosing

```
Decision in Java?                    -> managed        (then: cmd package compile -m verify -f)
Native, crosses a module boundary?   -> PLT/GOT        (cheapest, reversible, invisible to text checksums)
Native, intra-module call?           -> inline         (nothing else reaches it)
Native method, C name unknown?       -> RegisterNatives (and be early)
Every caller in the process?         -> inline on the export (and accept the noise)
Only need to KNOW, not change?       -> observe. Always cheaper, always a better finding.
```

---

## 2. Verified AArch64 encodings

Round-tripped with NDK 25.2.9519653 clang 14.0.7 (`clang -c -x assembler` → `llvm-objdump -d`).
Cross-checked against [`18-ARM/scripts/arm64-patch.py --show-encodings`](../18-ARM/scripts/arm64-patch.py).

| Instruction | Word | Bytes in file (LE) | Use |
|---|---|---|---|
| `ldr x16, #8` | `0x58000050` | `50 00 00 58` | Absolute-jump patch, word 0 |
| `br  x16` | `0xd61f0200` | `00 02 1f d6` | Absolute-jump patch, word 1 |
| `ldr x17, #8` | `0x58000051` | `51 00 00 58` | Same, using IP1 |
| `br  x17` | `0xd61f0220` | `20 02 1f d6` | Same, using IP1 |
| `blr x16` | `0xd63f0200` | `00 02 3f d6` | Call through a register |
| `ret` | `0xd65f03c0` | `c0 03 5f d6` | Wholesale replacement, word 1 |
| `nop` | `0xd503201f` | `1f 20 03 d5` | Neutralise one instruction |
| `mov w0, #0` | `0x52800000` | `00 00 80 52` | Force `false` |
| `mov w0, #1` | `0x52800020` | `20 00 80 52` | Force `true` |
| `mov x0, #0` | `0xd2800000` | `00 00 80 d2` | Force null / 0 (64-bit) |
| `bti c` | `0xd503245f` | `5f 24 03 d5` | Re-emit a BTI landing pad you overwrote |
| `brk #0` | `0xd4200000` | `00 00 20 d4` | Breakpoint-based hook |
| `b   .` (offset 0) | `0x14000000` | `00 00 00 14` | Base for a direct branch |
| `b   .+4` | `0x14000001` | `01 00 00 14` | Confirms the ×4 scaling |
| `b   .-4` | `0x17ffffff` | `ff ff ff 17` | Confirms sign extension |
| `bl  .` (offset 0) | `0x94000000` | `00 00 00 94` | Base for a direct call |
| `stp x29,x30,[sp,#-16]!` | `0xa9bf7bfd` | `fd 7b bf a9` | Typical prologue word 0 |
| `ldp x29,x30,[sp],#16` | `0xa8c17bfd` | `fd 7b c1 a8` | Typical epilogue |
| `adrp x0, #0` | `0x90000000` | `00 00 00 90` | Base for an `adrp` |

> **Bytes in file are reversed relative to the word.** `fd 7b bf a9` is the word `a9bf7bfd`.
> Confusing the two is the most common reason a hand patch lands backwards.

---

## 3. The three patch forms

| Form | Bytes | Reach | Displaces | Needs a trampoline? |
|---|---|---|---|---|
| **Direct branch** | 4 | ±128 MiB | 1 instruction | Yes, to call through |
| **Absolute jump** | 16 | unlimited | 4 instructions | Yes, to call through |
| **Wholesale replacement** | 8 | n/a | 2 instructions, **discarded** | **No** |

```
ABSOLUTE JUMP (16 bytes)                 WHOLESALE REPLACEMENT (8 bytes)
  +0   58000050   ldr x16, #8              +0   52800020   mov w0, #1
  +4   d61f0200   br  x16                  +4   d65f03c0   ret
  +8   .quad <destination>

DIRECT BRANCH (4 bytes)
  +0   0x14000000 | (((dest - here) >> 2) & 0x03FFFFFF)
       refuse if |dest - here| > 128 MiB
```

---

## 4. Branch and address-formation reach

| Instruction | Immediate | Scale | Reach | Relocatable by this chapter's engine? |
|---|---|---|---|---|
| `b`, `bl` | 26 bits signed | ×4 | **±128 MiB** | Refused (encodable, but a wrong branch fails far from the bug) |
| `adrp` | 21 bits signed | ×4096 | **±4 GiB** | **Yes — re-encode the immediate** |
| `adr` | 21 bits signed | ×1 | ±1 MiB | Refused |
| `ldr` (literal) | 19 bits signed | ×4 | ±1 MiB | Refused |
| `b.cond` | 19 bits signed | ×4 | ±1 MiB | Refused (needs a veneer) |
| `cbz`, `cbnz` | 19 bits signed | ×4 | ±1 MiB | Refused (needs a veneer) |
| `tbz`, `tbnz` | 14 bits signed | ×4 | **±32 KiB** | Refused |

---

## 5. Relocating `adrp`

```
Encoding:   31   30 29    28..24     23.................5   4..0
             1   immlo    1 0 0 0 0  immhi (19 bits)        Rd

Computes:   (PC & ~0xFFF) + (SignExtend(immhi:immlo) << 12)
Immediate:  signed count of 4 KiB PAGES, 21 bits  ->  ±4 GiB
```

```c
int64_t imm  = sign_extend(((w >> 5) & 0x7FFFF) << 2 | ((w >> 29) & 3), 21);
uintptr_t page  = (old_pc & ~0xFFFULL) + (imm << 12);              /* where it pointed  */
int64_t   delta = (int64_t)(page - (new_pc & ~0xFFFULL)) >> 12;    /* from the new home */
/* refuse if delta > 0xFFFFF or delta < -0x100000 */
uint32_t out = (w & 0x9F00001FU) | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5);
```

**Worked example, measured:**

| | |
|---|---|
| Original at | `0x71f982b71c`, page `0x71f982b000`, imm `1` |
| Targets page | `0x71f982b000 + (1 << 12)` = `0x71f982c000` |
| Copy at | `0x71f9829008`, page `0x71f9829000` |
| New imm | `(0x71f982c000 − 0x71f9829000) >> 12` = `3` |
| Re-encoded | `0xb0000008 \| (3 << 29)` = **`0xf0000008`** |

---

## 6. Instruction classification masks

```c
is_adrp(w)    (w & 0x9F000000) == 0x90000000
is_adr(w)     (w & 0x9F000000) == 0x10000000
is_ldr_lit(w) (w & 0x3B000000) == 0x18000000
is_b(w)       (w & 0xFC000000) == 0x14000000
is_bl(w)      (w & 0xFC000000) == 0x94000000
is_bcond(w)   (w & 0xFF000010) == 0x54000000
is_cbz(w)     (w & 0x7E000000) == 0x34000000
is_tbz(w)     (w & 0x7E000000) == 0x36000000
is_ret(w)     (w & 0xFFFFFC1F) == 0xD65F0000
is_bti(w)     (w & 0xFFFFFF3F) == 0xD503241F
```

Everything not matched above is position independent and may be copied verbatim.

---

## 7. The six steps of an inline hook

| # | Step | Call / value |
|---|---|---|
| 1 | Find the target | `dlsym`, or `module_base + file_offset` from `dl_iterate_phdr` |
| 2 | Choose the patch size | 4 / 8 / 16 bytes — see §3 |
| 3 | Allocate a trampoline **within range** | `mmap(..., MAP_FIXED_NOREPLACE)` and search outward |
| 4 | Copy + relocate displaced words, append a jump back to `target+N` | §5, §6 |
| 5 | `mprotect` RW(X), write, `mprotect` back | Retry without `PROT_EXEC` if refused |
| 6 | **Flush the I-cache** | `__builtin___clear_cache(start, end)` |

---

## 8. Trampoline allocation

| | |
|---|---|
| `mmap` hint (advisory) | **Do not rely on it.** Measured: returned a page **10.3 GiB** away, outside `adrp` range |
| `MAP_FIXED` | **Never.** Silently unmaps whatever is there; the process dies elsewhere |
| `MAP_FIXED_NOREPLACE` | **Correct.** Maps exactly there or fails. Search ± page by page |
| Range requirement | Within ±4 GiB of every relocated `adrp` target page; ±128 MiB if using a direct branch |
| Measured result with the search | Trampoline landed **10,004 bytes** below the target |

---

## 9. PLT / GOT

| | |
|---|---|
| Table | `.got.plt`, populated from `DT_JMPREL` relocations, sized by `DT_PLTRELSZ` |
| Relocation type | **1026** = `0x402` = `R_AARCH64_JUMP_SLOT` |
| Alternative | **1025** = `0x401` = `R_AARCH64_GLOB_DAT`, under `DT_RELA` (goes through `.got`) |
| Slot address | `load_base + r_offset` |
| Symbol name | `DT_STRTAB + symtab[ELF64_R_SYM(r_info)].st_name` |
| Rebasing caveat | `d_un.d_ptr` may or may not be pre-relocated — add the base when the value is below it |
| Full RELRO | Costs **one `mprotect`**. Does not prevent the hook |
| Scope | **One module.** Measured: library's `strcmp` redirected, host binary's `strcmp` untouched |

```bash
llvm-readelf --relocs lib.so | grep JUMP_SLOT     # what can be PLT-hooked
llvm-readelf -d       lib.so | grep -E 'BIND_NOW|FLAGS'
llvm-readelf -l       lib.so | grep GNU_RELRO
```

---

## 10. Why hooks fail

| Failure | Symptom | One-command diagnostic | Fix |
|---|---|---|---|
| **Callee inlined** | Fires when called directly, never in the app | `llvm-objdump -d lib.so \| grep "bl.*<name>"` → empty | Hook the caller; or the PLT call the inlined copy still makes |
| **AOT-compiled caller** | Managed hook installs, never dispatches | — | `adb shell cmd package compile -m verify -f <pkg>` then force-stop |
| **Target unresolved** | `dlsym` → `NULL`; `ClassNotFoundException` | `llvm-readelf --dyn-syms lib.so \| grep name` | Hook `dlopen`; use `base + offset`; enumerate `ClassLoader`s |
| **Timing** | Everything correct, output empty | — | `frida -U -f` (spawn) not `-n` (attach); hook `android_dlopen_ext` |
| **Prologue unrelocatable** | `Interceptor` throws; hand engine refuses | `python3 -B hookability.py lib.so --symbol name` | Smaller patch; different hook point; different hook type |
| **Branch into patch region** | Works, then corrupts on a specific path | `hookability.py` reports it | Different hook point |
| **BTI landing pad destroyed** | Indirect calls fault, direct calls fine | `hookability.py` warns | Re-emit `bti c` (`0xd503245f`) first |

---

## 11. Diagnostic order

```
1. Did it install?        print bytes before and after
2. Did it fire?           log unconditionally on entry
3. Never fired, native?   grep for `bl` to the symbol -> inlining
4. Never fired, Java?     cmd package compile -m verify -f ; force-stop
5. Never fired, late?     spawn instead of attach ; hook dlopen
6. Fired, no change?      you hooked a producer; find the consumer
7. Only now               suspect the hooking engine
```

---

## 12. Registers at a function's first instruction

| Register | Holds | Safe for a hook to clobber? |
|---|---|---|
| `x0`–`x7` | Arguments | No — read them, then preserve |
| `x8` | Indirect result location | No |
| **`x16`, `x17`** | IP0/IP1, scratch | **Yes** — AAPCS64 permits a veneer to destroy them at a call boundary |
| `x18` | Shadow call stack pointer (Android) | **Never** |
| `x19`–`x28` | Callee-saved | No |
| `x29` | Frame pointer | No |
| `x30` | Return address (the caller) | No — but free to *read* |

The `x16`/`x17` licence applies **at the entry boundary only**. Mid-function, they may be live.

---

## 13. Commands

```bash
# device identity, before trusting any version-gated claim
adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk
adb shell "su -c id" 2>/dev/null || adb shell "su 0 id" 2>/dev/null || echo "not rooted"

# run a native binary when /data/local/tmp refuses execve (errno ENXIO, exit 126)
adb shell /system/bin/linker64 /data/local/tmp/prog

# build fixtures (outside the repo)
cd 65-Hooking/examples && ANDROID_NDK=... ./build-hook-fixtures.sh --run

# hook surface of a library or APK
./scripts/hook-surface.sh lib.so
./scripts/hook-surface.sh app.apk

# is one function safely inline-hookable?
python3 -B scripts/hookability.py lib.so --symbol name -v
python3 -B scripts/hookability.py lib.so --all
python3 -B scripts/hookability.py lib.so --symbol name --patch-bytes 4

# disassembly and symbols
llvm-objdump -d --section=.text lib.so | sed -n '/<name>:/,/^$/p'
llvm-readelf --dyn-syms lib.so | grep -E '\bJava_|JNI_OnLoad'
llvm-readelf --relocs   lib.so | grep JUMP_SLOT

# round-trip an encoding, never write one from memory
printf '.globl _e\n_e:\n  ret\n  nop\n' > /tmp/e.s
$NDK/aarch64-linux-android21-clang -c -x assembler /tmp/e.s -o /tmp/e.o && $NDK/llvm-objdump -d /tmp/e.o
python3 -B ../18-ARM/scripts/arm64-patch.py --show-encodings

# managed hook not firing
adb shell cmd package compile -m verify -f <pkg> && adb shell am force-stop <pkg>
```

---

## 14. Frida one-liners

```javascript
Module.findExportByName('libnative.so', 'checkLicense')
hexdump(Module.findExportByName('libnative.so', 'checkLicense'), { length: 32 })

Interceptor.attach(Module.findExportByName('libc.so', 'strcmp'), {
    onEnter: function (a) { console.log(a[0].readCString(), '<=>', a[1].readCString()); } });

Interceptor.replace(Module.findExportByName('libnative.so', 'checkLicense'),
    new NativeCallback(function () { return 1; }, 'int', []));

// GOT entries that point outside every mapped module = hooked, or a bug
Process.findModuleByName('libnative.so').enumerateImports()
    .filter(i => i.slot && !Process.findModuleByAddress(i.slot.readPointer()));

// what execution state is this Java method in?  -> 13-ART/scripts/artmethod-inspect.js
```

---

## 15. Measured facts from this chapter

Device: **`i9000S`, Android 13 / API 33, arm64, unrooted, no frida-server**, 8× Cortex-A53
(`implementer 0x41`, `part 0xd03`). Toolchain: NDK 25.2.9519653, clang 14.0.7.

| Claim | Measurement |
|---|---|
| `mmap` hints are advisory | Hint at target+1 MiB returned a page **+11,097,491,692 bytes** (10.3 GiB) away — outside `adrp` range; relocation failed |
| `MAP_FIXED_NOREPLACE` search works | Trampoline placed **−10,004 bytes** from the target |
| `adrp` relocation | `b0000008` → `f0000008`, imm `1` → `3`, target page `0x71f982c000` preserved |
| Static and dynamic agree | `hookability.py` reported target page `0x2000`; load base `0x71f982a000` + `0x2000` = `0x71f982c000` |
| Hook calls through | 4 hooked calls, exported `guard_counter` = **4** |
| `mprotect` RWX on library text | **Succeeded** for a `shell`-domain process on API 33 |
| Omitting the I-cache flush | **Did not fail**, twice, after 2,000,000 warm-up calls. Architecturally still required |
| PLT hook scope | Library's `strcmp` redirected (0 → 1); host binary's `strcmp("a","b")` still `−1` |
| `libguard.so` relocations | 3 × `DT_JMPREL`, all type **1026** (`R_AARCH64_JUMP_SLOT`) |
| Inlining at `-O2` | `lic_is_valid` exported at `0x164c`, body inlined into `lic_open_feature`; **zero** `bl` to it |
| Prologue checksum sensitivity | One `nop` at `+12` inside the checked region → `−2` (TAMPERED) |
| Constant folding defeats XOR obfuscation | `#define KEY 0x5A` let clang emit the decoded strings into `.rodata`; `volatile` prevents it |
| `/data/local/tmp` execve | Refused (`No such device or address`, exit 126); `/system/bin/linker64 <exe>` works |
