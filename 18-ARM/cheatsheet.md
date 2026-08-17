# 18 — ARM · Cheat Sheet

> Printable. Tables and commands only. Explanations are in [README.md](README.md).
> Every encoding and every listing here came from NDK 25.2.9519653 (clang 14.0.7) via
> `llvm-objdump`. Reproduce with [`examples/build-arm-fixtures.sh`](examples/build-arm-fixtures.sh).

---

## Registers — AArch64

| Register | Alias | Role (AAPCS64) | Preserved across a call? |
|---|---|---|---|
| `x0`–`x7` | `w0`–`w7` | Arguments 1–8; `x0` returns the result | No |
| `x8` | `w8` | Indirect result location; **syscall number** | No |
| `x9`–`x15` | `w9`–`w15` | Caller-saved scratch | No |
| `x16` | `w16` | `IP0` — linker veneer / PLT scratch | No |
| `x17` | `w17` | `IP1` — linker veneer / PLT scratch | No |
| `x18` | `w18` | Platform: **shadow call stack** on Android | Reserved |
| `x19`–`x28` | `w19`–`w28` | Callee-saved | **Yes** |
| `x29` | — | Frame pointer (`FP`) | **Yes** |
| `x30` | — | Link register (`LR`) — return address | **Yes** |
| `sp` | `wsp` | Stack pointer; 16-byte aligned | **Yes** |
| `pc` | — | Program counter; not writable | — |
| `xzr` | `wzr` | Zero register: reads 0, writes discarded | — |
| `v0`–`v7` | `q`/`d`/`s`/`h`/`b` | FP/SIMD arguments and result | No |
| `v8`–`v15` | | FP/SIMD | **Low 64 bits only** |
| `v16`–`v31` | | FP/SIMD | No |
| `TPIDR_EL0` | — | Thread pointer (system register, `mrs`) | — |

**Rule:** writing `wN` **zeroes** the upper 32 bits of `xN`.

## Registers — ARM32 (armeabi-v7a)

| Register | Role (AAPCS32) | Preserved? |
|---|---|---|
| `r0`–`r3` | Arguments 1–4; `r0` (and `r1`) return | No |
| `r4`–`r11` | Callee-saved (`r7` is the Thumb frame pointer, `r11` the ARM one) | **Yes** |
| `r12` (`ip`) | Veneer scratch | No |
| `r13` (`sp`) | Stack pointer | **Yes** |
| `r14` (`lr`) | Link register | **Yes** |
| `r15` (`pc`) | **Program counter — writable** | — |

## AAPCS64 at a glance

| What | Where |
|---|---|
| Integer/pointer args 1–8 | `x0`–`x7` |
| Integer/pointer arg 9+ | `[sp]`, `[sp,#8]`, … at the call |
| FP/vector args 1–8 | `v0`–`v7` (independent counter) |
| Integer return | `x0` |
| FP return | `v0` |
| Struct return ≤ 16 bytes | `x0`, `x1` |
| Struct return > 16 bytes | Caller buffer; pointer in `x8` |
| Return address | `x30` |
| **JNI: `JNIEnv*`** | `x0` |
| **JNI: `jobject`/`jclass`** | `x1` |
| **JNI: first Java argument** | `x2` |
| Stack alignment | `sp` 16-byte aligned when used as a base |

## Condition codes

| Code | Meaning | Flags | Signedness |
|---|---|---|---|
| `eq` / `ne` | == / != | `Z==1` / `Z==0` | — |
| `hs` (`cs`) / `lo` (`cc`) | ≥ / < | `C==1` / `C==0` | **unsigned** |
| `hi` / `ls` | > / ≤ | `C&&!Z` / else | **unsigned** |
| `ge` / `lt` | ≥ / < | `N==V` / `N!=V` | **signed** |
| `gt` / `le` | > / ≤ | `!Z&&N==V` / else | **signed** |
| `mi` / `pl` | negative / non-negative | `N==1` / `N==0` | signed |
| `vs` / `vc` | overflow / no overflow | `V==1` / `V==0` | signed |
| `al` | always | — | — |

**Flags are set only by** `cmp`, `cmn`, `tst`, and the `s`-suffixed forms (`adds`, `subs`, `ands`,
`bics`, `negs`). `cmp Xn, #k` is `subs xzr, Xn, #k`. `tst Wn, #k` is `ands wzr, Wn, #k`.

## Pattern recognition table

| You see | It is |
|---|---|
| `stp x29, x30, [sp, #-N]!` | Prologue: allocate + save FP/LR |
| `ldp x29, x30, [sp], #N` | Epilogue: restore + deallocate |
| No `stp x29, x30` anywhere | **Leaf function — calls nothing** |
| `stp x20, x19, [sp, #N]` | Values must survive a `bl` |
| `sub sp, sp, #N` then `stp x29,x30,[sp,#M]` | Frame too big for pre-index |
| `cbz x0, L` as the first real instruction | NULL check on argument 1 |
| `cmp Wn, #k` + `cset Wd, cc` + `ret` | **`return <comparison>;` — the check** |
| `csel Wd, Wn, Wm, cc` | Branchless `?:` |
| `tst Wn, #imm` | Bit test |
| `tbz`/`tbnz Xn, #b, L` | Test one bit and branch |
| `adrp Xd, P` + `add Xd, Xd, #o` | **Address** `P+o` — usually a `.rodata` string |
| `adrp Xd, P` + `ldr Xd, [Xd,#o]` | Load a pointer from the **GOT** |
| `movz` + `movk` chain | A large constant, 16 bits at a time |
| `adrp x16, P` / `ldr x17,[x16,#o]` / `add x16,x16,#o` / `br x17` | **PLT stub** |
| `b <addr>` as the last instruction, no `ret` | **Tail call** |
| `blr Xn` | Indirect call: function pointer / virtual method |
| `br x16` or `br x17` | PLT or veneer, not app logic |
| `ldp q1, q0, [x1]` + `stp q1, q0, [x0]` | Inlined 32-byte `memcpy` |
| `ldrb` | Byte load, **zero**-extended |
| `ldrsb` | Byte load, **sign**-extended |
| `ldur`/`stur` | Unscaled = negative offset, usually `[x29,#-N]` |
| `mrs Xn, TPIDR_EL0` + `ldr Xd, [Xn,#40]` | **Stack canary load** |
| `ldur Xd, [x29,#-8]` + `cmp` + `b.ne` | Canary check |
| `bl __stack_chk_fail` | Canary mismatch path |
| `mov w8, #N` + `svc #0` | **Direct syscall `N`** |
| `mrs Xn, CNTVCT_EL0` | Timing check (anti-debug) |
| `hint #34` | `bti c` landing pad — **do not overwrite** |
| `hint #25` / `paciasp` | Pointer authentication sign |
| `mov w0, wzr` + `ret` | `return false;` |
| `eor` … `orr` … `cmp #0` + `cset eq` | **Inlined constant-time `memcmp`** |
| `movi v0.2d,#0` … `addv s0,v0.4s` … scalar loop | Vectorised loop; read the scalar tail |
| `ldr w0, [x8, w0, sxtw #2]` after `b.hi` | `switch` jump table |
| `mvn`, `clz` + `lsr #5` (ARM32) | Branchless "is zero" |
| `pop {r4, r5, r11, pc}` (ARM32) | Return by popping into `pc` |
| `ite` / `it` (Thumb) | Conditional-execution block |

## Verified encodings

`python3 scripts/arm64-patch.py --show-encodings` reprints this with the assembly source.

| Instruction | Word | Bytes in file (LE) |
|---|---|---|
| `ret` | `0xd65f03c0` | `c0 03 5f d6` |
| `nop` | `0xd503201f` | `1f 20 03 d5` |
| `mov w0, #0` | `0x52800000` | `00 00 80 52` |
| `mov w0, #1` | `0x52800020` | `20 00 80 52` |
| `mov w0, #2` | `0x52800040` | `40 00 80 52` |
| `mov w0, #42` | `0x52800540` | `40 05 80 52` |
| `mov w0, #65535` | `0x529fffe0` | `e0 ff 9f 52` |
| `mov x0, #0` | `0xd2800000` | `00 00 80 d2` |
| `mov x0, #1` | `0xd2800020` | `20 00 80 d2` |
| `mov w0, wzr` | `0x2a1f03e0` | `e0 03 1f 2a` |
| `b .` (offset 0) | `0x14000000` | `00 00 00 14` |
| `bl .` (offset 0) | `0x94000000` | `00 00 00 94` |
| `cmp w0, #1` | `0x7100041f` | `1f 04 00 71` |
| `cset w0, gt` | `0x1a9fd7e0` | `e0 d7 9f 1a` |
| `cset w0, eq` | `0x1a9f17e0` | `e0 17 9f 1a` |
| `csel w0, w0, w1, lt` | `0x1a81b000` | `00 b0 81 1a` |
| `cbz x0, .` | `0xb4000000` | `00 00 00 b4` |
| `cbnz x0, .` | `0xb5000000` | `00 00 00 b5` |
| `stp x29, x30, [sp,#-16]!` | `0xa9bf7bfd` | `fd 7b bf a9` |
| `ldp x29, x30, [sp],#16` | `0xa8c17bfd` | `fd 7b c1 a8` |
| `mrs x8, TPIDR_EL0` | `0xd53bd048` | `48 d0 3b d5` |
| `svc #0` | `0xd4000001` | `01 00 00 d4` |
| `brk #0` | `0xd4200000` | `00 00 20 d4` |
| `blr x8` | `0xd63f0100` | `00 01 3f d6` |
| `br x16` | `0xd61f0200` | `00 02 1f d6` |
| `bti c` (`hint #34`) | `0xd503245f` | `5f 24 03 d5` |

**Building an encoding by hand:** `mov wN, #imm` = `0x52800000 | (imm << 5) | N`.
`mov xN, #imm` = `0xD2800000 | (imm << 5) | N`. `b <target>` =
`0x14000000 | (((target - here) / 4) & 0x03FFFFFF)`; `bl` uses `0x94000000`.

## Greppable byte signatures

All at 4-byte alignment. A hit at an odd offset is data.

| Bytes | Instruction | Why you care |
|---|---|---|
| `c0 03 5f d6` | `ret` | Function boundaries |
| `01 00 00 d4` | `svc #0` | **Direct syscall — evades libc hooks** |
| `00 00 20 d4` | `brk #0` | Trap / breakpoint |
| `.. d0 3b d5` | `mrs Xn, TPIDR_EL0` | **Canary-protected functions** |
| `5f 24 03 d5` | `bti c` | BTI landing pads |
| `3f 23 03 d5` | `paciasp` | PAC-protected functions |
| `e0 03 1f 2a` | `mov w0, wzr` | `return false` |
| `20 00 80 52` | `mov w0, #1` | Your patch |

## Address arithmetic

| Number | Source | Used for |
|---|---|---|
| Virtual address | `p_vaddr` in the program headers; what objdump/Ghidra/Frida print | Reading |
| **File offset** | `p_offset` in the program headers | **Patching** |
| Runtime address | `module.base + virtual address` | Hooking, breakpoints |
| Ghidra address | image base (`0x00100000` default) + virtual address | Only inside Ghidra |

```
file offset      = vaddr - segment.p_vaddr + segment.p_offset      (per segment!)
runtime address  = module base + vaddr
ghidra address   = 0x00100000 + vaddr                              (default image base)
```

**ARM32:** `st_value & 1` is the Thumb bit. Clear it to disassemble or compute an offset; keep it to
call through a pointer.

## Commands — build the fixtures

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"
cd 18-ARM/examples && ./build-arm-fixtures.sh /tmp/ch18
```

| Output | What it is |
|---|---|
| `libpatterns64.so` | arm64, `-O2`, canary on — the pattern catalogue |
| `libpatterns64-O0.so` | arm64, `-O0` — textbook prologues |
| `libpatterns64-nocanary.so` | arm64, `-O2`, `-fno-stack-protector` — the canary A/B |
| `libpatterns32-arm.so` | armeabi-v7a, ARM state (`-marm`) |
| `libpatterns32-thumb.so` | armeabi-v7a, Thumb state (`-mthumb`) |
| `liblicence.so` | arm64 — the patch target |
| `licence-runner` | arm64 Android executable that `dlopen`s it |

## Commands — disassemble

```bash
NB=$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt/<host>/bin

$NB/llvm-objdump -d --no-show-raw-insn lib.so | less        # easiest to read
$NB/llvm-objdump -d lib.so | less                            # with bytes (for patching)
$NB/llvm-objdump -d --start-address=0x48c4 --stop-address=0x48d0 lib.so
$NB/llvm-objdump -d --no-show-raw-insn lib.so | sed -n '/<fn>:/,/^$/p'
$NB/llvm-objdump -d -S lib.so                                # interleave source, if debug info
$NB/llvm-objdump -s -j .rodata lib.so                        # resolve adrp+add targets
$NB/llvm-objdump -h lib.so                                   # section addresses
```

## Commands — symbols, imports, hardening

```bash
$NB/llvm-readelf --dyn-syms -W lib.so | grep ' FUNC '        # exports
$NB/llvm-readelf --symbols  -W lib.so | grep ' FUNC '        # + internals, if not stripped
$NB/llvm-readelf --dyn-syms -W lib.so | grep ' UND '         # imports
$NB/llvm-readelf --dyn-syms    lib.so | grep __stack_chk_fail   # canary present?
$NB/llvm-readelf -d  lib.so | grep -E 'BIND_NOW|FLAGS'       # RELRO
$NB/llvm-readelf -h  lib.so | grep Machine                   # which ABI
$NB/llvm-readelf --notes lib.so                              # NDK + API level stamp
$NB/llvm-readelf -l  lib.so                                  # PT_LOAD -> the patch delta
```

## Commands — this chapter's scripts

> **Run these with `python3 -B`** if you invoke them from inside this repository.
> `find-check-shapes.py` loads `arm64-patch.py` with `importlib`, and CPython writes a
> `__pycache__/` next to the source when it does. `-B` suppresses that; `PYTHONDONTWRITEBYTECODE=1`
> does **not** suppress it for `importlib.util.module_from_spec`. This repository commits no build
> artefacts, and a stray `__pycache__` is one.

```bash
# triage: which functions look like checks?
python3 scripts/find-check-shapes.py liblicence.so
python3 scripts/find-check-shapes.py liblicence.so --show --min-score 5
python3 scripts/find-check-shapes.py liblicence.so --json

# the verified encoding table
python3 scripts/arm64-patch.py --show-encodings

# what is in this file, and where?
python3 scripts/arm64-patch.py liblicence.so --list-symbols

# look before you patch
python3 scripts/arm64-patch.py liblicence.so --symbol lc_is_licensed --show
python3 scripts/arm64-patch.py liblicence.so --symbol lc_is_licensed --show --objdump

# dry run, then apply (a .bak is made automatically)
python3 scripts/arm64-patch.py liblicence.so --symbol lc_is_licensed \
        --skip 1 --patch "mov w0,#1" --dry-run
python3 scripts/arm64-patch.py liblicence.so --symbol lc_is_licensed \
        --skip 1 --patch "mov w0,#1" --write

# two-instruction patch: force the value AND return
python3 scripts/arm64-patch.py liblicence.so --symbol lc_verify_signature \
        --patch "mov w0,#1" --patch ret --write

# by address, and by raw file offset
python3 scripts/arm64-patch.py liblicence.so --vaddr 0x4a74 --patch "b 0x4b20" --write
python3 scripts/arm64-patch.py liblicence.so --offset 0x8c4 --patch ret --write
```

### `arm64-patch.py` patch vocabulary

| Spec | Emits |
|---|---|
| `ret` | `0xd65f03c0` |
| `nop` | `0xd503201f` |
| `brk` / `brk#0` | `0xd4200000` |
| `zero` | `0x00000000` (not an instruction — an explicit blank) |
| `mov wN,#imm` | `0x52800000 \| (imm<<5) \| N`, `imm` in 0–65535 |
| `mov xN,#imm` | `0xd2800000 \| (imm<<5) \| N` |
| `b 0xADDR` | PC-relative, ±128 MiB, 4-byte aligned |
| `bl 0xADDR` | Same, writes `x30` |
| `raw:<hex>` | Whole 4-byte words, 8 hex digits each, written as you *read* the word |

## Commands — Frida

```bash
frida -U -f com.example.app -l scripts/dump-function.js --no-pause \
      -P '{"module":"libnative.so","symbol":"lc_verify_signature"}'
frida -U -f com.example.app -l scripts/dump-function.js --no-pause \
      -P '{"module":"libnative.so","offset":"0x48d0","count":40}'
frida -U -n com.example.app -l scripts/dump-function.js \
      -P '{"module":"libnative.so","symbol":"lc_is_licensed","trace":true}'
```

```javascript
// Frida REPL
rpc.exports.dump("libnative.so", "0x48d0", 30);   // disassemble in memory
rpc.exports.save("libnative.so", "0x48d0", 512);  // dump live bytes for Ghidra
rpc.exports.trace("libnative.so", "lc_is_licensed");

Process.arch;                                      // 'arm64' or 'arm' -- check first
Module.findBaseAddress('libnative.so');            // the ASLR base
Instruction.parse(ptr('0x7b3c0448c4'));            // one instruction
Memory.protect(addr, 16, 'rwx');                   // before writing
addr.writeByteArray([0x20,0x00,0x80,0x52, 0xc0,0x03,0x5f,0xd6]);  // mov w0,#1 ; ret
```

## Commands — device

```bash
adb push /tmp/ch18/licence-runner /tmp/ch18/liblicence.so /data/local/tmp/
adb shell chmod 755 /data/local/tmp/licence-runner
adb shell /data/local/tmp/licence-runner /data/local/tmp/liblicence.so
adb shell /data/local/tmp/licence-runner /data/local/tmp/liblicence.so ARM64-IS-NOT-HARD

# if exec from /data is blocked by a vendor policy (ENXIO / EINTR):
adb shell /system/bin/linker64 /data/local/tmp/licence-runner /data/local/tmp/liblicence.so

adb shell getprop ro.product.cpu.abi          # which ABI will load
adb shell cat /proc/<pid>/maps | grep '\.so'  # which library actually loaded
adb shell ls -t /data/tombstones | head -1    # the newest native crash
```

## LLDB

```bash
adb push $NDK/.../aarch64/lldb-server /data/local/tmp/
adb shell /data/local/tmp/lldb-server platform --listen "*:5039" --server &
adb forward tcp:5039 tcp:5039
```

```text
(lldb) platform select remote-android
(lldb) platform connect connect://localhost:5039
(lldb) process attach --pid <pid>
(lldb) image list -o -f                 # load offsets
(lldb) disassemble --start-address 0x... --count 20
(lldb) register read x0 x1 x2 x8 x29 x30
(lldb) breakpoint set --address 0x...
(lldb) watchpoint set expression -s 8 -- 0x...
(lldb) memory read --format x --size 4 --count 8 $pc
```

## ARM32 / Thumb quick reference

| | AArch64 | ARM32 (A32) | Thumb (T32) |
|---|---|---|---|
| Instruction width | 4 bytes | 4 bytes | **2 or 4 bytes** |
| Argument registers | `x0`–`x7` | `r0`–`r3` | `r0`–`r3` |
| Return address | `x30` | `r14` (`lr`) | `r14` (`lr`) |
| Return | `ret` | `bx lr` or `pop {…, pc}` | `bx lr` or `pop {…, pc}` |
| Syscall number in | `x8` | `r7` | `r7` |
| Thread pointer | `mrs Xn, TPIDR_EL0` | `mrc p15,0,Rn,c13,c0,3` | same |
| Conditional execution | `csel`/`cset` only | **almost every instruction** | `it`/`ite` blocks |
| `pc` writable | No | **Yes** (`r15`) | **Yes** |
| Symbol low bit | always 0 | 0 | **1** |

**Do not patch Thumb with a fixed-4-byte tool.** `arm64-patch.py` refuses ELF32 for this reason.

## Version matrix

| Feature | Armv8 | Android API | Visible as |
|---|---|---|---|
| AArch64 | 8.0 | 21 | `arm64-v8a` ABI |
| Pointer Authentication | 8.3 | HW-dependent | `paciasp` / `autiasp` / `retaa` |
| Branch Target Identification | 8.5 | HW-dependent | `bti c` = `hint #34` |
| Memory Tagging Extension | 8.5 | 31+, opt-in | Tagged pointers; heap faults |
| Shadow call stack | software | 29+ platform | `x18` reserved |
| Scudo allocator | — | 28+ / default 30+ | Changes heap corruption behaviour |
| 16 KiB pages | — | 35+ | `-Wl,-z,max-page-size=16384` |

## Failure modes, and what they mean

| Symptom | Cause | §README |
|---|---|---|
| Patch applied, `objdump` confirms, behaviour unchanged | The check was **inlined**; you patched a dead copy | §5.4 |
| Patch corrupted unrelated data | Wrote at the **virtual address** instead of the file offset | §6.6 |
| Patch works on one function, breaks another | Used one segment delta for the whole file | §2.4 |
| Indirect calls fault after patching | Overwrote a `bti` landing pad | §3.12 |
| Frida hook on `access()` never fires | The app used a raw `svc` | §5.3.3 |
| Disassembly is nonsense from one address on | You started one byte into a Thumb instruction | §3.13 |
| `find-check-shapes.py` returns nothing | Checks are inlined, or the library is packed | §8.3 |
| File and memory disassembly disagree | Packed, self-modifying, or already hooked | §7.1 |
| `/data/local/tmp/foo` fails to exec | Vendor policy blocks `execve` on `/data` | §7.7 |
| Gate patched, output is garbage | The check supplied the **key**, not just the gate | §5.4 |
