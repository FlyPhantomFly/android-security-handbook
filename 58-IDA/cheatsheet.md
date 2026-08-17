# 58 — IDA · Cheat sheet

Printable. Tables and commands only.

> **Honesty marker.** Rows marked **[M]** were measured on this repository's hardware. Rows marked
> **[D]** are documentation-derived from hex-rays.com and have **not** been exercised — IDA is not
> installed on the machine where this chapter was written. See the README's opening callout.

---

## Editions — what you can actually do [D]

| Edition | Disassemblers | Decompiler | Scripting | Commercial |
|---|---|---|---|---|
| **Free** | x86-32, x86-64 **only** | Cloud, x86 only | **IDC only, no IDAPython** | **No** |
| **Home** | + ARM-32, **ARM-64** | **Cloud only** | Yes | Hobbyist |
| **Classroom** | one of PC/ARM/MIPS/PPC/RISC-V | Cloud only | Yes | Education |
| **Pro Essential** | all 60+ | 2, **in the cloud** | Yes | Yes |
| **Pro Expert-2/4/6** | all 60+ | 2/4/6, **local** | Yes | Yes |
| **Pro Ultimate** | all 60+ | all, **local** | Yes | Yes |

**IDA Free cannot open an Android arm64 library.** For NDA work you need a **local** decompiler:
Expert-N or Ultimate.

---

## Keyboard [D — verify on your build]

| Key | Does |
|---|---|
| `F5` | Decompile the current function |
| `Ctrl+Shift+F8` | Microcode view; `>` / `<` move between maturity levels |
| `Y` | Set type / prototype |
| `N` | Rename |
| `X` | Cross-references **to** here |
| `G` | Go to address |
| `;` / `:` | Repeatable / regular comment |
| `Shift+F12` | Strings window |
| `Shift+F1` | Local Types (structs and enums, from 9.0) |
| `Ctrl+F9` | Parse C header file into local types |
| `Alt+F7` | Run a script file |
| `Space` | Toggle graph / text view |
| `Ctrl+E` | Jump to an entry point |
| `Alt+T` | Text search |
| `U` | Undefine |
| `C` / `D` / `A` | Make code / data / string |
| `P` | Create function at cursor |
| `Alt+P` | Edit function boundaries and flags (including non-returning) |
| `Esc` / `Ctrl+Enter` | Navigate back / forward |

---

## Headless [D]

```bash
idat64 -A -c -o<db>.i64 -S"<script.py> <args>" -L<log> <file>
```

| Flag | Meaning |
|---|---|
| `-A` | Autonomous — never prompt. **Omit it and a batch run hangs on the first dialogue** |
| `-c` | Fresh database, discard any existing one |
| `-S"…"` | Script + args after autoanalysis; quote as ONE argument; reaches `idc.ARGV` |
| `-L<f>` | Log file — the only place a headless failure explains itself |
| `-o<f>` | Database output path. Use it, or `.i64` files litter the APK tree |
| `-p<t>` | Force processor type |
| `-B` | Batch: analyse, emit `.asm`, exit |

From IDA 9.0 the 32/64 split is gone: the binary is `idat`, not `idat64`.

---

## IDAPython essentials

| Need | Call |
|---|---|
| Wait for autoanalysis | `ida_auto.auto_wait()` — **mandatory in headless scripts** |
| Iterate functions | `for ea in idautils.Functions():` |
| Function name | `ida_funcs.get_func_name(ea)` |
| Function object | `ida_funcs.get_func(ea)` → `.start_ea`, `.end_ea`, `.flags` |
| Mark non-returning | `f.flags \|= idaapi.FUNC_NORET; ida_funcs.update_func(f)` |
| Rename | `ida_name.set_name(ea, "name", ida_name.SN_CHECK)` |
| Set prototype | `idc.SetType(ea, "int f(char *, int);")` |
| Cross-references to | `for x in idautils.XrefsTo(ea): x.frm` |
| Read bytes | `ida_bytes.get_bytes(ea, n)` |
| Instruction mnemonic | `ida_ua.print_insn_mnem(ea)` |
| Operand type | `idc.get_operand_type(ea, 0)` |
| Image base | `idaapi.get_imagebase()` |
| Filename | `ida_nalt.get_root_filename()` |
| Decompile | `ida_hexrays.decompile(ea)` |
| Exit headless | `idc.qexit(0)` |

### IDA 9.0 removals — check before running any older script

| Gone | Use |
|---|---|
| `idaapi.get_inf_structure()` | `ida_ida.inf_get_min_ea()`, `inf_get_max_ea()`, `inf_get_procname()`, `inf_is_64bit()` |
| `ida_struct`, `ida_enum` | `ida_typeinf` — Structures and Enums became **Local Types** |

---

## FLIRT

### `.pat` line format

```text
<64 hex chars, '..' = variant>  <ALEN 2>  <ACRC 4>  <TLEN 4>  :0000 <name>  [^OFF <ref>]
```

| Field | Meaning |
|---|---|
| pattern | First **32 bytes**; `..` = a byte the linker rewrites |
| ALEN | Bytes after the pattern the CRC covers; stops at first variant byte and at `0xFF` |
| ACRC | CRC16 over those bytes |
| TLEN | Total function length |
| `:OFF name` | Public name at that offset |
| `^OFF name` | A name this function references — the ARM tie-breaker |

### Workflow

```bash
pelf lib.a out.pat                    # patterns from a library you HAVE symbols for
sigmake -n"name" out.pat out.sig      # compile; collisions land in out.exc
cp out.sig "$IDADIR/sig/arm/"         # then View > Open subviews > Signatures, Insert
```

Free substitute, no licence:

```bash
python3 -B scripts/01-make-flirt-pat.py lib.a --explain
```

### Measured pattern strengths, one static archive, AArch64 **[M]**

| Function | Informative bytes / 32 | CRC bytes | Why |
|---|---:|---:|---|
| `ch58_crc32` (table-driven) | **12** | 12 | 5 relocated `adrp`/`add` words masked |
| `ch58_fnv1a64` (no table) | **32** | 24 | constants are immediates, not relocations |
| `ch58_hex` | 24 | 40 | 2 relocated words |

**The distinctive-constant function produced the weakest signature.** On AArch64 a relocation masks the
whole 4-byte instruction word, opcode included — structurally worse than x86.

---

## Debugger

| Item | Value |
|---|---|
| Default port | **23946** [D] |
| arm64-v8a server | `<IDA>/dbgsrv/android_server` [D] |
| armeabi-v7a | `android_server32` [D] |
| x86_64 emulator | `android_x64_server` [D] |
| x86 emulator | `android_x86_server` [D] |
| Options | `-p` port · `-i` bind addr · `-P` password · `-v` verbose · `-t` plain TCP · `-K` kill on close [D] |
| Connect | *Debugger → Attach → Remote ARM Linux/Android debugger*, `127.0.0.1:23946` [D] |

```bash
# host — preconditions, all checks executed [M]
./scripts/04-android-server-preflight.sh
adb push android_server /data/local/tmp/mine/
adb shell "su 0 sh -c 'cd /data/local/tmp/mine && ./android_server -i127.0.0.1 -p23946 &'"
adb forward tcp:23946 tcp:23946
```

**Bind to loopback.** `0.0.0.0` turns a phone into a remote-code-execution service.

### Measured preconditions, `sdk_gphone16k_x86_64`, Android 15 / API 35 **[M]**

| Check | Result |
|---|---|
| `su 0 id` | `uid=0(root) … context=u:r:su:s0` — **AVDs need `su 0`, not `su -c`** |
| `/proc/sys/kernel/yama/ptrace_scope` | **ABSENT.** Most published guides tell you to set it |
| `getenforce` | `Enforcing` — leave it; find the AVC instead |
| `adb forward tcp:23946` | works |
| `ro.product.cpu.abilist` | `x86_64,arm64-v8a` — pick the server by the **process**, not the device |

### Costs of attaching

- `TracerPid` in `/proc/<pid>/status` becomes non-zero. (A JDWP debugger does **not** — chapter 38.)
- **One tracer per process.** Frida and IDA's debugger cannot both be attached.

---

## Triage before you open anything **[M]**

```bash
NDKBIN="$ANDROID_HOME/ndk/25.2.9519653/toolchains/llvm/prebuilt/<host>/bin"

"$NDKBIN/llvm-readelf" -h lib.so                       # arch, type, entry
"$NDKBIN/llvm-readelf" -S lib.so | grep symtab          # stripped? absent = yes
"$NDKBIN/llvm-nm" -D --defined-only lib.so | grep ' T Java_'   # static JNI
"$NDKBIN/llvm-nm" -D --defined-only lib.so | grep JNI_OnLoad   # dynamic JNI
"$NDKBIN/llvm-nm" -D -u lib.so                          # imports
"$NDKBIN/llvm-strings" -a -n 6 lib.so
"$NDKBIN/llvm-readelf" -r lib.so | grep -i relative     # pointers that read as zero
"$NDKBIN/llvm-readelf" -p .comment lib.so               # which compiler built it

./scripts/03-ida-batch-triage.sh --backend llvm app.apk # all of the above, tabulated
```

| Signature | Means |
|---|---|
| stripped + no `Java_*` + `JNI_OnLoad` | **dynamic binding** — recover the `RegisterNatives` table |
| stripped + no `Java_*` + no `JNI_OnLoad` | reached by `dlsym`, not loaded by this app, **or** registered by internal C++ (AOSP's `libandroid_runtime.so` does this) **[M]** |
| not stripped | start here; cheapest library in the set |
| `mprotect` imported | packer, JIT, or self-modifying code |
| very few strings | encoded. The absence is the finding |

---

## Address arithmetic

```text
runtime = module_base + (ida_ea - ida_imagebase)
```

| Value | Where from |
|---|---|
| `ida_imagebase` | `idaapi.get_imagebase()` — **never assume** |
| `module_base` | `Process.findModuleByName(...)`, or `/proc/<pid>/maps` first `r--p` mapping at file offset 0 |

**Work in `module + offset`, never in absolute addresses.**

---

## Structure recovery — three rules

| Rule | Detail |
|---|---|
| The instruction names the width | `ldrb`=1 · `ldrh`=2 · `ldr w`=4 · `ldr x`=8 · `ldrs*`= signed |
| A loop bound gives an array length | `strb` loop from `+0x10` ending on `cmp x8, #16` → 16 bytes at `+0x10` |
| `memset`'s third argument gives `sizeof` | Look in the initialiser |

**A recovered structure is a hypothesis.** Print every field at run time; one garbage field = one wrong
offset. **Padding is invisible** to access-based recovery. A perfectly dense layout is suspicious.

IDA shortcut: right-click a base pointer in the pseudocode → *Create new struct type*. **It sees only
the current function** — generate from the initialiser. [D]

---

## Hex-Rays microcode maturity levels [D]

| # | Constant | By this point |
|---|---|---|
| 1 | `MMAT_GENERATED` | Naive expansion. Huge |
| 2 | `MMAT_PREOPTIMIZED` | Pre-optimisation done |
| 3 | `MMAT_LOCOPT` | Per-block optimisation; CFG exists |
| 4 | `MMAT_CALLS` | **Call arguments detected** |
| 5–7 | `MMAT_GLBOPT1/2/3` | Global optimisation |
| 8 | `MMAT_LVARS` | **Local variables allocated.** ctree is built from here |

Also `MMAT_ZERO`. **Microcode is the semantics; the ctree is the syntax.**

---

## Database files

| Ext | Contains |
|---|---|
| `.i64` / `.idb` | Packed database, 64-bit / 32-bit. **Contains a COPY of the program's bytes** |
| `.id0` | Netnode B-tree — the analysis. Loose only while open or after a crash |
| `.id1` | Per-byte flags |
| `.nam` | Name index |
| `.til` | Type library |
| `.sig` / `.pat` | Compiled / source FLIRT signatures |
| `.idc` | IDA's own scripting language |

**Never email an `.i64`.** Add `*.i64 *.idb *.id0 *.id1 *.nam *.til` to `.gitignore`.

---

## Measured facts about what the compiler did **[M]**

NDK 25.2.9519653, clang 14.0.7, `-O2`, aarch64.

| Fact | Detail |
|---|---|
| Strip removed | 43 symbols → 11 (`.dynsym` untouched) |
| Exported predicate call sites | **0** — inlined into every caller. Patching it changes nothing |
| Jump table | **byte** entries, not words: `ldrb` + `lsl #2` from an `adr` anchor. 12 bytes, not 48 |
| Two jump tables | One function inlined twice; the specialised copy collapses one extra case |
| 32-bit magic `0x5345534E` | `mov #21326` + `movk #21317, lsl #16`. **Byte search finds nothing** |
| Function-pointer table | 3 × `R_AARCH64_RELATIVE`; reads as **24 zero bytes** on disk |
| Own exports called via | **the PLT** — default visibility makes them interposable. `bl.*<name(@plt)?>` |
| Tail call | `b`, not `bl`+`ret`. `if (x<0)` became `tbnz w1, #31` |
| Encoded strings | 0 matches for either plaintext in the file |
| `static const` fn-ptr table | **devirtualised entirely** by clang — 0 `blr`. Needs an exported setter to survive |

---

## When to open IDA at all

| Work | Tool |
|---|---|
| Deciding which file to open | free `llvm-*` sweep, or radare2 |
| Java layer, manifests, network, storage | not this chapter |
| One hard native function, C++-heavy | **IDA** |
| Library identification at scale | **IDA** (FLIRT) or Ghidra (FID) |
| Live values through recovered types | **IDA debugger** |
| Print a function's arguments | Frida |
| Batch over hundreds of files | radare2, or free sweep |
| Learning, no budget | **Ghidra** |
| Client binary under NDA | IDA Pro **Expert-N/Ultimate**, or Ghidra. **Not** a cloud tier |

---

## Related

[README](README.md) · [faq](faq.md) · [mindmap](mindmap.md) · [labs](labs/) ·
[57-Ghidra](../57-Ghidra/README.md) · [59-radare2](../59-radare2/README.md) ·
[18-ARM](../18-ARM/README.md) · [15-Native-Code](../15-Native-Code/README.md) ·
[68-ReverseEngineering](../68-ReverseEngineering/README.md)
