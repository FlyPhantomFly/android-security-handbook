# 59 — radare2 cheat sheet

> Every radare2 command here is **📘 Unverified** — radare2 was not installed on the machine where
> this chapter was written. Byte encodings, ELF facts and device behaviour are **✅ Measured**.
> See [README.md](README.md) for the full statement.

---

## The grammar in one table

| Piece | Examples |
|---|---|
| **Root verb** | `a` analyse · `i` info · `p` print · `s` seek · `w` write · `f` flag · `e` eval · `S` sections · `d` debug · `V` visual |
| **Narrowing** | `l` list · `f` function · `x` xrefs · `z` strings · `i` imports · `E` exports |
| **Suffix** | `j` JSON · `q` quiet · `*` replayable r2 commands · `,` table · `?` help for this prefix |
| **Operators** | `@` temporary seek · `@@` iterate · `~` internal grep · `\|` shell pipe · `>` redirect |

**`?` after any prefix explains that subtree.** `a?` → `af?` → `afl?`. This replaces memorisation.

---

## Launching

| Command | Mode |
|---|---|
| `r2 file.so` | Read-only (default) |
| `r2 -w file.so` | **Read-write, edits in place, no undo.** Copy first |
| `r2 -A file.so` | Run `aaa` on load |
| `r2 -n file.so` | No `r_bin` parsing — raw bytes |
| `r2 -q -c 'cmd' file` | Run one command, print, exit |
| `r2 -i script.r2 file` | Run a script, then drop to the shell |
| `r2 -p project` | Reopen a saved project |
| `r2 -d ./prog` | Under the debugger |
| `r2 'frida://usb//com.pkg'` | Live process via r2frida |

---

## Info — no analysis required, fast on any size

| Command | `rabin2` | Shows |
|---|---|---|
| `iI` | `-I` | arch, bits, stripped, PIC, NX, canary, RELRO |
| `ii` | `-i` | imports |
| `iE` | `-E` | exports |
| `is` | `-s` | symbols |
| `iz` | `-z` | strings in data sections |
| `izz` | `-zz` | strings in the whole file |
| `il` | `-l` | linked libraries (`DT_NEEDED`) |
| `iS` | `-S` | sections |
| `iSS` | `-SS` | segments (program headers) |
| `ie` | `-e` | entry points |
| `ir` | `-R` | relocations |
| `ic` | `-c` | classes (DEX) |
| `ij` | `-j` | any of the above as JSON |

---

## Analysis — the expensive family

| Command | Does | Cost |
|---|---|---|
| *(none)* | Nothing; `i*` still works fully | Zero |
| `aa` | Functions from symbols and entry, follow calls | Baseline |
| `aaa` | `aa` + auto-name + all xrefs + type propagation | Several × `aa` |
| `aaaa` | `aaa` + emulation-assisted passes | Much more |
| `aab` | Basic blocks only | Cheap |
| `aap` | Search for function prologues | Moderate |
| `af` | **Only** the function at the cursor | Tiny |
| `aef` | ESIL-emulate a function | Expensive, per-function |

**Decision rule:** if the question is about imports, exports, strings, sections or libraries, run
**no analysis**. If it is about one function, `s` then `af`. Only cross-reference questions need
`aaa`.

---

## Functions and cross-references

| Command | Does |
|---|---|
| `afl` | List functions |
| `afl~?` | **Count** functions |
| `aflj` | As JSON — the scripting form |
| `afl,` | Sortable table |
| `afi` | Info on the current function |
| `afn <name>` | Rename the current function |
| `afv` | Local variables and arguments |
| `axt <addr>` | **Xrefs TO** — who references this |
| `axf <addr>` | Xrefs FROM — what this references |

> `axt` needs analysis. Without it, it returns nothing **silently**.
> `axt` cannot see indirect calls (`blr x8`). It is a lower bound, never an inventory.

---

## Print

| Command | Renders |
|---|---|
| `pd N` | N instructions |
| `pdf` | The whole current function |
| `pdr` | Recursively through calls |
| `px N` | Hex dump |
| `ps` | String at the cursor |
| `pf <fmt>` | Apply a struct format |
| `pdc` | Pseudo-decompiler (**not** a real decompiler) |
| `pdg` | Real decompiled C — requires the `r2ghidra` plugin |

---

## Seek and search

| Command | Does |
|---|---|
| `s <addr>` / `s <flag>` | Seek |
| `s +N` / `s -N` | Relative |
| `s-` / `s+` | Undo / redo a seek (history) |
| `/ text` | Search literal string |
| `/w text` | Wide (UTF-16) string |
| `/x cafe` | Hex pattern |
| `/x ca..fe` | Hex with nibble wildcards |
| `/v4 0x01000193` | **4-byte value, endianness handled** |
| `/a mov x0, 1` | Assemble, then search for those bytes |
| `/R pop rdi` | ROP gadget search |
| `/c jmp` | Search disassembly text |

> Byte searches must respect endianness. On little-endian AArch64 the constant `0x01000193` sits in
> the file as `93 01 00 01`. Use `/v4` and let radare2 handle it.

---

## Flags — the naming layer

| Prefix | Means |
|---|---|
| `sym.` | Symbol defined here |
| `sym.imp.` | **Imported** symbol — the PLT stub, not the real function |
| `str.` | String |
| `sect.` | Section |
| `fcn.` | Function radare2 discovered with no symbol |
| `loc.` | Label inside a function |
| `obj.` | Data object |

| Command | Does |
|---|---|
| `f name @ addr` | Bind a name |
| `f- name` | Remove |
| `f*` | Dump all flags as **replayable** r2 commands |
| `fs` | List flag spaces |

**Why `axt sym.imp.X` works:** all calls to an imported function within one library go through a
single PLT stub, so xrefs to the stub are a complete local call list.

---

## Writing / patching

| Command | Writes |
|---|---|
| `wa <asm>` | Assemble and write |
| `wx <hex>` | Raw hex bytes |
| `wao nop` | Nop the current instruction (arch-correct) |
| `wao ret1` | Make the function return 1 |
| `w <string>` | ASCII |
| `wz <string>` | Zero-terminated ASCII |
| `wv <value>` | Value with correct size/endianness |
| `wf <file>` | File contents |
| `wtf <file> <n>` | Dump n bytes **to** a file |

| Safety | Command |
|---|---|
| Stage writes in memory | `e io.cache=1` |
| Commit staged writes | `wci` |
| Discard staged writes | `wc-` |
| List staged writes | `wc` |

> `r2 -w` edits the file immediately with no undo and no backup. **Copy first**, and set
> `e io.cache=1` before touching anything.

### AArch64 patch encodings — ✅ Measured

| Instruction | Bytes (file order) | Word |
|---|---|---|
| `mov w0, #1` | `20 00 80 52` | `0x52800020` |
| `mov w0, #0` | `00 00 80 52` | `0x52800000` |
| `ret` | `c0 03 5f d6` | `0xd65f03c0` |
| `nop` | `1f 20 03 d5` | `0xd503201f` |

### Virtual address is not file offset

```
file_offset = vaddr - (section_vaddr - section_file_offset)
```

Computed **per section**. `iS` shows both columns. Measured example: `.text` at vaddr `0x4794`,
file offset `0x794` — delta `0x4000`.

---

## Visual and panels

| Key | Mode / action |
|---|---|
| `V` | Visual mode; `q` to leave |
| `VV` | **Graph view** — basic blocks and edges |
| `v` | Panels (tiled multi-pane) |
| `p` / `P` | Cycle print modes |
| `hjkl` | Move |
| `g` | Seek to a flag by name |
| `x` / `X` | Xrefs to / from, with jump |
| `;` | Add a comment |
| `d` | Define as code / data / string / function |
| `A` | Assemble here |
| `u` / `U` | Undo / redo seek |
| `:` | Run a normal r2 command |

> **Graph shape is a diagnosis.** A tree flowing downwards is a normal function. A wheel — one
> central dispatcher with blocks radiating out and returning — is control-flow flattening.

---

## Configuration

| Variable | Purpose |
|---|---|
| `e asm.arch=arm` / `e asm.bits=64` | Architecture |
| `e asm.cpu=thumb` | ARM32 Thumb mode |
| `e asm.describe=1` | Plain-English note on every instruction — excellent while learning |
| `e asm.emu=1` | Annotate with emulated values — useful on obfuscated code |
| `e asm.pseudo=1` | Pseudo-C rendering |
| `e asm.bytes=0` | Hide raw bytes |
| `e anal.hasnext=1` | Keep analysing past function ends (stripped binaries) |
| `e bin.demangle=1` | Demangle C++ |
| `e scr.color=0` | No colour (redirecting to a file) |
| `e io.cache=1` | Stage writes |
| `e?` / `e??<prefix>` | List / help |

---

## Projects

| Command | Does |
|---|---|
| `Ps <name>` | Save project |
| `Po <name>` | Open project |
| `r2 -p <name>` | Open from the shell |

Save after any expensive `aaa`. Re-running it every morning on a 6 MB `.text` is self-inflicted.

---

## The other tools

| Tool | Job | rizin name |
|---|---|---|
| `rabin2` | Headers, symbols, strings, sections | `rz-bin` |
| `rafind2` | Byte/pattern search across files | `rz-find` |
| `radiff2` | Binary and function-level diff | `rz-diff` |
| `rasm2` | Assemble / disassemble one instruction | `rz-asm` |
| `ragg2` | Shellcode builder | `rz-gg` |
| `r2pm` | Package manager | `rz-pm` |

```bash
radiff2 -C old.so new.so      # function similarity table -- patch diffing
radiff2 -s old.so new.so      # one similarity number
rafind2 -x c0035fd6 -r lib/   # hex pattern across a tree
rafind2 -s '/system/bin/su' -r lib/
rasm2 -a arm -b 64 'mov w0, 1'      # assemble
rasm2 -a arm -b 64 -d 20008052      # disassemble
```

---

## r2pipe (Python)

```python
import r2pipe
r2 = r2pipe.open("libfoo.so", flags=["-2"])
r2.cmd("aa")                       # text back
funcs = r2.cmdj("aflj")            # parsed JSON back
r2.quit()
```

| Form | Meaning |
|---|---|
| `r2pipe.open("file")` | Spawn r2 on a file |
| `r2pipe.open()` | Attach to the r2 running this script (`#!pipe`) |
| `r2pipe.open("frida://usb//com.pkg")` | Live process |

> `pip install r2pipe` installs only a **client**. radare2 itself must also be on PATH.

---

## r2frida — live process

```bash
r2pm -ci r2frida
r2 'frida://usb//com.example.app'          # attach
r2 'frida://spawn/usb//com.example.app'    # spawn (needed to catch JNI_OnLoad)
```

| Command | Does |
|---|---|
| `:i` | Target info |
| `:dm` | Memory map |
| `:dmm` | Modules with base addresses |
| `:is <lib>` / `:ie <lib>` | Symbols / exports |
| `:dt <addr>` | Trace calls |
| `:dxc <addr> <args>` | **Call a function in the target** |
| `:eval <js>` | Run JavaScript in the agent |
| `wtf out.so <n> @ <base>` | Dump a module from memory |

---

## Android triage recipes

```bash
# unpack
unzip -o target.apk -d x/ && ls x/lib/

# one-line orientation per library
for f in x/lib/arm64-v8a/*.so; do echo "== $f"; rabin2 -I "$f"; done

# which libraries import something interesting
for f in x/lib/arm64-v8a/*.so; do
  rabin2 -qi "$f" 2>/dev/null | grep -qE 'ptrace|__system_property_get|dlopen' \
    && echo "INTERESTING: $f"
done

# strings across the whole lib directory with filenames attached
for f in x/lib/arm64-v8a/*.so; do
  rabin2 -qz "$f" 2>/dev/null | sed "s|^|$(basename $f): |"
done | grep -iE 'su\b|magisk|frida|http://'
```

| Question | Command |
|---|---|
| Root detection? | `iz~su,magisk,superuser` · `ii~access,stat` |
| Emulator detection? | `axt sym.imp.__system_property_get` |
| Anti-debug? | `ii~ptrace,prctl` · `iS~init_array` |
| Anti-tamper responses? | `axt sym.imp.abort` |
| JNI entry points? | `iE~Java_` |
| Dynamic JNI registration? | `iE` shows only `JNI_OnLoad`; then `iz~^\(` |
| Code at load time? | `iS~init_array` |
| Hardcoded keys? | `iz~key,token,secret` then `axt` |

---

## JNI offsets — ✅ Measured

The JNI specification fixes the table order, so **an offset is a function name**.

| Offset | Decimal | Function | Table |
|---|---|---|---|
| `0x30` | 48 | `GetEnv` | `JNIInvokeInterface` (`JavaVM`) |
| `0x30` | 48 | `FindClass` | `JNINativeInterface` (`JNIEnv`) |
| `0x548` | 1352 | `GetStringUTFChars` | `JNIEnv` |
| `0x6b8` | 1720 | `RegisterNatives` | `JNIEnv` |

Pattern to recognise: `ldr x8, [x0]` · `ldr x8, [x8, #imm]` · `blr x8`.

---

## AArch64 patterns worth recognising

| Pattern | Means |
|---|---|
| `adrp` + `add` | Materialising an address (`.rodata`/`.data`). ±4 GiB reach |
| `adrp` + `ldr` | Loading a value from a global |
| `ldr x8,[x0]` + `ldr x8,[x8,#N]` + `blr x8` | **A JNI call**; `N` names it |
| `bl sym.imp.X` | Call to an import — what `axt` indexes |
| `cbz`/`cbnz` right after a `bl` | **A decision on a return value** — security gates live here |
| `mov wN,#a` + `movk wN,#b,lsl #16` | A 32-bit constant in two halves — magic values |
| `cset wN, eq` | Comparison to boolean 0/1 |
| A single `b` as a whole function | Tail call — the real code is elsewhere |
| `stp x29,x30,[sp,#-N]!` | Prologue (function boundary) |
| `paciasp` / `retaa` | Pointer authentication, not obfuscation |

**Algorithm constants** (search with `/v4`):

| Constant | Algorithm |
|---|---|
| `0x811C9DC5` / `0x01000193` | FNV-1a 32-bit (basis / prime) |
| shifts 13, 17, 5 | xorshift32 |
| `0x6A09E667` | SHA-256 |
| `0x67452301` | MD5 / SHA-1 |
| `0xEDB88320` | CRC-32 |

---

## Measured facts from this chapter

| Fact | Value |
|---|---|
| Corpus libraries stripped | **10 of 11**; AArch64 `libc.so` kept 2,667 symbols |
| AArch64 `libsqlite.so` | 1,657,588 code bytes / 414,397 instructions / **364** names |
| x86_64 `libhwui.so` | 6,336,785 code bytes / **1,080** names |
| Linear disassembly rate (floor, `llvm-objdump`) | ~210k–281k instructions/second |
| `libLLVM_android.so` linear sweep | 2,551,900 lines in 9,089 ms |
| XOR string obfuscation at `-O2` | **Folded away; plaintext shipped.** `-O0` hid it |
| Fix that held | `static volatile` key |
| Patching `lt_verify_license` | **No behavioural change** — upstream guard short-circuits it |
| Stock Google AVD | **Ships `/system/xbin/su`**, setuid root — but `/system/xbin` is `root:shell` `0750`, so it is visible to `adb shell` and **invisible to an app**. The check fires from the shell only |

---

## Common traps

| Trap | Fix |
|---|---|
| `axt` returns nothing | Run `aa` first; confirm with `afl~?` |
| `axt` treated as a complete call list | It misses every indirect call |
| `r2 -w` with no backup | Copy first; `e io.cache=1` |
| Patched the security-sounding function | `axt` it and read the callers first |
| Static address pasted into Frida | Always `Module.base.add(offset)` |
| `/x 01000193` finds nothing | Endianness — use `/v4` |
| Attached instead of spawned for `RegisterNatives` | `frida -U -f <pkg>` |
| Re-running `aaa` every session | `Ps` / `Po` |
| `pdc` mistaken for a decompiler | Install `r2ghidra`, use `pdg` |
| rizin command not found | `rabin2` → `rz-bin`, `r2pipe` → `rzpipe` |

---

## Where to go instead

| Need | Tool |
|---|---|
| Decompiled C | [Ghidra](../57-Ghidra/README.md), or `r2ghidra` |
| Java / DEX | [JADX](../56-JADX/README.md) |
| Best-in-class decompiler, C++ classes | [IDA](../58-IDA/README.md) |
| Runtime behaviour | [Frida](../53-Frida/README.md) |
| Corpus triage, SSH, on-device | **radare2** |
