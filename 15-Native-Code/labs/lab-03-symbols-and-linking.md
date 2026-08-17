# Lab 03 — Symbols, stripping, and what `findExportByName` is really searching

> **Objective:** establish, by experiment rather than by being told, exactly which symbols survive
> stripping and which do not; walk one function call from a `.text` instruction through a PLT stub
> to a GOT slot to a relocation to an import name; and recover a library's entire dynamic symbol
> table from a file whose section headers have been deleted.

**Prerequisites:** [Lab 01](lab-01-elf-by-hand.md),
[15-Native-Code §3.6](../README.md#36-symbols-dynsym-symtab-and-what-findexportbyname-searches),
[§3.7](../README.md#37-relocations-the-blanks-the-linker-fills-in),
[§3.8](../README.md#38-plt-and-got-the-indirection-that-makes-hooking-possible)
**Difficulty:** Intermediate
**Time:** 75 minutes
**You will need:** the fixtures from [Lab 01](lab-01-elf-by-hand.md), Python 3. A device and Frida
are optional and used only in Part 5.

---

## Why this lab exists

[53-Frida](../../53-Frida/README.md) sends readers to chapter 15 with one question: *what is
`Module.findExportByName` actually searching?* The one-sentence answer is "the `.dynsym` table of
the named module". That sentence is useless until you have seen what it implies, which is four
things that surprise people:

- a **stripped** library still resolves every export by name;
- a **hidden-visibility** function never resolves, stripped or not;
- a **C++** function resolves only under its mangled name;
- passing `null` for the module gives you the linker's answer, which may not be the right one.

This lab makes each of those four something you have observed rather than something you have read.

---

## Setup

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"
cd 15-Native-Code/examples && ./build-fixtures.sh /tmp/ch15-fixtures
cd /tmp/ch15-fixtures
S=~/…/15-Native-Code/scripts        # adjust to your path
```

If you have no NDK, Parts 1, 2 and 3 work against any `.so` you can obtain, though the specific
symbol names will differ.

---

## Part 1 — The two tables

### Task 1.1 — count them

```bash
# host
python3 $S/elf-inspect.py libdemo-hard.so --symbols | head -3
python3 $S/elf-inspect.py libdemo-hard.so --dynsyms | head -3
python3 $S/elf-inspect.py libdemo-hard-stripped.so --symbols | head -3
python3 $S/elf-inspect.py libdemo-hard-stripped.so --dynsyms | head -3
```

| File | `.symtab` count | `.dynsym` count |
|---|---|---|
| `libdemo-hard.so` | | |
| `libdemo-hard-stripped.so` | | |

<details>
<summary>Reference</summary>

| File | `.symtab` | `.dynsym` |
|---|---|---|
| `libdemo-hard.so` | ~53 | 17 |
| `libdemo-hard-stripped.so` | **absent** | **17 — unchanged** |

The two files are byte-identical in every mapped region. `strip` removed `.symtab`, `.strtab` and
`.comment`, none of which is covered by a `PT_LOAD`.

</details>

### Task 1.2 — prove they are the same code

```bash
# host — the program headers should be identical apart from e_shoff
python3 $S/elf-inspect.py libdemo-hard.so          --segments > /tmp/a.txt
python3 $S/elf-inspect.py libdemo-hard-stripped.so --segments > /tmp/b.txt
diff /tmp/a.txt /tmp/b.txt
```

<details>
<summary>What you should see, and what it proves</summary>

No differences in the `PT_LOAD` rows at all. The mapped image is identical; the addresses of every
function are identical. **Stripping changes nothing about the running program.** That is why it is
safe to do, and it is also why it buys the developer far less than they hope.

</details>

### Task 1.3 — classify every symbol

```bash
# host
python3 $S/elf-inspect.py libdemo-hard.so --dynsyms
```

For each row, decide: is it an import or an export? What tells you?

<details>
<summary>Answer</summary>

The `value` column. `UND` means `st_shndx == SHN_UNDEF` (0), which means "this symbol is not defined
in this file" — an **import**. An address means the symbol is defined here — an **export**.

You should see roughly nine `UND` rows (`__cxa_finalize`, `__strcpy_chk`, `__stack_chk_fail`,
`malloc`, `__vsprintf_chk`, `system`, `vsnprintf`, `printf`, `__cxa_atexit`) and seven defined ones
(`check_password`, `build_command`, `run_helper`, `set_logger`, `emit`, `public_checksum`, and the
`OBJECT` `g_logger`).

Note that `g_logger` is `STT_OBJECT`, not `STT_FUNC` — a **variable** in the export table. Libraries
export data as well as functions, and an exported writable global is a hooking target that costs
nothing to reach.

</details>

---

## Part 2 — Visibility: the thing that actually hides a function

### Task 2.1 — find the function that is missing from `.dynsym`

```bash
# host
python3 $S/elf-inspect.py libdemo-hard.so --symbols --grep checksum
python3 $S/elf-inspect.py libdemo-hard.so --dynsyms --grep checksum
```

<details>
<summary>Expected</summary>

```text
.symtab -- 2 shown of 53
  value              size     type     bind       vis    name
  0x4df8             40       FUNC     LOCAL      HIDDEN internal_checksum
  0x4e20             40       FUNC     GLOBAL     DEFAULT public_checksum

.dynsym -- 1 shown of 17
  0x4e20             40       FUNC     GLOBAL     DEFAULT public_checksum
```

`internal_checksum` is `LOCAL`/`HIDDEN` and is **not in `.dynsym`**. It is a real function, at
`0x4df8`, forty bytes long, and it executes every time `public_checksum` is called. It simply has no
name that the dynamic linker — or Frida, or `nm -D`, or `dlsym` — can see.

</details>

### Task 2.2 — the three ways a function disappears, ranked

Fill in what each removes:

| Technique | Removed from `.symtab`? | Removed from `.dynsym`? | Findable by name at run time? |
|---|---|---|---|
| `strip` | | | |
| `visibility("hidden")` | | | |
| `static` (file-local) | | | |
| `-flto` inlining | | | |

<details>
<summary>Answers</summary>

| Technique | `.symtab` | `.dynsym` | Findable at run time? |
|---|---|---|---|
| `strip` | **removed** | untouched | **Yes**, if exported |
| `visibility("hidden")` | present as `LOCAL`/`HIDDEN` | **never there** | **No** |
| `static` | present as `LOCAL` | **never there** | **No** |
| `-flto` inlining | may vanish entirely | never there | No — **the function may not exist as a separate function at all** |

The ranking matters. Developers reach for `strip` believing it hides things; it hides the least.
`-fvisibility=hidden` is the setting that genuinely shrinks the attack surface, and it is also good
engineering practice for unrelated reasons (faster loading, fewer symbol collisions, more
optimisation freedom).

</details>

### Task 2.3 — reach it anyway

Find `internal_checksum` in the **stripped** file, using only the stripped file.

<details>
<summary>Method and answer</summary>

1. `public_checksum` is exported at `0x4e20`. Get that from `.dynsym`.
2. `public_checksum` does exactly one thing: call `internal_checksum` and return. So disassemble
   from `0x4e20` and follow the `bl`.

Without a disassembler, you can bound it: `internal_checksum` is 40 bytes ending immediately before
`public_checksum` starts, so it is at `0x4e20 - 40 = 0x4df8`. That guess happens to be right here
because the compiler emitted them adjacently, and it is *not* a general technique — but the general
technique is the same shape: **anchor on a symbol you have, and navigate by offset.**

At run time:

```javascript
// Frida REPL
var base = Module.findBaseAddress('libdemo-hard-stripped.so');
var hidden = base.add(0x4df8);
Interceptor.attach(hidden, { onEnter: function (a) { console.log('hidden called'); } });
```

Note the fragility: `0x4df8` is valid for exactly this build. The next release moves it. This is why
serious tooling anchors on byte patterns or on exported neighbours rather than on raw offsets.

</details>

---

## Part 3 — Walk one call from instruction to import

This is §3.8 made concrete. You are going to trace `strcpy` — actually `__strcpy_chk` in the
hardened build — from the relocation table back to a name.

### Task 3.1 — the PLT/GOT map

```bash
# host
python3 $S/elf-inspect.py libdemo-hard.so --plt
```

<details>
<summary>Expected shape</summary>

```text
PLT / GOT correspondence
  DT_PLTGOT (.got.plt base) = 0x90c8
  GOT slot (r_offset) index    import
  0x90e0             0        __cxa_finalize
  0x90e8             1        __cxa_atexit
  0x90f0             2        __strcpy_chk
  0x90f8             3        __stack_chk_fail
  0x9100             4        malloc
  ...
```

Each row is one 8-byte GOT slot and the import whose address the linker will write into it.

</details>

### Task 3.2 — find the relocation that describes it

```bash
# host
python3 $S/elf-inspect.py libdemo-hard.so --relocs | grep -i strcpy
```

<details>
<summary>Answer</summary>

```text
  0x90f0             R_AARCH64_JUMP_SLOT      __strcpy_chk           0x0
```

Read that as: *at address `0x8fb0` (relative to the load base), write the resolved address of the
symbol `__strcpy_chk`*. `JUMP_SLOT` is specifically the "this is a function called through the PLT"
relocation type.

</details>

### Task 3.3 — join the chain up, in writing

Complete this sentence with real numbers from your own output:

> A call to `__strcpy_chk` inside `check_password` is compiled as a direct branch to a PLT stub in
> `.plt`. That stub loads a pointer from GOT slot `0x____`. That slot is described by a
> `R_AARCH64________` relocation naming the symbol `__strcpy_chk`, which the linker resolves against
> `libc.so` at load time. Because this library has **full RELRO**, the slot is made ________ after
> relocation, so a hook that rewrites it must first call ________.

<details>
<summary>Completed</summary>

> ... GOT slot `0x90f0`. That slot is described by a `R_AARCH64_JUMP_SLOT` relocation naming the
> symbol `__strcpy_chk`, which the linker resolves against `libc.so` at load time. Because this
> library has full RELRO, the slot is made **read-only** after relocation, so a hook that rewrites it
> must first call **`mprotect`**.

</details>

### Task 3.4 — count the RELATIVE relocations, and explain them

```bash
# host
python3 $S/elf-inspect.py libdemo-hard.so --relocs | grep -c RELATIVE
python3 $S/elf-inspect.py libdemo-hard.so --relocs | grep RELATIVE | head
```

Why do these have no symbol name?

<details>
<summary>Answer</summary>

Because they are not about symbols. A `RELATIVE` relocation says "add the load base to the value
stored here". It is fixing a pointer that already points somewhere *inside this library* — a string
pointer in a static struct, a C++ vtable entry, an `.init_array` slot — which needs adjusting only
because the library moved.

In a large real library these are the overwhelming majority of relocations, often more than 90 per
cent, which is exactly why Android invented the packed and RELR encodings to compress them.

</details>

---

## Part 4 — A file with no section headers

This is what a packer leaves you, and it is the situation where all the fallbacks in §3.9 earn their
keep.

### Task 4.1 — confirm the sections are gone

```bash
# host
python3 $S/elf-inspect.py libnoshdr.so --header | grep -E 'e_shoff|e_shnum|e_shstrndx'
python3 $S/elf-inspect.py libnoshdr.so --sections
```

You should see `e_shoff = 0`, `e_shnum = 0`, and "No section header table in this file."

### Task 4.2 — recover the symbols anyway

```bash
# host
python3 $S/elf-inspect.py libnoshdr.so --dynsyms --defined-only
python3 $S/elf-harden-check.py libnoshdr.so
```

<details>
<summary>What you should see</summary>

```text
  ! no section header table. The file still loads -- the linker never reads
    sections -- but every section-based answer below falls back to PT_DYNAMIC
    and is less complete.

[info] JNI surface       2 statically registered Java_* export(s), JNI_OnLoad present
```

Both `Java_*` exports are recovered. Nothing was lost.

</details>

### Task 4.3 — explain the recovery path

How did the parser find the symbol table with no section headers, and how did it know how many
entries there were?

<details>
<summary>Answer</summary>

1. `PT_DYNAMIC` is a **program header**, so it survives. It points at the dynamic array.
2. `DT_SYMTAB` (tag 6) gives the virtual address of the symbol table; `DT_STRTAB` (tag 5) gives the
   string table; `DT_STRSZ` (tag 10) gives its size.
3. Those are *virtual* addresses, so they must be converted to file offsets by walking the `PT_LOAD`
   segments and finding the one whose `[p_vaddr, p_vaddr + p_filesz)` range contains the address.
   That conversion is `vaddr_to_offset()` in the script.
4. Neither `DT_SYMTAB` nor the dynamic array says **how many symbols** there are. The count comes
   from `DT_HASH`, whose second 32-bit word is `nchain`, which by construction equals the number of
   dynamic symbols. If the file has only `DT_GNU_HASH`, the parser walks the bucket and chain arrays
   to find the highest index — and says so in its output if it cannot.

Everything the *linker* needs is reachable without section headers, by definition, because the
linker never reads them. So everything an analyst needs is reachable too. Deleting section headers
costs an attacker nothing and costs you about four lines of code.

</details>

### Task 4.4 — see what a naive tool does

```bash
# host, if you have binutils
readelf -S libnoshdr.so     ; echo "exit=$?"
nm -D libnoshdr.so          ; echo "exit=$?"
strings libnoshdr.so | head -5
```

Record which tools cope and which give up. This is the observation that makes the chapter's
dependency-free parsers worth having.

---

## Part 5 — `findExportByName`, live *(optional — needs a device)*

If you have a rooted device or emulator with `frida-server`, and any app with native libraries.

### Task 5.1 — the four surprises, in one session

```bash
# host
frida -U -f com.example.app -l ~/…/15-Native-Code/scripts/native-map.js --no-pause
```

```javascript
// Frida REPL
rpc.exports.modules();

// 1. a stripped library still resolves its exports
rpc.exports.find('libnative.so', 'JNI_OnLoad');

// 2. an internal function does not
rpc.exports.find('libnative.so', 'some_internal_helper');

// 3. a C++ symbol resolves only when mangled
rpc.exports.find('libnative.so', 'decrypt');
rpc.exports.find('libnative.so', '_ZN6Crypto7decryptEPKc');

// 4. null searches every module, and may not give you the one you want
rpc.exports.find(null, 'open');
```

### Task 5.2 — watch RELRO in the live process

```javascript
// Frida REPL
rpc.exports.got('libnative.so');
```

<details>
<summary>What to look for</summary>

```text
  strcmp                       slot 0x7b2c149eb8 [r--] -> libc.so!+0x8a340
  ...
  10 import slots, 0 currently writable.
  Every slot is read-only: full RELRO is in effect and binding already happened.
```

The **`[r--]`** is the point. In the file, `.got.plt` is in a `RW` `PT_LOAD` segment. In the live
process it is read-only, because the linker `mprotect`ed the RELRO region after relocating. That is
the difference between "the file requested full RELRO" and "full RELRO happened", and only the live
process can tell you the second.

Any slot pointing at `unmapped/unknown` is a JIT trampoline or an existing hook. Investigate every
one.

</details>

### Task 5.3 — the reconciliation

Pick one export. Confirm that:

```text
Module.findExportByName(mod, name)  ==  Module.findBaseAddress(mod) + <address from elf-inspect.py>
```

```javascript
// Frida REPL
var b = Module.findBaseAddress('libnative.so');
var e = Module.findExportByName('libnative.so', 'JNI_OnLoad');
console.log('base', b, 'export', e, 'file vaddr', e.sub(b));
```

Compare `e.sub(b)` with the `value` column from `elf-inspect.py --dynsyms`. They must match exactly.
If they do not, you took the base from the wrong `/proc/<pid>/maps` line — use the mapping with file
offset `00000000`.

---

## Success criteria

- [ ] You showed `.dynsym` is byte-for-byte unchanged by `strip` while `.symtab` disappears
- [ ] You found a function that is in `.symtab` but never in `.dynsym`, and explained why
- [ ] You located that function's address in the **stripped** file
- [ ] You traced one import from a `.text` call through the PLT stub, the GOT slot, and the
      relocation, to a name — and can recite the chain without notes
- [ ] You explained why `RELATIVE` relocations have no symbol
- [ ] You recovered the full dynamic symbol table from a file with `e_shoff = 0`, and can describe
      the four-step recovery path
- [ ] *(optional)* You confirmed `findExportByName` result == base + `.dynsym` value

---

## Going further

1. **Mangle something.** Add a C++ file to the fixtures with a class method, build it, and look at
   the symbol. Then run `llvm-cxxfilt` over the export list and notice how much more readable it
   becomes.
2. **Break the hash table.** Take `libnoshdr.so`, zero out the `DT_HASH` entry in the dynamic array,
   and re-run the parser. Watch it fall back to walking `DT_GNU_HASH`, and read the message it prints
   when it cannot be exact.
3. **Compare `.gnu.hash` and `.hash`.** Most libraries carry both. Work out why, and which one Bionic
   actually uses.
4. **Find an exported writable variable** in a real library — `elf-inspect.py --dynsyms
   --defined-only | grep OBJECT` — and think about what you could do with it. Exported globals are
   badly under-examined.

---

## Next

[Lab 04 — From APK entry to mapped page](lab-04-apk-to-mapping.md).
