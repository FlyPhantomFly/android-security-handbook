# 15 — Native Code · Cheat Sheet

> Tables and commands. Prose is in [README.md](README.md).
> Related: [16-JNI](../16-JNI/README.md) · [17-Libraries](../17-Libraries/README.md) ·
> [53-Frida](../53-Frida/README.md) · [57-Ghidra](../57-Ghidra/README.md)

---

## 1. ELF header — ELF64 / ELF32

| Field | 64 off | 32 off | Size 64/32 | Notes |
|---|---|---|---|---|
| `e_ident[EI_MAG]` | `0x00` | `0x00` | 4 | `7F 45 4C 46` |
| `e_ident[EI_CLASS]` | `0x04` | `0x04` | 1 | `1`=ELF32, `2`=ELF64 |
| `e_ident[EI_DATA]` | `0x05` | `0x05` | 1 | `1`=LSB (always on Android) |
| `e_ident[EI_VERSION]` | `0x06` | `0x06` | 1 | `1` |
| `e_ident[EI_OSABI]` | `0x07` | `0x07` | 1 | `0`=System V on Android |
| `e_ident[EI_ABIVERSION]` | `0x08` | `0x08` | 1 | `0` |
| `e_type` | `0x10` | `0x10` | 2 | `3`=`ET_DYN` |
| `e_machine` | `0x12` | `0x12` | 2 | `183`=AArch64 |
| `e_version` | `0x14` | `0x14` | 4 | `1` |
| `e_entry` | `0x18` | `0x18` | 8/4 | `0` in a plain `.so` |
| `e_phoff` | `0x20` | `0x1C` | 8/4 | program header table |
| `e_shoff` | `0x28` | `0x20` | 8/4 | `0` = no section headers |
| `e_flags` | `0x30` | `0x24` | 4 | |
| `e_ehsize` | `0x34` | `0x28` | 2 | `64` / `52` |
| `e_phentsize` | `0x36` | `0x2A` | 2 | `56` / `32` |
| `e_phnum` | `0x38` | `0x2C` | 2 | |
| `e_shentsize` | `0x3A` | `0x2E` | 2 | `64` / `40` |
| `e_shnum` | `0x3C` | `0x30` | 2 | |
| `e_shstrndx` | `0x3E` | `0x32` | 2 | section-name string table index |

### `e_type`

| Value | Name | Meaning |
|---|---|---|
| 1 | `ET_REL` | object file (`.o`) |
| 2 | `ET_EXEC` | fixed-address executable — **refused by Android since API 21** |
| 3 | `ET_DYN` | shared object or PIE — **everything on Android** |
| 4 | `ET_CORE` | core dump |

### `e_machine` → ABI directory

| Value | Hex | Name | Directory |
|---|---|---|---|
| 3 | `0x03` | `EM_386` | `lib/x86/` |
| 40 | `0x28` | `EM_ARM` | `lib/armeabi-v7a/` |
| 62 | `0x3E` | `EM_X86_64` | `lib/x86_64/` |
| 183 | `0xB7` | `EM_AARCH64` | `lib/arm64-v8a/` |
| 243 | `0xF3` | `EM_RISCV` | `lib/riscv64/` |

---

## 2. Program headers — the loader's table

**ELF64, 56 bytes:** `p_type`(0,4) `p_flags`(4,4) `p_offset`(8,8) `p_vaddr`(16,8) `p_paddr`(24,8) `p_filesz`(32,8) `p_memsz`(40,8) `p_align`(48,8)

**ELF32, 32 bytes:** `p_type`(0,4) `p_offset`(4,4) `p_vaddr`(8,4) `p_paddr`(12,4) `p_filesz`(16,4) `p_memsz`(20,4) **`p_flags`(24,4)** `p_align`(28,4)

| `p_type` | Value | Role |
|---|---|---|
| `PT_NULL` | 0 | unused |
| `PT_LOAD` | 1 | **map this into memory** |
| `PT_DYNAMIC` | 2 | the dynamic array |
| `PT_INTERP` | 3 | `/system/bin/linker64` |
| `PT_NOTE` | 4 | build-id, android ident |
| `PT_PHDR` | 6 | the header table itself |
| `PT_TLS` | 7 | thread-local template |
| `PT_GNU_EH_FRAME` | `0x6474E550` | unwind tables |
| `PT_GNU_STACK` | `0x6474E551` | **stack permissions — NX** |
| `PT_GNU_RELRO` | `0x6474E552` | **make read-only after relocation** |
| `PT_GNU_PROPERTY` | `0x6474E553` | BTI/PAC feature notes |
| `PT_ARM_EXIDX` | `0x70000001` | ARM32 unwind index |

| `p_flags` | Value |
|---|---|
| `PF_X` | 1 |
| `PF_W` | 2 |
| `PF_R` | 4 |

**Reading a `PT_LOAD`:** take `p_filesz` bytes from file offset `p_offset`, map at
`base + p_vaddr` with `p_flags`, zero-fill to `p_memsz`. The gap is `.bss`.

---

## 3. Section headers — the tools' table

**ELF64, 64 bytes:** `sh_name`(0,4) `sh_type`(4,4) `sh_flags`(8,8) `sh_addr`(16,8) `sh_offset`(24,8) `sh_size`(32,8) `sh_link`(40,4) `sh_info`(44,4) `sh_addralign`(48,8) `sh_entsize`(56,8)
**ELF32, 40 bytes:** same order, every field 4 bytes.

| `sh_type` | Value | | `sh_type` | Value |
|---|---|---|---|---|
| `SHT_NULL` | 0 | | `SHT_DYNSYM` | 11 |
| `SHT_PROGBITS` | 1 | | `SHT_INIT_ARRAY` | 14 |
| `SHT_SYMTAB` | 2 | | `SHT_FINI_ARRAY` | 15 |
| `SHT_STRTAB` | 3 | | `SHT_PREINIT_ARRAY` | 16 |
| `SHT_RELA` | 4 | | `SHT_GNU_HASH` | `0x6FFFFFF6` |
| `SHT_HASH` | 5 | | `SHT_ANDROID_REL` | `0x60000001` |
| `SHT_DYNAMIC` | 6 | | `SHT_ANDROID_RELA` | `0x60000002` |
| `SHT_NOTE` | 7 | | `SHT_ANDROID_RELR` | `0x6FFFFF00` |
| `SHT_NOBITS` | 8 | | `SHT_GNU_versym` | `0x6FFFFFFF` |
| `SHT_REL` | 9 | | `SHT_GNU_verneed` | `0x6FFFFFFE` |

| `sh_flags` | Value |
|---|---|
| `SHF_WRITE` | `0x1` |
| `SHF_ALLOC` | `0x2` |
| `SHF_EXECINSTR` | `0x4` |
| `SHF_MERGE` | `0x10` |
| `SHF_STRINGS` | `0x20` |
| `SHF_TLS` | `0x400` |

### Sections you will name

| Section | Perms | Contents | Survives `strip`? |
|---|---|---|---|
| `.text` | r-x | code | yes |
| `.rodata` | r-- | constants, **keys, URLs** | yes |
| `.data` | rw- | writable globals — **RELRO does not cover it** | yes |
| `.bss` | rw- | zero-init globals, no file bytes | yes |
| `.data.rel.ro` | rw→r-- | vtables, relocated constants | yes |
| `.plt` | r-x | call stubs | yes |
| `.got` / `.got.plt` | rw- / r-- | resolved addresses — **hook target** | yes |
| `.dynamic` | r-- | `DT_*` array | yes |
| `.dynsym` / `.dynstr` | r-- | **exports + imports** | **yes — cannot be removed** |
| `.rela.dyn` / `.rela.plt` | r-- | relocations | yes |
| `.init_array` | rw→r-- | **constructors, run before `JNI_OnLoad`** | yes |
| `.fini_array` | rw→r-- | destructors | yes |
| `.gnu.hash` / `.hash` | r-- | symbol lookup; `.hash` gives the symbol count | yes |
| `.note.gnu.build-id` | r-- | unique build hash | yes |
| `.note.android.ident` | r-- | NDK target API | yes |
| `.symtab` / `.strtab` | not mapped | **all** symbols | **no** |
| `.comment` | not mapped | clang/NDK banner | no |
| `.debug_*` | not mapped | DWARF | no |

---

## 4. Dynamic array (`DT_*`)

ELF64 entry = 16 bytes (tag, value); ELF32 = 8. Terminated by `DT_NULL`.

| Tag | Value | Holds | | Tag | Value | Holds |
|---|---|---|---|---|---|---|
| `DT_NULL` | 0 | end | | `DT_INIT_ARRAY` | 25 | ctor array |
| `DT_NEEDED` | 1 | dependency (str) | | `DT_FINI_ARRAY` | 26 | dtor array |
| `DT_PLTRELSZ` | 2 | bytes | | `DT_INIT_ARRAYSZ` | 27 | bytes |
| `DT_PLTGOT` | 3 | `.got.plt` addr | | `DT_FINI_ARRAYSZ` | 28 | bytes |
| `DT_HASH` | 4 | SysV hash; `nchain` = symbol count | | `DT_RUNPATH` | 29 | search path (str) |
| `DT_STRTAB` | 5 | dynamic strings | | `DT_FLAGS` | 30 | bitmask |
| `DT_SYMTAB` | 6 | dynamic symbols | | `DT_PREINIT_ARRAY` | 32 | runs first |
| `DT_RELA` | 7 | RELA table | | `DT_PREINIT_ARRAYSZ` | 33 | bytes |
| `DT_RELASZ` | 8 | bytes | | `DT_RELRSZ` | 35 | RELR bytes |
| `DT_RELAENT` | 9 | 24 | | `DT_RELR` | 36 | RELR table |
| `DT_STRSZ` | 10 | bytes | | `DT_RELRENT` | 37 | 8 |
| `DT_SYMENT` | 11 | 24 / 16 | | `DT_GNU_HASH` | `0x6FFFFEF5` | modern hash |
| `DT_INIT` | 12 | legacy ctor | | `DT_VERSYM` | `0x6FFFFFF0` | versioning |
| `DT_FINI` | 13 | legacy dtor | | `DT_RELACOUNT` | `0x6FFFFFF9` | count |
| `DT_SONAME` | 14 | **canonical name** | | `DT_FLAGS_1` | `0x6FFFFFFB` | bitmask |
| `DT_RPATH` | 15 | legacy search path | | `DT_VERNEED` | `0x6FFFFFFE` | |
| `DT_REL` | 17 | REL table (ARM32) | | `DT_VERNEEDNUM` | `0x6FFFFFFF` | |
| `DT_RELSZ` | 18 | bytes | | `DT_ANDROID_REL` | `0x6000000F` | packed |
| `DT_RELENT` | 19 | 8 | | `DT_ANDROID_RELSZ` | `0x60000010` | |
| `DT_PLTREL` | 20 | 7=RELA, 17=REL | | `DT_ANDROID_RELA` | `0x60000011` | packed |
| `DT_TEXTREL` | 22 | **rejected API 23+** | | `DT_ANDROID_RELASZ` | `0x60000012` | |
| `DT_JMPREL` | 23 | PLT relocations | | `DT_ANDROID_RELR` | `0x6FFFE000` | |
| `DT_BIND_NOW` | 24 | eager binding | | `DT_ANDROID_RELRENT` | **`0x6FFFE003`** | note the gap |

| `DT_FLAGS` bit | Value | | `DT_FLAGS_1` bit | Value |
|---|---|---|---|---|
| `DF_ORIGIN` | `0x1` | | `DF_1_NOW` | `0x1` |
| `DF_SYMBOLIC` | `0x2` | | `DF_1_GLOBAL` | `0x2` |
| `DF_TEXTREL` | `0x4` | | `DF_1_NODELETE` | `0x8` |
| `DF_BIND_NOW` | `0x8` | | `DF_1_NOOPEN` | `0x40` |
| `DF_STATIC_TLS` | `0x10` | | `DF_1_PIE` | `0x08000000` |

---

## 5. Symbols

**ELF64 entry, 24 bytes:** `st_name`(0,4) `st_info`(4,1) `st_other`(5,1) `st_shndx`(6,2) `st_value`(8,8) `st_size`(16,8)
**ELF32 entry, 16 bytes:** `st_name`(0,4) `st_value`(4,4) `st_size`(8,4) `st_info`(12,1) `st_other`(13,1) `st_shndx`(14,2)

| Binding (`st_info >> 4`) | Value | | Type (`st_info & 0xF`) | Value |
|---|---|---|---|---|
| `STB_LOCAL` | 0 | | `STT_NOTYPE` | 0 |
| `STB_GLOBAL` | 1 | | `STT_OBJECT` | 1 |
| `STB_WEAK` | 2 | | `STT_FUNC` | 2 |
| | | | `STT_SECTION` | 3 |
| | | | `STT_FILE` | 4 |
| | | | `STT_GNU_IFUNC` | 10 |

| Visibility (`st_other & 3`) | Value | Effect |
|---|---|---|
| `STV_DEFAULT` | 0 | exported, interposable |
| `STV_INTERNAL` | 1 | reserved |
| `STV_HIDDEN` | 2 | **not in `.dynsym` — invisible to `findExportByName`** |
| `STV_PROTECTED` | 3 | in `.dynsym`, binds locally |

| `st_shndx` | Value | Meaning |
|---|---|---|
| `SHN_UNDEF` | 0 | **an IMPORT** |
| `SHN_ABS` | `0xFFF1` | absolute value |
| `SHN_COMMON` | `0xFFF2` | uninitialised common |

### `.dynsym` vs `.symtab`

| | `.dynsym` | `.symtab` |
|---|---|---|
| Contents | exports + imports | everything, incl. `static` |
| Mapped | yes | no |
| Needed at run time | yes | no |
| Removed by `strip` | **no** | **yes** |
| Searched by `findExportByName` | **yes** | no |

---

## 6. Relocations

| | `REL` | `RELA` |
|---|---|---|
| 64-bit entry size | 16 | **24** |
| Fields | `r_offset`, `r_info` | `r_offset`, `r_info`, `r_addend` |
| Value source | the slot | **the addend** |
| Used by | ARM32 | AArch64, x86-64 |

`r_info`: 64-bit → `sym = r_info >> 32`, `type = r_info & 0xFFFFFFFF`. 32-bit → `sym = r_info >> 8`,
`type = r_info & 0xFF`.

| AArch64 | Value | ARM32 | Value | x86-64 | Value | Effect |
|---|---|---|---|---|---|---|
| `R_AARCH64_ABS64` | 257 | `R_ARM_ABS32` | 2 | `R_X86_64_64` | 1 | `sym + addend` |
| `R_AARCH64_GLOB_DAT` | 1025 | `R_ARM_GLOB_DAT` | 21 | `R_X86_64_GLOB_DAT` | 6 | GOT data slot |
| `R_AARCH64_JUMP_SLOT` | 1026 | `R_ARM_JUMP_SLOT` | 22 | `R_X86_64_JUMP_SLOT` | 7 | PLT/GOT function slot |
| `R_AARCH64_RELATIVE` | 1027 | `R_ARM_RELATIVE` | 23 | `R_X86_64_RELATIVE` | 8 | `base + addend`, no symbol |
| `R_AARCH64_IRELATIVE` | 1032 | `R_ARM_IRELATIVE` | 160 | `R_X86_64_IRELATIVE` | 37 | call resolver |

> **AArch64 `.init_array` slots read as `0` in the file. The address is in the `RELA` addend.**
> ARM32 `REL` has no addend, so the value really is in the slot.

---

## 7. The hardening checklist

| Item | Observed by | GOOD | MISSING |
|---|---|---|---|
| PIE | `e_type` @ `0x10` | `3` (`ET_DYN`) | `2` (`ET_EXEC`) |
| NX | `PT_GNU_STACK` `p_flags` | no `PF_X` (`RW-`) | `PF_X` set (`RWE`) |
| W^X | every `PT_LOAD` `p_flags` | no `PF_W|PF_X` | any segment both |
| RELRO — partial | `PT_GNU_RELRO` present | | absent |
| RELRO — full | + `DT_BIND_NOW` \| `DF_BIND_NOW` \| `DF_1_NOW` | all present | binding is lazy |
| Stack canary | `__stack_chk_fail` in symbols | referenced | absent |
| FORTIFY | `__*_chk` imports | present | absent |
| CFI | `__cfi_*` symbols | present | no evidence |
| Shadow Call Stack | — | **not statically detectable** | — |
| TEXTREL | `DT_TEXTREL` / `DF_TEXTREL` | absent | present |
| RPATH/RUNPATH | `DT_RPATH` / `DT_RUNPATH` | absent or `$ORIGIN` | writable absolute path |
| Stripped | `.symtab` present? | — | informational only |
| 16 KiB pages | min `PT_LOAD` `p_align` | `>= 0x4000` | `0x1000` |

### Runnable — this chapter's tools

```bash
python3 scripts/elf-harden-check.py libnative.so
python3 scripts/elf-harden-check.py lib/arm64-v8a/*.so
python3 scripts/elf-harden-check.py --apk target.apk
python3 scripts/elf-harden-check.py --apk target.apk --abi arm64-v8a
python3 scripts/elf-harden-check.py libnative.so --verbose      # evidence + caveats
python3 scripts/elf-harden-check.py libnative.so --json
python3 scripts/elf-harden-check.py lib/arm64-v8a/*.so --strict # exit 1 on MISSING
```

### Runnable — with `readelf`

```bash
SO=lib/arm64-v8a/libnative.so
readelf -h  "$SO" | grep -E 'Type|Machine'                    # PIE, ABI
readelf -lW "$SO" | grep GNU_STACK                            # NX  (must not be RWE)
readelf -lW "$SO" | grep GNU_RELRO                            # RELRO present?
readelf -d  "$SO" | grep -E 'BIND_NOW|FLAGS'                  # RELRO full?
readelf --dyn-syms -W "$SO" | grep -c __stack_chk_fail        # canary
readelf --dyn-syms -W "$SO" | grep -E '_chk$'                 # FORTIFY
readelf -SW "$SO" | grep -E '\.symtab|\.debug'                # stripped?
readelf -d  "$SO" | grep -E 'RPATH|RUNPATH|TEXTREL'           # paths, textrel
readelf -lW "$SO" | awk '/LOAD/{print $NF}' | sort -u         # 16 KiB alignment
readelf -n  "$SO" | grep -A1 'Build ID'                       # provenance
```

> Use **`llvm-readelf`** (ships in every NDK) on Android targets. Binutils `readelf` cannot decode
> `DT_ANDROID_REL/RELA` and reports zero relocations where there are thousands.

### Runnable — nothing installed at all

```bash
head -c 4 x.so | od -c | head -1              # 177 E L F ?
od -A d -t u1 -j 4 -N 1 x.so                  # 1=ELF32 2=ELF64
od -A d -t x1 -j 18 -N 2 x.so                 # e_machine, little-endian
strings -a x.so | grep -E '^\.(symtab|dynsym|debug_info)$'   # stripped?
strings -a x.so | grep -E '^lib.*\.so$' | sort -u            # dependencies
strings -a x.so | grep -c __stack_chk_fail                   # canary (approximate)
```

### Severity, at a glance

| Observation | Standalone severity |
|---|---|
| Executable stack | **Low** — report it |
| `RWX` `PT_LOAD` | Low–Medium, always investigate (packer) |
| No RELRO / partial | Informational |
| **No stack canary** | **Informational — NOT a finding** |
| No FORTIFY / no CFI | Informational |
| Not stripped | Informational |
| DWARF present | Low info disclosure |
| `RUNPATH` to a writable path | Medium |
| 4 KiB alignment only | Low **compatibility**, not security |
| Secret in `.rodata` | Low → Critical, by what it unlocks |
| Reachable memory-corruption bug | High → Critical; mitigations become impact multipliers |

---

## 8. `elf-inspect.py`

```bash
python3 scripts/elf-inspect.py x.so --header        # every field, with its file offset
python3 scripts/elf-inspect.py x.so --segments      # program headers
python3 scripts/elf-inspect.py x.so --sections      # section headers
python3 scripts/elf-inspect.py x.so --dynamic       # DT_* decoded
python3 scripts/elf-inspect.py x.so --dynsyms       # .dynsym
python3 scripts/elf-inspect.py x.so --symbols       # .symtab (unstripped only)
python3 scripts/elf-inspect.py x.so --relocs        # .rela.dyn + .rela.plt
python3 scripts/elf-inspect.py x.so --plt           # GOT slot -> import map
python3 scripts/elf-inspect.py x.so --init          # constructors, addend resolved
python3 scripts/elf-inspect.py x.so --notes         # build-id, NDK API, .comment
python3 scripts/elf-inspect.py x.so --strings --min 16
python3 scripts/elf-inspect.py x.so --hex .init_array
python3 scripts/elf-inspect.py x.so --all
python3 scripts/elf-inspect.py x.so --no-sections   # ignore section headers entirely
python3 scripts/elf-inspect.py x.so --dynsyms --defined-only --grep Java_
python3 scripts/elf-inspect.py x.so --dynsyms --undefined-only
```

---

## 9. Getting the library out of an APK

```bash
unzip -l app.apk | grep '\.so$'                             # what is there
unzip -o app.apk 'lib/*' -d out/                            # extract (quote for MSYS)
python3 scripts/elf-harden-check.py --apk app.apk           # audit in place
python3 scripts/elf-harden-check.py --apk app.apk | grep 'in APK'   # STORED? aligned?
apktool d -f app.apk -o out/ && grep -o 'extractNativeLibs="[^"]*"' out/AndroidManifest.xml
```

| `extractNativeLibs` | ZIP entry | Result |
|---|---|---|
| `true` (or compressed) | `DEFLATED` | copied to `/data/app/~~xxx/<pkg>-n/lib/<arch>/` at install |
| `false` | `STORED` **and** page-aligned | mapped straight out of the APK, one copy on disk |

| Device path | Note |
|---|---|
| `/data/app/~~<rand>/<pkg>-<rand>/base.apk` | the APK |
| `/data/app/~~<rand>/<pkg>-<rand>/lib/arm64/` | extracted libraries — note `arm64`, **not** `arm64-v8a` |
| `/data/app/.../oat/` | compiled DEX, not native libs |

---

## 10. Run time

```bash
adb shell 'pm path com.example.app'
adb shell 'run-as com.example.app cat /proc/self/maps | grep "\.so"'
adb shell 'su -c "grep -m1 libnative /proc/$(pidof com.example.app)/maps"'
adb shell 'su -c "grep rwx /proc/$(pidof com.example.app)/maps"'
strace -f -e trace=openat,mmap,mprotect -p $(pidof com.example.app) 2>&1 | grep '\.so'
```

> `adb shell` does not preserve host quoting. Wrap the whole device-side command in single quotes,
> or `su -c` runs only the first word.

```javascript
// Frida — scripts/native-map.js
rpc.exports.modules();                        // app libraries, base and size
rpc.exports.detail('libnative.so');           // ranges, exports, imports, JNI
rpc.exports.got('libnative.so');              // GOT slots, values, permissions
rpc.exports.find('libnative.so', 'strcpy');   // findExportByName, explained
rpc.exports.wx();                             // writable+executable pages
rpc.exports.watchload();                      // every future dlopen
```

```javascript
// the arithmetic, both directions
var base = Module.findBaseAddress('libnative.so');
var runtime = base.add(0x4b04);      // Ghidra address -> live
var fileva  = runtime.sub(base);     // live -> Ghidra address
```

| Frida call | Reads |
|---|---|
| `Module.findExportByName(mod, name)` | `.dynsym` of `mod` |
| `Module.findExportByName(null, name)` | every module, link order — first match wins |
| `Module.enumerateExports()` | defined `.dynsym` entries |
| `Module.enumerateImports()` | `SHN_UNDEF` entries, with GOT `slot` |
| `Process.enumerateModules()` | the linker's `link_map` — **a library can unlink itself** |
| `Process.enumerateRanges()` | the kernel's view — **it cannot** |

---

## 11. Loading sequence

| # | Step | Observable as |
|---|---|---|
| 1 | resolve name in the caller's linker namespace | `openat` attempts |
| 2 | already loaded by `SONAME`? return early | **no syscalls at all** |
| 3 | open, read ELF + program headers | `openat`, `read` |
| 4 | reserve the whole image | one `mmap` `PROT_NONE` |
| 5 | map each `PT_LOAD` | one `mmap` per segment |
| 6 | load `DT_NEEDED` recursively | more `openat` |
| 7 | apply relocations, write GOT | no syscalls |
| 8 | RELRO | `mprotect(..., PROT_READ)` |
| 9 | `DT_INIT`, then `DT_INIT_ARRAY`, **dependencies first** | **library code runs** |
| 10 | `dlopen` returns; ART then calls `JNI_OnLoad` | |

---

## 12. Version matrix

| Behaviour | API |
|---|---|
| ASLR for libraries | 14 |
| **Non-PIE (`ET_EXEC`) refused** | **21** |
| Text relocations refused | 23 |
| Packed relocations (`DT_ANDROID_REL/RELA`) | 23 |
| Linker namespaces | 24 |
| `DT_ANDROID_RELR` | 28 |
| Standard `DT_RELR` (36) | 30 |
| Scudo default allocator | 30 |
| MTE on supporting hardware | 31+ |
| 16 KiB pages; `max-page-size=16384` needed | 35 era |

---

## 13. Build flags

| Flag | Effect |
|---|---|
| `-fPIC` | position-independent code |
| `-fstack-protector-strong` | canary on functions with arrays or address-taken locals |
| `-fstack-protector-all` | every function |
| `-fno-stack-protector` | none |
| `-D_FORTIFY_SOURCE=2` | `__*_chk` variants where sizes are known |
| `-fvisibility=hidden` | keep symbols out of `.dynsym` |
| `-flto` | link-time optimisation; symbols disappear |
| `-Wl,-z,relro` | `PT_GNU_RELRO` |
| `-Wl,-z,now` | eager binding → full RELRO |
| `-Wl,-z,noexecstack` | `PT_GNU_STACK` without `PF_X` |
| `-Wl,-z,execstack` | **the defect** |
| `-Wl,-z,max-page-size=16384` | 16 KiB page compatibility |
| `-Wl,-rpath,$ORIGIN` | `DT_RUNPATH` |
| `llvm-strip x.so` | removes `.symtab`, `.strtab`, `.comment` |

> NDK defaults come from `android.toolchain.cmake` / `ndk-build`, **not** from the compiler driver.
> Invoking `aarch64-linux-android21-clang` directly gives you RELRO and NX and **no canary, no
> FORTIFY**.

---

## 14. Triage in order

```bash
bash scripts/so-triage.sh lib/arm64-v8a/libnative.so
bash scripts/so-triage.sh --apk target.apk
```

| # | Question | Command |
|---|---|---|
| 1 | What is it? | `--header`, `sha256sum` |
| 2 | What does it need? | `--dynamic \| grep NEEDED` |
| 3 | What does it offer? | `--dynsyms --defined-only --grep Java_` |
| 4 | How hardened? | `elf-harden-check.py` |
| 5 | What runs first? | `--init` |
| 6 | Secrets? | `--strings --min 16` |
| 7 | Which library and version? | `17-Libraries/scripts/lib-fingerprint.py` |
| 8 | What does it do? | [57-Ghidra](../57-Ghidra/README.md) |

| Marker in strings | Suggests |
|---|---|
| `/system/bin/su`, `magisk`, `superuser` | root detection |
| `frida`, `gum-js`, `re.frida`, `gadget` | anti-instrumentation |
| `TracerPid`, `/proc/self/status`, `ptrace` | anti-debugging |
| `xposed`, `LSPosed` | hook detection |
| `libhoudini` | emulator detection |
| very few strings for the file size | encrypted strings / packer |
