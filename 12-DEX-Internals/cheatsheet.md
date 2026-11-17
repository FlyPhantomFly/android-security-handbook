# 12 — DEX Internals · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these is true.

---

## File identity

```bash
xxd -l 8 classes.dex
```

| Bytes | Meaning |
|---|---|
| `64 65 78 0a 30 33 35 00` | `dex\n035\0` — baseline |
| `...30 33 37 00` | `037` — Android 7.0, default/static interface methods |
| `...30 33 38 00` | `038` — Android 8.0, invoke-polymorphic/custom, method handles |
| `...30 33 39 00` | `039` — Android 9, hidden-API data |
| `64 65 79 0a` | `dey\n` — a **Dalvik ODEX**, not a DEX |
| `7f 45 4c 46` | ELF — this is an **OAT** file (`base.odex`), see [13](../13-ART/cheatsheet.md) |

---

## Header — the constants that must hold

| Field | Offset | Must be |
|---|---:|---|
| `magic` | `0x00` | `dex\n0NN\0` |
| `checksum` | `0x08` | Adler-32 of bytes `[12:]` |
| `signature` | `0x0C` | SHA-1 of bytes `[32:]` |
| `file_size` | `0x20` | == actual file length |
| `header_size` | `0x24` | **`0x70`** always |
| `endian_tag` | `0x28` | **`0x12345678`** |
| `map_off` | `0x34` | near the end of the file |

checksum and signature are **unkeyed**. `apktool` recomputes them. They detect corruption, not
tampering. Real integrity = APK signing ([10](../10-APK-Internals/cheatsheet.md)).

---

## File layout

```
┌──────────────────┐ 0x00
│ header_item      │ 112 bytes
├──────────────────┤
│ string_ids       │ 4 bytes each
│ type_ids         │ 4
│ proto_ids        │ 12
│ field_ids        │ 8
│ method_ids       │ 8
│ class_defs       │ 32
│ call_site_ids    │ 4      (038+)
│ method_handles   │ 8      (038+)
├──────────────────┤
│ data section     │ variable-length items
├──────────────────┤
│ map_list         │ the table of contents
└──────────────────┘
```

---

## Encodings

### ULEB128

```
0x00        → 0
0x7F        → 127
0x80 0x01   → 128       (0x01<<7 | 0x00)
0xFF 0x7F   → 16383
```
Low 7 bits are data, high bit means "continue".

| Variant | Use |
|---|---|
| `uleb128` | sizes, counts, indices |
| `uleb128p1` | value − 1, so `0x00` means **−1** (= "absent") |
| `sleb128` | signed; used by `encoded_catch_handler.size` |

### MUTF-8

| Differs from UTF-8 | How |
|---|---|
| U+0000 | encoded `C0 80`, never a bare `00` |
| Supplementary chars | CESU-8 **surrogate pair** (two 3-byte seqs), not one 4-byte seq |

A genuine 4-byte UTF-8 sequence in a DEX is invalid — a sign of hand-crafting.

### Type descriptors

| Descriptor | Java |
|---|---|
| `V` | void |
| `Z B S C I J F D` | boolean byte short char int long float double |
| `Ljava/lang/String;` | a class |
| `[I` | `int[]` |
| `[[Ljava/lang/String;` | `String[][]` |

Shorty: return type + params, all references collapsed to `L`. `(Ljava/lang/String;I)Z` → `ZLI`.

---

## Registers

```
first parameter register = registers_size − ins_size
```

| Fact | Consequence |
|---|---|
| Arguments live at the **top** of the frame | `p0` is an alias for a `v` number that shifts if you change `.registers` |
| Instance method | `p0 == this` |
| Static method | `p0 == first declared parameter` |
| `long` / `double` | occupies **two adjacent** registers, named by the lower |
| 4-bit register fields | can only address `v0`–`v15` |

`.locals N` is safer than `.registers N` — the assembler does the arithmetic.
**Never mix both in one method.**

---

## Instruction format identifiers

`NAx` = **N** code units · **A** registers · **x** operand kind

| Suffix | Operand |
|---|---|
| `b` `n` `s` `i` `l` | signed byte / nibble / short / int / long literal |
| `c` | constant-pool index |
| `h` | high bits (low bits zero) |
| `t` | branch target |
| `x` | none |

| Format | Size | Example |
|---|---:|---|
| `10x` | 1 | `return-void` |
| `11n` | 1 | `const/4 v0, #1` |
| `11x` | 1 | `move-result v0`, `return v0` |
| `12x` | 1 | `move v0, v1` |
| `21c` | 2 | `const-string v0, "x"`, `sget-object`, `new-instance` |
| `21t` | 2 | `if-eqz v0, :label` |
| `22b` | 2 | `add-int/lit8 v0, v1, #4` |
| `22c` | 2 | `iget v0, v1, Field` |
| `23x` | 2 | `add-int v0, v1, v2`, `aget`, `aput` |
| `31i` | 3 | `const v0, #0x12345678` |
| `31t` | 3 | `packed-switch`, `fill-array-data` |
| `35c` | 3 | `invoke-virtual {v1, v2}, Meth` |
| `3rc` | 3 | `invoke-virtual/range` |
| `51l` | 5 | `const-wide v0, #0x...` |

---

## Opcodes you actually need

| Hex | Mnemonic | Note |
|---:|---|---|
| `00` | `nop` | also starts the payloads |
| `0A`–`0C` | `move-result`, `-wide`, `-object` | **must immediately follow the invoke** |
| `0D` | `move-exception` | only as the first instruction of a catch handler |
| `0E`–`11` | `return-void/-/-wide/-object` | |
| `12` | `const/4 vA, #+B` | the patch instruction |
| `1A` `1B` | `const-string`, `/jumbo` | **grep for this** |
| `1F` `20` | `check-cast`, `instance-of` | |
| `22` | `new-instance` | does **not** run `<init>` |
| `26` | `fill-array-data` | → payload, **where keys live** |
| `27` | `throw` | |
| `28`–`2A` | `goto`, `/16`, `/32` | |
| `2B` `2C` | `packed-switch`, `sparse-switch` | default is **fall-through** |
| `32`–`37` | `if-eq/ne/lt/ge/gt/le` | two registers |
| `38`–`3D` | `if-eqz/nez/ltz/gez/gtz/lez` | vs zero |
| `44`–`51` | `aget*` / `aput*` | array access |
| `52`–`5F` | `iget*` / `iput*` | instance fields |
| `60`–`6D` | `sget*` / `sput*` | static fields |
| `6E` | `invoke-virtual` | vtable |
| `6F` | `invoke-super` | |
| `70` | `invoke-direct` | private + `<init>` |
| `71` | `invoke-static` | no receiver |
| `72` | `invoke-interface` | |
| `74`–`78` | `invoke-*/range` | >5 args, consecutive registers |
| `FA`–`FD` | `invoke-polymorphic`, `invoke-custom` | 038+ |

Binary op shapes: `<op>-<type>` (`23x`) · `/2addr` (`12x`) · `/lit16` (`22s`) · `/lit8` (`22b`)

`E3`–`F9` = **quickened** opcodes (Android 8–10). Not valid standalone DEX — `baksmali` fails.
Needs unquickening. Gone from Android 11+.

---

## Payloads (all start with `00` = nop)

| Ident | Structure |
|---:|---|
| `0x0100` | `packed-switch-payload`: size, first_key, targets[] |
| `0x0200` | `sparse-switch-payload`: size, keys[] (sorted), targets[] |
| `0x0300` | `fill-array-data-payload`: element_width, size, data[] |

**`fill-array-data-payload` is where hardcoded keys live.** `strings` will not find them.

```bash
grep -rn "fill-array-data" out/smali*/           # find them in Smali
python3 examples/find_array_literals.py classes.dex --keys-only
```

---

## try / catch

`try_item` (8 bytes): `start_addr` (code units) · `insn_count` (code units) · `handler_off` (**bytes**,
relative to the handler list)

Unit change in the third field. Common parser bug.

`encoded_catch_handler.size` is **signed**:

| `size` | Meaning |
|---:|---|
| `> 0` | that many typed handlers, **no** catch-all, no `catch_all_addr` field |
| `< 0` | `abs(size)` typed handlers **plus** a catch-all |
| `== 0` | catch-all only — a bare `finally` |

---

## map_list — the packer detector

```bash
python3 examples/dex_parser.py classes.dex --map-coverage
```

**In a legitimate `d8` output every byte is covered by exactly one map entry.**
Uncovered regions = packer payload, appended DEX, or smuggled data.

| Code | Type |
|---:|---|
| `0x0000` | HEADER_ITEM |
| `0x0001`–`0x0008` | the fixed-stride index tables, in file order |
| `0x1000` | MAP_LIST |
| `0x1001`–`0x1003` | TYPE_LIST, ANNOTATION_SET_REF_LIST, ANNOTATION_SET_ITEM |
| `0x2000`–`0x2006` | CLASS_DATA, CODE, STRING_DATA, DEBUG_INFO, ANNOTATION, ENCODED_ARRAY, ANNOTATIONS_DIRECTORY |
| `0xF000` | HIDDENAPI_CLASS_DATA (platform DEX only) |

---

## Access flags

| Value | Class | Field | Method |
|---:|---|---|---|
| `0x00001` | PUBLIC | PUBLIC | PUBLIC |
| `0x00002` | PRIVATE | PRIVATE | PRIVATE |
| `0x00008` | — | STATIC | STATIC |
| `0x00010` | FINAL | FINAL | FINAL |
| `0x00040` | — | VOLATILE | BRIDGE |
| `0x00080` | — | TRANSIENT | VARARGS |
| `0x00100` | — | — | **NATIVE** |
| `0x00200` | INTERFACE | — | — |
| `0x00400` | ABSTRACT | — | ABSTRACT |
| `0x01000` | SYNTHETIC | SYNTHETIC | SYNTHETIC |
| `0x04000` | ENUM | ENUM | — |
| `0x10000` | — | — | CONSTRUCTOR |
| `0x20000` | — | — | DECLARED_SYNCHRONIZED |

`ACC_NATIVE` → no `code_item`, body is in a `.so`. Count them to gauge native migration.
`ACC_SYNTHETIC` → compiler-generated. Filter it out to see code someone wrote.

---

## The 64K limit

**References, not methods you wrote.** `method_ids`, `field_ids`, `type_ids` each cap at 65,536
because several instruction formats use 16-bit index fields.

```bash
unzip -l app.apk | grep -E 'classes[0-9]*\.dex'    # ALWAYS check for multidex
```

| API | Multidex |
|---|---|
| ≤ 20 | Needs the MultiDex support library |
| ≥ 21 | Native — `multiDexEnabled true` suffices |

Index numbers are **per file**. `method@0x100` in `classes.dex` ≠ in `classes2.dex`.

---

## Commands

| Need | Command |
|---|---|
| Header | `dexdump -f classes.dex` |
| Disassembly | `dexdump -d classes.dex` |
| With line numbers | `dexdump -d -l plain classes.dex` |
| Class list | `baksmali list classes classes.dex` |
| Disassemble | `baksmali d classes.dex -o smali/` |
| Reassemble | `smali a smali/ -o classes.dex` |
| Full decode | `apktool d app.apk -o work/` |
| Rebuild | `apktool b work/ -o patched.apk` |
| Decompile | `jadx -d out app.apk` |
| Extract from device | `oatdump --vdex-file=base.vdex --export-dex-to=<dir>` |
| Parse by hand | `python3 examples/dex_parser.py classes.dex` |
| Find keys | `python3 examples/find_array_literals.py classes.dex --keys-only` |
| Full audit | `./scripts/dex-audit.sh app.apk` |

### Rebuild cycle — order matters

```bash
apktool b work/ -o patched.apk
zipalign -p -f -v 4 patched.apk aligned.apk      # ALIGN
apksigner sign --ks ~/.android/debug.keystore --ks-pass pass:android \
  --out signed.apk aligned.apk                    # THEN SIGN
apksigner verify -v signed.apk
adb install -r signed.apk
```

---

## Greps that pay

```bash
grep -rn "fill-array-data" out/smali*/                    # hardcoded keys
grep -rn "\.method.*native" out/smali*/ | wc -l           # native migration
grep -rn "Ldalvik/system/.*ClassLoader" out/smali*/       # dynamic loading
grep -rn "Ljava/lang/reflect/\|Class;->forName" out/smali*/  # reflection
grep -rhoE 'const-string [vp][0-9]+, ".*"' out/smali*/ \
  | sed 's/.*, "//;s/"$//' | sort | uniq -c | sort -rn | head -50
```

---

## Patching failure modes

| Symptom | Cause |
|---|---|
| Installs, crashes on one screen | **Verification failure.** Check `adb logcat -s art` |
| "Cannot encode register" | Register above `v15` in a 4-bit field — use `/from16` |
| Wrong values at runtime | Miscounted a wide (`long`/`double`) pair |
| `p` alias reads garbage | Changed `.registers` without recomputing `registers_size − ins_size` |
| Verifier rejects the method | Instruction inserted between `invoke` and `move-result` |

---

## Rules

1. **Process every `classes*.dex`.** Missing `classes2.dex` is how people conclude a feature is absent.
2. `move-result` must **immediately** follow its invoke. Insert code before the invoke or after the
   `move-result`.
3. `long`/`double` = **two** registers.
4. `p0` is not `v0`. Compute `registers_size − ins_size`.
5. Align **before** signing.
6. The header checksum is **not** a security control.
7. The verifier is **not** a sandbox — it is correctness so the compiler can omit checks.
8. Map gaps mean something is hidden.
9. Hardcoded keys are in `fill-array-data`, not the string pool.
10. When tools disagree with the runtime, the runtime is right.
