# 12 — DEX Internals · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

Runtime questions (OAT, VDEX, compilation, hooking) are answered in [13-ART/faq.md](../13-ART/faq.md).

---

**1. What actually is a DEX file? I've been told "it's Android bytecode" and that hasn't helped.**

It is a *container*. Inside are the compiled instructions for many classes, plus a set of lookup
tables holding every string, type name, method name and field name those classes refer to.

The key design difference from Java's `.class` format is sharing. A `.class` file holds one class and
its own private constant pool, so if fifty classes mention `java.lang.String`, that name is stored
fifty times across fifty files. A DEX holds all fifty classes and stores `java.lang.String` **once**,
with each class referring to it by index. On 2008 hardware with slow flash, that mattered enormously.

---

**2. Do I really need to know this at the byte level? Can't I just use jadx?**

For most work, jadx is fine and you should use it. You need the bytes in three situations, and all
three come up.

Your tools disagree with each other, or with the device — which means a crafted DEX, and only the
bytes settle it. Your tools fail outright on a deliberately malformed file. Or you are *patching*, and
a wrong register count produces an app that installs and then crashes on one screen with no useful
error.

You do not need to memorise the tables. You need to know they exist and where to look.

---

**3. Why is there a `classes2.dex`? Did the build break?**

No — that is multidex, and it is normal for any app of size. A single DEX can reference at most 65,536
methods, types or fields, because several instruction formats encode the index in 16 bits. Past that,
the build splits into `classes.dex`, `classes2.dex`, and so on.

**The practical consequence for you:** always process every one of them. Concluding "the app doesn't
contain that feature" after only reading `classes.dex` is a real and embarrassing mistake.

```bash
unzip -l app.apk | grep -E 'classes[0-9]*\.dex'
```

---

**4. The 64K limit — is that 64,000 methods I wrote?**

No, and this trips up developers constantly. It counts *references*: every distinct method referenced
anywhere in that DEX, including every framework and library method your code calls.

An app with 8,000 of its own methods can blow through 65,536 references purely through its
dependencies. That is why the build error mentions a number far larger than the app's own method
count.

---

**5. In Smali, why do I see both `v0` and `p0`? Are there two sets of registers?**

One set, two naming schemes. Incoming arguments occupy the **last** `ins_size` registers of the frame,
so:

```
first parameter register = registers_size − ins_size
```

With `registers_size = 5` and `ins_size = 2`, `p0` *is* `v3` and `p1` *is* `v4`. They are the same
storage.

This matters when patching: if you add a local and bump `.registers`, every `p` alias now maps to a
different `v` number. Use `.locals` instead where you can — the assembler does the arithmetic.

---

**6. I added one instruction to a method and now the app crashes. It installed fine though.**

That combination — installs successfully, crashes when you reach the class — is almost always
**verification failure**, not a signature problem.

The most likely cause: you inserted something between an `invoke-*` and its `move-result`. The
verifier requires them to be adjacent, because the invocation result lives in a distinguished slot
valid for exactly one instruction. Even a `nop` between them is fatal.

Put your inserted code **before** the invoke, or **after** the `move-result`.

```bash
adb logcat -s art
```

will usually name the offending method.

---

**7. Why did my patch produce wrong numbers rather than crashing?**

You probably miscounted a wide value. `long` and `double` occupy **two adjacent registers**, named by
the lower one. If a method takes `(long a, int b)`, then `p0` is the long occupying `v1:v2`, and `p1`
is `v3` — not `v2`.

Read half a long as an int and you get plausible-looking garbage rather than an error.

---

**8. What is the difference between `.registers` and `.locals`?**

`.registers N` declares the **total** frame size, so you must compute `registers_size − ins_size`
yourself to know where the parameters landed. `.locals N` declares only the locals and lets the
assembler add the parameter count.

`.locals` is safer for exactly that reason. **Never use both in the same method** — the results are
confusing and version-dependent.

---

**9. How do I decode an instruction like `1A 00 12 05` by hand?**

Look up the opcode, then its format.

`0x1A` is `const-string`, format `21c`. The identifier tells you everything: **2** code units (4
bytes), **1** register, and a **c**onstant-pool index.

So byte 1 (`0x00`) is the destination register `v0`, and code unit 2 (`0x0512` little-endian) is an
index into `string_ids`. Follow that index to its `string_data_item`, read the ULEB128 length, then
the MUTF-8 bytes.

Result: `const-string v0, <string #1298>`. Confirm with `dexdump -d`.

---

**10. What does the format identifier `35c` actually mean?**

**3** code units, up to **5** registers addressable, and a **c**onstant-pool index. It is the standard
`invoke-*` encoding.

The "5" is a maximum, not a count — the actual argument count is in a nibble. The encoding is
genuinely awkward: registers are packed as nibbles across two code units. That awkwardness is exactly
why `invoke-*/range` (`3rc`) exists: with more than five arguments it takes a *first register* and a
*count*, requiring the arguments to sit consecutively.

---

**11. I ran `strings` on the DEX and found no keys. Does that mean there are none?**

No, and this is one of the most valuable things in the chapter.

When a developer writes `byte[] key = {0x2b, 0x7e, ...}`, the compiler does **not** put those bytes in
the string pool. It emits a `fill-array-data-payload`: a contiguous run of raw bytes in the data
section. Because it is not text, `strings` walks straight past it.

```bash
grep -rn "fill-array-data" out/smali*/
python3 examples/find_array_literals.py classes.dex --keys-only
```

Every "we searched for hardcoded keys and found none" report that only ran `strings` missed this.

---

**12. Does the DEX header checksum protect against tampering?**

No. The Adler-32 checksum and the SHA-1 signature in the header are **unkeyed**. Anyone who modifies
the file recomputes them — `apktool` does it automatically without being asked.

They exist to detect *corruption*, not *tampering*. Real integrity comes from APK signing, which is
keyed. An app that checks its own DEX checksum is checking something any attacker satisfies for free.

---

**13. Is the bytecode verifier a security sandbox?**

No, and getting this wrong leads to real design errors.

The verifier proves that bytecode respects the runtime's own type model: registers hold what
instructions expect, branches land on instruction boundaries, references are initialised before use.
Its actual purpose is **performance** — having proven type safety statically, the generated code need
not re-check dynamically.

It says nothing about what the app may *do*, and it is bypassed entirely the moment execution enters
JNI. Its genuine security value is narrower and worth stating precisely: it stops a malformed DEX from
corrupting ART's own state. That protects the runtime from the app, not the user from the app.

---

**14. `baksmali` refuses to parse instructions it says are invalid. What's wrong?**

You have almost certainly extracted DEX from an Android 8, 9 or 10 device and hit **quickening**.

Those releases rewrote some instructions into "quick" forms carrying precomputed vtable indices and
field offsets instead of symbolic references — `iget-quick`, `invoke-virtual-quick`. Those forms are
not valid standalone DEX, because the information needed to interpret them lives in the OAT metadata.

You need an unquickening step (`vdexExtractor` exists for this). On Android 11 and later the problem
does not arise — quickening was removed when `nterp` arrived.

---

**15. What is the `map_list` for, if the header already has all the offsets?**

Redundancy, and it is the most useful redundancy in the format for a security tester.

The header names the index tables. The `map_list` enumerates **every** section including the
variable-length data items, sorted by offset. A parser could reconstruct the file from the map alone.

More importantly: in a legitimate `d8` output, **every byte of the file is covered by exactly one map
entry**. Run the coverage check and any gap is a red flag with a short list of explanations — a
packer's encrypted payload, a second DEX appended, a configuration blob, or data smuggled past a
scanner that only reads the map.

```bash
python3 examples/dex_parser.py classes.dex --map-coverage
```

---

**16. Why would anyone deliberately malform a DEX?**

To make your tools disagree with the device.

If a crafted file causes `apktool` to show a benign manifest while `PackageManager` parses something
else, an automated store review passes and the installed app behaves differently. The levers include
unused header fields, a `map_list` that contradicts the header, `header_size` larger than `0x70`, and
string entries whose declared length disagrees with the actual bytes.

The defence is tool diversity: run `dexdump`, `baksmali` and `jadx` and treat any disagreement in the
class or method list as the finding.

---

**17. What is `ULEB128p1` and why does it exist?**

It is a ULEB128 whose decoded value is the encoded value **minus one**. So the single byte `0x00`
decodes to `−1`.

It exists because several fields need to express "absent" alongside a range of valid non-negative
indices. Rather than reserving a sentinel like `0xFFFFFFFF` and spending four bytes, the format uses
`−1` and encodes it in one byte. You meet it in `debug_info_item`'s parameter names, among other
places.

---

**18. Why does MUTF-8 encode null as two bytes?**

So that a string can never contain an embedded `0x00` byte, which means C-style null-terminated
handling works throughout the runtime without special-casing.

The other difference — supplementary characters encoded as a CESU-8 surrogate *pair* rather than one
four-byte sequence — comes from Java's internal UTF-16 representation. A genuine four-byte UTF-8
sequence in a DEX is invalid, and encountering one is a strong hint the file was hand-crafted.

---

**19. What does `ACC_NATIVE` on a method mean for my analysis?**

That the method has no `code_item` at all — `code_off` is 0 — because the body lives in a `.so` file
reached through JNI. Your DEX analysis stops there and continues in
[15-Native-Code](../15-Native-Code/README.md) and [16-JNI](../16-JNI/README.md).

Counting native methods is a fast way to gauge how much logic an app has pushed out of the DEX, which
is a common anti-reverse-engineering measure:

```bash
grep -rn "\.method.*native" out/smali*/ | wc -l
```

---

**20. What is `ACC_SYNTHETIC` and why do I care?**

It marks anything the compiler generated that the programmer did not write: bridge methods, lambda
bodies, accessors for outer-class private fields (`access$000`), enum `values()`/`valueOf()`, and
everything R8 creates.

Filtering on that bit is how you separate "code someone wrote" from "code the toolchain wrote", which
makes triage of a large app dramatically faster.

---

**21. The signed `size` in `encoded_catch_handler` — why not just use two fields?**

Because it packs two pieces of information into one variable-length value, and the format is
relentlessly space-conscious.

`size > 0` means that many typed handlers with **no** catch-all, and no `catch_all_addr` field is
present at all. `size ≤ 0` means `abs(size)` typed handlers **plus** a catch-all whose address
follows.

The reason it is `≤ 0` and not `< 0` is subtle and a good interview question: `size == 0` must be able
to mean "catch-all only", which is what a bare `finally` compiles to. With a plain unsigned count that
would be indistinguishable from "no handlers", which would be a pointless entry.

---

**22. Where is the `default` case of a switch stored?**

Nowhere. It is **fall-through**.

`packed-switch` and `sparse-switch` branch only when the value matches a case; otherwise execution
continues at the next instruction. That is why decompiled and disassembled switches look odd — the
default body sits immediately after the switch instruction, before any of the labelled cases.

---

**23. Which DEX is actually running on the device — the one in the APK?**

Not necessarily. On Android 8 and later, the bytecode the runtime uses lives in the **VDEX** file
alongside the compiled OAT. If the app was patched in place, or a packer rewrote things at install
time, the two differ.

```bash
# adb shell as root
oatdump --vdex-file=<path>/base.vdex --export-dex-to=/data/local/tmp/dex_out
```

Then compare hashes against the APK's copy. A mismatch is worth investigating. See
[13-ART](../13-ART/README.md).

---

**24. What is the single highest-value thing I can do with this chapter's knowledge tomorrow?**

Three things, in order.

Run the map-coverage check on every APK you triage — it takes seconds and finds hidden payloads that
entry-based scanners miss. Grep for `fill-array-data` to find hardcoded keys that `strings` cannot
see. And when your tools produce something surprising, run a second parser before believing the first.

Everything else in the chapter supports those three.
