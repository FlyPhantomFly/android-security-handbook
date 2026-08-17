# 18 — ARM · FAQ

Real questions, answered directly. The "dumb" ones are here on purpose — they are the ones people
are least likely to ask out loud and most likely to be stuck on.

---

### 1. Do I have to memorise the whole instruction set?

No, and nobody has. You need about twenty-five instructions and roughly the same number of *shapes*
— recurring two- and three-instruction phrases. That is what
[README §3.10](README.md#310-the-pattern-catalogue) is. Everything else you look up in
[Arm's online A64 reference](https://developer.arm.com/documentation/ddi0602/latest), one instruction
per page, in about fifteen seconds.

The honest test of whether you know enough: can you read a fifteen-instruction function and say what
it returns? If yes, you can do the work in this chapter.

---

### 2. What is the difference between `x0` and `w0`? Are they different registers?

They are the same physical register. `x0` is all 64 bits of it; `w0` is the bottom 32.

The rule that catches people out: **writing to `w0` zeroes the top 32 bits of `x0`.** It does not
preserve them. So `mov w0, #1` leaves `x0` holding exactly `0x0000000000000001`, and there is no way
to write only the low half.

Which one you see tells you the C type. `w` means the value is 32 bits or narrower — an `int`, a
`float`, a `bool`. `x` means 64 bits — a `long`, a pointer, a `double`.

---

### 3. Why is there no `x31`?

Because register number 31 was worth more as a special case. Depending on the instruction, the
encoding slot that would name `x31` means either the **stack pointer** or the **zero register**
(`xzr`), which reads as 0 and discards writes.

That one decision removes the need for a separate "clear this register" instruction (`mov w0, wzr`),
a separate "compare" instruction (`cmp x0, #1` is really `subs xzr, x0, #1` — subtract and throw the
result away, keeping only the flags), and a separate "discard the result" mechanism.

---

### 4. I keep seeing `cset`. What is it and why is it everywhere?

`cset Wd, cond` sets `Wd` to 1 if the condition holds and 0 otherwise. It is the compiler's way of
turning a comparison into a boolean **without a branch**, because a mispredicted branch costs ten to
twenty cycles and this costs one.

It is everywhere because "return true if X" is an extremely common thing for code to do — and
critically, it is what a security check compiles to:

```
cmp   w0, #1
cset  w0, gt
ret
```

That is `return tier >= 2;` from
[`examples/licence-check.c`](examples/licence-check.c), compiled at `-O2`. Replace the `cset` with
`mov w0, #1` and the function always says yes.

---

### 5. Where does a function's first argument live? How do I know?

`x0` (or `w0` for a 32-bit value). Arguments two to eight are in `x1` through `x7`. The ninth and
beyond are on the stack. Floating-point arguments use a completely separate sequence, `v0` through
`v7`, with its own counter.

You know because of **AAPCS64**, the Procedure Call Standard — a document Arm publishes that all
compilers agree to follow. It is the treaty that lets separately compiled code call itself. The
hardware enforces none of it; it is a convention, and hand-written assembly can ignore it (and
occasionally does).

[README §3.4](README.md#34-aapcs64--the-calling-convention) is the full rule set, with the compiled
proof for each rule.

---

### 6. In a JNI function, why is my first argument in `x2` and not `x0`?

Because a `Java_*` function is an ordinary C function, and its C prototype begins with two arguments
you did not write:

```c
jboolean Java_com_example_Native_isLicensed(JNIEnv *env, jobject thiz, jint tier)
```

`env` takes `x0`, `thiz` takes `x1`, and your `tier` lands in `x2`. That is not a JNI rule — it is
AAPCS64 applied to a prototype JNI added two arguments to.

You can see it in exactly three instructions:

```text
0000000000004b84 <Java_com_example_arm_Native_isLicensed>:
    4b84: 5f 04 00 71   cmp     w2, #1      <-- w2, not w0
    4b88: e0 d7 9f 1a   cset    w0, gt
    4b8c: c0 03 5f d6   ret
```

For a `static` native method the second slot is a `jclass` instead of a `jobject`, but the shift is
the same. [16-JNI](../16-JNI/README.md) owns the JNI convention itself.

---

### 7. Why does `objdump` print a function name next to `adrp` that has nothing to do with anything?

Because `adrp` computes a **page base**, not a target, and objdump annotates the number with the
nearest preceding symbol — which for a page base is meaningless.

```text
    5248:  adrp  x0, 0x0 <pat_tbz>
    524c:  add   x0, x0, #3208
```

The `<pat_tbz>` is noise. The real target is `0x0 + 3208 = 0xc88`, which is a string in `.rodata`.
**Ignore the angle-bracket annotation on any `adrp` line** and read the number, then add the `add`'s
immediate.

---

### 8. What is `adrp` actually doing, and why is it always followed by something?

A 32-bit instruction cannot hold a 64-bit address, and position-independent code cannot bake absolute
addresses in anyway. So `adrp` gives you the base of the 4 KiB page containing the target, computed
PC-relative, which reaches ±4 GiB in one instruction. Its low 12 bits are always zero.

The partner supplies those 12 bits, and which partner it is changes the meaning completely:

- `add Xd, Xd, #off` → `Xd` is now the **address**. Almost always a string or a table in `.rodata`.
- `ldr Xd, [Xd, #off]` → `Xd` is now the **contents** of that address, usually a pointer loaded from
  the GOT.

---

### 9. I patched the function, `objdump` confirms the bytes changed, and the app behaves exactly as before. What did I do wrong?

Probably nothing wrong — you hit the **inlining trap**, and it is the single most common patching
failure.

At `-O2` the compiler copies small functions into their callers. The exported standalone copy
survives only because it is exported and the linker cannot prove nothing needs it. So there can be
two copies of a check in one library, and you patched the one nothing calls.

[README §5.4](README.md#54-the-worked-example-what-patching-a-check-actually-buys-you) works through a
real case, verified on a device: `lc_verify_signature` was forced to return 1 and demonstrably
returned 1, while `lc_decrypt_flag` — whose C source calls it — kept refusing, because clang had
inlined the entire body into it.

**How to confirm:** trace the patched function at runtime. If the trace never fires, nothing calls
it. **How to fix:** find the check's *contents* in the caller — the same `strlen` call, the same
length comparison, the same `movk` constant chain — and patch that, or patch every copy.

---

### 10. Why can't I just open the `.so` in a hex editor, seek to the address `objdump` printed, and write four bytes?

Because `objdump` prints a **virtual address** and a hex editor seeks to a **file offset**, and they
are different numbers.

For this chapter's fixture, `lc_is_licensed` is at virtual address `0x48c4` and file offset `0x8c4` —
a delta of `0x4000`. Writing at `0x48c4` in the file lands somewhere entirely unrelated.

Worse, **the delta is not constant across a file.** A library has several `PT_LOAD` segments with
different deltas: in the same file, `.rodata` at virtual address `0x660` sits at file offset `0x660`,
delta zero. Compute the delta once and apply it everywhere and you will corrupt data while believing
you patched code.

[`scripts/arm64-patch.py`](scripts/arm64-patch.py) reads the program headers and does it per segment,
and prints the arithmetic so you can check it:

```text
vaddr    : 0x48c4
file off : 0x8c4   (segment vaddr 0x4874 -> offset 0x874, delta -0x4000)
```

---

### 11. Ghidra shows `0x001048c4` and objdump shows `0x48c4`. Which is right?

Both. Ghidra loads a shared object at a default **image base** of `0x00100000` and adds it to every
address. Subtract `0x00100000` to get the virtual address that objdump, `readelf` and Frida all use,
or set Ghidra's image base to 0 (Window → Memory Map → the image-base button) and the numbers match.

Then, at runtime, the library is mapped at an ASLR-randomised base, and the runtime address is
`module_base + 0x48c4`. Four names for one instruction:

| Name | Value here | Used for |
|---|---|---|
| Virtual address | `0x48c4` | Reading, and all cross-references |
| File offset | `0x8c4` | **Patching the file** |
| Ghidra address | `0x001048c4` | Only inside Ghidra |
| Runtime address | `base + 0x48c4` | Hooking, breakpoints |

---

### 12. Is patching a `.so` legal?

Patching software you own or have written permission to test is normal security work. Patching
software you do not, distributing patched binaries, or circumventing a technical protection measure
can be unlawful depending on your jurisdiction and on the licence you agreed to. A script does not
make it lawful, and [`scripts/arm64-patch.py`](scripts/arm64-patch.py) says so in its own header.

Get the scope in writing. This chapter's fixtures exist so you can practise on something you built
yourself.

---

### 13. What is the stack canary, and why does AArch64 read it from a system register?

A canary is a random value the compiler plants between local buffers and the saved return address. A
linear overflow that reaches the return address must cross it, so a mismatch at the end of the
function proves an overflow happened, and the process aborts instead of returning to attacker-chosen
code.

It has to live somewhere per-thread and unwritable by the overflow itself, so it lives in
**thread-local storage**. x86-64 reaches TLS through the `%fs` segment register and reads the guard
at `%fs:0x28`. AArch64 has no segment registers; it has `TPIDR_EL0`, a system register holding the
thread pointer, read with `mrs`. Bionic keeps the guard in TLS slot 5, and slots are 8 bytes, so the
offset is 40 — which is `0x28`, the same number as x86's by coincidence of layout.

```text
    48e0: 54 d0 3b d5   mrs     x20, TPIDR_EL0
    48e4: 88 16 40 f9   ldr     x8, [x20, #40]
    48e8: a8 83 1f f8   stur    x8, [x29, #-8]
```

Because `mrs` is otherwise rare in user-space code, this is the fastest way to find every protected
function in a library.

---

### 14. Is a missing stack canary a vulnerability I should report?

No. It is a **missing mitigation**, and reporting it as a finding is one of the fastest ways to lose
a client's trust in a report.

A canary only ever matters when a linear stack overflow already exists *and* reaches the saved return
address. If no such bug is present, the canary would never have fired and its absence changed no
outcome. It becomes relevant as *impact context* on an overflow you have already demonstrated: "and
because the library is built without `-fstack-protector-strong`, this overflow yields control of the
return address rather than a controlled abort."

[15-Native-Code §5](../15-Native-Code/README.md) makes the same argument at more length.

---

### 15. The app checks for root but Frida's hook on `access()` never fires. What is happening?

It is very likely issuing the syscall directly, with no libc involved:

```text
    5404:  mov  w8, #172
    5408:  svc  #0
```

`svc #0` is the only way user space enters the kernel; the syscall number goes in `x8`. There is no
import to hook and no symbol to find.

Three responses, in increasing effort: `strace` the process, which observes at the syscall boundary
and sees everything; use Frida's Stalker to watch the instruction stream; or find and patch the `svc`
sites. They are greppable — `svc #0` is the bytes `01 00 00 d4` at a 4-byte-aligned offset, and the
preceding `mov w8, #N` tells you which syscall.

---

### 16. Why is `strings` finding nothing, when I know there is a key in there?

Because the constant is probably not stored as data. A 64-bit constant is built four instructions at
a time:

```text
    4940:  mov   x10, #21057
    4948:  movk  x10, #13901, lsl #16
    4950:  movk  x10, #11572, lsl #32
    495c:  movk  x10, #21321, lsl #48
```

That is `0x53492D34364D5241`, whose little-endian bytes spell `ARM64-IS`. It is in `.text`, split
across four instructions, and no byte-string search of `.rodata` will ever find it.

Reassemble it by hand: each `movk` gives you a 16-bit field and its shift. Write the fields out from
high to low, then read the bytes low to high because AArch64 is little-endian.
[README §3.10 pattern 24](README.md#310-the-pattern-catalogue) does this for a full 17-byte token.

---

### 17. Everything in a function is `eor` and `orr` and then `cmp #0`. What is it doing?

It is comparing two blocks of memory. XOR gives zero exactly when two values are equal, so XOR the
pieces, OR the results together, and test the total against zero: it is zero if and only if every
piece matched.

That is `memcmp` or `strcmp`, inlined and unrolled. It is also, incidentally, constant-time — the
work does not depend on *where* the difference is — which is why compilers sometimes accidentally fix
a timing bug that the source code has.

---

### 18. I found a function whose entire body is one `b` instruction. Is the binary corrupt?

No. That is a **tail call**. When the last thing a function does is call something else and return
its result, the compiler jumps rather than calls, and the callee returns directly to the original
caller. One instruction, no `ret`, and completely correct:

```text
0000000000005294 <pat_calls_import>:
    5294:  b  0x5530 <strlen@plt>
```

Practical consequence: hooking such a function with `Interceptor.attach` will not give you a sensible
`onLeave`, because it never returns.

---

### 19. What is `hint #34` and why is it at the start of so many functions?

`hint #34` is `bti c` — a **Branch Target Identification** landing pad. On an Armv8.5 CPU with BTI
enabled, an indirect branch (`br` or `blr`) that lands on anything other than a `bti` raises an
exception. The point is to remove mid-function gadgets from the reachable set for jump-oriented
programming.

On a CPU without BTI it is a 4-byte no-op, which is why the NDK can emit it unconditionally.

**The practical rule: never overwrite it.** If the first instruction of a function you want to patch
is `hint #34`, patch at `+4` instead — `arm64-patch.py --skip 1` does exactly that. Otherwise every
indirect call to that function faults on BTI hardware, and the crash will be nowhere near your patch.

---

### 20. My disassembly of a 32-bit library turns to garbage after the first instruction. Why?

You almost certainly started one byte too late, because the symbol table gave you an **odd** address.

On ARM32, bit 0 of a branch target selects the instruction set state: 1 means Thumb, 0 means ARM.
Since instructions are at least 2-byte aligned, that bit is free in any real code address, so the
linker stores Thumb function addresses with it set:

```text
# llvm-readelf --dyn-syms libpatterns32-thumb.so
    16: 00001cad    32 FUNC    GLOBAL DEFAULT    12 pat_boolean_check

# llvm-objdump -d libpatterns32-thumb.so
00001cac <pat_boolean_check>:
    1cac: d0 b5   push  {r4, r6, r7, lr}
```

`st_value` says `0x1cad`; the code starts at `0x1cac`. Clear the low bit to disassemble or to compute
a file offset. Keep it when calling through a function pointer, because `bx` needs it.

---

### 21. Can I use `arm64-patch.py` on a 32-bit library?

It will read the file, map addresses and list symbols (clearing Thumb bits and telling you it did).
It **refuses** to assemble patches, deliberately.

The reason is that Thumb is a variable-length encoding. Writing four bytes over what you assumed was
one 4-byte instruction may actually clobber two 2-byte instructions and half of a third, producing
code that disassembles as plausible nonsense — the worst possible failure, because it looks fine.

For a 32-bit target, assemble the replacement with the NDK's own assembler at the correct address,
check the resulting length, and only then write bytes. Or hook it at runtime instead, which is
usually the better answer.

---

### 22. Should I patch the file or patch memory with Frida?

Both are this chapter's material and the encodings are identical. Choose deliberately.

| | File patch | Memory patch (Frida) |
|---|---|---|
| Address arithmetic | Virtual → file offset | Module base + offset only |
| Survives a restart | Yes | No |
| Survives an integrity check over the file | **No** | **Yes** |
| Needs Frida running (itself detectable) | No | Yes |
| Needs the APK resigned to install | Usually yes | No |
| Good for | Long experiments, distributing a modified fixture | Quick iteration, hardened apps |

```javascript
// Frida REPL -- the memory version of the four-byte patch
var a = Module.findExportByName('liblicence.so', 'lc_is_licensed');
Memory.protect(a, 16, 'rwx');
a.writeByteArray([0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]);  // mov w0,#1 ; ret
```

---

### 23. I forced the check open and now the app produces garbage instead of the secret. Did the patch fail?

The patch worked. You have run into the difference between a check that **gates** a computation and a
check that **supplies input to** one.

In [`examples/licence-check.c`](examples/licence-check.c), `lc_decrypt_flag` verifies the token and
then XORs the ciphertext with **the token itself**. Force the gate open with the wrong token and the
function runs to completion and produces:

```text
lc_decrypt_flag    : WNF*<IY1'YLOQ U[Q
```

With the right token, the same patched library produces `ANDROID-ARM64-FLAG`.

This is what real cryptography looks like from the attacker's side, and it is the honest answer to
"why can't I just patch it". A boolean can be forced; a key cannot. When you write the finding, say
which one you found.

---

### 24. Is AArch64 easier or harder to reverse than x86?

Easier to *read*, for four reasons: fixed 4-byte instructions mean disassembly is unambiguous and
misalignment tricks do not work; the load/store discipline makes every memory access explicit; the
large register file means fewer stack spills to follow; and the encoding is regular enough that you
can decode instructions by hand when you have to.

Harder in two ways: listings are longer, because what x86 does in one instruction often takes three;
and compilers produce more aggressive branchless code (`cset`, `csel`, conditional selects), which
means the control flow you expect from the source is often not there at all.

Net: if you can read one, you can learn the other in a weekend. The concepts transfer; the mnemonics
and the calling convention do not.

---

### 25. Do I need a device to do this chapter?

For three of the four labs, no. Labs 01, 02 and 04 need only the NDK and Python 3, and lab 04 needs
nothing but Python 3.

You need a device or emulator for lab 03, and for the runtime confirmation step of lab 02 — which
is optional but is the step that teaches the most, because it is where you discover whether your
patch changed *behaviour* or only *bytes*.

If your device refuses to execute binaries from `/data/local/tmp` (some OEM builds do, failing with
"No such device or address" or "Interrupted system call"), invoke the linker explicitly:

```bash
adb shell /system/bin/linker64 /data/local/tmp/licence-runner /data/local/tmp/liblicence.so
```

---

### 26. My disassembly does not match the chapter's addresses. Is one of us wrong?

Neither. Register allocation, instruction scheduling and inlining decisions change between clang
releases, and addresses shift with any change in code size. This chapter states its toolchain
explicitly — **NDK 25.2.9519653, clang 14.0.7, API 21** — precisely so you can tell.

Compare **shapes**, not addresses. If your `lc_is_licensed` is `cmp` / `cset` / `ret` at a different
address, everything in the chapter still applies. If it is a completely different sequence, check
your optimisation level first: `-O0` and `-O2` produce dramatically different code from identical
source, and [README §3.5](README.md#35-prologues-epilogues-and-the-frame) shows both.

---

### 27. `find-check-shapes.py` found nothing in a library I know has a licence check. Is it broken?

Probably not. Three ordinary explanations, in order of likelihood:

1. **The check is inlined** into its caller, so there is no function to find. This is the script's
   documented blind spot and it says so in its own header.
2. **The library is stripped of `.symtab`**, so the script sees only `.dynsym` exports and every
   internal helper is invisible. Use a decompiler's function detection instead —
   [57-Ghidra §4](../57-Ghidra/README.md).
3. **The library is packed**, and nothing on disk is real code. Dump it from memory
   ([README §7](README.md#7-dynamic-analysis)) and analyse the dump.

Lower `--min-score` before concluding anything, and remember the converse too: a high score is a
*reading list entry*, not a finding. A boolean-returning getter has exactly the same shape as a
licence check.

---

### 28. What should I read next?

- [57-Ghidra](../57-Ghidra/README.md) — the decompiler, which is the faster tool for anything longer
  than about fifty instructions. This chapter is what you fall back on when it fails.
- [53-Frida](../53-Frida/README.md) — runtime instrumentation, and Stalker, which rewrites the
  instruction stream you have just learned to read.
- [16-JNI](../16-JNI/README.md) — the bridge whose far side you can now read.
- [37-RootDetection](../37-RootDetection/README.md) — a whole catalogue of checks with exactly the
  shapes in §3.10.
- [40-Obfuscation](../40-Obfuscation/README.md) — what happens to those shapes when someone is
  actively trying to stop you.
