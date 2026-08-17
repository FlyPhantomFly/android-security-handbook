# 59 — radare2 FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

> Every radare2 command here is **📘 Unverified** — radare2 was not installed on the machine where
> this chapter was written. Facts about binaries, byte encodings and device behaviour are
> **✅ Measured**. See [README.md](README.md) for the full statement.

---

**1. Why does radare2 look like someone leaned on the keyboard?**

Because it is compressed, not arbitrary. Commands are a root verb, some narrowing letters, and a
suffix: `afl` is `a` (analyse) + `f` (function) + `l` (list). Once you know that, `afi`, `afn`, `afv`
and `aflj` are things you can *derive* rather than look up.

The reason it looks hostile is that everybody's first act is typing `?`, which prints the whole root
level at once. That is not a list to read; it is a map of trees to descend. Append `?` to any prefix
to go one level down: `a?`, then `af?`, then `afl?`.

[Lab 01](labs/lab-01-the-command-language.md) is one focused hour on exactly this, and it is the
highest-return hour in the chapter.

---

**2. Do I have to memorise hundreds of commands?**

No, and anyone who tells you otherwise has not been shown `?`. You memorise about a dozen root verbs
and four operators. Everything else you navigate to.

The practical test: without looking anything up, can you find the command that lists a function's
local variables? Type `a?`, see `af` for functions, type `af?`, see `afv`. That is the workflow, and
it never stops working.

---

**3. radare2 or Ghidra?**

Wrong question. The right one is **"is my question about *one* function or about *many* files?"**

Many files, or no display available, or the binary is on a phone: radare2. One function that you need
to read carefully with a decompiler: [Ghidra](../57-Ghidra/README.md). It is entirely normal to
triage in radare2, do the sustained work in Ghidra, and open [IDA](../58-IDA/README.md) for the one
function that defeats both.

[57-Ghidra](../57-Ghidra/README.md) §3.16 explicitly routes two workloads here — batch triage of
hundreds of files, and "quick look, over SSH, no JVM". Those are radare2's home ground.

---

**4. Does radare2 have a decompiler?**

Not really, and the honest answer matters.

Base radare2 ships `pdc`, a "pseudo-decompiler" that prettifies disassembly. It does no meaningful
type inference or control-flow structuring. Calling it a decompiler sets you up for disappointment.

For real decompiled C, install the `r2ghidra` plugin (`r2pm -ci r2ghidra`) and use `pdg`. That embeds
**Ghidra's actual decompiler engine** — the same one described in
[57-Ghidra](../57-Ghidra/README.md) §3.2 — inside radare2, with no JVM. rizin's equivalent is
`rz-ghidra`, and Cutter bundles it.

So: radare2 plus `r2ghidra` gives you Ghidra's output with radare2's driving. That is a genuinely
good combination and it is how a lot of people work.

---

**5. What is the difference between radare2, rizin and Cutter?**

rizin is a **fork** of radare2 from late 2020, with different governance and more emphasis on API
stability and documentation. Cutter is a Qt GUI that followed rizin at the fork. `iaito` is the GUI
that stayed with radare2.

The command grammar is the same in both, which is what matters — everything in this chapter's §3.2
transfers. What differs is the *tool* names: `rabin2` becomes `rz-bin`, `radiff2` becomes `rz-diff`,
`r2pipe` becomes `rzpipe`. A script that shells out to `rabin2` needs one line changed.

Pick one, learn the grammar, and stop worrying about it.

---

**6. What does `aaa` actually do, and why do people say it is slow?**

`aaa` is *analysis*: deciding which bytes are instructions, where functions begin and end, building
basic blocks, computing every cross-reference, and auto-naming. None of that is recorded in a
stripped ELF — all of it is inferred.

It is slow because the work is proportional to the amount of code.

> **✅ Measured** — AArch64 `libsqlite.so` from an API 35 device carries **1,657,588 bytes of code —
> 414,397 instructions — behind 364 exported names.** That is roughly one name per 4,554 bytes of
> machine code. Analysis is not reading names; it is inventing 400,000 instructions' worth of
> structure from a few hundred starting points.

The fix is usually not to make `aaa` faster. It is to notice you did not need it.

---

**7. When should I *not* run analysis?**

Whenever your question is about structure rather than code. Imports, exports, strings, sections,
linked libraries and hardening flags all come from parsing the ELF header and two or three tables.
That cost is bounded by symbol-table size, not code size.

> **✅ Measured** — x86_64 `libhwui.so` is 13,005,808 bytes with **6,336,785 bytes of code** and just
> **1,080 dynamic symbols**. Structural parsing reads the 1,080-entry table and never touches the
> 6.3 MB. Those two numbers differ by orders of magnitude and that gap is the whole argument.

Concretely: "does this library import `ptrace`?" is a symbol-table lookup. Running `aaa` to answer it
is buying a call graph to read one row of a table.

---

**8. `axt` returns nothing. Is there really nothing there?**

Almost certainly not. Two causes:

**You did not run analysis.** Cross-references are computed by `aaa` (or `aar`). On a freshly opened
binary `axt` returns nothing **silently**, which looks identical to a genuine negative. Run `aa`
first and confirm with `afl~?`, which prints the function count.

**The reference is indirect.** `axt` can only see references it computed statically. A call through a
register has no static target.

> **✅ Measured** — every JNI call in this chapter's sample target is exactly this. From
> `llvm-objdump -d`:
> ```
>     1a40: 08 5d 43 f9   ldr   x8, [x8, #1720]
>     1a44: 00 01 3f d6   blr   x8
> ```
> No cross-reference analysis will report that this calls `RegisterNatives`. The instruction says
> `blr x8` and nothing more.

**The rule: a static cross-reference graph is a lower bound, never an inventory.** Anything reached
through a function pointer, vtable, jump table, `dlsym` or JNI dispatch is missing from it.

---

**9. What is `sym.imp.access`? Why not just `access`?**

`sym.imp.access` is the **PLT stub** inside the library you are looking at — a small piece of code
that jumps through the Global Offset Table to wherever the dynamic linker put the real `access` in
libc. It is not libc's `access`; libc is a different file.

That distinction is what makes `axt sym.imp.access` so useful: every call to `access` within this
library funnels through that one stub, so cross-references to the stub are a *complete* list of call
sites in this binary. That is why
[39-EmulatorDetection](../39-EmulatorDetection/README.md) §8.4 and
[67-BypassingProtections](../67-BypassingProtections/README.md) §8.4 both reach for it.

---

**10. Can radare2 open an APK or a DEX file?**

DEX yes, APK no.

An APK is a zip; unzip it first. radare2 opens the `.dex` inside, and `pd` will disassemble **Dalvik
bytecode** — `invoke-virtual`, `const-string` and so on — because there is a Dalvik architecture
plugin. `rabin2 -c` lists classes, `rabin2 -z` dumps the string pool.

What you will *not* get is Java. There is no Java decompiler. Also: multi-DEX means one session per
`classes*.dex` with no shared cross-reference graph, and nothing links a `native` method declaration
in DEX to its implementation in a `.so`.

**Use [JADX](../56-JADX/README.md) for DEX.** radare2's DEX support earns its place in two narrow
cases: batch metadata extraction across thousands of APKs, and deliberately malformed DEX that makes
JADX bail out — radare2 is not trying to reconstruct Java, only to decode bytes, so it often still
works. In that second case it may be the only tool that helps.

---

**11. I patched a function and nothing changed. What did I do wrong?**

Probably nothing wrong with the patch. This chapter measured it happening with a correct patch.

> **✅ Measured** — `lt_verify_license` was patched to `mov w0,#1; ret`, the bytes were verified in
> place with `llvm-objdump`, and the program's output on a real device was **identical** to the
> unpatched binary. The cause was in the caller:
> ```
>     48b0: bl    0x481c <lt_probe_paths>
>     48b4: cbz   w0, 0x48c0        ; if the probe fired, return 0 immediately
> ```
> An upstream root probe short-circuited the gate, so the patched function was never called. The
> probe fired because the stock Google AVD **ships `/system/xbin/su`**.

There are at least four mechanisms for this symptom:

1. The check was **inlined**, so the standalone copy is dead — measured in
   [18-ARM](../18-ARM/README.md) §5.4.
2. An **earlier guard short-circuits** it — measured here.
3. There are **multiple copies** of the check.
4. The result is **re-verified elsewhere**, possibly server-side, in which case no client patch works.

The diagnosis for the first three is identical and takes one command: **`axt` the function and read
every caller.** If you cannot say what happens to the return value, you are guessing.

---

**12. `r2 -w` destroyed my file. Where is the undo?**

There isn't one, and this catches everybody once. `wa` writes through to disk the moment you press
Enter. No save step, no confirmation, no backup.

Two habits fix it permanently:

```bash
cp target.so target.so.patched      # always work on a copy
```

```
# 📘 Unverified
[0x0]> e io.cache=1                 # stage writes in memory
[0x0]> wa mov w0, 1; ret
[0x0]> pdf                          # inspect before committing
[0x0]> wci                          # commit
[0x0]> wc-                          # or discard
```

`io.cache` is the undo the tool otherwise lacks. Turn it on before every patching session.

---

**13. My patch went to the wrong place in the file.**

You used a virtual address as a file offset. They are not the same.

> **✅ Measured** — in this chapter's sample executable, `llvm-readelf -S` reports `.text` at virtual
> address `0x4794` and file offset `0x794`. The delta is `0x4000`. A function at virtual address
> `0x4854` lives at file offset `0x854`. Writing at `0x4854` in a hex editor would land past the end
> of the file entirely.

The rule, computed **per section** because deltas differ:

```
file_offset = vaddr - (section_vaddr - section_file_offset)
```

`iS` prints both columns, which is exactly why doing this inside radare2 is safer than doing it by
hand.

---

**14. Why do I keep getting `fcn.00001234` instead of real names?**

The binary is stripped, which is the normal state of shipped Android native code. `fcn.` means
"radare2 found a function here and nothing told it the name". `sym.` means a symbol supplied one.

> **✅ Measured** — of eleven real Android system libraries pulled from an API 35 device, **ten had
> zero `.symtab` sections**. The exception was AArch64 `libc.so`, which kept a full symbol table of
> **2,667** entries.

That exception is worth a habit: `llvm-nm <file> | wc -l` costs nothing and is either zero or a gift.
When a platform library kept its symbols, stop reversing and start reading names.

For the stripped majority, work from exports, imports and strings. `afl~fcn.~?` against `afl~sym.~?`
gives you the ratio as two numbers.

---

**15. I XOR-encrypted my strings but `strings` still finds them. How?**

This is the most useful finding in the chapter, and it is almost universally believed to be
impossible.

> **✅ Measured** — the same source file, two builds with NDK 25.2.9519653:
>
> | Build | `strings \| grep xbin` |
> |---|---|
> | `-O2` | **`/system/xbin/su`** |
> | `-O0` | *(nothing)* |
>
> At `-O2`, clang evaluated the entire XOR decode loop **at compile time**, because both the
> ciphertext and the key were compile-time constants. The loop does not exist in the shipped binary.
> What remains is a single 16-byte NEON load of the finished plaintext:
> ```
>     1924: 00 a5 c1 3d   ldr   q0, [x8, #1680]     ; 1680 = 0x690 = .rodata
> ```

**Optimisation deleted the protection.** The developer who tests at `-O0`, sees nothing in `strings`,
and ships at `-O2` has shipped the plaintext.

The fix is one word — make the key opaque to the optimiser:

```c
static volatile unsigned char g_xor_key = 0xA7;
```

> **✅ Measured** — with `volatile`, the `-O2` build hides the string and the decode loop survives
> (vectorised, but real). Same reasoning as
> [19-Memory](../19-Memory/README.md)'s `volatile` scrubbing loop: a standard defensive idiom that
> the optimiser is otherwise entitled to delete.

Note what this does **not** buy: the string is absent from the file and present in memory at run
time. It is a rate limiter, not a boundary.

---

**16. Can I really run radare2 on the phone?**

Yes, and it is the one thing nothing else in this repository's static toolchain does.

```bash
# on-device, in Termux -- no root needed
pkg install radare2
```

Or push a static AArch64 build to `/data/local/tmp` and `chmod 755` it.

Two traps this repository has measured:

- Some vendor builds **block `execve` on `/data/local/tmp`**. Workaround:
  `adb shell /system/bin/linker64 /data/local/tmp/r2 -v`.
- On **16 KiB-page devices** — including current AVDs — binaries not linked with
  `-Wl,-z,max-page-size=16384` segfault at load with no diagnostic pointing at page size. A
  three-line `int main(void){return 42;}` exits **139**.

It is worth the trouble when the file exists only on the device: a packer's decrypted payload, a
dropper's second stage, a library whose integrity check refuses to run if the path differs.

---

**17. What is r2frida and why would I want it?**

An IO plugin that makes a live [Frida](../53-Frida/README.md) session look like a file to radare2.
Once open, *every* radare2 command operates on process memory: `pd` disassembles live code, `px`
dumps live memory, `w` writes to the process.

```bash
r2pm -ci r2frida
r2 'frida://spawn/usb//com.example.app'
```

It is the answer to "the file on disk is not the code that runs" — packers, self-modifying code and
runtime string decryption are all transparent to it, because you are reading memory *after* the
runtime did the work. `:dxc` even lets you call a function in the target with arguments you choose,
which turns a reverse-engineering question into an experiment.

Cost: it inherits every Frida detection surface. See
[67-BypassingProtections](../67-BypassingProtections/README.md).

---

**18. `pip install r2pipe` worked but my script fails at `r2pipe.open()`.**

`r2pipe` is a **client**. It works by launching `r2` as a subprocess and talking over pipes. Installing
the Python module does not install radare2, so the import succeeds and the open fails.

Install radare2 itself and make sure `r2` is on `PATH`. Both shipped scripts in this chapter check
for both up front and exit non-zero with an explanation, precisely because this failure is confusing.

---

**19. My batch script reported no findings across 400 libraries. Is that good?**

Verify that it *ran* before you believe it. A scanner that prints an empty report when its tools are
missing produces a false negative indistinguishable from a clean result — and in a security context
that is worse than no scanner, because it manufactures false confidence.

Both scripts here fail loudly and exit non-zero.
[`scripts/r2-triage.py`](scripts/r2-triage.py) additionally records per-file parse failures in an
`error` column rather than silently dropping the row, and treats "every single file errored" as a
tooling failure rather than a clean corpus.

---

**20. How do I find native methods when the library only exports `JNI_OnLoad`?**

The mapping is built at run time by `RegisterNatives`, so no symbol names the implementations.

**Statically**, four threads to pull:

```
# 📘 Unverified
[0x0]> iz~^\(              # JNI signatures always start with "("
[0x0]> iz                  # the method name is usually the adjacent string
[0x0]> iS~data.rel.ro      # the JNINativeMethod table usually lives here
[0x0]> aa; pdf @ sym.JNI_OnLoad
```

> **✅ Measured** — in this chapter's sample the whole of `.rodata` is fifty bytes and contains, in
> order: `/system/xbin/su`, `com/pentest/ch59/Native`, `(Ljava/lang/String;)I`, `dynGate`,
> `gate=%d`. Class, signature and method name sit adjacent because the compiler emitted them in
> reference order. The C function implementing it is `static` and appears in **no** symbol table.

**Dynamically**, and far more cheaply: hook `RegisterNatives` with Frida and print what it is handed.
See [README.md §7.2](README.md#72-recovering-dynamic-jni-registrations-at-runtime). You must
**spawn**, not attach — registration happens at `System.loadLibrary` time, so by the time you attach
it has already happened. That is the single most common reason the script "does not work".

---

**21. What does `ldr x8, [x8, #1720]` mean and why do you keep pointing at it?**

`1720` is `0x6b8`, and in the `JNIEnv` function table that offset is `RegisterNatives`.

The JNI specification fixes the order of the ~230 entries in `JNINativeInterface`, and every entry is
one pointer. So on a 64-bit target **an offset is a function name**, and the pattern
`ldr x8,[x0]` · `ldr x8,[x8,#N]` · `blr x8` is always a JNI call with `N` identifying which one.

> **✅ Measured** — in the sample target, offset `48` (`0x30`) is `FindClass` and offset `1720`
> (`0x6b8`) is `RegisterNatives`, independently confirming the table in
> [57-Ghidra](../57-Ghidra/README.md) §3.8.

This is the most transferable skill in native Android RE and it needs no tool at all — just
`jni.h`. See [16-JNI](../16-JNI/README.md).

---

**22. Why did my Frida hook attach to garbage after radare2 told me the address?**

You pasted a static address into `Interceptor.attach`. radare2 reports offsets *relative to the
library*; the dynamic linker maps the library at a different base in every process, and ASLR changes
it every run.

```javascript
// Frida REPL -- always go through the module base
const m = Process.getModuleByName("libfoo.so");
Interceptor.attach(m.base.add(0x190c), { /* ... */ });
```

The dangerous case is not a crash. It is attaching to valid-but-unrelated memory, which produces
confident and completely wrong output.

---

**23. Is a graph view really useful, or is it a gimmick?**

Useful, for one specific reason: **shape recognition**, not reading.

A normal function is a tree flowing downwards. A function processed by a control-flow-flattening
obfuscator is a wheel — one central dispatcher block with dozens of blocks radiating out and
returning to it. You can identify obfuscation from across the room without reading an instruction.

`VV` on a function, then `x` to jump to a caller, then `VV` again is how you map an unfamiliar
library in ten minutes. See [40-Obfuscation](../40-Obfuscation/README.md).

---

**24. `/x 01000193` finds nothing but I know the constant is there.**

Endianness. AArch64 is little-endian, so the 32-bit value `0x01000193` sits in the file as the bytes
`93 01 00 01`. Searching for the digits in the order you wrote them finds nothing.

Use `/v4 0x01000193`, which searches for a 4-byte *value* and handles endianness for you. This
catches everybody at least once.

---

**25. Is radare2 safe to run on malware?**

Safer than most alternatives, with caveats.

`rabin2` and a plain `r2` session **parse** a file; they do not execute it. There is no equivalent of
"open this document and it runs a macro". radare2 also opens files **read-only by default**, so
running it does not alter evidence — relevant for forensics.

The caveats: a maliciously malformed file is an attack surface for any parser, so run it in a VM or
container if the sample is untrusted. `r2 -n` skips `r_bin` entirely and gives you a raw byte view
when structure-aware parsing crashes, which is often the state anti-analysis tricks leave a tool in.
And obviously the debugger and r2frida *do* execute the target — that is their job.

Hash before you touch anything. `#sha256` inside a session hashes the current block.

---

**26. How do I find what changed between two versions of an app's library?**

```bash
radiff2 -C old/lib/arm64-v8a/libfoo.so new/lib/arm64-v8a/libfoo.so
```

`-C` prints matched functions with a similarity percentage; it matches across versions even when
addresses moved. Sort ascending: 100% is unchanged, 0% is new or removed, and the handful in between
are what actually changed.

On a security release, those functions *are* the patch, and the patch describes the bug. See
[70-VulnerabilityResearch](../70-VulnerabilityResearch/README.md).

---

**27. Everyone says radare2 is fast. Is it?**

For the right question, decisively. For the wrong question, no faster than anything else.

Being precise about which: radare2 is fast at **structural parsing** and at **starting up**. It is
not magic at code analysis — discovering functions in 400,000 instructions is the same hard problem
for every tool.

> **✅ Measured (a floor, not radare2)** — this chapter could not time `aaa` because radare2 was not
> installed. It measured the cheapest possible subset — decoding every instruction once, with
> `llvm-objdump` — at roughly **210,000–281,000 instructions per second**, linear in `.text` size
> and essentially independent of file size. Anything that also discovers functions and computes
> cross-references does strictly more work per instruction.

The honest claim is not "radare2 analyses faster". It is "radare2 lets you *not analyse*", plus a
process spawn instead of a JVM start-up. Across 480 files that difference is enormous; on one file
it is a rounding error.

---

**28. What can radare2 — or any static tool — never tell me?**

Five things, and knowing them is what stops you over-claiming in a report.

- **Which code actually runs.** Reachability through function pointers, vtables, `dlsym` and JNI
  dispatch is not decidable in practice. A function can exist and never execute.
- **Runtime values.** Anything derived from server responses, device state, time or user input is not
  in the binary. A key derived at run time is not there at all.
- **Whether a check matters.** This chapter measured a patched function that was provably correct and
  completely irrelevant.
- **Whether a finding is exploitable.**
  [70-VulnerabilityResearch](../70-VulnerabilityResearch/README.md) measured one heap overflow
  presenting three different ways, two of them completely silent.
- **What the server does**, which is usually the fact that determines a client-side control's real
  severity.

A static finding is a hypothesis with an address attached. Report it as "reachable from
`Java_com_x_Y_z`, not confirmed at runtime" and you are accurate and useful. Report it as "the app is
vulnerable" and you will eventually be wrong in front of a client.

---

**29. The chapter says radare2 was not installed. Should I trust it?**

Trust it exactly as far as it claims, which is the point of the marking.

Every radare2 **command** is marked **📘 Unverified**: transcribed from the tool's documentation and
source, believed correct, not executed here. Every claim about a **binary** — sizes, sections, symbol
counts, disassembly listings, byte encodings, timings, and the behaviour of patched programs on a
real Android device — is marked **✅ Measured** and names the tool and device that produced it.

That split is deliberate. The hard part of this chapter is not which letters to type; it is what is
actually inside an Android native library and what question to ask of it. Those facts were measured
with the NDK's LLVM toolchain and an attached API 35 emulator.

Fabricating a plausible `r2` session transcript would have been easy and would have been the worst
possible failure for a tool chapter. If a command here behaves differently from what is written,
**the tool is right** — fix the chapter.

---

**30. What is the one thing to take away?**

Two, and they are the measured ones.

**Before patching a function, run `axt` on it and read every caller.** If you cannot say what happens
to the return value, you are guessing. A correct, verified patch on the wrong function is
indistinguishable from a patch that failed.

**Run `strings` on the release artefact, not the debug build.** Compile-time obfuscation is a comment
to the optimiser, and at `-O2` it may simply be deleted.
