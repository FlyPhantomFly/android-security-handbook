# 58 — IDA · FAQ

Real questions, including the ones people are embarrassed to ask. Answered directly.

> Answers marked **[measured]** rest on a measurement taken while writing this chapter. Answers marked
> **[docs]** come from Hex-Rays' published documentation and have **not** been exercised — IDA is not
> installed on the machine where this chapter was written, and the README's opening callout says so in
> full.

---

### 1. Is IDA worth the money?

For most Android mobile-application testers, **no**. Most of your hours go on the Java layer,
manifests, network and storage, and none of that needs a native disassembler. When you do open a
`.so`, [Ghidra](../57-Ghidra/README.md) has a local ARM-64 decompiler, full scripting and an Apache 2.0
licence.

It becomes worth it when you do native reverse engineering **weekly**, on C++-heavy targets, under an
NDA that requires local decompilation, or when you do vulnerability research and patch diffing. The
chapter's §3.12 has the decision table.

The honest test: count the engagements in the last year that were actually blocked on something only
IDA can do. If that number is zero, the licence is buying comfort. Comfort is a legitimate purchase —
just not out of the wrong budget line.

---

### 2. Can I just use IDA Free?

**Not for Android.** IDA Free supports x86-32 and x86-64 only — no ARM-64 disassembler at all — and it
has no IDAPython, only IDC. Android native code is overwhelmingly `arm64-v8a`. **[docs]**

Every tutorial telling you to "download IDA Free and follow along" for Android work is either old or
wrong. Use Ghidra.

---

### 3. What is the difference between IDA Home and IDA Pro, in one sentence I can take to my manager?

IDA Home is a hobbyist licence whose decompiler **runs in Hex-Rays' cloud**; IDA Pro's Expert and
Ultimate plans run it **locally**, and only the local ones are safe under a typical NDA. **[docs]**

The trap in the middle is **IDA Pro Essential**, which is a Pro licence but whose two decompilers are
also cloud-hosted. Read the plan sheet carefully.

---

### 4. Is the cloud decompiler actually a problem? Hex-Rays says they do not keep anything.

They say they process no personal data except your IP address and persist nothing after the
decompilation, and there is no reason to doubt it. **[docs]**

**That is not the question your NDA asks.** A standard mobile-application NDA prohibits *transmitting*
the binary, or any part of it, to a third party. A cloud decompiler transmits function bytes to a
third party by construction. Whether the third party keeps them is a separate clause that usually is
not there.

So the answer is: it is not a security problem, it is a **contract** problem, and it is one you
discover at the wrong moment if you do not check before purchase.

---

### 5. What does IDA actually do that Ghidra does not?

Four things, honestly:

1. **Microcode at eight maturity levels.** When a decompilation is wrong you can watch the moment it
   goes wrong, which tells you whether the problem is decoding, call-argument detection, or a global
   optimisation. Ghidra exposes no equivalent progression. **[docs]**
2. **FLIRT's ecosystem.** Ghidra has Function ID, which is the same idea, but the signature databases
   and the tooling around them are far more mature on the IDA side.
3. **The debugger.** Ghidra's works; IDA's is less fragile and renders live memory through your
   recovered types.
4. **C++.** Virtual call resolution and class reconstruction are stronger. Chapter 57 says so about
   itself, in its §3.16.

And two things Ghidra does that IDA does not: it is free, and it decompiles on your own machine at
every price point.

---

### 6. My decompiled output is full of `_DWORD` and `__int64` casts. Is the binary obfuscated?

Almost certainly not. Those are the decompiler telling you it could not determine a type — the exact
counterpart of Ghidra's `undefined8`. They are a statement about the *state of your project*, not a
property of the binary.

The fix is to supply the types: set the function's prototype, retype the parameters, define the
structure. Each fact you supply propagates. The chapter's §3.6 and lab 02 are entirely about this.

---

### 7. I patched the check function, verified it returns 1, and nothing changed. What went wrong?

The compiler inlined it. At `-O2` a small predicate is spliced into every caller and the standalone
copy is called by nothing.

**[measured]** In this chapter's fixture, `session_check_magic` is exported, correct, and has
**zero** call sites. Chapter 18 §5.4 measured the same failure on a different fixture and calls it the
most useful teaching artefact in that chapter; chapter 65 hit it from the hooking side; chapter 54
found objection failing on it.

**Check cross-references before you patch.** One keystroke (`X`) in IDA, one grep otherwise — and
write the grep as `bl.*<name(@plt)?>`, because the bare form produces a false negative on PLT-routed
calls.

---

### 8. I found a 32-bit constant in the disassembly but searching the binary for it finds nothing.

That is the correct result and it involves no obfuscation.

AArch64 cannot encode an arbitrary 32-bit immediate in one instruction, so the compiler builds the
value in two: `mov w9, #0x534E` then `movk w9, #0x5345, lsl #16`. **[measured]** The complete
constant `0x5345534E` exists only in a register, only at run time, and its four bytes are nowhere in
the file.

Search for the *shape* — a `mov` immediately followed by a `movk` with `lsl #16` on the same register
— and reassemble the halves yourself.

---

### 9. A table of function pointers reads as all zeroes in the hex dump. Is it filled in at run time?

Yes, by the loader, and you can read the values right now.

An `ET_DYN` object does not know where it will be loaded, so it cannot store absolute addresses. It
stores **relocations** instead: `R_AARCH64_RELATIVE` entries whose *addend* is the value the loader
will write. **[measured]** The fixture's three-entry table is 24 zero bytes on disk and three
relocations in `.rela.dyn`.

```bash
llvm-readelf -r lib.so | grep -i relative
```

Check whether your tool applies relocations before concluding a table is empty. IDA and Ghidra do;
`xxd` does not.

---

### 10. Should I build FLIRT signatures from the target I am analysing?

No — and this is the most common misunderstanding of the mechanism.

Signatures flow **from a library you have symbols for, to a target you do not.** A stripped binary has
no `STT_FUNC` symbols, so there are no names to associate with the patterns. It cannot be a source; it
is the destination.

Build from: the NDK sysroot's static libraries, a vendor SDK you were given as a `.a` or an unstripped
`.so`, or an open-source library built at the version the target ships.

---

### 11. Which functions make good FLIRT signatures?

Long ones, with few relocations in their first 32 bytes, and with plenty of non-variant bytes after
the window for the CRC to cover.

**[measured]** — and the result is counter-intuitive. On one static archive:

| Function | Informative bytes of 32 |
|---|---:|
| table-driven CRC-32 | **12** |
| table-free FNV-1a | **32** |

The CRC-32 — the function everyone thinks is easy to identify because of its distinctive constant —
produced the **weakest** signature, because its prologue takes the addresses of two globals and each
`adrp`/`add` pair is a relocation. The FNV-1a builds its constants from immediates, which are not
relocations, so nothing is masked.

---

### 12. Why is FLIRT worse on ARM than on x86?

Because FLIRT masks at **byte** granularity, and AArch64 packs the relocated field *inside* a
four-byte instruction word alongside the opcode bits. Masking a relocation therefore destroys the
opcode too.

On x86 a relocated absolute address is usually a separate 4-byte operand; mask it and the opcode
survives and still discriminates.

This is a property of the format meeting the architecture, not a criticism of anyone's database — and
it is why the "referenced names" (`^OFF name`) field matters more on ARM: it recovers discriminating
power that masking threw away.

---

### 13. How do I get `JNIEnv` types into IDA?

Parse the NDK's `jni.h` with *File → Load file → Parse C header file…* (`Ctrl+F9`). **[docs]**

It will probably fail on the first attempt, in IDA and in Ghidra alike, because the header pulls in
platform definitions the parser does not have. Two fixes: a small wrapper header that defines the
macros the parser complains about and then `#include`s `jni.h`; or a trimmed header containing just
`JNINativeInterface`, `_JNIEnv`, `JNINativeMethod` and the `j*` typedefs.

**Check afterwards that the type you wanted actually exists.** The parse can partially succeed, and a
type library missing exactly the struct you needed is easy not to notice.

Chapter 57 §3.8 explains *why* this is the highest-value action in Android native RE and this chapter
does not restate the argument. Lab 03 §5 gives a minimal header to start from.

---

### 14. My headless script reports the library has eleven functions. It plainly has more.

You forgot `ida_auto.auto_wait()`.

`-S` runs your script when the initial autoanalysis is *scheduled*, not when it has finished. Without
the wait, your script enumerates functions before they exist. The results are plausible, wrong, and
perfectly reproducible, which is the worst combination.

Put `ida_auto.auto_wait()` at the top of every headless script.

---

### 15. I found a script online and it fails with `ImportError: No module named ida_struct`.

The script predates IDA 9.0. **[docs]** `ida_struct` and `ida_enum` were **removed** in 9.0, along
with `struct.hpp` and `enum.hpp`; the Structures and Enums windows became **Local Types** and the
functionality moved to `typeinf.hpp` / `ida_typeinf`.

`idaapi.get_inf_structure()` was removed in the same release; use the individual `inf_get_*()`
accessors.

Hex-Rays publishes a porting guide. The first removal can usually be shimmed; the second generally
means a rewrite of any structure-creating code.

---

### 16. Can I run Frida and IDA's debugger on the same process?

No. `ptrace` permits **one tracer per process**. Whichever attaches second fails, usually with an
error that does not explain itself.

Detach one first. In practice the split that works is: IDA for static understanding and annotation,
Frida for runtime — which is also chapter 57's recommendation for Ghidra, and it does not change here.

---

### 17. Every guide says to set `/proc/sys/kernel/yama/ptrace_scope` before debugging Android. It does not exist.

**[measured]** On an `sdk_gphone16k_x86_64` AVD running Android 15 / API 35, that file is **absent**.
`ptrace_scope` is a control exposed by the Yama LSM, and this Android image does not expose it.

A large fraction of published Android debugging advice tells you to write `0` to it. On such a device
there is nothing to write, and if your attach is failing, `ptrace_scope` is not why. Check first:

```bash
adb shell 'cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "(absent)"'
```

The chapter's preflight script does this check and four others, and names whichever one failed.

---

### 18. Should I run `setenforce 0` to get the debugger working?

No, if the device is one whose behaviour you are assessing. You would then be measuring a device that
no longer resembles the one your finding is about, and any conclusion about access control becomes
worthless. Chapter 22 owns the reasoning.

**[measured]** SELinux was `Enforcing` on the AVD used here and remote debugging's preconditions were
otherwise satisfied — a server launched from the `su` domain generally has the ptrace permissions it
needs. If an attach is silently refused, find the AVC:

```bash
adb shell 'su 0 dmesg -T' | grep -i avc | tail
```

If you genuinely need permissive, use a dedicated test device and say so in the methodology.

---

### 19. `su -c id` says the device is not rooted, but I am sure it is.

**[measured]** On Android emulators the form is `su 0 <cmd>`, not `su -c <cmd>`. AOSP's `su` rejects
the `-c` form with `su: invalid uid/gid '-c'`, which reads exactly like "not rooted" — while
`su 0 id` on the same device returns `uid=0(root) … context=u:r:su:s0` seconds later. Chapter 68
nearly recorded the API 35 AVD as unrooted on that basis, and chapters 63 and 64 hit it
independently. Magisk's `su` on a physical device accepts `-c`, so neither form is universally
correct.

```bash
adb shell 'su 0 id'      # emulators
adb shell 'su -c id'     # Magisk on a physical device
```

Try both before concluding anything.

---

### 20. I am on Windows with Git Bash and `adb push` says my device path does not exist.

Git Bash rewrites arguments that look like Unix paths into Windows paths before `adb` sees them, so
`/system/lib64/libfoo.so` becomes `C:/Program Files/Git/system/lib64/libfoo.so`.

`MSYS_NO_PATHCONV=1` fixes the device side — **and breaks the host side**, because `adb.exe` wants a
Windows path for local files. The working recipe:

```bash
W=$(cygpath -m /tmp/out)
MSYS_NO_PATHCONV=1 adb pull /system/lib64/libfoo.so "$W/libfoo.so"
```

Chapter 68 documented this. It cost time here too, twice, in the same session.

---

### 21. Is it safe to send someone my `.idb` so they can see what I mean?

**No, unless you are also willing to send them the binary** — because you are.

An `.i64` contains a copy of the analysed program's loaded segments. It is self-sufficient, which is
why it opens cleanly on someone else's machine without the original. On a client engagement that makes
"here are my notes" a redistribution of the client's software.

Export what you actually want to share: the pseudocode as text, the listing of one function, the
recovered structure as C. And add `*.i64 *.idb *.id0 *.id1 *.nam *.til` to your `.gitignore`.

---

### 22. IDA crashed and now there are `.id0` and `.id1` files next to my library. Is the database corrupt?

Probably not. IDA works on an *unpacked* database while it is open and packs it into the single `.i64`
on close. Those loose files are the unpacked form; a crash leaves them behind and IDA will offer to
recover from them next time you open the file.

---

### 23. What is Lumina, and should I turn it on?

Lumina is a Hex-Rays service that stores function metadata — names, prototypes, comments — keyed by a
function hash. Push what you have named, pull what somebody else named. **[docs]**

Decide per **engagement**, not once:

- **Your own research, open-source targets:** turn it on. It is a genuine accelerator.
- **Client work under NDA:** push off. Your names are your findings, and pushing
  `derive_key_from_imei` publishes them. Even a pull discloses that somebody is analysing something
  containing that function — for a bespoke function in an unreleased product, that is a fingerprint.
- **Want the benefit on client work:** buy Private Lumina and host it inside your own boundary.

Then write which you did into the report's methodology. "Which third parties saw the binary?" is a
question a mature client eventually asks.

---

### 24. How do I know which `.so` in the APK to analyse?

The one the running process actually maps. Do not infer it from the directory listing:

```bash
adb shell "cat /proc/$(adb shell pidof com.example.app)/maps" | grep '\.so'
```

An APK ships several ABI directories and may ship libraries it never loads. Chapter 68 measured a
session correlating an API 35 emulator's runtime against an API 30 phone's static corpus and calls it
the worst kind of error, because everything downstream stays internally consistent and is about the
wrong thing.

---

### 25. There are no `Java_*` exports. Does that mean there are no native methods?

No. There are at least three binding patterns and everyone teaches two:

1. **Static registration.** An exported symbol named by mangling the fully qualified Java name.
2. **Dynamic registration.** `JNI_OnLoad` calls `RegisterNatives` with a table of
   name/signature/pointer triples. Chapter 57 §3.9 owns recovering it.
3. **[measured] Neither.** AOSP's `libandroid_runtime.so` has no `Java_*` exports *and* no
   `JNI_OnLoad`; it registers through internal C++ functions called during runtime startup. A triage
   rule that concludes "no JNI here" is wrong about it.

Also worth remembering: dynamic registration is not an evasion technique. **[measured]**
`libmedia_jni.so` — a stock AOSP library with no obfuscation — uses it.

---

### 26. My tool shows one `br x10` and then a lot of code that belongs to no function.

That is an unrecovered switch table, and it is a legitimate outcome to record rather than a defect to
hide.

**[measured]** clang 14 emitted a **byte** table for a twelve-case switch — one byte per case, scaled
by 4, counted from an `adr` anchor — not the table of 32-bit offsets most references print. Twelve
bytes, in `.rodata`, nothing that looks like a pointer in a hex dump.

Recover it by hand: find the `adr` before the `ldrb`; that is the anchor. Each table byte × 4, added to
the anchor's address, is one case body.

---

### 27. Can I decompile DEX with IDA?

There is a DEX loader and a Dalvik debugger, and the debugger is genuinely distinctive — very few
tools step Dalvik bytecode. But the decompilation is not competitive with the dedicated tools. Use
[JADX](../56-JADX/README.md) for Java.

---

### 28. How much of a library can I honestly say I reviewed?

Count the places where a purely static reading stopped: every `blr <reg>` and every `br <reg>` your
tool did not resolve into cases. That count is your coverage statement and it belongs in the
methodology.

**[measured]** The chapter's fixture has exactly one `blr` in about 300 lines of source. A real library
protected by control-flow flattening has hundreds, all the same dispatcher, and a purely static
reading covers very little of it.

Chapter 68 §3.17 calls what you did not look at **the residue**, and argues it is part of the result.

---

### 29. The pseudocode looks clean and correct. Can I quote it in the report?

Quote it, and **label it as decompiler output with the tool and version.** It is a reconstruction, not
the program, and the reader is entitled to know which.

Chapter 56 built a case where decompiled Java is clean, warning-free and returns **100** while the
bytecode returns **105**, and shipped a program that runs both readings and prints both numbers. That
is a measured divergence in a mainstream tool, not a hypothetical.

Support any load-bearing claim with the disassembly, or with observed execution.

---

### 30. I am learning and have no budget. What should I do?

Install [Ghidra](../57-Ghidra/README.md). Work chapter 57, then this chapter's labs — **all four work
without an IDA licence**, because the target is one you build and each lab gives the free-tool route
alongside the IDA one.

Then read chapter 18 for the instruction set and chapter 68 for the method. The method is what
transfers; the tool is what you happen to have.

This repository will not point you at cracked builds, key generators or licence circumvention for IDA
or any other commercial tool. The legitimate routes are IDA Free (x86 only), IDA Home, the educational
licence, and Ghidra — and for Android arm64 work, Ghidra is not a consolation prize.

---

[README](README.md) · [cheatsheet](cheatsheet.md) · [mindmap](mindmap.md) · [labs](labs/) ·
[references](references/README.md)
