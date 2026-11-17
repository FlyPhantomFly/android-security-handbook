# 57 — Ghidra · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

> **Provenance.** Ghidra **is** installed here (12.1.2 PUBLIC, Java 24.0.2) and was run headless
> against this chapter's own target, so tool behaviour described below is **Measured**. The worked
> scenarios in [README §9](README.md#9-examples) are **Illustrative**: `libcrypto_helper.so`,
> `libsecure.so` and `libapi.so` do not exist, and **the 32-byte "AES key" in README §9.1 is
> invented** — it is not a key recovered from any application. See
> [README.md](README.md#read-this-before-you-read-anything-else-what-is-measured-here-and-what-is-not).

---

**1. What is the actual difference between a disassembler and a decompiler? They both show me code.**

A disassembler *translates*. Machine code and assembly are the same information in two notations, so
the mapping is one-to-one and mechanical. Given the right processor, disassembly is correct by
construction.

A decompiler *infers*. It has to reconstruct things the compiler threw away: which memory locations
were variables, what types they had, where loops and conditionals were, what each function's
signature was. None of that survives compilation, so the decompiler reasons about it and produces its
best guess as C.

The practical consequence appears the moment they disagree, and they will: **the disassembly is right
and the C is a hypothesis**. In particular, sign extension, integer width, pointer versus integer
arithmetic, and comparison operators are exactly the things a decompiler renders approximately, and
exactly the things a security conclusion turns on. When your finding depends on `<` versus `<=`, go and
read the instruction.

---

**2. What is P-Code, and why should I care about an internal detail?**

P-Code is Ghidra's intermediate representation. Each machine instruction is translated, according to
that processor's SLEIGH specification, into a short sequence of simple operations — `COPY`, `LOAD`,
`STORE`, `INT_ADD`, `INT_SLESS`, `BRANCH`, `CALL` — each with precisely defined semantics.

The reason it exists is decoupling. Without an IR, every analysis (constant propagation, dead-code
elimination, type inference, the decompiler itself) would need writing once per architecture. With it,
the architecture-specific work is confined to a file describing what instructions *mean*, and every
analysis is written once. That is why Ghidra supports so many processors.

You should care for one practical reason: the C you read is derived from P-Code, not from the assembly
text. When the output looks wrong, "is the P-Code semantics for this instruction right?" is a real
question with a real answer — you can view P-Code directly in the Listing pane's field options.

---

**3. Everything is `FUN_00103a10` and `undefined8 uVar1`. Is the binary broken?**

No. Those are two different, entirely normal messages.

`FUN_<address>` means the symbol table was stripped, so Ghidra has no name for that function and
invented one from its address. Release builds are stripped; this is the expected state.

`undefined8` means "eight bytes, meaning unknown". It is Ghidra telling you honestly that it has
inferred the *size* of a value but not its *type*. That is not a property of the binary; it is the
state of your project before you have done any work.

Fixing it is the work, and it is the highest-value activity in the tool. Start with the function
signature (`F` on the function name), because parameter types propagate outward through the whole
function. For a JNI function, one signature line turns unreadable output into readable output.

---

**4. Why is everyone so insistent about defining `JNIEnv` first?**

Because without it, every JNI call is rendered as arithmetic. `JNIEnv` is a pointer to a pointer to a
struct of roughly 230 function pointers, so a call to `GetStringUTFChars` decompiles as:

```c
(**(code **)(*(long *)param_1 + 0x548))(param_1,param_3,0);
```

That is correct and useless. A function making fifteen JNI calls gives you fifteen of those, and you
cannot tell a string read from a class lookup from a method call.

With `JNIEnv` defined, the identical line becomes:

```c
(*env)->GetStringUTFChars(env,input,(jboolean *)0x0);
```

Nothing about the binary changed. Only what Ghidra knows about the type of `param_1` did. That is the
general lesson of decompiler work in one example.

Fastest route: download `jni_all.gdt` from the JNIAnalyzer project, then Data Type Manager →
down-arrow → *Open File Archive…*. Thirty seconds, and you never do it again.

---

**5. The Java class declares `native String decrypt(String)` but `nm -D` shows no `Java_*` symbol. Did
I get the wrong file?**

Probably not. The app used **dynamic registration**: `JNI_OnLoad` calls
`RegisterNatives(env, clazz, methods, count)` with an array of
`JNINativeMethod { const char *name; const char *signature; void *fnPtr; }`. The functions it names
are usually `static` in C terms, so they are not exported at all.

This is a deliberate choice. It exists to break exactly the `nm` command you just ran.

Your options, cheapest first:

1. Run [`scripts/RecoverRegisterNatives.py`](scripts/RecoverRegisterNatives.py), which scans read-only
   data for pointer triples that look like the table and renames the targets.
2. Read `JNI_OnLoad` manually: define `JNIEnv`, find the call through `+0x6b8`, follow the third
   argument to the table, apply the array type.
3. Recover it at runtime by hooking `RegisterNatives` — see
   [`../53-Frida/scripts/native-tracer.js`](../53-Frida/scripts/native-tracer.js), `nat.table()`.

If the table is built at runtime rather than being a static array, option 3 is the only one that
works, and the fact that it was built at runtime is itself worth reporting.

---

**6. Which ABI's library should I analyse? The APK has three.**

The one the target actually runs, which depends on the device *and* on whether the process is 32- or
64-bit. On a 64-bit device, an app whose native libraries include `arm64-v8a` runs 64-bit and loads
that one; an app shipping only `armeabi-v7a` runs 32-bit even on a 64-bit device.

Do not guess:

```bash
# adb shell — what is actually mapped?
cat /proc/$(pidof com.example.app)/maps | grep -oE '/[^ ]+\.so' | sort -u
```

Spending an afternoon on the ARM32 build when the device runs ARM64 is a real and common way to waste
a day, and the two builds genuinely differ — different instruction encodings, different inlining
decisions, sometimes different code paths.

---

**7. How do I know a `.so` in the APK is even used?**

You check the running process, as above. An APK can contain libraries no code path ever `dlopen`s:
leftovers from a removed feature, dependencies of an SDK the app disabled, or ABI variants for devices
this one is not.

```javascript
// Frida — the same question, with base addresses as a bonus
Process.enumerateModules().forEach(m => console.log(m.base + "  " + m.name));
```

Checking takes ten seconds. It is the cheapest possible way to avoid the most expensive possible
mistake.

---

**8. What does `extractNativeLibs="false"` change?**

Where the library lives, not whether it can be read. Normally the installer extracts
`lib/<abi>/*.so` from the APK into the app's native library directory, and the linker loads it from
there. With `extractNativeLibs="false"`, the libraries are stored uncompressed and page-aligned inside
the APK, and the linker maps them straight out of it — saving disk space and install time.

For you this changes two things. First, `/proc/<pid>/maps` shows a path like
`/data/app/~~xxx/com.example-yyy/base.apk!/lib/arm64-v8a/libnative.so` rather than a standalone file.
Second, `adb pull` of the extracted `.so` will not find it — you pull the APK and `unzip` instead.

It hides nothing. The bytes are identical.

---

**9. The decompilation is complete nonsense. What do I do?**

Work through this list in order; each step is cheap.

1. **Read the disassembly at the same address.** If the *instructions* look like garbage, the problem
   is the load, not the decompiler — wrong processor, wrong image base, or ARM-versus-Thumb
   mis-detection. Re-import.
2. **Check the function signature.** A wrong parameter count or calling convention misattributes
   everything downstream. Set it explicitly with `F`.
3. **Fix the types.** Pointer arithmetic rendered as integer arithmetic is the single most common
   cause of "this makes no sense".
4. **Check whether Ghidra disassembled data as code.** A function full of nonsensical operations on
   constants is often a jump table or a string being decoded as instructions.
5. **Consider obfuscation.** A single enormous function with a `switch` on a variable reassigned in
   every branch is control-flow flattening; the output is *correct* and still unreadable. That is a
   different problem, and the answer is usually dynamic analysis.

---

**10. Ghidra takes ten minutes to analyse one library. Is that normal?**

For a large ARM64 library, yes — but it is often a heap problem rather than a work problem. Ghidra's
default JVM heap is modest and a big library will thrash.

```properties
# ghidra/support/launch.properties
VMARGS=-Xmx8G
```

Also: turn off *Aggressive Instruction Finder* unless you need it (it is expensive and creates false
functions), and use `-analysisTimeoutPerFile` in headless runs so one pathological binary does not
stall a corpus job.

---

**11. What is `analyzeHeadless` for, if I can just use the GUI?**

Repeatability and scale, which are the same thing viewed from different distances.

Repeatability: the same analysis, from a script, with no human variance, so a result from three months
ago can be reproduced exactly.

Scale: forty APKs is not a GUI problem. Extract every `.so`, run a script that emits an inventory
line per library, and you have a CSV in minutes. Then — and this is the actual point — run it again
next quarter and **diff the two**. "What changed" is a far more valuable question than "what exists":
a new `dlopen` import, a library that stopped being stripped, a jump in JNI surface. Those deltas are
where human review time belongs.

See [`scripts/so-triage.sh`](scripts/so-triage.sh) and [`scripts/FindJNI.py`](scripts/FindJNI.py).

---

**12. How do I connect an address in Ghidra to a running process?**

Through the module base, and the arithmetic is always the same:

```
runtime_addr = module_base + (ghidra_addr - image_base)
```

Ghidra loads a shared object at a default image base (usually `0x100000`), so the addresses you see
are effectively offsets. At runtime, ASLR places the library somewhere else entirely, and somewhere
different on every launch.

```javascript
// Frida — never write a raw address from a previous run
const m = Process.findModuleByName("libnative.so");
Interceptor.attach(m.base.add(0x3e40), { onEnter(args) { /* ... */ } });
```

Every workflow that crosses between the static and dynamic worlds is this one operation. Getting it
wrong — usually by pasting a raw address — is the most common error at this boundary.

---

**13. Should I use Ghidra or IDA Pro? What about radare2?**

Ghidra when the work is Android native code and the decompiler matters. It is free, so everyone on the
team can have it; its ARM64 decompiler is genuinely good; its type management is excellent; and
headless mode makes batch work straightforward.

IDA Pro when you need the best-in-class disassembler on an awkward target, when you depend on a
specific plugin, when the binary is heavily obfuscated and IDA's analysis does better, or when
your team is standardised on it — and you have the budget.

radare2 or rizin when you want something fast and scriptable from the command line, are working over
SSH on a device, or want triage without launching a JVM.

The honest answer is that these are not exclusive. It is entirely normal to triage in radare2, do the
sustained work in Ghidra, and open one stubborn function in IDA. The cost of switching is low; the
cost of forcing one tool onto an unsuitable job is high.

---

**14. What can a decompiler fundamentally *not* tell me?**

Six things, and knowing them is what stops you over-claiming in a report.

- **Which code actually runs.** Reachability across function pointers, dynamic dispatch and JNI is not
  decidable in practice. A function can exist and never execute.
- **Runtime values.** Anything derived from device state, server responses, time or user input exists
  only at execution time. A key derived at runtime is not in the binary at all.
- **What the compiler discarded** — original variable names, comments, most type names, source-level
  signedness, inlined function boundaries, and often whether a loop was a `for` or a `while`.
- **Indirect control flow targets** — virtual calls and jump tables depend on runtime values.
- **Exact semantics.** The C is a reconstruction. The disassembly is the ground truth.
- **Intent.** That a function computes an HMAC is recoverable; whether the protocol uses it correctly
  is not visible from the function alone.

The practical rule: write "the binary contains a function that, when called, does X", not "the app does
X", unless you have also observed it running.

---

**15. Is it worth learning to read ARM64 assembly, or can I live in the decompiler?**

You can get a long way in the decompiler, and most days you will. But you need enough assembly to do
three things.

First, **arbitrate**. When the C looks wrong, only the disassembly settles it, and you cannot arbitrate
in a language you cannot read.

Second, **read what the decompiler refuses**. Obfuscated functions, hand-written assembly, and
mis-analysed regions all produce failed or nonsensical decompilation, and those are disproportionately
the interesting ones.

Third, **patch**. Writing `mov w0, #0; ret` over a check requires knowing what those encode.

Aim for reading fluency, not writing fluency: the AArch64 subset that compilers actually emit is small
and you will meet the same twenty patterns constantly. [18-ARM](../18-ARM/README.md) covers it.

---

**16. What is `.init_array` and why does everyone say to look at it first?**

It is a section holding pointers to functions that the dynamic linker calls when the library is
loaded — `__attribute__((constructor))` in C. They run at `dlopen` time, which is **before**
`JNI_OnLoad` and long before any Java code touches the library.

That earliness is exactly why anti-analysis and unpacking logic is put there. A library that decrypts
its real code, or that checks for a debugger and exits, will do it from a constructor so that by the
time you attach, it has already happened.

```bash
# host — is there anything there?
readelf -S libnative.so | grep -A1 init_array
objdump -s -j .init_array libnative.so
```

`FindJNI.py` enumerates and resolves them for you.

---

**17. I found a hard-coded key with `strings`. Is that the finding?**

It is *an* observation, and often the start of a finding rather than the whole of it. Three questions
turn it into one.

What is the key *for*? A key that signs analytics events and a key that authorises transactions are
very different findings.

Is it *used*? A constant in `.rodata` with no cross-references is dead. Check `Ctrl+Shift+F` on the
address.

Does using it *achieve* anything? Forge a request with it and see whether the server accepts. That last
step is what converts "the binary contains a key" into "an attacker can forge authenticated requests",
and it is what makes the report actionable rather than theoretical.

---

**18. The library seems to decrypt itself at load time. How do I analyse it?**

Analyse the decrypted form, from memory, rather than the encrypted form on disk.

1. Let the app run until the library has initialised.
2. Find the module's base and size — `Process.findModuleByName("libx.so")`.
3. Dump the mapped region to a file with Frida (`readByteArray`, then `send` it to the host).
4. Import the dump into Ghidra **at the base address it occupied**, so that absolute cross-references
   and pointers resolve correctly. This is the step people forget, and skipping it makes every string
   reference point at nothing.

See [§7.4](README.md#74-dumping-memory-to-feed-back-into-ghidra) and
[40-Obfuscation](../40-Obfuscation/README.md).

---

**19. Should I rename functions as I go, or push through and understand it all first?**

Rename as you go, always. Two reasons, one obvious and one less so.

The obvious one: knowledge that lives only in your head evaporates overnight and cannot be handed to a
colleague. A Ghidra project with a hundred renamed functions and twenty defined structs is an asset;
your memory of yesterday is not.

The less obvious one: renaming compounds. Every function you name makes its callers easier to read,
which makes *their* callers easier to read. Analysis speed accelerates through a binary rather than
being constant, and the acceleration only happens if you record what you learn.

Also add comments for what you *deduced*, not what the code says. `// returns 1 when the licence hash
matches; called from JNI_OnLoad's constructor` is worth keeping. `// adds two numbers` is not.

---

**20. Can I paste decompiled C into a compiler and get an equivalent program?**

No, and expecting to is a category error. Decompiled C is a *rendering*: variable names are invented,
types are inferred, calling conventions are assumed, and Ghidra emits constructs (`undefined8`,
`CONCAT44`, `SUB84`, `in_x28`) that exist to describe machine behaviour rather than to compile.

What you *can* legitimately do is read it, grep it, diff two versions of it, and reimplement the
algorithm by hand once you understand it — which is a different and much more reliable activity than
compiling the output.

And frequently you should not reimplement it at all. If the question is "what does this produce for
input X", calling the real function with Frida's `NativeFunction` answers it in minutes and cannot be
wrong, because you are running the actual code. Reversing an algorithm you could call is a
common and expensive mistake.

---

**21. How do I tell whether a library is obfuscated before I waste an hour on it?**

Cheap signals, in order:

```bash
# host
strings -a -n 6 libnative.so | wc -l          # very few strings -> encrypted strings
readelf -S libnative.so | grep -c ''          # unusual section names?
nm -D --defined-only libnative.so | wc -l     # very few exports for a large file?
ls -l libnative.so                            # large file, few functions -> flattening
```

Then in Ghidra: a small number of enormous functions, a huge number of tiny basic blocks per function,
a `switch` on a variable reassigned in every branch, or an entropy profile that looks uniform across
`.text`. Ghidra's function list sorted by size tells you most of this in one glance.

If it is flattened or virtualised, change strategy rather than pushing harder: dynamic analysis and
coverage diffing ([53-Frida §7.9](../53-Frida/README.md#79-stalker-in-practice-when-instruction-level-tracing-is-worth-it))
answer "which code decided" without reading any of it.

---

**22. What is Version Tracking and is it worth learning?**

It is Ghidra's binary-diffing feature: given two versions of a binary, it correlates functions between
them using several matching strategies (exact bytes, exact instructions, function signatures,
reference patterns) and lets you carry names, comments and types from the analysed version to the new
one.

Worth learning if you analyse the same product repeatedly — which is most of enterprise security work.
The alternative is re-doing an afternoon of naming on every release, which nobody sustains.

Be aware of the limits: a recompilation with different optimisation settings can rearrange everything,
and correlation quality drops sharply on obfuscated binaries. Treat its matches as suggestions to
confirm, not as facts.

---

**23. Where do I even start with a library I know nothing about?**

This order, and it is the same order every time.

1. **Triage on the command line** before opening anything — `file`, `readelf -h -d`, `nm -D`,
   `strings`. Two minutes. Or run [`scripts/so-triage.sh`](scripts/so-triage.sh).
2. **Import with the right processor.** Confirm the disassembly at an export looks like a sane function
   prologue.
3. **Define `JNIEnv`** immediately.
4. **Look at the exports.** `Java_*` functions are your entry points; if there are none, go to
   `JNI_OnLoad`.
5. **Set the signature** on the one function you care about most, and read it.
6. **Follow the strings.** Search for the interesting ones and use cross-references to find the code
   that uses them.
7. **Form one hypothesis and confirm it dynamically** with Frida before reading any further.

The mistake is starting at step 5 with a binary you have not triaged, in a project where step 3 has not
been done.

---

**24. Ghidra found a function but shows it as undefined bytes. How do I make it a function?**

Position the cursor at the start, press `D` to disassemble, then right-click → *Create Function* (or
`F`). If the disassembly still looks wrong afterwards, the address is probably not a function start —
check the alignment, and on 32-bit ARM check whether you are in the wrong instruction set (a Thumb
function disassembled as ARM produces plausible-looking nonsense).

Common causes of a missed function: it is only reached through a function pointer or a jump table, so
nothing references it directly; auto-analysis was conservative; or the bytes really are data.

---

**25. What is the single highest-value habit in this chapter?**

Setting the function signature before reading the function. It costs ten seconds, it propagates types
through the entire body, and it is the difference between a screen of `undefined8` arithmetic and
readable C. For JNI functions specifically:

```c
jstring Java_com_example_Crypto_decrypt(JNIEnv *env, jobject thiz, jstring input)
```

That one line, plus an imported `jni_all.gdt`, is most of what separates people who find Ghidra useful
from people who find it impenetrable.
