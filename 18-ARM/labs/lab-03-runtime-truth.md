# Lab 03 — Runtime truth: memory versus the file

> **Objective:** stop trusting the file. Disassemble a function as it exists in a running process,
> correct every address for ASLR by hand and then by tool, watch AAPCS64 argument registers arrive at
> a function you did not write, patch memory instead of disk, and end up able to state — with
> evidence — whether the code you analysed statically is the code the CPU is executing.

**Prerequisites:** [Lab 01](lab-01-read-your-first-disassembly.md),
[Lab 02](lab-02-patch-the-licence-check.md);
[18-ARM §3.4](../README.md#34-aapcs64--the-calling-convention),
[§7](../README.md#7-dynamic-analysis); [53-Frida](../../53-Frida/README.md) for getting
`frida-server` running at all
**Difficulty:** Intermediate–Hard
**Time:** 2–3 hours
**You will need:** an **arm64-v8a** Android device or emulator with root and a matching
`frida-server`, `adb`, the NDK, and Python 3

---

## Why this lab exists

Everything you did in Labs 01 and 02 read bytes off a disk. That is fine, right up until it is
catastrophically wrong.

| Situation | The file lies because |
|---|---|
| A packed library | An `.init_array` constructor decrypts `.text` in place before anything else runs |
| A self-modifying check | The function rewrites its own comparison constant at startup |
| Another hooking framework is loaded | The first instructions have been replaced with somebody else's trampoline |
| Relocations | The GOT on disk is zeros; in memory it holds resolved addresses |
| The wrong ABI | You disassembled `arm64-v8a` and the process is running `armeabi-v7a` |
| A patched file that never loaded | The app loaded a copy from somewhere else entirely |

There is also a number you simply cannot get from the file: **the load base**. Every Ghidra address,
every offset in your notes, and every breakpoint you want to set has to be corrected by it, and it
changes on every launch.

And there is a practical payoff that matters in real work. A **memory** patch and a **file** patch
have the same encodings and different properties. A file patch survives a restart and is caught by
any integrity check over the `.so`. A memory patch does neither. Knowing which you did — and saying
so — is the difference between a finding and an anecdote.

---

## Setup

### The fixtures

```bash
# host
export ANDROID_HOME="$HOME/Android/Sdk"
cd 18-ARM/examples
./build-arm-fixtures.sh /tmp/ch18
cd /tmp/ch18

adb push licence-runner liblicence.so /data/local/tmp/
adb shell chmod 755 /data/local/tmp/licence-runner
```

### Confirm the device is what you think it is

```bash
# host
adb shell getprop ro.product.cpu.abi          # must be arm64-v8a
adb shell getprop ro.build.version.sdk
adb shell uname -m
```

If `ro.product.cpu.abi` is not `arm64-v8a`, stop. Every register name in this lab is AArch64 and the
whole thing will mislead you. [README §3.13](../README.md#313-armeabi-v7a-arm-state-thumb-state-and-the-low-bit)
covers 32-bit.

### Frida

Getting `frida-server` onto a device is [53-Frida](../../53-Frida/README.md)'s subject, not this
lab's. The short version:

```bash
# host
frida --version                                  # note it; the server must MATCH
adb shell "su -c '/data/local/tmp/frida-server &'"   # outer quotes: the & must reach the device
frida-ps -U | head
```

### The one that catches everyone out

```bash
# host
adb shell /data/local/tmp/licence-runner /data/local/tmp/liblicence.so
```

If you get one of these:

```text
/system/bin/sh: /data/local/tmp/licence-runner: No such device or address
/system/bin/sh: /data/local/tmp/licence-runner: Interrupted system call
```

your device's vendor policy blocks `execve` on `/data`. It is not your build — copy
`/system/bin/toybox` to the same directory and it fails identically. Use the linker directly:

```bash
# host
adb shell /system/bin/linker64 /data/local/tmp/licence-runner /data/local/tmp/liblicence.so
```

Everything below works with either form.

---

## Part A — ASLR, by hand

### A1 — Find the load base three ways

Run the runner in a loop so you have a live process to look at. Simplest: use an app you own, or add
a `sleep` by running the runner under a shell that keeps it alive. The cleanest target for this lab
is any app you are allowed to instrument that loads a native library.

```bash
# adb shell -- method 1: the process map
cat /proc/<pid>/maps | grep liblicence.so
```

```text
7b3c040000-7b3c041000 r--p 00000000 fd:03 123456   /data/local/tmp/liblicence.so
7b3c044000-7b3c045000 r-xp 00000000 fd:03 123456   /data/local/tmp/liblicence.so
```

1. There are several mappings for one file. Match each to a `PT_LOAD` from
   `llvm-readelf -l liblicence.so`. Which one is `r-xp`, and why does that matter?
2. The **base** is the lowest mapping's start address. Why the lowest, and not the start of the
   executable mapping?

```javascript
// Frida REPL -- method 2
Module.findBaseAddress('liblicence.so');
Process.findModuleByName('liblicence.so');
```

```javascript
// Frida REPL -- method 3, and the one that also gives you the offset back
var m = Process.findModuleByName('liblicence.so');
var a = Module.findExportByName('liblicence.so', 'lc_is_licensed');
console.log('base   ', m.base);
console.log('addr   ', a);
console.log('offset ', a.sub(m.base));      // must equal 0x48c4
```

3. Does `a.sub(m.base)` equal `0x48c4`, the virtual address from Lab 02?
4. Kill the process, start it again, and repeat. What changed, and what did not?
5. Write down the complete conversion table for `lc_is_licensed` on *your* device right now:

| Name | Value |
|---|---|
| Virtual address (objdump) | `0x48c4` |
| File offset | `0x8c4` |
| Ghidra address (default base) | |
| Module base (this launch) | |
| Runtime address | |

---

## Part B — Disassemble the live process

```bash
# host
frida -U -n <process> -l 18-ARM/scripts/dump-function.js \
      -P '{"module":"liblicence.so","symbol":"lc_is_licensed","count":6}'
```

The script prints, in order: the module and its path, the base and size, the resolved address, the
module-relative offset, the page protection, and then the instructions.

```text
module      : liblicence.so  /data/local/tmp/liblicence.so
base        : 0x7b3c040000   size 0x5000
address     : 0x7b3c0448c4
offset      : 0x48c4   <- type this into Ghidra (plus its image base)
protection  : r-x

  +0x48c4  0x7b3c0448c4  1f 04 00 71   cmp	w0, #1
  +0x48c8  0x7b3c0448c8  e0 d7 9f 1a   cset	w0, gt
  +0x48cc  0x7b3c0448cc  c0 03 5f d6   ret
```

> Your `base` and `address` **will differ** — that is ASLR doing its job. The `offset` column and the
> raw bytes are what you compare against the chapter.

6. Compare the three instructions and their raw bytes against your Lab 01 static listing. Identical?
7. `protection` says `r-x`. What would `(unmapped!)` have meant, and what would you do about it?
8. The script disassembles with Capstone via `Instruction.parse`, not with `llvm-objdump`. Find one
   place in a longer function where the two render the same instruction differently. Is either
   wrong?

### B1 — By offset, with no symbol

Real targets are stripped. Do it without a name:

```bash
# host
frida -U -n <process> -l 18-ARM/scripts/dump-function.js \
      -P '{"module":"liblicence.so","offset":"0x48d0","count":30}'
```

9. Why does the script accept a string like `"0x48d0"` rather than a number? (Read `resolve()` and
   `dump()`.)
10. Disassemble from `0x48d0` and compare against the static listing of `lc_verify_signature`. Find
    the `mrs x20, TPIDR_EL0`. What is its runtime address?

### B2 — Save the live bytes for Ghidra

```javascript
// Frida REPL
rpc.exports.save("liblicence.so", "0x48d0", 512);
```

```text
wrote 512 bytes from 0x7b3c0448d0 to /data/local/tmp/liblicence.so_0x48d0.bin
pull it with:  adb pull /data/local/tmp/liblicence.so_0x48d0.bin
then in Ghidra: File > Import, format "Raw Binary", language AARCH64:LE:64:v8A, base address 0x48d0
```

11. Pull it and diff it against the same range of the file:

```bash
# host
adb pull /data/local/tmp/liblicence.so_0x48d0.bin
dd if=liblicence.so bs=1 skip=$((0x8d0)) count=512 of=/tmp/fromfile.bin 2>/dev/null
cmp /tmp/fromfile.bin liblicence.so_0x48d0.bin && echo IDENTICAL
```

12. They should be identical for this library. Name three kinds of library where they would **not**
    be, and say which of the three you could detect with this exact command.

---

## Part C — Watch AAPCS64 happen

This is the part that makes the calling convention stop being a table you memorised.

```bash
# host
frida -U -n <process> -l 18-ARM/scripts/dump-function.js \
      -P '{"module":"liblicence.so","symbol":"lc_verify_signature","trace":true,"nargs":3}'
```

```text
>>> liblicence.so+0x48d0  thread 12345
    lr (x30, caller) : 0x7b3c04a1f8   liblicence.so!0x...
    x0 : 0x7b3c05a120  dec=94371616  str="ARM64-IS-NOT-HARD"
    x1 : 0x0  NULL
    x2 : 0x7fe3a4c0b0  dec=-478248784
<<< returned x0 = 0x1  dec=1
```

13. `x0` printed a string. **Why does the script print each register three ways** — as a pointer, as
    a signed integer, and as a C string? Read `describe()` and answer in terms of what AAPCS64 does
    and does not tell you.
14. `x1` and `x2` hold values even though the function takes one argument. Are they arguments?
15. `lr` is the caller's return address. Why is it in a register rather than on the stack, and what
    can you do with it that you could not do on x86-64?
16. Trace it again with a wrong token. What changes in the entry dump, and what changes in
    `returned x0`?

### C1 — The JNI shift, live

```javascript
// Frida REPL
Interceptor.attach(
    Module.findExportByName('liblicence.so', 'Java_com_example_arm_Native_isLicensed'), {
    onEnter: function () {
        console.log('x0 (JNIEnv*) : ' + this.context.x0);
        console.log('x1 (jobject) : ' + this.context.x1);
        console.log('x2 (tier)    : ' + this.context.x2.toInt32());
    },
    onLeave: function (r) { console.log('return       : ' + r.toInt32()); }
});
```

17. `x0` should be a pointer into `libart.so`'s data. Confirm it:

```javascript
// Frida REPL
Process.findRangeByAddress(this.context.x0);           // inside onEnter
DebugSymbol.fromAddress(this.context.x0.readPointer()); // the JNI function table
```

18. Explain, in one sentence, why the Java-visible argument is in `x2`, using only the words
    "AAPCS64" and "prototype".

### C2 — `x8` and the large struct return

Trace `pat_big_return` from `libpatterns64.so` and print `x8` on entry.

19. Is `x8` a readable, writable address on entry?
20. Where does the return value end up, and why is `x0` unchanged?

---

## Part D — Patch memory instead of disk

```javascript
// Frida REPL -- the four-byte patch from Lab 02, in memory
(function () {
    var a = Module.findExportByName('liblicence.so', 'lc_is_licensed');
    console.log('before:');
    for (var p = a, i = 0; i < 3; i++) {
        var ins = Instruction.parse(p);
        console.log('  ' + p + '  ' + ins.mnemonic + '\t' + ins.opStr);
        p = ins.next;
    }
    Memory.protect(a.add(4), 4, 'rwx');
    a.add(4).writeByteArray([0x20, 0x00, 0x80, 0x52]);   // mov w0, #1
    console.log('after:');
    for (var p2 = a, j = 0; j < 3; j++) {
        var ins2 = Instruction.parse(p2);
        console.log('  ' + p2 + '  ' + ins2.mnemonic + '\t' + ins2.opStr);
        p2 = ins2.next;
    }
})();
```

21. Why `Memory.protect(..., 'rwx')` first? What happens without it, and what does that tell you
    about how `.text` is mapped?
22. Call `lc_is_licensed(0)` through Frida and confirm the new answer:

```javascript
// Frida REPL
var f = new NativeFunction(
    Module.findExportByName('liblicence.so', 'lc_is_licensed'), 'int', ['int']);
console.log(f(0), f(1), f(2));
```

23. `20 00 80 52` is the same four bytes you wrote to disk in Lab 02. Why is the *address* different
    and the *encoding* identical?
24. Detach Frida, restart the process, and check again. What happened, and why?

### D1 — The comparison that matters

Fill this in from your own results:

| | File patch (Lab 02) | Memory patch (here) |
|---|---|---|
| Address you computed | | |
| Bytes written | | |
| Survives process restart | | |
| Survives a SHA-256 check over the `.so` on disk | | |
| Survives a check that hashes the mapped `.text` | | |
| Requires the APK to be resigned to install | | |
| Requires a detectable agent in the process | | |

25. An app hashes its own `.so` file at startup and compares against a value baked in at build time.
    Which of your two patches does it catch?
26. An app instead hashes the **mapped** `.text` range every ten seconds. Which does it catch?
27. Design a third approach that beats both. (Hint: what if the patch were applied *after* each check
    and reverted before the next? What does that cost you, and what would catch it?)

---

## Part E — Find something that only exists at runtime

### E1 — GOT contents

```javascript
// Frida REPL -- what has the linker actually resolved?
var m = Process.findModuleByName('liblicence.so');
m.enumerateImports().slice(0, 10).forEach(function (i) {
    console.log(i.type, i.name, i.module, i.address);
});
```

28. Compare against the file:

```bash
# host
$NB/llvm-readelf --dyn-syms -W liblicence.so | grep UND
$NB/llvm-objdump -s -j .got.plt liblicence.so
```

29. What is in `.got.plt` on disk, and what is in it in memory? Explain the difference in terms of
    what the dynamic linker did.
30. `strlen` resolves into `libc.so`. Find the runtime address it resolved to, and then find the PLT
    stub in `liblicence.so` that loads it. Show that the stub's `ldr x17, [x16, #N]` reads exactly
    that slot.

### E2 — Somebody else's hook

```javascript
// Frida REPL -- attach, then look at the entry point again
Interceptor.attach(Module.findExportByName('liblicence.so', 'lc_is_licensed'), {
    onEnter: function () {}
});
rpc.exports.dump("liblicence.so", "0x48c4", 4);
```

31. The first instructions are no longer `cmp w0, #1`. What are they, and who put them there?
32. **This is the single most useful diagnostic in this lab.** If you attach a disassembler to a
    process and the entry point of a function is an unexpected `ldr x16` / `br x16`, what have you
    learned about the process?
33. Detach and dump again. Did the original instructions come back?

---

## Part F — Which library is actually loaded?

```bash
# adb shell
cat /proc/<pid>/maps | grep '\.so' | awk '{print $6}' | sort -u
```

34. For a real app that ships both `arm64-v8a` and `armeabi-v7a`, which one is mapped? What decided
    that?
35. If the app was installed with `android:extractNativeLibs="false"`, where does the path point?
    (This is [15-Native-Code](../../15-Native-Code/README.md)'s and
    [10-APK-Internals](../../10-APK-Internals/README.md)'s territory; the point here is that you must
    disassemble the file that is *mapped*.)
36. Push a **patched** `liblicence.so` to a different directory, run the runner against the pristine
    path, and confirm from `/proc/<pid>/maps` which one loaded. Then explain how the same mistake
    happens in a real assessment.

---

## Success criteria

- [ ] You can produce the load base three different ways and convert between file offset, virtual
      address, Ghidra address and runtime address in both directions.
- [ ] You disassembled a function in memory and confirmed it byte-for-byte against the file.
- [ ] You traced a function and read its arguments out of `x0`–`x7`, and can say why the script
      prints each register three ways.
- [ ] You observed the JNI shift live: `JNIEnv*` in `x0`, `jobject` in `x1`, the real argument in
      `x2`.
- [ ] You patched memory with the same four bytes you wrote to disk in Lab 02, and can state four
      properties on which the two patches differ.
- [ ] You explained what a `.got.plt` slot contains on disk versus in memory.
- [ ] You can recognise another framework's trampoline at a function entry point.
- [ ] You verified which library a process actually mapped, rather than assuming.

---

## Where next

- [Lab 04 — CTF](lab-04-ctf-four-decisions.md): back to static, with everything stripped.
- [53-Frida](../../53-Frida/README.md): Stalker, which recompiles the instruction stream you have now
  learned to read, and `Arm64Writer`, which emits it.
- [57-Ghidra](../../57-Ghidra/README.md) §7: the same address arithmetic, from the decompiler's side.
- 38-TamperDetection: the checks that would have caught you in Part D.
