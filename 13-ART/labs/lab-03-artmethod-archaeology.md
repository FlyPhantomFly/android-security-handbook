# Lab 03 — ArtMethod Archaeology

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-compiler-filters-and-hooks.md),
[Chapter 13 §3.15–3.17](../README.md#3-deep-internal-working),
[19-Memory](../../19-Memory/README.md), comfort with Frida's native API

---

## Objective

Read `ArtMethod` structures directly out of a live process, classify each method's execution state from
its entry point, watch the entry point change as the JIT compiles a method, and finally **patch one by
hand** — implementing the core of a hooking framework yourself, without using `Java.use(...)
.implementation`.

## Why this matters

Frida's Java bridge is excellent, and you should use it for real work. But it is a black box, and when
it fails you have no next step unless you know what it was doing.

This lab opens the box. Afterwards you will be able to reason about hook failures structurally, write
tooling that works where the Java bridge does not, and read the ART source with confidence.

> **Warning.** This lab writes to another process's memory. Do it on a test device with a target
> app you built. Getting an offset wrong crashes the app; getting it very wrong can destabilise the
> system. Never do this to an app you did not build, on a device you care about.

---

## Setup

Use the target from [Lab 02](lab-02-compiler-filters-and-hooks.md), or any app you control.

```bash
# host
adb shell cmd package compile -m verify -f com.artlab.target
adb shell am force-stop com.artlab.target
frida --version
adb shell "su -c '/data/local/tmp/frida-server --version'"
```

Confirm the versions match before starting.

---

## Steps

### Step 1 — Get an ArtMethod pointer

Frida's Java bridge exposes the underlying `ArtMethod` pointer as `.handle` on a resolved method.

```javascript
// step1.js — frida -U -f com.artlab.target -l step1.js
Java.perform(function () {
    var Check = Java.use("com.artlab.target.Check");

    // Resolve a specific overload so we get exactly one ArtMethod.
    var m = Check.isSecure.overload();
    console.log("[+] ArtMethod* for isSecure() = " + m.handle);

    var d = Check.describe.overload();
    console.log("[+] ArtMethod* for describe()  = " + d.handle);
});
```

**Question 1.** Are the two pointers close together in memory? What does that suggest about how a
class's methods are stored?

### Step 2 — Locate libart and the trampolines

To classify an entry point you need to know what the known trampoline addresses are.

```javascript
// step2.js
Java.perform(function () {
    var libart = Process.findModuleByName("libart.so");
    console.log("[+] libart.so base=" + libart.base + " size=" + libart.size);

    var trampolines = [
        "art_quick_to_interpreter_bridge",
        "art_quick_generic_jni_trampoline",
        "art_quick_resolution_trampoline",
        "art_quick_imt_conflict_trampoline",
        "art_quick_instrumentation_entry"
    ];

    trampolines.forEach(function (name) {
        var addr = Module.findExportByName("libart.so", name);
        console.log("    " + (addr ? addr : "<not exported>") + "  " + name);
    });
});
```

**Question 2.** Some of these may print `<not exported>`. Why, and what does that tell you about
writing portable ART tooling?

### Step 3 — Find the entry point offset empirically

`ArtMethod`'s field layout varies by ART version, so **do not hard-code the offset**. Derive it.

The strategy: take a method you *know* is interpreted (because you forced `verify`), and scan the first
few words of its `ArtMethod` looking for the value of `art_quick_to_interpreter_bridge`.

```javascript
// step3.js
Java.perform(function () {
    var bridge = Module.findExportByName("libart.so", "art_quick_to_interpreter_bridge");
    if (bridge === null) {
        console.log("[-] Bridge symbol not exported on this build — see Hint 2");
        return;
    }
    console.log("[*] interpreter bridge = " + bridge);

    var Check = Java.use("com.artlab.target.Check");
    var m = Check.isSecure.overload();
    var base = ptr(m.handle);

    console.log("[*] Scanning ArtMethod at " + base);
    for (var off = 0; off < 64; off += Process.pointerSize) {
        var val = base.add(off).readPointer();
        var mark = val.equals(bridge) ? "   <== INTERPRETER BRIDGE" : "";
        console.log("    +0x" + off.toString(16) + " = " + val + mark);
    }
});
```

**Record** the offset at which the bridge appears. That is
`entry_point_from_quick_compiled_code_` on your device.

**Question 3.** Why is deriving the offset this way more reliable than reading it from a blog post?

### Step 4 — Classify execution state

Now write a function that, given any method, reports its state.

```javascript
// step4.js
Java.perform(function () {
    var ENTRY_OFF = 0x18;   // <-- replace with YOUR value from step 3

    var known = {};
    ["art_quick_to_interpreter_bridge",
     "art_quick_generic_jni_trampoline",
     "art_quick_resolution_trampoline",
     "art_quick_imt_conflict_trampoline",
     "art_quick_instrumentation_entry"].forEach(function (n) {
        var a = Module.findExportByName("libart.so", n);
        if (a !== null) known[a.toString()] = n;
    });

    var libart = Process.findModuleByName("libart.so");

    function classify(handle, label) {
        var ep = ptr(handle).add(ENTRY_OFF).readPointer();
        var state;

        if (known[ep.toString()] !== undefined) {
            state = known[ep.toString()];
        } else {
            // Not a known trampoline. Is it inside a file-backed module (AOT)
            // or in anonymous memory (JIT code cache)?
            var mod = Process.findModuleByAddress(ep);
            if (mod !== null) {
                state = "AOT code in " + mod.name;
            } else {
                var range = Process.findRangeByAddress(ep);
                state = "JIT code cache (anon " +
                        (range ? range.protection : "?") + ")";
            }
        }
        console.log("    " + label + "  ep=" + ep + "  -> " + state);
    }

    var Check = Java.use("com.artlab.target.Check");
    console.log("[*] Method states:");
    classify(Check.isSecure.overload().handle, "isSecure()");
    classify(Check.describe.overload().handle, "describe()");
});
```

**Question 4.** Under `verify`, what state does each method report?

### Step 5 — Watch the JIT change the entry point

This is the most satisfying part of the lab.

```bash
# host — restore JIT-friendly conditions
adb shell cmd package compile --reset com.artlab.target
adb shell am force-stop com.artlab.target
```

```javascript
// step5.js — poll the entry point while the app runs its hot loop
Java.perform(function () {
    var ENTRY_OFF = 0x18;   // <-- your value

    var Check = Java.use("com.artlab.target.Check");
    var handle = ptr(Check.describe.overload().handle);
    var last = null;

    setInterval(function () {
        var ep = handle.add(ENTRY_OFF).readPointer();
        if (last === null || !ep.equals(last)) {
            var mod = Process.findModuleByAddress(ep);
            console.log("[!] entry point changed: " + ep +
                        "  (" + (mod ? mod.name : "anonymous / JIT") + ")");
            last = ep;
        }
    }, 200);

    console.log("[*] Watching describe()'s entry point...");
});
```

Let the app run its loop. You should observe the entry point change from the interpreter bridge to an
address in anonymous memory as the JIT compiles the method.

**Question 5.** What does it mean when the new address is in anonymous memory rather than in a
file-backed module?

### Step 6 — Patch an entry point by hand

Now implement the core of a hook without the Java bridge.

The plan: allocate a small native function that returns `false` (0), then overwrite `isSecure()`'s
entry point to point at it.

```javascript
// step6.js — MINIMAL manual hook. Test device only.
Java.perform(function () {
    var ENTRY_OFF = 0x18;   // <-- your value

    var Check = Java.use("com.artlab.target.Check");
    var handle = ptr(Check.isSecure.overload().handle);

    // Save the original so we can restore it.
    var original = handle.add(ENTRY_OFF).readPointer();
    console.log("[*] original entry point = " + original);

    // Build a tiny AArch64 function:  mov w0, #0 ; ret
    // ART's quick calling convention passes the ArtMethod* in x0 and returns
    // the result in w0/x0. Returning 0 means Java false.
    var code = Memory.alloc(Process.pageSize);
    Memory.protect(code, Process.pageSize, "rwx");

    Memory.patchCode(code, 8, function (p) {
        var w = new Arm64Writer(p, { pc: code });
        w.putMovRegU64("x0", 0);   // return value = 0 = false
        w.putRet();
        w.flush();
    });

    console.log("[*] stub at " + code);

    // Point the method at our stub.
    handle.add(ENTRY_OFF).writePointer(code);
    console.log("[+] entry point patched — isSecure() now returns false");

    // Provide a way to undo it.
    global.restore = function () {
        handle.add(ENTRY_OFF).writePointer(original);
        console.log("[+] restored");
    };
});
```

Observe the app's output. `describe()` should now report `insecure`.

> **Warning.** This stub ignores the calling convention beyond the return value, does no argument
> handling, and does not support calling the original. It is a demonstration of the *mechanism*, not a
> hooking framework. Real frameworks generate a proper trampoline that preserves registers, marshals
> arguments, and can invoke the original through a saved `ArtMethod` copy.

**Question 6.** Why must this be done while the method is interpreted for the effect to be visible?

### Step 7 — Read other ArtMethod fields

```javascript
// step7.js — dump the whole structure and interpret it
Java.perform(function () {
    var Check = Java.use("com.artlab.target.Check");
    var base = ptr(Check.isSecure.overload().handle);

    console.log("[*] ArtMethod raw dump:");
    console.log(hexdump(base, { length: 64, ansi: false }));

    // Field offsets vary by version. On many builds:
    //   +0x00 declaring_class_ (GcRoot, 4 bytes, compressed)
    //   +0x04 access_flags_
    //   +0x08 dex_code_item_offset_ / dex_method_index_
    //   +0x0c dex_method_index_ / method_index_ + hotness_count_
    // ALWAYS verify against art/runtime/art_method.h for your ART version.
    var accessFlags = base.add(0x04).readU32();
    console.log("[*] access_flags_ = 0x" + accessFlags.toString(16));
    console.log("    ACC_PUBLIC   " + ((accessFlags & 0x0001) !== 0));
    console.log("    ACC_PRIVATE  " + ((accessFlags & 0x0002) !== 0));
    console.log("    ACC_STATIC   " + ((accessFlags & 0x0008) !== 0));
    console.log("    ACC_FINAL    " + ((accessFlags & 0x0010) !== 0));
    console.log("    ACC_NATIVE   " + ((accessFlags & 0x0100) !== 0));
});
```

**Question 7.** Compare the decoded access flags against the method's declaration in your Java source.
Do they match? Which bits did you *not* account for, and what might they be?

---

## Hints

<details>
<summary>Hint 1 — the offset scan finds nothing</summary>

Confirm the method really is interpreted:
```bash
adb shell cmd package compile -m verify -f com.artlab.target
adb shell am force-stop com.artlab.target
```
Also try scanning further than 64 bytes, and remember that on a 64-bit device
`Process.pointerSize` is 8 — a 32-bit field read as a pointer will produce nonsense.
</details>

<details>
<summary>Hint 2 — trampoline symbols are not exported</summary>

Some ART builds strip them. Alternatives: use `DebugSymbol.findFunctionsMatching("*quick_to_interpreter*")`,
or take the empirical route — record the entry point of a method you know is interpreted and treat
*that value* as the bridge, without needing its name.
</details>

<details>
<summary>Hint 3 — the app crashes when you patch</summary>

Almost always a wrong offset. Re-derive it in Step 3 and confirm the value you read back matches the
bridge address before writing anything. Also confirm you are writing a pointer
(`writePointer`) and not a 32-bit value.
</details>

<details>
<summary>Hint 4 — Arm64Writer is unavailable or the device is 32-bit</summary>

Check `Process.arch`. On `arm` use `ThumbWriter`/`ArmWriter` and the corresponding instruction
sequence. On `x64` use `X86Writer` and emit `xor eax, eax; ret`.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** They are typically adjacent, separated by exactly `sizeof(ArtMethod)`. A class's methods are
stored in a contiguous array (`mirror::Class::methods_`), which is why a hooking framework can walk
from the class to any method by index — and why `oatdump`'s per-class output is organised the way it
is.

**2.** Symbol export varies because ART is built with different visibility settings across releases and
because it is a Mainline module updated independently of the OS. The lesson is that **any tool relying
on ART symbol names or structure offsets must probe rather than assume**. This is the single biggest
reason public Frida scripts break on some devices and not others.

**3.** Because the offset genuinely differs across ART versions, and ART updates independently of
Android via Mainline — so two devices reporting the same Android release can have different layouts. A
blog post captures one build at one moment. Deriving the offset from an invariant you can observe (a
method you forced into the interpreter must point at the interpreter bridge) works on any build.

**4.** Both should report `art_quick_to_interpreter_bridge`. That is what `verify` means: nothing is
compiled, so every method routes through the interpreter.

**5.** File-backed means the code came from the OAT file — it is AOT-compiled. Anonymous means the code
was generated at runtime into the JIT code cache. Seeing the transition live is direct confirmation of
the state machine in §2.4, and it explains why `[anon:jit-code-cache]` regions are legitimate rather
than evidence of injection (§3.14).

**6.** If the method were AOT-compiled and its callers had inlined it, the callers would not consult the
entry point at all — they would execute the folded-in constant. Patching the entry point only changes
behaviour where a real dispatch through the `ArtMethod` occurs, which interpretation guarantees at
every call site. This is Lab 02's lesson, now visible at the level of the individual pointer you are
writing.

**7.** The low bits should match your Java declaration exactly (`public` → `ACC_PUBLIC`, and so on).
The bits you did not account for include ART-internal flags such as `kAccFastNative`,
`kAccCompileDontBother`, `kAccPreviouslyWarm`, and — importantly — the **hidden API** access bits that
implement non-SDK interface restrictions. Those upper bits are why `access_flags_` is interesting to
attackers: clearing the hidden-API bits is one route to bypassing non-SDK restrictions (§3.15).

</details>

---

## Success criteria

- [ ] You obtained `ArtMethod` pointers and can explain why a class's methods are adjacent in memory
- [ ] You **derived** the entry-point offset empirically rather than hard-coding it
- [ ] You can classify any method as interpreted, AOT-compiled, JIT-compiled, or trampolined
- [ ] You watched an entry point change live as the JIT compiled a hot method
- [ ] You patched an entry point by hand and observed the behaviour change
- [ ] You restored the original entry point cleanly
- [ ] You decoded `access_flags_` and know which bits carry hidden-API state
- [ ] You can explain in your own words why every Java hooking framework converges on this technique
- [ ] You can explain why offset-hard-coding scripts break across devices on the same Android version
