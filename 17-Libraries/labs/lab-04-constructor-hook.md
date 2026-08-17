# Lab 04 — Catch the Constructor

**Difficulty:** Advanced
**Time:** 4–6 hours
**Prerequisites:** [Lab 01](lab-01-library-inventory.md),
[Chapter 17 §9.1](../README.md#9-examples) (the ordering example),
[§7.2](../README.md#7-dynamic-analysis) (catching libraries as they load),
[53-Frida](../../53-Frida/README.md), the Android NDK, a rooted or debuggable test device.
The target is [`../examples/init_array_guard.c`](../examples/init_array_guard.c).

---

## Objective

Defeat a native anti-analysis check that runs in `.init_array` — that is, **inside `dlopen()`, before
`JNI_OnLoad`, before any Java code in the process has executed**.

You will do it in a specific order, and the order is the lab:

1. **Fail three times, deliberately**, with the approaches that look obviously correct.
2. **Prove** the ordering that made them fail, with timestamps rather than belief.
3. **Succeed five different ways**, and understand why each one works, where each one breaks, and
   which one you would actually reach for on an engagement.

Do not skip to part 3. The failures are not padding — the reason this technique defeats experienced
testers is that it defeats them *silently*, and you only learn to distrust a silent success by
experiencing one.

---

## Why this matters

Chapter §13 states it as a key point:

> Library **constructors in `.init_array` run inside `dlopen`, before `JNI_OnLoad`, before any Java
> code**. Anti-analysis lives there. Spawn, do not attach.

And chapter §11 lists it as a reverse engineer mistake:

> **Ignoring `.init_array`.** The earliest and most important code in a hostile library is there, and
> it never appears in a call graph rooted at `JNI_OnLoad`.

Three reasons this specific window matters more than its size suggests:

**It is invisible to every tool rooted in Java.** A call graph built from `JNI_OnLoad` does not
contain it. A `Java.perform` hook cannot see it. An Objection class listing cannot see it. Every
tool will happily report "no anti-tamper found", and every tool will be wrong.

**Failure is silent by design.** Well-written anti-analysis does not crash, log, or show a dialog. It
sets a flag and lets you carry on, and three hours later you are debugging why the payment flow
returns garbage. The library in this lab returns `"the weather is fine"` for exactly that reason.

**The window is genuinely narrow.** Between "the linker has mapped and relocated the library" and
"the constructors have run" there is no return to your code at all. You cannot hook a function in a
library that does not exist yet, and by the time it exists the decision is made. Getting into that
window requires understanding what is *already* loaded — which is the insight the lab is built to
produce.

---

## Setup

### Build the target

Take [`../examples/init_array_guard.c`](../examples/init_array_guard.c) as-is. Its header has the
CMake and Gradle it needs. The Java side is four lines:

```java
// app/src/main/java/com/liblab/guarded/Guard.java
package com.liblab.guarded;

public class Guard {
    static { System.loadLibrary("guarded"); }
    public static native String secret();
    public static native boolean tripped();
}
```

```java
// app/src/main/java/com/liblab/guarded/MainActivity.java
package com.liblab.guarded;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        Log.i("LIBLAB", "tripped=" + Guard.tripped());
        Log.i("LIBLAB", "secret=" + Guard.secret());
    }
}
```

### Confirm the shape before you attack it

```bash
# host — the constructor really is registered
readelf -S app/build/.../libguarded.so | grep -A1 init_array
readelf --dyn-syms app/build/.../libguarded.so | grep -E 'JNI_OnLoad|Java_'

# host — or with nothing installed but python3
python3 ../scripts/lib-fingerprint.py app/build/.../libguarded.so
```

You should see `.init_array` with a non-zero size, `JNI_OnLoad`, and two `Java_com_liblab_guarded_*`
exports. **Note that `early_guard` itself is not in the symbol table** — it is `static`, so its name
never leaves the compiler. You will need that fact in method 3.

### The clean baseline

Run it with nothing attached, and keep this output. Everything you do from here is measured against
it.

```bash
# host
adb logcat -c
adb shell am start -n com.liblab.guarded/.MainActivity
adb logcat -d | grep -E 'libguarded|LIBLAB'
```

```text
I libguarded: constructor ran: traced=0 mapped=0 verdict=0
I libguarded: JNI_OnLoad ran (guard already decided: 0)
I LIBLAB: tripped=false
I LIBLAB: secret=clean-load-token-5aa53cc3
```

**`clean-load-token-5aa53cc3` is the answer.** Every attempt below is judged on one question: did you
get that string out of the process while your instrumentation was attached?

---

## Part 1 — Fail three times

### Attempt 1 — attach and hook the Java method

The obvious move. The app is running; hook the method that returns the wrong answer.

```javascript
// frida -U -n com.liblab.guarded -l attempt1.js
// Attach to the RUNNING app and hook the Java surface.
Java.perform(function () {
  const Guard = Java.use("com.liblab.guarded.Guard");
  Guard.tripped.implementation = function () {
    console.log("[*] tripped() called; forcing false");
    return false;
  };
  console.log("[+] hooks installed");
});
```

```bash
# host
adb shell am start -n com.liblab.guarded/.MainActivity
frida -U -n com.liblab.guarded -l attempt1.js
# then rotate the device or relaunch the activity
```

**Q1.** What does `secret()` return now? Why did forcing `tripped()` to `false` not change it?

**Q2.** You could hook `secret()` too and return a string of your choosing. Why is that not a
solution? (The answer is not "it is inelegant". Look at what the token is derived from.)

### Attempt 2 — spawn instead of attach, and hook `JNI_OnLoad`

"Attach was too late. Spawn, and get in before the library loads."

```javascript
// frida -U -f com.liblab.guarded -l attempt2.js --no-pause
// Spawn-gated: our code runs before the app's first instruction. Then hook
// JNI_OnLoad, which is the first thing in the library that has a name.
const t0 = Date.now();
function log(m) { console.log("[+" + (Date.now() - t0) + "ms] " + m); }

log("script loaded; app has not started yet");

const dlopenExt = Module.findExportByName(null, "android_dlopen_ext");
Interceptor.attach(dlopenExt, {
  onEnter(args) { this.path = args[0].isNull() ? null : args[0].readCString(); },
  onLeave(retval) {
    if (!this.path || this.path.indexOf("libguarded.so") < 0) return;
    log("libguarded.so is now loaded: " + this.path);
    const jniOnLoad = Module.findExportByName("libguarded.so", "JNI_OnLoad");
    Interceptor.attach(jniOnLoad, {
      onEnter() { log("JNI_OnLoad entered -- installing our fix now"); }
    });
  }
});
```

**Q3.** Read the logcat and the Frida output together. In what order did these four things happen?

- your script loaded
- `android_dlopen_ext` returned
- `constructor ran:` appeared in logcat
- `JNI_OnLoad entered` appeared in Frida

**Q4.** You spawned. You were present from the first instruction of the process. Why was that *still*
not early enough?

### Attempt 3 — hook `dlopen` and fix it in `onLeave`

"Fine — I will not wait for `JNI_OnLoad`. I will act the moment `dlopen` returns."

Modify attempt 2 so that `onLeave` looks up the module, finds the guard's state, and repairs it.

**Q5.** Try to write that hook. You will immediately hit a problem that is not about timing at all.
What is it? (Look at your `readelf --dyn-syms` output again.)

**Q6.** Even setting that problem aside: at the moment `android_dlopen_ext` returns, how many of the
library's constructors have run? Where exactly, in the sequence, does the linker call them?

---

## Part 2 — Prove the ordering

Stop guessing. Measure.

```bash
# host — the ordering, from the target's own logs
adb logcat -c
adb shell am start -n com.liblab.guarded/.MainActivity
adb logcat -d -v time | grep -E 'libguarded|LIBLAB'
```

```javascript
// frida -U -f com.liblab.guarded -l timeline.js --no-pause
// One timeline, four events, real timestamps.
const t0 = Date.now();
const at = () => "[+" + (Date.now() - t0) + "ms] ";

console.log(at() + "spawn gate: script running. Modules already mapped:");
Process.enumerateModules().slice(0, 8).forEach(m => console.log("    " + m.name));

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
  onEnter(args) {
    this.path = args[0].isNull() ? "(null)" : args[0].readCString();
    if (this.path.indexOf("libguarded") >= 0) console.log(at() + "dlopen ENTER " + this.path);
  },
  onLeave(retval) {
    if (this.path && this.path.indexOf("libguarded") >= 0) {
      console.log(at() + "dlopen LEAVE -> " + retval);
      const m = Process.findModuleByName("libguarded.so");
      console.log(at() + "  module base " + (m ? m.base : "not found"));
    }
  }
});

// __android_log_print is in liblog.so, which is mapped long before our target.
// Hooking it lets us timestamp the guard's own log line from OUTSIDE it.
const alp = Module.findExportByName("liblog.so", "__android_log_print");
if (alp) {
  Interceptor.attach(alp, {
    onEnter(args) {
      const tag = args[1].isNull() ? "" : args[1].readCString();
      if (tag === "libguarded") console.log(at() + "  guard logged: " + args[2].readCString());
    }
  });
}
```

**Q7.** Write down the observed order. It should be:

```text
spawn gate  ->  dlopen ENTER  ->  guard logged "constructor ran"  ->  dlopen LEAVE
            ->  JNI_OnLoad    ->  Java code
```

The guard's log line appears **between** `dlopen ENTER` and `dlopen LEAVE`. Say what that means in
one sentence, without using the word "somehow".

**Q8.** At the spawn gate, which modules were already mapped? List them. This is the single most
important observation in the lab, and part 3 is built entirely on it.

**Q9.** Chapter §9.1 makes the same point with two log lines. Why is the timestamped, externally
observed version worth doing anyway?

> **🔬 Under the Hood**
> `dlopen` on Android goes through `android_dlopen_ext` into the linker's loader, which maps the
> segments, applies relocations, resolves symbols, applies RELRO protections, and then — as the last
> step before returning — walks `DT_INIT` and `DT_INIT_ARRAY` and calls every function pointer it
> finds. All of that happens inside one call that has not returned. The AOSP source is
> `bionic/linker/linker.cpp` and `bionic/linker/linker_soinfo.cpp`; see also
> `bionic/linker/linker_main.cpp` for the process-startup path. Note in passing that
> `DT_PREINIT_ARRAY` is processed **only for the executable**, never for a shared library — so
> `.preinit_array` is not a place an SDK can hide, however much it might want to.

---

## Part 3 — Five ways in

### Method 1 — Hook the layer that is already loaded

**This is the general answer, and it is a layering argument rather than a trick.**

Q8 told you that at the spawn gate `libc.so`, `libdl.so`, `liblog.so` and the linker are already
mapped. `libguarded.so` is not. You cannot hook a function in a library that does not exist — but the
guard does not do its work alone. It calls `fopen`, `fgets`, `strstr`, `fclose`. Every one of those
lives in a library that has been mapped since before your script ran.

**So do not hook the code that checks. Hook the thing it asks.**

```javascript
// frida -U -f com.liblab.guarded -l method1-libc.js --no-pause
// Install at the spawn gate, into libc, which is already mapped. When the
// guard's constructor runs -- later, inside dlopen, in a library that does
// not yet exist -- it calls straight into these hooks.
const NEEDLES = /frida|gum-js-loop|gadget|linjector|re\.frida/i;

const fgets = Module.findExportByName("libc.so", "fgets");
Interceptor.attach(fgets, {
  onEnter(args) { this.buf = args[0]; this.size = args[1].toInt32(); },
  onLeave(retval) {
    if (retval.isNull()) return;
    let line;
    try { line = this.buf.readCString(); } catch (e) { return; }
    if (!line) return;

    let replacement = null;
    if (line.indexOf("TracerPid:") === 0 && line.indexOf("TracerPid:\t0") !== 0) {
      replacement = "TracerPid:\t0\n";
    } else if (NEEDLES.test(line)) {
      // Rewrite rather than drop: dropping a line means faking a whole read
      // loop, and a benign-looking mapping is indistinguishable to a
      // substring search.
      replacement = "7f0000000000-7f0000001000 r--p 00000000 00:00 0 \n";
    }
    if (replacement !== null && replacement.length < this.size) {
      this.buf.writeUtf8String(replacement);
      console.log("[*] rewrote a line the guard was about to read");
    }
  }
});

console.log("[+] libc hooks installed at the spawn gate, "
          + "before the target library exists");
```

```bash
# host
frida -U -f com.liblab.guarded -l method1-libc.js --no-pause
adb logcat -d | grep -E 'libguarded|LIBLAB'
```

Expected: `verdict=0`, and `secret=clean-load-token-5aa53cc3` — the real token, produced by the
library itself, with your instrumentation attached the whole time.

**Q10.** This works, and it is also a blunt instrument. What else in the process reads through
`fgets`? What could that break, and how would you narrow the hook so that it only lies to the caller
you care about?

**Q11.** The guard could have used `open`/`read` instead of `fopen`/`fgets`, or issued the `openat`
syscall directly with inline assembly. At each of those layers, what is the last thing that is still
already-loaded and hookable? Where does this approach finally run out?

### Method 2 — Repair the verdict afterwards

The verdict is a variable, written once and read later. If you can find it, you can rewrite it.

`g_analysis_detected` is `static`, so it has no symbol. But `Java_com_liblab_guarded_Guard_tripped`
does, and its entire body is "load that variable and return it".

```bash
# host — three instructions, one of which contains the address
objdump -d --start-address=... libguarded.so | less
# or open it in Ghidra and read the function
```

On AArch64 you are looking for `adrp x8, <page>` followed by `ldr w0, [x8, #<offset>]`. The variable
is at `page + offset`, relative to the module base.

```javascript
// frida -U -f com.liblab.guarded -l method2-patch.js --no-pause
// Let the guard run and reach the wrong conclusion, then correct the record.
const OFFSET_DETECTED = 0x0;   // <-- fill in from your disassembly
const OFFSET_SEED     = 0x0;   // <-- and this one

Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
  onEnter(args) { this.path = args[0].isNull() ? null : args[0].readCString(); },
  onLeave(retval) {
    if (!this.path || this.path.indexOf("libguarded.so") < 0) return;
    const m = Process.getModuleByName("libguarded.so");
    m.base.add(OFFSET_DETECTED).writeU32(0);
    m.base.add(OFFSET_SEED).writeU32(0x5AA53CC3);
    console.log("[*] verdict and seed corrected post hoc");
  }
});
```

**Q12.** You had to patch **two** variables, not one. Why? What does that tell you about the design
of a check whose result poisons a *value* rather than setting a *flag*?

**Q13.** Suppose the constructor had used the verdict immediately — say, as one input to a key
derivation — and then zeroed it. Would method 2 still work? Would method 1?

> **⚠️ Warning**
> Method 2 is the one people reach for because it is concrete, and it is the one that fails silently
> on real targets. Any check whose result is *consumed and discarded* inside the constructor is
> immune to it. Method 1 is immune to that counter-move, because it lies to the check itself.

### Method 3 — Patch the library on disk

No instrumentation at all. Change the file so the constructor never does anything.

The chain, which is a good half-hour of ELF work:

1. Find `.init_array` and read its contents. On a PIE shared object the slots are filled in at load
   time by **relocations**, so the raw bytes in the file may be zero or may be a link-time address.
2. Find the `R_AARCH64_RELATIVE` relocation in `.rela.dyn` whose `r_offset` is that slot. Its
   **addend** is the offset of `early_guard`.
3. That is the function's address — the name never existed, but the relocation had to point
   somewhere.
4. Patch its first instruction to `RET` (`0xd65f03c0`, little-endian `c0 03 5f d6`).

```bash
# host
readelf -S --wide libguarded.so | grep -E 'init_array|rela\.dyn'
readelf -r libguarded.so | grep -i relative | head
# then patch at the file offset with any hex editor, or:
python3 - <<'PY'
data = bytearray(open("libguarded.so","rb").read())
off = 0x0            # <-- file offset of early_guard, from step 3
data[off:off+4] = bytes.fromhex("c0035fd6")
open("libguarded.so","wb").write(data)
PY
```

Then repackage and re-sign the APK — see [10-APK-Internals](../../10-APK-Internals/README.md).

**Q14.** Why can you not simply zero the `.init_array` slot in the file and be done?

**Q15.** What does this method cost you that methods 1 and 2 do not? (Two things: one about the
artifact, one about what any *other* integrity check in the app will now notice.)

### Method 4 — Get between the map and the call

The linker maps the library, then calls its constructors. If you can hook the linker function that
performs the second step, you own the exact window.

```javascript
// Frida REPL -- what can we actually see inside the linker?
Process.enumerateModules()
  .filter(m => /linker/.test(m.name))
  .forEach(m => {
    console.log(m.name + " " + m.base);
    Module.enumerateSymbols(m.name)
      .filter(s => /call_constructor|do_dlopen|soinfo/.test(s.name))
      .slice(0, 20)
      .forEach(s => console.log("   " + s.address + "  " + s.name));
  });
```

If `__dl__ZN6soinfo17call_constructorsEv` or something like it is resolvable, attaching to it gives
you control after mapping and relocation but before a single constructor has executed — which is
precisely the window that does not otherwise exist.

**Q16.** Run the enumeration on your device. What is actually available? Why is this method the most
powerful and the least dependable of the five? (Two independent reasons: one about symbols, one about
Android versions.)

### Method 5 — Be there before the process is

`wrap.<package>` is a platform property that makes Zygote launch a specific app under a wrapper
command. It is the earliest hook that exists on Android, because it changes how the process is
created rather than what happens inside it.

```bash
# adb shell — debuggable app on a user build, or any app on userdebug/eng
setprop wrap.com.liblab.guarded '"LD_PRELOAD=/data/local/tmp/shim.so"'
am force-stop com.liblab.guarded
am start -n com.liblab.guarded/.MainActivity
```

Your `shim.so` is loaded by the dynamic linker *before the application's own code runs at all*, so
its constructors run before everything in this lab.

**Q17.** What are the practical limits of this on a modern device? (Property naming and app
debuggability are both worth checking on the device in front of you rather than trusting a blog
post.)

**Q18.** Rank all five methods for an engagement where you have a rooted test device, no source, and
a deadline. Justify first place in one sentence.

---

## Part 4 — Make it harder

Change the target so each of your methods breaks in turn. This is where the lab stops being an
exercise and starts being research.

1. **Consume the verdict immediately.** Derive the seed from the check result inside the constructor
   and zero the flag before returning. Which methods still work?
2. **Use `openat` directly** instead of `fopen`, then use inline syscalls instead of `openat`. At
   which step does method 1 finally stop being available, and what is left after it?
3. **Load the guarded library from native code.** Add a second, innocuous `.so` that the app loads
   with `System.loadLibrary`, and have *its* constructor `dlopen` the guarded one. Now every hook
   that keyed on `System.loadLibrary` sees nothing.
4. **Two constructors with priorities.** Add `__attribute__((constructor(102)))` alongside the
   existing one and confirm the order. Does your `.init_array` count change? Does the inventory
   script notice?
5. **Check for the check.** Have the constructor verify that `fgets` in libc still starts with the
   bytes it expects. Now method 1 leaves a trace. What would you do about it, and what does that cost
   in reliability?

**Q19.** After change 3, what is the earliest observable event that still tells you a library was
loaded? (It is not a Java hook.)

---

## Hints

<details>
<summary>Hint — Q2, why faking the Java return value is not a solution</summary>

Look at what `secret()` builds its answer from:

```c
snprintf(out, sizeof(out), "clean-load-token-%08x", g_seed);
```

and at what sets `g_seed`:

```c
g_seed = g_analysis_detected ? 0xDEADBEEFu : 0x5AA53CC3u;
```

The verdict does not gate a message. It selects a **value**, and everything downstream is computed
from that value. You can make the Java layer return any string you like, but you cannot make it
return the *correct* string, because you do not have the number — the number only exists inside a
process where the check passed.

This is not an artificial construction. It is how competent anti-tamper is built, and the reason is
exactly this: a boolean can be flipped, but a value that feeds a key derivation, a checksum, or a
decryption cannot be guessed. Chapter 40 makes the same point about packers from the other
direction.
</details>

<details>
<summary>Hint — Q5, the problem that is not about timing</summary>

`early_guard` is declared `static`. In C that means internal linkage: the name is never emitted into
the symbol table at all. `readelf --dyn-syms` will never show it, `Module.findExportByName` will
never find it, and `frida-trace -I` will never generate a stub for it.

It is still perfectly reachable — the `.init_array` relocation has to point at it, and that pointer
is right there in the file. But you have to go and find it, and "the function has no name" is a
different obstacle from "I attached too late". Distinguishing the two is the point of the question.
</details>

<details>
<summary>Hint — Q8, the modules mapped at the spawn gate</summary>

You will see roughly: the linker (`linker64`), `libc.so`, `libdl.so`, `libm.so`, `liblog.so`, and
some of the runtime. You will **not** see `libguarded.so`.

That asymmetry is the whole of part 3, method 1. You cannot instrument a library that has not been
loaded — but every library that will ever be loaded has to make its system calls through the ones
that already are. Hook downward, into what exists, and you are automatically present when the code
above it appears.

Generalise it: **when you cannot be early enough for the code, be early enough for what the code
depends on.**
</details>

<details>
<summary>Hint — Q11, where method 1 runs out</summary>

The ladder, from most hookable to least:

| Layer | Hookable at spawn? | Notes |
|---|---|---|
| `fopen`/`fgets` (stdio) | Yes | Exported by libc, resolved through the PLT on the first call |
| `open`/`read`/`openat` (POSIX wrappers) | Yes | Also exported libc symbols |
| The raw `svc #0` instruction, inline in the target | **No** | There is no symbol and no call. The instruction is inside a library that does not exist yet |

When the target issues syscalls inline, you have left the "hook a function" world. What is left:
`ptrace`-based syscall interception, a seccomp filter with `SECCOMP_RET_TRAP`, a kernel-side tracer,
or — most practically — going back to methods 2 through 5, which do not depend on function calls at
all.

Knowing where a technique ends is more useful than knowing that it works.
</details>

<details>
<summary>Hint — Q14, why zeroing the .init_array slot is not enough</summary>

A shared library is position-independent, so it cannot contain absolute addresses at build time. The
slot in `.init_array` is filled in **at load time**, by a `R_AARCH64_RELATIVE` relocation that says
"take my addend, add the load base, store the result at this offset".

Zero the slot in the file and the linker will helpfully write the correct pointer back over your
zero during relocation, because the relocation is what actually determines the value.

You have two real options: neutralise the relocation itself (in `.rela.dyn`), or leave the pointer
alone and patch the *function* it points at. The second is easier to get right and easier to reverse,
which is why it is the one the lab walks.
</details>

---

## Solution notes

<details>
<summary>Q3 and Q7 — the observed ordering, and the sentence to remember</summary>

```text
[+0ms]    spawn gate: script running
[+312ms]  dlopen ENTER /data/app/.../lib/arm64/libguarded.so
[+318ms]    guard logged: constructor ran: traced=0 mapped=0 verdict=0
[+319ms]  dlopen LEAVE -> 0xb400007...
[+319ms]  JNI_OnLoad entered
[+325ms]  Java: tripped=false
```

Roughly six milliseconds between `dlopen ENTER` and the constructor's log line, and one more before
`dlopen LEAVE`. There is no point in that window where control returns to anything you wrote.

The sentence:

> The constructor runs inside `dlopen`, so any hook installed in `onLeave` — or anywhere downstream
> of it — is installed after the decision it was meant to influence.

And the corollary, which is the actually useful half:

> Therefore the only code that can observe the constructor is code that was already running when
> `dlopen` was called.
</details>

<details>
<summary>Q12 — flag versus value, and what it means for your methodology</summary>

Two variables because the check produces two effects: a boolean that gates behaviour, and a number
that everything downstream is computed from. Patch the boolean alone and `tripped()` returns `false`
while `secret()` still returns the wrong token — a *partial* bypass, which is the most dangerous
outcome available, because it looks like success.

The methodology consequence is a habit, not a fact: after any bypass, verify against a **known-good
baseline** you captured before you started. That is why this lab makes you record
`clean-load-token-5aa53cc3` in the setup and not at the end. Without the baseline you have no way to
tell a real bypass from a plausible-looking one, and "the app did not crash" is not a test.
</details>

<details>
<summary>Q18 — the ranking, and the reasoning</summary>

1. **Method 1 (hook libc at the spawn gate).** First because it needs no static analysis, no
   repackaging, no root beyond what you already have, and it generalises: the same script works
   against the next app with a different guard, because it targets the *questions* rather than the
   code that asks them.
2. **Method 5 (`wrap.` property).** Earliest of all, and the right answer when the target has already
   loaded something before Frida's gate. Costs a device configuration and a shim you have to build.
3. **Method 4 (linker `call_constructors`).** Exactly the right window, when the symbols happen to be
   there. Version-fragile.
4. **Method 3 (patch the file).** Reliable and permanent, and it is the answer when you need a target
   that stays defeated. Costs repackaging and re-signing, changes every hash, and trips any integrity
   check the app also has.
5. **Method 2 (repair afterwards).** Last, despite being the most intuitive, because it only works
   when the verdict persists — and you cannot know that it persists until you have already done the
   static analysis that would have made method 3 available.

The general principle underneath all five: **do not fight for the window; take the layer below it.**
</details>

---

## Success criteria

- [ ] You produced `clean-load-token-5aa53cc3` from a process with instrumentation attached, by at
      least **two** different methods.
- [ ] You have a timeline showing the constructor's log line strictly between `dlopen` enter and
      `dlopen` leave, with timestamps you gathered.
- [ ] You can explain, without the word "somehow", why a `Java.perform` hook cannot observe
      `.init_array` code — and why spawning does not fix that on its own.
- [ ] You located `early_guard` in a stripped-of-symbols sense: you found a function that has no name
      by following the relocation that points at it.
- [ ] You can name what is already mapped at the Frida spawn gate, and explain why that list is the
      basis of method 1.
- [ ] You attempted at least two of the part 4 hardening changes and can say which of your methods
      survived each.
- [ ] You can state the one-sentence generalisation of method 1 and apply it to a check you have not
      seen yet.

---

## Where to go next

| Next | Why |
|---|---|
| [Lab 05 — The library that lied](lab-05-ctf-library-that-lied.md) | A constructor that does something worse than check for you |
| [37-RootDetection](../../37-RootDetection/README.md) | The same layering argument, applied to a whole category of checks |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What happens when the constructor is also obfuscated, and where that chapter's lab 04 meets this one |
| [57-Ghidra](../../57-Ghidra/README.md) | For method 3, when reading the disassembly is the shortest path |
| [Chapter 17 §7.2](../README.md#7-dynamic-analysis) | Re-read the `dlopen` tracing section; it will read differently now |
