# 53 — Frida · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. Everyone says "inject". What is actually being injected, and into what?**

A shared library — `frida-agent.so` — is loaded into the target app's process, exactly as if the app
had called `System.loadLibrary` on it. That library contains a complete JavaScript engine and a set of
bindings. Your `.js` file is not injected; it is sent over a socket to the engine that is already
running inside the app and evaluated there.

The "injection" part is getting that library loaded into a process that never asked for it. Frida does
it by `ptrace`-attaching to the process, hijacking one of its threads, making that thread call `mmap`
to allocate a page of executable memory *in its own address space*, writing a small piece of machine
code into that page, and pointing the thread's program counter at it. That code calls
`android_dlopen_ext` to load the agent. Then the original registers are restored and `ptrace` detaches.

Everything after that is normal in-process code. There is no ongoing debugger relationship.

---

**2. Why does `frida --version` matter so much?**

Because the host tool and `frida-server` speak a wire protocol that changes between major versions,
and Frida does not negotiate down. A 17.x host and a 16.x server produce
`unable to communicate with remote frida-server; please ensure that major versions match` and nothing
else. Fetch the `frida-server` asset whose version string exactly equals your `frida --version`
output.

The second half of the same problem is the ABI. A 64-bit `frida-server` cannot inject into a 32-bit
process. If a device is `arm64-v8a` but the app ships only `armeabi-v7a` native libraries, the app runs
32-bit and you need the `arm` server as well.

There is a third half, and it is not a version *mismatch* at all — the server can be the right
version and the right ABI and still refuse to start, because it was **built with a toolchain newer
than the device image's dynamic linker**. See question 2a.

---

**2a. `frida-server` prints `CANNOT LINK EXECUTABLE … empty/missing DT_HASH/DT_GNU_HASH`. Is my
device broken? Did I lose root?**

No to both. Verbatim, after several hundred `unused DT entry` linker warnings:

```
CANNOT LINK EXECUTABLE "/data/local/tmp/frida-server": empty/missing DT_HASH/DT_GNU_HASH in
"/data/local/tmp/frida-server" (new hash type from the future?)
```

The binary was produced by a toolchain newer than that image's linker understands. It is a
**Frida-build problem, not a root problem and not a device problem** — `su 0 id` returns uid 0 on
the same device seconds later. This is the state of the AVD this repository was written against:
`sdk_gphone16k_x86_64` (`emu64xa16k`), **Android 15 / API 35, x86_64**, rooted with Magisk 30.7. It
is a known failure mode on recent API-35 x86_64 images generally, not a quirk of one machine.

Two things you need to know about it:

- **`frida-ps -U` still enumerates processes while this is happening.** The failure appears only on
  attach. If you smoke-test with `frida-ps` you will conclude Frida works and then debug a script
  that was never going to run.
- **Nothing else is affected.** Root, SELinux, `adb`, `su`, and every non-Frida technique in the
  repository still work on that device.

The fix is to match the `frida-server` build to the image (or use an image the build supports).
Where you cannot, `frida-gadget` avoids the standalone binary entirely — it is loaded by the app
itself — and §§1–6 of the chapter, including the miniature-Frida build in §4.4, need no server at
all. The full disclosure, with the table of what to do instead, is
[at the top of the chapter](README.md#-read-this-before-you-install-anything-frida-server-does-not-run-on-every-image).

Frida is not broken in general. This is one named, reproducible, version-specific failure, and on a
matched host/image pair everything in this chapter runs as written.

---

**3. My hook installs without any error and never fires. What is going on?**

Four causes, in order of frequency. Work them in order and never skip one.

1. **The method was inlined.** The optimizing compiler copied its body into the caller, so there is no
   call instruction and the entry point you rewrote is never consulted. Fix:
   `adb shell cmd package compile -m verify -f <pkg>`, then `am force-stop`, then re-run. If the method
   is missing from JADX output entirely, R8 inlined it at build time instead and no runtime trick
   recovers it — hook the callers.
2. **Wrong `ClassLoader`.** This throws `ClassNotFoundException`, so if you got no exception it is not
   this one.
3. **Wrong overload.** You hooked `check(String)`, the app calls `check(String, boolean)`.
4. **You attached instead of spawning**, so the code ran before you arrived.

Detection is the *last* thing to consider, and it looks different: the process dies, exits, or shows a
dialog. A hook that installs cleanly and silently never fires is almost never detection.

---

**4. Why is `-f` so much better than `-n`? It seems like a small difference.**

It is the difference between being present for the app's entire life and arriving after the
interesting part is over. `-f` asks the device to start the process and hold it suspended *before any
application code executes*, injects your agent, and only then resumes.

What runs before you could possibly attach with `-n`:

- The `Application` subclass's static initialiser
- `Application.attachBaseContext` — where packers decrypt their real DEX and where anti-debug checks
  live specifically because it is early
- `Application.onCreate` — analytics, pinning configuration, `System.loadLibrary`
- Any `ContentProvider`'s `onCreate`, which happens before `Application.onCreate`
- Native `__attribute__((constructor))` functions inside every loaded `.so`

By the time a human sees the app on screen and types a command, all of that is seconds in the past.

---

**5. `Java.use` throws `ClassNotFoundException` for a class I can see clearly in JADX. Why?**

Because `Java.use` resolves names through one specific `ClassLoader` — `Java.classFactory.loader` —
and your class is in a different one.

Java class loading delegates *upward*: a loader asks its parent first, and only searches its own path
if the parent cannot help. That means a child can see everything its parent can, but a parent cannot
see its children's classes. `Java.classFactory.loader` points at the `PathClassLoader` for `base.apk`.
A class that arrived in a downloaded `plugin.dex` (`DexClassLoader`) or was decrypted into memory
(`InMemoryDexClassLoader`) lives in a *child* of that loader, and is invisible from where you are
standing.

Fix:

```javascript
Java.enumerateClassLoaders({
  onMatch(loader) {
    try { loader.loadClass("com.example.secret.Engine"); } catch (e) { return; }
    const Engine = Java.ClassFactory.get(loader).use("com.example.secret.Engine");
    // hook Engine here
  },
  onComplete() {}
});
```

Or use `cls.use("com.example.secret.Engine")` from
[`scripts/class-enumerator.js`](scripts/class-enumerator.js), which does exactly this.

---

**6. Do I really need root?**

For the standard `frida-server` workflow, yes: injection needs `ptrace` on a process owned by a
different UID, and only root can do that. The alternatives all avoid root by changing the APK instead:

| Path | Root | Re-signs the APK |
|---|---|---|
| `frida-server` | yes | no |
| `frida-gadget` embedded | no | **yes** |
| `frida-apk --debuggable` | no | **yes** |
| Magisk module running the server | Magisk | no |

There is no configuration that avoids both. If the app checks its own signing certificate, or if the
server does, the re-signing paths are visible.

---

**7. What is `frida-gadget` exactly, and why is the config file named `.so` when it is JSON?**

The gadget is Frida packaged as a shared library that the *target loads itself*, rather than a server
that injects from outside. You put `libgadget.so` in the APK's `lib/<abi>/` directory and add a
`System.loadLibrary("gadget")` to the earliest class initialiser you can find. When the app loads it,
the gadget starts and either waits for you to connect or runs a script on its own.

The config file is named `libgadget.config.so` because Android's packaging and installation tooling
only extracts files from `lib/<abi>/` that look like native libraries — the name must begin with `lib`
and end with `.so`. The contents are JSON regardless of the extension; nothing tries to `dlopen` it.

---

**8. What does `Java.perform` actually do, and why does my code abort without it?**

Every call into ART goes through JNI, and JNI requires that the calling thread is attached to the Java
VM and holds a valid `JNIEnv`. `Java.perform` attaches the current thread if it is not already
attached, sets up the class factory, runs your callback, and detaches cleanly. Without it you get
`JNI DETECTED ERROR IN APPLICATION: a thread ... making JNI calls without being attached`, which is an
`abort()`, not a catchable exception — the process dies.

Use `Java.performNow` when you already know you are on a VM thread (for example, inside a Java hook)
and want the callback to run synchronously rather than being scheduled.

---

**9. I get a stack overflow inside my hook and the app crashes. What did I do?**

You almost certainly called the original method through the class wrapper instead of through `this`:

```javascript
const C = Java.use("com.example.C");
C.m.implementation = function (a) {
  return C.m(a);          // WRONG — re-enters your own hook, forever
};
```

The wrapper's `m` *is* your hook now. Use `this.m(a)`, or for a specific overload,
`ov.apply(this, arguments)`. This is the second most common self-inflicted Frida bug.

---

**10. When do I need `.overload()` and what exactly do I pass to it?**

Whenever the method name has more than one signature. Frida will tell you:
`check(): has more than one overload, use .overload(<signature>) to choose`. The dangerous case is
silent: if there is only one overload, you hook it happily — even when the app calls a *different*
method with the same name on a different class.

Always list first:

```javascript
Java.use("com.example.C").check.overloads.forEach((ov, i) =>
  console.log(i, ov.argumentTypes.map(t => t.className).join(", ")));
```

The strings are Java *binary* names, not source names and not JVM descriptors:

| Source | String |
|---|---|
| `byte[]` | `"[B"` |
| `String[]` | `"[Ljava.lang.String;"` |
| `Outer.Inner` | `"com.example.Outer$Inner"` |
| `List<String>` | `"java.util.List"` (generics are erased) |
| `f(String...)` | `"[Ljava.lang.String;"` |
| constructor | member name `$init` |

---

**11. What is the difference between `Interceptor.attach` and `Interceptor.replace`?**

`attach` leaves the original function alone and runs your `onEnter` and `onLeave` callbacks around it.
The program still works; you are watching, and can modify arguments and the return value.

`replace` substitutes your function for the original completely. The original does not run unless you
saved a `NativeFunction` pointing at it and call it yourself. Use `replace` when you want to *neutralise*
something — a root check, a verification callback.

The trap with `replace` is reentrancy: calling the function you replaced, by address, goes through your
replacement again. Save a `NativeFunction` to the original address *before* replacing, and call that.

---

**12. My script worked for ten minutes and then the app crashed somewhere completely unrelated.**

Almost certainly a garbage-collected `NativeCallback`. The `NativeCallback` object is a JavaScript
object that owns a native trampoline; if the last JavaScript reference to it goes out of scope, the
JS garbage collector frees the trampoline while native code still holds its address. The next call
jumps into freed memory.

```javascript
const KEEP = [];                                  // module scope
const cb = new NativeCallback(fn, "int", []);
KEEP.push(cb);                                    // now it survives
Interceptor.replace(addr, cb);
```

The same applies to `Memory.alloc` results that native code stores for later.

---

**13. What is Stalker for? `frida-trace` seems easier.**

`frida-trace` hooks functions you can name. Stalker traces every instruction a thread executes,
whether or not anything has a name. Reach for it when:

- The function you need is **not exported** and you cannot find it statically.
- Control flow is **flattened or virtualised** and reading the disassembly is hopeless.
- You want to know **which basic blocks ran for input A but not input B** — feed a correct PIN and a
  wrong PIN, diff the block sets, and the difference is the validation logic.
- The target **verifies the integrity of its own code**. `Interceptor` writes a few bytes at the
  prologue; Stalker instruments a relocated *copy* and never touches the original.

The cost is a ten- to hundred-fold slowdown on the followed thread. Manage it with
`Stalker.exclude(Process.getModuleByName("libc.so"))` and friends, prefer `compile` events over `exec`
events, never `console.log` from a callout on a hot path, and always `unfollow` then `garbageCollect`.

---

**14. Why do my backtraces come back empty?**

`Backtracer.ACCURATE` walks the stack using frame pointers or unwind tables. Android release builds
are compiled with frame-pointer omission and often without full unwind info, so there is nothing to
walk and you get one frame or none.

Fall back to `Backtracer.FUZZY`, which scans the stack for values that look like return addresses. It
almost always produces output — but stale return addresses from calls that already returned are still
lying on the stack, so some of those frames are not in the current call chain. Treat `FUZZY` output as
*candidates to verify*, not as a call chain.

On Android the Java stack trace is usually more useful anyway, because it names the app's own classes:

```javascript
Java.use("android.util.Log")
    .getStackTraceString(Java.use("java.lang.Exception").$new());
```

---

**15. The app is fully obfuscated — every class is `a.b.c`. Where do I even start?**

Hook the **platform**, not the app. R8 can rename the app's own classes; it cannot rename
`javax.crypto.Cipher`, `okhttp3.CertificatePinner` or `java.io.FileOutputStream`. Every interesting
operation eventually crosses into platform code.

So: hook `Cipher.doFinal`, print a Java stack trace on every call, exercise the feature, and read the
frames below yours. Those frames are the app's obfuscated classes — and now you know their names. That
is the whole technique, and it works on nearly everything.

`trace.framework()` in [`scripts/java-method-tracer.js`](scripts/java-method-tracer.js) installs the
standard set for you.

---

**16. Is Frida detectable? Everyone claims their bypass is "undetectable".**

Yes, trivially, by a dozen independent signals: `frida-agent.so` in `/proc/self/maps`, threads named
`gum-js-loop` and `gmain` in `/proc/self/task/*/comm`, a listening socket on port 27042, a non-zero
`TracerPid` during the attach window, modified prologue bytes at hooked functions, and timing anomalies.

Every one of those checks can also be defeated, because every one of them executes inside a process
you control. That is the whole point: it is an arms race inside the attacker's own territory, and the
attacker always eventually wins. The defender's correct conclusion is that client-side detection buys
hours, and that the security-relevant decision belongs on the server or in the TEE.

"Undetectable" claims usually mean "defeats the specific checks the author tested against".

---

**17. Should I use `Java.deoptimizeEverything()` or `cmd package compile -m verify -f`?**

Prefer the command, for three reasons. It changes the app's compilation state **on disk before the
process starts**, so even code in `<clinit>` and `attachBaseContext` runs interpreted — deopting from
a script is already too late for that. It does not leave ART's instrumentation machinery visibly
active, which a timing-sensitive app can detect. And it does not slow the entire runtime for the whole
session.

Use `Java.deoptimizeEverything()` when you cannot change the app's compilation state — a device you do
not control, or an app you cannot force-stop.

Remember to run `cmd package compile --reset <pkg>` before you write the finding up, and confirm it
still reproduces.

---

**18. Frida hooks everything successfully but Burp still shows nothing. Why?**

The app's TLS stack is native. Flutter, Cronet, React Native's networking layer, Unity and any app
with a hand-rolled `.so` may perform the entire TLS handshake in native code with a statically linked
BoringSSL. No Java hook reaches that code, so every Java-level hook you installed reports success and
changes nothing.

Hook the native side instead: `SSL_CTX_set_custom_verify` (modern BoringSSL) and `SSL_CTX_set_verify`
(classic OpenSSL), replacing the verification callback with one that always accepts. Note that the
symbol may live in the app's own library rather than `libssl.so`, so search *every* loaded module —
[`scripts/ssl-pinning-bypass.js`](scripts/ssl-pinning-bypass.js) does this.

The other possibility is that the proxy is not configured at all for the app's traffic, or that the
app ignores the system proxy setting, which some native stacks do.

---

**19. `Module.findExportByName is not a function`. Did I break something?**

No — you are on Frida 17, which reorganised the Module API. Write library code that works on both:

```javascript
function globalExport(name) {
  try { if (typeof Module.getGlobalExportByName === "function")
          return Module.getGlobalExportByName(name); } catch (e) {}
  try { return Module.findExportByName(null, name); } catch (e) { return null; }
}
```

Every script in this chapter's `scripts/` directory contains a version of this helper for exactly this
reason.

---

**20. Why did my script make the app freeze / show "Application Not Responding"?**

Three usual causes, all of them things you did on the app's main thread:

- `Memory.scanSync` over a large range. Filter to anonymous `rw-` ranges first and use the async
  `Memory.scan` for broad sweeps.
- `Stalker.follow` on the UI thread. Ten- to hundred-fold slowdown on a thread that must respond
  within five seconds is an ANR by construction.
- `recv(...).wait()` inside an `Interceptor.onEnter` that fires on the main thread. That blocks the
  JavaScript thread until the host replies. Sometimes that is exactly what you want (an interactive
  allow/deny prompt); usually it is a mistake.

`console.log` from a very hot hook will also do it, because the message queue backs up.

---

**21. How do I hook a native function that has no symbol?**

By module base plus offset. Get the offset from a disassembler
([57-Ghidra](../57-Ghidra/README.md)), then resolve it against the runtime base — which differs every
run because of ASLR:

```javascript
const m = Process.findModuleByName("libnative.so");
Interceptor.attach(m.base.add(0x3e40), { onEnter(args) { /* ... */ } });
```

`nat.offset("libnative.so", 0x3e40)` in [`scripts/native-tracer.js`](scripts/native-tracer.js) does
this with bounds checking. Never write a raw address you saw in a previous run; it will be wrong.

---

**22. `nm` shows no `Java_*` symbols but the app clearly has `native` methods. Where are they?**

The app called `RegisterNatives` from `JNI_OnLoad` instead of relying on name-based lookup. That binds
arbitrary — usually stripped, non-exported — functions to Java method names at runtime, so the mapping
exists only in memory. It is a deliberate obfuscation choice and it is very common.

Recover it by hooking `RegisterNatives` inside `libart.so` and reading the `JNINativeMethod` array it
is passed. `nat.jni()` in [`scripts/native-tracer.js`](scripts/native-tracer.js) does this, tries
several mangled-symbol candidates because the name differs across ART versions, and prints
`module+offset` for each recovered function — which is exactly what you paste into Ghidra.

---

**23. Can I use Frida on an app installed from the Play Store, or do I need the APK?**

You do not need the APK to instrument it — `frida -U -f com.example.app` works on any installed app.
You will *want* the APK for static reconnaissance (class names, native symbols, manifest facts), and
you can pull it:

```bash
adb shell pm path com.example.app
adb pull /data/app/~~xxxx/com.example.app-yyyy/base.apk
```

Note that an app installed from Play has a cloud profile and is therefore likely to be AOT-compiled
with inlining, whereas a sideloaded one usually is not. That difference alone changes whether a hook
fires, which is why `cmd package compile -m verify -f` matters more on Play-installed apps.

---

**24. What is the difference between Frida and Xposed/LSPosed? When would I use each?**

They perform the *same fundamental operation* — rewriting `ArtMethod`'s entry point — but they get
there differently and that changes what they are good for.

| | Frida | LSPosed |
|---|---|---|
| How it gets in | Injects into a running process via `ptrace` | Zygisk injects into **Zygote**, so it is present before the app process even specialises |
| Persistence | Session only | Survives reboots, applies to every launch |
| Detectability of the injection | An injection event exists and leaves traces | No injection event in the app process |
| Language | JavaScript, hot-reloadable | Java/Kotlin module, requires a rebuild |
| Iteration speed | Seconds | Minutes |
| Native instrumentation | First class (`Interceptor`, `Stalker`) | Limited without extra work |

Use Frida for exploration and for anything you will change ten times an hour. Use LSPosed when the
modification must persist, or when the target dies on injection. See
[63-LSPosed](../63-LSPosed/README.md).

---

**25. `frida-server` starts and dies a few seconds later. Nothing in the output.**

Check three places, in this order:

```bash
adb shell "su -c 'dmesg | grep -i avc | tail -20'"     # SELinux denials
adb shell "logcat -b all -d | grep -i frida | tail"    # anything logged
adb shell "su -c 'cat /proc/sys/kernel/yama/ptrace_scope'"   # should be 0
```

Common causes: SELinux denying `execute` on `/data/local/tmp`; a low-memory killer reaping it; a
Magisk module conflict; or the binary being the wrong ABI, which usually fails immediately with a
"not executable" error rather than a delayed death.

Running the server from a Magisk service script rather than an `adb shell` often resolves the SELinux
case, because it inherits a more permissive context.

If it never started at all rather than dying — run it in the foreground once, without `-D`, and read
the output. A `CANNOT LINK EXECUTABLE … DT_HASH/DT_GNU_HASH` there is question 2a, not this one, and
it has a completely different fix.

---

**26. Is it safe to run scripts from `frida --codeshare`?**

Understand what it does: it downloads someone else's JavaScript and executes it inside the process you
are testing, on a device you probably have root on. That is the same trust decision as `curl | sh`.
Read the script first. Most codeshare scripts are fine; the point is that "most" is not a security
property.

The related habit worth building is not running a bypass script you have not read and then concluding
from its silence that the app has no protection. Absence of a log line from someone else's code is not
evidence.

---

**27. My finding only reproduces with `-m verify`. Is it still a finding?**

The vulnerability is a finding; the *reproduction steps* need fixing. The compiler filter affects your
instrumentation, not the app's security properties — a client-side authorisation check is client-side
regardless of how it was compiled.

But a report that says "run this command that changes the runtime configuration, then the bypass
works" will be rejected, and correctly, because the reviewer cannot tell whether you found a real
issue or an artefact. So: after you understand the issue, run `cmd package compile --reset <pkg>`,
restart the app, and demonstrate it again in the app's normal state. If the *demonstration* needs
`verify` but the *issue* does not, say so explicitly and explain why.

---

**28. How do I instrument code that runs in a separate process?**

Find the extra processes first:

```bash
frida-ps -Ua | grep example
# 12043  Example  com.example.app
# 12110  Example  com.example.app:remote
```

Then use child gating from Python, because the CLI instruments one process:

```python
device.enable_child_gating()
device.on("child-added", lambda c: (attach(c.pid), device.resume(c.pid)))
```

The manifest tells you in advance: `grep -oE 'android:process="[^"]*"' AndroidManifest.xml`. A
surprising amount of interesting code — payment SDKs, DRM, WebView renderers — lives in `:remote`
processes, and a single-session test never sees it.

---

**29. What is the fastest way to find out what a button does?**

```bash
frida-trace -U -f com.example.app -j "com.example.*!*"
```

Let it install handlers, press the button, `Ctrl-C`, and read which handlers fired. If the app is
obfuscated so that class names tell you nothing, trace the framework instead:

```bash
frida-trace -U -f com.example.app -j "javax.crypto.*!*" -j "okhttp3.*!*"
```

Then turn on Java stack traces on whichever one fired, and the frames below it name the app's own
class. Two minutes, no disassembler.

---

**30. I keep breaking things. What is the minimum discipline that prevents most problems?**

Six habits:

1. Spawn with `-f`, always.
2. Run `cmd package compile -m verify -f <pkg>` before debugging any hook.
3. List `.overloads` before assigning `.implementation`.
4. Guard every symbol lookup; treat `null` as normal.
5. Keep every `NativeCallback` in a module-scope array.
6. Implement `dispose()` and actually undo your hooks.

Those six prevent the large majority of the failures in this chapter's §11.
