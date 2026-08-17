# 11 — Android Runtime · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

Implementation-level questions (OAT files, `ArtMethod`, garbage collection) are answered in
[13-ART/faq.md](../13-ART/faq.md).

---

**1. What actually *is* a runtime? I keep reading the word and nodding.**

It is a program whose job is to run *your* program. You write instructions in an abstract form
(DEX bytecode). The runtime reads that form and makes the processor do what it says — either by
interpreting each instruction one at a time, or by translating them into real machine instructions
first. While your program runs, the runtime also allocates memory for it, reclaims that memory when it
is no longer used, checks types, and handles exceptions.

The one-sentence version: **the runtime is the translator and the housekeeper**.

---

**2. Why can't Android just run the same Java a desktop runs?**

Three reasons, all practical rather than ideological. Licensing around Java SE was a genuine obstacle
in 2007. The desktop JVM's memory footprint was unsuited to a phone with tens of megabytes of RAM. And
the `.class` file format stores one class per file with a per-class constant pool, which wastes space
and I/O compared to DEX's single shared pool across an entire application — a real difference when
your storage is slow flash.

---

**3. What is the difference between the runtime, the VM, ART and Dalvik?**

"Runtime" and "virtual machine" are used almost interchangeably here. **Dalvik** was Android's VM from
1.0 to 4.4. **ART** replaced it, becoming the default in Android 5.0. Both execute **DEX** bytecode,
which is why the DEX format and Smali syntax survived the transition unchanged. When someone says "the
Android runtime" today they mean ART.

---

**4. My Frida script says `ClassNotFoundException`, but I can plainly see the class in JADX. Is the
app blocking me?**

Almost certainly not. This is the single most misdiagnosed problem in Android dynamic analysis.

`Java.use()` searches one specific `ClassLoader`. If the app loaded that class dynamically — through
`DexClassLoader` or `InMemoryDexClassLoader` — it lives in a *different* loader that `Java.use()` never
looks at. Enumerate the loaders and switch:

```javascript
Java.perform(function () {
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                loader.loadClass("com.example.hidden.Payload");
                console.log("[+] found in " + loader);
                Java.classFactory.loader = loader;
            } catch (e) {}
        },
        onComplete: function () {}
    });
});
```

If that finds it, it was never a protection — it was a loader problem.

---

**5. Why does everyone insist on `frida -f` instead of `frida -n`?**

Because of *when* app code first runs. The earliest app-controlled code in a process is
`Application.attachBaseContext()`, which executes before any Activity and before
`Application.onCreate()`. Packers put their decryption and `ClassLoader` construction there
deliberately.

`frida -U -f <pkg>` starts the process suspended and injects **before** any app code runs.
`frida -U -n <pkg>` attaches to an already-running process, by which point the payload is loaded and
the constructor hook you installed will never fire.

If you are analysing anything that might be packed, spawn.

---

**6. What is parent delegation, in plain terms?**

When you ask a `ClassLoader` for a class, it does not look in its own bag first. It asks its parent,
and its parent asks *its* parent, all the way up to the `BootClassLoader` that holds the framework.
Only if nobody upstream has the class does the loader search its own DEX files.

The point is that an app cannot define its own `java.lang.String` and have the system use it — the
framework's version is found first and wins.

---

**7. So does parent delegation protect me from anything as a defender?**

It protects **platform** classes from being shadowed. That is all. It gives you nothing against an
attacker who controls the app's own process, because that attacker is the one doing the loading. And
`DelegateLastClassLoader` deliberately inverts the order, searching itself before the parent — so when
you see it in a target, note it, because a class that looks like it comes from the framework may be
coming from the app.

---

**8. Is the bytecode verifier a sandbox?**

No, and this misconception causes real design errors. The verifier checks that the bytecode is
internally consistent: field accesses match declared types, jumps land on instruction boundaries,
register types line up. That is a **correctness** property, and its real purpose is to let the compiler
optimise aggressively without re-checking.

It says nothing about what the app is permitted to *do*, and it is bypassed entirely the moment the app
calls into its own native library. The real boundaries are the process/UID line and SELinux.

---

**9. Does `private` protect anything?**

Not from an attacker. `private` is enforced by the *compiler*, not the runtime. Reflection with
`setAccessible(true)` reads private fields freely, and Frida does it routinely. It is a design tool for
managing complexity, not access control. Same for Kotlin's `internal`, which compiles to public with a
mangled name.

---

**10. An app I'm testing loads a DEX file from `/sdcard`. How bad is that?**

Bad. External storage is not private. Another app with storage access — or anyone with ADB or root —
can replace that file. The substituted code then runs **with the victim app's UID, its granted
permissions, and its signature identity**. That is arbitrary code execution in the app's context.

Rate it High when the DEX is on shared storage or fetched over a channel without integrity protection.
Medium when it is app-private but unverified, since exploitation then needs root or a separate write
primitive.

---

**11. The app hashes the DEX before loading it. Is that enough?**

No, and this is a subtle and common mistake. If an attacker can replace the DEX file, they can usually
also replace whatever stores the expected hash — a shared preference, a constant in a patched APK, a
file next to it.

The correct control is a **signature** over the DEX, verified against a **public key pinned inside the
app**, with the private key held server-side. An attacker who cannot sign cannot substitute code, even
with full write access to the file.

---

**12. What does `android:vmSafeMode="true"` do, and why would an app set it?**

It disables JIT and AOT optimisation, so the app runs entirely interpreted. It was introduced as a
workaround for JIT bugs. In the wild it is usually a leftover that nobody removed after the underlying
bug was fixed.

For you it is convenient: an interpreted app is the friendliest possible target for hooking. Worth
noting in a report as a performance concern rather than a security one.

---

**13. Where should I look first when I open an unfamiliar APK?**

`<application android:name>` in the manifest.

If it is something like `com.example.MyApplication`, you are probably looking at a normal app. If it is
a single obscurely-named class — `com.stub.a`, or a name from a known protector — you are looking at a
packer stub, the real code is elsewhere, and your entire approach changes.

```bash
aapt2 dump xmltree app.apk --file AndroidManifest.xml | grep -A2 "E: application"
```

---

**14. What is the difference between `DexClassLoader` and `InMemoryDexClassLoader`, and why do I care?**

`DexClassLoader` takes a **file path**. There is a file on disk you can find and copy.

`InMemoryDexClassLoader` takes a **`ByteBuffer`**. No file is ever written. The payload exists only in
process memory, so any scanner enumerating APK entries or watching the filesystem sees nothing.

That is exactly why the counter-technique is a runtime hook on the constructor rather than a static
scan. Hook the constructor, grab the buffer, write it out.

---

**15. Reflection is everywhere in this app. Is that a finding?**

By itself, no. Reflection is a normal Java technique used by every dependency-injection framework, JSON
parser and serialization library on Android. Reporting "the app uses reflection" is noise.

The finding is **what the reflection reaches**. Hook `Class.forName`, `getMethod` and `Method.invoke`,
log what comes through, and assess *that*. If it is reaching hidden APIs or loading code from an
untrusted source, you have something.

---

**16. What are "hidden APIs" and can I just turn the restriction off?**

Framework methods and fields Google marks as internal and does not guarantee across releases. Since
Android 9 the runtime blocks or warns on reflective access to them, classified by flags in the member's
`access_flags_`.

For research on your own device:

```bash
adb shell settings put global hidden_api_policy 1   # 0=enforce 1=allow all 2=warn
```

Note this resets on reboot and needs root. And note the security lesson: enforcement is in-process,
using in-process data, which is precisely why bypass libraries work at all. It is a compatibility
mechanism, not a security control.

---

**17. My hook fires but the app's behaviour doesn't change.**

Different problem from question 4. The method was probably **inlined** into its caller by the
optimizing compiler, so the call site your hook was waiting for no longer exists in the compiled code.

```bash
adb shell cmd package compile -m verify -f com.example.target
adb shell am force-stop com.example.target
```

That forces everything back into the interpreter, where every call dispatches through the method's
entry point. If the hook works now, compilation was the cause. Full explanation in
[13-ART §3.17](../13-ART/README.md).

---

**18. Why does forking from Zygote weaken ASLR?**

Because `fork()` produces a child with the *same* address-space layout as the parent. Android forks app
processes from Zygote rather than `exec`ing them fresh, so every app on the device has the framework
and its libraries at the same addresses until the next reboot.

An address leaked from any process is therefore useful against every other process. It matters for
native exploitation and is largely irrelevant to app-layer testing. It is the price paid for fast app
startup and shared memory.

---

**19. Can an app modify its own code in memory?**

Yes. The app owns its process. It can allocate executable memory, load DEX, patch its own compiled
code, and rewrite the runtime's own data structures. So can anything else running in that process,
including Frida.

This is the reason no client-side integrity check can be trusted: it is code, running in a process the
adversary controls, checking on behalf of a party who is not present.

---

**20. Then what *can* a developer actually rely on?**

The kernel and the server. UID isolation, seccomp, DAC and SELinux are enforced by something the app
cannot reach. Permission checks happen in `system_server` against the caller's UID, which cannot be
spoofed over Binder. And anything genuinely security-critical should be decided server-side, where the
attacker has no code execution.

Everything inside the app's own process buys time, not security. That is not a flaw in the runtime — it
follows from the process belonging to the app.

---

**21. Is dynamic code loading always a vulnerability?**

No. It is a *capability* whose risk depends entirely on where the code comes from and how it is
verified. App-private storage plus a signature checked against a pinned public key is a legitimate,
defensible design. Shared storage with no verification is arbitrary code execution.

Assess the source and the verification, not the technique.

---

**22. `logcat -s art` prints a lot of noise. What am I looking for?**

Verification failures (a class that would not verify), dexopt events (compilation happening), GC
activity, and errors loading DEX. During an analysis session the useful signals are usually class
verification failures — which can indicate deliberately malformed DEX — and dexopt events telling you
the compilation state just changed under you.

---

**23. What's the difference between the "dalvik heap" and the "native heap" in `dumpsys meminfo`?**

The dalvik heap (the name is a Dalvik-era survivor) is the **managed** heap where your Java and Kotlin
objects live, managed by the garbage collector. The native heap is ordinary `malloc` memory used by
C/C++ — the runtime's own internals and any JNI libraries the app loads.

Beginners conflate them constantly. The distinction matters because managed objects move during garbage
collection while native allocations do not.

---

**24. I've read this chapter. What should I actually do differently tomorrow?**

Four things. Read `<application android:name>` before anything else. Spawn with `-f` rather than
attaching. When Frida cannot find a class, enumerate loaders instead of assuming anti-hooking. And when
writing a report, be precise about whether a control you bypassed was a *boundary* or merely a
*correctness feature* — because that distinction determines whether the bypass is the finding or just
the prerequisite for one.
