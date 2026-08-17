# 13 — ART · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. There's a file called `base.odex` next to the APK. Isn't ODEX a Dalvik thing? Dalvik is dead.**

You are right that ODEX was Dalvik's format, and you are right that Dalvik is gone. The *filename*
survived; the contents did not. On any device from Android 5.0 onward, `base.odex` is an **OAT file**,
which is a valid ELF shared object containing real ARM64 machine code.

Prove it to yourself:

```bash
xxd -l 8 base.odex
# 7f45 4c46 ...  → ELF magic. A genuine Dalvik ODEX would start with "dey\n".
```

This catches everyone exactly once. Running a Dalvik-era "deodex" tool against it will fail.

---

**2. Where is the actual DEX bytecode of an installed app?**

In the **VDEX** file, on Android 8 and later. Not the OAT, and not necessarily the APK.

```bash
oatdump --vdex-file=<path>/base.vdex --export-dex-to=/data/local/tmp/dex_out
```

This matters when the installed bytecode might differ from what you downloaded — after an in-place
patch, with a packer that rewrites DEX at install time, or for a preinstalled system app whose APK you
cannot cleanly obtain.

---

**3. My Frida hook installs without any error, but it never fires. What is going on?**

Most likely the method was **inlined** into its caller by the optimizing compiler, so there is no
longer a call instruction for your hook to intercept.

Diagnose it in one command:

```bash
adb shell cmd package compile -m verify -f com.example.target
adb shell am force-stop com.example.target
```

That forces everything back to the interpreter. Re-run your hook. If it now fires, the cause was
compilation. If it still does not, the cause is one of the other three: wrong `ClassLoader`, wrong
overload, or you hooked an interface declaration while the app calls the concrete implementation.

---

**4. Why did my hook work yesterday and stop working today? I changed nothing.**

You probably left the device plugged in overnight. Background dexopt runs when the device is **idle
and charging**, and it recompiled your target from `verify` to `speed-profile`. Methods that were
interpreted yesterday are native code today, and some are now inlined.

This is the single most common cause of "it worked yesterday" in Android dynamic analysis. The fix is
question 3.

---

**5. What exactly does `cmd package compile -m verify -f` do, and is it safe?**

It tells the platform to recompile the package with the `verify` filter, which means "verify the
bytecode but compile nothing". Every method then starts in the interpreter. `-f` forces it even if the
current state already nominally satisfies the request.

It is completely safe and fully reversible:

```bash
adb shell cmd package compile -m speed-profile -f com.example.target   # restore
adb shell cmd package compile --reset com.example.target               # or wipe artifacts
```

The only cost is performance — the app runs slower until you restore it. On an analysis device that is
exactly the trade you want.

---

**6. Does forcing `verify` create the vulnerability I'm reporting?**

No, and this is important to get right in a report. The compiler filter affects **your
instrumentation**, not the application's logic. Forcing interpretation makes hooks reliable; it does
not introduce a flaw.

That said, you must verify the finding reproduces without it. State in the report that `-m verify` was
used to make instrumentation reliable, and that the underlying issue is present regardless of
compilation state.

---

**7. What is `ArtMethod` and why does everyone keep mentioning it?**

It is the C++ structure ART uses to represent a Java method. It holds the declaring class, access
flags, DEX index, a JIT hotness counter — and one field called
`entry_point_from_quick_compiled_code_`, which is a raw function pointer telling the CPU where to go
when the method is called.

**Every Java hooking framework on Android works by overwriting that one pointer.** Frida, Xposed and
LSPosed all do the same thing. Once you know that, hooking stops being magic.

---

**8. Why is patching `ArtMethod` reliable? Isn't it fighting the runtime?**

Not at all — and this is the elegant part. The runtime rewrites that same field constantly on its own:
when the JIT compiles a method, when instrumentation is installed, when deoptimization occurs. The
field is *designed* to be mutated at arbitrary times, and `ArtMethod` structures are deliberately not
on the Java heap so the garbage collector never moves them.

Hooking frameworks are using the mechanism as intended, just for their own purposes.

---

**9. I wrote a Frida script using `ArtMethod` field offsets. It works on my phone and crashes on my
colleague's — same Android version. Why?**

Because ART is a **Mainline module**. Since Android 12 it updates through Play System Updates
independently of the OS, so two devices reporting the same Android release can be running different
ART builds with different structure layouts.

Never hard-code offsets. Probe for them, or use Frida's Java bridge which handles this for you. And
record the module version in your notes:

```bash
adb shell dumpsys package com.google.android.art | grep versionName
```

---

**10. What is deoptimization and why would I want it?**

It is the runtime abandoning compiled code and continuing execution in the interpreter, reconstructing
an interpreter frame from the compiled one mid-execution.

You want it because interpreted execution reads bytecode from a data structure and honours the entry
point at *every* call site, whereas compiled code may have inlined the callee away entirely. Forcing
deoptimization is how you make a hook land when compilation has defeated it.

The runtime does it for its own reasons too: when a debugger attaches, when instrumentation is
installed, or when a speculative optimisation turns out to be invalid.

---

**11. Is the bytecode verifier a sandbox? It sounds like one.**

No, and this misconception causes real design errors. The verifier guarantees *type safety within the
runtime's own model* — that a field access reads a field that exists at the expected type, that jumps
land on instruction boundaries, that register types line up.

It says nothing about what the app is permitted to do, and it is bypassed entirely the moment the app
calls into its own native library. Treat it as a correctness mechanism the runtime relies on in order
to optimise, not as containment. The real boundaries are the process/UID line and SELinux.

---

**12. Why can't I just cache a Java object's address in my Frida script?**

Because ART's default collector is a **concurrent copying** collector. Live objects are physically
moved to new regions during collection, and the old header is repurposed to hold a forwarding address.

Cache a raw address, let a GC happen, dereference it, and you are reading either garbage or unrelated
memory. This is why Frida hands you handles rather than pointers.

---

**13. Why is `String` a bad place to keep a password?**

Two reasons, both structural. `String` is immutable, so you cannot overwrite its contents after use —
the bytes stay in memory until the object is collected, and possibly long after. And string literals
are interned, so they may live for the entire process lifetime in a shared table.

A heap dump or a `Java.choose()` search will find them. Use `char[]` or `byte[]` and explicitly zero it
when finished. The absence of this pattern is a legitimate, if usually Low-severity, finding.

---

**14. What's the difference between the "dalvik heap" and the "native heap" in `dumpsys meminfo`?**

The dalvik heap (the name is another Dalvik-era survivor) is the **managed** heap where Java/Kotlin
objects live, managed by ART's garbage collector. The native heap is ordinary `malloc` memory used by
C/C++ code, including ART's own internals and any of the app's JNI libraries.

Beginners frequently conflate them. `ArtMethod` structures, for example, live in native memory — which
is exactly why the GC never moves them.

---

**15. Why does attaching a debugger make the app so much slower?**

Because the runtime switches from `nterp` — a fast, hand-written assembly interpreter — to the switch
interpreter, a portable C++ implementation that can be an order of magnitude slower. It has to,
because single-stepping and breakpoints need the observability the fast interpreter does not provide.

This is also why some timing-based anti-debug checks work: they are not detecting the debugger
directly, they are detecting the interpreter change.

---

**16. What is a profile file, and why should I care?**

`/data/misc/profiles/ref/<pkg>/primary.prof` records which methods and classes the app actually
executed on this device. ART uses it to decide what to compile.

For you it is a **behavioural record of executed code**. It distinguishes "this method exists in the
APK" from "this method actually ran here", which is genuinely useful for finding live code in a huge
obfuscated app and is strong forensic evidence. Dump it with:

```bash
adb shell cmd package snapshot-profile com.example.target
adb shell profman --dump-only --profile-file=/data/misc/profman/com.example.target-primary.prof
```

Snapshot it *before* doing anything that triggers recompilation.

---

**17. `baksmali` won't parse the DEX I extracted. It complains about instructions I've never seen.**

You are on Android 8, 9 or 10 and you have hit **quickening**. Instructions like `iget-quick` and
`invoke-virtual-quick` carry precomputed offsets instead of symbolic references, and they are not valid
standalone DEX — the information needed to interpret them lives in the OAT metadata.

You need an unquickening step (`vdexExtractor` was written for exactly this). On Android 11 and later
the problem simply does not exist, because `nterp` made quickening unnecessary and it was removed.

---

**18. Why does an OTA or a Play System Update make my phone slow and hot for an hour afterwards?**

Because every app's compiled artifacts just became invalid. The OAT file records the boot classpath
checksums and ART version it was built against; an update changes those, so every OAT file fails
validation and is discarded.

The device then recompiles everything in the background over the following hours. `odrefresh`
regenerates the boot image first, `odsign` signs it, and then app-level dexopt catches up.

---

**19. Can a malicious app write its own compiled code into its OAT file?**

No. `dex2oat` runs as a separate process in its own SELinux domain, and writes to a directory the app
has no permission to write to. The app supplies the input (its DEX) but a more-privileged component
produces the output.

This is a genuinely meaningful trust property: an attacker who compromises an app cannot persist by
planting malicious native code in its compiled artifacts.

---

**20. An app deletes its own OAT file at startup. What is it doing?**

Usually attempting to defeat analysis of its compiled code, or to force a predictable execution state
for timing-based checks.

It does not achieve much. The DEX is still in the VDEX and the APK, and the runtime simply interprets
the app instead. It makes the app measurably slower for every real user, and it arguably makes your job
*easier* by guaranteeing interpretation. It is a poor trade, and worth noting in a report as a
performance concern.

---

**21. I see `[anon:jit-code-cache]` in `/proc/<pid>/maps` — is that injected code?**

No, that is the JIT code cache and it is entirely legitimate. It is anonymous, executable memory
because that is what a JIT compiler needs.

This matters because naive anti-Frida checks look for "executable anonymous memory" as an injection
indicator and therefore false-positive on every app that uses the JIT — which is all of them. A
well-written check has to be more specific.

---

**22. Should I disable the JIT on my analysis device?**

It is a reasonable option. `dalvik.vm.usejit false` combined with
`cmd package compile -m verify -f <pkg>` gives you a device where essentially all app code is
interpreted — the maximally observable configuration.

The cost is performance, which on a dedicated analysis device is exactly the right trade. Just
remember you have done it, and note it in your methodology so results are reproducible.

---

**23. Does an app installed from Play behave differently from the same app installed with `adb`?**

Yes, and this surprises people. Play supplies a **Cloud Profile** in a `.dm` file alongside the APK, so
the app can be compiled with `speed-profile` immediately using aggregated real-world usage data.
`adb install` supplies no profile, so the app starts at `verify` — fully interpreted.

Your test device may therefore be in a materially different execution state from a real user's device.
Note the install method in your report, especially when assessing timing-sensitive behaviour.

---

**24. I hooked an interface method and nothing happened.**

The app is probably calling the method through the concrete implementing class rather than through the
interface. `invoke-virtual` on the implementation and `invoke-interface` on the interface reach the
same `ArtMethod` at runtime, but `Java.use("com.example.MyInterface")` gives you the interface's
declaration, which is a different `ArtMethod` object.

Hook the concrete class instead. If you do not know which class implements it, `Java.choose` on the
interface will show you the live instances and their real types.

---

**25. What is the fastest way to tell whether an app's code is compiled or interpreted right now?**

```bash
adb shell dumpsys package dexopt | grep -A5 "\[com.example.target\]"
```

Or, authoritatively, straight from the OAT header:

```bash
adb shell oatdump --oat-file=<path>/base.odex --header-only | grep -i compiler-filter
```

`verify` means interpreted and friendly. `speed` means compiled, inlined and hostile to hooking. Check
this *before* you start debugging a misbehaving script, not after.
