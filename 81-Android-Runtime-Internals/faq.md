# 81 — Android Runtime Internals · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. Is Zygisk a hooking framework?**

No. Zygisk is a lifecycle for loading native module code into a zygote child and giving it callbacks
around specialization. It does not provide a Java hook API. A Zygisk module that hooks Java methods
is using another library (LSPlant, Frida's Java bridge, or a custom engine) to do the actual work.

---

**2. Is ZygiskNext a different module API?**

No. A normal Zygisk module still implements `onLoad`, `preAppSpecialize`, `postAppSpecialize`,
`preServerSpecialize` and `postServerSpecialize`. ZygiskNext implements that ABI as a standalone
package for KernelSU, Magisk and APatch. It also has a separate native-only API for init-oriented
processes, but that is not the API ordinary Zygisk modules use.

---

**3. Is Vector just LSPosed with a new name?**

Vector is the 2026 continuation of LSPosed. The v2.0 release renamed the project and described a
rewritten Zygisk architecture; v2.2 added libxposed API 102 and hot reload. The module model is
still Xposed/libxposed-compatible, but the native injection path is not the old LSPosed code. Treat
"Vector" and "LSPosed" as the same lineage, not as the same binary.

---

**4. Why does my hook install but never fire?**

The most common cause is inlining: the compiler copied the target's body into its caller, so the call
no longer goes through the target's entrypoint. Other causes are a wrong process, a wrong class
loader, a wrong overload, or a caller already executing JIT/OSR code. Start by compiling with
`-m verify -f`, then test again. If it works, the difference is compilation.

---

**5. Why does `cmd package compile -m verify -f` fix some hooks?**

`verify` avoids AOT-compiling method bodies, so more execution stays in the interpreter and goes
through the method's entrypoint. It is a diagnostic, not a production fix. It changes performance
and is not something an attacker can rely on in a release build.

---

**6. What is the "quick entrypoint"?**

It is the pointer ART calls for a method invocation using the quick calling convention. It can point
at AOT code, JIT code, `nterp`, a resolution stub, a class-initialization stub, a JNI trampoline or a
deoptimization bridge. "Quick" describes the calling convention, not the destination.

---

**7. Can I hard-code the `ArtMethod` entrypoint offset?**

You can, and it will work on the build you tested. It will break on another ART build, another
pointer width, or the next Mainline update. Derive the offset from the runtime's structures, or pin
the exact build and state that you did.

---

**8. Does LSPlant disable the JIT?**

No. LSPlant integrates with the JIT: it prevents the target from being recompiled in a way that
bypasses the hook, and it tracks target/backup movement in the JIT code cache. "Hooks turn off the
JIT" is an oversimplification that leads to wrong predictions about hot methods.

---

**9. What is the difference between OSR and deoptimization?**

OSR (on-stack replacement) enters compiled code from a running interpreted loop. Deoptimization
leaves optimized code and reconstructs interpreter state. They are opposite directions. A hook in a
long-running loop may need to handle OSR; a hook that missed an inlined caller may need
deoptimization.

---

**10. Why does `InMemoryDexClassLoader` not make a module invisible?**

Because the DEX still exists in memory, the loader still exists in the process, and the classes it
defines are enumerable. The constructor avoids writing a file to the app's data directory; it does
not remove the loader, the mappings or the class metadata. "In memory" is not "undetectable".

---

**11. What is hidden-API enforcement?**

It is ART's restriction on access to non-SDK framework members. The decision uses the member's flags,
the caller's domain, the target SDK and exemptions. It is not SELinux and not a sandbox. A trusted DEX
can be allowed to access members that an ordinary app cannot, which is why hook frameworks use
`MakeDexFileTrusted`.

---

**12. Why does the same module work in an app but crash `system_server`?**

Because `system_server` has a different UID, SELinux domain, hidden-API policy and boot-critical
role. A hook that is safe in an app can deadlock or crash the system server. Test in an app first,
keep a recovery path, and never weaken SELinux to make it boot.

---

**13. Is ZygiskNext open source?**

It was GPL-3.0 before `v4-0.9.2`. Since that release, the project reserves all rights and the public
repository contains the README, `module.yaml`, the API header and documentation, not the loader
implementation. The last public snapshot is useful for understanding the design, but it is not proof
of what a current binary does.

---

**14. How do I tell whether an executable mapping is a hook or the JIT?**

Compare the same app on the same build with and without the suspected loader. Inspect the mapping
name, the owning library, the thread that created it and the entrypoints of the methods the app
executes. The JIT code cache is created by ART and has a recognisable mapping; a hook trampoline is
usually in an anonymous mapping owned by an injected library. The combination is the evidence, not a
single string.

---

**15. Can a client-side check be made unhookable?**

No. If the attacker controls the process, they can change what the process does. The realistic goal
is to move the decision to a boundary the client does not control, use hardware-backed evidence where
it changes the risk, and treat local detection as a signal with false positives and false negatives.

---

**16. What should I record before claiming a runtime behaviour?**

The build fingerprint, SDK/API level, ABI, ART module version, loader name and version, the target
app's package and version, and the exact commands you ran. "Android 16" alone is not enough, because
ART is a Mainline module and the loader can change independently.

---

**17. Why is `system_server` scope special in Vector?**

Because `system_server` is boot-critical and already running when the scope changes. Vector stores it
under the key `system` and expands it to the `system_server` process/UID 1000. A change requires a
restart to replace the loaded module set; hot-swapping it is not safe.

---

**18. Does root give a module root inside the app process?**

No. The loader may run with root before specialization, but the app process is specialized to the
app's UID and SELinux domain. A module that needs privileged work uses a companion process over a
socket; it does not inherit the loader's root after the transition.

---

**19. What is the most common mistake in runtime detection?**

Attribution. An observation — an extra mapping, a loader, a property — is evidence that something is
present, not proof of which tool or intent. Compare with a build-matched baseline, state the vantage,
and treat a difference as a question rather than a verdict.

---

**20. Where do I start if I have never looked at ART internals?**

Read [11-Android-Runtime](../11-Android-Runtime/README.md) for the concept, then
[13-ART](../13-ART/README.md) for the implementation, then this chapter for the injection and
hooking stack. Do the labs in order; Lab 01 requires no hooking at all.
