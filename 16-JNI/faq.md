# 16 — JNI · FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the chapter
section is given so you can go deeper.

---

### 1. Why is the first argument always `JNIEnv*`? It is not one of my parameters.

Because a native function has no other way to reach the runtime.

A native JNI function is not "running inside the VM". It is plain machine code that the VM jumped to.
There is no ambient "current VM" it can consult, no implicit `this` pointing at runtime state. If it
wants to create a Java string, call a Java method, or throw a Java exception, it needs a handle to
the runtime, and that handle has to arrive somehow.

It could have been a global variable. That fails immediately, because JNI is multi-threaded and the
runtime needs per-thread state — which thread is calling, that thread's local reference table, that
thread's pending exception. A global cannot express that.

So the runtime passes it explicitly, as the first argument, on every call. `JNIEnv*` is *the calling
thread's* interface to the runtime. That is also why you must never share one between threads.

Practical consequence: in `Interceptor.attach`, `args[0]` is the environment, `args[1]` is the
receiver, and **your first real parameter is `args[2]`.**

→ [§3.9](README.md#39-the-calling-convention-every-native-hook-sees), [§3.10](README.md#310-jnienv-javavm-and-what-each-is-for)

---

### 2. What is a `jobject`, *really*?

It is an index into a table, not an address.

ART's garbage collector **moves objects**. The concurrent copying collector relocates live objects to
compact the heap. If native code held a raw pointer to an object, that pointer would go stale the
moment a collection ran, and there is no way for the collector to find and update every pointer
sitting in C locals, C globals and C structs.

So JNI hands out *indirect references*: opaque handles that index one of three tables (local, global,
weak global). When the collector moves an object, it updates the table entry. The handle native code
holds keeps working.

Everything strange about `jobject` falls out of that one decision:

- You cannot compare two of them with `==`, because two different handles can name one object. Use
  `IsSameObject`.
- The numeric value is meaningless and unstable — printing it tells you nothing.
- A local handle is only valid in the frame and on the thread that created it.

→ [§2.5](README.md#25-the-reference-tables-drawn), [§3.13](README.md#313-references--local-global-weak-global)

---

### 3. Why did the `Java_*` symbol disappear after they added `RegisterNatives`?

Because it was never needed in the first place, and removing it is the point.

Static registration works by *name*: ART computes `Java_com_example_Crypto_decrypt` and calls
`dlsym`. For that to work, the symbol must be exported, which means it appears in `.dynsym`, which
means `nm -D` shows it — and it means R8 cannot rename the Java class, because renaming it would make
ART look for a symbol that does not exist.

`RegisterNatives` binds by *address instead*. The library says "for this class, this name with this
signature lives at this address". The implementation function can then be declared `static` — internal
linkage, no symbol anywhere — and the Java class is free to be renamed to `a.b.c`.

So an app that switches to `RegisterNatives` gains exactly two things: no symbol table entry, and no
forced class name. Both are anti-analysis wins, and that is why protectors do it.

The counter is that ART must be handed the name, signature and address in **plaintext**, because it
looks the method up on the class by exact string comparison. Hook `RegisterNatives` and the whole
table falls out.

→ [§3.8](README.md#38-dynamic-registration--registernatives), [§7.2](README.md#72-dumping-the-dynamic-registration-table), [Lab 03](labs/lab-03-recovering-dynamic-natives.md)

---

### 4. Is `System.loadLibrary` the same as `dlopen`?

No. It *contains* a `dlopen`, and does four other things around it.

| | `dlopen("libfoo.so")` | `System.loadLibrary("foo")` |
|---|---|---|
| Name handling | verbatim | maps `foo` to `libfoo.so` |
| Path | the linker's search path | the **calling ClassLoader's** native library path |
| Bookkeeping | the linker's | ART records the library **and its ClassLoader** |
| `JNI_OnLoad` | not called | **called, before the method returns** |
| Duplicate loads | refcounted by the linker | ART returns early if already loaded by that ClassLoader |

The ClassLoader association is the part that surprises people. It is what later restricts which
libraries ART will search when it needs to bind a native method: a library loaded by the app's
ClassLoader cannot satisfy a native method on a framework class.

`System.load("/path/to/x.so")` skips the name mapping and the path search, and uses the path
verbatim. An app calling that on a file in its own data directory is loading code that was not in the
APK and is not covered by the APK signature — a high-signal finding.

→ [§3.1](README.md#31-systemloadlibrary-and-systemload), [§4.2](README.md#42-trace-a--systemloadlibrary-to-dlopen-to-jni_onload)

---

### 5. Why does my hook crash when I call a Java method from a native thread?

Because that thread has no `JNIEnv`, and using one from another thread corrupts state rather than
failing cleanly.

A `JNIEnv*` is per thread. Threads that ART created (the main thread, binder threads, anything from
`java.lang.Thread`) are attached and have one. A thread created by `pthread_create` inside a native
library does not. Neither does a thread Frida spins up for a `setTimeout` callback.

The correct sequence:

```c
JNIEnv *env; int attached = 0;
jint rc = (*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6);
if (rc == JNI_EDETACHED) {
    if ((*g_vm)->AttachCurrentThread(g_vm, &env, NULL) != JNI_OK) return;
    attached = 1;
}
/* ... use env ... */
if (attached) (*g_vm)->DetachCurrentThread(g_vm);
```

In Frida:

```javascript
let env;
try { env = Java.vm.getEnv(); }            // throws if not attached
catch (e) { env = Java.vm.attachCurrentThread(); }
```

Two traps beyond that. A thread that attached **must** detach before it exits, or ART aborts the
process. And `FindClass` from a thread ART did not create resolves against the *system* ClassLoader,
so it will not find your app's classes — which is why libraries do all their `FindClass` work inside
`JNI_OnLoad` and cache the results as global references.

Inside `Interceptor.attach`'s `onEnter` you are on the app's own thread, which is attached, so
`Java.*` is safe there. The failures happen when you defer work.

→ [§3.19](README.md#319-threads--attaching-detaching-and-the-per-thread-jnienv), [§7.5](README.md#75-calling-back-into-java-from-a-native-hook)

---

### 6. My `grep` for the method name finds nothing in the `.so`. Is the symbol missing?

Probably not — you are grepping for the wrong string.

The symbol is the *mangled* name. Three escapes account for almost every miss:

| Java | In the symbol |
|---|---|
| `check_root` | `check_1root` — a literal `_` becomes `_1` |
| `Outer$Inner` | `Outer_00024Inner` — `$` becomes `_0` plus four hex digits |
| an overloaded method | gains `__` and the parameter descriptors |

```bash
# host
python3 scripts/jni_mangle.py --mangle 'com.my_app.Guard.check_root'
#   Java_com_my_1app_Guard_check_1root
```

Grep for *that*. If it is still absent, the method is dynamically registered.

→ [§3.5](README.md#35-name-mangling--the-complete-rules)

---

### 7. Is it `_0024` or `_00024` for a dollar sign?

`_00024`. Six characters.

The escape is `_0` followed by **four** hexadecimal digits of the UTF-16 code unit. `$` is U+0024, so
the four digits are `0024`, and `_0` + `0024` = `_00024`.

This is the single most frequently mis-remembered rule in JNI, and getting it wrong means your search
for an inner class's native method silently finds nothing. Check it against any real library that has
a native method on an inner class: it will contain `_00024`.

→ [§3.5](README.md#35-name-mangling--the-complete-rules)

---

### 8. Why does the return type not appear in the symbol name?

Because JNI only needs enough to disambiguate *overloads*, and Java does not permit two methods that
differ only in return type. Parameters are sufficient; the return type would be redundant.

The practical consequence matters more than the reason: **a JNI symbol tells you the class, the
method and the parameter types, and never the return type.** If you need it, read it from the Java
side — `jadx`, or the DEX `method_id`.

→ [§3.6](README.md#36-demangling-by-hand)

---

### 9. Why does `(*env)->Foo(env, ...)` in one tutorial and `env->Foo(...)` in another do the same thing?

Because one is C and one is C++, and `jni.h` defines `JNIEnv` differently for each.

In **C**, `JNIEnv` is `const struct JNINativeInterface *`, and you receive a `JNIEnv *` — a pointer to
that pointer. So you dereference once to reach the table, then select the function, and pass `env`
explicitly as the first argument: `(*env)->FindClass(env, "...")`.

In **C++**, `jni.h` defines `JNIEnv` as a struct with inline member functions that do exactly those
two dereferences and pass `this` for you: `env->FindClass("...")`.

**They compile to identical machine code.** The difference is source-level sugar. In a decompilation
you see the same thing either way:
`(**(code **)(*(long *)param_1 + 0x30))(param_1, "...")`.

C++ has one real advantage: `jni.h` gives `jstring`, `jbyteArray` and friends distinct types there, so
the compiler catches passing one where another is expected. In C they are all `void*` and it will not.

→ [§2.3](README.md#23-the-jnienv-double-indirection), [§3.12](README.md#312-the-jni-type-system-on-the-c-side)

---

### 10. What does `local reference table overflow (max=512)` mean, and can I catch it?

It means native code created more than 512 local references on one thread without deleting any, and
**no, you cannot catch it.** It is an `abort()`, not a Java exception.

Local references are created implicitly by almost everything: every object argument, every
`FindClass`, every `NewStringUTF`, every `GetObjectArrayElement`, every `Call*Method` that returns an
object. They are freed when the native method **returns** — not at the end of a loop iteration. So a
loop that touches one object per iteration accumulates one reference per iteration.

```c
for (jsize i = 0; i < n; i++) {
    jstring s = (*env)->GetObjectArrayElement(env, arr, i);
    use(s);
    (*env)->DeleteLocalRef(env, s);          /* the missing line */
}
```

The security angle: if `n` comes from data you control — a JSON array, a certificate chain, a ZIP
entry count — you can **kill the process on demand**. Report it as availability impact, and state
which trust boundary the count crossed.

→ [§3.14](README.md#314-the-local-reference-table-and-its-capacity-limit), [§5.4](README.md#54-vulnerability-class-3--local-reference-exhaustion)

---

### 11. Why does my C code keep running after a Java callback threw?

Because **JNI does not unwind.** This is the rule that surprises every C++ programmer.

When a JNI call fails, or when a Java method you invoked throws, the runtime records a *pending
exception* on the current thread and **returns to your C code normally**. The next C statement
executes. Nothing about the source suggests anything went wrong.

Two things then go wrong at once. First, whatever the failing call was supposed to return is `NULL`,
and you are about to use it. Second, calling almost any JNI function while an exception is pending is
undefined behaviour — only a small set is legal.

```c
if ((*env)->ExceptionCheck(env)) {
    jthrowable e = (*env)->ExceptionOccurred(env);
    (*env)->ExceptionClear(env);       /* clear FIRST */
    /* ... now other JNI calls are legal ... */
    (*env)->DeleteLocalRef(env, e);
}
```

And when you raise one, `ThrowNew` does not stop your function either. **Throw, then `return` on the
very next line.**

The review heuristic: correct JNI code is visually branch-heavy — a check after nearly every call.
Straight-line JNI code is suspicious by shape, before you read a single argument.

→ [§3.18](README.md#318-exceptions--jni-does-not-unwind), [§5.3](README.md#53-vulnerability-class-2--the-missing-exception-check)

---

### 12. Is `jbyte` signed? My comparison never matches.

Yes, `jbyte` is **signed** — it is `int8_t`. A byte array containing `0xFF` arrives in C as `-1`, so
`data[i] > 0x7F` is always false.

The full trap list:

| Type | Signedness | Trap |
|---|---|---|
| `jboolean` | **unsigned** 8-bit | any nonzero is truthy to C; return `JNI_TRUE`/`JNI_FALSE`, not `2` |
| `jbyte` | **signed** 8-bit | `0xFF` is `-1` |
| `jchar` | **unsigned** 16-bit | it is a UTF-16 *code unit*, not a character |

Cast explicitly (`(unsigned char)data[i]`) or copy into an `unsigned char` buffer before parsing.

→ [§3.12](README.md#312-the-jni-type-system-on-the-c-side)

---

### 13. Why does the app crash with a 128-byte buffer and a 127-character string?

Because you counted UTF-16 units and wrote UTF-8 bytes.

| Call | Counts |
|---|---|
| `GetStringLength` | UTF-16 **code units** |
| `GetStringUTFLength` | **bytes** of the modified-UTF-8 form |

A character outside ASCII takes two or three bytes in modified UTF-8, and a character outside the
Basic Multilingual Plane takes six (two three-byte surrogate encodings). So 127 units can be up to
381 bytes — or 762 for astral characters.

`GetStringUTFRegion` compounds it: its start and length arguments are in **units**, but it writes
**bytes**. Size the destination from `GetStringUTFLength`, always.

→ [§3.15](README.md#315-strings-and-modified-utf-8), [§5.6](README.md#56-vulnerability-class-5--string-length-confusion)

---

### 14. Is putting a secret in native code actually safer?

It raises the cost of extraction. It does not change the outcome.

The secret has to exist in process memory at the moment it is used, and the JNI boundary is exactly
where it materialises — as a `const char*` from `GetStringUTFChars`, or a `jbyte*` from
`GetByteArrayElements`. Hook the boundary, or hook the crypto primitive the library is forced to
call, and read it. Chapter [40 Obfuscation](../40-Obfuscation/README.md) calls the JNI boundary
"plaintext" for precisely this reason.

What native code genuinely buys you is a higher skill floor and slower iteration for the attacker.
That is worth something in a fraud model where you care about scale and about the marginal attacker.
It is worth nothing in a model where a single extraction is fatal, because that extraction will
happen.

The design answer is server-side secrets, hardware-backed keys
([49 KeyStore](../49-KeyStore/README.md)) and attestation — not obfuscation.

→ [§5.9](README.md#59-how-developers-misuse-it), [§10 Staff Engineer](README.md#staff-engineer)

---

### 15. `RegisterNatives` returns −1 and I cannot see why.

The name or the signature does not match a `native` method on that class, **exactly**, character for
character. That is the cause in the overwhelming majority of cases.

Check, in this order:

1. Is the method declared `native` in Java? `RegisterNatives` refuses non-native methods.
2. Is the descriptor exactly right? `Ljava/lang/String;` — slashes, and the trailing semicolon.
   `Ljava.lang.String;` is wrong and looks fine.
3. Is the **return type** in the signature correct? It is part of the match.
4. Is the class the one you think? `FindClass` from the wrong thread resolves against the system
   ClassLoader.
5. Did `FindClass` succeed at all? If it returned `NULL` you are calling `RegisterNatives` with an
   exception already pending.

`NoSuchMethodError` is pending when it fails, and its message names the descriptor it looked for.
Print it with `ExceptionDescribe` while debugging.

→ [§4.4](README.md#44-trace-c--registernatives-inside-art)

---

### 16. I hooked the function I recovered and every argument is garbage.

Four candidate causes, in order of likelihood.

1. **You counted from `args[0]`.** That is the `JNIEnv*`. Real arguments start at `args[2]`.
2. **The method is `@CriticalNative`.** Then there is no `JNIEnv*` and no `jclass` at all, and the
   first real argument *is* `args[0]`. Check the DEX:
   `grep -rn 'optimization/CriticalNative' smali*/`.
3. **You hooked a decoy.** Some libraries register a stub and re-register the real implementation
   later. Run the `RegisterNatives` hook for the whole session and look for the same class appearing
   twice.
4. **Floating-point parameters.** On ARM64 those travel in `v0`–`v7`, not in the integer `args[]`
   sequence, so a method mixing `int` and `float` will not line up.

→ [§3.9](README.md#39-the-calling-convention-every-native-hook-sees), [§3.21](README.md#321-fastnative-and-criticalnative)

---

### 17. Why did I get `UnsatisfiedLinkError` ten seconds after the library loaded fine?

Because static binding is **lazy and per method**. ART looks the symbol up when that specific method
is first called, not when the library is loaded.

So `System.loadLibrary` succeeding tells you nothing about whether any given method is bound. An app
can declare ten `native` methods and ship a library implementing three; the other seven are invisible
until somebody calls them.

This is also a useful tool. The error message names **both** symbols ART tried:

```text
No implementation found for java.lang.String com.example.Hasher.sha256(java.lang.String)
  (tried Java_com_example_Hasher_sha256
     and Java_com_example_Hasher_sha256__Ljava_lang_String_2)
```

You never have to guess a mangling — make the runtime print it.

→ [§3.7](README.md#37-static-registration--binding-by-symbol-lookup), [Lab 01 Part 5](labs/lab-01-building-the-bridge.md)

---

### 18. What is a `long` doing in this native method signature?

It is almost certainly a raw pointer.

Java has no way to hold a C++ object, so the universal workaround is to store the native object's
address in a Java `long` field and pass it back on every call. The pattern is idiomatic and appears in
AOSP itself.

It also means **Java code chooses the address the native code dereferences**. Three bugs live there:

| Bug | Trigger |
|---|---|
| Arbitrary pointer dereference | call the native method by reflection with a value you chose |
| Use after free | call `close()` then a method that uses the handle |
| Double free | call `close()` twice, especially from two threads |

Test it in one line: pass `0x4141414141414141` and look at the fault address in the tombstone. If it
matches, you have proved controlled dereference.

The fix is to expose an opaque index into a native-side registry rather than an address, and to make
close atomic on the Java side.

→ [§5.5](README.md#55-vulnerability-class-4--the-jlong-handle), [`enterprise_bridge.cpp`](./examples/enterprise_bridge.cpp)

---

### 19. What is CheckJNI and why should I turn it on?

It is ART's validating implementation of the whole JNI function table. Enabling it swaps the
`JNIEnv`'s table pointer for one whose entries check their arguments before delegating — which is
itself a nice demonstration of why the `JNIEnv` indirection exists.

```bash
# adb shell — root; applies to processes started afterwards
setprop dalvik.vm.checkjni true
```

It is on by default for debuggable apps and on `userdebug` builds, and off for release apps on user
builds — which is why a bug that aborts instantly on a developer's device silently corrupts memory on
a user's.

For a pentester it is the cheapest bug oracle available. Every abort names the JNI function, the rule
broken, the native method executing, and the Java stack that reached it. That is enough to write a
finding without opening a disassembler. The aborts are not themselves vulnerabilities — they point at
code that does not respect the contract, and that is where the memory-safety bugs are.

→ [§3.23](README.md#323-checkjni), [§7.6](README.md#76-turning-on-checkjni), [13-ART §3.24](../13-ART/README.md)

---

### 20. Why do some class names survive obfuscation in an otherwise fully renamed app?

Because those classes declare **statically registered** native methods, and renaming them would break
the binding.

ART finds the C function by computing `Java_<class>_<method>` and calling `dlsym`. If R8 renamed
`com.vendor.security.Attestation` to `a.b.c`, ART would look for `Java_a_b_c_check` and find nothing.
R8 cannot rewrite the prebuilt `.so`, so it must not rename the class. The rule that enforces this
ships in the default `proguard-android.txt`:

```proguard
-keepclasseswithmembernames class * { native <methods>; }
```

For you this is a free foothold. In an app where every class is `a.b.c`, the classes with native
methods keep **real, meaningful names** — and they are, by definition, the ones the developer thought
were important enough to move into native code. Run
`nm -D lib*.so | grep ' T Java_'` on any obfuscated APK and read the surviving names as the app's own
table of contents for its most sensitive logic.

And when they *do* disappear, that is a signal too: the developer switched to `RegisterNatives`
deliberately.

→ [§3.7](README.md#37-static-registration--binding-by-symbol-lookup), [§6.4](README.md#64-what-obfuscation-does-to-it)

---

### 21. `nm -D` shows nothing at all. Is the library stripped?

Stripping is not the explanation. `strip` removes `.symtab`, the *static* symbol table. Exported
symbols live in `.dynsym`, which the dynamic linker needs at load time and which stripping does not
touch. A statically registered `Java_*` symbol therefore survives stripping.

So an empty result means one of:

| Cause | How to confirm |
|---|---|
| Everything is registered dynamically | `nm -D libx.so \| grep JNI_OnLoad` returns a hit |
| Built with `-fvisibility=hidden` and dynamic registration | same, plus nothing else exported |
| It is not a JNI library at all — a dependency of one | check other libraries' `readelf -d ... \| grep NEEDED` |
| Wrong ABI directory | `ls lib/` |
| Your `nm` cannot read it | try `llvm-nm`, or `readelf --dyn-syms -W` |

→ [§6.3](README.md#63-in-the-shared-object), [§6.4](README.md#64-what-obfuscation-does-to-it)

---

### 22. I dumped `RegisterNatives` and got nothing. Does that mean there is none?

No. It almost always means you were late.

`RegisterNatives` is normally called from `JNI_OnLoad`, which ART calls during `System.loadLibrary`,
which for most apps runs in a `static` initialiser — long before you can attach to a running process.

**Spawn, do not attach:**

```bash
frida -U -f com.example.app -l scripts/dump-registernatives.js --no-pause
```

If the library is loaded later — on a login, a payment, or after a download — attaching works. Tell
the two cases apart by hooking `dlopen`/`android_dlopen_ext` and watching when the interesting `.so`
appears.

→ [§7.2](README.md#72-dumping-the-dynamic-registration-table), [Lab 03](labs/lab-03-recovering-dynamic-natives.md)

---

### 23. Does the JNI boundary count as a security boundary?

No, and treating it as one is a category error.

A boundary is meaningful only when the two sides have different privileges. Here they do not: same
process, same UID, same address space, same attacker. Native code cannot be protected from Java code
in the same process, and Java code cannot be protected from native code — native code can read and
write the whole address space including the runtime's own structures.

What the boundary *is*: a place where memory safety ends, which makes it a place where bugs
concentrate. And a **cost** control — it takes an attacker longer to work in a disassembler than in
`jadx`. Cost is a real property and worth buying deliberately. It is not trust.

→ [§5.1](README.md#51-the-thesis-stated-exactly), [§10 Principal Engineer](README.md#principal-engineer), [21 App Sandbox](../21-App-Sandbox/README.md)

---

## Still stuck?

| Symptom | Go to |
|---|---|
| The symbol name is wrong | [§3.5](README.md#35-name-mangling--the-complete-rules) and `scripts/jni_mangle.py --selftest` |
| The arguments are wrong | [§3.9](README.md#39-the-calling-convention-every-native-hook-sees) |
| There is no symbol | [§3.8](README.md#38-dynamic-registration--registernatives) and `scripts/dump-registernatives.js` |
| The process aborts | [§3.14](README.md#314-the-local-reference-table-and-its-capacity-limit), [§3.18](README.md#318-exceptions--jni-does-not-unwind), [§3.19](README.md#319-threads--attaching-detaching-and-the-per-thread-jnienv) |
| The decompilation is unreadable | [§3.11](README.md#311-the-function-table-index-by-index) and [57 Ghidra §3.8](../57-Ghidra/README.md) |
| You need a bug, fast | [§7.6](README.md#76-turning-on-checkjni) — turn on CheckJNI |
