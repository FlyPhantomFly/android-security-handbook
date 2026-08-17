# 04 — Java FAQ

Questions people actually ask while working through [04 — Java](README.md), answered directly. The
"obvious" questions are here on purpose, because nobody asks them out loud and everybody has them.

---

## Getting started

### 1. Do I need to learn Java if modern Android apps are written in Kotlin?

Yes, and the reason has nothing to do with which language developers prefer. Kotlin does not compile
to a Kotlin runtime on Android. It compiles to Java bytecode, which `d8` converts to DEX, which is
what you get back when you decompile an APK. When you open a Kotlin app in JADX, the tool
reconstructs Java source, not Kotlin source, because Java is what the bytecode most closely
describes. Every Kotlin `data class` you meet in the field will appear to you as a Java class with
`equals`, `hashCode`, `toString`, `component1`, and `copy` methods. Every Kotlin `object` singleton
appears as a Java class with a `static final INSTANCE` field initialised in `<clinit>`. If you do not
know what those Java constructs mean, the decompiled output is noise.

The practical order is: learn Java first because it is what you read, then learn Kotlin in
[05 — Kotlin](../05-Kotlin/README.md) because it is what you write when you build test apps and
because Kotlin adds its own recognisable artefacts on top.

> **🧠 Mental Model**
> Java is the language the *artefact* speaks. Kotlin is a language the *author* speaks. As a reverse
> engineer you spend your life reading artefacts, so you must be fluent in the artefact's language
> first.

### 2. What is the difference between the JDK, the JRE, and the JVM?

They are three nested things, and the confusion is entirely reasonable because installers have used
the names inconsistently for twenty years.

| Name | Stands for | What it contains | You need it to |
|---|---|---|---|
| JVM | Java Virtual Machine | The engine that executes bytecode | Run a program (it is not shipped alone) |
| JRE | Java Runtime Environment | JVM plus the standard class library | Run a program |
| JDK | Java Development Kit | JRE plus `javac`, `javap`, `jar`, `jdb`, `jshell` | Compile and inspect a program |

Install a JDK. It contains everything else. As a security person you specifically need `javap`,
which is a JDK tool and is absent from a JRE-only install, because `javap -c` is how you read
bytecode without any third-party tooling.

> **⚠️ Warning**
> Since Java 11 there is no separate downloadable JRE from most vendors. If a tutorial tells you to
> "install the JRE", it is old. Install a current JDK (Temurin, Zulu, Oracle, or your distribution's
> `openjdk-21-jdk` package) and move on.

### 3. Why does everyone say Java is slow?

Because of a benchmark culture from roughly 1997 that never quite died. The original Java
implementations interpreted bytecode one instruction at a time, which really was slow compared to
compiled C. Modern JVMs use a just-in-time compiler that watches which methods run often and compiles
those to native machine code with optimisations an ahead-of-time compiler cannot perform, because the
JIT knows the actual runtime types and branch behaviour. Long-running Java server code is routinely
within a small factor of C, and sometimes faster on branch-heavy workloads.

On Android the picture is different again. ART compiles ahead of time during installation and at idle
using profiles gathered from real use, so the app you attack on a device is usually running native
machine code, not interpreted DEX. What remains genuinely slower than C is startup time, memory
footprint, and anything that allocates heavily, because garbage collection is not free.

> **🔍 Pentester's Note**
> The "Java is slow" folklore matters to you in one concrete way: developers sometimes push
> performance-sensitive or security-sensitive logic into native code via JNI, believing native code
> is both faster and harder to reverse. That belief moves your target from
> [12 — DEX Internals](../12-DEX-Internals/README.md) to
> [15 — Native Code](../15-Native-Code/README.md), so notice when it happens.

### 4. Is the Java on Android the same Java as on my laptop?

The *language* is the same, the *class library* is mostly the same, and the *execution model* is
different. Android's class library is not Oracle's; it is an OpenJDK-derived library that lives in
AOSP under `libcore/`. Your laptop's JVM executes stack-based `.class` bytecode. Android's ART
executes register-based DEX bytecode. Android also lacks parts of the desktop library entirely
(Swing, AWT, RMI, JMX) and adds a large `android.*` surface that does not exist on the desktop.

| Aspect | Desktop JVM | Android ART |
|---|---|---|
| Bytecode | Stack-based `.class` | Register-based `.dex` |
| Standard library | OpenJDK `java.*` | `libcore` `java.*` plus `android.*` |
| Compilation | Interpret then JIT | AOT at install plus JIT plus profiles |
| Class loading | `URLClassLoader` and friends | `PathClassLoader`, `DexClassLoader` |
| Serialization | Fully supported | Supported but discouraged, `Parcelable` preferred |
| Language level | Whatever your JDK is | Subset, plus desugaring for older API levels |

### 5. What actually is a `.class` file, a `.dex` file, and an `.apk`?

A `.class` file is the output of `javac` for exactly one class, containing that class's constant
pool, fields, methods, and stack-based bytecode. A `.dex` file is the output of `d8` for *many*
classes at once, containing a single shared string table, type table, and method table for all of
them, with register-based bytecode. An `.apk` is a ZIP archive containing one or more `classes*.dex`
files, compiled resources, the manifest, native libraries, and a signature.

The sharing is the important part. Because a DEX file has one string table for the whole application,
every string literal in the app — every URL, every log message, every hardcoded credential — sits in
one contiguous, easily dumped table. That is the structural reason string-hunting is the highest
value-per-minute activity in early Android analysis, and it is what
[`scripts/dump-strings.py`](scripts/dump-strings.py) exploits.

---

## Language semantics that bite

### 6. Why does `==` work for small Integers but fail for large ones?

Because `==` on object references compares *identity*, not value, and the JDK caches small boxed
integers so that identical small values happen to be the same object.

When you write `Integer a = 127;` the compiler inserts a call to `Integer.valueOf(127)`. That method
keeps a preallocated array of `Integer` objects for the range −128 through 127 and returns the cached
instance. Two variables assigned 127 therefore point at the same object and `a == b` is `true`. Write
128 instead and `valueOf` falls off the end of the cache, allocates a fresh `Integer` each time, and
`a == b` is `false` even though both hold the value 128.

```java
// host — save as Cache.java and run with: java Cache.java
public class Cache {
    public static void main(String[] args) {
        Integer a = 127, b = 127;
        Integer c = 128, d = 128;
        System.out.println(a == b);        // true  — same cached object
        System.out.println(c == d);        // false — two distinct objects
        System.out.println(c.equals(d));   // true  — value comparison
    }
}
```

> **🔬 Under the Hood**
> The cache is `java.lang.Integer.IntegerCache`, an inner class whose upper bound can be raised with
> `-XX:AutoBoxCacheMax` on HotSpot. This means the exact threshold is a tunable implementation
> detail, not a language guarantee. That is precisely why relying on it is a bug rather than a
> feature: the same code can behave differently on two JVMs.

### 7. So when is `==` ever correct?

`==` is correct and preferred in exactly these cases: comparing primitives (`int`, `long`, `char`,
`boolean` and friends), comparing an object reference against `null`, comparing enum constants, and
the rare case where you genuinely mean "is this the same object in memory". Everywhere else you want
`.equals()`.

| Comparison | Correct operator | Why |
|---|---|---|
| `int` to `int` | `==` | Primitives have no identity |
| any reference to `null` | `==` | `null` has no `equals` method to call |
| enum to enum | `==` | Enum constants are singletons, and `==` is null-safe |
| `String` to `String` | `.equals()` | Identity is an accident of the string pool |
| boxed number to boxed number | `.equals()` | Identity is an accident of the cache |
| password to password | `MessageDigest.isEqual` on bytes | Value equality *and* constant time |

### 8. If I mark a field `private`, can an attacker still read it?

Yes, trivially, and in more than one way. Access modifiers are a *compile-time* contract enforced by
`javac` and re-checked by the verifier at load time for normal calls. They are not encryption, not
memory protection, and not a runtime boundary against someone who controls the process.

An attacker with the APK can read the field's value directly out of the DEX if it is a constant,
because `private static final String KEY = "..."` still puts `"..."` in the shared string table where
`strings` finds it. An attacker running inside the process can read the field with reflection:
`getDeclaredField("key")` followed by `setAccessible(true)` followed by `get(instance)`. An attacker
with Frida can read it without reflection at all, by walking the object layout. An attacker with a
memory dump reads it out of the heap.

> **⚠️ Warning**
> `private`, `final`, and package-private communicate *intent to other developers*. Treat any
> sentence of the form "it is safe because the field is private" as a finding, not a mitigation. The
> only real boundaries on Android are process boundaries, the kernel, and hardware-backed key storage
> — see [21 — App Sandbox](../21-App-Sandbox/README.md) and
> [49 — KeyStore](../49-KeyStore/README.md).

### 9. Why is `String` immutable, and why should I care?

`String` is immutable so that it can be safely shared: the string pool, `HashMap` keys, and
cross-thread sharing all depend on the value never changing after construction. Immutability is why
`"abc".toUpperCase()` returns a new object instead of modifying the original, and why every
concatenation in a loop allocates.

You care for one security reason above all: **an immutable object cannot be wiped**. Once a password
is in a `String`, you cannot zero it. You can drop the reference, but the characters stay in the heap
until garbage collection happens to reclaim and reuse that memory, and a heap dump taken in between
contains the password in plain text. That is the reason the JDK's own password APIs, such as
`javax.crypto.spec.PBEKeySpec` and `java.net.PasswordAuthentication`, take `char[]` rather than
`String`: a `char[]` can be overwritten with `Arrays.fill(pw, '\0')` the moment you are done.

> **🔍 Pentester's Note**
> "Password is held in a `String`" is a legitimate, reportable finding under
> `MASVS-STORAGE`. Confirm it by dumping the heap of a running app and searching for the credential.
> The technique lives in [51 — Dynamic Analysis](../51-DynamicAnalysis/README.md).

### 10. Why does my `HashMap` lookup return `null` for a key I definitely put in?

Almost always one of three causes.

The first is a broken `equals`/`hashCode` pair. `HashMap` locates a key by computing `hashCode()`,
using it to pick a bucket, and then walking that bucket calling `equals()`. If you overrode `equals`
but not `hashCode`, two objects you consider equal produce different hash codes, land in different
buckets, and the lookup never even reaches the `equals` call. The map is not broken; the contract is.

The second is a mutable key. If you insert an object into a map and then change a field that
`hashCode()` reads, the object's hash code changes, but the entry stays in the bucket it was filed
under. The key is now permanently unreachable — you cannot find it even with the very object you used
to insert it.

The third is a type mismatch that the compiler could not catch, typically after generics were erased
or after a cast through `Object`, so you are looking up an `Integer` in a map keyed by `String`.

[`examples/CollectionsDemo.java`](examples/CollectionsDemo.java) reproduces all three so you can see
them fail rather than take my word for it.

### 11. What does type erasure mean for reading decompiled generics?

It means the type argument is a compile-time fiction that has been checked, used to insert casts, and
then largely discarded. `List<String>` and `List<byte[]>` compile to the identical DEX type
`Ljava/util/List;`. The only reason JADX can print `List<String>` at all is that the compiler also
stores a `Signature` metadata attribute (`dalvik.annotation.Signature` in DEX) that records the
original generic text — metadata that any obfuscator can strip without breaking the app.

Three consequences for you.

First, when JADX shows you a generic type, it is quoting metadata, not deducing it from code. If the
metadata was stripped, you will see the raw type instead, and the code will look like it is
manipulating `Object`s.

Second, the `check-cast` instructions you see all over decompiled collection code are not the
developer's casts; the compiler inserted them at every point where a generic value was read into a
typed variable. A `ClassCastException` from such a cast usually means someone put the wrong type into
a collection through a raw reference, which is called heap pollution.

Third, there is no runtime type check at insertion time in the erased path, so a `List<String>`
reached through a raw `List` reference will happily accept an `Integer`. This is occasionally
exploitable when data crosses a trust boundary and validation was written as a generic bound.

### 12. What is `<clinit>` and why do I keep seeing it?

`<clinit>` is the class initializer: the single synthetic method into which the compiler collects
every `static { ... }` block and every static field initialiser, in source order. The runtime calls it
exactly once, lazily, the first time the class is actively used, and it is thread-safe by
construction because the runtime holds the class initialisation lock.

It matters to you because `<clinit>` is where interesting things hide. Native library loading
(`System.loadLibrary`) usually happens there. String decryption routines that populate a static table
usually happen there. Root-detection state, licence checks, and anti-tamper baselines are frequently
computed there. When you open an obfuscated class in JADX and the constructor looks empty, read
`<clinit>` before anything else.

### 13. Is `final` a security feature?

No. `final` on a field prevents *reassignment through the language*, which stops accidental
overwrites and enables safe publication across threads. It does not prevent reflection from writing
the field on most configurations, does not prevent Frida from writing the underlying memory, and does
not prevent an attacker from editing the Smali and rebuilding the APK with the value changed.

`final` on a *class* prevents subclassing, and that one has a mild, real security value: it stops an
attacker who can inject a class into your process from subclassing a security-relevant type and
overriding a check. It is a speed bump, not a wall.

`static final` with a compile-time constant is actively *bad* for secrets, because the compiler
inlines the value at every use site. Changing the constant later does not change already-compiled
callers, and the value appears in the string table once per compilation unit that used it.

---

## Reverse engineering the output

### 14. Why do I see `Outer$1` classes in JADX?

Because the JVM and ART have no concept of a class nested inside another class. Nesting is a source
language convenience. The compiler flattens every nested, inner, local, and anonymous class into its
own top-level class file whose name encodes the relationship with a `$`.

| Source construct | Generated class | Extra members |
|---|---|---|
| `static class Inner` | `Outer$Inner` | none |
| `class Inner` (non-static) | `Outer$Inner` | `final Outer this$0` field |
| anonymous `new Runnable(){…}` | `Outer$1` | `this$0`, plus `val$x` per captured local |
| second anonymous class in `Outer` | `Outer$2` | same |
| local class `class Helper{}` inside a method | `Outer$1Helper` | same |
| lambda compiled by `javac` | method `lambda$foo$0` in `Outer` | none |
| lambda desugared by D8/R8 | `Outer$$ExternalSyntheticLambda0` | captured values as fields |

> **🧠 Mental Model**
> `$` in a class name means "the compiler made this, not the programmer". Numbers after `$` are
> allocation order within the enclosing class, which means `Outer$1` is the first anonymous class in
> the source file, `Outer$2` the second, and so on. That ordering is a genuinely useful hint when you
> are trying to map decompiled output back to a source layout.

### 15. What are `this$0`, `val$x`, and `access$000`?

They are the three synthetic members the compiler generates to make nested classes behave as if the
nesting were real.

`this$0` is a field the compiler adds to every non-static inner class, holding a reference to the
enclosing instance. It is how `inner.doThing()` can read the outer object's fields.

`val$x` is a field the compiler adds when an anonymous or local class captures a local variable `x`
from the enclosing method. Java captures by value, so the value is copied into this field at
construction time. This is why captured locals must be effectively final.

`access$000`, `access$100` and similar are synthetic static bridge methods generated by `javac` so
that an inner class can read or write a `private` member of the outer class without violating the
verifier. Each distinct accessed member gets its own numbered accessor.

> **🔍 Pentester's Note**
> Synthetic accessors are a small but real attack surface: `access$000` is package-private, not
> private, so a class you inject into the same package can call it and reach a member that the source
> code declared `private`. Modern `javac` targeting Java 11+ can use nestmates instead of synthetic
> accessors, which removes this. Seeing `access$NNN` therefore also tells you something about the
> build's target level.

### 16. How do I tell reflection is being used to hide an API call?

Look for the combination, not any single call. Legitimate reflection exists — dependency injection,
serialization libraries, backwards-compatibility shims that call an API only present on newer
Android versions. Deliberate hiding has a distinct shape.

| Signal | Benign explanation | Suspicious when |
|---|---|---|
| `Class.forName("android.os.SystemProperties")` | Version compatibility shim | Argument is not a literal |
| Argument to `forName` is a decoded string | rare | Built from Base64, XOR, char arithmetic, or a `Cipher` |
| `getDeclaredMethod` + `setAccessible(true)` | Test frameworks, DI | Combined with a decoded method name |
| `Method.invoke` in a loop over a table | Framework dispatch | Table populated in `<clinit>` from encrypted data |
| `DexClassLoader` | Plugin architectures | Source path is a downloaded or decrypted file |
| Reflection wrapped in `try/catch (Exception)` swallowing everything | defensive coding | Combined with all of the above |

The practical static workflow is: grep the Smali for `Class;->forName`, then for each hit walk
*backwards* through the register that supplies the argument. If it traces to a `const-string`, you
have the class name for free. If it traces to `Base64;->decode`, decode it. If it traces to a
`Cipher`, you need dynamic analysis. [`scripts/find-reflection.sh`](scripts/find-reflection.sh)
automates the grep phase, and [`labs/lab-03-reflection-hunt.md`](labs/lab-03-reflection-hunt.md)
walks the whole workflow end to end.

The dynamic confirmation is one Frida hook on `Class.forName` and one on `Method.invoke`, logging
every argument. Nothing hides from that, because whatever transformation the app applied must be
undone before the runtime is called.

### 17. Should I learn Smali, or is JADX enough?

Learn to *read* Smali; you rarely need to *write* it. JADX is a decompiler, which means it is
guessing at source that would produce the observed bytecode. That guess is usually excellent and
occasionally wrong, and it fails outright on deliberately malformed bytecode, on heavily obfuscated
control flow, and on constructs the decompiler does not model. Smali is a faithful, lossless textual
rendering of the actual instructions, so it is the ground truth you fall back to.

Concretely, you need Smali when JADX emits a comment saying it could not decompile a method, when the
decompiled code does not match observed behaviour, when you want to patch an app and rebuild it, and
whenever you are looking at anti-analysis code, because anti-analysis code is specifically written to
break decompilers.

You do not need to memorise the opcode list. You need to recognise about twenty opcodes, which are in
section 9 of [`cheatsheet.md`](cheatsheet.md).

### 18. Why does JADX sometimes produce broken code or a comment saying decompilation failed?

Because decompilation is not the inverse of compilation. Compilation discards information —
local variable names, source structure, whether a loop was `for` or `while`, whether a value came
from a ternary or an `if`. The decompiler reconstructs a plausible source, and there are bytecode
sequences no plausible Java source produces, either because they came from a different source
language, from a bytecode-level optimiser, or from an obfuscator that deliberately emits legal but
un-decompilable control flow.

When you hit it, run `jadx --show-bad-code` to get the partial output, and read the method in Smali.
If several methods in one class fail, treat that as a signal in itself: someone spent effort there.
See [40 — Obfuscation](../40-Obfuscation/README.md) and [56 — JADX](../56-JADX/README.md).

---

## Concurrency and serialization

### 19. What does `synchronized` actually lock?

It locks an *object's monitor*, and the interesting question is always "which object".

`synchronized void f()` on an instance method locks `this`. `static synchronized void f()` locks the
`Class` object for that class, which is a completely different monitor from any instance.
`synchronized (x) { ... }` locks whatever `x` refers to. Two threads only exclude each other if they
lock the *same* object, which is why the classic bug is one method locking `this` and another locking
a private lock object, giving the appearance of synchronisation with none of the protection.

In Smali the block form is visible as `monitor-enter` and `monitor-exit` on a register, with an extra
`monitor-exit` on the exception path. The method form is a `declared-synchronized` access flag with
no explicit instructions, because the runtime does the locking.

### 20. Is `volatile` enough to make a counter thread-safe?

No. `volatile` guarantees *visibility* and *ordering*: a write is immediately visible to other
threads and the compiler and CPU may not reorder around it. It does not make a read-modify-write
sequence atomic. `count++` is three operations — read, add, store — and two threads can interleave
between them and lose an increment no matter how `volatile` the field is.

| Need | Use |
|---|---|
| One thread writes a flag, others read it | `volatile boolean` |
| Multiple threads increment a counter | `AtomicInteger` or `synchronized` |
| Multiple threads update a map | `ConcurrentHashMap` with `compute`/`merge` |
| Lazy singleton initialisation | static holder class, or `volatile` with double-checked locking done exactly right |
| Compound check-then-act | an explicit lock around the whole sequence |

> **⚠️ Warning**
> Security checks written as check-then-act are the concurrency bug class you should care about
> most. "Verify the file's owner, then open the file" and "check the permission, then perform the
> action" are both exploitable if anything can change between the two steps. That is a
> time-of-check-to-time-of-use bug, and it is not fixed by `volatile`.

### 21. Why is deserialization dangerous if the data is just my own app's data?

Because "my own app's data" is an assumption about the *source* of the bytes, and deserialization is
a mechanism that turns bytes into live objects with side effects before you have looked at them.

`ObjectInputStream.readObject()` reads a class name from the stream, resolves it, allocates an
instance, populates fields, and — critically — calls that class's `readObject` method if it has one,
all before returning anything to your code. Your validation runs after. If an attacker can influence
the byte stream, they choose which classes get instantiated, and they choose from every class on your
classpath, including every library you depend on. A gadget chain is a sequence of such classes whose
`readObject`, `readResolve`, `finalize`, or `hashCode` implementations, when composed, do something
useful to the attacker.

On Android, the bytes reach you from more places than developers expect: `Intent` extras from another
app, a file in shared storage, a network response, a `SharedPreferences` blob, a backup restored from
a different device. Any of those can be attacker-influenced on a rooted or malicious-app-hosting
device.

The mitigations, in order of preference, are: do not deserialize untrusted input at all and use an
explicitly parsed format such as JSON with a schema; if you must, install an `ObjectInputFilter`
allow-list; validate before you construct, never after. All three are demonstrated in
[`examples/SerializationDemo.java`](examples/SerializationDemo.java).

### 22. What is the difference between `Serializable` and `Parcelable`, and does it change the risk?

`Serializable` is a JDK mechanism that uses reflection to walk an object graph and write a
self-describing stream containing class names and field metadata. `Parcelable` is an Android
mechanism where you write the marshalling code yourself, field by field, into a `Parcel`, and a
`CREATOR` reads them back in the same order.

| Property | `Serializable` | `Parcelable` |
|---|---|---|
| Who writes the code | The runtime, reflectively | You, explicitly |
| Stream is self-describing | Yes, class names included | No, position-dependent |
| Intended lifetime | Persistence and transport | In-memory IPC only |
| Speed | Slower, reflective | Faster |
| Version tolerance | `serialVersionUID` | None — field order is the contract |
| Arbitrary class instantiation from the stream | Yes, this is the gadget problem | No, only the declared `CREATOR` runs |
| Safe to persist to disk | Discouraged | No, explicitly unsupported |

The risk profile genuinely differs. `Parcelable` does not let an attacker choose arbitrary classes,
which removes the classic gadget-chain shape. It replaces it with a different bug class: mismatched
write and read order, and type-confusion between what was written and what `createFromParcel` reads.
Android has historically had serious bugs of exactly that shape in `Bundle` handling, where a `Bundle`
written by one process and lazily unparcelled in another could be crafted so that the reading side
disagreed with the writing side about where each value ended. Study that pattern in
[26 — Intent](../26-Intent/README.md) and [25 — Binder](../25-Binder/README.md).

---

## Practicalities

### 23. Do I need Android Studio to do the labs in this chapter?

No. Everything in [`labs/`](labs/) runs from a terminal with a JDK, plus `d8` and `jadx` for the
DEX-related steps. `d8` ships inside the Android SDK build-tools, which you can install with the
standalone `cmdline-tools` package without ever opening Android Studio. `jadx` is a standalone
download. You will want a full Android Studio install later, for the emulator and the debugger, but
not for chapter 4.

### 24. Which decompiler should I trust when two disagree?

Neither, until you check the Smali. Different decompilers make different guesses, and when they
disagree the disagreement itself localises the ambiguity for you.

| Tool | Input | Strength |
|---|---|---|
| JADX | DEX and APK directly | Best Android support, good obfuscation handling, has a GUI with cross-references |
| CFR | JVM `.class` | Very good with modern language features such as lambdas and records |
| Procyon | JVM `.class` | Strong on generics and control flow reconstruction |
| Fernflower | JVM `.class` | The engine inside IntelliJ IDEA |
| baksmali | DEX | Not a decompiler — a lossless disassembler, the tiebreaker |

For DEX input, JADX is the default. For a `.class` file from a lab, comparing CFR and Procyon output
is a genuinely instructive exercise, because you see which parts of the source were reconstructable
and which were guesses.

### 25. How much Java is enough before I move on to chapter 5?

You are ready when you can do all of the following without looking anything up: write and compile a
class with a constructor, a private field, and a static method; explain why `==` on two `String`
objects can be `true` in one place and `false` in another; read a short `javap -c` listing and say
what the source was; recognise `invoke-virtual`, `invoke-static`, `invoke-direct`, `iget`, `sget`,
and `const-string` in a Smali dump; explain what `Outer$1` and `this$0` are; and explain to a
developer, in one paragraph and without hedging, why marking a field `private` does not protect a
secret.

The three labs plus the three examples in this chapter cover all of that. If a lab's success criteria
still feel like magic rather than a consequence, repeat the lab rather than moving on — every later
chapter assumes this material silently.
