# 16 — JNI · Examples

The five graded examples from [§9 of the chapter](../README.md#9-examples), shipped as sources.

> **✅ Every C and C++ file here has now been compiled.** All six build **clean** with
> `-Wall -Wextra` using `aarch64-linux-android21-clang` and `aarch64-linux-android21-clang++` from
> **NDK 25.2.9519653**, targeting `arm64-v8a` at API 21. Run [`build.sh`](build.sh) to reproduce
> that in one command; it builds out of tree and then measures the three claims this page makes
> about the resulting binaries rather than asserting them.
>
> This note used to say the opposite — *"Nothing here has been compiled… the machine this repository
> was written on has no C toolchain"* — and that was wrong twice over. The toolchain was there all
> along, and compiling the files disproved one of the claims below. See
> [the -O2 result](#the--o2-result-a-claim-on-this-page-was-wrong).

---

## What is here

| File | Example | What it demonstrates |
|---|---|---|
| [`HelloJni.java`](HelloJni.java) | 9.1 | A statically registered native method, an overloaded pair, and a static native |
| [`hello_jni.c`](hello_jni.c) | 9.1 | The minimum correct C side: two synthetic parameters, NULL checks, paired releases |
| [`safe_jni.c`](safe_jni.c) | 9.2 | Strings and arrays handled correctly on every path, including the error paths |
| [`unsafe_jni.c`](unsafe_jni.c) | 9.3a | **Deliberately vulnerable.** Five defects, each marked `VULN:` with its trigger |
| [`fixed_jni.c`](fixed_jni.c) | 9.3b | The same five functions written correctly, each change marked `FIX:` |
| [`UnsafeDemo.java`](UnsafeDemo.java) | 9.3c | The Java side, with three working bypasses of its own validation |
| [`dynamic_registration.c`](dynamic_registration.c) | 9.4 | A library exporting **only** `JNI_OnLoad`; the target for Lab 03 |
| [`EnterpriseBridge.java`](EnterpriseBridge.java) | 9.5a | A disciplined public API: opaque tokens, atomic close, no length parameters |
| [`enterprise_bridge.cpp`](enterprise_bridge.cpp) | 9.5b | RAII wrappers, a session registry, thread attachment, full exception discipline |
| [`build.sh`](build.sh) | — | Builds all six out of tree with `-Wall -Wextra`, then measures the symbol claims below |

---

## What "verified" means for these files

| File | Built as | Flags | Result |
|---|---|---|---|
| `hello_jni.c` | `libhellojni.so` | `-shared -fPIC -O2 -Wall -Wextra` | clean, 4 `Java_*` exports |
| `safe_jni.c` | `libsafe.so` | hardened set below | clean |
| `unsafe_jni.c` | `libunsafe.so` | `-O0 -fno-stack-protector -U_FORTIFY_SOURCE` | clean |
| `fixed_jni.c` | `libfixed.so` | hardened set below | clean |
| `dynamic_registration.c` | `libguard.so` | `-shared -fPIC -O2 -Wall -Wextra` | clean, 2 exports, **and see §the -O2 result** |
| `enterprise_bridge.cpp` | `libenterprise.so` | `-std=c++17 -fvisibility=hidden -static-libstdc++`, hardened | clean |

Compiler: `aarch64-linux-android21-clang` / `clang++` from NDK **25.2.9519653**
(`clang version 14.0.7`, `Linker: LLD 14.0.7`), host tag `windows-x86_64`, target `arm64-v8a`.

"Clean" here means **zero diagnostics**, not "no errors". `build.sh` treats any warning as a failure
for exactly the reason this chapter exists: in JNI, the warnings that matter — a missing `const`, an
unchecked return, a signed/unsigned comparison on a `jsize` — are the ones that turn into the
vulnerability classes in [§5](../README.md#5-security-perspective).

What has **not** been verified: none of these libraries has been loaded by ART on a device, because
the Java sides of examples 9.2 and 9.4 are deliberately left for you to write (see below). Symbol
layout, obfuscation behaviour and warning-cleanliness are measured; runtime behaviour is not.

---

## Safety notice

`unsafe_jni.c` and `UnsafeDemo.java` are intentionally exploitable. They exist to make one sentence
concrete: *a bounds check written in Java protects nothing once the value crosses into C.*

- Build them only inside a throwaway app, on a device or emulator you own.
- Do not copy any function out of `unsafe_jni.c`. Copy from `fixed_jni.c`.
- The two files export **identical symbol names**, deliberately: swapping the library is the whole
  fix, with no Java change required. That is also how you verify a correction — run Lab 02's triggers
  against each in turn.

---

## Building

### The one-command route

```bash
# host — builds all six out of tree, then runs the symbol measurements below
./build.sh

# host — 32-bit ARM instead of arm64
ABI=armeabi-v7a ./build.sh

# host — put the binaries somewhere specific
OUTDIR=/tmp/ch16 ./build.sh
```

[`build.sh`](build.sh) finds your NDK, applies the right flag set to each file (hardened for the
libraries that should be hardened, deliberately soft for `unsafe_jni.c`), and **treats any warning
as a failure**. It writes nothing into the repository: `.so` and `.o` are on the artefact blocklist,
so everything lands under `$OUTDIR`, which defaults to `${TMPDIR:-/tmp}/ch16-build`.

Read the rest of this section if you want to know what those flags are and why. The manual commands
below are what the script runs.

### What you need

| Tool | Why | Where |
|---|---|---|
| Android NDK r21 or newer | the clang cross-compiler and `jni.h` | <https://developer.android.com/ndk/downloads> |
| A JDK 11 or newer | `javac`, and `javac -h` to generate headers | any distribution |
| `nm`, `readelf`, `strings` | verifying the symbols came out right | binutils, or the NDK's `llvm-*` equivalents |

Set these first:

```bash
# host
export NDK=$HOME/Android/Sdk/ndk/26.1.10909125          # your path
export HOSTTAG=linux-x86_64                              # or darwin-x86_64, windows-x86_64
export TC=$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin
export API=21
```

### One library, directly with clang

```bash
# host — arm64
$TC/aarch64-linux-android$API-clang \
    -shared -fPIC -O2 \
    -o libhellojni.so hello_jni.c

# host — arm32
$TC/armv7a-linux-androideabi$API-clang \
    -shared -fPIC -O2 \
    -o libhellojni.so hello_jni.c
```

For the hardened build that `fixed_jni.c` and `enterprise_bridge.cpp` assume:

```bash
# host
$TC/aarch64-linux-android$API-clang \
    -shared -fPIC -O2 \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    -o libfixed.so fixed_jni.c
```

And for `unsafe_jni.c`, if you want the overflows to be *visible* rather than caught by a canary:

```bash
# host — the deliberately soft build, for the lab only
$TC/aarch64-linux-android$API-clang \
    -shared -fPIC -O0 -fno-stack-protector -U_FORTIFY_SOURCE \
    -o libunsafe.so unsafe_jni.c
```

Keeping the hardening on is the more realistic test. It turns most of these from silent corruption
into a clean abort — which is exactly the severity conversation
[§5.2](../README.md#52-vulnerability-class-1--the-java-check-that-the-native-code-does-not-honour)
tells you to have with a client.

The C++ example needs the C++ driver and the STL:

```bash
# host
$TC/aarch64-linux-android$API-clang++ \
    -shared -fPIC -O2 -std=c++17 -fvisibility=hidden \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now \
    -static-libstdc++ \
    -o libenterprise.so enterprise_bridge.cpp
```

### Inside an Android Studio project

Drop the sources into `app/src/main/cpp/` and add:

```cmake
# app/src/main/cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.22)
project(jnidemo)

add_library(hellojni SHARED hello_jni.c)
add_library(safe     SHARED safe_jni.c)
add_library(unsafe   SHARED unsafe_jni.c)
add_library(fixed    SHARED fixed_jni.c)
add_library(guard    SHARED dynamic_registration.c)
add_library(enterprise SHARED enterprise_bridge.cpp)

# The hardened set. Note `unsafe` is deliberately NOT hardened.
foreach(t safe fixed guard enterprise)
    target_compile_options(${t} PRIVATE -fstack-protector-strong -D_FORTIFY_SOURCE=2)
    target_link_options(${t} PRIVATE -Wl,-z,relro,-z,now)
endforeach()

target_compile_options(unsafe PRIVATE -fno-stack-protector -U_FORTIFY_SOURCE -O0)
```

```kotlin
// app/build.gradle.kts
android {
    externalNativeBuild {
        cmake { path = file("src/main/cpp/CMakeLists.txt") }
    }
    defaultConfig {
        ndk { abiFilters += listOf("arm64-v8a") }
    }
}
```

The Java sources go under `app/src/main/java/` in packages matching their `package` declarations:

| File | Package | Path |
|---|---|---|
| `HelloJni.java` | `com.example.jnidemo` | `java/com/example/jnidemo/HelloJni.java` |
| `UnsafeDemo.java` | `com.example.jnidemo` | `java/com/example/jnidemo/UnsafeDemo.java` |
| `EnterpriseBridge.java` | `com.example.bridge` | `java/com/example/bridge/EnterpriseBridge.java` |

`safe_jni.c` implements methods on a class `com.example.jnidemo.SafeCodec` that is not shipped here;
declare it yourself from the signatures in the comments, or read the file as reference material. The
declarations you need are:

```java
package com.example.jnidemo;

public class SafeCodec {
    static { System.loadLibrary("safe"); }
    public native byte[] transform(byte[] in);            // ([B)[B
    public native String normalise(String s);             // (Ljava/lang/String;)Ljava/lang/String;
    public native int    countNonEmpty(String[] items);   // ([Ljava/lang/String;)I
    public native void   deliver(Callback cb, byte[] p);  // (Lcom/example/jnidemo/Callback;[B)V
}
```

Similarly `dynamic_registration.c` registers against `com.example.jnidemo.Guard`:

```java
package com.example.jnidemo;

public class Guard {
    static { System.loadLibrary("guard"); }
    private native boolean check(String tag);      // (Ljava/lang/String;)Z
    private native byte[]  seal(byte[] payload);   // ([B)[B
    private static native long nativeInit();       // ()J
    public  void onVerdict(boolean ok) { }         // (Z)V — the cached callback
}
```

Those two are left for you to write because writing them is the exercise: you have to get the
descriptors exactly right or `RegisterNatives` fails with `NoSuchMethodError`, and that failure is
itself the lesson.

---

## Verifying the build did what the chapter says

Every block below is **real output**, captured from the binaries `build.sh` produced with NDK
25.2.9519653 for `arm64-v8a`. Addresses will differ on your NDK revision; the symbol names will not.

```bash
# host — static registration produced exported symbols
llvm-nm -D --defined-only libhellojni.so | grep ' T Java_'
#   00000000000018b8 T Java_com_example_jnidemo_HelloJni_describe__I
#   0000000000001908 T Java_com_example_jnidemo_HelloJni_describe___3B   <- three underscores
#   00000000000017cc T Java_com_example_jnidemo_HelloJni_greeting
#   00000000000019fc T Java_com_example_jnidemo_HelloJni_version

# host — dynamic registration produced almost nothing
llvm-nm -D --defined-only libguard.so | grep ' T '
#   000000000000183c T JNI_OnLoad
#   0000000000001aac T JNI_OnUnload

# host — the signatures still leak, because RegisterNatives needs them at runtime
llvm-strings -a libguard.so | grep -E '^\([A-Z\[L]'
#   (Z)V
#   (L%s/%s/String;)Z

# host — and the class name? See the next section. This does NOT print nothing.
llvm-strings -a libguard.so | grep -i 'com/example'
#   com/example/jnidemo/Guar([B)[B
```

Two details in that output are worth pausing on, because both are things a reader would otherwise
assume were typos:

- `describe___3B` really has **three** consecutive underscores. Two come from the overload separator
  `__`, and the third is the `_3` escape that encodes `[` (array) in front of `B` (byte). One
  underscore is the mangling; the run of three is the mangling of a mangling.
- `(L%s/%s/String;)Z` is not a corrupted descriptor. `dynamic_registration.c` assembles that
  signature at runtime with `snprintf(g_s1, …, "(L%s/%s/String;)Z", "java", "lang")`, so what lands
  in `.rodata` is the *template*, not the result. Whereas `(Z)V` — the `onVerdict` callback
  signature, passed straight to `GetMethodID` — is a plain literal and is fully readable.

### The -O2 result: a claim on this page was wrong

This page used to state that `strings -a libguard.so | grep -i 'com/example'` produces **no output**,
because `dynamic_registration.c` XORs the class name `com/example/jnidemo/Guard` with `0x5A` and
decodes it into a stack buffer inside `JNI_OnLoad`. That claim was never compiled. When it was, it
turned out to be **false at exactly the optimisation level this page told you to use**.

Same source file, five optimisation levels, one `grep` — measured, not argued:

| Build | `strings -a … \| grep -i com/example` |
|---|---|
| `-O0` | *(nothing — obfuscation holds)* |
| `-O1` | *(nothing — obfuscation holds)* |
| **`-O2`** | **`com/example/jnidemo/Guar([B)[B`** |
| `-Os` | *(nothing — obfuscation holds)* |
| `-Oz` | *(nothing — obfuscation holds)* |

> **🔬 Under the Hood**
> At `-O2`, clang can see that `kClassEnc` is a compile-time constant array, that `XK` is a
> compile-time constant, and that `unxor()` is a small loop with no side effects. So it evaluates the
> loop **at compile time** and emits the answer directly. The de-obfuscation code that appears in
> the source does not exist in the binary.

The disassembly says it plainly. This is `JNI_OnLoad` in the `-O2` build:

```text
18ac: adrp  x8, 0x0
18b0: adrp  x9, 0x0
18bc: ldr   q0, [x8, #1488]     ; 0x5d0 -> 16 bytes: "com/example/jnid"
18c0: mov   w8, #100            ; 100 == 0x64 == 'd'
18c4: ldr   d1, [x9, #1504]     ; 0x5e0 ->  8 bytes: "emo/Guar"
18c8: str   q0, [sp]
18cc: str   d1, [sp, #16]
18d0: strh  w8, [sp, #24]       ; 'd' and the NUL, as a halfword immediate
18dc: blr   x8                  ; FindClass(env, "com/example/jnidemo/Guard")
```

The first 24 characters are copied out of `.rodata` as one 16-byte and one 8-byte load. The 25th,
`'d'`, is an **immediate operand** — `mov w8, #100` — so it never becomes a byte in a data section.
That is why `strings` prints `Guar` and not `Guard`, and why the run continues straight into the
adjacent `([B)[B`: there is no NUL between them. Confirm it in the section dump:

```bash
# host
llvm-readelf -x .rodata libguard.so | head -3
#   0x000005d0 636f6d2f 6578616d 706c652f 6a6e6964 com/example/jnid
#   0x000005e0 656d6f2f 47756172 285b4229 5b42006f emo/Guar([B)[B.o
```

**Three things follow, and they are the point of the whole example.**

1. **A truncated-by-one plaintext string is a fingerprint, not a coincidence.** When you find
   `com/example/foo/Guar`, `getRuntim`, or `/system/xbin/s` in a stripped library, you are almost
   certainly looking at a constant-folded de-obfuscation routine whose tail character became an
   immediate. Search the disassembly near the string's cross-reference for a `mov` of a printable
   ASCII value; it will complete the name for you.
2. **String obfuscation that the optimiser can evaluate is not obfuscation.** Nothing was wrong with
   the XOR loop as written. It was defeated by the compiler, silently, with no diagnostic, in the
   build configuration a release APK actually ships. Defeating it requires a runtime-derived key,
   a `volatile` barrier, or an opaque predicate the optimiser cannot fold — all of which
   [40-Obfuscation](../../40-Obfuscation/README.md) covers, and none of which change the recovery
   technique in [lab 03](../labs/lab-03-recovering-dynamic-natives.md).
3. **You cannot know which you have without looking at the binary you shipped.** Reading the source
   would tell you the name is hidden. Only `strings` on the artefact tells you it is not — and the
   answer changes with `-O`, with the NDK revision, and with LTO. This is the concrete reason
   [§8](../README.md#8-static-analysis) insists on analysing the built `.so` rather than the code
   that produced it.

`build.sh` reproduces the whole table above under step **3**, so you can watch the claim fail on
your own toolchain rather than believing this one.

Check any symbol against the demangler without leaving your desk:

```bash
# host
python3 ../scripts/jni_mangle.py --demangle Java_com_example_jnidemo_HelloJni_describe___3B
python3 ../scripts/jni_mangle.py --mangle 'com.example.jnidemo.HelloJni.describe([B)Ljava/lang/String;'
```

---

## Related

- [Chapter README §9](../README.md#9-examples) — what each example is for
- [`../labs/lab-02-references-and-exceptions.md`](../labs/lab-02-references-and-exceptions.md) — drives `unsafe_jni.c` and `fixed_jni.c`
- [`../labs/lab-03-recovering-dynamic-natives.md`](../labs/lab-03-recovering-dynamic-natives.md) — drives `dynamic_registration.c`
- [`../scripts/jni_mangle.py`](../scripts/jni_mangle.py) — mangle and demangle offline
- [`../scripts/dump-registernatives.js`](../scripts/dump-registernatives.js) — recover what `nm -D` cannot see
- [`../../37-RootDetection/examples/native_root_check.c`](../../37-RootDetection/examples/native_root_check.c) — the same dynamic-registration technique applied to a root check
