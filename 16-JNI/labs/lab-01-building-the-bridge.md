# Lab 01 — Building the bridge, and breaking it on purpose

**Difficulty:** Beginner
**Time:** 90–150 minutes
**Prerequisites:** [Chapter 16 §1–§3.9](../README.md#1-introduction) ·
[04 Java](../../04-Java/README.md) · [12 DEX Internals](../../12-DEX-Internals/README.md)

**What you need:**

| Requirement | Needed for | If you do not have it |
|---|---|---|
| Python 3.8+ | Parts 1 and 2 | — (nothing else needed) |
| Any APK with native libraries | Part 3 | Take any app off your own device with `adb pull` |
| `nm` / `readelf` / `strings` | Part 3 | Use the NDK's `llvm-nm`, `llvm-readelf`, `llvm-strings` |
| Android NDK + a device or emulator | Parts 4–6 | Parts 1–3 stand alone; skip 4–6 and read them |
| Frida | Part 6 | Skip Part 6 |

---

## Objective

By the end you will be able to:

1. Mangle any Java method name to its JNI symbol, and demangle any symbol back, **by hand**, with no
   tool.
2. Read a real APK's native surface offline and say which methods are statically registered.
3. Make the runtime *tell you* the exact symbol it is looking for, so you never have to guess a
   mangling again.
4. Hook a native method and read its arguments from the correct slots.

The lab is deliberately front-loaded with paper exercises. Every hour spent later staring at a hook
whose arguments look like garbage is an hour you did not spend on Part 1.

---

## Part 1 — Mangling and demangling by hand

Do these **on paper first**. Then check with the script. Checking first defeats the point.

### 1.1 Mangle

Write the exported C symbol for each of the following. Assume none is overloaded unless stated.

| # | Java | Your answer |
|---|---|---|
| a | `com.example.Crypto.decrypt` | |
| b | `com.example.Hasher.sha256` | |
| c | `com.my_app.core.Guard.check_root` | |
| d | `com.example.Outer$Inner.compute` | |
| e | `com.x.Y$Z$W.go` | |
| f | `a.b.C.m` where `m` is overloaded and this one takes `(int)` | |
| g | `a.b.C.m` where this one takes `(byte[])` | |
| h | `a.b.C.m` where this one takes `(byte[], int, int)` | |
| i | `a.b.C.log` where this one takes `(String)` | |
| j | `com.example.A.f_` where this one takes `(int)` | |

<details>
<summary>Answers</summary>

| # | Symbol | The rule that bit |
|---|---|---|
| a | `Java_com_example_Crypto_decrypt` | dots become underscores |
| b | `Java_com_example_Hasher_sha256` | digits are fine unescaped |
| c | `Java_com_my_1app_core_Guard_check_1root` | **a literal `_` becomes `_1`**, in the package *and* the method |
| d | `Java_com_example_Outer_00024Inner_compute` | `$` is `_0` + four hex digits `0024` = `_00024` |
| e | `Java_com_x_Y_00024Z_00024W_go` | once per `$` |
| f | `Java_a_b_C_m__I` | `__` then the parameter descriptors, **no return type** |
| g | `Java_a_b_C_m___3B` | `__` + `_3B`: **three** underscores |
| h | `Java_a_b_C_m___3BII` | descriptors concatenate with no separator |
| i | `Java_a_b_C_log__Ljava_lang_String_2` | `/` becomes `_`, `;` becomes `_2` |
| j | `Java_com_example_A_f_1__I` | the method's trailing `_` is `_1`, *then* the marker |

</details>

### 1.2 Demangle

Recover the class, method and parameters. State explicitly what you **cannot** recover.

| # | Symbol | Your answer |
|---|---|---|
| a | `Java_org_conscrypt_NativeCrypto_EVP_1MD_1CTX_1create` | |
| b | `Java_com_a_b_c_d_e` | |
| c | `Java_com_vendor_Guard_00024Native_verify___3BLjava_lang_String_2` | |
| d | `Java_p_q_R_s_1t_1u__I_3B` | |

<details>
<summary>Answers</summary>

| # | Recovered | Notes |
|---|---|---|
| a | class `org.conscrypt.NativeCrypto`, method `EVP_MD_CTX_create` | three `_1` escapes in one method name; this shape is everywhere in real crypto bindings |
| b | class `com.a.b.c`, method `d_e`? **No** — class `com.a.b.c.d`, method `e` | the *last* separator splits class from method, and there is no way to tell a short package from a long one; you need the Java side to be sure |
| c | class `com.vendor.Guard$Native`, method `verify`, params `(byte[], String)` | `_00024` for the inner class, `_3B` for `byte[]`, `Ljava_lang_String_2` for `String` |
| d | class `p.q.R`, method `s_t_u`, params `(int, byte[])` | escapes decoded *before* the `__` split |

In every case the **return type is not recoverable**. The JNI long name encodes parameters only.

</details>

### 1.3 Check with the tool

```bash
# host
cd 16-JNI/scripts
python3 jni_mangle.py --selftest

python3 jni_mangle.py --mangle 'com.my_app.core.Guard.check_root'
python3 jni_mangle.py --mangle 'a.b.C.m([BII)V'
python3 jni_mangle.py --demangle Java_com_vendor_Guard_00024Native_verify___3BLjava_lang_String_2
```

> **Success criterion for Part 1.** You got at least 8 of 10 in 1.1 and 3 of 4 in 1.2 *before*
> running the script, and you can state the four escapes and the overload rule from memory.

---

## Part 2 — Descriptors and the argument layout

### 2.1 Signatures

Write the JNI signature for each declaration.

| Java declaration | Signature |
|---|---|
| `void run()` | |
| `int size()` | |
| `byte[] encrypt(byte[] plain, int mode)` | |
| `boolean verify(String sig, byte[] data)` | |
| `String join(String[] parts, char sep)` | |
| `long open(android.content.Context ctx, boolean readOnly)` | |
| `Outer.Inner find(long id)` in package `com.example` | |
| a constructor taking `(byte[])` | |

<details>
<summary>Answers</summary>

`()V` · `()I` · `([BI)[B` · `(Ljava/lang/String;[B)Z` ·
`([Ljava/lang/String;C)Ljava/lang/String;` · `(Landroid/content/Context;Z)J` ·
`(J)Lcom/example/Outer$Inner;` · `([B)V` with the name `<init>`

</details>

### 2.2 The layout

For each of these, say what is in `args[0]`, `args[1]`, `args[2]`, `args[3]`.

| Declaration | `args[0]` | `args[1]` | `args[2]` | `args[3]` |
|---|---|---|---|---|
| `public native byte[] encrypt(byte[] p, int mode)` | | | | |
| `public static native boolean verify(String s, byte[] d)` | | | | |
| `@CriticalNative static native int fastHash(long ptr, int len)` | | | | |

<details>
<summary>Answers</summary>

| Declaration | `args[0]` | `args[1]` | `args[2]` | `args[3]` |
|---|---|---|---|---|
| instance `encrypt` | `JNIEnv *` | `jobject` (the receiver) | `jbyteArray p` | `jint mode` |
| static `verify` | `JNIEnv *` | `jclass` (the declaring class) | `jstring s` | `jbyteArray d` |
| `@CriticalNative fastHash` | `jlong ptr` | `jint len` | — | — |

The third row is the exception that proves the rule, and the reason
[§3.21](../README.md#321-fastnative-and-criticalnative) exists. If you hook a `@CriticalNative`
method with the standard assumption, every argument is off by two.

</details>

Check yourself:

```bash
# host
python3 jni_mangle.py --parse '([BI)[B'
python3 jni_mangle.py --parse '(Ljava/lang/String;[B)Z' --static
python3 jni_mangle.py --parse '(JI)I' --critical
```

---

## Part 3 — Read a real APK, offline

Pick any app on your own device that ships native code. A messaging app, a game, or a banking app all
work; the more protected it is, the more interesting Part 3.5 becomes.

```bash
# host — get an APK off the device
adb shell pm list packages | grep -i <something>
adb shell pm path com.example.target
adb pull /data/app/~~.../base.apk target.apk
```

### 3.1 Inventory

```bash
# host
unzip -l target.apk 'lib/*'
mkdir -p work && unzip -oq target.apk 'lib/*' -d work
ls work/lib/
```

Record: how many ABIs? How many `.so` files? Which look like third-party SDKs by name?

### 3.2 Static registration

```bash
# host
for so in work/lib/arm64-v8a/*.so; do
  echo "== $(basename "$so")"
  nm -D --defined-only "$so" 2>/dev/null | awk '$2=="T"{print $3}' | grep '^Java_'
done
```

Demangle everything you found:

```bash
# host
for so in work/lib/arm64-v8a/*.so; do
  nm -D --defined-only "$so" 2>/dev/null | awk '$2=="T"{print $3}' | grep '^Java_' \
  | while read -r s; do python3 16-JNI/scripts/jni_mangle.py --demangle "$s"; echo; done
done
```

### 3.3 Dynamic registration signal

```bash
# host
for so in work/lib/*/*.so; do
  if nm -D "$so" 2>/dev/null | grep -q JNI_OnLoad; then
    n=$(nm -D --defined-only "$so" 2>/dev/null | grep -c ' Java_')
    echo "$so   exports JNI_OnLoad, Java_* count = $n"
  fi
done
```

A library exporting `JNI_OnLoad` with **zero** `Java_*` symbols is registering everything
dynamically. Note which ones; Lab 03 comes back for them.

### 3.4 The signature strings

```bash
# host
strings -a work/lib/arm64-v8a/libtarget.so | grep -E '^\([A-Z\[L]' | sort -u | head -30
strings -a work/lib/arm64-v8a/libtarget.so | grep -E '^[a-z]+(/[A-Za-z0-9_$]+)+$' | sort -u | head -30
```

These survive dynamic registration, because `RegisterNatives` needs them as plain strings. Note the
difference in form: `FindClass` takes `com/example/Crypto` with no `L` and no `;`, while a descriptor
inside a signature is `Lcom/example/Crypto;`.

### 3.5 The obfuscation observation

Now decompile the app and look at the classes whose names you recovered in 3.2.

```bash
# host
jadx -d out target.apk 2>/dev/null | tail -5
grep -rn "class " out/sources/ | grep -c .        # rough class count
```

**The question to answer, in writing:** in an app whose classes are otherwise named `a.b.c`, why do
the classes with native methods still have real names? Write the answer in one sentence, then check
it against [§3.7](../README.md#37-static-registration--binding-by-symbol-lookup).

> **Success criterion for Part 3.** You have a table: every `.so`, its exported `Java_*` symbols
> demangled, and a yes/no on whether it also exports `JNI_OnLoad`. And you can explain why the
> surviving class names are an analysis foothold rather than a coincidence.

You can produce the same table in one command:

```bash
# host
bash 16-JNI/scripts/jni-triage.sh target.apk
```

Run it *after* doing it by hand once. The script is a time-saver, not a substitute for knowing what
it does.

---

## Part 4 — Build the bridge yourself

Follow [`../examples/README.md`](../examples/README.md) to build `HelloJni.java` and `hello_jni.c`
into a test app.

### 4.1 Confirm the symbols

```bash
# host
nm -D --defined-only libhellojni.so | grep ' T Java_'
```

You should see exactly four symbols, including `..._describe__I` and `..._describe___3B`. Count the
underscores in the second one. **Three.**

### 4.2 Confirm the DEX side

```bash
# host — after building the APK
apktool d -f -o out app-debug.apk >/dev/null
grep -rn "\.method.*native" out/smali/com/example/jnidemo/HelloJni.smali
```

Note that each native method has **no body and no `.locals`** — there is no bytecode for it. In the
DEX these carry `ACC_NATIVE` (`0x0100`) with `code_off = 0`
([12 DEX Internals](../../12-DEX-Internals/README.md) §3.13).

---

## Part 5 — Make the runtime tell you the symbol

This is the technique to remember from this lab.

### 5.1 Break the binding

Take a copy of your library and remove one symbol, or simply rename the C function and rebuild:

```c
/* change */  Java_com_example_jnidemo_HelloJni_greeting
/* to     */  Java_com_example_jnidemo_HelloJni_greetingX
```

Rebuild, reinstall, run.

### 5.2 Read the answer out of logcat

```bash
# host
adb logcat -c
adb shell am start -n com.example.jnidemo/.MainActivity
adb logcat | grep -A5 UnsatisfiedLinkError
```

You will see something of this shape:

```text
java.lang.UnsatisfiedLinkError: No implementation found for
  java.lang.String com.example.jnidemo.HelloJni.greeting(java.lang.String)
  (tried Java_com_example_jnidemo_HelloJni_greeting
     and Java_com_example_jnidemo_HelloJni_greeting__Ljava_lang_String_2)
```

**ART just printed both names it searched for.** You never have to guess a mangling: declare the
method, call it without an implementation, and read the answer.

### 5.3 Two things to notice

1. **The failure happened at the call, not at load.** `System.loadLibrary` succeeded. Binding is
   lazy and per method ([§3.7](../README.md#37-static-registration--binding-by-symbol-lookup)).
   Add a log line before and after `loadLibrary` to see this for yourself.
2. **It tried the short name first, then the long one.** That ordering is why an overloaded method
   works without you doing anything special, and why a *non*-overloaded method still binds if you
   only export the long form.

> **Success criterion for Part 5.** You can state, without notes, how to make ART print the exact
> symbol it wants, and why the error appears at call time rather than load time.

---

## Part 6 — Your first correct native hook

### 6.1 Hook it wrongly, on purpose

```javascript
// frida -U -f com.example.jnidemo -l wrong.js --no-pause
const a = Module.findExportByName('libhellojni.so',
                                  'Java_com_example_jnidemo_HelloJni_greeting');
Interceptor.attach(a, {
  onEnter(args) {
    // WRONG on purpose: treating args[0] as the first Java parameter.
    console.log('name = ' + args[0].readCString());
  }
});
```

Run it. You will get garbage, or a crash. Write down what you actually saw — the point of doing this
deliberately is that you will recognise the symptom in six months when you do it by accident.

### 6.2 Hook it correctly

```javascript
// frida -U -f com.example.jnidemo -l right.js --no-pause
'use strict';

function jstringToJs(h) {
  if (h.isNull()) return null;
  const env = Java.vm.getEnv();
  const p = env.getStringUtfChars(h, null);
  const s = p.readCString();
  env.releaseStringUtfChars(h, p);      // pair the get, always
  return s;
}

Java.perform(function () {
  const a = Module.findExportByName('libhellojni.so',
                                    'Java_com_example_jnidemo_HelloJni_greeting');
  Interceptor.attach(a, {
    onEnter(args) {
      console.log('args[0] JNIEnv* = ' + args[0]);
      console.log('args[1] jobject = ' + args[1]);
      console.log('args[2] jstring = ' + jstringToJs(args[2]));   // the real argument
    },
    onLeave(retval) {
      // retval is a jstring HANDLE, not a char*. Go back through JNIEnv.
      console.log('returned        = ' + jstringToJs(retval));
    }
  });
});
```

### 6.3 Use the tracer

```bash
# host — edit the TARGETS array first
frida -U -f com.example.jnidemo -l ../scripts/jni-arg-tracer.js --no-pause
```

The default `TARGETS` entry in that script is exactly this method, so it should work unmodified
against the example app.

### 6.4 The static one

Hook `Java_com_example_jnidemo_HelloJni_version` and print `args[1]`. It is a `jclass`, not a
`jobject`. Confirm with:

```javascript
// inside onEnter
const env = Java.vm.getEnv();
console.log('ref type = ' + env.getObjectRefType(args[1]));   // 1 = local
```

> **Success criterion for Part 6.** You can hook any native method in the sample and print every
> declared argument correctly, and you can explain to somebody else why `args[0]` is not the first
> argument.

---

## Hints

<details>
<summary>Hint 1 — my grep for the method name finds nothing in the .so</summary>

Almost certainly an escape. `check_root` is `check_1root`. An inner class contains `_00024`. Run the
name through `jni_mangle.py --mangle` and grep for *that*.

</details>

<details>
<summary>Hint 2 — nm prints nothing at all</summary>

Three possibilities, in order of likelihood: you are looking at the wrong ABI directory; the library
registers dynamically (check for `JNI_OnLoad`); or your `nm` cannot read the file — try
`llvm-nm` from the NDK, or `readelf --dyn-syms -W`.

</details>

<details>
<summary>Hint 3 — Frida cannot find the export</summary>

The library may not be loaded yet. Either spawn with `-f` and hook `dlopen` to wait for it, or use
the retry loop at the bottom of `jni-arg-tracer.js`. Confirm what is loaded with
`Process.enumerateModules().map(m => m.name)`.

</details>

<details>
<summary>Hint 4 — the string I print is empty or truncated</summary>

`GetStringUTFChars` returns modified UTF-8, which is NUL-terminated, so `readCString` is right. An
empty result usually means you read `args[1]` (the receiver) rather than `args[2]`.

</details>

---

## Success criteria

| # | Criterion |
|---|---|
| 1 | You mangled and demangled by hand, correctly, before touching the script |
| 2 | You can state the four escapes and the overload rule from memory |
| 3 | You produced the static-registration inventory for a real APK and demangled every symbol |
| 4 | You identified at least one library that registers dynamically, or established that none does |
| 5 | You made ART print the two symbols it searched for |
| 6 | You explained why binding fails at call time, not load time |
| 7 | You hooked a native method and read every declared argument from the correct slot |
| 8 | You can explain the obfuscation anchor in one sentence |

---

## What to write down

Keep a one-page note for the target you triaged. It is the start of every engagement:

```text
target: com.example.target
abis:   arm64-v8a, armeabi-v7a
libs:   libfoo.so   (12 Java_* symbols, no JNI_OnLoad)   -> static
        libbar.so   (0 Java_* symbols, JNI_OnLoad)       -> DYNAMIC, revisit in lab 03
        libc++_shared.so                                  -> runtime, ignore
classes surviving obfuscation (from the symbols):
        com.target.security.Attestation
        com.target.crypto.Sealer
open questions:
        libbar.so registers what, against which class?
```

---

## Next

[Lab 02 — References, exceptions, and the crash you can cause](lab-02-references-and-exceptions.md)
