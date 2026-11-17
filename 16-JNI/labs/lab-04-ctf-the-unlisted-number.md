# Lab 04 — CTF: The Unlisted Number

**Difficulty:** CTF
**Time:** 3–6 hours
**Prerequisites:** [Lab 01](lab-01-building-the-bridge.md) · [Lab 02](lab-02-references-and-exceptions.md) ·
[Lab 03](lab-03-recovering-dynamic-natives.md) · all of
[Chapter 16 §3](../README.md#3-deep-internal-working)

---

## The challenge

An app has one screen: a text field and a button. Type the flag, press the button, and it says
**Correct** or **Nope**.

Your usual moves do not work.

- `jadx` shows a class called `com.unlisted.b.a` with a method `a(String)` that returns nothing
  useful, and a `native` method whose name is a single letter.
- `nm -D` on the library shows exactly two symbols: `JNI_OnLoad` and `JNI_OnUnload`.
- `strings` on the library finds no flag and no method names. It does find two signature fragments
  and the class name — see the warning under **Build** for exactly which, and why none of them helps.
- Hooking the Java method and forcing it to return `true` makes the app say **Correct** — and gives
  you nothing, because the flag is what you are being asked for.
- You hook the native function you recovered, and every argument you print is garbage.

**Recover the flag.**

There are at least four independent solutions. Find one. Then find a second, because the point of
this lab is that the JNI boundary offers several different angles on the same secret.

---

## Rules

- **No brute-forcing the whole flag.** The per-byte oracle is one of the intended solutions and is
  explicitly allowed; guessing 30 characters at once is not.
- **No reading the flag out of a string constant.** There isn't one. It is derived at runtime.
- **No patching the app to print it.** You may patch to *explore*, but the solve must recover the
  real value.
- **You must be able to explain the mechanism that defeated your first attempt.** All four defences
  below are things this chapter told you about. If you got stuck on one, name which section covers
  it.

---

## Building the challenge

Building it is part of the lab: you will understand each defence better having implemented it. All
three files go into a throwaway app.

### `Checker.java`

```java
// app/src/main/java/com/unlisted/b/a.java  (class name deliberately obfuscation-shaped)
package com.unlisted.b;

public final class a {

    static {
        System.loadLibrary("unlisted");
    }

    // Registered dynamically, so this name is free to be meaningless.
    // Signature: (Ljava/lang/String;)I
    // Returns the index of the first mismatching character, or -1 for a match.
    private native int c(String candidate);

    // A @CriticalNative helper: NO JNIEnv*, NO jclass, primitives only.
    // Signature: (JI)I
    @dalvik.annotation.optimization.CriticalNative
    private static native int d(long ctx, int idx);

    // Returns an opaque long. Or does it?
    // Signature: ()J
    private static native long e();

    private long ctx;

    public a() {
        ctx = e();
    }

    /** The only public entry point. */
    public boolean check(String candidate) {
        if (candidate == null) return false;
        return c(candidate) < 0;
    }
}
```

> **Note on `@CriticalNative`.** The annotation lives in `dalvik.annotation.optimization` and is not
> part of the public SDK, so a plain app build may warn or refuse. If your toolchain rejects it,
> build the challenge without the annotation and *pretend* the calling convention is
> different for `d` — or better, read [§3.21](../README.md#321-fastnative-and-criticalnative) and
> work out by hand what a hook on it would see. The lesson survives either way. On a platform build
> or with the annotation stripped from the DEX manually, it works as written.

### `MainActivity.java`

```java
// app/src/main/java/com/unlisted/MainActivity.java
package com.unlisted;

import android.app.Activity;
import android.os.Bundle;
import android.widget.*;
import com.unlisted.b.a;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle s) {
        super.onCreate(s);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);

        final EditText in = new EditText(this);
        final TextView out = new TextView(this);
        Button go = new Button(this);
        go.setText("check");

        final a checker = new a();
        go.setOnClickListener(v ->
            out.setText(checker.check(in.getText().toString()) ? "Correct" : "Nope"));

        root.addView(in); root.addView(go); root.addView(out);
        setContentView(root);
    }
}
```

### `unlisted.c`

```c
/* app/src/main/cpp/unlisted.c
 *
 * The challenge library. Four defences, each one a technique from chapter 16:
 *
 *   D1  dynamic registration, so no Java_* symbol exists at all      (3.8)
 *   D2  a DECOY registration first, replaced by the real one later    (3.8, 4.4)
 *   D3  one method is @CriticalNative, so args[0] is NOT JNIEnv*      (3.21)
 *   D4  the expected bytes are derived at runtime into a heap struct
 *       whose address is handed to Java as a jlong                    (5.5)
 *
 * The flag is never a string constant anywhere.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- */
/* The context. Its ADDRESS is what e() returns to Java as a jlong.  */
/* ---------------------------------------------------------------- */

#define FLAG_LEN 30

typedef struct {
    unsigned  magic;              /* 0x4A4E4931 = "JNI1" */
    int       len;
    unsigned char expected[64];   /* derived at runtime; never a literal */
} Ctx;

/* Obfuscated seed material: seed[i] = flag[i] ^ key(i).
 * There is therefore NO plaintext flag anywhere in the binary, and
 * `strings` finds nothing. `expected` exists only in heap memory, and only
 * after e() has been called. */
static const unsigned char kSeed[FLAG_LEN] = {
    0x10, 0x0f, 0x25, 0x70, 0x42, 0xb5, 0xcb, 0xb8, 0xec, 0xdc,
    0x39, 0x11, 0x2d, 0x77, 0x7f, 0xb8, 0xde, 0xe2, 0xe3, 0x2e,
    0x28, 0x01, 0x39, 0x44, 0xa6, 0xca, 0x80, 0xfe, 0x00, 0x00
};

static unsigned char keyfor(int i) {
    /* A trivial keystream. Its weakness is deliberate and irrelevant: the
     * lesson of this lab is that the STRENGTH of the obscuring does not
     * change any of the recovery paths. */
    unsigned x = 0x5A ^ (unsigned)((i * 0x1B) & 0xFF);
    return (unsigned char)(x & 0xFF);
}

static void derive(Ctx *c) {
    c->magic = 0x4A4E4931u;
    c->len = 28;                                  /* the flag's real length */
    for (int i = 0; i < c->len; i++) {
        c->expected[i] = (unsigned char)(kSeed[i] ^ keyfor(i));
    }
    c->expected[c->len] = 0;
}

/* Regenerate kSeed with:
 *   python3 -c "
 * flag='...'
 * key=lambda i:(0x5A^((i*0x1B)&0xFF))&0xFF
 * print(', '.join('0x%02x'%(ord(c)^key(i)) for i,c in enumerate(flag)))"
 */

/* ---------------------------------------------------------------- */
/* D3 -- @CriticalNative. NO JNIEnv*, NO jclass. Primitives only.    */
/*       Java: static native int d(long ctx, int idx);               */
/*       C:    jint d(jlong ctx, jint idx);                          */
/* ---------------------------------------------------------------- */
static jint crit_byte_at(jlong ctxv, jint idx) {
    Ctx *c = (Ctx *)(intptr_t)ctxv;
    if (c == NULL || c->magic != 0x4A4E4931u) return -1;
    if (idx < 0 || idx >= c->len) return -1;
    return (jint)c->expected[idx];
}

/* ---------------------------------------------------------------- */
/* D2 -- the DECOY. Registered first, from JNI_OnLoad. Always fails. */
/* ---------------------------------------------------------------- */
static jint decoy_check(JNIEnv *env, jobject thiz, jstring cand) {
    (void)env; (void)thiz; (void)cand;
    return 0;      /* "first character is wrong" -- a plausible lie */
}

/* ---------------------------------------------------------------- */
/* The real check. Registered LATER, over the top of the decoy.      */
/* Instance method: env, thiz, then the declared parameter.          */
/*                                                                    */
/* It returns the index of the first mismatch, which is an ORACLE.   */
/* Java reduces it to a boolean, so the leak is invisible from Java  */
/* but wide open from a native hook.                                  */
/* ---------------------------------------------------------------- */
static Ctx *g_ctx = NULL;

static jint real_check(JNIEnv *env, jobject thiz, jstring cand) {
    (void)thiz;
    if (cand == NULL || g_ctx == NULL) return 0;

    const char *s = (*env)->GetStringUTFChars(env, cand, NULL);
    if (s == NULL) return 0;

    jint result = -1;
    for (int i = 0; i < g_ctx->len; i++) {
        if (s[i] == '\0' || (unsigned char)s[i] != g_ctx->expected[i]) {
            result = i;                 /* early return: the oracle */
            break;
        }
    }
    if (result < 0 && (int)strlen(s) != g_ctx->len) result = g_ctx->len;

    (*env)->ReleaseStringUTFChars(env, cand, s);
    return result;
}

/* ---------------------------------------------------------------- */
/* D4 -- hands Java a raw heap pointer as a jlong. Static method.    */
/* ---------------------------------------------------------------- */
static jlong make_ctx(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    if (g_ctx == NULL) {
        g_ctx = (Ctx *)calloc(1, sizeof(Ctx));
        if (g_ctx == NULL) return 0;
        derive(g_ctx);
    }
    /* The address of a heap allocation, as a number, to Java. */
    return (jlong)(intptr_t)g_ctx;
}

/* ---------------------------------------------------------------- */
/* Registration. Names and signatures built at runtime so `strings`  */
/* finds nothing.                                                     */
/* ---------------------------------------------------------------- */
static char n1[4], s1[32], n2[4], s2[8], n3[4], s3[8];
static JNINativeMethod tbl[3];

static void build(void *fn_check) {
    n1[0] = 'c'; n1[1] = 0;
    memcpy(s1, "(L", 2); memcpy(s1 + 2, "java/lang/String;)I", 20);
    n2[0] = 'd'; n2[1] = 0;  memcpy(s2, "(JI)I", 6);
    n3[0] = 'e'; n3[1] = 0;  memcpy(s3, "()J", 4);

    tbl[0].name = n1; tbl[0].signature = s1; tbl[0].fnPtr = fn_check;
    tbl[1].name = n2; tbl[1].signature = s2; tbl[1].fnPtr = (void *)crit_byte_at;
    tbl[2].name = n3; tbl[2].signature = s3; tbl[2].fnPtr = (void *)make_ctx;
}

/* "com/unlisted/b/a" XOR 0x5A. Regenerate with:
 *   python3 -c "print(', '.join('0x%02x'%(ord(c)^0x5A) for c in 'com/unlisted/b/a'))" */
static const unsigned char kCls[] = {
    0x39, 0x35, 0x37, 0x75, 0x2f, 0x34, 0x36, 0x33, 0x29, 0x2e,
    0x3f, 0x3e, 0x75, 0x38, 0x75, 0x3b, 0x00
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    char cls[32];
    int i = 0;
    for (; kCls[i] != 0 && i < 31; i++) cls[i] = (char)(kCls[i] ^ 0x5A);
    cls[i] = 0;

    jclass k = (*env)->FindClass(env, cls);
    if (k == NULL) return JNI_ERR;

    /* D2, part 1: register the DECOY. */
    build((void *)decoy_check);
    if ((*env)->RegisterNatives(env, k, tbl, 3) != JNI_OK) {
        (*env)->DeleteLocalRef(env, k);
        return JNI_ERR;
    }

    /* D2, part 2: replace it. Re-registration is explicitly permitted and
     * ART overwrites the ArtMethod's native pointer. An analyst who
     * stops reading after the first [jni] block gets the decoy. */
    build((void *)real_check);
    if ((*env)->RegisterNatives(env, k, tbl, 3) != JNI_OK) {
        (*env)->DeleteLocalRef(env, k);
        return JNI_ERR;
    }

    (*env)->DeleteLocalRef(env, k);
    return JNI_VERSION_1_6;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *r) { (void)vm; (void)r; }
```

### Build

```bash
# host
$TC/aarch64-linux-android21-clang -shared -fPIC -O2 \
    -fvisibility=hidden -o libunlisted.so unlisted.c

# confirm the challenge conditions hold
llvm-nm -D --defined-only libunlisted.so | grep ' T '     # only JNI_OnLoad / JNI_OnUnload
llvm-strings -a libunlisted.so | grep -i 'JNI{'           # nothing -- the flag is not in the file
```

The first check is the one that must hold: if any implementation function is exported, D1 is gone
and the challenge collapses. The second must also hold, and does — the flag is derived into heap
memory at runtime (D4) and no part of it exists on disk.

> **Warning — two things `strings` *does* find, and neither is a broken build.**
> An earlier version of this lab added a third check, `strings -a libunlisted.so | grep -E
> '^\([A-Z\[L]'`, annotated "nothing", and told you to fix the build if it produced output. **The
> source above can never pass that check**, and the instruction was impossible to follow. Compiled
> with the exact command in this section, NDK 25.2.9519653, `arm64-v8a`:
>
> | You will see | Why |
> |---|---|
> | `(JI)I` | `build()` does `memcpy(s2, "(JI)I", 6)`. That is a five-character **string literal**; the assembly-at-runtime is a `memcpy` of a constant, which puts the constant in `.rodata` |
> | `java/lang/String;)I` | Same cause — the split `memcpy(s1, "(L", 2)` + `memcpy(s1 + 2, "java/lang/String;)I", 20)` hides only the leading `(L`, and `(L` is two characters, below `strings`' four-character default minimum. Raise it with `strings -n 2` and that appears too |
> | `com/unlisted/b/a` | The XOR'd class name, **fully recovered by the optimiser** at `-O2` and `-Os`, hidden at `-O0`, `-O1` and `-Oz`. Same mechanism as [lab 03 Part 2](lab-03-recovering-dynamic-natives.md#part-2--build-a-known-target): clang constant-folds the decode loop |
>
> None of the three weakens the challenge, which is why the build command is unchanged:
> `com.unlisted.b.a` is **already visible in JADX** and is given to you in the briefing, and a
> signature without a name tells you a method's *shape*, not its identity — the whole point of
> [§5.3 of lab 03](lab-03-recovering-dynamic-natives.md#53-where-the-static-route-fails). What they
> do weaken is the sentence "`strings` finds no method names and no signatures", which is why it now
> reads "no flag and no method names".
>
> **Take the general lesson, because it outlives this lab.** Splitting a string across `memcpy`
> calls, or XOR-ing it with a compile-time constant, hides it from `strings` **in the source**. The
> optimiser decides whether it is hidden in the *artefact*, and it decides differently at each `-O`
> level, each NDK revision, and with LTO on or off. Never write a "the binary contains no X" claim
> you have not run `strings` against.

---

## The four defences, and which section covers each

You are expected to be defeated by at least two of these on the first pass. That is the design.

| # | Defence | What it breaks | Read |
|---|---|---|---|
| D1 | Dynamic registration | `nm -D`, JADX method names, any static symbol search | [§3.8](../README.md#38-dynamic-registration--registernatives) |
| D2 | Decoy registration, replaced later | Anyone who reads only the first `RegisterNatives` call | [§3.8](../README.md#38-dynamic-registration--registernatives), [§4.4](../README.md#44-trace-c--registernatives-inside-art) |
| D3 | `@CriticalNative` on the byte accessor | The `args[0] == JNIEnv*` assumption | [§3.21](../README.md#321-fastnative-and-criticalnative), [§3.9](../README.md#39-the-calling-convention-every-native-hook-sees) |
| D4 | The flag derived into a heap struct, address handed out as a `jlong` | `strings`, and any search for a constant | [§5.5](../README.md#55-vulnerability-class-4--the-jlong-handle) |

D4 is a *defence* from the developer's point of view and a **gift** from yours. That
inversion is the lesson of the whole lab.

---

## Solution paths

Do not read past the heading of a path until you have tried it. Each is a complete solve.

<details>
<summary><b>Path A — follow the jlong</b> (the shortest, and the most instructive)</summary>

The Java constructor stores `e()`'s return value in a field called `ctx`. `e` is a static native
returning `J`. In this chapter, a `jlong` returned from native code is almost always **a raw
pointer** ([§5.5](../README.md#55-vulnerability-class-4--the-jlong-handle)).

Recover the address, then read memory at it.

```javascript
// frida -U -f com.unlisted -l pathA.js --no-pause
Java.perform(function () {
  const A = Java.use('com.unlisted.b.a');
  const inst = A.$new();                 // runs e()
  const ctx = inst.ctx.value;            // the jlong
  console.log('ctx = 0x' + ctx.toString(16));

  const p = ptr(ctx);
  console.log(hexdump(p, { length: 96, ansi: false }));

  // struct Ctx { unsigned magic; int len; unsigned char expected[64]; }
  const magic = p.readU32();
  const len   = p.add(4).readS32();
  console.log('magic=0x' + magic.toString(16) + '  len=' + len);
  console.log('flag = ' + p.add(8).readCString());
});
```

The `expected` array begins 8 bytes in (two 4-byte fields, no padding on this layout), and it is
NUL-terminated because `derive` writes the terminator. The flag falls out in one `readCString`.

**What this teaches:** a `long` in a Java field that came from native code is a pointer until proven
otherwise. It is readable, writable, and — as Lab 02 showed — forgeable.

</details>

<details>
<summary><b>Path B — the oracle in the return value</b></summary>

`check(String)` returns `c(candidate) < 0`. Java throws away everything except the sign. The native
method returns *the index of the first mismatch*.

Hook the native return before Java collapses it, and you have a byte-at-a-time oracle.

```javascript
// frida -U -f com.unlisted -l pathB.js --no-pause
Java.perform(function () {
  const A = Java.use('com.unlisted.b.a');
  const inst = A.$new();

  const ALPHABET = 'abcdefghijklmnopqrstuvwxyz' +
                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}';
  let known = '';

  for (let pos = 0; pos < 40; pos++) {
    let advanced = false;
    for (const ch of ALPHABET) {
      const guess = known + ch + 'A'.repeat(40 - known.length);
      // c() is private; Java.use exposes it.
      const idx = inst.c(guess);
      if (idx < 0) { known += ch; console.log('FLAG = ' + known); return; }
      if (idx > known.length) { known += ch; advanced = true; break; }
    }
    if (!advanced) { console.log('stuck at: ' + known); return; }
  }
});
```

Read the condition carefully: `idx > known.length` means the native code got *past* the character we
just guessed, which is exactly the definition of "that guess was right".

**What this teaches:** an early return in a comparison loop is an information leak even when the Java
layer discards the detail. Look for it whenever a native method returns an `int` that Java compares
against zero.

**Variant, without Frida at all:** the same oracle works by reflection from inside a patched app,
because `c` is only `private`.

</details>

<details>
<summary><b>Path C — the JNI boundary itself</b></summary>

You do not need to find the check at all. The candidate string must be handed to native code, and
the only way to do that is through the `JNIEnv` table. Hook `GetStringUTFChars` and you see every
string that crosses — and hook the comparison the native code performs, and you see what it compares
against.

```javascript
// frida -U -f com.unlisted -l pathC.js --no-pause
// Hook the JNIEnv function-table entry rather than any app symbol.
Java.perform(function () {
  const env = Java.vm.getEnv();
  const table = env.handle.readPointer();
  const ps = Process.pointerSize;
  const getUtf = table.add(169 * ps).readPointer();   // GetStringUTFChars, index 169

  Interceptor.attach(getUtf, {
    onEnter(args) { this.js = args[1]; },
    onLeave(retval) {
      if (!retval.isNull()) {
        const s = retval.readCString();
        if (s && s.length > 4) console.log('[GetStringUTFChars] ' + s);
      }
    }
  });
});
```

That shows you the input, not the flag. To get the flag, put a hook one level lower: the real check
reads `g_ctx->expected[i]` in a loop. Hook the recovered `real_check` address and dump the memory the
comparison touches — or, more directly, `real_check` dereferences a global that Path A
already told you how to find.

**The general lesson**, which is worth more than this flag: the JNI function table is a
process-wide chokepoint. One hook on `GetStringUTFChars` at index 169 or
`GetByteArrayElements` at index 184 sees data from **every** library in the process, including ones
you have not identified.

</details>

<details>
<summary><b>Path D — recover the real registration, then read the code</b></summary>

The proper reverse-engineering route.

1. Dump registrations, and **do not stop at the first block**:

   ```bash
   frida -U -f com.unlisted -l ../scripts/dump-registernatives.js --no-pause | tee reg.log
   grep '^\[jni\]' -A5 reg.log
   ```

   You will see the class `com.unlisted.b.a` registered **twice** with three methods each. The
   addresses for `c` differ between the two blocks. The second one is live.

2. Rebase the second address into Ghidra and read `real_check`. It is short: `GetStringUTFChars`,
   a loop comparing against a global, an early `break`, `ReleaseStringUTFChars`.

3. The global it compares against is `g_ctx`. Find where it is assigned — `make_ctx` — and read
   `derive`. The keystream is trivial, but you do not even need to invert it: hook `make_ctx`'s
   return and read the struct, which is Path A arriving from the other direction.

**What this teaches:** re-registration is legal and ART overwrites the pointer. An analyst who
reads the first table and moves on is analysing a decoy. Always run the hook for the whole session
and look for duplicate class/method pairs.

</details>

<details>
<summary><b>The @CriticalNative trap (D3), explained</b></summary>

`d(long ctx, int idx)` is annotated `@CriticalNative`. Its C implementation is:

```c
jint crit_byte_at(jlong ctxv, jint idx);
```

**No `JNIEnv*`. No `jclass`.** If you hook it with the standard assumption you read:

| You think | Actually |
|---|---|
| `args[0]` = `JNIEnv*` | the `ctx` pointer |
| `args[1]` = `jclass` | the index |
| `args[2]` = first real argument | whatever was left in `x2` — garbage |

Which is why "every argument I print is garbage" is in the challenge description. The correct hook
is:

```javascript
Interceptor.attach(addr, {
  onEnter(args) {
    console.log('ctx=' + args[0] + '  idx=' + args[1].toInt32());   // NOT args[2], args[3]
  },
  onLeave(r) { console.log(' -> byte 0x' + r.toInt32().toString(16)); }
});
```

And once you can hook it correctly, `d` is itself a complete oracle: call it in a loop for
`idx = 0..len-1` and read the flag out one byte at a time, with no guessing at all.

```javascript
Java.perform(function () {
  const A = Java.use('com.unlisted.b.a');
  const inst = A.$new();
  const ctx = inst.ctx.value;
  let flag = '';
  for (let i = 0; i < 40; i++) {
    const b = A.d(ctx, i);
    if (b < 0) break;
    flag += String.fromCharCode(b);
  }
  console.log('FLAG = ' + flag);
});
```

That is a fifth solution, and arguably the most elegant: the developer wrote you an accessor.

**How to detect the annotation before you get burned:**

```bash
# host
apktool d -f -o out app.apk >/dev/null
grep -rn "optimization/CriticalNative" out/smali*/
```

</details>

---

## Hints

<details>
<summary>Hint 1 — I cannot find any native symbol at all</summary>

That is D1, and it is the whole reason Lab 03 exists. `nm -D` will never show these. Go to
`../scripts/dump-registernatives.js` and **spawn** the process rather than attaching.

</details>

<details>
<summary>Hint 2 — I hooked the recovered address and it always returns 0</summary>

You are on the decoy (D2). Look at your registration log again: is the class registered more than
once? Compare the addresses for method `c` between the blocks.

</details>

<details>
<summary>Hint 3 — forcing the return value says "Correct" but I still do not have the flag</summary>

Correct, and that is deliberate. A forced boolean proves you can reach the decision; it does not
recover the secret. Ask instead: *where does the expected value physically live at the moment of
comparison?*

</details>

<details>
<summary>Hint 4 — the arguments to method `d` make no sense</summary>

Check the DEX for an annotation on that method. Then re-read
[§3.21](../README.md#321-fastnative-and-criticalnative). Count from `args[0]`, not `args[2]`.

</details>

<details>
<summary>Hint 5 — I have the ctx address but hexdump shows nothing readable</summary>

Two possibilities. You read the field before the constructor ran, so it is 0 — construct the object
first and read the field afterwards. Or the struct layout differs on your build: dump 96 bytes raw
and look for the `magic` value `0x4a4e4931` to locate the start, then count forward.

</details>

<details>
<summary>Hint 6 — the oracle in Path B never advances</summary>

Your padding character may collide with a real flag character at that position, making the index jump
further than expected. Use a padding byte that cannot be in the flag (`\x01`), and treat *any*
increase in the returned index as a hit.

</details>

---

## Success criteria

| # | Criterion |
|---|---|
| 1 | You have the flag |
| 2 | You solved it a **second**, independent way |
| 3 | You can name each of the four defences and the chapter section that covers it |
| 4 | You can explain why re-registration works, in terms of what ART stores on the `ArtMethod` |
| 5 | You can state what a `@CriticalNative` hook sees in `args[0]`, and why |
| 6 | You can explain why the runtime recovery of the registration table cannot be prevented |
| 7 | You wrote the remediation: what should the developer have done instead, as code |

---

## The remediation question (criterion 7)

This is the part most people skip, and it is the part that separates a researcher from a
CTF player. Answer all four:

1. **The `jlong` context pointer.** What should `e()` have returned instead? Write the fix. (See
   the token scheme in `enterprise_bridge.cpp` — indexed from
   [the examples README](../examples/README.md) — and
   [§5.5](../README.md#55-vulnerability-class-4--the-jlong-handle) fix (c).)
2. **The oracle.** Why is returning the mismatch index a defect, and what is the constant-time
   alternative? Write it.
3. **The decoy.** Does it protect anything, or does it only cost the analyst ten minutes? What is
   your honest assessment of its value?
4. **The whole design.** The flag has to exist in memory at the moment of comparison. Given that,
   what — if anything — could this app have done to keep a secret from someone holding the device?
   Answer honestly. The correct answer is uncomfortable, and it is in
   [§10, Principal Engineer](../README.md#principal-engineer).

---

## The flag

`JNI{th3_numb3r_w4s_unl1st3d}`

Do not read that until you have it. If you did, at minimum go back and produce it a second way — the
paths above are each worth doing.

---

## Where this goes next

| If you enjoyed | Read |
|---|---|
| Recovering the registration table | [57 Ghidra](../../57-Ghidra/README.md) — the decompiler workflow |
| Hooking the JNI function table | [65 Hooking](../../65-Hooking/README.md), [53 Frida](../../53-Frida/README.md) |
| The anti-analysis in `JNI_OnLoad` | [38 TamperDetection](../../38-TamperDetection/README.md), [37 RootDetection](../../37-RootDetection/README.md) |
| Libraries decrypted at runtime | [40 Obfuscation](../../40-Obfuscation/README.md) Lab 04 |
| The native memory-safety side | `15-Native-Code/`, [19 Memory](../../19-Memory/README.md) |
