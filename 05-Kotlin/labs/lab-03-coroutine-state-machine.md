# Lab 03 — CTF: Reconstruct the Coroutine State Machine

Part of chapter [05 — Kotlin](../README.md). Follows
[lab 01](lab-01-spot-the-kotlin.md) and [lab 02](lab-02-null-safety-in-jadx.md).

---

## Objective

A `suspend` function checks a token across two suspension points. In decompiled form the function is no
longer readable as a sequence of statements: it has become a class with an integer field and a `switch`.
Your job is to put it back together.

You must:

1. Read the decompiled `invokeSuspend` and reconstruct the original Kotlin control flow, statement by
   statement.
2. State what each value of the `label` field means, including the strange one with the sign bit set.
3. Identify which local variables were promoted to continuation fields, and which field holds which
   variable — without running the program.
4. Use Frida to hook the continuation at runtime and recover the token.
5. Submit the flag.

**The flag has the form `FLAG{CH-<number>:<24 lowercase hex characters>}`.** You will never learn the
correct input to `unlock`; you recover the flag by reading the coroutine's state, not by guessing.

> **🧠 Mental Model**
> A thread's stack holds "where I am" and "what I was holding". A coroutine cannot use the thread stack,
> because it gives the thread back every time it suspends. So the compiler builds a small object that
> holds both: an integer saying where it is (`label`) and a set of fields holding what it was carrying
> (`L$0`, `L$1`, and so on). Reading that object at the right moment is like reading a stack frame that
> has been politely written down for you.

---

## Prerequisites

- [Lab 01](lab-01-spot-the-kotlin.md) and [lab 02](lab-02-null-safety-in-jadx.md).
- The coroutines material in the chapter [README](../README.md), specifically Continuation Passing Style
  and the meaning of `COROUTINE_SUSPENDED`.
- [Chapter 04 — Java](../../04-Java/README.md) for `switch` statements and inner classes.

| Tool | Purpose |
|---|---|
| `kotlinc` 1.9+ | Compile the challenge |
| `kotlinx-coroutines-core-jvm` jar | Required on the classpath and at runtime |
| JADX 1.4+ | Decompile |
| Frida 16+ | Recover the token at runtime |
| JDK 17+ | Run the challenge |

Download the coroutines jar once. Any 1.7 or 1.8 release works; the generated shapes are identical.

```bash
# host
curl -LO https://repo1.maven.org/maven2/org/jetbrains/kotlinx/kotlinx-coroutines-core-jvm/1.8.1/kotlinx-coroutines-core-jvm-1.8.1.jar
```

**Estimated time:** 2 hours. Budget an hour for the reconstruction alone; that is the part that teaches
you the most.

---

## Setup

### The challenge source

This is the *exact* source. Read it once, then close it and do not look at it again until you have
finished the reconstruction — the whole point is to rebuild it from the decompiled output.

```kotlin
// host — save as ~/kotlin-lab-03/Vault.kt
package com.example.ctf

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import java.security.MessageDigest

object Vault {

    private const val PEPPER = "n0t-s0-s3cr3t-p3pp3r"

    /** Suspension point 1. Stands in for a network round trip that fetches a nonce. */
    suspend fun fetchChallenge(): String {
        delay(120)
        return "CH-" + (System.currentTimeMillis() / 86_400_000L)
    }

    /** Suspension point 2. Stands in for a server-side derivation of the expected token. */
    suspend fun resolveToken(challenge: String): String {
        delay(180)
        return sha256Hex(challenge + PEPPER).take(24)
    }

    fun sha256Hex(input: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(input.toByteArray())
            .joinToString("") { String.format("%02x", it) }
}

/**
 * Two suspension points. `challenge` is used again after the second one,
 * so it has to survive a suspension.
 */
suspend fun unlock(userSupplied: String): String {
    val challenge = Vault.fetchChallenge()
    val token = Vault.resolveToken(challenge)
    return if (userSupplied == token) "FLAG{$challenge:$token}" else "ACCESS DENIED"
}

fun main() = runBlocking {
    val attempt = readlnOrNull() ?: ""
    println(unlock(attempt))
}
```

### Build it

```bash
# host
cd ~/kotlin-lab-03
kotlinc Vault.kt -cp kotlinx-coroutines-core-jvm-1.8.1.jar -d classes/

# run it — any input you type will be rejected
echo "guess" | java -cp "classes:kotlinx-coroutines-core-jvm-1.8.1.jar:$KOTLIN_HOME/lib/kotlin-stdlib.jar" com.example.ctf.VaultKt
```

Expected output:

```
ACCESS DENIED
```

Confirm the classes the compiler produced. Count them and note how many you did not write.

```bash
# host
find classes -name '*.class' | sort
```

```
classes/com/example/ctf/Vault.class
classes/com/example/ctf/Vault$fetchChallenge$1.class
classes/com/example/ctf/Vault$resolveToken$1.class
classes/com/example/ctf/Vault$sha256Hex$1.class
classes/com/example/ctf/VaultKt.class
classes/com/example/ctf/VaultKt$main$1.class
classes/com/example/ctf/VaultKt$unlock$1.class
```

Three classes you wrote no code for exist purely to hold coroutine state. Their names follow the rule
`<OwnerClass>$<functionName>$1`, which is the fastest way to find the state machine belonging to a
function you care about.

### Decompile

```bash
# host
jar cf challenge.jar -C classes .
jadx --no-res -d jadx_out challenge.jar
ls jadx_out/sources/com/example/ctf/
```

---

## Steps

### Step 1 — Find the rewritten signature of `unlock`

```bash
# host
grep -n "unlock" jadx_out/sources/com/example/ctf/VaultKt.java | head
```

You will find something equivalent to:

```java
public static final Object unlock(String userSupplied, Continuation<? super String> $completion)
```

Write down the three changes the compiler made to `suspend fun unlock(userSupplied: String): String`:

| Change | Before | After |
|---|---|---|
| Extra parameter | none | `Continuation<? super String> $completion`, always last |
| Return type | `String` | `Object` |
| Reason for the return type change | — | The method may return either the real `String` or the `COROUTINE_SUSPENDED` sentinel, and those have no common supertype other than `Object` |

### Step 2 — Read the continuation prologue

The first block of `unlock` is boilerplate that appears, near-identical, in every named suspend function
in every Kotlin application ever compiled. Learn to skip it, but understand it once.

```java
// jadx output — expected shape
public static final Object unlock(String userSupplied, Continuation<? super String> $completion) {
    VaultKt$unlock$1 $continuation;
    if ($completion instanceof VaultKt$unlock$1) {
        $continuation = (VaultKt$unlock$1) $completion;
        if (($continuation.label & Integer.MIN_VALUE) != 0) {
            $continuation.label -= Integer.MIN_VALUE;
        } else {
            $continuation = new VaultKt$unlock$1($completion);
        }
    } else {
        $continuation = new VaultKt$unlock$1($completion);
    }
    Object $result = $continuation.result;
    Object coroutine_suspended = IntrinsicsKt.getCOROUTINE_SUSPENDED();
    switch ($continuation.label) {
        ...
    }
}
```

This code answers one question: **am I being called for the first time, or am I being resumed?**

- If `$completion` is not one of *my* continuation class, this is a fresh call, so allocate a new state
  object.
- If it is my class *and* the sign bit of `label` is set, this is a genuine resumption of *this*
  function. Clear the sign bit and reuse the object.
- If it is my class but the sign bit is clear, the object belongs to a different invocation that happens
  to share the type, so allocate a fresh one.

> **🔬 Under the Hood**
> The sign bit is a one-bit flag smuggled into the same integer as the program counter, to avoid
> allocating a second field. It is set by the continuation's own `invokeSuspend` immediately before it
> re-enters the function, and cleared here. Because `label` values are small non-negative integers, the
> top bit is free. Seeing `label & Integer.MIN_VALUE` or `label -= Integer.MIN_VALUE` in decompiled code
> is a certain sign of a named suspend function, as opposed to a suspending lambda, which does not need
> the trick.

### Step 3 — Read the state machine and reconstruct the control flow

This is the core exercise. Here is the `switch` body.

```java
// jadx output — expected shape
    switch ($continuation.label) {
        case 0:
            ResultKt.throwOnFailure($result);
            $continuation.L$0 = userSupplied;
            $continuation.label = 1;
            Object c = Vault.INSTANCE.fetchChallenge($continuation);
            if (c == coroutine_suspended) {
                return coroutine_suspended;
            }
            $result = c;
            // falls through to the body of case 1
            break;

        case 1:
            userSupplied = (String) $continuation.L$0;
            ResultKt.throwOnFailure($result);
            String challenge = (String) $result;
            $continuation.L$0 = userSupplied;
            $continuation.L$1 = challenge;
            $continuation.label = 2;
            Object t = Vault.INSTANCE.resolveToken(challenge, $continuation);
            if (t == coroutine_suspended) {
                return coroutine_suspended;
            }
            $result = t;
            break;

        case 2:
            String challenge = (String) $continuation.L$1;
            userSupplied  = (String) $continuation.L$0;
            ResultKt.throwOnFailure($result);
            String token = (String) $result;
            return Intrinsics.areEqual(userSupplied, token)
                 ? "FLAG{" + challenge + ":" + token + "}"
                 : "ACCESS DENIED";

        default:
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
    }
```

> **⚠️ Warning**
> JADX will not always render the fall-through between cases as cleanly as shown. Depending on the
> version and on how R8 or `d8` laid out the blocks, you may see `goto` comments, a `while (true)` loop
> wrapping the switch, or the cases merged into `if` chains on `label`. The *semantics* are always the
> same. If the output confuses you, look at the smali instead: `iget ... label`, `packed-switch`, and
> `iput ... label` tell an unambiguous story.

Now do the reconstruction. Fill in this table before reading the solution.

| `label` on entry | Meaning | Original source lines it covers | Value arriving in `$result` |
|---|---|---|---|
| `0` | ? | ? | ? |
| `1` | ? | ? | ? |
| `2` | ? | ? | ? |
| sign bit set | ? | ? | ? |
| anything else | ? | ? | ? |

Then write out, in ordinary Kotlin, what the original function must have been. You have everything you
need: the order of the calls, the assignments to and from `L$0` and `L$1`, and the final expression.

### Step 4 — Read the continuation class itself

```bash
# host
grep -n "class VaultKt\$unlock\$1" -A 25 jadx_out/sources/com/example/ctf/VaultKt.java
```

```java
// jadx output — expected shape
@DebugMetadata(
    c = "com.example.ctf.VaultKt",
    f = "Vault.kt",
    i = {0, 1, 1},
    l = {33, 34},
    m = "unlock",
    n = {"userSupplied", "userSupplied", "challenge"},
    s = {"L$0", "L$0", "L$1"}
)
@Metadata(k = 3, mv = {1, 9, 0}, xi = 48)
static final class VaultKt$unlock$1 extends ContinuationImpl {
    Object L$0;
    Object L$1;
    int label;
    /* synthetic */ Object result;

    VaultKt$unlock$1(Continuation<? super VaultKt$unlock$1> continuation) {
        super(continuation);
    }

    @Override
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return VaultKt.unlock(null, this);
    }
}
```

The `@DebugMetadata` annotation is the single most valuable artefact in this lab. Decode it.

| Field | Meaning | Value here |
|---|---|---|
| `c` | Class that owns the suspend function | `com.example.ctf.VaultKt` |
| `f` | Original source **file name** | `Vault.kt` |
| `m` | Original **function name** | `unlock` |
| `l` | Source **line numbers** of each suspension point, in order | lines 33 and 34 |
| `n` | Original **names** of the spilled local variables | `userSupplied`, `userSupplied`, `challenge` |
| `s` | The continuation **field** each spilled local lives in, index-aligned with `n` | `L$0`, `L$0`, `L$1` |
| `i` | Which `label` state each spill belongs to, index-aligned with `n` and `s` | states 0, 1, 1 |

Read the three arrays together, column by column:

| Index | `i` (state) | `n` (name) | `s` (field) |
|---|---|---|---|
| 0 | 0 | `userSupplied` | `L$0` |
| 1 | 1 | `userSupplied` | `L$0` |
| 2 | 1 | `challenge` | `L$1` |

That tells you, with no reverse engineering at all, that at label 1 the field `L$1` contains a variable
the developer named `challenge`. Note also `invokeSuspend` passes `null` as the first argument when it
re-enters `unlock` — the real `userSupplied` is restored from `L$0` inside the switch, so the parameter
slot is unused on the resume path.

> **🔍 Pentester's Note**
> `@DebugMetadata` is a runtime-visible annotation emitted by default. It is not stripped by standard R8
> configurations because the coroutines debug agent reads it. In an otherwise fully obfuscated release
> APK, it hands you original file names, function names, source line numbers, and local variable names
> for every suspending function in the application. Grep for `DebugMetadata` first when you open an
> obfuscated coroutine-heavy app; it is frequently the richest source of original identifiers in the
> whole binary.

### Step 5 — Hook the continuation with Frida and recover the token

You now know that at the moment the second suspension resumes, the incoming result is the token, and
`L$1` holds the challenge. Hook the resume path and read both.

The universal interception point is `BaseContinuationImpl.resumeWith`, which every compiler-generated
continuation inherits. Every resumption in the entire process passes through it.

```javascript
// host — save as recover.js
// Run against the JVM challenge with:
//   java -cp "classes:kotlinx-coroutines-core-jvm-1.8.1.jar:$KOTLIN_HOME/lib/kotlin-stdlib.jar" \
//        com.example.ctf.VaultKt &
//   frida -n java -l recover.js
// Run against an Android build with:
//   frida -U -f com.example.ctf -l recover.js
//
// WHAT THIS DOES
//   Intercepts every coroutine resumption in the process. For each one it prints the
//   continuation's class name, its current `label`, the incoming resume value, and the
//   contents of every spilled-local field (L$0, L$1, I$0, ...). For our target class it
//   additionally reassembles the flag.

'use strict';

var TARGET = 'com.example.ctf.VaultKt$unlock$1';

function dumpFields(obj) {
    var out = {};
    try {
        var cls = obj.getClass();
        var fields = cls.getDeclaredFields();
        for (var i = 0; i < fields.length; i++) {
            var f = fields[i];
            var name = f.getName();
            // Spilled locals are named L$n (objects) and I$n / J$n (primitives);
            // `label` is the state; `result` is the pending resume value.
            if (!/^([LIJDFZ]\$\d+|label|result)$/.test(name)) continue;
            try {
                f.setAccessible(true);
                var v = f.get(obj);
                out[name] = (v === null) ? 'null' : String(v);
            } catch (e) {
                out[name] = '<unreadable: ' + e.message + '>';
            }
        }
    } catch (e) {
        out['<error>'] = e.message;
    }
    return out;
}

Java.perform(function () {
    var Base;
    try {
        Base = Java.use('kotlin.coroutines.jvm.internal.BaseContinuationImpl');
    } catch (e) {
        console.log('[-] BaseContinuationImpl not found. Does this app ship kotlinx-coroutines?');
        return;
    }

    Base.resumeWith.overload('java.lang.Object').implementation = function (result) {
        var name;
        try { name = this.getClass().getName(); } catch (e) { name = '<unknown>'; }

        var fields = dumpFields(this);
        console.log('[resume] ' + name + '  label=' + fields['label']);
        console.log('         incoming = ' + (result === null ? 'null' : String(result)));
        Object.keys(fields).forEach(function (k) {
            if (k === 'label') return;
            console.log('         ' + k + ' = ' + fields[k]);
        });

        if (name === TARGET) {
            // label 2 means: the SECOND suspension is resuming, so `incoming`
            // is the return value of resolveToken -- the token itself.
            // L$1 still holds `challenge`, spilled during state 1.
            var lbl = parseInt(fields['label'], 10);
            var normalised = (lbl < 0) ? (lbl - (-2147483648)) : lbl;   // clear the sign bit
            if (normalised === 2) {
                console.log('');
                console.log('  >>> FLAG{' + fields['L$1'] + ':' + String(result) + '}');
                console.log('');
            }
        }

        return this.resumeWith(result);
    };

    console.log('[+] hooked BaseContinuationImpl.resumeWith');
    console.log('[+] watching for ' + TARGET);
});
```

Run it, type anything at the prompt, and read the output.

```bash
# host — terminal 1
java -cp "classes:kotlinx-coroutines-core-jvm-1.8.1.jar:$KOTLIN_HOME/lib/kotlin-stdlib.jar" \
     com.example.ctf.VaultKt

# host — terminal 2, while the program is waiting on stdin
frida -n java -l recover.js
```

> **⚠️ Warning**
> `resumeWith` fires for *every* coroutine in the process, including internals of `delay` and of the
> dispatcher. On a real Android application this hook is extremely noisy and can slow the app enough to
> cause ANRs. Filter by class name as early as possible, as the script above does for the flag path, and
> consider hooking `VaultKt$unlock$1.invokeSuspend` directly once you know the class name.

The targeted alternative, once you have identified the class:

```javascript
// Frida REPL — narrow hook, far less noise
Java.perform(function () {
    var C = Java.use('com.example.ctf.VaultKt$unlock$1');
    C.invokeSuspend.overload('java.lang.Object').implementation = function (obj) {
        console.log('[invokeSuspend] label=' + this.label.value +
                    '  L$0=' + this.L$0.value +
                    '  L$1=' + this.L$1.value +
                    '  incoming=' + obj);
        return this.invokeSuspend(obj);
    };
});
```

Note the Frida field-access syntax: `this.label.value`, not `this.label`. Field wrappers require
`.value` to read or write; forgetting it prints an object description instead of the number and is the
most common mistake at this point.

### Step 6 — Verify the flag

Confirm your recovered flag by feeding the token back in as the answer.

```bash
# host — replace <token> with the 24 hex characters you recovered
echo "<token>" | java -cp "classes:kotlinx-coroutines-core-jvm-1.8.1.jar:$KOTLIN_HOME/lib/kotlin-stdlib.jar" \
     com.example.ctf.VaultKt
```

If your reconstruction was correct, the program itself now prints the flag.

---

## Hints

<details>
<summary>Hint 1 — I cannot tell which case is which; the switch looks like a loop</summary>

Ignore the surface structure and follow the *writes* to `label`. Each `$continuation.label = N;` is
immediately followed by the call that may suspend. That pairing is the whole map: the assignment says
"if this call suspends, come back at state N". So the call following `label = 1` is suspension point 1,
and state 1 is where its result arrives.

Read the code as a list of pairs, from the smali if necessary:

```bash
# host
baksmali d classes/com/example/ctf/VaultKt.class -o smali_out/ 2>/dev/null || \
  echo "use d8 to make a dex first, then baksmali it"
grep -n "iput.*label\|packed-switch\|invoke-.*fetchChallenge\|invoke-.*resolveToken" smali_out/**/VaultKt.smali
```
</details>

<details>
<summary>Hint 2 — how do I know which local went into which L$ field?</summary>

Read `@DebugMetadata`. The `n` and `s` arrays are index-aligned: the *k*-th entry of `n` is the original
variable name, and the *k*-th entry of `s` is the field it was spilled into. The `i` array tells you
which state that spill belongs to.

If `@DebugMetadata` has been stripped, fall back to the code itself: find the `$continuation.L$1 = X;`
assignment and see what `X` was. The store and the matching load `(String) $continuation.L$1` bracket the
suspension point.
</details>

<details>
<summary>Hint 3 — my Frida hook fires but every field prints as an object address</summary>

You are reading the field wrapper rather than the value. In Frida's Java bridge, an instance field
accessed as `this.label` returns a wrapper object; the value is `this.label.value`. The same applies when
writing: `this.label.value = 0`.

If you are reading fields reflectively as in `recover.js`, the equivalent mistake is forgetting
`f.setAccessible(true)`, which throws `IllegalAccessException` on private fields.
</details>

<details>
<summary>Hint 4 — the label I read is a huge negative number</summary>

That is the sign bit. `invokeSuspend` sets `label |= Integer.MIN_VALUE` just before re-entering the
function, and the function's prologue clears it with `label -= Integer.MIN_VALUE`. If you hook
`resumeWith`, you are observing the object *before* the prologue runs, so you may see either form.
Normalise with `label & 0x7fffffff`, or equivalently subtract `Integer.MIN_VALUE` when the value is
negative.
</details>

<details>
<summary>Hint 5 — I want to skip the reconstruction and just hook resolveToken</summary>

You can, and on a real assessment you would. `Vault.resolveToken` is an ordinary method with the
signature `(String, Continuation) -> Object`, so hooking it and printing the return value is much less
work.

But it does not always work. If the token were computed *inside* the suspend function rather than
returned by a separate one, there would be no method boundary to hook, and the continuation fields would
be the only place the value ever existed. Do the reconstruction; it is the technique that generalises.
</details>

---

## Success criteria

You have completed this lab when:

1. You submitted a flag matching `FLAG{CH-<number>:<24 lowercase hex characters>}`, recovered from the
   continuation rather than by guessing the input.
2. Feeding the recovered 24-character token back into the program's stdin makes the program itself print
   the same flag.
3. You produced a written reconstruction of `unlock` from decompiled output alone, and it matches the
   original source in call order, variable usage, and final expression.
4. You completed the `label` table from step 3, including what a negative `label` means.
5. You can state which continuation field held `challenge` and cite the specific `@DebugMetadata` entries
   that prove it.
6. You can explain in one sentence why `unlock` returns `Object` rather than `String`.

---

## Solution

<details>
<summary>Full solution — reconstruction, label table, expected output, and the flag</summary>

### The completed label table

| `label` on entry | Meaning | Original source it covers | Value arriving in `$result` |
|---|---|---|---|
| `0` | First entry; the function has never run | From the start of `unlock` up to and including the call to `fetchChallenge` | The `result` field of a freshly allocated continuation, which is `null` and is passed to `ResultKt.throwOnFailure` harmlessly |
| `1` | Resuming after suspension point 1 | From just after `fetchChallenge` returned, through the assignment to `challenge`, up to and including the call to `resolveToken` | The `String` returned by `fetchChallenge`, that is, the challenge |
| `2` | Resuming after suspension point 2 | The comparison and the returned expression | The `String` returned by `resolveToken`, that is, the token |
| Sign bit set, for example `-2147483647` | `invokeSuspend` has just set the marker and is re-entering `unlock`; the prologue will clear the bit and fall through to the real state | Not a state of its own | Whatever value the resumption carried, already stored in the `result` field |
| Any other value | Impossible in correct execution; it means `resume` was called on a continuation that was never invoked | — | — |

The `default` branch's message, `"call to 'resume' before 'invoke' with coroutine"`, is a fixed string in
the Kotlin compiler. Grepping a DEX for that sentence counts the suspending code blocks in an
application in one command.

### The reconstruction

```kotlin
suspend fun unlock(userSupplied: String): String {
    val challenge = Vault.fetchChallenge()        // suspension point 1
    val token = Vault.resolveToken(challenge)     // suspension point 2
    return if (userSupplied == token) "FLAG{$challenge:$token}" else "ACCESS DENIED"
}
```

Every element of this is derivable from the decompiled output without seeing the source:

| Evidence in the decompiled code | Conclusion |
|---|---|
| Two distinct `$continuation.label = N` assignments | Exactly two suspension points |
| `Vault.INSTANCE.fetchChallenge($continuation)` after `label = 1` | The first suspending call, on an `object` declaration |
| `Vault.INSTANCE.resolveToken(challenge, $continuation)` after `label = 2` | The second suspending call, taking the previous result as its argument |
| `L$0` written in state 0 and read in states 1 and 2 | `userSupplied` must survive both suspensions, so it is the function parameter |
| `L$1` written in state 1 and read in state 2 | A value produced by suspension 1 and consumed after suspension 2 |
| `@DebugMetadata` `n = {"userSupplied","userSupplied","challenge"}`, `s = {"L$0","L$0","L$1"}` | Confirms the names directly |
| `Intrinsics.areEqual(userSupplied, token)` in state 2 | A null-safe string comparison, so the source used `==` |
| The string concatenation `"FLAG{" + challenge + ":" + token + "}"` | A Kotlin string template using both values |

### Why `unlock` returns `Object`

Because a suspending function has two possible outcomes at the JVM level: it either produces its real
value, here a `String`, or it produces the `COROUTINE_SUSPENDED` sentinel to tell the caller "I did not
finish; you will be called back". Those two are unrelated types, so the only signature that can express
both is one returning `Object`. The sentinel is a private singleton retrieved by
`IntrinsicsKt.getCOROUTINE_SUSPENDED()`, and comparing against it by reference identity is how the
generated code decides whether to return early.

### Expected Frida output

Trimmed to the lines that matter; you will also see resumptions belonging to `delay` and to the
dispatcher.

```
[+] hooked BaseContinuationImpl.resumeWith
[+] watching for com.example.ctf.VaultKt$unlock$1

[resume] com.example.ctf.Vault$fetchChallenge$1  label=-2147483647
         incoming = kotlin.Unit
         L$0 = null

[resume] com.example.ctf.VaultKt$unlock$1  label=-2147483647
         incoming = CH-20669
         L$0 = guess
         L$1 = null
         result = CH-20669

[resume] com.example.ctf.Vault$resolveToken$1  label=-2147483647
         incoming = kotlin.Unit

[resume] com.example.ctf.VaultKt$unlock$1  label=-2147483646
         incoming = 8a1f5c93e07b6d24af310e58
         L$0 = guess
         L$1 = CH-20669
         result = 8a1f5c93e07b6d24af310e58

  >>> FLAG{CH-20669:8a1f5c93e07b6d24af310e58}
```

Two notes on reading this. First, the labels are negative because `invokeSuspend` sets the sign bit
before calling back into `unlock`, and `resumeWith` runs before the prologue clears it;
`-2147483646` is `2 | Integer.MIN_VALUE`, so the underlying state is 2. Second, `L$0` still contains the
string you typed, which is a small reminder that the continuation carries the function's parameters as
well as its locals — on a real target, that is where request bodies, credentials, and decrypted payloads
sit while a network call is in flight.

**Your flag will differ from the one above.** The challenge embeds `System.currentTimeMillis() /
86_400_000L`, which is the number of whole days since the Unix epoch, so the value changes daily and the
derived token changes with it. That is deliberate: it makes the flag non-shareable and forces you to
actually run the recovery. The format is fixed, however, and criterion 2 is the check that matters —
feeding your recovered token back to the program must make the program itself print the identical flag.

### Verification run

```bash
# host
echo "8a1f5c93e07b6d24af310e58" | java -cp "classes:kotlinx-coroutines-core-jvm-1.8.1.jar:$KOTLIN_HOME/lib/kotlin-stdlib.jar" com.example.ctf.VaultKt
FLAG{CH-20669:8a1f5c93e07b6d24af310e58}
```

### What generalises to real targets

| Technique from this lab | Real-world use |
|---|---|
| Locate `<Owner>$<function>$1` classes | Find the state machine for a named suspending function without reading the whole app |
| Read `@DebugMetadata` | Recover original file, function, line, and local variable names from an obfuscated release build |
| Pair `label = N` with the following call | Enumerate every suspension point and therefore every asynchronous boundary in a flow |
| Read `L$n` fields at resume time | Recover values that exist only in memory: decrypted payloads, session keys, request bodies awaiting a response |
| Hook `BaseContinuationImpl.resumeWith` | A single hook that observes every asynchronous operation in the process, useful for mapping an unfamiliar app before narrowing down |
| Normalise the sign bit | Avoid misreading state when hooking before the function prologue runs |

The general workflow on an unknown application is: run the broad `resumeWith` hook briefly to discover
which continuation classes are active during the feature you care about, then switch to a narrow
`invokeSuspend` hook on those specific classes for detailed, low-overhead observation. The reusable
version of both hooks is in [scripts/hook-kotlin.js](../scripts/hook-kotlin.js).

</details>

---

**Back to:** [chapter README](../README.md) · [cheatsheet](../cheatsheet.md) · [faq](../faq.md)
