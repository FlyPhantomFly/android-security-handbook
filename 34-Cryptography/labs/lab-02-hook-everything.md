# Lab 02 — Hook Everything

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-break-the-vault.md),
[Chapter 34 §2.3, §7.1–7.5](../README.md), [53-Frida](../../53-Frida/README.md),
frida-server running and version-matched

---

## Objective

Build your own JCA hook **from scratch**, one method at a time, then compare it against
[`scripts/frida-jca-universal-hook.js`](../scripts/frida-jca-universal-hook.js). Use the result to
produce a complete inventory of every cryptographic operation a target app performs: algorithm, key,
IV, plaintext, ciphertext, and the call site that asked for it.

You will finish with a written inventory table you could hand to a client, and — more importantly —
the ability to write a five-line hook for a specific question rather than reaching for a 900-line
script every time.

## Why this matters

The reference script exists and works. So why write your own?

Because a script you did not write is a script you cannot debug. When a hook installs cleanly and
never fires, when `getEncoded()` returns null and you do not know whether that is a hardware key or a
provider quirk, when the app uses a `CipherSpi` directly and bypasses `Cipher` entirely — at that
point you need to reason about the call flow in [§2.3](../README.md#23-the-jca-call-flow-end-to-end),
not about someone else's abstraction.

There is also a professional reason. The universal script is loud: it prints everything, including the
hundreds of crypto operations the TLS stack performs on every network call. Real work is mostly
targeted hooks — five lines that answer one question — and knowing which five lines is the skill.

> **Mental Model**
> Obfuscation renames what the app owns. It cannot rename `javax.crypto.Cipher`, because the platform
> owns that name and the app must use it to reach the provider. Every hook in this lab exploits that
> asymmetry: **hook the boundary the app cannot move.**

---

## Setup

You need a target that performs several different operations. Either use the vault from
[Lab 01](lab-01-break-the-vault.md), or build this richer one.

**`CryptoZoo.java`**

```java
package com.zoo.target;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.util.Base64;
import android.util.Log;

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoZoo extends Activity {

    private static final String TAG = "ZOO";
    private static final byte[] STATIC_IV = new byte[12];   // zeroes: for the reuse demo

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        final Handler h = new Handler();
        h.postDelayed(new Runnable() {
            int round = 0;
            @Override public void run() {
                try { exercise(round++); } catch (Exception e) { Log.e(TAG, "boom", e); }
                h.postDelayed(this, 3000);          // keep going so you can attach late
            }
        }, 1000);
    }

    void exercise(int round) throws Exception {
        // 1. ECB with a hardcoded key
        Cipher ecb = Cipher.getInstance("AES");
        ecb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("HardcodedKey1234".getBytes(), "AES"));
        Log.i(TAG, "ecb=" + Base64.encodeToString(ecb.doFinal("same block same block ".getBytes()),
                                                  Base64.NO_WRAP));

        // 2. CBC with a fixed IV
        Cipher cbc = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cbc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("HardcodedKey1234".getBytes(), "AES"),
                 new IvParameterSpec(new byte[16]));
        Log.i(TAG, "cbc=" + Base64.encodeToString(cbc.doFinal(("round " + round).getBytes()),
                                                  Base64.NO_WRAP));

        // 3. GCM with a REUSED nonce — the finding this lab is really about
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("HardcodedKey1234".getBytes(), "AES"),
                 new GCMParameterSpec(128, STATIC_IV));
        gcm.updateAAD("ctx=v1".getBytes());
        Log.i(TAG, "gcm=" + Base64.encodeToString(gcm.doFinal(("secret " + round).getBytes()),
                                                  Base64.NO_WRAP));

        // 4. GCM done correctly, for contrast
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());
        SecretKey good = kg.generateKey();
        Cipher ok = Cipher.getInstance("AES/GCM/NoPadding");
        ok.init(Cipher.ENCRYPT_MODE, good);
        Log.i(TAG, "ok=" + Base64.encodeToString(ok.doFinal("fine".getBytes()), Base64.NO_WRAP));

        // 5. Weak digest
        MessageDigest.getInstance("MD5").digest(("device" + round).getBytes());

        // 6. HMAC
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("MacKey0123456789".getBytes(), "HmacSHA256"));
        mac.doFinal(("round " + round).getBytes());

        // 7. PBKDF2 with a low iteration count
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        f.generateSecret(new PBEKeySpec("hunter2".toCharArray(),
                                        "saltsalt".getBytes(), 1000, 256));
    }
}
```

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
```

> **Warning**
> If your hooks install but never fire, the method was inlined by the optimizing compiler. Force
> interpretation before you debug anything else:
> ```bash
> # host
> adb shell cmd package compile -m verify -f com.zoo.target
> adb shell am force-stop com.zoo.target
> ```
> See [13-ART §3.17](../../13-ART/README.md).

---

## Steps

### Step 1 — Hook one method, badly, and understand why it is not enough

Start with the naive version everyone writes first.

**`h1.js`**

```javascript
// frida -U -f com.zoo.target -l h1.js
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
        console.log('[getInstance] ' + t);
        return this.getInstance(t);
    };
});
```

```bash
# host
frida -U -f com.zoo.target -l h1.js
```

**Question 1.** You see transformation strings. What can you conclude, and what can you not? Which of
the seven operations in the target does this hook miss entirely, and why?

**Question 2.** Run it against a networked app instead — anything that makes an HTTPS request. How much
of the output is the app, and how much is the TLS stack? What does that tell you about the value of a
package filter?

### Step 2 — Handle every overload

`Cipher.getInstance` has three overloads. `Cipher.init` has far more. Hooking one signature silently
misses the others, and "the hook didn't fire" is indistinguishable from "the app doesn't do that".

**`h2.js`**

```javascript
// frida -U -f com.zoo.target -l h2.js
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.getInstance.overloads.forEach(function (ov, i) {
        ov.implementation = function () {
            console.log('[getInstance #' + i + '] ' + arguments[0]);
            return ov.apply(this, arguments);
        };
    });

    console.log('[*] hooked ' + Cipher.getInstance.overloads.length + ' getInstance overloads');
    console.log('[*] init has ' + Cipher.init.overloads.length + ' overloads');
});
```

**Question 3.** How many `init` overloads does your device report? List their argument types. Which one
does the target actually use for the GCM case, and how would you have found that out without the
source?

### Step 3 — Extract the key

The key arrives at `init` as a `java.security.Key`. Getting bytes out of it is the whole game.

**`h3.js`**

```javascript
// frida -U -f com.zoo.target -l h3.js
function hex(a) {
    return Array.prototype.map.call(a, function (b) {
        return ('0' + (b & 0xff).toString(16)).slice(-2);
    }).join(' ');
}
function ascii(a) {
    return Array.prototype.map.call(a, function (b) {
        b &= 0xff;
        return (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.';
    }).join('');
}

Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.init.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var args = arguments;
            try {
                var key = args[1];
                if (key !== null && key !== undefined) {
                    var enc = key.getEncoded();
                    if (enc === null) {
                        console.log('[init] key=<' + key.$className +
                                    '> getEncoded()=null — NOT EXPORTABLE');
                    } else {
                        console.log('[init] alg=' + this.getAlgorithm() +
                                    ' keylen=' + enc.length);
                        console.log('       hex   ' + hex(enc));
                        console.log('       ascii ' + ascii(enc));
                    }
                }
            } catch (e) { console.log('[init] ' + e); }
            return ov.apply(this, args);
        };
    });
});
```

**Question 4.** For operation 4 (the `KeyGenerator`-produced key) you get bytes. For an AndroidKeyStore
key you would get `null`. Explain precisely what that null means, in terms of where the key physically
is and what request the app is actually making when it calls `doFinal`.

**Question 5.** What is the *right* next step when you see `getEncoded() == null`? Give two specific
things you would test.

### Step 4 — Capture plaintext and ciphertext

`doFinal` is where the data is, but there is a wrinkle: the same method both encrypts and decrypts, and
`Cipher` does not expose the opmode publicly.

**`h4.js`**

```javascript
// frida -U -f com.zoo.target -l h4.js
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    var System = Java.use('java.lang.System');
    var state = {};                                  // identityHashCode -> opmode

    Cipher.init.overloads.forEach(function (ov) {
        ov.implementation = function () {
            state[System.identityHashCode(this)] = arguments[0];
            return ov.apply(this, arguments);
        };
    });

    Cipher.doFinal.overloads.forEach(function (ov) {
        ov.implementation = function () {
            var input = (arguments.length > 0 && arguments[0] !== null &&
                         arguments[0].length !== undefined) ? arguments[0] : null;
            var ret = ov.apply(this, arguments);
            var op = state[System.identityHashCode(this)];
            var dir = (op === 1) ? 'ENCRYPT' : (op === 2 ? 'DECRYPT' : 'op=' + op);
            console.log('[doFinal] ' + dir + ' ' + this.getAlgorithm() +
                        ' in=' + (input ? input.length : 0) +
                        ' out=' + ((ret && ret.length !== undefined) ? ret.length : '?'));
            if (input) console.log('    in  ' + Java.use('java.lang.String').$new(input));
            return ret;
        };
    });
});
```

**Question 6.** Why does tracking the opmode need a map keyed by object identity, rather than a single
variable? Construct the case where a single variable gives you a wrong answer.

**Question 7.** `String.$new(input)` mangles non-UTF-8 bytes. When does that matter, and what should
you print instead?

### Step 5 — Detect nonce reuse yourself

This is the finding the target is built around, and it is the one you should be able to write from
memory.

**`h5.js`**

```javascript
// frida -U -f com.zoo.target -l h5.js
Java.perform(function () {
    var seen = {};
    var GCM = Java.use('javax.crypto.spec.GCMParameterSpec');

    GCM.$init.overload('int', '[B').implementation = function (tLen, iv) {
        var h = Array.prototype.map.call(iv, function (b) {
            return ('0' + (b & 0xff).toString(16)).slice(-2);
        }).join('');
        if (seen[h]) {
            console.error('[!!!] GCM NONCE REUSE: ' + h + ' (seen ' + seen[h] + ' times)');
        }
        seen[h] = (seen[h] || 0) + 1;
        if (tLen < 96) console.error('[!] short GCM tag: ' + tLen + ' bits');
        return this.$init(tLen, iv);
    };
});
```

**Question 8.** This hook tracks nonces alone. Why is `(key, nonce)` the correct unit, and construct a
case in which nonce-only tracking produces a false positive.

**Question 9.** Operation 4 in the target uses GCM correctly and never constructs a `GCMParameterSpec`
on encryption. Would this hook see it? What does that imply about relying on constructor hooks alone?

### Step 6 — Compare against the reference script

```bash
# host
frida -U -f com.zoo.target -l ../scripts/frida-jca-universal-hook.js \
      -P '{"filterPackage":"com.zoo","maxDump":128,"showStacks":true}'
```

Let it run through several rounds, then in the REPL:

```
jca.report()
jca.keys()
```

**Question 10.** List three things the reference script reports that your hooks did not. For each, say
which method it had to hook to get it.

**Question 11.** The reference script flags the hardcoded key by noticing that the bytes are printable
ASCII. Give two ways that heuristic fails — one false positive, one false negative — and say what would
resolve each.

### Step 7 — Build the inventory

Produce a table for the target. This is the deliverable.

| # | Operation | Transformation | Key (hex, truncated) | Key origin | IV/nonce | Fresh? | Data | Finding |
|---|---|---|---|---|---|---|---|---|
| 1 | encrypt | `AES` → ECB | `4861726…` | `SecretKeySpec` from literal | n/a | n/a | `same block same block ` | F-01, F-02 |
| 2 | … | | | | | | | |

Fill in all seven. Then answer:

**Question 12.** Which single row would you lead the report with, and why? Justify against the three
severity questions in [§5.1](../README.md#51-how-to-think-about-severity-before-we-start).

### Step 8 — Go below the JCA

Some apps do not use the JCA at all. Flutter, several commercial SDKs, and deliberately hardened apps
call BoringSSL directly through JNI.

```bash
# host
frida -U -n com.zoo.target -l - <<'JS'
['EVP_EncryptInit_ex', 'EVP_DecryptInit_ex', 'EVP_CipherInit_ex',
 'EVP_AEAD_CTX_seal', 'EVP_AEAD_CTX_open', 'AES_set_encrypt_key'].forEach(function (n) {
    var a = Module.findExportByName('libcrypto.so', n);
    if (a === null) { console.log('[-] ' + n + ' not exported'); return; }
    Interceptor.attach(a, { onEnter: function (args) { console.log('[native] ' + n); } });
    console.log('[+] hooked ' + n);
});
JS
```

**Question 13.** Which of these symbols resolve on your device, and which do not? Why does BoringSSL
export fewer symbols than upstream OpenSSL, and what does that mean for your tooling?

**Question 14.** You attach to an app and the Java hooks show *no* cryptographic activity, yet the app
still stores encrypted data. List four explanations, in the order you would test them.

---

## Hints

<details>
<summary>Hint 1 — the hook installs but never fires</summary>

In order:

```bash
# host
adb shell cmd package compile -m verify -f com.zoo.target   # defeat inlining
adb shell am force-stop com.zoo.target
```

Then check: are you spawning (`-f`) or attaching (`-n`)? Attaching misses everything that happened
before you arrived, and a lot of crypto happens in `Application.onCreate`.

Then check the ClassLoader. If the class lives in a dynamically loaded DEX, `Java.use` will not find
it in the default loader:

```javascript
Java.enumerateClassLoaders({
    onMatch: function (l) { try { l.loadClass('com.zoo.target.CryptoZoo'); console.log('[+] ' + l); } catch (e) {} },
    onComplete: function () {}
});
```
</details>

<details>
<summary>Hint 2 — reading Java byte[] in Frida</summary>

A Java `byte[]` reaches JS as an array-like of **signed** numbers, so `-1` means `0xff`. Always mask:

```javascript
(b & 0xff).toString(16)
```

Forgetting the mask produces hex like `-1` and `-42`, which is the most common cosmetic bug in
home-made crypto hooks and makes output that cannot be pasted into a report.
</details>

<details>
<summary>Hint 3 — calling the original from inside a replacement</summary>

Two idioms, both correct:

```javascript
// when you hooked a named method and the signature is unambiguous
Cipher.doFinal.implementation = function (x) { return this.doFinal(x); };

// when iterating overloads — capture the overload object
Cipher.doFinal.overloads.forEach(function (ov) {
    ov.implementation = function () { return ov.apply(this, arguments); };
});
```

Do **not** capture the overload in a loop variable declared with `var` outside a function scope in
older JS engines; the classic closure bug gives every hook the last overload. `forEach` gives each
iteration its own scope, which is why it is used throughout the reference script.
</details>

<details>
<summary>Hint 4 — the output is unreadably noisy</summary>

Three levers, in order of usefulness:

1. Filter by stack: only print when the Java stack mentions the target package. That removes the TLS
   stack, the media framework and Play Services in one step.
2. Filter by transformation: TLS uses specific ones; the app usually uses different ones.
3. Aggregate instead of streaming: collect into a map and print a summary on demand. That is what
   `jca.report()` does, and it is nearly always the right shape for a long capture.
</details>

<details>
<summary>Hint 5 — getEncoded() returns null and you want the key anyway</summary>

You cannot have it. That is the point of the design, and it is working.

Stop attacking the key and start attacking the *usage*:

- Can you call the app's own decrypt method with your own input? Enumerate live objects with
  `Java.choose` and invoke it.
- Is the key bound to user authentication? If not, an attacker with code execution has a permanent
  local oracle, and that is the finding — phrased accurately, not as "we extracted the key".
- Does the app ever hold the plaintext somewhere you can reach — a cache, a log, a WebView?
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** You can conclude which transformations exist and immediately raise F-02 for the bare `AES`. You
cannot conclude anything about keys, IVs, data, or whether an operation ever runs — `getInstance`
firing only means a `Cipher` object was created. It misses operations 4 through 7 entirely, because
`KeyGenerator`, `MessageDigest`, `Mac` and `SecretKeyFactory` are different classes with their own
`getInstance`. The JCA's provider pattern means "getInstance" is a family of unrelated static methods,
not one chokepoint.

**2.** On a networked app the overwhelming majority is TLS — Conscrypt performing key agreement,
record encryption and MAC computation for every connection. On a busy screen this can be hundreds of
operations per second, and the app's own two calls are invisible in it. A package filter (checking that
the Java stack mentions the target's package) is not a convenience; it is what makes the output usable
at all.

**3.** Device-dependent; typically six to eight, including `(int, Key)`, `(int, Key, AlgorithmParameterSpec)`,
`(int, Key, AlgorithmParameters)`, `(int, Key, SecureRandom)`, `(int, Certificate)` and the
combinations. The GCM case uses `(int, Key, AlgorithmParameterSpec)`. Without source you find out by
printing `ov.argumentTypes` inside each replacement, or by logging which overload index fires.

**4.** `null` means the key material is not present in the app's address space. The `SecretKey` object
is a handle — a Binder reference to a key blob held by the keystore daemon, whose plaintext exists only
inside the TEE (or a StrongBox secure element). When the app calls `doFinal`, it is not computing AES;
it is sending the data across Binder to `keystore2`, which asks KeyMint in the secure world to perform
the operation and returns the result. The app never touches the key, so neither do you.

**5.** (a) Test whether the key is bound to user authentication — call `SecretKeyFactory.getKeySpec(k,
KeyInfo.class)` through Frida and read `isUserAuthenticationRequired()` and the validity window; an
unbound key is a permanent local oracle. (b) Test whether you can reach the app's own decrypt path
without authenticating — enumerate live objects with `Java.choose` and invoke the method directly. Both
tests move the question from "can I steal the key" (no) to "can I use it" (usually yes, and that is the
finding).

**6.** `Cipher` objects are independent, and a single app can hold several simultaneously — an
encrypting one and a decrypting one, or one per thread. A single variable records whichever `init` ran
most recently, so with an encrypt and a decrypt interleaved you will label the decryption's output as
plaintext-in rather than plaintext-out and report the wrong direction. Identity-keyed state is the only
correct approach, and it is why the reference script uses `System.identityHashCode`.

**7.** It matters whenever the bytes are not text — which is every ciphertext, every key, every digest.
`String.$new` decodes as the platform charset and replaces invalid sequences, so the output is lossy
and not reversible. Print hex as the primary representation and ASCII as an annotation, exactly as the
reference script does. If you may need the bytes later, write them to a file.

**8.** A nonce is only required to be unique **per key**. The same nonce under two different keys is
perfectly safe — that is exactly what happens when two independent users each start their counter at
zero. Tracking nonces alone therefore false-positives whenever the app uses more than one key, which
is common in any multi-account or per-record-key design. The correct unit is the pair, which is why
`checkNonceReuse` in the reference script keys on `keyHex + '|' + ivHex`.

**9.** No. Correct GCM encryption never constructs a `GCMParameterSpec` — the provider generates the
nonce and you read it back with `getIV()`. So a constructor hook sees only the *incorrect* usage, which
is convenient for finding bugs and useless for building a complete inventory. The general lesson:
constructor hooks find what the app supplies; you also need to hook the getters to see what the
provider supplied.

**10.** Examples: (a) the PBKDF2 iteration count and salt — from `PBEKeySpec.$init`; (b) the
`MessageDigest` algorithm and its input — from `MessageDigest.getInstance` and `.digest`; (c) the HMAC
key — from `Mac.init`; (d) repeated ciphertext blocks proving ECB — computed from the `doFinal` return
value, not from any hook; (e) the call site of each operation — from a synthetic stack trace.

**11.** False positive: an app legitimately derives a key with PBKDF2 and, by chance, all 32 bytes fall
in the printable range. Probability is about (95/256)^32, which is negligible for 32 bytes but not for
an 8-byte DES key — so the heuristic should be length-aware. False negative: the key is a hardcoded
**hex or Base64 string decoded at runtime**, so the bytes reaching `SecretKeySpec` are high-entropy and
look random. Resolution for both: correlate across runs and installs. A key that is byte-identical on
two fresh installs is hardcoded regardless of what it looks like; a key that differs is not.

**12.** The GCM nonce reuse (operation 3). Against the three questions: what is protected is
application data under a key also used elsewhere; the attacker needs only two ciphertexts, which are
observable on disk or on the wire with no privileged access; and exploitation yields the XOR of two
plaintexts *and* recovery of the GHASH subkey H, permitting forgery of arbitrary authenticated
messages under that key. It outranks the hardcoded key in mechanism severity — though in practice you
would report both, and confirm that the hardcoded key makes the nonce-reuse finding moot since the
attacker already has the key. Saying that explicitly is what distinguishes an analysis from a list.

**13.** BoringSSL is a fork that removed large parts of OpenSSL's API and does not maintain ABI
stability, because it is only ever consumed by Google's own code. Many upstream symbol names are gone,
renamed or made static, and the AEAD interface (`EVP_AEAD_CTX_seal`) is the modern path while
`EVP_EncryptInit_ex` may not be used at all. The consequence for tooling: never assume a symbol exists,
always check the return of `findExportByName`, and expect the set to differ between Android releases
because `libcrypto.so` ships in a Mainline module.

**14.** In order of likelihood: (1) you attached too late — the crypto ran during
`Application.onCreate`; respawn with `-f`. (2) The app uses native crypto, not the JCA; hook
`libcrypto.so`, and if that is empty look for a statically linked or custom implementation. (3) The
data is not encrypted by this app at all — it arrived already encrypted from a server, or it is
compressed rather than encrypted (check entropy and magic bytes). (4) The app detected instrumentation
and changed behaviour; check for anti-Frida measures, see
[38-TamperDetection](../../38-TamperDetection/README.md).

</details>

---

## Success criteria

- [ ] You wrote a working hook for `getInstance`, `init` and `doFinal` from scratch
- [ ] You handled **every** overload rather than one signature
- [ ] You extracted a key, printed it correctly in hex with the sign mask applied, and matched it
      against the source constant
- [ ] You explained what `getEncoded() == null` means physically, not just "it's a KeyStore key"
- [ ] You detected the nonce reuse with your own code before running the reference script
- [ ] You can state why `(key, nonce)` is the correct tracking unit
- [ ] You produced a complete seven-row inventory table for the target
- [ ] You ran the reference script and identified three things it caught that you missed
- [ ] You attempted native hooking and can say which BoringSSL symbols exist on your device
- [ ] You can write a five-line targeted hook for a specific question without consulting anything
