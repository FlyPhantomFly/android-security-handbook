# Lab 03 — Find the Hidden Key

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-decode-instructions.md),
[Chapter 12 §3.27](../README.md), [34-Cryptography](../../34-Cryptography/README.md)

---

## Objective

Locate hardcoded cryptographic key material in a DEX where `strings` finds nothing, recover it, and
use it to decrypt data the app stored on disk. Then do it the other way — at runtime — and compare
which approach was faster and which was more reliable.

## Why this matters

"We searched for hardcoded secrets and found none" appears in an enormous number of mobile reports,
and a large share of those searches were `strings | grep -i key`.

When a developer writes `byte[] key = {0x2b, 0x7e, ...}`, the bytes do **not** go in the string pool.
They become a `fill-array-data-payload` — raw bytes in the data section. `strings` walks straight
past them. So does every scanner that only looks at the string table.

This lab makes that concrete, and gives you the two techniques that actually work.

---

## Setup

Build a target that stores encrypted data using a hardcoded key. This is a deliberately vulnerable app
you control.

**`SecretStore.java`**

```java
package com.artlab.keylab;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SecretStore {

    private static final String TAG = "KEYLAB";

    // The key. NOT in the string pool — this compiles to a
    // fill-array-data payload. See ../README.md section 3.27.
    private static final byte[] KEY = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
        (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c
    };

    // A static IV — itself a finding. See ../../34-Cryptography/.
    private static final byte[] IV = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    public static void store(Context ctx, String plaintext) {
        try {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.ENCRYPT_MODE,
                   new SecretKeySpec(KEY, "AES"),
                   new IvParameterSpec(IV));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            File f = new File(ctx.getFilesDir(), "vault.bin");
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(ct);
            }
            Log.d(TAG, "stored " + ct.length + " bytes, b64=" +
                       Base64.encodeToString(ct, Base64.NO_WRAP));
        } catch (Exception e) {
            Log.e(TAG, "store failed", e);
        }
    }
}
```

Call it once from your Activity with a recognisable secret:

```java
SecretStore.store(this, "ARTLAB{the_key_was_never_a_string}");
```

Build **release** with `minifyEnabled true` so the exercise is realistic:

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
# launch the app once so it writes vault.bin
```

---

## Steps

### Step 1 — Prove the naive approach fails

```bash
# host
unzip -o app-release.apk 'classes*.dex' -d dex/
strings dex/classes.dex | grep -iE "key|secret|password" | head -20
strings dex/classes.dex | grep -E "^[0-9a-f]{32}$" | head
```

**Q1.** Did you find the key? Did you find *anything* that looks like key material?

Now try the string table properly, not just `strings`:

```bash
python3 ../examples/dex_parser.py dex/classes.dex --strings | grep -iE "key|aes|secret"
```

**Q2.** What *did* you find? Is any of it the key? What does what you found tell you anyway?

### Step 2 — Find the array literals

```bash
# host
python3 ../examples/find_array_literals.py dex/classes.dex
```

**Q3.** How many payloads are there in total? How many are 16 bytes?

```bash
python3 ../examples/find_array_literals.py dex/classes.dex --keys-only
```

**Q4.** Write down every 16-byte payload with its file offset and hex bytes. You should have at least
two — the key and the IV. Can you tell which is which from the bytes alone?

**Q5.** The tool reports "byte diversity" for each. What do the two values suggest? Which candidate
looks more like a key and which more like a counter or IV?

### Step 3 — Confirm by finding the reference

A payload on its own is a candidate. Confirm it by finding the instruction that references it and
following where the array goes.

```bash
# host
baksmali d dex/classes.dex -o smali/
grep -rn "fill-array-data" smali/ | head
```

**Q6.** Which class and method contains each `fill-array-data`? Given `minifyEnabled true`, are the
names still meaningful?

Now follow the data:

```bash
grep -rn "SecretKeySpec\|IvParameterSpec\|Cipher;->getInstance" smali/
```

**Q7.** Find the `SecretKeySpec` constructor call. Trace backwards: which register holds the byte
array, and which `fill-array-data` filled it?

**Q8.** Same for `IvParameterSpec`. You should now know definitively which payload is the key and
which is the IV.

**Q9.** What transformation string is passed to `Cipher.getInstance`? Read it from the string table.
Note the mode — is it a finding in its own right?

### Step 4 — Extract the ciphertext

```bash
# host — the app is debuggable in a release build only if you made it so;
# otherwise use root
adb shell "run-as com.artlab.keylab cat files/vault.bin" > vault.bin 2>/dev/null \
  || adb shell "su -c 'cat /data/data/com.artlab.keylab/files/vault.bin'" > vault.bin
xxd vault.bin | head
```

**Q10.** How large is the file? Is the length a multiple of 16? What does that tell you about the
mode and padding?

### Step 5 — Decrypt offline

```bash
# host
python3 - <<'PY'
from Crypto.Cipher import AES          # pip install pycryptodome
from Crypto.Util.Padding import unpad

key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")   # <-- your key
iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")   # <-- your IV
ct  = open("vault.bin","rb").read()

pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
print(pt.decode())
PY
```

If you prefer no dependencies:

```bash
# host — openssl equivalent
openssl enc -d -aes-128-cbc \
  -K 2b7e151628aed2a6abf7158809cf4f3c \
  -iv 000102030405060708090a0b0c0d0e0f \
  -in vault.bin
```

**Q11.** Did you recover the flag? If decryption produced garbage, which of your two candidates did
you have as the key?

### Step 6 — Now do it the other way, at runtime

Static analysis gave you the answer. Confirm it dynamically, and compare the effort.

```bash
# host
frida -U -f com.artlab.keylab -l ../../34-Cryptography/scripts/frida-jca-universal-hook.js
```

That script instruments the whole Java Cryptography Architecture and prints far more than this lab
needs. If you would rather see only the key material, and understand every line of what you are
running, use this minimal version instead:

```javascript
// keydump.js
Java.perform(function () {
    var SKS = Java.use("javax.crypto.spec.SecretKeySpec");
    SKS.$init.overload("[B", "java.lang.String").implementation = function (k, alg) {
        console.log("[SecretKeySpec] alg=" + alg + " key=" +
            Array.from(k).map(function (b) {
                return ("0" + (b & 0xff).toString(16)).slice(-2);
            }).join(""));
        return this.$init(k, alg);
    };

    var IVP = Java.use("javax.crypto.spec.IvParameterSpec");
    IVP.$init.overload("[B").implementation = function (iv) {
        console.log("[IvParameterSpec] iv=" +
            Array.from(iv).map(function (b) {
                return ("0" + (b & 0xff).toString(16)).slice(-2);
            }).join(""));
        return this.$init(iv);
    };

    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (t) {
        console.log("[Cipher.getInstance] " + t);
        return this.getInstance(t);
    };
});
```

**Q12.** Does the runtime key match the one you extracted statically?

**Q13.** Which approach was faster for you? Which would still work if the key were **derived** at
runtime rather than hardcoded? Which would still work if the app were heavily obfuscated?

### Step 7 — Make it harder, then defeat it again

Modify the app so the key is XOR-obfuscated at rest:

```java
private static final byte[] OBF = { /* KEY[i] ^ 0x5A for each byte */ };

private static byte[] key() {
    byte[] k = new byte[OBF.length];
    for (int i = 0; i < OBF.length; i++) k[i] = (byte) (OBF[i] ^ 0x5A);
    return k;
}
```

Rebuild and repeat.

**Q14.** Does `find_array_literals.py` still find a 16-byte payload? Is it still the key?

**Q15.** Does the static approach still get you the plaintext? What extra step is now required?

**Q16.** Does the **runtime** approach need any change at all? What does that tell you about the
relative durability of the two techniques?

### Step 8 — Write it up

Draft the finding as you would for a client. Include:

- What the issue is, in one sentence a non-technical stakeholder can act on
- The threat model: who the attacker is and what they need
- Evidence: the payload offset, the hex, and the code path that consumes it
- Impact: what the key protects and what its disclosure yields
- Severity, with justification
- Remediation, as code

**Q17.** What severity did you assign, and why? Would it change if the key protected only
non-sensitive cached data?

---

## Hints

<details>
<summary>Hint 1 — find_array_literals finds nothing</summary>

Check you are scanning every DEX:

```bash
for f in dex/classes*.dex; do echo "=== $f"; python3 ../examples/find_array_literals.py "$f"; done
```

Also try lowering `--min-size`. If the array is small the default may filter it out.
</details>

<details>
<summary>Hint 2 — I have two 16-byte payloads and cannot tell them apart</summary>

That is the point of Step 3 — do not guess. Follow the `fill-array-data` instruction to the register,
then find which constructor consumes that register. `SecretKeySpec` takes the key;
`IvParameterSpec` takes the IV.

As a weaker heuristic: an IV is often sequential or all-zero (low byte diversity), while a key
usually looks random (high diversity). The tool reports this. But confirm by following the code.
</details>

<details>
<summary>Hint 3 — run-as fails</summary>

`run-as` only works on `debuggable` apps. For a release build use root:

```bash
adb shell "su -c 'cat /data/data/com.artlab.keylab/files/vault.bin'" > vault.bin
```

Or temporarily set `android:debuggable="true"` in your test build.
</details>

<details>
<summary>Hint 4 — decryption gives padding errors</summary>

Three usual causes: you swapped the key and IV; the file transfer corrupted the binary (make sure
`adb shell cat` output was not mangled by line-ending conversion — use `adb pull` or
`exec-out` instead); or the mode is not what you assumed. Re-read the transformation string from
Step 3 Q9.

```bash
adb exec-out run-as com.artlab.keylab cat files/vault.bin > vault.bin
```
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1–Q2.** `strings` finds nothing resembling the key, because the key is not a string. What you
*will* find in the string table is `"AES"`, `"AES/CBC/PKCS5Padding"` and possibly `"vault.bin"` —
which is itself valuable: it tells you cryptography is happening, which algorithm and mode, and where
the output lands. Strings point you at the code even when they do not contain the secret.

**Q3–Q5.** You should find at least two 16-byte payloads. Byte diversity distinguishes them
heuristically: the key looks random, the IV in this app is sequential `00 01 02 ...` and so has low
diversity. **Heuristics are for prioritising, not for concluding.**

**Q6.** With `minifyEnabled true` the class and method names are obfuscated to something like
`a.b.c->d()`. The `fill-array-data` instruction and the `SecretKeySpec` reference are **not**
obfuscated, because they are framework references — which is exactly why following the data works when
following the names does not.

**Q9.** `AES/CBC/PKCS5Padding` with a **static IV** is a finding in its own right: identical
plaintexts produce identical ciphertexts, defeating semantic security. See
[34-Cryptography](../../34-Cryptography/README.md).

**Q10.** CBC with PKCS#5 padding always produces a length that is a multiple of the 16-byte block
size, and always adds at least one byte of padding.

**Q13.** Static analysis is faster when the key is a literal, and gives you a definitive answer you can
cite by file offset. Runtime hooking still works when the key is **derived**, **decrypted**, or
**fetched**, and is largely immune to name obfuscation. Neither is strictly better; a competent tester
runs the static sweep first because it is cheap, and reaches for runtime when it comes up empty.

**Q14–Q16.** With XOR obfuscation the payload is still 16 bytes and still found, but it is no longer
the key — you must now also locate and replicate the de-obfuscation routine. The **runtime** approach
needs no change whatsoever, because `SecretKeySpec` receives the *final* key regardless of how it was
produced.

That is the durable lesson of this lab: **static analysis finds secrets at rest; runtime hooking finds
secrets in use.** Obfuscation raises the cost of the first and does essentially nothing to the second.

**Q17.** Typically **High** when the key protects authentication material, personal data or payment
information, because extraction is trivial and yields plaintext for every user of the app. Drops to
**Medium** or **Low** if it protects only non-sensitive cached data, and the honest report says so.
The severity comes from what the key protects, not from the fact that a key was found. See
[80-Appendix](../../80-Appendix/README.md) on severity.

</details>

---

## Success criteria

- [ ] You demonstrated that `strings` fails to find the key, and can explain why in one sentence
- [ ] You located every `fill-array-data` payload and identified the 16-byte candidates
- [ ] You determined which candidate is the key by **following the code**, not by guessing
- [ ] You read the cipher transformation from the string table and assessed the mode
- [ ] You extracted the ciphertext and decrypted it offline to recover the flag
- [ ] You confirmed the key independently at runtime with a Frida hook
- [ ] You defeated the XOR-obfuscated variant and observed that the runtime approach needed no change
- [ ] You can state when static beats runtime and when runtime beats static
- [ ] You wrote the finding up with a severity you can defend, and can say what would change it
