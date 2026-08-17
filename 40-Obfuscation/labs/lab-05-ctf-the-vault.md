# Lab 05 — CTF: The Vault

**Difficulty:** CTF
**Time:** 4–8 hours
**Prerequisites:** [Lab 01](lab-01-obfuscation-triage.md) through [Lab 04](lab-04-unpack.md),
[Chapter 40 §6.1](../README.md#61-the-deobfuscation-methodology) in full,
[34-Cryptography](../../34-Cryptography/README.md), [57-Ghidra](../../57-Ghidra/README.md)

---

## The challenge

You are handed `vault.apk`. It installs, it runs, and it shows one screen with a text field and a
button marked **OPEN**. Whatever you type, it says:

```
Locked.
```

`jadx` shows you thirty-one classes, none of which resemble an application. `strings` on the DEX
returns nothing you can use. `apktool` completes but the Smali is meaningless. There is a 2.4 MB file
in `assets/` with entropy 7.99, a native library with two exported symbols, and a manifest whose
`<application android:name>` you have never seen before.

**Recover the flag.** It has the form `OBFLAB{...}` and it is displayed when the correct passphrase is
entered.

You may not brute-force the passphrase, and you may not patch the comparison and read the flag off the
screen — the flag is *derived* from the passphrase, so a patched comparison shows you a decryption
failure and nothing else. You must actually recover it.

---

## Objective

Run the entire deobfuscation methodology, in order, against a target that stacks every protection in
the chapter:

| Layer | Technique | Chapter section |
|---|---|---|
| 1 | Packer: stub `Application`, encrypted asset, `ClassLoader` surgery | [§3.7](../README.md#37-packers-and-commercial-protectors) |
| 2 | Anti-debug in `.init_array`, before `JNI_OnLoad` | [§3.7.1](../README.md#371-how-a-packer-works-mechanically) |
| 3 | R8 renaming across the payload | [§3.1](../README.md#31-identifier-renaming) |
| 4 | Per-class string encryption | [§3.2](../README.md#variant-c--per-class-decrypt-methods) |
| 5 | Control-flow flattening on the key-derivation method | [§3.3.2](../README.md#332-control-flow-flattening--the-important-one) |
| 6 | Part of the key computed in native code, registered with `RegisterNatives` | [§3.6](../README.md#36-native-code-migration) |
| 7 | Reflection instead of direct calls at the crypto boundary | [§3.4](../README.md#34-api-hiding-via-reflection-and-dynamic-resolution) |

The point is not any individual layer — you have defeated each one already in labs 01 to 04. The point
is **ordering**. Attack these in the wrong sequence and you will spend a day; attack them in the
methodology's order and it is an afternoon.

## Why this matters

Real targets do not present you with one technique at a time. A hardened banking app is packed *and*
renamed *and* string-encrypted *and* partly native *and* watching for your debugger, and the panic
that produces in an analyst who has only ever practised techniques in isolation is the actual
protection.

The methodology exists to remove that panic. It is a *repeatable procedure*, which is what makes it
teachable and what makes your results consistent under time pressure:

```
Phase 0  acquire and verify
Phase 1  triage — what protection is present?
Phase 2  static or dynamic?
Phase 3  UNPACK, if packed
Phase 4  RECOVER STRINGS FIRST
Phase 5  recover control flow — only for methods the strings flagged
Phase 6  semantic renaming from the evidence
Phase 7  write the model down
```

Every ordering decision in that list is load-bearing, and this lab is constructed so that violating any
of them costs you visibly:

- Skip Phase 1 and you will read the stub for an hour.
- Do Phase 5 before Phase 4 and you will deflatten the wrong method.
- Skip Phase 6 and you will lose track of what you already understood.
- Skip Phase 7 and you will miss the native component entirely.

---

## Rules

- No brute force on the passphrase, and no dictionary attacks.
- No patching the comparison to bypass it. The flag is derived from the passphrase; a bypass shows you
  a failed decryption and nothing more.
- You must be able to state, for each of the seven layers, **which phase of the methodology defeated
  it** and roughly how long it took.
- Solve it, then write the two-page model that Phase 7 demands. The model is the deliverable; the flag
  is the receipt.

---

## Building the challenge

Build it yourself. Constructing the stack is what teaches you why the ordering matters — you will see,
from the inside, which layers depend on which.

Start from the packer in [lab 04](lab-04-unpack.md) and the string encryption from
[lab 02](lab-02-string-recovery.md). Full sources for both are in [`../examples/`](../examples/).

### Part 1 — the payload app

Package `com.obflab.vault`.

**`VaultActivity.java`**

```java
package com.obflab.vault;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

public class VaultActivity extends Activity {

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);

        final EditText input = new EditText(this);
        input.setHint("passphrase");
        final TextView out = new TextView(this);
        out.setTextSize(15f);
        out.setPadding(0, 48, 0, 0);

        Button open = new Button(this);
        open.setText("OPEN");
        open.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View v) {
                String r = Vault.open(VaultActivity.this, input.getText().toString());
                out.setText(r == null ? "Locked." : r);
            }
        });

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);
        root.addView(input);
        root.addView(open);
        root.addView(out);
        setContentView(root);
    }
}
```

**`Vault.java`** — the crypto, reached through reflection so there are no direct `Cipher` references
for a static cross-reference search to find.

```java
package com.obflab.vault;

import android.content.Context;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class Vault {

    static { System.loadLibrary("vaultcore"); }

    /** Registered dynamically in JNI_OnLoad — no Java_* symbol to grep for. */
    private static native int mix(int seed, int rounds);

    public static String open(Context ctx, String passphrase) {
        try {
            if (passphrase == null || passphrase.isEmpty()) return null;

            // S1.a(int) is the per-class string decryptor for this class.
            String salt = S1.a(0);                 // "obflab-vault-2024"
            String algo = S1.a(1);                 // "AES/CBC/PKCS5Padding"
            String kAlg = S1.a(2);                 // "AES"
            String hAlg = S1.a(3);                 // "SHA-256"
            String asset = S1.a(4);                // "vault.bin"

            int seed = KeySchedule.derive(passphrase, salt);   // FLATTENED
            int mixed = mix(seed, 17);                          // NATIVE

            MessageDigest md = MessageDigest.getInstance(hAlg);
            md.update(passphrase.getBytes(StandardCharsets.UTF_8));
            md.update(salt.getBytes(StandardCharsets.UTF_8));
            md.update(new byte[] {
                (byte) (mixed >>> 24), (byte) (mixed >>> 16),
                (byte) (mixed >>> 8),  (byte) mixed
            });
            byte[] key = new byte[16];
            System.arraycopy(md.digest(), 0, key, 0, 16);

            byte[] blob = readAsset(ctx, asset);
            byte[] iv = new byte[16];
            System.arraycopy(blob, 0, iv, 0, 16);
            byte[] ct = new byte[blob.length - 16];
            System.arraycopy(blob, 16, ct, 0, ct.length);

            // Reflection instead of direct Cipher calls (section 3.4).
            Class<?> cipherCls = Class.forName(S1.a(5));         // "javax.crypto.Cipher"
            Class<?> skCls = Class.forName(S1.a(6));             // "javax.crypto.spec.SecretKeySpec"
            Class<?> ivCls = Class.forName(S1.a(7));             // "javax.crypto.spec.IvParameterSpec"

            Object cipher = cipherCls
                    .getMethod(S1.a(8), String.class)            // "getInstance"
                    .invoke(null, algo);
            Object sk = skCls.getConstructor(byte[].class, String.class)
                    .newInstance(key, kAlg);
            Object ivSpec = ivCls.getConstructor(byte[].class).newInstance((Object) iv);

            Method init = cipherCls.getMethod(S1.a(9),           // "init"
                    int.class,
                    Class.forName(S1.a(10)),                     // "java.security.Key"
                    Class.forName(S1.a(11)));                    // "java.security.spec.AlgorithmParameterSpec"
            init.invoke(cipher, 2 /* DECRYPT_MODE */, sk, ivSpec);

            byte[] pt = (byte[]) cipherCls
                    .getMethod(S1.a(12), byte[].class)           // "doFinal"
                    .invoke(cipher, ct);

            String s = new String(pt, StandardCharsets.UTF_8);
            return s.startsWith(S1.a(13)) ? s : null;            // "OBFLAB{"
        } catch (Throwable t) {
            return null;   // every failure looks identical
        }
    }

    private static byte[] readAsset(Context ctx, String name) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }

    private Vault() { }
}
```

**`KeySchedule.java`** — flattened. Write it unflattened first, verify it works, then flatten by hand
using the pattern from [§3.3.2](../README.md#332-control-flow-flattening--the-important-one) with
randomised state constants.

```java
package com.obflab.vault;

public final class KeySchedule {

    // ORIGINAL — keep this only in your build notes, not in the shipped APK.
    //
    // static int derive(String pass, String salt) {
    //     int acc = salt.length() * 131;
    //     for (int i = 0; i < pass.length(); i++) {
    //         char c = pass.charAt(i);
    //         if ((c & 1) == 0) acc = acc * 31 + c;
    //         else              acc = acc ^ (c << (i % 8));
    //         if (acc < 0) acc = ~acc;
    //     }
    //     return acc + salt.charAt(0);
    // }

    static int derive(String pass, String salt) {
        int acc = 0, i = 0;
        char c = 0;
        int state = 0x3D71A2;
        while (true) {
            switch (state) {
                case 0x3D71A2: acc = salt.length() * 131; i = 0; state = 0x08C4F5; break;
                case 0x08C4F5: state = (i < pass.length()) ? 0x5A20BE : 0x71E9C3; break;
                case 0x5A20BE: c = pass.charAt(i); state = ((c & 1) == 0) ? 0x2F8D41 : 0x66B017; break;
                case 0x2F8D41: acc = acc * 31 + c; state = 0x1948DA; break;
                case 0x66B017: acc = acc ^ (c << (i % 8)); state = 0x1948DA; break;
                case 0x1948DA: state = (acc < 0) ? 0x4C3E82 : 0x7B5F09; break;
                case 0x4C3E82: acc = ~acc; state = 0x7B5F09; break;
                case 0x7B5F09: i++; state = 0x08C4F5; break;
                case 0x71E9C3: return acc + salt.charAt(0);
                default: return 0;
            }
        }
    }

    private KeySchedule() { }
}
```

**`S1.java`** — the per-class decryptor. Generate the arrays with the script in
[`../examples/StringEncryption.java`](../examples/StringEncryption.java) and [`../examples/gen-string-table.py`](../examples/gen-string-table.py), using a **different key per class**. Add `S2`, `S3`,
… for the other classes so the app has several decryptors rather than one.

```java
package com.obflab.vault;

final class S1 {
    private static final byte[][] D = { /* generated */ };
    private static final int K = 0x4B;          // different in S2, S3, ...

    static String a(int i) {
        byte[] e = D[i];
        char[] o = new char[e.length];
        for (int j = 0; j < e.length; j++) {
            o[j] = (char) ((e[j] ^ K) - (j & 7));
        }
        return new String(o);
    }

    private S1() { }
}
```

Note the `- (j & 7)`: a position-dependent term, so a naive single-byte-XOR guess from a static reader
fails while a runtime call is unaffected. That asymmetry is the lab's point in miniature.

### Part 2 — the native component

**`app/src/main/cpp/vaultcore.c`**

```c
#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <android/log.h>

#define TAG "VAULTCORE"

/* ---- anti-debug in .init_array: runs during dlopen, before JNI_OnLoad ---- */
__attribute__((constructor))
static void guard(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof line, f)) {
            if (strncmp(line, "TracerPid:", 10) == 0 && atoi(line + 10) != 0) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "traced");
                fclose(f);
                exit(1);
            }
        }
        fclose(f);
    }
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "traceme failed");
        exit(1);
    }
}

/* ---- the mixing function: part of the key, computed in native code ------ */
static jint mix_impl(jint seed, jint rounds) {
    unsigned int x = (unsigned int) seed;
    for (int i = 0; i < rounds; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x += 0x9E3779B9u;
    }
    return (jint) x;
}

static jint JNICALL native_mix(JNIEnv *env, jclass c, jint seed, jint rounds) {
    (void) env; (void) c;
    return mix_impl(seed, rounds);
}

/* Registered dynamically, so there is no Java_com_obflab_vault_Vault_mix
 * symbol in .dynsym for anyone to grep for. */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;

    jclass cls = (*env)->FindClass(env, "com/obflab/vault/Vault");
    if (cls == NULL) return JNI_ERR;

    static const JNINativeMethod m[] = {
        { "mix", "(II)I", (void *) native_mix }
    };
    if ((*env)->RegisterNatives(env, cls, m, 1) != JNI_OK) return JNI_ERR;

    (*env)->DeleteLocalRef(env, cls);
    return JNI_VERSION_1_6;
}
```

### Part 3 — generate the vault blob

Choose a passphrase, compute the key exactly as the app does, and encrypt the flag.

```python
#!/usr/bin/env python3
# host — make-vault.py. Run from a scratch directory.
import hashlib, os, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PASS = "the-order-is-the-lesson"
SALT = "obflab-vault-2024"
FLAG = b"OBFLAB{strings_before_control_flow}"

def derive(pw, salt):
    acc = (len(salt) * 131) & 0xFFFFFFFF
    for i, ch in enumerate(pw):
        c = ord(ch)
        if (c & 1) == 0:
            acc = (acc * 31 + c) & 0xFFFFFFFF
        else:
            acc = acc ^ ((c << (i % 8)) & 0xFFFFFFFF)
        if acc & 0x80000000:                 # Java int is signed
            acc = (~acc) & 0xFFFFFFFF
    return (acc + ord(salt[0])) & 0xFFFFFFFF

def mix(seed, rounds):
    x = seed & 0xFFFFFFFF
    for _ in range(rounds):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        x = (x + 0x9E3779B9) & 0xFFFFFFFF
    return x

seed = derive(PASS, SALT)
mixed = mix(seed, 17)

h = hashlib.sha256()
h.update(PASS.encode()); h.update(SALT.encode())
h.update(struct.pack(">I", mixed))
key = h.digest()[:16]

iv = os.urandom(16)
pad = 16 - (len(FLAG) % 16)
pt = FLAG + bytes([pad]) * pad
enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
open("vault.bin", "wb").write(iv + enc.update(pt) + enc.finalize())
print(f"seed={seed:#x} mixed={mixed:#x} -> vault.bin")
```

> **⚠️ Warning**
> Run this from a scratch directory, outside the repository. It writes `vault.bin` and nothing else.

### Part 4 — assemble

1. Build the payload app with R8 enabled (`minifyEnabled true`), with `vault.bin` and the native
   library included.
2. Extract its `classes.dex`.
3. Pack it with `pack.py` from [lab 04](lab-04-unpack.md).
4. Build the stub, with `payload.dat` in `assets/` and `vault.bin` carried through.
5. Sign, install, verify it says `Locked.` for a wrong passphrase and shows the flag for the right one.
6. **Delete your build notes**, or hand the APK to someone else. Knowing the passphrase spoils it.

---

## Your first three attempts (all of which will fail)

Do them. Failing deliberately, in order, is the fastest way to internalise why the order exists.

### Attempt 1 — open it in jadx and read the code

```bash
# host
jadx -d v_jadx --no-res vault.apk
find v_jadx/sources -name '*.java' | wc -l
```

**Q1.** How many classes? Do any of them mention a vault, a passphrase, or a cipher? What are you
actually looking at, and which single command would have told you that before you opened `jadx`?

### Attempt 2 — attach Frida and hook something

```bash
# host
frida -U -n com.obflab.vault -l ../scripts/frida-string-decryptor.js
```

**Q2.** What happens? Now try `frida -U -f com.obflab.vault -l ... --pause`. What happens *then*, and at
which point does the process die?

**Q3.** Explain the death mechanically. Which section of the chapter predicted it, and what are the two
things you can hook instead?

### Attempt 3 — grep for the flag

```bash
# host
strings vault.apk | grep -i obflab
unzip -p vault.apk classes.dex | strings -n 6 | grep -iE 'vault|pass|key|aes'
```

**Q4.** Nothing. Name the three independent reasons the flag is not greppable, and rank them by which
one you must defeat first.

---

## The methodology, in order

### Phase 0 — acquire and verify

**Q5.** Record the hash and the signer. Why does this belong in the report even for a CTF?

### Phase 1 — triage

```bash
# host
../scripts/apk-obfuscation-triage.sh vault.apk --deep
```

**Q6.** Fill in the six-row table. For each row, name the **phase** that will address it.

**Q7.** The triage flags a large high-entropy asset *and* a second one. What are they, and why is
noticing that there are **two** important?

### Phase 2 — static or dynamic

**Q8.** The app has anti-debug. Work through the Phase 2 decision tree
([§6.1](../README.md#phase-2--decide-static-or-dynamic)) out loud and state your decision with the
reason.

### Phase 3 — unpack

```bash
# host
frida -U -f com.obflab.vault -l ../scripts/frida-classloader-dump.js --pause
```

Remember what attempt 2 taught you before you `%resume`.

**Q9.** Which configuration change did you need? Was it sufficient on its own?

**Q10.** State Phase 3's success criterion and confirm you met it. Which manifest-named component did
you look for?

**Q11.** You now have the payload DEX. Re-run triage against *it*. Which rows changed, and what does
that tell you about triaging a packed app before unpacking it?

### Phase 4 — recover strings FIRST

```bash
# host
frida -U -f com.obflab.vault -l ../scripts/frida-string-decryptor.js --pause
```

```
sd.candidates()
sd.loaders()
sd.useLoader(<n>)
```

**Q12.** `Java.use("com.obflab.vault.Vault")` fails at first. Why, and what fixes it? What does this
tell you about instrumenting *any* unpacked app?

**Q13.** How many decryptors did `candidates()` rank? Exhaust them all — write the loop. How many
strings did you recover in total?

**Q14.** Triage the dump. Which recovered string tells you the salt? Which tells you the cipher
configuration? Which tells you the asset filename? Which tells you the flag's prefix, and why did the
developer have to include that one?

**Q15.** Annotate the Smali:

```bash
# host
apktool d -f -o v_out unpacked.dex 2>/dev/null || baksmali d unpacked.dex -o v_out
python3 ../scripts/annotate-smali-strings.py --smali v_out --json strings-dump.json --write --triage
grep -rn '\[str\]' v_out/ | head -30
```

Which method is obviously the crypto now? How long did that take, and how long would it have taken
without Phase 4?

### Phase 5 — recover control flow

**Only now**, and only for the method the strings flagged.

**Q16.** Which method is flattened? How did the strings tell you it was the one that mattered — and
name a flattened method in this app that you should **not** spend time on.

**Q17.** Build the state-transition table for `KeySchedule.derive`. Reconstruct the original. What does
it return for `derive("test", "obflab-vault-2024")`?

**Q18.** Verify with Frida rather than trusting your reconstruction. Which is faster here, and under
what circumstance would the reconstruction have been worth the extra time anyway?

### Phase 5b — the native component

**Q19.** `readelf --dyn-syms` on the library shows no `Java_*` symbols. How do you find the
implementation of `mix` anyway? Name two routes.

**Q20.** Reconstruct `mix` from Ghidra. Which well-known algorithm family is it, and what gave it away?
What is the constant `0x9E3779B9` and why does recognising it save you time?

**Q21.** You do not actually need to reconstruct it. Explain why, and produce the flag using that
shortcut instead.

### Phase 6 — semantic renaming

**Q22.** Rename at least eight things. List each rename and the evidence category it came from
(recovered string, manifest, framework API, JNI signature, structure).

### Phase 7 — the model

**Q23.** Write it. What does the app do, which classes implement it, where are the trust boundaries,
and what have you not looked at?

**Q24.** Recover the flag. State the passphrase and the flag.

---

## Hints

<details>
<summary>Hint 1 — you are not stuck, you are out of order</summary>

If you are reading flattened Smali and have not recovered strings, stop. If you are recovering strings
and have not unpacked, stop — you are recovering the stub's strings, and the stub has none worth
having.

The phases are ordered because each one makes the next cheaper. Working out of order is not slower by a
constant factor; it is slower by a factor that grows with the size of the target.
</details>

<details>
<summary>Hint 2 — the ClassLoader after unpacking</summary>

`Java.use` resolves against `Java.classFactory.loader`, which after unpacking is **not** the loader
holding the real classes. `sd.loaders()` lists them; `sd.useLoader(n)` switches. Everything else works
normally afterwards.

This is not specific to this lab. It is true of every unpacked app, and it is the second most common
"Frida cannot see my class" cause after attaching too late.
</details>

<details>
<summary>Hint 3 — you do not need to understand `mix`</summary>

Re-read [§3.3.2's Pentester's Note](../README.md#332-control-flow-flattening--the-important-one). The
question is not "how do I reverse this?" but "**do I need to?**"

You need one number: what `mix` returns for the seed the app computes. That is a boundary question, and
boundary questions are answered by hooks in thirty seconds regardless of what is inside.
</details>

<details>
<summary>Hint 4 — the passphrase</summary>

You are not meant to guess it, and you cannot derive it from the key — that is the wrong direction
through a hash. Look at where it comes from. It is not in the crypto path at all.

Consider: the app must be *able* to be opened by someone. Where would that someone learn the
passphrase? Check every resource, every asset, every string you recovered, and the manifest. Then check
what the string decryptor returns for indices your annotation pass left unused — `exhaust` recovers
strings from code paths that never run, and this is exactly the case it exists for.
</details>

---

## Solutions

Do not read until you have made a genuine attempt at each phase.

<details>
<summary>Solution — Phases 0 to 3: getting to the real code</summary>

**Q1.** Thirty-one classes, none of them an application. You are looking at the packer stub. The single
command that would have told you first:

```bash
unzip -l vault.apk | grep -E 'classes.*\.dex'
```

A `classes.dex` measured in tens of KB against a multi-megabyte APK is the whole answer, in two
seconds, before any tool is opened. That is Phase 1, and skipping it is the most expensive minute you
can save.

**Q2.** Attaching: the app has already started, so you see nothing of `attachBaseContext` and the
decryptor has already run. Spawning with `--pause`: the process dies during `%resume`, before any Java
hook fires.

**Q3.** `System.loadLibrary("vaultcore")` runs inside `attachBaseContext`. The dynamic linker maps the
library and, **before `dlopen` returns**, executes every function pointer in `.init_array`. The
`__attribute__((constructor))` guard reads `/proc/self/status`, sees a non-zero `TracerPid` (Frida's
spawn mode traces the process), and calls `exit(1)`.

Predicted by [§3.7.1's Under the Hood note](../README.md#371-how-a-packer-works-mechanically) and by
§2's runtime diagram, both of which say plainly that `.init_array` runs before `JNI_OnLoad`.

What to hook instead: (1) `android_dlopen_ext`, so you are present *before* the library is mapped and
can install your `fopen`/`ptrace` hooks in `onEnter`; (2) Frida's spawn gating itself, which has you
attached before the process's first instruction — which is what `--pause` gives you, provided your
hooks are installed before you resume.

**Q4.** Three independent reasons, and the ranking is the lesson:

1. **The flag is not in the DEX you are grepping** — the real code is packed. *Defeat first.*
2. **The flag is not a string at all** — it is AES ciphertext in `vault.bin`, derived from a passphrase.
3. **The strings that would lead you to it are encrypted**, per class, with position-dependent keys.

You must defeat them in that order, and the order is not a preference: recovering strings from a stub
gives you the stub's strings, and reasoning about the ciphertext without the salt and the algorithm
name gives you nothing.

**Q5.** Because a finding that cannot be reproduced against a known artefact is not a finding. Six
months later, when someone disputes your result, the SHA-256 is what establishes that you and they are
discussing the same file. Practise it in the CTF and it will be automatic in the engagement.

**Q6.**

| Question | Answer | Phase that addresses it |
|---|---|---|
| Packed? | Yes — tiny DEX, foreign `<application>`, high-entropy asset | Phase 3 |
| Names obfuscated? | Yes (of the stub; unknown for the payload) | Phase 6 |
| Strings encrypted? | Unknown — you are measuring the stub | Phase 4, *after* Phase 3 |
| Native code? | Yes — one `.so`, `JNI_OnLoad`, populated `.init_array`, no `Java_*` | Phase 5b |
| Anti-analysis? | Yes — `ptrace`, `TracerPid` strings | Phase 2 decision |
| Tools work? | `apktool` and `jadx` succeed, on the stub | — |

**Q7.** Two high-entropy assets: `payload.dat` (the packed DEX, several hundred KB) and `vault.bin`
(the encrypted flag, a few dozen bytes plus IV).

Noticing there are two matters because they have completely different roles, and conflating them sends
you down a blind alley. `payload.dat` is defeated by unpacking; `vault.bin` is not defeated by
unpacking at all and must be *decrypted with a key you derive*. An analyst who assumes one blob will
spend time trying to unpack the flag.

**Q8.** The tree: do you have a device? Yes. Does it detect and refuse to run? Yes, under
instrumentation. Can you bypass in reasonable time? Yes — the anti-debug is two known checks
(`TracerPid` and `PTRACE_TRACEME`) and both have standard counters. Therefore: **dynamic**.

The reason to insist on dynamic even though static unpacking is possible here: every protection in this
chapter is stronger against static analysis than dynamic, because every protection must be undone at
runtime by the program itself. The per-class decryptors in particular are a static nightmare and a
dynamic non-event.

**Q9.** `cld.cfg.neutralisePtrace = true` before `%resume`. **Not sufficient on its own** — that
handles `PTRACE_TRACEME` but not the `/proc/self/status` read. You also need:

```javascript
// in the REPL, BEFORE %resume
var f = Module.findExportByName("libc.so", "fopen");
Interceptor.attach(f, {
    onEnter: function (a) {
        this.deny = false;
        try { this.deny = a[0].readUtf8String() === "/proc/self/status"; } catch (e) { }
    },
    onLeave: function (r) { if (this.deny) r.replace(ptr(0)); }
});
```

Note that this is a *native* hook for a *native* check. No Java hook could ever see it — the same
structural fact as
[37-RootDetection §3.12](../../37-RootDetection/README.md#312-native-stat--access-checks-that-bypass-java-hooks).

**Q10.** Criterion: `jadx` opens the dumped DEX and shows classes matching the manifest's component
names. Look for `com.obflab.vault.VaultActivity`, which the manifest names as the launcher activity. If
it is there, you have the payload; if you only see `com.obflab.stub.*`, you dumped the stub again.

**Q11.** Re-triaging the payload changes the "strings encrypted" row from *unknown* to *yes*, and the
"names obfuscated" row now describes the real app rather than the stub.

The lesson: **triage of a packed app describes the packer, not the application.** Phase 1 tells you it
is packed and then stops being informative; you must re-run it after Phase 3. Reporting "the app uses
no string encryption" on the basis of a stub scan is a real mistake with a real consequence.
</details>

<details>
<summary>Solution — Phase 4: strings, and why they unlock everything</summary>

**Q12.** `Java.use` resolves against `Java.classFactory.loader`, which is the *original* loader — the
one the stub's `attachBaseContext` replaced. The real classes live in the `InMemoryDexClassLoader` the
packer created.

```
sd.loaders()
sd.useLoader(1)          // whichever index is the InMemoryDexClassLoader
sd.candidates()
```

This is true of **every** unpacked app, not just this one. After the ClassLoader swap, anything that
resolves classes by the default factory sees the stub's world. It is the second most common "Frida
cannot see my class" cause after attaching too late, and unlike that one it produces a
`ClassNotFoundException` rather than silence, which at least tells you something is wrong.

**Q13.** Several — one per class with strings, typically four to eight in this build. Exhaust them all:

```javascript
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf("com.obflab.vault") !== 0) return;
            var C;
            try { C = Java.use(name); } catch (e) { return; }
            var ms;
            try { ms = C.class.getDeclaredMethods(); } catch (e) { return; }
            for (var i = 0; i < ms.length; i++) {
                var sig = ms[i].toString();
                if (sig.indexOf("java.lang.String ") === -1) continue;
                if (sig.indexOf("(int)") === -1) continue;
                sd.exhaust(name, ms[i].getName(), 0, 128);
            }
        },
        onComplete: function () { sd.stats(); sd.save(); }
    });
});
```

Note again what this does not need: the number of decryptors, their keys, or their algorithms. Per-class
decryption defeats static recovery and costs dynamic recovery nothing.

**Q14.**

| Recovered string | Role |
|---|---|
| `obflab-vault-2024` | the salt, fed to both `derive` and the SHA-256 |
| `AES/CBC/PKCS5Padding`, `AES`, `SHA-256` | the cipher configuration — you now know the whole scheme |
| `vault.bin` | the asset holding IV + ciphertext |
| `javax.crypto.Cipher`, `getInstance`, `init`, `doFinal` | the reflection targets — §3.4's "transparent to dynamic analysis" in practice |
| `OBFLAB{` | the plaintext prefix |

The developer had to include `OBFLAB{` because the code checks it: with no plaintext check, a wrong
passphrase produces mojibake rather than a clean `Locked.`, and the app would look broken rather than
locked. That necessity is a general one — **any code that must recognise correct output must contain a
description of correct output**, and that description is a gift to you. It is the same reason a packer
must keep the real `Application` name.

**Q15.** After annotation, one grep lands you in `Vault.open`:

```bash
grep -rn '\[str\].*AES/CBC' v_out/
```

Seconds. Without Phase 4: you would be reading reflection through `Class.forName` on decrypted strings,
with no idea which class is which, across a renamed payload — realistically an hour or more of reading,
and easy to give up on. That ratio is the entire justification for Phase 4's position in the ordering,
and this lab is built so you feel it rather than being told it.
</details>

<details>
<summary>Solution — Phase 5: control flow and native, and the shortcut</summary>

**Q16.** `KeySchedule.derive` is flattened. The strings told you it mattered indirectly but decisively:
the annotated Smali showed `Vault.open` as the crypto method, and `derive` is the only non-framework
call in its key-construction path.

The one **not** to spend time on: any other flattened method in the payload — the UI helper, the string
table initialiser, whatever else the flattener touched. They are equally unreadable and completely
irrelevant, and without Phase 4 you would have had no way to tell them apart. That is the whole reason
Phase 5 comes after Phase 4 rather than before it.

**Q17.** Transition table:

| State | Does | Next |
|---|---|---|
| `0x3D71A2` (entry) | `acc = salt.length()*131; i = 0` | `0x08C4F5` |
| `0x08C4F5` | test `i < pass.length()` | `0x5A20BE` if yes, `0x71E9C3` if no |
| `0x5A20BE` | `c = pass.charAt(i)`, test `(c & 1) == 0` | `0x2F8D41` if even, `0x66B017` if odd |
| `0x2F8D41` | `acc = acc*31 + c` | `0x1948DA` |
| `0x66B017` | `acc = acc ^ (c << (i % 8))` | `0x1948DA` |
| `0x1948DA` | test `acc < 0` | `0x4C3E82` if yes, `0x7B5F09` if no |
| `0x4C3E82` | `acc = ~acc` | `0x7B5F09` |
| `0x7B5F09` | `i++` | `0x08C4F5` |
| `0x71E9C3` | `return acc + salt.charAt(0)` | — |

Sorted by reachability, that is a `for` loop with an `if`/`else` body and a sign correction — exactly
the commented original. Compute the value for your test input by hand, then check it.

**Q18.** The Frida check is faster:

```javascript
Java.perform(function () {
    var K = Java.use("com.obflab.vault.KeySchedule");
    console.log(K.derive("test", "obflab-vault-2024"));
});
```

Thirty seconds against ten minutes of tabling.

When the reconstruction is worth it anyway: when you need to **reimplement** rather than **predict** —
here, if you wanted to compute the key offline for many candidate passphrases, or to explain the
derivation in a report, or to demonstrate that the scheme is weak. Prediction needs a hook;
understanding needs the table. Ask which you need before you start.

**Q19.** Two routes to `mix` with no `Java_*` symbol:

1. **Hook `RegisterNatives`.** The JNI function table entry is at a known index, and the
   `JNINativeMethod` array passed to it contains the method name, signature, and the **function
   pointer** — everything you need, handed to you at load time.

```javascript
// Frida REPL — read the registration table as it is submitted
var lib = Process.getModuleByName("libvaultcore.so");
// or resolve RegisterNatives through the JNIEnv function table
```

2. **Read `JNI_OnLoad` in Ghidra.** The `JNINativeMethod` array is a static structure in `.data.rel.ro`
   containing pointers to the name string, the signature string, and the implementation. Follow the
   third pointer.

Route 1 is faster and version-independent; route 2 works with no device. `RegisterNatives` costs an
attacker minutes, not hours — but it removes the single easiest anchor and costs the developer nothing,
which is a fair trade for them to make.

**Q20.** It is an **xorshift** PRNG step — the `x ^= x << 13; x ^= x >> 17; x ^= x << 5` triple is the
canonical xorshift32 sequence and is recognisable on sight once you have seen it once.

`0x9E3779B9` is the 32-bit golden-ratio constant (2^32 / φ), used as an additive step in TEA, XXTEA,
Threefish, and countless hash mixers. Recognising it saves you time because it tells you immediately
that you are looking at a **mixing function, not a cipher** — there is no key, no secret, and nothing to
attack. It is obfuscation-by-arithmetic, and the correct response is to stop reading and call it.

Constants like this are worth memorising: `0x9E3779B9`, `0x67452301` (MD5/SHA-1 init), `0x6A09E667`
(SHA-256 init), `0x5F3759DF` (fast inverse square root). Each one is a free identification.

**Q21.** You do not need to reconstruct it because you only need one number. Hook the boundary:

```javascript
// Frida REPL — after unpacking, with the right ClassLoader selected
Java.perform(function () {
    var V = Java.use("com.obflab.vault.Vault");
    V.mix.implementation = function (seed, rounds) {
        var r = this.mix(seed, rounds);
        console.log("mix(" + seed + ", " + rounds + ") = " + r);
        return r;
    };
    var K = Java.use("com.obflab.vault.KeySchedule");
    K.derive.implementation = function (p, s) {
        var r = this.derive(p, s);
        console.log("derive(" + p + ", " + s + ") = " + r);
        return r;
    };
});
```

Type any passphrase in the app and both numbers appear. Feed the right passphrase and the app decrypts
the flag itself — which is the whole "let the program do the work, then steal the result" principle,
applied one last time.
</details>

<details>
<summary>Solution — Phases 6 and 7, and the flag</summary>

**Q22.** Representative renames and their evidence categories:

| Renamed to | Evidence | Category |
|---|---|---|
| `Vault.open` | contains `AES/CBC/PKCS5Padding` and `vault.bin` | recovered string |
| `VaultActivity` | named in `AndroidManifest.xml` as the launcher | manifest |
| `KeySchedule.derive` | only non-framework call in the key path | structure |
| `S1.decryptString` | returns `String`, called from everywhere | structure + behaviour |
| `Vault.mix` | `JNINativeMethod` name `"mix"`, signature `"(II)I"` | JNI registration table |
| `readAsset` | calls `Context.getAssets().open` | framework API |
| `SALT`, `CIPHER_SPEC`, `ASSET_NAME` fields | the strings they hold | recovered string |
| `StubApplication` | `<application android:name>` | manifest |

The point of tabulating by category: **strings are the largest source of evidence but not the only
one.** The survivors table is a checklist of free information, and an analyst who only uses strings
leaves half of it unused. The JNI row is the one people miss most often.

**Q23.** A good model, compressed:

> The application is a single-activity vault. The shipped `classes.dex` is a packer stub
> (`com.obflab.stub.StubApplication`) which, in `attachBaseContext`, loads `libvaultcore.so`, decrypts
> `assets/payload.dat` with a fixed XOR key, hands the plaintext DEX to an `InMemoryDexClassLoader`,
> replaces `LoadedApk.mClassLoader` reflectively, and forwards the lifecycle to the real application.
>
> `libvaultcore.so` performs two jobs. In `.init_array` it checks `TracerPid` in `/proc/self/status`
> and calls `ptrace(PTRACE_TRACEME)`, terminating the process if either indicates instrumentation. In
> `JNI_OnLoad` it registers one native method, `Vault.mix(II)I`, using `RegisterNatives` so that no
> `Java_*` symbol is exported.
>
> The payload is R8-renamed with per-class string encryption (position-dependent XOR, one key per
> class). `Vault.open` derives a 16-byte AES key from the user's passphrase via a flattened schedule
> (`KeySchedule.derive`) and the native xorshift mixer, then decrypts `assets/vault.bin` — IV in the
> first 16 bytes — through reflectively resolved `javax.crypto` APIs, and validates the plaintext
> against the prefix `OBFLAB{`.
>
> **Trust boundaries:** none that hold. Every key input is present on the device, the passphrase is
> recoverable from the app's own resources, and the ciphertext ships with the app. The protections are
> cost-imposition only; total recovery effort was approximately three hours, of which roughly forty
> minutes was the anti-debug and the remainder was mechanical.
>
> **Not examined:** the resource table beyond the strings referenced by code; the second and third
> string decryptor classes were exhausted but their outputs were not individually attributed to call
> sites; no network behaviour was observed because the app makes no network calls.

That last paragraph is the one that matters most and the one people omit. Writing "what I have not
looked at" is how you discover that you never opened the resources — which, in this lab, is where the
passphrase is.

**Q24.** The passphrase is `the-order-is-the-lesson`, recovered from a string that `exhaust` returned
but that no executed code path used — a hint string the developer left in the string table (check the
indices your annotation pass reported as unused, and check `res/values/strings.xml`).

The flag:

```
OBFLAB{strings_before_control_flow}
```

Which is, of course, the entire point of the lab.
</details>

---

## Debrief questions

Answer in writing. They are the actual assessment.

1. For each of the seven layers, name the methodology phase that defeated it and roughly how long it
   took. Which layer cost the most, and was that cost proportional to its security value?
2. You did Phase 4 before Phase 5. Estimate, concretely, what doing them in the other order would have
   cost, and name the specific wasted work.
3. Which single protection, removed, would have cost you the most additional time? Is it the same one
   the developer probably thinks is strongest?
4. The `mix` function is a keyless PRNG step. What did it actually protect, and what would have been a
   better use of the same engineering effort?
5. The anti-debug ran once, in `.init_array`, and stopped mattering thereafter. Design a stronger
   version, then say honestly what it would and would not buy.
6. Write the finding, as it would appear in a client report, for the fact that the flag ciphertext, the
   key derivation, and the passphrase are all shipped inside the APK.
7. Rank the seven layers by cost-to-the-attacker per unit of cost-to-the-developer. Which two would you
   tell a client to keep, and which would you tell them to drop?
8. You have five hours and a similar target. Write your plan as a numbered list before opening
   anything. How does it differ from what you actually did here?

---

## Success criteria

- [ ] You recovered the flag without brute force and without patching the comparison
- [ ] You ran all seven phases in order and can name what each one contributed
- [ ] You identified the packing in under two minutes, from the file listing
- [ ] You diagnosed the `.init_array` anti-debug from the timeline and defeated **both** checks, at the
      native layer
- [ ] You unpacked and met Phase 3's criterion by finding a manifest-named component
- [ ] You re-triaged the payload and can explain why triaging a packed app describes the packer
- [ ] You switched `Java.classFactory.loader` and can explain why that is required for any unpacked app
- [ ] You exhausted every per-class decryptor with one loop, and can say why per-class decryption costs
      dynamic recovery nothing
- [ ] You annotated the Smali and found the crypto method by grep
- [ ] You identified the flattened method **from the strings** and can name a flattened method you
      correctly ignored
- [ ] You built the transition table for `derive` and verified it against a hook
- [ ] You located `mix` despite `RegisterNatives`, by at least one of the two routes
- [ ] You recognised `0x9E3779B9` and the xorshift shape, and used that to stop reading
- [ ] You produced the flag using a boundary hook rather than a reimplementation, and can justify it
- [ ] You renamed at least eight things, spanning at least four evidence categories
- [ ] You wrote the Phase 7 model including "what I have not looked at"
- [ ] You answered all eight debrief questions in writing

---

## Note for instructors

The pedagogical goal is **ordering**, not any individual technique. Participants have already defeated
each of the seven layers in isolation in labs 01 to 04; what they have not done is choose the sequence
under pressure.

Run it as follows. Hand out only the APK. Give no hint that it is packed. Watch how long each
participant spends in `jadx` before someone runs `unzip -l` — that interval is the single most
instructive measurement of the session, and it is usually between fifteen and forty minutes.

Bring the group back with one question: **"What are you currently reading, and how do you know it is
the app?"**

Then let them proceed, and intervene only when someone starts deflattening before recovering strings.
The intervention is again a question, not an answer: **"Which method are you deflattening, and what
told you it was the right one?"**

Debrief on question 2. Participants who did Phase 5 early will have concrete, personal numbers for what
it cost them, and a lesson someone has paid for in their own time is the only kind that survives
contact with a real engagement.

Finally, land question 6. The flag ciphertext, the key derivation and the passphrase are all inside the
APK, which means the vault was never protected by any of the seven layers — it was protected by the
reader's patience. That is the chapter's thesis as a concrete artefact, and it is worth more than the
flag.
