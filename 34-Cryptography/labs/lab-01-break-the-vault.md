# Lab 01 — Break the Vulnerable Vault

**Difficulty:** Beginner
**Time:** 90–120 minutes
**Prerequisites:** [Chapter 34 §3.1–3.5, §5.2 F-01/F-02/F-03](../README.md),
[10-APK-Internals](../../10-APK-Internals/README.md), `jadx` and `apktool` installed,
a rooted device or emulator

---

## Objective

Given an APK that uses the patterns from [`examples/01-vulnerable-crypto.java`](../examples/01-vulnerable-crypto.java),
recover the encryption key **without running the app**, decrypt everything the app has stored on the
device, and write the finding the way a client will read it.

You will finish with three artefacts: the key, the decrypted data, and a written finding that includes
an honest severity.

## Why this matters

This is the single most common paid engagement task in Android security. Not exotic memory corruption,
not a novel side channel — a key compiled into the APK, protecting data the app told the user was
encrypted.

It matters that you can do it **statically**, without instrumentation, for three reasons. First, some
targets detect Frida and you need a path that does not touch the running app. Second, a static
recovery proves the key is the same for **every installation**, which is what turns "the key on my
device is readable" into "one APK download compromises every user" — a different severity entirely.
Third, static analysis is what a client's own build pipeline could have caught, so it is the finding
they can most easily prevent next time.

> **Mental Model**
> Encryption moves a secret. It does not remove one. If the app can decrypt without asking anyone
> anything, then everything needed to decrypt is inside the app, and you can have it too. Your first
> question about any local encryption scheme is always: **where does the key come from, and who else
> can reach that place?**

---

## Setup

### Build the target

Build it yourself. Reading a vulnerability is not the same as having produced one, and you need a
target whose answers you know so you can tell a tool failure from a genuine negative.

**`app/src/main/java/com/vault/target/VaultActivity.java`**

```java
package com.vault.target;

import android.app.Activity;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class VaultActivity extends Activity {

    private static final String TAG = "VAULT";

    // F-01. Sixteen characters, so exactly an AES-128 key.
    private static final String MASTER_KEY = "Str0ngKey!2024AB";

    // F-03. One IV, forever.
    private static final byte[] IV = "InitialVector123".getBytes();

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        TextView tv = new TextView(this);
        setContentView(tv);

        SharedPreferences prefs = getSharedPreferences("vault", MODE_PRIVATE);

        try {
            // Three records with deliberately similar structure, so ECB's
            // pattern leakage is observable in the stored bytes.
            prefs.edit()
                 .putString("session",  encryptCbc("eyJ1aWQiOjQyLCJyb2xlIjoiYWRtaW4ifQ"))
                 .putString("card",     encryptCbc("4111111111111111|12/27|123"))
                 .putString("note",     encryptEcb("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
                 .putString("pin",      encryptCbc("4917"))
                 .apply();

            tv.setText("vault sealed");
            Log.i(TAG, "sealed 4 records");
        } catch (Exception e) {
            Log.e(TAG, "seal failed", e);
        }
    }

    static String encryptCbc(String plain) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE,
               new SecretKeySpec(MASTER_KEY.getBytes("UTF-8"), "AES"),
               new IvParameterSpec(IV));
        return Base64.encodeToString(c.doFinal(plain.getBytes("UTF-8")), Base64.NO_WRAP);
    }

    static String encryptEcb(String plain) throws Exception {
        Cipher c = Cipher.getInstance("AES");            // silent ECB
        c.init(Cipher.ENCRYPT_MODE,
               new SecretKeySpec(MASTER_KEY.getBytes("UTF-8"), "AES"));
        return Base64.encodeToString(c.doFinal(plain.getBytes("UTF-8")), Base64.NO_WRAP);
    }
}
```

Build **release**, not debug, and enable R8 so the exercise resembles a real target:

```bash
# host
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
adb shell am start -n com.vault.target/.VaultActivity
```

**`app/build.gradle`** — make sure minification is on:

```groovy
buildTypes {
    release {
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
    }
}
```

> **Warning**
> Enabling R8 is the point of this setup. Half the value of the lab is watching the key survive
> obfuscation completely intact, which is what tells you that "we obfuscate our app" is not an answer
> to "where is your key".

---

## Steps

### Step 1 — Unpack, without running anything

```bash
# host
mkdir -p work && cd work
cp ~/app-release.apk target.apk
unzip -o target.apk -d unzipped/
apktool d target.apk -o apktool-out/
jadx -d jadx-out/ target.apk
```

**Question 1.** How many `classes*.dex` files are there, and what does that tell you about how the app
was built?

### Step 2 — The one-line grep

Before any tooling, run the highest-yield grep in the chapter:

```bash
# host
grep -rEn 'Cipher\.getInstance\("[^"]+"\)' jadx-out/sources/
```

**Question 2.** Which transformations does the app use? One of them has no mode token. What does the
JCA resolve it to, and why is that a finding on its own?

Now the Smali view, which does not depend on the decompiler having succeeded:

```bash
# host
grep -rn 'Ljavax/crypto/Cipher;->getInstance' apktool-out/smali*/ | head
grep -rn 'const-string' apktool-out/smali*/ | grep -E '"AES|"RSA|/CBC/|/ECB/|/GCM/'
```

**Question 3.** The decompiled Java and the Smali agree here. Name one situation in which they would
not, and which you would trust.

### Step 3 — Find the key

```bash
# host
grep -rn "SecretKeySpec" jadx-out/sources/
grep -rEn '"[A-Za-z0-9+/=!@#$%^&*()_-]{16,}"' jadx-out/sources/ | grep -iE 'key|secret|iv|pass'
```

If the decompiler produced usable output you will see the constant directly. Now prove you could have
found it without the decompiler:

```bash
# host — the DEX string pool, no decompilation at all
strings unzipped/classes.dex | grep -E '^[A-Za-z0-9+/!@#$%^&*_-]{16}$'
```

**Question 4.** R8 renamed the class and the methods. Why is the key string untouched? What tooling
would be required to change that, and would it actually help?

### Step 4 — Confirm with the automated detector

```bash
# host
python3 ../scripts/detect-ecb.py apktool-out/
python3 ../scripts/detect-ecb.py jadx-out/sources/ --code
```

**Question 5.** Which findings did the script raise that your greps did not? Which of its hits are
false positives, and how would you tell?

### Step 5 — Pull the data

```bash
# adb shell as root
run-as com.vault.target cat shared_prefs/vault.xml
# or, if run-as is unavailable on a release build:
su -c 'cat /data/data/com.vault.target/shared_prefs/vault.xml'
```

```bash
# host
adb shell "su -c 'cat /data/data/com.vault.target/shared_prefs/vault.xml'" > vault.xml
cat vault.xml
```

**Question 6.** Look at the four Base64 values. Two of them share a visible structural property.
Which two, and what does the shared property tell you before you decrypt anything?

### Step 6 — Decrypt

Write it yourself. Do not reach for an online tool; the point is that you can produce the plaintext
under your own control, on a machine you can put in a report.

```python
#!/usr/bin/env python3
# host — decrypt.py
# Requires: pip install pycryptodome
import base64, sys
from Crypto.Cipher import AES

KEY = b"Str0ngKey!2024AB"          # recovered in Step 3
IV  = b"InitialVector123"          # recovered in Step 3

def unpad(b):
    n = b[-1]
    return b[:-n] if 1 <= n <= 16 else b

def cbc(ct):
    return unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(base64.b64decode(ct)))

def ecb(ct):
    return unpad(AES.new(KEY, AES.MODE_ECB).decrypt(base64.b64decode(ct)))

for name, value in [line.split("=", 1) for line in sys.stdin if "=" in line]:
    raw = base64.b64decode(value.strip())
    print(f"{name:10s} {len(raw):4d} bytes")
    for label, fn in (("cbc", cbc), ("ecb", ecb)):
        try:
            print(f"    {label}: {fn(value.strip())!r}")
        except Exception as e:
            print(f"    {label}: failed ({e})")
```

Extract the values from the XML and feed them in:

```bash
# host
grep -oP '(?<=name=")[^"]+(?=">)[^<]*' vault.xml   # or just read it and copy
python3 decrypt.py < values.txt
```

**Question 7.** One record decrypts under ECB and the others under CBC. If you did not have the source,
how would you have determined which was which from the ciphertext alone?

### Step 7 — Prove ECB from the data, not the code

```bash
# host
adb shell "su -c 'tar czf /sdcard/appdata.tgz /data/data/com.vault.target'"
adb pull /sdcard/appdata.tgz && tar xzf appdata.tgz
python3 ../scripts/detect-ecb.py ./data/data/com.vault.target
python3 ../scripts/detect-ecb.py --entropy ./data/data/com.vault.target
```

The `note` record was 32 identical `A` characters — two identical 16-byte plaintext blocks.

**Question 8.** What do the two ciphertext blocks look like, and why is that the strongest possible
form of this finding to put in front of a developer who disputes your reading of their code?

### Step 8 — Confirm dynamically (optional but do it)

```bash
# host
frida -U -f com.vault.target -l ../scripts/frida-jca-universal-hook.js
```

**Question 9.** Compare the key printed by the hook against the constant you recovered statically. Why
is running both worth the extra ten minutes, even when you are confident?

### Step 9 — Write the finding

Write it properly, in the shape a client report uses. Not "hardcoded key — Critical". Include:

1. **Title** naming the mechanism, not the tool.
2. **Affected component** — class and method after de-obfuscation, plus the Smali path so the developer
   can verify independently.
3. **Evidence** — the key, the ciphertext, the plaintext. Redact the middle of the card number.
4. **Impact** — what an attacker gets, and who the attacker has to be.
5. **Severity**, with your reasoning against the three questions in [§5.1](../README.md#51-how-to-think-about-severity-before-we-start).
6. **Remediation as code** — not "use a KeyStore" but the actual replacement, from
   [`examples/04-keystore-backed-vault.kt`](../examples/04-keystore-backed-vault.kt).

**Question 10.** Your finding covers three defects (F-01, F-02, F-03). Do you file one finding or
three? Argue both sides, then decide and justify.

---

## Hints

<details>
<summary>Hint 1 — jadx produced nothing useful</summary>

Some builds defeat the decompiler. Fall back in this order:

```bash
# host
jadx --show-bad-code -d jadx-out/ target.apk      # accept broken output
baksmali d unzipped/classes.dex -o smali-out/     # disassemble instead
strings unzipped/classes.dex | less               # the string pool always works
```

The string pool is the important lesson. A key that must reach `SecretKeySpec` as bytes has to exist
somewhere the runtime can read it, and in practice that is a DEX string or a `fill-array-data` block.
Neither is renamed by R8.
</details>

<details>
<summary>Hint 2 — which strings are candidate keys?</summary>

AES keys are 16, 24 or 32 bytes. Look for:

- String literals of exactly those lengths.
- Base64 literals decoding to those lengths (22–24, 32, 43–44 characters).
- Hex literals of 32, 48 or 64 characters.
- `fill-array-data` blocks with 16, 24 or 32 entries in Smali.

```bash
# host
grep -rn "fill-array-data" apktool-out/smali*/ -A20 | grep -c "0x"
```

Beware: a 32-entry array is not necessarily a key. Lookup tables, S-boxes and colour palettes have the
same shape. Confirm by following the array to its use.
</details>

<details>
<summary>Hint 3 — run-as does not work</summary>

`run-as` only works for debuggable packages. On a release build use root:

```bash
# adb shell as root
su -c 'ls -la /data/data/com.vault.target/shared_prefs/'
su -c 'cat /data/data/com.vault.target/shared_prefs/vault.xml'
```

If you have neither root nor a debuggable build, the data is genuinely out of reach — and that is
worth noting in the report, because it changes who the attacker has to be. See
[21-App-Sandbox](../../21-App-Sandbox/README.md).
</details>

<details>
<summary>Hint 4 — the CBC decryption produces garbage</summary>

Three things to check, in order:

1. Is the IV right? A wrong IV corrupts **only the first block**; if bytes 17 onward are readable, you
   have the right key and the wrong IV. That asymmetry is a useful diagnostic in itself.
2. Is the whole ciphertext there? Base64 with `NO_WRAP` has no newlines; if you copied from a terminal
   you may have lost characters.
3. Is the first 16 bytes actually the IV? In this target the IV is a constant and is **not** prepended.
   In most real apps it is. Try both.
</details>

<details>
<summary>Hint 5 — telling CBC from ECB without the source</summary>

Encrypt a known plaintext with both and compare, or reason from the data:

- ECB: two identical 16-byte plaintext blocks give identical ciphertext blocks. Look for repeats.
- CBC with a fixed IV: two records with the same first plaintext block share their first ciphertext
  block, but repeats *within* a record do not appear.
- CBC with a random prepended IV: nothing repeats anywhere, and record length is `16 + 16n`.

`detect-ecb.py` implements exactly these checks.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** One `classes.dex` for a target this small. Multiple files mean multidex — the app exceeded the
65,536-method limit of a single DEX, which is normal for anything using large libraries. It matters
because tools that take a single DEX will silently analyse only part of the app, and because the class
you want may not be in `classes.dex`. See [12-DEX-Internals](../../12-DEX-Internals/README.md).

**2.** `AES/CBC/PKCS5Padding` and `AES`. The bare `AES` resolves to `AES/ECB/PKCS5Padding` — the JCA
permits a one-token transformation and substitutes provider defaults. It is a finding on its own
because ECB encrypts every 16-byte block independently: identical plaintext blocks produce identical
ciphertext blocks (structure leaks) and blocks can be reordered or spliced between records with no
detection (integrity and authorisation break).

**3.** They disagree whenever the decompiler guesses. Common cases: heavily optimised code where jadx
emits `// decompilation failed`; Kotlin coroutine state machines; obfuscators that emit valid DEX which
does not map to legal Java; and DEX crafted to confuse parsers (see
[12-DEX-Internals lab 04](../../12-DEX-Internals/labs/lab-04-ctf-the-lying-dex.md)). Trust the Smali —
it is a direct transcription of the bytecode. Trust the VDEX over both, because that is what actually
executes.

**4.** R8 is a *renamer* and shrinker. It rewrites identifiers — class, method and field names — because
those are indirections it controls. A string constant is data the program reads at runtime; changing it
would change behaviour, so R8 leaves it alone. Making the constant unreadable requires string
encryption (DexGuard and similar commercial tools), and that does not solve the problem either: the
decryption routine ships in the same APK, so the string is recoverable by running that routine, or by
hooking whatever consumes the plaintext. Obfuscation raises cost; it does not create a secret.

**5.** The script additionally flags the constant `IvParameterSpec`, the `new byte[16]` pattern if
present, and any weak digest. Likely false positives: `MD5` used for a cache key, `Arrays.equals` on
non-secret data, and the "secret-looking name" rule firing on a resource named `api_key_placeholder`.
You tell by following each hit to its use — a rule fires on a shape, only the data flow tells you the
meaning.

**6.** The `session` and `card` records share their first 16 ciphertext bytes if their first 16
plaintext bytes match — but more reliably here, **all** CBC records were produced with the same IV, so
any two records whose plaintexts start identically will start identically in ciphertext. Before
decrypting anything you can already state: the IV is fixed (F-03), and the scheme is deterministic.
Record lengths that are all multiples of 16 also tell you it is a block mode with padding, not a stream
mode and not GCM (which would be `12 + n + 16`).

**7.** From the ciphertext alone. The `note` record decrypts to 32 identical characters, so under ECB
its two ciphertext blocks are identical — visible immediately by splitting the decoded bytes into
16-byte chunks and comparing. The CBC records show no internal repeats. If no record happened to
contain repeated blocks you could not distinguish them this way, which is worth knowing: ECB detection
from data is *conclusive when it fires* and *uninformative when it does not*.

**8.** The two blocks are byte-for-byte identical. That is impossible under CBC, CTR or GCM regardless
of key, and it does not require the developer to accept your reading of their obfuscated code, your
choice of decompiler, or your competence with Smali. It is a property of the bytes on their device. In
a disputed finding, evidence that survives disagreement about tooling is worth ten times evidence that
does not.

**9.** Three reasons. First, static analysis proves the key is *in the APK*; dynamic analysis proves it
is *the key actually used* — a decoy constant that no code path reaches is a real anti-analysis
technique. Second, the hook shows you every other cryptographic operation the app performs, which
frequently reveals a second key you did not find statically. Third, if the two disagree, that
disagreement is itself the most interesting finding in the report.

**10.** Arguments for one finding: they share a root cause (nobody reviewed the crypto), one
remediation fixes all three, and a client reading twenty findings triages worse than one reading five.
Arguments for three: they have different severities, different MASVS mappings (F-01 is
MASVS-CRYPTO-2, F-02 and F-03 are MASVS-CRYPTO-1), and a partial fix — say, moving to CBC with a random
IV while keeping the hardcoded key — would close one and leave the others, which a merged finding lets
the client mark as resolved incorrectly.

The defensible answer is **one finding for the hardcoded key** (F-01, High, with the decrypted data as
evidence) and **one for the mode and IV handling** (F-02 + F-03, Medium, same component). That maps to
the two distinct remediations — change where the key comes from, change how the cipher is used — and it
survives a partial fix.

</details>

---

## Success criteria

- [ ] You recovered the key **without running the app**
- [ ] You recovered it a second way, from the DEX string pool, with no decompiler
- [ ] You can explain why R8 did not protect it, and what would, and why that would not help either
- [ ] You decrypted all four stored records with your own script
- [ ] You proved ECB from the stored ciphertext alone, independently of the source code
- [ ] You identified the fixed IV and stated what it costs before decrypting anything
- [ ] You confirmed the key dynamically and compared it against the static result
- [ ] You wrote a finding containing evidence, impact, an argued severity and remediation as code
- [ ] You can state, in one sentence, why a hardcoded key is a global compromise and not a local one
