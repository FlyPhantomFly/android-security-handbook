# Lab 04 — CTF: The Vault That Lies

**Difficulty:** CTF / Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-keystore-inventory.md), [Lab 02](lab-02-extraction-vs-use.md),
[Lab 03](lab-03-attestation-analysis.md), a rooted device or emulator with `frida-server`

---

## The challenge

`com.ctf.vault` is a password manager. Its marketing copy, its privacy policy and its in-app security
screen all say the same thing:

> "Your vault is protected by a 256-bit AES key stored in your device's hardware security module. The
> key never leaves the secure element, and your master secret is protected by your fingerprint. Even we
> cannot read your data."

Exactly one clause in that paragraph is true.

**Recover the flag.** It is a string of the form `KEYSTORE{...}` held in the vault's private storage.

There are **five independent flaws**, and they chain: the first three each yield a fragment, the fourth
lets you confirm the assembly, and the fifth explains why the app's own defences never noticed. Find at
least three.

---

## Rules

- **You may use root and Frida.** Unlike the sandbox CTF, this one is about cryptographic design, and
  code execution in the process is the assumed starting position for most of it.
- **But for every flaw you find, state the prerequisite.** Which of your five findings would work
  against a *non-rooted* device? At least two of them will, and identifying which is half the exercise.
- **No brute force.** Every flaw is a design defect, not a weak parameter.
- For each flaw, you must be able to answer: **"what did I learn that I did not already have?"** A flaw
  that only works because you already had code execution in the process is a different, weaker finding
  from one that does not, and your write-up must say which is which.
- No reading the flag off the screen. The app displays it after a successful unlock; that teaches
  nothing.

---

## Building the challenge

Build it yourself — implementing the mistakes is most of the education, and you will recognise every
one of them in real apps afterwards.

Create an Android project, `applicationId com.ctf.vault`, `minSdk 23`, `targetSdk 34`, with
`androidx.biometric`.

### The flag

```kotlin
// vault: src/main/java/com/ctf/vault/Flag.kt
package com.ctf.vault

import java.security.SecureRandom

object Flag {
    /**
     * Generated once, at first run, so there is nothing to decompile out of the
     * APK. The three fragments are protected three different (broken) ways.
     */
    fun create(): Triple<String, String, String> {
        val n = SecureRandom().nextInt(0xFFFF)
        return Triple(
            "KEYSTORE{hardcoded_",
            "keys_never_reach_",
            "the_hardware_%04x}".format(n)
        )
    }
}
```

### Flaw 1 — the key that never reaches the Keystore

This is the most common real mistake in the whole subject, and it is dressed up here exactly as it
appears in production code: obfuscated, assembled at runtime, and sitting in a class called
`HardwareCrypto`.

```kotlin
// vault: src/main/java/com/ctf/vault/HardwareCrypto.kt
package com.ctf.vault

import android.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * "Hardware-backed" encryption. The class name is doing all the work.
 */
object HardwareCrypto {

    // Split and XOR'd so `strings` finds nothing and a reviewer's eye slides off.
    private val A = byteArrayOf(0x5a, 0x71, 0x2e, 0x03, 0x6c, 0x18, 0x44, 0x7f,
                                0x2b, 0x60, 0x11, 0x59, 0x3d, 0x0a, 0x77, 0x24)
    private val B = byteArrayOf(0x13, 0x4c, 0x08, 0x6e, 0x21, 0x55, 0x7a, 0x0f,
                                0x36, 0x1d, 0x62, 0x04, 0x48, 0x7b, 0x2c, 0x51)

    private fun key() = SecretKeySpec(
        ByteArray(16) { (A[it].toInt() xor B[it].toInt()).toByte() }, "AES")

    // A fixed IV, because "the ciphertext has to be stable for our sync".
    private val IV = ByteArray(16)

    fun encrypt(s: String): String {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.ENCRYPT_MODE, key(), IvParameterSpec(IV))
        return Base64.encodeToString(c.doFinal(s.toByteArray()), Base64.NO_WRAP)
    }

    fun decrypt(s: String): String {
        val c = Cipher.getInstance("AES/CBC/PKCS5Padding")
        c.init(Cipher.DECRYPT_MODE, key(), IvParameterSpec(IV))
        return String(c.doFinal(Base64.decode(s, Base64.NO_WRAP)))
    }
}
```

**Fragment 1** is stored with `HardwareCrypto.encrypt()` in `shared_prefs/vault_meta.xml`.

### Flaw 2 — the plaintext copy the migration left behind

```kotlin
// vault: src/main/java/com/ctf/vault/Migration.kt
package com.ctf.vault

import android.content.Context

/**
 * Version 4.2 moved the vault from plain preferences to Keystore-backed
 * storage. The migration wrote the new encrypted copy, verified it, and — in a
 * `finally` block someone deleted during a merge conflict — was supposed to
 * remove the old one.
 */
object Migration {
    fun migrateIfNeeded(ctx: Context, fragment2: String) {
        val legacy = ctx.getSharedPreferences("vault_legacy", Context.MODE_PRIVATE)
        val modern = ctx.getSharedPreferences("vault_secure", Context.MODE_PRIVATE)

        if (modern.getString("frag2_ct", null) == null) {
            // 1. write the properly protected copy
            val blob = KeystoreVault.encrypt(fragment2.toByteArray())
            modern.edit().putString("frag2_ct", blob).apply()

            // 2. keep the old one "until we're sure the migration worked"
            legacy.edit().putString("frag2", fragment2).apply()

            // 3. TODO: legacy.edit().clear().apply()
        }
    }
}
```

`KeystoreVault` is a genuinely correct implementation — real `AndroidKeyStore` key, AES-GCM,
KeyMint-generated IV, `setRandomizedEncryptionRequired(true)`. That is the point: **flaw 2 makes it
irrelevant.**

```kotlin
// vault: src/main/java/com/ctf/vault/KeystoreVault.kt
package com.ctf.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object KeystoreVault {
    private const val ALIAS = "vault_data_key_v4"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build())
        kg.generateKey()
        return KeyStore.getInstance("AndroidKeyStore")
            .apply { load(null) }.getKey(ALIAS, null) as SecretKey
    }

    fun encrypt(pt: ByteArray): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        val ct = c.doFinal(pt)
        return Base64.encodeToString(c.iv, Base64.NO_WRAP) + ":" +
               Base64.encodeToString(ct, Base64.NO_WRAP)
    }

    fun decrypt(blob: String): ByteArray {
        val (ivB64, ctB64) = blob.split(":")
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(),
               GCMParameterSpec(128, Base64.decode(ivB64, Base64.NO_WRAP)))
        return c.doFinal(Base64.decode(ctB64, Base64.NO_WRAP))
    }
}
```

### Flaw 3 — the decorative biometric

```kotlin
// vault: src/main/java/com/ctf/vault/BiometricGate.kt
package com.ctf.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.KeyGenerator

object BiometricGate {

    private const val ALIAS = "vault_master_key_v4"

    fun ensureKey() {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(ALIAS)) return
        val kg = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            // "300 seconds so users don't have to re-auth constantly"
            .setUserAuthenticationParameters(300,
                KeyProperties.AUTH_BIOMETRIC_STRONG or
                KeyProperties.AUTH_DEVICE_CREDENTIAL)
            // "our QA kept getting locked out when they added a fingerprint"
            .setInvalidatedByBiometricEnrollment(false)
            .build())
        kg.generateKey()
    }

    /** The prompt. Note what is NOT passed to authenticate(). */
    fun unlock(activity: FragmentActivity, onUnlocked: () -> Unit) {
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your vault")
            .setNegativeButtonText("Cancel")
            .build()

        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    r: BiometricPrompt.AuthenticationResult) {
                    unlocked = true          // <-- a boolean, in this process
                    onUnlocked()
                }
            }).authenticate(info)            // <-- no CryptoObject
    }

    @Volatile var unlocked = false
}
```

**Fragment 3** is returned by `VaultActivity.revealFragment3()`, which checks
`BiometricGate.unlocked` and then decrypts with the master key.

### Flaw 4 — GCM nonce reuse

```kotlin
// vault: src/main/java/com/ctf/vault/SyncCrypto.kt
package com.ctf.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * "The sync protocol needs a deterministic nonce so both sides agree."
 */
object SyncCrypto {
    private const val ALIAS = "vault_sync_key_v4"
    private val NONCE = ByteArray(12) { 0x42 }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // THE LINE. Without this, KeyMint refuses a caller-supplied IV.
            .setRandomizedEncryptionRequired(false)
            .build())
        kg.generateKey()
        return KeyStore.getInstance("AndroidKeyStore")
            .apply { load(null) }.getKey(ALIAS, null) as SecretKey
    }

    fun seal(pt: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key(), GCMParameterSpec(128, NONCE))
        return c.doFinal(pt)
    }
}
```

The app calls `SyncCrypto.seal()` on **two** payloads under the same key and nonce: a debug banner of
known content, and the assembled flag. Both blobs land in
`files/sync_queue/` as `banner.bin` and `payload.bin`.

### Flaw 5 — the self-check that checks itself

```kotlin
// vault: src/main/java/com/ctf/vault/Integrity.kt
package com.ctf.vault

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.cert.X509Certificate

/**
 * "We use key attestation to make sure the device isn't rooted."
 * On the device. Which is rooted.
 */
object Integrity {
    private const val ALIAS = "vault_attest_v4"
    private const val OID = "1.3.6.1.4.1.11129.2.1.17"

    fun deviceIsTrustworthy(): Boolean {
        return try {
            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val b = KeyGenParameterSpec.Builder(ALIAS,
                    KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                // A CONSTANT challenge. Replayable forever.
                .setAttestationChallenge("vault-integrity-check".toByteArray())
            try {
                kpg.initialize(b.setIsStrongBoxBacked(true).build())
                kpg.generateKeyPair()
            } catch (e: StrongBoxUnavailableException) {
                // Silent downgrade. Nothing records which we got, and the app
                // continues to tell the user "secure element".
                kpg.initialize(b.setIsStrongBoxBacked(false).build())
                kpg.generateKeyPair()
            }
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val leaf = ks.getCertificateChain(ALIAS)[0] as X509Certificate
            val ext = leaf.getExtensionValue(OID) ?: return false
            // Verified here, in this process, by code the attacker owns.
            parseAndCheckLocally(ext)
        } catch (e: Exception) {
            Log.w("vault", "attestation failed, allowing anyway", e)
            true                                   // fail-open
        }
    }

    private fun parseAndCheckLocally(ext: ByteArray): Boolean {
        // Implementation left as a stub — it does not matter what it does.
        // That is the finding.
        return true
    }
}
```

`VaultActivity` calls `Integrity.deviceIsTrustworthy()` at startup and refuses to open the vault if it
returns `false`.

### Wiring and install

```kotlin
// vault: VaultActivity.onCreate (abbreviated)
val (f1, f2, f3) = Flag.create()
prefs.edit().putString("frag1_ct", HardwareCrypto.encrypt(f1)).apply()
Migration.migrateIfNeeded(this, f2)
BiometricGate.ensureKey()
storeFragment3Encrypted(f3)
SyncCrypto.seal(BANNER.toByteArray()).writeTo("sync_queue/banner.bin")
SyncCrypto.seal((f1 + f2 + f3).toByteArray()).writeTo("sync_queue/payload.bin")
```

```bash
# host
./gradlew :vault:assembleRelease
adb install -r vault/build/outputs/apk/release/vault-release.apk
adb shell am start -n com.ctf.vault/.VaultActivity
adb logcat -c
```

Confirm the wall is standing before you start:

```bash
# adb shell as root
ls -la /data/data/com.ctf.vault/shared_prefs/
ls -la /data/data/com.ctf.vault/files/sync_queue/
```

---

## Reconnaissance

Do this before attempting anything. Every flaw is discoverable from the outside.

```bash
# host
jadx -d out vault-release.apk
grep -rn 'SecretKeySpec'                        out/sources/
grep -rn 'AndroidKeyStore'                      out/sources/
grep -rn 'setUserAuthenticationRequired'        out/sources/
grep -rn 'setUserAuthenticationParameters'      out/sources/
grep -rn 'setInvalidatedByBiometricEnrollment'  out/sources/
grep -rn 'setRandomizedEncryptionRequired'      out/sources/
grep -rn 'setAttestationChallenge'              out/sources/
grep -rn 'CryptoObject'                         out/sources/     # absence is the finding
grep -rn 'authenticate('                        out/sources/
```

```bash
# host
frida -U -f com.ctf.vault -l ../scripts/hook-keygenparameterspec.js
frida -U -f com.ctf.vault -l ../scripts/enumerate-keystore.js
frida -U -f com.ctf.vault -l ../scripts/hook-secretkeyspec.js
```

**The single most valuable line in that whole list is the first one.** Run it first, every time, on
every engagement.

---

## The five flaws

Do not read a section until you have tried it.

<details>
<summary>Flaw 1 — the "hardware" key that is a constant (fragment 1)</summary>

`HardwareCrypto` never touches the Keystore. The key is XOR'd together at runtime from two arrays
compiled into the APK, so `strings` finds nothing and the constant does not appear in any grep for
hex — but it becomes a `byte[]` at the `SecretKeySpec` constructor like every other key ever has.

```bash
# host
frida -U -f com.ctf.vault -l ../scripts/hook-secretkeyspec.js
```

The hook prints the assembled 16 bytes, the entropy, and the stack. Take the key and decrypt
`frag1_ct` from `shared_prefs/vault_meta.xml` yourself — or just watch, because
`hook-cipher-keystore.js` prints the plaintext going in.

**Prerequisite: possession of the APK.** That is *nothing*: no device, no root, no user interaction.
The XOR-obfuscated arrays are in the APK, so a static attacker recovers the key too — it takes longer,
but the result is identical and it works against **every installation**.

This is Finding 1 in §5.2, and it is the most common real mistake in this subject. The class name
`HardwareCrypto` is a nice touch and is not fictional; naming a class after the property you wish it
had is a recognisable pattern in production code.
</details>

<details>
<summary>Flaw 2 — the plaintext copy (fragment 2)</summary>

`KeystoreVault` is genuinely correct: a real Keystore key, AES-256-GCM, KeyMint-generated IV,
`setRandomizedEncryptionRequired(true)`. Attacking it directly requires code execution in the process,
and even then you only get the value the app was going to decrypt anyway.

You do not need to. The migration wrote a second copy and never deleted it.

```bash
# adb shell as root
cat /data/data/com.ctf.vault/shared_prefs/vault_legacy.xml
```

**Prerequisite: read access to the app's data directory.** A rooted device, a debuggable build, a
device backup, or physical access — meaningfully lower than "code execution in the process", and with
no cryptographic work at all.

This is Finding 3, and it is the most demoralising finding to deliver, because the team did the hard
part correctly. It is also common: it is almost always the residue of an incomplete migration, and the
deleted `finally` block in the source above is a real shape that real merge conflicts produce.

The lesson to carry: **always look for the second copy.** `grep -r` the recovered plaintext across the
whole data directory, the logs, shared storage, the backup, WebView storage and any analytics queue.
</details>

<details>
<summary>Flaw 3 — the decorative biometric (fragment 3)</summary>

Two separate defects, and you should be able to name both.

**3a. The prompt is not bound.** `authenticate(info)` is called with no `CryptoObject`, so the result
is a boolean in the app's own memory. Set it:

```javascript
// Frida REPL
Java.perform(function () {
    var G = Java.use('com.ctf.vault.BiometricGate');
    G.unlocked.value = true;
    console.log('[+] unlocked = ' + G.unlocked.value);
});
```

Or hook the callback and call it yourself. Either way the sensor is never involved.

**3b. The key's own binding is a 300-second window, and enrolment invalidation is off.** Even if the
app had used a `CryptoObject`, `setUserAuthenticationParameters(300, ...)` means any authentication —
including an unrelated device unlock — authorises five minutes of unrestricted use by any code in the
process. And `setInvalidatedByBiometricEnrollment(false)` means an attacker with the device and the PIN
can enrol their own finger and inherit the key permanently.

Confirm both from the outside:

```
ks.one("vault_master_key_v4")
```

**Prerequisite: code execution in the process** for 3a. For 3b's enrolment path: physical possession of
an unlocked device, or the PIN — **no root, no code execution.**

Findings 4, 5 and 6 in §5.2, chained.
</details>

<details>
<summary>Flaw 4 — GCM nonce reuse (confirming the assembly)</summary>

`SyncCrypto` sets `setRandomizedEncryptionRequired(false)`, which is the only thing that makes a
caller-supplied IV possible at all, and then supplies a **constant** 12-byte nonce. Two payloads are
sealed under the same key and the same nonce.

GCM is counter mode with an authenticator. Under the same key and nonce, the keystream is identical, so:

```
C1 = P1 XOR KS
C2 = P2 XOR KS
C1 XOR C2 = P1 XOR P2
```

The banner is known plaintext, so `P2 = C1 XOR C2 XOR P1` recovers the flag with **no key at all**.

```bash
# host
adb pull /data/data/com.ctf.vault/files/sync_queue/banner.bin
adb pull /data/data/com.ctf.vault/files/sync_queue/payload.bin
python3 - <<'EOF'
b = open('banner.bin','rb').read()[:-16]     # strip the GCM tag
p = open('payload.bin','rb').read()[:-16]
KNOWN = b"vault sync v4.2 debug banner"
ks = bytes(x ^ y for x, y in zip(b, KNOWN))
print(bytes(x ^ y for x, y in zip(p, ks)))
EOF
```

**Prerequisite: the two ciphertexts and knowledge of one plaintext.** No key, no root *if* the blobs
are reachable any other way — a backup, a sync endpoint, a log.

This is Finding 7, and it is worth understanding properly rather than as a rule: nonce reuse in GCM
does not weaken it, it **removes** it. Confidentiality is gone by XOR, and repeated nonces also permit
forging the authentication tag, so integrity goes too. This class of error is not hypothetical — it is
the mechanism behind published trusted-execution-environment key-recovery research.
</details>

<details>
<summary>Flaw 5 — the self-check that checks itself</summary>

`Integrity.deviceIsTrustworthy()` does four wrong things in twenty lines, and you should be able to
enumerate them:

1. **It verifies on the device.** The attestation is parsed and checked by code in the attacker's own
   process. Hook it and return `true`; or hook `getExtensionValue`; or do nothing at all, because —
2. **it fails open.** `catch (e: Exception) { return true }`.
3. **The challenge is a constant.** `"vault-integrity-check"` never changes, so even a correct server
   would accept a chain captured once from a clean device, forever.
4. **StrongBox is silently downgraded** and nothing records which level was obtained, while the app
   continues to tell the user "secure element".

```javascript
// Frida — the entire bypass
Java.perform(function () {
    Java.use('com.ctf.vault.Integrity').deviceIsTrustworthy.implementation = function () {
        return true;
    };
});
```

**Prerequisite: code execution in the process.** Which is the point: the check exists to detect exactly
that adversary, and is implemented in a place that adversary controls.

Findings 8 and 9 in §5.2. The write-up should be sympathetic and precise: the developers
understood what attestation is *for* and then spent the entire effort on the side of the wire where it
cannot work. The fix is not more client-side checking — it is moving the verifier to the server, with a
server-issued single-use challenge. See [lab 03](lab-03-attestation-analysis.md).
</details>

---

## Questions

**Question 1.** For each of the five flaws, state the prerequisite an attacker needs. Which of the five
work against a **non-rooted, non-debuggable** device?

**Question 2.** Flaw 2 defeats a genuinely correct Keystore implementation. Rank flaws 1, 2 and 3 by
severity and justify the ranking in terms of the attacker's starting position, not the sophistication
of the technique.

**Question 3.** For flaw 3a you set a boolean. Answer the chapter's recurring question: *what did you
learn that you did not already have?* Then answer it for flaw 2, and explain why the two answers are
different.

**Question 4.** The vault's marketing paragraph has five clauses. Identify the one true clause and
explain, for each of the other four, precisely which flaw makes it false.

**Question 5.** Flaw 4 recovers a plaintext with no key. Explain why that is possible in terms of what
GCM actually is, and state what else — beyond confidentiality — nonce reuse destroys.

**Question 6.** The developer of flaw 4 says: "we needed a deterministic nonce because both sides of
the sync protocol have to derive the same ciphertext." Write the two-sentence reply that both accepts
the requirement and rejects the implementation, and name the construction they should have used.

**Question 7.** Flaw 5 fails open in a `catch`. Suppose you fixed only that — fail closed instead.
Would the check then be effective? Explain.

**Question 8.** Which single change to the vault would have blunted **three** of the five flaws at
once? Which flaws survive it, and why?

**Question 9.** Write the executive summary paragraph — three sentences — for a client whose lead
engineer will open with "but the key is in the hardware Keystore, so the data is safe". You must be
correct, specific, and non-adversarial.

**Question 10.** Write the five remediations as code or configuration, not as prose advice.

---

## Hints

<details>
<summary>Hint 1 — where to start</summary>

`grep -rn 'SecretKeySpec' out/sources/`. It is the first command in the recon list for a reason, and it
finds flaw 1 in about four seconds.

Then, before anything clever: `ls -laR /data/data/com.ctf.vault/` and read every file. Flaw 2 is
sitting in plain text in a file called `vault_legacy.xml` and requires no technique whatsoever. The
temptation in a CTF is to reach for the interesting attack; the discipline is to look for the boring
one first, because that is the order a real attacker works in.
</details>

<details>
<summary>Hint 2 — the SecretKeySpec hook fires but the bytes look random</summary>

They should — the XOR of two arbitrary arrays looks like a key. That is the entropy check misleading
you, and it is a useful lesson: entropy is a hint about *how* a key was made, not about whether it is
secret.

The question that settles it is not entropy but **constancy**:

```bash
# host
adb uninstall com.ctf.vault
adb install -r vault-release.apk
# re-run the hook
```

Same bytes on a fresh install means hardcoded. Different bytes means per-install, and you would then go
looking for what it is derived from.
</details>

<details>
<summary>Hint 3 — you cannot find the second copy</summary>

Take the plaintext you already have and grep for it everywhere, rather than guessing where it might be:

```bash
# adb shell as root
grep -rl 'KEYSTORE{' /data/data/com.ctf.vault/ 2>/dev/null
grep -rl 'keys_never_reach' /data/data/com.ctf.vault/ /sdcard/ 2>/dev/null
```

And do not stop at the data directory. Check `logcat`, shared storage, the backup
(`bmgr backupnow`), WebView storage, and any analytics or crash-reporting queue. The second copy is
frequently somewhere nobody thought of as storage.
</details>

<details>
<summary>Hint 4 — flaw 4's XOR gives garbage</summary>

Three things to check. Strip the **16-byte GCM tag** from the end of both ciphertexts before XORing —
it is not keystream. Confirm your known plaintext is byte-exact, including any trailing newline. And
XOR only up to the length of the shorter ciphertext; beyond that you have no keystream.

If it still fails, confirm the two blobs really were produced under the same key and nonce:

```bash
frida -U -n com.ctf.vault -l ../scripts/hook-cipher-keystore.js
cy.summary()        # reports repeated IVs explicitly
```
</details>

<details>
<summary>Hint 5 — flaw 3: setting the boolean does nothing</summary>

`BiometricGate.unlocked` may be read once and cached, or the reveal path may re-derive from the key
rather than checking the flag. Find the actual decision point:

```javascript
Java.perform(function () {
    var V = Java.use('com.ctf.vault.VaultActivity');
    V.revealFragment3.implementation = function () {
        var r = this.revealFragment3();
        console.log('[+] revealFragment3 -> ' + r);
        return r;
    };
});
```

If the reveal genuinely uses the auth-bound key, you need flaw 3b instead: authenticate once by any
means — including a plain device unlock, since the key allows `AUTH_DEVICE_CREDENTIAL` — and then use
the key freely for 300 seconds.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.**

| Flaw | Prerequisite | Works without root? |
|---|---|---|
| 1 — hardcoded key | Possession of the APK | **Yes.** No device at all |
| 2 — plaintext copy | Read access to the data directory (root, debuggable build, backup, or physical access) | **Partly** — via a device backup or a debuggable build |
| 3a — unbound prompt | Code execution in the process | No |
| 3b — 300s window + enrolment invalidation off | Physical possession of an unlocked device, or the PIN | **Yes** |
| 4 — nonce reuse | The two ciphertexts plus one known plaintext | **Yes**, if the blobs are reachable by any route |
| 5 — local attestation check | Code execution in the process | No |

Flaws 1, 3b and 4 are the ones that do not require a compromised device, and they are therefore the
ones that matter most in a report.

**2.** **1 > 2 > 3.**

- **Flaw 1** requires nothing but the APK — no device, no root, no user, no privilege — and works
  against every installation simultaneously, forever, until a new build ships.
- **Flaw 2** requires read access to the data directory. Meaningfully harder than "download the APK",
  but still no cryptographic work and no code execution.
- **Flaw 3a** requires arbitrary code execution in the process, which is the strongest prerequisite of
  the three and one that gives the attacker many other options anyway. (3b is a different matter and
  ranks with flaw 2.)

The ranking principle: **severity is set by the attacker's starting position, not by the elegance of
the technique.** A one-line grep that works with no device outranks a clever hook that needs root.

**3.** Flaw 3a: **nothing.** You had code execution in the process. An attacker in that position could
have read the fragment after the app decrypted it, or scraped it out of the view hierarchy, or hooked
the reveal method directly. Setting a boolean was the *easiest* route, not a new capability. The
finding is real — the app presents the biometric to the user as *the* control — but its severity is
carried by the prerequisite, and the write-up must say so.

Flaw 2: **everything.** No code execution, no crypto, no key. You read a file. It works against a
backup taken from a device you never had shell on. That is a categorically different capability, and it
is why the boring finding outranks the interesting one.

**4.** The one true clause is **"the key never leaves the secure element"** — for the keys that are
genuinely in the Keystore (`vault_data_key_v4`, `vault_master_key_v4`, `vault_sync_key_v4`), the
material really is non-extractable, and lab 02 establishes that this holds even against root.

The other four:

| Clause | Made false by |
|---|---|
| "a 256-bit AES key" | Flaw 1 — the key protecting fragment 1 is 128-bit and hardcoded |
| "stored in your device's hardware security module" | Flaw 1 (never in the Keystore) and flaw 5 (StrongBox silently downgraded, with the app still claiming "secure element") |
| "your master secret is protected by your fingerprint" | Flaw 3 — the prompt has no `CryptoObject`, and the key's binding is a 300-second window that any device unlock satisfies |
| "even we cannot read your data" | Flaw 2 — a plaintext copy sits in `vault_legacy.xml` |

**5.** GCM is **counter mode plus a polynomial authenticator**. Counter mode generates a keystream from
the key and the nonce alone — the plaintext plays no part in producing it — and encrypts by XOR. So two
messages under the same key and nonce use the *identical* keystream, and XORing the two ciphertexts
cancels it entirely, leaving the XOR of the two plaintexts. Knowing one gives you the other.

Beyond confidentiality, nonce reuse also destroys **integrity**. GHASH's authentication key is derived
from the block cipher, and repeated nonces leak enough information to recover the hash subkey, which
lets an attacker forge valid authentication tags for messages the sender never produced. So an app with
this flaw has lost both properties GCM was chosen for, and the AEAD guarantee is gone rather than
weakened.

**6.** Something close to:

> "The requirement is legitimate — a sync protocol does need both sides to agree on the nonce, and
> randomising it per message would break that. But a *constant* nonce is not a deterministic nonce, it
> is a reused one, and under GCM that removes both confidentiality and integrity rather than weakening
> them. Use a deterministic construction that is unique per message instead: a monotonic counter
> carried alongside the ciphertext, or an SIV-style / nonce-misuse-resistant AEAD such as AES-GCM-SIV,
> which is designed for exactly this requirement."

**7.** No. Fail-closed removes the *laziest* bypass and nothing else. The check still runs **in the
attacker's process**, so hooking `deviceIsTrustworthy()` to return `true` still works, as does hooking
`getExtensionValue`, as does patching the APK. And the constant challenge means even a *correct* remote
verifier would accept a replayed chain from a clean device.

The defect is architectural, not a missing `else`. Client-side verification of an attestation is an
expensive `return true;` no matter how carefully the parsing is written. The only fix is to send the
chain to the server, with a server-issued single-use challenge, and verify it there — reading the
hardware-enforced list, pinning the Google root, and binding the attested key to the session
afterwards.

**8.** **Not storing the flag fragments at all — deriving them, or keeping them server-side and binding
the session to the attested key.** More practically at the code level: routing every protected value
through `KeystoreVault` with per-use auth binding, and deleting every other copy.

That blunts flaws **1, 2 and 4**, because all three ultimately depend on reading bytes the app wrote
down: flaw 1 has nothing left to hardcode a key for, flaw 2 has no legacy copy, and flaw 4 has no
second ciphertext to XOR against.

It does **not** help with flaws **3 and 5**, and the reason is the chapter's central point. Neither of
those reads anything. Flaw 3 makes the app *use* its own key and hand over the result; flaw 5 makes the
app decide, in the attacker's process, that the attacker is trustworthy. An attacker who can make
privileged code act on their behalf never needs the secret at all — which is exactly the
extraction-versus-use distinction from [lab 02](lab-02-extraction-vs-use.md).

**9.**

> "The application does use the Android Keystore correctly for three of its keys: the material for
> those is genuinely non-extractable, and we confirmed that it could not be recovered even with root.
> However, the value those keys protect is also present in plaintext in `shared_prefs/vault_legacy.xml`,
> a fourth key never reaches the Keystore at all and is recoverable from the APK alone with no device
> access, and the biometric prompt is not cryptographically bound to any key, so it can be satisfied by
> setting a boolean. The cryptographic engineering here is sound; the failures are all in what was
> stored beside it, which is both good news and the reason the current design provides much less
> protection than intended."

**10.**

```kotlin
// Flaw 1: delete HardwareCrypto entirely. Route through the Keystore.
//   (KeystoreVault above is already correct — use it.)
//   If a key must originate on a server, use secure key import so the material
//   never enters the heap:
//     KeyStore.setEntry(alias, KeyStore.WrappedKeyEntry(wrapped), protection)
```

```kotlin
// Flaw 2: the migration must delete the old copy, in a finally, and must
// verify before deleting rather than "keeping it until we're sure".
try {
    val blob = KeystoreVault.encrypt(fragment2.toByteArray())
    modern.edit().putString("frag2_ct", blob).commit()          // commit, not apply
    check(String(KeystoreVault.decrypt(blob)) == fragment2)     // verify FIRST
} finally {
    legacy.edit().clear().commit()                              // then delete, always
}
```

```kotlin
// Flaw 3: per-use binding, enrolment invalidation on, and a CryptoObject.
kg.init(KeyGenParameterSpec.Builder(ALIAS, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
    .setBlockModes(BLOCK_MODE_GCM)
    .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)  // 0 = per-use
    .setInvalidatedByBiometricEnrollment(true)
    .setUnlockedDeviceRequired(true)
    .build())

// and at the call site — decrypt with result.cryptoObject.cipher, nothing else:
prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
```

```kotlin
// Flaw 4: let KeyMint choose the nonce, and carry it with the ciphertext.
kg.init(KeyGenParameterSpec.Builder(ALIAS, PURPOSE_ENCRYPT or PURPOSE_DECRYPT)
    .setBlockModes(BLOCK_MODE_GCM)
    .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
    .setRandomizedEncryptionRequired(true)     // refuses a caller-supplied IV
    .build())

val c = Cipher.getInstance("AES/GCM/NoPadding")
c.init(Cipher.ENCRYPT_MODE, key())             // no GCMParameterSpec on encrypt
val blob = c.iv + c.doFinal(pt)                // ship the IV alongside
```

```kotlin
// Flaw 5: delete deviceIsTrustworthy() from the app. Attest with a
// SERVER-ISSUED, single-use challenge and verify SERVER-SIDE.
val challenge = api.getAttestationChallenge()          // 32 fresh random bytes
val chainPem  = KeyAttestation.attest(challenge)       // examples/03-key-attestation.java
api.submitAttestation(chainPem)                        // server runs 04-verify-attestation.py
// then sign every subsequent request with the attested key:
val sig = KeyAttestation.sign(requestBytes)
```

</details>

---

## Success criteria

- [ ] You recovered the complete flag
- [ ] You found at least **three** of the five flaws independently
- [ ] You found flaw 1 with a single grep before running anything dynamic
- [ ] You found flaw 2 by reading files, before attacking any cryptography
- [ ] You stated the prerequisite for every flaw and identified which work without root
- [ ] You ranked the flaws by the attacker's starting position rather than by technique
- [ ] You answered "what did I learn that I did not already have?" for flaws 2 and 3a, and can say why
      the answers differ
- [ ] You recovered a plaintext from flaw 4 with no key, and can explain GCM nonce reuse from first
      principles including the integrity consequence
- [ ] You identified the one true clause in the vault's marketing paragraph
- [ ] You named the single change that blunts three flaws, and explained why two survive it
- [ ] You wrote all five remediations as code
- [ ] Your write-up credits the parts the developers got right
