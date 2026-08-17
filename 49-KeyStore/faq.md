# 49 — Android Keystore · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

---

**1. What does the Keystore actually guarantee?**

One thing, precisely: **the key material never enters your application's process.** You generate a key
under an alias, and what you get back is a *handle*. `getEncoded()` on it returns `null`. When you
encrypt, your plaintext travels over Binder to the `keystore2` daemon, into the KeyMint HAL, into
secure hardware, and the ciphertext comes back. The bytes of the key are never in your address space,
so they cannot be dumped out of it.

It guarantees **non-extractability**. It does not guarantee **non-usability**, and confusing the two
is the single most consequential mistake in this area.

---

**2. So if the device is rooted, is the Keystore useless?**

No, but it protects less than people expect.

Root gives an attacker code execution inside your app's process. Code in your process can call
`Cipher.doFinal()` with your key, exactly as your own code does, and get the plaintext. So the
attacker gets **everything the key can do**.

What they do *not* get is the key itself. They cannot copy it to another device, decrypt your backups
elsewhere, or forge signatures after you have revoked the device. That is a real and meaningful
property — it means a compromise is bounded to that device and that moment, rather than yielding a
transferable secret.

State it in a report exactly that way: "an attacker with code execution in the application's process
can use the key; they cannot extract it."

---

**3. Where are the keys physically stored?**

On Android 12 and later, as encrypted blobs in `/data/misc/keystore/persistent.sqlite`, owned by UID
1017 (`keystore`). Before that, one file per key under `/data/misc/keystore/user_N/`.

The blobs are encrypted under a **hardware-unique key** that lives inside the secure hardware and
never leaves it, and the key's authorization list is bound into the authentication tag. So a stolen
blob is inert on any other device, and you cannot edit its permissions — flipping `noAuthRequired` in
the blob just makes it fail to decrypt.

The metadata, however, is not opaque, and it is worth reading:

```bash
# adb shell as root
sqlite3 /data/misc/keystore/persistent.sqlite "select id, domain, namespace, alias from keyentry;"
```

---

**4. Can another app read or use my Keystore key?**

No. Every key belongs to a namespace, and for ordinary apps the namespace is the app's UID.
`aliases()` returns only your own; another app cannot list, use, or delete your keys.

Three exceptions to check for:

- **`sharedUserId`.** Two apps with the same UID share a namespace, and therefore share keys. If one
  of them is a neglected "companion" or "updater" with an exported component, compromising it gives
  you the hardened app's Keystore namespace with no root at all. That is a genuine, non-root,
  cross-application key-use finding.
- **`grant()`.** An explicit API for handing another UID the right to use one key. Rare in third-party
  apps; when you see it, follow it, because it is a deliberate widening of the trust boundary.
- **The work profile.** A different Android user is a different UID and therefore a different
  namespace entirely.

---

**5. What is the single most common real Keystore mistake?**

A key that never goes near the Keystore at all:

```java
// The most common Keystore finding is not IN the Keystore.
byte[] k = { (byte)0x2f, (byte)0x91, /* … */ };
SecretKey key = new SecretKeySpec(k, "AES");
```

`SecretKeySpec` wraps raw bytes that exist in your heap. They came from somewhere — a constant, a
string resource, an asset, a value XOR'd together at runtime, or a native library. All of those ship
inside the APK, and the APK is world-readable on every device.

Grep for `SecretKeySpec` **before** you grep for anything else, and hook
`javax.crypto.spec.SecretKeySpec.$init` for the whole session on every engagement. That hook catches
it even when the key is assembled from obfuscated fragments or produced in native code, because
everything eventually has to become a `byte[]` at that constructor.

---

**6. And the second most common?**

A value protected by the Keystore that also exists in plaintext somewhere else.

The app carefully encrypts the session token with a hardware key and writes the ciphertext to
`shared_prefs/secure.xml` — and also caches the raw token in `shared_prefs/session.xml`, or logs it at
startup, or writes it into an analytics payload, or leaves it in a WebView cookie store, or exports it
in a "debug" file on shared storage.

The Keystore is then decorative. Whatever the crypto costs, the data is available without it.

This is why the methodology in §7.1 has a step called "map each key to *what it protects*". A Keystore
inventory that lists aliases without tracing what each one guards tells you nothing, and it will miss
this finding entirely.

---

**7. `setUserAuthenticationRequired(true)` — is that enough?**

Not by itself. The timeout decides everything.

```java
// (A) PER-USE — the strong form.
.setUserAuthenticationRequired(true)
.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)

// (B) TIME WINDOW — a 30-second free pass.
.setUserAuthenticationRequired(true)
.setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG
                                   | KeyProperties.AUTH_DEVICE_CREDENTIAL)
```

In form (A), the hardware issues an authentication token bound to one specific operation handle. The
key can only be used by a `Cipher` that was itself authorised, which means `BiometricPrompt` must
receive a `CryptoObject` wrapping that exact cipher. There is no window for unrelated code to ride
along.

In form (B), **any** authentication in the last 30 seconds — including the user simply unlocking the
device for an unrelated reason — authorises **any** use of the key by **any** code in the process,
with no prompt at all. Your hook does not have to defeat the biometric; it just has to wait for the
user to unlock their phone.

Also read the `type` argument. `AUTH_DEVICE_CREDENTIAL` alone means a shoulder-surfed PIN satisfies
it.

---

**8. The app shows a fingerprint prompt before decrypting. Is that binding?**

Only if a `CryptoObject` is involved. Look for this:

```java
biometricPrompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(cipher));
```

If you see `authenticate(promptInfo)` with **no** second argument, and the app then decrypts
something, the prompt's result is just a boolean in the app's own memory. Hook
`onAuthenticationSucceeded` and call it yourself; if the decryption then works, the biometric was
decorative.

That is a reliable, repeatable, high-value demonstration, and it settles arguments. See
[48 — Biometrics](../48-Biometrics/README.md) §7 for the full technique and
[`examples/02-auth-bound-key.java`](examples/02-auth-bound-key.java) for the correct pattern.

---

**9. My app throws `KeyPermanentlyInvalidatedException`. What happened?**

The user changed something the key was bound to. Most commonly they enrolled a new fingerprint or
face, which invalidates auth-bound keys because `setInvalidatedByBiometricEnrollment` defaults to
`true`. It also happens when the lock screen is removed entirely, or after a factory reset.

The key is gone. There is no recovery — you delete the alias, generate a new key, and re-establish
whatever it protected (usually by re-authenticating to the server).

The security-relevant version of this question is the inverse: an app that explicitly sets
`setInvalidatedByBiometricEnrollment(false)` has opted out of that protection. An attacker who can
reach the settings screen — someone with the unlocked device, or with the PIN — enrols their own
finger and inherits the key. That is Finding 5, and it is a real one.

---

**10. What is StrongBox and do I need it?**

StrongBox is a **discrete secure element** — separate silicon with its own CPU, RAM and secure
storage — as opposed to a TEE, which is a protected execution mode on the main application processor.
It is a higher bar: resistant to a wider range of physical and side-channel attacks, and much smaller,
so its attack surface is smaller too.

Request it with `setIsStrongBoxBacked(true)`. It throws `StrongBoxUnavailableException` on a device
that lacks it, which is where the interesting bug is:

```java
try {
    kg.init(specWithStrongBox);
} catch (StrongBoxUnavailableException e) {
    kg.init(specWithoutStrongBox);   // silent downgrade — and nobody records it
}
```

That fallback is correct engineering *if the app records which it got and tells the server*. It is a
finding when the app then claims StrongBox protection to a server, or in its marketing, or in its own
UI, without knowing which it actually has. Always read back `KeyInfo.getSecurityLevel()`.

See [50 — Hardware-Backed Security](../50-HardwareBackedSecurity/README.md).

---

**11. What does "hardware-backed" actually mean on the device in my hand?**

Ask the device, not the code:

```java
KeyInfo info = (KeyInfo) SecretKeyFactory
    .getInstance(key.getAlgorithm(), "AndroidKeyStore")
    .getKeySpec(key, KeyInfo.class);
int level = info.getSecurityLevel();     // API 31+
```

| Value | Meaning |
|---|---|
| `SECURITY_LEVEL_SOFTWARE` (0) | Protected only by the OS. Recoverable on a rooted device. **The "hardware-backed" claim is false here.** |
| `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` (1) | In the TEE. The normal result |
| `SECURITY_LEVEL_STRONGBOX` (2) | Discrete secure element |
| `SECURITY_LEVEL_UNKNOWN` (-1) | Treat as software; investigate |
| `SECURITY_LEVEL_UNKNOWN_SECURE` (-2) | Secure, level unreported. Acceptable |

Below API 31 you have `isInsideSecureHardware()`, which is a boolean floor, not a grade: `true` tells
you "not pure software" and nothing about whether the TEE is robust or minimal.

`KeyGenParameterSpec` is what you asked for. `KeyInfo` is what you got. Never audit an app from the
spec alone, and always read the level on the *target's* hardware, not on your Pixel.

---

**12. What is key attestation, in one paragraph?**

Your server wants to know that a public key's private half really is in a real device's secure
hardware, on a device that is genuinely locked and unmodified. Every client-side check of that claim
is code the attacker owns, so it proves nothing. Attestation escapes the circularity: the *hardware*
makes the statement, signs it with a factory-provisioned key that software cannot reach, and the
signature chains to a root certificate Google published. Your server verifies the chain and reads the
statement out of an X.509 extension in the leaf certificate. The device's claim about itself becomes
verifiable by someone who does not trust the device.

---

**13. Where does attestation verification usually go wrong?**

Almost always on the server, and almost always in one of four ways:

1. **Reading `softwareEnforced` instead of `hardwareEnforced`.** Every field in the authorization list
   appears twice. The software-enforced copy is asserted by the Android framework, which is on the
   attacker's side of the line. A verifier that reads `rootOfTrust` or `origin` from it — or that
   merges both lists into one dictionary — is trivially defeated. Check this first.
2. **Not checking the challenge, or accepting a constant one.** Attestation without a fresh,
   server-issued, single-use nonce is replayable, and a replayed attestation from a clean device
   proves nothing about the device in front of you.
3. **Pinning an intermediate instead of the root.** Under Remote Key Provisioning the intermediates
   are short-lived and rotate. Pinning one is a robustness bug that will page someone at 3am.
4. **Not checking `attestationApplicationId`.** Without it, a repackaged copy of the app on the same
   device produces an equally valid attestation.

And the one everyone forgets: **bind the attested key to the account and require it to sign every
subsequent request.** An app that attests at registration and then sends bearer tokens has thrown the
entire guarantee away.

See [`examples/04-verify-attestation.py`](examples/04-verify-attestation.py) and
[`labs/lab-03-attestation-analysis.md`](labs/lab-03-attestation-analysis.md).

---

**14. Can I just verify the attestation on the device?**

No. That is an expensive `return true;`.

The whole point of attestation is that it produces a statement a *third party* can verify without
trusting the device. Verifying it on the device means the attacker, who controls the device, controls
the verifier. Hook the method, return `true`, done.

If you find an app doing this, it is a finding — and a particularly instructive one, because the
developers clearly understood the mechanism and then spent all the effort in the wrong place.

---

**15. Does attestation prove the app has not been tampered with at runtime?**

No, and this is the most common overclaim.

Attestation makes a statement about the **device** and the **key** at the moment of generation:
verified boot state, bootloader lock, patch level, the key's properties, and which app packages share
the calling UID. It says nothing about whether Frida is attached right now, whether a method has been
hooked, or whether the code path that produced this request is the one the developer wrote.

An attested key on a locked, verified device can still be driven by an attacker who gets code into
the process. `verifiedBootState == Verified` and `deviceLocked == true` raise that attacker's cost
considerably — they now need a device compromise rather than just Magisk — but they do not eliminate
them.

---

**16. Why does the plaintext cross Binder? Isn't that the whole thing being defeated?**

It is a real and often-missed detail, but it is not a defeat.

When you `Cipher.doFinal(plaintext)`, the plaintext travels from your process to `keystore2` and into
the HAL. So the plaintext is visible to your process (obviously — you produced it) and to `keystore2`,
which is a more privileged, more trusted component running as UID 1017 in its own SELinux domain.

The **key** still never crosses. That is the property being protected. If you can already read the
plaintext in the app's process, you have gained nothing by watching it go over Binder.

Where it does matter: it explains why hooking `Cipher` in the app's process is so effective, and why
"we use hardware crypto" does not mean "the data is never in memory". The data is always in memory at
some point; only the key is not.

---

**17. Why is importing a key with `setEntry()` a red flag?**

Look at the argument:

```java
ks.setEntry("k", new KeyStore.SecretKeyEntry(new SecretKeySpec(rawKeyBytes, "AES")), protection);
```

`rawKeyBytes`. The plaintext key material existed in the application's heap before it went in. So:

- It came from somewhere. **Follow that.** The source is now the weakest link and it is where you
  attack — a server response, a file, a constant, a derivation from a device identifier.
- It was hookable, dumpable, and possibly written to a heap dump or swapped.
- `KeyInfo.getOrigin()` and the attestation `origin` tag will say `IMPORTED`, not `GENERATED`. That
  difference is visible to a verifying server, and a server accepting attestations should reject
  imported keys for anything claiming device-binding.

The correct pattern when a key genuinely must come from a server is **secure key import**
(`WrappedKeyEntry`, API 28+): the server wraps the key under a Keystore-generated wrapping key whose
public half was attested, and the plaintext never exists in the app's process. It is uncommon, and
finding it means you are looking at a mature team.

---

**18. Can obfuscation hide Keystore usage from me?**

Essentially not.

`"AndroidKeyStore"` is a platform string that must appear literally for `getInstance()` to work.
Framework class and method names — `KeyGenParameterSpec$Builder`, `setUserAuthenticationRequired`,
`Cipher.getInstance` — cannot be renamed, because they are not the app's symbols. Transformation
strings like `"AES/GCM/NoPadding"` must survive too.

So a manifest-and-framework-first analysis works on almost any APK, and the dynamic hooks in
[`scripts/`](scripts/) work regardless of what R8 did to the app's own names. What obfuscation *does*
hide is the app's business logic around the crypto: which alias protects what, and where the
ciphertext ends up. That is what you spend your time on.

---

**19. `getEncoded()` returns `null` and my code broke. Is that a bug?**

That is the Keystore working exactly as designed, and it is the fastest single diagnostic in this
chapter.

A genuine `AndroidKeyStore` key is a handle with no material behind it, so `getEncoded()` returns
`null`. If a key's `getEncoded()` returns actual bytes, that key is **not** in the Keystore — it is a
`SecretKeySpec` or similar, and the material is in the heap.

Use it as a one-line test on any key an app hands around:

```javascript
// Frida
console.log('getEncoded() = ' + key.getEncoded());   // null == genuinely in the Keystore
```

---

**20. The app decrypts fine, but my attempt throws `UserNotAuthenticatedException`. Did I do it
wrong?**

Probably not — you have most likely just confirmed that the key is correctly bound with per-use
authentication, and that your session has no valid auth token.

This is a **positive result for the application**, and you should report it as one. Testers who only
write up what they broke give clients no way to distinguish a control that worked from one nobody
tested. A findings section that says "the refresh-token key is bound per-use with
`AUTH_BIOMETRIC_STRONG` and could not be exercised without a live biometric authentication" makes
every other finding in the report more believable.

If you want to proceed anyway, the attack is not on the key — it is on the **prompt**. See question 8.

---

**21. What is the difference between a TEE and StrongBox, practically?**

| | TEE | StrongBox |
|---|---|---|
| Where | A protected mode on the main application processor | Separate physical chip with its own CPU, RAM, secure storage |
| Attests as | `TrustedEnvironment` (1) | `StrongBox` (2) |
| Attack surface | Larger; shares silicon and caches with the OS | Much smaller |
| Side channels | Historically vulnerable to several | Substantially better isolated |
| Availability | Essentially universal on modern devices | Pixel 3+ and some flagships; far from universal |
| Performance | Fast | Slower, and with tighter limits on key count and sizes |

Practical guidance: request StrongBox for high-value keys, catch the exception, fall back to TEE, and
**record which you got**. Never assume; read `KeyInfo.getSecurityLevel()`.

---

**22. Should an app use `EncryptedSharedPreferences` instead of doing this by hand?**

Usually yes, and finding it is a mild positive. It is Jetpack Security's wrapper: it generates a
Keystore master key and uses it to encrypt preference keys and values, so a developer does not
hand-roll AES-GCM.

Three things to still check, because the wrapper does not make the hard decisions for you:

1. **Is the master key auth-bound?** By default it is not. `EncryptedSharedPreferences` protects
   against another app or an offline attacker; it does nothing against in-process code, and nothing
   against "the user with the device" unless the master key requires authentication.
2. **Is the same value also stored in plain preferences?** (Question 6.) This happens constantly
   during migrations.
3. **What is the master key's actual security level?** Read it back.

---

**23. How do I test the auth binding properly?**

Four experiments, in order, and record all four:

1. Call the app's decrypt path with **no** prior authentication. If it works, there is no binding.
2. Authenticate once, then call it again 60 seconds later without re-authenticating. If it works,
   there is a time window rather than per-use binding — measure the window.
3. Hook `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded` and invoke it yourself
   without touching the sensor. If decryption then works, the prompt is decorative and there is no
   `CryptoObject`.
4. Lock the screen and try again in the background. This tests `setUnlockedDeviceRequired`.

Each one distinguishes a different configuration, and reporting "no auth binding" when the truth is "a
30-second window" will be corrected by the developer, expensively, in front of the client.

---

**24. What are the real vulnerability classes in the Keystore itself, as opposed to in apps?**

Three layers, and they are very different in character.

The **daemon** (`keystore2`) historically had memory-safety bugs reachable from app-controlled input
such as alias strings; the Rust rewrite in Android 12 removed that class from the parsing layer. Logic
bugs — namespace confusion, grant handling, access control — remain possible.

The **vendor HAL and trusted application** are still C and still vendor-specific. This is where the
most serious published research lands: implementation errors in a manufacturer's Keymaster/KeyMint TA
that allow key material recovery or IV reuse. The Shakevsky, Ronen and Wool paper on Samsung's
TrustZone Keymaster (USENIX Security 2022) is the canonical example and is worth reading in full.

The **TEE OS itself** is the deepest layer, and exploitation there is specialised, device-specific
work.

For app engagements: this is almost never where your finding is. Describe the class, do not go
hunting, and never invent an identifier. Pull specifics from the Android Security Bulletin for the
affected release.

---

**25. An app stores an "encrypted" blob in SharedPreferences. Is that a finding?**

Not by itself — that is the correct place for it. The question is what the blob is and what protects
it. Work through:

- What is the plaintext? A cache is not a credential.
- Which key encrypts it? Is that key in the Keystore, or is it a `SecretKeySpec`?
- What is the key's actual security level on this device?
- Is the key auth-bound, and with what timeout?
- Is the IV random per operation, or fixed?
- **Does the same value exist in plaintext anywhere else?**
- What does recovering it actually get you — and is the credential short-lived, device-bound, or
  revocable?

The finding is never "data in SharedPreferences". It is a statement about a credential's lifetime,
binding, revocability and blast radius.

---

**26. What is the one question I should ask after every successful decryption?**

**"What did I learn that I did not already have?"**

If you hooked a `Cipher` in the app's process and recovered the token, you had code execution in the
process. An attacker with code execution in the process could also have read the token before it was
ever encrypted, or after it was decrypted, or scraped it out of a network buffer. The Keystore was
never the weak link, and writing it up as a Keystore finding misattributes the problem.

The findings that survive review are the ones where the crypto genuinely changed the outcome: a
hardcoded key that works on *every* installation without any device access; a plaintext copy that
needs no code execution at all; an auth binding that turns out to be decorative; an attestation
verifier that accepts a replay.

Ask the question every time. It is the step that turns a screenshot into a finding.
