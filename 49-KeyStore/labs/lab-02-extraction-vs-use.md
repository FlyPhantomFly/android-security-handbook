# Lab 02 — Prove Extraction Versus Use

**Difficulty:** Intermediate
**Time:** 2 hours
**Prerequisites:** [Lab 01](lab-01-keystore-inventory.md), [Chapter 49 §1.3, §3.5.3, §7.5](../README.md),
a rooted device or emulator with `frida-server`, an enrolled biometric and a secure lock screen.

---

## Objective

Prove, empirically and in the same session, both halves of the sentence this entire chapter is built
on:

1. You **cannot extract** a hardware-backed Keystore key. No hook, no heap scan, no memory dump, no
   database copy produces the key material. This holds even with root.
2. You **can freely use** it. Code executing in the app's process commands the key at will, gets the
   plaintext, and never touches the sensor.

Then establish where the line actually falls, by finding the one key configuration for which step 2
fails — and by answering, honestly, what step 2 proved that you did not already have.

## Why this matters

This is the flagship lab of the chapter because the extraction/use distinction decides the severity of
almost every Keystore finding, and almost everyone gets it wrong in one direction or the other.

Developers get it wrong optimistically: *"the key is in secure hardware, so the data is safe."* It is
not — anything in the process can use the key.

Testers get it wrong pessimistically: *"I dumped the token with Frida, therefore the Keystore is
broken."* It is not — you had code execution in the process, which is a much stronger starting
position than the Keystore was ever designed to defend against, and you would probably have got the
token without touching the crypto at all.

> **📖 Definition — non-extractability**
> The guarantee that key material never enters the application's process. The app holds an alias and a
> handle; `getEncoded()` returns `null`; the bytes live in `keystore2` and then in secure hardware. It
> is a real, strong property and it holds against root.

> **📖 Definition — non-usability**
> A guarantee the Keystore does **not** make by default. Any code in the app's process can command any
> key the app owns, for any operation the key's authorization list permits.

> **🧠 Mental Model**
> The Keystore is a safe bolted to the floor of the app's office, with a slot in the door. You cannot
> carry the safe away — that is non-extractability, and it is genuinely useful, because it means a
> compromise of one device does not yield a transferable secret. But anyone standing in the office can
> post a document through the slot and take the result. Authentication binding is the only thing that
> puts a lock on the slot.

---

## Setup

Build two keys in a scratch app so you know the ground truth. Use
[`../examples/01-basic-aes-key.java`](../examples/01-basic-aes-key.java) for the unbound key and
[`../examples/02-auth-bound-key.java`](../examples/02-auth-bound-key.java) for the bound one, or build
the complete store from [`../examples/05-secure-token-store.kt`](../examples/05-secure-token-store.kt),
which creates both:

| Alias | Binding |
|---|---|
| `tokenstore_access_v2` | none — `setUserAuthenticationRequired` never called |
| `tokenstore_refresh_v2` | per-use, `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` |

For the third experiment you will also want a key with a *time window*. Add one:

```java
new KeyGenParameterSpec.Builder("window_key_v1",
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG
                                       | KeyProperties.AUTH_DEVICE_CREDENTIAL)
    .build();
```

Store a recognisable value under each — a fake token such as
`eyJhbGciOiJIUzI1NiJ9.LAB02-SECRET.sig` — and note where the ciphertext and IV are written.

```bash
# adb shell as root
/data/local/tmp/frida-server &
```

---

## Steps

### Step 1 — Confirm the target is genuinely hardware-backed

If the key turns out to be software-backed, everything below still runs but proves something much
weaker. Establish the baseline first.

```bash
# host
frida -U -f com.example.keystorelab -l ../scripts/enumerate-keystore.js
```

```
ks.one("tokenstore_access_v2")
ks.one("tokenstore_refresh_v2")
```

Record `securityLevel` (or `isInsideSecureHardware`) and `origin` for both.

**Question 1.** Suppose `securityLevel` reports `SECURITY_LEVEL_SOFTWARE`. Which of the two claims
this lab sets out to prove would still hold, and which would collapse? Explain in terms of where the
key material actually is.

### Step 2 — Try to extract the key. Try hard.

Work through every avenue in turn and record the result of each. The point is not to succeed; it is to
exhaust the space so that when you say "the key cannot be extracted" you have earned the sentence.

**2a. The API.**

```
ks.proveHandle("tokenstore_access_v2")
```

**2b. The heap.**

```bash
# host
frida -U -n com.example.keystorelab -l ../scripts/hook-secretkeyspec.js
```

```
sks.heap()
```

`Java.choose` walks the live heap for instances. Note what it finds — and what it does not.

**2c. The Keystore database.**

```bash
# adb shell as root
ls -la /data/misc/keystore/
sqlite3 /data/misc/keystore/persistent.sqlite ".tables"
sqlite3 /data/misc/keystore/persistent.sqlite \
    "select id, domain, namespace, alias from keyentry;"
sqlite3 /data/misc/keystore/persistent.sqlite \
    "select id, subcomponent_type, length(blob) from blobentry limit 10;"
```

**2d. A full process memory dump.**

```bash
# adb shell as root
PID=$(pidof com.example.keystorelab)
cat /proc/$PID/maps | head -40
```

Then dump the heap and search it for the key. (Any dumper works; the point is the negative result.)

**2e. The key's own class internals.**

```javascript
// Frida REPL
Java.perform(function () {
    var ks = Java.use('java.security.KeyStore').getInstance('AndroidKeyStore');
    ks.load(null);
    var k = ks.getKey('tokenstore_access_v2', null);
    console.log('class: ' + k.$className);
    var fields = k.getClass().getDeclaredFields();
    for (var i = 0; i < fields.length; i++) {
        fields[i].setAccessible(true);
        console.log('  ' + fields[i].getName() + ' = ' + fields[i].get(k));
    }
});
```

**Question 2.** Complete this table. For every row the answer should be "no", and for every row you
should be able to say *why* in one sentence.

| Attempt | Key material recovered? | Why not |
|---|---|---|
| `getEncoded()` | | |
| `Java.choose` heap scan | | |
| Reflection over the key object's fields | | |
| `persistent.sqlite` | | |
| Full process memory dump | | |
| Copying the blob to another device | | |

**Question 3.** 2e printed the object's fields and they contain an alias and a descriptor, but no
bytes. Explain what `AndroidKeyStoreSecretKey` actually *is*, and why this is the deepest reason a heap
scan cannot find the key.

### Step 3 — Now use the key you could not extract

```bash
# host
frida -U -n com.example.keystorelab -l ../scripts/hook-cipher-keystore.js
```

Get the ciphertext and IV the app stored:

```bash
# adb shell as root
cat /data/data/com.example.keystorelab/shared_prefs/tokenstore_ciphertext_v2.xml
```

Then, in the Frida REPL, with **no prompt, no user interaction, and no key material**:

```
cy.decrypt("tokenstore_access_v2", "<ivHex>", "<ctHex>")
```

**Question 4.** The plaintext appeared. State, in one precise sentence each: what you proved about
extraction, and what you proved about use. Then state what the Keystore's guarantee actually bought the
application here — because it did buy something, and a report that says otherwise is wrong.

### Step 4 — The same attack against the bound key

```
cy.decrypt("tokenstore_refresh_v2", "<ivHex>", "<ctHex>")
```

**Question 5.** This throws `UserNotAuthenticatedException`. Where exactly was that decision made —
which process, which component, on which side of the trust boundary — and why can hooking not defeat
it? Contrast that with the earlier claim that "in-process code can use every key".

**Question 6.** This is a *positive* result for the application. Write the sentence you would put in
the "controls observed" section of a report. Why does including it make your negative findings more
credible rather than less impressive?

### Step 5 — The window key: the middle case

```
cy.decrypt("window_key_v1", "<ivHex>", "<ctHex>")
```

It fails. Now unlock the device — just unlock it normally, for any reason, not in the app — and
immediately try again.

**Question 7.** It succeeds. Measure the window: retry every 5 seconds and record when it starts
failing again. Then write the one-sentence description of this key's real security property, and
describe what an attacker actually has to *do*. Compare that effort with defeating the per-use key.

### Step 6 — Attack the prompt instead

The refresh key resisted you. Its protection depends on the app using the `CryptoObject` pattern
correctly. Test whether it does.

```javascript
// Frida REPL — does the app's own logic depend on a boolean?
Java.perform(function () {
    var CB = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
    CB.onAuthenticationSucceeded.implementation = function (result) {
        console.log('[hook] onAuthenticationSucceeded called');
        console.log('       cryptoObject = ' + result.getCryptoObject());
        return this.onAuthenticationSucceeded(result);
    };
});
```

Then find where the app calls `authenticate`:

```bash
# host
frida -U -n com.example.keystorelab -l ../scripts/hook-cipher-keystore.js
```

and in the REPL:

```javascript
Java.perform(function () {
    var BP = Java.use('androidx.biometric.BiometricPrompt');
    BP.authenticate.overload(
        'androidx.biometric.BiometricPrompt$PromptInfo').implementation = function (i) {
        console.log('[!] authenticate() called WITHOUT a CryptoObject — the result is a');
        console.log('    boolean in this process, and the key knows nothing about it.');
        return this.authenticate(i);
    };
    BP.authenticate.overload(
        'androidx.biometric.BiometricPrompt$PromptInfo',
        'androidx.biometric.BiometricPrompt$CryptoObject').implementation = function (i, c) {
        console.log('[+] authenticate() called WITH a CryptoObject — binding is real.');
        return this.authenticate(i, c);
    };
});
```

**Question 8.** Which overload does the correct implementation call? Now modify the app to call the
one-argument overload and decrypt separately, rebuild, and repeat the attack from Step 4. What changes,
and what does that tell you about where the control actually lives?

**Question 9.** You have now seen two different failures of a "biometric-protected" key: one where the
key has no binding, and one where the key is bound but the app's logic is not. How do you distinguish
them from the outside, with one command each?

### Step 7 — Answer the question that decides the finding

You recovered a token in Step 3. Before you write anything down:

**Question 10.** *What did you learn that you did not already have?*

Answer it honestly for each of these three scenarios, and say which of them produces a finding worth
writing:

| Scenario | Did the crypto change the outcome? |
|---|---|
| A. The unbound key: you hooked the process and decrypted the stored token | |
| B. The key turned out to be a `SecretKeySpec` built from a constant in the APK | |
| C. The same token was also sitting in plaintext in `session.xml` | |

**Question 11.** Rank A, B and C by severity and justify the ranking in terms of what the attacker must
have before they start.

### Step 8 — The honest write-up

**Question 12.** Write the finding for scenario A as it would appear in a report: vulnerable
configuration, why developers write it, static and dynamic detection, the exploit, the fix as code, and
a severity **with its prerequisite stated**. Then add one sentence stating what the Keystore did
correctly.

---

## Hints

<details>
<summary>Hint 1 — <code>cy.decrypt</code> throws InvalidAlgorithmParameterException</summary>

You are probably passing the IV on an *encrypt* operation against a key created with
`setRandomizedEncryptionRequired(true)`, which forbids a caller-supplied IV. That is the key doing the
right thing.

For decryption the IV is required and expected. Check that you split the stored blob correctly: the
examples store `IV || ciphertext` with a 12-byte GCM nonce, so the first 24 hex characters are the IV.
</details>

<details>
<summary>Hint 2 — AEADBadTagException</summary>

Wrong IV, wrong ciphertext, wrong tag length, or you have accidentally included the IV in the
ciphertext. GCM's tag is the last 16 bytes of the ciphertext and `doFinal` expects it there — do not
strip it.

Print what you are passing before you pass it. Half the failures in this lab are hex-slicing errors,
not crypto.
</details>

<details>
<summary>Hint 3 — the heap scan finds a SecretKeySpec you did not expect</summary>

Excellent — follow it. Either the app is using a non-Keystore key somewhere you did not know about
(Finding 1 or 2), or it uses the Keystore only to *wrap* a data-encryption key which then lives in the
heap while in use (Finding 9's second shape).

The second pattern is common and worth understanding: the Keystore protects the KEK, but the DEK is a
plain `byte[]` in the process for the duration of every operation, and `Java.choose` finds it. That is
a real and reportable weakening of the design, and the fix is to use the Keystore key directly rather
than as a wrapper.
</details>

<details>
<summary>Hint 4 — the window key never seems to be authorised</summary>

`AUTH_DEVICE_CREDENTIAL` in the type mask means a PIN, pattern or password unlock counts. If you
enrolled only a biometric and the key requires `AUTH_BIOMETRIC_STRONG` only, an unlock with the PIN may
not satisfy it. Check what you actually built with `ks.one("window_key_v1")` and look at
`userAuthenticationType`.

Also confirm the device's screen actually locked and unlocked — a device that never locked never
produced a new auth token.
</details>

<details>
<summary>Hint 5 — you want to be certain the key material is not in memory anywhere</summary>

Search the dump for the key you *think* it might be. You cannot search for something you do not know,
so create a second, deliberately software key with known bytes (`KeyGenerator.getInstance("AES")` with
no provider), encrypt with it, and confirm your dumping and searching method finds *that* one.

Then apply the identical method to the Keystore key and get nothing. A negative result is only
meaningful once you have shown the method produces a positive result on a known-positive control. That
discipline is worth carrying into every "we could not find X" statement you ever write.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**1.** Claim 2 — that in-process code can use the key — holds regardless of security level; it is a
property of the API surface, not the hardware.

Claim 1 collapses. With `SECURITY_LEVEL_SOFTWARE`, the key material is protected only by the operating
system: it is stored encrypted at rest under a software-derived key, but a sufficiently privileged
attacker on that device can recover it. `getEncoded()` still returns `null` — the *framework* still
does not hand you the bytes — but the underlying guarantee is now "the OS is not compromised", not
"the bytes have never been outside secure hardware".

This is why Step 1 exists. A lab result that says "we could not extract the key" means something very
different on a TEE-backed key than on a software one.

**2.**

| Attempt | Recovered? | Why not |
|---|---|---|
| `getEncoded()` | No | `AndroidKeyStoreSecretKey` deliberately returns `null`; there is nothing behind it |
| `Java.choose` heap scan | No | There is no `SecretKeySpec` and no `byte[]` of key material to find; the object holds an alias, not bytes |
| Reflection over fields | No | Same reason. The fields are an alias string and a `KeyDescriptor`, both of which are references, not material |
| `persistent.sqlite` | No | The blobs are encrypted under a hardware-unique key that never leaves the secure hardware |
| Full memory dump | No | The material was never mapped into this process's address space at any point |
| Blob on another device | No | The other device has a different hardware-unique key, so the blob is inert. Editing the authorization list does not help either: it is bound into the authentication tag, so tampering makes decryption fail rather than loosening permissions |

**3.** `AndroidKeyStoreSecretKey` is a **handle**, not a container. It implements `SecretKey` so it can
be passed to `Cipher.init()`, but its state is an alias string and a `KeyDescriptor` identifying the
key inside `keystore2`. When you call `Cipher.doFinal()`, the framework's `CipherSpi` streams your data
over Binder to `keystore2`, which drives KeyMint, which drives the hardware.

That is the deepest reason a heap scan fails: there is no representation of the key material in this
process to find. You are not searching for something well hidden; you are searching for something that
does not exist here. Contrast `SecretKeySpec`, which is exactly a `byte[]` with a label — which is why
`Java.choose` on it is such a productive hook.

**4.** *Extraction:* the key material could not be recovered by any means available in the app's
process or on the device's filesystem, including with root. *Use:* code executing in the app's process
commanded the key and obtained the plaintext with no user interaction and no key material.

What the guarantee bought the application, and this matters: the compromise is **bounded to this device
and this moment**. The attacker cannot take the key away, cannot decrypt data captured from the network
or from a backup elsewhere, cannot decrypt this user's data on a different device, and cannot continue
to decrypt after the device is wiped or the key is deleted. A hardcoded key gives an attacker a
transferable secret that works everywhere forever; this gives them one compromised device. That is a
genuine and substantial difference, and a report that says "the Keystore provided no benefit" is
incorrect.

**5.** The decision was made **inside KeyMint**, in the secure hardware, on the far side of the Binder
boundary — not in the app process, not in the framework, and not in `keystore2`'s policy code.

The key's authorization list, which is bound into the blob's authentication tag, lacks `NO_AUTH_REQUIRED`
and carries an auth type and timeout. KeyMint therefore refuses to `begin()` an operation unless it is
presented with a valid, cryptographically signed hardware auth token from Gatekeeper or the biometric
HAL, matching that key's requirements.

Hooking cannot defeat it because there is nothing in the app's process to hook. You can rewrite every
Java method you like; the refusal happens after your data has already left the process. This is the
same reason purpose restrictions hold: you cannot hook a decrypt-only key into signing either.

The earlier claim needs the qualifier it always had: in-process code can use every key the app owns
**that the key's own authorization list permits it to use**. Auth binding is precisely the mechanism
that narrows that permission.

**6.** Something like:

> *"The refresh-token key (`tokenstore_refresh_v2`) is bound to per-use strong biometric authentication
> (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`) and could not be exercised from an
> instrumented process without a live authentication; attempts returned
> `UserNotAuthenticatedException`. The application uses the `CryptoObject` pattern correctly, so the
> authentication is bound to the specific cryptographic operation rather than to an application-level
> boolean."*

It makes the negative findings more credible because it demonstrates that you tested the controls
rather than assuming them, and that you can tell a working control from a broken one. A report
containing only failures reads as an adversarial document and invites the client to argue with every
item. A report that says "this worked, this did not, and here is exactly how I distinguished them" is
much harder to dismiss — and it tells the client which of their engineering investments actually paid
off, which is information they cannot get anywhere else.

**7.** Real security property: *"Any user authentication within the preceding 30 seconds — including
an unrelated device unlock performed for any reason — authorises unlimited use of this key by any code
in the application's process, with no prompt and no interaction."*

What the attacker has to do: **wait**. That is the entire technique. They do not defeat the biometric,
do not hook a callback, do not touch the sensor. The user unlocks their phone, as they do a hundred
times a day, and the window opens.

Compare with the per-use key, where the attacker must either obtain a genuine authentication bound to
the specific operation, or find a flaw in how the app uses `CryptoObject`. The difference between
`0` and `30` is the difference between those two attacker workloads, and it is one integer in one
builder call.

**8.** The correct implementation calls the **two-argument** overload,
`authenticate(promptInfo, cryptoObject)`.

Changing it to the one-argument overload and decrypting separately does not change the *key* at all —
`KeyInfo` still reports per-use binding. But the decryption now needs a `Cipher` that was never
authorised, so either the app fails outright, or (much more commonly) the developer also relaxes the
key's binding to make it work, and you are back to Finding 4.

The instructive middle case: if the app keeps the bound key but obtains its authorisation through a
*different* `CryptoObject` and then decrypts with an unrelated `Cipher`, it simply throws. That is why
the `CryptoObject` pattern is not merely a convention — the platform enforces it.

What this tells you: the control lives in **two places that must agree**. The key's authorization list
is enforced by hardware and cannot be hooked. The app's decision to route its authentication through
that key is ordinary application logic and can be. A key that is correctly configured but whose
authentication the app satisfies through some other path is a real and common finding.

**9.** One command each:

- **Key has no binding:** `ks.one("<alias>")` and read `isUserAuthenticationRequired`. `false` settles
  it, statically, with no attack needed.
- **Key is bound but the app's logic is not:** hook `BiometricPrompt.authenticate` and see which
  overload fires. The one-argument overload means the prompt's result is a boolean in the app's memory,
  and the key is being satisfied — or bypassed — somewhere else.

The two produce identical symptoms from the user's point of view (a prompt appears, data unlocks) and
require completely different remediation, so distinguishing them is not pedantry.

**10.**

| Scenario | Did the crypto change the outcome? |
|---|---|
| A | **Barely.** You already had code execution in the process. An attacker in that position could equally have read the token before encryption, after decryption, or out of a network buffer. The Keystore was not the weak link; the prerequisite was. |
| B | **Completely.** No device access is required at all. Download the APK — which is world-readable on every device — extract the key, decrypt data from any installation. |
| C | **Completely.** No code execution, no key, no crypto. Read a different file. |

**11.** B and C are High; A is Low to Medium and its severity is carried almost entirely by the
prerequisite.

- **B (hardcoded key)** — prerequisite: possession of the APK. That is *nothing*: no device, no root,
  no user interaction, no privilege. It works against every installation simultaneously and cannot be
  rotated without shipping a new build.
- **C (plaintext copy)** — prerequisite: read access to the app's data directory, which means a rooted
  device, a debuggable build, a backup, or physical access. Higher than B, still much lower than A, and
  it renders the entire cryptographic design irrelevant.
- **A (in-process use of an unbound key)** — prerequisite: arbitrary code execution in the application's
  process, which typically means a compromised device. An attacker who has that has many other options.

The ranking principle is the one to internalise: **severity is set by the easiest path to the data, and
the prerequisite is part of the finding, not a footnote.**

**12.**

> **Vulnerable configuration.** The key `tokenstore_access_v2` is created without
> `setUserAuthenticationRequired(true)`. Because `false` is the default, the omission is invisible in
> the builder chain. The key is consequently usable by any code executing in the application's process,
> at any time, with no user interaction.
>
> **Why developers write it.** `setUserAuthenticationRequired(true)` is not the default, and adding it
> imposes real costs: the `CryptoObject` pattern restructures the calling code, generation fails on
> devices with no secure lock screen, and `KeyPermanentlyInvalidatedException` must be handled when the
> user enrols a new biometric. Prompting on every API call is also unusable, so for a short-lived
> access token an unbound key is a defensible decision — provided it *is* a decision. The finding is
> that it was not documented as one, and that the same pattern is used for longer-lived credentials.
>
> **Detection — static.**
> `grep -rn 'setUserAuthenticationRequired' out/sources/` — note that the significant result is its
> *absence* from a builder chain, which is why the dynamic check below is more reliable.
>
> **Detection — dynamic.**
> `frida -U -f <pkg> -l scripts/hook-keygenparameterspec.js` reports options that were never called,
> together with their defaults. `scripts/enumerate-keystore.js` then confirms
> `isUserAuthenticationRequired == false` on the created key.
>
> **Exploit.** With `frida -U -n <pkg> -l scripts/hook-cipher-keystore.js` attached, and the ciphertext
> and IV read from `shared_prefs/tokenstore_ciphertext_v2.xml`,
> `cy.decrypt("tokenstore_access_v2", "<iv>", "<ct>")` returns the plaintext session token with no
> prompt and no user interaction.
>
> **Fix.**
> ```java
> new KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
>     .setBlockModes(BLOCK_MODE_GCM)
>     .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
>     .setRandomizedEncryptionRequired(true)
>     .setUserAuthenticationRequired(true)
>     .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)  // 0 = per-use
>     .setInvalidatedByBiometricEnrollment(true)
>     .setUnlockedDeviceRequired(true)
>     .build();
> ```
> and, at every use site, `prompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher))` with
> the decryption performed using the `Cipher` from `result.getCryptoObject()`.
>
> **Severity.** Low to Medium. **Prerequisite: arbitrary code execution within the application's
> process**, which in practice requires a rooted or otherwise compromised device. An attacker in that
> position has other routes to the same data, and this should be weighed accordingly. The finding is
> material because the application's own documentation describes the stored credential as
> "biometrically protected", which is not true of this key.
>
> **What the Keystore did correctly.** The key material itself could not be recovered by any means
> tested, including a full process memory dump and direct inspection of `/data/misc/keystore/`. The
> compromise is therefore bounded to the tested device: the attacker gained the ability to use the key
> on that handset, not a transferable secret usable against other installations.

</details>

---

## Success criteria

- [ ] You confirmed the target key's actual security level before drawing any conclusion from it
- [ ] You attempted extraction by at least five independent routes and recorded a "why not" for each
- [ ] You validated your memory-search method against a known-software key before relying on a negative
- [ ] You explained what `AndroidKeyStoreSecretKey` actually holds
- [ ] You decrypted a stored value using an unbound key with no user interaction
- [ ] You attempted the same against a per-use bound key and got `UserNotAuthenticatedException`
- [ ] You can say where that refusal was decided and why hooking cannot defeat it
- [ ] You measured the window on a positive-timeout key and can describe the attacker's workload
- [ ] You determined which `BiometricPrompt.authenticate` overload the app calls
- [ ] You can distinguish "key not bound" from "key bound, app logic not bound" with one command each
- [ ] You answered "what did I learn that I did not already have?" for three scenarios and ranked them
- [ ] Your write-up states the prerequisite and includes what the Keystore did correctly
