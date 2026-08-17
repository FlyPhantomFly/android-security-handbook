# 50 — Hardware-Backed Security — FAQ

Real questions, including the ones people are embarrassed to ask. Answers are direct; the long
version is in [README.md](README.md).

---

### 1. What is a TEE, really? Not the marketing version.

It is a second, small operating system running on the same physical CPU cores as Android, in a
different *security state* that the hardware enforces. Not a separate chip. Not a sandbox. Not a
process. The CPU has a signal called `NS` (non-secure) that it asserts on every memory access, and
a memory controller (the TZASC) that is configured at boot to refuse non-secure access to certain
physical DRAM ranges. So when Linux — even a fully compromised Linux running as root — tries to
read secure-world memory, **the memory controller refuses in hardware**. No code evaluated a
permission. There is a wire, and it says no.

The TEE runs its own tiny kernel (QSEE, Kinibi, TEEGRIS, Beanpod, Trusty) and a handful of trusted
applications: the one that holds keys (KeyMint), the one that checks your PIN (Gatekeeper), the one
that matches your fingerprint, and the one that decodes DRM video. That is roughly all it does. Its
security comes overwhelmingly from being small.

---

### 2. Is my key safe if my phone is rooted?

Depends entirely on what you mean by "safe", and this is the single most important distinction in
this area.

**The key material is safe.** Root cannot extract a TEE-backed key. There is nothing in Android's
memory to extract — the bytes only ever exist inside the secure world, and the on-disk blob is
ciphertext under a key fused into the chip.

**The key's *use* is not safe at all.** Root can inject code into the app that owns the key, and
that code can call the key exactly as the app does, getting exactly the same plaintext back. It
never learns the key and it does not need to.

So: a rooted attacker cannot steal your key and use it on their laptop, or on another phone, or
after your phone is wiped. They can use it on your phone, while your phone is running, from inside
your app. If your threat model is "my phone is stolen", hardware backing is excellent. If it is
"the user of this phone is my adversary", hardware backing does very little, and that is not a
defect — it was never the promise. See [49 §1.3](../49-KeyStore/README.md).

---

### 3. What is StrongBox and does my phone have it?

StrongBox is a KeyMint implementation running on a **physically separate chip** — its own
processor, its own memory, its own flash, its own random number generator and its own clock —
connected to the main SoC over a serial bus. Google's Titan M in Pixels is the best-known example.

Whether you have one: run

```bash
adb shell pm list features | grep strongbox
```

If nothing comes back, you almost certainly do not have it. All three devices measured for this
chapter — two physical phones from different silicon vendors and a current emulator image — lack it
and throw `StrongBoxUnavailableException` for every request.

**And that is fine.** Not having StrongBox is the normal condition of Android devices. It is not a
vulnerability in your phone and it is not a finding in a report.

---

### 4. Can a TEE be broken?

Yes. It has been, repeatedly, and pretending otherwise is how people build brittle systems.

TEEs run code, that code is written by humans, and it is often closed-source vendor code in C.
Published work has found memory corruption in trustlets reachable from ordinary Android, and
outright cryptographic mistakes *inside* the trusted application — the best-documented being IV
reuse in a Keymaster TA's key wrapping, analysed in the USENIX Security 2022 paper *"Trust Dies in
Darkness"*.

What is true is that breaking a TEE is *expensive* and *specific*. It takes serious research, it
usually applies to one vendor's implementation, and it gets patched. Compare that with reading a
file as root, which takes one command and works everywhere. The value of the TEE is not that it is
unbreakable; it is that it moves the attack from "trivial and universal" to "hard and narrow".

The honest framing for a report is: the TEE's soundness is a dependency you have taken on, exactly
like your dependency on the manufacturer's boot chain. Name it, check the attested patch level, and
do not claim more.

---

### 5. Why does my key vanish after a PIN change?

Because that is exactly what you asked for when you wrote `setUserAuthenticationRequired(true)`.

When a lock-screen credential is enrolled, Gatekeeper generates a **Secure User ID** — a random
value identifying *that enrolment*. Your key gets that SID baked into its authenticated
authorisation list. Every time the key is used, KeyMint demands an auth token carrying a matching
SID.

Change the PIN and a new enrolment happens with a **new** SID. No token will ever match the old one
again, so the key is permanently unusable and you get `KeyPermanentlyInvalidatedException`.

This is not a rough edge. If changing the credential did *not* invalidate the keys, then an attacker
who could reach the settings screen could set their own PIN and inherit everything the old PIN
protected. The design is: a credential change revokes everything that credential authorised.

What you should do about it: catch the exception, delete the alias, regenerate the key, and re-run
whatever enrolment your feature needs. What you should not do is set
`setInvalidatedByBiometricEnrollment(false)` to make the symptom go away — that is the biometric
version of the same problem, and turning it off is a real finding.

---

### 6. Is "hardware-backed" the same as "unhackable"?

No, and the gap between those two phrases is most of this chapter. "Hardware-backed" is a statement
about *where the key material is stored*. It says nothing about who can command the key, whether the
app's logic around it is sound, whether the server checks anything, or whether the data was already
in a log file before it was ever encrypted.

---

### 7. My app uses the Android Keystore. Isn't that automatically hardware-backed?

No. The Keystore is an API; whether it is backed by hardware is a property of the device. Measured
for this chapter: identical code produced TEE keys on two physical phones and **software keys on an
emulator**. Nothing in the app differed.

The only way to know is to ask at runtime:

```java
KeyInfo info = (KeyInfo) SecretKeyFactory
        .getInstance(key.getAlgorithm(), "AndroidKeyStore")
        .getKeySpec(key, KeyInfo.class);
int level = info.getSecurityLevel();       // API 31+
```

If your app has never called that, its hardware claim has never been verified on any device it has
ever run on.

---

### 8. Why is "the app doesn't use StrongBox" not a finding?

Because almost no device has StrongBox, so the app could not use it even if it wanted to. Writing it
up as a vulnerability is like reporting that the app does not require the user to own a specific
phone. Reviewers discount it, and it costs you credibility on the findings that matter.

What *is* a finding is a mismatch between claim and reality: an app that says "hardware-backed" and
never checked; a StrongBox request whose fallback lands on a software key; an authentication
requirement that was never bound to a key; a server that reads attestation fields from the
software-enforced list. Every one of those exists independently of what hardware the user owns.

---

### 9. Can I test any of this without rooting my phone?

Yes — far more than most methodology assumes. You can measure the entire *device* posture with no
root, no Frida and no installed app, using `app_process` to run real Keystore code from an ADB
shell:

```bash
./scripts/probe-security-levels.sh
```

That gives you the real security level for every algorithm, StrongBox availability, and a full
attestation chain. Two of the four labs in this chapter need nothing else.

What you cannot do without root is measure *a specific app's* keys, because that needs code
execution inside that app's process. For that you need Frida, and Frida needs root.

---

### 10. What is the difference between Keymaster and KeyMint, and does it matter?

Keymaster is the old HAL (HIDL-based, versions 0 through 4.1). KeyMint is the new one (AIDL-based,
versions 1 through 3+, with a Rust reference implementation in AOSP).

It matters mainly because of a trap: **the Android version does not tell you which one the device
uses.** Measured for this chapter, a phone running Android 13 (API 33) is backed by
`android.hardware.keymaster@4.1-service.beanpod` — a legacy HIDL Keymaster — with `keystore2`
driving it through a compatibility shim. Every KeyMint-only capability is simply absent on that
device, no matter what the API level says.

Read the running HAL:

```bash
adb shell 'ps -A -o NAME' | grep -iE 'keymaster|keymint'
```

---

### 11. What actually is the hardware auth token, in plain terms?

A small signed note that says "the user proved who they were at time T, using authenticator type X,
and the credential enrolment involved was number S". It is a fixed binary structure — challenge,
SID, authenticator id, authenticator type, timestamp — with an HMAC-SHA256 over the whole thing.

The signing key is shared between Gatekeeper, the biometric matcher and KeyMint, and it exists
**only inside the secure world**. That is the entire reason the note cannot be forged: nothing in
Android has the pen.

When your app uses an auth-bound key, KeyMint refuses the operation unless it has a note whose
signature checks out, whose SID matches the key's, and whose timestamp is recent enough (or, for
per-use binding, whose challenge names this exact operation).

---

### 12. If root can't forge the token, why do biometric bypasses work?

Because most apps never asked for a token at all.

`BiometricPrompt` will happily authenticate with no `CryptoObject`. When it does, the result is a
callback into your app — `onAuthenticationSucceeded` — and that callback is just a method in a
process the attacker controls. Hook it, call it, and the app believes the user authenticated.
Nothing cryptographic happened, so nothing cryptographic can refuse.

If the app had instead created the key with `setUserAuthenticationRequired(true)`, initialised a
`Cipher`, and passed it as `new BiometricPrompt.CryptoObject(cipher)`, then the decryption itself
would require a genuine token bound to that operation, and hooking the callback would achieve
nothing at all.

So "biometric bypass" almost always means "the biometric was never bound to a key". Test it with the
PIN-change trick in question 5 — no tooling required.

---

### 13. My server checks the attestation. Am I done?

Probably not. Attestation verifiers fail in four well-worn ways:

1. **Reading the wrong list.** Every authorisation appears in `softwareEnforced` and
   `hardwareEnforced`. Only the second is a hardware claim. A verifier that merges them into one
   dictionary will read `rootOfTrust` from a value the attacker supplied. Measured on the emulator:
   the hardware-enforced list is completely empty and everything moves into the software one — and
   the chain still verifies perfectly.
2. **Pinning an intermediate.** Under Remote Key Provisioning the intermediates are short-lived.
   A verifier pinned to one breaks, and the fix teams reach for is "stop checking".
3. **A challenge that is not fresh.** If it is constant, one captured chain is valid forever. If it
   is client-chosen, it is not a challenge.
4. **Attesting once and then not using the key.** Attestation proves a key is in hardware. If every
   subsequent request is authenticated by a bearer token instead of a signature from that key, the
   guarantee was thrown away at step one.

---

### 14. What does `SID: 0` mean in `dumpsys lock_settings`?

That no lock-screen credential is set on the device. Gatekeeper holds no password handle, so there
is no Secure User ID, so **no auth-bound key can be created at all** — attempts fail with an
`IllegalStateException` mentioning Gatekeeper, which reads like a missing service and is not.

Be careful with that error, though: it has a second possible cause, which is that the calling
domain cannot see `IGateKeeperService` (SELinux). `dumpsys lock_settings` is what distinguishes
them: `SID: 0` with `CredentialType: None` means the credential really is absent.

---

### 15. What is rollback resistance and do my keys have them?

Rollback resistance means that once you delete a key, it is destroyed — restoring an old flash image
cannot bring it back. Without it, "the app deletes the key on logout" is weaker than it sounds,
because the key blob is a file, and files can be restored from a snapshot taken earlier.

Implementing it requires per-key state in storage the normal world cannot roll back: on-chip
non-volatile memory, a monotonic counter, or an RPMB partition. That storage is scarce, so
implementations that support it usually support only a handful of such keys.

Do your keys have it? Almost certainly not. There is no public API to request it, and neither
physical device measured for this chapter reported it. **Assume absent unless an attestation says
otherwise.**

---

### 16. Why is the emulator useless for this?

Because it has no secure hardware to emulate faithfully. Measured on a current API 35 emulator
image: every key type comes back `SOFTWARE`, StrongBox throws, and the attestation reports
`attestationSecurityLevel: Software` with a completely empty hardware-enforced list, chaining to a
root called `O=Google Test LLC, CN=Droid Unregistered Device CA`.

That chain is *internally valid* — every signature verifies — which is exactly why it is dangerous.
A verifier that does not pin the real root and does not check the security level will accept it, and
you will have "tested" a control that does not work.

Use the emulator to develop; use a physical device to conclude.

---

### 17. Can I see the key material if I have physical possession of the phone and unlimited time?

Not by any of the obvious routes. Desolder the flash and you get ciphertext under a key derived from
fuses inside the SoC, which is still soldered to the board. Copy the blob to another phone and it
decrypts under a different HUK, which is to say it does not decrypt.

What is left is attacking the silicon itself — glitching, decapping, side-channel analysis of the
main SoC. That is a real discipline with real results, it targets one specific device rather than a
model line (the HUK is per chip), and it is precisely the attack StrongBox's separate,
tamper-resistant chip exists to resist.

---

### 18. `getEncoded()` returns `null` on my key. Is it broken?

No — that is the correct and expected behaviour, and it is the clearest one-line proof that the key
is genuinely in the Keystore. There are no bytes in your process to return.

The alarming case is the opposite one. If `getEncoded()` returns actual bytes, the object is not a
Keystore key at all; it is something like a `SecretKeySpec` built from raw material in the heap, and
every hardware claim about it is false. That is worth grepping for.

---

### 19. Why does the same code give different results on different phones?

Because "supported" is a property of the device's KeyMint or Keymaster implementation, not of the
API level. Measured across three targets: one accepted 3DES in the TEE while two rejected it
outright with `NoSuchAlgorithmException`; none supported Ed25519 or X25519; one accepted a
**1024-bit RSA key in hardware**; and one threw `NoSuchMethodError` for `setMaxUsageCount` at the
exact API level where the documentation says the method exists.

The operational rule: an API level is a promise about AOSP, not about the phone in your hand. Guard
by capability, catch specific exceptions, and measure on the target.

---

### 20. What is the single most useful thing in this chapter?

Two minutes on a rooted test device:

```bash
adb shell getprop ro.boot.verifiedbootstate                  # says: green
./scripts/probe-security-levels.sh --attest | sed -n '/BEGIN CHAIN/,/END CHAIN/p' > chain.pem
python3 -B ./scripts/parse-attestation.py chain.pem          # says: Unverified, deviceLocked=false
```

That is a device contradicting its own claim about itself, with the hardware's version signed and
the software's version not. It settles every argument about property-based integrity checks, it
needs no app and no root to produce, and it is the most persuasive artefact you can put in front of
a developer.
