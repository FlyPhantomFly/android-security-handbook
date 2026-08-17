# 48 — Biometrics · FAQ

Real questions, including the ones people are embarrassed to ask. Answered directly.

---

### 1. Can an app read my fingerprint?

No. The sensor image travels a trusted path into the Trusted Execution Environment and is turned
into a template there. The template is stored in TEE-controlled storage. Matching also happens inside
the TEE. Android never receives the image or the template, so no app, no system service and no root
user can read it. What crosses back into Android is at most "a match happened" plus a signed token.

This is genuinely reassuring and it is also why sensor-spoofing research is largely irrelevant to an
app security assessment — see question 14.

---

### 2. So if the fingerprint is safe, what exactly am I attacking?

The app's logic. Specifically:

1. Whether the app bound the authentication to a cryptographic operation, or just to an `if`.
2. What it does when the biometric is unavailable or errors.
3. Whether its key is per-use or time-bound.
4. Whether it handles re-enrolment safely.

None of those involve the sensor.

---

### 3. What is a `CryptoObject`, in one sentence, for someone who has never used cryptography?

It is a way of saying to the system: *"do not just tell me the user authenticated — carry this
half-finished lock-opening operation into the authentication and finish it for me only if the
authentication really succeeds."* Without it, the system just tells you, and telling can be faked.

---

### 4. Why can't I just check a boolean? My code is obfuscated anyway.

Because obfuscation renames things; it does not make them unreachable. `Java.choose` finds an
instance by class name whatever that name is, and Frida can enumerate fields and set them. There is
no arrangement of Java code that stops someone who runs code inside your process from writing your
boolean.

The reason `CryptoObject` works is not that it is hidden. It is that the decision is made by a
processor your code cannot address.

---

### 5. My app uses `CryptoObject`. Am I done?

Not necessarily, and this is the most common false sense of security in the topic. Check the key's
validity window. If `setUserAuthenticationValidityDurationSeconds` is a positive number, the key is
**time-bound** — any authentication of an accepted type within that window satisfies it, performed
by any process, with no prompt from your app.

This was measured for this chapter: a key with a 24-hour window encrypted data with **no
authentication at all** in the probing process, and a 30-second key flipped from refused to allowed
after an `adb shell locksettings verify` issued by an unrelated process.

---

### 6. What window is safe, then?

None, in the sense you mean. The safe design is **no window**: a per-use key.

If your product genuinely cannot tolerate a prompt per operation, keep the key per-use and enforce
the session timeout in your *application* instead. That way the policy is soft and the key is not —
at the moment of use, the operation is still bound to a fresh authentication.

If you must use a window, make it seconds, and write down in your own documentation that it is
satisfied by any device unlock, so that nobody reads `setUserAuthenticationRequired(true)` in two
years and believes the guarantee is stronger than it is.

---

### 7. `Cipher.init` is throwing `UserNotAuthenticatedException`. How do I fix it?

You do not. That exception **is the feature.** It means the hardware is refusing to use the key
because nobody has authenticated. The correct response is to hand the uninitialised `Cipher` to
`BiometricPrompt` inside a `CryptoObject` and let the framework complete it after a real
authentication.

The dangerous "fix" — catching it and regenerating the key without the auth requirement — appears in
real code and is exactly how a correct implementation becomes a broken one during a bug-fix sprint.

---

### 8. Why does the framework reject `CryptoObject` together with `DEVICE_CREDENTIAL`?

Because a device-credential authentication cannot mint the Class 3 token an auth-bound key requires.
The combination is not weaker; it is impossible, so the framework tells you rather than silently
producing something that will not work.

Beware the "fix" some teams apply: dropping the `CryptoObject` so the combination is legal. That
converts a strong design straight into a callback-only one.

---

### 9. What does Class 1, 2, 3 actually mean? Is Class 3 just "more accurate"?

No. Class is about **how much the platform lets a sensor authorise**, not how good it is.

- **Class 1** — cannot drive `BiometricPrompt` at all. Keyguard only.
- **Class 2** — drives the prompt; **cannot** release a hardware auth token, so it can never back a
  key.
- **Class 3** — drives the prompt **and** has a hardware trust chain to KeyMint.

A very accurate sensor with no hardware path is Class 2 forever. A merely adequate one with a proper
chain can be Class 3. The Compatibility Definition Document (§7.3.10) sets the spoof- and
imposter-acceptance thresholds; the class structure is stable across versions, the numbers are not.

---

### 10. `BIOMETRIC_WEAK` sounds worse than `BIOMETRIC_STRONG`. Why is its value bigger?

`BIOMETRIC_STRONG` is `0x000F` and `BIOMETRIC_WEAK` is `0x00FF`. The strong bits are a **subset** of
the weak bits, which encodes containment: anything satisfying STRONG also satisfies WEAK. The
framework can then test `(sensorStrength & requested) == requested`.

So "the app asks for WEAK" means "the app will *accept* a weak sensor", not "the app uses one". On a
phone whose only sensor is Class 3 the behaviour is identical — until the user's next phone.

---

### 11. Is `BIOMETRIC_WEAK` ever the right choice?

Yes, when you are not binding a key. If the prompt is shoulder-surfing resistance over a screen —
hiding notes, hiding a balance — Class 2 costs you nothing and works on more devices. Say so in a
comment so the next reader knows it was a decision rather than a copy-paste.

The moment you introduce a `CryptoObject`, `BIOMETRIC_WEAK` becomes wrong.

---

### 12. Why does my app fail on a device with no fingerprint enrolled, at key *creation* time?

Because a per-use auth-bound key cannot be created when nothing could ever authorise it. The exact
message is `IllegalStateException: At least one biometric must be enrolled to create keys requiring
user authentication for every use`, and it reproduced on both devices used for this chapter.

Create the key when the user *enables* the feature, not eagerly at first launch. And do not "fix" it
by falling back to an unbound key.

---

### 13. Somebody could just enrol their own fingerprint. Doesn't that defeat everything?

It would, which is why `setInvalidatedByBiometricEnrollment(true)` exists: adding an enrolment
destroys keys created with the flag. Note that enrolling a biometric itself requires the device
credential, so the attack has a real precondition.

Two traps. First, apps turn the flag off because users lose their saved credentials when adding a
second finger. Second — measured for this chapter — **the flag is silently ignored on a time-bound
key**: it was requested `true` and `KeyInfo` read it back `false`, with no exception and no warning.
So a time-bound key is doubly exposed.

---

### 14. Can I unlock a phone with a photograph or a gummy fingerprint?

Sometimes, against Class 1 and some Class 2 sensors. This is a real research area and a legitimate
*device* finding.

It is almost never an *app* finding, and confusing the two damages a report. The app did not choose
the sensor. Write two separate sentences: what the device's sensor class is and what that implies
for device unlock, and separately whether the app requests `BIOMETRIC_STRONG` and would therefore
refuse the weak authenticator.

This chapter deliberately covers presentation attacks at the level of *what an authorised assessor
evaluates and reports* — sensor class, `oemStrength` vs `updatedStrength`, confirmation
requirements, liveness configurability — and not at the level of building artefacts. Biometric data
is a special category of personal data in many jurisdictions; do not collect or retain anyone's
without written consent.

---

### 15. `dumpsys biometric` prints nothing. Does my phone have no biometric hardware?

Almost certainly not. On the Android 11 device used for this chapter, `dumpsys biometric` and
`dumpsys auth` both produced **empty output** on a phone with a working, enrolled fingerprint
sensor — while `service list` showed `IBiometricService` registered. `dumpsys fingerprint` worked
fine and returned JSON.

Run all three, plus `pm list features | grep -i biometric`, before concluding anything.

---

### 16. What is `acceptCrypto` in `dumpsys fingerprint` and why do you keep mentioning it?

`dumpsys fingerprint` returns per-sensor counters, and they come in two parallel sets:

```
"accept":3,"reject":2,"acquire":18, ... "acceptCrypto":0,"rejectCrypto":0,"acquireCrypto":0
```

The `*Crypto` set counts authentications that carried a `CryptoObject`. On the device measured for
this chapter, `accept` was **3** and `acceptCrypto` was **0** — three successful biometric
authentications since boot, none of them bound to a cryptographic operation.

It is the fastest triage in the whole chapter: note the counters, use the app's biometric unlock,
note them again. If `accept` moved and `acceptCrypto` did not, the app is callback-only and you have
not opened a single tool.

---

### 17. I forged the callback and the app unlocked. Is that a critical finding?

Not by itself. You proved the **UI gate** is bypassable. You have not proved that protected data was
reachable. Ask:

- Did any cryptographic operation actually run? (Hook `Cipher.init`.)
- What was behind the gate?
- Was it reachable *without* the bypass — in `SharedPreferences`, a database, a log, `adb backup`?

If the data was Base64 in `SharedPreferences`, the real finding is the storage and the honest
severity is Low or Informational. Reporting that as a Critical biometric bypass is how a report
loses its reader.

---

### 18. `forge()` succeeded against a correctly-implemented app. Did I break it?

No, and this is the single most misread result in the topic. `forge()` calls a public Java method;
of course it returns. Frida reports no error because nothing errored.

The difference appears one step later. Watch the `Cipher.init`. If it throws
`UserNotAuthenticatedException`, the keystore refused and your forged callback bought a screen that
says "welcome" and nothing else. Report that as a **pass**.

---

### 19. Can root defeat an auth-bound key?

No. The check is not in Android. KeyMint runs in the TEE — a separate execution environment on the
same chip — and will not authorise an operation without a valid hardware auth token. Tokens are
HMAC-authenticated with a key shared between the biometric/Gatekeeper trusted applications and
KeyMint, and none of that material is reachable from the normal world.

Root gives you all of Android. The TEE is not part of Android.

What root **does** give you: the ability to read the plaintext out of the app's memory *after* a
legitimate authentication, to read anything the app wrote unencrypted, and to observe everything.
Binding stops forgery, not observation.

---

### 20. Why did my `app_process` probe say "Gatekeeper service not available"?

Because you are the `shell` domain and SELinux does not grant it `find` on that service. Verify it
yourself:

```bash
# adb shell as shell
service check android.service.gatekeeper.IGateKeeperService     # not found
service list | grep -i gatekeeper                                # registered, descriptor empty
# after adb root
service check android.service.gatekeeper.IGateKeeperService     # found
```

It is not a device property, and it is not "no PIN is set" — setting a PIN changes
`canAuthenticate(DEVICE_CREDENTIAL)` from `11` to `0` and leaves this error exactly where it was.
Report the measurement with the uid that produced it.

---

### 21. Why does my probe say `NoSuchProviderException: AndroidKeyStore`?

`app_process` does not run the app-startup path that registers the `AndroidKeyStore` JCA provider.
Call `install()` on `android.security.keystore2.AndroidKeyStoreProvider` (Android 12+) or
`android.security.keystore.AndroidKeyStoreProvider` (Android 6–11) first.

Without it, every key operation fails and it looks like the device has no hardware keystore. It is
chapter 50's finding and `scripts/BiometricProbe.java` reuses it.

---

### 22. My grader says grade A but I do not believe it. What now?

Trust the instinct. Grade A is a claim about **the code path that was found**, and three things
routinely hide a worse one:

- A legacy `FingerprintManager` branch for old API levels.
- A "remember me" or "trusted device" flow that skips the prompt entirely.
- A debug or QA build flag.

Also check whether the grade came from an unresolved constant. This chapter's grader graded its own
worst reference file **A** until it learned to resolve `private const val VALIDITY_SECONDS = 86_400`
— a static tool that cannot see a value reports the *absence of a problem*, not the absence of
evidence.

---

### 23. Should the biometric result be sent to my server?

Only as a signature over a server-issued challenge, never as a flag.

"The user authenticated: true" arriving at your server is a client assertion, and this whole chapter
is about why client assertions are worthless. The strong pattern is an EC key in the keystore, per-use
auth-bound, used with a `Signature` in the `CryptoObject` to sign a fresh random challenge the server
issued. Then the server holds cryptographic evidence rather than a claim.

The challenge must be random, single-use, short-lived and bound to the operation being authorised.
[46 — Tokens](../46-Tokens/README.md) and [47 — Authentication](../47-Authentication/README.md) own
that side.

---

### 24. Does an emulator tell me anything useful?

For *shape*, yes: API behaviour, return codes, which exceptions fire, the time-window experiment.
This chapter's most important measurement was made on one.

For *enforcement*, no. On an emulator every key is `SOFTWARE`, `hardwareEnforced` is empty — and
chapter 50 measured that the attestation chain **still verifies perfectly**. A valid chain proves
the chain, not the hardware. Any conclusion about hardware enforcement drawn on an emulator is a
conclusion about a software implementation of the interface.

---

### 25. My phone has face unlock but `pm list features` shows no face feature. Is it broken?

No — it is telling you the truth, and it is an important truth. On the MIUI device used for this
chapter, `pm list features` reports only `android.hardware.fingerprint`. Yet the device has face
unlock: `miui.face.FaceService` is registered, `com.miui.face` is running, and
`settings list secure` shows MIUI's own tuning values.

That face unlock is **entirely outside the biometric framework**. It is not a registered sensor,
`BiometricManager` cannot see it, and it can never satisfy an auth-bound key. It exists to unlock
the OEM's keyguard.

The consequence for users is uncomfortable: on that phone, "unlock with your face" and "unlock with
a biometric prompt" are different security systems with different guarantees, and nothing in the UI
distinguishes them. For testers: **never infer an app-facing biometric capability from what the
lock screen offers.**

---

### 26. Is `androidx.biometric` safe on old Android versions?

It works, but the guarantee is weaker than the code suggests. On API 23–27 there was no system
biometric dialog to delegate to, so `androidx.biometric` **draws its own** on top of
`FingerprintManager`. The "the system draws the pixels, so an app cannot phish them" property simply
does not exist there.

The key binding still works on those versions. It is the anti-phishing half that is missing, and it
is worth a line in a report for an app with `minSdk 23`.

---

### 27. Why is `setConfirmationRequired` a security setting? It just adds a tap.

Because fingerprint is **active** and face is **passive**. A fingerprint requires a deliberate touch.
Face and iris authenticate whoever the device is pointed at — including a sleeping user, an
unconscious user, or a user whose phone is being held up in front of them.

`setConfirmationRequired(true)` restores intent: it distinguishes "the user was present" from "the
user agreed". The framework ignores it for active modalities, so it costs nothing on a fingerprint
device.

---

### 28. What is the single fastest way to know if an app's biometric is real?

Look at the number of arguments to `authenticate()`.

```bash
grep -rn "->authenticate(Landroidx/biometric/BiometricPrompt\$PromptInfo;)V" smali/
```

One argument means no binding. It is not the whole story — a two-argument call over a time-bound key
is still weak — but one argument settles it in seconds and needs nothing but a decompiled APK.

---

### 29. Everyone else's writeups make this look easier than my results. Why?

Because most published biometric-bypass writeups stop after the callback fires and show a
screenshot. That is one of three passes. The third pass — did a cryptographic operation actually
succeed — is where the interesting answers live, and it is the pass that sometimes says "you did not
break this".

A result that says "the binding held" is a good result. Report it.

---

### 30. How much of this chapter can I do without root?

Most of it. Specifically, with no root at all:

- All of the static analysis and grading.
- `dumpsys fingerprint` / `biometric` / `trust` / `pm list features` / `lshal`.
- The `accept` vs `acceptCrypto` triage.
- `probe-biometrics.sh` for features and unbound-key behaviour.
- Fail-open testing (remove enrolment, force `ERROR_LOCKOUT`) — no tooling whatsoever.
- Re-enrolment testing.

You need root or an emulator for: Frida-based callback forgery on most devices, and the time-bound
key experiment (because Gatekeeper is not reachable from the `shell` SELinux domain).

Note which of the CTF's four flags need no tooling — it is two of them, and they carry the higher
severities.
