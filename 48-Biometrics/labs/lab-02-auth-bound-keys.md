# Lab 02 — Measuring the binding yourself

> **Objective:** reproduce, on your own hardware, the measurement that decides whether an
> auth-bound key is worth anything: **three keys, identical except for one integer, and three
> different answers.** By the end you will have your own version of the chapter's §3.6 table, and
> you will have watched a key open because a *completely different process* authenticated.

| | |
|---|---|
| **Difficulty** | Intermediate |
| **Time** | 45–75 minutes |
| **Needs** | Any device for part A. **Root, or an emulator, for parts B and C** — see §1.2 |
| **Chapter sections** | [§3.5](../README.md), [§3.6](../README.md), [§7.3](../README.md) |
| **Files** | [`../scripts/probe-biometrics.sh`](../scripts/probe-biometrics.sh), [`../scripts/BiometricProbe.java`](../scripts/BiometricProbe.java), [`../examples/03-TimeBoundTrap.kt`](../examples/03-TimeBoundTrap.kt) |

> **⚠️ Warning**
> Part C sets a lock-screen PIN. **Do this on an emulator or a dedicated test device, never on a
> phone you rely on.** The lab removes the PIN at the end, but a device left in an unexpected lock
> state is a bad afternoon. If your only device is a daily driver, do parts A and B and read part C.

---

## 0. Why this lab exists

Lab 01 taught you to look for a `CryptoObject`. That is necessary and it is not sufficient.

An app can pass a `CryptoObject`, over a key with `setUserAuthenticationRequired(true)`, and still
be defeated by an attacker who does nothing more sophisticated than *unlock the phone normally*.
The whole difference is one argument, and neither the compiler nor a code review nor most static
tools will comment on it.

You are going to demonstrate that with three keys and one integer. Nothing about this lab is
theoretical — the runs printed below were produced on the hardware described in §1.3, and yours
should look the same shape even if the numbers differ.

---

## 1. Setup

### 1.1 Tooling check

```bash
# host
adb devices -l
javac -version                        # any JDK
ls "$HOME/AppData/Local/Android/Sdk/build-tools"       # need d8
ls "$HOME/AppData/Local/Android/Sdk/platforms"         # need an android.jar, API 30+
```

The runner finds these itself on a standard SDK layout. Override with `ANDROID_JAR` and
`BUILD_TOOLS` if it cannot.

### 1.2 Which parts your hardware can do

| Part | What it needs | Why |
|---|---|---|
| **A** — device capability | Any device with `adb` | Reads features and creates unbound keys |
| **B** — per-use refusal | A device with a fingerprint **enrolled** | A per-use key cannot be *created* with nothing enrolled |
| **C** — the time-window experiment | **Root or an emulator**, plus a lock credential | `IGateKeeperService` is not reachable from the `shell` SELinux domain |

Part C's requirement is not a limitation of the script; it is a measured property of the platform,
and you will verify it yourself in §4.1 rather than taking it on trust.

### 1.3 Record your device, before anything else

```bash
# host
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell getprop ro.build.version.security_patch
adb shell 'pm list features | grep -iE "fingerprint|biometric|strongbox"'
adb shell 'dumpsys trust | grep -o "deviceLocked=[01]"'
```

The runs in this lab came from two devices:

| | Physical | Emulator |
|---|---|---|
| Model | Redmi `M2101K6P` (`sweetin`), MIUI 12.5 | `sdk_gphone16k_x86_64` |
| Release / API | Android 11 / API 30 | Android 15 / API 35 |
| Root | yes | `adb root` |
| Features | `android.hardware.fingerprint` only | `fingerprint` **and** `biometrics.face` |
| Keystore | TEE (`isInsideSecureHardware=true`), no StrongBox | `SOFTWARE` |

> **🔍 Pentester's Note**
> Note what is *absent* from the Redmi's feature list: `android.hardware.biometrics.face`. That
> phone has face unlock — `miui.face.FaceService` is registered, `com.miui.face` is running, and
> `settings list secure` shows `facelock_liveliness_recognition_threshold=2.2`. It is entirely
> outside the biometric framework: `BiometricManager` cannot see it and it can never satisfy an
> auth-bound key. **Do not infer a device's app-facing biometric capability from what the lock
> screen offers.**

---

## 2. Part A — What can this device do?

```bash
# host, from the chapter root
./scripts/probe-biometrics.sh
```

The runner compiles `BiometricProbe.java`, pushes a DEX to `/data/local/tmp`, runs it under
`app_process` as uid 2000, deletes every key it created, and removes the DEX.

### 2.1 Expected output, and how to read it

```
device: M2101K6P   Android 11 (API 30)
trust: deviceLocked=0   (an unlocked device satisfies time-bound keys)

== DEVICE ====================================================================
  model                                      M2101K6P
  android.release                            11
  android.sdk                                30
  security.patch                             2021-12-01
  probe.uid                                  2000
  provider.install                           android.security.keystore.AndroidKeyStoreProvider
  context                                    android

== HARDWARE FEATURES (PackageManager) ========================================
  feature.android.hardware.fingerprint       true
  feature.android.hardware.biometrics.face   false
  feature.android.hardware.biometrics.iris   false
  feature.android.hardware.strongbox_keystore false
```

Three lines to stop on.

**`provider.install`.** `app_process` does not register the `AndroidKeyStore` JCA provider — that
happens on the app startup path. Without an explicit `install()` call, every key operation throws
`NoSuchProviderException: no such provider: AndroidKeyStore` and a beginner concludes the device has
no hardware keystore. This is chapter 50's finding, reused here. Note **which** class installed: the
Redmi took the legacy `android.security.keystore.AndroidKeyStoreProvider`, the API 35 emulator took
`android.security.keystore2.AndroidKeyStoreProvider`.

**`probe.uid 2000`.** You are the shell, not an app. Everything below is subject to the shell
domain's permissions and SELinux policy, and §4.1 shows exactly where that bites.

**`trust: deviceLocked=0`.** The device is unlocked *right now*, which is precisely the condition
that makes a time-bound key open. If you forget this you will measure the wrong thing and conclude
the wrong thing.

### 2.2 The MIUI noise

On the Redmi the probe prints a `FileNotFoundException` stack trace before the feature list:

```
java.io.FileNotFoundException: /data/system/theme_config/theme_compatibility.xml: ENOENT
    at miui.content.res.ThemeCompatibilityLoader.getVersion(...)
    ...
    at android.app.ActivityThread.systemMain(...)
```

It is noise. `ActivityThread.systemMain()` still returns a usable context (the next line reads
`context  android`). Filter it out and move on; chasing it wastes an hour.

### 2.3 The permission wall

On the Redmi, every `canAuthenticate` call failed:

```
canAuthenticate(BIOMETRIC_WEAK)  THREW java.lang.SecurityException:
    Must have USE_BIOMETRIC permission: Neither user 2000 nor current
    process has android.permission.USE_BIOMETRIC.
```

with the device's own stack naming `com.android.server.biometrics.AuthService.checkPermission`.

On the API 35 emulator the same calls **succeeded**, because that build's shell package holds the
permission. **Two devices, two answers.** Record which one you have; do not generalise from either.

If your device is the first kind, you have measured something real — write it down — and you will
need an installed app to query `canAuthenticate`, which is exactly what lab 01 built.

### 2.4 The two refusals — and only one is about your device

```
key.peruse.create      REFUSED AT CREATION: java.lang.IllegalStateException:
    At least one biometric must be enrolled to create keys requiring
    user authentication for every use

key.timebound_30.create  REFUSED AT CREATION: java.lang.IllegalStateException:
    Gatekeeper service not available
```

These look similar and are completely different.

The **first** is a genuine device state. A per-use key cannot exist if nothing could ever authorise
it. It reproduced identically on both devices when nothing was enrolled. An app that creates its key
eagerly at first launch will hit this in production — and the wrong fix (catch it, fall back to an
unbound key) is a real origin of the vulnerability from lab 01.

The **second** is a property of *your probe*, not of the device. Part B proves it.

---

## 3. Part B — Prove the second refusal is yours, not the device's

### 3.1 The direct test

```bash
# adb shell, as shell (uid 2000)
service check android.service.gatekeeper.IGateKeeperService
service list | grep -i gatekeeper
```

Measured on the Redmi:

```
Service android.service.gatekeeper.IGateKeeperService: not found
19  android.service.gatekeeper.IGateKeeperService: []
```

Read those two lines together, because they contradict each other and the contradiction is the
answer. `service list` **can see** the service — it is registered, at handle 19 — but its interface
descriptor comes back empty and `service check` reports "not found". `checkService()` returned
`null` for this caller.

The cause is SELinux: the `shell` domain lacks `find` on the gatekeeper service. It is the same
shape as chapter 60's measurement that `shell` cannot read `/data/misc/adb/adb_keys` even though the
DAC group bit permits it — **both layers must allow an operation**, and DAC saying yes is not
enough.

### 3.2 The control

```bash
# host — on an emulator
adb root
adb shell 'service check android.service.gatekeeper.IGateKeeperService'
```

Measured on the API 35 emulator:

```
Service android.service.gatekeeper.IGateKeeperService: found
```

Same device, same service, different domain, different answer.

### 3.3 The second control — rule out "no credential set"

It would be reasonable to guess that the error means "no PIN is configured, so there is no secure
user ID". Test that guess directly:

```bash
# host — emulator only
adb shell locksettings set-pin 1234
adb shell 'dumpsys trust | grep -o "deviceLocked=[01]"'
```

Then re-run the probe **as shell** (not root):

```bash
# host
adb unroot
./scripts/probe-biometrics.sh
```

Measured result: `canAuthenticate(DEVICE_CREDENTIAL)` changed from `11` (`ERROR_NONE_ENROLLED`) to
`0` (`BIOMETRIC_SUCCESS`) — so the credential definitely took — and
`key.timebound_30.create` **still failed** with `Gatekeeper service not available`.

> **🧠 Mental Model**
> You have just run a proper controlled experiment. One variable (the credential) changed and the
> symptom did not; another variable (the SELinux domain) changed and the symptom did. That is the
> difference between "I think it's a permissions thing" and "it is a permissions thing", and it is
> the standard the rest of this repository holds itself to.

### 3.4 Record it correctly

In your notes, write:

> `IllegalStateException: Gatekeeper service not available` when creating a time-bound key from
> `app_process` as uid 2000 is an **artefact of the shell SELinux domain**, not a device property.
> Verified by (a) `service check` failing as shell and succeeding as root on the same device, and
> (b) setting a device credential changing `canAuthenticate(DEVICE_CREDENTIAL)` without changing the
> error.

That paragraph is worth more in a report than any number of successful key creations.

---

## 4. Part C — The measurement

This is the lab. Everything before it was setup.

### 4.1 Set up the conditions

```bash
# host — EMULATOR OR DEDICATED TEST DEVICE ONLY
adb root
adb shell locksettings set-pin 1234
adb shell 'dumpsys trust | grep -o "deviceLocked=[01]"'
```

You now have: a device credential (so Gatekeeper has a secure user ID), and a root shell (so the
probe can reach the Gatekeeper service).

### 4.2 Run 1 — cold

Wait at least sixty seconds after setting the PIN, so that any authentication from that operation is
older than the 30-second window. Then:

```bash
# host
./scripts/probe-biometrics.sh 2>&1 | grep -E 'timebound_(1|30|86400)\.cipherInit'
```

**Measured on the API 35 emulator:**

```
key.timebound_30.cipherInit     UserNotAuthenticatedException - HARDWARE REFUSED (this is the correct answer)
key.timebound_1.cipherInit      UserNotAuthenticatedException - HARDWARE REFUSED (this is the correct answer)
key.timebound_86400.cipherInit  OK - encrypted 20 bytes with NO authentication
```

Stop and look at that third line. A key configured with `setUserAuthenticationRequired(true)` just
performed a cryptographic operation, and **no authentication of any kind occurred during this
process's lifetime**. No prompt. No finger. No PIN entry. The key opened because the window is
twenty-four hours long and someone set a PIN earlier.

### 4.3 Run 2 — after an unrelated authentication

Now issue a credential verification **from a completely different process**. This stands in for
"the user unlocked their phone", which is what happens in real life dozens of times a day:

```bash
# host
adb shell locksettings verify --old 1234
```

Expected: `Lock credential verified successfully`.

Immediately re-run the probe:

```bash
# host
./scripts/probe-biometrics.sh 2>&1 | grep -E 'timebound_(1|30|86400)\.cipherInit'
```

**Measured:**

```
key.timebound_30.cipherInit     OK - encrypted 20 bytes with NO authentication
key.timebound_1.cipherInit      UserNotAuthenticatedException - HARDWARE REFUSED (this is the correct answer)
key.timebound_86400.cipherInit  OK - encrypted 20 bytes with NO authentication
```

### 4.4 Your table

Fill this in from your own two runs:

| Validity window | Run 1 (cold) | Run 2 (after `locksettings verify`) |
|---|---|---|
| 1 second | | |
| 30 seconds | | |
| 86,400 seconds | | |

The reference result:

| Validity window | Run 1 (cold) | Run 2 (after verify) |
|---|---|---|
| 1 second | refused | **refused** — the build-push-run cycle takes longer than 1 s |
| 30 seconds | refused | **allowed** |
| 86,400 seconds | **allowed** | allowed |

### 4.5 What those six cells prove

Write out each conclusion in your own words before reading these.

1. **The window is real and the keystore enforces it.** The only difference between the three keys
   was an integer. One always refused, one flipped, one always allowed.

2. **A time-bound key is not bound to your app's prompt.** The authentication that opened the
   30-second key was `cmd lock_settings verify`, issued over `adb`, by a process with no
   relationship to the key's owner. The app showed nothing and was not consulted.

3. **A 24-hour window is not a security control.** A real user unlocks their phone many times a
   day. The window is effectively always open.

4. **The 1-second key is the shape of per-use, approximated.** It refused even immediately after a
   verification, because the token was already stale by the time the operation ran. A true per-use
   key removes the race entirely by requiring a token minted *for that operation*.

5. **You did not bypass anything.** You created keys, waited, and used them. Any attacker holding an
   unlocked phone can do the same to an app that ships this configuration.

---

## 5. Part D — Read the key back, and catch a discarded flag

The probe also prints `KeyInfo` for every key it creates. Look at the time-bound keys:

```
key.timebound_30.authRequired               true
key.timebound_30.validitySeconds            30
key.timebound_30.invalidatedByEnrolment     false
key.timebound_30.authType                   3 AUTH_DEVICE_CREDENTIAL AUTH_BIOMETRIC_STRONG
key.timebound_30.enforcedBySecureHardware   false
key.timebound_30.securityLevel              SOFTWARE
```

Now open [`../scripts/BiometricProbe.java`](../scripts/BiometricProbe.java) and find the spec table.
The `timebound_30` row passes `Boolean.TRUE` for `setInvalidatedByBiometricEnrollment`.

**`true` was requested. `false` came back.**

The builder accepted a security-relevant argument and discarded it — no exception, no warning, no
log line. Enrolment invalidation applies to per-use keys; on a time-bound key the flag is dropped
silently. A developer who sets it and reasons "an attacker enrolling a finger will destroy my key"
is reasoning about something that does not exist.

**The `authType` is the second finding in the same block.** `3` is
`AUTH_DEVICE_CREDENTIAL | AUTH_BIOMETRIC_STRONG`. The legacy
`setUserAuthenticationValidityDurationSeconds` setter accepts **both** — so this "fingerprint" key
is opened by the PIN. That is not a bug; it is the documented default, and it is invisible unless
you read `KeyInfo` back. On API 30+ only `setUserAuthenticationParameters(0,
KeyProperties.AUTH_BIOMETRIC_STRONG)` says "biometric only".

### 5.1 The engineering lesson

Nobody reads `KeyInfo` back. Add it to your review checklist and to your client's code:

```java
SecretKeyFactory f = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
KeyInfo info = (KeyInfo) f.getKeySpec(key, KeyInfo.class);
if (!info.isUserAuthenticationRequired()
        || info.getUserAuthenticationValidityDurationSeconds() > 0
        || !info.isUserAuthenticationRequirementEnforcedBySecureHardware()) {
    disableBiometricUnlock("key binding not enforced as requested");
}
```

That block would have caught every discrepancy in this section, at runtime, on the user's device.

---

## 6. Part E — Diff two devices

```bash
# host
ANDROID_SERIAL=<physical> ./scripts/probe-biometrics.sh --json > /tmp/phone.json
ANDROID_SERIAL=<emulator> ./scripts/probe-biometrics.sh --json > /tmp/emu.json
diff <(python3 -B -m json.tool /tmp/phone.json) <(python3 -B -m json.tool /tmp/emu.json)
```

Things worth noticing in the diff:

| Field | Physical | Emulator | Why it matters |
|---|---|---|---|
| `provider.install` | legacy `keystore` class | `keystore2` class | Platform generation |
| `feature.…biometrics.face` | `false` | `true` | The OEM face unlock is outside the framework |
| `canAuthenticate(*)` | `SecurityException` | numeric results | Shell permission differs by build |
| `key.baseline.securityLevel` | `isInsideSecureHardware=true` | `SOFTWARE` | An emulator enforces nothing in hardware |
| `key.*.enforcedBySecureHardware` | — | `false` | Correlates with the above |

> **⚠️ Warning**
> The emulator row is the one to remember. Chapter 50 measured that **on an emulator every key is
> `SOFTWARE`, `hardwareEnforced` is empty, and the attestation chain still verifies perfectly.** A
> valid chain proves the chain, not the hardware. Any conclusion about *enforcement* drawn on an
> emulator is a conclusion about a software implementation of the interface.

---

## 7. Success criteria

- [ ] Your own filled-in §4.4 table, with your device and API level written next to it.
- [ ] A one-paragraph explanation of why the 86,400-second key opened in run 1.
- [ ] Evidence (two commands and their output) that `Gatekeeper service not available` is an SELinux
      artefact, plus the control that rules out "no credential set".
- [ ] The `KeyInfo` block showing `invalidatedByEnrolment: false` when `true` was requested.
- [ ] The `authType: 3` line, and one sentence on why a "fingerprint" key that a PIN opens may or may
      not be acceptable *in a specific threat model*.
- [ ] Confirmation that every `ch48_probe_*` key was deleted (`keysDeleted` in the output).

---

## 8. Hints

<details>
<summary>All six key creations fail with NoSuchProviderException</summary>

The JCA provider bootstrap did not run. Check the `provider.install` line — if it reads `FAILED`,
neither `AndroidKeyStoreProvider` class was found, which would mean a very unusual platform. More
likely the probe crashed before reaching it; read the whole output rather than the grep.
</details>

<details>
<summary>Every timebound key is refused, even the 86,400-second one</summary>

Good — that means no authentication has happened on this device within the window. Set a PIN (§4.1)
or unlock the device, then re-run. If you have *never* set a credential, Gatekeeper has no secure
user ID and the keys will refuse in a different way.
</details>

<details>
<summary>Every timebound key succeeds, even the 1-second one</summary>

Your probe run is completing faster than one second after an authentication, or the device performed
one during the run. Lock the device (`adb shell input keyevent 26`), wait, and re-run. Also check
`dumpsys trust | grep deviceLocked`.
</details>

<details>
<summary>The per-use keys never create, even with a fingerprint enrolled</summary>

Confirm the enrolment is for **the current user**: `dumpsys fingerprint` shows `"count":N`. A count
of 0 with a fingerprint you believe you enrolled usually means it belongs to a different Android
user or work profile.
</details>

<details>
<summary>d8 warns "An API level of 35 is not supported by this compiler"</summary>

Harmless — the DEX still builds and runs. Install newer build-tools if it bothers you, or set
`BUILD_TOOLS` to an older directory.
</details>

---

## 9. Clean up

**Do this. Chapter 50's run was interrupted by a device swap mid-session and left
`/data/local/tmp/ch50probe.dex` behind, along with up to four `ch50_probe_*` keys in the shell
keystore namespace — invisible to apps and harmless, but not ours to leave, and still uncleaned
because that phone has not been reattached since.**

```bash
# host
./scripts/probe-biometrics.sh                       # a run without --keep deletes every ch48_probe_* key
adb shell 'ls /data/local/tmp | grep -i ch48'       # expect nothing

# if you set a PIN in part C, remove it — EMULATOR / TEST DEVICE ONLY
adb root
adb shell locksettings clear --old 1234       # see the warning below: root is required
adb shell locksettings set-disabled false     # restore the pre-lab state
adb unroot

# confirm the credential is really gone — canAuthenticate(DEVICE_CREDENTIAL) must return to 11
./scripts/probe-biometrics.sh 2>&1 | grep 'canAuthenticate(DEVICE'
```

> **⚠️ Warning — `locksettings clear` lies to you when you are not root**
> Measured while cleaning up after writing this lab. As uid 2000 on the API 35 emulator:
>
> ```
> $ adb shell locksettings clear --old 1234
> The device does not support lock screen - ignoring the command.
> ```
>
> That message is false. The same device reports `feature:android.software.secure_lock_screen`, and
> the identical command after `adb root` returns `Lock credential cleared`. **The PIN was still set
> the whole time**, and the only reason this was caught is that the probe was re-run afterwards and
> `canAuthenticate(DEVICE_CREDENTIAL)` still returned `0` instead of `11`.
>
> This is the third misleading refusal in this chapter's orbit — alongside
> `Gatekeeper service not available` (§3) and chapter 60's three distinct `run-as` refusals. The
> pattern is consistent enough to be a rule: **on Android, a permission failure frequently arrives
> disguised as a capability failure.** Never accept "this device does not support X" without
> checking whether you are simply not allowed to do X. And always verify a cleanup rather than
> trusting its exit message.

The probe deletes its keys by **enumerating and filtering on the `ch48_probe_` prefix**, never by
wildcard, and it never touches a key it did not create. Read the `cleanup()` method if you want to
confirm that before running it against anything you care about.

---

## 10. Where to go next

- [Lab 03 — Audit a real app](lab-03-audit-a-real-app.md) applies all of this to something you did
  not write.
- [`../examples/03-TimeBoundTrap.kt`](../examples/03-TimeBoundTrap.kt) is this lab's defect as a
  shipping app, with the measurement quoted in its header comment.
- [50 — Hardware-Backed Security lab 02](../../50-HardwareBackedSecurity/labs/lab-02-gatekeeper-and-the-hat-chain.md)
  is the other end of the same mechanism: the token itself, rather than the key that demands it.
