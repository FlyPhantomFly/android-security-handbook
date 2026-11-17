# Lab 01 — Determine the real security level of every key an app can create on your device

> **Difficulty:** beginner to intermediate
> **Time:** 45–90 minutes
> **Needs root:** **no**, for parts A–D. Part E needs root and Frida.
> **Needs an installed app:** **no**, for parts A–D.

---

## Objective

Stop guessing. By the end of this lab you will have a table, produced by measurement on hardware
you are holding, that says for every algorithm, key size and option an application can request:

- whether the key lands in **StrongBox**, the **TEE**, or **software**;
- whether the request is refused outright, and with which exception;
- and whether the answer matches what the documentation promised.

Then you will do the same for a specific *app*, and compare. The gap between "what this device can
do" and "what this app actually got" is where every finding in this area lives.

> **The point of this lab is not the numbers.** It is the habit. Almost every wrong claim about
> hardware-backed security comes from someone reading an API level, a feature flag or a
> `KeyGenParameterSpec` and inferring the answer instead of asking the device.

---

## Why this lab exists

Read [README §1.4](../README.md) before you start, and hold it in mind throughout:

> **"No StrongBox" is not a finding.** The finding is a *mismatch* — an app claiming hardware
> backing it never verified, or requiring authentication it never bound to a key.

You cannot identify a mismatch without both halves. This lab produces both halves.

---

## Setup

### What you need

| Item | Notes |
|---|---|
| A physical Android device with USB debugging | An emulator works and is *educational*, because it demonstrates the software-only case — but never conclude from it |
| `adb` on PATH | |
| A JDK (`javac`) | Any recent one. JDK 24 was used to write this lab |
| Android SDK build-tools with `d8` | 35.0.1 was used |
| An `android.jar` from **API 31 or later** | Needed so that `KeyInfo.getSecurityLevel()` resolves at compile time. You can still *run* against an older device |
| This chapter's `scripts/` directory | |

### Step 0 — identify the device, and write it down

Do this **every single time**, before anything else. It is the first step of the lab because it is
the step people skip.

```bash
# host
adb devices -l
adb shell getprop ro.product.model
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```

> **This is not a formality.** While this chapter was being measured, the attached device
> **changed mid-session**: an `i9000S` on Android 13 disappeared from `adb devices` between two
> commands and a Redmi `M2101K6P` on Android 11 appeared in its place. Half a results table had
> already been produced against the first device. Every number in this chapter therefore carries
> the target it came from, and yours should too.

If `adb devices` lists more than one entry, set `ANDROID_SERIAL` explicitly:

```bash
# host
export ANDROID_SERIAL=<the serial you intend to test>
```

Create a results file now and put the device identity at the top of it:

```bash
# host
{
  echo "# Lab 01 results"
  echo "device : $(adb shell getprop ro.product.model | tr -d '\r')"
  echo "android: $(adb shell getprop ro.build.version.release | tr -d '\r') (API $(adb shell getprop ro.build.version.sdk | tr -d '\r'))"
  echo "serial : ${ANDROID_SERIAL:-<single device>}"
  echo "date   : $(date -u +%FT%TZ)"
  echo
} > lab01-results.md
```

---

## Part A — Establish the capability ceiling (15 minutes)

Before measuring, find out what the device *claims* it can do. You will compare this against
reality in Part B, and the comparison is instructive.

```bash
# host
cd 50-HardwareBackedSecurity
./scripts/hw-security-inventory.sh | tee -a lab01-results.md
```

### A.1 — Answer these from the output

| Question | Where in the output |
|---|---|
| Is `android.hardware.strongbox_keystore` declared? | DECLARED FEATURES |
| Is `android.hardware.hardware_keystore` declared, and with what value? | DECLARED FEATURES |
| Which HAL process is actually running? | THE HAL THAT ACTUALLY BACKS THE KEYSTORE |
| Is it **KeyMint** (AIDL) or **Keymaster** (HIDL)? | the process name: `keymint@N-service.*` versus `keymaster@4.x-service.*` |
| Which Keystore daemon? | `service list`: `android.system.keystore2.*` = keystore2; `android.security.keystore` = legacy |
| Which TEE vendor? | `ro.hardware.gatekeeper`, and the HAL process suffix |
| Is a lock-screen credential set? | GATEKEEPER — look for `SID` and `CredentialType` |
| What does the bootloader claim? | VERIFIED BOOT — and remember §5.1 before believing it |

### A.2 — The trap in this section

Write down your answer to this before continuing:

> *"Based on the feature flags alone, will this device give me hardware-backed keys?"*

Then read this measured result from the chapter:

- Target A (`i9000S`, API 33) declared `android.hardware.hardware_keystore=41` and **no**
  strongbox feature.
- Target B (Redmi, API 30) declared **neither feature** — and put *every single key type* in the
  TEE anyway.

The `android.hardware.hardware_keystore` constant only exists from API 31. On an older device its
absence carries no information whatsoever. **A feature flag is a ceiling, and sometimes not even
that.**

---

## Part B — Measure what a key actually gets (20 minutes)

Now ask the hardware instead of the documentation.

```bash
# host
./scripts/probe-security-levels.sh | tee -a lab01-results.md
```

### B.1 — What just happened

The script did four things, and it is worth understanding them because the technique is reusable
far beyond this lab:

1. Compiled `SecurityLevelProbe.java` against `android.jar` on the host.
2. Converted the class to DEX with `d8`.
3. Pushed the DEX to `/data/local/tmp` and ran it with **`app_process`** — the same binary Zygote
   is launched from, which boots a real ART runtime with the whole framework on the classpath.
4. Deleted every key it created and removed its own DEX.

**No root. No installed app. No Frida.** The probe runs as uid 2000 (`shell`), in the shell's own
Keystore namespace, so it cannot see or touch any app's keys and no app can see its. That is what
makes it safe to run on a daily-driver phone.

### B.2 — Read your table

You should have one row per key type. Fill in this template in `lab01-results.md`:

| Key requested | Level got | Notes / exception |
|---|---|---|
| AES-128 GCM | | |
| AES-256 GCM | | |
| AES-256 GCM +StrongBox | | |
| HMAC-SHA256 | | |
| HMAC-SHA512 | | |
| 3DES CBC/PKCS7 | | |
| RSA-2048 PSS | | |
| RSA-3072 PSS | | |
| RSA-4096 PSS | | |
| RSA-1024 | | |
| RSA-2048 +StrongBox | | |
| EC P-256 | | |
| EC P-384 | | |
| EC P-521 | | |
| EC P-256 +StrongBox | | |
| Ed25519 | | |
| X25519 | | |
| rollback-resistant AES | | |
| `setMaxUsageCount(1)` | | |
| auth-bound (per-use) | | |

### B.3 — Questions to answer from your own table

1. **Is the answer uniform across algorithms?** Do not assume. Measured for this chapter, target B
   put 3DES in the TEE while targets A and C refused it entirely with
   `NoSuchAlgorithmException: no such algorithm: DESede for provider AndroidKeyStore`.

2. **Did an undersized key get refused?** The 1024-bit RSA row is there deliberately.
   [49 §3.5.1](../../49-KeyStore/README.md) says undersized RSA "should be rejected by the
   hardware, but check". Checked: target B **generated it and reported `TRUSTED_ENVIRONMENT`**.
   The hardware enforces the policy attached to the key; it does not enforce your idea of good
   cryptography. What did yours do?

3. **Which modern curves are missing?** Neither physical target supported Ed25519 or X25519. The
   error message on target B lists exactly what *is* supported, which is more useful than any
   compatibility table:
   ```
   InvalidAlgorithmParameterException: Unsupported EC curve name: ed25519.
   Supported: [p-224, p-256, p-384, p-521, prime256v1, secp224r1, secp256r1, secp384r1, secp521r1]
   ```

4. **Did any documented API turn out to be absent?** On target B, `setMaxUsageCount` — documented
   at API 30, on an API 30 device — threw:
   ```
   NoSuchMethodError: No virtual method setMaxUsageCount(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;
   ```
   If yours did too, you have independently reproduced one of this chapter's measured contradictions.

5. **Did the auth-bound key succeed?** If not, read the exception carefully — see Part C.

### B.4 — If the probe fails

| Symptom | Cause and fix |
|---|---|
| `AndroidKeyStore not found` | The JCA provider was not installed. The probe does this by reflection; if your platform's class name differs, look at `installProvider()` |
| `Failed to obtain application Context from ActivityThread` | Android ≤ 11 legacy provider. The probe bootstraps a system context automatically and prints that it did |
| `ServiceSpecificException` with code 6 (`PERMISSION_DENIED`) | This device's SELinux policy denies the `shell` domain access to `keystore2`. Rare, but real. You must fall back to an installed APK |
| `no android.jar found` | Set `ANDROID_JAR` explicitly |
| `adb: error: cannot stat …` on Windows/Git Bash | Path conversion. The script handles this with `cygpath`; if you are running the commands manually, `export MSYS_NO_PATHCONV=1` and convert the *local* path yourself |
| It hangs on RSA-4096 | Some TEEs are slow. Give it a minute before assuming failure |

---

## Part C — The auth-bound key, and reading its failure honestly (15 minutes)

The auth-bound row is the most interesting one, because its failure is ambiguous and most people
misread it.

### C.1 — What you may have seen

```
AES-256 auth-bound (per-use)   REFUSED   IllegalStateException: Gatekeeper service not available
```

That message reads like "this device has no Gatekeeper", which is almost certainly false. There are
**two** possible causes and the probe deliberately refuses to guess:

| Cause | Meaning |
|---|---|
| (a) No lock-screen credential is set | Gatekeeper holds no password handle, so the Secure User ID is 0, so there is no identity to bind a key to |
| (b) The `shell` domain cannot reach `IGateKeeperService` | An SELinux/service-visibility limitation of *how you are testing*, not of the device |

### C.2 — Settle it

```bash
# host
adb shell dumpsys lock_settings | head -25
adb shell service check android.service.gatekeeper.IGateKeeperService
```

Look for:

```
    SID: 0
    Quality: 0
    CredentialType: None
```

`SID: 0` together with `CredentialType: None` is definitive: **no credential exists**, so cause (a)
holds regardless of anything else. A non-zero `SID` means a credential does exist, and the value is
that enrolment's identity — the thing every auth-bound key is tied to.

On target B, both conditions were true simultaneously: `SID: 0` *and*
`Service android.service.gatekeeper.IGateKeeperService: not found` from the shell.

### C.3 — Make the auth-bound row succeed

On a device you are allowed to modify (**not** somebody's daily driver, and not without asking):

1. Set a PIN in Settings.
2. Re-run `./scripts/probe-security-levels.sh`.
3. The auth-bound row should now report a security level instead of an exception.
4. Note `authEnforcedByHw` in the detail column — that is
   `isUserAuthenticationRequirementEnforcedBySecureHardware()`, and it tells you whether the
   binding is a hardware promise or only a framework one.

Record whether it changed. If you cannot set a credential on this device, say so in your results
rather than leaving the row blank — an unmeasured row and a failed row are different facts.

---

## Part D — Attest, and compare the hardware against the device's own claims (20 minutes)

```bash
# host
./scripts/probe-security-levels.sh --attest \
  | sed -n '/BEGIN CHAIN/,/END CHAIN/p' > chain.pem
python3 -B ./scripts/parse-attestation.py chain.pem | tee -a lab01-results.md
```

### D.1 — Record these six fields

| Field | Your value |
|---|---|
| `attestationSecurityLevel` | |
| `keymasterSecurityLevel` | |
| `attestationVersion` | |
| `rootOfTrust.verifiedBootState` (hardware-enforced) | |
| `rootOfTrust.deviceLocked` | |
| root certificate subject and `spki-sha256` | |

### D.2 — The comparison that matters

```bash
# host
adb shell getprop ro.boot.verifiedbootstate
adb shell getprop ro.boot.veritymode
```

Now put the property next to the attested value.

| | Says |
|---|---|
| `ro.boot.verifiedbootstate` (normal world, unsigned) | |
| attestation `rootOfTrust.verifiedBootState` (secure world, signed) | |

On target B — a rooted device — these **disagreed**: the property said `green`, the hardware said
`Unverified`, `deviceLocked=false`, with an all-zero `verifiedBootKey`. If your device is not
rooted they will agree, and that agreement is also a result worth recording.

### D.3 — Which list did each field come from?

Look at your parser output again and note which fields appeared under **HARDWARE-ENFORCED** and
which under **SOFTWARE-ENFORCED**. On a real TEE device you should see `rootOfTrust`, `origin`,
`purpose`, `algorithm` and `keySize` in the hardware list, and `creationDateTime` and
`attestationApplicationId` in the software list.

If you ran this on an emulator, you will see something very different: an **empty** hardware list
and everything in the software list. That is [README §3.9.2](../README.md), and it is the shape of
the single most exploited attestation-verifier bug.

---

## Part E — Now measure an *app* (30 minutes, needs root)

Everything so far measured the **device**. The device is only half the comparison.

### E.1 — Pick a target

Any app that stores credentials: a password manager, a banking app, a note-taking app with a "lock"
feature, or — best of all — a deliberately vulnerable app you built from
[`../examples/AssumesHardwareKeyManager.java`](../examples/AssumesHardwareKeyManager.java).

### E.2 — Attach

```bash
# host
frida -U -f com.target.app -l scripts/hook-security-level.js
```

Then **drive the app**. Keys are created lazily: log in, enable the lock feature, enrol a
biometric, open the protected screen. An app you do not exercise will show you nothing, and a blank
log is not a result.

### E.3 — What to extract

| Line in the log | Meaning |
|---|---|
| `ASK new Builder(alias=…, purposes=…)` | A key policy is being declared. Note the alias — it tells you what the key is *for* |
| `ASK .setIsStrongBoxBacked(true)` | The developer thought about hardware |
| `ASK .setUserAuthenticationParameters(N, …)` | `N = 0` is per-use (strong). `N > 0` is a window — write the number down |
| `GOT alias=… SECURITY LEVEL = …` | **The measurement.** Compare against your Part B table |
| `StrongBoxUnavailableException constructed` | Watch the next few lines closely — what does the app do about it? |
| `SecretKeySpec(N bytes, "AES")` | Raw key material in the heap. The Keystore is not involved at all |
| `AUDIT … has NOT read KeyInfo.getSecurityLevel()` | The app has never verified its own hardware claim |

### E.4 — The comparison, which is the whole point

| Device can do (Part B) | App actually got (Part E) | Verdict |
|---|---|---|
| TEE | TEE | Working as intended. Not a finding |
| TEE | SOFTWARE | **Finding.** The app is below the device's capability. Find out why — a broad `catch`? A fallback path? |
| SOFTWARE | SOFTWARE | Device limitation, **not an app defect** — *unless* the app claims otherwise |
| TEE | `SecretKeySpec` in the heap | **Finding, higher severity.** The app is not using the Keystore at all on this path |
| anything | anything, and no `KeyInfo` read anywhere | **Finding.** The hardware claim is unverified |

### E.5 — If you have no root

You cannot run Part E. Do not fake it, and do not substitute the device measurement for the app
measurement — they answer different questions. What you *can* do without root:

- Everything in Parts A–D.
- The static analysis in [README §8.1](../README.md): count `KeyGenParameterSpec` sites against
  `KeyInfo` reads in the decompiled app. Many policies and zero checks is a defensible finding from
  static evidence alone.
- The PIN-change test in [Lab 02](lab-02-gatekeeper-and-the-hat-chain.md), which needs no tooling
  at all and tells you whether the auth binding is real.

State explicitly in your writeup which measurements you performed and which you did not. A gap you
name is methodology; a gap you hide is a false report.

---

## Success criteria

You have completed this lab when you can produce, without looking anything up:

- [ ] The **model, Android version and API level** of the device every number came from.
- [ ] A completed Part B table with a level or an exception in **every** row.
- [ ] The name of the **HAL process** backing the Keystore, and whether it is KeyMint or Keymaster.
- [ ] Whether StrongBox is present, and the exact exception when it is not.
- [ ] At least **one** row where the device's behaviour contradicts a documented expectation, with
      the verbatim exception text.
- [ ] Whether a lock-screen credential exists, and the evidence (`SID` and `CredentialType`).
- [ ] The `attestationSecurityLevel` and `rootOfTrust.verifiedBootState`, and whether the latter
      agrees with `ro.boot.verifiedbootstate`.
- [ ] A one-sentence answer to: *"Is anything here a finding, and against whom — the app, or the
      device?"*

---

## Hints

<details>
<summary>Hint 1 — the probe prints nothing and exits immediately</summary>

Check that the DEX actually reached the device:

```bash
adb shell ls -l /data/local/tmp/ch50-slprobe.dex
```

If the push failed on Windows, it is path conversion — Git Bash rewrites `/data/local/tmp` into a
`C:\` path. The script sets `MSYS_NO_PATHCONV=1` and converts the local path with `cygpath`
specifically to avoid this.
</details>

<details>
<summary>Hint 2 — everything comes back SOFTWARE</summary>

Check what you are attached to before concluding anything:

```bash
adb devices -l
```

If it says `emulator-*`, that is the expected and correct answer for an emulator, and it is not a
result about any real device. Re-run against physical hardware before writing anything down.
</details>

<details>
<summary>Hint 3 — I want to inspect the keys the probe created</summary>

```bash
./scripts/probe-security-levels.sh --keep
```

They stay in the **shell's** namespace under the `ch50_probe_` prefix. Re-run without `--keep` to
delete them, and do delete them — leaving state behind on someone's phone is bad practice even when
that state is harmless.
</details>

<details>
<summary>Hint 4 — the Frida script shows builder calls but never a GOT line</summary>

The app is building a spec but not generating a key — usually because the key already exists from a
previous run. Clear the app's data and try again:

```bash
adb shell pm clear com.target.app
```

this deletes the app's Keystore keys along with everything else, which is exactly what you
want here and is destructive, so only do it on a test install.
</details>

<details>
<summary>Hint 5 — is a SOFTWARE result from the app a finding or not?</summary>

Ask one question: **could this device have done better?** Your Part B table is the answer. If the
device gives TEE keys to the probe and software keys to the app, something in the app chose that —
find it. If the device gives software keys to everything, the app had no choice, and the only
possible finding is a false claim in its documentation.
</details>

---

## What to write up

A finding from this lab should read approximately like this:

> **The application's master key is software-backed on a device capable of hardware backing.**
>
> On <model, Android version, API level>, the device's Keystore returns
> `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` for AES-256/GCM keys (measured directly with
> `KeyInfo.getSecurityLevel()` through `app_process`, no root required). The application's own key
> `<alias>` returns `SECURITY_LEVEL_SOFTWARE` on the same device in the same session. The cause is
> a `catch (Exception)` around the key-generation path that falls back to
> `new SecretKeySpec(...)`; raw key material is consequently present in the application's heap.
>
> The application does not call `KeyInfo.getSecurityLevel()` or `isInsideSecureHardware()` anywhere,
> so it has never detected this on any device.
>
> **Severity: Medium.** The key material is recoverable by an attacker with root or with code
> execution in the process — which would *not* be true of a Keystore-backed key.the
> absence of StrongBox on this device is **not** part of this finding; no device tested has one.

And a *non*-finding should read like this, because writing these down is just as important:

> **StrongBox is unavailable on this device.** All StrongBox key requests throw
> `StrongBoxUnavailableException`. This is a hardware characteristic of the device, shared by the
> large majority of Android devices, and is not a defect in the application. It is recorded here so
> that the application's fallback behaviour (below) can be interpreted correctly.

---

## Next

- [Lab 02 — Gatekeeper and the auth-token chain](lab-02-gatekeeper-and-the-hat-chain.md): why the
  auth-bound row in your table behaves the way it does.
- [Lab 03 — Read an attestation offline](lab-03-attestation-offline.md): take the `chain.pem` from
  Part D apart field by field.
