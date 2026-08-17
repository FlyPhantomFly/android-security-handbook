# 48 — Biometrics · Cheat Sheet

Printable. Tables and commands only. Full reasoning is in [README.md](README.md).

---

## The one test

| Question | If yes | If no |
|---|---|---|
| Did a **cryptographic operation succeed that would otherwise have failed**? | authentication happened | a dialog was displayed |

---

## Authenticator constants

| Constant | Hex | Decimal | Class | Can back a key |
|---|---|---:|---|---|
| `BIOMETRIC_STRONG` | `0x000F` | 15 | 3 | **Yes** |
| `BIOMETRIC_WEAK` | `0x00FF` | 255 | 2 (superset of 3) | No |
| `DEVICE_CREDENTIAL` | `0x8000` | 32768 | — | Time-bound only |
| `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` | `0x800F` | 32783 | — | Rejected with a `CryptoObject` |

## `canAuthenticate()` return codes

| Code | Constant | Note |
|---:|---|---|
| `0` | `BIOMETRIC_SUCCESS` | |
| `1` | `ERROR_HW_UNAVAILABLE` | fail-open trigger |
| `11` | `ERROR_NONE_ENROLLED` | fail-open trigger; easiest to arrange |
| `12` | `ERROR_NO_HARDWARE` | fail-open trigger |
| `15` | `ERROR_SECURITY_UPDATE_REQUIRED` | API 31+; sensor demoted below the requested class |
| `-1` | `BIOMETRIC_STATUS_UNKNOWN` | not an error |
| `-2` | `BIOMETRIC_ERROR_UNSUPPORTED` | bad argument combination |

**`canAuthenticate` answers "can ANY of these succeed?"** Measured on API 35: `BIOMETRIC_STRONG` →
`11` and `BIOMETRIC_STRONG|DEVICE_CREDENTIAL` → `0`, same device, same run. The no-arg API 29 form
equals `BIOMETRIC_WEAK`.

## `onAuthenticationError` codes worth forcing

| Code | Constant |
|---:|---|
| `1` | `ERROR_HW_UNAVAILABLE` |
| `5` | `ERROR_CANCELED` |
| `7` | `ERROR_LOCKOUT` — **attacker-controllable, no tooling** |
| `9` | `ERROR_LOCKOUT_PERMANENT` |
| `10` | `ERROR_USER_CANCELED` |
| `11` | `ERROR_NO_BIOMETRICS` |
| `12` | `ERROR_HW_NOT_PRESENT` |
| `14` | `ERROR_NO_DEVICE_CREDENTIAL` |

---

## Key builder flags

| Method | API | Correct value | Wrong value does |
|---|---:|---|---|
| `setUserAuthenticationRequired(b)` | 23 | `true` | no binding at all |
| `setUserAuthenticationValidityDurationSeconds(n)` | 23, dep. 30 | **omit**, or `-1` | `n > 0` = time-bound |
| `setInvalidatedByBiometricEnrollment(b)` | 24 | `true` | attacker enrols their finger |
| `setUserAuthenticationParameters(t, types)` | 30 | `(0, AUTH_BIOMETRIC_STRONG)` | `t > 0` = time-bound; omitting types admits the PIN |
| `setIsStrongBoxBacked(b)` | 28 | `true` with fallback | throws where unavailable |

## `KeyInfo` read-back

| Reader | Good | Bad |
|---|---|---|
| `isUserAuthenticationRequired()` | `true` | `false` |
| `getUserAuthenticationValidityDurationSeconds()` | `-1` (per-use) | `> 0` (time-bound). Returns `0` when auth not required |
| `isUserAuthenticationRequirementEnforcedBySecureHardware()` | `true` | `false` = framework-only |
| `isInvalidatedByBiometricEnrollment()` | `true` | `false` — **silently `false` on time-bound keys even when `true` was requested** |
| `getUserAuthenticationType()` | `2` = `AUTH_BIOMETRIC_STRONG` | `3` = credential also accepted |
| `getSecurityLevel()` (API 31+) | `1` TEE, `2` STRONGBOX | `0` SOFTWARE, `-1` UNKNOWN |

## Per-use vs time-bound — measured, API 35 emulator

| Window | Cold | After an unrelated `locksettings verify` |
|---|---|---|
| 1 s | refused | refused |
| 30 s | refused | **allowed** |
| 86,400 s | **allowed** | allowed |

A time-bound key is satisfied by any authentication of an accepted type, by **any process**, with no
prompt from the app.

---

## `adb` triage — no root, no Frida

```bash
pm list features | grep -iE 'biometric|fingerprint|face|iris'
dumpsys biometric                      # sensor list, oemStrength/updatedStrength, modality
dumpsys fingerprint                    # JSON: accept vs acceptCrypto, count = enrolments
dumpsys auth
dumpsys trust | grep -o 'deviceLocked=[01]'
lshal 2>/dev/null | grep -iE 'biometric|fingerprint|face'
dumpsys package <pkg> | grep -iE 'USE_BIOMETRIC|USE_FINGERPRINT'
service check android.service.gatekeeper.IGateKeeperService
```

### The counter trick

```bash
dumpsys fingerprint | grep -o '"accept":[0-9]*,.*"acceptCrypto":[0-9]*'
#   ... use the app's biometric unlock ...
dumpsys fingerprint | grep -o '"accept":[0-9]*,.*"acceptCrypto":[0-9]*'
```

| Delta | Verdict |
|---|---|
| `accept` up, `acceptCrypto` flat | callback-only |
| both up | crypto-bound |
| neither up, app unlocked | you forged the callback; nothing authenticated |

### `dumpsys biometric` sensor line

```
ID(0), oemStrength: 15, updatedStrength: 15, modality 2, state: 0
```

| Field | Meaning |
|---|---|
| `oemStrength` / `updatedStrength` | `15` = `0x000F` = Class 3. **Differ = demoted in the field** |
| `modality` | `1` credential, `2` fingerprint, `4` iris, `8` face |

---

## Frida

```bash
frida -U -f <pkg> -l scripts/hook-biometric-prompt.js
frida -U -n <pkg> -l scripts/hook-biometric-prompt.js
```

| REPL | Does |
|---|---|
| `keys()` | every `KeyGenParameterSpec` built, with a verdict |
| `forge()` | fire `onAuthenticationSucceeded` with a null `CryptoObject` |
| `forge(true)` | same with a synthetic `CryptoObject` over an unauthorised `Cipher` |
| `report()` | verdict table |
| `cfg.verbose = true` | stack trace at every prompt call |

### One-liners

```javascript
// callback forgery
Java.choose('<pkg>.LoginActivity$1', {
    onMatch: function (cb) { cb.onAuthenticationSucceeded(null); },
    onComplete: function () {} });

// the boolean, which is usually easier
Java.choose('<pkg>.LoginActivity', {
    onMatch: function (a) { a.unlocked.value = true; },
    onComplete: function () {} });

// force the fail-open branch
Java.use('androidx.biometric.BiometricManager')
    .canAuthenticate.overload('int').implementation = function (a) { return 12; };

// watch the adjudicator
Java.use('javax.crypto.Cipher').init.overload('int', 'java.security.Key')
    .implementation = function (m, k) {
        try { return this.init(m, k); }
        catch (e) { console.log('REFUSED: ' + e); throw e; } };
```

## Objection

```bash
objection -g <pkg> explore
android hooking watch class_method androidx.biometric.BiometricPrompt.authenticate --dump-args
android hooking search classes biometric
android heap search instances androidx.biometric.BiometricPrompt$CryptoObject
```

A successful *hook* is not evidence of *use*. Wait for it to fire.

---

## Device probe

```bash
./scripts/probe-biometrics.sh                 # probe, print, delete every key
./scripts/probe-biometrics.sh --json          # for diffing devices
./scripts/probe-biometrics.sh --keep          # leave keys (lab 02)
ANDROID_SERIAL=<serial> ./scripts/probe-biometrics.sh
```

| Probe limit | Cause | Workaround |
|---|---|---|
| `canAuthenticate` throws `SecurityException` | shell package may lack `USE_BIOMETRIC` | installed APK |
| `Gatekeeper service not available` | `shell` SELinux domain lacks `find` on the service | `adb root`, or an app |
| `At least one biometric must be enrolled` | genuine device state | enrol a fingerprint |
| `NoSuchProviderException: AndroidKeyStore` | `app_process` does not install the JCA provider | `AndroidKeyStoreProvider.install()` |

---

## Static

```bash
python3 -B scripts/grade-biometric-usage.py <tree> --show-evidence
python3 -B scripts/grade-biometric-usage.py <tree> --json
python3 -B scripts/grade-biometric-usage.py <tree> --min-grade C
python3 -B scripts/grade-biometric-usage.py <tree> --keep-comments    # reproduce the bug
```

| Grade | Meaning |
|---|---|
| **A** | per-use `CryptoObject` binding |
| **B** | time-bound binding |
| **C** | `CryptoObject` present, binding unproven / unresolved constant |
| **D** | callback-only |
| **F** | `FingerprintManager`, self-drawn dialog, no `CryptoObject` |

**The worst grade in the tree is the finding.**

### Greps

```bash
grep -rn "androidx.biometric" .
grep -rn "\.authenticate("  .                     # ONE argument or TWO
grep -rn "setUserAuthenticationRequired" .
grep -rn "setUserAuthenticationValidityDurationSeconds" .    # READ THE ARGUMENT
grep -rn "setInvalidatedByBiometricEnrollment" .
grep -rn "BIOMETRIC_STRONG\|BIOMETRIC_WEAK\|DEVICE_CREDENTIAL" .
grep -rn -A6  "canAuthenticate" . | grep -nE "true|unlock|proceed"
grep -rn -A12 "onAuthenticationError" . | grep -nE "true|unlock|proceed"
grep -rn -A15 "KeyPermanentlyInvalidatedException" . | grep -nE "generateKey|createKey"
```

### Smali descriptors — the unambiguous check

```smali
# NO binding
->authenticate(Landroidx/biometric/BiometricPrompt$PromptInfo;)V

# binding attempted
->authenticate(Landroidx/biometric/BiometricPrompt$PromptInfo;Landroidx/biometric/BiometricPrompt$CryptoObject;)V

# the key
->setUserAuthenticationRequired(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;
->setUserAuthenticationValidityDurationSeconds(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;
->setUserAuthenticationParameters(II)Landroid/security/keystore/KeyGenParameterSpec$Builder;
->setInvalidatedByBiometricEnrollment(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;
```

### Constants to recognise on sight

| Hex | Decimal | Is |
|---|---:|---|
| `0xf` | 15 | `BIOMETRIC_STRONG` |
| `0xff` | 255 | `BIOMETRIC_WEAK` |
| `0x8000` | 32768 | `DEVICE_CREDENTIAL` |
| `0xe10` | 3600 | one hour |
| `0x15180` | 86400 | one day |
| `-0x1` | −1 | per-use sentinel |

---

## Structural tells

| See this | Means |
|---|---|
| Real work inside the `try` around `Cipher.init` | key is **time-bound** (per-use always throws) |
| `AuthenticationResult` parameter never referenced | callback-only |
| `doFinal` on a cipher from a **field**, not from `result` | forged callback still wins |
| `generateKey` inside a `catch (KeyPermanentlyInvalidatedException)` | silent re-enrolment recovery |
| `canAuthenticate` result OR-ed with `DEVICE_CREDENTIAL` then read as "has biometrics" | measured false positive |

---

## Vulnerability → severity

| Vulnerability | Precondition | Typical severity |
|---|---|---|
| Callback-only, over data already readable | code execution | **Low / Informational** |
| Callback-only, over a token encrypted at rest | code execution | **High** |
| Fail-open on `canAuthenticate` | **none** | **High** |
| Fail-open on `ERROR_LOCKOUT` | **none** | **High** |
| Time-bound key, long window | device unlocked | **Medium** (High if stolen-device model) |
| Silent re-enrolment recovery | device credential | **Medium/High** |
| Correct binding, plaintext copy elsewhere | root / `run-as` | **High** — biometric is a *pass* |

---

## Ten-minute checklist

1. `dumpsys fingerprint` — note `accept` / `acceptCrypto`
2. `pm list features`, `dumpsys biometric` — what hardware, what class
3. `grade-biometric-usage.py` — static grade
4. Frida, pass 1 — one argument or two
5. `forge()` — does the UI open
6. **Read pass 3** — did any crypto run
7. `dumpsys fingerprint` again — did `acceptCrypto` move
8. Severity from **what you actually reached**

---

## Boundaries

| Topic | Chapter |
|---|---|
| Key material, KeyStore API | [49](../49-KeyStore/README.md) |
| TEE vs StrongBox, Gatekeeper→HAT, attestation, `verifiedbootstate` | [50](../50-HardwareBackedSecurity/README.md) |
| Credentials, sessions, MFA, account flows | [47](../47-Authentication/README.md) |
| Storage of what the gate protects | [33](../33-Storage/README.md) |
| Root / tamper detection | [37](../37-RootDetection/README.md), [38](../38-TamperDetection/README.md) |
| Bypass methodology | [67](../67-BypassingProtections/README.md) |
