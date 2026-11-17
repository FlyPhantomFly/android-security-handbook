# 48 — Biometrics · References

Annotated. Each entry says what it is *for*, because the biometric literature is unusually
repetitive and most of it answers a question you did not ask.

---

## 1. AOSP source

Paths are stable across releases; line numbers are not, and none are quoted anywhere in this
chapter. Browse at `cs.android.com` or in a local checkout.

### Public API

| Path | Read it for |
|---|---|
| `frameworks/base/core/java/android/hardware/biometrics/BiometricPrompt.java` | The `authenticate()` overloads, `PromptInfo.Builder`, the nested `CryptoObject` and `AuthenticationCallback`. The difference between the one- and two-argument overloads is the whole chapter |
| `frameworks/base/core/java/android/hardware/biometrics/BiometricManager.java` | `canAuthenticate()` and the nested `Authenticators` interface where `BIOMETRIC_STRONG`/`_WEAK`/`DEVICE_CREDENTIAL` are defined. The bit patterns are worth reading directly |
| `frameworks/base/core/java/android/hardware/biometrics/BiometricAuthenticator.java` | The `TYPE_*` modality flags. `dumpsys biometric`'s `modality 2` / `modality 8` decode from here |
| `frameworks/base/core/java/android/hardware/biometrics/IAuthService.aidl` | The Binder interface an app actually crosses |
| `frameworks/base/core/java/android/hardware/fingerprint/FingerprintManager.java` | The deprecated API 23 path, still shipped in real apps as a `minSdk` fallback |

### Framework services

| Path | Read it for |
|---|---|
| `frameworks/base/services/core/java/com/android/server/biometrics/AuthService.java` | Permission enforcement. This is the class whose `checkPermission` refused this chapter's shell-uid probe with `Must have USE_BIOMETRIC permission` |
| `frameworks/base/services/core/java/com/android/server/biometrics/BiometricService.java` | Modality selection and the session state machine |
| `frameworks/base/services/core/java/com/android/server/biometrics/Utils.java` | The authenticator-strength arithmetic — the containment test the bitmasks were designed for, and where `oemStrength` and `updatedStrength` are reconciled |
| `frameworks/base/services/core/java/com/android/server/biometrics/sensors/fingerprint/FingerprintService.java` | The dump path that produces `dumpsys fingerprint`'s JSON, including the `acceptCrypto` counters this chapter leans on |
| `frameworks/base/services/core/java/com/android/server/biometrics/sensors/face/FaceService.java` | The face equivalent |
| `frameworks/base/services/core/java/com/android/server/locksettings/LockSettingsService.java` | What `locksettings verify` reaches, and therefore what satisfied the 30-second key in §3.6 |

### Keys

| Path | Read it for |
|---|---|
| `frameworks/base/core/java/android/security/keystore/KeyGenParameterSpec.java` | Every flag in §3.5, and the javadoc describing how `setInvalidatedByBiometricEnrollment` interacts with a validity duration — which is what this chapter measured |
| `frameworks/base/core/java/android/security/keystore/KeyInfo.java` | The read-back that catches a discarded flag. `isUserAuthenticationRequirementEnforcedBySecureHardware()` is the important one |
| `frameworks/base/core/java/android/security/keystore/KeyProperties.java` | `AUTH_BIOMETRIC_STRONG` (`2`) and `AUTH_DEVICE_CREDENTIAL` (`1`) |
| `frameworks/base/core/java/android/security/keystore/UserNotAuthenticatedException.java` | The throw that means the system is working |
| `frameworks/base/core/java/android/security/GateKeeper.java` | `getSecureUserId()` — the call behind `IllegalStateException: Gatekeeper service not available` |
| `system/security/keystore2/src/` | The Rust `keystore2` daemon (API 31+). Where the KeyMint error code becomes a Java exception |

### HALs

| Path | Read it for |
|---|---|
| `hardware/interfaces/biometrics/fingerprint/aidl/` | The modern AIDL fingerprint HAL. **The `operationId` parameter on `authenticate()` is the mechanism of per-use binding** |
| `hardware/interfaces/biometrics/fingerprint/2.1/IBiometricsFingerprint.hal` | The legacy HIDL 2.1 interface — what the Redmi used for this chapter's measurements |
| `hardware/interfaces/biometrics/face/aidl/` | The face equivalent |
| `hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/HardwareAuthToken.aidl` | The token structure: challenge, user secure id, authenticator id, authenticator type, timestamp, MAC |
| `hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl` | `NO_AUTH_REQUIRED`, `USER_SECURE_ID`, `USER_AUTH_TYPE`, `AUTH_TIMEOUT` — the four tags that decide everything in §3.5 |
| `hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/ErrorCode.aidl` | `KEY_USER_NOT_AUTHENTICATED` |
| `hardware/interfaces/gatekeeper/1.0/IGatekeeper.hal` | The credential side. [50](../../50-HardwareBackedSecurity/README.md) owns this |

### AndroidX

The `biometric` module in the AndroidX repository (`frameworks/support`). Read `BiometricPrompt.java`
for the argument validation the platform class does not do — including the rejection of a
`CryptoObject` combined with `DEVICE_CREDENTIAL` — and `BiometricFragment.java` for the dialog it
draws on API 23–27, where no system dialog existed.

---

## 2. Official documentation

| Source | Why |
|---|---|
| Android Developers — *Biometric authentication* guide | The canonical starting point.its simplest sample uses the one-argument `authenticate()`, which is a large part of why the modal implementation is callback-only |
| Android Developers — `androidx.biometric` reference | Version fragmentation lives here. Check which release introduced `setAllowedAuthenticators` before reasoning about an app's bundled version |
| Android Developers — `KeyGenParameterSpec` reference | **The most important documentation page for this chapter.** Read the interaction between `setUserAuthenticationRequired`, `setUserAuthenticationValidityDurationSeconds`, `setUserAuthenticationParameters` and `setInvalidatedByBiometricEnrollment` closely |
| Android Developers — `KeyInfo` reference | The read-back API almost nobody calls |
| AOSP — *Security > Authentication* | Gatekeeper, biometrics, and the auth-token flow, from the platform's own perspective |
| AOSP — *Security > Biometrics* | Measurement methodology for SAR/IAR and the HAL architecture |
| **Android Compatibility Definition Document, §7.3.10 Biometric Sensors** | **Normative.** The definition of Class 1/2/3 and the numeric acceptance thresholds. Read the CDD for the exact Android version under test — the class structure is stable, the numbers are revised between releases |
| Android Security Bulletin | The authoritative, searchable index of biometric CVEs by component and month. Look identifiers up here; do not quote them from memory |

---

## 3. OWASP

| Identifier | Requirement | Where this chapter meets it |
|---|---|---|
| **MASVS-AUTH-2** | Local authentication is performed securely | §3.4, §5.3 V1 |
| **MASVS-AUTH-3** | Biometric authentication is bound to a cryptographic operation and is not event-bound | §3.4–§3.6 — the spine |
| **MASVS-CRYPTO-1** | Key management follows best practice | §3.5, and [49](../../49-KeyStore/README.md) |
| **MASVS-STORAGE-1** | Sensitive data is not stored unprotected | §5.3 V1's severity table; CTF flag 4 |
| MASTG | *Testing Biometric Authentication (Android)*, *Testing Local Authentication* | §7's three passes map onto these directly |

> **MASVS-AUTH-3 is one of the most commonly mis-passed requirements in the standard.** It is
> routinely marked satisfied on the strength of a screenshot of a fingerprint dialog. Attach the
> `KEYSPEC` line from `hook-biometric-prompt.js`, or the `acceptCrypto` counter delta, or attach
> nothing.

---

## 4. RFCs and standards

| Reference | Relevance |
|---|---|
| **RFC 2606** | Reserves `.invalid`. Every network endpoint in this chapter's example code uses it, so nothing can accidentally resolve |
| **NIST SP 800-63B** | Digital identity guidelines. Its treatment of biometrics as *something you are, bound to something you have* is the framing behind §9.3's signed-challenge pattern |
| **FIDO2 / WebAuthn** | The same architecture — per-use hardware-bound key, server-issued challenge, signature — standardised for the web. If §9.3 looks familiar, this is why |
| **ISO/IEC 30107** | Presentation attack detection. The vocabulary behind the CDD's SAR/IAR thresholds |

---

## 5. Research and talks

Fixed citation lists date badly. These searches do not:

| Search | What you will find |
|---|---|
| `"Android biometric bypass CryptoObject"` | The technique in §5.3 V1, published many times. Note how many stop at pass 2 |
| `"Android keystore auth-bound key"` | The key-side literature; overlaps [49](../../49-KeyStore/README.md) and [50](../../50-HardwareBackedSecurity/README.md) |
| `"setUserAuthenticationValidityDurationSeconds"` | Far less written than it deserves, which is why §3.6 was measured rather than cited |
| `"presentation attack detection Android CDD"` | The §5.6 material |
| `"BiometricPrompt setAllowedAuthenticators DEVICE_CREDENTIAL CryptoObject"` | Developers hitting the rejection in §3.4, and the wrong fixes they apply |

Conference tracks that carry this material: Black Hat and DEF CON mobile tracks, Objective by the
Sea (OBTS), the Android Security Symposium, and OWASP AppSec.

---

## 6. This chapter's artefacts

| File | What it is | Verified by |
|---|---|---|
| [`../scripts/probe-biometrics.sh`](../scripts/probe-biometrics.sh) | Build, push, run, clean up. No root, no APK, no Gradle | Run on both devices in the table below |
| [`../scripts/BiometricProbe.java`](../scripts/BiometricProbe.java) | Features, `canAuthenticate` × 6, six key configurations, `KeyInfo` read-back, cleanup by prefix filter | Same |
| [`../scripts/hook-biometric-prompt.js`](../scripts/hook-biometric-prompt.js) | Three-pass Frida script: observe, forge, adjudicate | `node --check`; hook set designed against frida 16.1.6 |
| [`../scripts/grade-biometric-usage.py`](../scripts/grade-biometric-usage.py) | Static grader A–F, with comment stripping and constant resolution | Graded `../examples/` correctly (D/B/A) after two documented failures |
| [`../examples/01-CallbackOnlyVault.java`](../examples/01-CallbackOnlyVault.java) | Grade D, deliberately vulnerable, eight numbered mistakes | Grader |
| [`../examples/02-CryptoBoundVault.java`](../examples/02-CryptoBoundVault.java) | Grade A, twelve numbered fixes | Grader |
| [`../examples/03-TimeBoundTrap.kt`](../examples/03-TimeBoundTrap.kt) | Grade B — the one that passes review | Grader |
| [`../labs/lab-01-callback-vs-crypto.md`](../labs/lab-01-callback-vs-crypto.md) | One attack, two apps | — |
| [`../labs/lab-02-auth-bound-keys.md`](../labs/lab-02-auth-bound-keys.md) | Reproduce the 1s/30s/86400s measurement | — |
| [`../labs/lab-03-audit-a-real-app.md`](../labs/lab-03-audit-a-real-app.md) | Full method, with a measured 38-app sweep | — |
| [`../labs/lab-04-ctf-the-fifth-finger.md`](../labs/lab-04-ctf-the-fifth-finger.md) | CTF, four flags, two needing no tooling | Flags decoded and verified |

### Devices these measurements came from

| | Physical | Emulator |
|---|---|---|
| Model | Redmi `M2101K6P` (`sweetin`), MIUI 12.5 | `sdk_gphone16k_x86_64` |
| Release / API | Android 11 / API 30 | Android 15 / API 35 |
| Security patch | 2021-12-01 | 2024-09-05 |
| Root | yes (Magisk/APatch), frida-server 16.1.6 | `adb root` |
| Fingerprint HAL | `android.hardware.biometrics.fingerprint@2.1` (HIDL) | simulated |
| Keymaster / KeyMint | `android.hardware.keymaster@4.0` | software |
| Face exposed to apps | **no** | yes |
| `dumpsys biometric` | **empty** | works |
| `USE_BIOMETRIC` for shell | **no** | yes |
| Keystore level | TEE, no StrongBox | `SOFTWARE` |

**Two devices, and they disagree about six of those rows.** Record which one produced any figure you
repeat.

---

## 7. Related chapters

| Chapter | Boundary — who owns what |
|---|---|
| [33 — Storage](../../33-Storage/README.md) | What the gate protects. Its WAL and world-readable-file findings are frequently the *real* finding behind a "biometric bypass" |
| [34 — Cryptography](../../34-Cryptography/README.md) | AES-GCM, AEAD tag failure — the second, independent refusal in lab 01's outcome B |
| [37 — Root Detection](../../37-RootDetection/README.md) | Anti-tamper controls. This chapter does not restate them |
| [38 — Tamper Detection](../../38-TamperDetection/README.md) | Repackaging and integrity. Its split-APK and 18-of-18 detector findings both apply to §8 here |
| [46 — Tokens](../../46-Tokens/README.md) | What is behind the gate, and the server-side half of §9.3 |
| [47 — Authentication](../../47-Authentication/README.md) | **Owns** credential handling, session lifecycle, MFA and account flows. It links here for the biometric prompt and crypto binding; this chapter does not duplicate its session material |
| [49 — KeyStore](../../49-KeyStore/README.md) | **Owns** key material and the KeyStore API surface. Its §3.5.3 and §7.5 are the key-side view of §3.4 here; its faq points here for the prompt-bypass technique |
| [50 — Hardware-Backed Security](../../50-HardwareBackedSecurity/README.md) | **Owns** TEE vs StrongBox, the Gatekeeper→HAT chain, key attestation, and `ro.boot.verifiedbootstate`. Its §3.7 is the token this chapter's prompt causes to be minted. Its `probe-security-levels.sh` and the `AndroidKeyStoreProvider.install()` requirement are reused here rather than re-derived |
| [51 — Dynamic Analysis](../../51-DynamicAnalysis/README.md) | Liveness checks before silence means anything — directly applicable to §7's `INCONCLUSIVE` verdict |
| [52 — Static Analysis](../../52-StaticAnalysis/README.md) | The funnel discipline behind §8.3a's 38-app sweep |
| [53 — Frida](../../53-Frida/README.md) | The instrumentation §7 rests on |
| [54 — Objection](../../54-Objection/README.md) | Its measured caution — a successful hook message proves a hook installed, not that the app does the thing — applies verbatim to §7.5 |
| [55 — MobSF](../../55-MobSF/README.md) | Where MobSF's biometric flag sits in the funnel: it answers question 1 and never questions 2 or 3 |
| [56 — JADX](../../56-JADX/README.md) | Its 30× under-reporting of decompilation failures is why §2.3 of lab 03 counts the tree, not the console |
| [60 — ADB](../../60-ADB/README.md) | The `run-as` refusal taxonomy used in lab 03 §5 and CTF flag 4 |
| [67 — Bypassing Protections](../../67-BypassingProtections/README.md) | **Owns** the bypass methodology. This chapter supplies one seam within it |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | MASVS-AUTH placement |
| [79 — Glossary](../../79-Glossary/README.md) | Terms defined once, across the repository |
