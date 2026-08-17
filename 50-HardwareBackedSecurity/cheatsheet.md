# 50 — Hardware-Backed Security — Cheat Sheet

Dense reference. Prose lives in [README.md](README.md).

---

## 1. The security-level capability matrix

| | SOFTWARE (0) | TRUSTED_ENVIRONMENT (1) | STRONGBOX (2) |
|---|---|---|---|
| Constant | `KeyProperties.SECURITY_LEVEL_SOFTWARE` | `..._TRUSTED_ENVIRONMENT` | `..._STRONGBOX` |
| Where key material lives in use | Android kernel memory | Secure-world RAM, same SoC | RAM inside a separate chip |
| Where at rest | Encrypted under a lock-screen-derived key | Encrypted under a HUK-derived key | Encrypted, often in the element's own flash |
| Survives root | **No** | Yes (extraction) | Yes (extraction) |
| Survives kernel compromise | No | Yes (extraction) | Yes (extraction) |
| Survives TEE compromise | No | **No** | Yes |
| Survives physical attack on the SoC | No | Usually not | Designed to resist |
| Prevents *use* by in-process code | No | **No** | **No** |
| Rate limiting enforced by | nothing | TEE secure timer | element's own clock |
| Typical availability | all devices | nearly all since ~2015 | small minority |
| Speed | fastest | slower (world switch) | much slower (serial bus) |
| Typical limits | none | generous | RSA often capped at 2048; limited slots |
| Requested by | default | default | `setIsStrongBoxBacked(true)` |
| Failure mode when absent | n/a | n/a | `StrongBoxUnavailableException` |

Also possible from `getSecurityLevel()`:

| Value | Constant | Read as |
|---|---|---|
| `-1` | `SECURITY_LEVEL_UNKNOWN` | treat as software; usually a legacy Keymaster |
| `-2` | `SECURITY_LEVEL_UNKNOWN_SECURE` | secure, level unreported; acceptable |

---

## 2. Determine each capability on a device

| Question | Command |
|---|---|
| Which device (**do this first, every time**) | `adb devices -l && adb shell getprop ro.product.model && adb shell getprop ro.build.version.sdk` |
| StrongBox declared? | `adb shell pm list features \| grep strongbox_keystore` |
| KeyMint/Keymaster version (API 31+) | `adb shell pm list features \| grep hardware_keystore` |
| Which HAL is running? | `adb shell 'ps -A -o NAME' \| grep -iE 'keymaster\|keymint\|keystore\|gatekeeper'` |
| Which HAL is declared? | `adb shell lshal \| grep -iE 'keymaster\|keymint\|gatekeeper'` |
| Keystore daemon generation | `adb shell service list \| grep -i keystore` — `android.system.keystore2.IKeystoreService` = keystore2; `android.security.keystore` = legacy |
| Legacy HAL behind keystore2? | presence of `android.security.compat` in `service list` |
| Which TEE OS? | `adb shell getprop ro.hardware.gatekeeper`, plus the HAL process suffix (`-qti`, `.beanpod`, …) |
| Lock-screen credential set? | `adb shell dumpsys lock_settings \| grep -E 'SID\|CredentialType\|Quality'` |
| Verified boot, per the **normal world** (untrustworthy) | `adb shell getprop ro.boot.verifiedbootstate` |
| Verified boot, per the **hardware** (trustworthy) | attestation `rootOfTrust.verifiedBootState`, hardware-enforced list |
| SELinux state | `adb shell getenforce` |
| Security patch levels | `adb shell getprop ro.build.version.security_patch`, `ro.vendor.build.security_patch` |
| **What a key actually gets** | `./scripts/probe-security-levels.sh` |
| What *an app's* key gets | `frida -U -f <pkg> -l scripts/hook-security-level.js` |

### Feature-flag value encoding

| Value of `android.hardware.hardware_keystore` | Means |
|---|---|
| `41` | Keymaster 4.1 |
| `100` | KeyMint 1.0 |
| `200` | KeyMint 2.0 |
| `300` | KeyMint 3.0 |
| absent | **nothing** below API 31 — the constant did not exist |

---

## 3. The scripts

| Script | Root? | App? | Does |
|---|---|---|---|
| [`scripts/hw-security-inventory.sh`](scripts/hw-security-inventory.sh) | no | no | Read-only posture: HAL, TEE, StrongBox, Gatekeeper, credential state, boot props |
| [`scripts/probe-security-levels.sh`](scripts/probe-security-levels.sh) | **no** | **no** | Builds+pushes `SecurityLevelProbe.java`, runs it via `app_process`, prints the real level per algorithm |
| [`scripts/SecurityLevelProbe.java`](scripts/SecurityLevelProbe.java) | no | no | The probe itself. `--attest`, `--keep`, `--prefix`, `--wait` |
| [`scripts/parse-attestation.py`](scripts/parse-attestation.py) | n/a | n/a | Offline chain parse + real ECDSA/RSA verification, pure stdlib. `--json`, `--expect-challenge` |
| [`scripts/hook-security-level.js`](scripts/hook-security-level.js) | **yes** | yes | Frida: every builder option asked for, versus the level actually got |
| [`examples/hardware_posture_policy.py`](examples/hardware_posture_policy.py) | n/a | n/a | Turns parsed JSON into a trust TIER with reasons |

```bash
# the whole device-side workflow, no root
./scripts/hw-security-inventory.sh
./scripts/probe-security-levels.sh
./scripts/probe-security-levels.sh --attest | sed -n '/BEGIN CHAIN/,/END CHAIN/p' > chain.pem
python3 -B ./scripts/parse-attestation.py chain.pem
python3 -B ./scripts/parse-attestation.py chain.pem --json > parsed.json
python3 -B ./examples/hardware_posture_policy.py parsed.json
```

---

## 4. Measured results (record the device with every number)

| Key requested | A `i9000S` API 33 MediaTek | B Redmi `M2101K6P` API 30 Qualcomm | C emulator API 35 |
|---|---|---|---|
| AES-128 / AES-256 GCM | TEE | TEE | **SOFTWARE** |
| AES + StrongBox | `StrongBoxUnavailableException` | `StrongBoxUnavailableException` | `StrongBoxUnavailableException` |
| HMAC-SHA256 / SHA512 | TEE | TEE | SOFTWARE |
| 3DES | `NoSuchAlgorithmException` | TEE (168) | `NoSuchAlgorithmException` |
| RSA 2048 / 3072 / 4096 | not measured | TEE | SOFTWARE |
| RSA 1024 | not measured | **TEE — accepted** | SOFTWARE — accepted |
| EC P-256 / P-384 / P-521 | not measured | TEE | SOFTWARE |
| Ed25519 / X25519 | not measured | unsupported curve | partial / agreement only |
| `setMaxUsageCount(1)` | not measured | **`NoSuchMethodError`** | accepted |
| auth-bound per-use | not measured | `IllegalStateException: Gatekeeper service not available` | same |
| Attestation chain | not measured | 4 certs → Google root, `TrustedEnvironment` | 3 certs → `Google Test LLC`, `Software` |
| Backing HAL | `keymaster@4.1-service.beanpod` | `keymaster@4.0-service-qti` | software KeyMint 3.0 |

Target A vanished mid-session and was replaced by target B. **Identify the device before every measurement.**

---

## 5. Gatekeeper and the hardware auth token

### Objects

| Object | Lives | Contains |
|---|---|---|
| Password handle | `/data/system_de/<user>/spblob/`, framework side | version, SID, flags, salt, `HMAC(K_gk, salt‖SID‖password)` |
| `K_gk` | **secure world only** | the key that makes the handle unforgeable and un-brute-forceable |
| `K_shared` | **secure world only** | shared by Gatekeeper, the biometric TA and KeyMint; signs the HAT |
| SID (Secure User ID) | in the handle and in keys | identifies one credential *enrolment*; changes on every credential change |
| HAT | passed framework→KeyMint | version, challenge, userId(SID), authenticatorId, authenticatorType, timestamp, HMAC |

### HAT fields

| Field | Bytes | Meaning |
|---|---|---|
| `version` | 1 | format version |
| `challenge` | 8 | operation handle, for per-use binding |
| `userId` | 8 | SID |
| `authenticatorId` | 8 | biometric enrolment set |
| `authenticatorType` | 4 BE | 0 none, 1 password/credential, 2 fingerprint |
| `timestamp` | 8 BE | ms since boot, **secure timer** |
| `hmac` | 32 | HMAC-SHA256 under `K_shared` |

### What root can and cannot do

| Can | Cannot |
|---|---|
| Suppress a HAT (denial of service) | Mint a HAT |
| Replay a HAT inside its window | Alter a HAT's SID or timestamp |
| Fake the *UI* result of a prompt | Satisfy a per-use binding without real authentication |
| Use any key that is not auth-bound | Make KeyMint skip `Tag::USER_SECURE_ID` |
| Rewrite `ro.boot.verifiedbootstate` | Change `rootOfTrust` in an attestation |

### Reading credential state

```bash
adb shell dumpsys lock_settings | grep -E 'SID|CredentialType|Quality|Last changed'
```

| Output | Means |
|---|---|
| `SID: 0`, `CredentialType: None` | No credential. **No auth-bound key can be created** |
| `SID: <nonzero>` | A credential exists; that value is this enrolment's identity |
| `Last changed: …` | When the credential last changed — every key bound to the old SID died then |

### Auth binding forms

| Form | Code | Strength |
|---|---|---|
| Per-use | `setUserAuthenticationParameters(0, type)` | **Strongest.** HAT names one operation handle |
| Per-use (legacy) | `setUserAuthenticationValidityDurationSeconds(-1)` | Same, deprecated at API 30 |
| Time window | `setUserAuthenticationParameters(N, type)` | Any code in the process may use the key freely for N seconds after any unlock |
| None | omit `setUserAuthenticationRequired` | `noAuthRequired` in the attestation |

**Zero-tooling test:** change the PIN. Key dies (`KeyPermanentlyInvalidatedException`) → bound. Feature keeps working → not bound.

---

## 6. Attestation

### Extension

`1.3.6.1.4.1.11129.2.1.17`, in the **leaf** certificate.

| Field | Read as |
|---|---|
| `attestationVersion` | schema; 3 = Keymaster era, 100/200/300 = KeyMint 1/2/3 |
| `attestationSecurityLevel` | **where the STATEMENT was made.** `Software` ⇒ worthless |
| `keymasterVersion` | implementation version |
| `keymasterSecurityLevel` | **where the KEY lives** |
| `attestationChallenge` | must equal the nonce you issued, single-use |
| `uniqueId` | usually empty for third-party apps |
| `softwareEnforced` | asserted by Android. **Never trust for a security decision** |
| `hardwareEnforced` | asserted by the secure world. **Only this list counts** |

### RootOfTrust

| Field | Read as |
|---|---|
| `verifiedBootKey` | digest of the key that verified boot; all zeros = none |
| `deviceLocked` | bootloader lock state |
| `verifiedBootState` | `Verified`(0) `SelfSigned`(1) `Unverified`(2) `Failed`(3) |
| `verifiedBootHash` | digest of the verified boot state |

### Enum traps

| Enum | Values |
|---|---|
| `KeyPurpose` (in the attestation) | ENCRYPT 0, DECRYPT 1, SIGN 2, VERIFY 3, DERIVE_KEY 4, AGREE_KEY 5, ATTEST_KEY 6 |
| `KeyProperties.PURPOSE_*` (in Java) | ENCRYPT 1, DECRYPT 2, SIGN 4, VERIFY 8, WRAP 32, AGREE 64, ATTEST 128 |
| `Algorithm` | RSA 1, EC 3, AES 32, TRIPLE_DES 33, HMAC 128 |
| `Digest` | NONE 0, MD5 1, SHA1 2, SHA-224 3, SHA-256 4, SHA-384 5, SHA-512 6 |
| `Padding` | NONE 1, RSA_OAEP 2, RSA_PSS 3, PKCS1_ENCRYPT 4, PKCS1_SIGN 5, PKCS7 64 |
| `EcCurve` | P-224 0, P-256 1, P-384 2, P-521 3, CURVE_25519 4 |
| `Origin` | GENERATED 0, DERIVED 1, IMPORTED 2, UNKNOWN 3, SECURELY_IMPORTED 4 |

**Never decode the attestation's `purpose` with the Java constants.** They differ by one and the output looks plausible.

### Emulator tells (any one is enough)

1. `attestationSecurityLevel: Software`
2. `hardwareEnforced` list **empty**
3. Root is `O=Google Test LLC, CN=Droid Unregistered Device CA`

### Verifier review checklist

| Check | Bug if wrong |
|---|---|
| Reads `hardwareEnforced` only | merged dict ⇒ emulator supplies `rootOfTrust` |
| Pins the **root**, not an intermediate | breaks under RKP, then gets disabled |
| Challenge server-issued, single-use, consumed | replay |
| `attestationSecurityLevel` ∈ {TrustedEnvironment, StrongBox} | emulator accepted |
| `rootOfTrust.verifiedBootState == Verified` and `deviceLocked` | rooted device accepted |
| `attestationApplicationId` matched to package **and** signer | repackaged app accepted |
| `osPatchLevel` ≥ minimum | stale device accepted |
| Attested key **bound to the account and used for later requests** | attestation was a one-off ceremony |

---

## 7. Key builder options that matter here

| Option | Min API | Hardware-enforced? | Finding when |
|---|---|---|---|
| `setIsStrongBoxBacked(true)` | 28 | yes | fallback catches `Exception`, not `StrongBoxUnavailableException` |
| `setUserAuthenticationRequired(true)` | 23 | yes | absent on a key that gates a transaction |
| `setUserAuthenticationParameters(t, type)` | 30 | yes | `t > 0` on a sensitive key |
| `setInvalidatedByBiometricEnrollment(false)` | 24 | yes | explicit `false` |
| `setUnlockedDeviceRequired(true)` | 28 | framework-signalled | absence is a hardening note only |
| `setRandomizedEncryptionRequired(false)` | 23 | yes | explicit `false` — IV reuse |
| `setMaxUsageCount(N)` | 30 | yes, where supported | **`NoSuchMethodError` measured on an API 30 device** |
| `setAttestationChallenge(b)` | 24 | n/a | constant challenge |
| rollback resistance | — | yes, where supported | `@hide`; assume absent |

---

## 8. Static-analysis one-liners

```bash
grep -rn "AndroidKeyStore" out/sources/                       # uses the Keystore at all?
grep -rn "KeyGenParameterSpec" out/sources/       | wc -l      # how many key policies
grep -rn "getSecurityLevel\|isInsideSecureHardware" out/sources/ | wc -l   # how many checks
grep -rn "setIsStrongBoxBacked" out/sources/                  # asks for the element?
grep -rn "SecretKeySpec" out/sources/                         # raw key bytes in the heap
grep -rn "1\.3\.6\.1\.4\.1\.11129\.2\.1\.17" out/             # local attestation parsing
grep -rn "verifiedbootstate\|flash.locked\|SystemProperties" out/sources/  # spoofable checks
grep -rn "CryptoObject" out/sources/                          # is the prompt bound?
apktool d app.apk -o s && grep -rn "setIsStrongBoxBacked\|setUserAuthenticationParameters" s/smali*/
```

**Policies ≫ checks is the finding.** Many `KeyGenParameterSpec`, zero `KeyInfo` = an unverified hardware claim.

---

## 9. Severity language

| Observation | Severity |
|---|---|
| Device has no StrongBox | **Not a finding.** Hardware fact |
| Device gives software keys and the app never claimed otherwise | **Not a finding.** Device limitation |
| App claims hardware backing and never reads `KeyInfo` | Low; Medium–High if a control or a public claim rests on it |
| App falls back to `SecretKeySpec` on any exception | **Medium–High** |
| Fallback drops the auth binding | **Medium–High** |
| Biometric prompt with no `CryptoObject` on a sensitive action | **Medium–High** |
| Attestation verified on-device only | Info as design; **High** if the server trusts the client verdict |
| Constant attestation challenge | **High** |
| Server merges software/hardware lists | **High** |
| Server pins an intermediate | Medium (reliability that becomes security) |
| Frida hook of a Keystore key on your own rooted device | **Informational** — that is *use*, not extraction |

---

## 10. Failure messages, decoded

| Message | Cause |
|---|---|
| `StrongBoxUnavailableException` | No secure element. Normal on most devices |
| `AndroidKeyStore KeyStore not available` | JCA provider not installed — you are in `app_process`; call `AndroidKeyStoreProvider.install()` |
| `Failed to obtain application Context from ActivityThread` | Legacy provider (API ≤ 30) with no Application — bootstrap with `ActivityThread.systemMain()` |
| `IllegalStateException: Gatekeeper service not available` | Either no lock-screen credential (SID 0), or the caller's domain cannot see `IGateKeeperService`. `dumpsys lock_settings` settles it |
| `NoSuchAlgorithmException: no such algorithm: DESede` | This device's Keystore has no 3DES. Support is per-device |
| `InvalidAlgorithmParameterException: Unsupported EC curve name: ed25519` | Curve not implemented; the message lists the supported set |
| `NoSuchMethodError: … setMaxUsageCount` | The method is missing from this device's framework at its documented API level |
| `UserNotAuthenticatedException` | KeyMint refused at `begin()`: no valid HAT |
| `KeyPermanentlyInvalidatedException` | SID changed (credential change) or biometric enrolment changed. **Evidence the binding is real** |

---

## 11. Quick recall

- Unreadable by any software, ever → **the HUK**.
- TEE survives → **Android, root included**. StrongBox additionally survives → **the SoC and the TEE**.
- Neither prevents → **use by in-process code**.
- A PIN is safe because → **guessing must happen on the chip, and the chip throttles**.
- The HAT is signed with → **`K_shared`, secure world only**.
- Keys die on a PIN change because → **the SID changed**.
- Trust only → **`hardwareEnforced`**.
- "No StrongBox" is → **not a finding**. A **mismatch** is.
- Before every number, record → **which device**.
