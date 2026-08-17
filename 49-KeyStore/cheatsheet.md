# 49 — Android Keystore · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these is true.

---

## The one sentence

The Keystore guarantees **non-extractability**, not **non-usability**. Key material never enters the
app's process; code executing inside that process can use every key the app owns. Almost every
severity decision in this chapter follows from that distinction.

---

## The stack

```
your code            Cipher / Signature / Mac / KeyGenerator
  ↓ JCA
framework            AndroidKeyStoreProvider  (android.security.keystore2)
  ↓ Binder  (plaintext crosses here)
daemon               keystore2, uid 1017, SELinux domain keystore
  ↓ AIDL
HAL                  android.hardware.security.keymint
  ↓
hardware             TEE (TrustedEnvironment)  or  StrongBox (discrete SE)
```

| Era | Daemon | Language | Interface | Backend | Storage |
|---|---|---|---|---|---|
| ≤ Android 11 | `keystore` | C++ | `android.security.IKeystoreService` | Keymaster HIDL | one file per key, `/data/misc/keystore/user_N/` |
| Android 12+ | `keystore2` | Rust | `android.system.keystore2.IKeystoreService` | KeyMint AIDL | `/data/misc/keystore/persistent.sqlite` |

---

## `KeyGenParameterSpec` — the options that decide severity

| Method | Min API | Default | Read it as |
|---|---|---|---|
| `setUserAuthenticationRequired(b)` | 23 | **`false`** | **The** control. `false` on a key gating payment or session data is the second most common finding |
| `setUserAuthenticationParameters(timeout, type)` | 30 | — | `timeout 0` = per-use (`CryptoObject`). `timeout N>0` = an N-second window where **any** code can use the key with no prompt |
| `setUserAuthenticationValidityDurationSeconds(n)` | 23, dep. 30 | — | `-1` = per-use; `>0` = window |
| `setInvalidatedByBiometricEnrollment(b)` | 24 | **`true`** | Explicit `false` = attacker enrols their own finger and inherits the key |
| `setIsStrongBoxBacked(b)` | 28 | `false` | Throws `StrongBoxUnavailableException` if absent — **read the catch block** |
| `setUnlockedDeviceRequired(b)` | 28 | `false` | Strong, rare. Absence is a hardening note unless the app decrypts in the background |
| `setRandomizedEncryptionRequired(b)` | 23 | **`true`** | `false` permits a caller-supplied IV. IV reuse destroys GCM |
| `setBlockModes(...)` | 23 | none permitted | `BLOCK_MODE_ECB` on AES is an immediate finding |
| `setEncryptionPaddings(...)` | 23 | none permitted | Prefer `RSA_OAEP` over `RSA_PKCS1` |
| `setSignaturePaddings(...)` | 23 | none permitted | `RSA_PSS` preferred over `RSA_PKCS1` |
| `setDigests(...)` | 23 | none permitted | `SHA1`/`MD5` on signing = finding. `DIGEST_NONE` on RSA = raw signing of attacker data |
| `setKeySize(n)` | 23 | AES 128, RSA 2048, EC 256 | Check for undersized RSA |
| `setAttestationChallenge(b[])` | 24 | `null` | If present, the **server** must verify. A constant challenge is replayable and worthless |
| `setDevicePropertiesAttestationIncluded(b)` | 31 | `false` | Adds brand/device/product/manufacturer/model |
| `setMaxUsageCount(n)` | 30 | unlimited | Hardware use counter; excellent, rare |
| `setKeyValidityStart/End(Date)` | 23 | none | Enforced against the secure clock where available |
| `setAttestKeyAlias(String)` | 31 | none | `PURPOSE_ATTEST_KEY` designs / RKP |
| `setUserPresenceRequired(b)` | 28 | `false` | StrongBox button; essentially absent on phones |
| `setUserConfirmationRequired(b)` | 28 | `false` | Android Protected Confirmation. Very rare, very strong |

### Purposes bitmask

| Constant | Value |
|---|---|
| `PURPOSE_ENCRYPT` | 1 |
| `PURPOSE_DECRYPT` | 2 |
| `PURPOSE_SIGN` | 4 |
| `PURPOSE_VERIFY` | 8 |
| `PURPOSE_WRAP_KEY` | 32 |
| `PURPOSE_AGREE_KEY` | 64 (API 31) |
| `PURPOSE_ATTEST_KEY` | 128 (API 31) |

Decoding: `3` = ENCRYPT|DECRYPT · `12` = SIGN|VERIFY · `4` = SIGN only.

Purposes are enforced **inside KeyMint** at `begin()`. Hooking cannot turn a decrypt-only key into a
signing key — the rejection happens on the other side of the trust boundary.

---

## `KeyInfo` — what you actually got

```java
// Symmetric
SecretKey k = (SecretKey) ks.getKey(alias, null);
KeyInfo i = (KeyInfo) SecretKeyFactory.getInstance(k.getAlgorithm(), "AndroidKeyStore")
                                      .getKeySpec(k, KeyInfo.class);
// Asymmetric
KeyInfo i = (KeyInfo) KeyFactory.getInstance(alg, "AndroidKeyStore")
                                .getKeySpec(privateKey, KeyInfo.class);
```

| Method | API | Note |
|---|---|---|
| `getSecurityLevel()` | 31+ | The authoritative answer |
| `isInsideSecureHardware()` | 23–30, deprecated 31 | A floor, not a grade |
| `getOrigin()` | 23 | `GENERATED` / `IMPORTED` / `DERIVED` |
| `isUserAuthenticationRequired()` | 23 | |
| `getUserAuthenticationValidityDurationSeconds()` | 23 | `-1`/`0` = per-use |
| `isUserAuthenticationValidWhileOnBody()` | 24 | |
| `isInvalidatedByBiometricEnrollment()` | 24 | |
| `getPurposes()`, `getBlockModes()`, `getEncryptionPaddings()`, `getSignaturePaddings()`, `getDigests()` | 23 | |
| `getKeySize()`, `getKeystoreAlias()` | 23 | |
| `getKeyValidityStart()`, `…ForOriginationEnd()`, `…ForConsumptionEnd()` | 23 | |
| `isTrustedUserPresenceRequired()`, `isUserConfirmationRequired()` | 28 | |

### Security levels

| Value | Constant | Means |
|---|---|---|
| `0` | `SECURITY_LEVEL_SOFTWARE` | OS-protected only. Recoverable on a rooted device. **The "hardware-backed" claim is false here** |
| `1` | `SECURITY_LEVEL_TRUSTED_ENVIRONMENT` | TEE. The normal result |
| `2` | `SECURITY_LEVEL_STRONGBOX` | Discrete secure element |
| `-1` | `SECURITY_LEVEL_UNKNOWN` | Treat as software; investigate |
| `-2` | `SECURITY_LEVEL_UNKNOWN_SECURE` | Secure, level unreported. Acceptable |

> `KeyGenParameterSpec` is what you **asked for**. `KeyInfo` is what you **got**. Never audit from the
> spec alone — read back `KeyInfo` on the real target hardware.

---

## Attestation

Extension OID **`1.3.6.1.4.1.11129.2.1.17`**, in the **leaf** certificate.

```
KeyDescription ::= SEQUENCE {
    attestationVersion       INTEGER,
    attestationSecurityLevel ENUMERATED,   -- Software(0) TrustedEnvironment(1) StrongBox(2)
    keymasterVersion         INTEGER,
    keymasterSecurityLevel   ENUMERATED,
    attestationChallenge     OCTET STRING, -- your server nonce, echoed
    uniqueId                 OCTET STRING,
    softwareEnforced         AuthorizationList,   -- ATTACKER-SIDE. IGNORE.
    hardwareEnforced         AuthorizationList }  -- THE ONLY ONE THAT COUNTS
```

| Tag | Field | Tag | Field |
|---|---|---|---|
| 1 | purpose | 503 | noAuthRequired |
| 2 | algorithm | 504 | userAuthType |
| 3 | keySize | 505 | authTimeout |
| 5 | digest | 506 | allowWhileOnBody |
| 6 | padding | 507 | trustedUserPresenceRequired |
| 10 | ecCurve | 508 | trustedConfirmationRequired |
| 200 | rsaPublicExponent | 509 | unlockedDeviceRequired |
| 400 | activeDateTime | 701 | creationDateTime |
| 401 | originationExpire | 702 | origin |
| 402 | usageExpire | 704 | **rootOfTrust** |
| 705 | osVersion | 706 | osPatchLevel |
| 709 | **attestationApplicationId** | 718 | vendorPatchLevel |
| 710–717 | brand, device, product, serial, imei, meid, manufacturer, model | 719 | bootPatchLevel |

```
RootOfTrust ::= SEQUENCE {
    verifiedBootKey    OCTET STRING,
    deviceLocked       BOOLEAN,
    verifiedBootState  ENUMERATED,  -- Verified(0) SelfSigned(1) Unverified(2) Failed(3)
    verifiedBootHash   OCTET STRING }
```

### Server verification checklist

| # | Check |
|---|---|
| 1 | Chain verifies to a **pinned Google hardware attestation root** — the root, not an intermediate (RKP rotates intermediates) |
| 2 | Every certificate's validity dates are current |
| 3 | Revocation checked against Google's attestation status list |
| 4 | `attestationChallenge` byte-equals a nonce **we** issued, single-use, recent — then consume it |
| 5 | `attestationSecurityLevel` ∈ {`TrustedEnvironment`, `StrongBox`} |
| 6 | **From `hardwareEnforced` only:** `rootOfTrust.verifiedBootState == Verified` and `deviceLocked == true` |
| 7 | `attestationApplicationId` contains our package name **and** our signing-cert digest |
| 8 | `osPatchLevel` ≥ our minimum |
| 9 | `origin == GENERATED`, plus purpose/algorithm/keySize/authTimeout match policy |
| 10 | **Bind the leaf public key to the account and require it to sign every later request** |

> **The softwareEnforced trap.** Every field appears in both lists. A verifier that reads
> `rootOfTrust` or `origin` from `softwareEnforced` — or merges both lists into one dictionary — is
> trivially defeated. Check this first when reviewing a verifier.

---

## The ten findings

| # | Finding | Tell | Typical severity |
|---|---|---|---|
| 1 | **Hardcoded key via `SecretKeySpec`** — never touches the Keystore | `new SecretKeySpec(bytes, "AES")` with a constant, an asset, or a derivation | High. **The most common by far** |
| 2 | Software key generated at runtime and written to a file | `KeyGenerator.getInstance("AES")` with no provider, then file I/O | High |
| 3 | Keystore-protected value **also stored in plaintext** elsewhere | Same value in prefs, cache, log, or on shared storage | High. Makes the whole thing decorative |
| 4 | `setUserAuthenticationRequired(false)` on a key gating sensitive data | Absent from the builder chain (it is the default) | Medium–High |
| 5 | `setInvalidatedByBiometricEnrollment(false)` | Explicit call | Medium |
| 6 | No auth binding — usable by any code in the process | `KeyInfo.isUserAuthenticationRequired() == false` | Contextual |
| 7 | `setRandomizedEncryptionRequired(false)` + fixed IV | Constant IV in code or a zero IV | High for GCM |
| 8 | StrongBox requested, silently downgraded | `catch (StrongBoxUnavailableException)` that retries without it and does not record the fact | Medium |
| 9 | "We use the Keystore" that survives no scrutiny | `KeyInfo.getSecurityLevel() == SOFTWARE`, or the Keystore only wraps a DEK left in the heap | Contextual |
| 10 | Keys shared via `sharedUserId` or `grant()` | Two APKs, one UID | Medium–High |

---

## Frida

```bash
# host
frida -U -f com.target.app -l scripts/hook-keygenparameterspec.js   # how every key is configured
frida -U -f com.target.app -l scripts/enumerate-keystore.js          # every alias + full KeyInfo
frida -U -f com.target.app -l scripts/hook-secretkeyspec.js          # keys that NEVER reach the Keystore
frida -U -f com.target.app -l scripts/hook-cipher-keystore.js        # plaintext through Keystore keys
```

| Hook | Answers |
|---|---|
| `android.security.keystore.KeyGenParameterSpec$Builder` | Findings 4, 5, 7, 8 in one run, through any obfuscation |
| `javax.crypto.spec.SecretKeySpec.$init` | Finding 1, even when assembled from XOR fragments or built in native code |
| `javax.crypto.Cipher.init` / `doFinal` / `update` | The plaintext, the IV, and which key |
| `java.security.KeyStore.getKey` / `aliases` | Which aliases the app actually uses at runtime |
| `Java.choose('javax.crypto.spec.SecretKeySpec')` | Live non-hardware keys on the heap — `AndroidKeyStoreSecretKey` holds nothing, so this finds exactly the set you care about |

---

## Objection

```bash
# host
objection -g com.target.app explore
```

```
android keystore list
android keystore watch
android hooking watch class javax.crypto.Cipher
android hooking watch class_method javax.crypto.spec.SecretKeySpec.$init
android heap search instances javax.crypto.spec.SecretKeySpec
```

---

## Without Frida

```bash
# host
adb shell getprop | grep -Ei 'keystore|keymaster|keymint|strongbox'
adb shell pm list features | grep -Ei 'hardware_keystore|strongbox|keystore'
adb shell 'lshal 2>/dev/null | grep -i keymint'
adb shell 'service list | grep -i keystore'
```

```bash
# adb shell as root — blobs are opaque; metadata is not
ls -la /data/misc/keystore/
sqlite3 /data/misc/keystore/persistent.sqlite ".tables"
sqlite3 /data/misc/keystore/persistent.sqlite "select id, domain, namespace, alias from keyentry;"
```

```bash
# host — where the real leaks are
adb shell "su -c 'ls -laR /data/data/com.target.app/'"
adb logcat -d | grep -Ei 'token|bearer|secret|password|key='
```

---

## Static analysis greps

```bash
# host — after jadx -d out target.apk
grep -rn 'SecretKeySpec'                       out/sources/   # <<< START HERE
grep -rn 'AndroidKeyStore'                     out/sources/
grep -rn 'KeyGenParameterSpec'                 out/sources/
grep -rn 'setUserAuthenticationRequired'       out/sources/
grep -rn 'setInvalidatedByBiometricEnrollment' out/sources/
grep -rn 'setRandomizedEncryptionRequired'     out/sources/
grep -rn 'setIsStrongBoxBacked'                out/sources/
grep -rn 'StrongBoxUnavailableException'       out/sources/   # then read the catch block
grep -rn 'setAttestationChallenge'             out/sources/
grep -rn 'IvParameterSpec\|GCMParameterSpec'   out/sources/
grep -rnE 'Cipher\.getInstance\("[^"]*ECB'     out/sources/
grep -rn 'KeyPermanentlyInvalidatedException'  out/sources/
grep -rn 'CryptoObject'                        out/sources/   # absent + BiometricPrompt = decorative
grep -rnE '"[A-Za-z0-9+/]{22,}={0,2}"'         out/sources/   # base64-looking constants
```

```bash
# host — where "hardcoded" often really lives
unzip -o target.apk -d work/
strings work/assets/* work/res/raw/* 2>/dev/null | grep -iE 'key|secret'
grep -rnE 'android:sharedUserId' work/AndroidManifest.xml
```

### Smali fingerprint of Finding 1

```
const-string v0, "AndroidKeyStore"    ← the CORRECT path starts here
...
new-instance v1, Ljavax/crypto/spec/SecretKeySpec;   ← the BROKEN path starts here
invoke-direct {v1, v2, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
```

---

## Exception → meaning

| Exception | Means |
|---|---|
| `UserNotAuthenticatedException` | Auth binding is real and unsatisfied. **A positive result for the app — report it as such** |
| `KeyPermanentlyInvalidatedException` | Biometric enrolled, lock screen removed, or factory reset. Key is gone forever |
| `StrongBoxUnavailableException` | No discrete SE. Check what the catch block does next |
| `InvalidAlgorithmParameterException` on `init` | Usually `setRandomizedEncryptionRequired(true)` refusing a caller-supplied IV — a sign the app is doing it right |
| `KeyStoreException: Failed to load key` | Alias absent, or wrong namespace |
| `getEncoded()` returns `null` | Confirms a genuine Keystore key. Non-null means it was never in the Keystore |

---

## Rules

1. `getEncoded()` returning `null` is the fastest proof a key is genuinely in the Keystore.
2. Grep `SecretKeySpec` **before** anything else. It finds the most common real mistake.
3. Read `KeyInfo` on the real device. What the code requested is not what the device provided.
4. A biometric prompt with **no** `CryptoObject` is a boolean in the attacker's memory.
5. `timeout 0` is per-use binding. Any positive timeout is a window.
6. Attestation verification is worthless unless it is **server-side** and reads `hardwareEnforced`.
7. Pin the Google **root**, never an intermediate — RKP rotates intermediates.
8. Extraction and use are different guarantees. Say which one your finding breaks.
9. A key that is correctly bound and fails your attack is a finding too. Report the controls that worked.
10. After recovering a plaintext, answer: **what did I learn that I did not already have?**
