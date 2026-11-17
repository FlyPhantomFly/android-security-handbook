# 50 — Hardware-Backed Security — References

Annotated. Every entry says what it is *for*, because in this subject the difference between a
useful source and a misleading one is large and is not obvious from the title.

Two standing rules for this chapter's sources:

- **AOSP file paths are stable and safe to cite. Line numbers are not** — navigate by symbol name.
- **Verify every CVE identifier against NVD before it reaches a client report.** TEE advisories are
  frequently renumbered by vendor, and a wrong identifier in a report is worse than no identifier.

---

## 1. AOSP source — the primary sources for this chapter

| Path | Why you would open it |
|---|---|
| `system/gatekeeper/` | The portable Gatekeeper reference implementation, in plain C++ with no Android dependencies. **The single most rewarding read in this chapter.** The list of pure-virtual platform hooks in `include/gatekeeper/gatekeeper.h` — `GetPasswordKey`, `GetAuthTokenKey`, `GetMillisecondsSinceBoot`, `GetFailureRecord` — *is* the security model, written as a checklist |
| `system/gatekeeper/gatekeeper.cpp` | The `Enroll`/`Verify` logic, including the ordering that matters: throttle first, compare second |
| `hardware/interfaces/gatekeeper/1.0/IGatekeeper.hal` | The whole HAL: `enroll`, `verify`, `deleteUser`, `deleteAllUsers`. Short enough to read in five minutes |
| `system/keymint/` | Google's **Rust reference KeyMint**. Because vendor trustlets are closed, this is the best available statement of what each tag actually means and how it is enforced |
| `hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Tag.aidl` | The complete tag vocabulary with the numeric values that appear in an attestation |
| `.../keymint/KeyPurpose.aidl` | **Read this before writing any attestation parser.** These values are not the Java `KeyProperties.PURPOSE_*` bitmask, and confusing them produces plausible, wrong output |
| `.../keymint/SecurityLevel.aidl` | `SOFTWARE`, `TRUSTED_ENVIRONMENT`, `STRONGBOX` at the source |
| `.../keymint/HardwareAuthToken.aidl` | The modern auth-token structure |
| `hardware/libhardware/include/hardware/hw_auth_token.h` | The classic `hw_auth_token_t` layout, still the clearest field-by-field statement |
| `hardware/interfaces/keymaster/` | The legacy HIDL Keymaster HALs (3.0, 4.0, 4.1). **Not historical** — measured live on two of this chapter's three targets |
| `system/security/keystore2/src/` | The Rust Keystore daemon: access control, namespaces, the blob database, and the `km_compat` shim that lets it drive a legacy Keymaster HAL |
| `system/hardware/interfaces/keystore2/aidl/android/system/keystore2/` | `IKeystoreService.aidl`, `IKeystoreSecurityLevel.aidl` — the Binder surface an app reaches |
| `system/hardware/interfaces/keystore2/aidl/android/security/authorization/IKeystoreAuthorization.aidl` | How an auth token reaches the Keystore |
| `frameworks/base/services/core/java/com/android/server/locksettings/LockSettingsService.java` | The framework side of the credential: enrolment, verification, lockout policy |
| `frameworks/base/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java` | The synthetic password — why a credential change does not re-encrypt the world, and what the `spblob` files in `/data/system_de/<user>/spblob/` are |
| `frameworks/base/keystore/java/android/security/keystore2/` | The framework provider. Owned by [49](../../49-KeyStore/README.md); listed here because §7.2's `app_process` technique calls `AndroidKeyStoreProvider.install()` directly |
| `trusty/` | Google's open-source TEE OS. The only TEE in this chapter whose source you can actually read |

---

## 2. Official documentation

| Source | Why |
|---|---|
| AOSP Security — *Hardware-backed security* | The platform's own statement of the trust model. Short; read it once |
| AOSP Security — *Gatekeeper* | Enrolment, verification, throttling, and the auth-token handoff, as the platform describes it |
| AOSP Security — *Key and ID attestation* | The authoritative field list for the attestation extension, including the schema version history |
| AOSP Security — *StrongBox* / *Keystore* | What a StrongBox implementation is required to provide |
| AOSP Security — *Remote Key Provisioning* | Why chains got longer and intermediates short-lived, and why pinning an intermediate breaks |
| **Android Compatibility Definition Document (CDD)**, cryptography section | Where "hardware-backed keystore required" actually comes from. When a developer asks "is my device *supposed* to have this?", this is the answer, per Android version |
| Android developer reference — `KeyGenParameterSpec`, `KeyInfo`, `KeyProperties` | The API surface.documented API levels are promises about AOSP, not about shipping devices — see the `setMaxUsageCount` measurement in [README §2.3](../README.md) |
| Android developer reference — `PackageManager.FEATURE_STRONGBOX_KEYSTORE`, `FEATURE_HARDWARE_KEYSTORE` | Including `getSystemFeatureVersion`, which carries the Keymaster/KeyMint version |
| Android developer reference — `BiometricPrompt.CryptoObject` | The object that turns a prompt into a cryptographic fact |

---

## 3. ARM and hardware

| Source | Why |
|---|---|
| ARM — *TrustZone for Cortex-A* | The architecture. Explains the `NS` bit, the two security states, and why EL3 exists |
| ARM — *SMC Calling Convention* | How arguments cross the world boundary. Useful when reading a vendor HAL's kernel driver |
| ARM — TZC-400 / TrustZone Address Space Controller documentation | The component that makes secure DRAM physically unreadable from the normal world. This is the thing people mean when they say "hardware isolation" |
| GlobalPlatform — *TEE System Architecture*, *TEE Internal Core API* | The vendor-neutral specification most TEE operating systems claim conformance to. Read when you need to know what a TEE is *required* to do rather than what Android asks of it |

---

## 4. Standards and RFCs

| Reference | Relevance |
|---|---|
| RFC 2104 — HMAC | The construction behind both the Gatekeeper password handle and the auth token signature |
| RFC 5280 — X.509 and CRL profile | The certificate structure `parse-attestation.py` walks |
| RFC 5480 — ECC subject public key information | How the EC public keys in an attestation chain are encoded |
| RFC 8017 — PKCS #1 v2.2 | RSA signature verification, implemented in `parse-attestation.py` for the Google root |
| ITU-T X.690 — DER | The encoding rules the attestation extension follows, and the reason `NULL`-typed tags are statements by presence |

---

## 5. Research and vulnerabilities

| Work | What it teaches |
|---|---|
| *"Trust Dies in Darkness: Shedding Light on Samsung's TrustZone Keymaster Design"*, USENIX Security 2022 | **The best worked example available** of cryptographic misuse *inside* a trusted application: IV reuse in AES-GCM key wrapping, leading to key recovery, plus a version-downgrade issue. Associated identifiers **CVE-2021-25444** and **CVE-2021-25490** |
| The Qualcomm QSEE trustlet research line, 2015–2016 | How a normal-world attacker reaches and exploits a trustlet, and what full secure-world compromise then yields. Associated identifiers **CVE-2015-6639** and **CVE-2016-2431** |
| Published work on attestation-key extraction | Explains why Google maintains a revocation status list and why Remote Key Provisioning exists. Treat as a class rather than citing an identifier |
| Side-channel literature against TrustZone (cache, power, EM) | The reason StrongBox's separate die is a meaningfully different guarantee rather than marketing |

> Every identifier above is given because the issue is well documented and widely referenced.
> **Check each against NVD before quoting it.** Where you are unsure, describe the class — this
> repository's standing rule, and it matters most in exactly this area.

---

## 6. OWASP

| Identifier | Applies to |
|---|---|
| MASVS-STORAGE-1 | Sensitive data uses platform secure storage; hardware backing is what makes that meaningful |
| MASVS-CRYPTO-1 | Proven cryptographic implementations — a `SecretKeySpec` fallback fails this |
| MASVS-CRYPTO-2 | Key management: the security level and `origin` are the evidence |
| MASVS-AUTH-2 | **Local authentication bound to a cryptographic operation.** This chapter's §3.7 is the mechanism behind this control |
| MASVS-AUTH-3 | Sensitive operations require authentication; per-use versus window is *how strongly* |
| MASVS-RESILIENCE-1, MASVS-RESILIENCE-4 | Platform integrity and anti-tamper; attestation is the only mechanism here that is not client-side |
| MASTG — Android key material and local authentication test procedures | The practical procedures. Prefer measuring the level over reading the manifest |

---

## 7. This chapter's own artefacts

| File | Use |
|---|---|
| [`../scripts/hw-security-inventory.sh`](../scripts/hw-security-inventory.sh) | Read-only device posture; run it first |
| [`../scripts/probe-security-levels.sh`](../scripts/probe-security-levels.sh) | The real security level per algorithm. **No root, no installed app** |
| [`../scripts/SecurityLevelProbe.java`](../scripts/SecurityLevelProbe.java) | The probe itself; read it for the two `app_process` traps |
| [`../scripts/parse-attestation.py`](../scripts/parse-attestation.py) | Offline chain parsing and real signature verification, standard library only |
| [`../scripts/hook-security-level.js`](../scripts/hook-security-level.js) | Frida: what the app asked for versus what it got |
| [`../examples/StrongBoxAwareKeyFactory.java`](../examples/StrongBoxAwareKeyFactory.java) | The correct degradation pattern |
| [`../examples/AssumesHardwareKeyManager.java`](../examples/AssumesHardwareKeyManager.java) | The same feature with five real defects, annotated |
| [`../examples/hardware_posture_policy.py`](../examples/hardware_posture_policy.py) | Tiering rather than a boolean, with reasons |
| [`../labs/lab-01-measure-every-key-type.md`](../labs/lab-01-measure-every-key-type.md) | Measure the device, then the app |
| [`../labs/lab-02-gatekeeper-and-the-hat-chain.md`](../labs/lab-02-gatekeeper-and-the-hat-chain.md) | The PIN-to-hardware chain, broken deliberately |
| [`../labs/lab-03-attestation-offline.md`](../labs/lab-03-attestation-offline.md) | Read a chain with no network; catch a lying property |
| [`../labs/lab-04-ctf-the-honest-phone.md`](../labs/lab-04-ctf-the-honest-phone.md) | CTF |

---

## 8. Related chapters

| Chapter | Relationship |
|---|---|
| [49 — Keystore](../../49-KeyStore/README.md) | **The chapter directly above this one.** Owns the API, aliases, namespaces, `KeyGenParameterSpec` option by option, the extraction-versus-use distinction, and the server-side attestation policy verifier. Read it first; this chapter explains why its guarantees hold |
| [20 — Security Architecture](../../20-Security-Architecture/README.md) | Owns Verified Boot, AVB, dm-verity, FBE and Play Integrity. This chapter consumes its `RootOfTrust` and explains why the attested version is trustworthy and the property version is not |
| [34 — Cryptography](../../34-Cryptography/README.md) | AES-GCM, HMAC, ECDSA, RSA padding — the primitives underneath everything here |
| [18 — ARM](../../18-ARM/README.md) | Exception levels, `smc`, and the instruction set the secure world runs on |
| [19 — Memory](../../19-Memory/README.md) | Why key material in normal-world memory is recoverable and secure-world memory is not |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | The uid boundary that Keystore namespaces build on |
| [22 — SELinux](../../22-SELinux/README.md) | The `keystore_key` object class; why `shell` reaches `keystore2` but not `IGateKeeperService` |
| [25 — Binder](../../25-Binder/README.md) | The transport for every Keystore call |
| [33 — Storage](../../33-Storage/README.md) | Where wrapped blobs end up, and why a backup containing one is a different problem |
| [37 — Root Detection](../../37-RootDetection/README.md) | Owns detection. §5.1 here is the measurement showing why its property-based half cannot work |
| [38 — Tamper Detection](../../38-TamperDetection/README.md) | Signature and integrity checks; attestation is the only non-client-side one |
| [46 — Tokens](../../46-Tokens/README.md) | What happens after attestation if the attested key is not used to sign later requests |
| [53 — Frida](../../53-Frida/README.md) | The instrumentation in §7.3 |
| [65 — Hooking](../../65-Hooking/README.md) | The mechanism behind it |
| [62 — Magisk](../../62-Magisk/README.md) | The rooting stack that rewrote `ro.boot.verifiedbootstate` on target B |
| [67 — Bypassing Protections](../../67-BypassingProtections/README.md) | Owns bypass technique; this chapter owns what cannot be bypassed, and why |
| [15 — Native Code](../../15-Native-Code/README.md), [16 — JNI](../../16-JNI/README.md), [57 — Ghidra](../../57-Ghidra/README.md) | For §6.3 native key handling and §6.4 trustlet identification |
| [71 — OWASP Mobile](../../71-OWASP-Mobile/README.md) | The MASVS mapping in §5.5 in its own context |

**[48 — Biometrics](../../48-Biometrics/README.md)** owns `BiometricPrompt`, enrolment and the sensor
pipeline. This chapter owns the hardware auth-token chain that a biometric authentication feeds into
([README §3.7](../README.md)). 48 links here for the token; this chapter links there for the prompt.
[`48-Biometrics/scripts/probe-biometrics.sh`](../../48-Biometrics/scripts/probe-biometrics.sh)
reuses this chapter's `AndroidKeyStoreProvider.install()` finding rather than re-deriving it, and
cites it in both the script header and the code.
