# 49 — Android Keystore · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Primary source — AOSP

Read these on [cs.android.com](https://cs.android.com/), which gives you cross-references and history.
See [07-AOSP](../../07-AOSP/README.md) for the navigation technique. No line numbers are quoted; they
change every release.

### The framework layer — Java, in your process

| Path | Open it when |
|---|---|
| `frameworks/base/keystore/java/android/security/keystore/KeyGenParameterSpec.java` | You need the exact semantics or the API level of a builder option. **The single most useful file in this chapter** — the Javadoc on each setter is the authoritative statement of what it constrains. |
| `frameworks/base/keystore/java/android/security/keystore/KeyProperties.java` | You are decoding a purpose bitmask, a security-level constant, or an auth-type flag |
| `frameworks/base/keystore/java/android/security/keystore/KeyInfo.java` | You want the complete list of what can be read back off a key |
| `frameworks/base/keystore/java/android/security/keystore/KeyProtection.java` | You are looking at an **imported** key and need the import-time policy object |
| `frameworks/base/keystore/java/android/security/keystore2/` | The Android 12+ provider: `AndroidKeyStoreProvider`, `AndroidKeyStoreSpi`, `AndroidKeyStoreSecretKey`, `AndroidKeyStoreCipherSpiBase` |
| `frameworks/base/keystore/java/android/security/keystore2/AndroidKeyStoreCipherSpiBase.java` | You want to see exactly where your plaintext leaves the process and how the operation is streamed |
| `frameworks/base/keystore/java/android/security/KeyStore2.java` | The Java-side wrapper over the `keystore2` AIDL interface |

### The daemon

| Path | Covers |
|---|---|
| `system/security/keystore2/src/` | The Rust daemon. `service.rs`, `security_level.rs`, `database.rs`, `permission.rs` |
| `system/security/keystore2/src/permission.rs` | Namespaces, ownership and grants — the access-control model from §3.3 |
| `system/security/keystore2/src/database.rs` | The `persistent.sqlite` schema, including the `keyentry` table you can read on a rooted device |
| `system/security/keystore/` | The legacy C++ daemon, for devices at Android 11 and below |
| `system/sepolicy/private/keystore.te` | The SELinux domain the daemon runs in |

### The HAL and the hardware interface

| Path | Covers |
|---|---|
| `hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/` | **The KeyMint interface.** `Tag.aidl` and `TagType.aidl` are the definitive tag list — read these rather than any written summary, including this chapter's |
| `hardware/interfaces/security/keymint/aidl/.../IKeyMintDevice.aidl` | `generateKey`, `importKey`, `importWrappedKey`, `begin`, and the operation model |
| `hardware/interfaces/security/keymint/aidl/.../SecurityLevel.aidl` | `SOFTWARE`, `TRUSTED_ENVIRONMENT`, `STRONGBOX` |
| `hardware/interfaces/security/keymint/aidl/.../HardwareAuthToken.aidl` | The token Gatekeeper and the biometric HAL produce, which is what makes auth binding real |
| `system/keymint/` | The Rust reference KeyMint implementation. Readable, and the best way to understand what a TA actually does |
| `hardware/interfaces/keymaster/` | The legacy Keymaster HIDL interfaces, for older devices |

### Attestation

| Path | Covers |
|---|---|
| `system/security/keystore2/src/attestation.rs` (and the KeyMint TA sources) | How the chain and the extension are produced |
| `hardware/interfaces/security/keymint/aidl/.../attestation/` | The published ASN.1 schema for the `KeyDescription` extension. **Cite this, not a blog post.** |
| `system/keymint/` | Contains a readable implementation of the extension encoding |

### Adjacent

| Path | Covers |
|---|---|
| `system/gatekeeper/` | PIN/pattern/password verification and the auth token it issues |
| `hardware/interfaces/biometrics/fingerprint/aidl/` | The biometric side of auth binding — see [48-Biometrics](../../48-Biometrics/README.md) |
| `frameworks/base/core/java/android/hardware/biometrics/BiometricPrompt.java` | `CryptoObject` and the authenticate overloads that decide whether binding is real |
| `packages/modules/` | Where a `RemoteProvisioner`-style RKP component lives on recent releases |

---

## Official documentation

| Resource | Why |
|---|---|
| [Android Keystore system](https://developer.android.com/privacy-and-security/keystore) | The canonical developer-facing overview. Read once, properly. |
| [Verifying hardware-backed key pairs with Key Attestation](https://developer.android.com/privacy-and-security/security-key-attestation) | The attestation guide, including the extension schema and the Google root |
| [Hardware-backed Keystore](https://source.android.com/docs/security/features/keystore) | AOSP's own architectural statement — the TEE/StrongBox model |
| [KeyMint](https://source.android.com/docs/security/features/keystore/attestation) | The HAL, its tags, and attestation from the platform side |
| [Remote Key Provisioning](https://source.android.com/docs/core/ota/modular-system/remote-key-provisioning) | Why the chain is longer and the intermediates are short-lived on modern devices — and why pinning an intermediate breaks |
| [Android Compatibility Definition Document §9.11](https://source.android.com/docs/compatibility/cdd) | What an OEM is *required* to implement. When a device behaves oddly, this tells you whether that is permitted. |
| [`BiometricPrompt.CryptoObject`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject) | The API that makes an auth binding real rather than decorative |
| [Jetpack Security (`EncryptedSharedPreferences`, `MasterKey`)](https://developer.android.com/privacy-and-security/cryptography) | What most apps actually use; know its defaults, especially that the master key is not auth-bound by default |
| [Behaviour changes index](https://developer.android.com/about/versions) | **Check before asserting any version-dependent behaviour.** |

---

## Standards and specifications

| Resource | Why |
|---|---|
| Attestation extension OID `1.3.6.1.4.1.11129.2.1.17` — schema published in AOSP | The only authoritative source for the `KeyDescription` structure |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) | X.509 path validation. The rules your attestation verifier must actually implement |
| [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) | GCM. Read §8.2 on IV construction to understand exactly why IV reuse is catastrophic |
| [RFC 5116](https://www.rfc-editor.org/rfc/rfc5116) | AEAD as an interface — useful framing for why GCM is the default recommendation |
| [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017) (PKCS#1 v2.2) | OAEP and PSS, and why they are preferred over the v1.5 constructions |
| [NIST SP 800-57 Part 1](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) | Key management lifecycle — the vocabulary for writing rotation recommendations |

---

## Tooling

| Tool | Where | Use |
|---|---|---|
| [Frida](https://frida.re/docs/android/) | host + device | Everything in §7. See [`../scripts/`](../scripts/) |
| [Objection](https://github.com/sensepost/objection) | host | `android keystore list`, `android keystore watch`, heap search — a lot of §7 without writing a script |
| `openssl` | host | `openssl x509 -in leaf.pem -text -noout` to see the chain; `-certopt ext_parse` for a first look at the extension |
| [`asn1crypto`](https://github.com/wbond/asn1crypto) / [`pyasn1`](https://github.com/pyasn1/pyasn1) | host (Python) | Parsing the attestation extension properly. Used by [`../examples/04-verify-attestation.py`](../examples/04-verify-attestation.py) |
| [`cryptography`](https://cryptography.io/) | host (Python) | Certificate chain verification with real path validation |
| [google/android-key-attestation](https://github.com/google/android-key-attestation) | host (Java) | Google's own reference verifier. **Read it before writing your own**, and compare any verifier you are reviewing against it |
| [jadx](https://github.com/skylot/jadx) | host | Decompilation for the §8 greps |
| [apktool](https://apktool.org/) | host | Manifest and resources — where hardcoded "keys" often really live |
| `sqlite3` | device (root) | `/data/misc/keystore/persistent.sqlite` metadata |
| `lshal`, `service list`, `pm list features` | device | Which KeyMint HAL is present and whether hardware support exists at all |

---

## Security research

| Resource | Why |
|---|---|
| Shakevsky, Ronen, Wool — *Trust Dies in Darkness: Shedding Light on Samsung's TrustZone Keymaster Design*, USENIX Security 2022 | **The paper to read.** IV reuse in a vendor Keymaster TA leading to key material recovery. It is the clearest published demonstration that the vendor TA, not the framework, is where the deep bugs live. |
| Gal Beniamini's published work on Qualcomm's Secure Execution Environment | The foundational public research on TrustZone exploitation on Android. Long, technical, and worth the time. |
| [Android Security Bulletins](https://source.android.com/docs/security/bulletin) | Monthly, authoritative. Read for the *pattern* of which components recur, and pull any specific identifier from the bulletin for the affected release rather than from memory. |
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | Occasional deep work on TEEs and secure elements |
| [Android VRP rules](https://bughunters.google.com/about/rules) | How Google itself rates a Keystore or TEE issue — useful for calibrating severity |

> **Note on CVE citation.** This chapter describes vulnerability *classes* rather than accumulating
> identifiers. Keystore and TEE issues are numerous, vendor-specific and version-specific, and a
> misattributed CVE in a client report is worse than no citation. Where the README names one, it says
> explicitly to verify the NVD entry before citing it. Do that.

---

## OWASP

| Identifier | Relevance |
|---|---|
| **MASVS-CRYPTO-1** | The app uses proven cryptographic primitives with appropriate parameters — block modes, paddings, digests, key sizes |
| **MASVS-CRYPTO-2** | The app performs key management according to best practice — this is where hardcoded keys and missing rotation land |
| **MASVS-STORAGE-1** | Sensitive data is stored appropriately — Finding 3, the plaintext copy elsewhere |
| **MASVS-AUTH-2 / AUTH-3** | Local authentication is bound to a cryptographic operation — the `CryptoObject` question |
| [MASTG](https://mas.owasp.org/MASTG/) | The key-management and biometric-authentication test cases map directly onto §7 |

See [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) for the current identifier scheme, which has
changed more than once.

---

## Books and long-form

| Work | Why |
|---|---|
| *Android Security Internals* — Nikolay Elenkov | The best structural account of the Keystore's place in the platform. Dated on `keystore2` specifics; the architecture is still correct. |
| *Serious Cryptography* — Jean-Philippe Aumasson | If GCM, nonce reuse, or AEAD feels vague, this is the fastest way to fix that. Chapter on authenticated encryption especially. |
| *Cryptography Engineering* — Ferguson, Schneier, Kohno | Key management as a discipline — the framing behind most of the remediation advice in §5 |
| *Bulletproof TLS and PKI* — Ivan Ristić | X.509 path validation, pinning, and revocation, all of which an attestation verifier has to get right |

---

## Conference talks worth finding

Search for topics rather than URLs, since hosting moves:

- Samsung Keymaster / TrustZone Keymaster design flaws — the USENIX 2022 presentation
- Android key attestation bypasses and attestation-key extraction — Black Hat and OffensiveCon mobile tracks
- StrongBox and secure element design — Google's own platform security talks
- Biometric authentication bypasses on Android — mobile security tracks; overlaps heavily with [48-Biometrics](../../48-Biometrics/README.md)

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [34 — Cryptography](../../34-Cryptography/README.md) | The primitives, modes, paddings and IV rules this chapter assumes |
| [47 — Authentication](../../47-Authentication/README.md) | Where the tokens the Keystore protects come from, and what their lifetimes should be |
| [48 — Biometrics](../../48-Biometrics/README.md) | `BiometricPrompt`, `CryptoObject`, and the prompt-bypass technique that turns "auth-bound" into "decorative" |
| [50 — Hardware-Backed Security](../../50-HardwareBackedSecurity/README.md) | TEE, StrongBox, Gatekeeper, verified boot — the layer beneath this one |
| [21 — App Sandbox](../../21-App-Sandbox/README.md) | Why the *process* is the boundary, why `sharedUserId` merges Keystore namespaces, and why in-process code can do anything the app can |
| [33 — Storage](../../33-Storage/README.md) | Where the ciphertext ends up, and where the plaintext copy usually turns up too |
| [37 — Root Detection](../../37-RootDetection/README.md) | Why client-side integrity checks fail, and therefore why attestation exists |
| [38 — Tamper Detection](../../38-TamperDetection/README.md), [67 — Bypassing Protections](../../67-BypassingProtections/README.md) | The controls apps build around the Keystore, and how they are defeated |
| [51 — Dynamic Analysis](../../51-DynamicAnalysis/README.md), [53 — Frida](../../53-Frida/README.md), [54 — Objection](../../54-Objection/README.md) | The instrumentation used throughout §7 |
| [52 — Static Analysis](../../52-StaticAnalysis/README.md) | The grep and decompilation workflow of §8 |
| [15 — Native Code](../../15-Native-Code/README.md), [57 — Ghidra](../../57-Ghidra/README.md) | When the key is assembled in a `.so` and passed up through JNI |
