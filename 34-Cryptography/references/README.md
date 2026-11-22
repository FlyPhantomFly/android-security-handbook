# 34 — Cryptography · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time pressure.

---

## Standards and RFCs — the ones you will actually cite

These are safe to reference in a client report. Unlike CVE identifiers, standards numbers do not go
stale and are not easy to misattribute.

| Document | Open it when |
|---|---|
| [**RFC 8018** — PKCS #5 v2.1](https://www.rfc-editor.org/rfc/rfc8018) | You need the authoritative definition of PBKDF2, including the minimum salt length (8 bytes) and the structure `T_i = U_1 ⊕ … ⊕ U_c`. **This is the citation for every password-derivation finding.** It also explains why requesting more output than one hash length costs the defender more than the attacker |
| [**NIST SP 800-38D** — GCM and GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final) | You are writing up a GCM finding. §8 is the uniqueness requirement for the IV; §5.2.1.2 gives the permitted tag lengths (128, 120, 112, 104, 96); Appendix A quantifies the forgery probability for short tags. **The citation for nonce reuse and for tag-length bugs** |
| [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104) | You need to explain why `H(secret ‖ data)` is not a MAC, and what HMAC's two-pass construction fixes |
| [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869) | You are separating a password KDF from a key-based KDF, or explaining what the `info` parameter is for. §3 on the salt and `info` is short and worth reading in full |
| [RFC 8017 — PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017) | RSA: OAEP for encryption, PSS for signatures, and why PKCS#1 v1.5 encryption padding is the Bleichenbacher class |
| [RFC 8439 — ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439) | The AEAD to recommend when AES hardware acceleration is absent |
| [RFC 8452 — AES-GCM-SIV](https://www.rfc-editor.org/rfc/rfc8452) | The app genuinely cannot guarantee nonce uniqueness and you need a misuse-resistant alternative |
| [RFC 6979 — Deterministic ECDSA](https://www.rfc-editor.org/rfc/rfc6979) | You are explaining why a repeated ECDSA nonce reveals the private key, and what the fix is |
| [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106) | You are recommending Argon2id and need the parameter guidance rather than a blog post's numbers |
| [NIST SP 800-38A — Block cipher modes](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) | The formal definitions of ECB, CBC, CFB, OFB and CTR, including the requirement that the CBC IV be unpredictable |
| [NIST SP 800-57 Part 1 — Key management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final) | You need a defensible statement about key lifetimes or crypto-period |
| [NIST SP 800-131A — Algorithm transitions](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final) | You need an authority for "2048-bit RSA is the minimum" or "SHA-1 is disallowed for signatures" |
| [NIST SP 800-90A — DRBGs](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final) | You are reasoning about what `SecureRandom` is actually doing underneath |
| [FIPS 197 — AES](https://csrc.nist.gov/pubs/fips/197/final) | You want the actual specification: SubBytes, ShiftRows, MixColumns, AddRoundKey |
| [FIPS 186-5 — Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final) | ECDSA and RSA signature parameters, curve definitions |

---

## OWASP

| Resource | Why |
|---|---|
| [**MASVS-CRYPTO**](https://mas.owasp.org/MASVS/06-MASVS-CRYPTO/) | The two controls every finding in this chapter maps to. **MASVS-CRYPTO-1**: the app uses current, strong cryptography according to industry best practice. **MASVS-CRYPTO-2**: the app performs key management according to industry best practice. Cite the *control*, not the MASTG test id, because control ids are stable across MASTG refactors |
| [MASVS](https://mas.owasp.org/MASVS/) | The full control set. MASVS-STORAGE and MASVS-AUTH also carry crypto findings — see §5.4 |
| [MASTG](https://mas.owasp.org/MASTG/) | The test procedures. Relevant entries: testing symmetric cryptography, testing the configuration of cryptographic standard algorithms, testing key management, testing random number generation |
| [MASTG Android crypto tests](https://mas.owasp.org/MASTG/0x05e-Testing-Cryptography/) | The Android-specific procedures, with the exact greps and hooks |
| [**Password Storage Cheat Sheet**](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | **The source for the iteration counts in this chapter.** Check it rather than quoting a number from memory; it is updated as hardware improves |
| [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | A concise defensible answer for "what should we use", suitable for pasting into a remediation section |
| [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) | Rotation, storage and lifecycle guidance when the finding is architectural rather than a single line |
| [MASTG test apps](https://mas.owasp.org/MASTG/apps/) | UnCrackable and friends — legal practice targets for [Lab 03](../labs/lab-03-audit-a-real-app.md) |

---

## Official Android documentation

| Resource | Why |
|---|---|
| [Cryptography](https://developer.android.com/guide/topics/security/cryptography) | Google's own list of recommended algorithms and, importantly, the deprecated ones. Useful in a report because the client cannot argue with the platform vendor |
| [Android Keystore system](https://developer.android.com/privacy-and-security/keystore) | `KeyGenParameterSpec` in full, every builder option and the API level each arrived in |
| [Security best practices](https://developer.android.com/privacy-and-security/security-tips) | The developer-facing guidance your remediation should align with |
| [Jetpack Security](https://developer.android.com/topic/security/data) | `EncryptedSharedPreferences` and `EncryptedFile`. Note the library's maintenance status before recommending it — check the current release notes rather than assuming |
| [Behaviour changes by API level](https://developer.android.com/about/versions) | **Check before asserting any version-dependent claim.** The `setSeed` change at API 24 and the Bouncy Castle removals are the ones that bite most often |
| [Cryptography changes in Android P](https://android-developers.googleblog.com/2018/03/cryptography-changes-in-android-p.html) | Why Bouncy Castle algorithms started disappearing and what replaced them. Explains a whole class of "worked on Android 8, crashes on Android 9" reports |
| [Tink](https://developers.google.com/tink) | The library to recommend. The "Primitives" and "Key management" pages are the ones worth reading |
| [Tink Android integration](https://github.com/tink-crypto/tink-java/tree/main/src_android) | `AndroidKeysetManager` and the master key URI — the part apps get wrong |
| [Conscrypt](https://github.com/google/conscrypt) | The provider that implements almost everything. Read `OpenSSLCipher` when you need to know what a transformation actually resolves to |
| [BoringSSL](https://boringssl.googlesource.com/boringssl/) | The native layer beneath Conscrypt. Read it when hooking below the JCA |

---

## AOSP source

Read these on [cs.android.com](https://cs.android.com/), which gives cross-references and history. See
[07-AOSP](../../07-AOSP/README.md) for the navigation technique.

| Path | Open it when |
|---|---|
| `libcore/ojluni/src/main/java/javax/crypto/Cipher.java` | You need to see exactly how a transformation string is parsed and how provider selection works. **The single most useful file in this chapter** — it is where `"AES"` becomes `AES/ECB/PKCS5Padding` |
| `libcore/ojluni/src/main/java/javax/crypto/spec/SecretKeySpec.java` | You want to confirm that `getEncoded()` returns a copy, and why hooking the constructor captures every software key |
| `libcore/ojluni/src/main/java/java/security/Security.java` | You are reasoning about provider ordering and why `getInstance` returns what it returns |
| `libcore/ojluni/src/main/java/java/security/MessageDigest.java` | You need the `isEqual` implementation to confirm it is constant-time |
| `external/conscrypt/common/src/main/java/org/conscrypt/OpenSSLProvider.java` | The algorithm registry — the authoritative list of what this device actually supports |
| `external/conscrypt/common/src/main/java/org/conscrypt/OpenSSLCipher.java` | The cipher SPI implementations, including where the GCM nonce is generated when the caller supplies none |
| `external/conscrypt/common/src/main/java/org/conscrypt/NativeCrypto.java` | The JNI surface. The bridge you cross when you move from Java hooks to native hooks |
| `external/boringssl/src/crypto/fipsmodule/aes/` | AES itself, including the hardware-accelerated paths |
| `external/boringssl/src/crypto/fipsmodule/modes/gcm.c` | GHASH — read it if you want to understand *why* nonce reuse recovers the subkey `H` |
| `external/boringssl/src/crypto/rand/` | The DRBG and `CRYPTO_sysrand`. The bottom of the randomness stack |
| `frameworks/base/keystore/java/android/security/keystore/KeyGenParameterSpec.java` | Every option and its API level, authoritatively |
| `frameworks/base/keystore/java/android/security/keystore/KeyInfo.java` | The fields you read to prove where a key lives |
| `system/security/keystore2/` | The keystore daemon (Android 12+). Read it to understand what actually happens across Binder when the app calls `doFinal` on a keystore key |
| `hardware/interfaces/security/keymint/` | The KeyMint HAL — the boundary between Android and the secure world |

---

## Tooling

| Tool | Where | Use |
|---|---|---|
| [Frida](https://frida.re/docs/android/) | host + device | The engine behind [`scripts/frida-jca-universal-hook.js`](../scripts/frida-jca-universal-hook.js) |
| [Frida Java API](https://frida.re/docs/javascript-api/#java) | docs | `Java.use`, `Java.choose`, `.overloads`, `Java.enumerateClassLoaders` |
| [Objection](https://github.com/sensepost/objection) | host | `android keystore list` and `android heap search instances` are the two commands worth knowing |
| [Semgrep](https://semgrep.dev/) | host | Runs [`scripts/semgrep-crypto.yml`](../scripts/semgrep-crypto.yml). AST matching, so it does not fire on commented-out code |
| [jadx](https://github.com/skylot/jadx) | host | Decompilation. Use `--show-bad-code` when it fails |
| [apktool](https://apktool.org/) | host | Smali plus decoded resources. The Smali is ground truth when the decompiler is not |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | host | Fast first pass. Treat every crypto finding it reports as a candidate, never as a conclusion |
| [CyberChef](https://gchq.github.io/CyberChef/) | host, browser | Quick decode/decrypt experiments. **Never paste client key material into a hosted instance** — run it locally |
| [PyCryptodome](https://pycryptodome.readthedocs.io/) | host | Writing your own decryptor, as in [Lab 01](../labs/lab-01-break-the-vault.md) |
| [`cryptography`](https://cryptography.io/) | host | The other Python option; better primitives, stricter API |
| [PadBuster](https://github.com/GDSSecurity/PadBuster) | host | A reference padding-oracle implementation to check your own against, after [Lab 04](../labs/lab-04-ctf-padding-oracle.md) |
| [SQLCipher](https://www.zetetic.net/sqlcipher/) | library | You will meet it in apps; know how its key derivation works before assessing it |

---

## Papers and named attacks

Safe to cite by name. Each is well documented and unambiguous.

| Work | Why it matters here |
|---|---|
| Shannon, *Communication Theory of Secrecy Systems* (1949) | The one-time pad proof — why "random, as long as the message, never reused" is the only unbreakable scheme, and why nobody uses it |
| Vaudenay, *Security Flaws Induced by CBC Padding* (EUROCRYPT 2002) | **The padding oracle.** The source for [Lab 04](../labs/lab-04-ctf-padding-oracle.md) |
| Bleichenbacher, *Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1* (CRYPTO '98) | Why RSA PKCS#1 v1.5 encryption padding is a finding; revived as ROBOT in 2017 |
| Joux, *Authentication Failures in NIST version of GCM* | The forbidden attack: repeated nonces recover the GHASH subkey `H` |
| Böck, Zauner, Devlin, Somorovsky, Jovanovic, *Nonce-Disrespecting Adversaries* (WOOT 2016) | The same attack demonstrated at internet scale against real TLS servers. The citation that makes GCM nonce reuse concrete for a sceptical developer |
| AlFardan and Paterson, *Lucky Thirteen* (2013) | Timing side channel in MAC-then-encrypt. Why the ordering is not stylistic |
| Duong and Rizzo, BEAST (2011) | Why CBC IVs must be unpredictable, not merely unique |
| Stevens et al., *The first collision for full SHA-1* (2017) | SHAttered. The citation for "SHA-1 must not be used for signatures" |
| Bhargavan and Leurent, *On the Practical (In-)Security of 64-bit Block Ciphers* (2016) | Sweet32 — why 3DES and Blowfish are deprecated |
| Biryukov, Dinu, Khovratovich, *Argon2* | The Password Hashing Competition winner and its parameter reasoning |
| Kelsey, Schneier, Wagner, Hall, *Cryptanalytic Attacks on Pseudorandom Number Generators* (1998) | Why PRNG state recovery is a practical attack, not a theoretical one |

### Historical cases worth knowing by name

| Case | Lesson |
|---|---|
| Sony PS3 ECDSA (2010) | A constant `k` in ECDSA signing revealed the code-signing private key. The canonical nonce-reuse story, and the one that makes the point fastest in a room |
| Debian OpenSSL PRNG (CVE-2008-0166) | A patch removed entropy, reducing the keyspace to 32,768 keys. Nothing looked wrong for two years. The canonical "randomness failure is invisible" case |
| Android `SecureRandom` seeding (August 2013) | Improper PRNG seeding in some app contexts led to repeated ECDSA nonces and Bitcoin key theft. The reason Android's `SecureRandom` guidance exists in the form it does |
| ROCA (CVE-2017-15361) | Structured RSA key generation in an Infineon library allowed factoring. Shows that key *generation* is part of the attack surface |

> **Warning**
> Do not cite a CVE number you have not verified against the vendor's own advisory. In a client report,
> one incorrect CVE reference undermines every other claim in the document. When in doubt, describe the
> vulnerability class by name ("a padding oracle in the CBC decryption path") rather than reaching for
> an identifier. Every CVE listed above is well documented; anything else, check first.

---

## Books and long-form

| Work | Why |
|---|---|
| *Serious Cryptography* — Jean-Philippe Aumasson | The best single book for this chapter's audience. Modern, practical, honest about what matters. If you read one book, this one |
| *Cryptography Engineering* — Ferguson, Schneier, Kohno | The design-level companion: how to combine primitives without inventing a flaw. The chapters on key management and randomness are the strongest |
| *Real-World Cryptography* — David Wong | Protocol-oriented and current; good on AEAD, key exchange and what the industry actually deploys |
| *The Cryptopals Crypto Challenges* — cryptopals.com | Not a book, but the best way to internalise this material. Set 2 is ECB and CBC; Set 3 is the padding oracle. Do them in the language you use daily |
| *Android Security Internals* — Nikolay Elenkov | The keystore and provider architecture in structural detail. Dated in specifics, still the clearest account of the shape |
| *A Graduate Course in Applied Cryptography* — Boneh & Shoup (free online) | When you want the proofs behind a claim rather than the claim |

---

## Talks worth finding

Search by topic rather than URL, since hosting moves.

- Padding oracle attacks explained and demonstrated live — Black Hat and DEF CON, multiple years
- "Nonce-Disrespecting Adversaries" — the WOOT 2016 presentation of the GCM nonce-reuse survey
- Android KeyStore and hardware-backed security — Android Security & Privacy talks at Google I/O
- Tink design rationale — Google crypto team talks on misuse-resistant API design
- Mobile app crypto failures — OWASP AppSec and MASTG project sessions

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [33-Storage](../../33-Storage/README.md) | Where the ciphertext lands, and where the plaintext copy usually is |
| [35-SSL](../../35-SSL/README.md) | The same primitives applied to transport |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Pinning the public key — signatures in practice |
| [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | The XML that governs trust decisions |
| [46-Tokens](../../46-Tokens/README.md) | JWT signing and the `alg:none` class of failure |
| [47-Authentication](../../47-Authentication/README.md) | Where passwords come from, before they reach a KDF |
| [48-Biometrics](../../48-Biometrics/README.md) | The authentication side of `setUserAuthenticationRequired` |
| [**49-KeyStore**](../../49-KeyStore/README.md) | **Hardware-backed key storage in depth — read this next** |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | TEE, StrongBox, KeyMint and attestation |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Why XOR strings are usually not a crypto finding |
| [13-ART](../../13-ART/README.md) | Why your hook did not fire, and how to extract installed bytecode |
| [53-Frida](../../53-Frida/README.md) | The instrumentation engine behind every script here |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | Cryptography as the attacker's tool: config and payload decryption |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Mapping findings to MASVS controls |
