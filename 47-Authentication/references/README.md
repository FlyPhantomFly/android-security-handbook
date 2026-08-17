# 47 — Authentication · References

Annotated. Every entry says **why you would open it**, not just what it is.

---

## Read these first

| Source | Why |
|---|---|
| **NIST SP 800-63B**, *Digital Identity Guidelines: Authentication and Lifecycle Management* | The authoritative source on password policy, rate limiting, factor strength and session lifetime. It is also the document that killed mandatory password rotation and composition rules, so it is what you cite when a client insists on both. Read §5 (authenticators) and §7 (session management). |
| **OWASP MASVS**, MASVS-AUTH | The control taxonomy your report will be mapped against. Three controls: remote enforcement, local authentication correctness, step-up. |
| **OWASP MASTG**, the MASVS-AUTH test cases | The procedures. Read them alongside [§7](../README.md#7-dynamic-analysis) — this chapter's ordering (proxy first, Frida last) is deliberate and the MASTG does not impose one. |
| **W3C Web Authentication (WebAuthn) Level 3** | The passkey ceremony. Read the *relying party* verification steps, because that is where every passkey integration is actually broken — see [`examples/03`](../examples/03-CredentialManagerLogin.kt). |

---

## Android platform documentation

| Source | Why |
|---|---|
| *Sign in your user with Credential Manager* | The modern unified API. Note the API-34 platform / `androidx.credentials` split described in [§3.6](../README.md#36-credential-manager-and-passkeys). |
| *Autofill framework* and *Optimize your app for autofill* | What crosses the boundary to a third-party password manager, and the `importantForAutofill` attribute that is so often applied backwards. |
| *Retrieve a verification code automatically* (SMS Retriever API) | The permissionless OTP path, the 11-character hash, and the 140-byte message format. |
| *Request one-time consent to read a verification code* (SMS User Consent API) | Use this when you cannot control the message format. |
| *AccountManager* and *Creating a custom account type* | The consumer and the authenticator sides. The documentation does **not** tell you the storage is plaintext SQLite; [§3.4](../README.md#34-accountmanager--what-is-actually-on-disk) measures it. |
| *Digital Asset Links* / *Verify Android App Links* | The origin binding that makes a passkey app-specific. Fetch a target's `assetlinks.json` and read it — a wildcard, a debug certificate or a stale test package silently destroys the phishing resistance. |
| Android Security — *Authentication* (Gatekeeper, synthetic password, Weaver) | The device-credential stack behind `KeyguardManager`. Background for [48-Biometrics](../../48-Biometrics/README.md). |

---

## AOSP source

Stable file paths. No line numbers — they move between releases, and this repository does not
cite them.

### Accounts

| Path | Why |
|---|---|
| `frameworks/base/core/java/android/accounts/AccountManager.java` | Where every account call begins before becoming a Binder transaction |
| `frameworks/base/core/java/android/accounts/IAccountManager.aidl` | **Read this rather than the docs.** The AIDL is the true API surface |
| `frameworks/base/core/java/android/accounts/AbstractAccountAuthenticator.java` | The authenticator contract — `addAccount`, `getAuthToken`, `confirmCredentials` |
| `frameworks/base/core/java/android/accounts/Account.java` | The value type and its safe-string form. This is why `dumpsys account` masks names even for root |
| `frameworks/base/services/core/java/com/android/server/accounts/AccountManagerService.java` | The visibility checks, the caller-uid checks, and the `dumpsys` output |
| `frameworks/base/services/core/java/com/android/server/accounts/AccountsDb.java` | The CE/DE split and the table definitions measured in [§3.4](../README.md#34-accountmanager--what-is-actually-on-disk) |

### Autofill

| Path | Why |
|---|---|
| `frameworks/base/core/java/android/app/assist/AssistStructure.java` | **The security-relevant file.** Its `ViewNode` accessors define exactly what a third-party service receives |
| `frameworks/base/core/java/android/view/autofill/AutofillManager.java` | The in-process client and its session state machine |
| `frameworks/base/core/java/android/service/autofill/AutofillService.java` | What a password manager extends |
| `frameworks/base/services/autofill/java/com/android/server/autofill/AutofillManagerService.java` | Per-user service resolution from the `autofill_service` secure setting |

### Credential Manager (API 34+)

| Path | Why |
|---|---|
| `frameworks/base/core/java/android/credentials/CredentialManager.java` | The platform client |
| `frameworks/base/core/java/android/service/credentials/CredentialProviderService.java` | What a third-party provider extends |
| `frameworks/base/services/credentials/java/com/android/server/credentials/CredentialManagerService.java` | The broker. Note it is the autofill architecture again, for the same anti-phishing reason |

### Lock settings and windows

| Path | Why |
|---|---|
| `frameworks/base/services/core/java/com/android/server/locksettings/LockSettingsService.java` | Backs `KeyguardManager.isDeviceSecure()` |
| `frameworks/base/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java` | The `spblob` artefacts that persist even with no credential set |
| `frameworks/base/core/java/android/app/KeyguardManager.java` | `isDeviceSecure`, `createConfirmDeviceCredentialIntent` |
| `frameworks/base/core/java/android/view/WindowManager.java` | `LayoutParams.FLAG_SECURE = 0x2000` — the constant javac inlines |
| `frameworks/base/services/core/java/com/android/server/wm/WindowState.java` | Where the flag becomes window state and the screenshot path consults it |
| `frameworks/base/telephony/java/android/telephony/SmsManager.java` | `createAppSpecificSmsToken` |

> **The SMS Retriever API is not in AOSP.** It is a Google Play services component with no
> public source, so its hash-matching behaviour is *documented* rather than verifiable. The
> empirical check is whether a message carrying the computed hash is delivered.

---

## RFCs and standards

| Identifier | Title | Why here |
|---|---|---|
| RFC 6750 | Bearer Token Usage | Defines the word that makes possession sufficient |
| RFC 8252 | OAuth 2.0 for Native Apps | Why the system browser and not a WebView — see [45-OAuth](../../45-OAuth/README.md) |
| RFC 9449 | DPoP | Sender-constrained credentials; the implementation of the top of the device-binding ladder |
| RFC 6238 / RFC 4226 | TOTP / HOTP | App-based second factors |
| RFC 7519 | JSON Web Token | See [46-Tokens](../../46-Tokens/README.md), which owns the format entirely |
| RFC 2606 | Reserved Top Level DNS Names | Why every endpoint in this chapter is `.invalid` — it can never resolve |
| FIDO2 CTAP2 | Client to Authenticator Protocol | What the authenticator actually does during a passkey ceremony |

---

## CWE

Authentication defects rarely receive CVEs — they live in one application and its backend and
are fixed by a deployment. CWE is the correct taxonomy, and a CWE plus a clean reproduction is
stronger than an invented CVE number. See
[§5.0](../README.md#50-how-this-section-is-organised-and-a-note-on-identifiers).

| CWE | Title |
|---|---|
| CWE-287 | Improper Authentication |
| CWE-603 | Use of Client-Side Authentication |
| CWE-306 | Missing Authentication for Critical Function |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts |
| CWE-203 / CWE-204 | Observable Discrepancy / Response Discrepancy |
| CWE-256 / CWE-522 | Plaintext Storage / Insufficiently Protected Credentials |
| CWE-613 | Insufficient Session Expiration |
| CWE-620 | Unverified Password Change |
| CWE-639 | Authorization Bypass Through User-Controlled Key (IDOR / BOLA) |
| CWE-640 | Weak Password Recovery Mechanism |
| CWE-798 | Use of Hard-coded Credentials |
| CWE-384 | Session Fixation |

**OWASP API Security Top 10** is worth reading alongside these: its API1 (Broken Object Level
Authorization) and API2 (Broken Authentication) are exactly [§5.9](../README.md#59-idor--bola--the-authorisation-half)
and [§5.1](../README.md#51-the-client-side-authentication-gate), from the backend's side of the
same boundary.

---

## Talks and research worth your time

Rather than list conference talks by title and risk misattributing them, here are the **search
terms that find the current best material**, which is more useful because this area moves:

- *"passkey relying party verification mistakes"* — the recurring integration errors are
  challenge reuse, unchecked origin, and trusting `assetlinks.json` served from infrastructure
  the identity team does not control.
- *"OAuth and OIDC mobile app security"* — for the boundary this chapter shares with
  [45-OAuth](../../45-OAuth/README.md).
- *"BOLA API security testing methodology"* — the two-account replay method in
  [§5.9](../README.md#59-idor--bola--the-authorisation-half) is the standard one.
- *"SIM swap account recovery"* — the threat that bounds what SMS OTP can be worth.
- *"account recovery is the weakest link"* — the general argument behind
  [§3.13](../README.md#313-registration-password-reset-and-the-flows-nobody-tests), and the one
  that becomes most important as passkeys remove the primary-flow weaknesses.

---

## This chapter's own artefacts

| File | What it is |
|---|---|
| [`../scripts/auth-surface-scan.py`](../scripts/auth-surface-scan.py) | APK authentication-surface inventory. **Read its header** — it documents two false positives it made about itself |
| [`../scripts/auth-hooks.js`](../scripts/auth-hooks.js) | Frida. Recovers the whole authentication design at runtime by hooking platform classes only |
| [`../scripts/accountmanager-audit.sh`](../scripts/accountmanager-audit.sh) | Device account-database audit. Never prints a credential value |
| [`../scripts/sms-retriever-hash.py`](../scripts/sms-retriever-hash.py) | The 11-character app hash from an APK. Cross-validated against `apksigner` on 5 of 5 real APKs |
| [`../scripts/enum-timing-probe.py`](../scripts/enum-timing-probe.py) | Four enumeration oracles, and a verdict that can be INCONCLUSIVE |
| [`../scripts/session-lifecycle-probe.py`](../scripts/session-lifecycle-probe.py) | Seven lifecycle tests, two accounts, no guessing |
| [`../labs/authlab/auth_server.py`](../labs/authlab/auth_server.py) | Twelve labelled defects and their fixes, sharing one API |
| [`../labs/ctf/vault_auth.py`](../labs/ctf/vault_auth.py) | The CTF backend. `--verify` proves all four flag paths before you start |
| [`../examples/06-otp-verify.c`](../examples/06-otp-verify.c) | Constant-time comparison, measured on real arm64 hardware |

---

## Measurements recorded in this chapter

Recorded here because they are the kind of thing that gets "corrected" back to the wrong answer
by somebody editing from memory. All were taken on a physical **Redmi `M2101K6P` (`sweetin`),
Android 11 / API 30, arm64-v8a**, rooted with Magisk.

| Claim | What measurement showed |
|---|---|
| Grep an APK for `FLAG_SECURE` to check it is set | **Impossible.** An Activity that provably sets it was compiled: the identifier is absent from the `.class` and the DEX, while `setFlags` survives and the constant appears only as `const/16 v0, #int 8192`. True-positive rate zero |
| `AccountManager.setPassword` is legacy and unused | **In use on a shipping consumer device** — a 352-character value in the plaintext `accounts.password` column |
| Modern bearer credentials are JWTs | **117 real cached tokens, zero JWTs.** 108 were opaque Google `ya29` access tokens |
| `dumpsys account` masks names because of a permission check | **Unconditional.** Root and shell produce byte-identical masked output |
| A non-constant-time comparison of an OTP is a timing oracle | **Did not reproduce at 6 bytes (delta −51 ns) or 64 bytes (+1 ns)**, locally, 200,000 samples. Distinguishable only at 512 bytes (+417 ns). `ct_compare` measured **+0 ns at every length** |
| Expired auth tokens are cleaned up | **106 of 116 expiry records were in the past** and retained indefinitely. Longest live TTL ~51 min |
| `GET_ACCOUNTS` in a manifest means the app can list accounts | Grants nothing since API 26. **7 of 17 real apps still declare it**; 5 declare the removed `AUTHENTICATE_ACCOUNTS` |
| Credential Manager is available on modern devices | **No `credentials` service below API 34.** `android.security.identity` is present from API 30 and is a *different* API |
| Apps have moved to the permissionless OTP path | **12 of 17 have SMS Retriever markers and 9 also have full-inbox SMS markers.** The overlap is the finding |
| "Device binding" means a hardware key | **15 of 17 use an OS identifier; 3 of 17 attest a key.** The weak form is ~5x more common |

Two of those corrected this chapter's **own** tooling, and the method is the transferable part:
`getPassword` was rated a STRONG `AccountManager` marker until cross-referencing the type
descriptor showed at least 2 of 15 hits were pure false positives, and the certificate parser in
`sms-retriever-hash.py` produced a confident, plausible, **wrong** fingerprint until it was
checked against `apksigner`. **If the output looks reasonable, verify it against an independent
tool before believing it.**

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [45-OAuth](../../45-OAuth/README.md) | Owns the delegation protocol: grant types, PKCE, redirect URIs, scheme hijacking. This chapter owns the first-party decision |
| [46-Tokens](../../46-Tokens/README.md) | Owns the credential's format, storage and the eight verification failure classes — including the JWT distinction between signature failures and claim failures |
| [48-Biometrics](../../48-Biometrics/README.md) | Owns the prompt, sensor classes and `CryptoObject` binding. This chapter owns only where a local prompt belongs in the flow |
| [49-KeyStore](../../49-KeyStore/README.md) | Owns key material and the extraction-versus-use distinction |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | Attestation, and the measured fact that a boot-state property can lie while the TEE does not |
| [34-Cryptography](../../34-Cryptography/README.md) | The KDF a password reaches after these flows. Its references table points here for where passwords come from |
| [33-Storage](../../33-Storage/README.md) | Where a credential lands, and why presence is not a finding |
| [35-SSL](../../35-SSL/README.md) · [36-CertificatePinning](../../36-CertificatePinning/README.md) | The transport carrying every request here |
| [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | Trust configuration, and the modified-system-store methodology trap |
| [43-WebView](../../43-WebView/README.md) | The second cookie jar that logout forgets |
| [30-Activities](../../30-Activities/README.md) | Launching a post-login screen, tapjacking, and the no-Gradle APK build recipe the CTF client uses |
| [32-Manifest](../../32-Manifest/README.md) | Reading permissions, authenticator services and `autoVerify` |
| [25-Binder](../../25-Binder/README.md) | Why `getCallingUid()` is unforgeable, which is what makes account visibility a real control |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) · [22-SELinux](../../22-SELinux/README.md) | The two layers that actually protect `accounts_ce.db` |
| [19-Memory](../../19-Memory/README.md) | Why scrubbing a password is best-effort, and why `explicit_bzero` is not available |
| [40-Obfuscation](../../40-Obfuscation/README.md) · [42-R8](../../42-R8/README.md) | What survives minification; Kotlin property names as a member-level mapping with no mapping file |
| [53-Frida](../../53-Frida/README.md) · [54-Objection](../../54-Objection/README.md) | The instrumentation in [§7](../README.md#7-dynamic-analysis), and the measured limits of canned bypasses |
| [51-DynamicAnalysis](../../51-DynamicAnalysis/README.md) · [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Why a sweep produces leads, and why runtime evidence cannot supply its own denominator |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Remote attestation, and the split-APK trap that makes a scan report zero controls |
| [37-RootDetection](../../37-RootDetection/README.md) · [67-BypassingProtections](../../67-BypassingProtections/README.md) | The controls that sit around an authentication gate, and the altitude vocabulary this chapter borrows |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS mapping and report structure |
| [79-Glossary](../../79-Glossary/README.md) | IDOR, BOLA, HKDF/PBKDF2 and the rest of the vocabulary |
