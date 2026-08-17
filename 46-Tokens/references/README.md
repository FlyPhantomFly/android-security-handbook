# 46 — Tokens · References

Annotated. Every entry says *why you would open it*, not just what it is.

Ordered by how often you will actually reach for them, not by RFC number.

---

## Start here

**RFC 8725 — JSON Web Token Best Current Practices**
The single most useful document for this chapter, and short. It is the normative source for
almost every control in [§5](../README.md#5-security-perspective). The sections you will
cite in reports:

| Section | Says |
|---|---|
| §3.1 | Perform algorithm verification — the verifier decides, not the token |
| §3.2 | Use appropriate algorithms; maintain an allow-list |
| §3.3 | Validate all cryptographic operations; avoid RSA1_5 key wrapping |
| §3.5 | Use appropriate key sizes and entropy — this is the weak-secret rule |
| §3.8 | **Do not trust received public keys** — the `jku` / `jwk` / `x5u` / `x5c` rule |
| §3.9 | Validate issuer and subject; validate expiry |
| §3.10 | Use `typ` and `crit` correctly |
| §3.11 | Use mutually exclusive validation rules; be strict about encoding |

If you read one reference, read this one.

**OWASP JSON Web Token Cheat Sheet**
A current, practical summary of the same failure classes from a defensive angle. Good for
handing to a developer alongside a finding, because it is written for them rather than for
you.

---

## The formats

**RFC 7519 — JSON Web Token (JWT)**
The claims set. §4.1 defines the seven registered claims and NumericDate; §6 defines the
unsecured (`alg: none`) JWT, which is worth reading precisely so you can quote the RFC when
somebody insists `none` "is not a real algorithm". It is.

**RFC 7515 — JSON Web Signature (JWS)**
The three-segment structure and the JOSE header. §5.1 defines the signing input as
`ASCII(BASE64URL(header) || '.' || BASE64URL(payload))` — this is the normative source for
"never re-serialise a token you intend to verify". §4.1.11 covers `crit`.

**RFC 7516 — JSON Web Encryption (JWE)**
The five-segment form. Read it once so you recognise a JWE and stop trying to decode it.

**RFC 7517 — JSON Web Key (JWK)**
The key format and the JWKS document. You will meet it when reconstructing a public key
from a `jwks_uri`, which is step one of the algorithm-confusion attack.

**RFC 7518 — JSON Web Algorithms (JWA)**
The algorithm registry. **§3.2 is the one to cite**: an HMAC key must be at least as long
as the hash output — 32 bytes for HS256. §3.4 specifies that ECDSA signatures in JOSE are
the raw `r‖s` concatenation, not DER, which is the detail that breaks every hand-rolled
ES256 implementation.

**RFC 7638 — JWK Thumbprint**
Required members only, sorted lexicographically, no whitespace. This is `cnf.jkt`. Get the
serialisation wrong and your DPoP thumbprint silently does not match the server's.

**RFC 4648 §5 — base64url**
Two characters and the padding rule. Twenty lines, and it settles every "is this base64"
argument.

---

## The security mechanisms

**RFC 6750 — OAuth 2.0 Bearer Token Usage**
Defines `Authorization: Bearer` and is admirably direct about the threat model that comes
with it. §5 (Security Considerations) is the citation for "possession is sufficient".

**RFC 9449 — DPoP (Demonstrating Proof of Possession)**
Sender-constraining at the application layer. §4.2 lists the proof's claims (`jti`, `htm`,
`htu`, `iat`, `ath`); §4.3 lists what the server must check; §8 covers the nonce mechanism
you will hit the first time a server turns it on. Read §4.3 before testing a DPoP
deployment — it is a ready-made test plan.

**RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Tokens**
The transport-layer alternative. `cnf["x5t#S256"]`. Relevant in open banking and FAPI
estates, awkward on mobile, stronger than DPoP where the PKI already exists.

**RFC 7800 — Proof-of-Possession Key Semantics for JWTs**
Defines the `cnf` claim itself. Short. Worth reading to understand that DPoP and mTLS are
two instantiations of one idea.

**RFC 7009 — OAuth 2.0 Token Revocation**
The endpoint that logout should be calling and usually is not. Note §2.2: the server returns
200 even for an unknown token, deliberately, so a revocation call is not an oracle for token
validity.

**RFC 7662 — OAuth 2.0 Token Introspection**
How a resource server validates an opaque token. The other half of the opaque-versus-JWT
trade in [§3.3](../README.md#33-opaque-tokens-and-why-the-distinction-changes-everything).

**RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens**
`typ: at+jwt`, the required claims, and — the sentence to quote — the explicit requirement
that the resource server validate `aud`. When you find an `at+jwt` token whose audience is
not checked, this RFC is your citation.

**RFC 8693 — OAuth 2.0 Token Exchange**
Delegation versus impersonation, `subject_token` and `actor_token`, and the scope rules that
servers forget to intersect.

**RFC 6749 §6 — Refreshing an Access Token**
Three paragraphs, and one of them says the scope requested on a refresh must not exceed the
original grant. That is the citation for the scope-escalation finding.

**OAuth 2.0 Security Best Current Practice (`draft-ietf-oauth-security-topics`)**
The refresh-token guidance that [45-OAuth §3.8](../../45-OAuth/README.md) defers to this
chapter for: public-client refresh tokens must be sender-constrained *or* rotated with
reuse detection. Also the source of the mix-up and code-injection analyses. Track the
current draft; it has been stable in substance for some time.

**RFC 8252 — OAuth 2.0 for Native Apps**
Owned by [45-OAuth](../../45-OAuth/README.md), listed here because §8.6 is about token
storage on the device and is the normative hook for half of
[§3.7](../README.md#37-where-a-token-lives-on-android--the-four-options).

---

## Android platform

**`android.util.Base64` — developer documentation**
The flag constants and their values. `URL_SAFE` (8), `NO_WRAP` (2), `NO_PADDING` (1). All
three are needed for JOSE, and recognising `8`, `10` and `11` in decompiled code is how you
find every JOSE site in an app.

**`java.util.Base64` — API 26**
Listed as a trap rather than a resource. Code copied from a server-side JWT example uses it
and crashes on anything below Oreo without core library desugaring.

**Jetpack Security — `androidx.security:security-crypto`**
`EncryptedSharedPreferences` and `MasterKey`. Read the documentation for the two encryption
schemes: AES-SIV for keys (deterministic, so lookups work) and AES-GCM for values
(randomised and authenticated). API 23 floor.

**`android.accounts.AccountManager` — developer documentation**
The shared token store. Read the `getAuthToken` overloads and the account-type ownership
model before deciding whether a token there is reachable by another app.

**Android Keystore system — developer documentation**
`KeyGenParameterSpec`, `setIsStrongBoxBacked`, `setUserAuthenticationRequired`, and
`KeyInfo.getSecurityLevel()`. [49-KeyStore](../../49-KeyStore/README.md) covers all of it
properly; this is the pointer for when you need the API surface quickly.

**Auto Backup and `android:dataExtractionRules`**
The API 31+ format with its two independent sections, `cloud-backup` and `device-transfer`.
Excluding a token store from one and not the other is an easy and common half-fix.

---

## AOSP source

Paths, not line numbers — AOSP file paths are stable, line numbers are not.

| Path | Why |
|---|---|
| `frameworks/base/core/java/android/util/Base64.java` | The encode and decode tables. The URL-safe alphabet differs from the standard one in exactly two entries, and the **decoder accepts both** — a parser-differential hazard worth knowing about |
| `frameworks/base/core/java/android/accounts/AccountManager.java` | The client API for the shared token store |
| `frameworks/base/services/core/java/com/android/server/accounts/AccountManagerService.java` | The grants model, and the `accounts_ce.db` / `accounts_de.db` split that makes token storage Direct-Boot aware |
| `frameworks/base/core/java/android/accounts/AbstractAccountAuthenticator.java` | What an app implements to own an account type |
| `frameworks/base/core/java/android/app/SharedPreferencesImpl.java` | `apply()` versus `commit()`, and the `.bak` file `writeToFile` leaves behind — the file people forget to read during a sweep |
| `external/conscrypt/` | The provider doing the actual signature verification, if an app verifies locally |

---

## OWASP

**MASVS v2 — MASVS-AUTH**
AUTH-1 (server-enforced authentication and authorisation), AUTH-2 (local authentication
bound to a cryptographic operation), AUTH-3 (step-up for sensitive operations).
[71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) cites this chapter against AUTH's
*"Replayed requests with downgraded session"*, which maps to two tests here: replay after
logout, and the DPoP Bearer downgrade.

**MASVS-STORAGE-1 and -2**
Sensitive data not stored insecurely, and not leaked through unintended channels.
[§3.7](../README.md#37-where-a-token-lives-on-android--the-four-options) and
[§5.9](../README.md#59-android-specific-leak-paths).

**MASTG**
The session-management and credential-confidentiality test cases. **Cite the current
identifiers from the live site.** The project renumbers its tests between major versions,
and a stale MASTG-TEST ID in a report is worse than none.

---

## Tools

| Tool | Use |
|---|---|
| `hashcat -m 16500` | GPU HS* secret cracking. Roughly four orders of magnitude faster than this chapter's Python implementation, which exists to make the mechanism legible |
| `jwt_tool` | A mature JWT attack toolkit covering the same classes as this chapter's gauntlet, plus a few more. Cited in [80-Appendix](../../80-Appendix/README.md) |
| Burp Suite — JWT extensions | In-proxy tampering. Convenient, and no substitute for understanding what it is doing |
| `openssl rsa -pubin -text` | Reading a public key when you need to match its exact byte form for algorithm confusion |
| `jq` | Every token response in this chapter |

**This chapter's own tools**, which are the ones the labs use:

| Script | Use |
|---|---|
| [`scripts/jwt-analyse.py`](../scripts/jwt-analyse.py) | Every claim with a verdict, every failure class flagged, **never transmits** — has a socket guard and a `--self-test` that proves it |
| [`scripts/jwt-weak-secret.py`](../scripts/jwt-weak-secret.py) | Offline HS* cracking against a wordlist, plus secret grading |
| [`scripts/token-storage-sweep.sh`](../scripts/token-storage-sweep.sh) | Device-side sweep that prints its **access level first**, so an empty result is never read as "no tokens" |
| [`scripts/token-hooks.js`](../scripts/token-hooks.js) | Six Frida hook surfaces, redacted output, fingerprint correlation between storage and network |
| [`labs/gauntlet/issuer.py`](../labs/gauntlet/issuer.py) | The local token issuer every lab uses |
| [`labs/gauntlet/run-gauntlet.py`](../labs/gauntlet/run-gauntlet.py) | Nine tokens, two verifiers, an asserted result matrix |
| [`labs/ctf/ledger_api.py`](../labs/ctf/ledger_api.py) | The CTF backend — four flaws at four layers, loopback only |

---

## Research and talks

Search by topic and speaker rather than by URL; hosting moves and a dead link in a
reference list is worse than a search term.

- **"Critical vulnerabilities in JSON Web Token libraries"** — the 2015 Auth0 write-up that
  named algorithm confusion and the `alg: none` class. Still the clearest statement of the
  mechanism, and the reason both are in every checklist.
- **"Hacking JSON Web Tokens"** — the general body of conference material on `kid`
  injection, `jku` abuse and embedded-key headers. Look for AppSec and Black Hat sessions.
- **OAuth security analyses from the IETF OAuth working group** — the formal analyses behind
  the Security BCP. Dense, and the source of the mix-up attack material.
- **"Sign in with X" account-takeover research** — a recurring bug-bounty pattern, almost
  always an unchecked `aud` or an unverified signature at the relying party's backend.
  [45-OAuth §5.1 Attack 6](../../45-OAuth/README.md) has the flow.
- **PASETO's design rationale** — worth reading as a *critique* of JOSE. Its core argument is
  that a token format should not let the token choose its own algorithm, which is exactly
  [§5.1](../README.md#51-failure-class-1--alg-none-accepted) and
  [§5.2](../README.md#52-failure-class-2--hsrs-algorithm-confusion) stated as a design
  principle. You do not have to agree to learn from it.

---

## Related chapters

| Chapter | What it owns, and why you would go there |
|---|---|
| [**45-OAuth**](../../45-OAuth/README.md) | **The flow that produced the token**: grant types, PKCE, redirect handling, custom-scheme hijacking, Custom Tabs versus WebView, `state` and `nonce`. Go there when the question is *how the token was obtained*; stay here when it is *what the token is*. Its §3.8 explicitly defers to this chapter for refresh-token handling |
| [**34-Cryptography**](../../34-Cryptography/README.md) | **The primitives** underneath the signature: HMAC, RSA, ECDSA, SHA-256, modes, padding, randomness. Go there when the finding is about the algorithm rather than about how it was assembled — and for what a hardcoded-key finding is really worth |
| [**49-KeyStore**](../../49-KeyStore/README.md) | **Key storage**: hardware backing, attestation, and the extraction-versus-use distinction that decides the severity of half the findings in this chapter. §1.3 is the paragraph to memorise |
| [**33-Storage**](../../33-Storage/README.md) | **At-rest mechanics**: SharedPreferences and SQLite file formats, the WAL where deleted rows survive, CE/DE, backup channels, and the reachability method (§5.3) that separates a finding from noise |
| [35-SSL](../../35-SSL/README.md) | **Transport.** Go there to capture the token in the first place; come back to find out what it means |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Why you cannot see the token yet |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | Why another app usually *cannot* read the token store — the control you must argue past before a storage finding stands |
| [43-WebView](../../43-WebView/README.md) | Tokens injected into a page or into `localStorage`, where any script in the WebView reaches them |
| [27-ContentProviders](../../27-ContentProviders/README.md) | An exported provider that hands out the token, and the traversal that reaches its file |
| [26-Intent](../../26-Intent/README.md) | A callback URI or token forwarded in an Intent extra, and what `dumpsys` records about it |
| [29-BroadcastReceivers](../../29-BroadcastReceivers/README.md) | The measurement that `dumpsys` keeps broadcast extras in cleartext — relevant to your own testing hygiene, not just to the app |
| [53-Frida](../../53-Frida/README.md) | The instrumentation engine behind `token-hooks.js`, and setup for a device that has frida-server |
| [52-StaticAnalysis](../../52-StaticAnalysis/README.md) | Sweeping an app for token handling, and the measured lesson that a sweep produces leads rather than findings |
| [56-JADX](../../56-JADX/README.md) | Reading the decompiled token-handling code, and why the decompiler's own error count understates its failures by 30x |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What R8 removes, and why claim names survive it — they are part of a contract with the server |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Mapping these findings to MASVS controls and writing them up in the form a client expects |
| [79-Glossary](../../79-Glossary/README.md) | One-line definitions: bearer token, JWT, DPoP |
| [80-Appendix](../../80-Appendix/README.md) | The tool table (`jwt_tool`, `hashcat`) and the review checklist that cites this chapter |

Referred to in plain text throughout the chapter rather than linked, and **all now written**:
**[47-Authentication](../../47-Authentication/README.md)** (sessions and server-side enforcement),
**[48-Biometrics](../../48-Biometrics/README.md)** (`CryptoObject` binding),
**[50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md)**,
**[51-DynamicAnalysis](../../51-DynamicAnalysis/README.md)**.

---

Back to [the chapter](../README.md) · [cheat sheet](../cheatsheet.md) ·
[mind map](../mindmap.md) · [FAQ](../faq.md)
