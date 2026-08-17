# 71 — OWASP MAS · Cheat Sheet

Printable. Tables only. The condensed version lives in
[README §13](README.md#13-summary); **this is the full version** — every category with every control,
the identifier schemes, the citation forms, the retired-identifier problem, and a finding-to-control
lookup sized for a report write-up.

> **Provenance.** Control *titles* below are paraphrases written for testers, not quotations of the
> standard. Identifier **prefixes** and **structure** are stable and safe to rely on. Before any
> identifier reaches a client report, resolve it at <https://mas.owasp.org/> and record the document
> version you resolved it against — see [Citation forms](#5-citation-forms) and
> [Retired identifiers](#6-retired-identifiers-and-how-to-survive-them).

---

## 1. The four artefacts

| Artefact | Answers | Shape | You use it to |
|---|---|---|---|
| **MASVS** | *What must be true?* | 8 category groups, ~two dozen controls, one page each | Scope, and give a finding a control to violate |
| **MASWE** | *What specifically goes wrong?* | Numbered weakness entries grouped under MASVS categories | Name the failure precisely, between the control and the test |
| **MASTG** | *How do I test it?* | Tests, Techniques, Tools, Apps, Demos, Best Practices | Produce evidence; hand a junior a procedure |
| **MAS Checklist** | *Did we cover everything?* | Spreadsheet joining controls to tests | Scope tracking, and the deliverable a compliance team asks for |

| Direction | Chain |
|---|---|
| Planning (top-down) | MASVS control → MASWE weaknesses → MASTG tests → your test plan |
| Reporting (bottom-up) | Observation → evidence → MASWE weakness → MASVS control → business impact |

---

## 2. MASVS categories at a glance

| Category | One line | Applies when | Evidence type | Repo chapters |
|---|---|---|---|---|
| **MASVS-STORAGE** | Data at rest, plus incidental leakage | Always | Filesystem diff + log capture | `33-Storage`, [09](../09-Android-App-Internals/README.md), [21](../21-App-Sandbox/README.md) |
| **MASVS-CRYPTO** | Algorithms, modes, keys, randomness | Any app that encrypts, signs or hashes | Runtime JCA trace | [34](../34-Cryptography/README.md), [49](../49-KeyStore/README.md) |
| **MASVS-AUTH** | Server-enforced authN/authZ, local auth binding | Any app with accounts | Replayed requests with downgraded session | [45](../45-OAuth/README.md), `46-Tokens`, `47-Authentication`, `48-Biometrics` |
| **MASVS-NETWORK** | Transport security and endpoint identity | Always | Full capture + deliberate bad certificate | `35-SSL`, `36-CertificatePinning`, `44-NetworkSecurityConfig` |
| **MASVS-PLATFORM** | IPC, WebView, UI surfaces | Always | Invocation **from an unprivileged app** | [24](../24-IPC/README.md), [27](../27-ContentProviders/README.md), [32](../32-Manifest/README.md), `43-WebView` |
| **MASVS-CODE** | Platform version, updates, dependencies, input handling | Always | Dependency inventory with versions | [17](../17-Libraries/README.md), [08](../08-Build-System/README.md), `52-StaticAnalysis` |
| **MASVS-RESILIENCE** | Cost of tamper, hooking, static and dynamic RE | **Only** when the device owner is in the threat model | Protection inventory + measured bypass cost | [37](../37-RootDetection/README.md), [40](../40-Obfuscation/README.md), `38`, `39`, `41`, `42`, `67` |
| **MASVS-PRIVACY** | Minimisation, non-identification, transparency, control | Any app touching user data (i.e. all of them) | Egress inventory incl. third-party SDKs | `23-Permissions`, [17](../17-Libraries/README.md), `33-Storage` |

---

## 3. Every control, and what it actually requires

Eight groups. The **Requires in practice** column is the operative one: it is what you must be able to
say you did before you claim the control was assessed.

### MASVS-STORAGE

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| STORAGE-1 | Sensitive data is stored securely | Enumerate every write to the private data dir, shared storage, KeyStore and any SDK cache; classify each value | Session token in plain `shared_prefs` |
| STORAGE-2 | Sensitive data does not leak by unintended channels | Logs, IPC, clipboard, backups, recents thumbnail, crash reporters, WebView cache, autofill | `Log.d(TAG, "token=" + t)` in a release build |

### MASVS-CRYPTO

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| CRYPTO-1 | Strong, correctly-used cryptography | Algorithm, mode, padding, IV source and reuse, and RNG for every operation — captured at runtime | AES/ECB; static IV; `java.util.Random` |
| CRYPTO-2 | Sound key management | Where each key is generated, stored, and what protects it; hardware backing; `setUserAuthenticationRequired` | `SecretKeySpec` over a hardcoded byte array |

### MASVS-AUTH

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| AUTH-1 | Secure authN/authZ protocols, enforced server-side | Replay every captured endpoint unauthenticated, and as a lower-privileged user | IDOR; authorization decided in the UI |
| AUTH-2 | Local authentication done properly | Biometric/PIN result must gate a `CryptoObject`-backed key operation, not a boolean | `onAuthenticationSucceeded` sets `unlocked = true` |
| AUTH-3 | Sensitive operations get additional authentication | Step-up auth on payment, transfer, credential change, export | Step-up prompt shown client-side only |

### MASVS-NETWORK

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| NETWORK-1 | All traffic secured to current best practice | Full capture including non-HTTP; present expired/self-signed/wrong-host certificates and record each result | Empty `checkServerTrusted`; `usesCleartextTraffic` |
| NETWORK-2 | Identity pinning for developer-controlled endpoints | Which endpoints are pinned, by what mechanism, with what expiry and backup pin | Expired `<pin-set>` — silently no pinning at all |

### MASVS-PLATFORM

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| PLATFORM-1 | IPC used securely | Full exported inventory; invoke each **from an unprivileged app UID** | Exported provider; intent redirection; mutable `PendingIntent` |
| PLATFORM-2 | WebViews used securely | Every `WebView` config: JS, file access, universal access, JS bridges, content debug | `addJavascriptInterface` + attacker-controlled URL |
| PLATFORM-3 | The user interface used securely | Overlay handling, screenshot/recents, clipboard, keyboard, deep-link consent | No `FLAG_SECURE` on a screen displaying an OTP |

### MASVS-CODE

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| CODE-1 | An up-to-date platform version is required | `minSdk`, `targetSdk`, and every legacy behaviour a low value re-enables | `targetSdk` 27 in 2026 — cleartext, implicit export, legacy storage |
| CODE-2 | The app can enforce its own update | Is there a version gate, and is it enforced by the **server**? | Update prompt dismissible; server serves old clients forever |
| CODE-3 | No components with known vulnerabilities | Dependency inventory with versions, fingerprinted from the APK when Gradle files are absent | Ancient bundled HTTP or image-parsing library |
| CODE-4 | Untrusted input validated and sanitised | Every entry point: intents, deep links, provider args, WebView messages, push payloads, files | Path traversal in a provider `openFile` |

### MASVS-RESILIENCE

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| RESILIENCE-1 | Platform integrity is validated | Root/bootloader/attestation checks — and whether the **server** consumes the verdict | Play Integrity verdict checked on the client |
| RESILIENCE-2 | Anti-tampering | Signature/DEX/native integrity checks; measure how many and how deep | Single signature check, one Frida hook defeats it |
| RESILIENCE-3 | Anti-static-analysis | Name mangling, string/class encryption, native packing; measure what survives `jadx` | Release build with full symbol names |
| RESILIENCE-4 | Anti-dynamic-analysis | Debugger, emulator, hooking-framework and memory-tamper detection | No detection at all, or one that only logs |

### MASVS-PRIVACY

| Control | Titled, roughly | Requires in practice | Typical failure |
|---|---|---|---|
| PRIVACY-1 | Minimise access to sensitive data and resources | Permission-by-permission justification against actual code use | `QUERY_ALL_PACKAGES` requested and never used |
| PRIVACY-2 | Prevent identification of the user | Which identifiers are collected/derived; resettable vs permanent; cross-SDK linkage | SSAID or hardware ID joined to an account ID |
| PRIVACY-3 | Transparency about collection and use | Compare captured egress against the published privacy policy, line by line | SDK transmits contacts; policy never mentions it |
| PRIVACY-4 | User control over their data | Delete/export/opt-out paths exist and actually work end to end | "Delete account" clears local state only |

---

## 4. Identifier schemes

| Prefix | Names | Stable? | Where it appears in your work |
|---|---|---|---|
| `MASVS-<CATEGORY>` | A control group | Yes | Scope statement, finding header |
| `MASVS-<CATEGORY>-<n>` | An individual control | Yes within a major version | Finding header, coverage table |
| `MASWE-<nnnn>` | A specific weakness | Numbered; entries added over time | The "what went wrong" line of a finding |
| `MASTG-TEST-<nnnn>` | A test procedure | **Renumbered between v1 and v2** | Methodology; steps-to-reproduce provenance |
| `MASTG-TECH-<nnnn>` | A reusable technique (e.g. bypassing pinning) | v2 onward | Methodology appendix |
| `MASTG-TOOL-<nnnn>` | A tool reference page | v2 onward | Tooling appendix |
| `MASTG-APP-<nnnn>` | A deliberately vulnerable / demo app | v2 onward | Lab material, training plans |
| `MASTG-DEMO-<nnnn>` | A worked example with expected output | v2 onward | Sanity-checking your own procedure |
| `MASTG-BEST-<nnnn>` | A best-practice/remediation page | v2 onward | Remediation section of a finding |
| `MSTG-<CATEGORY>-<n>` | **Retired** v1 requirement ID | No — do not use for new work | Only when reading historical reports |

> **Never type a four-digit ID from memory.** Numbers are assigned by the project and change across
> restructures. Resolve every one on the site or in the GitHub repository at the time of writing, and
> record the version.

---

## 5. Citation forms

| Situation | Write this | Not this |
|---|---|---|
| Finding maps to a control cleanly | `MASVS-STORAGE-1` plus the MASTG test ID you actually followed | `OWASP MASVS` |
| You are unsure of the exact test number | Name the category and describe the procedure in one clause | An invented `MASTG-TEST-0123` |
| Standard version matters (it always does) | "Assessed against MASVS v2.x and MASTG v2.x, resolved 2026-08-05" | "Assessed against OWASP" |
| Finding has no clean control | Closest category + one sentence saying it falls outside the letter of the standard + an external anchor (RFC, ASVS) | Silently forcing it into a control |
| A control is out of scope | "MASVS-RESILIENCE not assessed: agreed threat model excludes a hostile device owner" | Omitting the category |
| Reading an old report | "cited as `MSTG-STORAGE-2` under MASVS v1; the equivalent area is MASVS-STORAGE" | Assuming the number still resolves |

**Minimum viable finding header:**

| Field | Example |
|---|---|
| Severity | High — argued from threat model, not from the control |
| MASVS | `MASVS-STORAGE-1` |
| MASWE | the weakness entry, resolved and pasted |
| MASTG | the test you followed, resolved and pasted |
| Standard version | MASVS v2.x / MASTG v2.x, resolved *date* |
| Affected build | package, versionName, versionCode, APK SHA-256 |
| Device | model, build fingerprint, patch level |

Severity and the rest of the finding body belong to
[80-Appendix §5 and §6](../80-Appendix/README.md#5-severity-cvss-and-business-impact) — do not
restage them here.

---

## 6. Retired identifiers, and how to survive them

| Fact | Consequence for you |
|---|---|
| v1 requirement IDs were `MSTG-<CATEGORY>-<n>`; v2 controls are `MASVS-<CATEGORY>-<n>` | A v1 ID pasted into a modern search resolves to nothing, or worse, to a different control |
| v1 had an **ARCH** group (architecture, design, threat modelling). v2 has no ARCH category | Historical ARCH findings must be re-homed by *meaning*, usually into CODE, PRIVACY or the report's methodology section |
| v1 defined verification levels **L1 / L2 / R** inside the standard; v2 removed them from the standard body | "L2 compliant" is a v1 sentence. If a client says it, ask what they mean before agreeing |
| MASTG v1 was narrative chapters; v2 is atomic `MASTG-TEST-<nnnn>` pages, renumbered | A v1 test reference does not map one-to-one; some v1 tests split, some merged |
| Counts of controls per category changed between major versions | Never state "we tested all N controls" without naming the version |

**Reading a historical assessment — the four-step drill:**

| Step | Do |
|---|---|
| 1 | Find the version statement. If there is none, date the report and infer; say you inferred |
| 2 | Translate by **category**, never by number. `MSTG-STORAGE-*` is the STORAGE area; that is all you may safely conclude |
| 3 | Re-read the finding text. The meaning is authoritative; the identifier is a pointer that has rotted |
| 4 | In your own report write both: "previously reported as MSTG-…; assessed here as MASVS-…" |

---

## 7. Levels, profiles and depth

| Concept | Where it lives | What it actually controls |
|---|---|---|
| L1 (baseline) | MASVS v1; carried on in checklist/profile form | Which controls are in scope at all |
| L2 (defence in depth) | MASVS v1; ditto | Adds controls for apps handling sensitive data |
| R (resilience) | MASVS v1; MASVS-RESILIENCE in v2 | **Orthogonal.** Applies only when the device owner is the adversary |
| Depth of verification | Your scope statement, not the standard | How hard you look at a control that is in scope |

| Question | Answer that survives review |
|---|---|
| "Are we L1 or L2?" | "Which data does the app handle?" — the data decides, not the label |
| "Do we need R?" | "Name the adversary you want it to stop." No name, no R |
| "Is the control in scope?" | It is in scope if a failure of it would matter under the agreed threat model |
| "Did you test every control?" | Say exactly which, and list the exclusions with reasons |

---

## 8. Finding → control lookup

For report write-up. Find the finding, take the category, then resolve the exact control and test IDs
on the site before pasting them. Chapter column is where the *technique* is taught — chapter 71 owns
the mapping, not the method.

### Storage and leakage

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| Session/refresh token in plaintext `SharedPreferences` | STORAGE | STORAGE-1 | `33-Storage` |
| Credentials or PII in an unencrypted SQLite database | STORAGE | STORAGE-1 | `33-Storage` |
| Sensitive files on shared/external storage | STORAGE | STORAGE-1 | `33-Storage`, [21](../21-App-Sandbox/README.md) |
| `android:allowBackup="true"` with sensitive local state | STORAGE | STORAGE-1 | [32](../32-Manifest/README.md) |
| Secrets in `Log.d` / `Log.v` / crash reports | STORAGE (+ PRIVACY) | STORAGE-2 | `33-Storage` |
| Sensitive screen in recents thumbnail (no `FLAG_SECURE`) | PLATFORM (+ STORAGE) | PLATFORM-3 | `33-Storage` |
| Sensitive value left on the clipboard | PLATFORM (+ STORAGE) | PLATFORM-3 / STORAGE-2 | `33-Storage` |
| WebView cache / cookie DB retains authenticated content | STORAGE | STORAGE-2 | `43-WebView` |
| Key material recoverable from memory long after use | STORAGE / CRYPTO | STORAGE-1 / CRYPTO-2 | [49](../49-KeyStore/README.md) |

### Cryptography

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| Hardcoded symmetric key in DEX or `.so` | CRYPTO | CRYPTO-2 | [34](../34-Cryptography/README.md) |
| `AES/ECB/*` | CRYPTO | CRYPTO-1 | [34](../34-Cryptography/README.md) |
| Static or all-zero IV; IV reuse under GCM | CRYPTO | CRYPTO-1 | [34](../34-Cryptography/README.md) |
| `java.util.Random` for key, token or nonce | CRYPTO | CRYPTO-1 | [34](../34-Cryptography/README.md) |
| MD5 / SHA-1 used for integrity or signatures | CRYPTO | CRYPTO-1 | [34](../34-Cryptography/README.md) |
| Key derived from a constant or device-guessable value | CRYPTO | CRYPTO-2 | [34](../34-Cryptography/README.md) |
| KeyStore key without `setUserAuthenticationRequired` where the design implies it | CRYPTO (+ AUTH) | CRYPTO-2 / AUTH-2 | [49](../49-KeyStore/README.md) |
| Software key where hardware backing was available and warranted | CRYPTO | CRYPTO-2 | [49](../49-KeyStore/README.md) |

### Authentication and authorization

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| IDOR / missing server-side object authorization | AUTH | AUTH-1 | `47-Authentication` (+ OWASP ASVS) |
| `isLoggedIn` boolean in preferences gating access | AUTH | AUTH-1 | `47-Authentication` |
| Logout clears local state; server session stays valid | AUTH | AUTH-1 | `46-Tokens` |
| OTP or password returned in an API response | AUTH | AUTH-1 | `47-Authentication` |
| Biometric success is a boolean, no `CryptoObject` | AUTH | AUTH-2 | `48-Biometrics` |
| No step-up authentication on a money movement | AUTH | AUTH-3 | `47-Authentication` |
| JWT with no expiry, or `alg: none` accepted | AUTH | AUTH-1 | `46-Tokens` |
| PKCE sent by the app but not enforced by the server | AUTH (imperfect fit — see §9) | AUTH-1 | [45](../45-OAuth/README.md) |

### Network

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| Cleartext HTTP endpoint in use | NETWORK | NETWORK-1 | `44-NetworkSecurityConfig` |
| `checkServerTrusted` empty / all-trusting `TrustManager` | NETWORK | NETWORK-1 | `35-SSL` |
| `HostnameVerifier` returning `true` | NETWORK | NETWORK-1 | `35-SSL` |
| `onReceivedSslError` → `handler.proceed()` | NETWORK (+ PLATFORM) | NETWORK-1 / PLATFORM-2 | `43-WebView` |
| `<debug-overrides>` or user trust anchors in a release build | NETWORK | NETWORK-1 | `44-NetworkSecurityConfig` |
| Expired `<pin-set>`, or pinning with no backup pin | NETWORK | NETWORK-2 | `36-CertificatePinning` |
| Non-HTTP protocol (raw socket, MQTT) unencrypted | NETWORK | NETWORK-1 | `35-SSL` |

### Platform

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| Unintentionally exported activity/service/receiver | PLATFORM | PLATFORM-1 | [32](../32-Manifest/README.md) |
| Exported provider leaking rows | PLATFORM | PLATFORM-1 | [27](../27-ContentProviders/README.md) |
| SQL injection or path traversal in a provider | PLATFORM (+ CODE) | PLATFORM-1 / CODE-4 | [27](../27-ContentProviders/README.md) |
| `FileProvider` with `root-path` | PLATFORM | PLATFORM-1 | [27](../27-ContentProviders/README.md) |
| Intent redirection (extra `Intent` re-launched) | PLATFORM | PLATFORM-1 | [24](../24-IPC/README.md) |
| Mutable `PendingIntent` handed to a third party | PLATFORM | PLATFORM-1 | [24](../24-IPC/README.md) |
| `addJavascriptInterface` reachable with attacker-controlled content | PLATFORM | PLATFORM-2 | `43-WebView` |
| `setAllowUniversalAccessFromFileURLs(true)` | PLATFORM | PLATFORM-2 | `43-WebView` |
| `setWebContentsDebuggingEnabled(true)` in release | PLATFORM (+ CODE) | PLATFORM-2 / CODE-1 | `43-WebView` |
| Unverified deep link performing a state change | PLATFORM (+ CODE) | PLATFORM-1 / CODE-4 | `26-Intent` |
| Task hijacking via `taskAffinity` / `singleTask` | PLATFORM | PLATFORM-1 / PLATFORM-3 | `30-Activities` |
| Tapjacking / overlay not defended on a consent screen | PLATFORM | PLATFORM-3 | `30-Activities` |
| `sharedUserId` with a weaker sibling app | PLATFORM | PLATFORM-1 | [21](../21-App-Sandbox/README.md) |
| Custom permission at `normal` guarding a sensitive component | PLATFORM | PLATFORM-1 | `23-Permissions` |

### Code and build

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| `android:debuggable="true"` in a release build | CODE | CODE-1 | [32](../32-Manifest/README.md) |
| Low `targetSdk` re-enabling legacy behaviours | CODE | CODE-1 | [32](../32-Manifest/README.md), [80 §2](../80-Appendix/README.md#2-the-android-version-matrix) |
| Bundled library with known vulnerabilities | CODE | CODE-3 | [17](../17-Libraries/README.md) |
| No enforced minimum client version server-side | CODE | CODE-2 | [08](../08-Build-System/README.md) |
| `mapping.txt` or source maps shipped inside the APK | CODE (+ RESILIENCE) | CODE-1 / RESILIENCE-3 | [40](../40-Obfuscation/README.md) |
| Shipped `<instrumentation>` or test-only build | CODE | CODE-1 | [32](../32-Manifest/README.md) |
| Unsafe deserialisation of attacker-reachable data | CODE | CODE-4 | [04](../04-Java/README.md) |
| Native memory-safety bug in a bundled `.so` | CODE | CODE-4 | [15](../15-Native-Code/README.md) |

### Resilience — only when the device owner is in the threat model

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| No root/integrity check at all | RESILIENCE | RESILIENCE-1 | [37](../37-RootDetection/README.md) |
| Integrity verdict evaluated client-side only | RESILIENCE | RESILIENCE-1 | [37](../37-RootDetection/README.md) |
| Signature check defeated by one hook | RESILIENCE | RESILIENCE-2 | `38-TamperDetection` |
| Release build with no name mangling | RESILIENCE | RESILIENCE-3 | [40](../40-Obfuscation/README.md) |
| Secrets recoverable as plain strings from the APK | RESILIENCE (+ CRYPTO) | RESILIENCE-3 / CRYPTO-2 | [40](../40-Obfuscation/README.md) |
| No debugger/hooking detection on a high-value flow | RESILIENCE | RESILIENCE-4 | `39-EmulatorDetection`, `67-BypassingProtections` |

### Privacy

| Finding | Category | Likely control | Chapter |
|---|---|---|---|
| Permission requested and never used | PRIVACY | PRIVACY-1 | `23-Permissions` |
| Precise location where coarse would do | PRIVACY | PRIVACY-1 | `23-Permissions` |
| Persistent hardware/device identifier collected | PRIVACY | PRIVACY-2 | `23-Permissions` |
| Advertising ID joined to an authenticated user ID | PRIVACY | PRIVACY-2 | [17](../17-Libraries/README.md) |
| Third-party SDK transmits data the policy never names | PRIVACY | PRIVACY-3 | [17](../17-Libraries/README.md) |
| PII inside crash-reporter payloads | PRIVACY (+ STORAGE) | PRIVACY-3 / STORAGE-2 | [17](../17-Libraries/README.md) |
| Account deletion does not delete server-side | PRIVACY | PRIVACY-4 | `47-Authentication` |
| No opt-out for analytics where one is required | PRIVACY | PRIVACY-4 | [17](../17-Libraries/README.md) |

---

## 9. Findings that do not map cleanly

The category exists because it is common, not because it is rare. Handle it, do not hide it.

| Finding shape | Why it does not fit | Write it as |
|---|---|---|
| Server does not enforce PKCE although the app sends it | Server-side behaviour; the app is compliant | Closest: AUTH. Anchor to RFC 7636 and OWASP ASVS. State the gap |
| Business-logic flaw (negative quantity, refund replay) | No control describes your client's business | Closest: AUTH or none. Anchor to threat model. Severity from impact only |
| Race condition between two correct components | Controls are per-component, not per-interaction | Describe the chain; cite each component's control as context, not as the finding |
| Chain of individually-Low findings producing a High | Controls are scored individually | Report the chain as one finding with its own severity; list the constituent controls |
| Weakness in a platform/OEM component the app depends on | Not the app's control surface | Report as an environmental finding; cite the platform advisory, not a MASVS control |
| Privacy harm that is lawful and disclosed but still harmful | PRIVACY-3 is satisfied by disclosure | Report as an observation with explicit reasoning; do not force a control |

| Rule | |
|---|---|
| A finding without a control is still a finding | Lab 03 exists to prove this |
| A control without a finding is still coverage | Record it as tested-and-passed, with the evidence |
| Never delete a finding to make a coverage table tidy | The tidiness is the tell |

---

## 10. Evidence that satisfies each category

The claim "we assessed MASVS-X" is worth exactly what you can show. One artefact per category, minimum.

| Category | Minimum artefact | Command family |
|---|---|---|
| STORAGE | Before/after tarball diff of the data dir across a full feature exercise, plus a filtered logcat | `tar` + `diff -rq`; `adb logcat --pid=` |
| CRYPTO | A runtime trace of every `Cipher`/`KeyGenerator`/`SecureRandom` call with parameters | Frida JCA hook — [34](../34-Cryptography/README.md) |
| AUTH | Request/response pairs for every endpoint, replayed unauthenticated and as a low-privileged user | Burp / `mitmproxy` |
| NETWORK | Full pcap including non-HTTP, plus results for expired / self-signed / wrong-host certificates | `tcpdump`, `mitmproxy` |
| PLATFORM | Exported inventory + invocation results **from a probe app**, not `adb shell` | [21 probe app](../21-App-Sandbox/labs/lab-03-attacker-app.md) |
| CODE | Dependency inventory with versions, from the shipped APK | `apkid`, class-signature fingerprinting — [17](../17-Libraries/README.md) |
| RESILIENCE | Protection inventory with measured time-to-bypass for each | [37](../37-RootDetection/README.md), [40](../40-Obfuscation/README.md) |
| PRIVACY | Egress inventory by destination host, mapped against the published policy | pcap + host attribution |

---

## 11. Scoping decision table

| Signal about the app | Effect on scope |
|---|---|
| Handles money, health, identity or credentials | Full depth on all categories; AUTH and CRYPTO weighted |
| Internal app on managed devices | RESILIENCE out; say so explicitly and record who agreed |
| Consumer app with a hostile-user incentive (banking, DRM, gaming, licensing) | RESILIENCE in; name the adversary in the scope statement |
| Heavy third-party SDK footprint | PRIVACY and CODE weighted; budget a full day for egress attribution |
| WebView-first or hybrid architecture | PLATFORM-2 weighted; treat the web content as its own target |
| Backend in scope | Add OWASP ASVS explicitly; this is where severity concentrates |
| Backend **not** in scope | Say so in the scope statement in one unambiguous sentence |
| Source code provided | CODE and CRYPTO get cheaper; PLATFORM does not — still test from a probe app |
| No rooted device available | RESILIENCE and parts of STORAGE become unverifiable; record the limitation |

---

## 12. Common mechanical errors

| Error | Correction |
|---|---|
| `adb shell` used to prove an exported component is reachable | UID 2000 holds privileges no app has. Re-test from a probe app |
| "MASVS compliant" written without a version or a scope | Name version, categories assessed, and exclusions |
| Category ticked after testing one control in it | Coverage is per control, not per category |
| Tool output mapped to controls and shipped | A tool cannot judge what is *sensitive*. That judgement is the assessment |
| Severity taken from the control | Severity comes from the threat model — [80 §5](../80-Appendix/README.md#5-severity-cvss-and-business-impact) |
| Resilience recommended with no named adversary | Delete the recommendation or name the adversary |
| Static-only conclusion that a control passes | The path you read may never run; the one that does may be native |
| Retired `MSTG-*` ID copied forward from an old report | Translate by category and show both |
| Exclusions omitted from the report | An exclusion the client cannot see is an exclusion they cannot revisit |

---

## 13. Chapter tooling

| File | Use |
|---|---|
| [`scripts/mas-coverage.py`](scripts/mas-coverage.py) | Findings list → per-control coverage, gaps, and a multi-app heatmap |
| [`scripts/scope-checklist.py`](scripts/scope-checklist.py) | App profile → controls in scope, **and a written reason for every exclusion** |
| [`examples/assessment-result-table.md`](examples/assessment-result-table.md) | A worked control-by-control result table in report shape |
| [`examples/finding-mapped-twice.md`](examples/finding-mapped-twice.md) | One finding mapped mechanically, then mapped thoughtfully, with the difference explained |
| [`examples/findings-ovaa.csv`](examples/findings-ovaa.csv) | Findings fixture for `mas-coverage.py` |
| [`examples/portfolio-findings.csv`](examples/portfolio-findings.csv) | Three-app fixture for the heatmap mode |
| [`examples/profile-banking.json`](examples/profile-banking.json) / [`profile-internal-tool.json`](examples/profile-internal-tool.json) | App profiles for `scope-checklist.py` |
