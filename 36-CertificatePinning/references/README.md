# 36 — Certificate Pinning · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

---

## AOSP source

Read these on [cs.android.com](https://cs.android.com/), which cross-references symbols and shows
history. [07-AOSP](../../07-AOSP/README.md) covers the navigation technique. **No line numbers are
cited anywhere in this chapter** — they move between releases and a wrong one is worse than none.

| Path | Open it when |
|---|---|
| `external/conscrypt/common/src/main/java/org/conscrypt/TrustManagerImpl.java` | **The single most useful file for this chapter.** Chain building, the three `checkServerTrusted` overloads, and `checkTrustedRecursive` — the method modern OkHttp actually reaches, and the one a layer-1-only bypass misses |
| `external/conscrypt/common/src/main/java/org/conscrypt/TrustedCertificateStore.java` | You need to know exactly which directories the trust store is read from, and in what order |
| `external/conscrypt/common/src/main/java/org/conscrypt/NativeCrypto.java` | The JNI boundary. The line you cross when moving from Java hooks to native hooks |
| `external/conscrypt/common/src/main/java/org/conscrypt/OpenSSLProvider.java` | The provider registry — what this device actually supports |
| `frameworks/base/core/java/android/security/net/config/NetworkSecurityTrustManager.java` | `<pin-set>` enforcement. Read it to confirm that the pin is compared against the **cleaned** chain, not the wire chain |
| `frameworks/base/core/java/android/security/net/config/RootTrustManager.java` | Per-domain dispatch: how the platform picks a config for a hostname |
| `frameworks/base/core/java/android/security/net/config/NetworkSecurityConfig.java` | The parsed config object, including the pin set and the expiry check |
| `frameworks/base/core/java/android/security/net/config/PinSet.java` | Twelve lines that define what a pin set *is*: a set of pins and an `expirationTime` |
| `frameworks/base/core/java/android/security/net/config/Pin.java` | One pin: a digest algorithm and bytes. Confirms `SHA-256` is the only accepted digest |
| `frameworks/base/core/java/android/security/net/config/XmlConfigSource.java` | The parser. Read it to see that a malformed `expiration` is a hard error, not a silent skip |
| `frameworks/base/core/java/android/net/http/X509TrustManagerExtensions.java` | The sanctioned per-host API that returns the cleaned chain |
| `libcore/ojluni/src/main/java/javax/net/ssl/SSLContext.java` | `init(km, tm, random)` — layer 1's injection point |
| `libcore/ojluni/src/main/java/javax/net/ssl/TrustManagerFactory.java` | The other route to the same `TrustManager[]` |
| `external/boringssl/src/ssl/ssl_x509.cc` | `SSL_CTX_set_verify` and `SSL_CTX_set_custom_verify`. Read it to see that `custom_verify` **replaces** the library's own chain verification rather than supplementing it |
| `external/boringssl/src/ssl/handshake_client.cc` | Where the verification callback is invoked during the handshake |
| `external/boringssl/src/crypto/x509/x_pubkey.c` | `i2d_X509_PUBKEY` — the serialisation a native pin hashes |

---

## Library source

| Resource | Why |
|---|---|
| [OkHttp `CertificatePinner`](https://javadoc.io/doc/com.squareup.okhttp3/okhttp/latest/okhttp3/CertificatePinner.html) | **The reference for the `sha256/` format**, the wildcard pattern semantics (`*` versus `**`), and the exact exception text. Pair it with the [HTTPS guide](https://github.com/square/okhttp/blob/master/docs/features/https.md) before advising anybody |
| [OkHttp source, `CertificatePinner.kt`](https://github.com/square/okhttp/blob/master/okhttp/src/commonJvmAndroid/kotlin/okhttp3/CertificatePinner.kt) | `findMatchingPins`, the `check` loop, and `check$okhttp`. Answers "would this pattern match that host" definitively |
| [Conscrypt](https://github.com/google/conscrypt) | The provider itself, with a readable history of how `TrustManagerImpl` changed |
| [BoringSSL](https://boringssl.googlesource.com/boringssl/) | The native layer under everything on Android |
| [Appmattus certificatetransparency](https://github.com/appmattus/certificatetransparency) | The Android CT library you will meet. Read it when a bypass succeeds and the connection still fails — CT rejects *after* the pin accepts |
| [TrustKit Android](https://github.com/datatheorem/TrustKit-Android) | A pinning library with its own config format and reporting. Recognise its classes;its reporting is a tripwire |
| [Flutter engine](https://github.com/flutter/engine) | Where Dart's `SecurityContext` and the bundled root list live. Read `third_party/boringssl` integration when you need to know what the engine is actually doing |

---

## Official Android documentation

| Resource | Why |
|---|---|
| [**Network security configuration**](https://developer.android.com/privacy-and-security/security-config) | The `<pin-set>` element, the `expiration` attribute, trust anchors, and `<debug-overrides>`. **The citation for every declarative pinning finding** |
| [Security with HTTPS and SSL](https://developer.android.com/privacy-and-security/security-ssl) | Google's own account, and notable for saying out loud that pinning carries operational risk. Useful in a report because the client cannot argue with the platform vendor |
| [`X509TrustManagerExtensions`](https://developer.android.com/reference/android/net/http/X509TrustManagerExtensions) | The API reference. Note the return type: the cleaned chain |
| [`WebViewClient.onReceivedSslError`](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError)) | The WebView's error path, and the documentation's own warning about calling `proceed()` |
| [Behaviour changes by API level](https://developer.android.com/about/versions) | **Check before asserting any version-dependent claim.** The API 24 user-CA change is the one that bites most often |
| [Android APEX](https://source.android.com/docs/core/ota/apex) | Why Conscrypt can change without an OS update, and why two devices on the same release can differ |
| [Play Integrity API](https://developer.android.com/google/play/integrity) | The control with an enforcement point outside the app process — what a developer asking "how do I stop pinning bypasses" actually wants |

---

## Standards and RFCs

Safe to cite in a client report. Unlike CVE identifiers, standards numbers do not go stale.

| Document | Open it when |
|---|---|
| [**RFC 5280** — X.509 / PKIX](https://www.rfc-editor.org/rfc/rfc5280) | You need the authoritative definition of `SubjectPublicKeyInfo` (§4.1.2.7) — the structure a pin hashes. Also the path-validation algorithm that "chain cleaning" implements |
| [**RFC 7469** — HTTP Public Key Pinning](https://www.rfc-editor.org/rfc/rfc7469) | **Deprecated for the web, and worth reading precisely because of that.** It specifies the SPKI pin format, mandates a backup pin, and its stated failure modes — hostile pinning, accidental self-DoS, the impossibility of recovery — are exactly the ones mobile pinning still has. The web abandoned HPKP for reasons that apply to your app |
| [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) and [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) | Certificate Transparency v1 and v2. The detective control pinning is compared to |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3. §4.4.2 is the Certificate message a pin inspects |
| [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) | Hostname verification, done properly. The citation when a finding is a name mismatch rather than a pin failure |
| [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) | TLS 1.2, still what a great many mobile connections negotiate |
| [RFC 8017 — PKCS #1](https://www.rfc-editor.org/rfc/rfc8017) | RSA key encoding, if you need to reason about what is inside the SPKI BIT STRING |
| [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480) | The EC equivalent: how an EC public key is represented in an SPKI |
| [CA/Browser Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/) | You need an authority for what a public CA is and is not permitted to do — useful when arguing about whether the pinning threat model is real |

---

## OWASP

| Resource | Why |
|---|---|
| [**MASVS-NETWORK**](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/) | The two controls every finding here maps to. **NETWORK-1**: traffic is secured per current best practice. **NETWORK-2**: identity pinning for endpoints under the developer's control. **Read the qualifiers in NETWORK-2 before writing a finding** — it is conditional on the threat model, not universal |
| [MASVS-RESILIENCE](https://mas.owasp.org/MASVS/11-MASVS-RESILIENCE/) | Where pinning-as-anti-analysis actually belongs. RESILIENCE controls are explicitly best-effort, which is the project agreeing that a pin does not survive device compromise |
| [MASTG](https://mas.owasp.org/MASTG/) | The test procedures. Cite the **control id**, not the test id — control ids are stable across MASTG refactors |
| [MASTG Android network tests](https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/) | The Android-specific procedures, with the greps and hooks |
| [OWASP Certificate and Public Key Pinning cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html) | A concise defensible answer for "what should we pin", suitable for pasting into a remediation section |
| [OWASP Transport Layer Security cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | The baseline the app should meet before pinning is even the question |
| [MASTG test apps](https://mas.owasp.org/MASTG/apps/) | Legal practice targets. Use these rather than a real third-party app |

---

## Weakness classification

| Resource | Why |
|---|---|
| [**CWE-295** — Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html) | **The class to cite.** Most findings that get written up as "pinning" are actually this: a permissive `TrustManager`, `onReceivedSslError` calling `proceed()`, a verifier returning `true` |
| [CWE-297 — Improper Validation of Certificate with Host Mismatch](https://cwe.mitre.org/data/definitions/297.html) | The hostname-verification half, when the finding is a name mismatch |
| [CWE-599 — Missing Validation of OpenSSL Certificate](https://cwe.mitre.org/data/definitions/599.html) | The native equivalent: `SSL_VERIFY_NONE` with no compensating check |
| [CWE-757 — Selection of Less-Secure Algorithm During Negotiation](https://cwe.mitre.org/data/definitions/757.html) | When a downgrade is what the app permitted, rather than a pin failure |

> **Do not invent CVE identifiers.** There are many CVEs in individual apps for improper certificate
> validation, and several well-known historical CA incidents that motivate pinning. Cite the CWE
> class and describe the issue rather than attaching a number you are not certain of — a wrong CVE
> in a report is checkable, and it will be checked.

---

## Tools

| Tool | Why |
|---|---|
| [Frida](https://frida.re/docs/android/) | The instrumentation engine. [53-Frida](../../53-Frida/README.md) owns it; §7.3 of this chapter explains what its pinning script is doing |
| [Objection](https://github.com/sensepost/objection) | `android sslpinning disable` — a curated set of Java hooks, quick to type once you have already mapped the surface |
| [`apktool`](https://apktool.org/) | Unpack, edit smali, rebuild. The static route |
| [`apksigner` and `zipalign`](https://developer.android.com/tools/apksigner) | Re-signing after a patch |
| [jadx](https://github.com/skylot/jadx) | Decompilation. Search for `CertificatePinner` and you land on the configuration regardless of obfuscation of the surrounding class |
| [Ghidra](https://ghidra-sre.org/) | Locating a native pin by structure when the string is gone. [57-Ghidra](../../57-Ghidra/README.md) |
| [Burp Suite](https://portswigger.net/burp) / [mitmproxy](https://mitmproxy.org/) | The proxy. Neither helps against a native stack that calls `connect(2)` directly |
| [OpenSSL](https://www.openssl.org/docs/) | `s_client -showcerts` for the chain, and the pipeline that computes a pin |
| [testssl.sh](https://testssl.sh/) | Server-side posture, when the finding turns out to be the server rather than the app |
| [crt.sh](https://crt.sh/) | Certificate Transparency log search. Check what certificates exist for a domain — the defensive half of the threat pinning addresses |

---

## Talks and writing worth finding

Search by topic rather than URL, since hosting moves.

- **The deprecation of HTTP Public Key Pinning** — the discussions around removing HPKP from Chrome.
  The clearest available account of why pinning is operationally dangerous, written by people who
  shipped it and then withdrew it.
- **Certificate Transparency design rationale** — talks from the CT project explaining why detection
  was chosen over prevention for the ecosystem.
- **Flutter TLS interception** — a recurring conference and blog topic, because the technique breaks
  with each engine release. Search for the current engine version rather than trusting an old post.
- **Mobile pinning bypass at scale** — OWASP AppSec and MASTG project sessions on what actually
  appears in production apps.
- **CA incident post-mortems** — the industry's own write-ups of mis-issuance events. These are the
  evidence base for whether the pinning threat model is real, and they are more persuasive in a
  report than an assertion.

---

## This chapter's own artefacts

| File | What it is |
|---|---|
| [`../scripts/pinning-surface.py`](../scripts/pinning-surface.py) | Which layers does this app appear to pin at, before you try any bypass. Detection only, safe to point anywhere |
| [`../scripts/pin-attribution.js`](../scripts/pin-attribution.js) | Which layer *rejected* this connection. Wraps every check instead of disabling it |
| [`../scripts/spki-pin.sh`](../scripts/spki-pin.sh) | The pin for a host, certificate, key or CSR, labelled leaf/intermediate/root, with ready-to-paste config |
| [`../examples/README.md`](../examples/README.md) | Five graded examples, simple to enterprise |
| [`../labs/lab-01-map-the-pinning-surface.md`](../labs/lab-01-map-the-pinning-surface.md) | Measure the surface of every app on your device. Detection only |
| [`../labs/lab-02-defeat-a-two-layer-pin.md`](../labs/lab-02-defeat-a-two-layer-pin.md) | Build it, bypass Java, watch it still fail, defeat native |
| [`../labs/lab-03-attribute-the-rejection.md`](../labs/lab-03-attribute-the-rejection.md) | Attribution, plus a real certificate renewal and a real key rotation |
| [`../labs/lab-04-ctf-the-pin-that-moved.md`](../labs/lab-04-ctf-the-pin-that-moved.md) | A CTF whose oracle refuses to accept "I disabled it" as an answer |
| [`../cheatsheet.md`](../cheatsheet.md) | Commands and constants, printable |
| [`../faq.md`](../faq.md) | Twenty questions, including the dumb ones |

---

## Related chapters

| Chapter | Relationship |
|---|---|
| [**35-SSL**](../../35-SSL/README.md) | **TLS and trust** — the handshake, trust anchors, user-CA behaviour, permissive `TrustManager`s. Everything up to the point an app goes beyond standard validation. **Read this first if a rejection lands at the trust layer** |
| [**44-NetworkSecurityConfig**](../../44-NetworkSecurityConfig/README.md) | **The XML**, including `<pin-set>` as a declaration. This chapter owns its runtime behaviour and its bypass |
| [**53-Frida**](../../53-Frida/README.md) | The instrumentation engine, and `ssl-pinning-bypass.js` itself. §7.3 here explains every layer that script addresses |
| [15-Native-Code](../../15-Native-Code/README.md) | ELF and the dynamic section — where a `NEEDED libssl.so` finding comes from, and why `DT_SONAME` is a claim rather than a fact |
| [17-Libraries](../../17-Libraries/README.md) | Library identification: `libflutter.so`, `libapp.so`, Cronet, React Native, Unity |
| [16-JNI](../../16-JNI/README.md) | The Java-to-native boundary a pin crosses |
| [34-Cryptography](../../34-Cryptography/README.md) | SHA-256, DER encoding and signatures — the primitives a pin is built from |
| [18-ARM](../../18-ARM/README.md) | Patching native code, and the measured lesson about a patch to an inlined function |
| [57-Ghidra](../../57-Ghidra/README.md) | Locating a native pin by structure when the constant is obfuscated |
| [10-APK-Internals](../../10-APK-Internals/README.md) | Unpack, modify, rebuild, resign — the loop behind every static patch |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What renaming and string encryption do to a pin, and what they structurally cannot touch |
| [43-WebView](../../43-WebView/README.md) | The WebView's own network stack and trust path |
| [37-RootDetection](../../37-RootDetection/README.md) | The sibling control: also enforced in-process, also defeated on a device you own, also over-reported |
| [38-TamperDetection](../../38-TamperDetection/README.md) | What bites you after you patch and resign an APK |
| [49-KeyStore](../../49-KeyStore/README.md) | Where a mutual-TLS client key lives when it cannot be extracted |
| [50-HardwareBackedSecurity](../../50-HardwareBackedSecurity/README.md) | Attestation — the control whose enforcement point is *not* in the app process |
| [62-Magisk](../../62-Magisk/README.md) | Installing a system CA reversibly, with a module rather than a `/system` remount |
| [69-MalwareAnalysis](../../69-MalwareAnalysis/README.md) | Pinning as the attacker's tool: C2 channels you have to open |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Mapping findings to MASVS controls |
| [55-MobSF](../../55-MobSF/README.md) | Why its "app uses certificate pinning" finding is usually wrong, and how to say so |
| [54-Objection](../../54-Objection/README.md) | `android sslpinning disable`, and its limits |
