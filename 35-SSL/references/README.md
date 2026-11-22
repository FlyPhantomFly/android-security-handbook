# 35 — SSL/TLS · References

Annotated. Each entry says *why* you would open it, so you can pick the right one under time
pressure.

Everything measured in this chapter was taken on a Redmi M2101K6P (`sweetin`), Android 11 / API 30,
MIUI 12.5, rooted, with frida 16.1.6 on the host. Where a source below contradicts a measurement,
check your own device before believing either — the trust store in particular moved recently and a
great deal of published guidance is correct for exactly one Android version.

---

## RFCs — the ones you will actually cite

Standards numbers do not go stale and are not easy to misattribute, which makes them the safest
citations in a client report.

| Document | Open it when |
|---|---|
| [**RFC 8446** — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) | **The current protocol.** §4.1 is the handshake message-by-message; §4.1.3 gives the fixed `HelloRetryRequest` random that `tls-posture.py` matches on; §4.4.2.4 is certificate validation; Appendix D lists exactly what was removed from TLS 1.2 and why. Read this before claiming TLS 1.3 fixes anything about client validation — it does not |
| [**RFC 5280** — X.509 / PKIX certificate and CRL profile](https://www.rfc-editor.org/rfc/rfc5280) | **The citation for every chain-validation finding.** §4.2.1.9 `basicConstraints` and `pathLenConstraint`; §4.2.1.6 `subjectAltName`; §6.1 is the complete path-validation algorithm, which is the authoritative version of this chapter's six steps |
| [**RFC 6125** — identity verification](https://www.rfc-editor.org/rfc/rfc6125) | **The citation for every hostname-verification finding.** Why `subjectAltName` supersedes the legacy `CN`, and the wildcard-matching rules — `*.example.com` matches one label, not two |
| [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246) | Still the version most endpoints run. §7.2.2 is the alert table your proxy is printing numbers from; §7.4 is the handshake |
| [RFC 6066 — TLS extension definitions](https://www.rfc-editor.org/rfc/rfc6066) | §3 defines **SNI**. Read it when a proxy is producing alert 112 `unrecognized_name`, or when you need to explain why hostnames leak in plaintext |
| [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996) | The authority for "TLS 1.0/1.1 must not be used". Cite this rather than a vendor blog when a client argues that their TLS 1.0 endpoint is fine |
| [RFC 7465 — Prohibiting RC4](https://www.rfc-editor.org/rfc/rfc7465) | The authority for an RC4 finding, and it is unambiguous: RC4 must not be negotiated at all |
| [RFC 7568 — Deprecating SSL 3.0](https://www.rfc-editor.org/rfc/rfc7568) | The companion to POODLE. Cite alongside CVE-2014-3566 |
| [RFC 6176 — Prohibiting SSL 2.0](https://www.rfc-editor.org/rfc/rfc6176) | For the rare legacy endpoint that still answers an SSL 2.0 hello |
| [RFC 6960 — OCSP](https://www.rfc-editor.org/rfc/rfc6960) | Revocation, and why soft-fail makes it weaker than people assume. Relevant because Android does not check by default |
| [RFC 6961 / RFC 8449 — OCSP stapling and certificate status](https://www.rfc-editor.org/rfc/rfc6961) | The server-side answer to OCSP's privacy and latency problems |
| [RFC 7301 — ALPN](https://www.rfc-editor.org/rfc/rfc7301) | How HTTP/2 is selected inside the handshake; occasionally the reason a proxy sees nothing |
| [RFC 5077 / RFC 8446 §2.2 — session resumption](https://www.rfc-editor.org/rfc/rfc5077) | Why your second connection skipped the certificate exchange you were trying to observe |

---

## Official Android documentation

| Resource | Why |
|---|---|
| [**Security with HTTPS and SSL**](https://developer.android.com/privacy-and-security/security-ssl) | Google's own account of `SSLSocket`, `TrustManager`, `HostnameVerifier` and the common failure modes. **The single best link to put in a remediation section**, because the client cannot argue with the platform vendor about what the platform expects |
| [**Network security configuration**](https://developer.android.com/privacy-and-security/security-config) | The XML that decides which anchors apply, `debug-overrides`, `trust-anchors`, `cleartextTrafficPermitted`. Chapter 44, NetworkSecurityConfig, owns the subject; this is the reference for it |
| [**Changes to Trusted Certificate Authorities in Android Nougat**](https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html) | **The announcement of the API 24 change** that is the single most common cause of "Burp works in the browser but not in the app". Cite this when a developer insists their app should trust an installed CA |
| [Android 14 behaviour changes](https://developer.android.com/about/versions/14/behavior-changes-all) | Where to confirm the move of the root store into the Conscrypt APEX. **Check it against your own device** — the measurement on API 30 shows no `cacerts` directory in the APEX at all |
| [Behaviour changes by API level](https://developer.android.com/about/versions) | Check before asserting any version-dependent claim. TLS 1.0/1.1 disabled at API 29, cleartext blocked by default at API 28, and the API 24 trust change are the three that bite most often |
| [Android security bulletins](https://source.android.com/docs/security/bulletin) | The authoritative place to verify a CVE before putting it in a report |
| [`KeyChain`](https://developer.android.com/reference/android/security/KeyChain) | The API behind user CA installation, and where the requirement for a secure lock screen comes from |
| [`SSLCertificateSocketFactory.getInsecure()`](https://developer.android.com/reference/android/net/SSLCertificateSocketFactory) | Read the documented warning in full. AOSP ships a trust-nothing `TrustManager`, and an app calling this did not write the bug — it borrowed one from the framework |
| [Conscrypt](https://github.com/google/conscrypt) | The provider that implements Android's TLS. The upstream repository is easier to browse than the AOSP mirror |
| [BoringSSL](https://boringssl.googlesource.com/boringssl/) | The native layer beneath Conscrypt, and where you end up when an app's TLS is not in Java |

---

## AOSP source

Read these on [cs.android.com](https://cs.android.com/), which gives cross-references and history.
See [07-AOSP](../../07-AOSP/README.md) for the navigation technique.

**File paths are stable; line numbers are not.** Nothing below cites a line number, and neither
should your report. Note also that Conscrypt's tree is split into source sets — `common/` for
portable code and `platform/` for Android-specific code — so search the tree rather than assuming a
file's directory.

### The platform trust decision

`frameworks/base/core/java/android/security/net/config/`

| File | Open it when |
|---|---|
| `NetworkSecurityConfig.java` | **The most useful single file in this chapter.** `getDefaultBuilder(ApplicationInfo)` is where the targetSdk 24 rule is actually expressed — read it and you will never again be unsure which store an app trusts. On API 30 there is exactly one overload, taking `android.content.pm.ApplicationInfo`, which is what makes it callable from Frida with synthetic values |
| `RootTrustManager.java` | The outermost `TrustManager` an app talks to. The head of the measured delegation chain |
| `NetworkSecurityTrustManager.java` | The middle link, and the class that would enforce a `<pin-set>`. It is loaded in every app whether or not a single pin is configured, which is why its presence proves nothing about pinning |
| `TrustAnchor.java` | What an "anchor" is as a Java object, including the `overridesPins` flag |
| `SystemCertificateSource.java` | **Where the system store path is decided in code.** Read this instead of trusting a blog post about which directory holds the anchors on which release |
| `UserCertificateSource.java` | The user store, `/data/misc/user/<userId>/cacerts-added` |
| `DirectoryCertificateSource.java` | The shared parent of both, and where the `subject_hash_old` filename lookup happens |
| `ApplicationConfig.java` | How per-domain configurations are selected for a given hostname |
| `XmlConfigSource.java` | The parser for `network_security_config.xml`. Read it when the XML does not behave as documented |
| `ManifestConfigSource.java` | How the platform falls back when the manifest declares no config at all |
| `RootTrustManagerFactorySpi.java` | How the platform `TrustManager` gets installed as the default in the first place |

### Conscrypt — where validation actually happens

`external/conscrypt/common/src/main/java/org/conscrypt/`

| File | Open it when |
|---|---|
| `TrustManagerImpl.java` | **The real chain validation.** The bottom of the measured delegation chain, and where the `IllegalArgumentException` for a null or zero-length chain is thrown — which is exactly what the empty-chain oracle relies on |
| `OkHostnameVerifier.java` | **The real hostname check.** RFC 6125 matching in code: `subjectAltName` first, wildcard rules, IP-address handling. Read it before arguing about whether a wildcard should have matched |
| `TrustedCertificateIndex.java` | How candidate issuers are found while building a chain, and why a missing intermediate is fatal |
| `ConscryptEngine.java` | The handshake state machine on the Java side |
| `NativeCrypto.java` | The JNI surface. The bridge you cross when Java hooks stop being enough |
| `SSLParametersImpl.java` | Where enabled protocols and cipher suites are resolved into defaults — the source of truth for "what does this API level offer by default" |

`external/conscrypt/platform/src/main/java/org/conscrypt/`

| File | Open it when |
|---|---|
| `TrustedCertificateStore.java` | **The store on disk.** System directory, user `cacerts-added`, user `cacerts-removed`, and the `subject_hash_old` filename convention, in code. The authoritative answer to question 8 of the FAQ |
| `Platform.java` | The Android-specific hooks Conscrypt uses, including how it reaches the network security config |

### Elsewhere in the tree

| Path | Open it when |
|---|---|
| `frameworks/base/core/java/android/net/SSLCertificateSocketFactory.java` | **AOSP's own deliberately-insecure `TrustManager`**, returned by `getInsecure()`. Measured to accept a zero-length chain while all three real trust managers throw |
| `frameworks/base/keystore/java/android/security/KeyChain.java` | The user CA installation path, and the lock-screen requirement |
| `libcore/ojluni/src/main/java/javax/net/ssl/X509TrustManager.java` | The interface contract in full — including the requirement to throw `IllegalArgumentException` for a null or zero-length chain, and the fact that `checkServerTrusted` returns `void` |
| `libcore/ojluni/src/main/java/javax/net/ssl/HostnameVerifier.java` | The other interface. Two methods, one boolean, and the entire attack surface of question 22 |
| `libcore/ojluni/src/main/java/javax/net/ssl/SSLContext.java` | Provider selection and `init`, which is the choke point `trace-tls-validation.js` hooks |
| `external/boringssl/` | The native TLS implementation. `ssl/handshake_client.cc` and `ssl/ssl_x509.cc` are where you go when the Java layer is not in the picture |
| `system/ca-certificates/files/` | The stock root store as shipped in the AOSP tree — the source of the 138 stock certificates measured on the device |

---

## OWASP

| Resource | Why |
|---|---|
| [**MASVS-NETWORK-1**](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/) | *The app secures all network traffic according to the current best practices.* **The control every finding in this chapter maps to** except the pinning ones. Covers protocol version, cipher suites, certificate validation and hostname verification together |
| [**MASVS-NETWORK-2**](https://mas.owasp.org/MASVS/08-MASVS-NETWORK/) | *The app performs identity pinning for all remote endpoints under the developer's control.* Owned by chapter 36, CertificatePinning — but trust-store manipulation findings map here too, because replacing the anchor set is an identity decision |
| [MASVS](https://mas.owasp.org/MASVS/) | The full control set. MASVS-PLATFORM-2 also carries the WebView `proceed()` finding |
| [MASTG](https://mas.owasp.org/MASTG/) | The test procedures. The network ones worth working through: testing data encryption on the network, testing the TLS settings, **testing endpoint identity verification**, testing custom certificate stores and pinning, testing the security provider |
| [MASTG Android network tests](https://mas.owasp.org/MASTG/0x05g-Testing-Network-Communication/) | The Android-specific procedures, with the exact greps and hooks |
| [MASVS v1 requirement identifiers](https://github.com/OWASP/owasp-masvs) | The legacy `MSTG-NETWORK-1` … `MSTG-NETWORK-6` identifiers are still what many clients' templates expect. `MSTG-NETWORK-3` (endpoint identity verification) is this chapter's core requirement |
| [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | A concise, defensible server-side configuration answer, suitable for pasting into a remediation section |
| [Certificate Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html) | For the handoff to chapter 36 |
| [MASTG test apps](https://mas.owasp.org/MASTG/apps/) | Legal practice targets |

> **Warning**
> Cite the MASVS **control**, not a MASTG test id. Control identifiers are stable across MASTG
> refactors; test identifiers have been renumbered more than once, and a stale test id in a report is
> an easy thing for a client to use to discredit the rest of it.

---

## CVEs

| CVE | What |
|---|---|
| [**CVE-2014-3566** — POODLE](https://nvd.nist.gov/vuln/detail/CVE-2014-3566) | The SSL 3.0 CBC padding oracle. Plaintext recovered a byte at a time from any CBC suite under SSL 3.0. **The one identifier this chapter cites**, and the reason `tls-posture.py` probes SSL 3.0 at all — even though no current Android client negotiates it by default |

> **Warning**
> Do not cite any other CVE number here without verifying it against the vendor's own advisory first.
> For the well-known TLS attacks that do not need an identifier — BEAST, CRIME, Lucky 13, FREAK,
> Logjam, Sweet32, ROBOT, Heartbleed — **name the attack**, which is unambiguous and cannot be
> misattributed. In a client report one wrong CVE reference undermines every other claim in the
> document.

---

## Research papers

Cited by title and authors. Where a stable public URL is not certain, the title and venue are enough
to find the paper and are safer than a link that may have moved.

| Work | Why it matters here |
|---|---|
| **Fahl, Harbach, Muders, Baumgärtner, Freisleben, Smith — "Why Eve and Mallory Love Android: An Analysis of Android SSL (In)Security"** (ACM CCS 2012) | **The founding paper for this chapter.** A static analysis of 13,500 popular free Android apps found roughly 8% with TLS code vulnerable to interception, and a manual audit of 100 of those confirmed real credential theft against banking, social and cloud apps. It is the origin of the observation that the permissive `TrustManager` is not rare — it is endemic |
| **Fahl, Harbach, Perl, Koetter, Smith — "Rethinking SSL Development in an Appified World"** (ACM CCS 2013) | The follow-up. It asked *why* developers write the broken code, and found the honest answer: the shortest path out of a self-signed staging certificate under deadline. This is the paper to cite when a report needs to explain the pattern rather than just list it |
| **Georgiev, Iyengar, Jana, Anubhai, Boneh, Shmatikov — "The Most Dangerous Code in the World: Validating SSL Certificates in Non-Browser Software"** (ACM CCS 2012) | **The other essential paper.** It shows the failure is not Android-specific: SSL certificate validation is broken across payment SDKs, shopping carts, cloud client libraries and middleware, and the root cause is badly designed APIs whose insecure use looks like ordinary code. The origin of the chapter's core claim that the *void* return type of `checkServerTrusted` is the bug |
| Sounthiraraj, Sahs, Greenwood, Lin, Khan — "SMV-Hunter: Large Scale, Automated Detection of SSL/TLS Man-in-the-Middle Vulnerabilities in Android Apps" (NDSS 2014) | Automated detection at scale, combining static and dynamic analysis. Useful for understanding why scanners produce the false positives they do |
| Onwuzurike, De Cristofaro — "Danger is My Middle Name: Experimenting with SSL Vulnerabilities in Android Apps" (WiSec 2015) | A later re-measurement showing the problem had not gone away. Good for arguing that this is a current issue, not a 2012 one |
| Möller, Duong, Kotowicz — "This POODLE Bites: Exploiting the SSL 3.0 Fallback" | The original POODLE write-up behind CVE-2014-3566, and the origin of `TLS_FALLBACK_SCSV` (alert 86) |
| Bhargavan, Delignat-Lavaud, Fournet, Pironti, Strub — "Triple Handshake" (IEEE S&P 2014) | Why TLS session resumption and renegotiation were dangerous, and part of why TLS 1.3 deleted renegotiation outright |

---

## Tooling

| Tool | Where | Use |
|---|---|---|
| [`scripts/tls-posture.py`](../scripts/tls-posture.py) | host | **This chapter's server-side prober.** No dependencies, no root, no device. Its raw `ClientHello` engine exists because your local OpenSSL refuses to *offer* SSL 3.0 or RC4, which turns the finding you were looking for into a false negative |
| [`scripts/trace-tls-validation.js`](../scripts/trace-tls-validation.js) | host + device | **This chapter's client-side tracer.** Observes and bypasses nothing, on purpose. `verdict()` and `oracle()` are the two calls that matter |
| [`examples/InsecureTlsClient.java`](../examples/InsecureTlsClient.java) | source | The four failure patterns as compilable code: permissive `TrustManager`, permissive `HostnameVerifier`, `AndroidCAStore`, cleartext fallback |
| [OpenSSL](https://www.openssl.org/docs/manmaster/man1/) | host | `s_client`, `s_server`, `x509`, `verify`. `-subject_hash_old` is the flag this chapter turns on — the newer `-subject_hash` gives the wrong filename |
| [Burp Suite](https://portswigger.net/burp/documentation/desktop/mobile/config-android-device) | host | PortSwigger's own Android configuration guide, including the CA export step |
| [mitmproxy](https://docs.mitmproxy.org/stable/) | host | Scriptable, free, and its `mitmproxy-ca-cert.cer` is easy to convert to the DER the trust store wants |
| [**badssl.com**](https://badssl.com/) | host | **The fastest deliberate-bad-certificate fixture there is.** `expired.`, `wrong.host.`, `self-signed.`, `untrusted-root.`, `revoked.` — one subdomain per validation step, and measured in this chapter |
| [testssl.sh](https://testssl.sh/) | host | The wide-coverage server-side scanner. Use it to cross-check `tls-posture.py`; where they disagree, find out why before reporting either |
| [SSLyze](https://github.com/nabla-c0d3/sslyze) | host | The Python alternative, with a stable machine-readable output format |
| [SSL Labs Server Test](https://www.ssllabs.com/ssltest/) | browser | The grade a client will quote at you. Know what it does and does not measure — it says nothing about the app |
| [Wireshark](https://www.wireshark.org/) | host | Read the actual `ClientHello`, the SNI, and the alert byte when nothing else agrees |
| [Frida](https://frida.re/docs/android/) | host + device | The engine behind the tracer. **Version 16.1.6 has no `--no-pause` flag**: spawn resumes by default and `--pause` opts in. Chapter 53 owns the tool |
| [Objection](https://github.com/sensepost/objection) | host | `android sslpinning disable` is a bypass, not a measurement. Use it after you have assessed, never before |
| [jadx](https://github.com/skylot/jadx) | host | Decompilation. Framework method signatures survive R8 renaming, which is what makes the greps in the cheat sheet work |
| [apktool](https://apktool.org/) | host | Smali plus decoded resources, including `res/xml/network_security_config.xml` |
| [Magisk](https://github.com/topjohnwu/Magisk) | device | The `trustusercerts` module class that promotes a user CA into the system store via a tmpfs overlay and per-certificate bind mounts |
| [IANA TLS parameter registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml) | reference | The authoritative table of cipher suite identifiers, alert codes and extension numbers. Look up an unrecognised suite here rather than guessing |

---

## Books and long-form

| Work | Why |
|---|---|
| *Bulletproof TLS and PKI* — Ivan Ristić | **The best single book on this chapter's subject.** Protocol, certificates, attacks and configuration, written by the author of SSL Labs. The chapters on PKI and on attacks against TLS are the two to read first |
| *Serious Cryptography* — Jean-Philippe Aumasson | The primitives underneath, at the right level. Its TLS chapter is a good short orientation |
| *The Mobile Application Hacker's Handbook* — Chell, Erasmus, Colley, Whitehouse | Dated in specifics, still sound on the methodology of testing transport security on a device |
| *Android Security Internals* — Nikolay Elenkov | The clearest structural account of the platform's credential storage and trust machinery, even where the specifics have moved on |
| *Real-World Cryptography* — David Wong | Protocol-oriented and current. Good on what TLS 1.3 changed and why |

---

## Talks worth finding

Search by topic and speaker rather than by URL, since hosting moves.

- "Why Eve and Mallory Love Android" — the CCS 2012 presentation of the paper above
- "The Most Dangerous Code in the World" — the CCS 2012 presentation, which is more pointed about API design than the paper
- POODLE and the SSL 3.0 fallback — the 2014 disclosure talks, for the mechanism behind alert 86
- TLS 1.3 design rationale — IETF TLS working group presentations, for what was deleted and why
- Mobile TLS interception and pinning bypass — OWASP AppSec and MASTG project sessions
- Android platform security updates — Android Security and Privacy talks at Google I/O, for trust-store and APEX changes

---

## Related chapters

| Chapter | What it owns, and why you would go there |
|---|---|
| [34-Cryptography](../../34-Cryptography/README.md) | The **primitives** underneath TLS: AES-GCM, ECDHE, RSA, SHA-256, and what each one guarantees. Go there when a finding is about the algorithm rather than about the trust decision |
| [**36-CertificatePinning**](../../36-CertificatePinning/README.md) | **Pinning** — narrowing trust from "any of 139 anchors" to one key. Go there the moment the CA is in the system store and the handshake still fails. Pin evaluation happens *after* everything in this chapter succeeds |
| [**44-NetworkSecurityConfig**](../../44-NetworkSecurityConfig/README.md) | **The XML** that configures trust anchors, `debug-overrides`, per-domain rules and cleartext policy. Go there to change *which* anchors an app uses; this chapter only tells you which it currently has |
| [43-WebView](../../43-WebView/README.md) | The **browser widget**, its own certificate error path, and `SslErrorHandler.proceed()`. Go there when the finding is in a WebView rather than in the app's HTTP client |
| [45-OAuth](../../45-OAuth/README.md) | The **authorisation flow** that travels on the channel. Go there once you can read the traffic and need to know whether the flow itself is sound |
| [46-Tokens](../../46-Tokens/README.md) | What the intercepted **bearer tokens** actually are, and what you can do with one. Go there to turn "I can read the traffic" into an impact statement |
| [49-KeyStore](../../49-KeyStore/README.md) | **Hardware-backed key storage**, including client certificates and keys used for mutual TLS. Go there when the app authenticates itself with a key rather than a password |
| [53-Frida](../../53-Frida/README.md) | The **instrumentation engine** behind `trace-tls-validation.js`, and the native-hooking technique you need when the TLS stack is not in Java |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Mapping the findings above to **MASVS controls** and writing them up in the form a client expects |
| [37-RootDetection](../../37-RootDetection/README.md) | Why the app stopped working after you rooted the device and installed a CA — which is a different finding, not a TLS one |
| [07-AOSP](../../07-AOSP/README.md) | How to navigate the source paths listed above without getting lost |

Back to [the chapter](../README.md) · [cheat sheet](../cheatsheet.md) · [mind map](../mindmap.md) ·
[FAQ](../faq.md)
