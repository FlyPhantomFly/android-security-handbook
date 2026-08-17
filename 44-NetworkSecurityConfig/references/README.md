# 44 — Network Security Config — References

Annotated. Every entry says what is in it and why you would open it, because a bare link is a
bookmark, not a reference.

---

## 1. AOSP source

The subsystem is small enough to read in an afternoon and it repays doing so. Everything in
[README §3](../README.md#3-deep-internal-working) is decided in these files.

| Path | Read it for |
|---|---|
| `frameworks/base/core/java/android/security/net/config/` | The whole thing. Twenty-one files, one class per XML element, and the class names are what you will see in a Frida session and in a stack trace |
| `.../net/config/XmlConfigSource.java` | **The parser.** Which elements are accepted, which attributes exist, what happens to an unknown tag, how `expiration` is parsed, and where the `overridePins` default flips inside `<debug-overrides>` |
| `.../net/config/NetworkSecurityTrustManager.java` | `isPinningEnforced()` and `checkPins()` — the three conditions under which pinning silently does not happen. The most important twenty lines in the subsystem |
| `.../net/config/ApplicationConfig.java` | Hostname matching, the per-domain table, `ensureInitialized()`'s laziness, and the public `setDefaultInstance()` an app can use to replace the whole policy |
| `.../net/config/NetworkSecurityConfig.java` | The resolved policy object, `getDefaultBuilder(ApplicationInfo)` (where the targetSdk-dependent defaults come from), and the `Builder`'s parent chaining, which is inheritance |
| `.../net/config/NetworkSecurityConfigProvider.java` | `install()`. Three lines that make every HTTP library on the platform use the config without knowing it exists |
| `.../net/config/PinSet.java`, `Pin.java` | `EMPTY_PINSET` with `Long.MAX_VALUE`; `isSupportedDigestAlgorithm` (SHA-256 only) |
| `.../net/config/DirectoryCertificateSource.java`, `SystemCertificateSource.java`, `UserCertificateSource.java` | Where the two stores are on disk and how they are read and cached |
| `.../net/config/RootTrustManagerFactorySpi.java`, `RootTrustManager.java` | What `TrustManagerFactory.getInstance("PKIX")` actually returns inside an app |
| `frameworks/base/core/java/android/security/NetworkSecurityPolicy.java` | The public API. Note the two `isCleartextTrafficPermitted` overloads and that they can disagree |
| `frameworks/base/core/java/android/app/ActivityThread.java` | `handleBindApplication` — the manifest boolean is set, then the config replaces it. This ordering is the "config wins" rule |
| `frameworks/base/core/java/android/content/pm/ApplicationInfo.java` | `networkSecurityConfigRes`, `FLAG_DEBUGGABLE`, `FLAG_USES_CLEARTEXT_TRAFFIC` |
| `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h` | The AXML chunk grammar and the `resources.arsc` table structures both of this chapter's scripts parse |
| `external/conscrypt/` | `TrustManagerImpl` — the chain building and validation the platform's trust manager delegates to |

Line numbers are deliberately absent throughout this chapter. They move between releases and this
repository does not invent them. File paths are stable.

---

## 2. Official Android documentation

| Link | Why |
|---|---|
| `https://developer.android.com/privacy-and-security/security-config` | The schema reference and the canonical examples. **Read it, then read [README §3.7](../README.md#3-deep-internal-working)** — the guide does not make the `<debug-overrides>` / `FLAG_DEBUGGABLE` dependency explicit enough, and that omission is the source of a very large number of bad findings |
| `https://developer.android.com/privacy-and-security/security-ssl` | The wider HTTPS guidance, including the `X509TrustManager` advice the config exists to replace |
| `https://developer.android.com/about/versions/nougat/android-7.0-changes` | The API 24 trust-store change, in the platform's own words |
| `https://developer.android.com/about/versions/pie/android-9.0-changes-28` | The API 28 cleartext change |
| `https://developer.android.com/reference/android/security/NetworkSecurityPolicy` | The public API's own documentation. Short, and honest that it is advisory |
| `https://developer.android.com/studio/build/build-variants` | Source sets and manifest merging — the mechanism that makes `src/debug/res/xml/` safe |

---

## 3. Standards

| Document | Relevance |
|---|---|
| **RFC 7469** — *Public Key Pinning Extension for HTTP* | The definition of an SPKI pin that the platform, OkHttp and TrustKit all implement, and **§4.3**, which requires a backup pin. The HPKP header the RFC describes is dead; the pin definition is not |
| **RFC 5280** — *Internet X.509 PKI Certificate and CRL Profile* | What a certificate, a chain and a trust anchor are. Read at least §6, path validation |
| **RFC 6797** — *HTTP Strict Transport Security* | Context for the undocumented `hstsEnforced` attribute |
| **RFC 6125** — *Representation and Verification of Domain-Based Application Service Identity* | Hostname verification, which is a separate step from trust and is not configurable here |

---

## 4. OWASP

| Identifier | What it asks for | Where this chapter answers it |
|---|---|---|
| **MASVS-NETWORK-1** | Secure network traffic; TLS everywhere | `cleartextTrafficPermitted` in every scope, the manifest-versus-config precedence, and the enforcement gaps in [§3.5](../README.md#3-deep-internal-working) |
| **MASVS-NETWORK-2** | Endpoint identity verification | Trust anchors and `<pin-set>` as declarations, plus the three silent failures in [§3.6](../README.md#3-deep-internal-working) |
| **MASTG** — "Testing the Network Security Configuration" | The static procedure | [§8](../README.md#8-static-analysis) |
| **MASTG** — "Testing Endpoint Identify Verification" | The dynamic procedure | [§7](../README.md#7-dynamic-analysis), and chapter 36 for the bypass |

`https://mas.owasp.org/MASVS/` and `https://mas.owasp.org/MASTG/`.

> **Note on the MASTG test IDs.** They were renumbered when MASVS v2 landed. Cite the test by
> **title** as well as by identifier so a reader can find it after the next renumbering.

---

## 5. Tools

| Tool | Use |
|---|---|
| [`../scripts/nsc-audit.py`](../scripts/nsc-audit.py) | Extract, resolve the resource ID through `resources.arsc`, decode the AXML, model the inheritance, and report every trust decision with a severity and a next step. Standard library only |
| [`../scripts/nsc-runtime.js`](../scripts/nsc-runtime.js) | Read the platform's own `ApplicationConfig` inside a running app. The authority when the static read and the device disagree |
| [`../../10-APK-Internals/examples/parse_axml.py`](../../10-APK-Internals/examples/parse_axml.py) | The AXML decoder this chapter's auditor imports. Also usable directly: `--extract app.apk --entry res/xml/nsc.xml` |
| `aapt2 dump resources` / `aapt2 dump xmltree` | Shares `libandroidfw` with the platform, so it is the closest host-side approximation of what the device parses. Ships with the Android SDK build-tools |
| `apktool` | Decodes the config back to text XML with the original names. Convenient, and a third opinion |
| `jadx` | Shows the config under Resources, with the manifest reference already resolved |
| `openssl` | Computing pins, reading certificates, and `-subject_hash_old` for CA store filenames |
| `frida` / `objection` | [53-Frida](../../53-Frida/README.md) and chapter 36 |
| MobSF | Good first pass. Produces exactly the two false positives this chapter is about: `<debug-overrides>` in a non-debuggable build, and "pinning implemented" without checking the expiration |

---

## 6. Research and talks

Named by topic rather than by URL where this chapter has not verified a stable link, because a dead
link is worse than a description you can search for.

- **"Why Eve and Mallory Love Android"** (Fahl et al., CCS 2012) — the study that quantified broken
  TLS in Android apps and is the historical reason the declarative config exists. It found empty
  `TrustManager` implementations at a scale that made a platform-level answer unavoidable.
- **Android's own security bulletins** — search for network security configuration and trust store
  entries. Note the pattern: the platform-side bugs are rare; the app-side misconfigurations are
  endemic.
- **Google Play's policy notices on unsafe SSL** — the rejection notices that quote the exact
  `checkServerTrusted` pattern from [README §1.2](../README.md#1-introduction). Worth reading because
  they show what Google's own scanners look for.
- **Conference material on certificate pinning bypass** — plentiful, and almost all of it belongs to
  chapter 36 rather than here. What is scarce, and what this chapter tried to add, is material on
  pinning that *was never enforced in the first place*.

---

## 7. What this chapter measured, so you can re-measure it

Every claim marked "measured" was produced on:

| | |
|---|---|
| Device | Redmi `M2101K6P` (`sweetin`), MIUI 12.5 |
| Android | 11, API 30, kernel 4.14.180 |
| Root | Yes — APatch, with a tmpfs bind-mount over `/system/etc/security/cacerts` |
| Trust stores | 139 system certificates, 1 user certificate (a PortSwigger/Burp CA, present in **both**) |
| Instrumentation | frida-server on device, frida-tools 16.1.6 on host |
| Apps read | `com.vendor.socialmedia`, `com.vendor.marketplace`, `com.vendor.streaming`, `com.vendor.filemanager`, `com.vendor.professionalnet`, `com.vendor.fileexplorer`, `com.miui.calculator`, `com.mobilehackinglab.fridaone` |

> **The six `com.vendor.*` rows are pseudonyms, and the identities are withheld deliberately.**
> They are commercial applications that happened to be installed on the test device; this chapter
> assigns severities to what they ship, and a severity attached to a named third party is a
> disclosure decision this repository is not entitled to make on their behalf. What is published is
> everything that carries the argument: every `targetSdk`, resource path, pin count, expiration
> date, days-expired figure, domain count and trust-anchor source is the real measured value, and
> the pseudonyms are stable across chapters 28, 33, 36, 43, 48, 55, 56 and 68 so one app can be
> followed through all of them. The hostnames and the one SPKI pin value quoted in §5.5 are
> substituted for the same reason — a real pin or domain reconstructs the vendor immediately. The
> counts attached to them are not. See
> [72-RealWorldFindings §4](../../72-RealWorldFindings/references/README.md) for the pseudonym
> table and for the three classes of name that are deliberately *not* pseudonymised.

To reproduce:

```bash
# host
adb shell pm list packages -3
adb shell pm path com.example.app
adb pull /data/app/~~…/base.apk
python3 -B ../scripts/nsc-audit.py base.apk --xml
frida -U -p $(adb shell pidof com.example.app) -l ../scripts/nsc-runtime.js
```

Version numbers of the apps are not recorded here on purpose: they change weekly, and a finding
against a version you cannot obtain is not reproducible. Re-measure against whatever you have.

---

## 8. Related chapters

| Chapter | Relationship |
|---|---|
| [10-APK-Internals](../../10-APK-Internals/README.md) | Owns Android binary XML at the byte level. [`nsc-audit.py`](../scripts/nsc-audit.py) **imports** [`parse_axml.py`](../../10-APK-Internals/examples/parse_axml.py) rather than shipping a second decoder |
| [32-Manifest](../../32-Manifest/README.md) | Owns the manifest audit and `android:networkSecurityConfig` as an attribute. Its §4.7 traces `usesCleartextTraffic` into the platform; this chapter's §4.6 continues the trace into the config |
| 35-SSL | TLS, the handshake, chain validation, and trust anchors as a concept |
| 36-CertificatePinning | Pinning's runtime behaviour and how to defeat it. `<pin-set>` as a *declaration* is chapter 44's; the bypass is 36's |
| [43-WebView](../../43-WebView/README.md) | Cleartext policy reaches WebView; `onReceivedSslError` does not |
| [45-OAuth](../../45-OAuth/README.md) | Depends on [§7.3](../README.md#7-dynamic-analysis) for the recipe that makes the token leg visible in a proxy |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | Lists `<debug-overrides>` or user trust anchors in a release build as NETWORK-1. [§3.7](../README.md#3-deep-internal-working) and [§5.6](../README.md#5-security-perspective) supply the qualification |
| [08-Build-System](../../08-Build-System/README.md) | Source sets and manifest merging — why `src/debug/res/xml/` is where a relaxation belongs |
| [62-Magisk](../../62-Magisk/README.md) | Installing a CA into the system store with a module, properly |
| [53-Frida](../../53-Frida/README.md) | The instrumentation [`nsc-runtime.js`](../scripts/nsc-runtime.js) is built on |
| [34-Cryptography](../../34-Cryptography/README.md) | Public keys, digests, and what an SPKI is |
| [37-RootDetection](../../37-RootDetection/README.md) | Apps that notice your modified system store and refuse to run |
| [23-Permissions](../../23-Permissions/README.md) | `targetSdkVersion` as a behaviour gate, the same mechanism that drives API 24 and 28 here |
