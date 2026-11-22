# 10 — APK Internals · References

Every entry has a one-line annotation saying why you would open it. Where a URL is uncertain, the
title and venue are given instead of a guessed link — follow the repository rule that a wrong
identifier is worse than no identifier.

---

## 1. AOSP source — signing (`tools/apksig`)

`apksig` is the library behind the `apksigner` command line tool, the Android Gradle Plugin, and the
reference for the platform's own verifiers. If you want to know what "verifies" means, this is the
ground truth.

| Path | Why you would read it |
|---|---|
| `tools/apksig/src/main/java/com/android/apksig/ApkVerifier.java` | The top-level entry point that decides which schemes to require for a given SDK range and produces the per-scheme verdicts you see in `apksigner verify -v`. |
| `tools/apksig/src/main/java/com/android/apksig/ApkSigner.java` | The signing counterpart; shows the order in which schemes are applied and how the signing block is assembled. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/ApkSigningBlockUtils.java` | The APK Signing Block reader/writer: size prefix, ID-value pairs, size suffix, magic, and the chunked digest construction over the three covered regions. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/v1/V1SchemeVerifier.java` | JAR signing verification: `MANIFEST.MF` section parsing, `.SF` digest checking, PKCS#7 block handling, and the `X-Android-APK-Signed` downgrade check. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/v1/V1SchemeSigner.java` | How `MANIFEST.MF` and `.SF` are generated, including exactly which bytes each digest covers. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/v2/V2SchemeVerifier.java` | Scheme v2 signer parsing and the digest comparison that makes any post-signing byte change fatal. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/v2/V2SchemeSigner.java` | The v2 block layout and supported signature algorithm IDs, from the producing side. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/v3/V3SchemeVerifier.java` | Scheme v3 verification including `minSdk`/`maxSdk` scoping and proof-of-rotation attribute handling. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/v3/V3SchemeConstants.java` | The v3 and v3.1 block IDs and rotation-related attribute identifiers in one file. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/v4/V4SchemeVerifier.java` | Scheme v4: how the `.idsig` side file is bound to the v2/v3 signature. |
| `tools/apksig/src/main/java/com/android/apksig/SigningCertificateLineage.java` | The lineage file format and the per-step capability flags that decide what a rotated-away key is still trusted for. |
| `tools/apksig/src/main/java/com/android/apksig/apk/ApkUtils.java` | Locating the ZIP sections and the signing block in an arbitrary APK; the code your own parser should agree with. |
| `tools/apksig/src/main/java/com/android/apksig/internal/zip/` | `LocalFileRecord`, `CentralDirectoryRecord`, `EocdRecord` and `ZipUtils` — a compact, readable ZIP implementation. |
| `tools/apksig/src/main/java/com/android/apksig/internal/apk/stamp/` | Source stamp signing and verification, including the `stamp-cert-sha256` entry. |

Browse at `https://android.googlesource.com/platform/tools/apksig/` and append
`+/refs/heads/main/<path-below-tools/apksig/>` to reach a file.

---

## 2. AOSP source — platform-side verification and package parsing

| Path | Why you would read it |
|---|---|
| `frameworks/base/core/java/android/util/apk/ApkSignatureVerifier.java` | The platform's scheme dispatcher: tries v4, v3.1, v3, v2, then v1, and records the result as `SigningDetails`. |
| `frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV2Verifier.java` | On-device v2 verification, independent of the `apksig` host library. |
| `frameworks/base/core/java/android/util/apk/ApkSignatureSchemeV3Verifier.java` | On-device v3/v3.1 verification and lineage extraction. |
| `frameworks/base/core/java/android/util/apk/ApkSigningBlockUtils.java` | The device-side signing block reader; compare it with the `apksig` version when hunting for parser divergence. |
| `frameworks/base/core/java/android/util/apk/SourceStampVerifier.java` | Source stamp verification as the platform performs it. |
| `frameworks/base/core/java/android/content/pm/PackageParser.java` | The historical monolithic parser. Still the clearest single file for understanding how a manifest becomes a `PackageInfo`; deprecated in favour of the package below. |
| `frameworks/base/core/java/android/content/pm/parsing/ParsingPackageUtils.java` | The modern manifest parser: attribute-by-attribute handling of `<manifest>`, `<application>` and every component tag. |
| `frameworks/base/core/java/android/content/pm/parsing/ApkLiteParseUtils.java` | The fast "lite" parse used to read package name, version and split names before the full parse. |
| `frameworks/base/core/java/android/content/pm/SigningInfo.java` | The public object returned by `GET_SIGNING_CERTIFICATES`; defines `getApkContentsSigners()` and `getSigningCertificateHistory()`. |
| `frameworks/base/core/java/android/content/pm/SigningDetails.java` | The internal representation of a package's signers and lineage, and the capability checks used by `hasSigningCertificate`. |
| `frameworks/base/core/java/android/content/pm/Signature.java` | The `Signature` class — a thin wrapper over a DER certificate; explains why `toCharsString()` returns hex. |
| `frameworks/base/services/core/java/com/android/server/pm/PackageManagerService.java` | Install-time flow: where signature verification sits relative to parsing, and where `INSTALL_FAILED_UPDATE_INCOMPATIBLE` is raised. |
| `frameworks/base/services/core/java/com/android/server/pm/InstallPackageHelper.java` | The modern install path, including split consistency and signer-match enforcement across splits. |

Browse at `https://android.googlesource.com/platform/frameworks/base/`.

---

## 3. AOSP source — resources, binary XML and ARSC (`libs/androidfw`, `tools/aapt2`)

| Path | Why you would read it |
|---|---|
| `frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h` | The single most useful header in this chapter: every chunk type constant, every struct layout, `Res_value` data types, and `ResTable_config`. On older trees the same file lives at `frameworks/base/include/androidfw/ResourceTypes.h`. |
| `frameworks/base/libs/androidfw/ResourceTypes.cpp` | The implementations of `ResStringPool`, `ResXMLTree`/`ResXMLParser` and `ResTable`. Read `ResXMLParser::next()` to see exactly how strictly the device validates chunk sizes. |
| `frameworks/base/libs/androidfw/AssetManager2.cpp` | Resource resolution at runtime: package lookup, configuration matching, and overlay precedence. |
| `frameworks/base/libs/androidfw/LoadedArsc.cpp` | Loading and validating `resources.arsc`, including the sparse and 16-bit-offset entry encodings. |
| `frameworks/base/libs/androidfw/ApkAssets.cpp` | How an APK is opened and its `resources.arsc` and `AndroidManifest.xml` mapped. |
| `frameworks/base/libs/androidfw/Idmap.cpp` | Runtime resource overlay ID mapping — the mechanism behind resource shadowing. |
| `frameworks/base/tools/aapt2/` | The compiler/linker that *produces* AXML and `resources.arsc`; `format/binary/` contains the serialisers that mirror `ResourceTypes.h`. |
| `frameworks/base/tools/aapt2/dump/` | The implementation behind `aapt2 dump xmltree` and `aapt2 dump chunks`, which is what you compare tool output against. |

---

## 4. AOSP source — ZIP handling and archive safety

| Path | Why you would read it |
|---|---|
| `system/libziparchive/zip_archive.cc` | The native ZIP reader used by the framework and installer: central directory parsing, duplicate-name rejection, and the checks that closed the Master Key class. |
| `system/libziparchive/include/ziparchive/zip_archive.h` | The public API and the error codes you will see in `logcat` when an APK fails to open. |
| `libcore/ojluni/src/main/java/java/util/zip/ZipFile.java` | The Java `ZipFile` an app uses; where entry names come from and what is (and is not) validated. |
| `libcore` — `dalvik/system/ZipPathValidator.java` | The Android 14 path-traversal guard applied by default to apps targeting API 34+. |
| `bionic/linker/` | How a `.so` mapped directly out of an APK is loaded when `extractNativeLibs="false"`, and the page-alignment constraints that follow. |
| `system/security/` | Keystore and related trust components; relevant when signature checks are chained to hardware-backed keys — see [49-KeyStore](../../49-KeyStore/README.md). |

Browse at `https://android.googlesource.com/platform/system/libziparchive/`,
`https://android.googlesource.com/platform/libcore/` and
`https://android.googlesource.com/platform/bionic/`.

---

## 5. Official Android documentation

| Link | Why |
|---|---|
| https://source.android.com/docs/security/features/apksigning | Overview of the signing schemes and which platform version introduced each. |
| https://source.android.com/docs/security/features/apksigning/v2 | The normative v2 specification: signing block layout, ID-value pairs, the three covered regions, chunked digest algorithm, and the signature algorithm ID table. |
| https://source.android.com/docs/security/features/apksigning/v3 | The v3 specification: proof-of-rotation, lineage structure, `minSdk`/`maxSdk` in signed data. Also documents v3.1. |
| https://source.android.com/docs/security/features/apksigning/v4 | The v4 specification: fs-verity Merkle tree, the `.idsig` file format, and the dependency on v2/v3. |
| https://developer.android.com/studio/publish/app-signing | Play App Signing, upload keys versus app signing keys, and key rotation from the developer's side. |
| https://developer.android.com/tools/apksigner | Complete `apksigner` flag reference including `rotate` and `lineage`. |
| https://developer.android.com/tools/zipalign | What alignment means and why it must come before signing. |
| https://developer.android.com/tools/aapt2 | `aapt2` compile/link/dump reference; the `dump` subcommands are the ones used throughout this chapter. |
| https://developer.android.com/guide/app-bundle | The App Bundle format and how splits are generated from it. |
| https://developer.android.com/tools/bundletool | `bundletool` reference: `build-apks`, `install-apks`, `extract-apks`, `get-device-spec`. |
| https://developer.android.com/guide/app-bundle/app-bundle-format | The internal layout of an `.aab`, which is *not* the same as an APK's. |
| https://developer.android.com/guide/practices/page-sizes | 16 KB page size support: ZIP alignment, ELF segment alignment, and the compatibility timeline. |
| https://developer.android.com/topic/performance/reduce-apk-size | Where APK size actually goes; useful for reasoning about what is in an unfamiliar APK. |
| https://developer.android.com/reference/android/content/pm/PackageManager | `GET_SIGNING_CERTIFICATES`, `checkSignatures`, `hasSigningCertificate` and their return values. |
| https://developer.android.com/reference/android/content/pm/SigningInfo | The lineage-aware signature API an app should be using. |
| https://developer.android.com/guide/topics/manifest/application-element | Attribute semantics for `extractNativeLibs`, `debuggable`, `networkSecurityConfig` — see also [32-Manifest](../../32-Manifest/README.md). |
| https://developer.android.com/about/versions/14/behavior-changes-all | Android 14 behaviour changes including the default ZIP path validation. |

---

## 6. Format specifications

| Link / title | Why |
|---|---|
| PKWARE **.ZIP File Format Specification** (APPNOTE.TXT) — https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT | The normative ZIP specification. Sections 4.3.7 (local file header), 4.3.12 (central directory header), 4.3.16 (EOCD), 4.3.14 (Zip64 EOCD) and 4.4.4 (general purpose bit flag) are the ones this chapter uses. |
| Oracle **JAR File Specification** — https://docs.oracle.com/en/java/javase/17/docs/specs/jar/jar.html | Defines `MANIFEST.MF` and `.SF` syntax, the 72-byte line-wrapping rule, and signed JAR semantics that APK v1 signing inherits verbatim. |
| **RFC 5652** — Cryptographic Message Syntax (CMS) — https://www.rfc-editor.org/rfc/rfc5652 | The `SignedData` structure inside `META-INF/CERT.RSA`. |
| **RFC 5280** — X.509 PKI Certificate and CRL Profile — https://www.rfc-editor.org/rfc/rfc5280 | The certificate format you dump with `openssl x509`;Android does not build or validate a chain to a trust anchor for app signing — identity continuity is what matters. |
| **RFC 8017** — PKCS #1 v2.2 (RSA) — https://www.rfc-editor.org/rfc/rfc8017 | RSASSA-PSS and RSASSA-PKCS1-v1_5, the two RSA modes in the v2/v3 signature algorithm table. |
| **RFC 1951** — DEFLATE Compressed Data Format — https://www.rfc-editor.org/rfc/rfc1951 | Compression method 8, the default for APK entries. |
| **RFC 1952** — GZIP file format | Occasionally relevant for `assets/` payloads; not used for ZIP entries themselves. |
| Linux kernel **fs-verity** documentation — https://www.kernel.org/doc/html/latest/filesystems/fsverity.html | The Merkle tree construction and descriptor that scheme v4 signs. |

---

## 7. OWASP MASVS / MASTG

The Mobile Application Security Verification Standard (MASVS) states *controls*; the Mobile
Application Security Testing Guide (MASTG) states *how to test them*. MASVS v2 replaced the old
`MSTG-*` requirement numbering with category identifiers, and MASTG v2 renumbered its tests, so both
naming schemes are given where they are stable.

| Identifier | Relevance to this chapter |
|---|---|
| https://mas.owasp.org/MASVS/ | MASVS root; start here for the current control identifiers. |
| https://mas.owasp.org/MASTG/ | MASTG root; the test and demo pages. |
| **MASVS-CODE-1** | The app requires an up-to-date platform version — ties directly to the "targeting API ≥ 30 requires v2" rule. |
| **MASVS-CODE-3** | Only components without known vulnerabilities — covers shipping a bundled ZIP/unarchiving library with a ZipSlip-class bug. |
| **MASVS-CODE-4** | Validates and sanitises untrusted input — the control ZipSlip findings belong under, because archive entry names are untrusted input. |
| **MASVS-RESILIENCE-1** | Validates the integrity of the platform — root/bootloader checks that are commonly implemented alongside signature checks. |
| **MASVS-RESILIENCE-2** | Implements anti-tampering mechanisms — where runtime self-signature verification findings belong. See [38-TamperDetection](../../38-TamperDetection/README.md). |
| **MASVS-RESILIENCE-3** | Anti-static-analysis — relevant when parser-confusion or packing is used to defeat tooling. See [40-Obfuscation](../../40-Obfuscation/README.md). |
| Legacy **MSTG-CODE-1** | "The app is signed and provisioned with a valid certificate, of which the private key is properly protected." Still the identifier most report templates expect for signing findings. |
| Legacy **MSTG-CODE-2** | "The app has been built in release mode, with settings appropriate for a release build (e.g. non-debuggable)." The `android:debuggable` check. |
| Legacy **MSTG-RESILIENCE-3** | "The app detects, and responds to, tampering with executable files and critical data within its own sandbox." |
| MASTG test — *Making Sure That the App Is Properly Signed* | The procedure that reduces to `apksigner verify -v --print-certs`. Referred to by name rather than a numeric ID because MASTG v2 renumbered it. |
| MASTG test — *Testing whether the App is Debuggable* | Manifest `android:debuggable` verification, and the reason the three-way manifest diff in this chapter matters. |

---

## 8. CVEs

Only two CVE identifiers are named in this chapter. Everything else is described as a *class*.

| CVE | One-line summary | Link |
|---|---|---|
| **CVE-2017-13156** ("Janus") | A DEX file prepended to a v1-only-signed APK still passes JAR signature verification because the ZIP structure is located from the end of the file, while the runtime's code-loading path reads the DEX magic at offset 0 and executes the attacker's classes; fixed by requiring APK Signature Scheme v2, which digests the whole file from offset 0. Affected Android 5.0–8.0. | https://nvd.nist.gov/vuln/detail/CVE-2017-13156 |
| **CVE-2013-4787** ("Master Key") | A ZIP archive containing two entries with the same name caused the signature verifier and the code loader to operate on different copies, letting an attacker append a replacement `classes.dex` to a legitimately signed APK and have it executed; two related variants in the same period abused disagreements over ZIP length-field interpretation rather than duplicate names as such. | https://nvd.nist.gov/vuln/detail/CVE-2013-4787 |

Both entries are also reachable through https://source.android.com/docs/security/bulletin — the
Android Security Bulletin index is the right place to confirm which builds carry a given fix.

For the ZipSlip class generally, treat it as a *pattern* rather than a single CVE: it has been
assigned hundreds of identifiers across ecosystems. Cite the specific library version in the app you
are testing, not a generic identifier.

---

## 9. Research, talks and long-form writing

URLs are omitted where they are not certain; the title and venue are enough to find the material.

| Work | Venue / author | Why it matters here |
|---|---|---|
| *Android: One Root to Own Them All* | Jeff Forristal (Bluebox Security), Black Hat USA 2013 | The original public presentation of the Master Key signature-verification bypass; still the clearest explanation of the "two parsers, one archive" problem. |
| GuardSquare's disclosure of the Janus vulnerability | GuardSquare, 2017 | The write-up that introduced CVE-2017-13156 and the DEX-prepending technique; the vendor blog is the primary source. |
| Google Android Developers Blog — *APK Signature Scheme v2* announcement | Google, 2016 | The design rationale for moving from per-entry to whole-file signing, written by the people who did it. |
| Android Security Bulletins | Google, monthly | The authoritative record of which platform builds fixed which parsing and signing issues. |
| MASTG chapter — *Android Anti-Reversing Defenses* | OWASP | Systematic treatment of integrity checks, including the ones that read the app's own signature. |
| Research on Android manifest and AXML parser divergence | Multiple groups, ongoing | Search terms: "AXML parser confusion", "Android manifest parser differential", "APK tool evasion". Treat individual write-ups carefully — several describe techniques against tool versions that have since been hardened. |
| Baksmali / smali documentation | Ben Gruver, project wiki | The Smali syntax reference you need for [lab 02](../labs/lab-02-unpack-modify-rebuild-resign.md). |
| Apktool documentation | Connor Tumbleson, https://ibotpeaches.github.io/Apktool/documentation/ | `apktool.yml`, framework handling, and the known limitations that cause rebuild failures. |
| JADX documentation | skylot, project wiki | Flags that change what you see, including `--show-bad-code`. See [56-JADX](../../56-JADX/README.md). |

---

## 10. Tooling homepages

| Tool | Link |
|---|---|
| Apktool | https://apktool.org/ |
| JADX | https://github.com/skylot/jadx |
| smali / baksmali | https://github.com/google/smali |
| bundletool | https://github.com/google/bundletool |
| Android command line tools (contains `apksigner`, `zipalign`, `aapt2`) | https://developer.android.com/studio#command-line-tools-only |
| Frida | https://frida.re/ — used by `scripts/apk-signature-hooks.js`; see [53-Frida](../../53-Frida/README.md) |
| MobSF | https://github.com/MobSF/Mobile-Security-Framework-MobSF — see [55-MobSF](../../55-MobSF/README.md) |
| OpenSSL | https://www.openssl.org/docs/ — certificate and PKCS#7 inspection |

---

## 11. Where to go next in this repository

| Chapter | Connection |
|---|---|
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | What the installed app looks like on disk once the APK has been processed. |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | The format of the `classes*.dex` entries this chapter only counts. |
| [15-Native-Code](../../15-Native-Code/README.md) | ELF, `lib/<abi>/`, and how libraries are mapped out of the APK. |
| [32-Manifest](../../32-Manifest/README.md) | The semantics of every attribute the AXML parser in this chapter decodes. |
| [34-Cryptography](../../34-Cryptography/README.md) | Digests, RSA/ECDSA and X.509, which the signing schemes assume you understand. |
| [38-TamperDetection](../../38-TamperDetection/README.md) | Runtime self-signature verification, the defence this chapter's Frida script targets. |
| [40-Obfuscation](../../40-Obfuscation/README.md) | Why decompiler output disagrees with reality, beyond parser confusion. |
| [53-Frida](../../53-Frida/README.md) | The instrumentation framework used by `scripts/apk-signature-hooks.js`. |
| [56-JADX](../../56-JADX/README.md) | Getting readable Java out of the DEX files inside the APK. |
