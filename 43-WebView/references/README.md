# 43 — WebView — References

Annotated. Each entry says **why you would open it**, not just what it is. The chapter itself is
[../README.md](../README.md).

Two standing warnings that apply to everything below:

- **Anything that states a WebView default without stating a provider version is unreliable.**
  WebView is a Mainline module; the defaults are implemented in `AwSettings`, in an APK that updates
  through the Play Store. This chapter's table (`../README.md` §3.4) is a measurement on
  **150.0.7871.181**, and the probe that produced it ships in `../examples/webview-probe/`.
- **This repository does not cite CVE identifiers it has not read.** Where a well-known issue is
  referenced below it is described by *class* rather than by number.

---

## 1. AOSP source

Platform paths are stable and safe to cite. Line numbers are not, and none are given.

| Path | Why you would open it |
|---|---|
| `frameworks/base/core/java/android/webkit/WebView.java` | The public API. `addJavascriptInterface`, `loadUrl`, `setWebContentsDebuggingEnabled`, `getCurrentWebViewPackage` |
| `frameworks/base/core/java/android/webkit/WebSettings.java` | **Abstract.** The `MIXED_CONTENT_*` constants are here; the defaults are not. This is the file that proves you must measure |
| `frameworks/base/core/java/android/webkit/WebViewClient.java` | **The most important file in the chapter.** `onReceivedSslError`'s base implementation calls `handler.cancel()`. Also `shouldOverrideUrlLoading` and `shouldInterceptRequest` |
| `frameworks/base/core/java/android/webkit/SslErrorHandler.java` | `proceed()` and `cancel()`, both empty in the platform. The real class is the provider's subclass — `WV.e53` on this device |
| `frameworks/base/core/java/android/webkit/WebChromeClient.java` | `onPermissionRequest`, `onGeolocationPermissionsShowPrompt`, `onConsoleMessage` — where a *web page* asks for a device capability |
| `frameworks/base/core/java/android/webkit/WebViewFactory.java` | Provider selection and the ClassLoader boundary that breaks naive Frida hooks (§4.5) |
| `frameworks/base/core/java/android/webkit/JavascriptInterface.java` | The annotation itself. Runtime-visible, which is why it survives into the DEX and can be enumerated |
| `frameworks/base/core/java/android/webkit/CookieManager.java` | The WebView's cookie jar — the one your logout code forgets |
| `frameworks/base/core/java/android/webkit/WebStorage.java` | `deleteAllData()`, the second call your logout code forgets |
| `frameworks/base/core/java/android/net/http/SslError.java` | The six primary error codes. `getPrimaryError()` returns only the most severe |
| `frameworks/base/core/java/android/security/NetworkSecurityPolicy.java` | What Chromium calls through JNI before a cleartext request. The proof that chapter 44's config reaches inside a WebView |
| `frameworks/base/services/core/java/com/android/server/webkit/` | `WebViewUpdateService` — the provider selection policy whose output `dumpsys webviewupdate` prints |
| `external/chromium-webview/` | The **prebuilt** Chromium delivered as the provider APK. Prebuilts, not source — the source is in the Chromium project under `android_webview/` |

> **Reading `external/chromium-webview/` honestly.** In AOSP this directory holds prebuilt APKs per
> architecture. You cannot read `AwSettings` there. To see the provider's actual manifest — including
> the `isolatedProcess` renderer declaration — pull the installed APK off a device and decode it:
> ```bash
> adb shell pm path com.google.android.webview
> adb pull /data/app/.../base.apk webview-provider.apk
> python3 -B ../../10-APK-Internals/examples/parse_axml.py webview-provider.apk
> ```

---

## 2. Chromium

| Source | Why |
|---|---|
| Chromium project, `android_webview/` | The real implementation of everything the platform declares abstract. `AwSettings`, `AwContents`, `AwContentsClientBridge` |
| Chrome DevTools Protocol specification | What is on the far end of `@webview_devtools_remote_<pid>`. `Runtime.evaluate` is the method that turns a socket into script execution |
| Chromium security architecture / site isolation documentation | Why the renderer is a separate process and what the sandbox is expected to contain |
| Chromium release notes and the Chrome Releases blog | The only reliable way to map a WebView provider version to the fixes it contains |

---

## 3. Official Android documentation

| Document | Why |
|---|---|
| `WebView`, `WebSettings`, `WebViewClient`, `WebChromeClient` reference pages | Method-by-method. Note where they state a default and where they do not — the gaps are why the probe exists |
| "Managing WebView objects" | Google's own guidance, including the `addJavascriptInterface` warnings |
| "Web-based content" security guidance | The official position on file access and JavaScript interfaces |
| `androidx.webkit` — `WebViewAssetLoader` | **The replacement for `file://`.** Serves packaged assets over a virtual `https://` origin so the same-origin policy behaves normally |
| `androidx.webkit` — `WebViewCompat.addWebMessageListener` | **The replacement for `addJavascriptInterface`.** Origin allow-list enforced by Chromium before the message crosses |
| `androidx.webkit` — `WebViewFeature` | Feature detection, because the provider version varies per device |
| Safe Browsing in WebView | The `EnableSafeBrowsing` manifest meta-data and what turning it off costs |
| Project Mainline / Android modular system components | Why the WebView version is not the OS version (§3.1) |
| `android:isolatedProcess` on `<service>` | The mechanism the renderer uses. See also [21-App-Sandbox](../../21-App-Sandbox/README.md) |

---

## 4. OWASP MASVS and MASTG

| Identifier | Relevance |
|---|---|
| **MASVS-PLATFORM-2** — WebViews are configured securely | The chapter's primary mapping. §3.4–§3.13 and `../scripts/webview-audit.py` |
| MASVS-PLATFORM-1 — IPC used securely | The bridge as an IPC surface; the DevTools abstract socket |
| MASVS-NETWORK-1 — secure network traffic | `onReceivedSslError`, mixed content |
| MASVS-NETWORK-2 — endpoint identity verification | The failure path chapter 44's file cannot express |
| MASVS-STORAGE-2 — no sensitive data in unintended storage | `app_webview/` cache, cookies and `localStorage` |
| MASVS-CODE-1 — no debug settings in release | `setWebContentsDebuggingEnabled` |
| MASTG — testing JavaScript execution in WebViews | The static half of §8 |
| MASTG — testing WebView protocol handlers | `file://`, `content://`, custom schemes |
| MASTG — determining whether native methods are exposed through WebViews | The bridge enumeration in §7 |
| MASTG — testing WebViews cleanup | The six logout calls in §3.14 |

One qualification on [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md)'s cheatsheet: it lists
`setJavaScriptEnabled(true)` alongside the other WebView rows. It should not be reported as a
PLATFORM-2 finding on its own — see §3.5 and `WV-070`.

---

## 5. Research and background

Described by class rather than by citation where this chapter has not read the primary source.

| Topic | Why it matters here |
|---|---|
| The `addJavascriptInterface` reflection-to-`Runtime.exec` issue | The historical pre-API-17 remote code execution class. Documented in Android Security Bulletins; §3.7 reconstructs the mechanism rather than citing an identifier |
| Large-scale studies of `onReceivedSslError` in Play Store binaries | Several academic and industry surveys have found thousands of apps proceeding on certificate errors. The methodology is essentially `../scripts/webview-audit.py`'s `WV-001` check at scale |
| Same-origin policy and `file://` origins | Background for §3.9. Every local file shares the single origin string `file://`, which is why the relaxation switches exist |
| Abstract-namespace unix sockets on Linux | [24-IPC](../../24-IPC/README.md) covers the mechanism; `man 7 unix` is the primitive reference |
| Cordova / Ionic / Capacitor security documentation | For hybrid apps, `config.xml`'s `<access>` and `<allow-navigation>` **are** the navigation gate, and the plugin list **is** the bridge inventory |

---

## 6. Tools

| Tool | Use |
|---|---|
| [`../scripts/webview-audit.py`](../scripts/webview-audit.py) | Static: every setting an APK applies *and* every one it inherits from its `targetSdkVersion`, plus bridges and `onReceivedSslError` bodies |
| [`../scripts/trace-webview.js`](../scripts/trace-webview.js) | Runtime: effective settings read back off live objects, bridges enumerated by reflection, `proceed()` vs `cancel()`, and the `forceCancel` control |
| [`../../44-NetworkSecurityConfig/scripts/nsc-audit.py`](../../44-NetworkSecurityConfig/scripts/nsc-audit.py) | **Run this alongside, always.** It answers the cleartext and trust-anchor half |
| [`../../35-SSL/scripts/trace-tls-validation.js`](../../35-SSL/scripts/trace-tls-validation.js) | Its *silence* during a page load is the diagnostic that the traffic is Chromium's, not the Java stack's |
| [`../../10-APK-Internals/examples/parse_axml.py`](../../10-APK-Internals/examples/parse_axml.py) | Decode `AndroidManifest.xml`. Imported by the auditor |
| [`../../12-DEX-Internals/examples/dex_parser.py`](../../12-DEX-Internals/examples/dex_parser.py) | DEX header, strings, type and method tables. Imported by the auditor |
| JADX | First look. The whole settings block is legible in one screen |
| apktool + Smali | For the greps in §8.2 and for the annotation enumeration |
| `dexdump` (Android build-tools) | Produced every bytecode listing in §6.2 |
| Frida / frida-python | §7. Drive it through the Python API, not the REPL — §7.9 |
| Chrome `chrome://inspect` | With `adb forward` in place, a full inspector on an app's WebView |
| objection | Quick triage only; §7.7 lists what it cannot do |

---

## 7. Related chapters

| Chapter | What it owns, and why you would go there from here |
|---|---|
| [09-Android-App-Internals](../../09-Android-App-Internals/README.md) | What a process and a UID are — the foundation for "the page runs as your app" |
| [10-APK-Internals](../../10-APK-Internals/README.md) | Binary XML and the APK container. Its `parse_axml.py` is imported by this chapter's auditor |
| [12-DEX-Internals](../../12-DEX-Internals/README.md) | DEX structure. Its `dex_parser.py` is imported by the auditor; §6.2's bytecode listings assume its instruction-format material |
| [21-App-Sandbox](../../21-App-Sandbox/README.md) | UIDs, SELinux domains and `isolatedProcess` **mechanics**. This chapter supplies its flagship user: the renderer |
| [22-SELinux](../../22-SELinux/README.md) | `isolated_app`, MCS categories. Read before interpreting the renderer's label |
| [24-IPC](../../24-IPC/README.md) | **Abstract-namespace sockets.** `@webview_devtools_remote_<pid>` is their most consequential instance; §3.13 is the case study |
| [26-Intent](../../26-Intent/README.md) | Intent resolution and redirection. How the attacker's URL reaches the Activity; this chapter owns what happens after |
| [27-ContentProviders](../../27-ContentProviders/README.md) | Providers, and what is on the far end of a `content://` fetch. §3.8 is the WebView half of its MASVS-PLATFORM-2 note |
| [28-Services](../../28-Services/README.md) | Service declaration and `isolatedProcess` from the service side |
| [30-Activities](../../30-Activities/README.md) | The exported Activity as a confused deputy — the component the deep link lands on |
| [32-Manifest](../../32-Manifest/README.md) | `BROWSABLE`, `exported`, `debuggable`, `allowBackup`. Its "unverified deep link → WebView" row terminates here |
| [33-Storage](../../33-Storage/README.md) | Reading `app_webview/`. Read its false-positive numbers before reporting a `localStorage` hit |
| [35-SSL](../../35-SSL/README.md) | TLS and trust **generally**. Its tracer's silence is this chapter's diagnostic; its browser-widget note points here |
| [36-CertificatePinning](../../36-CertificatePinning/README.md) | Pinning in the Java stack — and why none of it transfers to WebView traffic |
| [40-Obfuscation](../../40-Obfuscation/README.md) | What survives R8. Bridge method names must be kept, which makes WebView auditing unusually high-yield |
| [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) | **The XML.** It governs cleartext inside WebViews; it cannot express `onReceivedSslError`. Run its auditor alongside this chapter's, always |
| [45-OAuth](../../45-OAuth/README.md) | Why an embedded user agent is the wrong place for an authorisation flow, in depth |
| [53-Frida](../../53-Frida/README.md) | The instrumentation used throughout §7 |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | The MASVS mapping, with the `setJavaScriptEnabled` qualification above |

---

## 8. This chapter's own artefacts

| File | What it is |
|---|---|
| [../scripts/webview-audit.py](../scripts/webview-audit.py) | The static auditor. Computes defaults, backtracks to constant arguments, classifies SSL handlers |
| [../scripts/trace-webview.js](../scripts/trace-webview.js) | The runtime tracer, with `settings()`, `bridges()`, `verdict()` and `forceCancel()` |
| [../examples/webview-probe/ProbeActivity.java](../examples/webview-probe/ProbeActivity.java) | The measurement app behind §3.4 |
| [../examples/vulnerable-webview/VulnerableWebViewActivity.java](../examples/vulnerable-webview/VulnerableWebViewActivity.java) | Eleven tagged defects |
| [../examples/vulnerable-webview/LeakyBridge.java](../examples/vulnerable-webview/LeakyBridge.java) | The bridge, with the annotation gate demonstrable rather than asserted |
| [../examples/hardened-webview/HardenedWebViewActivity.java](../examples/hardened-webview/HardenedWebViewActivity.java) | Every defect fixed, each tagged with the `[Vn]` it answers |
| [../examples/attacker-page/evil.html](../examples/attacker-page/evil.html) | The exploit page. Ordinary JavaScript; no exploit, no CVE |
| [../examples/build.sh](../examples/build.sh) | Gradle-free build, out of tree. Ships sources, never APKs |
| [../labs/lab-01-exploit-a-javascript-bridge.md](../labs/lab-01-exploit-a-javascript-bridge.md) | Build it, exploit it, measure the origin matrix |
| [../labs/lab-02-onreceivedsslerror-defeats-a-correct-config.md](../labs/lab-02-onreceivedsslerror-defeats-a-correct-config.md) | The certificate half, with the causation control |
| [../labs/lab-03-audit-a-real-app.md](../labs/lab-03-audit-a-real-app.md) | Static plus runtime against a real app, stopping at detection |
| [../labs/lab-04-ctf-the-deputy-in-the-browser.md](../labs/lab-04-ctf-the-deputy-in-the-browser.md) | Five flags, one red herring |
| [../cheatsheet.md](../cheatsheet.md) | The settings table with defaults **and** the version each changed at |
| [../mindmap.md](../mindmap.md) | The chapter as one map |
| [../faq.md](../faq.md) | Twenty-one questions, including the ones people avoid asking |
