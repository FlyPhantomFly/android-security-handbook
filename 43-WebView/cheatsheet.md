# 43 — WebView — Cheat Sheet

Dense reference. Prose is in [README.md](README.md).

Everything marked **(M)** was **measured** on the device below, not read from documentation.
Re-measure before quoting: WebView is a Mainline module and its defaults live in provider code.

```
device      Redmi M2101K6P (sweetin), MIUI 12.5, rooted (APatch), frida-server 16.1.6
OS          Android 11 / API 30
WebView     com.google.android.webview  150.0.7871.181  (versionCode 787118103)
factory     /product/app/WebViewGoogle   92.0.4515.131   <- the OEM copy, superseded
measured    examples/webview-probe/ProbeActivity.java
```

---

## 1. WebSettings defaults by targetSdkVersion — the table **(M)**

`javaScriptEnabled` is `false` at every level. `mixedContentMode`: `0`=ALWAYS_ALLOW,
`1`=NEVER_ALLOW, `2`=COMPATIBILITY_MODE.

| targetSdk | `allowFileAccess` | `allowFileAccessFromFileURLs` | `allowUniversalAccessFromFileURLs` | `allowContentAccess` | `mixedContentMode` | `domStorageEnabled` | `safeBrowsingEnabled` |
|---|---|---|---|---|---|---|---|
| 14 | true | **true** | **true** | true | **0** | false | true |
| 15 | true | **true** | **true** | true | **0** | false | true |
| **16** | true | **false** | **false** | true | 0 | false | true |
| 17 | true | false | false | true | 0 | false | true |
| 18 | true | false | false | true | 0 | false | true |
| 19 | true | false | false | true | **0** | false | true |
| **21** | true | false | false | true | **1** | false | true |
| 23 | true | false | false | true | 1 | false | true |
| 24 | true | false | false | true | 1 | false | true |
| 26 | true | false | false | true | 1 | false | true |
| 28 | true | false | false | true | 1 | false | true |
| 29 | **true** | false | false | true | 1 | false | true |
| **30** | **false** | false | false | true | 1 | false | true |
| 31 | false | false | false | true | 1 | false | true |
| 33 | false | false | false | true | 1 | false | true |
| 34 | false | false | false | true | 1 | false | true |
| 35 | false | false | false | **true** | 1 | false | true |

### The version each default changed at **(M)**

| Setting | Default | Changed at targetSdk | From → To |
|---|---|---|---|
| `setJavaScriptEnabled` | `false` | **never** | — |
| `setAllowFileAccess` | version-dependent | **30** (R) | `true` → `false` |
| `setAllowFileAccessFromFileURLs` | version-dependent | **16** (JELLY_BEAN) | `true` → `false` |
| `setAllowUniversalAccessFromFileURLs` | version-dependent | **16** (JELLY_BEAN) | `true` → `false` |
| `setAllowContentAccess` | **`true`** | **never — 14 through 35** | — |
| `setDomStorageEnabled` | `false` | never | — |
| `setDatabaseEnabled` | `false` | never | — |
| `setMixedContentMode` | version-dependent | **21** (LOLLIPOP) | `0` ALWAYS_ALLOW → `1` NEVER_ALLOW |
| `setSafeBrowsingEnabled` | `true` | never (getter exists from API 26) | — |
| `setJavaScriptCanOpenWindowsAutomatically` | `false` | never | — |
| `setMediaPlaybackRequiresUserGesture` | `true` | never | — |
| `setCacheMode` | `-1` LOAD_DEFAULT | never | — |
| `setBlockNetworkLoads` | `false` | never | — |
| `setLoadsImagesAutomatically` | `true` | never | — |
| `setGeolocationEnabled` | `true` | never | still gated by app permission + prompt |
| `setSavePassword` | n/a | ignored from API 18 | — |
| `setSaveFormData` | n/a | no-op from API 26 | — |

---

## 2. Severity, honestly

| Observation | Alone | Escalates with |
|---|---|---|
| `setJavaScriptEnabled(true)` | **INFO — not a finding** | nothing; it is a precondition |
| `addJavascriptInterface` present | LOW–MEDIUM | JS on → MEDIUM; attacker-controlled URL → HIGH; a method returning a secret → HIGH |
| `setAllowContentAccess` default `true` | INFO | JS on → LOW; attacker-influenced `file://` origin → MEDIUM |
| `setAllowFileAccess(true)`, targetSdk < 30 | INFO (default) | explicit at ≥ 30 → LOW; local write → MEDIUM |
| `setAllowFileAccessFromFileURLs(true)` | MEDIUM | local write → HIGH |
| `setAllowUniversalAccessFromFileURLs(true)` | **HIGH** | reachability → CRITICAL |
| `setMixedContentMode(0)` | MEDIUM | permissive cleartext policy → HIGH; strict → LOW, latent |
| `onReceivedSslError` overridden, no `proceed` | INFO | — |
| `onReceivedSslError` proceeds behind a branch | **HIGH, UNRESOLVED** | read the branch |
| `onReceivedSslError` proceeds unconditionally | **CRITICAL** | — |
| `setWebContentsDebuggingEnabled(true)` release | **HIGH** | confirm the socket, or downgrade |
| DOM storage enabled | INFO | secrets in the LevelDB → MEDIUM |
| Old WebView provider on the device | INFO | it is device posture, not an app defect |

---

## 3. Commands

### Version, always both

```bash
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell dumpsys webviewupdate | grep "Current WebView package"
adb shell "dumpsys package com.google.android.webview | grep versionName"
```

### Before any trust claim, on any rooted device

```bash
adb shell mount | grep cacerts        # APatch/Magisk here means the store is MODIFIED
```

### Remote debugging

```bash
adb shell "cat /proc/net/unix | grep -i devtools"     # grep 'devtools', NOT the package name
# real name: @webview_devtools_remote_<pid>   (@chrome_devtools_remote is Chrome's)
adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>
curl -s http://127.0.0.1:9222/json/version
curl -s http://127.0.0.1:9222/json/list
# then chrome://inspect on the host
```

### Processes

```bash
adb shell "ps -A -Z -o LABEL,USER,PID,PPID,NAME" | grep -E "sandboxed_process|webview_zygote"
# renderer: u0_iNNNNN  u:r:isolated_app:s0:...  PPID = webview_zygote
```

### Logcat

```bash
adb logcat | grep ERR_CLEARTEXT_NOT_PERMITTED    # chapter 44's config working inside the WebView
adb logcat -s chromium:V | grep -iE "ssl|cert|blocked|mixed"
```

### Deep link into a WebView

```bash
adb shell am start -a android.intent.action.VIEW -d 'scheme://host?url=http://127.0.0.1:8000/x.html'
adb reverse tcp:8000 tcp:8000
python3 -B -m http.server 8000
```

---

## 4. Static analysis

```bash
# this chapter's auditor: explicit calls + inherited defaults + bridges + SSL handlers
python3 -B scripts/webview-audit.py base.apk
python3 -B scripts/webview-audit.py base.apk --json
python3 -B scripts/webview-audit.py base.apk --fail-on HIGH
python3 -B scripts/webview-audit.py classes.dex --target-sdk 30

# ALWAYS run chapter 44's alongside it
python3 -B ../44-NetworkSecurityConfig/scripts/nsc-audit.py base.apk

# is this a stub? (facebook: 57 MB apk, one 72 KB classes.dex)
python3 -B -c "import zipfile,sys,re;z=zipfile.ZipFile(sys.argv[1]);d=[n for n in z.namelist() if re.fullmatch(r'classes\d*\.dex',n)];print(len(d),sum(z.getinfo(n).file_size for n in d))" base.apk
adb shell pm path com.example.app      # splits?
```

### The greps

```bash
apktool d base.apk -o work

grep -rn "SslErrorHandler;->proceed"                     work/smali*/   # THE grep
grep -rn "onReceivedSslError"                            work/smali*/
grep -rn -B4 "WebView;->addJavascriptInterface"          work/smali*/
grep -rl "Landroid/webkit/JavascriptInterface;"          work/smali*/
grep -rn -B3 "WebSettings;->setJavaScriptEnabled"        work/smali*/
grep -rn -B3 "WebSettings;->setAllowFileAccess"          work/smali*/
grep -rn -B3 "WebSettings;->setAllowUniversalAccessFromFileURLs" work/smali*/
grep -rn -B3 "WebSettings;->setAllowContentAccess"       work/smali*/
grep -rn -B3 "WebSettings;->setMixedContentMode"         work/smali*/
grep -rn -B3 "setWebContentsDebuggingEnabled"            work/smali*/
grep -rn "shouldOverrideUrlLoading\|shouldInterceptRequest" work/smali*/
grep -rn "Intent;->parseUri"                             work/smali*/   # page -> Intent
grep -rn -B6 "WebView;->loadUrl" work/smali*/ | grep -i "getIntent\|getData\|getQueryParameter"

unzip -l base.apk | grep -E "assets/www|cordova|capacitor|\.html$"      # hybrid app?
```

### Manifest

```bash
python3 -B ../10-APK-Internals/examples/parse_axml.py base.apk
```

| Attribute | Meaning |
|---|---|
| `exported=true` + `BROWSABLE` + `<data scheme>` | the entry point |
| `debuggable=true` | everything is worse |
| `networkSecurityConfig` | run chapter 44's auditor |
| `<meta-data android:name="android.webkit.WebView.EnableSafeBrowsing" value="false">` | protection removed app-wide |
| `allowBackup=true` | `app_webview/` extractable without root |

---

## 5. Dynamic analysis

```bash
adb shell cmd package compile -m verify -f com.example.app     # stop the JIT inlining hooks away
frida -U -f com.example.app -l scripts/trace-webview.js        # ALWAYS spawn, never attach
```

REPL exports:

| Call | Does |
|---|---|
| `settings()` | read back the **effective** value of every setting, including inherited defaults |
| `bridges()` | every bridge, its global name, and its `@JavascriptInterface` methods by reflection |
| `verdict()` | one-paragraph summary for the report |
| `forceCancel(true)` | make every `proceed()` send `cancel()` — the **control** for a certificate finding |
| `stacks(true)` | Java stack traces on bridge / SSL / load events |
| `eval("js")` | run JavaScript in the newest WebView |

### From a page or DevTools console

```javascript
for (var k in AndroidBridge) console.log(k, typeof AndroidBridge[k]);
typeof AndroidBridge.getClass          // "undefined" on API 17+ — the gate working
location.origin                        // 'file://' for ANY local file
```

---

## 6. The boundary table

| Question | Governed by | Chapter |
|---|---|---|
| May the WebView load `http://`? | network security config | **44** |
| Whose certificates does the Java stack trust? | network security config | **44**, 35 |
| Whose certificates does Chromium trust? | Chromium; test it | 43 + 44 |
| **What happens when validation FAILS?** | **`onReceivedSslError`, in code** | **43** |
| Does an OkHttp pin protect WebView traffic? | **No** | 43 + 36 |
| Do `TrustManager` hooks fire on WebView traffic? | **No** | 43 + 35 |
| What is on the end of a `content://` fetch? | the provider | 27 |
| How did the attacker's URL get here? | Intent resolution | 26, 30 |
| What is an abstract socket? | — | 24 |
| What is `isolatedProcess`? | — | 21, 28 |

---

## 7. Numbers measured on 11 real APKs from this device

| | |
|---|---|
| APKs audited | 11 |
| `onReceivedSslError` overrides found | **46** |
| ...that call `proceed()` | **3** (all behind a branch — UNRESOLVED) |
| ...that proceed **unconditionally** | **0** |
| bridge classes | 93 |
| `@JavascriptInterface` methods exposed | **863** |
| `setWebContentsDebuggingEnabled` static call sites | **20** |
| live `@webview_devtools_remote` sockets on the device | **0** |
| APKs shipping a network security config | 7 of 11 |
| `setAllowUniversalAccessFromFileURLs(true)` | 0 |
| explicit `setAllowContentAccess(false)` | 3 of 11 |
| APKs whose settings were `COMPUTED` (not literal) | 4 of 11 |

---

## 8. Measured facts that contradict common tables

| Common claim | Measured |
|---|---|
| The DevTools socket is `@<package>_devtools_remote` | **`@webview_devtools_remote_<pid>`**. `@chrome_devtools_remote` is Chrome's |
| Safe Browsing defaults on from API 26 | The **getter** arrives at 26; the default was `true` at every targetSdk from 14 |
| Any web page can read the app's providers via `content://` | Only from a **`file://` origin**. A remote page gets status 0 |
| `setAllowContentAccess` was tightened in a recent API level | **Never.** `true` from 14 to 35 |
| An Android 11 device runs an Android-11-era WebView | This one runs **Chromium 150** |
| A second navigation re-triggers `onReceivedSslError` | **No** — Chromium caches the proceed decision **per host** |

---

## 9. Remediation, as code

```java
WebSettings s = web.getSettings();
s.setJavaScriptEnabled(true);                 // keep, if the page needs it
s.setAllowFileAccess(false);                  // write it; the default only flipped at targetSdk 30
s.setAllowFileAccessFromFileURLs(false);
s.setAllowUniversalAccessFromFileURLs(false);
s.setAllowContentAccess(false);               // THE line nobody writes
s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
s.setSafeBrowsingEnabled(true);

WebView.setWebContentsDebuggingEnabled(
    (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);

// no addJavascriptInterface. If you need a bridge:
WebViewCompat.addWebMessageListener(web, "appBridge",
        new HashSet<>(Arrays.asList("https://lab.example.com")), listener);

// serve packaged assets over a virtual https origin, never file://
WebViewAssetLoader loader = new WebViewAssetLoader.Builder()
        .addPathHandler("/assets/", new WebViewAssetLoader.AssetsPathHandler(this)).build();

// do NOT override onReceivedSslError. The base implementation cancels.

// validate every URL: parse, check scheme, reject userinfo, compare host exactly
static boolean allowed(Uri u) {
    return u != null && "https".equalsIgnoreCase(u.getScheme())
        && u.getUserInfo() == null && u.getHost() != null
        && ALLOWED_HOSTS.contains(u.getHost().toLowerCase(Locale.ROOT));
}

// logout: all six
CookieManager.getInstance().removeAllCookies(null);
CookieManager.getInstance().flush();
WebStorage.getInstance().deleteAllData();
web.clearCache(true);
web.clearHistory();
web.clearFormData();
```

---

## 10. On-disk artefacts

| `/data/data/<pkg>/…` | Contents |
|---|---|
| `app_webview/Cookies` | SQLite; **separate from OkHttp's jar** |
| `app_webview/Local Storage/leveldb/` | `localStorage`, plain text |
| `app_webview/Session Storage/` | `sessionStorage` |
| `app_webview/Cache/`, `cache/WebView/` | **response bodies** — the forensic prize |
| `app_webview/Web Data` | autofill |
| `app_webview/databases/` | WebSQL |

---

## 11. `SslError` primary error codes

| Constant | Value | Meaning |
|---|---|---|
| `SSL_NOTYETVALID` | 0 | not yet valid |
| `SSL_EXPIRED` | 1 | expired |
| `SSL_IDMISMATCH` | 2 | hostname mismatch |
| `SSL_UNTRUSTED` | 3 | **untrusted CA** — what a self-signed certificate produces |
| `SSL_DATE_INVALID` | 4 | invalid date |
| `SSL_INVALID` | 5 | generic |

Only the most severe is returned by `getPrimaryError()`. Use `hasError(int)` for the rest.
