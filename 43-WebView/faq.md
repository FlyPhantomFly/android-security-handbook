# 43 — WebView — FAQ

Real questions, including the ones people feel stupid asking. Full treatment in
[README.md](README.md); the tables are in [cheatsheet.md](cheatsheet.md).

---

### 1. Is a WebView the same thing as Chrome?

Same **engine**, completely different **container**.

A WebView uses Chromium — the same Blink renderer and V8 JavaScript engine that Chrome uses. On this
test device the WebView reports `Chrome/150.0.7871.181` in its user agent, because it genuinely is
that code.

Everything around the engine is different:

| | Chrome | WebView |
|---|---|---|
| Where it runs | Its own app, its own UID | **Inside your app's process, as your app's UID** |
| Cookies | Chrome's profile | The app's own jar, in `app_webview/Cookies` |
| Address bar | Yes | No — the user cannot see the URL |
| Certificate errors | Shows an interstitial to the user | **Asks the app, and does what the app says** |
| Can the page call native code? | No | **Yes, if the app registered a bridge** |
| Extensions, sync, history | Yes | No |

The last two rows are the whole of this chapter. And note the "no address bar" row for phishing: a
user inside an app has no way to see which site they are on.

---

### 2. If it is the same engine, why does the version look wrong? My phone is Android 11 and the WebView says Chrome 150.

Because **WebView is a Mainline module** — it is packaged as an APK and updated through the Play
Store, independently of the operating system. The point is to get Chromium security fixes to devices
without waiting for an OEM to build a full system update.

Measured on the test device:

```
Android release                       11        (API 30)
WebView the phone shipped with        92.0.4515.131   (/product/app/WebViewGoogle)
WebView actually in use               150.0.7871.181  (/data/app, from Play)
```

So this is normal, not a sign of anything wrong. What it *does* mean is that "Android 11 WebViews
behave like X" is an unverifiable statement. Always record both numbers:

```bash
adb shell getprop ro.build.version.release
adb shell dumpsys webviewupdate | grep "Current WebView package"
```

---

### 3. Why does my JavaScript bridge work in one app and not in another?

Six reasons, in the order worth checking:

1. **JavaScript is not enabled.** `setJavaScriptEnabled` defaults to `false`. A bridge with no script
   engine is inert.
2. **The method is not annotated.** From API 17, only methods carrying
   `@android.webkit.JavascriptInterface` are exposed. An unannotated public method is not merely
   unreachable — `typeof AndroidBridge.thatMethod` is `"undefined"`.
3. **You are in an iframe and the app uses the modern API.** `addJavascriptInterface` injects into
   every frame; `WebViewCompat.addWebMessageListener` is scoped to an origin allow-list and is
   deliberately not there for you.
4. **The name is different.** The global name is the second argument to `addJavascriptInterface` and
   it is an arbitrary string. Enumerate rather than guess: `for (var k in window)`.
5. **The bridge is registered late.** Registration takes effect on the *next* navigation. A bridge
   added after the page loaded is not in that page.
6. **The argument type is not supported.** Only primitives and `String` cross. Passing an object
   silently gives `undefined` on the Java side, which looks like the method being broken.

The reliable way to find out which: attach `scripts/trace-webview.js` and call `bridges()`. It lists
every registered bridge, its global name, and its annotated methods, by reflection, at the moment of
registration.

---

### 4. Can a web page read my app's files?

Sometimes. It depends on the **origin of the page** and on three settings, and the answer is narrower
than most write-ups claim. Measured on WebView 150 / API 30 with everything set permissively:

| The page was loaded from | `XHR file:///data/data/<pkg>/files/secret.txt` |
|---|---|
| `http://` or `https://` — a remote page | **status 0. Blocked.** |
| `file:///…/evil.html` — a local page | **status 200. The file's contents.** |

So a remote page cannot read your files directly. A **local HTML file** can, when
`setAllowFileAccess` is on (the default below targetSdk 30) and either
`setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs` is on.

**But** a remote page can call a *bridge method* that reads the file, because bridge calls never
consult the origin. That is what the lab measures: from an `http://` origin the direct XHR failed and
`AndroidBridge.readFile("/data/data/…/session.txt")` succeeded.

---

### 5. What is `content://` and why does it matter here?

`content://` is Android's URI scheme for talking to a **ContentProvider** — the standard way apps
expose data, including their own private files
([27-ContentProviders](../27-ContentProviders/README.md)).

It matters because `WebSettings.setAllowContentAccess` **defaults to `true` at every
`targetSdkVersion` from 14 to 35** — measured, no exceptions, no plan to change. When page script
fetches a `content://` URI, the request goes through your app's `ContentResolver`, and the provider on
the other end sees **your app** asking.

Measured on the lab app: a provider declared `android:exported="false"` — correctly not exported —
handed its contents to a web page. "Not exported" protects you from other apps. It does not protect
you from your own renderer.

Same origin caveat as question 4: the direct `XHR content://…` needs a `file://`-origin page. A
bridge method that calls `ContentResolver` works from anywhere.

The fix is one line, and it is the single most valuable line in a WebView hardening review because
almost nobody writes it:

```java
webView.getSettings().setAllowContentAccess(false);
```

---

### 6. Why did my WebView stop loading `http://` URLs?

Almost certainly the **network security config**, and almost certainly because the app's
`targetSdkVersion` reached 28. From API 28 the default policy denies cleartext HTTP everywhere.

The tell is in logcat:

```bash
adb logcat | grep ERR_CLEARTEXT_NOT_PERMITTED
```

That error means the mechanism is working, not that something is broken. Chromium consults the
platform's `NetworkSecurityPolicy` through JNI before starting a cleartext request, so the policy
reaches inside the WebView — it applies to the top-level document *and* to subresources.

[44-NetworkSecurityConfig](../44-NetworkSecurityConfig/README.md) owns the file and how to scope an
exception. The lab app in `examples/vulnerable-webview/` ships a config permitting cleartext to
`127.0.0.1` only, precisely so you can delete the attribute and watch the same load fail.

---

### 7. What is a "renderer process" and why should I care?

It is a **separate operating-system process** that runs the page's HTML parsing and JavaScript. Your
app does not run the page; it asks that process to.

Measured, with the lab app rendering a page:

```
u:r:untrusted_app:s0:c61,c257    u0_a317   27084  com.pentest.ch43.vuln
u:r:isolated_app:s0:c512,c768    u0_i9093  27141  com.google.android.webview:sandboxed_process0:…
```

Different UID (99093, in the "isolated" range), different SELinux domain (`isolated_app`), and its
parent is `webview_zygote` rather than your app. It has no access to your app's files, no network of
its own, and cannot call most system services.

**Why you should care:** it means a memory-corruption bug in Blink or V8 — the classic "visit a page,
get code execution" — lands in a process that can do essentially nothing. Turning that into a real
compromise needs a *second* bug to escape the sandbox. That is expensive, and it is why remote WebView
exploitation is rare.

**Why it does not save you:** the bridge object runs in **your** process, not the renderer. When page
script calls `AndroidBridge.getSessionToken()`, a message crosses to your process and *your* code
reads the token. The sandbox is not defeated; it is used exactly as designed. No sandbox protects you
from a deputy you volunteered.

---

### 8. Is `setJavaScriptEnabled(true)` a vulnerability?

**No.** This is the most common junior mistake in WebView reporting.

Almost every WebView that shows real content needs JavaScript. Turning it off is not a fix for
anything else — it is a decision to ship a different, poorer product.

What it is, is a **precondition**. It is what turns other things into findings: a bridge, `content://`
access, universal file access, a permissive navigation gate. Report it inside the evidence line of the
finding it enables, never as the headline. `scripts/webview-audit.py` emits it as `WV-070 [INFO]` with
that reasoning printed, because the temptation to inflate it is strong.

---

### 9. I found `addJavascriptInterface`. Is that automatically critical?

No. Ask three questions, in order:

1. **What do the annotated methods do?** A method that returns a session token is a very different
   finding from one that shows a toast. Name the method in your report.
2. **Can attacker-controlled content reach this WebView?** A bridge on a page whose URL is a hardcoded
   `https://` constant is a supply-chain risk against that host. A bridge on a page whose URL comes
   from an Intent is exploitable today. Prove the path with `adb shell am start`.
3. **Is JavaScript actually on?** A bridge with script disabled is inert.

Also check whose bridge it is. Across eleven real APKs this chapter measured **863 exposed methods
across 93 classes**, and the class names are overwhelmingly third-party SDKs — chat support, captcha
widgets, ad networks, Flutter WebView plugins. Report it as "your chat SDK exposes
`handleAction(String)` to every page it renders", not as "you call `addJavascriptInterface`". The
first gets fixed.

---

### 10. The app has a perfect network security config. Can I still intercept its WebView?

Yes, if it overrides `onReceivedSslError` and calls `handler.proceed()`.

This is measured, not argued. The lab app ships a config with
`cleartextTrafficPermitted="false"`, `<certificates src="system"/>` and no debug overrides — a config
that would pass any audit. Pointed at an HTTPS server with a self-signed certificate:

```
CH43VULN: loading https://127.0.0.1:8443/evil.html
CH43VULN: SSL error ignored: primaryError=3 url=https://127.0.0.1:8443/evil.html
CH43VULN: bridge: getSessionToken()
```

The page loaded and its JavaScript ran.

The reason is simple once you see it. The config describes **whom to trust**. `onReceivedSslError` is
called at the exact moment the answer to "did anyone we trust vouch for this server?" came back
**no**. The config has already run and already said no, and the app is overruling it. There is no
element in that XML schema that says "and do not let the app override this", because the schema is
not part of that conversation.

---

### 11. Why doesn't my SSL pinning bypass work on this app?

Because the WebView is not using the code your bypass hooks.

Your bypass hooks `X509TrustManager.checkServerTrusted`, OkHttp's `CertificatePinner`, TrustKit, or
`HostnameVerifier`. Those all belong to the **Java** network stack. A WebView uses **Chromium's**
network stack, with its own certificate verifier, its own cookie jar and its own cache. None of your
hooks are on the path.

The thirty-second discriminator:

```bash
frida -U -f com.example.app -l ../35-SSL/scripts/trace-tls-validation.js
```

Load a page. **Silence** means it is Chromium's stack and you are in the right chapter. **Output**
means it is the Java stack and [35-SSL](../35-SSL/README.md) and
[36-CertificatePinning](../36-CertificatePinning/README.md) apply.

An app can be perfectly pinned in OkHttp and completely unpinned in its WebView, at the same time.

---

### 12. My proxy intercepts the app's WebView. Doesn't that prove it trusts user-installed CAs?

**Not on this device, and possibly not on yours.**

The test device's system CA store has been **modified**: an APatch `trustusercerts` module has
bind-mounted an interception CA into `/system/etc/security/cacerts`. So the proxy CA is in the
*system* store, and a successful intercept proves only that the app trusts the system store — which
every app does.

Check before making any trust claim:

```bash
adb shell mount | grep cacerts
```

If that shows APatch or Magisk, the device cannot answer user-store-versus-system-store questions at
all. That is why every certificate demonstration in this chapter uses a **self-signed certificate
from a CA that is in no store anywhere** — the result then does not depend on the device's posture.

---

### 13. What is `@webview_devtools_remote` and why is it dangerous?

It is a **unix socket in the abstract namespace**, opened when an app calls
`WebView.setWebContentsDebuggingEnabled(true)`.

"Abstract namespace" means the socket has **no filesystem path** — so it has no owner, no permission
bits and no file label. The only access control is SELinux policy between the two processes. That is
what [24-IPC](../24-IPC/README.md) means when it says abstract sockets carry no permissions.

Measured on the device, with the lab app running:

```
@webview_devtools_remote_22865
```

Note the name. It is **not** `@<package>_devtools_remote`, which is what most guides say, and it is
not `@chrome_devtools_remote`, which belongs to Chrome itself. Grep for `devtools`, not for either
specific string.

What it gives an attacker, from an ordinary `adb shell` with **no root**:

```bash
adb forward tcp:9222 localabstract:webview_devtools_remote_22865
curl -s http://127.0.0.1:9222/json/list
```

A full Chrome DevTools Protocol session: read the DOM, run arbitrary JavaScript in the page, and —
because script in the page can call the bridge — invoke every `@JavascriptInterface` method.

In a release build this is a HIGH. Gated on `ApplicationInfo.FLAG_DEBUGGABLE`, as in
`examples/hardened-webview/`, it is not a finding — and the hardened app was verified to produce no
socket at all.

---

### 14. My auditor found 20 `setWebContentsDebuggingEnabled` calls. Should I report 20 findings?

No. Measured across the same eleven APKs: **20 static call sites, and zero live sockets on the
device** — checked as root, across all 17 abstract sockets present.

Every one of those calls is guarded by a debug check. Reporting them without checking gives you 20
wrong findings, and the twenty-first thing that happens is that the programme stops reading your
reports.

The check takes five seconds:

```bash
adb shell "cat /proc/net/unix | grep -i devtools"
```

This is the best example in the chapter of the difference between a **lead** and a **finding**.

---

### 15. The auditor found nothing. Is the app secure?

Check what you actually scanned first.

`com.vendor.socialmedia` on this device produced a completely empty report. Its `base.apk` is 57 MB — and
contains **one `classes.dex` of 72 KB**. Its `versionName` on the device is literally
`stub (69.0.21)`. The real application is downloaded at runtime. `com.vendor.professionalnet` was a 334 KB
`base.apk`.

```bash
# the ten-second check
python3 -B -c "
import zipfile,sys,re
z=zipfile.ZipFile(sys.argv[1])
d=[n for n in z.namelist() if re.fullmatch(r'classes\d*\.dex',n)]
print(len(d),'dex,',sum(z.getinfo(n).file_size for n in d),'bytes of code')
" base.apk

adb shell pm path com.example.app     # are there splits you did not pull?
```

And even against a complete APK, "nothing statically visible" and "secure" are different claims. Four
of the eleven APKs returned `COMPUTED` for most settings, meaning the values are decided at runtime.
Attach `scripts/trace-webview.js` before writing the second sentence.

---

### 16. Which is worse, `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs`?

**Universal, by a long way.**

- `AllowFileAccessFromFileURLs(true)` — a `file://` page may read other **`file://`** URLs. Local file
  exfiltration.
- `AllowUniversalAccessFromFileURLs(true)` — a `file://` page may read **any origin**: other files,
  `content://` providers, and remote `https://` sites *with the app's cookies*. That is the same-origin
  policy switched off for local documents.

Both default to `false` from `targetSdkVersion` 16, so seeing either set to `true` means somebody
wrote the line deliberately. Universal is a HIGH on shape alone.

---

### 17. `location.origin` on a local page prints `file://` with nothing after it. Is that a bug?

No. Every `file://` document shares a single origin string, `file://` — there is no per-file or
per-directory origin. That is exactly why the two relaxation switches exist as separate settings, and
why local pages are treated specially by browsers in general.

It is also the reason the modern advice is to stop serving packaged content from `file://` at all.
`androidx.webkit.WebViewAssetLoader` serves your `assets/` over a **virtual `https://` origin**
(`https://appassets.androidplatform.net/` by default). The page then has a normal web origin, the
same-origin policy behaves normally, and you can set `setAllowFileAccess(false)` without losing
anything.

---

### 18. Does clearing the app's data log the user out of the WebView?

Clearing the app's data, yes — it deletes `app_webview/` along with everything else. But **calling
your app's own logout code does not**, and that is the bug that ships.

A WebView keeps its own cookie jar, entirely separate from OkHttp's or `HttpURLConnection`'s:

| `/data/data/<pkg>/…` | Contents |
|---|---|
| `app_webview/Cookies` | SQLite — the WebView's session cookies |
| `app_webview/Local Storage/leveldb/` | `localStorage`, plain text |
| `app_webview/Cache/` | **actual response bodies** — the page content the user saw |
| `app_webview/Web Data` | autofill |

A complete logout is six calls:

```java
CookieManager.getInstance().removeAllCookies(null);
CookieManager.getInstance().flush();
WebStorage.getInstance().deleteAllData();
webView.clearCache(true);
webView.clearHistory();
webView.clearFormData();
```

Apps ship one or two of them. Check all six, then go and read the files.

---

### 19. Where do I find the defaults in AOSP? I cannot find them.

You will not. `android.webkit.WebSettings` is an **abstract class** — it declares
`public abstract void setJavaScriptEnabled(boolean flag);` and nothing else. There is no `= false`
initialiser anywhere in `frameworks/base` to read.

The implementation is `org.chromium.android_webview.AwSettings`, which lives in the **WebView provider
APK** — a separately-shipped Mainline module, not in the platform tree. In AOSP,
`external/chromium-webview/` contains prebuilt APKs, not source.

Which is why §3.4 of the README is a **measurement**. `examples/webview-probe/ProbeActivity.java`
assigns to `getApplicationInfo().targetSdkVersion`, constructs a fresh `WebView`, reads every getter,
and repeats for seventeen values. One install, the whole table, on whatever provider version you
actually have.

---

### 20. Why does my Frida hook on `SslErrorHandler` do nothing?

Because `android.webkit.SslErrorHandler` is abstract and its `proceed()` and `cancel()` bodies are
**empty in the platform**. The object the framework hands your app is a concrete subclass from the
WebView provider APK — measured on this device as the obfuscated class **`WV.e53`**.

And `Java.use('WV.e53')` throws `ClassNotFoundException`, because the provider APK is loaded with its
**own ClassLoader** that the app's default loader knows nothing about. The fix:

```javascript
var H = safeUse(clsName);                                 // try the app's loader
if (H === null) {
    var loader = handler.getClass().getClassLoader();     // the PROVIDER's loader
    H = Java.ClassFactory.get(loader).use(clsName);
}
```

Two related traps in the same area, both of which produced silently wrong output in an earlier version
of `scripts/trace-webview.js`:

- **`WebSettings` is abstract too.** The concrete class is
  `com.android.webview.chromium.ContentSettingsAdapter`. Hook both and print which fired.
- **A Java wrapper is only valid for its JNI frame.** Storing a `WebSettings` object and calling a
  getter on it later fails with `Error: expected a pointer`. `Java.retain()` is mandatory.

---

### 21. I tested the certificate bypass once and now I cannot reproduce it. What happened?

**Chromium caches the proceed decision per host.**

After an app calls `handler.proceed()` for a host, subsequent navigations to that same host do not
re-invoke `onReceivedSslError` at all. Your hooks fire on nothing and the page just loads, which looks
like the hook broke.

Measured while writing this chapter: a second navigation to `https://127.0.0.1:8443/` produced no SSL
callback; changing the hostname to `https://localhost:8443/` — the same server, the same certificate —
fired it immediately.

Use a different hostname between attempts, or clear the app's data.
