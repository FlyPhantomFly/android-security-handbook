# Chapter 43 — WebView examples

Four directories and one build script. Three of the directories are Android apps; the fourth is a
page served from your host machine that attacks one of them.

> **⚠️ Authorised testing only.** `vulnerable-webview/` is deliberately insecure — it is an
> app that will hand its private files to any page it renders. Install it on a device you own,
> and uninstall it when you are finished (`./build.sh --uninstall`). Do not put it on a phone
> you use for anything else.

---

## 1. What is here

| Directory | What it is | Used by |
|---|---|---|
| `webview-probe/` | A measurement app. Prints the actual `WebSettings` defaults on **your** device at a given `targetSdkVersion`. | [§3.4](../README.md) of the chapter — every number in that table came out of this app |
| `vulnerable-webview/` | A WebView host with eleven defects, each tagged `[V1]`…`[V11]`. | [lab 01](../labs/lab-01-exploit-a-javascript-bridge.md), [lab 02](../labs/lab-02-onreceivedsslerror-defeats-a-correct-config.md), [lab 04](../labs/lab-04-ctf-the-deputy-in-the-browser.md) |
| `hardened-webview/` | The same app, same feature, every defect fixed. | Read side by side with the above |
| `attacker-page/` | `evil.html` — the page that exercises the bridge and the `file://` relaxations. Served from your **host**, reached over `adb reverse`. | labs 01 and 03 |
| `build.sh` | Builds all three APKs with SDK build-tools and a JDK. No Gradle, no Android Studio, no network. | Everything |

The repository ships **sources, never built APKs**. `.apk`, `.dex` and `.class` are on the
artefact blocklist, so `build.sh` builds out of tree — everything it produces lands under
`$OUTDIR` (default `/tmp/ch43-build`), including a throwaway signing key generated on the spot.
Nothing is written next to the sources.

```bash
./build.sh --install
```

Read the header of [`build.sh`](build.sh) before you run it. It documents two Git-Bash traps that
cost real time (`cygpath` for the native SDK binaries, `MSYS_NO_PATHCONV=1` for `adb push`), and
what the script will *not* do for you — notably, it cannot get past an OEM "Install via USB"
restriction on its own, though it detects that exact failure and retries through root.

---

## 2. The defect map

This is the table to read while you have both Activities open. The point of the pair is that the
hardened version is **not longer, cleverer, or slower**. It is the same code with different
arguments, and one method deliberately *not* overridden.

| Tag | The defect in `vulnerable-webview/` | What `hardened-webview/` does |
|---|---|---|
| **V1** | `setJavaScriptEnabled(true)` with attacker-reachable content | **Kept on.** The page needs it. Script execution is not by itself a finding — it is the amplifier for the rest of this table |
| **V2** | `addJavascriptInterface` — a Java bridge (`LeakyBridge`) exposed to page script | No bridge at all |
| **V3** | `setAllowFileAccess(true)`, re-enabled after the API 30 default flipped to `false` | Off, explicitly |
| **V4** | `setAllowFileAccessFromFileURLs(true)` | Off, explicitly |
| **V5** | `setAllowUniversalAccessFromFileURLs(true)` — a `file://` document may read **any** origin | Off, explicitly |
| **V6** | `setAllowContentAccess` left at its default (`true`) with JS on | Off, explicitly. Note what the vulnerable app does *not* contain: any call at all. The default is the defect |
| **V7** | `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` | `MIXED_CONTENT_NEVER_ALLOW` |
| **V8** | `onReceivedSslError` → `handler.proceed()` | **The method is not overridden.** See below |
| **V9** | A navigation allow-list written with `String.contains()` | Parse the URL, compare the **host**, exactly, case-folded, against a set |
| **V10** | `setWebContentsDebuggingEnabled(true)` unconditionally | Only in a debuggable build |
| **V11** | The URL comes straight from an exported `BROWSABLE` Intent | The Intent is treated as a *request*, not as the answer |

**V8 is the defect of this chapter.** Every other row can be argued about; that one cannot. It is
also the row that no amount of correct configuration elsewhere can save you from: a Network
Security Config is XML consumed by the platform's trust evaluation, and
`onReceivedSslError → proceed()` runs *after* that evaluation has already returned "reject". The
XML cannot govern the callback. [Lab 02](../labs/lab-02-onreceivedsslerror-defeats-a-correct-config.md)
is nine lines of Java defeating a config that is, on its own terms, perfect.

**V6 is the row people miss in review**, because there is nothing to find. `setAllowContentAccess`
defaults to `true`, and `NotesProvider` — which is correctly `android:exported="false"` — is still
reachable from JavaScript inside this app's own WebView, because the resolver call is made with
*this app's* identity. "Not exported" protects you from other apps. It does not protect you from
your own renderer. Providers themselves belong to
[27-ContentProviders](../../27-ContentProviders/README.md).

`LeakyBridge.java` is worth reading on its own for the API 17 boundary: from API 17 the
`@JavascriptInterface` annotation is what makes a method callable from page script, and before it
there was no annotation and **every** public method of the bridged object was exposed — including
the ones inherited from `java.lang.Object`. `getClass()` is public on every object, which is what
made the pre-17 situation catastrophic rather than merely dangerous.

---

## 3. The smallest WebView that is not a finding

The pattern referenced from [§9.1](../README.md) of the chapter. It is kept inline there because it
is short, and it is repeated here because it is the thing to compare every real app against:

```java
WebView wv = new WebView(this);
WebSettings s = wv.getSettings();

s.setJavaScriptEnabled(true);              // only if the page genuinely needs it
s.setAllowFileAccess(false);
s.setAllowFileAccessFromFileURLs(false);
s.setAllowUniversalAccessFromFileURLs(false);
s.setAllowContentAccess(false);
s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);

// No addJavascriptInterface.
// No onReceivedSslError override.
// Navigation restricted by exact host match, not by String.contains().

wv.loadUrl("https://example.com/");
```

Nine lines, and eight of them are turning something off. That asymmetry is the chapter's whole
argument: WebView's insecure states are mostly *defaults inherited from an older `targetSdkVersion`*
or *callbacks that were written when they should have been left alone*, not exotic mistakes.

---

## 4. The one thing to measure yourself

`webview-probe/` exists because `WebSettings` defaults **are not constants**. Several are chosen at
`WebView` construction time from the host app's `targetSdkVersion`, and the WebView implementation
itself updates through the Play Store independently of the OS. The table in §3.4 was measured on the
chapter's reference device; the correct move on an engagement is to run the probe on the target's
own OS and WebView version rather than to quote anyone's table, including this one.

```bash
./build.sh --install webview-probe
adb shell am start -n com.pentest.ch43.probe/.ProbeActivity
adb logcat -s CH43PROBE
```

The probe does not need to be rebuilt to sweep the range: it overwrites
`ApplicationInfo.targetSdkVersion` in memory before constructing each `WebView`, so one build
reports the whole table. Its manifest `targetSdkVersion` is therefore irrelevant to its own
results — which is exactly why the numbers can be trusted as a comparison rather than eleven
separate builds that might differ in other ways.

The two lab apps are a different matter. Both are built at `targetSdk 30` — the level at which
`setAllowFileAccess` defaults to `false`, so that the vulnerable app's explicit
`setAllowFileAccess(true)` reads as a visible *re-enable* rather than an inherited default. Change
`APPS_TARGET` in `build.sh` if you want to watch a defect stop being explicit and start being
inherited, which is what an old `targetSdkVersion` does to a real codebase.
