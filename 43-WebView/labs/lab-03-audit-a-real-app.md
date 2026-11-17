# Lab 03 — Audit a real app end to end

**Difficulty:** advanced
**Time:** 2–3 hours for the first app, 20 minutes for the fifth
**Prerequisites:** [Lab 01](lab-01-exploit-a-javascript-bridge.md) and
[Lab 02](lab-02-onreceivedsslerror-defeats-a-correct-config.md); [43-WebView §5.4, §5.8, §5.9, §7 and
§8](../README.md). Lab 02's habit of demanding a control is the one you will use most.

---

## The rule, before anything else

**This lab works against a third-party application and stops at *detection*.**

You are going to read an APK that is already on a device you own, and observe the app's own process
while *you* use it normally. Nothing here exercises, modifies, weakens or exploits software you did
not write. Concretely:

| Allowed | Not allowed |
|---|---|
| Pull and statically analyse an APK from your own device | Repackage, patch or redistribute it |
| Attach the tracer in **observation mode** and use the app yourself | Call `forceCancel()`, `eval()`, or any export that changes behaviour |
| Read `/proc/net/unix`, `dumpsys`, logcat on your own device | Point the app at a listener you control |
| Read the app's own data directory as root, on your own device | Send it a crafted deep link, or serve it an attack page |
| Write a finding that says "this exists and here is the evidence" | Write a finding that says "and I exploited it" |

That table is not bureaucracy. It is also the *methodologically* correct boundary for this stage of an
engagement: everything on the left is repeatable, deniable-proof and produces evidence a client can
verify. Everything on the right needs a signed scope document naming the application.

> **The tracer has two halves and this lab uses one.**
> [`../scripts/trace-webview.js`](../scripts/trace-webview.js) reports (`settings()`, `bridges()`,
> `verdict()`) and it mutates (`forceCancel()`, `eval()`). Lab 02 used the mutating half against an
> app you built, because a control was needed. Here you use only the reporting half. Knowing which
> tool does which — and being able to say so when asked — is part of the job.

---

## Objective

By the end you will be able to:

1. Pull a real APK correctly, splits included, and know within ten seconds whether you pulled a stub.
2. Run both auditors and read their output as *leads*, not findings.
3. Trace the running app and produce the three classes of result static analysis structurally cannot:
   inherited defaults, runtime-injected bridges, and the provider version.
4. **Reconcile** the two, producing a table with three columns of outcome: confirmed, **downgraded**,
   and discovered-at-runtime.
5. Write up the findings that survive — and, harder, correctly kill the ones that do not.

Item 5 is why this lab exists. Anyone can produce a list of static hits. The skill being trained here
is deleting most of them on evidence.

---

## Part 0 — Choose a target and record the environment

Pick an app **you installed on a device you own**, that plainly renders web content: a shopping app, a
support-chat-bearing app, a file manager with a built-in viewer. The eleven-app corpus in
[README §5.4](../README.md) is what this chapter measured, and any of them makes a good first target
because you can compare your numbers against published ones.

```bash
# host
adb shell pm list packages -3 | sort | head -40
```

Record the environment now. Every number below is qualified by these three lines:

```bash
# host
adb shell getprop ro.build.version.release      # 11
adb shell getprop ro.build.version.sdk          # 30
adb shell dumpsys webviewupdate | grep "Current WebView package"
#   (com.google.android.webview, 150.0.7871.181)
```

**WebView is a Mainline module.** The OS is Android 11; the engine is Chromium 150.0.7871.181. Record
both, separately, and never write a WebView finding that names only one — a reader cannot reproduce it
otherwise, and half the behaviours in this chapter are engine behaviours.

---

## Part A — Pull the APK, splits included

```bash
# host
PKG=com.example.target
adb shell pm path $PKG
```

Measured on this device, for one of the corpus apps:

```
package:/data/app/~~7-s4dcB89DA9j6wy7tqiTQ==/com.vendor.socialmedia-5zoC-RMU0NEYtG4o8bdLRw==/base.apk
```

**Look at how many lines that printed.** One line is a single APK. Several lines means split APKs, and
**WebView code very often lives in a feature split** — a `config.*` split, a `split_*.apk`, a dynamic
feature module. Auditing only `base.apk` when splits exist is the second most common way to produce a
falsely clean report (the first is Part B).

```bash
# host
mkdir -p "$OUTDIR/audit/$PKG" && cd "$OUTDIR/audit/$PKG"
for p in $(adb shell pm path $PKG | sed 's/^package://' | tr -d '\r'); do
    adb pull "$p" .
done
ls -la
```

> **If `adb` says "more than one device/emulator"**, you have a second device or a running emulator
> attached. Pin every command with `-s <serial>`, taken from `adb devices -l`. Doing this by accident
> — auditing an APK from an emulator and tracing a process on a phone — produces a reconciliation
> table that disagrees with itself for no discoverable reason.

---

## Part B — The stub check, before you believe anything

**Do this before you read a single line of audit output.** It takes ten seconds and it is the
difference between an audit and an embarrassment.

```bash
# host
python3 -B -c "
import zipfile,sys,re
z=zipfile.ZipFile(sys.argv[1])
d=[n for n in z.namelist() if re.fullmatch(r'classes\d*\.dex',n)]
print(len(d),'dex files,',sum(z.getinfo(n).file_size for n in d),'bytes of code')
" base.apk
adb shell dumpsys package $PKG | grep -m1 versionName
```

Measured on this device, for `com.vendor.socialmedia`, the `versionName` line alone is enough to stop
you:

```
    versionName=stub (69.0.21)
```

and the DEX check agrees: **a 57 MB APK containing one `classes.dex` of about 72 KB**, whose
`versionName` is literally the word **`stub`**. `com.vendor.professionalnet` on the same device is a 334 KB
`base.apk`.

> **What a clean report means, and does not.** `webview-audit.py` produced a completely empty
> finding list for `com.vendor.socialmedia`. That report is correct and worthless: the real application
> code is downloaded at runtime and was never in the file. **"No findings" is not "secure".** If the
> DEX total is a few tens of kilobytes for a large app, stop, and go and find where the code actually
> is — the splits, an `oat`/`vdex` on device, or a DEX written into the data directory at first run.

Write down your DEX byte total. It goes in the report's methodology section, because it is the sentence
that stops someone quoting your clean result about an app you never actually read.

---

## Part C — Static: both auditors, same APK

Run them together. [README §5.9](../README.md) puts them in the same step because a WebView finding
and a transport finding constantly get attributed to each other's layer — which is exactly what lab
02 was about.

```bash
# host — from the repository root
python3 -B 43-WebView/scripts/webview-audit.py "$OUTDIR/audit/$PKG/"*.apk
PYTHONIOENCODING=utf-8 python3 -B 44-NetworkSecurityConfig/scripts/nsc-audit.py \
    "$OUTDIR/audit/$PKG/base.apk"
```

Pass every APK you pulled to the WebView auditor at once; it accepts multiple inputs and a split is
just another DEX container.

### Reading the effective settings table

This is the part people skim and it is the part that matters. Each row carries a **source**:

| Source | Meaning | What you do with it |
|---|---|---|
| `explicit` (marked `*`) | A literal was passed at a call site | Take it at face value; note the call site |
| `default` | **Nobody wrote this line.** The value came from `targetSdkVersion` | The dangerous ones are here. `setAllowContentAccess` is `true` by default at **every** target level from 14 to 35 |
| `COMPUTED` | The argument is not a literal — a field, a build flavour, a remote config | **This is an instruction, not a result.** Go and measure it in Part D |
| `CONFLICT` | Different call sites pass different literals | Which WebView you are looking at decides the answer. Measure |
| `RUNTIME` | Most values are computed | The whole configuration must be measured |

[README §5.4](../README.md) measured four of eleven real apps returning `RUNTIME` for most settings —
`com.vendor.filemanager`, `com.vendor.homeservices`, `com.vendor.marketplace`,
`com.vendor.grocery` — and the marketplace app additionally showing `CONFLICT` on three settings. If
your target does this, **the static pass has told you to go to Part D**, and a report written without
Part D is a report full of guesses.

### The findings list is a list of leads

Note which of these you get, and resist writing any of them up yet:

| Code | Severity | What it actually is at this stage |
|---|---|---|
| `WV-001` | CRITICAL | `onReceivedSslError` proceeds with no branch. **Rare.** 0 of 46 in the corpus |
| `WV-002` | HIGH, **UNRESOLVED** | Proceeds behind a branch. 3 of 46. A human must read the method |
| `WV-010` | HIGH | `setAllowUniversalAccessFromFileURLs(true)`. **Zero apps** in the corpus |
| `WV-020` | HIGH/MEDIUM | A bridge exists. Impact is what the methods *do* |
| `WV-030` | MEDIUM | `content://` reachable from script — usually a setting nobody wrote |
| `WV-040` | HIGH | `setWebContentsDebuggingEnabled(true)`. **20 static call sites, 0 live sockets** |
| `WV-050` | INFO | Navigation is filtered in app code. Go and read the allow-list |
| `WV-060` | MEDIUM | BROWSABLE deep link plus a non-constant `loadUrl`. The standard chain |
| `WV-070` | INFO | JavaScript enabled. **Not a finding.** Context inside another finding, or nothing |

### Read the bridge class names — they tell you who to talk to

The corpus had **863 `@JavascriptInterface` methods across 93 classes**, and reading the names told
the story: `io.intercom.android.sdk.*` (support chat), `com.google.android.recaptcha.internal.*`,
`com.pichillilorenzo.flutter_inappwebview_android.*`, `com.stripe.hcaptcha.*`. **The app team did not
write these and mostly does not know they exist.**

This changes how the finding gets fixed. "Your chat SDK exposes a `handleAction(String)` bridge to
every page it renders" produces a ticket. "You use `addJavascriptInterface`" produces a shrug.

---

## Part D — Runtime: observe, do not touch

```bash
# host — the JIT can inline a hot method out from under your hook
adb shell cmd package compile -m verify -f $PKG
```

**Spawn, never attach.** A WebView is configured in `onCreate`; an attach arrives after every setting
you came to see, and the tracer will show you a near-empty configuration that you will then
misinterpret as a hardened app.

On Windows the `frida` CLI exits the moment stdin closes, so drive it through the Python API
([README §7.9](../README.md)) — and note what this script deliberately does **not** call:

```python
#!/usr/bin/env python3
# host - save OUTSIDE the repository. OBSERVATION ONLY: no forceCancel, no eval, no am start.
import frida, time, sys

PKG = sys.argv[1]
dev  = frida.get_usb_device(timeout=10)
pid  = dev.spawn([PKG])
sess = dev.attach(pid)
sc   = sess.create_script(open("43-WebView/scripts/trace-webview.js", encoding="utf-8").read())
sc.on("message", lambda m, d: print(m.get("payload") or m.get("stack"), flush=True))
sc.load()
dev.resume(pid)

# Now USE THE APP YOURSELF on the device: open the screens that render web content --
# help, support chat, terms, a promo banner, an OAuth login. 90 seconds is not enough
# for a real app; give it as long as it takes to reach the WebView screens.
time.sleep(180)

sc.exports_sync.settings()
sc.exports_sync.bridges()
sc.exports_sync.verdict()
sess.detach()
```

> **You have to drive the app by hand, and that is the point.** A WebView that is never opened is
> never configured. Most of the interesting screens in a real app are three taps deep behind a login.
> If `settings()` prints nothing, you did not reach a WebView — that is a coverage problem, not a
> finding, and it must be stated as one.

### The three things that only appear here

**1. The effective value of every setting nobody wrote.**

```
[EFFECTIVE] WebSettings #0  [com.android.webview.chromium.ContentSettingsAdapter]
    javaScriptEnabled                      true
    allowFileAccess                        true
    allowFileAccessFromFileURLs            false
    allowUniversalAccessFromFileURLs       false
    allowContentAccess                     true
    mixedContentMode                       0 (ALWAYS_ALLOW)
    safeBrowsingEnabled                    true
    userAgentString                        Mozilla/5.0 (Linux; Android 11; M2101K6P
                                           Build/RKQ1.200826.002; wv) ... Chrome/150.0.7871.181 ...
```

This is read back off the live `WebSettings` object. Every `COMPUTED` from Part C becomes a boolean
here, and so does every setting the app never touched.

**2. Bridges the APK does not contain.** On this MIUI device, tracing the chapter's own lab app —
which registers exactly **one** bridge — produced **two**:

```
[BRIDGE] addJavascriptInterface(com.pentest.ch43.vuln.LeakyBridge, "AndroidBridge")
    @JavascriptInterface methods (4): deviceInfo(0), getSessionToken(0), readContent(1), readFile(1)

[BRIDGE] addJavascriptInterface(miui.contentcatcher.sdk.WebViewDetector, "MiWebViewDetector")
    @JavascriptInterface methods (1): onCatch(1)
```

`miui.contentcatcher.sdk.WebViewDetector` is **MIUI framework code injected into the WebView of an app
that never asked for it**, exposing a global `MiWebViewDetector.onCatch(String)` to every page that app
renders. No static tool can find it, including this chapter's own.

Write it up as what it is and no more: an additional, undocumented, unremovable attack surface present
in every WebView **on this device build**. It is an OEM content feature and this repository does not
claim it is a vulnerability. Investigating what `onCatch` does would be attacking software you did not
write, which is where this lab stops. **And note the wider lesson: a finding measured on a
heavily-customised OEM build is a finding about that build. Name the device.**

**3. The provider version**, printed by the tracer alongside the OS version, from inside the process.

---

## Part E — Reconcile

This is the deliverable. Build the table yourself; it is what a client is paying for.

| Static said | Runtime showed | Outcome | Evidence |
|---|---|---|---|
| `WV-020` bridge, 12 methods | 14 methods, one class not in the APK | **Confirmed + extended** | `bridges()` output; OEM class name |
| `WV-030` `content://` reachable, source `default` | `allowContentAccess true` | **Confirmed** | `settings()` row |
| `WV-040` debugging enabled, 3 call sites | no socket in `/proc/net/unix` | **DOWNGRADED to INFO** | the `grep` below |
| `WV-002` proceeds behind a branch | never entered during 3 minutes of use | **UNRESOLVED** | say so explicitly |
| `setMixedContentMode` `COMPUTED` | `0 (ALWAYS_ALLOW)` | **Resolved to a value** | `settings()` row |
| — | `MiWebViewDetector` bridge | **New, runtime only** | `bridges()` output |

Four rules for filling it in:

1. **Where the two disagree, the device wins.** The process is the authority. The APK is a claim about
   the process.
2. **A static hit with no runtime confirmation is not automatically wrong** — it may be a coverage
   problem (you did not reach that screen). "Unresolved" and "not present" are different words and
   only one of them is honest when you did not look.
3. **Absence of a runtime observation is evidence only when you can show you looked.** Three minutes
   in the app is not a proof of absence.
4. **Never resolve `WV-002` from the outside.** Read the method. That is what the tool is telling you
   to do by marking it UNRESOLVED.

---

## Part F — The downgrades, which are the real skill

### The debugging socket

```bash
# host — grep for "devtools", NOT for the package name
adb shell "su -c 'cat /proc/net/unix'" | grep -i devtools
```

Measured on this device across the whole corpus, as root: **nothing**. Zero live sockets, against
**20 static `setWebContentsDebuggingEnabled` call sites**. Every one of those calls is guarded — by
`ApplicationInfo.FLAG_DEBUGGABLE`, by a build flavour, by a remote config.

> **This is the single best example in the chapter of why a static hit is a lead and not a finding.**
> Report those 20 without checking and 20 of your findings are wrong. One command, ten seconds.

If you *do* find a socket, then you have a real finding, and you can prove its impact without touching
the app's logic at all:

```bash
# host
adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>
curl -s http://127.0.0.1:9222/json/list
```

Listing the targets is detection. Evaluating script in the page through that socket is not, and this
lab does not do it.

> **The socket name is not what most guides say.** It is `@webview_devtools_remote_<pid>` — not
> `@<package>_devtools_remote`, and not `@chrome_devtools_remote`, which belongs to Chrome. Grep for
> `devtools` and you will find it whatever it is called on your provider version.

### The certificate overrides

Measured across the corpus: **46 `onReceivedSslError` overrides, 3 that call `proceed()`, and 0
unconditional.** Not a single `WV-001 [CRITICAL]`.

The three that proceed all branch first, and the auditor rates them `WV-002 [HIGH] UNRESOLVED`, which
is the correct output — a branch might be a hand-rolled certificate comparison (a pin, fine) or
`if (BuildConfig.DEBUG)` (not fine, and it ships). **Somebody has to read the method** — in a
decompiler, or in the smali, where [README §6.3](../README.md) shows exactly what the pattern looks
like. That is the number to quote at anyone who claims automated WebView scanning is a solved problem.

> **And note what you must *not* do here.** In lab 02 you resolved this question by running
> `forceCancel(true)` and pointing the app at your own HTTPS listener. Against a third-party app both
> halves of that are out of scope: one modifies the app's behaviour, the other requires you to control
> what it loads. Read the method statically, and if you cannot resolve it, **report it as unresolved**
> with the branch condition quoted. That is a legitimate, defensible finding.

### The severity table to hold yourself to

From [README §5.8](../README.md), the rows that produce the most bad reports:

| Observation | Severity **by itself** | What raises it |
|---|---|---|
| `setJavaScriptEnabled(true)` | **INFO. Not a finding.** | Nothing. It is a precondition |
| `addJavascriptInterface` present | LOW–MEDIUM | A method returning a secret, or attacker-reachable content → HIGH, with the method named |
| `setAllowContentAccess` default `true` | INFO | A `file://` origin the attacker can influence → MEDIUM; a provider holding something → HIGH |
| `setAllowUniversalAccessFromFileURLs(true)` | **HIGH** | Reachability → CRITICAL. Nothing lowers it |
| `onReceivedSslError` overridden, no `proceed()` | INFO | — |
| `setWebContentsDebuggingEnabled(true)` unguarded, release | HIGH | A live socket → HIGH **with proof**. No socket → **downgrade and say why** |
| WebView provider several versions behind | INFO | It is the *user's* Play Store state, not the app's defect |

That last row catches people constantly. "The device runs an old WebView and there are known Chromium
CVEs" is a finding about the **device**, not the app — the app cannot choose the provider version. It
belongs in a device-posture section. The exception is an app bundling its own engine, which is a
different animal.

---

## Part G — Write it up

Produce **three** write-ups from your target. The set matters more than any one of them.

### 1. A finding you keep

Use lab 02's shape: mechanism, evidence, environment, bounded impact, remediation. For a real app it
must additionally say **what you did not do**:

> **MEDIUM — `content://` URIs are reachable from page script.** `setAllowContentAccess` is at its
> platform default (`true`) — no call site sets it — and JavaScript is enabled. Confirmed at runtime:
> the live `WebSettings` read back `allowContentAccess true`. Script rendered in this WebView can
> issue requests to `content://` URIs, which the resolver serves as this application.
> **Scope note: reachability was not tested.** No content was injected into the WebView and no
> provider was queried; this finding is the configuration, not a demonstrated exploit. To exercise it,
> an attacker needs a page origin the app will load — see the preconditions in
> [43-WebView §3.8](../README.md).
> **Environment.** Android 11 / API 30, `M2101K6P` (MIUI), WebView `com.google.android.webview`
> 150.0.7871.181.

That "scope note" paragraph is not weakness. It is the paragraph that makes the rest of the report
trustworthy.

### 2. A finding you downgrade, in writing

> **INFO (downgraded from HIGH) — `setWebContentsDebuggingEnabled(true)` call sites present.** Static
> analysis found 3 call sites. On the device, with the app running and after exercising its WebView
> screens, `cat /proc/net/unix | grep devtools` as root returned no matching socket. The calls are
> therefore guarded at runtime. Recorded for completeness; not a finding in this build.

Write the downgrade down. A downgrade you performed silently is indistinguishable from a check you
never did, and the client cannot tell the difference either.

### 3. A finding you cannot resolve

> **HIGH, UNRESOLVED — `onReceivedSslError` may accept certificate errors.**
> `com.example.Foo$Bar.onReceivedSslError` calls `SslErrorHandler.proceed()` on one path, guarded by
> `<quote the exact branch condition>`. Whether that condition is ever true in a release build was not
> determined: resolving it requires either reading the branch's inputs — recommended, and cheap for
> the development team — or exercising the certificate path, which is outside the agreed scope for
> this application. **Recommendation: the development team should confirm the condition; if it is a
> debug flag, this is a CRITICAL finding.**

An unresolved finding, honestly labelled with the work required to resolve it, is worth more than a
confident guess in either direction.

---

## Part H — Calibrate against the published corpus

Eleven APKs from this device, from [README §5.4](../README.md). **Detection results only — no
third-party app was attacked, exercised or modified.**

| Package | targetSdk | `onReceivedSslError` | of those, `proceed()` | bridge classes | `@JavascriptInterface` methods |
|---|---|---|---|---|---|
| `com.vendor.marketplace` | 30 | 16 | 3 | 20 | 214 |
| `com.vendor.filemanager` | 30 | 17 | 0 | 27 | 211 |
| `com.vendor.grocery` | 36 | 8 | 0 | 19 | 68 |
| `com.vendor.homeservices` | 35 | 3 | 0 | 22 | **340** |
| `com.vendor.hrapp` | 36 | 0 | 0 | 4 | 8 |
| `com.vendor.streaming` | 30 | 1 | 0 | 1 | 22 |
| `com.vendor.fileexplorer` | 29 | 1 | 0 | 0 | 0 |
| `com.mobilehackinglab.FridaThree` | 34 | 0 | 0 | 0 | 0 |
| `com.mobilehackinglab.fridaone` | 34 | 0 | 0 | 0 | 0 |
| `com.vendor.professionalnet` | 29 | 0 | 0 | 0 | 0 |
| `com.vendor.socialmedia` | 30 | 0 | 0 | 0 | 0 |
| **totals** | | **46** | **3** | **93** | **863** |

Use it as a sanity check on your own numbers.

- Your app shows **zero** of everything and is a large consumer app? Check Part B — you are probably
  looking at a stub, exactly like the last two rows.
- Your app shows a **three-figure** method count? Normal. Read the class names; most of it is SDKs.
- You found a `WV-001 [CRITICAL]`? Genuinely rare — 0 in 46 here. Verify it twice before you send it.
- **`setAllowUniversalAccessFromFileURLs(true)`: zero apps in the corpus.** If you find one, it is the
  headline of your report.
- Explicit `setAllowContentAccess(false)`: three apps (the streaming app, the grocery app, the marketplace app). Everyone else
  inherits `true`. Seven of eleven ship a network security config, which is why chapter 44's auditor
  runs alongside this one.

---

## Hints

<details>
<summary>The auditor reports nothing at all and the app definitely has a WebView</summary>

In order of likelihood:

1. **You audited a stub.** Part B.
2. **You audited only `base.apk`** and the WebView code is in a split. `adb shell pm path` again and
   pass every line to the auditor.
3. **The code is loaded at runtime** — a downloaded DEX, or a cross-platform runtime (Flutter, React
   Native, Cordova) whose WebView usage lives in a plugin. Hybrid apps deserve a different pass; see
   [README §8.4](../README.md).
4. **`--dex-parser` could not resolve.** Check the note the tool prints at the top of its output.
</details>

<details>
<summary>`settings()` prints nothing, or an empty table</summary>

Either no WebView was ever created — you did not reach a web-rendering screen, which is a coverage
problem to be stated, not a finding — or you **attached instead of spawning**. A WebView is configured
in `onCreate`. Re-run with `dev.spawn()` and drive the app by hand for several minutes.
</details>

<details>
<summary>The app crashes, or detects Frida, the moment it starts</summary>

Common in banking and payments apps, and it is a finding in the *other* direction: the app has
anti-instrumentation. See [37-RootDetection](../../37-RootDetection/README.md) and
[53-Frida](../../53-Frida/README.md).

**Do not defeat it on a third-party app in this lab.** Bypassing an anti-tamper control is modifying
software you did not write, which is exactly what the rule at the top excludes. Record its presence,
finish the static half, and mark the runtime half not-performed with the reason.
</details>

<details>
<summary>adb says "more than one device/emulator"</summary>

`adb devices -l`, then pin every command with `-s <serial>`. Mixing an emulator's APK with a phone's
process produces a reconciliation table that contradicts itself for no discoverable reason, and you
will not find the cause by reading the output.
</details>

<details>
<summary>The tracer prints a settings class name I have never seen</summary>

`android.webkit.WebSettings` is **abstract**. The concrete object is
`com.android.webview.chromium.ContentSettingsAdapter`, loaded from the provider APK by a different
ClassLoader — and the name varies with provider version. The script discovers it from the live object
rather than hard-coding it ([README §7.3](../README.md)). Record what you saw next to your provider
version.
</details>

<details>
<summary>My TLS interception tooling shows nothing for this app's WebView traffic</summary>

Expected, and worth understanding rather than working around: **WebView has its own network stack**.
Java `TrustManager` hooks, OkHttp's `CertificatePinner` and objection's pinning bypass are all inert
against it ([README §7.6](../README.md)). Silence during a page load means the traffic is Chromium's —
this chapter. Output during a page load means it is the Java stack — chapters 35 and 36. That
thirty-second discriminator saves hours.
</details>

<details>
<summary>Can I put the OEM-injected bridge in my report?</summary>

Yes — as an observation, with the measurement attached, naming the device build, and with no
speculation about what the method does. "An OEM framework class is injected into every WebView on this
device build, exposing `MiWebViewDetector.onCatch(String)` to every page rendered" is a true,
verifiable sentence. Anything beyond it requires investigating vendor code, which is out of scope.
</details>

---

## Success criteria

You have completed the lab when **all** of the following are true and you have the output to prove
each one:

- [ ] You recorded OS release, API level and WebView provider version, separately.
- [ ] You pulled every APK `pm path` listed, not just `base.apk`, and you can say how many there were.
- [ ] You ran the DEX-size check **before** reading any audit output, and your report's methodology
      section quotes the byte total.
- [ ] You ran **both** auditors against the same APK set.
- [ ] You identified at least one setting whose static source was `default`, `COMPUTED` or `CONFLICT`,
      and resolved it to a concrete value at runtime.
- [ ] You traced the running app in **observation mode only** — no `forceCancel`, no `eval`, no
      crafted deep link — and can point at the lines in your driver script that prove it.
- [ ] Your reconciliation table has at least one row in each of three outcomes: **confirmed**,
      **downgraded**, and **runtime-only**.
- [ ] You ran `cat /proc/net/unix | grep devtools` and recorded the result either way.
- [ ] You wrote three write-ups: one kept, one **downgraded in writing**, one **unresolved with the
      work required to resolve it**.
- [ ] Nothing you did modified, patched, redistributed or exploited an application you did not write,
      and you could defend that statement line by line.

---

## Clean up — leave the device as you found it

```bash
# host
adb forward --remove-all
adb reverse --remove-all
adb shell am force-stop $PKG
```

The `cmd package compile -m verify -f` in Part D changed the app's compilation state. Restore it, so
the app runs at full speed again:

```bash
# host
adb shell cmd package compile -m speed-profile -f $PKG
```

The pulled APKs live under `$OUTDIR/audit/`, outside the repository. Keep them if the engagement is
live; delete them otherwise — a third-party APK sitting in a scratch directory is someone else's
copyrighted binary on your disk.

```bash
# host — from the repository root: no artefacts, nothing written into the repo
find . -name '__pycache__' -o -name '*.pyc' -o -name '*.apk' | head
```

Must print nothing. If it prints `__pycache__`, you ran a script without `-B`.

---

## What to carry into the CTF

The habit this lab trains is subtraction. You started with a list of static hits and finished with a
shorter list plus a written reason for every deletion. That is the difference between a scanner and an
analyst, and it is worth more per hour than any exploit in this chapter.

[Lab 04](lab-04-ctf-the-deputy-in-the-browser.md) reverses the pressure: five flags across the chain
from deep link to provider, against apps you built, with **one deliberate red herring** that will look
exactly like the most famous WebView vulnerability there is. The subtraction habit is what gets you
past it.
