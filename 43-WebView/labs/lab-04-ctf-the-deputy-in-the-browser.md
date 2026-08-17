# Lab 04 — CTF: The Deputy in the Browser

**Difficulty:** advanced
**Time:** 2 hours if labs 01–03 are fresh; 4 if you are reconstructing them
**Prerequisites:** [Lab 01](lab-01-exploit-a-javascript-bridge.md),
[Lab 02](lab-02-onreceivedsslerror-defeats-a-correct-config.md) and
[Lab 03](lab-03-audit-a-real-app.md); [43-WebView §3](../README.md) in full
**Artefacts:** the apps you built with [`../examples/build.sh`](../examples/build.sh) — nothing new to
download

**Everything in this CTF targets an application you built yourself.** The listeners are on your own
machine, reached through `adb reverse`. No third-party software is touched at any point.

---

## The brief

A development team has shipped `com.pentest.ch43.vuln` and their security lead has signed off on it
with this note:

> *"The WebView is fine. Our network security config is correct — HTTPS only, system anchors, no debug
> overrides — and it passes our CI gate. The `ContentProvider` holding customer notes is
> `android:exported="false"`, so nothing outside the app can reach it. We use `addJavascriptInterface`
> but we are on a modern API level, so the old `getClass()` remote code execution is closed. The
> navigation allow-list restricts the WebView to our own domain."*

**Every sentence in that paragraph is either false, or true in a way that does not mean what they
think it means.** One of them is true in a way that will cost you forty minutes if you take it as an
invitation rather than as a statement of fact.

**Your job:** capture five flags, and name the sentence that is the trap.

---

## The confused deputy, since it is the title

A **confused deputy** is a program with more authority than its caller, which can be talked into using
that authority on the caller's behalf. That is a WebView exactly:

- The page has no permissions and no UID of its own.
- The app has the INTERNET permission, a Linux UID, a private data directory, a SELinux domain, and a
  `ContentResolver` that speaks for it.
- Every bridge call, every `content://` fetch and every `file://` read the page makes is performed
  **by the app, as the app**.

The provider is not exported. It never needed to be. The deputy was already inside.

---

## Rules

1. **Reason before you run.** Predict the outcome of each flag's step before you take it, and write
   the prediction down. Where reality disagrees, you have found something worth more than the flag.
2. **Every answer names a mechanism.** "It worked" is not an answer. "The bridge is origin-agnostic
   because the injection happens per-`WebView`, not per-origin" is.
3. **Two flags are captured strings. Three are constructed** from your own measurements, in the format
   each challenge specifies. No brute force is possible or intended.
4. **You may not read `LeakyBridge.java`, `NotesProvider.java` or `VulnerableWebViewActivity.java`
   until you have all five flags.** You have read them in earlier labs; the point is to work from the
   APK and the device, as you would on a real target.
5. **Only the apps you built.** No third-party application is a valid source of any flag.

---

## Setup

```bash
# host
cd 43-WebView/examples && ./build.sh --install
adb reverse tcp:8000 tcp:8000        # attack page + collector
adb reverse tcp:8443 tcp:8443        # the HTTPS listener from lab 02
adb shell pm list packages | grep ch43
```

Record the environment. Two of the five flags are only meaningful next to these numbers:

```bash
# host
adb shell getprop ro.build.version.release      # 11
adb shell getprop ro.build.version.sdk          # 30
adb shell dumpsys webviewupdate | grep "Current WebView package"
#   (com.google.android.webview, 150.0.7871.181)
adb shell "su -c 'mount'" | grep -i "on /system/etc/security/cacerts"
#   APatch on /system/etc/security/cacerts type tmpfs ...   <-- read lab 02 Part 0 again
```

---

## Flag 1 — The deputy is handed its instructions

**The chain:** an exported `BROWSABLE` deep link reaches an Activity, the Activity puts the Intent's
`url` query parameter into `loadUrl`, and a page of your choosing is now running inside the app.

**Capture the app's session token from a page served over plain `http://` from your own machine, with
no reverse engineering of the bridge.**

Constraints that make it a challenge rather than a recipe:

- You must **discover the bridge's name and its method list from inside the page**, not from the APK
  and not from this repository's source files. If you already know the answer, prove you could have
  found it: your write-up must include the enumeration output, not the method names copied from
  memory.
- The page origin must be `http://`, not `file://`. That matters for flag 3.

Start here, and go no further into the source than the auditor's own output:

```bash
# host
python3 -B 43-WebView/scripts/webview-audit.py "$OUTDIR/vulnerable-webview/vulnerable-webview.apk"
```

**Flag 1 is a literal string** of the form `CH43{...}`, and it is the value the app considers its
session token.

**Question to answer alongside it:** the page is remote and the bridge answered anyway. State the
mechanism in one sentence — why does a `http://` origin get the same bridge as the app's own asset
page?

---

## Flag 2 — The deputy reads the file cabinet

`NotesProvider` is declared `android:exported="false"`. Confirm that yourself from the APK's manifest
before you do anything else:

```bash
# host
python3 -B 10-APK-Internals/examples/parse_axml.py \
    "$OUTDIR/vulnerable-webview/vulnerable-webview.apk" | grep -i -A4 provider
```

Then verify what "not exported" actually buys, from outside:

```bash
# host — a query from adb's own UID, which is NOT the app
adb shell content query --uri content://com.pentest.ch43.vuln.notes/note
```

That should fail with a permission denial. Good. The control works — against the thing it was designed
to stop.

**Now read the note anyway, from a web page, without calling any bridge method.**

That last clause is the challenge. There are two routes from a page to a provider and only one of them
is in scope for this flag:

| Route | In scope for flag 2? |
|---|---|
| A bridge method that calls `ContentResolver` | **No.** That is flag 1's mechanism again |
| `XMLHttpRequest` / `fetch` directly at `content://…` with no Java involved | **Yes** |

The direct route has a precondition that most write-ups get wrong. Lab 01 Part C measured it. If your
first attempt returns `status=0` with an empty body, you have not failed — you have measured the
precondition, and you are one step from flag 3.

**Flag 2 is a literal string** of the form `CH43{...}`, and it is the body of the note.

**Question to answer alongside it:** the provider is not exported and a web page read it. In one
sentence, why is that not a contradiction?

---

## Flag 3 — The matrix, constructed

Fill in this table from **your own runs**, both rows, all four cells:

| Page origin | bridge call | `XHR content://` | `XHR file://` |
|---|---|---|---|
| `http://127.0.0.1:8000/evil.html` | | | |
| `file:///…/evil.html` | | | |

For the `file://` row you need HTML the app will load locally. Model an attacker with any local-write
primitive; lab 01 step 9 shows the exact commands and the ownership fix that goes with them.

**Flag 3 is constructed:**

```
CH43{<scheme of the origin from which XHR content:// returns 200>_<the numeric status the OTHER origin got>}
```

Two fields. Lower case for the scheme, no colon, no slashes. If your two rows are identical you have
made an error — most likely the file was planted with the wrong owner and the app could not read it,
which produces a failure that looks like the wrong answer.

**Question to answer alongside it:** the app sets `setAllowFileAccess(true)`,
`setAllowFileAccessFromFileURLs(true)` **and** `setAllowUniversalAccessFromFileURLs(true)`, and
`setAllowContentAccess` is at its default `true`. All four are on, and one row of your table still
shows failures. Why? And what does that do to how you would write the finding — specifically, what
precondition must appear in it so a developer testing from a remote page does not dispute you?

---

## Flag 4 — The deputy is lied to about who it is talking to

The security lead's claim was: *"our network security config is correct — HTTPS only, system anchors,
no debug overrides — and it passes our CI gate."*

**Verify the claim, then defeat it.**

Part one — verify it, and get the exit code, because that is the part the lead is actually relying on:

```bash
# host
PYTHONIOENCODING=utf-8 python3 -B 44-NetworkSecurityConfig/scripts/nsc-audit.py \
    43-WebView/examples/vulnerable-webview/network_security_config.xml \
    --target-sdk 30 --debuggable false --fail-on HIGH > /dev/null; echo "exit=$?"
```

Part two — serve the attack page over HTTPS with a certificate **self-signed by an issuer in no store
anywhere** (lab 02 Part D; and re-read lab 02 Part 0 for why it must not be a proxy CA on this
device), point the deep link at it, and observe what the app decides.

**Flag 4 is constructed:**

```
CH43{<primaryError as an integer>_<the SslError constant with that value>_<the SslErrorHandler method the app called>}
```

Three fields. The constant in upper case exactly as `android.net.http.SslError` declares it; the
method name bare, with no parentheses and no class prefix.

**You must also produce a control.** A flag captured without one is not evidence — "the page loaded"
is equally consistent with the certificate having been acceptable. Lab 02 Part E gives you the control
and the per-host caching trap that will otherwise make you think your hook broke.

**Question to answer alongside it:** name the element of the network security config schema that would
have prevented this, or state that none exists and say why the schema has nothing to say about it.

---

## Flag 5 — The deputy leaves a door open

The app calls `WebView.setWebContentsDebuggingEnabled(true)` unconditionally, in every build. Find the
consequence **on the device**, not in the bytecode.

```bash
# host
adb shell "su -c 'cat /proc/net/unix'" | grep -i <the right string here>
```

Choosing the right string to grep for **is** the challenge. Lab 03 measured **20 static call sites and
zero live sockets** across a corpus of real apps, because every one of them was guarded — so a
grep that finds nothing is a result you must be able to distinguish from a grep that was wrong. Most
published guides give a socket name that does not exist on this platform, and a second one that
belongs to a different application entirely.

Having found it, prove it is real by listing the DevTools targets:

```bash
# host
adb forward tcp:9222 localabstract:<the socket name you found>
curl -s http://127.0.0.1:9222/json/list
```

**Flag 5 is constructed:**

```
CH43{<the socket's name, without the leading @ and without the trailing _<pid>>}
```

One field. Exactly as it appears in `/proc/net/unix`, minus the abstract-namespace `@` and minus the
process id.

**Question to answer alongside it:** abstract-namespace unix sockets have no filesystem path. State,
in one sentence, what that means for who can attach to this socket — and then say why lab 03 downgraded
this same observation to INFO on every real app it examined.

---

## The trap

**One of the five sentences in the security lead's note is a statement of fact that reads like an
invitation.** Chasing it is the single most common way to lose an afternoon in this chapter, because
the thing it points at is the most famous WebView vulnerability ever published, it is plainly visible
in any decompiler, and it has been dead since 2012.

You will know you are in it when a method you can see in the APK is `undefined` from JavaScript and
you start writing increasingly creative property accessors to reach it.

**Name it in your write-up.** State what it was, why it does not work here, what exactly closed it, and
— the part that matters — what it did *not* close. A candidate who can explain the difference is
worth more than one who found all five flags.

---

## Scoring

| | Points |
|---|---|
| Flag 1 | 10 |
| Flag 2 | 15 |
| Flag 3 | 20 |
| Flag 4 | 25, and **0 without the control** |
| Flag 5 | 10 |
| The trap, correctly named and explained | 20 |

**Full marks require the trap.** That is deliberate: it is worth as much as the hardest flag, and it
is the only item on the list that is about *not* reporting something.

---

## Hints

<details>
<summary>Hint 1 — Flag 1, discovering the bridge from the page</summary>

A Java bridge is an ordinary JavaScript object hanging off `window`. Every method the developer
annotated is one of its enumerable properties. A `for…in` loop over `window`, filtering for objects
whose properties are all functions, finds it in one line with no tooling at all.

[`../examples/attacker-page/evil.html`](../examples/attacker-page/evil.html) already does this, and
reading how it does it is in scope — it is the attacker's code, not the app's.
</details>

<details>
<summary>Hint 2 — Flag 2, the direct route returns status 0</summary>

That is the correct result *from the origin you are currently on*, and it is the measurement flag 3
asks you to record. The relaxation you need is not a bridge and not a permission; it is a property of
the **document**, not of the request. Read [README §3.8 and §3.9](../README.md), then look at which of
the app's four file-related settings only take effect for a particular kind of origin.
</details>

<details>
<summary>Hint 3 — Flag 3, my two rows are identical</summary>

Almost always the plant, not the measurement. After copying the HTML into the app's data directory as
root, the file is owned by `root`, and the app's UID cannot read it — so the load fails and you
attribute the failure to the origin rules.

```bash
# host
OWNER=$(adb shell "su -c 'stat -c %u:%g /data/data/com.pentest.ch43.vuln/files'" | tr -d '\r')
adb shell "su -c 'chown $OWNER /data/data/com.pentest.ch43.vuln/files/evil.html'"
adb shell "su -c 'chmod 644 /data/data/com.pentest.ch43.vuln/files/evil.html'"
```

Also force-stop between runs. `am start` on a live Activity delivers a new Intent to a new instance
and the behaviour looks stale.
</details>

<details>
<summary>Hint 4 — Flag 4, the second run produces no SSL callback at all</summary>

Chromium **caches the proceed decision per host**. Once the app has proceeded for `127.0.0.1`,
later navigations to `127.0.0.1` never re-enter the callback. Change the hostname — `localhost` is
already in your certificate's SAN if you followed lab 02 — or `adb shell pm clear` between attempts.

This trap has convinced more than one person that their Frida hook broke. It did not.
</details>

<details>
<summary>Hint 5 — Flag 5, my grep finds nothing</summary>

You are almost certainly grepping for the package name. The socket is **not** named after the package.
It is also not the name Chrome uses. Grep for the word `devtools` and read what comes back — the
answer is in [README §3.13](../README.md), which measured this precisely because the commonly
published name is wrong.

If a `devtools` grep genuinely returns nothing, check the app is actually running and that a WebView
has been created: force-stop, re-launch with the deep link, and grep again.
</details>

<details>
<summary>Hint 6 — the trap</summary>

Which sentence in the brief is a *defence* the lead is claiming, rather than a *feature* they are
describing? Two are defences. One of those two is genuinely, completely effective — against precisely
one attack, which is not any of the five in this CTF.

The version number that matters is not 30.
</details>

---

## Answer key

**Do not open this until you have five flags and a name for the trap.**

<details>
<summary>Full answers, the flags, and the trap</summary>

### Flag 1

```
CH43{bridge_is_the_bug_not_the_annotation}
```

Captured by driving `ch43vuln://open?url=http://127.0.0.1:8000/evil.html` and reading the collector's
`token` row.

**Mechanism.** `addJavascriptInterface` injects the object into the WebView's JavaScript context, and
that injection is a property of the **WebView instance**, not of the document's origin. The bridge is
re-injected into every document the WebView loads. There is no origin check anywhere in the path,
because the API has no parameter for one. **A bridge is origin-agnostic**, which is why it is the
widest path into a hybrid app and why it, not the settings, is the headline of almost every real
WebView finding.

The auditor reports the chain as `WV-060` (BROWSABLE plus a non-constant `loadUrl`) and the bridge as
`WV-020`. Neither is the finding on its own; the intersection is.

### Flag 2

```
CH43{content_scheme_resolves_as_the_host_app}
```

Captured by a direct `XMLHttpRequest` to `content://com.pentest.ch43.vuln.notes/note` from a page
loaded from `file:///data/data/com.pentest.ch43.vuln/files/evil.html`, with no bridge method called.

**Mechanism, and why it is not a contradiction.** `android:exported="false"` is enforced by
`ActivityManagerService` on the *calling UID*. The call here is made by Chromium's network stack
inside the host app's own process, so the calling UID **is** the provider's own UID, and the check
passes trivially. `setAllowContentAccess` — measured `true` by default at every `targetSdkVersion`
from 14 to 35 — is what permits script to originate such a request at all.

> "Not exported" protects you from other apps. It does not protect you from your own renderer.

Note also that `adb shell content query` failed, and that failure is *correct*: adb runs as `shell`,
a different UID, and the export flag did its job. The two results together are the whole lesson.

### Flag 3

```
CH43{file_0}
```

The matrix:

| Page origin | bridge call | `XHR content://` | `XHR file://` |
|---|---|---|---|
| `http://127.0.0.1:8000` | **works** | blocked, status 0 | blocked, status 0 |
| `file:///…/evil.html` | **works** | **200, data returned** | **200, data returned** |

**Why the settings being "all on" is not enough.** `setAllowFileAccessFromFileURLs`,
`setAllowUniversalAccessFromFileURLs` and `setAllowContentAccess` are relaxations of the same-origin
policy **for documents whose origin is `file://`**. A document served over `http://` is not such a
document, and none of the three applies to it — the request is refused by the origin rules before any
setting is consulted. Only the bridge, which has no origin concept at all, crosses.

**What must appear in the finding.** The precondition: *the attacker must be able to get HTML into a
location the app will load from `file://`*. Omit it and a developer will test from a remote page, see
`status=0`, and close your ticket as unreproducible — and they will be right about the test they ran.

A third fact worth carrying: `location.origin` for any local file is the bare string `file://`. Every
local file shares one origin, which is why these relaxations exist as separate switches and why the
modern advice is to stop using `file://` entirely in favour of `WebViewAssetLoader`.

### Flag 4

```
CH43{3_SSL_UNTRUSTED_proceed}
```

`nsc-audit.py --fail-on HIGH` exits **0**: the config passes, and the security lead's sentence about
it is entirely true. Then, over `https://127.0.0.1:8443/` with a certificate whose subject and issuer
are both `CN=ch43-lab-impostor`:

```
CH43VULN: SSL error ignored: primaryError=3 url=https://127.0.0.1:8443/evil.html
[SSL]   --> app called handler.proceed()   THE LOAD CONTINUES, certificate error and all
```

**The control** (required for the points): the same navigation under
[`../scripts/trace-webview.js`](../scripts/trace-webview.js) with `forceCancel(true)`, against a
different hostname to dodge the per-host proceed cache:

```
[SSL]   --> app called handler.proceed(), forceCancel is ON so cancel() is being sent instead
[SSL]   --> app called handler.cancel()    the load is refused
```

One variable changed; the outcome inverted. That pair is what makes it evidence.

**Which element of the schema would have prevented it: none, and none can exist.**
`<trust-anchors>` names whose certificates are acceptable. `<pin-set>` narrows that further.
`cleartextTrafficPermitted` governs whether a plaintext request may be made at all.
`onReceivedSslError` is invoked at the moment the answer to "did anyone acceptable vouch for this
server?" came back **no** — the config has already run and already said no, and the app is overruling
it in Java. The schema is not in that conversation.

The correct remediation is to **delete the override**; `WebViewClient`'s base implementation calls
`cancel()`.

### Flag 5

```
CH43{webview_devtools_remote}
```

The socket is `@webview_devtools_remote_<pid>`. It is **not** `@<package>_devtools_remote`, which is
what most guides say and which does not exist, and **not** `@chrome_devtools_remote`, which belongs to
Chrome. Grep for `devtools`.

**What the abstract namespace means.** An abstract-namespace unix socket has no filesystem path, and
therefore **no filesystem permissions** — no owner, no mode, no SELinux file label to constrain it.
Any local process that can reach the abstract namespace can attach a full DevTools session: read the
DOM, evaluate script in the page, and through that call every bridge method the app exposes. On this
app that includes `getSessionToken()`.

**Why lab 03 downgraded it on every real app.** Because a static call site is a lead, not a finding.
Measured: **20 `setWebContentsDebuggingEnabled` call sites across eleven real APKs, and zero live
sockets** on the device, checked as root across all 17 abstract sockets present. Every one of those
calls is guarded. Report them without checking and twenty of your findings are wrong. Here, in an app
built to be wrong, the call is unguarded and the socket is real — which is why the flag exists and why
the check is one command.

### The trap

> *"We use `addJavascriptInterface` but we are on a modern API level, so the old `getClass()` remote
> code execution is closed."*

**That sentence is completely true, and it is not a defence of anything you are testing.**

The attack it refers to: before **API 17**, every `public` method of a bridged object was exposed to
JavaScript, including the ones inherited from `java.lang.Object`. `getClass()` is public on every Java
object, so page script could walk
`AndroidBridge.getClass().getClassLoader().loadClass("java.lang.Runtime")` and reach
`Runtime.getRuntime().exec(...)` — arbitrary command execution from one line of JavaScript. It is the
most published WebView vulnerability there has ever been.

From API 17, only methods carrying `@android.webkit.JavascriptInterface` are exposed. Prove it rather
than believing it:

```
typeof AndroidBridge            = object
typeof AndroidBridge.deviceInfo = function
typeof AndroidBridge.notExposed = undefined
typeof AndroidBridge.getClass   = undefined
```

`notExposed()` is a **public** method of the bridge class, plainly visible in any decompiler, and it is
absent from the JavaScript object entirely — not refused, absent. So is `getClass()`. There is no
accessor you can write that reaches either. Every minute spent on it is a minute lost.

**What the annotation closed, and what it did not.** It closed one specific catastrophic path. It
closed nothing else. The four annotated methods are exactly the methods the developer intended to
expose, and they hand a web page the app's session token, the contents of any file the app's UID can
read, and a `ContentResolver`. Flags 1 and 2 were both captured through methods that were *supposed*
to be there.

> **The risk is the bridge, not the annotation.**

**A second, lesser decoy**, worth noticing but not the trap: the lead's claim that *"the navigation
allow-list restricts the WebView to our own domain"*. `shouldOverrideUrlLoading` does contain an
allow-list, written with `String.contains("lab.example.com")` — the classic bypassable pattern
(`https://lab.example.com.attacker.invalid/`, `https://attacker.invalid/?x=lab.example.com`, a
userinfo prefix). But read both `return` statements: the method returns `false` on **every** path.
There is nothing to bypass, because nothing is being blocked. Report it as a latent defect — the day
someone "fixes" the method by making the deny path return `true`, the substring match becomes the only
control — and do not claim you bypassed a gate that was never closed.

### The five flags together

```
CH43{bridge_is_the_bug_not_the_annotation}
CH43{content_scheme_resolves_as_the_host_app}
CH43{file_0}
CH43{3_SSL_UNTRUSTED_proceed}
CH43{webview_devtools_remote}
```

</details>

---

## Success criteria

- [ ] Five flags, captured or constructed, without opening the answer key.
- [ ] You named the trap, said what closed it, and said what it did **not** close.
- [ ] You enumerated the bridge from inside the page and have the output to show for it.
- [ ] Flag 4 is accompanied by a control, and you can explain why a flag without one is not evidence.
- [ ] You can state, in one sentence each: why a remote page reached the bridge; why an unexported
      provider answered a web page; why three "all on" settings still produced a blocked request.
- [ ] You recorded OS release, API level and WebView provider version — separately — and checked the
      device's CA store posture before making any claim about trust.
- [ ] You ran the `devtools` grep and understand why the same observation is a finding here and an
      INFO on every real app in lab 03's corpus.

---

## Clean up — leave the device as you found it

```bash
# host
adb shell "su -c 'rm -f /data/data/com.pentest.ch43.vuln/files/evil.html'"
adb shell am force-stop com.pentest.ch43.vuln
adb reverse --remove-all
adb forward --remove-all
rm -f "$OUTDIR/ch43-tls/key.pem" "$OUTDIR/ch43-tls/cert.pem"

cd 43-WebView/examples && ./build.sh --uninstall
adb shell pm list packages | grep ch43        # must be empty
```

```bash
# host — from the repository root: no artefacts, nothing written into the repo
find . -name '__pycache__' -o -name '*.pyc' -o -name '*.apk' | head
```

Must print nothing. If it prints `__pycache__`, you ran a script without `-B`.

---

## Where to go next

- [README §5.8](../README.md) — honest severity. Re-read it now that you have five flags and know how
  little most of them would be worth without their preconditions attached.
- [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) — flag 4's other half, and its
  own CTF, where the *configuration* is what lies rather than the code.
- [36-CertificatePinning](../../36-CertificatePinning/README.md) — what pinning that is genuinely live
  looks like, and why none of your WebView tooling touches it.
- [27-ContentProviders](../../27-ContentProviders/README.md) — flag 2's far end. The provider you read
  was a stub with one row; a real one is a database.
- [26-Intent](../../26-Intent/README.md) and [30-Activities](../../30-Activities/README.md) — flag 1's
  near end. The deep link is where a WebView finding usually begins, and it is not this chapter's.
