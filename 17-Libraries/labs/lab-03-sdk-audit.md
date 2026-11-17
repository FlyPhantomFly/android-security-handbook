# Lab 03 — SDK Data-Collection Audit

**Difficulty:** Intermediate
**Time:** 4–6 hours
**Prerequisites:** [Lab 01](lab-01-library-inventory.md),
[Chapter 17 §3.5](../README.md#3-deep-internal-working) (SDK categories and the seven questions),
[§7](../README.md#7-dynamic-analysis) (attribution and payload capture),
[53-Frida](../../53-Frida/README.md), an intercepting proxy, and a device you control.

---

## Objective

Take an application, attribute **every outbound request** to the SDK that made it, decode the
payloads — including the compressed, encoded and binary ones — and produce the **data-collection
table**: one row per destination, saying who sends it, what is in it, how often, and whether the user
agreed to it.

The client's claim is almost always "we send anonymous analytics". Your job is to turn that sentence
into a table of facts, in either direction. Disproving it is a finding. Confirming it, with evidence,
is worth just as much to a client who has to sign a privacy statement.

---

## Why this matters

Chapter §3.5 states the structural fact that makes this necessary:

> An SDK runs inside the app's process, with the app's UID, holding the app's permissions, able to
> read the app's private files, able to see the app's network traffic, able to read the app's memory,
> and able to make network requests to its own servers. There is no sandbox between the app and the
> SDK. None.

So there is no technical control to review. There is no configuration to audit. The only way to know
what an SDK sends is to **watch it send**.

Three things make this the most valuable page in many mobile reports:

- **Nobody has looked.** The developer integrated the SDK by adding one Gradle line and reading a
  quickstart. They have never seen a payload.
- **The interesting leaks are in parameters, not endpoints.** `logEvent("search", ...)` is fine.
  `logEvent("search", {query: "…", user_email: "…"})` is a finding, and both produce the same host in
  a proxy log.
- **It maps directly onto obligations the client already has.** A data-collection table is the input
  to a privacy notice, a DPIA, and an app-store data-safety declaration. It converts a security
  finding into something a legal team acts on within a week.

---

## Setup

> **Warning**
> Only run this against an application you have written permission to test. Intercepting and
> decoding traffic from a third-party app you do not own is not a grey area.

### The target

Best option: build a small app with four SDKs of different categories — an analytics SDK, a crash
reporter, an attribution or ads SDK, and one you write yourself that behaves badly on purpose. You
control the ground truth, and the SDK you write yourself lets you plant exactly the leak you want to
learn to catch.

Second option: an application whose owner has engaged you.

### Interception

```bash
# host
mitmproxy --mode regular --listen-port 8080
# or Burp Suite; the technique is identical

# adb shell — point the device at it
adb shell settings put global http_proxy 10.0.2.2:8080
```

Install the proxy's CA. On a modern device this is not enough on its own, and the reasons are worth
knowing before you spend an hour confused:

| Obstacle | Symptom | What to do |
|---|---|---|
| App targets API 24+ | Only *system* CAs are trusted; your user CA is ignored | Add a debug `network_security_config` if it is your build; otherwise use a system CA store on a rooted device or Magisk module |
| Android 14+ | The system CA store moved under APEX/Conscrypt control | The old `/system/etc/security/cacerts` remount trick no longer applies; see [62-Magisk](../../62-Magisk/README.md) for current approaches |
| Certificate pinning | TLS handshake fails for *some* hosts only | Unpin at runtime. Note **which** hosts pin — that itself belongs in your table, because a pinning SDK is one you cannot audit passively |
| Native TLS | Traffic never appears in the proxy at all, but the app still works | The SDK is not using the Java stack. See step 5 |

**Q0.** Before you capture anything: which of the four obstacles above applies to your target? You
will misread an empty proxy log as "no traffic" at least once in your career. Do it here instead.

---

## Steps

### Step 1 — Predict, before you capture

From lab 01's inventory alone, write down what you *expect* to see. Doing this first is what turns
the capture from browsing into an experiment.

```bash
# host — the self-starting SDKs, from the manifest
apktool d -f app.apk -o work >/dev/null
grep -oE '<provider[^>]*android:name="[^"]*"' work/AndroidManifest.xml | sort -u
grep -oE 'android:authorities="[^"]*"' work/AndroidManifest.xml | sort -u

# host — every hostname the app carries as a literal
python3 ../../04-Java/scripts/dump-strings.py app.apk --min-len 8 \
  | grep -aoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' \
  | sed -E 's#(https?://[^/]+).*#\1#' | sort | uniq -c | sort -rn
```

**Q1.** List the SDKs you expect, and for each the host you expect it to contact. Keep this list.
Every host that appears in the capture and is *not* on it is a question you must answer.

**Q2.** Which hosts in the string dump are not attributable to anything in your inventory?
Those get priority.

### Step 2 — Capture with attribution

A proxy log tells you *what host*. It does not tell you *which code*. For that you need a stack trace
at the moment the request is made. Chapter §7.3 gives the OkHttp and `URLConnection` hooks; start
from those, then extend downward:

```javascript
// frida -U -f com.example.target -l attribute-deep.js --no-pause
// Attribution at three layers, because SDKs do not all use the same one.
// Chapter 17 section 7.3 covers the OkHttp and URLConnection layers; this
// adds the two below them, which is where the SDKs you did not expect live.
Java.perform(function () {
  const Log = Java.use("android.util.Log");
  const Exception = Java.use("java.lang.Exception");
  const stack = () => Log.getStackTraceString(Exception.$new());

  // Layer 3: the socket itself. Catches every Java-level HTTP client,
  // including ones you have never heard of, at the cost of noise.
  try {
    const Socket = Java.use("java.net.Socket");
    Socket.connect.overload("java.net.SocketAddress", "int")
      .implementation = function (addr, timeout) {
        console.log("\n[socket] " + addr.toString());
        console.log(stack());
        return this.connect(addr, timeout);
      };
  } catch (e) { console.log("[-] java.net.Socket hook failed: " + e); }

  // Layer 4: DNS. An SDK that resolves a name has decided to talk to it,
  // even if the request later fails or is batched for hours.
  try {
    const InetAddress = Java.use("java.net.InetAddress");
    InetAddress.getAllByName.implementation = function (host) {
      console.log("\n[dns] " + host);
      console.log(stack());
      return this.getAllByName(host);
    };
  } catch (e) {}
});
```

**Q3.** For each captured request, read the stack trace and name the SDK. Which package appears
immediately below the HTTP client in the frames? That is your attribution.

**Q4.** Some stack traces will be entirely obfuscated (`a.b.c.d`). You still have to attribute them.
Name three ways to do it without deobfuscating anything.

### Step 3 — Read the payloads, not the endpoints

Bodies are where the findings are, and bodies are frequently not plain JSON.

| Encoding you will meet | How you know | How to read it |
|---|---|---|
| gzip | `Content-Encoding: gzip`, or a body starting `1f 8b` | The proxy usually does it. If not, hook `GZIPOutputStream.write` and catch the plaintext *before* compression — chapter §9.4 has that hook |
| Base64 inside a form field | A long `A–Za–z0–9+/=` run | Decode it; then check whether what comes out is *itself* compressed |
| Protocol Buffers | `Content-Type: application/x-protobuf`, or a body that is binary with no framing | Walk the wire format; the field numbers are enough to see the shape. Script below |
| Custom framing or encryption | Nothing decodes, entropy is high | Stop attacking the wire. Hook the SDK's **serialisation call** instead — one layer above the encryption, where the data is still structured |

The last row is the one that matters. Chapter §9.4's method is right: hook at the API boundary,
before the SDK batches, compresses or encrypts. You do not need to break anything.

A protobuf body with no `.proto` file is still readable — the wire format is self-describing enough
to show you the shape:

```python
#!/usr/bin/env python3
# host — walk an unknown protobuf body far enough to see what is in it.
# Standard library only. Field NAMES are not on the wire; field numbers,
# types and values are, and that is enough to spot an email address or a
# device identifier.
import sys

WIRE = {0: "varint", 1: "64-bit", 2: "bytes", 5: "32-bit"}

def uvarint(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, i
        s += 7

def walk(b, depth=0):
    i, pad = 0, "  " * depth
    while i < len(b):
        try:
            key, i = uvarint(b, i)
        except IndexError:
            return
        field, wt = key >> 3, key & 7
        if wt == 0:
            v, i = uvarint(b, i)
            print(f"{pad}{field} varint = {v}")
        elif wt == 2:
            n, i = uvarint(b, i)
            chunk, i = b[i:i + n], i + n
            try:
                s = chunk.decode("utf-8")
                if s.isprintable():
                    print(f"{pad}{field} string = {s!r}")
                    continue
            except UnicodeDecodeError:
                pass
            print(f"{pad}{field} bytes[{n}] -- descending")
            walk(chunk, depth + 1)     # nested message, or just binary
        elif wt == 5:
            i += 4; print(f"{pad}{field} 32-bit")
        elif wt == 1:
            i += 8; print(f"{pad}{field} 64-bit")
        else:
            print(f"{pad}unknown wire type {wt}, stopping"); return

walk(open(sys.argv[1], "rb").read())
```

**Q5.** For each SDK, list every field in its payload. Not the interesting ones — *every* one. The
findings are usually in the field you nearly skipped.

**Q6.** Which fields are stable across app restarts, and which change? A stable identifier that
survives restart and reinstall is a very different privacy fact from a per-session one.

### Step 4 — Identifiers, and the join

This is the question that decides whether "anonymous" is true.

```javascript
// frida -U -f com.example.target -l identifiers.js --no-pause
// Every place an SDK is handed something that identifies the human being.
Java.perform(function () {
  const Log = Java.use("android.util.Log");
  const Exception = Java.use("java.lang.Exception");
  const stack = () => Log.getStackTraceString(Exception.$new());

  function watch(clazz, method) {
    try {
      const C = Java.use(clazz);
      C[method].overloads.forEach(function (ov) {
        ov.implementation = function () {
          const args = Array.prototype.slice.call(arguments).join(", ");
          console.log("\n[id] " + clazz + "." + method + "(" + args + ")");
          console.log(stack());
          return ov.apply(this, arguments);
        };
      });
    } catch (e) {}
  }

  // Identifiers being SET on an SDK -- the join key to the client's own records
  watch("com.google.firebase.analytics.FirebaseAnalytics", "setUserId");
  watch("com.google.firebase.crashlytics.FirebaseCrashlytics", "setUserId");

  // Identifiers being READ from the platform
  watch("android.provider.Settings$Secure", "getString");
  watch("android.telephony.TelephonyManager", "getDeviceId");
  watch("android.telephony.TelephonyManager", "getSubscriberId");
  watch("android.accounts.AccountManager", "getAccounts");
});
```

**Q7.** Does any SDK receive an identifier that also exists in the client's own systems — an account
ID, an email, an order number? If yes, the data at that vendor is joinable to the client's customer
records, and "anonymous" is not the right word for it.

**Q8.** Which SDK reads `Settings.Secure.ANDROID_ID`, and what is it used for? Is the same value sent
to more than one vendor? (Cross-vendor correlation is a finding even when each vendor individually
looks harmless.)

### Step 5 — The traffic your proxy cannot see

An SDK with native code can do HTTP without touching the Java stack at all. If lab 01 found
`curl_easy_setopt` or `SSL_write` exported from a `.so`, this applies to you.

```javascript
// frida -U -f com.example.target -l native-tls.js --no-pause
// Read plaintext at the TLS write boundary, above the socket and below any
// pinning. Works for a statically linked OpenSSL/BoringSSL in an app's .so
// as long as the symbol is exported -- which lab 01 already told you.
["libcore.so", null].forEach(function (mod) {
  const addr = Module.findExportByName(mod, "SSL_write");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      const len = args[2].toInt32();
      if (len > 0 && len < 8192) {
        console.log("\n[SSL_write " + len + " bytes]");
        console.log(hexdump(args[1], { length: Math.min(len, 512) }));
      }
    }
  });
});
```

**Q9.** Did any traffic appear here that never appeared in the proxy? What does its existence mean
for the completeness of everything else in this lab?

**Q10.** If the symbol is stripped and `SSL_write` is not exported, what is your next move? (Chapter
§7.4 shows the pattern; you are looking for the function by something other than its name.)

### Step 6 — Frequency, triggers, and consent

A capture without a timeline is half an answer.

**Q11.** For each SDK: what triggers a send? App start, every screen, a timer, a batch threshold?
Drive the app through the same workflow three times and see what is constant.

**Q12.** **Does anything leave the device before the user has agreed to anything?** Kill the app, wipe
its data, start the capture, launch it, and do not touch the consent dialog. Anything that transmits
in that window was sent without consent, and initialisation `ContentProvider`s are exactly the
mechanism that makes it happen — they run before `Application.onCreate()`, which is before your
consent code exists.

This single test produces a reportable finding more often than any other step in this lab.

**Q13.** Now decline consent, and repeat. Does the traffic stop?

### Step 7 — The table

| Host | SDK | Category | Data observed | Identifiers | Frequency | Before consent? | Consent respected? | Notes |
|---|---|---|---|---|---|---|---|---|
| | | | | | | | | |

Rules:

- One row per **host**, not per SDK. An SDK with three endpoints has three rows, because they may
  carry very different data.
- **Data observed** lists field names and value *types*, with values redacted or truncated. You are
  writing a document that may itself contain personal data; do not create a new problem.
- A cell you did not test is **"not tested"**, never blank. Blank reads as "nothing".
- Add a row for every host you predicted in step 1 and never saw. Absence is data too — it may mean
  the SDK is dormant, or that you did not exercise the workflow that wakes it.

---

## Hints

<details>
<summary>Hint — Q4, attributing an obfuscated stack trace</summary>

1. **The frames above and below are not obfuscated.** Platform and library classes keep their names.
   A frame sequence of `okhttp3.RealCall` under `a.b.c` under `androidx.work.Worker` tells you the
   call came from a background job, and the job's tag is usually readable.
2. **The endpoint attributes itself.** The hostname, the URL path shape, and the `User-Agent` name
   the vendor, and none of them can be obfuscated because the server has to understand them.
3. **Thread names.** `/proc/<pid>/task/*/comm`, or Frida's `Thread` APIs. SDKs name their threads
   after themselves and R8 does not touch string literals used as thread names.
4. **What it touches.** A class that reads `Settings.Secure.ANDROID_ID` and writes a
   `SharedPreferences` file called `vendor_prefs.xml` has told you who it is; the prefs file name is
   a string constant and is rarely obfuscated because it is a persistent key.
</details>

<details>
<summary>Hint — Q10, finding a stripped SSL_write</summary>

Three routes, cheapest first:

1. **The dependency graph.** If the `.so` has `NEEDED libssl.so`, it uses the platform's, and the
   platform's export is not stripped. Hook it there.
2. **A constant or a string.** Statically linked TLS carries distinctive `.rodata` — error strings,
   cipher suite names, the OpenSSL banner. Find one, then find the code that references it, and walk
   outward. Chapter §7.4 shows the `Memory.scan` pattern.
3. **The layer below.** `send`, `sendto` and `write` in libc are always exported, always hookable,
   and always carry the *ciphertext*. That is a worse view but a guaranteed one, and it at least
   proves the traffic exists so that you can say so honestly.

And the professional option: if the answer matters and the cost is climbing, say in the report that
this SDK's native traffic could not be inspected within the engagement, and why. That is a finding
about auditability, not a failure.
</details>

<details>
<summary>Hint — Q12, the pre-consent window</summary>

The mechanism is chapter §3.5's initialisation `ContentProvider`. `ContentProvider.onCreate()` runs
before `Application.onCreate()`, which means before any consent logic the app's developers wrote can
possibly have executed.

So the developer's belief — "we only initialise analytics after consent" — can be sincere and still
be false, because the SDK initialised itself out of the merged manifest and the developer never wrote
the line that would have controlled it.

That is why this test is so productive. You are not catching anybody lying. You are catching a
mechanism nobody in the room knew about, and the fix (`tools:node="remove"` on the provider, or the
SDK's documented deferred-initialisation mode) is something the developer can apply the same day.
</details>

---

## Solution notes

<details>
<summary>What a good finding looks like, and what a bad one looks like</summary>

**Bad:** "The application shares data with third parties."

True of every app ever written. Nothing to act on.

**Good:**

> The crash-reporting SDK receives the authenticated user's account identifier via `setUserId`, and
> receives HTTP response bodies as breadcrumb logs via `FirebaseCrashlytics.log`. One captured
> breadcrumb contained a bearer token in full (`/v2/session` response, redacted in appendix C). The
> vendor therefore holds a credential capable of authenticating as the user, in a system outside the
> scope of your access controls and retained under the vendor's policy, not yours.
>
> Reproduction: attach with `frida -U -f <pkg> -l analytics-audit.js`, sign in, trigger the network
> error path on the payment screen. Observed at 14:02, 14:07 and 14:19 in three separate sessions.

Specific, reproducible, and it names the consequence rather than the mechanism.
</details>

<details>
<summary>Q6 — stable versus per-session, and why it decides the severity</summary>

An identifier that is regenerated per session supports counting and little else. One that survives
app restart supports a profile. One that survives *reinstall* — a hardware ID, or a value stashed in
backup-eligible storage — supports linking a person across their whole history with the app, and is
close to unremovable from the user's side.

Test it in this order, because each step costs more than the last:

1. Force-stop and relaunch. Does the value change?
2. Clear app data. Does it change?
3. Uninstall and reinstall. Does it change?

Report the answer as one of those three levels rather than as "an identifier". The remediation is
completely different for each.
</details>

---

## Success criteria

- [ ] Every host observed in the capture is attributed to a named SDK, or explicitly listed as
      unattributed with the reason.
- [ ] Every host you predicted from static analysis appears in the table, including the ones that
      never sent anything.
- [ ] At least one payload that was not plain JSON has been decoded, and you can say which layer you
      hooked to do it.
- [ ] You have tested the pre-consent window and the consent-declined case, and recorded both.
- [ ] You checked whether native traffic exists outside the proxy, and said so in the table either
      way.
- [ ] The table's "Data observed" cells name actual field names, with values redacted.
- [ ] You can state, for one SDK, whether the data it receives is joinable to the client's own
      customer records, and how you established that.

---

## Where to go next

| Next | Why |
|---|---|
| [Lab 04 — Catch the constructor](lab-04-constructor-hook.md) | An SDK that notices you are doing this, and decides not to run |
| [Lab 05 — The library that lied](lab-05-ctf-library-that-lied.md) | An SDK whose behaviour and whose name are different things |
| [Chapter 17 §9.4](../README.md#9-examples) | The worked retail-app audit this lab generalises |
| [71-OWASP-Mobile](../../71-OWASP-Mobile/README.md) | MASVS-PRIVACY, which is where this table maps in a report |
