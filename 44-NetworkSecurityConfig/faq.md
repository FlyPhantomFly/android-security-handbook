# 44 — Network Security Config — FAQ

Real questions, including the ones people are embarrassed to ask. Answered directly.

---

### 1. Where does this file even live? I opened the APK and I cannot find it.

Three places, and only one of them has a name you would recognise.

- **`AndroidManifest.xml`** holds `android:networkSecurityConfig` — but its value is a **32-bit
  number**, not a filename. Something like `0x7f0b0000`.
- **`resources.arsc`** maps that number to a path, e.g. `res/xml/alt_network_security_config.xml`.
  This is the only file in the APK containing the string `network_security_config`.
- **`res/xml/<whatever>.xml`** is the policy itself, stored as Android **binary XML**, not text. A
  text editor shows you mostly garbage.

So `grep`ping the APK for `cleartextTrafficPermitted` finds nothing useful, and `grep`ping the
manifest for it finds nothing at all — it is not a manifest attribute.

The fastest way to see it:

```bash
# host
python3 -B scripts/nsc-audit.py base.apk --xml
```

or, if you have the Android SDK:

```bash
# host
aapt2 dump resources base.apk | grep -A2 'xml/network_security'
aapt2 dump xmltree base.apk --file res/xml/network_security_config.xml
```

And it is **not called `network_security_config.xml` in every app**. The social-media app's is
`alt_network_security_config.xml`. The name is whatever the developer chose; only the resource ID is
fixed.

---

### 2. Why doesn't my Burp / mitmproxy CA work?

Because of a change in Android 7.0 (API 24): **the default trust store no longer includes
user-installed certificate authorities.** You installed your CA through Settings, which puts it in
the *user* store, and the app is not looking there.

Five things to check, in order:

1. **Does the app target API 24 or later?** `nsc-audit.py` prints `targetSdkVersion`. If it targets
   23 or lower, user CAs *are* trusted and your problem is something else.
2. **Does the config trust `src="user"`?** If it does, and it still does not work, the problem is not
   trust.
3. **Is there a live `<pin-set>`?** Check its `expiration` against today. An expired one is not the
   problem.
4. **Is the app even using the system proxy?** Many are not. `adb shell settings put global
   http_proxy host:port` reaches more apps than the wifi proxy setting does.
5. **Is the app using the platform's HTTP stack at all?** Flutter, a bundled Cronet, and native code
   using BoringSSL directly do not consult any of this. Trace the trust manager
   (`CONFIG.trace = true` in [`scripts/nsc-runtime.js`](scripts/nsc-runtime.js)) — if it never fires
   during a successful HTTPS request, none of the above matters.

Your options once you know which it is are in [README §7.3](README.md#7-dynamic-analysis).

---

### 3. What is the actual difference between the "system" store and the "user" store?

| | System | User |
|---|---|---|
| Path | `/system/etc/security/cacerts/` | `/data/misc/user/0/cacerts-added/` |
| Written by | The OS image | Settings, or an MDM policy |
| Needs root to change | Yes | No |
| Trusted by default since API 24 | Yes | **No** |
| Shows a persistent "network may be monitored" warning | No | Yes |

They are the same file format — one PEM per file, named after the OpenSSL subject hash. A Burp CA is
almost always `9a5ba575.0` in either store.

---

### 4. What happens if the app has no config at all?

It gets the platform default, derived from `targetSdkVersion` alone:

| targetSdk | Cleartext | User CAs | Pinning |
|---|---|---|---|
| < 24 | permitted | **trusted** | none |
| 24–27 | permitted | not trusted | none |
| ≥ 28 | **denied** | not trusted | none |

`android:usesCleartextTraffic` in the manifest overrides the cleartext column, in either direction.

**"No network security config found" is not a finding.** At targetSdk 24 and above the defaults are
the safe ones, and writing it up as a vulnerability tells the reader you did not check what the
defaults are.

---

### 5. Why is my `<debug-overrides>` being ignored?

Because your build is not debuggable.

`<debug-overrides>` is applied **only** when the running app's `ApplicationInfo.flags` carries
`FLAG_DEBUGGABLE` — that is, when `android:debuggable="true"` in the merged manifest. Gradle sets
this for the `debug` build type and not for `release`.

Check:

```bash
# host
adb shell "run-as com.example.app id"
# works  -> the app is debuggable
# "not debuggable" -> the block is inert
```

or read it directly:

```bash
# host
frida -U -p $(adb shell pidof com.example.app) -l scripts/nsc-runtime.js | head -8
#   FLAG_DEBUGGABLE               : false
```

If you built with `./gradlew assembleRelease`, or you are testing an APK from the Play Store, the
block does nothing. Build the debug variant, or put the relaxation in
`app/src/debug/res/xml/network_security_config.xml` where it applies to the debug variant regardless
of the debuggable flag.

---

### 6. So an app with `<certificates src="user"/>` in `<debug-overrides>` is vulnerable, right?

**No** — not in a release build, and this is the single most over-reported item in mobile testing.

The platform parses the block and then builds nothing from it when `FLAG_DEBUGGABLE` is not set.
Measured: the professional-network app's shipping APK contains exactly this and nothing else, and the running app's
trust anchor sources read `SystemCertificateSource` alone.

It becomes a finding only when `android:debuggable="true"` in the build you were given — and then the
finding is *"the release build is debuggable"*, with this as the impact. See
[README §3.7](README.md#3-deep-internal-working) and [§5.6](README.md#5-security-perspective).

---

### 7. Does any of this apply to WebView?

Partly, and the split matters.

- **Cleartext: yes.** WebView and the Chromium stack behind it read the policy through JNI and refuse
  to load an `http://` URL, including subresources, when the policy denies it.
- **Trust anchors: mostly yes**, but Chromium does its own chain validation and a `<pin-set>` does
  not reliably apply to WebView's own requests. Test it rather than assuming.
- **Certificate errors: no, and this is the hole.** If the app overrides
  `WebViewClient.onReceivedSslError()` and calls `handler.proceed()`, every certificate error is
  accepted and nothing in this file prevents it. That is a bigger problem than anything the config
  can express, and it belongs to [43-WebView](../43-WebView/README.md).

So: read the config for the cleartext verdict, then go and grep the DEX for `onReceivedSslError`.

---

### 8. The manifest says `usesCleartextTraffic="true"` but the config says `false`. Which wins?

**The config.** Every time.

`ActivityThread.handleBindApplication` sets the policy from the manifest boolean, and *then*
`NetworkSecurityConfigProvider.install()` replaces the whole `NetworkSecurityPolicy` object with one
backed by the parsed config. The boolean is dead from that moment.

Measured on the marketplace app's: `FLAG_USES_CLEARTEXT_TRAFFIC` is set in `ApplicationInfo`, and the
effective verdict is `false`. Any tool that reads only the manifest reports the wrong answer.

---

### 9. There is a `<pin-set>` — so the app is pinned?

Only if the `expiration` has not passed, the set is not empty, and no trust anchor in the chain is
marked `overridePins`.

**Compute the date. Every time.** This is a five-second check and this chapter measured a hit rate of
two out of five large apps: the social-media app's pin-set expired in July 2021 and the marketplace app's in July 2022, both
still shipping in 2026 with fifteen and ten pins respectively.

An expired pin-set produces no log, no exception, and no observable change. The app validates chains
the ordinary way and accepts anything from any trusted CA. Static tools report "pinning implemented".
Nothing is.

---

### 10. Why would anyone put an expiration on a pin-set at all?

Because the alternative failure mode is worse in a specific, brutal way.

Without an expiration, if every pinned key has to be replaced faster than users install an update —
a key compromise, a CA revocation, an acquisition — the installed base **cannot reach the endpoint at
all**, and no server-side change can fix it. Apps have been bricked this way. It is the reason many
organisations tried pinning once and never again.

The expiration is a safety valve: on that date, the extra control lapses and the app keeps working.

The defensible use is a date slightly beyond your certificate rotation window, plus a calendar entry
and a CI check. The common use is a date set once and never revisited, which gets you the downside
of both approaches.

---

### 11. My `<domain-config>` sets a `<pin-set>`. Does it still deny cleartext?

Only if something above it says so.

Inheritance is **per property**. A `<domain-config>` that declares only a `<pin-set>` inherits its
`cleartextTrafficPermitted` from the enclosing `<domain-config>`, then from `<base-config>`, then from
the platform default. If `<base-config>` says `true`, so does your pinned host.

This is the commonest misreading of the whole file, and it is what makes the file-manager app's config
look stricter than it is (README §5.4).

---

### 12. I wrote `<domain>*.example.com</domain>` and it does not match anything. Why?

Because there are **no wildcards**. `<domain>` holds a literal hostname. `*.example.com` is a
hostname whose first label is the character `*`, and no server has that name.

Use `includeSubdomains`:

```xml
<domain includeSubdomains="true">example.com</domain>
```

That matches `example.com` and every host ending in `.example.com`.

---

### 13. I added `<certificates src="@raw/my_ca"/>` and now the app cannot reach anything. What did I break?

You **replaced** the trust anchors instead of adding to them. `<trust-anchors>` is not merged with
the inherited set — declaring one `<certificates>` child discards the whole thing, including the
system CAs.

If you meant "also trust my CA":

```xml
<trust-anchors>
    <certificates src="system" />
    <certificates src="@raw/my_ca" />
</trust-anchors>
```

If you meant "trust **only** my CA for this host" — which is the stronger configuration and often the
right one — leave `system` out, and expect every public certificate to be rejected for that host,
because that is what you asked for.

---

### 14. I typed `cleartextTrafficPermited` (one `t`) and nothing complained. Is that normal?

Yes, and it is dangerous. **Unknown attributes are silently dropped**; unknown *elements* are a parse
error. So a misspelt attribute compiles, installs, runs, and the value is inherited from somewhere
else — the developer believes they set a policy the platform never saw.

`nsc-audit.py` reports this as `NSC-021`.

---

### 15. My app throws on its first network call after I edited the config. Why not at launch?

Because the parse is **lazy**. `XmlConfigSource` does not read the XML during
`NetworkSecurityConfigProvider.install()`; it reads it the first time something calls
`getConfigForHostname()`. A malformed config therefore does not stop the app launching — it throws a
`RuntimeException` wrapping a `ParserException` on the first request, which is a much harder failure
to attribute.

Common causes: an unknown element, `digest="SHA-1"` (only SHA-256 is accepted), an `expiration` that
is not `yyyy-MM-dd`, or a `<domain-config>` with no `<domain>` child.

---

### 16. Can I just check this with `adb` or `dumpsys`?

No. Measured on API 30:

```
$ dumpsys package com.vendor.socialmedia | grep flags=
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
$ dumpsys package packages | grep -c CLEARTEXT
0
```

`FLAG_USES_CLEARTEXT_TRAFFIC` is never printed, for any of the 49 third-party packages on the device,
and `networkSecurityConfigRes` is not printed either. This is unusual — most of the manifest *is*
visible through `dumpsys` — and it is why the runtime check has to be a Frida script.

---

### 17. Does `cleartextTrafficPermitted="false"` actually stop plaintext traffic?

It stops the **cooperating** libraries: `HttpURLConnection`, OkHttp, Volley, WebView, and ExoPlayer's
default data sources. It does not stop:

- a raw `java.net.Socket` with HTTP written by hand,
- native code using BoringSSL or libcurl directly,
- Flutter's `dart:io` `HttpClient`, which has its own stack and its own trust store,
- a Cronet build that bundles its own network stack.

There is no kernel enforcement, no netfilter rule, nothing in `/proc`. It is entirely userspace and
entirely advisory. **Confirm with a capture, every time.**

---

### 18. On my rooted phone I put the Burp CA in the system store and everything decrypts. Have I proved the app trusts user CAs?

No — you have proved the opposite is untestable on that device.

Once a Magisk or APatch module bind-mounts a tmpfs over `/system/etc/security/cacerts` and copies
your CA in, the same certificate is in *both* stores, and a successful interception no longer
distinguishes "the app trusts the user store" from "your CA is a system CA now". Measured on this
chapter's test device:

```
$ adb shell "su -c 'mount | grep cacerts'"
APatch on /system/etc/security/cacerts type tmpfs (rw,seclabel,relatime,…)
$ adb shell "grep -l -a PortSwigger /system/etc/security/cacerts/*"
/system/etc/security/cacerts/9a5ba575.0
```

Keep a clean device or a fresh emulator for measurements about default trust, and **say in your
report which device you used**. Check the mount table before you check anything else.

---

### 19. Which chapter do I go to for bypassing a pin?

chapter 36, `36-CertificatePinning`. This chapter owns the `<pin-set>` as a
*declaration* — how many pins, when they expire, whether they can still bite. Making a live pin stop
biting at runtime is 36's subject, and [53-Frida](../53-Frida/README.md) is the instrumentation.

For TLS itself — what a handshake is, how a chain validates, what a trust anchor means
cryptographically — that is 35-SSL.

---

### 20. What is the single highest-value thing to check in this file?

The `expiration` on every `<pin-set>`, against today's date.

It takes five seconds, it needs no device, no proxy and no root, and this chapter's sample of five
large apps found two of them shipping expired pin-sets — one by nearly five years. It is
under-reported precisely because nothing breaks when it lapses.

Second place: whether `<certificates src="user"/>` appears **outside** `<debug-overrides>`. That is
the finding that changes what the rest of your engagement looks like.

---

### 21. How do I write this up so it is not thrown back at me?

| Do not write | Write |
|---|---|
| "The app trusts user-installed certificates" (from a `<debug-overrides>` block) | Nothing. It is inert. Or a one-line note saying so |
| "No network security config found" | The defaults you computed, as context |
| "Certificate pinning is implemented" | The expiry date and whether it has passed |
| "Cleartext traffic is permitted" | The host, the request, and the data, with the capture |
| "Traffic was intercepted" | Which route: user store, system store, repackaged, or Frida |

The difference between a finding that lands and one that gets disputed is almost always a capture and
a runtime dump attached to it. `nsc-runtime.js` output is short enough to paste into a report
verbatim and is difficult to argue with, because it is the platform's own answer.
