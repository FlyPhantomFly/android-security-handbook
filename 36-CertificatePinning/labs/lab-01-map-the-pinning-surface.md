# Lab 01 — Map the pinning surface before you touch anything

> **Difficulty:** beginner
> **Time:** 60–90 minutes
> **Prerequisites:** [10-APK-Internals](../../10-APK-Internals/README.md),
> [15-Native-Code](../../15-Native-Code/README.md), a device or emulator with `adb`
> **Authorisation:** this lab is **detection only**. Everything in it reads files that are already
> on your own device. Nothing is hooked, patched, installed, or intercepted. That is what makes it
> safe to run against third-party apps — and the line you must not cross in this lab is doing
> anything more to them than looking.

---

## 1. Why this lab exists

Almost every published pinning workflow starts at the wrong end:

1. Set the proxy.
2. Run the universal bypass script.
3. If traffic appears, celebrate. If not, try a different script.

Step 3 is where the hours go. "No traffic" is a single observation with at least six distinct
causes — a missed layer, a native stack, a proxy that is not on the path, an app that never made the
request, a hostname the app resolves differently, an app that crashed on startup — and the bypass
script cannot distinguish between them, because it only ever reports on the hooks it installed.

The fix is embarrassingly simple and almost nobody does it: **find out what the app pins at before
you try to defeat it.** Ten minutes of static work turns "the bypass didn't work" into "the bypass
addressed layers 1 through 6 and this app pins in a statically-linked BoringSSL, so of course it
didn't".

By the end of this lab you will have a measured, per-app map of the pinning surface for every app on
your device, and you will be able to explain why the most common automated finding in this area —
"the application uses certificate pinning" — is wrong most of the time it is reported.

---

## 2. Objectives

By the end you can:

- [ ] Run [`pinning-surface.py`](../scripts/pinning-surface.py) against an APK and a package.
- [ ] Explain the difference between **a pin value**, **trust material**, and **a pinning surface**,
      and why the tool reports them separately.
- [ ] Recognise a Flutter app from its APK alone, and say what that means for every Java hook.
- [ ] Find a configured `sha256/` pin in a DEX with `grep` alone, without the tool.
- [ ] Say, for a given app, exactly which layers a bypass would have to address — before installing
      a single hook.
- [ ] Explain why "okhttp3.CertificatePinner is in the DEX" is not evidence of pinning.

---

## 3. Setup

### 3.1 Confirm the device

```bash
# host
adb devices -l
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
```

The reference device for this chapter is a Redmi `M2101K6P` (`sweetin`), Android 11 / API 30, MIUI
12.5, rooted with Magisk. Nothing in this lab needs root except the optional `--live` step in §7.

> **⚠️ Warning — this may be your daily driver**
> Every command in this lab is a read. `adb pull` copies an APK to your host; `pm list packages` and
> `pm path` only query. Nothing is installed, nothing is force-stopped, no setting is written. If a
> step in this lab asks you to change device state, you have misread it.

### 3.2 Check the tool runs

```bash
# host
cd 36-CertificatePinning/scripts
python3 -B pinning-surface.py --help
```

`-B` is not optional in this repository. Python writes `__pycache__` in circumstances that
`PYTHONDONTWRITEBYTECODE` does not cover, and a committed `__pycache__` is a build artefact.

---

## 4. Step 1 — one app, read the whole report

Pick any installed app. Start with something large and commercial, because a trivial app has no
surface to map.

```bash
# host
python3 -B pinning-surface.py --package com.example.someapp
```

The tool pulls the APK (and every split, which matters — see §4.2), scans the DEX bytes, the native
libraries and the compiled resources, and prints findings grouped by layer.

### 4.1 Read the confidence column first, not the layer

Each finding carries one of four confidence levels, and the whole value of the tool is in that
column:

| Level | Meaning | Example |
|---|---|---|
| `HIGH` | A **pin value** was found. Someone configured a pin | `sha256/` followed by 43 base64 characters and `=`; a `<pin-set>` element |
| `MATRL` | **Trust material** is embedded. Certainly present, genuinely ambiguous | A PEM certificate compiled into the DEX or a `.so` |
| `MED` | The app **took control of trust**. Might be a pin, might be the opposite | A custom `X509TrustManager`; `X509TrustManagerExtensions` |
| `LOW` | A library that **contains** pinning code is on the classpath | `okhttp3.CertificatePinner` appears in the type pool |

> **🔍 Pentester's Note**
> The `LOW` row is the one that matters for your report. `okhttp3.CertificatePinner` is referenced by
> `OkHttpClient` itself, so it lands in the DEX of **every app that uses OkHttp**, pinned or not.
> Any tool that reports "certificate pinning detected" on that basis is reporting "this app uses
> OkHttp". That finding has been in circulation for years and it is wrong every time the app has an
> empty pin set — which is most of the time.

### 4.2 Splits

`pm path` prints one line per APK in the install. On a Play-installed app the base APK holds the DEX
and `split_config.arm64_v8a.apk` holds every native library. A scanner that reads only the first
line reports "0 native libs" for an app that is entirely native, and therefore reports "no native
pinning" for a Flutter app.

Check what your target actually is:

```bash
# host
adb shell pm path com.example.someapp
```

If you see more than one line, the tool is pulling all of them. If you see exactly one, this app was
sideloaded or preinstalled as a single APK.

---

## 5. Step 2 — measure the whole device

```bash
# host
for p in $(adb shell pm list packages -3 | sed 's/^package://' | tr -d '\r'); do
    echo "### $p"
    python3 -B pinning-surface.py --package "$p" 2>/dev/null | grep 'VERDICT'
done
```

This pulls every third-party APK, so it is slow and it will use several gigabytes of temporary
space (the tool deletes each APK after analysing it). Restrict it to a dozen packages the first
time.

### 5.1 What was measured on the reference device

Run on the Redmi `M2101K6P`, Android 11 / API 30, against fourteen third-party packages that were
already installed. These are **detection-only** results on apps that were not otherwise touched.
`L1` = custom `TrustManager`, `L1b` = `X509TrustManagerExtensions`, `L3` = OkHttp `CertificatePinner`,
`L5` = `network_security_config`, `L7` = native TLS.

| Package | dex | libs | Pin value found | Trust material | Surface |
|---|---:|---:|---|---|---|
| `com.vendor.professionalnet` | 1 | 0 | — | — | L5 |
| `com.vendor.streaming` | 1 | 0 | — | — | L5 |
| `com.vendor.socialmedia` | 1 | 0 | **L5** | — | L5 |
| `com.vendor.marketplace` | 14 | 44 | **L5** | L1 | L1, L1b, L3, L5, L7 |
| `com.vendor.grocery` | 9 | 10 | — | L1 | L1, L1b, L3, L5, L7 |
| `com.vendor.hrapp` | 4 | 2 | — | — | L1, L1b, L3 |
| `com.vendor.homeservices` | 3 | 7 | — | L1 | L1, L1b, L3, L5, L7 |
| `com.vendor.loyalty` | 26 | 14 | **L3** | L1 | L1, L1b, L3, L5, L7 |
| `com.vendor.oemshop` | 5 | 13 | — | L1, L7 | L1, L1b, L3, L7 |
| `com.vendor.remotectl` | 3 | 14 | — | L1, L7 | L1, L3, L5, L7 |
| `com.vendor.filemanager` | 8 | 4 | — | L1 | L1, L3, L5 |
| `com.vendor.appstore` | 6 | 5 | **L3** | L1 | L1, L1b, L3, L5 |
| `com.mobilehackinglab.fridaone` | 3 | 0 | — | — | — |
| `com.vendor.fileexplorer` | 1 | 0 | — | — | L1 |

Four observations from that table are worth more than the table itself.

**Only four of fourteen apps have a pin value anywhere in the APK.** Twelve of the fourteen have a
"pinning surface" — code that could pin. If you had reported on the surface, you would have written
twelve findings, eight of which are wrong.

**The surface is almost always multi-layer.** Seven apps show four or five layers. For any of those,
a bypass that handles OkHttp alone addresses one fifth of the problem, and the four remaining fifths
fail silently.

**Three of these are Flutter apps**, identified by `libflutter.so` or `libapp.so` plus
`assets/flutter_assets/`: `com.vendor.homeservices`, `com.vendor.loyalty`, `com.vendor.oemshop`.
Every Java hook in every published bypass script is irrelevant to their Dart-side traffic, because
Flutter's Dart `HttpClient` runs on a BoringSSL that is statically linked into `libflutter.so` and
uses its **own** compiled-in root list — it does not read the Android system trust store at all. See
[§3.7 of the chapter](../README.md#37-flutter-and-the-tls-stack-that-ignores-you).

**`com.vendor.loyalty` is the most interesting row in the table.** It is a Flutter app — native
TLS stack, own trust store — *and* it carries a real, configured OkHttp pin in its Java code:

```
[3. OkHttp CertificatePinner]
    + [HIGH ] CONFIGURED OkHttp/NSC pin value
              where: com.vendor.loyalty.0.apk!classes24.dex
              value: 1 distinct value(s): sha256/V5L96iSCz0XLFgvKi7YVo6M4SIkOP9zSkDjZ0EoU6b8=
```

That is exactly the shape this chapter is about. Two independent stacks, two independent trust
decisions, one of them reachable by a Java hook and one not. Bypassing the OkHttp pin would get you
the Java traffic and precisely none of the Dart traffic — and the bypass script would report total
success.

> **⚠️ Warning — stop here**
> You have now detected a pin in a third-party application. **Do not proceed to bypass it.** You are
> not authorised to test `com.vendor.loyalty`, and neither was the author of this chapter.
> Detection on an APK sitting on your own disk is not an attack; instrumenting a running third-party
> app to defeat its security control is. Lab 02 gives you an app you built yourself to break
> instead, and it is a better teacher anyway because you know the answer.

---

## 6. Step 3 — do it by hand, without the tool

A tool you cannot reproduce by hand is a tool you cannot debug. Everything above is four greps.

### 6.1 Pull an APK

```bash
# host
adb shell pm path com.example.someapp
adb pull /data/app/~~<hash>/com.example.someapp-<hash>/base.apk ./target.apk
```

### 6.2 Find a configured pin value

The pin format is `sha256/` followed by base64 of a 32-byte digest. Base64 of 32 bytes is always
exactly 44 characters ending in one `=`. That shape does not occur by accident:

```bash
# host
unzip -p target.apk classes.dex | strings -a | grep -E 'sha256/[A-Za-z0-9+/]{43}='
```

For multi-DEX apps, loop:

```bash
# host
mkdir -p /tmp/dexes && unzip -o -j target.apk 'classes*.dex' -d /tmp/dexes
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/dexes/*.dex | sort -u
```

**A hit here is a real finding.** A miss is weaker evidence than it looks: the pin may be built at
runtime from parts, stored as raw bytes rather than base64, delivered by remote config (see
[example 5](../examples/05-enterprise-pin-rotation.kt)), or live in native code.

Now try the *wrong* grep, the one most people run:

```bash
# host
grep -a -c 'sha256/' /tmp/dexes/*.dex
```

That matches OkHttp's own parser constant and hits on essentially every OkHttp app. The 43-character
suffix is what turns a useless grep into a finding.

### 6.3 Find a declared `<pin-set>`

The network security config is compiled to binary XML, but the element names survive in the string
pool:

```bash
# host
unzip -o -j target.apk 'res/xml/*' -d /tmp/nsc 2>/dev/null
grep -l -a 'pin-set' /tmp/nsc/* 2>/dev/null
```

Then decode it properly:

```bash
# host — needs build-tools on PATH
aapt2 dump xmltree --file res/xml/network_security_config.xml target.apk
```

`aapt2` gives you the actual pins, the `expiration` attribute and the domains. That last one is what
turns "the app pins" into "the app pins `api.example.com` and not the four other hosts it talks to".

> **📖 Definition — `<pin-set>`**
> A declaration in `res/xml/network_security_config.xml` naming SHA-256 SPKI digests for a domain.
> The XML itself is chapter [44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md)'s
> subject. What happens at runtime when one of those pins does not match — which platform class
> throws, what the exception says, and how to attribute it — is this chapter's.

### 6.4 Find a native TLS stack

```bash
# host
unzip -l target.apk | grep '\.so$'
```

Names that decide the answer:

| Library | What it means |
|---|---|
| `libflutter.so`, `libapp.so` | Flutter. Own BoringSSL, own root list, ignores the system trust store |
| `libcronet*.so` | Cronet/Chromium. Trust and pinning are native |
| `libssl.so`, `libcrypto.so` | A separate OpenSSL/BoringSSL. Might be TLS, might be hashing |
| `libreactnativejni.so`, `libhermes.so` | React Native — usually routes through OkHttp in Java, so Java hooks **do** work |
| `libmonodroid.so` | Xamarin/Mono, with its own HTTP handler |
| `libunity.so` | Unity, often with a bundled TLS stack |

Then look inside for the verification entry points:

```bash
# host
unzip -o -j target.apk 'lib/arm64-v8a/*.so' -d /tmp/libs
for f in /tmp/libs/*.so; do
    if strings -a "$f" | grep -q 'SSL_CTX_set_custom_verify\|SSL_CTX_set_verify'; then
        echo "TLS verify entry point in: $f"
    fi
done
```

A `NEEDED libssl.so` in the dynamic section leads here too — that is the thread
[15-Native-Code](../../15-Native-Code/README.md) hands you:

```bash
# host — NDK llvm-readelf
llvm-readelf -d /tmp/libs/libsomething.so | grep NEEDED
```

### 6.5 Find a permissive trust manager pretending to be a pin

```bash
# host
grep -a -c 'checkServerTrusted' /tmp/dexes/*.dex
```

A hit means the app has its own trust manager. It does **not** tell you which kind — a pinning one
or a `{ }`-bodied accept-everything one. Only decompilation answers that, and
[example 4, case 3](../examples/04-pins-that-are-not-pins.kt) shows exactly what the dangerous
version looks like in `jadx`.

---

## 7. Step 4 (optional, needs root) — the live view

Static analysis sees the libraries that ship in the APK. It does not see libraries downloaded at
runtime, and it does not see which of the shipped ones were ever actually loaded.

```bash
# host — the app must be running
python3 -B pinning-surface.py --package com.example.someapp --live
```

This reads `/proc/<pid>/maps` through `su` and lists mapped `.so` files. Two things it can tell you
that the APK cannot:

- A TLS library that was **not** in the APK is loaded — downloaded, or supplied by a Play service.
- A library that **was** in the APK is never mapped, so its pinning code never runs.

Reading another process's `maps` requires root, and on some builds SELinux refuses it even to
`adb shell` — measured on Android 13, where the denial is precisely why
[`19-Memory/examples/fixture-app-maps.txt`](../../19-Memory/examples/fixture-app-maps.txt) ships as a
synthetic capture, labelled as such, instead of a real one. If it fails, that is an environment fact,
not a bug.

---

## 8. Step 5 — write the finding

Take the app you analysed in §4 and write two sentences. Not a paragraph — two sentences, because
that is what a report has room for and it is where the discipline lives.

The template that is defensible:

> The application's network layer presents a pinning surface at *[layers]*. A configured pin value
> was *[found at layer N / not found statically]*, so pinning is *[confirmed / not confirmed]*;
> traffic interception therefore requires *[addressing those layers / only a trusted CA]*.

The template that is not:

> ❌ The application implements certificate pinning.

Nothing in a static scan supports that sentence unless you found a pin value, and even then it
supports "a pin is configured" rather than "pinning is enforced on the paths that matter". The
runtime half is [Lab 03](lab-03-attribute-the-rejection.md).

---

## 9. Hints

<details>
<summary>The tool reports 0 dex and 0 native libs</summary>

You pulled a stub. Some distribution channels install a tiny placeholder APK and fetch the real
payload later; some OEM preloads are stubs until first launch. Check the size — a 300 KB `base.apk`
for a large commercial app is a stub. Open the app once, then re-run.

Both `com.vendor.professionalnet` and `com.vendor.streaming` behaved this way on the reference device,
which is why their rows in §5.1 show 1 dex and 0 libs. Those two rows are a measurement of the
*install*, not of the application, and the table would be dishonest if it did not say so.
</details>

<details>
<summary>Every app reports a "surface" at L1</summary>

`checkServerTrusted` and `javax.net.ssl.X509TrustManager` appear in almost every app that does
networking, because the strings are in library code. That is why L1 evidence is graded `MED` and
never `HIGH`. The surface is real — a bypass would have to address it — but it is not a pin.
</details>

<details>
<summary>I found a PEM certificate in the DEX. Is that a pin?</summary>

Probably not, and that is why the tool grades it `MATRL` rather than `HIGH`. A bundled private root,
a payment SDK's own trust store, a licence-verification key and a test fixture all look identical
from outside. Decide by reading the code that *loads* it: a certificate fed to a `KeyStore` and then
to a `TrustManagerFactory` is a private trust store; a certificate whose public key is hashed and
compared is a pin.
</details>

<details>
<summary>Flutter app: where do I even look for the pin?</summary>

Not in the DEX, unless the app also pins on the Java side (`com.vendor.loyalty` does both).
Dart-side pinning is compiled into `libapp.so` as AOT machine code with the pin as a byte array. It
is findable — `strings` on `libapp.so` sometimes yields the base64 — but it is a reverse-engineering
exercise, not a grep, and it belongs to [57-Ghidra](../../57-Ghidra/README.md).
</details>

---

## 10. Success criteria

- [ ] You ran `pinning-surface.py` against at least five packages and can name, for each, the layers
      a bypass would have to address.
- [ ] You found at least one app with a **configured pin value** and at least one where the tool
      reports a surface but no pin — and you can articulate the difference.
- [ ] You reproduced one of the tool's findings by hand with `unzip` and `grep`.
- [ ] You identified at least one app with a native TLS stack and stated what that means for Java
      hooking.
- [ ] You wrote the two-sentence finding in §8 for one app, and it does not contain the phrase "the
      application implements certificate pinning" unqualified.
- [ ] **You did not bypass, hook, patch or intercept anything.** Every command in this lab was a
      read.

---

## 11. What you should take away

The pinning surface of a real app is wider than one layer, and the pinning *implementation* is
usually narrower than the surface. Those two facts pull in opposite directions and both matter:

- Wider surface means a single-layer bypass fails, silently, in a way that looks like a broken tool.
- Narrower implementation means most "pinning detected" findings are false, and reporting them
  costs your credibility with a developer who knows their own code.

Ten minutes of static mapping tells you which of those you are in. It is the cheapest ten minutes in
mobile network testing and it is the step almost everybody skips.

---

**Next:** [Lab 02 — defeat a two-layer pin you built yourself](lab-02-defeat-a-two-layer-pin.md),
where you experience the multi-layer failure from the inside, on an app whose answer you already know.
