# Lab 03 — Prove it on the device

**Difficulty:** intermediate to advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-extract-a-real-config.md) and
[Lab 02](lab-02-make-an-app-trust-your-ca.md); [53-Frida](../../53-Frida/README.md) for the
instrumentation basics
**Needs:** a rooted device or emulator with `frida-server` running, `frida-tools` on the host, and
several third-party apps installed

---

## Objective

Stop inferring, and measure. Every claim in this chapter that is marked "measured" was produced by
the procedure in this lab, and by the end you should be able to reproduce all of them and to produce
new ones on an app nobody has looked at.

Specifically, you will measure:

1. that `<debug-overrides>` is **discarded** in a non-debuggable build — in a third-party release
   APK, not just your own;
2. that the config **overrides** `android:usesCleartextTraffic`;
3. that an expired `<pin-set>` is **present in the platform's own objects with a past expiry**;
4. that `dumpsys` reports **none** of this;
5. that your rooted device's system certificate store is **not the platform's**, and what that does
   to every other measurement you make on it;
6. and — the honest part — the boundary of what a rooted device can prove at all.

---

## Why measurement rather than reading

A static read of a config tells you what the file says. Six things sit between the file and the
policy in force:

- inheritance, which turns absences into values;
- `FLAG_DEBUGGABLE`, which is not in the config;
- split APKs and resource overlays, which can replace the resource;
- OEM framework patches — this chapter's device already has vendor patches to activity and service
  starts, so assume nothing;
- `ApplicationConfig.setDefaultInstance()`, which is public and which an app can call;
- and the possibility that you resolved the wrong resource ID.

When the static read and the device disagree, **the device is right and the disagreement is the
finding.** That is the whole argument for this lab.

---

## Setup

```bash
# host
adb devices -l
adb shell getprop ro.build.version.release
adb shell getprop ro.build.version.sdk
adb shell "su -c id"
adb shell "ps -A -o NAME | grep frida"
frida --version
```

Expected, on the device this chapter used:

```
84f7a024               device product:sweetin model:M2101K6P device:sweetin
11
30
uid=0(root) gid=0(root) groups=0(root) context=u:r:magisk:s0
frida-server
16.1.6
```

> **Warning — this is somebody's phone**
> Root is a capability, not a licence. This lab launches applications and reads their memory. It does
> **not** install anything, does not change any setting permanently, and force-stops every app it
> starts. Keep it that way: record what you launched and stop it afterwards.
>
> ```bash
> # host - restore state after each part
> adb shell "am force-stop <package>"
> ```

### The keyguard trap

On MIUI, and on several other OEM builds, **an app-originated activity start is refused while the
keyguard is up**, and the refusal is logged at debug level and never reaches the caller. Half your
commands succeed and half fail and the pattern looks random.

```bash
# host - check before trusting any result
adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
# deviceLocked=0    good
# deviceLocked=1    unlock the device before continuing
```

Do **not** disable the lock screen to work around it.

---

## Part 1 — Attach and read the platform's own answer

Pick an app that is already running, so nothing new is launched:

```bash
# host
frida-ps -Ua
```

```
  PID  Name               Identifier
-----  -----------------  ---------------------------------------
24799  Calculator         com.miui.calculator
23751  Chrome             com.android.chrome
 3274  Settings           com.android.settings
```

> **Hint**
> `frida -U -n <name>` matches the **display name** in that first column, not the package. It is
> easier to be unambiguous: `frida -U -p $(adb shell pidof com.miui.calculator)`.

```bash
# host
frida -U -p $(adb shell pidof com.miui.calculator | tr -d '\r') -l ../scripts/nsc-runtime.js
```

Measured output:

```
=== app ==========================================================
  package                       : com.miui.calculator
  targetSdkVersion              : 29
  ApplicationInfo.flags         : 0x30e8be45
  FLAG_DEBUGGABLE               : false
  FLAG_USES_CLEARTEXT_TRAFFIC   : false
  networkSecurityConfigRes      : 0x7f140004

=== certificate stores, as they are RIGHT NOW ====================
  SystemCertificateSource : 139 certificate(s)   (/system/etc/security/cacerts)
  UserCertificateSource : 1 certificate(s)   (/data/misc/user/0/cacerts-added)

=== per-domain configurations the platform built =================
  sandbox.api.collect.data.intl.miui.com   (+ all subdomains)
      cleartextTrafficPermitted : true
      hstsEnforced              : false
      trust anchor sources      : SystemCertificateSource
      trust anchors resolved    : 139 certificate(s)
      pin-set                   : 0 pin(s)

=== default configuration  <-- every host no domain-config matches =
  <base-config> or platform default
      cleartextTrafficPermitted : false
      trust anchor sources      : SystemCertificateSource
      pin-set                   : 0 pin(s)

=== answers for specific hostnames (the platform's own matching) =
  host                                 cleartext   anchors  pins  expiry
  example.com                         false       139      0     never
  localhost                           false       139      0     never
  127.0.0.1                           false       139      0     never
  10.0.2.2                            false       139      0     never

  NetworkSecurityPolicy.isCleartextTrafficPermitted() (no host) : false
```

Two things worth pausing on:

- **The calculator has a network security config**, and it permits cleartext to one telemetry
  hostname. That is the "honest severity" case in miniature: scoped, one host, and the finding is
  whatever that beacon actually carries, not the flag.
- **The two forms of `isCleartextTrafficPermitted` disagree** — `false` with no argument, `true` for
  `sandbox.api.collect.data.intl.miui.com`. Which one a given library calls decides whether the
  request goes out.

> **Checkpoint 1**
> Run the script against three apps. For each, write down whether it declares a config
> (`networkSecurityConfigRes` non-zero), and what the default configuration's anchor sources are.

---

## Part 2 — Measure that `<debug-overrides>` is discarded

This is the measurement that makes [README §3.7](../README.md#3-deep-internal-working) reportable.
Lab 02 did it on your own build; here you do it on a third-party release APK, which is the case that
actually appears in reports.

Find an app whose config contains **only** a `<debug-overrides>` block. On the test device,
`com.vendor.professionalnet` is one. Confirm statically first:

```bash
# host
adb pull "$(adb shell pm path com.vendor.professionalnet | head -1 | sed 's/package://' | tr -d '\r')" linkedin.apk
python3 -B ../scripts/nsc-audit.py linkedin.apk --xml
```

```
   android:debuggable           False
   resolved to                  res/xml/network_security_config.xml

-- decoded configuration --
   <network-security-config>
     <debug-overrides>
       <trust-anchors>
         <certificates src="system" />
         <certificates src="user" />
       </trust-anchors>
     </debug-overrides>
   </network-security-config>
```

A grep-driven report writes this up as "the application trusts user-installed certificates". Now ask
the device.

```bash
# host
adb shell "monkey -p com.vendor.professionalnet -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
sleep 5
frida -U -p $(adb shell pidof com.vendor.professionalnet | tr -d '\r' | awk '{print $1}') \
      -l ../scripts/nsc-runtime.js
adb shell "am force-stop com.vendor.professionalnet"
```

Measured:

```
  package                       : com.vendor.professionalnet
  targetSdkVersion              : 29
  FLAG_DEBUGGABLE               : false
  networkSecurityConfigRes      : 0x7f0d0001

=== per-domain configurations the platform built =================
  the set is empty

=== default configuration =========================================
  <base-config> or platform default
      cleartextTrafficPermitted : false
      trust anchor sources      : SystemCertificateSource
      pin-set                   : 0 pin(s)
```

**`UserCertificateSource` is absent.** The block was parsed and discarded. There is no finding.

> **Checkpoint 2**
> Save this output. Paired with the static read above, it is a complete, self-contained argument that
> `<debug-overrides>` in a non-debuggable build is not a vulnerability — and you will need it, because
> a scanner will hand you this finding on most engagements.

### The subtlety: empty is not null

Compare with an app that declares **no config at all**:

```bash
# host
adb shell "monkey -p com.vendor.fileexplorer -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
sleep 5
frida -U -p $(adb shell pidof com.vendor.fileexplorer | tr -d '\r' | awk '{print $1}') \
      -l ../scripts/nsc-runtime.js | sed -n '1,25p'
adb shell "am force-stop com.vendor.fileexplorer"
```

```
  networkSecurityConfigRes      : 0x0   (no config declared - platform defaults apply)
=== per-domain configurations the platform built =================
  mConfigs is null: this app has NO <domain-config> at all.
```

`ApplicationConfig.mConfigs` is **null** for an app with no config and an **empty set** for an app
whose config declares no `<domain-config>`. Both produce the same effective policy; the difference
matters only if you are writing tooling — and the first version of `nsc-runtime.js` crashed on the
null case, which is how this ended up documented.

---

## Part 3 — Measure that the config beats the manifest

Find an app that declares `android:usesCleartextTraffic="true"` **and** a config. On the test device,
The marketplace app's does.

```bash
# host
PKG=com.vendor.marketplace
adb pull "$(adb shell pm path $PKG | head -1 | sed 's/package://' | tr -d '\r')" amazon.apk
python3 -B ../scripts/nsc-audit.py amazon.apk | grep -E 'usesCleartext|NSC-026' -A3
```

```
   android:usesCleartextTraffic True
   [INFO    ] NSC-026  manifest and config disagree about cleartext; the CONFIG wins
       evidence  : android:usesCleartextTraffic=true but <base-config cleartextTrafficPermitted=false>
```

Now the device:

```bash
# host
adb shell "monkey -p $PKG -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1
sleep 8
frida -U -p $(adb shell pidof $PKG | tr -d '\r' | awk '{print $1}') \
      -l ../scripts/nsc-runtime.js | grep -E 'FLAG_USES|cleartextTrafficPermitted' | head -4
adb shell "am force-stop $PKG"
```

```
  FLAG_USES_CLEARTEXT_TRAFFIC   : true    <-- the manifest boolean; a config OVERRIDES it
      cleartextTrafficPermitted : false
```

The `ApplicationInfo` flag is set, and the effective policy is `false`.

> **Checkpoint 3**
> Write one sentence explaining why a manifest-only cleartext checker produces a false positive on
> this app, and one sentence explaining how to construct the opposite — an app whose manifest says
> `false` and whose effective policy is `true`.

---

## Part 4 — Measure an expired pin-set

The finding this chapter exists to publicise. Find an app with a `<pin-set expiration="...">`:

```bash
# host
for f in *.apk; do
  echo -n "$f: "
  python3 -B ../scripts/nsc-audit.py "$f" 2>/dev/null | grep -o 'expiration="[^"]*"' | head -1
  echo
done
```

On the test device, two of five large apps had one, and both had passed. The social-media app:

```bash
# host
PKG=com.vendor.socialmedia
adb shell "am start -n $PKG/.LoginActivity" >/dev/null 2>&1
sleep 6
frida -U -p $(adb shell pidof $PKG | tr -d '\r' | awk '{print $1}') \
      -l ../scripts/nsc-runtime.js | grep -A6 '^  socialvendor.example'
adb shell "am force-stop $PKG"
```

Measured:

```
  socialvendor.example   (+ all subdomains)
      cleartextTrafficPermitted : false
      hstsEnforced              : false
      trust anchor sources      : SystemCertificateSource, UserCertificateSource
      trust anchors resolved    : 139 certificate(s)
      pin-set                   : 15 pin(s)
      pin-set expiry            : 2021-06-30T18:30:00Z  *** EXPIRED 1869 days ago ***
```

Three separate observations in six lines:

1. **Fifteen pins, expired.** `NetworkSecurityTrustManager.isPinningEnforced()` compares
   `expirationTime` to now before applying them, and returns false. The pins have not constrained
   anything since 2021.
2. **The anchors include the user store**, inherited from `<base-config>` — the `<domain-config>`
   declares no `<trust-anchors>` of its own.
3. **The timestamp is `18:30:00Z`, not midnight.** The config says `expiration="2021-07-1"` and
   `SimpleDateFormat` parsed it in the **device's** timezone (IST, UTC+5:30). A pin-set expires at
   slightly different instants on phones in different timezones. It has never mattered, but it tells
   you precisely which parser ran.

> **Checkpoint 4**
> Check whether the app also honours an un-padded day. `2021-07-1` is not strictly `yyyy-MM-dd`, and
> it parsed anyway, because `SimpleDateFormat` is lenient by default. What would `2021-13-45` do?
> Predict, then test it on your own build from lab 02.

---

## Part 5 — Measure that `dumpsys` tells you nothing

```bash
# device shell
dumpsys package com.vendor.socialmedia | grep -E 'flags=|privateFlags=|targetSdk|networkSecurity'
```

```
    versionCode=... minSdk=9 targetSdk=30
    flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
    privateFlags=[ PRIVATE_FLAG_ACTIVITIES_RESIZE_MODE_RESIZEABLE_VIA_SDK_VERSION … ]
    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
```

No `FLAG_USES_CLEARTEXT_TRAFFIC`, no `networkSecurityConfigRes`. And it is not this package:

```bash
# device shell
dumpsys package packages | grep -c CLEARTEXT
```

```
0
```

Zero, across every third-party package on the device — including the file-manager app and the marketplace app, both of
which have the flag set in `ApplicationInfo` (Part 3 measured it directly).

> **Pentester's Note**
> This is genuinely unusual. Most of the manifest is inspectable through `dumpsys` — chapter 32 relies
> on it for component export state — and this subsystem is not. There is **no adb-only way** to read
> an app's effective network policy on API 30. If you are in an environment where you cannot run
> Frida, you are limited to the static read and you should say so.

> **Checkpoint 5**
> Confirm the count is zero on your own device, then confirm with `nsc-runtime.js` that at least one
> package on it does have the flag set. That contradiction is the point.

---

## Part 6 — Measure what root did to your system store

The most important part of this lab, because it invalidates measurements you might otherwise make.

```bash
# host
adb shell "su -c 'mount | grep cacerts'" | head -3
adb shell "ls /system/etc/security/cacerts | wc -l"
adb shell "su -c 'ls -la /data/misc/user/0/cacerts-added/'"
adb shell "grep -l -a PortSwigger /system/etc/security/cacerts/* 2>/dev/null"
```

Measured on the test device:

```
APatch on /system/etc/security/cacerts type tmpfs (rw,seclabel,relatime,size=2836508k,…)
/dev/block/dm-10 on /system/etc/security/cacerts/d41b5e2a.0 type f2fs (rw,lazytime,…)
…
139
-rw-r--r-- 1 system system 939 2026-04-28 18:36 9a5ba575.0
/system/etc/security/cacerts/9a5ba575.0
```

Read that last line again. **The Burp CA is in the system store.** The root solution has bind-mounted
a tmpfs over `/system/etc/security/cacerts`, re-bind-mounted every real system certificate into it
individually, and added `9a5ba575.0`.

What that costs you:

| Measurement | Still valid? | Why |
|---|---|---|
| Which anchor *sources* a config declares | **Yes** | `nsc-runtime.js` reads `mCertificatesEntryRefs`, which names the source class, not the certificates |
| Effective cleartext policy per host | **Yes** | Unrelated to the stores |
| Pin count and expiry | **Yes** | Unrelated |
| "This app trusts my CA because it trusts the user store" | **No** | Your CA is a system CA here too. A successful interception proves nothing about which store was consulted |
| "The API 24 change means user CAs are ignored" | **No** | You cannot demonstrate the negative on this device |
| Anchor **counts** | **Misleading** | The union of 139 system and 1 user certificate is 139, because the user certificate is a duplicate |

That last row is why `nsc-runtime.js` prints the anchor **sources** and not only the count. Measured
on the social-media app, whose config trusts both stores:

```
      trust anchor sources      : SystemCertificateSource, UserCertificateSource
      trust anchors resolved    : 139 certificate(s)
```

139, not 140. Two sources, one deduplicated set. **The source list is the contamination-proof
measurement; the count is not.**

> **Checkpoint 6**
> Write, in your own words, the sentence you would put in a report's methodology section describing
> your test device's certificate store state. If your report does not contain such a sentence, a
> competent reviewer cannot evaluate your trust findings.

### Doing it cleanly

To measure default trust honestly you need a device where the system store is the platform's:

- a fresh emulator image with no CA installed anywhere, or
- your rooted device with the CA-injection module disabled and rebooted, or
- an unrooted device — in which case you lose Frida, and you are back to the static read.

Do at least one run on a clean image and compare. The comparison is the lab.

---

## Part 7 — Prove the trust manager is on the code path

Everything so far is policy. This is the check that tells you whether the policy is *used*.

Edit `../scripts/nsc-runtime.js`:

```javascript
var CONFIG = {
    hosts: ['api.example.com', 'localhost', '10.0.2.2'],
    trace: true                      // <-- turn this on
};
```

```bash
# host
frida -U -f com.example.app -l ../scripts/nsc-runtime.js
```

Then use the app so it makes a request. You should see:

```
[trust] checkServerTrusted host=api.example.com authType=ECDHE_RSA leaf=CN=api.example.com
[trust]   -> accepted, chain length 3
```

**Silence during a successful HTTPS request is the finding.** It means the app validated the
certificate somewhere the config does not reach:

| Cause | How to confirm |
|---|---|
| The app installs its own `X509TrustManager` | `grep -rn "X509TrustManager" work/smali*/` |
| A bundled Cronet with its own store | `ls work/lib/*/ \| grep -i cronet` |
| Flutter's `dart:io` HTTP client | `ls work/lib/*/ \| grep -i flutter` |
| Native code using BoringSSL or libcurl directly | `ls work/lib/*/ \| grep -iE 'ssl\|crypto'` |
| The traffic is not TLS at all | Capture it |

> **Warning**
> `-f` spawns the process, and your script may run before `ActivityThread.handleBindApplication`
> finishes. `nsc-runtime.js` detects a null `Application` and tells you so rather than throwing an
> unhelpful error, but the fix is to attach after launch rather than spawning.

> **Checkpoint 7**
> Find one app on your device where the trust manager fires and one where it does not. The second is
> more interesting.

---

## Part 8 — What this lab could NOT prove, and why saying so matters

Three claims in this chapter are **read from the platform's structure, not measured on a device**.
They are marked as such in the README, and closing them is the natural extension of this lab.

1. **That an unknown element in a config is a hard parse error while an unknown attribute is silently
   dropped.** Build two variants of your lab-02 app — one with `<domain-cfg>` instead of
   `<domain-config>`, one with `cleartextTrafficPermited` — install both, watch logcat on the first
   network call, and record what happens.

2. **That the parse is lazy — that a broken config throws on the first network call rather than at
   launch.** Same builds. Does the app start? Does it survive until you press the button?

3. **That an expired pin-set truly does not reject a mismatched chain.** Take your lab-02 app with
   deliberately wrong pins, set `expiration` to yesterday, and confirm that the connection which
   failed in lab 02 part 5 now succeeds. That is the cleanest possible demonstration of §3.6 and it
   takes ten minutes.

Doing all three turns this chapter's "three silent failure modes" from a structural claim into three
measurements you performed.

> **Mental Model**
> The distinction between "I read this in the source" and "I watched this happen" is the difference
> between a chapter and a report. Both are legitimate; conflating them is not. Every claim in this
> repository that says "measured" was, and every claim that was not says so.

---

## Success criteria

- [ ] You dumped the platform's own `ApplicationConfig` for at least four apps.
- [ ] You measured a third-party release APK whose `<debug-overrides>` block was discarded, and you
      have the static read and the runtime dump side by side.
- [ ] You measured an app whose manifest and config disagree about cleartext, and confirmed which
      wins.
- [ ] You measured a `<pin-set>` whose expiry has passed, and recorded the date and the day count.
- [ ] You confirmed `dumpsys package packages | grep -c CLEARTEXT` returns 0 while at least one app
      has the flag set.
- [ ] You checked `mount | grep cacerts` and can state whether your device's system store is the
      platform's.
- [ ] You can name the one measurement in this lab that is contamination-proof (anchor **sources**)
      and the one that is not (anchor **counts**).
- [ ] You traced `checkServerTrusted` and found at least one app where it does not fire.
- [ ] Every app you launched has been force-stopped.

---

## Extension exercises

1. **Sweep the whole device.** Script Parts 1 to 4 across every third-party package: launch, attach,
   dump, force-stop. Produce a table of package against effective default cleartext, anchor sources,
   pin count and expiry. What proportion of the device's apps trust the user store? What proportion
   have an expired pin-set?

2. **Watch a config change under you.** `NetworkSecurityConfig.handleTrustStorageUpdate()` exists so
   the platform can react to a certificate being installed or removed. Hook it, then install a CA
   through Settings while an app is running, and see whether the app's anchor set changes without a
   restart.

3. **Replace the policy at runtime.** `ApplicationConfig.setDefaultInstance()` is public. Build a
   `NetworkSecurityConfig` with a permissive builder and install it into a running app. This is a
   pinning bypass in three lines and it belongs to chapter 36, but building it here shows you why
   reading the file is never the last word.

4. **Compare two devices.** Run the same measurements on a clean emulator and on your rooted phone.
   Every difference is either a version difference or something root did, and telling them apart is
   the skill this lab is really teaching.

---

## Where to go next

- [Lab 04](lab-04-ctf-the-config-that-lies.md) — a config, a manifest and a runtime that disagree on
  purpose.
- [README §5.5](../README.md#5-security-perspective) — how to write up an expired pin-set so it is
  not dismissed.
- Chapter 36 — when the pins are live and you need them not to be.
