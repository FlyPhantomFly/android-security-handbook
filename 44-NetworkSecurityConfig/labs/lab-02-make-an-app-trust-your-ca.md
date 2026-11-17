# Lab 02 — Make an app you built trust your proxy CA

**Difficulty:** intermediate
**Time:** 2–3 hours
**Prerequisites:** [Lab 01](lab-01-extract-a-real-config.md);
[README §3.7](../README.md#3-deep-internal-working) and [§7.3](../README.md#7-dynamic-analysis);
[08-Build-System](../../08-Build-System/README.md) for source sets and manifest merging
**Needs:** Android SDK (build-tools + platform), a JDK, a device or emulator, and Burp Suite or
mitmproxy. Gradle and Android Studio are convenient but not required — a no-Gradle path is given.

---

## Objective

Build an app that talks HTTPS. Watch it refuse your proxy. Then make it accept your proxy **two
different ways**, and prove — by measurement, not by the app working — which mechanism is live in
which build variant.

By the end you will be able to:

- reproduce the exact failure a tester sees when their CA is not trusted, and name it;
- write both forms of the debug relaxation and explain their different failure modes;
- demonstrate that `<debug-overrides>` is inert in a release build **of your own APK**, where you
  control every variable;
- and hand [45-OAuth](../../45-OAuth/README.md) the recipe it needs for the token leg.

This is the lab that turns "user CAs aren't trusted since API 24" from a fact you repeat into a
thing you have seen happen and un-happen.

---

## Why both forms matter

There are two ways to make a build trust your CA, they are not equivalent, and choosing between them
is a real engineering decision that this lab makes concrete.

| | Form A — debug **source set** | Form B — `<debug-overrides>` |
|---|---|---|
| Where the file lives | `app/src/debug/res/xml/` | `app/src/main/res/xml/` |
| Live when | The debug variant is built. Always | `FLAG_DEBUGGABLE` is set at runtime |
| Can it reach production? | **No.** The file is not in the release APK at all | Yes — and it does nothing there |
| Failure mode if you get it wrong | You put it in `src/main/` and ship a permissive `<base-config>` | You forget `debuggable true` and spend an hour wondering why your proxy is broken |
| What a tester sees in the release APK | Nothing | An inert `<debug-overrides>` block that scanners flag |

Form A is safer. Form B is the one you meet in the wild, and the one whose semantics generate the
most bad findings, so you need to have watched it not work.

---

## Setup

### 1. Your proxy and its CA

```bash
# host - Burp: Proxy > Proxy settings > Import/export CA certificate > Certificate in DER format
#        mitmproxy: ~/.mitm/mitmproxy-ca-cert.pem already exists after first run
openssl x509 -inform DER -in burp.der -out burp.pem
openssl x509 -in burp.pem -noout -subject -issuer -dates
```

```
subject=C = PortSwigger, ST = PortSwigger, L = PortSwigger, O = PortSwigger,
        OU = PortSwigger CA, CN = PortSwigger CA
notBefore=Aug  4 15:22:31 2014 GMT
notAfter=Aug  4 15:22:31 2035 GMT
```

Compute the filename Android's certificate stores use — the old-style OpenSSL subject hash:

```bash
# host
openssl x509 -inform PEM -subject_hash_old -in burp.pem -noout
# 9a5ba575
cp burp.pem 9a5ba575.0
```

> **Hint**
> `-subject_hash_old` (MD5-based), not `-subject_hash` (SHA-1-based). Android uses the old algorithm.
> Getting this wrong produces a certificate that sits in the directory and is never loaded, which is
> a maddening failure because nothing reports it.

### 2. Install the CA in the **user** store only

Push it and install it through the UI. Do **not** use the root path yet — the whole point of the
first half of this lab is to observe the user store being ignored.

```bash
# host
adb push burp.pem /sdcard/Download/burp.crt
```

Then on the device: **Settings → Security → Encryption & credentials → Install a certificate → CA
certificate**, accept the warning, and pick the file.

Confirm:

```bash
# host
adb shell "su -c 'ls -la /data/misc/user/0/cacerts-added/'"
# -rw-r--r-- 1 system system 939 … 9a5ba575.0
```

> **Warning — check the system store too**
> If you have ever installed a CA into the system store with a Magisk or APatch module, this lab's
> measurements are meaningless, because your CA will be trusted through the *system* path regardless
> of what the config says.
>
> ```bash
> # host
> adb shell "su -c 'mount | grep cacerts'"
> adb shell "grep -l -a PortSwigger /system/etc/security/cacerts/* 2>/dev/null"
> ```
>
> If either produces output, disable the module and reboot, or use a clean emulator for this lab.
> On the device this chapter was written against, both do — which is exactly why chapter 44 flags
> this as a methodology trap rather than a footnote.

### 3. Point the device at your proxy

```bash
# host
ip addr | grep 'inet '                       # find your host's LAN address
adb shell settings put global http_proxy 192.168.1.50:8080
adb shell settings get global http_proxy
```

Verify the proxy works at all, before involving an app:

```bash
# host - the browser should show your CA warning, or work if the CA is installed
adb shell am start -a android.intent.action.VIEW -d https://example.com
```

Restore it when you are done with the lab:

```bash
# host
adb shell settings put global http_proxy :0
```

---

## Part 1 — Build an app that makes one HTTPS request

### The minimum viable app

```
nsclab/
  app/
    src/
      main/
        AndroidManifest.xml
        java/com/pentest/nsclab/MainActivity.java
        res/
          layout/activity_main.xml
          xml/network_security_config.xml
      debug/
        res/xml/network_security_config.xml       <- created in Part 3
```

**`app/src/main/java/com/pentest/nsclab/MainActivity.java`**

```java
// app/src/main/java/com/pentest/nsclab/MainActivity.java
// A deliberately minimal HTTPS client. Everything interesting is in the
// exception, so the catch block prints the whole chain of causes.
package com.pentest.nsclab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends Activity {

    private static final String TAG = "NSCLAB";
    // Change this to your own endpoint if you prefer. Anything that returns
    // a short body over HTTPS will do.
    private static final String TARGET = "https://example.com/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        final TextView tv = new TextView(this);
        tv.setPadding(32, 64, 32, 32);
        setContentView(tv);

        new Thread(new Runnable() {
            @Override public void run() {
                final String result = fetch();
                runOnUiThread(new Runnable() {
                    @Override public void run() { tv.setText(result); }
                });
            }
        }).start();
    }

    private String fetch() {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(TARGET).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(8000);
            int code = c.getResponseCode();
            BufferedReader r = new BufferedReader(
                    new InputStreamReader(c.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            int n = 0;
            while ((line = r.readLine()) != null && n++ < 5) {
                sb.append(line).append('\n');
            }
            r.close();
            Log.i(TAG, "OK " + code);
            return "HTTP " + code + "\n\n" + sb;
        } catch (Exception e) {
            // Print every cause. The useful information is usually two or three
            // levels down, not in the top-level message.
            StringBuilder sb = new StringBuilder();
            Throwable t = e;
            int depth = 0;
            while (t != null && depth++ < 8) {
                sb.append(t.getClass().getName()).append('\n')
                  .append("    ").append(String.valueOf(t.getMessage())).append("\n\n");
                t = t.getCause();
            }
            Log.e(TAG, "FAILED\n" + sb, e);
            return "FAILED\n\n" + sb;
        } finally {
            if (c != null) { c.disconnect(); }
        }
    }
}
```

**`app/src/main/AndroidManifest.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.pentest.nsclab">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:label="NSC Lab"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

**`app/src/main/res/xml/network_security_config.xml`** — the hardened one, verbatim from
[`../examples/hardened_network_security_config.xml`](../examples/hardened_network_security_config.xml),
or this trimmed version if you would rather start small:

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

**`app/build.gradle.kts`**

```kotlin
// app/build.gradle.kts
plugins { id("com.android.application") }

android {
    namespace = "com.pentest.nsclab"
    compileSdk = 34
    defaultConfig {
        applicationId = "com.pentest.nsclab"
        minSdk = 24
        targetSdk = 34          // >= 24, so user CAs are NOT trusted by default
        versionCode = 1
        versionName = "1.0"
    }
    buildTypes {
        debug {
            isDebuggable = true          // makes <debug-overrides> live
        }
        release {
            isMinifyEnabled = false
            isDebuggable = false
        }
    }
}
```

### If you do not want Gradle

`30-Activities/examples/build.sh` implements a complete no-Gradle APK build — `aapt2 link`,
`javac --release 8`, `d8`, `zipalign`, `apksigner` — using build-tools 35.0.1, `android-35`'s
`android.jar` and a keystore it generates on the spot, and it builds **out of tree** so no `.apk`,
`.dex` or `.class` reaches the repository. Copy it and change the package name and sources.

Two things it already handles that you would otherwise rediscover painfully:

- On Git Bash, every SDK tool path needs `cygpath -w` or `aapt2` reports "failed to load XML file"
  against a file that plainly exists.
- XML comments must not contain `--`. The XML specification forbids it and `aapt2` rejects the whole
  resource.

### Build and install

```bash
# host
./gradlew assembleDebug assembleRelease
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

> **Pentester's Note — MIUI**
> On the device this chapter was written against, both `adb install` and `pm install` return
> `INSTALL_FAILED_USER_RESTRICTED` regardless of the APK, because "Install via USB" is disabled at
> the vendor level. `settings put global verifier_verify_adb_installs 0` does not help. Root does:
>
> ```bash
> # host
> adb push app-debug.apk /data/local/tmp/nsclab.apk
> adb shell "su -c 'pm install -r /data/local/tmp/nsclab.apk'"
> adb shell rm -f /data/local/tmp/nsclab.apk
> ```
>
> `30-Activities/examples/build.sh` detects this exact failure and falls back automatically.

---

## Part 2 — Watch it refuse your CA

Launch the app with the proxy on and your CA in the **user** store.

```bash
# host
adb shell am start -n com.pentest.nsclab/.MainActivity
adb logcat -s NSCLAB
```

**Expected result:**

```
FAILED

javax.net.ssl.SSLHandshakeException
    java.security.cert.CertPathValidatorException: Trust anchor for certification
    path not found.

java.security.cert.CertificateException
    java.security.cert.CertPathValidatorException: Trust anchor for certification
    path not found.

java.security.cert.CertPathValidatorException
    Trust anchor for certification path not found.
```

Read that message carefully, because it is the *specific* failure this whole chapter is about:

> **Trust anchor for certification path not found.**

The chain your proxy presented is well-formed and correctly signed. It terminates in your CA. Your CA
is on the device. It is **not in the set of anchors the app was given**, because the app
targets API 24 or later and its config asks only for `src="system"`.

Contrast it with the two other failures you might have seen:

| Message | Meaning |
|---|---|
| `Trust anchor for certification path not found` | Your CA is not in the app's anchor set. **This lab** |
| `Certificate pinning failure` / a `CertificateException` naming pin values | A live `<pin-set>` rejected the chain. Chapter 36 |
| `CLEARTEXT communication to X not permitted by network security policy` | You used `http://`, and cleartext is denied |
| Timeout, or no exception and no proxy traffic | The app is not using the proxy or not using the platform stack |

> **Checkpoint 1**
> Reproduce the failure and paste the exact message into your notes. If you got a *different* message,
> stop and work out which row of the table above you are in — the rest of the lab depends on being in
> the first one.

Confirm from inside the process that this is a trust question and not something else:

```bash
# host
frida -U -p $(adb shell pidof com.pentest.nsclab) -l ../scripts/nsc-runtime.js
```

```
  FLAG_DEBUGGABLE               : true
  networkSecurityConfigRes      : 0x7f110000
  SystemCertificateSource : 139 certificate(s)
  UserCertificateSource   : 1 certificate(s)
  <base-config> or platform default
      cleartextTrafficPermitted : false
      trust anchor sources      : SystemCertificateSource
```

**One certificate in the user store, and the app's only anchor source is the system store.** That is
the whole failure, stated by the platform itself.

---

## Part 3 — Form A: the debug source set

Create the file in `src/debug/`, **not** `src/main/`:

```xml
<!-- app/src/debug/res/xml/network_security_config.xml
     Same resource name as the main one. The manifest merger and the resource
     merger give the debug source set higher precedence for the debug variant,
     so this file REPLACES the main one there and is absent from release. -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

```bash
# host
./gradlew assembleDebug assembleRelease
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.pentest.nsclab/.MainActivity
```

**Expected result:** the request succeeds, and it appears in your proxy.

Now prove it is a *variant* difference and not luck, by auditing both APKs:

```bash
# host
python3 -B ../scripts/nsc-audit.py app/build/outputs/apk/debug/app-debug.apk --xml
python3 -B ../scripts/nsc-audit.py app/build/outputs/apk/release/app-release-unsigned.apk --xml
```

The debug APK's config contains `<certificates src="user"/>`. **The release APK's does not contain
it at all** — the file is a different file. That is the property that makes Form A safe: the
relaxation cannot reach production because it is not compiled into the release APK.

> **Checkpoint 2**
> Diff the two decoded configs and confirm they are different documents, not the same document
> interpreted differently. This is the distinction between Form A and Form B and the rest of the lab
> turns on it.

---

## Part 4 — Form B: `<debug-overrides>`

Delete `app/src/debug/res/xml/network_security_config.xml` and instead put the relaxation into the
**main** config, inside a `<debug-overrides>` block:

```xml
<!-- app/src/main/res/xml/network_security_config.xml
     ONE file, present in every variant. Whether the debug block does anything is
     decided at RUNTIME by FLAG_DEBUGGABLE. -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>

    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

```bash
# host
./gradlew assembleDebug assembleRelease
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.pentest.nsclab/.MainActivity
```

**Expected result:** the request succeeds again, and appears in your proxy — because
`isDebuggable = true` on the debug build type.

### Now the measurement that matters

Audit both APKs. **They contain the identical config file.**

```bash
# host
unzip -p app/build/outputs/apk/debug/app-debug.apk   res/xml/network_security_config.xml | sha256sum
unzip -p app/build/outputs/apk/release/app-release-unsigned.apk res/xml/network_security_config.xml | sha256sum
```

The two hashes should match. Same bytes, same resource, same everything — and yet:

```bash
# host
python3 -B ../scripts/nsc-audit.py app/build/outputs/apk/debug/app-debug.apk | grep -E '^   \[|debuggable'
#    android:debuggable           True
#    [CRITICAL] NSC-009  <debug-overrides> IS ACTIVE - the app is debuggable

python3 -B ../scripts/nsc-audit.py app/build/outputs/apk/release/app-release-unsigned.apk | grep -E '^   \[|debuggable'
#    android:debuggable           False
#    [INFO    ] NSC-010  <debug-overrides> present but INERT - the app is not debuggable
```

**Identical file, opposite verdicts, and the only difference is one manifest attribute.** That is the
fact §3.7 of the README is built on, and you have now produced it yourself rather than read it.

### Prove it at runtime, in your own release build

Sign the release APK and install it:

```bash
# host
keytool -genkeypair -keystore lab.keystore -alias lab -storepass labpass \
        -keypass labpass -keyalg RSA -keysize 2048 -validity 365 \
        -dname "CN=nsc lab, O=lab" 2>/dev/null

zipalign -p -f 4 app/build/outputs/apk/release/app-release-unsigned.apk aligned.apk
apksigner sign --ks lab.keystore --ks-pass pass:labpass --out release-signed.apk aligned.apk
adb install -r release-signed.apk
adb shell am start -n com.pentest.nsclab/.MainActivity
```

**Expected result:** the release build **fails** with `Trust anchor for certification path not
found`, from the same config file that works in the debug build.

Confirm from inside the process:

```bash
# host
frida -U -p $(adb shell pidof com.pentest.nsclab) -l ../scripts/nsc-runtime.js | head -25
```

```
  FLAG_DEBUGGABLE               : false   <-- decides whether <debug-overrides> applies AT ALL
  networkSecurityConfigRes      : 0x7f110000
  <base-config> or platform default
      cleartextTrafficPermitted : false
      trust anchor sources      : SystemCertificateSource
```

`UserCertificateSource` is **absent**. The platform parsed the `<debug-overrides>` block and built
nothing from it.

> **Checkpoint 3**
> You now have, from your own build, the evidence that makes the the professional-network app example in
> [README §3.7](../README.md#3-deep-internal-working) reportable. Save both `nsc-runtime.js` outputs.
> Two runs of the same script against the same config file, differing only in `FLAG_DEBUGGABLE`, is
> the most persuasive artefact in this chapter.

---

## Part 5 — Make the debug build ignore its own pins

Add a pin-set to the main config, with pins that are deliberately wrong:

```xml
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2030-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=</pin>
        </pin-set>
    </domain-config>
```

Keep the `<debug-overrides>` block from Part 4.

```bash
# host
./gradlew assembleDebug assembleRelease
```

Now run three experiments and predict each before you run it.

| # | Build | Proxy | CA in user store | Prediction | Result |
|---|---|---|---|---|---|
| 1 | release | off | yes | ? | |
| 2 | release | on | yes | ? | |
| 3 | debug | on | yes | ? | |

**What actually happens:**

1. **Release, no proxy: fails.** The real `example.com` certificate does not match either pin. The
   pin-set is live and the pins are wrong, so the connection is rejected. This is what a working pin
   looks like from the outside.
2. **Release, proxy on: fails.** Two independent reasons now — your CA is not an anchor, and the pins
   do not match. Only the first is reported, because trust is checked before pins.
3. **Debug, proxy on: succeeds.** Your CA is an anchor via `<debug-overrides>`, **and**
   `overridePins` defaults to `true` inside that block, so the chain terminating in your CA is exempt
   from the pin-set entirely.

> **Checkpoint 4**
> Experiment 3 is the one worth pausing on. You did not write `overridePins="true"` anywhere. The
> platform applied it because the anchor came from `<debug-overrides>`. This is why a debuggable
> release build with a debug block is a CRITICAL rather than a HIGH: it does not only add trust, it
> removes pinning.

Confirm with the runtime script that the debug build's anchor entry carries the flag:

```bash
# host
frida -U -p $(adb shell pidof com.pentest.nsclab) -l ../scripts/nsc-runtime.js \
  | grep -A4 'example.com'
```

```
  example.com   (+ all subdomains)
      cleartextTrafficPermitted : false
      trust anchor sources      : UserCertificateSource [overridePins], SystemCertificateSource [overridePins]
      pin-set                   : 2 pin(s)
```

---

## Part 6 — Prove the config beats the manifest

Add to the manifest:

```xml
    <application
        android:label="NSC Lab"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config">
```

and leave `<base-config cleartextTrafficPermitted="false">` in the config. Change `TARGET` in
`MainActivity` to an `http://` URL.

```bash
# host
./gradlew assembleRelease
# … sign and install …
adb shell am start -n com.pentest.nsclab/.MainActivity
adb logcat -s NSCLAB
```

**Expected result:**

```
FAILED

java.net.UnknownServiceException
    CLEARTEXT communication to example.com not permitted by network security policy
```

The manifest said `true`. The config said `false`. The config won.

```bash
# host
python3 -B ../scripts/nsc-audit.py release-signed.apk | grep -A6 NSC-026
```

```
   [INFO    ] NSC-026  manifest and config disagree about cleartext; the CONFIG wins
       evidence  : android:usesCleartextTraffic=true but <base-config cleartextTrafficPermitted=false>
```

and from inside the process:

```
  FLAG_USES_CLEARTEXT_TRAFFIC   : true    <-- the manifest boolean; a config OVERRIDES it
  <base-config> or platform default
      cleartextTrafficPermitted : false
```

> **Checkpoint 5**
> You have now reproduced, in a build you control, the exact situation measured in the marketplace app's shopping
> app in [README §4.6](../README.md#4-source-code-walkthrough-aosp). Any manifest-only cleartext check
> produces a false positive here.

---

## Part 7 — The tester's version: repackage an app you did not build

Everything so far assumed you control the source. Now do it the other way, on the APK from
[lab 01](lab-01-extract-a-real-config.md).

```bash
# host
apktool d -f target.apk -o work/

mkdir -p work/res/xml
cat > work/res/xml/network_security_config.xml <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
XML
```

If the app already declares a config, `apktool` will have written it to that path under its original
name — overwrite **that** file, not a new one, or the manifest will still point at the old resource.
If the app declares no config, add the attribute:

```xml
<!-- work/AndroidManifest.xml -->
<application ... android:networkSecurityConfig="@xml/network_security_config">
```

```bash
# host
apktool b work/ -o repacked.apk
zipalign -p -f 4 repacked.apk aligned.apk
apksigner sign --ks lab.keystore --ks-pass pass:labpass --out final.apk aligned.apk

# VERIFY BEFORE INSTALLING - this is the step people skip
python3 -B ../scripts/nsc-audit.py final.apk --xml
```

If the audit does not show your config, the manifest is pointing somewhere else and installing would
have wasted twenty minutes.

> **Warning**
> Re-signing changes the signing certificate, which breaks everything keyed to it: Google Sign-In,
> Play Integrity / SafetyNet, any server-side APK signature check, and App Links verification. If the
> app stops working after repackaging, that is almost always why, and it is **not a finding**. Say so
> in your notes so nobody later mistakes it for one.

> **Checkpoint 6**
> Record which route you used to get traffic. "The application's traffic was intercepted" means four
> very different things depending on whether you used the user store, the system store, a repackaged
> APK or Frida — and only the first is a finding about the app.

---

## Success criteria

- [ ] You reproduced `Trust anchor for certification path not found` with your CA installed in the
      user store and can explain, in one sentence, why the CA being present is irrelevant.
- [ ] You made the debug build work using Form A, and showed the release APK does not contain the
      relaxed file at all.
- [ ] You made the debug build work using Form B, and showed the debug and release APKs contain a
      **byte-identical** config with opposite effects.
- [ ] You captured `nsc-runtime.js` output from both variants showing `UserCertificateSource` present
      in one and absent in the other.
- [ ] You demonstrated that `<debug-overrides>` also defeats a `<pin-set>` without you writing
      `overridePins` anywhere.
- [ ] You demonstrated that the config overrides `android:usesCleartextTraffic`.
- [ ] You repackaged a third-party APK and verified the injected config **before** installing.
- [ ] Your notes state which interception route produced each result.

---

## Extension exercises

1. **Scope it properly.** Change Form A's debug config so it trusts the user store only for the one
   host you are testing, not globally. Confirm with `nsc-runtime.js` that a different host still uses
   system anchors only. This is what a competent developer would write, and being able to read the
   difference is worth more than being able to write the permissive version.

2. **A private CA.** Generate your own root, put its DER in `res/raw/lab_ca`, and write a
   `<domain-config>` that trusts **only** it for one host. Confirm the host is now unreachable through
   any public certificate. Then run `nsc-audit.py` and check that it extracts the certificate,
   computes its SPKI pin, and tells you whether your declared `<pin>` matches — deliberately declare
   one that does not, and watch it say so.

3. **A pin that actually matches.** Compute the real SPKI pin for your target host
   ([`../examples/README.md`](../examples/README.md) has the `openssl` pipeline), put it in the
   pin-set, and confirm the release build now succeeds without a proxy and fails with one.

4. **The typo.** Change `cleartextTrafficPermitted` to `cleartextTrafficPermited` in the release
   config, rebuild, and confirm that the app builds, installs, runs — and that the policy is now the
   inherited default rather than what you wrote. Then check that `nsc-audit.py` catches it as
   `NSC-021`.

5. **Hand it to chapter 45.** [45-OAuth lab 01](../../45-OAuth/labs/lab-01-intercept-the-flow.md)
   needs exactly the Part 3 or Part 4 recipe to make the token leg visible. Do that lab now, with
   your own app, and note where the authorisation leg differs because it runs in a browser.

---

## Where to go next

- [Lab 03](lab-03-prove-it-on-the-device.md) — measure the platform's behaviour rather than inferring
  it, including the claims this chapter did **not** measure.
- [Lab 04](lab-04-ctf-the-config-that-lies.md) — a config, a manifest and a runtime that disagree.
- Chapter 36 — when your CA is trusted and a live pin still stops you.
