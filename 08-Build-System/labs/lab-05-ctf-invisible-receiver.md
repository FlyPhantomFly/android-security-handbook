# Lab 05 — CTF: The invisible receiver

**Difficulty:** Advanced
**Time:** 2–4 hours
**Chapter:** [08 — The Android Build System](../README.md) — everything in §3.10, §3.12, §3.16, §5.3, §6

---

## The scenario

You are handed a single signed APK. No source. No repository. The client says:

> "It's a simple loyalty-card app. We've had it pentested twice. There's nothing in it."

There is a flag in it. It is reachable only through a component the developer never wrote, and its value
is not in `classes.dex`.

**Flag format:** `FLAG{...}`

---

## Rules

- Static and dynamic analysis of the provided APK only.
- Do not attack any network service. The app's endpoints are non-routable placeholders.
- The flag is recoverable **without** modifying and re-signing the APK, though doing so is a valid
  alternative route and is worth attempting afterwards for practice.

---

## Building the challenge

This lab ships as a recipe rather than a binary, so you can build it, break it, and then read exactly
how it was constructed. **Have someone else build it for you if you can** — the challenge is much better
if you have not seen the source.

<details>
<summary><b>Challenge construction (spoilers — do not open if you are solving it)</b></summary>

Create a two-module project: `app` (the loyalty-card application) and `analytics-sdk` (a library).

**`analytics-sdk/src/main/AndroidManifest.xml`** — injects a receiver the app developer never wrote:

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
          package="com.metrics.collect">
    <application>
        <receiver
            android:name="com.metrics.collect.ConfigReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.metrics.collect.RELOAD_CONFIG" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

**`analytics-sdk/src/main/java/com/metrics/collect/ConfigReceiver.kt`**:

```kotlin
package com.metrics.collect

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class ConfigReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // The receiver reads a config key name from an attacker-controlled
        // extra and resolves it as a STRING RESOURCE. The value therefore
        // lives in resources.arsc, never in classes.dex.
        val key = intent.getStringExtra("config_key") ?: "default_endpoint"
        val id = context.resources.getIdentifier(key, "string", context.packageName)
        if (id == 0) {
            Log.i("Metrics", "unknown config key: $key")
            return
        }
        val value = context.resources.getString(id)
        Log.i("Metrics", "config[$key] = $value")
    }
}
```

**`app/build.gradle.kts`** — the flag is injected as a *resource*, not a BuildConfig field:

```kotlin
android {
    defaultConfig {
        // resValue lands in resources.arsc. A `strings classes.dex` search
        // will never find it; only the integer resource ID is in the DEX.
        resValue("string", "diagnostic_support_token",
                 "FLAG{merged_manifest_plus_arsc_equals_findings}")
        resValue("string", "default_endpoint", "https://metrics.invalid/v1")
        buildConfigField("String", "API_BASE", "\"https://api.invalid/\"")
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false     // keep the unreferenced string
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
            signingConfig = signingConfigs.getByName("debug")  // any key; identity is not the point
        }
    }
}
dependencies { implementation(project(":analytics-sdk")) }
```

The app itself never references `diagnostic_support_token`. Build with
`./gradlew :app:assembleRelease` and hand over the APK only.

Difficulty knobs:
- Rename the resource to something dull (`str_cfg_7`) so keyword grepping fails.
- Set `isShrinkResources = true` and add a `res/raw/keep.xml` with
  `tools:keep="@string/diagnostic_support_token"` so the resource survives shrinking without being
  referenced from code.
- Split the flag across two resources that the receiver concatenates.

</details>

---

## Guided route (use only if you are stuck)

Work through these in order. Stop reading as soon as you have a lead.

<details>
<summary><b>Hint 1 — where to start</b></summary>

Do not open JADX first. Establish what the artefact *is*:

```bash
# host
aapt2 dump badging challenge.apk
apksigner verify --verbose --print-certs challenge.apk
unzip -p challenge.apk META-INF/com/android/build/gradle/app-metadata.properties
unzip -l challenge.apk | grep -oE "META-INF/[a-zA-Z0-9_.-]+\.version"
```

You now know the AGP version, the signing identity, whether it is debuggable, and roughly which
libraries are present.
</details>

<details>
<summary><b>Hint 2 — the component surface is not what you think</b></summary>

```bash
# host
apktool d -f challenge.apk -o out/
grep -nE 'android:exported="true"' out/AndroidManifest.xml
```

Look at the **package names** of the exported components. Any component whose package does not match
the application's own package came from a dependency, via the manifest merger. That is a component the
app's developers never wrote, have never read, and cannot patch.

See [§3.10](../README.md#310-the-manifest-merger-in-depth).
</details>

<details>
<summary><b>Hint 3 — read what the injected component does</b></summary>

```bash
# host
jadx -d src --deobf challenge.apk
grep -rn --include=*.java "getIdentifier" src/sources/ | head
```

`Resources.getIdentifier(name, "string", package)` resolves a **runtime string** to a resource ID. If
the name comes from an `Intent` extra, then the caller — you — chooses which resource is read.

Note what that implies: the interesting value is in `resources.arsc`, not in `classes.dex`. A
`strings classes.dex | grep FLAG` will find nothing, and that is by design.
</details>

<details>
<summary><b>Hint 4 — enumerate the resource table</b></summary>

```bash
# host
aapt2 dump resources challenge.apk > res.txt
wc -l res.txt
grep -nE "^\s+resource 0x[0-9a-f]+ string/" res.txt | head -60

# or, from the apktool output
cat out/res/values/strings.xml
```

Every string resource in the app is listed here, including ones no code references.
See [§3.16](../README.md#316-resources-aapt2-compile-and-link).
</details>

<details>
<summary><b>Hint 5 — reach the component</b></summary>

```bash
# host
adb install -r challenge.apk
adb logcat -c

# adb shell
am broadcast -a com.metrics.collect.RELOAD_CONFIG \
   -n <applicationId>/com.metrics.collect.ConfigReceiver \
   --es config_key "<resource_name_from_hint_4>"
```

```bash
# host
adb logcat -d -s Metrics
```
</details>

<details>
<summary><b>Hint 6 — the fully static route</b></summary>

You never actually needed the device. The value is in the resource table:

```bash
# host
aapt2 dump resources challenge.apk | grep -A2 -iE "token|diagnostic|flag|support"
```

Both routes are valid, and doing both is the point: the static route is faster, and the dynamic route
is what you would use if the value were assembled at runtime.
</details>

---

## Solution structure (spoilers)

<details>
<summary><b>Full walkthrough</b></summary>

1. **Fingerprint the APK.** `aapt2 dump badging` gives the package, `targetSdk` and the debuggable
   flag. `app-metadata.properties` gives the AGP version. `META-INF/*.version` gives library versions.

2. **Enumerate the exported surface.** `apktool d` and grep for `exported="true"`. Notice
   `com.metrics.collect.ConfigReceiver` — a package that is not the application's own. It arrived
   through the manifest merger from a dependency.

3. **Read the injected component.** JADX shows `ConfigReceiver.onReceive` calling
   `Resources.getIdentifier` with a string from `intent.getStringExtra("config_key")`. The caller
   controls which resource is read.

4. **Realise where the value lives.** `getIdentifier` resolves against `resources.arsc`. The DEX
   contains only integer IDs. This is why a DEX string search fails, and it is the trap the challenge
   is built around.

5. **Enumerate string resources.** `aapt2 dump resources` (or `out/res/values/strings.xml` from
   apktool) lists every string, including ones nothing references.

6. **Recover the flag**, either statically from the resource dump, or dynamically by broadcasting to
   the receiver with the resource name as `config_key` and reading logcat.

**The lesson, stated plainly:** two previous pentests missed this because they looked at
`classes.dex` and at the developer's source. The finding lived in a component that arrived via the
manifest merger and a value that lived in `resources.arsc`. Both are build-system artefacts, and both
are covered by a five-second command that most testers do not run.

</details>

---

## Success criteria

- [ ] You recovered `FLAG{...}`.
- [ ] You can name which dependency injected the receiver, and how you determined that.
- [ ] You can explain why `strings classes.dex | grep FLAG` returns nothing.
- [ ] You recovered the flag **both** statically and dynamically.
- [ ] You wrote the remediation as code: the `tools:` marker that removes the receiver, and the reason
      the resource should not have existed either.

---

## Write it up

Produce a finding as you would deliver it to the client, containing:

1. **Title** — precise, naming the mechanism rather than the symptom.
2. **Component provenance** — which dependency, at which version, injected the receiver, and how you
   established it (the merger report if you had the source; the package name if you did not).
3. **Reproduction** — the exact `am broadcast` command.
4. **Impact** — what an arbitrary app on the device can read, and why the resource table is not a
   secure store.
5. **Severity, with reasoning** — use the table in
   [§5.3.2](../README.md#532-an-sdk-injected-exported-component) and defend your rating.
6. **Remediation as code** — the `tools:node="remove"` element, plus the argument that the token should
   never have been a `resValue` in the first place.
7. **Prevention** — the build-time gate from [`../examples/03-SecurityGatePlugin.kt`](../examples/03-SecurityGatePlugin.kt),
   so the next SDK upgrade that injects a component fails the pull request rather than the pentest.

---

## Extension challenges

1. **Rebuild the flag out.** Use `apktool b` and `apksigner` to produce a version with the receiver
   removed and the resource deleted. Confirm the broadcast now fails and the string is gone from
   `resources.arsc`.
2. **Make it harder.** Split the flag across two resources concatenated at runtime, then solve your own
   challenge dynamically with [`../scripts/dump-build-config.js`](../scripts/dump-build-config.js).
3. **Turn it into a bundle.** Build the same app as an AAB, install it with `bundletool`, and repeat the
   analysis using only `base.apk`. Note what you would have missed, and connect that to §3.19.
