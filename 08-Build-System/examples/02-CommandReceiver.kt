/*
 * examples/02-CommandReceiver.kt
 * ===========================================================================
 * Place at: evil-sdk/src/main/java/com/evil/sdk/CommandReceiver.kt
 *
 * PURPOSE
 *     The component that the library's manifest injects into the host app.
 *     Its only job is to PROVE, on a real device, that code shipped by a
 *     dependency runs inside the host application's security context.
 *
 *     Nothing here is an exploit. It reads its own process's identity and logs
 *     it, so that when you run
 *
 *         adb shell am broadcast -a com.evil.sdk.EXECUTE \
 *             -n com.example.host/com.evil.sdk.CommandReceiver \
 *             --es cmd "whoami"
 *         adb logcat -d -s EvilSDK
 *
 *     you see the HOST app's uid, the HOST app's package name, and the HOST
 *     app's private data directory in the output — sent there by a broadcast
 *     from a completely different application.
 *
 * evil-sdk/build.gradle.kts for this module:
 *
 *     plugins {
 *         id("com.android.library")
 *         id("org.jetbrains.kotlin.android")
 *     }
 *     android {
 *         namespace = "com.evil.sdk"
 *         compileSdk = 35
 *         defaultConfig { minSdk = 24 }
 *         compileOptions {
 *             sourceCompatibility = JavaVersion.VERSION_17
 *             targetCompatibility = JavaVersion.VERSION_17
 *         }
 *         kotlinOptions { jvmTarget = "17" }
 *     }
 *
 * and in app/build.gradle.kts:
 *
 *     dependencies { implementation(project(":evil-sdk")) }
 *
 * SEE
 *     ../README.md sections 3.10, 5.3.2, 9.2
 * ===========================================================================
 */

package com.evil.sdk

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Process
import android.util.Log
import java.io.File

class CommandReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "EvilSDK"
    }

    override fun onReceive(context: Context, intent: Intent) {

        // --- 1. Whose process is this? -------------------------------------
        // Every value below belongs to the HOST application, not to the SDK.
        // A dependency does not get its own sandbox: it shares the host's.
        val appInfo = context.applicationInfo
        Log.w(TAG, "=== injected component executing ===")
        Log.w(TAG, "  host package   = ${context.packageName}")
        Log.w(TAG, "  host uid       = ${appInfo.uid}")
        Log.w(TAG, "  my uid         = ${Process.myUid()}      (identical)")
        Log.w(TAG, "  my pid         = ${Process.myPid()}")
        Log.w(TAG, "  data dir       = ${appInfo.dataDir}")
        Log.w(TAG, "  source apk     = ${appInfo.sourceDir}")
        Log.w(TAG, "  targetSdk      = ${appInfo.targetSdkVersion}")

        // --- 2. What did the caller send? ----------------------------------
        // Extras are fully attacker-controlled. Any component that acts on
        // them without validation is where a finding lives: a URL loaded into
        // a WebView, a nested Intent passed to startActivity, a file path
        // written to, a class name reflected on.
        val cmd = intent.getStringExtra("cmd")
        val endpoint = intent.getStringExtra("endpoint")
        Log.w(TAG, "  extra cmd      = $cmd")
        Log.w(TAG, "  extra endpoint = $endpoint")
        Log.w(TAG, "  sending uid    = (see 'dumpsys package' for the caller)")

        // --- 3. What can this code reach? ----------------------------------
        // Demonstration only: list the host app's private storage. Real SDK
        // code has exactly this access, on every launch, in every app that
        // depends on it.
        val filesDir: File = context.filesDir
        val prefsDir = File(appInfo.dataDir, "shared_prefs")
        Log.w(TAG, "  filesDir       = $filesDir " +
                   "(${filesDir.listFiles()?.size ?: 0} entries)")
        Log.w(TAG, "  shared_prefs   = ${prefsDir.absolutePath} " +
                   "(${prefsDir.listFiles()?.size ?: 0} entries)")
        prefsDir.listFiles()?.forEach { f ->
            Log.w(TAG, "      would be readable: ${f.name}")
        }

        // --- 4. What this deliberately does NOT do -------------------------
        // It does not read the contents of those files, open a socket, or send
        // anything anywhere. The capability is what matters for the lesson;
        // demonstrating it does not require weaponising it. When you show this
        // to a development team, the log output above is more persuasive than
        // a working implant would be, and it is safe to run on their device.
        Log.w(TAG, "=== end ===")
    }
}
