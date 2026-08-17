// examples/AppIdentityProbe.kt
package com.example.probe

import android.app.Activity
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.UserHandle
import android.widget.ScrollView
import android.widget.TextView
import java.io.File

class AppIdentityProbe : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val uid = Process.myUid()
        // The arithmetic from section 3.2, done by hand so you can see it.
        val userId = uid / 100000
        val appId = uid % 100000

        val ai = applicationInfo
        val de: Context = createDeviceProtectedStorageContext()

        val report = buildString {
            appendLine("=== identity ===")
            appendLine("packageName      : $packageName")
            appendLine("uid              : $uid")
            appendLine("  userId         : $userId")
            appendLine("  appId          : $appId")
            appendLine("pid              : ${Process.myPid()}")
            appendLine("userHandle       : ${Process.myUserHandle()}")
            appendLine("isolated?        : ${appId in 90000..99999}")
            appendLine()
            appendLine("=== flags ===")
            // FLAG_DEBUGGABLE = 0x2, FLAG_ALLOW_BACKUP = 0x8000, FLAG_SYSTEM = 0x1
            appendLine("debuggable       : ${(ai.flags and 0x2) != 0}")
            appendLine("allowBackup      : ${(ai.flags and 0x8000) != 0}")
            appendLine("system app       : ${(ai.flags and 0x1) != 0}")
            appendLine("targetSdk        : ${ai.targetSdkVersion}")
            appendLine("minSdk           : ${if (Build.VERSION.SDK_INT >= 24) ai.minSdkVersion else -1}")
            appendLine()
            appendLine("=== storage ===")
            appendLine("dataDir (CE)     : ${ai.dataDir}")
            appendLine("deviceProtected  : ${ai.deviceProtectedDataDir}")
            appendLine("filesDir         : $filesDir")
            appendLine("cacheDir         : $cacheDir")
            appendLine("codeCacheDir     : $codeCacheDir")
            appendLine("noBackupFilesDir : $noBackupFilesDir")
            appendLine("DE filesDir      : ${de.filesDir}")
            appendLine("externalFilesDir : ${getExternalFilesDir(null)}")
            appendLine()
            appendLine("=== code ===")
            appendLine("sourceDir        : ${ai.sourceDir}")
            appendLine("splitSourceDirs  : ${ai.splitSourceDirs?.joinToString() ?: "(none)"}")
            appendLine("nativeLibraryDir : ${ai.nativeLibraryDir}")
            appendLine()
            appendLine("=== who else shares this uid? ===")
            val siblings = packageManager.getPackagesForUid(uid)
            appendLine(siblings?.joinToString("\n") ?: "(only this package)")
            appendLine()
            appendLine("=== what the kernel says ===")
            appendLine(readOrNull("/proc/self/status", listOf("Uid:", "Gid:", "Groups:", "TracerPid:")))
            appendLine("selinux          : ${readOrNull("/proc/self/attr/current", null).trim()}")
            appendLine("oom_score_adj    : ${readOrNull("/proc/self/oom_score_adj", null).trim()}")
        }

        setContentView(ScrollView(this).apply {
            addView(TextView(this@AppIdentityProbe).apply {
                setPadding(32, 32, 32, 32)
                textSize = 11f
                typeface = android.graphics.Typeface.MONOSPACE
                text = report
            })
        })
        android.util.Log.i("AppIdentityProbe", report)
    }

    /** Reads a /proc file, optionally keeping only lines that start with one of [prefixes]. */
    private fun readOrNull(path: String, prefixes: List<String>?): String = try {
        val lines = File(path).readLines()
        val kept = if (prefixes == null) lines else lines.filter { l -> prefixes.any { l.startsWith(it) } }
        kept.joinToString("\n")
    } catch (e: Exception) {
        "(unreadable: ${e.javaClass.simpleName})"
    }
}
