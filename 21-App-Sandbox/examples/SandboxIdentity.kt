/*
 * SandboxIdentity.kt — print this process's complete sandbox identity.
 *
 * WHAT IT DOES
 *   Dumps everything that defines what this process is allowed to do: its UID
 *   and the arithmetic behind it, its data directories, its APK path, and then —
 *   crucially — the KERNEL's own record from /proc/self/status and
 *   /proc/self/attr/current.
 *
 * WHY IT MATTERS
 *   The framework's view (ApplicationInfo, Process.myUid()) describes what the
 *   app INTENDS. /proc describes what the kernel will actually enforce. Reading
 *   both side by side, in one output block, is the fastest way to internalise
 *   that the sandbox is not a runtime feature — it is a set of numbers in a
 *   struct cred that a privileged parent set before this code existed.
 *
 *   Three lines in the output carry most of the chapter:
 *     Groups: ... 3003 ...      GID 3003 is AID_INET. This line IS the INTERNET
 *                               permission — a Linux group, not a framework check.
 *     CapBnd: 0000000000000000  The capability BOUNDING set is empty, so no
 *                               capability can ever be acquired by any route.
 *     Seccomp: 2                SECCOMP_MODE_FILTER. Your adb shell shows 0,
 *                               which is why a shell experiment answers a
 *                               different question from an app experiment.
 *
 *   Chapter 21 section 9.1. See also ../scripts/sandbox-inspect.sh, which prints
 *   the same information from outside and annotates it.
 *
 * HOW TO RUN
 *   Drop into any app and call SandboxIdentity.dump(this) from onCreate().
 *
 *   # host
 *   adb logcat -c
 *   adb shell am start -n com.example.sandboxlab/.MainActivity
 *   adb logcat -s SANDBOXPROBE:I
 *
 * REQUIREMENTS
 *   Android 8+ (API 26). No permissions. Kotlin. Compiles against the platform
 *   SDK alone — no AndroidX, no third-party dependency. That is deliberate:
 *   this is evidence, and the fewer non-platform classes it contains, the less
 *   room there is to argue the result came from something other than the APIs
 *   any app can call.
 *
 * AUTHORISED TESTING ONLY.
 */

package com.example.sandboxlab

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Process
import android.util.Log
import java.io.File

object SandboxIdentity {

    private const val TAG = "SANDBOXPROBE"

    /** Kernel status fields that describe the sandbox. Everything else is noise. */
    private val STATUS_KEYS = listOf(
        "Uid", "Gid", "Groups",
        "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
        "Seccomp", "Seccomp_filters", "NoNewPrivs"
    )

    /** GIDs worth naming inline. The full table is in ../cheatsheet.md. */
    private val GID_NAMES = mapOf(
        1007 to "AID_LOG",
        1015 to "AID_SDCARD_RW",
        1023 to "AID_MEDIA_RW",
        3001 to "AID_NET_BT_ADMIN",
        3002 to "AID_NET_BT",
        3003 to "AID_INET  <<< THIS IS THE INTERNET PERMISSION",
        3004 to "AID_NET_RAW",
        3005 to "AID_NET_ADMIN",
        3006 to "AID_NET_BW_STATS",
        3007 to "AID_NET_BW_ACCT",
        3009 to "AID_READPROC",
        3010 to "AID_WAKELOCK",
        9997 to "AID_EVERYBODY"
    )

    fun dump(ctx: Context) {
        val uid = Process.myUid()
        val ai = ctx.applicationInfo

        line("========== FRAMEWORK VIEW ==========")
        line("package          = ${ctx.packageName}")
        line("uid              = $uid")
        line("userId           = ${uid / 100_000}     (uid / 100000)")
        line("appId            = ${uid % 100_000}     (uid % 100000)")
        line("uidClass         = ${classify(uid)}")
        line("pid              = ${Process.myPid()}")
        line("dataDir          = ${ai.dataDir}")
        line("filesDir         = ${ctx.filesDir}")
        line("cacheDir         = ${ctx.cacheDir}")
        line("codeCacheDir     = ${ctx.codeCacheDir}")
        line("noBackupFilesDir = ${ctx.noBackupFilesDir}")
        line("apk (sourceDir)  = ${ai.sourceDir}")
        line("nativeLibraryDir = ${ai.nativeLibraryDir}")
        line("targetSdkVersion = ${ai.targetSdkVersion}")
        line("device sdk       = ${Build.VERSION.SDK_INT}  (${Build.VERSION.RELEASE})")
        line("debuggable       = ${(ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0}")
        line("allowBackup      = ${(ai.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0}")
        line("externalFilesDir = ${runCatching { ctx.getExternalFilesDir(null) }.getOrNull()}")

        // Device-encrypted context. Small, readable before first unlock, and
        // therefore the first place to look for anything a developer made
        // available to Direct Boot.
        line("deviceProtected  = " + runCatching {
            ctx.createDeviceProtectedStorageContext().filesDir.absolutePath
        }.getOrElse { "unavailable: ${it.javaClass.simpleName}" })

        line("")
        line("========== KERNEL VIEW (the authoritative one) ==========")
        val status = readLines("/proc/self/status")
        if (status.isEmpty()) {
            line("could not read /proc/self/status")
        } else {
            status.filter { l -> STATUS_KEYS.any { l.startsWith("$it:") } }
                .forEach { line(it.replace(Regex("\\s+"), " ").trim()) }
        }

        // Expand the Groups line, because it is the most information-dense one.
        status.firstOrNull { it.startsWith("Groups:") }
            ?.substringAfter(':')?.trim()?.split(Regex("\\s+"))
            ?.filter { it.isNotEmpty() }
            ?.forEach { g ->
                val n = g.toIntOrNull() ?: return@forEach
                line("   gid $n  ${GID_NAMES[n] ?: derivedGidName(n)}")
            }

        line("selinux          = " + read("/proc/self/attr/current").trim(' ', '\n', '\u0000'))

        line("")
        line("========== WHAT THOSE THREE LINES MEAN ==========")
        line("Groups 3003 present -> this process can create AF_INET sockets. Absent")
        line("  -> socket() returns EACCES from the KERNEL, before any DNS lookup,")
        line("  and no amount of hooking inside this process can change that.")
        line("CapBnd all zeros    -> no capability can EVER be held by this process")
        line("  or anything it execve()s. With nosuid on /data and NoNewPrivs=1 that")
        line("  is three independent reasons a setuid binary cannot escalate here.")
        line("Seccomp 2           -> SECCOMP_MODE_FILTER. adb shell shows 0. That one")
        line("  difference is why a shell experiment cannot answer 'can an app do X'.")
    }

    // ------------------------------------------------------------------ util

    private fun classify(uid: Int): String {
        val appId = uid % 100_000
        return when {
            uid == 0                    -> "AID_ROOT"
            uid == 1000                 -> "AID_SYSTEM"
            uid == 2000                 -> "AID_SHELL (adb shell — NOT an app)"
            appId in 10_000..19_999     -> "ordinary application"
            appId in 20_000..29_999     -> "SDK sandbox; host app uid ${appId - 10_000}"
            appId in 90_000..98_999     -> "ISOLATED (App Zygote)"
            appId in 99_000..99_999     -> "ISOLATED (android:isolatedProcess)"
            else                        -> "platform/daemon uid"
        }
    }

    private fun derivedGidName(n: Int): String = when (n) {
        in 20_000..29_999 -> "derived per-app GID (20000 + appId)"
        in 50_000..59_999 -> "derived per-app shared GID (50000 + appId)"
        in 10_000..19_999 -> "an application GID"
        else              -> "(see android_filesystem_config.h)"
    }

    private fun read(path: String): String =
        runCatching { File(path).readText() }.getOrElse { "unreadable: ${it.javaClass.simpleName}" }

    private fun readLines(path: String): List<String> =
        runCatching { File(path).readLines() }.getOrElse { emptyList() }

    private fun line(s: String) = Log.i(TAG, s)
}
