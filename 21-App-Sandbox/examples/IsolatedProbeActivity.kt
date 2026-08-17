/*
 * IsolatedProbeActivity.kt — the host side of the isolated-process comparison.
 *
 * WHAT IT DOES
 *   Prints the host process's own sandbox identity, then binds three services
 *   that run identical probe code in three different configurations, and prints
 *   each of their reports. Finally it hands each of them a read-only
 *   ParcelFileDescriptor for a file in the app's private storage and asks it to
 *   count the lines.
 *
 * WHY IT MATTERS
 *   Because the three reports are the experiment. Same code, three manifest
 *   declarations, three completely different sets of capability:
 *
 *     A. no attribute            same process, the app's UID
 *     B. android:process=":x"    a DIFFERENT process with the SAME UID
 *     C. android:isolatedProcess a different process with a THROWAWAY UID,
 *                                no permissions, no network, no data directory
 *
 *   B is the trap. It looks like isolation, it is named like isolation, and it
 *   provides none — the new process holds the app's UID and can open every file
 *   the main process can. Reporting "the parser runs in a separate process, so
 *   it is isolated" on the basis of android:process is a real and common
 *   mistake, in both directions: testers under-report, and developers believe
 *   they have hardened something.
 *
 *   The countLines() result is the second lesson. The isolated process cannot
 *   open ANY file, yet it successfully reads one — because a file descriptor is
 *   access that has ALREADY been granted, and the kernel does not recheck reads
 *   through it. That is what makes isolated workers usable, and it is the same
 *   mechanism behind ContentProvider.openFile() traversal (escape class 5).
 *
 *   Chapter 21 sections 3.7, 3.12 and 9.2. Lab: ../labs/lab-02-isolated-process.md.
 *
 * HOW TO RUN
 *   # host
 *   adb logcat -c
 *   adb shell am start -n com.example.sandboxlab/.IsolatedProbeActivity
 *   adb logcat -s SANDBOXPROBE:I
 *
 *   Then confirm from outside, which is the part that makes it evidence:
 *   # adb shell
 *   ps -A -o USER,PID,NAME | grep sandboxlab
 *   ps -A -Z             | grep sandboxlab
 *
 * REQUIREMENTS
 *   Android 8+ (API 26). AIDL enabled. The host must declare INTERNET so that
 *   the isolated process's lack of network is attributable to isolation rather
 *   than to a missing permission.
 *
 *   Manifest:
 *     <uses-permission android:name="android.permission.INTERNET" />
 *     <service android:name=".MainProcessService"     android:exported="false" />
 *     <service android:name=".SeparateProcessService" android:process=":worker"
 *                                                     android:exported="false" />
 *     <service android:name=".RiskyParserService"     android:isolatedProcess="true"
 *                                                     android:exported="false" />
 *
 * AUTHORISED TESTING ONLY.
 */

package com.example.sandboxlab

import android.app.Activity
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File

class IsolatedProbeActivity : Activity() {

    private val connections = mutableListOf<ServiceConnection>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // The baseline. Everything below is compared against this.
        Log.i(TAG, "########## HOST PROCESS ##########")
        SandboxIdentity.dump(this)

        // Make sure there is something to hand across the boundary.
        File(filesDir, "input.txt").apply {
            if (!exists()) writeText("alpha\nbeta\ngamma\n")
        }

        bindAndReport(MainProcessService::class.java,     "A: same process (app UID)")
        bindAndReport(SeparateProcessService::class.java, "B: android:process (SAME UID)")
        bindAndReport(RiskyParserService::class.java,     "C: android:isolatedProcess")
    }

    private fun bindAndReport(cls: Class<*>, label: String) {
        val conn = object : ServiceConnection {

            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                val parser = IRiskyParser.Stub.asInterface(service)

                Log.i(TAG, "")
                Log.i(TAG, "########## $label ##########")

                // 1. What can it reach?
                runCatching { parser.probeSandbox() }
                    .onSuccess { it.lines().forEach { l -> Log.i(TAG, l) } }
                    .onFailure { Log.i(TAG, "probeSandbox failed: $it") }

                // 2. Hand it exactly one file, read-only, and nothing else.
                //    WE open it, as the app's UID. The kernel checks permissions
                //    HERE, once. The descriptor then travels.
                runCatching {
                    ParcelFileDescriptor.open(
                        File(filesDir, "input.txt"),
                        ParcelFileDescriptor.MODE_READ_ONLY
                    ).use { pfd ->
                        Log.i(TAG, "countLines via passed FD = ${parser.countLines(pfd)}")
                    }
                }.onFailure { Log.i(TAG, "countLines failed: $it") }
            }

            override fun onServiceDisconnected(name: ComponentName) {
                Log.i(TAG, "$label disconnected")
            }
        }
        connections += conn

        val ok = bindService(Intent(this, cls), conn, Context.BIND_AUTO_CREATE)
        if (!ok) {
            // bindService returning false is a DENIAL, not an error — it is how
            // the platform reports "you may not bind this". Record it as such.
            Log.i(TAG, "$label : bindService() returned false — DENIED")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        connections.forEach { runCatching { unbindService(it) } }
    }

    companion object { private const val TAG = "SANDBOXPROBE" }
}

/*
 * The three services. Identical implementations; only the manifest differs.
 * Keeping the code identical is what makes the comparison valid.
 */

class MainProcessService : android.app.Service() {
    private val binder = object : IRiskyParser.Stub() {
        override fun probeSandbox() = ProbeShared.report(this@MainProcessService)
        override fun countLines(pfd: ParcelFileDescriptor) = ProbeShared.countLines(pfd)
    }
    override fun onBind(intent: Intent): IBinder = binder
}

class SeparateProcessService : android.app.Service() {
    private val binder = object : IRiskyParser.Stub() {
        override fun probeSandbox() = ProbeShared.report(this@SeparateProcessService)
        override fun countLines(pfd: ParcelFileDescriptor) = ProbeShared.countLines(pfd)
    }
    override fun onBind(intent: Intent): IBinder = binder
}

/** Shared so that A, B and C differ only in their manifest declaration. */
object ProbeShared {

    fun report(ctx: Context): String = buildString {
        val uid = android.os.Process.myUid()
        appendLine("pid            = ${android.os.Process.myPid()}")
        appendLine("uid            = $uid")
        appendLine("appId          = ${uid % 100_000}")
        appendLine("isIsolated     = ${uid % 100_000 in 90_000..99_999}")
        appendLine("selinux        = " + attempt {
            File("/proc/self/attr/current").readText().trim(' ', '\n')
        })
        listOf("Groups", "CapBnd", "Seccomp").forEach { k ->
            appendLine("%-14s = %s".format(k.lowercase(), procStatus(k)))
        }
        val hostData = File("/data/data/${ctx.packageName}")
        appendLine("hostData       = exists=${hostData.exists()} read=${hostData.canRead()}")
        appendLine("filesDir       = " + attempt { ctx.filesDir.absolutePath })
        appendLine("network        = " + attempt { java.net.Socket().use { "socket created" } })
        appendLine("packageManager = " + attempt {
            "${ctx.packageManager.getInstalledPackages(0).size} packages"
        })
        val ext = File("/storage/emulated/0")
        appendLine("sharedStorage  = exists=${ext.exists()} read=${ext.canRead()}")
    }

    fun countLines(pfd: ParcelFileDescriptor): Int =
        java.io.FileInputStream(pfd.fileDescriptor).bufferedReader().useLines { it.count() }

    private fun procStatus(key: String) = runCatching {
        File("/proc/self/status").readLines()
            .first { it.startsWith("$key:") }.substringAfter(':').trim()
    }.getOrElse { "unreadable" }

    private inline fun attempt(block: () -> String) =
        runCatching(block).getOrElse { "DENIED: ${it.javaClass.simpleName}: ${it.message}" }
}
