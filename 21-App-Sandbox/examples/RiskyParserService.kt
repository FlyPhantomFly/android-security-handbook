/*
 * RiskyParserService.kt — a service that runs in a genuinely isolated process.
 *
 * WHAT IT DOES
 *   Implements IRiskyParser. When declared with android:isolatedProcess="true"
 *   it runs in a process with a throwaway UID (99000-99999, or 90000-98999 with
 *   an App Zygote), in the SELinux domain isolated_app, with every permission
 *   check denied, no network, and no data directory of its own.
 *
 *   probeSandbox() reports what it can reach, so you can diff it against the
 *   same code running in the host process. countLines() proves that it can
 *   still do useful work on data handed to it as a file descriptor.
 *
 * WHY IT MATTERS
 *   Parsers are where memory-corruption bugs live: video containers, PDFs,
 *   fonts, HTML, protobufs from an untrusted peer. If the parser runs in your
 *   app's main process and it is compromised, the attacker gets YOUR app's
 *   identity — your data directory, your granted permissions, your network
 *   access, your signed-in session.
 *
 *   The ordinary sandbox does not help, because the ordinary sandbox is a
 *   boundary BETWEEN apps and this attacker is INSIDE yours.
 *   android:isolatedProcess is the platform's answer, and it is one manifest
 *   attribute. Android relies on it for its own highest-risk code: WebView
 *   renderer processes execute page JavaScript in isolated processes, so a
 *   remote code execution bug in the JavaScript engine lands in isolated_app
 *   rather than in your app's UID.
 *
 *   The contrast with android:process is the point of the example. One word
 *   apart; an entire security boundary apart. android:process gives you a new
 *   process with the SAME UID — a crash boundary and a memory-release
 *   mechanism, and zero isolation.
 *
 *   Chapter 21 sections 3.7 and 9.2. Lab: ../labs/lab-02-isolated-process.md.
 *
 * HOW TO RUN
 *   Manifest:
 *     <service android:name=".RiskyParserService"
 *              android:isolatedProcess="true"
 *              android:exported="false" />
 *
 *   Bind it from IsolatedProbeActivity.kt, then:
 *     # host
 *     adb logcat -c
 *     adb shell am start -n com.example.sandboxlab/.IsolatedProbeActivity
 *     adb logcat -s SANDBOXPROBE:I
 *     # adb shell — confirm from outside
 *     ps -A -Z | grep sandboxlab
 *
 * REQUIREMENTS
 *   Android 8+ (API 26); useAppZygote needs Android 10 (API 29). AIDL enabled.
 *   No permissions. The host app should declare INTERNET, so that the ABSENCE
 *   of network here is attributable to isolation rather than to a missing
 *   permission — that is the control in the experiment and it is easy to forget.
 *
 * WARNING
 *   An isolated service must be android:exported="false" and must have no
 *   <intent-filter>. Isolation protects YOU from the code inside the process;
 *   exporting it lets any app on the device drive that code.
 *
 * AUTHORISED TESTING ONLY.
 */

package com.example.sandboxlab

import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.File
import java.io.FileInputStream

class RiskyParserService : Service() {

    private val binder = object : IRiskyParser.Stub() {

        override fun probeSandbox(): String = buildString {
            val uid = Process.myUid()

            appendLine("pid            = ${Process.myPid()}")
            appendLine("uid            = $uid")
            appendLine("appId          = ${uid % 100_000}")
            appendLine("isIsolated     = ${uid % 100_000 in 90_000..99_999}")
            appendLine("selinux        = ${statusFile("/proc/self/attr/current")}")

            // The kernel's record. Groups is the interesting line: no 3003.
            listOf("Uid", "Gid", "Groups", "CapBnd", "Seccomp", "NoNewPrivs").forEach { k ->
                appendLine("%-14s = %s".format(k.lowercase(), procStatus(k)))
            }

            // 1. Can we reach our HOST app's data? Expected: no. Different UID,
            //    and isolated_app has no allow rule for app_data_file at all —
            //    so even mode 0777 on that directory would not help us.
            val hostData = File("/data/data/com.example.sandboxlab")
            appendLine("hostData       = exists=${hostData.exists()} read=${hostData.canRead()}")

            // 2. Do we have a data directory of our own? Expected: no, the
            //    platform never created one for this throwaway UID.
            appendLine("filesDir       = " + attempt { filesDir.absolutePath })

            // 3. Network. The host app HOLDS android.permission.INTERNET; we do
            //    not, because we are not in AID_INET (GID 3003) and policy
            //    forbids socket creation. The failure is a KERNEL denial —
            //    EACCES from socket() — not a framework permission check.
            appendLine("network        = " + attempt {
                java.net.Socket().use { "socket created" }
            })

            // 4. PackageManager and other Binder services. Isolated processes
            //    reach only a very small allowlist.
            appendLine("packageManager = " + attempt {
                "${packageManager.getInstalledPackages(0).size} packages"
            })
            appendLine("clipboard      = " + attempt {
                getSystemService(Context.CLIPBOARD_SERVICE)?.javaClass?.simpleName ?: "null"
            })

            // 5. Shared storage.
            val ext = File("/storage/emulated/0")
            appendLine("sharedStorage  = exists=${ext.exists()} read=${ext.canRead()}")

            // 6. /proc visibility.
            appendLine("procEntries    = " +
                (File("/proc").list { _, n -> n.all(Char::isDigit) }?.size ?: -1))
        }

        /**
         * The ONLY data this process ever sees is what arrives on this
         * descriptor. We cannot open the file; we can read through a descriptor
         * the host opened, because the kernel checked permissions once — in the
         * host's process, at open() time — and does not recheck reads.
         */
        override fun countLines(pfd: ParcelFileDescriptor): Int =
            FileInputStream(pfd.fileDescriptor).bufferedReader().useLines { it.count() }
    }

    override fun onBind(intent: Intent): IBinder = binder

    // ------------------------------------------------------------------ util

    private fun statusFile(p: String) =
        runCatching { File(p).readText().trim(' ', '\n') }
            .getOrElse { "DENIED: ${it.javaClass.simpleName}" }

    private fun procStatus(key: String) = runCatching {
        File("/proc/self/status").readLines()
            .first { it.startsWith("$key:") }
            .substringAfter(':').trim()
    }.getOrElse { "unreadable" }

    /**
     * Every probe is independently guarded. A probe that lets the first denial
     * throw measures exactly one cell and loses all the others — and in an
     * isolated process almost everything denies.
     */
    private inline fun attempt(block: () -> String) =
        runCatching(block).getOrElse { "DENIED: ${it.javaClass.simpleName}: ${it.message}" }
}
