/*
 * AttackerProbe.kt — what an ordinary app can actually reach of another app.
 *
 * WHAT IT DOES
 *   A deliberately nosy object, meant to be dropped into an app that declares no
 *   dangerous permissions. It enumerates, one category at a time, what the
 *   sandbox lets it touch: other apps' private data directories, their shipped
 *   APKs, their exported ContentProviders, shared storage, /proc, and how much
 *   of the package list is visible at all.
 *
 *   Every "DENIED" line is the sandbox doing its job. Every "OK" line is
 *   something the sandbox was never designed to stop — read those carefully,
 *   because that is where the findings are.
 *
 * WHY IT MATTERS
 *   `adb shell` runs as UID 2000 in the SELinux domain `shell`, with no seccomp
 *   filter, a non-empty capability bounding set, and supplementary groups no
 *   application holds. A file you read or a provider you queried from a shell is
 *   NOT thereby proven reachable by an attacker.
 *
 *   This code runs as an ordinary app: a UID in the 10000+ range, the
 *   `untrusted_app` SELinux domain with its own MCS categories, `Seccomp: 2`,
 *   and an empty capability set. So what it can do, a malicious app can do —
 *   which is the only experiment that supports the sentence "any app the user
 *   installs can do this".
 *
 *   Chapter 21 section 9.3. Lab: ../labs/lab-03-attacker-app.md.
 *   The buildable, standalone version with a five-verdict vocabulary is in
 *   ./attacker-app/ — prefer that for real work; this file is the readable
 *   version for the chapter text.
 *
 * HOW TO RUN
 *   Drop into an app whose manifest declares a <queries> block naming the target
 *   (see ./attacker-app/AndroidManifest.xml — omitting it silently invalidates
 *   the whole run), then call AttackerProbe.run(this) from onCreate().
 *
 *   # host
 *   adb logcat -c
 *   adb shell am start -n com.attacker.sandboxprobe/.ProbeActivity
 *   adb logcat -s ATTACKER:W
 *
 * REQUIREMENTS
 *   Android 5.0+ (API 21). NO permissions at all — not even INTERNET is needed
 *   for anything here. Kotlin, platform SDK only, no dependencies.
 *
 * WARNING
 *   Build and install this only on a device you own or are explicitly authorised
 *   to test. Running code that enumerates other applications' data on someone
 *   else's device is, depending on jurisdiction, a criminal offence regardless
 *   of intent. Keep it off the Play Store; it would be flagged, correctly, as a
 *   Potentially Harmful Application.
 */

package com.example.attacker

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Process
import android.util.Log
import java.io.File

/**
 * A deliberately nosy app. Declares no permissions. Reports exactly what it can
 * reach. Every "DENIED" line is the sandbox doing its job; every "OK" line is
 * something the sandbox was never designed to stop.
 */
object AttackerProbe {

    private const val TAG = "ATTACKER"

    fun run(ctx: Context) {
        Log.w(TAG, "attacker uid = ${Process.myUid()}  pkg = ${ctx.packageName}")
        Log.w(TAG, "appId = ${Process.myUid() % 100_000}   " +
                "(ordinary app range is 10000-19999)")
        Log.w(TAG, "selinux = " + runCatching {
            File("/proc/self/attr/current").readText().trim(' ', '\n')
        }.getOrDefault("?"))
        Log.w(TAG, "seccomp = " + procStatus("Seccomp") +
                "   (2 = filtered. Your adb shell shows 0.)")
        Log.w(TAG, "capBnd  = " + procStatus("CapBnd") +
                "   (all zeros = no capability can ever be acquired)")
        Log.w(TAG, "Those four lines are what makes everything below meaningful: " +
                "they are the constraints of any app the user installs.")

        probeDirectAccess(ctx)
        probeApkReadability(ctx)
        probeExportedProviders(ctx)
        probeSharedStorage(ctx)
        probeProcFs()
        probePackageVisibility(ctx)

        Log.w(TAG, "")
        Log.w(TAG, "=== NOW RUN THE OTHER EXPERIMENT ===")
        Log.w(TAG, "Repeat every check from adb shell and put the two columns side " +
                "by side. Where they differ, THIS column is the honest one for a " +
                "claim about apps. The difference between the columns is the finding.")
    }

    /** 1. The classic: can we open another app's private files? */
    private fun probeDirectAccess(ctx: Context) {
        Log.w(TAG, "=== 1. direct filesystem access to other apps ===")
        val pm = ctx.packageManager
        for (app in pm.getInstalledApplications(0).take(25)) {
            if (app.packageName == ctx.packageName) continue
            val dir = File(app.dataDir)
            val prefs = File(app.dataDir, "shared_prefs")
            Log.w(TAG, "%-42s uid=%-8d dir.exists=%-5s dir.read=%-5s prefs.list=%s".format(
                app.packageName, app.uid, dir.exists(), dir.canRead(),
                prefs.list()?.size?.toString() ?: "null"))
        }
        Log.w(TAG, "   Expect false everywhere. The directory is mode 0700 owned by")
        Log.w(TAG, "   the app's UID, and the MISSING EXECUTE BIT means we cannot even")
        Log.w(TAG, "   traverse into it to stat() a file — so a careless 0666 file")
        Log.w(TAG, "   inside is still unreachable by us. SELinux MCS categories deny")
        Log.w(TAG, "   it a second time, independently.")
        Log.w(TAG, "   If any line reads TRUE, check for android:sharedUserId first:")
        Log.w(TAG, "     adb shell dumpsys package <pkg> | grep -i sharedUser")
    }

    /** 2. The surprise: APKs are world-readable. */
    private fun probeApkReadability(ctx: Context) {
        Log.w(TAG, "=== 2. other apps' APKs ===")
        val pm = ctx.packageManager
        for (app in pm.getInstalledApplications(0).take(10)) {
            if (app.packageName == ctx.packageName) continue
            val apk = File(app.sourceDir)
            Log.w(TAG, "%-42s apk.read=%-5s size=%d".format(
                app.packageName, apk.canRead(), if (apk.canRead()) apk.length() else -1))
        }
        Log.w(TAG, "   TRUE here is not a vulnerability — it is the design. The APK is")
        Log.w(TAG, "   mode 0644 owned by system, and PackageManager hands out its path.")
        Log.w(TAG, "   The CONSEQUENCE is the finding: everything shipped inside an APK")
        Log.w(TAG, "   is public. Any BuildConfig field, string resource, asset or")
        Log.w(TAG, "   bundled .so has been published to every user and every app.")
    }

    /** 3. The real attack path: doors the developers opened. */
    private fun probeExportedProviders(ctx: Context) {
        Log.w(TAG, "=== 3. exported content providers, queried with no permissions ===")
        val pm = ctx.packageManager
        val pkgs = pm.getInstalledPackages(PackageManager.GET_PROVIDERS)
        for (pkg in pkgs) {
            val providers = pkg.providers ?: continue
            for (p in providers) {
                if (!p.exported) continue
                if (p.readPermission != null) {
                    // NOT necessarily protected. A custom permission with
                    // protectionLevel="normal" is granted silently to any app
                    // that asks. Check the level before believing it.
                    Log.i(TAG, "guarded  ${p.authority}  (needs ${p.readPermission} " +
                            "— check its protectionLevel)")
                    continue
                }
                val uri = Uri.parse("content://${p.authority}")
                val result = runCatching {
                    ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
                        "rows=${c.count} cols=${c.columnNames.joinToString(",")}"
                    } ?: "null cursor — path may not match the UriMatcher, NOT a denial"
                }.getOrElse { "DENIED: ${it.javaClass.simpleName}" }
                Log.w(TAG, "OPEN     ${p.authority}  ->  $result")
            }
        }
        Log.w(TAG, "   This is where real findings come from. An OPEN line means any")
        Log.w(TAG, "   installed app reads that data with no permission, no prompt and")
        Log.w(TAG, "   no user interaction. Then test openFile() with ../ segments —")
        Log.w(TAG, "   a traversal there grants the TARGET's entire read authority,")
        Log.w(TAG, "   because the target opens the file itself and the kernel checks")
        Log.w(TAG, "   permissions once, at open(), in the OPENING process.")
        Log.w(TAG, "   See ../labs/lab-04-exported-components.md.")
    }

    /** 4. Data other apps put outside their own sandbox. */
    private fun probeSharedStorage(ctx: Context) {
        Log.w(TAG, "=== 4. shared storage ===")
        listOf(
            "/storage/emulated/0",
            "/storage/emulated/0/Download",
            "/storage/emulated/0/Documents",
            "/storage/emulated/0/DCIM",
            "/storage/emulated/0/Android/data",
            "/storage/emulated/0/Android/obb",
            "/data/local/tmp"
        ).forEach { path ->
            val f = File(path)
            Log.w(TAG, "%-40s exists=%-5s read=%-5s entries=%s".format(
                path, f.exists(), f.canRead(), f.list()?.size?.toString() ?: "null"))
        }
        // Our own app-specific external dir needs no permission at all.
        Log.w(TAG, "own external files dir = ${ctx.getExternalFilesDir(null)}")
        Log.w(TAG, "   /data/local/tmp is DENIED to us and freely writable from adb")
        Log.w(TAG, "   shell. That single row is this chapter's methodological")
        Log.w(TAG, "   argument in one line.")
        Log.w(TAG, "   Anything a target wrote to shared storage has LEFT its sandbox")
        Log.w(TAG, "   permanently: it survives the target's uninstall and can be")
        Log.w(TAG, "   inherited by whatever app later gets the recycled appId.")
    }

    /** 5. /proc — historically a rich side channel, now largely closed. */
    private fun probeProcFs() {
        Log.w(TAG, "=== 5. /proc visibility ===")
        val visible = File("/proc").list { _, n -> n.all(Char::isDigit) }?.size ?: -1
        Log.w(TAG, "numeric entries visible in /proc = $visible  (own threads only on API 29+)")
        listOf("/proc/net/tcp", "/proc/net/arp", "/proc/1/status", "/proc/self/status",
               "/data/system/packages.list").forEach {
            val f = File(it)
            Log.w(TAG, "%-30s exists=%-5s read=%-5s".format(it, f.exists(), f.canRead()))
        }
        Log.w(TAG, "   From Android 10, /proc is hardened so an app sees only its OWN")
        Log.w(TAG, "   processes. AID_READPROC (GID 3009) lifts this and no ordinary")
        Log.w(TAG, "   app has it. A closed side channel — note the closure rather")
        Log.w(TAG, "   than reporting it.")
    }

    /** 6. Package visibility — what can we even see? */
    private fun probePackageVisibility(ctx: Context) {
        Log.w(TAG, "=== 6. package visibility ===")
        val all = ctx.packageManager.getInstalledApplications(0)
        val third = all.count { (it.flags and ApplicationInfo.FLAG_SYSTEM) == 0 }
        Log.w(TAG, "packages visible = ${all.size}  (third-party: $third)")
        Log.w(TAG, "targetSdk = ${ctx.applicationInfo.targetSdkVersion} " +
                "— on 30+ without <queries> or QUERY_ALL_PACKAGES this list is FILTERED")
        Log.w(TAG, "   Filtering is a PRIVACY control, not a security boundary: it")
        Log.w(TAG, "   never makes an exported component unreachable, it only hides it")
        Log.w(TAG, "   from apps that did not ask. But if YOUR manifest forgot the")
        Log.w(TAG, "   <queries> block, every result above is a self-inflicted false")
        Log.w(TAG, "   negative and looks exactly like absence.")
    }

    private fun procStatus(key: String) = runCatching {
        File("/proc/self/status").readLines()
            .first { it.startsWith("$key:") }.substringAfter(':').trim()
    }.getOrElse { "unreadable" }
}

/*
 * =====================================================================
 * THE EXPECTED SHAPE OF THE RESULT ON A MODERN DEVICE
 * =====================================================================
 *
 *   Probe                        Expected                  What it teaches
 *   ---------------------------  ------------------------  ---------------------------
 *   1. Direct filesystem access  dir.read=false everywhere  The sandbox works
 *   2. APK readability           apk.read=true              It does not hide code
 *   3. Exported providers        a few OPEN lines           Where real findings are
 *   4. Shared storage            Android/data blocked       Scoped storage in action
 *   5. /proc                     own processes only         A side channel that closed
 *   6. Package visibility        short list on API 30+      The metadata sandbox
 *
 * READING THE OUTPUT
 *   Every DENIED is the sandbox doing its job — and those rows belong in a
 *   report too, because ruling things out is part of the work and a report that
 *   also says what is SAFE is far more credible than one that only lists
 *   problems.
 *
 *   Every OK is something the sandbox was never designed to stop. For each one,
 *   do the part no tool does for you: WALK THE REACH-THROUGH. What can you make
 *   that thing do that you could not do directly? A door is only as serious as
 *   the room behind it. An exported provider returning a version string is Low;
 *   one returning the credential store is High.
 *
 * BUILD IT AT TWO TARGET SDK LEVELS
 *   Half the platform's mitigations are targetSdk-gated. Build the TARGET at
 *   targetSdk 28 and at targetSdk 34 and run this against both. The rows that
 *   change are exactly your version-conditional findings, and knowing which
 *   those are is the difference between a report that survives review and one
 *   that does not.
 */
