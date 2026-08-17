/*
 * examples/02-HiddenApiProbe.kt
 * ===========================================================================
 * Reach hidden framework APIs by reflection, observe the blocklist denying
 * them, and see the hidden_api_policy setting change the outcome.
 *
 * PURPOSE
 *     Section 3.8 of ../README.md describes hidden-API enforcement in the
 *     abstract. This app makes it concrete: it attempts a graded set of
 *     accesses, reports exactly which succeed and which throw, and prints the
 *     app's own targetSdk so you can see the max-target-X rule in action.
 *
 *     Run it, then flip the policy and run it again. The difference is the
 *     lesson.
 *
 * SETUP
 *     app/build.gradle.kts:
 *         android {
 *             namespace = "com.example.hiddenapiprobe"
 *             compileSdk = 35
 *             defaultConfig {
 *                 applicationId = "com.example.hiddenapiprobe"
 *                 minSdk = 26
 *                 targetSdk = 35        // <-- change this and re-run; see below
 *             }
 *         }
 *
 * USAGE
 *     ./gradlew installDebug
 *     adb shell am start -n com.example.hiddenapiprobe/.MainActivity
 *     adb logcat -s HiddenApiProbe
 *
 *     # then relax the policy and re-run
 *     adb shell settings put global hidden_api_policy 1     # JUST_WARN
 *     adb shell am force-stop com.example.hiddenapiprobe
 *     adb shell am start -n com.example.hiddenapiprobe/.MainActivity
 *     adb logcat -s HiddenApiProbe
 *
 *     # watch the platform's own denial log at the same time
 *     adb logcat | grep -i "Accessing hidden"
 *
 *     # ALWAYS reset before handing a device back
 *     adb shell settings delete global hidden_api_policy
 *
 * EXPERIMENTS WORTH RUNNING
 *     1. Policy 2 (default) vs 1 (JUST_WARN) vs 0 (DISABLED).
 *     2. targetSdk 28 vs 35, with the policy at 2. Members on a max-target-X
 *        list become reachable when your targetSdk drops to or below X.
 *        This is why some old apps still work and a rebuild breaks them.
 *     3. The same app on two devices with different Android versions. The
 *        lists change between releases.
 *
 * NOTE ON LEGITIMACY
 *     Nothing here is an exploit. Every access below is ordinary Java
 *     reflection against the framework loaded in this app's own process. The
 *     point is to observe a PLATFORM control operating, not to defeat one.
 *
 * SEE ALSO
 *     ../README.md section 3.8
 *     ../labs/lab-04-hidden-api-hunting.md
 *     art/runtime/hidden_api.cc  (the enforcement implementation)
 * ===========================================================================
 */

package com.example.hiddenapiprobe

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import java.lang.reflect.Method

private const val TAG = "HiddenApiProbe"

class MainActivity : Activity() {

    private val report = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        header()
        probeSystemProperties()
        probeActivityThread()
        probeServiceManager()
        probeApplicationInfoHiddenFields()
        probeVmRuntime()
        footer()

        val tv = TextView(this).apply {
            text = report.toString()
            textSize = 11f
            setPadding(24, 24, 24, 24)
            typeface = android.graphics.Typeface.MONOSPACE
        }
        setContentView(ScrollView(this).apply { addView(tv) })
    }

    // -----------------------------------------------------------------------
    // Reporting helpers
    // -----------------------------------------------------------------------

    private fun line(s: String) {
        Log.i(TAG, s)
        report.append(s).append('\n')
    }

    private fun header() {
        line("=".repeat(64))
        line("  HIDDEN API PROBE")
        line("=".repeat(64))
        line("  android release   : ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
        line("  device            : ${Build.MANUFACTURER} ${Build.MODEL}")
        line("  build type        : ${Build.TYPE}")
        line("  my targetSdk      : ${applicationInfo.targetSdkVersion}")
        line("  my minSdk         : ${if (Build.VERSION.SDK_INT >= 24) applicationInfo.minSdkVersion else -1}")

        // The policy setting itself. Requires no permission to READ.
        val policy = try {
            Settings.Global.getString(contentResolver, "hidden_api_policy") ?: "null (default)"
        } catch (e: Throwable) {
            "unreadable: $e"
        }
        line("  hidden_api_policy : $policy")
        line("")
        line("  policy values: 0=DISABLED  1=JUST_WARN  2=ENABLED  null=platform default")
        line("  set with: adb shell settings put global hidden_api_policy 1")
        line("  reset with: adb shell settings delete global hidden_api_policy")
        line("")
    }

    private fun footer() {
        line("")
        line("-".repeat(64))
        line("  A denial throws the ORDINARY reflection exception")
        line("  (NoSuchMethodException / NoSuchFieldException), NOT anything")
        line("  named 'denied'. That is why a hidden-API denial in a real app")
        line("  looks like a completely unrelated bug.")
        line("")
        line("  Watch the platform's own log at the same time:")
        line("      adb logcat | grep -i 'Accessing hidden'")
        line("-".repeat(64))
    }

    private fun result(what: String, block: () -> Any?) {
        try {
            val v = block()
            line("  [OK ]  $what")
            line("         -> ${v.toString().take(90)}")
        } catch (e: Throwable) {
            line("  [DENY] $what")
            line("         -> ${e.javaClass.simpleName}: ${e.message?.take(80)}")
        }
    }

    // -----------------------------------------------------------------------
    // Probe 1 — android.os.SystemProperties
    //
    // The whole class is @hide. It is on the "unsupported" list, so it is
    // usually reachable but logged. Almost every root-detection routine in
    // existence uses it, which is exactly why it is on that list rather than
    // the blocked one: too many apps depend on it.
    // -----------------------------------------------------------------------

    private fun probeSystemProperties() {
        line("--- 1. android.os.SystemProperties (@hide class) ---")

        result("Class.forName(\"android.os.SystemProperties\")") {
            Class.forName("android.os.SystemProperties").name
        }

        result("SystemProperties.get(\"ro.build.fingerprint\")") {
            val c = Class.forName("android.os.SystemProperties")
            val m: Method = c.getMethod("get", String::class.java)
            m.invoke(null, "ro.build.fingerprint")
        }

        result("SystemProperties.get(\"ro.debuggable\")") {
            val c = Class.forName("android.os.SystemProperties")
            val m: Method = c.getMethod("get", String::class.java)
            m.invoke(null, "ro.debuggable")
        }

        result("SystemProperties.set(...) — expected to fail on permissions, not the blocklist") {
            val c = Class.forName("android.os.SystemProperties")
            val m: Method = c.getMethod("set", String::class.java, String::class.java)
            m.invoke(null, "debug.hiddenapiprobe", "1")
            "set returned without throwing"
        }
        line("")
    }

    // -----------------------------------------------------------------------
    // Probe 2 — android.app.ActivityThread
    //
    // currentApplication() and currentActivityThread() are @hide but heavily
    // used by libraries (and by every Frida script), so they sit on the
    // permissive end of the lists.
    // -----------------------------------------------------------------------

    private fun probeActivityThread() {
        line("--- 2. android.app.ActivityThread (@hide members) ---")

        result("ActivityThread.currentApplication()") {
            val c = Class.forName("android.app.ActivityThread")
            c.getMethod("currentApplication").invoke(null)?.javaClass?.name
        }

        result("ActivityThread.currentActivityThread()") {
            val c = Class.forName("android.app.ActivityThread")
            c.getMethod("currentActivityThread").invoke(null)?.javaClass?.name
        }

        result("ActivityThread.currentPackageName()") {
            val c = Class.forName("android.app.ActivityThread")
            c.getMethod("currentPackageName").invoke(null)
        }
        line("")
    }

    // -----------------------------------------------------------------------
    // Probe 3 — android.os.ServiceManager
    //
    // This is the interesting one. ServiceManager is how you obtain a handle
    // to ANY registered system service, including vendor services with no
    // public SDK. It is @hide and its restriction level has tightened over
    // releases, which makes it a good marker for how strict the device is.
    //
    // See README 5.3.1 and examples/03-binder-service-probe/.
    // -----------------------------------------------------------------------

    private fun probeServiceManager() {
        line("--- 3. android.os.ServiceManager (@hide — the gateway to every service) ---")

        result("ServiceManager.listServices()") {
            val c = Class.forName("android.os.ServiceManager")
            @Suppress("UNCHECKED_CAST")
            val names = c.getMethod("listServices").invoke(null) as Array<String>
            "${names.size} services registered; first few: ${names.take(6)}"
        }

        result("ServiceManager.getService(\"package\")") {
            val c = Class.forName("android.os.ServiceManager")
            val b = c.getMethod("getService", String::class.java).invoke(null, "package")
            b?.javaClass?.name
        }

        result("IBinder.getInterfaceDescriptor() on the package service") {
            val c = Class.forName("android.os.ServiceManager")
            val b = c.getMethod("getService", String::class.java).invoke(null, "package")
            val ib = Class.forName("android.os.IBinder")
            ib.getMethod("getInterfaceDescriptor").invoke(b)
        }
        line("")
    }

    // -----------------------------------------------------------------------
    // Probe 4 — @hide fields on a public class
    //
    // ApplicationInfo is public, but several of its fields and constants are
    // @hide. This shows that the blocklist operates per MEMBER, not per class.
    // -----------------------------------------------------------------------

    private fun probeApplicationInfoHiddenFields() {
        line("--- 4. @hide MEMBERS of a PUBLIC class (per-member enforcement) ---")

        result("ApplicationInfo.privateFlags (@hide field)") {
            val f = android.content.pm.ApplicationInfo::class.java.getDeclaredField("privateFlags")
            f.isAccessible = true
            "0x" + java.lang.Integer.toHexString(f.getInt(applicationInfo))
        }

        result("ApplicationInfo.PRIVATE_FLAG_PRIVILEGED (@hide constant)") {
            val f = android.content.pm.ApplicationInfo::class.java
                .getDeclaredField("PRIVATE_FLAG_PRIVILEGED")
            f.isAccessible = true
            "0x" + java.lang.Integer.toHexString(f.getInt(null))
        }

        result("PackageManager.getPackageInfoAsUser(...) (@hide method)") {
            packageManager.javaClass.getMethod(
                "getPackageInfoAsUser",
                String::class.java, Int::class.javaPrimitiveType, Int::class.javaPrimitiveType
            ).name
        }
        line("")
    }

    // -----------------------------------------------------------------------
    // Probe 5 — dalvik.system.VMRuntime
    //
    // VMRuntime is the class hidden-API bypass libraries historically target,
    // because setHiddenApiExemptions() is itself a hidden method that disables
    // the check. Whether it is reachable is a good single indicator of how the
    // device is configured.
    // -----------------------------------------------------------------------

    private fun probeVmRuntime() {
        line("--- 5. dalvik.system.VMRuntime (the class bypass libraries target) ---")

        result("VMRuntime.getRuntime()") {
            val c = Class.forName("dalvik.system.VMRuntime")
            c.getDeclaredMethod("getRuntime").invoke(null)?.javaClass?.name
        }

        result("VMRuntime.setHiddenApiExemptions (method LOOKUP only, not invoked)") {
            val c = Class.forName("dalvik.system.VMRuntime")
            c.getDeclaredMethod("setHiddenApiExemptions", Array<String>::class.java).name
        }

        result("VMRuntime.getTargetSdkVersion()") {
            val c = Class.forName("dalvik.system.VMRuntime")
            val rt = c.getDeclaredMethod("getRuntime").invoke(null)
            c.getDeclaredMethod("getTargetSdkVersion").invoke(rt)
        }
        line("")
    }
}

/*
 * ---------------------------------------------------------------------------
 * WHAT YOU SHOULD OBSERVE
 * ---------------------------------------------------------------------------
 *
 * policy = 2 (ENABLED, the platform default), targetSdk = current
 *     Probes 1-3 mostly succeed: SystemProperties, ActivityThread and
 *     ServiceManager are on the "unsupported" list because too many real apps
 *     depend on them to block outright. You will still see
 *     "Accessing hidden ..." lines in logcat for each one.
 *     Some of probes 4-5 are denied.
 *
 * policy = 1 (JUST_WARN)
 *     Everything succeeds; every access is logged. This is the research
 *     setting, and it is the reason Frida and instrumentation behave
 *     differently after you set it.
 *
 * policy = 0 (DISABLED)
 *     Everything succeeds, silently.
 *
 * targetSdk lowered to 28, policy = 2
 *     Members on max-target-P and above become reachable that were denied at
 *     targetSdk 35. This is the compatibility mechanism: an app built against
 *     an old SDK keeps working, and rebuilding it against a new one breaks it.
 *     If a client's app "stopped working after we bumped targetSdk", this is
 *     the first thing to check.
 *
 * ---------------------------------------------------------------------------
 * THE PENTESTER'S TAKEAWAY
 * ---------------------------------------------------------------------------
 *
 *  - `settings put global hidden_api_policy 1` works over PLAIN ADB on retail
 *    devices, because the shell UID holds WRITE_SECURE_SETTINGS. No root, no
 *    userdebug build.
 *  - It is GLOBAL and PERSISTS ACROSS REBOOTS. Reset it before handing a
 *    device back, and record its value in your evidence, because it changes
 *    app behaviour.
 *  - A denial throws an ordinary reflection exception, so an app that catches
 *    broadly will just behave differently with no visible cause. When an app
 *    misbehaves inexplicably, check `logcat | grep "Accessing hidden"` before
 *    anything else.
 */
