/*
 * examples/03-binder-service-probe/BinderProbe.kt
 * ===========================================================================
 * Enumerate every registered Binder service and call one by raw Parcel
 * transaction — from an application that holds NO permissions at all.
 *
 * PURPOSE
 *     Section 5.3.1 of ../../README.md describes the highest-yield finding
 *     class on OEM devices: a vendor-added system service, reachable over
 *     Binder, with no permission enforcement. Reaching such a service does not
 *     require the vendor's SDK, root, or any permission. It requires:
 *
 *       1. ServiceManager.getService("<name>")   — a @hide API, reachable by
 *                                                  reflection
 *       2. the interface descriptor string       — printed by this app
 *       3. a transaction code                    — from the AIDL, or by probing
 *
 *     This app does 1 and 2 for every service on the device, then lets you do
 *     3 against a chosen target. It is the practical counterpart to
 *     ../../scripts/binder-service-enum.sh, which does the same enumeration
 *     from the host but cannot call anything.
 *
 * ====================== RULES OF ENGAGEMENT ================================
 *
 *     Only run this against a device you are AUTHORISED to test.
 *
 *     Calling an unknown service with an arbitrary transaction code can crash
 *     system_server and reboot the device. That is itself a denial-of-service
 *     finding, but make sure it is a result you intended and are permitted to
 *     produce. On a client's production handset, enumerate first (SAFE_MODE),
 *     get agreement, then probe.
 *
 *     SAFE_MODE = true (the default) enumerates ONLY. It calls nothing except
 *     IBinder.getInterfaceDescriptor(), which is a read-only metadata query
 *     that every Binder implementation supports.
 *
 * ===========================================================================
 *
 * SETUP
 *     See AndroidManifest.xml in this directory — the app declares NO
 *     permissions, deliberately. That is the point: whatever it can reach, any
 *     app on the device can reach.
 *
 *     app/build.gradle.kts:
 *         android {
 *             namespace = "com.example.binderprobe"
 *             compileSdk = 35
 *             defaultConfig {
 *                 applicationId = "com.example.binderprobe"
 *                 minSdk = 26
 *                 targetSdk = 35
 *             }
 *         }
 *
 * USAGE
 *     ./gradlew installDebug
 *
 *     # 1. Enumerate everything (safe)
 *     adb shell am start -n com.example.binderprobe/.MainActivity
 *     adb logcat -s BinderProbe
 *
 *     # 2. Probe one service (only after enumeration and authorisation)
 *     adb shell am start -n com.example.binderprobe/.MainActivity \
 *         --es service "vendor.deviceconfig" \
 *         --es iface   "com.vendor.IDeviceConfig" \
 *         --ei code    2 \
 *         --es arg     "/data/system/packages.xml" \
 *         --ez unsafe  true
 *
 * NOTE ON HIDDEN APIS
 *     ServiceManager is @hide, so this app reaches it by reflection and is
 *     subject to hidden-API enforcement (../../README.md section 3.8). On a
 *     device where it is blocked:
 *         adb shell settings put global hidden_api_policy 1
 *     and remember to reset it afterwards. That an app can be *made* to reach
 *     ServiceManager is itself worth recording in your notes.
 *
 * SEE ALSO
 *     ../../README.md sections 3.6, 5.3.1, 6.4, 9.4
 *     ../../scripts/binder-service-enum.sh
 * ===========================================================================
 */

package com.example.binderprobe

import android.app.Activity
import android.os.Bundle
import android.os.IBinder
import android.os.Parcel
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import java.lang.reflect.Method

private const val TAG = "BinderProbe"

/** Enumerate only. Call nothing. Change via the --ez unsafe true extra. */
private const val SAFE_MODE_DEFAULT = true

class MainActivity : Activity() {

    private val out = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val unsafe = intent?.getBooleanExtra("unsafe", false) ?: false
        val safeMode = SAFE_MODE_DEFAULT && !unsafe

        header(safeMode)

        val services = enumerateServices()

        if (!safeMode) {
            val name = intent?.getStringExtra("service")
            val iface = intent?.getStringExtra("iface")
            val code = intent?.getIntExtra("code", -1) ?: -1
            val arg = intent?.getStringExtra("arg")
            if (name != null && iface != null && code >= 0) {
                probeService(name, iface, code, arg)
            } else {
                line("")
                line("[!] unsafe mode requested but --es service / --es iface / --ei code")
                line("    were not all supplied. Nothing was called.")
            }
        }

        footer(safeMode, services.size)

        val tv = TextView(this).apply {
            text = out.toString()
            textSize = 10f
            setPadding(20, 20, 20, 20)
            typeface = android.graphics.Typeface.MONOSPACE
        }
        setContentView(ScrollView(this).apply { addView(tv) })
    }

    // -----------------------------------------------------------------------

    private fun line(s: String) {
        Log.i(TAG, s)
        out.append(s).append('\n')
    }

    private fun header(safeMode: Boolean) {
        line("=".repeat(70))
        line("  BINDER SERVICE PROBE")
        line("  package     : $packageName")
        line("  uid         : ${applicationInfo.uid}")
        line("  permissions : ${declaredPermissions()}")
        line("  mode        : ${if (safeMode) "SAFE (enumerate only)" else "UNSAFE (will call)"}")
        line("=".repeat(70))
        line("")
        line("  Everything this app can reach, ANY app on this device can reach.")
        line("  It holds no permissions. See ../../README.md section 5.3.1.")
        line("")
    }

    private fun declaredPermissions(): String {
        return try {
            val pi = packageManager.getPackageInfo(
                packageName, android.content.pm.PackageManager.GET_PERMISSIONS
            )
            val p = pi.requestedPermissions
            if (p == null || p.isEmpty()) "NONE" else p.joinToString(", ")
        } catch (e: Throwable) {
            "unreadable"
        }
    }

    private fun footer(safeMode: Boolean, count: Int) {
        line("")
        line("-".repeat(70))
        line("  $count services enumerated.")
        line("")
        line("  NEXT STEPS")
        line("   1. Diff this list against a stock device of the SAME release.")
        line("      Everything extra is vendor code running as UID 1000.")
        line("      (../../scripts/binder-service-enum.sh -b does this for you)")
        line("   2. For each vendor service, find the implementing class:")
        line("      decompile /system/framework/services.jar and search for")
        line("      rg -n \"extends .*[\$]Stub\" svc-src/sources/")
        line("   3. Read every public method for enforceCallingPermission /")
        line("      checkCallingPermission / Binder.getCallingUid().")
        line("   4. Hunt the confused deputy: a permission check placed AFTER")
        line("      Binder.clearCallingIdentity(). See README section 5.3.2.")
        line("   5. Anything unguarded: probe it with --ez unsafe true.")
        if (safeMode) {
            line("")
            line("  SAFE MODE: nothing was called. Re-run with --ez unsafe true")
            line("  and explicit --es service / --es iface / --ei code to probe.")
        }
        line("-".repeat(70))
    }

    // -----------------------------------------------------------------------
    // Enumeration — safe. listServices() and getInterfaceDescriptor() are
    // metadata queries; neither invokes a service method.
    // -----------------------------------------------------------------------

    private fun enumerateServices(): List<Pair<String, String>> {
        val results = mutableListOf<Pair<String, String>>()

        val smClass = try {
            Class.forName("android.os.ServiceManager")
        } catch (e: Throwable) {
            line("[!] Cannot reach android.os.ServiceManager: $e")
            line("[!] It is @hide. If this is a hidden-API denial, run:")
            line("[!]   adb shell settings put global hidden_api_policy 1")
            line("[!] and reset it afterwards. See README section 3.8.")
            return results
        }

        val listServices: Method
        val getService: Method
        try {
            listServices = smClass.getMethod("listServices")
            getService = smClass.getMethod("getService", String::class.java)
        } catch (e: Throwable) {
            line("[!] ServiceManager methods not reachable: $e")
            return results
        }

        @Suppress("UNCHECKED_CAST")
        val names = try {
            (listServices.invoke(null) as Array<String>).sorted()
        } catch (e: Throwable) {
            line("[!] listServices() failed: $e")
            return results
        }

        line("--- REGISTERED SERVICES (${names.size}) ---")
        line("")
        line(String.format("  %-38s %s", "NAME", "INTERFACE DESCRIPTOR"))
        line("  " + "-".repeat(66))

        for (name in names) {
            val descriptor = try {
                val binder = getService.invoke(null, name) as IBinder?
                binder?.interfaceDescriptor ?: "(null binder)"
            } catch (e: Throwable) {
                "(unreachable: ${e.javaClass.simpleName})"
            }
            results.add(name to descriptor)

            // Flag anything that does not look like an AOSP service name.
            val looksVendor = !name.startsWith("android.") &&
                    !name.startsWith("com.android.") &&
                    !descriptor.startsWith("android.") &&
                    !descriptor.startsWith("com.android.") &&
                    descriptor != "(null binder)"

            line(String.format("  %s%-38s %s",
                if (looksVendor) "*" else " ", name, descriptor))
        }
        line("")
        line("  (* = does not look like an AOSP service — a candidate vendor addition)")
        line("")
        return results
    }

    // -----------------------------------------------------------------------
    // Probing — UNSAFE. This actually calls a method on a system service.
    // -----------------------------------------------------------------------

    private fun probeService(name: String, iface: String, code: Int, arg: String?) {
        line("")
        line("=".repeat(70))
        line("  PROBING  service=$name")
        line("           iface=$iface")
        line("           code=$code")
        line("           arg=${arg ?: "(none)"}")
        line("=".repeat(70))
        line("")

        val binder: IBinder = try {
            val smClass = Class.forName("android.os.ServiceManager")
            val getService = smClass.getMethod("getService", String::class.java)
            (getService.invoke(null, name) as IBinder?)
                ?: run { line("[!] service '$name' is not registered"); return }
        } catch (e: Throwable) {
            line("[!] could not obtain the service: $e")
            return
        }

        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        try {
            // The interface token is MANDATORY. The server's onTransact calls
            // enforceInterface(DESCRIPTOR) and rejects the transaction without
            // it. It is a type-confusion defence, not authentication — it does
            // not prove who you are, only which interface you meant.
            // See README section 4.1 step 5.
            data.writeInterfaceToken(iface)

            if (arg != null) {
                data.writeString(arg)
            }

            line("[*] calling transact(code=$code, data=${data.dataSize()} bytes, flags=0)")
            val ok = binder.transact(code, data, reply, 0)
            line("[*] transact returned: $ok")

            // readException() throws if the server wrote an exception into the
            // reply Parcel — which is what a SecurityException looks like from
            // the client side.
            try {
                reply.readException()
                line("[*] no exception in the reply")
            } catch (se: SecurityException) {
                line("[+] SecurityException — the service ENFORCED something.")
                line("    ${se.message}")
                line("    This is the GOOD outcome. Record which permission it named.")
                return
            } catch (e: Throwable) {
                line("[*] reply exception: ${e.javaClass.simpleName}: ${e.message}")
                return
            }

            // Try to read something back. We do not know the return type, so
            // report the raw size and attempt the two most common shapes.
            line("[!] NO EXCEPTION. The call was accepted from an app with NO")
            line("[!] permissions. If this method does anything privileged,")
            line("[!] that is a local privilege escalation. See README 5.3.1.")
            line("")
            line("    reply dataSize = ${reply.dataSize()} bytes")
            if (reply.dataSize() > 0) {
                val pos = reply.dataPosition()
                try {
                    reply.setDataPosition(pos)
                    line("    as String : ${reply.readString()?.take(300)}")
                } catch (e: Throwable) { }
                try {
                    reply.setDataPosition(pos)
                    line("    as int    : ${reply.readInt()}")
                } catch (e: Throwable) { }
                try {
                    reply.setDataPosition(pos)
                    val b = ByteArray(minOf(reply.dataSize() - pos, 64))
                    reply.readByteArray(b)
                    line("    as bytes  : ${b.joinToString(" ") { "%02x".format(it) }}")
                } catch (e: Throwable) { }
            }
        } catch (e: Throwable) {
            line("[!] transact threw: ${e.javaClass.name}: ${e.message}")
            line("    A DeadObjectException here may mean the service CRASHED,")
            line("    which is itself a denial-of-service finding — check")
            line("    'adb logcat -b crash' and whether system_server restarted.")
        } finally {
            data.recycle()
            reply.recycle()
        }
    }
}

/*
 * ---------------------------------------------------------------------------
 * FINDING THE TRANSACTION CODE
 * ---------------------------------------------------------------------------
 *
 * Transaction codes are assigned by the AIDL compiler in declaration order,
 * starting at IBinder.FIRST_CALL_TRANSACTION (1). Three ways to get one:
 *
 *  1. From the AIDL, if you have the source. Count the methods.
 *
 *  2. From the generated Stub, if you have the vendor's client SDK jar:
 *         jadx -d sdk-src vendor-sdk.jar
 *         rg -n "TRANSACTION_" sdk-src/sources/
 *     This is by far the most reliable route and it gives you method names.
 *
 *  3. By observation. Attach ../../scripts/binder-trace.js to system_server
 *     with FILTER_INTERFACE set to the vendor's descriptor, then exercise the
 *     vendor's own app. Every method it calls is printed with its code. This
 *     hands you the real API of an undocumented interface for free.
 *
 * Do NOT brute-force codes against an unknown service on a client device. It
 * is the fastest way to reboot their phone.
 *
 * ---------------------------------------------------------------------------
 * INTERPRETING THE RESULT
 * ---------------------------------------------------------------------------
 *
 *   SecurityException      The service enforced something. Record the
 *                          permission it named and check that permission's
 *                          protectionLevel — `normal` on a vendor permission
 *                          is its own finding (README 5.3.3).
 *
 *   No exception           The call was accepted from a zero-permission app.
 *                          Now determine what the method DOES. If it performs
 *                          a privileged action or discloses privileged data,
 *                          you have a local privilege escalation.
 *
 *   DeadObjectException    The service may have crashed. Check whether
 *                          system_server restarted (the device UI will have
 *                          flickered). A remotely-triggerable system_server
 *                          crash from an unprivileged app is a DoS finding.
 *
 *   Nothing at all         Either the service is not registered, or SELinux
 *                          denied `find` on it. Check:
 *                              adb shell dmesg | grep avc
 *                          An SELinux denial is the layer working correctly.
 */
