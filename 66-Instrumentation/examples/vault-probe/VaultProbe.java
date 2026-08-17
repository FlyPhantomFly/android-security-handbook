// examples/vault-probe/VaultProbe.java
//
// A bare android.app.Instrumentation. No androidx, no JUnit, no Espresso, no
// UiAutomator, no test-runner jar of any kind -- 240 lines of platform API and a
// manifest entry. It exists to answer one question with evidence:
//
//     WHAT CAN CODE DELIVERED BY `am instrument` ACTUALLY REACH?
//
// Run it with:
//
//   # host
//   adb shell am instrument -w -r \
//       com.pentest.ch66.vault.test/com.pentest.ch66.probe.VaultProbe
//
// Every finding is emitted twice: as an INSTRUMENTATION_RESULT key (machine
// readable, parsed by scripts/parse-instrumentation-results.py) and to logcat
// under the tag "ch66probe" (survives a crash, which results do not).
//
// SECTIONS OF THE REPORT
//   id.*      who am I -- pid, uid, package, process, SELinux context
//   seq.*     startup ordering: what had already run when I got control
//   read.*    the target's private state, three storage shapes
//   write.*   mutating the target's static state from inside its own process
//   cl.*      the ClassLoader chain that makes the above possible
//   deny.*    what this vantage CANNOT reach -- including things `adb shell` can
//   hidden.*  non-SDK API reachability, with and without --no-hidden-api-checks
//
// AUTHORISED TESTING ONLY. Point this at the chapter's own vault-target fixture,
// or at an application you own. Instrumenting somebody else's app is an intrusion.

package com.pentest.ch66.probe;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;

import java.io.File;
import java.util.Map;
import java.util.TreeMap;

public class VaultProbe extends Instrumentation {

    private static final String TAG = "ch66probe";
    private static final String TARGET_PKG = "com.pentest.ch66.vault";

    /** Findings, in insertion-independent alphabetical order for stable diffs. */
    private final Map<String, String> mFindings = new TreeMap<>();

    /** Captured in onCreate, i.e. BEFORE the target's Application.onCreate runs. */
    private String mSeqAtEntry = "unset";
    private long mEntryNs;

    // ----------------------------------------------------------------- entry --

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        mEntryNs = SystemClock.elapsedRealtimeNanos();
        Log.i(TAG, "Instrumentation.onCreate reached at t=" + mEntryNs);

        // Read the target's startup markers RIGHT NOW, before anything else can
        // run. Whatever is still zero at this instant had not yet executed when
        // this instrumentation took control -- and is therefore pre-emptable.
        ClassLoader cl = getContext().getClassLoader();
        mSeqAtEntry = "attachBaseContext="
                + Probes.readStaticField(cl, TARGET_PKG + ".VaultApp", "sAttachBaseContextAtNs")
                + " providerOnCreate="
                + Probes.readStaticField(cl, TARGET_PKG + ".SeedProvider", "sProviderOnCreateAtNs")
                + " applicationOnCreate="
                + Probes.readStaticField(cl, TARGET_PKG + ".VaultApp", "sApplicationOnCreateAtNs");
        Log.i(TAG, "seq@onCreate " + mSeqAtEntry);

        // start() spawns the instrumentation thread; onStart() continues there.
        // Returning from onCreate lets ActivityThread proceed to
        // callApplicationOnCreate(), so the two run concurrently -- which is why
        // onStart below explicitly waits rather than assuming.
        start();
    }

    // ------------------------------------------------------------- main body --

    @Override
    public void onStart() {
        try {
            collect();
        } catch (Throwable t) {
            Log.e(TAG, "probe failed", t);
            mFindings.put("probe.error", t.getClass().getName() + ": " + t.getMessage());
        }

        Bundle results = new Bundle();
        for (Map.Entry<String, String> e : mFindings.entrySet()) {
            results.putString(e.getKey(), e.getValue());
            Log.i(TAG, e.getKey() + " = " + e.getValue());
        }
        // finish() reports the bundle to ActivityManagerService and then kills
        // this process -- including the target application living in it.
        finish(Activity.RESULT_OK, results);
    }

    private void collect() {
        final Context testCtx = getContext();          // the TEST apk's context
        final Context targetCtx = getTargetContext();  // the TARGET apk's context
        final ClassLoader cl = testCtx.getClassLoader();

        // -- id ------------------------------------------------------------ //
        mFindings.put("id.pid", String.valueOf(Process.myPid()));
        mFindings.put("id.uid", String.valueOf(Process.myUid()));
        mFindings.put("id.contextPackage", testCtx.getPackageName());
        mFindings.put("id.targetContextPackage", targetCtx.getPackageName());
        mFindings.put("id.opPackage", targetCtx.getOpPackageName());
        mFindings.put("id.processName", String.valueOf(getProcessName()));
        mFindings.put("id.cmdline", Probes.readText("/proc/self/cmdline", 128));
        mFindings.put("id.selinux", Probes.readText("/proc/self/attr/current", 128));
        mFindings.put("id.targetDataDir", targetCtx.getApplicationInfo().dataDir);
        mFindings.put("id.testDataDir", testCtx.getApplicationInfo().dataDir);
        mFindings.put("id.targetSourceDir", targetCtx.getApplicationInfo().sourceDir);
        mFindings.put("id.testSourceDir", testCtx.getApplicationInfo().sourceDir);
        mFindings.put("id.component", String.valueOf(getComponentName()));

        // -- seq ----------------------------------------------------------- //
        mFindings.put("seq.atInstrumentationOnCreate", mSeqAtEntry);
        mFindings.put("seq.entryNs", String.valueOf(mEntryNs));

        // Now wait for the application's own startup to FINISH, so the storage
        // reads below are not racing it.
        //
        // Note which marker is waited on. sApplicationOnCreateAtNs is set on
        // ENTRY to Application.onCreate; waiting on it and then reading
        // shared_prefs returns ENOENT, which is exactly what the chapter's first
        // measured run got. sSeedCompleteAtNs is set on EXIT. Waiting for a flag
        // raised at the start of the work is waiting for nothing.
        long deadline = SystemClock.elapsedRealtime() + 10_000L;
        String appOnCreate = "0";
        String seedDone = "0";
        while (SystemClock.elapsedRealtime() < deadline) {
            appOnCreate = Probes.readStaticField(cl, TARGET_PKG + ".VaultApp",
                    "sApplicationOnCreateAtNs");
            seedDone = Probes.readStaticField(cl, TARGET_PKG + ".VaultApp",
                    "sSeedCompleteAtNs");
            if (!"0".equals(seedDone) && !seedDone.startsWith("ERROR")) {
                break;
            }
            SystemClock.sleep(25);
        }
        mFindings.put("seq.applicationOnCreateAfterWait", appOnCreate);
        mFindings.put("seq.seedCompleteAfterWait", seedDone);

        // -- read ---------------------------------------------------------- //
        SharedPreferences prefs =
                targetCtx.getSharedPreferences("vault", Context.MODE_PRIVATE);
        mFindings.put("read.prefs.api_key", String.valueOf(prefs.getString("api_key", "<absent>")));
        mFindings.put("read.prefs.refresh_token",
                String.valueOf(prefs.getString("refresh_token", "<absent>")));
        mFindings.put("read.prefs.premium", String.valueOf(prefs.getBoolean("premium", false)));

        File prefsXml = new File(targetCtx.getApplicationInfo().dataDir,
                "shared_prefs/vault.xml");
        mFindings.put("read.prefsXmlPath", prefsXml.getAbsolutePath());
        mFindings.put("read.prefsXmlBytes", Probes.probePath(prefsXml.getAbsolutePath()));

        File secret = new File(targetCtx.getFilesDir(), "secret.txt");
        mFindings.put("read.file.secretPath", secret.getAbsolutePath());
        mFindings.put("read.file.secret", Probes.readText(secret.getAbsolutePath(), 256));

        mFindings.put("read.static.sessionToken",
                Probes.readStaticField(cl, TARGET_PKG + ".VaultStore", "sSessionToken"));
        mFindings.put("read.static.premiumBefore",
                Probes.readStaticField(cl, TARGET_PKG + ".LicenseGate", "sPremium"));
        mFindings.put("read.call.isPremiumBefore",
                Probes.callStaticNoArg(cl, TARGET_PKG + ".LicenseGate", "isPremium"));

        // -- write --------------------------------------------------------- //
        mFindings.put("write.setPremium",
                Probes.writeStaticField(cl, TARGET_PKG + ".LicenseGate", "sPremium",
                        Boolean.TRUE));
        mFindings.put("write.call.isPremiumAfter",
                Probes.callStaticNoArg(cl, TARGET_PKG + ".LicenseGate", "isPremium"));

        // -- cl ------------------------------------------------------------ //
        mFindings.put("cl.testContext", Probes.classLoaderChain(testCtx.getClassLoader()));
        mFindings.put("cl.targetContext", Probes.classLoaderChain(targetCtx.getClassLoader()));
        mFindings.put("cl.same", String.valueOf(
                testCtx.getClassLoader() == targetCtx.getClassLoader()));
        mFindings.put("cl.probeOwn", Probes.classLoaderChain(VaultProbe.class.getClassLoader()));

        // -- deny ---------------------------------------------------------- //
        // Everything below is reachable from `adb shell` on this device, or
        // reachable from root, or both. From here -- inside an ordinary app UID --
        // it is not. `am instrument` buys the app's vantage and SELLS the shell's.
        mFindings.put("deny.otherAppData", Probes.probePath("/data/data/com.android.settings"));
        mFindings.put("deny.dataAdb", Probes.probePath("/data/adb"));
        mFindings.put("deny.systemXbinSu", Probes.probePath("/system/xbin/su"));
        mFindings.put("deny.procModules", Probes.probePath("/proc/modules"));
        mFindings.put("deny.procInit1Maps", Probes.probePath("/proc/1/maps"));
        mFindings.put("deny.dataLocalTmp", Probes.probePath("/data/local/tmp"));

        // -- hidden -------------------------------------------------------- //
        mFindings.put("hidden.SystemProperties.get",
                Probes.reflectHidden("android.os.SystemProperties", "get",
                        "ro.build.version.sdk"));
        mFindings.put("hidden.ServiceManager.getService",
                Probes.reflectHidden("android.os.ServiceManager", "getService", "activity"));
        // Counts, not single lookups. Re-run this instrumentation with
        // `am instrument --no-hidden-api-checks` and diff these three lines --
        // the numbers move, and the delta IS the size of the blocklist on these
        // classes for this process.
        mFindings.put("hidden.census.SystemProperties",
                Probes.memberCensus("android.os.SystemProperties", "set"));
        mFindings.put("hidden.census.ActivityThread",
                Probes.memberCensus("android.app.ActivityThread", "currentActivityThread"));
        mFindings.put("hidden.census.VMRuntime",
                Probes.memberCensus("dalvik.system.VMRuntime", "setHiddenApiExemptions"));
        mFindings.put("hidden.census.ActivityManager",
                Probes.memberCensus("android.app.ActivityManager", "getService"));

        // -- ua ------------------------------------------------------------ //
        // UiAutomation is the second half of the instrumentation privilege and
        // the half nobody talks about. getUiAutomation() returns a handle backed
        // by a connection the SYSTEM created on our behalf, and its
        // executeShellCommand() runs the command as uid 2000 (shell) -- from
        // inside a process running as uid 10210. If that works, an
        // instrumentation holds BOTH vantages at once.
        collectUiAutomation();
    }

    private void collectUiAutomation() {
        android.app.UiAutomation ua;
        try {
            ua = getUiAutomation();
        } catch (Throwable t) {
            mFindings.put("ua.available", "NO: " + t.getClass().getSimpleName()
                    + " " + t.getMessage());
            return;
        }
        if (ua == null) {
            mFindings.put("ua.available", "NO: getUiAutomation returned null");
            return;
        }
        mFindings.put("ua.available", "YES");
        mFindings.put("ua.id", String.valueOf(ua));
        mFindings.put("ua.shell.id", Probes.execShell(ua, "id"));
        mFindings.put("ua.shell.lsDataLocalTmp", Probes.execShell(ua, "ls -ld /data/local/tmp"));
        mFindings.put("ua.shell.readProcModules",
                Probes.execShell(ua, "head -c 40 /proc/modules"));
        mFindings.put("ua.shell.lsSystemXbinSu", Probes.execShell(ua, "ls -l /system/xbin/su"));
        // executeShellCommand execs the command; it does NOT hand the string to
        // a shell. A pipeline therefore produces nothing and no error. Both
        // forms are measured so the difference is on the record.
        mFindings.put("ua.shell.pipelineRaw",
                Probes.execShell(ua, "getprop | wc -l"));
        mFindings.put("ua.shell.pipelineViaSh",
                Probes.execShell(ua, "sh -c 'getprop | wc -l'"));
        mFindings.put("ua.shell.echoPlain", Probes.execShell(ua, "echo one two"));
        mFindings.put("ua.shell.echoQuoted", Probes.execShell(ua, "echo \"one two\""));
    }
}
