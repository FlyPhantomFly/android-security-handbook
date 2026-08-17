// examples/SelinuxProbe.java
//
// WHAT THIS IS
//   A self-contained class that reports an app's own SELinux position from
//   INSIDE the app, with no root, no Frida, and no adb. Drop it into any
//   Android project, call SelinuxProbe.report(context), and read logcat.
//
// WHY IT EXISTS
//   `adb shell` runs as u:r:shell:s0 with uid 2000, a non-empty capability
//   bounding set, and no seccomp filter. It is NOT an app. Any sentence of
//   the form "an app can do X" that was tested from an adb shell is
//   unsupported, and this is the single most common methodological error in
//   mobile security testing. This class lets you answer the question from
//   the only place where the answer is valid: the app's own process.
//
// HOW TO BUILD AND RUN
//   1. Create any empty Android app (minSdk 21+).
//   2. Copy this file into app/src/main/java/com/example/selinuxprobe/.
//   3. From your Activity.onCreate:
//          SelinuxProbe.report(this);
//   4. adb logcat -s SelinuxProbe:V
//
//   To see the denials this class provokes, in a second terminal:
//          adb logcat -d -b all | grep -a "avc:"
//   and decode them with:
//          python3 scripts/avc-decode.py denials.txt
//
// REQUIREMENTS
//   Nothing beyond the Android SDK. No permissions are declared or needed --
//   every probe here is a read that either succeeds or is refused, and being
//   refused is the interesting outcome.
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Whether a refusal was DAC or MAC. Java gives you IOException with
//     "Permission denied" for both, and there is no API that distinguishes
//     them. The class says REFUSED and tells you to correlate with an avc
//     record. Never guess.
//   - What rules the policy contains. There is no app-reachable API for
//     that, by design. An app can observe the effects of policy and nothing
//     else.
//   - Whether an operation would be refused on a different device. Vendor
//     policy differs. This measures ONE device.
//   - Whether SELinux is enforcing globally. /sys/fs/selinux/enforce is
//     world-readable on the devices tested and the class reads it, but a
//     modified kernel could lie, and a device could be enforcing globally
//     while the app's own domain is permissive. Check permissive= in the
//     audit records for the real answer.

package com.example.selinuxprobe;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.Process;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

public final class SelinuxProbe {

    private static final String TAG = "SelinuxProbe";

    /** Constants from android_filesystem_config.h. */
    private static final int AID_USER_OFFSET = 100000;
    private static final int AID_APP_START = 10000;
    private static final int AID_SDK_SANDBOX_PROCESS_START = 20000;
    private static final int AID_ISOLATED_START = 90000;

    private SelinuxProbe() { }

    // ---------------------------------------------------------------------
    // Entry point
    // ---------------------------------------------------------------------

    public static void report(Context ctx) {
        line("==========================================================");
        line(" SELinux probe -- measured from inside this app process");
        line("==========================================================");

        reportIdentity();
        reportContext();
        reportMcs();
        reportGlobalState();
        reportOwnPaths(ctx);
        reportProbes();
        reportExecuteTest(ctx);

        line("==========================================================");
        line("Now read the denials this run produced:");
        line("  adb logcat -d -b all | grep -a \"avc:\"");
        line("and decode them with scripts/avc-decode.py.");
        line("A REFUSED line above and an avc record with a matching");
        line("timestamp are the same event seen from two sides.");
        line("==========================================================");
    }

    // ---------------------------------------------------------------------
    // 1. Who am I, in DAC terms
    // ---------------------------------------------------------------------

    private static void reportIdentity() {
        int uid = Process.myUid();
        line("");
        line("--- DAC IDENTITY (21-App-Sandbox owns this layer) ---");
        line("pid                 : " + Process.myPid());
        line("uid                 : " + uid);
        line("This is the DISCRETIONARY identity. It decides file permission");
        line("bits. It is a completely separate mechanism from the context");
        line("below, and BOTH must permit an operation for it to succeed.");
    }

    // ---------------------------------------------------------------------
    // 2. Who am I, in MAC terms
    // ---------------------------------------------------------------------

    private static String readContext() {
        // /proc/self/attr/current is the kernel's own answer. There is no
        // framework API for this, and that is deliberate -- an app's context
        // is not something the framework hands out, it is something the
        // kernel already applied before the app's first instruction ran.
        String raw = readSmallFile("/proc/self/attr/current");
        if (raw == null) return null;
        // The kernel appends a NUL byte. Strip it and everything after.
        // Written as the escape \u0000 deliberately: a raw NUL byte in a
        // Java char literal is not valid source, makes the file register
        // as binary to grep, and does not survive copy-paste from a
        // rendered page. This repository shipped 17 raw C0 control bytes
        // across 9 files before a byte-level check caught them; grep reports
        // such a file only as "Binary file matches", which is why they
        // survived every earlier text-based pass.
        int nul = raw.indexOf('\u0000');
        if (nul >= 0) raw = raw.substring(0, nul);
        return raw.trim();
    }

    private static void reportContext() {
        line("");
        line("--- MAC IDENTITY (this chapter) ---");
        String ctx = readContext();
        if (ctx == null) {
            line("context             : COULD NOT READ /proc/self/attr/current");
            line("That is itself notable. On any modern Android device this");
            line("read succeeds. Investigate before assuming SELinux is off.");
            return;
        }
        line("context             : " + ctx);

        String[] f = ctx.split(":", 4);
        if (f.length >= 3) {
            line("  field 1 user      : " + f[0]
                 + "   -- always \"u\". Android defines exactly one SELinux");
            line("                        user, so this field carries no");
            line("                        information at all.");
            line("  field 2 role      : " + f[1]
                 + "   -- \"r\" for a process. Roles exist in the SELinux");
            line("                        model but Android does not use them;");
            line("                        also no information.");
            line("  field 3 TYPE      : " + f[2]);
            line("                        THIS IS THE ONE THAT MATTERS. For a");
            line("                        process the type is called the");
            line("                        DOMAIN. Every allow rule in policy is");
            line("                        written about a type. When someone");
            line("                        says \"the app runs as untrusted_app\",");
            line("                        they mean this field.");
            line("  field 4 level     : " + (f.length > 3 ? f[3] : "(absent)"));
            line("                        Sensitivity plus MCS categories.");
        }
    }

    // ---------------------------------------------------------------------
    // 3. The MCS arithmetic, predicted and checked
    // ---------------------------------------------------------------------

    private static void reportMcs() {
        line("");
        line("--- MCS CATEGORIES ---");
        int uid = Process.myUid();
        int userId = uid / AID_USER_OFFSET;
        int raw = uid % AID_USER_OFFSET;
        int appId;
        String range;
        if (raw >= AID_ISOLATED_START) {
            appId = raw - AID_ISOLATED_START;
            range = "isolated process";
        } else if (raw >= AID_SDK_SANDBOX_PROCESS_START) {
            appId = raw - AID_SDK_SANDBOX_PROCESS_START;
            range = "SDK sandbox";
        } else if (raw >= AID_APP_START) {
            appId = raw - AID_APP_START;
            range = "ordinary application";
        } else {
            appId = raw;
            range = "system/native AID";
        }

        int c0 = appId & 0xff;
        int c1 = 256 + (appId >> 8);
        int c2 = 512 + (userId & 0xff);
        int c3 = 768 + (userId >> 8);

        line("uid " + uid + " decomposes as:");
        line("  Android user id   : " + userId + "   (uid / 100000)");
        line("  raw app id        : " + raw + "   (uid % 100000)");
        line("  range             : " + range);
        line("  app id after offset: " + appId);
        line("");
        line("The encoding, from libselinux android_platform.c:");
        line("  c" + c0 + "  = appId & 0xff");
        line("  c" + c1 + "  = 256 + (appId >> 8)");
        line("  c" + c2 + "  = 512 + (userId & 0xff)");
        line("  c" + c3 + "  = 768 + (userId >> 8)");
        line("");
        String predAll = "s0:c" + c0 + ",c" + c1 + ",c" + c2 + ",c" + c3;
        String predUser = "s0:c" + c2 + ",c" + c3;
        String predApp = "s0:c" + c0 + ",c" + c1;
        line("predicted levelFrom=all  : " + predAll);
        line("predicted levelFrom=user : " + predUser);
        line("predicted levelFrom=app  : " + predApp);

        String ctx = readContext();
        String observed = null;
        if (ctx != null) {
            String[] f = ctx.split(":", 4);
            if (f.length > 3) observed = f[3];
        }
        line("observed level           : " + (observed == null ? "(none)" : observed));

        if (predAll.equals(observed)) {
            line("MATCH levelFrom=all.");
            line("  Both category pairs are present. The MLS constraint");
            line("  therefore separates this process from every OTHER app in");
            line("  the same domain -- because reading a file requires the");
            line("  subject's category set to CONTAIN the object's, and no");
            line("  other app's set contains c" + c0 + ".");
            line("  This is the mechanism behind app-vs-app isolation that");
            line("  type enforcement alone cannot provide, since every");
            line("  third-party app shares the type untrusted_app.");
        } else if (predUser.equals(observed)) {
            line("MATCH levelFrom=user.");
            line("  ONLY the user pair. Every process in this domain on this");
            line("  Android user has an IDENTICAL context. MCS does not");
            line("  separate them from each other at all; separation rests on");
            line("  DAC and on the domain's own restrictions.");
            line("  For a third-party app this indicates a LOW targetSdk --");
            line("  see the seapp_contexts ladder in the README.");
        } else if ("s0".equals(observed) || observed == null) {
            line("No categories. This domain is not category-isolated.");
        } else {
            line("NO MATCH against any levelFrom form. Either the process");
            line("started under a different uid, or a vendor seapp_contexts");
            line("rule applied. Worth investigating.");
        }
    }

    // ---------------------------------------------------------------------
    // 4. Global state, to the extent an app can see it
    // ---------------------------------------------------------------------

    private static void reportGlobalState() {
        line("");
        line("--- GLOBAL STATE (as far as an app can observe it) ---");
        String enforce = readSmallFile("/sys/fs/selinux/enforce");
        line("/sys/fs/selinux/enforce : "
             + (enforce == null ? "unreadable" : enforce.trim()));
        line("  1 = enforcing, 0 = permissive. This is the GLOBAL flag. A");
        line("  device can be globally enforcing while THIS app's domain is");
        line("  permissive, and this file will still say 1. The only way to");
        line("  tell is the permissive= field on an audit record.");

        String vers = readSmallFile("/sys/fs/selinux/policyvers");
        line("policy version          : "
             + (vers == null ? "unreadable" : vers.trim()));
        String mls = readSmallFile("/sys/fs/selinux/mls");
        line("MLS compiled in         : "
             + (mls == null ? "unreadable" : mls.trim()));
        line("  0 here would mean NO MCS categories anywhere, and app-vs-app");
        line("  isolation resting entirely on DAC. Treat as a finding.");
    }

    // ---------------------------------------------------------------------
    // 5. This app's own storage
    // ---------------------------------------------------------------------

    private static void reportOwnPaths(Context ctx) {
        line("");
        line("--- THIS APP'S OWN PATHS ---");
        ApplicationInfo ai = ctx.getApplicationInfo();
        String[] paths = {
            ai.dataDir,
            ai.sourceDir,
            ai.nativeLibraryDir,
            ctx.getFilesDir().getAbsolutePath(),
            ctx.getCacheDir().getAbsolutePath(),
            ctx.getCodeCacheDir().getAbsolutePath(),
        };
        for (String p : paths) {
            File f = new File(p);
            line(String.format("%-9s %-6s %s",
                    f.canRead() ? "readable" : "NO-READ",
                    f.canWrite() ? "write" : "ro",
                    p));
        }
        line("There is no Java API that returns a file's SELinux label. To");
        line("see the labels, run from a shell:");
        line("  adb shell run-as " + ctx.getPackageName() + " ls -Z .");
        line("(debuggable builds only), or use scripts/selinux-probe.js,");
        line("which calls lgetxattr(\"security.selinux\") directly.");
    }

    // ---------------------------------------------------------------------
    // 6. The probe set
    // ---------------------------------------------------------------------

    private static final class Probe {
        final String path;
        final String expected;
        Probe(String path, String expected) {
            this.path = path;
            this.expected = expected;
        }
    }

    private static List<Probe> probes() {
        List<Probe> p = new ArrayList<>();
        p.add(new Probe("/proc/self/attr/current",
                "OK -- your own context is always readable"));
        p.add(new Probe("/sys/fs/selinux/enforce",
                "OK -- world readable on every device tested"));
        p.add(new Probe("/sys/fs/selinux/policy",
                "REFUSED -- needs security:read_policy, which no app has"));
        p.add(new Probe("/data/system/packages.list",
                "REFUSED -- DAC 0640 system:package_info AND MAC. Both."));
        p.add(new Probe("/data/local/tmp/probe",
                "REFUSED or ABSENT -- shell_data_file; app domains have no rule"));
        p.add(new Probe("/proc/sys/kernel/randomize_va_space",
                "REFUSED -- proc_security"));
        p.add(new Probe("/proc/sys/kernel/kptr_restrict",
                "REFUSED -- proc_security"));
        p.add(new Probe("/system/etc/selinux/plat_seapp_contexts",
                "OK on most builds -- worth confirming on your target"));
        p.add(new Probe("/system/etc/selinux/plat_sepolicy.cil",
                "OK on most builds -- the whole platform policy, readable"));
        p.add(new Probe("/proc/1/attr/current",
                "REFUSED -- reading init's context needs process:getattr"));
        p.add(new Probe("/data/misc/keystore",
                "REFUSED -- keystore_data_file"));
        return p;
    }

    private static void reportProbes() {
        line("");
        line("--- ACCESS PROBE ---");
        line("Each result is a FACT about this device. A REFUSED result does");
        line("NOT tell you whether DAC or MAC refused it -- correlate with an");
        line("avc record before concluding anything.");
        for (Probe pr : probes()) {
            String verdict;
            try (FileInputStream in = new FileInputStream(pr.path)) {
                int b = in.read();
                verdict = (b >= 0 || b == -1) ? "OK      " : "ODD     ";
            } catch (FileNotFoundException e) {
                String m = String.valueOf(e.getMessage());
                if (m.contains("Permission denied") || m.contains("EACCES")) {
                    verdict = "REFUSED ";
                } else if (m.contains("No such file")) {
                    verdict = "ABSENT  ";
                } else {
                    verdict = "ERR     ";
                }
            } catch (IOException e) {
                verdict = "IOERR   ";
            }
            line(verdict + pr.path);
            line("          expected: " + pr.expected);
        }
    }

    // ---------------------------------------------------------------------
    // 7. Can this app execve a file it wrote itself?
    // ---------------------------------------------------------------------

    private static void reportExecuteTest(Context ctx) {
        line("");
        line("--- file:execute_no_trans TEST ---");
        line("Write a shell script into our own files/ directory, mark it");
        line("executable, and try to run it. DAC will permit this -- we own");
        line("the file and we set the mode. The only question is MAC.");

        File target = new File(ctx.getFilesDir(), "selinux_exec_probe.sh");
        try (FileOutputStream out = new FileOutputStream(target)) {
            out.write("#!/system/bin/sh\nexit 42\n".getBytes(Charset.forName("UTF-8")));
        } catch (IOException e) {
            line("could not write probe file: " + e);
            return;
        }
        if (!target.setExecutable(true, true)) {
            line("setExecutable failed -- the filesystem may be mounted noexec");
        }
        line("wrote  : " + target.getAbsolutePath());
        line("mode   : readable=" + target.canRead()
             + " writable=" + target.canWrite()
             + " executable=" + target.canExecute());

        try {
            java.lang.Process p = new ProcessBuilder(target.getAbsolutePath())
                    .redirectErrorStream(true).start();
            int rc = p.waitFor();
            line("EXECUTED. exit code " + rc);
            line("  This domain HAS file:execute_no_trans on app_data_file.");
            line("  On the measured Android 13 policy that is characteristic");
            line("  of untrusted_app_25 and untrusted_app_27 -- i.e. a LOW");
            line("  targetSdkVersion. On a modern targetSdk this should fail.");
        } catch (IOException e) {
            line("REFUSED: " + e.getMessage());
            line("  Expected on a modern targetSdk. untrusted_app has");
            line("  file:execute on app_data_file (so System.load of a .so in");
            line("  the data dir still works) but NOT file:execute_no_trans");
            line("  (so execve of a dropped binary does not).");
            line("  Confirm the mechanism, do not assume it:");
            line("    adb logcat -d -b all | grep -a execute_no_trans");
            line("  If no such record exists, the refusal was DAC or noexec,");
            line("  not MAC, and your finding would have named the wrong");
            line("  mechanism.");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            line("interrupted");
        } finally {
            // Leave no litter. The file is inert either way.
            if (!target.delete()) {
                line("(note: could not delete " + target + ")");
            }
        }
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    private static String readSmallFile(String path) {
        try (BufferedReader r = new BufferedReader(
                new InputStreamReader(new FileInputStream(path),
                        Charset.forName("UTF-8")))) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[512];
            int n;
            while ((n = r.read(buf)) > 0) {
                sb.append(buf, 0, n);
                if (sb.length() > 8192) break;
            }
            return sb.toString();
        } catch (IOException e) {
            return null;
        }
    }

    private static void line(String s) {
        Log.i(TAG, s);
    }
}
