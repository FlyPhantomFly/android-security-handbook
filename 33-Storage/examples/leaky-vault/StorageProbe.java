// examples/leaky-vault/StorageProbe.java
//
// A MEASUREMENT INSTRUMENT, not a vulnerability.
//
// Everything chapter 33 says about scoped storage, FUSE and the sandbox is a
// claim about what an ordinary app can and cannot do. This class is how those
// claims get tested from inside an ordinary app, on whatever device you are
// holding, instead of being read off a documentation page written about a
// different API level.
//
// It prints, to logcat under the tag CH33Probe and to a file you can pull:
//
//   * every storage root this Context can name, with the value the framework
//     actually returns rather than the path you expect;
//   * whether each one exists, is readable, is writable;
//   * the result of trying to read ANOTHER app's app-specific external
//     directory -- the API 30 scoped-storage restriction, tested rather than
//     asserted;
//   * the result of trying to read another app's private data directory,
//     which should fail at both the DAC and the SELinux layer;
//   * the result of trying to read a WORLD-READABLE file belonging to another
//     app, which is the interesting case: DAC permits it and MAC may not;
//   * whether MediaStore will hand this app rows describing other apps' files.
//
// Every probe prints PASS/FAIL in terms of what was OBSERVED, never in terms of
// what should have happened. A probe that fails to fail is the finding.
//
// Run it:
//     adb shell am start -n com.pentest.ch33.vault/.VaultActivity
//     adb logcat -s CH33Probe:V
// or pull the report:
//     adb shell "su -c 'cat /data/user/0/com.pentest.ch33.vault/files/probe.txt'"
//
// Compile: see examples/build.sh.

package com.pentest.ch33.vault;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

public class StorageProbe {

    private static final String TAG = "CH33Probe";

    private final Context ctx;
    private final List<String> lines = new ArrayList<String>();

    public StorageProbe(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    private void say(String s) {
        Log.i(TAG, s);
        lines.add(s);
    }

    public String run() {
        lines.clear();
        say("================================================================");
        say(" storage probe -- " + ctx.getPackageName());
        say("================================================================");
        say(String.format("  device      %s %s", Build.MANUFACTURER, Build.MODEL));
        say(String.format("  release     Android %s / API %d",
                Build.VERSION.RELEASE, Build.VERSION.SDK_INT));
        say(String.format("  uid         %d", android.os.Process.myUid()));
        say("");

        probeRoots();
        probeLegacyFlag();
        probeOtherAppExternal();
        probeOtherAppPrivate();
        probeWorldReadableOfAnotherApp();
        probeSharedRoot();
        probeMediaStore();

        say("");
        say("Every line above is an OBSERVATION on this device at this API level.");
        say("Do not generalise it to another device without re-running it.");

        StringBuilder sb = new StringBuilder();
        for (String l : lines) {
            sb.append(l).append('\n');
        }
        String report = sb.toString();
        try {
            File out = new File(ctx.getFilesDir(), "probe.txt");
            OutputStreamWriter w = new OutputStreamWriter(
                    new FileOutputStream(out), Charset.forName("UTF-8"));
            w.write(report);
            w.close();
        } catch (Exception e) {
            Log.w(TAG, "could not write probe.txt", e);
        }
        return report;
    }

    // -----------------------------------------------------------------------

    /**
     * What the framework actually returns for each root.
     *
     * Print these rather than assuming them. getFilesDir() is not always
     * /data/data/<pkg>/files: on a secondary user it is /data/user/10/<pkg>/files,
     * and under Direct Boot the device-protected context returns a completely
     * different tree. Hardcoding the string is a bug that only shows up on a
     * device with a work profile.
     */
    private void probeRoots() {
        say("---- roots as the framework reports them ----------------------");
        row("getFilesDir()", ctx.getFilesDir());
        row("getCacheDir()", ctx.getCacheDir());
        row("getCodeCacheDir()", ctx.getCodeCacheDir());
        row("getNoBackupFilesDir()", ctx.getNoBackupFilesDir());
        row("getDatabasePath(notes.db)", ctx.getDatabasePath("notes.db"));
        row("getDataDir()", ctx.getDataDir());

        try {
            Context de = ctx.createDeviceProtectedStorageContext();
            row("DE getFilesDir()", de.getFilesDir());
            say(String.format("  %-30s %s", "isDeviceProtectedStorage()",
                    de.isDeviceProtectedStorage()));
        } catch (Throwable t) {
            say("  device-protected context unavailable: " + t);
        }

        row("getExternalFilesDir(null)", ctx.getExternalFilesDir(null));
        row("getExternalCacheDir()", ctx.getExternalCacheDir());
        File[] media = ctx.getExternalMediaDirs();
        if (media != null) {
            for (int i = 0; i < media.length; i++) {
                row("getExternalMediaDirs()[" + i + "]", media[i]);
            }
        }
        File[] extFiles = ctx.getExternalFilesDirs(null);
        if (extFiles != null && extFiles.length > 1) {
            say("  NOTE: " + extFiles.length + " external volumes. Index 0 is the");
            say("        emulated primary; a real removable card is index 1+.");
        }
        say("");
    }

    private void row(String label, File f) {
        if (f == null) {
            say(String.format("  %-30s (null -- volume not mounted)", label));
            return;
        }
        say(String.format("  %-30s %s", label, f.getAbsolutePath()));
        say(String.format("  %-30s exists=%s read=%s write=%s", "",
                f.exists(), f.canRead(), f.canWrite()));
    }

    /**
     * The API 29/30 hinge, measured.
     *
     * isExternalStorageLegacy() answers "is this app still seeing the
     * pre-scoped-storage view". On API 30 an app targeting 30 gets false no
     * matter what requestLegacyExternalStorage says, because the opt-out was
     * honoured for API 29 targets only. Print it rather than reasoning about
     * it: the interaction between targetSdk, the manifest flag, and whether the
     * app was upgraded or freshly installed is genuinely confusing, and the
     * platform will just tell you.
     */
    private void probeLegacyFlag() {
        say("---- scoped storage state -------------------------------------");
        say(String.format("  %-30s %s", "targetSdkVersion",
                ctx.getApplicationInfo().targetSdkVersion));
        if (Build.VERSION.SDK_INT >= 29) {
            say(String.format("  %-30s %s", "isExternalStorageLegacy()",
                    Environment.isExternalStorageLegacy()));
            say("      true  = this app still sees the pre-Android-10 filesystem view");
            say("      false = scoped storage is in force for this app");
        } else {
            say("  below API 29 -- scoped storage does not exist here");
        }
        say(String.format("  %-30s %s", "getExternalStorageState()",
                Environment.getExternalStorageState()));
        say("");
    }

    /**
     * THE headline scoped-storage restriction: can this app read another app's
     * Android/data directory?
     *
     * On API 29 and below, with the storage permission, yes. On API 30 the
     * platform blocks it for every app that does not hold
     * MANAGE_EXTERNAL_STORAGE -- and the block is implemented in the FUSE
     * daemon, not in the permission check, which is why it applies even to a
     * direct File API call with no permission involved.
     */
    private void probeOtherAppExternal() {
        say("---- another app's Android/data (the API 30 restriction) ------");
        String[] victims = {"com.android.chrome", "com.google.android.gms",
                            "com.android.vending"};
        File androidData = new File(Environment.getExternalStorageDirectory(),
                                    "Android/data");
        say("  listing " + androidData + " ...");
        String[] kids = androidData.list();
        if (kids == null) {
            say("  RESULT: list() returned null -- the directory is not enumerable");
            say("          by this app. This is the scoped-storage behaviour.");
        } else {
            say("  RESULT: list() returned " + kids.length + " entries. This app CAN");
            say("          enumerate other packages' external data directories.");
        }
        for (String v : victims) {
            File d = new File(androidData, v + "/files");
            say(String.format("  %-42s exists=%-5s read=%-5s list=%s",
                    v + "/files", d.exists(), d.canRead(),
                    d.list() == null ? "null" : String.valueOf(d.list().length)));
        }
        say("");
    }

    /**
     * Another app's private data directory. This must fail. If it ever does
     * not, the sandbox is broken and that is a platform vulnerability, not an
     * app one -- see 21-App-Sandbox.
     */
    private void probeOtherAppPrivate() {
        say("---- another app's private data (must fail) -------------------");
        File other = new File("/data/data/com.android.chrome");
        say(String.format("  %-42s exists=%-5s read=%-5s", other.getPath(),
                other.exists(), other.canRead()));
        say("  NOTE: exists() returning false here does NOT mean the directory is");
        say("        absent. stat(2) on a path you cannot traverse fails with");
        say("        EACCES, and File.exists() reports that as false. The API");
        say("        cannot distinguish 'no such file' from 'not allowed to look',");
        say("        which is a persistent source of wrong conclusions.");
        say("");
    }

    /**
     * The genuinely interesting one, and the reason this chapter insists on
     * separating DAC from MAC.
     *
     * On the device this chapter was written against, a stock GMS install
     * leaves shared_prefs/google_sdk_flags.xml at mode 0664 inside a package
     * directory at mode 0711. DAC therefore permits any uid to open it -- and
     * `adb shell cat` as uid 2000 succeeds. Whether THIS app can read it is a
     * different question, decided by SELinux, and the only way to know is to
     * try. Do not reason about it; the answer depends on the label the OEM
     * assigned and on the app domain this process runs in.
     */
    private void probeWorldReadableOfAnotherApp() {
        say("---- a world-readable file in another app's dir ---------------");
        String[] targets = {
            "/data/data/com.google.android.gms/shared_prefs/google_sdk_flags.xml",
            "/data/data/com.google.android.gms/shared_prefs/google_ads_flags.xml",
        };
        for (String t : targets) {
            File f = new File(t);
            String verdict;
            int got = -1;
            try {
                FileInputStream in = new FileInputStream(f);
                try {
                    byte[] buf = new byte[64];
                    got = in.read(buf);
                    verdict = "READ OK (" + got + " bytes)";
                } finally {
                    in.close();
                }
            } catch (Exception e) {
                verdict = "DENIED (" + e.getClass().getSimpleName() + ")";
            }
            say(String.format("  %s", t));
            say(String.format("      canRead()=%-5s  open+read: %s", f.canRead(), verdict));
        }
        say("  If DENIED while `adb shell cat` on the same path SUCCEEDS, the");
        say("  refusal came from SELinux, not from the mode bits -- and every");
        say("  'world-readable file' finding needs that distinction made.");
        say("");
    }

    /** The shared root: what can an app with no storage permission do to /sdcard? */
    private void probeSharedRoot() {
        say("---- the shared root ------------------------------------------");
        File sd = Environment.getExternalStorageDirectory();
        say("  getExternalStorageDirectory() = " + sd);
        String[] kids = sd.list();
        say("  list() -> " + (kids == null ? "null (not enumerable)"
                                           : kids.length + " entries"));
        File probe = new File(sd, "ch33-probe-write.txt");
        try {
            FileOutputStream fos = new FileOutputStream(probe);
            fos.write("ch33".getBytes("UTF-8"));
            fos.close();
            say("  WRITE to the shared root SUCCEEDED at " + probe);
            say("      This app declares no storage permission. If this line");
            say("      appears, that root is writable without one on this device.");
            //noinspection ResultOfMethodCallIgnored
            probe.delete();
            say("      (probe file deleted)");
        } catch (Exception e) {
            say("  WRITE to the shared root DENIED: " + e.getClass().getSimpleName()
                    + " -- " + e.getMessage());
            say("      This is the expected scoped-storage result for an app with");
            say("      no permission and no MANAGE_EXTERNAL_STORAGE.");
        }
        say("");
    }

    /**
     * MediaStore is the sanctioned way to reach shared media -- and it carries
     * a column, owner_package_name, that tells any reader which app created
     * each file. That is a privacy surface in its own right, independent of the
     * file contents: knowing that a particular app downloaded a particular file
     * is often more sensitive than the file.
     */
    private void probeMediaStore() {
        say("---- MediaStore ------------------------------------------------");
        ContentResolver cr = ctx.getContentResolver();
        Uri uri = MediaStore.Files.getContentUri("external");
        String[] proj;
        if (Build.VERSION.SDK_INT >= 29) {
            proj = new String[]{MediaStore.MediaColumns._ID,
                                MediaStore.MediaColumns.DISPLAY_NAME,
                                MediaStore.MediaColumns.OWNER_PACKAGE_NAME};
        } else {
            proj = new String[]{MediaStore.MediaColumns._ID,
                                MediaStore.MediaColumns.DISPLAY_NAME};
        }
        Cursor c = null;
        try {
            c = cr.query(uri, proj, null, null, null);
            if (c == null) {
                say("  query returned null -- no access to the provider");
            } else {
                say("  rows visible to this app: " + c.getCount());
                int shown = 0;
                while (c.moveToNext() && shown < 8) {
                    StringBuilder sb = new StringBuilder("    ");
                    for (int i = 0; i < proj.length; i++) {
                        sb.append(proj[i]).append('=')
                          .append(c.getString(i)).append("  ");
                    }
                    say(sb.toString());
                    shown++;
                }
                say("  An app with NO storage permission normally sees only the rows");
                say("  it owns. A non-zero count including rows owned by OTHER");
                say("  packages means this app can attribute other apps' files.");
            }
        } catch (SecurityException e) {
            say("  SecurityException: " + e.getMessage());
            say("  This is the expected result without a media read permission.");
        } finally {
            if (c != null) {
                c.close();
            }
        }
        say("");
    }
}
