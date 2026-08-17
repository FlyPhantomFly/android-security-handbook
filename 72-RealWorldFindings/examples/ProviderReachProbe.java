/*
 * ProviderReachProbe.java -- answer chapter 72's Gate 2 from the vantage that
 *                            actually matters: an ordinary application uid
 *                            holding NO permissions at all.
 *
 * WHY THIS FILE EXISTS
 *   Every reachability result in this repository taken from `adb shell` carries
 *   an asterisk, because uid 2000 is not an app. 60-ADB measured why: the
 *   privilege does not come from the shell GID -- platform.xml grants that only
 *   INTERNET -- it comes from the `com.android.shell` PACKAGE, which requests
 *   200 permissions, holds 183 at install and 16 pre-granted runtime
 *   permissions flagged SYSTEM_FIXED, including READ_CONTACTS, RECORD_AUDIO and
 *   READ_SMS.
 *
 *   So `adb shell content query --uri content://victim.provider` returning rows
 *   proves that the SHELL can read it. This class proves whether an ATTACKER
 *   can, which is the only version of the claim that belongs in a report.
 *
 *   Chapter 72 section 7.3 is a live instance of the problem: the single
 *   authority in a 243-package corpus that returned rows to the shell probe
 *   belongs to a telephony component, and the shell holds telephony
 *   permissions -- so the chapter's most eye-catching result had to be recorded
 *   as INDETERMINATE pending exactly this test.
 *
 * THE MANIFEST IS PART OF THE EXPERIMENT
 *   This app must declare NO <uses-permission> at all. That is not an omission,
 *   it is the control: any permission you grant it weakens the claim you can
 *   make from the result. Minimum viable manifest:
 *
 *     <manifest xmlns:android="http://schemas.android.com/apk/res/android"
 *         package="com.pentest.ch72.probe">
 *         <!-- deliberately zero uses-permission elements -->
 *         <application android:label="ch72probe">
 *             <activity android:name=".ProviderReachProbe"
 *                       android:exported="true">
 *                 <intent-filter>
 *                     <action android:name="android.intent.action.MAIN"/>
 *                     <category android:name="android.intent.category.LAUNCHER"/>
 *                 </intent-filter>
 *             </activity>
 *         </application>
 *     </manifest>
 *
 *   On API 30+ you may also need a <queries> element to see other packages,
 *   but note that package visibility does NOT gate ContentResolver access to a
 *   provider you name explicitly by authority.
 *
 * BUILD AND RUN
 *   Build it however you normally build an APK. 30-Activities/examples/build.sh
 *   contains a complete no-Gradle path (aapt2 link -> javac -> d8 -> zipalign
 *   -> apksigner) that also handles INSTALL_FAILED_USER_RESTRICTED by falling
 *   back to a root install; copy that rather than re-deriving it. Build OUT OF
 *   TREE so no .apk/.dex/.class reaches this repository.
 *
 *     adb install -r ch72probe.apk
 *     adb shell am start -n com.pentest.ch72.probe/.ProviderReachProbe \
 *         --es authorities "com.victim.provider,com.victim.other"
 *     adb logcat -s CH72PROBE:V
 *
 *   Compare every line against the same authority probed from `adb shell`. Where
 *   the two disagree, the APP result is the one that belongs in the report.
 *
 * READING THE OUTPUT
 *   REACHABLE_ROWS         data crossed the boundary to a zero-permission app.
 *                          Gate 2 passes for the attacker position that matters.
 *   REACHABLE_EMPTY        the query executed; the table was empty. Gate 2
 *                          passes, Gate 3 is UNTESTED -- a clean device is not
 *                          a clean app. Do not write this up as harmless.
 *   REFUSED_PERMISSION     SecurityException before the app's code ran. Gate 2
 *                          fails. This is the correct, boring, common outcome.
 *   REACHED_APP_THREW      the target's own code threw. You are INSIDE and
 *                          holding the wrong verb -- try call/openFile/insert.
 *
 * AUTHORISATION
 *   Run only against applications and devices you are authorised to test. This
 *   reads data; treat anything it returns as belonging to the engagement.
 *
 * WAS THIS EXECUTED?
 *   NO -- it compiles, it was not run. It was type-checked with
 *   `javac -Xlint:all` against android-35's android.jar (see the note at the
 *   bottom of this file). It was NOT installed and run, because the only device
 *   attached while chapter 72 was written was an emulator whose only
 *   third-party packages belong to the machine's owner, and installing a probe
 *   to query their providers was outside what this chapter needed. The shell
 *   half of the experiment WAS run and is reported in section 7.3, labelled as
 *   a shell measurement throughout.
 */

package com.pentest.ch72.probe;

import android.app.Activity;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

public class ProviderReachProbe extends Activity {

    private static final String TAG = "CH72PROBE";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String arg = getIntent() == null
                ? null
                : getIntent().getStringExtra("authorities");
        if (arg == null || arg.trim().isEmpty()) {
            Log.w(TAG, "no --es authorities supplied; nothing to probe");
            Log.w(TAG, "usage: am start -n <pkg>/.ProviderReachProbe "
                    + "--es authorities \"a.b.c,d.e.f\"");
            finish();
            return;
        }

        Log.i(TAG, "=== vantage: uid=" + android.os.Process.myUid()
                + " pkg=" + getPackageName() + " (zero declared permissions) ===");

        for (String authority : arg.split(",")) {
            authority = authority.trim();
            if (!authority.isEmpty()) {
                probe(authority);
            }
        }
        finish();
    }

    /**
     * Query one authority read-only and classify WHICH LAYER refused.
     *
     * The classification is the whole point. A SecurityException raised by
     * ContentProvider.enforceReadPermissionInner arrives before the target's
     * code runs, so you are outside. Any other exception carries frames from
     * the target application, which means the binder transaction landed and the
     * framework's permission check passed -- you are inside, with the wrong
     * verb. Bucketing both as "error" throws away the distinction that decides
     * the finding.
     */
    private void probe(String authority) {
        Uri uri = Uri.parse("content://" + authority);
        ContentResolver cr = getContentResolver();
        Cursor c = null;
        try {
            c = cr.query(uri, null, null, null, null);
            if (c == null) {
                // A null Cursor is NOT a refusal. The provider returned nothing
                // without throwing, which usually means the authority resolved
                // but this path is not a table.
                Log.i(TAG, "INDETERMINATE_NULL   " + authority
                        + "  (null Cursor -- try a path segment)");
                return;
            }
            int rows = c.getCount();
            if (rows > 0) {
                Log.w(TAG, "REACHABLE_ROWS       " + authority
                        + "  rows=" + rows + " cols=" + c.getColumnCount());
                logColumns(c);
            } else {
                Log.i(TAG, "REACHABLE_EMPTY      " + authority
                        + "  cols=" + c.getColumnCount()
                        + "  (Gate 3 UNTESTED, not failed)");
                logColumns(c);
            }
        } catch (SecurityException e) {
            // The framework refused. This is Gate 2 failing, and it is the
            // correct outcome for a well-configured provider.
            Log.i(TAG, "REFUSED_PERMISSION   " + authority
                    + "  " + firstLine(e.getMessage()));
        } catch (RuntimeException e) {
            // The target's own code threw. You are inside.
            Log.w(TAG, "REACHED_APP_THREW    " + authority
                    + "  " + e.getClass().getName()
                    + ": " + firstLine(e.getMessage()));
            Log.w(TAG, "                     -> reachable; query() is the wrong "
                    + "verb. Try call/openFile/insert and enumerate paths.");
        } finally {
            if (c != null) {
                c.close();
            }
        }
    }

    /**
     * Column names are evidence even when there are no rows: they tell you what
     * the provider WOULD expose on a populated device, which is what turns
     * "empty on a clean emulator" into a defensible severity argument.
     */
    private void logColumns(Cursor c) {
        String[] names = c.getColumnNames();
        if (names == null || names.length == 0) {
            return;
        }
        StringBuilder sb = new StringBuilder("                     columns: ");
        for (int i = 0; i < names.length && i < 24; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(names[i]);
        }
        if (names.length > 24) {
            sb.append(", ... (").append(names.length).append(" total)");
        }
        Log.i(TAG, sb.toString());
    }

    private static String firstLine(String s) {
        if (s == null) {
            return "(no message)";
        }
        int nl = s.indexOf('\n');
        return nl < 0 ? s : s.substring(0, nl);
    }
}

/*
 * TYPE-CHECK RECORD
 *   Compiled out of tree on 2026-08-16, javac 24.0.2, against android-35:
 *
 *     javac -Xlint:all --release 8 -d <scratch> \
 *           -classpath "$ANDROID_HOME/platforms/android-35/android.jar" \
 *           ProviderReachProbe.java
 *
 *   Result: exit 0, no errors. The only output was three `[options]` warnings
 *   that source/target 8 is obsolete -- a property of the JDK, not of this file.
 *   Do NOT reach for `-bootclasspath` on a modern JDK; it is removed, and
 *   `--release 8 -classpath android.jar` is the form that works.
 *
 *   The .class output was written to a scratch directory outside the repository
 *   and deleted. Build artefacts (.class, .dex, .apk) are on this repository's
 *   blocklist -- never compile into the tree.
 */
