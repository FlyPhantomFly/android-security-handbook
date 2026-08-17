// examples/deputy-app/SecretActivity.java
//
// The prize. Declared android:exported="false" in AndroidManifest.xml, so
// ActivityStarter inside system_server refuses to start it for any caller whose
// uid differs from this app's:
//
//     if (!aInfo.exported && callingUid != aInfo.applicationInfo.uid) throw ...
//
// An attacker app that targets it DIRECTLY gets, in logcat:
//
//     Permission Denial: starting Intent { cmp=com.pentest.deputy/.SecretActivity }
//         from ProcessRecord{... com.pentest.attacker} (pid=..., uid=10xxx)
//         not exported from uid 10yyy
//
// That denial is the NEGATIVE CONTROL for lab 01. Without it in your evidence, a
// developer can reasonably claim your test harness never worked and that the
// "successful" redirection proved nothing.
//
// The same attacker app reaches this class anyway, through RedirectorActivity,
// because on the second start the calling uid is the DEPUTY's. Nothing here
// changes; the caller changes.
//
// DetailActivity and SettingsActivity live in this file as extra classes so that
// RedirectorActivityFixed's allow-list refers to something real. They are also
// non-exported, which is the point: the fixed router may reach them, an outside
// caller may not.

package com.pentest.deputy;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.widget.TextView;

public class SecretActivity extends Activity {

    private static final String TAG = "DEPUTY";

    /** The lab's flag string. Reaching this line IS the exploit result. */
    public static final String FLAG = "FLAG{non_exported_reached_via_deputy}";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String why = getIntent().getStringExtra("why");

        Log.w(TAG, "SecretActivity REACHED. uid=" + Process.myUid()
                + " why=" + why
                + " callingActivity=" + getCallingActivity()
                + " data=" + getIntent().getDataString());
        Log.w(TAG, FLAG);

        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);
        tv.setTextSize(16f);
        tv.setText("SecretActivity\n"
                + "android:exported=\"false\"\n\n"
                + FLAG + "\n\n"
                + "why  = " + why + "\n"
                + "data = " + getIntent().getDataString() + "\n"
                + "getCallingActivity() = " + getCallingActivity() + "\n\n"
                + "If you are reading this and you did not start it from inside\n"
                + "this app, a deputy started it for you.");
        setContentView(tv);
    }
}
