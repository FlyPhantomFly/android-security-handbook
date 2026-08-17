// examples/deputy-app/MainActivity.java
//
// The deputy app's only user-visible screen. It exists so the app has a launcher
// entry (and therefore an installable, launchable identity) and so the lab can
// show the app running normally before anything is attacked.
//
// It also prints its own uid, which lab 01 uses to read the "not exported from
// uid NNNNN" line in logcat and confirm the two apps really are different Linux
// users -- the boundary the whole exercise is about.

package com.pentest.deputy;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import android.util.Log;
import android.widget.TextView;

public class MainActivity extends Activity {

    private static final String TAG = "DEPUTY";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String msg = "Deputy app\n"
                + "package = " + getPackageName() + "\n"
                + "uid     = " + Process.myUid() + "\n"
                + "pid     = " + Process.myPid();
        Log.i(TAG, msg.replace('\n', ' '));

        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);
        tv.setTextSize(16f);
        tv.setText(msg
                + "\n\nExported:\n"
                + "  .RedirectorActivity       (VULNERABLE)\n"
                + "  .RedirectorActivityFixed  (validated)\n"
                + "\nNot exported:\n"
                + "  .SecretActivity\n"
                + "  .DetailActivity\n"
                + "  .SettingsActivity");
        setContentView(tv);
    }
}
