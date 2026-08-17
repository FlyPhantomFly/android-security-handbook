// examples/deputy-app/SettingsActivity.java
//
// The second allow-listed, non-exported destination. Its only job is to make the
// allow-list in RedirectorActivityFixed contain more than one entry, so that
// "allow-list" is visibly a SET and not a single special case.

package com.pentest.deputy;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class SettingsActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i("DEPUTY", "SettingsActivity (allow-listed route)");

        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);
        tv.setText("SettingsActivity\n"
                + "android:exported=\"false\"\n\n"
                + "The other route the FIXED router is permitted to reach.");
        setContentView(tv);
    }
}
