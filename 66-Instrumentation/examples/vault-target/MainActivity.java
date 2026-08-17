// examples/vault-target/MainActivity.java
//
// A one-screen Activity that prints the current values of the state the probe
// will manipulate. Its only job in the labs is to let you SEE that a change made
// from an instrumentation is visible to the app's own code, because both are in
// the same process and the same ART heap.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.vault;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setGravity(Gravity.CENTER);
        tv.setTextSize(18f);
        tv.setPadding(32, 32, 32, 32);
        tv.setBackgroundColor(Color.WHITE);
        tv.setTextColor(Color.BLACK);

        String body = "ch66 vault target\n\n"
                + "pid      = " + android.os.Process.myPid() + "\n"
                + "uid      = " + android.os.Process.myUid() + "\n"
                + "premium  = " + LicenseGate.isPremium() + "\n"
                + "session  = " + VaultStore.currentSessionToken() + "\n"
                + "dataDir  = " + getApplicationInfo().dataDir;

        tv.setText(body);
        setContentView(tv);

        Log.i(VaultApp.SEQ, "6 MainActivity.onCreate          premium="
                + LicenseGate.isPremium());
    }
}
