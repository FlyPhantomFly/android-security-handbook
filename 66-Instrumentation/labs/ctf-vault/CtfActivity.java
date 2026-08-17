// labs/ctf-vault/CtfActivity.java
//
// DELIBERATELY VULNERABLE CTF FIXTURE -- chapter 66, lab 04.
//
// The only UI. It reports the state of the three fragments WITHOUT revealing
// them, so an entrant can confirm progress without being handed the answer.
// Running the app by hand and staring at this screen is a legitimate first move
// and it is designed to be informative and insufficient in equal measure.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.ctf;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.TextView;

import java.io.File;

public class CtfActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        File frag = new File(getFilesDir(), EarlyProvider.FRAGMENT_FILE);

        String body = "ch66 CTF -- Before Application\n\n"
                + "pid       = " + android.os.Process.myPid() + "\n"
                + "uid       = " + android.os.Process.myUid() + "\n"
                + "dataDir   = " + getApplicationInfo().dataDir + "\n\n"
                + "fragment1 : " + (frag.exists()
                        ? "on disk, " + frag.length() + " encoded bytes"
                        : "MISSING") + "\n"
                + "fragment2 : " + (Secrets.sVolatile == null
                        ? "gone"
                        : "live (" + Secrets.sVolatile.length() + " chars)") + "\n"
                + "fragment3 : " + ("denied".equals(Secrets.sPart3)
                        ? "denied -- the gate was closed"
                        : ("unset".equals(Secrets.sPart3)
                                ? "not yet decided"
                                : "granted (" + Secrets.sPart3.length() + " chars)")) + "\n\n"
                + "Flag shape: CTF{f1_f2_f3}\n"
                + "The value in SharedPreferences under \"flag\" is not the flag.";

        TextView tv = new TextView(this);
        tv.setGravity(Gravity.CENTER);
        tv.setTextSize(15f);
        tv.setPadding(28, 28, 28, 28);
        tv.setBackgroundColor(Color.WHITE);
        tv.setTextColor(Color.BLACK);
        tv.setText(body);
        setContentView(tv);
    }
}
