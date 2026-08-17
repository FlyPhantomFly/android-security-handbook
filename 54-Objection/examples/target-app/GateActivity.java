// examples/target-app/GateActivity.java
//
// PURPOSE
//   An exported Activity with no intent-filter. It exists so that
//   `android intent launch_activity com.pentest.ch54.target.GateActivity`
//   has a target that can only be reached by explicit component name.
//
//   Re-running the gate from here is what lets you install hooks first and
//   trigger the checks second, which is the correct order and the one that
//   makes an attach-mode session usable at all.
//
// WHAT THIS WILL *NOT* TELL YOU
//   That an exported Activity is a vulnerability. It is not, by itself.
//   26-Intent and 30-Activities own that subject.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch54.target;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class GateActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(SecurityGate.TAG, "GateActivity re-running the gate");
        int score = SecurityGate.evaluate();

        TextView tv = new TextView(this);
        tv.setText("gate re-run: " + score + " / 5");
        tv.setPadding(48, 96, 48, 48);
        setContentView(tv);
    }
}
