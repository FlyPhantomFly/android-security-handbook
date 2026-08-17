// examples/target-app/MainActivity.java
//
// PURPOSE
//   The launcher Activity of the chapter 54 target app. It does three things,
//   all of them chosen to be observable from an objection REPL:
//
//     1. Runs SecurityGate.evaluate() from onCreate(), so the whole gate can be
//        re-triggered by relaunching the Activity -- which is what makes
//        `android intent launch_activity` a useful command rather than a trick.
//
//     2. Exposes AuthGate.checkPin(String), a boolean-returning instance method
//        with one String argument. That signature is the simplest thing
//        `android hooking watch class_method --dump-args --dump-return` and
//        `android hooking set return_value` can be demonstrated against.
//
//     3. Holds a String field containing a fake secret, so
//        `android heap search instances` and `android heap print fields` have
//        something to find. The value is not a real credential.
//
// TIMING MATTERS, AND THIS FILE IS WHERE YOU SEE IT
//   evaluate() runs in onCreate(). If you ATTACH objection to an already-running
//   process, onCreate has already happened and your hooks are too late; you will
//   see nothing until you relaunch the Activity. If objection SPAWNS the process
//   (because it was not running), the hooks are in place first. objection chooses
//   between those two silently -- see section 3.4 of the chapter README.
//
// WHAT THIS WILL *NOT* TELL YOU
//   Nothing here runs before Application.onCreate. A real app's toughest checks
//   run in attachBaseContext or a static initialiser, earlier than anything an
//   attach-mode session can reach. This app is deliberately easier than that.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch54.target;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    /** Not a real credential. It exists so heap search has a target. */
    private String sessionNote = "ch54-lab-not-a-real-secret";

    private final AuthGate gate = new AuthGate();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        int score = SecurityGate.evaluate();

        // A trivial UI so the Activity is visible and can be foregrounded.
        TextView tv = new TextView(this);
        tv.setText("CH54 Target\n\nroot checks firing: " + score + " / 5\n\n"
                + "see: adb logcat -s CH54");
        tv.setPadding(48, 96, 48, 48);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.addView(tv);
        setContentView(root);

        // Exercise the PIN gate once on startup so a watch placed before launch
        // has something to catch.
        boolean ok = gate.checkPin("0000");
        Log.i(SecurityGate.TAG, "startup pin probe accepted=" + ok
                + " note=" + sessionNote);
    }

    /**
     * A deliberately simple boolean gate.
     *
     * It is a separate class rather than a method on the Activity because
     * `android hooking watch class` takes a CLASS, and watching an Activity
     * subclass drags in every lifecycle callback and buries the signal.
     */
    public static class AuthGate {

        private final String expected = "4821";

        public boolean checkPin(String candidate) {
            boolean ok = expected.equals(candidate);
            Log.i(SecurityGate.TAG, "AuthGate.checkPin(" + candidate + ") -> " + ok);
            return ok;
        }

        /** A second overload, so overload selection can be demonstrated. */
        public boolean checkPin(int candidate) {
            return checkPin(Integer.toString(candidate));
        }
    }
}
