// examples/victim-app/InternalActivity.java
// Package: com.pentest.ch30.victim
//
// An Activity declared android:exported="false".
//
// It has two jobs.
//
// JOB 1 -- it is the control that makes confused-deputy REACHABILITY measurable
// rather than argued. Two facts are demonstrated against it in labs/lab-03:
//
//   1. `adb shell am start -n com.pentest.ch30.victim/.InternalActivity` is
//      REFUSED with a Permission Denial, even though adb shell runs as the
//      privileged uid 2000. Non-exported means non-exported.
//
//   2. The same component started through DeputyActivity SUCCEEDS, because at
//      that moment the caller is the victim app itself. Nothing about
//      InternalActivity changed; the identity of the caller did.
//
// JOB 2 -- it is the app's own, legitimate route into VaultActivity, and it
// opens that vault with startActivityForResult so that the vault's
// getCallingActivity() check passes. That is the intended design: "only code
// inside this app can open the vault, and here is the code that does it".
//
// Which makes this Activity the hinge of labs/lab-05. An attacker who can reach
// InternalActivity does not get the flag -- but they do get the app to unlock
// its own vault, which is a different and much more useful thing.
//
// A screen like this is where apps put things they believe are unreachable: an
// admin panel, a debug menu, a "you are already authenticated" landing page. The
// developer's mental model is "only my code can start this", and a deputy
// quietly makes that false.

package com.pentest.ch30.victim;

import android.content.Intent;
import android.util.Log;
import android.widget.LinearLayout;

public class InternalActivity extends Base {

    /** Arbitrary; only its non-negative-ness matters, because it selects
     *  startActivityForResult over startActivity. */
    private static final int RC_VAULT = 7;

    @Override
    protected void onBuildContent(LinearLayout root) {
        // If this line appears in logcat, something started a component that the
        // manifest says no other app may start. Either it was this app's own
        // code, or a deputy was used.
        Log.i(TAG, "InternalActivity REACHED -- exported=false, so the starter had "
                + "this app's identity. callingActivity=" + getCallingActivity());

        // The legitimate route into the vault.
        //
        // startActivityForResult -- NOT startActivity -- is what makes the
        // vault's getCallingActivity() non-null. Swap it for startActivity and
        // the vault can never be unlocked by anybody, including this app.
        // That one word is the entire authorisation mechanism.
        Intent open = new Intent(this, VaultActivity.class);
        Log.i(TAG, "InternalActivity opening the vault with startActivityForResult");
        startActivityForResult(open, RC_VAULT);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        Log.i(TAG, "InternalActivity onActivityResult rc=" + requestCode
                + " res=" + resultCode + " data=" + data);
    }
}
