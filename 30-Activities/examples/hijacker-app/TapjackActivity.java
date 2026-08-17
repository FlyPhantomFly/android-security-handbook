// examples/hijacker-app/TapjackActivity.java
// Package: com.pentest.ch30.attacker
//
// Raises and drops the tapjacking overlay.
//
// ---------------------------------------------------------------------------
// WHY A ONE-LINE ACTIVITY IS NEEDED AT ALL
// ---------------------------------------------------------------------------
// From Android 8.0 (API 26) an app in the background may not start a Service.
// `adb shell am startservice -n com.pentest.ch30.attacker/.OverlayService` fails
// with:
//
//     Error: app is in background uid null
//
// -- measured on the API 30 device this chapter was written against. The
// restriction is not about overlays; it is the general background-execution
// limit, and it catches this lab in passing.
//
// The fix is the one a real sample uses: be in the foreground at the moment you
// start the service. This Activity exists purely to occupy the foreground for
// the few milliseconds the startService() call needs, and then to get out of the
// way with finish(). The overlay it started is a window owned by the SERVICE, so
// it outlives this Activity entirely -- which is the whole reason the overlay
// lives in a Service in the first place.
//
// This is a useful piece of general knowledge for reading malware: an overlay
// sample almost always has a trivial launcher Activity whose only job is to make
// the service start legal. Do not mistake it for the payload.
//
// USAGE
//   # host -- raise the overlay, then bring the victim's consent screen forward
//   adb shell am start -n com.pentest.ch30.attacker/.TapjackActivity --es op show
//   adb shell am start -n com.pentest.ch30.victim/.ConsentActivity
//   adb shell input tap <x> <y>
//   adb shell logcat -d -s CH30:I
//
//   # host -- always clean up
//   adb shell am start -n com.pentest.ch30.attacker/.TapjackActivity --es op hide
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.attacker;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class TapjackActivity extends Activity {

    private static final String TAG = "CH30";

    @Override
    protected void onResume() {
        super.onResume();

        // TWO MEASURED TRAPS, both of which produce the SAME misleading error:
        //
        //     IllegalStateException: Not allowed to start service ...:
        //     app is in background uid UidRecord{... TPSL idle ...}
        //
        // TRAP 1 -- the theme. android:theme="@android:style/Theme.NoDisplay"
        //   means the Activity never resumes, and the uid's process state never
        //   reaches foreground, so the background check can never be satisfied.
        //   Give this Activity a real theme (the manifest does) and start the
        //   service from onResume rather than onCreate.
        //
        // TRAP 2 -- the lock screen. Read the process state in the error text:
        //   TPSL is PROCESS_STATE_TOP_SLEEPING. On a LOCKED device the activity
        //   really is top, and the platform still counts it as background,
        //   because the display is not interactive. On the API 30 device used to
        //   write this chapter, `dumpsys trust` reported deviceLocked=1
        //   throughout, and this call was refused every single time -- including
        //   when driven through root, because the check is made against the
        //   TARGET app's uid state, not the caller's.
        //
        // UNLOCK THE DEVICE BEFORE RUNNING lab-04. There is no way around this
        // and there should not be: the whole attack is about what a user sees
        // and taps, and a locked phone has neither.
        String op = getIntent().getStringExtra("op");
        if (op == null) {
            op = "show";
        }
        Log.i(TAG, "TapjackActivity op=" + op);

        Intent svc = new Intent(this, OverlayService.class);
        svc.putExtra("op", op);
        try {
            startService(svc);
        } catch (IllegalStateException e) {
            Log.i(TAG, "TapjackActivity could not start OverlayService: " + e);
        }

        // Leave. The overlay window belongs to OverlayService and is unaffected
        // by this Activity finishing -- that is the point of putting it there.
        finish();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    }
}
