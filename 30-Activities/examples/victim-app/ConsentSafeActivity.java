// examples/victim-app/ConsentSafeActivity.java
// Package: com.pentest.ch30.victim
//
// The hardened counterpart to ConsentActivity. Identical screen, one line
// different, and the difference is measurable in logcat.
//
// ---------------------------------------------------------------------------
// THE DEFENCE, AND WHY IT IS DISCARD RATHER THAN WARN
// ---------------------------------------------------------------------------
// View.setFilterTouchesWhenObscured(true) -- or android:filterTouchesWhenObscured
// in a layout -- makes the View DROP any MotionEvent whose
// FLAG_WINDOW_IS_OBSCURED bit is set. It is implemented in
// frameworks/base/core/java/android/view/View.java's onFilterTouchEventForSecurity(),
// which returns false for such events, and a View that returns false from that
// method never sees the touch at all.
//
// Discarding is the only workable policy, and the reason is worth stating
// because "why not just warn the user?" is the first thing everyone asks. A
// warning is a UI element, and the attacker already controls the pixels on top
// of your UI. Anything you draw, they can cover. The only action available to
// you that the attacker cannot paint over is REFUSING TO ACT.
//
// ---------------------------------------------------------------------------
// WHAT IT DOES NOT DO -- three limits worth knowing before you write the report
// ---------------------------------------------------------------------------
//   1. It protects the VIEW you set it on, not the Activity. Set it on the
//      root of the sensitive screen (as Base.java does) or, better, on each
//      consequential control. A dialog shown by this Activity is a different
//      window and needs its own treatment.
//
//   2. It does nothing about an attacker who does not need your touch --
//      an accessibility service can drive the UI directly, and a screen
//      recorder does not touch anything at all. FLAG_SECURE is the control for
//      the recording half; the accessibility half is a separate threat model.
//
//   3. Historically it did not fire for windows belonging to the SAME uid, and
//      some OEM launchers/overlays are system windows that the flag treats
//      differently. Measure on the target device rather than assuming; lab-04
//      shows exactly how.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.victim;

import android.graphics.Color;
import android.util.Log;
import android.view.MotionEvent;
import android.widget.Button;
import android.widget.LinearLayout;

public class ConsentSafeActivity extends Base {

    /** The one-line difference. Base.onCreate() applies it to the root view. */
    @Override
    protected boolean filterObscuredTouches() {
        return true;
    }

    @Override
    protected void onBuildContent(LinearLayout root) {
        Button grant = new Button(this);
        grant.setText("GRANT FULL ACCOUNT ACCESS (protected)");
        grant.setTextSize(18);
        grant.setBackgroundColor(Color.parseColor("#006600"));
        grant.setTextColor(Color.WHITE);

        // Belt and braces: set it on the button itself as well as on the root.
        // Defence in depth costs nothing here, and a future refactor that moves
        // the button out of this root does not silently remove the control.
        grant.setFilterTouchesWhenObscured(true);

        grant.setOnClickListener(v ->
                Log.i(TAG, "CONSENT GRANTED (safe screen) -- the sensitive action ran"));

        grant.setOnTouchListener((v, event) -> {
            // NOTE: with filtering enabled, an obscured event never reaches this
            // listener, so seeing NOTHING in logcat while an overlay is up is
            // the successful result. Absence of a log line is the evidence.
            Log.i(TAG, "ConsentSafeActivity touch action=" + event.getAction()
                    + " flags=0x" + Integer.toHexString(event.getFlags())
                    + " OBSCURED="
                    + ((event.getFlags() & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0));
            return false;
        });
        root.addView(grant);
    }
}
