// examples/victim-app/ConsentActivity.java
// Package: com.pentest.ch30.victim
//
// A consent screen with NO obscured-touch filtering. The tapjacking target.
//
// ---------------------------------------------------------------------------
// WHAT TAPJACKING IS, AND WHY IT IS AN ACTIVITY PROBLEM
// ---------------------------------------------------------------------------
// The user's finger lands on a pixel. Two windows claim that pixel: an overlay
// drawn by another app, and this Activity underneath it. If the overlay declares
// itself non-touchable (FLAG_NOT_TOUCHABLE), the touch passes THROUGH it and is
// delivered here -- to a button the user could not see and did not intend to
// press. The overlay chose what the user believed they were tapping; this
// Activity chose what actually happened.
//
// That is the whole attack. It needs no exploit, no memory corruption, and no
// permission on this app's side. It needs the attacker to hold
// SYSTEM_ALERT_WINDOW (or to be an accessibility service, or to use a toast
// window on old versions) and it needs THIS screen to accept a touch it should
// have refused.
//
// ---------------------------------------------------------------------------
// WHAT THE PLATFORM ALREADY DOES FOR YOU, AND WHERE IT STOPS
// ---------------------------------------------------------------------------
// The input system already tells you. Every MotionEvent carries flags, and
// FLAG_WINDOW_IS_OBSCURED (0x1) means "at the moment of this event, another
// window from a DIFFERENT application was covering some part of this window".
// Since API 29 there is also FLAG_WINDOW_IS_PARTIALLY_OBSCURED (0x2), which is
// set when the covering window does not overlap the touched point itself.
//
// The platform sets the flag and then delivers the event anyway. Acting on it is
// the app's job -- and the default is to do nothing. That default is why this
// class is a vulnerability and ConsentSafeActivity is not.
//
// This class logs the flags so labs/lab-04 can show the difference between
// "the platform did not notice" (it did) and "the app did not care" (it did not).
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.victim;

import android.graphics.Color;
import android.util.Log;
import android.view.MotionEvent;
import android.widget.Button;
import android.widget.LinearLayout;

public class ConsentActivity extends Base {

    /**
     * Base.onCreate() calls this and passes the answer to
     * View.setFilterTouchesWhenObscured(). Returning false is the vulnerability.
     */
    @Override
    protected boolean filterObscuredTouches() {
        return false;
    }

    @Override
    protected void onBuildContent(LinearLayout root) {
        Button grant = new Button(this);
        grant.setText("GRANT FULL ACCOUNT ACCESS");
        grant.setTextSize(18);
        grant.setBackgroundColor(Color.parseColor("#CC0000"));
        grant.setTextColor(Color.WHITE);

        grant.setOnClickListener(v -> {
            // In a real app this is the line that transfers money, approves an
            // OAuth scope, or disables a security control.
            Log.i(TAG, "CONSENT GRANTED -- the sensitive action ran");
        });
        root.addView(grant);

        // Purely diagnostic: prove the platform TOLD us and we ignored it.
        grant.setOnTouchListener((v, event) -> {
            int flags = event.getFlags();
            boolean obscured = (flags & MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0;
            // FLAG_WINDOW_IS_PARTIALLY_OBSCURED is API 29+; 0x2 is its value.
            boolean partial = (flags & 0x2) != 0;
            Log.i(TAG, "ConsentActivity touch action=" + event.getAction()
                    + " flags=0x" + Integer.toHexString(flags)
                    + " OBSCURED=" + obscured
                    + " PARTIALLY_OBSCURED=" + partial
                    + "  -> DELIVERED ANYWAY (filterTouchesWhenObscured=false)");
            return false;   // let the click through
        });
    }
}
