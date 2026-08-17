// examples/victim-app/Base.java
// Package: com.pentest.ch30.victim  (build.sh lays this file out under src/com/pentest/ch30/victim/)
//
// The shared superclass for every observable Activity in the victim app.
//
// WHY THIS EXISTS
//   A launch-mode experiment is only readable if you can distinguish
//   "the system reused the instance" from "the system built a new one".
//   `dumpsys activity activities` prints an ActivityRecord hash, but that is the
//   SYSTEM's bookkeeping object -- it is one-to-one with an activity record, not
//   with the Java object inside the app process. To see the app-side truth you
//   need the app to say which object it is.
//
//   System.identityHashCode(this) is that identity. Two log lines with the same
//   identityHashCode are the same Java object; two different values are two
//   separate onCreate() calls. Combined with getTaskId() that is everything you
//   need to read a launch mode off logcat:
//
//       onCreate   + new identityHashCode  -> a NEW instance was constructed
//       onNewIntent + old identityHashCode -> an EXISTING instance was REUSED
//
//   That single distinction is what separates `standard` from `singleTop` from
//   `singleTask`, and no amount of manifest reading substitutes for it.
//
// Filter the output with:  adb shell logcat -d -s CH30:I

package com.pentest.ch30.victim;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

public class Base extends Activity {

    protected static final String TAG = "CH30";

    /** Overridden by ConsentActivity/ConsentSafeActivity; harmless everywhere else. */
    protected boolean filterObscuredTouches() {
        return false;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        final String who = getClass().getSimpleName();
        final String line = who
                + " taskId=" + getTaskId()
                + " instance=" + System.identityHashCode(this)
                + " callingActivity=" + getCallingActivity();
        Log.i(TAG, "onCreate " + line);

        TextView text = new TextView(this);
        text.setText("VICTIM APP\n" + who + "\ntaskId=" + getTaskId()
                + "\ninstance=" + System.identityHashCode(this));
        text.setTextSize(18);
        text.setTextColor(Color.BLACK);
        text.setPadding(40, 120, 40, 40);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.WHITE);
        root.addView(text);

        // The single line that defends a screen against tapjacking. It tells the
        // input system to DISCARD any MotionEvent that arrived while another
        // window was covering this one. Chapter 30 section 3.9 explains why
        // "discard" rather than "warn" is the only workable policy.
        root.setFilterTouchesWhenObscured(filterObscuredTouches());

        onBuildContent(root);
        setContentView(root);
    }

    /** Subclasses add their own widgets here. Default: nothing. */
    protected void onBuildContent(LinearLayout root) {
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // Reaching this method AT ALL is the finding. It means the system chose
        // to reuse this instance rather than construct a new one, which only
        // happens for singleTop-at-top, singleTask, singleInstance, or an
        // explicit FLAG_ACTIVITY_SINGLE_TOP / FLAG_ACTIVITY_CLEAR_TOP.
        Log.i(TAG, "onNewIntent " + getClass().getSimpleName()
                + " taskId=" + getTaskId()
                + " instance=" + System.identityHashCode(this));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        Log.i(TAG, "onDestroy " + getClass().getSimpleName()
                + " instance=" + System.identityHashCode(this)
                + " isFinishing=" + isFinishing());
    }
}
