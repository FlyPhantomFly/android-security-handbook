// examples/victim-app/VaultActivity.java
// Package: com.pentest.ch30.victim
//
// The CTF target for labs/lab-05-ctf-the-understudy.md.
//
// ---------------------------------------------------------------------------
// WHAT IT IS SUPPOSED TO DO
// ---------------------------------------------------------------------------
// This is a screen that only the app's own code is meant to be able to unlock.
// The developer thought carefully about identity and picked the ONE genuinely
// trustworthy mechanism available to an Activity:
//
//     getCallingActivity() is set by the system, never by the caller, and it is
//     non-null only when the caller used startActivityForResult().
//
// That check is CORRECT. An external app cannot forge it. It is tier 2
// (system-stamped) in the language of README section 3.6, and if it were the
// only thing standing between an attacker and the flag, there would be no
// challenge here.
//
// ---------------------------------------------------------------------------
// WHERE IT GOES WRONG
// ---------------------------------------------------------------------------
// The check runs ONCE, in onCreate, and its answer is cached in a field.
//
// The Activity is declared android:launchMode="singleTop". When an instance is
// already at the top of its task, the system does not construct a new one -- it
// calls onNewIntent on the EXISTING object. Every field survives, including the
// cached authorisation. And a caller can force that path from outside with
// FLAG_ACTIVITY_SINGLE_TOP even on a `standard` Activity, so the launch mode is
// convenience rather than a precondition.
//
// onNewIntent below then acts on the NEW Intent while the authorisation it
// relies on was computed from the OLD one. Two different messages; one decision.
//
// This is not a contrived bug. It is one of the most common real Activity bugs
// there is, and it is invisible in review because both halves look right on
// their own. README section 3.1 states the general rule: onNewIntent does not
// update getIntent(), and any instance-reusing launch mode makes the gap
// reachable from outside.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.victim;

import android.content.Intent;
import android.graphics.Color;
import android.util.Log;
import android.widget.LinearLayout;
import android.widget.TextView;

public class VaultActivity extends Base {

    /** The prize. */
    private static final String FLAG = "CH30{a_stale_getIntent_is_a_second_entry_point}";

    /**
     * Computed once, in onCreate, and then trusted forever.
     * That word -- "once" -- is the whole vulnerability.
     */
    private boolean mUnlockedByOwnApp = false;

    private TextView mStatus;

    @Override
    protected void onBuildContent(LinearLayout root) {
        // getCallingActivity() is null unless the caller used
        // startActivityForResult, and the system fills it in -- the caller
        // cannot set it. Requiring it to name OUR OWN package means an
        // external app can never satisfy this check directly.
        android.content.ComponentName caller = getCallingActivity();
        mUnlockedByOwnApp = caller != null
                && getPackageName().equals(caller.getPackageName());

        Log.i(TAG, "VaultActivity onCreate callingActivity=" + caller
                + " unlocked=" + mUnlockedByOwnApp
                + " taskId=" + getTaskId()
                + " instance=" + System.identityHashCode(this));

        mStatus = new TextView(this);
        mStatus.setTextSize(17);
        mStatus.setTextColor(Color.BLACK);
        mStatus.setText("VAULT\nunlocked=" + mUnlockedByOwnApp
                + "\ncaller=" + caller
                + "\n\nsend a command with the extra \"cmd\"");
        root.addView(mStatus);

        // A command may also arrive on the very first Intent. Handled here so
        // that the legitimate in-app path works in one step.
        handle(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);

        // ------------------------------------------------------------------
        // THE BUG.
        //
        // Note what is NOT here:
        //   * no setIntent(intent), so getIntent() still returns the ORIGINAL
        //     Intent forever;
        //   * no re-evaluation of mUnlockedByOwnApp, so the authorisation
        //     computed from a DIFFERENT message is reused for this one.
        //
        // The fix is two lines, and it is stated in full in the lab.
        // ------------------------------------------------------------------
        Log.i(TAG, "VaultActivity onNewIntent (instance REUSED, unlocked=" + mUnlockedByOwnApp
                + ") callingActivity=" + getCallingActivity());
        handle(intent);
    }

    private void handle(Intent intent) {
        if (intent == null) {
            return;
        }
        String cmd = intent.getStringExtra("cmd");
        if (cmd == null) {
            return;
        }

        if (!"reveal".equals(cmd)) {
            Log.i(TAG, "VaultActivity unknown cmd=" + cmd);
            return;
        }

        if (!mUnlockedByOwnApp) {
            // The correct refusal -- and the one an attacker sees on a first,
            // direct attempt. It is what makes the challenge look impossible.
            Log.i(TAG, "VaultActivity REFUSED: not unlocked by this app");
            if (mStatus != null) {
                mStatus.setText("VAULT\nREFUSED: this vault was not opened by its own app.");
            }
            return;
        }

        Log.i(TAG, "VaultActivity REVEAL -> " + FLAG);
        if (mStatus != null) {
            mStatus.setText("VAULT\n" + FLAG);
        }
    }
}
