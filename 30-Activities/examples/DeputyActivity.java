// examples/DeputyActivity.java
// Package: com.pentest.ch30.victim  (ships as examples/victim-app/DeputyActivity.java too;
//                                    this copy is the annotated teaching version)
//
// THE VULNERABLE DEPUTY -- an Activity that starts an Intent somebody else wrote.
//
// ---------------------------------------------------------------------------
// WHY A COMPETENT DEVELOPER WRITES THIS
// ---------------------------------------------------------------------------
// Nobody sets out to build an open redirect. This code is what you get when a
// product team asks for a perfectly reasonable feature:
//
//     "After the user finishes the login flow, send them back where they came
//      from -- the notification, the deep link, the widget, whatever."
//
// The natural implementation is to let the caller state its destination, carry
// that destination through the flow, and fire it at the end. An Intent is
// Parcelable, so it is the obvious carrier. The code below is what that looks
// like, and it appears in production apps constantly.
//
// The bug is not the pattern. The bug is that this Activity is EXPORTED and the
// destination is never validated, so the "caller" can be any app on the device
// and the "destination" can be anything at all.
//
// ---------------------------------------------------------------------------
// WHAT THE ATTACKER GETS -- three distinct prizes, in rising order of severity
// ---------------------------------------------------------------------------
//   1. REACHABILITY. startActivity() here runs with the VICTIM's uid, so the
//      forwarded Intent can name a component that is exported="false" inside
//      this app. The attacker reaches screens the platform would have refused
//      to start for them. This is confused-deputy reachability.
//
//   2. GRANT LAUNDERING. If the attacker's nested Intent carries
//      FLAG_GRANT_READ_URI_PERMISSION and a content:// URI belonging to this
//      app, the system issues the grant on behalf of THIS app, to a target the
//      ATTACKER chose. The attacker now holds a read grant on a provider marked
//      exported="false". What the grant is worth is 27-ContentProviders'
//      subject; that it was issued at all is this file's fault.
//
//   3. RESULT THEFT. If the attacker sets FLAG_ACTIVITY_FORWARD_RESULT, the
//      result channel is re-pointed one level outward and any result -- and any
//      grant riding on it -- comes straight back to the attacker with no
//      cooperation from this Activity at all. See 26-Intent section 3.7.
//
// ---------------------------------------------------------------------------
// WHERE THE BOUNDARY IS
// ---------------------------------------------------------------------------
// 26-Intent owns the redirection PRIMITIVE -- the Intent message, resolution,
// and the taxonomy of redirection flavours. 27-ContentProviders owns what a
// laundered grant is WORTH. This chapter owns the DEPUTY: the Activity that
// holds the privilege, the Activity lifecycle in which the mistake is made, and
// the task/result plumbing that carries the stolen value back out.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.victim;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class DeputyActivity extends Activity {

    private static final String TAG = "CH30";

    /** The extra another app fills in to say "go here when you are done". */
    public static final String EXTRA_NEXT = "next";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent incoming = getIntent();

        // ------------------------------------------------------------------
        // THE BUG, IN THREE LINES.
        //
        // getParcelableExtra returns whatever the CALLER put in the Bundle.
        // The cast to Intent is the only "validation" present, and it validates
        // the TYPE, not the CONTENT. An Intent that names
        // com.attacker/.GrantSinkActivity casts to Intent just as happily as one
        // that names .InternalActivity.
        // ------------------------------------------------------------------
        Intent next = incoming.getParcelableExtra(EXTRA_NEXT);

        Log.i(TAG, "DeputyActivity forwarding: " + next);

        if (next != null) {
            // startActivity() runs as THIS app. Every privilege decision the
            // system is about to make -- component visibility, exported checks,
            // permission checks, URI grant issuance -- is made against the
            // victim's identity, not the attacker's.
            //
            // Note also what is NOT stripped: next.getFlags() still carries
            // whatever the attacker set, including FLAG_GRANT_READ_URI_PERMISSION
            // and FLAG_ACTIVITY_FORWARD_RESULT.
            startActivity(next);
        }

        finish();
    }
}
