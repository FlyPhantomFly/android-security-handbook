// examples/DeputyActivityFixed.java
// Package: com.pentest.ch30.victim  (ships as examples/victim-app/DeputyActivityFixed.java too)
//
// THE FIXED DEPUTY -- the counterpart to examples/DeputyActivity.java.
//
// ---------------------------------------------------------------------------
// THE RULE THIS FILE IMPLEMENTS
// ---------------------------------------------------------------------------
// A deputy is safe when the DESTINATION is decided by the deputy and the caller
// only supplies a *selector*. Everything below follows from that one sentence.
//
// The wrong instinct is to keep accepting an Intent and try to sanitise it. You
// cannot sanitise an Intent, because an Intent is a dozen independently
// attacker-controlled fields plus an arbitrary Bundle, and a filter has to be
// right about all of them forever. A closed allow-list of destinations has to be
// right about one thing, once.
//
// ---------------------------------------------------------------------------
// WHY THE OBVIOUS HALF-FIXES FAIL
// ---------------------------------------------------------------------------
// Each of these appears in real remediation commits and each is defeated:
//
//   "I check next.getComponent() is non-null."
//       Defeated. The attacker sets a component -- theirs.
//
//   "I check getPackage() equals my own package."
//       Defeated. setPackage() restricts RESOLUTION; it does not pin the
//       component. Worse, getPackage() is null on an Intent that only sets a
//       ComponentName, so the check is skipped entirely on the exact input that
//       matters. Resolve the component and compare THAT.
//
//   "I check the component's package is mine."
//       Better, and still not enough. Every exported="false" screen in your own
//       app is now reachable by any app on the device, which is precisely
//       confused-deputy reachability. It also does nothing about the FLAGS: a
//       FLAG_GRANT_READ_URI_PERMISSION on an Intent aimed at your OWN activity
//       still issues a grant, and your own activity may hand the URI onward.
//
//   "I strip FLAG_GRANT_* and forward it."
//       Better again, and still an open redirect to any of your own screens,
//       and still carries an attacker-authored Bundle into them.
//
//   "I check the URI's scheme is https."
//       Defeated by the DATA vs COMPONENT distinction: the component wins.
//
// The version below does not attempt any of that. It never looks at an Intent
// the caller wrote, because it never accepts one.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.victim;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DeputyActivityFixed extends Activity {

    private static final String TAG = "CH30";

    /** The caller supplies a KEY, not a destination. */
    public static final String EXTRA_DEST = "dest";

    /**
     * The closed allow-list. Adding an entry is a code change and a code review.
     * That is the property that makes this safe: the set of reachable
     * destinations is fixed at build time and cannot be widened by a message.
     */
    private static final Map<String, Class<?>> DESTINATIONS;
    static {
        Map<String, Class<?>> m = new HashMap<String, Class<?>>();
        m.put("home", MainActivity.class);
        m.put("internal", InternalActivity.class);
        DESTINATIONS = Collections.unmodifiableMap(m);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 1. Read a SELECTOR, not an Intent. getStringExtra cannot return
        //    anything that is startable, so there is no primitive to abuse.
        String dest = getIntent().getStringExtra(EXTRA_DEST);

        Class<?> target = dest == null ? null : DESTINATIONS.get(dest);
        if (target == null) {
            // 2. Fail CLOSED. An unknown selector is not "fall back to home";
            //    it is a rejected request, and it is worth logging because a
            //    stream of them is somebody enumerating your allow-list.
            Log.w(TAG, "DeputyActivityFixed rejected dest=" + dest);
            setResult(RESULT_CANCELED);
            finish();
            return;
        }

        // 3. Build the Intent HERE, from a class literal. The ComponentName is
        //    supplied by the compiler, so no field of the outgoing Intent has
        //    ever been touched by the caller.
        Intent next = new Intent(this, target);

        // 4. Carry nothing across. The incoming Bundle is not copied, so no
        //    attacker-authored extra reaches the internal screen, and no
        //    attacker-set flag reaches the system. In particular
        //    FLAG_GRANT_READ_URI_PERMISSION and FLAG_ACTIVITY_FORWARD_RESULT
        //    cannot be present, because nothing set them.
        //
        //    If you genuinely need to forward a value, forward THAT VALUE by
        //    name with a type-checked getter -- never the Bundle wholesale.
        //
        //    Intent.FLAG_ACTIVITY_NO_HISTORY is set so this trampoline does not
        //    linger in the back stack; that is hygiene, not a control.
        next.setFlags(Intent.FLAG_ACTIVITY_NO_HISTORY);

        Log.i(TAG, "DeputyActivityFixed forwarding to allow-listed " + target.getName());
        startActivity(next);
        finish();
    }
}
