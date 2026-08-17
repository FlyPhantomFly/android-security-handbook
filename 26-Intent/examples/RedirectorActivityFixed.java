// examples/RedirectorActivityFixed.java
//
// FIXED — the same router, written so that forwarding an attacker-supplied Intent
// cannot borrow this app's authority.
//
// This is the counterpart to examples/RedirectorActivity.java. Both are compiled
// into the same deputy app by examples/deputy-app/build.sh and both are exported,
// so lab 01 can fire the identical payload at each and show the difference.
//
// THE FIVE THINGS THAT MATTER, AND WHY EACH ONE IS NOT OPTIONAL
//
//   1. RESOLVE the component before looking at it. `next.getComponent()` can be
//      null (an implicit inner Intent), and code that reads `.getPackageName()`
//      off a null component either throws or -- worse -- treats null as safe.
//      resolveActivity() asks the platform what this Intent would actually reach.
//
//   2. CHECK THE PACKAGE IS OURS. `next.getPackage()` is only a HINT and does not
//      decide the target; the component wins. Compare the RESOLVED component's
//      package to getPackageName().
//
//   3. ALLOW-LIST THE CLASS, as a closed set. Not a prefix, not a regex. Confining
//      the target to "some component of this app" still exposes every non-exported
//      component we have -- that is the same bug in a smaller box.
//
//   4. STRIP THE GRANT FLAGS. FLAG_GRANT_READ/WRITE/PERSISTABLE/PREFIX_URI_PERMISSION
//      ride on the Intent. Forwarding them lends our read/write authority over any
//      content:// URI the attacker names. This is the laundering step that
//      27-ContentProviders section 5.4 exploits.
//
//   5. STRIP FLAG_ACTIVITY_FORWARD_RESULT and RE-SET the component. FORWARD_RESULT
//      re-points the result channel past us, straight back to the attacker, so any
//      grant returned by the next activity never passes through our hands at all.
//      Re-setting the component makes the Intent explicit, so nothing about its own
//      resolution can change the destination after we have checked it.
//
// AND ONE THING PEOPLE GET WRONG: validate the object you FORWARD. If you validate
// `next` and then forward `getIntent().getParcelableExtra("next")` a second time,
// you have re-read attacker-controlled data after the check.
//
// THE BETTER DESIGN, WHERE YOU CAN HAVE IT
//     Do not forward Intent objects at all. Take a route identifier -- a short
//     string -- and CONSTRUCT the Intent yourself. See routeByName() at the bottom;
//     it is what this activity would look like if the API had been designed rather
//     than grown.

package com.pentest.deputy;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class RedirectorActivityFixed extends Activity {

    private static final String TAG = "DEPUTY";

    /** A closed set of fully-qualified class names this router may reach. */
    private static final Set<String> ALLOWED = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    "com.pentest.deputy.DetailActivity",
                    "com.pentest.deputy.SettingsActivity")));

    /** Every URI-grant flag, plus the result-channel flag. */
    private static final int DANGEROUS_FLAGS =
            Intent.FLAG_GRANT_READ_URI_PERMISSION
            | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
            | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION
            | Intent.FLAG_ACTIVITY_FORWARD_RESULT;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Read ONCE. Everything below operates on this object.
        Intent next = getIntent().getParcelableExtra("next");
        if (next == null) {
            Log.i(TAG, "no 'next' extra; nothing to do");
            finish();
            return;
        }

        // (1) Ask the platform what this Intent would actually reach.
        ComponentName cn = next.resolveActivity(getPackageManager());
        if (cn == null) {
            Log.w(TAG, "REFUSED: the supplied Intent resolves to nothing");
            finish();
            return;
        }

        // (2) It must be one of ours.
        if (!getPackageName().equals(cn.getPackageName())) {
            Log.w(TAG, "REFUSED: target package " + cn.getPackageName()
                    + " is not " + getPackageName());
            finish();
            return;
        }

        // (3) ...and one we deliberately made routable.
        if (!ALLOWED.contains(cn.getClassName())) {
            Log.w(TAG, "REFUSED: " + cn.getClassName() + " is not on the allow-list");
            finish();
            return;
        }

        // (4) + (5) Strip what we are not willing to lend, then pin the target.
        next.removeFlags(DANGEROUS_FLAGS);
        next.setComponent(cn);

        Log.i(TAG, "forwarding validated Intent to " + cn.flattenToShortString());
        startActivity(next);
        finish();
    }

    /**
     * The design that removes the class of bug rather than filtering it.
     *
     * The caller nominates a ROUTE, not a destination. Nothing the caller sends
     * can become part of an Intent we send, so there is no object to validate and
     * no flag to strip. Where an API can be shaped like this, it should be.
     */
    @SuppressWarnings("unused")
    private void routeByName(String route) {
        Intent out;
        if ("detail".equals(route)) {
            out = new Intent(this, DetailActivity.class);
        } else if ("settings".equals(route)) {
            out = new Intent(this, SettingsActivity.class);
        } else {
            out = new Intent(this, MainActivity.class);
        }
        startActivity(out);
    }
}
