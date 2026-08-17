// examples/victim-app/SettingsHardenedActivity.java   [H1] HARDENED
//
// The fixed counterpart to SettingsActivity. Same class, same export, same
// reachability -- one different method body.
//
// Three properties make this correct, and all three matter:
//
//   1. The allowlist is a SET OF EXACT NAMES, not a prefix, not a package
//      check, not "ends with Fragment". A prefix test on the app's own package
//      still admits every Fragment in the app, which is where the interesting
//      ones live. See README section 11 for the four allowlists that do not work.
//
//   2. It is a static final Set built once, so it cannot be mutated by anything
//      the attacker influences, and it is the same on every call.
//
//   3. It is CLOSED. A name that is not in the set is refused, rather than a
//      name matching a deny pattern being refused. Denylists lose.
//
// It also does the thing the base class already does for you and is worth
// keeping: it returns false rather than throwing, so the platform's own
// IllegalArgumentException ("Invalid fragment for this activity: X") is the
// message you see in logcat. A tester can read that line and know the gate
// held. A silent success and a silent failure look identical.

package com.pentest.ch31.victim;

import android.os.Bundle;
import android.preference.PreferenceActivity;
import android.util.Log;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class SettingsHardenedActivity extends PreferenceActivity {

    /** Every Fragment this screen is allowed to host. Exact class names. */
    private static final Set<String> ALLOWED = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList(
                    PublicFragment.class.getName()
                    // AdminFragment is deliberately NOT here. It is not a
                    // screen this Activity is ever supposed to show.
            )));

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(Vault.TAG, "SettingsHardenedActivity.onCreate showFragment="
                + getIntent().getStringExtra(EXTRA_SHOW_FRAGMENT));
        super.onCreate(savedInstanceState);
    }

    @Override
    public void onBuildHeaders(List<Header> target) {
        Header general = new Header();
        general.title = "General";
        general.fragment = PublicFragment.class.getName();
        target.add(general);
    }

    @Override
    protected boolean isValidFragment(String fragmentName) {
        boolean ok = fragmentName != null && ALLOWED.contains(fragmentName);
        Log.i(Vault.TAG, "isValidFragment(" + fragmentName + ") -> " + ok + " (HARDENED)");
        return ok;
    }
}
