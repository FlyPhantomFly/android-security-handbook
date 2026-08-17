// examples/victim-app/SettingsActivity.java   [V1] VULNERABLE
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// The classic fragment injection shape, unchanged since it was first published.
// It is four lines long and every one of them is the sort of thing a developer
// writes on a Tuesday afternoon.
//
// WHAT THE PLATFORM DOES FOR YOU (measured on API 35, see README section 4):
//
//   PreferenceActivity.onCreate()
//     -> String initial = getIntent().getStringExtra(":android:show_fragment")
//     -> Bundle args    = getIntent().getBundleExtra(":android:show_fragment_args")
//     -> switchToHeader(initial, args)
//          -> switchToHeaderInner(...)
//               -> if (!isValidFragment(name)) throw IllegalArgumentException
//               -> Fragment.instantiate(this, name, args)
//               -> getFragmentManager().beginTransaction()
//                       .replace(internal container id, fragment)
//                       .commitAllowingStateLoss()
//
// isValidFragment is the ONLY gate on that path. The base implementation on
// API 35 is exactly:
//
//     protected boolean isValidFragment(String fragmentName) {
//         if (getApplicationInfo().targetSdkVersion < 19) return true;
//         throw new RuntimeException("Subclasses of PreferenceActivity must "
//             + "override isValidFragment(String) to verify that the Fragment "
//             + "class is valid! ...");
//     }
//
// So a modern app CANNOT use the default -- it crashes the moment anyone opens
// the screen. The developer is forced to write an override, and the override
// below is the one that makes the crash go away with the least thought.
//
// See SettingsHardenedActivity.java for the version that does the job.

package com.pentest.ch31.victim;

import android.os.Bundle;
import android.preference.PreferenceActivity;
import android.util.Log;

import java.util.List;

public class SettingsActivity extends PreferenceActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(Vault.TAG, "SettingsActivity.onCreate showFragment="
                + getIntent().getStringExtra(EXTRA_SHOW_FRAGMENT));
        // super.onCreate is where the whole reflective path above happens.
        super.onCreate(savedInstanceState);
    }

    @Override
    public void onBuildHeaders(List<Header> target) {
        // A real app loads these from XML with loadHeadersFromResource(). This
        // APK is built without resources, so the one header is built by hand.
        Header general = new Header();
        general.title = "General";
        general.fragment = PublicFragment.class.getName();
        target.add(general);
    }

    // ------------------------------------------------------------------ //
    // THE BUG.
    //
    // The platform demanded an override. It got one. It did not get a check.
    //
    // Everything about this is comfortable: it compiles, it silences the
    // RuntimeException, it never rejects a legitimate screen, and it will never
    // show up in a crash report. It also lets any application on the device
    // load any Fragment class that this app's classloader can see.
    // ------------------------------------------------------------------ //
    @Override
    protected boolean isValidFragment(String fragmentName) {
        Log.i(Vault.TAG, "isValidFragment(" + fragmentName + ") -> true (VULNERABLE)");
        return true;
    }
}
