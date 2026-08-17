// examples/victim-app/LegacySettingsActivity.java   [V3] THE 2013 SHAPE
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// A PreferenceActivity subclass with NO isValidFragment override at all. This
// is the original vulnerable shape: before the platform grew a gate, every
// PreferenceActivity subclass on Earth looked exactly like this, and every one
// of them would load any Fragment named in an Intent extra.
//
// What happens now depends entirely on the APK's targetSdkVersion, because the
// base implementation on API 35 is (measured from the device's own
// framework.jar, see README section 4):
//
//     protected boolean isValidFragment(String fragmentName) {
//         if (getApplicationInfo().targetSdkVersion < 19) return true;
//         throw new RuntimeException("Subclasses of PreferenceActivity must "
//             + "override isValidFragment(String) ...");
//     }
//
// So this file is an experiment with two arms, and build.sh runs both:
//
//   TARGET_SDK=35 ./build.sh     the app crashes the moment this screen is
//                                opened with any :android:show_fragment extra
//   TARGET_SDK=17 ./build.sh     the gate returns true and the injection lands
//                                with no developer mistake anywhere
//
// The second arm is the interesting one, and the measurement that matters is
// not "does the branch still exist" -- it plainly does -- but "can an APK that
// reaches it still be installed". README section 3.9 has the answer, and it is
// not the one the 2013 write-ups imply.

package com.pentest.ch31.victim;

import android.os.Bundle;
import android.util.Log;

import java.util.List;

public class LegacySettingsActivity extends android.preference.PreferenceActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Log.i(Vault.TAG, "LegacySettingsActivity.onCreate targetSdk="
                + getApplicationInfo().targetSdkVersion
                + " showFragment=" + getIntent().getStringExtra(EXTRA_SHOW_FRAGMENT));
        super.onCreate(savedInstanceState);
    }

    @Override
    public void onBuildHeaders(List<Header> target) {
        Header general = new Header();
        general.title = "General";
        general.fragment = PublicFragment.class.getName();
        target.add(general);
    }

    // No isValidFragment override. Deliberately.
}
