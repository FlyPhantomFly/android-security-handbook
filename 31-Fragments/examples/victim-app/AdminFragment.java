// examples/victim-app/AdminFragment.java
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// THE PRIZE.
//
// This Fragment is the thing fragment injection exists to reach. Read its code
// and notice what it does NOT do:
//
//   * it does not check who started the Activity hosting it;
//   * it does not check that a login happened;
//   * it does not check anything at all.
//
// That is not carelessness on the developer's part -- it is the normal way
// Fragments are written. A Fragment is an internal building block. The
// developer's mental model is "this Fragment is only ever added by
// LoginActivity, after the PIN check, so the PIN check IS the access control".
//
// Fragment injection breaks exactly that assumption: it lets an attacker add
// the Fragment without going through the code that was supposed to add it.
//
// The lesson generalises past Fragments. Any object whose security depends on
// "only my own code constructs it" is one reflective factory away from being
// constructed by somebody else.

package com.pentest.ch31.victim;

import android.app.Fragment;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

public class AdminFragment extends Fragment {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // The evidence channel for the labs. In a real app this Fragment would
        // render the secret on screen; logging it as well is what makes the
        // attack checkable from `adb logcat` without a screenshot.
        String secret = Vault.read(getActivity());
        Log.w(Vault.TAG, "ADMIN-FRAGMENT-REACHED secret=" + secret);

        Bundle args = getArguments();
        if (args != null) {
            // Arguments arrive from whoever asked for this Fragment. When the
            // Fragment is injected, that is the attacker. See lab 03.
            // NOTE: Bundle.keySet() returns an android.util.MapCollections$KeySet,
            // whose toString() is Object's. Printing it directly gives you
            // "android.util.MapCollections$KeySet@1325cbe1" and no information.
            // Copy it into an ArrayList first. This cost a re-run.
            Log.w(Vault.TAG, "ADMIN-FRAGMENT-ARGS keys="
                    + new java.util.ArrayList<String>(args.keySet()));
            String note = args.getString("note");
            if (note != null) {
                Log.w(Vault.TAG, "ADMIN-FRAGMENT-NOTE " + note);
            }
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle saved) {
        LinearLayout root = new LinearLayout(getActivity());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(40, 40, 40, 40);
        root.setBackgroundColor(Color.parseColor("#FFF3D0"));

        TextView t = new TextView(getActivity());
        t.setTextColor(Color.BLACK);
        t.setTextSize(15f);
        // NOTE the asymmetry, and it is deliberate. The secret goes to logcat
        // (so labs 01 to 04 are checkable without a screenshot) and the stage
        // key does NOT. The only way to obtain the stage key is to look at the
        // screen of the victim's own process -- which is exactly what an
        // injected Fragment gives you and exactly what it does not give you.
        // See README section 5.7 and labs/lab-05.
        t.setText("ADMIN PANEL\n\nsecret: " + Vault.read(getActivity())
                + "\n\nsession key: " + Vault.STAGE_KEY
                + "\n\nIf you are seeing this without having typed the PIN,\n"
                + "the login screen was skipped.");
        root.addView(t);
        return root;
    }
}
