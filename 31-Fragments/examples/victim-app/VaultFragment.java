// examples/victim-app/VaultFragment.java
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// STAGE TWO of the CTF in labs/lab-05.
//
// This is the Fragment nothing constructs.
//
// Grep the whole application: no Activity adds it, no navigation reaches it, no
// menu item mentions it, and it appears in no manifest because Fragments never
// do. In the developer's mental model it is dead code from a feature that was
// cut, left in the tree because deleting things is scary. It is also, by that
// same reasoning, "obviously unreachable" and therefore never reviewed.
//
// Two properties make it the right stage-two target:
//
//   1. It is a DialogFragment. It has its OWN WINDOW, so it renders as a modal
//      dialog belonging to the victim application, on top of the victim
//      application, with the victim's package as the window owner -- and it
//      needs no SYSTEM_ALERT_WINDOW to do it. README section 3.8.
//
//   2. It reads getArguments() and makes a decision from what it finds. That is
//      how Fragments are always written, because arguments have always come
//      from the app's own code. When the Fragment is injected, they come from
//      a stranger. README section 5.5.
//
// The unlock value is not in logcat anywhere. AdminFragment renders it on the
// screen and nothing else does, which forces the CTF to deal with the honest
// limit of this whole bug class: an injected Fragment makes the VICTIM display
// something, and getting it back out is a separate problem.

package com.pentest.ch31.victim;

import android.app.DialogFragment;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

public class VaultFragment extends DialogFragment {

    /** The argument key. A stranger supplies this when the Fragment is injected. */
    public static final String ARG_UNLOCK = "unlock";

    private boolean mUnlocked;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Bundle args = getArguments();
        String supplied = args != null ? args.getString(ARG_UNLOCK) : null;

        // The decision. Note what it is NOT: it is not a check on who started
        // the host Activity (impossible -- an Intent carries no caller identity),
        // and it is not a check on whether a login happened. It is a comparison
        // against a value the developer assumed only their own code could know.
        mUnlocked = Vault.STAGE_KEY.equals(supplied);

        Log.i(Vault.TAG, "VaultFragment: unlock=" + (supplied == null ? "<absent>" : "<supplied>")
                + " accepted=" + mUnlocked);

        if (mUnlocked) {
            Log.w(Vault.TAG, "VAULT-FRAGMENT-UNLOCKED " + Vault.FLAG2);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle saved) {
        LinearLayout root = new LinearLayout(getActivity());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 48, 48, 48);
        root.setBackgroundColor(mUnlocked
                ? Color.parseColor("#DFF0D8")
                : Color.parseColor("#F2DEDE"));

        TextView t = new TextView(getActivity());
        t.setTextColor(Color.BLACK);
        t.setTextSize(15f);
        t.setText(mUnlocked
                ? "VAULT UNLOCKED\n\n" + Vault.FLAG2
                : "VAULT LOCKED\n\nThis dialog wants a session key in its arguments.\n"
                  + "It was not given one, or it was given the wrong one.");
        root.addView(t);
        return root;
    }
}
