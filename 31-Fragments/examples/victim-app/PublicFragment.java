// examples/victim-app/PublicFragment.java
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// The Fragment the two host Activities are SUPPOSED to show. It holds nothing
// interesting, which is the point: it is the control for every experiment in
// this chapter. If you can load this one but not AdminFragment, the allowlist
// is working. If you can load both, it is not.

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

public class PublicFragment extends Fragment {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.i(Vault.TAG, "PUBLIC-FRAGMENT-REACHED (this one is harmless)");
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle saved) {
        LinearLayout root = new LinearLayout(getActivity());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(40, 40, 40, 40);
        root.setBackgroundColor(Color.parseColor("#E3F2E1"));

        TextView t = new TextView(getActivity());
        t.setTextColor(Color.BLACK);
        t.setTextSize(15f);
        t.setText("About this app\n\nVersion 1.0. No secrets here.\n\n"
                + "This is the Fragment the host Activity is meant to show.");
        root.addView(t);
        return root;
    }
}
