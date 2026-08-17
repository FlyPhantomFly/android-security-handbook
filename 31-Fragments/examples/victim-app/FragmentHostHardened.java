// examples/victim-app/FragmentHostHardened.java   [H2] HARDENED
//
// The fix for FragmentHostActivity, and the one worth copying, because it does
// not fix the bug -- it deletes the primitive.
//
// The vulnerable version accepts a CLASS NAME. Every mitigation you can write
// on top of a class name is a filter, and filters are argued about. This
// version accepts a KEY from a closed set and maps it, in code the compiler can
// see, to a constructor call the compiler can see. There is no reflection left
// to abuse, no allowlist to get subtly wrong, and R8 can prove which Fragments
// are reachable (which the reflective version prevents -- see chapter 42).
//
//   attacker sends screen=admin   ->  not a key  ->  refused, logged
//   attacker sends screen=about   ->  PublicFragment, which they could see anyway
//   attacker sends a class name   ->  not a key  ->  refused, logged
//
// The general rule, which outlives Fragments:
//
//   DO NOT ACCEPT A TYPE NAME FROM OUTSIDE A TRUST BOUNDARY.
//   Accept a token, and choose the type yourself.
//
// The second control here is just as important and is the one people skip: the
// destination Fragment still checks the session. Defence at the routing layer
// alone means any second route to the same Fragment reopens the hole.

package com.pentest.ch31.victim;

import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.FrameLayout;

public class FragmentHostHardened extends Activity {

    public static final String EXTRA_SCREEN = "screen";
    private static final int CONTAINER_ID = 0x0f310002;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        FrameLayout container = new FrameLayout(this);
        container.setId(CONTAINER_ID);
        container.setBackgroundColor(Color.WHITE);
        setContentView(container);

        if (savedInstanceState != null) {
            return;
        }

        String screen = getIntent().getStringExtra(EXTRA_SCREEN);
        Fragment f = create(screen);

        if (f == null) {
            Log.w(Vault.TAG, "FragmentHostHardened: refused screen=" + screen);
            finish();
            return;
        }

        // Arguments are BUILT HERE, from values this Activity decided, rather
        // than forwarded from the caller's Bundle. A forwarded Bundle is an
        // attacker controlled Bundle; see chapter 24 section 3.18 for what can
        // ride inside one.
        Bundle args = new Bundle();
        args.putString("source", "hardened-host");
        f.setArguments(args);

        FragmentTransaction tx = getFragmentManager().beginTransaction();
        tx.replace(CONTAINER_ID, f);
        tx.commitAllowingStateLoss();
    }

    /**
     * The closed map. No reflection, no class names, no allowlist to maintain.
     * Adding a screen means editing this method, which is exactly the review
     * gate you want on "which screens can strangers open".
     */
    private Fragment create(String screen) {
        if (screen == null) {
            return new PublicFragment();
        }
        switch (screen) {
            case "about":
                return new PublicFragment();
            // "admin" is intentionally absent. AdminFragment is reachable only
            // through LoginActivity, which is not exported.
            default:
                return null;
        }
    }
}
