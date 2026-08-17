// examples/victim-app/FragmentHostActivity.java   [V2] VULNERABLE
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// Fragment injection WITHOUT PreferenceActivity.
//
// Everyone remembers this bug class as "the PreferenceActivity bug", and that
// framing has done real damage: teams grep for `extends PreferenceActivity`,
// find nothing, and close the ticket. The bug is not PreferenceActivity. The
// bug is "a class name arrives from outside the app and something reflectively
// instantiates it". PreferenceActivity was simply the first place the platform
// shipped that pattern for you.
//
// This Activity is that pattern written by hand, and it is the shape you will
// actually meet in a modern app: one exported Activity, a deep link, a
// "screen" or "page" or "route" extra, a single dispatch point. It is how a
// notification, a push payload or a web link gets routed to a screen.
//
// TWO MODES, because the ordering of the type check is measurable and the two
// mainstream implementations differ:
//
//   mode=platform (default)
//       android.app.Fragment.instantiate(ctx, name, args)
//       Measured on API 35: the framework does Fragment.class.isAssignableFrom
//       BEFORE Class.getConstructor().newInstance(). A non Fragment class is
//       rejected without its constructor running.
//
//   mode=erasure
//       The shape androidx.fragment.app.FragmentFactory.instantiate compiles
//       to. Verified with `javap -c` against fragment-1.3.6's classes.jar:
//       loadFragmentClass() contains NO checkcast at all -- the generic cast is
//       erased -- and the only `checkcast androidx/fragment/app/Fragment` sits
//       at offset 21, AFTER `Constructor.newInstance` at offset 18.
//       So the arbitrary class's constructor runs first, and the
//       ClassCastException that follows is not in that method's exception
//       table. This mode reproduces that ordering so you can watch it on a
//       device. It is a REPLICA of AndroidX's shape, not AndroidX itself, and
//       the README says so where it reports the result.
//
// See FragmentHostHardened.java for the fix.

package com.pentest.ch31.victim;

import android.app.Activity;
import android.app.Fragment;
import android.app.FragmentTransaction;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.FrameLayout;

public class FragmentHostActivity extends Activity {

    /** The extra a caller uses to name the screen. */
    public static final String EXTRA_FRAGMENT = "fragment";
    /** Arguments handed to the Fragment, straight from the caller. */
    public static final String EXTRA_ARGS = "args";
    /** "platform" or "erasure" -- see the header. */
    public static final String EXTRA_MODE = "mode";

    /** Programmatic container id. This APK ships no resources, so no R.id. */
    private static final int CONTAINER_ID = 0x0f310001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        FrameLayout container = new FrameLayout(this);
        container.setId(CONTAINER_ID);
        container.setBackgroundColor(Color.WHITE);
        setContentView(container);

        if (savedInstanceState != null) {
            // The FragmentManager has already restored whatever was there.
            // Re-adding would double it up. See README section 3.6.
            return;
        }

        // ---------------------------------------------------------------- //
        // THE BUG, in three lines.
        //
        // getStringExtra returns whatever the caller put there. There is no
        // caller identity on an Intent (chapter 26 section 3.8), so "who asked
        // for this screen" is unanswerable here. The name is then handed to a
        // reflective factory, and the object it returns is attached to this
        // Activity, inside this app's process, with this app's uid.
        // ---------------------------------------------------------------- //
        String name = getIntent().getStringExtra(EXTRA_FRAGMENT);
        Bundle args = getIntent().getBundleExtra(EXTRA_ARGS);
        String mode = getIntent().getStringExtra(EXTRA_MODE);

        // A deep link reaches the same sink by a different road: the whole
        // point of putting both here is that a static scan for
        // getStringExtra("fragment") misses the URI path entirely.
        Uri data = getIntent().getData();
        if (name == null && data != null) {
            name = data.getQueryParameter("f");
            Log.i(Vault.TAG, "FragmentHostActivity: name came from the deep link: " + data);
        }

        if (name == null) {
            name = PublicFragment.class.getName();
        }

        Log.i(Vault.TAG, "FragmentHostActivity.onCreate name=" + name + " mode=" + mode);

        Fragment f;
        try {
            if ("erasure".equals(mode)) {
                f = instantiateTheAndroidXWay(name, args);
            } else {
                f = Fragment.instantiate(this, name, args);
            }
        } catch (Throwable t) {
            // Deliberately broad: the labs want to SEE which exception the two
            // paths produce, and they are different classes from different
            // places. Never write this in a real app.
            Log.e(Vault.TAG, "instantiate failed: " + t.getClass().getName()
                    + ": " + t.getMessage());
            return;
        }

        FragmentTransaction tx = getFragmentManager().beginTransaction();
        tx.replace(CONTAINER_ID, f);
        tx.addToBackStack("ch31");
        tx.commitAllowingStateLoss();
    }

    /**
     * The ordering AndroidX's FragmentFactory compiles to: load the class,
     * cast it with a cast that erasure deletes, construct it, and only then
     * check the type. Reproduced here so it can be measured on a device.
     */
    private Fragment instantiateTheAndroidXWay(String name, Bundle args) throws Exception {
        ClassLoader cl = getClassLoader();

        // Class.forName with initialize=false. Static initialisers do NOT run
        // here -- that is what the `false` buys, and it is worth knowing,
        // because a lot of write-ups claim otherwise.
        Class<?> clazz = Class.forName(name, false, cl);

        // The AndroidX source at this point is:
        //     return (Class<? extends Fragment>) clazz;
        // A cast to a generic type is unchecked. javac emits nothing for it.
        // The `catch (ClassCastException)` sitting under that line in the
        // AndroidX source is unreachable, and `javap -c` shows the protected
        // range containing no instruction that can throw one.
        Object o = clazz.getConstructor().newInstance();   // constructor runs HERE

        return (Fragment) o;                               // type checked HERE
    }
}
