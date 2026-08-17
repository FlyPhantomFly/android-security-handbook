// examples/victim-app/NotAFragment.java
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// A class that is NOT a Fragment, and that shouts when it is touched. It is the
// instrument for one specific measurement: does the reflective loader check the
// TYPE before or after it runs the CONSTRUCTOR?
//
// Three log lines, three distinct events:
//
//   NOTAFRAGMENT-CLINIT   the static initialiser ran (class initialisation)
//   NOTAFRAGMENT-CTOR     the no argument constructor ran (object creation)
//   (no line at all)      the class was rejected before either
//
// Point FragmentHostActivity at this class in each of its two modes and read
// logcat. The two answers are different, and the difference is the whole
// argument for why "it casts to Fragment, so it is safe" is not a control.
//
// In a real target the equivalent class is not a toy. It is whatever class in
// the app's classpath does something useful in a static initialiser or a
// no argument constructor -- a crash reporter that starts uploading, a cache
// that wipes itself, a feature flag holder that reloads from disk, a debug
// helper that opens a socket. Gadget hunting in an Android app is exactly this
// search, and it is the same skill as gadget hunting for Java deserialisation.

package com.pentest.ch31.victim;

import android.util.Log;

public class NotAFragment {

    static {
        Log.w(Vault.TAG, "NOTAFRAGMENT-CLINIT static initialiser ran");
    }

    public NotAFragment() {
        Log.w(Vault.TAG, "NOTAFRAGMENT-CTOR no argument constructor ran");
    }
}
