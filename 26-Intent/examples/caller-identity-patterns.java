// examples/caller-identity-patterns.java
//
// The three tiers of caller identity, as code, with the correct pattern for each
// and the two wrong patterns that appear constantly in production Android security
// code. Sections 3.8 and 9.5 of README.md walk through it.
//
// THE TIERS, ONCE, PLAINLY
//
//   TIER 1  KERNEL-STAMPED.  Binder.getCallingUid() inside a LIVE Binder
//                            transaction -- that is, inside a bound Service's
//                            AIDL method. The binder driver writes the sender's
//                            euid into the receiving thread's state; nothing in
//                            user space can forge it. Chapter 25 owns this half.
//
//   TIER 2  SYSTEM-STAMPED.  Activity.getCallingActivity() -- but ONLY after
//                            startActivityForResult -- and
//                            PendingIntent.getCreatorUid/getCreatorPackage.
//                            system_server fills these in from data it holds,
//                            not from the message. Trustworthy, narrow, easy to
//                            forget exists.
//
//   TIER 3  MESSAGE-CARRIED. Everything else: extras, EXTRA_REFERRER,
//                            getReferrer(), a "caller" string, a query parameter.
//                            ATTACKER-AUTHORED. Zero evidential value.
//
// When you review code that authorises a caller, find which tier it reads from.
// A surprising amount of production code reads tier 3 and believes it is reading
// tier 1.
//
// This file has no public class so it can carry a descriptive filename. Compile it
// against android.jar exactly as examples/intent-field-semantics.java is compiled.

package com.pentest.deputy;

import android.app.Activity;
import android.app.PendingIntent;
import android.app.Service;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.util.Log;

import java.security.MessageDigest;
import java.util.Arrays;

class CallerIdentityPatterns {
    private static final String TAG = "IDENTITY";

    // ===================================================================== //
    //  WRONG 1 -- reading tier 3 and calling it authorisation.               //
    // ===================================================================== //

    /**
     * BROKEN. Every value read here was written by the caller.
     *
     * getReferrer() falls back to Intent.EXTRA_REFERRER, which is an ordinary
     * extra. A "caller" extra is an ordinary extra. Both are one line to forge:
     *
     *     i.putExtra(Intent.EXTRA_REFERRER, Uri.parse("android-app://com.trusted"));
     *     i.putExtra("caller", "com.trusted");
     */
    static boolean brokenReferrerCheck(Activity ctx) {
        Object ref = ctx.getReferrer();                       // TIER 3
        String claimed = ctx.getIntent().getStringExtra("caller");   // TIER 3
        Log.w(TAG, "BROKEN check: referrer=" + ref + " claimed=" + claimed);
        return "com.trusted.app".equals(claimed);
    }

    /**
     * ALSO BROKEN, and much more common, because it LOOKS like tier 1.
     *
     * Binder.getCallingUid() inside onCreate returns THIS app's own uid. The
     * identity stamp exists on the transaction into system_server; delivering the
     * Activity to you is a separate, later transaction that originates FROM
     * system_server. By the time onCreate runs, the only calling identity in scope
     * is your own -- so this check always passes and its author always believes it
     * works. The same is true inside BroadcastReceiver.onReceive.
     */
    static boolean brokenUidCheckInActivity(Activity ctx) {
        int uid = Binder.getCallingUid();                     // == Process.myUid()
        Log.w(TAG, "BROKEN check: getCallingUid() in onCreate = " + uid
                + " (this is OUR uid, not the caller's)");
        return uid == 1000;
    }

    // ===================================================================== //
    //  PATTERN A -- tier 2, and its limits.                                  //
    // ===================================================================== //

    /**
     * Correct, within its limits. getCallingActivity() is set by the system and
     * cannot be forged -- but it is NULL unless the caller used
     * startActivityForResult, so the method must FAIL CLOSED on null.
     *
     * And a package NAME is still not an identity. Package names are
     * attacker-choosable wherever the attacker controls installation (sideloading,
     * a rooted device, an unclaimed name). Bind the name to a signing certificate,
     * which is what verifySigner below does.
     */
    static boolean patternA_callingActivity(Activity ctx, byte[] expectedCertSha256) {
        ComponentName caller = ctx.getCallingActivity();      // TIER 2
        if (caller == null) {
            Log.i(TAG, "no result channel -> no identity at all. Failing closed.");
            return false;
        }
        return verifySigner(ctx, caller.getPackageName(), expectedCertSha256);
    }

    // ===================================================================== //
    //  PATTERN B -- tier 1. The strong one.                                  //
    // ===================================================================== //

    /**
     * Expose the operation over a bound Service and read the kernel-stamped uid
     * inside the Binder transaction. This is the only place on the Intent-adjacent
     * surface where a real caller identity exists.
     *
     * Note getPackagesForUid: a uid can map to SEVERAL packages when they share a
     * sharedUserId, so every one of them must satisfy the signature check --
     * checking only the first is a bypass.
     */
    abstract static class StrongBridgeService extends Service {

        private final byte[] expected;

        StrongBridgeService(byte[] expectedCertSha256) {
            this.expected = expectedCertSha256;
        }

        private final IBinder binder = new Binder() {
            @Override
            protected boolean onTransact(int code, android.os.Parcel data,
                                         android.os.Parcel reply, int flags)
                    throws android.os.RemoteException {
                int uid = Binder.getCallingUid();             // TIER 1, unforgeable
                String[] pkgs = getPackageManager().getPackagesForUid(uid);
                if (pkgs == null || pkgs.length == 0) {
                    throw new SecurityException("uid " + uid + " has no packages");
                }
                for (String p : pkgs) {
                    if (!verifySigner(StrongBridgeService.this, p, expected)) {
                        throw new SecurityException("uid " + uid + " package " + p
                                + " is not signed by the expected key");
                    }
                }
                Log.i(TAG, "authorised uid " + uid + " " + Arrays.toString(pkgs));
                return super.onTransact(code, data, reply, flags);
            }
        };

        @Override public IBinder onBind(Intent intent) { return binder; }
    }

    // ===================================================================== //
    //  PATTERN C -- let the platform do it. Usually the right answer.        //
    // ===================================================================== //

    //  AndroidManifest.xml:
    //
    //      <permission android:name="com.pentest.deputy.permission.BRIDGE"
    //                  android:protectionLevel="signature"/>
    //
    //      <activity android:name=".AuthBridgeActivity"
    //                android:exported="true"
    //                android:permission="com.pentest.deputy.permission.BRIDGE"/>
    //
    //  There is nothing to write in Java. system_server enforces the permission
    //  before your code runs, and a signature-level permission can only be held by
    //  an app signed with your key -- which is the certificate check of pattern A
    //  and B, performed by the platform, at install time, for free.
    //
    //  Resolve the protectionLevel before trusting any permission you see in a
    //  manifest. A `normal`-level custom permission is not a control: any app can
    //  request it and receive it, silently. See 23-Permissions.

    // ===================================================================== //
    //  PATTERN D -- the receiving end of a PendingIntent.                    //
    // ===================================================================== //

    /**
     * If another app hands you a PendingIntent, you have tier 2 identity about its
     * CREATOR, filled in by the system. Use it. This is the one identity primitive
     * that works without a result channel and without a bound Service.
     *
     * It tells you who MINTED the token, which is not necessarily who handed it to
     * you -- a token can be passed on. That is usually what you want anyway: the
     * question is whose authority will be used when you fire it.
     */
    static boolean patternD_pendingIntentCreator(Context ctx, Intent in,
                                                 byte[] expectedCertSha256) {
        PendingIntent pi = in.getParcelableExtra("callback");
        if (pi == null) { return false; }
        String creator = pi.getCreatorPackage();              // TIER 2
        int creatorUid = pi.getCreatorUid();                  // TIER 2
        Log.i(TAG, "token creator = " + creator + " uid=" + creatorUid);
        return creator != null && verifySigner(ctx, creator, expectedCertSha256);
    }

    // ===================================================================== //
    //  The certificate check every pattern above depends on.                 //
    // ===================================================================== //

    /**
     * Map a package name to the SHA-256 of its signing certificate and compare.
     *
     * GET_SIGNING_CERTIFICATES (API 28+) returns the rotation-aware history;
     * getApkContentsSigners() is the current signer set. On older platforms the
     * equivalent is GET_SIGNATURES, which does not understand key rotation.
     *
     * MessageDigest.isEqual is used rather than Arrays.equals because it is the
     * constant-time comparison; the timing channel here is negligible, but the
     * habit is worth having and a reviewer will look for it.
     */
    static boolean verifySigner(Context ctx, String pkg, byte[] expectedSha256) {
        try {
            PackageManager pm = ctx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
            Signature[] sigs = pi.signingInfo.getApkContentsSigners();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (Signature s : sigs) {
                if (MessageDigest.isEqual(md.digest(s.toByteArray()), expectedSha256)) {
                    return true;
                }
            }
            Log.w(TAG, "signature mismatch for " + pkg);
            return false;
        } catch (Exception e) {
            Log.w(TAG, "cannot verify " + pkg + ": " + e);
            return false;    // fail closed
        }
    }

    // ===================================================================== //
    //  Putting it together: the enterprise shape from README section 9.5.    //
    // ===================================================================== //

    abstract static class AuthBridgeActivity extends Activity {

        protected abstract byte[] expectedCert();

        @Override
        protected void onCreate(Bundle b) {
            super.onCreate(b);

            // TIER 2, fail closed on null.
            ComponentName caller = getCallingActivity();
            if (caller == null) { setResult(RESULT_CANCELED); finish(); return; }

            // Bind the name to a certificate.
            if (!verifySigner(this, caller.getPackageName(), expectedCert())) {
                setResult(RESULT_CANCELED); finish(); return;
            }

            // TIER 3 -- validate as untrusted input, because that is what it is.
            String op = getIntent().getStringExtra("op");
            if (!"challenge".equals(op)) { setResult(RESULT_CANCELED); finish(); return; }

            // Never hand a bearer token to a caller identified only over an Intent.
            // Return something short-lived, single-use and bound to the audience.
            Intent result = new Intent();
            result.putExtra("response", signChallengeFor(caller.getPackageName()));
            setResult(RESULT_OK, result);
            finish();
        }

        protected abstract String signChallengeFor(String audiencePackage);
    }
}
