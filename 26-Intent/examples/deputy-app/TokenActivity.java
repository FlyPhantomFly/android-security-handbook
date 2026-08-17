// examples/deputy-app/TokenActivity.java
//
// EXPORTED. Hands two PendingIntents to whoever asks — one deliberately
// vulnerable, one correct — so lab 04 can fire both on a device and watch the
// difference rather than read about it.
//
// HANDING OUT A PENDINGINTENT IS NOT THE BUG. It is how notifications, alarms,
// widgets, media sessions and every app-to-app "call me back" flow work. The bug
// is handing out a MUTABLE one wrapping an UNDER-SPECIFIED Intent.
//
// WHY THE MUTABLE ONE IS A BLANK CHEQUE
//     A PendingIntent is a record held in system_server containing an Intent plus
//     the CREATOR's identity. When somebody calls send(context, code, fillIn),
//     PendingIntentRecord.sendInner does two things, in this order:
//
//         1. finalIntent.fillIn(fillInIntent, flags)   <- attacker data merged
//         2. Binder.clearCallingIdentity()             <- creator identity assumed
//
//     Intent.fillIn copies a field from the fill-in only when the base field is
//     UNSET. blankCheque() below wraps `new Intent()`, so action, data, type,
//     categories, package AND component are all unset -- the holder chooses every
//     one of them, and step 2 then runs the result as this app.
//
// THE API 31 MANDATE
//     From targetSdk 31, PendingIntent.getActivity throws IllegalArgumentException
//     unless FLAG_IMMUTABLE or FLAG_MUTABLE is passed. That did not make anything
//     safe -- plenty of code was "fixed" by pasting FLAG_MUTABLE to make the build
//     pass -- but it did make every mutable token a visible, greppable decision.
//     Rebuild with `./build.sh --target-sdk 31` and watch blankCheque() start
//     throwing at runtime on an API 31+ device.
//
// AUTHORISED TESTING ONLY.

package com.pentest.deputy;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import java.security.SecureRandom;

public class TokenActivity extends Activity {

    private static final String TAG = "DEPUTY";

    /**
     * A per-process nonce placed INSIDE the wrapped Intent of both tokens.
     *
     * It is what makes lab 04's third flag honest. A PendingIntent's wrapped
     * Intent is not readable by the holder on modern platforms, so an attacker
     * cannot learn this value -- but Intent.fillIn preserves base extras while
     * letting the holder supply the missing component. A VaultActivity that
     * demands the nonce can therefore only be reached BY FIRING THE TOKEN, which
     * is exactly the property the exercise is meant to demonstrate.
     */
    static final String NONCE = Long.toHexString(new SecureRandom().nextLong());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Log.i(TAG, "TokenActivity: handing out two PendingIntents to "
                + getCallingActivity());
        Log.i(TAG, "  note: we CAN see the caller here, because they used "
                + "startActivityForResult. We are handing the token over anyway. "
                + "Identity is not authorisation.");

        Intent result = new Intent();
        result.putExtra("vulnerable_token", blankCheque());
        result.putExtra("safe_token", safeToken());
        setResult(RESULT_OK, result);
        finish();
    }

    /**
     * DELIBERATELY VULNERABLE: mutable, wrapping a completely blank Intent.
     *
     * On targetSdk <= 30 no flag is needed, because mutable is the default.
     * On 31+ the explicit FLAG_MUTABLE is required for the call to succeed at all.
     */
    PendingIntent blankCheque() {
        int mutableFlag = (Build.VERSION.SDK_INT >= 31) ? 0x02000000 : 0; // FLAG_MUTABLE
        Intent blank = new Intent();      // no component, no action, no data
        blank.putExtra("nonce", NONCE);   // base extras survive fillIn; see above
        return PendingIntent.getActivity(this, 1001, blank,
                PendingIntent.FLAG_UPDATE_CURRENT | mutableFlag);
    }

    /**
     * The correct default for essentially every PendingIntent an app creates:
     * an explicit Intent, and FLAG_IMMUTABLE so the fill-in is discarded.
     */
    PendingIntent safeToken() {
        Intent explicit = new Intent(this, DetailActivity.class);
        explicit.putExtra("id", "42");
        explicit.putExtra("nonce", NONCE);
        return PendingIntent.getActivity(this, 1002, explicit,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }
}
