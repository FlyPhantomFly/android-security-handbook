// examples/RedirectorActivity.java
//
// VULNERABLE — the intent-redirection primitive, in its minimal honest form.
//
// This is the class the whole chapter is about. It is deliberately short, because
// the bug IS short: four lines. Everything that makes it dangerous happens in
// system_server, not here.
//
// WHY A COMPETENT DEVELOPER WRITES THIS
//     "Let the caller tell me where to go next" is how deep-link routers, login
//     gates, notification trampolines and share sheets are built. The developer is
//     thinking about composition. They are not thinking about the fact that a
//     Parcelable extra of type Intent is a fully attacker-authored object carrying
//     an arbitrary component, an arbitrary data URI and arbitrary flags.
//
// WHAT THE ATTACKER GAINS
//     startActivity() below is called BY THIS APP, so ActivityStarter inside
//     system_server sees Binder.getCallingUid() == this app's uid. Its export
//     check is literally `callingUid != aInfo.applicationInfo.uid`, so:
//
//       * this app's NON-EXPORTED components become reachable;
//       * permissions this app holds and the attacker does not are usable;
//       * FLAG_GRANT_* riding on the inner Intent are issued with this app's
//         authority (grant laundering -- see 27-ContentProviders section 5.4).
//
// HOW TO BUILD AND RUN IT
//     This file is compiled into the deputy app by examples/deputy-app/build.sh.
//     Lab 01 (labs/lab-01-intent-redirection.md) drives it end to end, with a
//     negative control.
//
// AUTHORISED TESTING ONLY. This is intentionally vulnerable code. Do not paste it
// into anything that ships.

package com.pentest.deputy;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class RedirectorActivity extends Activity {

    private static final String TAG = "DEPUTY";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // getCallingActivity() is null here unless the caller used
        // startActivityForResult. Even when it is not null, a package NAME is not
        // an identity. Printed so the lab can show what is and is not available.
        Log.i(TAG, "RedirectorActivity started. getCallingActivity() = "
                + getCallingActivity());

        // ------------------------------------------------------------------
        // FLAVOUR A -- the Parcelable extra.
        //
        // Reachable ONLY from a real application: `am` has no Parcelable extra
        // type, and Intent.parseUri has no syntax for a nested Intent. That is
        // why lab 01 ships an attacker APK instead of a shell one-liner.
        // ------------------------------------------------------------------
        Intent next = getIntent().getParcelableExtra("next");
        if (next != null) {
            Log.w(TAG, "forwarding an attacker-supplied Intent: " + next);
            // THE BUG. No validation of the component, the package, the data URI
            // or the flags. This runs as our uid.
            startActivity(next);
            finish();
            return;
        }

        // ------------------------------------------------------------------
        // FLAVOUR B -- the string / URI form.
        //
        // Same bug, but the payload is TEXT, so it survives a URL, a query
        // parameter, a push payload or `am --es`. If the entry filter carries
        // CATEGORY_BROWSABLE this is reachable from a WEB PAGE, which raises the
        // severity a band: no malicious app needs to be installed.
        // ------------------------------------------------------------------
        String uri = getIntent().getStringExtra("next_uri");
        if (uri == null && getIntent().getData() != null) {
            uri = getIntent().getData().getQueryParameter("to");
        }
        if (uri != null) {
            try {
                Intent parsed = Intent.parseUri(uri, Intent.URI_INTENT_SCHEME);
                Log.w(TAG, "forwarding a parsed Intent: " + parsed);
                startActivity(parsed);      // THE BUG, again
            } catch (Exception e) {
                Log.e(TAG, "parseUri failed: " + e);
            }
        }

        finish();
    }
}
