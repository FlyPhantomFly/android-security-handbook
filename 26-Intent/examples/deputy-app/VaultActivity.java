// examples/deputy-app/VaultActivity.java
//
// The CTF component for labs/lab-04-ctf-the-courier.md. It holds three of the four
// flags; the fourth lives in SecretActivity and is lab 01's result.
//
// Each flag is gated on the reader having UNDERSTOOD a mechanism, not on having
// guessed a string:
//
//   FLAG A — RESOLUTION / CROSS PRODUCT
//       This activity's BROWSABLE filter declares two schemes and two hosts in
//       separate <data> elements. The developer meant two URIs. The platform
//       stores schemes and authorities as INDEPENDENT SETS, so four are accepted.
//       The flag is emitted only for one of the two combinations the developer
//       never intended. You get it by computing the cross product, not by
//       fuzzing -- and you can compute it from `dumpsys package` alone.
//
//   FLAG C — PENDINGINTENT MUTABILITY
//       Emitted only when the arriving Intent carries the nonce that TokenActivity
//       placed INSIDE the wrapped Intent of its tokens. A PendingIntent's wrapped
//       Intent is not readable by the holder on modern platforms, so the nonce
//       cannot be guessed or read -- but Intent.fillIn preserves base extras while
//       letting the holder supply the missing COMPONENT. Arriving here with a valid
//       nonce therefore proves you filled in and fired the mutable token. Firing
//       the IMMUTABLE token cannot get you here, because the fill-in is discarded
//       and its own component (DetailActivity) wins.
//
//   FLAG D — CATEGORY_DEFAULT
//       Emitted for an action whose filter deliberately omits
//       android.intent.category.DEFAULT. Context.startActivity ADDS that category
//       to implicit Intents, so no implicit start can ever match this filter. It is
//       reachable explicitly, by class name, and the class name is in the manifest.
//       The flag is the reward for knowing that "not reachable implicitly" and
//       "not reachable" are different sentences.
//
// AUTHORISED TESTING ONLY. This class is part of a deliberately vulnerable app.

package com.pentest.deputy;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class VaultActivity extends Activity {

    private static final String TAG = "DEPUTY";

    static final String FLAG_A = "FLAG{cross_product_not_tuples}";
    static final String FLAG_C = "FLAG{blank_cheque_signed_with_their_uid}";
    static final String FLAG_D = "FLAG{default_is_added_by_startActivity}";

    /**
     * The combination the developer never meant to accept.
     *
     * The filter declares schemes {deputy, vault} and hosts {open, locker}, from
     * two <data> elements that were written as two pairs:
     *     deputy://locker   (intended)
     *     vault://open      (intended)
     * The platform also accepts:
     *     deputy://open
     *     vault://locker    <-- this one is the flag
     */
    private static final String UNINTENDED = "vault://locker";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent in = getIntent();
        String action = in.getAction();
        Uri data = in.getData();
        String nonce = in.getStringExtra("nonce");

        StringBuilder sb = new StringBuilder();
        sb.append("VaultActivity\n")
          .append("action = ").append(action).append('\n')
          .append("data   = ").append(data).append('\n')
          .append("caller = ").append(getCallingActivity()).append('\n')
          .append('\n');

        Log.i(TAG, "VaultActivity action=" + action + " data=" + data
                + " nonceSupplied=" + (nonce != null));

        // ---- FLAG A ---- the unintended cross-product combination ------------
        if (data != null) {
            String normalised = data.getScheme() + "://" + data.getHost();
            if (UNINTENDED.equals(normalised)) {
                sb.append(FLAG_A).append('\n');
                Log.w(TAG, FLAG_A);
            } else {
                sb.append("this URI is one the developer intended. Two of the four\n")
                  .append("combinations this filter accepts were never written down.\n");
            }
        }

        // ---- FLAG C ---- arrived by firing the mutable PendingIntent ---------
        if (nonce != null) {
            if (TokenActivity.NONCE.equals(nonce)) {
                sb.append(FLAG_C).append('\n');
                Log.w(TAG, FLAG_C);
                sb.append("you supplied a component we never chose, and the system\n")
                  .append("started it as US, because the token was mutable.\n");
            } else {
                sb.append("nonce present but wrong. It is not guessable: it lives\n")
                  .append("inside the token's wrapped Intent, which you cannot read.\n");
            }
        }

        // ---- FLAG D ---- reached through the filter with no DEFAULT ----------
        if ("com.pentest.deputy.VAULT_DIRECT".equals(action)) {
            sb.append(FLAG_D).append('\n');
            Log.w(TAG, FLAG_D);
            sb.append("that filter declares no CATEGORY_DEFAULT, so no implicit\n")
              .append("startActivity could ever have matched it. You came in by name.\n");
        }

        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);
        tv.setTextSize(13f);
        tv.setText(sb.toString());
        setContentView(tv);
    }
}
