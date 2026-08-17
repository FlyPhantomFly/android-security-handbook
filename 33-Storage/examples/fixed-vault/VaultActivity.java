// examples/fixed-vault/VaultActivity.java
//
// Same entry point, same adb-drivable interface, so the two apps can be
// exercised with identical commands and their storage diffs compared directly.
//
// One line differs, and it is the one that fixes a leak no filesystem diff of
// this app would ever have found:
//
//     getWindow().setFlags(FLAG_SECURE, FLAG_SECURE);
//
// Drive it exactly as the leaky app:
//     adb shell am start -n com.pentest.ch33.vaultfixed/.VaultActivity \
//         --es action store --es secret "hunter2-REPLACE-ME"
//     adb shell am start -n com.pentest.ch33.vaultfixed/.VaultActivity --es action notes
//     adb shell am start -n com.pentest.ch33.vaultfixed/.VaultActivity --es action logout
//     adb shell am start -n com.pentest.ch33.vaultfixed/.VaultActivity --es action wipe
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch33.vaultfixed;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.Arrays;

public class VaultActivity extends Activity {

    private static final String DEFAULT_SECRET =
            "ch33-demo-token-AAAABBBBCCCCDDDDEEEEFFFF00001111";

    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // ------------------------------------------------------------------
        // THE FIX THAT NO STORAGE SCAN FINDS.
        //
        // When an activity goes to the background, the system captures a
        // thumbnail of it for the recents switcher and writes that image to a
        // system-owned directory. The file belongs to system_server, not to
        // this app: it is outside this app's sandbox, it is not deleted when
        // this app's data is cleared, and it is invisible to every hook you
        // could install in this process and to every diff of this app's own
        // directories.
        //
        // FLAG_SECURE makes the window uncapturable. The system stores a
        // placeholder instead of the content, screenshots are refused, and the
        // window does not appear in a screen recording or on a cast display.
        //
        // Set it BEFORE setContentView, and set it on every activity that can
        // display a secret -- it is per-window, not per-application, and the
        // single most common mistake is setting it on the login screen and
        // forgetting the account screen that shows the same data afterwards.
        //
        // The cost is real and worth stating to a client: users lose the
        // ability to screenshot their own data, and the recents preview becomes
        // a blank rectangle. Applying it to the whole app when only one screen
        // needs it is a usability regression sold as security.
        // ------------------------------------------------------------------
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
                             WindowManager.LayoutParams.FLAG_SECURE);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);
        root.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText("CH33 Fixed Vault");
        title.setTextSize(22);
        title.setGravity(Gravity.CENTER_HORIZONTAL);
        root.addView(title);

        out = new TextView(this);
        out.setTextSize(11);
        out.setTextIsSelectable(true);
        ScrollView sv = new ScrollView(this);
        sv.addView(out);
        root.addView(sv);

        setContentView(root);
        handle(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handle(intent);
    }

    private void handle(Intent intent) {
        String action = intent == null ? null : intent.getStringExtra("action");
        if (action == null) {
            action = "store";
        }
        String secret = intent == null ? null : intent.getStringExtra("secret");
        if (secret == null) {
            secret = DEFAULT_SECRET;
        }

        StringBuilder log = new StringBuilder();
        log.append("action = ").append(action).append("\n\n");

        try {
            if ("store".equals(action)) {
                // Hand the vault a mutable buffer it can scrub. The String we
                // received from the Intent is still in memory and cannot be
                // scrubbed -- which is a limitation of driving the app through
                // an Intent for testing, not of the design. In production the
                // value would come from an EditText's Editable, which is
                // mutable for exactly this reason.
                byte[] buf = secret.getBytes("UTF-8");
                new Vault(this).store("primary-account", buf);
                Arrays.fill(buf, (byte) 0);
                log.append("Sealed. files/vault.bin is the ONLY copy.\n");
                log.append("Compare with the leaky app, which wrote four more.\n");

            } else if ("notes".equals(action)) {
                NoteStore ns = new NoteStore(this);
                ns.addNote("Bank", "checking account", "vault:1");
                ns.addNote("Mail", "recovery address", "vault:2");
                ns.addNote("Shopping list", "milk, bread", null);
                log.append("3 notes written. None carries a credential --\n");
                log.append("vault_ref is an opaque id.\n");
                log.append("rows now = ").append(ns.countNotes()).append('\n');

            } else if ("logout".equals(action)) {
                NoteStore ns = new NoteStore(this);
                int n = ns.clearSecretsOnLogout();
                log.append("logout: deleted ").append(n).append(" rows,\n");
                log.append("checkpointed the WAL to zero length and vacuumed.\n");
                log.append("Check: ls -l databases/notes.db-wal\n");

            } else if ("wipe".equals(action)) {
                new Vault(this).wipe();
                log.append("Vault wiped and the AndroidKeyStore key destroyed.\n");
                log.append("The ciphertext is now undecryptable by anyone,\n");
                log.append("including this app. That is the only deletion\n");
                log.append("guarantee flash storage actually supports.\n");

            } else if ("all".equals(action)) {
                byte[] buf = secret.getBytes("UTF-8");
                new Vault(this).store("primary-account", buf);
                Arrays.fill(buf, (byte) 0);
                NoteStore ns = new NoteStore(this);
                ns.addNote("Bank", "checking account", "vault:1");
                ns.addNote("Mail", "recovery address", "vault:2");
                ns.clearSecretsOnLogout();
                log.append("full session executed: store, notes, logout.\n");

            } else {
                log.append("unknown action. Try: store | notes | logout | wipe | all\n");
            }
        } catch (Throwable t) {
            Log.e(Vault.TAG, "action failed", t);
            log.append("FAILED: ").append(t).append('\n');
        }

        out.setText(log.toString());
        Log.i(Vault.TAG, "action " + action + " complete");
    }
}
