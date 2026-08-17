// examples/leaky-vault/VaultActivity.java
//
// The entry point. Deliberately headless-friendly: everything it does can be
// driven from `adb shell am start` with extras, so labs/lab-02 can exercise a
// full "session" without anybody touching the screen. A lab that depends on
// tapping buttons is a lab that cannot be repeated identically, and a
// filesystem diff is only meaningful if the exercise between the two snapshots
// is exactly reproducible.
//
// Drive it:
//     # host -- store a secret
//     adb shell am start -n com.pentest.ch33.vault/.VaultActivity \
//         --es action store --es secret "hunter2-REPLACE-ME"
//
//     # host -- add notes, then "log out"
//     adb shell am start -n com.pentest.ch33.vault/.VaultActivity --es action notes
//     adb shell am start -n com.pentest.ch33.vault/.VaultActivity --es action logout
//
//     # host -- run the measurement probe and print it
//     adb shell am start -n com.pentest.ch33.vault/.VaultActivity --es action probe
//     adb logcat -d -s CH33Probe:V
//
// NOTE ON THE TEST DEVICE USED FOR THIS CHAPTER: while the keyguard is up, this
// MIUI build refuses activity starts that originate from an app, though
// `am start` from adb still works. If a lab step appears to do nothing, unlock
// the screen and check:
//     adb shell "dumpsys trust" | grep -o "deviceLocked=[01]"
// The failure is silent: `am start` reports Success and delivers nothing,
// so the lab looks broken rather than blocked. It cost chapter 30 a whole
// demonstration before the keyguard state was checked.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch33.vault;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class VaultActivity extends Activity {

    /** Overwritten by --es secret. The default is obviously fake on purpose. */
    private static final String DEFAULT_SECRET =
            "ch33-demo-token-AAAABBBBCCCCDDDDEEEEFFFF00001111";

    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // ------------------------------------------------------------------
        // NOT setting FLAG_SECURE is a decision, and it is the one taken here.
        //
        // Without it, the system writes a task snapshot -- the image you see in
        // the recents switcher -- to a system-owned directory when this
        // activity goes to the background. That file is outside this app's
        // sandbox, is written by system_server rather than by this process, and
        // is therefore invisible to every hook, every diff of the app's own
        // directories, and every manifest audit. It is also not something the
        // app can delete.
        //
        // The fixed app does:
        //     getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE,
        //                          WindowManager.LayoutParams.FLAG_SECURE);
        // See README section 3.9 for where the snapshots land and how to look.
        // ------------------------------------------------------------------

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);
        root.setBackgroundColor(Color.WHITE);

        TextView title = new TextView(this);
        title.setText("CH33 Leaky Vault");
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
                new Vault(this).store("primary-account", secret);
                log.append("Stored. Ciphertext is in files/vault.bin.\n");
                log.append("Four plaintext copies were written alongside it.\n");
                log.append("Find them with:\n");
                log.append("  scripts/storage-map.sh com.pentest.ch33.vault\n");
                log.append("  scripts/leak-hunter.py --package com.pentest.ch33.vault\n");

            } else if ("notes".equals(action)) {
                NoteStore ns = new NoteStore(this);
                ns.addNote("Bank", "checking account",
                           "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch33");
                ns.addNote("Mail", "recovery address", "ch33-recovery-code-889912");
                ns.addNote("Shopping list", "milk, bread", null);
                log.append("3 notes written, 2 carrying a secret column.\n");
                log.append("rows now = ").append(ns.countNotes()).append('\n');

            } else if ("logout".equals(action)) {
                NoteStore ns = new NoteStore(this);
                int n = ns.clearSecretsOnLogout();
                log.append("logout: deleted ").append(n).append(" rows.\n");
                log.append("rows now = ").append(ns.countNotes()).append('\n');
                log.append("\nThe rows are gone from the table. They are NOT gone\n");
                log.append("from the disk. Check databases/notes.db-wal.\n");

            } else if ("probe".equals(action)) {
                log.append(new StorageProbe(this).run());

            } else if ("all".equals(action)) {
                new Vault(this).store("primary-account", secret);
                NoteStore ns = new NoteStore(this);
                ns.addNote("Bank", "checking account",
                           "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch33");
                ns.addNote("Mail", "recovery address", "ch33-recovery-code-889912");
                ns.clearSecretsOnLogout();
                log.append("full session executed: store, notes, logout.\n");

            } else {
                log.append("unknown action. Try: store | notes | logout | probe | all\n");
            }
        } catch (Throwable t) {
            Log.e(Vault.TAG, "action failed", t);
            log.append("FAILED: ").append(t).append('\n');
        }

        out.setText(log.toString());
        Log.i(Vault.TAG, "action " + action + " complete");
    }
}
