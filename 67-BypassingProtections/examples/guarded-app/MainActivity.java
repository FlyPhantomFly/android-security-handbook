/*
 * examples/guarded-app/MainActivity.java
 *
 * The whole app, on one screen: run the pipeline, print every stage, and open
 * the vault if the branch allows it.
 *
 * The UI is built in code rather than XML so that the app needs no resource
 * files beyond the manifest, which keeps ../build.sh to a single aapt2
 * invocation and keeps the sources readable as sources.
 *
 * READ THE ORDER OF onCreate() CAREFULLY. It is the timeline every lab in this
 * chapter refers to:
 *
 *   t0  process forks from zygote
 *   t1  NativeGuard's static initialiser -> System.loadLibrary("ch67guard")
 *         -> .init_array constructor runs        (native, seam S2)
 *         -> JNI_OnLoad runs, and may abort()    (native, seams S1 and S2)
 *   t2  Guard.evaluate()                         (Java, seams S1 and S2 -> S3)
 *   t3  Guard.enforce()                          (Java, seam S4)
 *   t4  Vault.open()                             (Java, seam S5)
 *
 * A Frida script that ATTACHES lands somewhere after t2 on a warm process and
 * has already missed t1 entirely. That is not a Frida limitation; it is what
 * "attach" means.
 */
package com.pentest.ch67.guarded;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {

    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (12 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("CH67 Guarded");
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextSize(20);
        root.addView(title);

        Button open = new Button(this);
        open.setText("Open the vault (checked)");
        root.addView(open);

        Button unchecked = new Button(this);
        unchecked.setText("Open the vault (unchecked entry)");
        root.addView(unchecked);

        out = new TextView(this);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextSize(10);
        out.setTextIsSelectable(true);
        ScrollView sv = new ScrollView(this);
        sv.addView(out);
        root.addView(sv);

        setContentView(root);

        /*
         * t1 - touch NativeGuard first, so the native tier runs before the
         * Java tier. Referencing any member of the class triggers its static
         * initialiser and therefore System.loadLibrary().
         *
         * A real packed application does this from
         * Application.attachBaseContext(), which is earlier still. The
         * difference matters to an attacker by about 200 milliseconds and by
         * one whole category of technique.
         */
        String nativeState = NativeGuard.isLoaded() ? "loaded" : "absent";
        append("native tier: " + nativeState);
        append(NativeGuard.report());
        append("");

        /*
         * t2 and t3.
         *
         * `simulate` is a lab harness, documented in full on Guard.evaluate.
         * It marks a named signal as fired without changing what the read
         * returned, so that a reader on a stock unrooted phone can still see
         * every response's death signature:
         *
         *   adb shell am start -n com.pentest.ch67.guarded/.MainActivity \
         *       --ez auto_open true --es simulate frida.threadnames
         */
        String simulate = (getIntent() == null) ? null : getIntent().getStringExtra("simulate");
        final Guard.Verdict v = Guard.evaluate(this, simulate);
        append(v.describe());

        open.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                append("--- checked open ---");
                try {
                    String secret = Vault.open(v);
                    append("SECRET: " + secret);
                } catch (Throwable t) {
                    // The THROW response arrives here. Catching it is what a
                    // real app would NOT do; it is caught so that the demo can
                    // show you the difference between a response that kills
                    // the process and one that only kills the operation.
                    append("refused: " + t);
                    Log.w(Guard.TAG, "checked open refused", t);
                }
            }
        });

        unchecked.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                append("--- unchecked open (seam " + Guard.SEAM_GATED + ") ---");
                append("SECRET: " + Vault.openUnchecked());
            }
        });

        /* Colour is only ever cosmetic, but a red screen is a fast signal in a
           lab where you are running the same app twenty times. */
        title.setTextColor(v.trusted ? Color.rgb(0, 128, 0) : Color.rgb(180, 0, 0));

        /*
         * A scripting affordance, not a protection bypass.
         *
         *   adb shell am start -n com.pentest.ch67.guarded/.MainActivity \
         *       --ez auto_open true
         *
         * runs the checked path with no human tapping a button, so that every
         * lab in this chapter can be reproduced from a shell script and so
         * that scripts/bypass-triage.py can drive the app itself. It reaches
         * the SAME Vault.open(v) the button reaches - nothing is skipped and
         * nothing is weakened. Deliberately left in the release variant too,
         * because a lab you cannot automate is a lab nobody repeats.
         */
        if (getIntent() != null && getIntent().getBooleanExtra("auto_open", false)) {
            append("--- auto_open: taking the checked path ---");
            try {
                append("SECRET: " + Vault.open(v));
            } catch (Throwable t) {
                append("refused: " + t);
                Log.w(Guard.TAG, "auto_open refused", t);
            }
        }
    }

    private void append(String s) {
        out.append(s);
        out.append("\n");
        Log.i(Guard.TAG, s);
    }
}
