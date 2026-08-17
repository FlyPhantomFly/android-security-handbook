/*
 * MainActivity.java
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   The visible half of the chapter 38 self-integrity demonstration app. It
 *   runs IntegrityGate off the main thread, prints every result on screen, and
 *   also writes each result to logcat under the tag CH38 so that the labs can
 *   read the outcome with `adb logcat` instead of squinting at a phone.
 *
 *   The app builds its whole UI in code. There is no layout XML, no resource
 *   IDs and no R class, because ../build.sh links a resource-free APK with
 *   aapt2 and that keeps the build to five commands with no Gradle anywhere.
 *
 * WHAT THIS APP DELIBERATELY DOES NOT DO
 *   It does not exit, crash, or hide functionality when a check fails. It
 *   REPORTS. A production app would do something, and section 5.8 of the
 *   chapter README argues at length that what it should do is tell a server and
 *   let the server decide. For a teaching artefact, "print the truth" beats
 *   "die mysteriously" every time - and dying mysteriously is exactly the
 *   behaviour lab 04's CTF asks you to diagnose in an app that does it.
 *
 * USAGE
 *   # host
 *   ./build.sh --install
 *   adb shell am start -n com.pentest.ch38.integrity/.MainActivity
 *   adb logcat -s CH38:V
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   Whether the device is clean. Read the header of IntegrityGate.java.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

package com.pentest.ch38.integrity;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.List;

public class MainActivity extends Activity {

    static final String TAG = "CH38";

    private TextView out;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView sv = new ScrollView(this);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setPadding(24, 48, 24, 48);

        TextView title = new TextView(this);
        title.setText("CH38 — self-integrity gate");
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setGravity(Gravity.START);
        col.addView(title, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        out = new TextView(this);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextSize(11);
        out.setTextIsSelectable(true);
        out.setText("running…");
        col.addView(out, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        sv.addView(col);
        setContentView(sv);

        // D6 opens a TCP socket. Any network operation on the main thread throws
        // NetworkOnMainThreadException from API 11 onwards, so the whole gate
        // runs on a worker. This is not a stylistic choice: run it on the main
        // thread and the app crashes before it prints anything, which is a
        // genuinely confusing first experience.
        final Handler ui = new Handler(Looper.getMainLooper());
        new Thread(new Runnable() {
            @Override public void run() {
                long t0 = System.nanoTime();
                final List<IntegrityGate.CheckResult> results = IntegrityGate.runAll(MainActivity.this);
                long us = (System.nanoTime() - t0) / 1000;

                final StringBuilder sb = new StringBuilder();
                int fails = 0, unknowns = 0;
                for (IntegrityGate.CheckResult r : results) {
                    if (r.verdict == IntegrityGate.Verdict.FAIL) fails++;
                    if (r.verdict == IntegrityGate.Verdict.UNKNOWN) unknowns++;
                    Log.i(TAG, r.id + " " + r.name + " = " + r.verdict + " | " + r.evidence);
                    sb.append(r).append("\n\n");
                }
                sb.append("---\n")
                  .append(results.size()).append(" checks, ")
                  .append(fails).append(" FAIL, ")
                  .append(unknowns).append(" UNKNOWN, in ")
                  .append(us).append(" us\n");

                Log.i(TAG, "SUMMARY checks=" + results.size() + " fail=" + fails
                        + " unknown=" + unknowns + " elapsed_us=" + us);

                ui.post(new Runnable() {
                    @Override public void run() {
                        out.setText(sb.toString());
                        out.setTextColor(Color.BLACK);
                    }
                });
            }
        }, "ch38-gate").start();
    }
}
