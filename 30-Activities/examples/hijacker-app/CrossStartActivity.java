// examples/hijacker-app/CrossStartActivity.java
// Package: com.pentest.ch30.attacker
//
// Not an attack. A measuring instrument for the single most confusing thing in
// the task model:
//
//     "I started another app's Activity. Whose task is it in?"
//
// ---------------------------------------------------------------------------
// WHY YOU CANNOT ANSWER THIS WITH `adb shell am start`
// ---------------------------------------------------------------------------
// `am start` runs in the shell process, which is not an Activity and has no
// task. The ActivityStarter therefore has no caller task to place the new
// activity into, and `am` supplies FLAG_ACTIVITY_NEW_TASK for you. Every
// measurement you take with `am` is silently a NEW_TASK measurement, so the
// interesting case -- an Activity starting another app's Activity WITHOUT
// NEW_TASK -- is one you can never reach from the shell.
//
// That is why this class exists. It is a real Activity in a real task, so it can
// perform the start both ways and let the reader see the difference.
//
// ---------------------------------------------------------------------------
// USAGE
// ---------------------------------------------------------------------------
//   # host -- start the victim's AlphaActivity WITHOUT FLAG_ACTIVITY_NEW_TASK
//   adb shell am start -n com.pentest.ch30.attacker/.CrossStartActivity \
//       --es target alpha --ez newtask false
//
//   # host -- the same start, WITH FLAG_ACTIVITY_NEW_TASK
//   adb shell am start -n com.pentest.ch30.attacker/.CrossStartActivity \
//       --es target alpha --ez newtask true
//
// Then read `adb shell dumpsys activity activities | grep -E "Task\{|Hist #"`.
// The expected results and what they mean are in labs/lab-01-read-the-task-graph.md.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.attacker;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class CrossStartActivity extends Activity {

    private static final String TAG = "CH30";
    private static final String VICTIM_PKG = "com.pentest.ch30.victim";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String target = getIntent().getStringExtra("target");
        boolean newTask = getIntent().getBooleanExtra("newtask", false);
        if (target == null) {
            target = "alpha";
        }

        String cls;
        if ("alpha".equals(target)) {
            cls = VICTIM_PKG + ".AlphaActivity";
        } else if ("gamma".equals(target)) {
            cls = VICTIM_PKG + ".GammaActivity";
        } else if ("delta".equals(target)) {
            cls = VICTIM_PKG + ".DeltaActivity";
        } else if ("main".equals(target)) {
            cls = VICTIM_PKG + ".MainActivity";
        } else {
            cls = VICTIM_PKG + ".AlphaActivity";
        }

        Log.i(TAG, "CrossStart myTaskId=" + getTaskId()
                + " target=" + cls + " newTask=" + newTask);

        TextView t = new TextView(this);
        t.setText("CrossStartActivity\ntaskId=" + getTaskId()
                + "\nstarting " + cls + "\nFLAG_ACTIVITY_NEW_TASK=" + newTask);
        t.setTextColor(Color.WHITE);
        t.setBackgroundColor(Color.parseColor("#004488"));
        t.setPadding(30, 140, 30, 30);
        setContentView(t);

        Intent i = new Intent();
        i.setComponent(ComponentName.unflattenFromString(VICTIM_PKG + "/" + cls));
        if (newTask) {
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        }

        try {
            startActivity(i);
        } catch (Exception e) {
            // A SecurityException here means the target was exported="false".
            // That is a result too -- record it rather than crashing the lab.
            Log.i(TAG, "CrossStart FAILED: " + e);
        }
    }
}
