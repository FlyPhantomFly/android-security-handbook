// examples/victim-app/LoginActivity.java
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// The INTENDED route to AdminFragment, and the control for the whole chapter.
//
// It is not exported, so no other application can start it. The PIN check is
// real. If this were the only way to construct AdminFragment, the app would be
// fine -- and this is precisely the reasoning that makes fragment injection so
// effective: the developer's security argument is correct about the route they
// thought about, and says nothing about the route the platform provides.
//
// Read this file and SettingsActivity.java side by side. The gate is here. The
// hole is there. Nothing connects them, which is why a code review that looks
// at the login flow finds nothing wrong.

package com.pentest.ch31.victim;

import android.app.Activity;
import android.app.FragmentTransaction;
import android.graphics.Color;
import android.os.Bundle;
import android.text.InputType;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

public class LoginActivity extends Activity {

    private static final String PIN = "4821";
    private static final int CONTAINER_ID = 0x0f310003;

    private EditText mPin;
    private FrameLayout mContainer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);
        root.setBackgroundColor(Color.WHITE);

        TextView t = new TextView(this);
        t.setTextColor(Color.BLACK);
        t.setText("Enter your PIN to open the admin panel.");
        root.addView(t);

        mPin = new EditText(this);
        mPin.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        mPin.setHint("PIN");
        root.addView(mPin);

        Button go = new Button(this);
        go.setText("Unlock");
        go.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                unlock();
            }
        });
        root.addView(go);

        mContainer = new FrameLayout(this);
        mContainer.setId(CONTAINER_ID);
        root.addView(mContainer);

        setContentView(root);
    }

    private void unlock() {
        if (!PIN.contentEquals(mPin.getText())) {
            Log.i(Vault.TAG, "LoginActivity: wrong PIN, refusing");
            mPin.setError("wrong PIN");
            return;
        }
        Log.i(Vault.TAG, "LoginActivity: PIN accepted, adding AdminFragment");

        // THIS is the only place in the app the developer believes AdminFragment
        // is ever constructed. It is not the only place it CAN be constructed.
        FragmentTransaction tx = getFragmentManager().beginTransaction();
        tx.replace(CONTAINER_ID, new AdminFragment());
        tx.commitAllowingStateLoss();
    }
}
