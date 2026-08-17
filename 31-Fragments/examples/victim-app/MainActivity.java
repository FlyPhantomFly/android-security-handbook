// examples/victim-app/MainActivity.java
//
// AUTHORISED TESTING ONLY -- deliberately vulnerable chapter 31 victim app.
//
// The launcher screen. It exists to seed the vault file and to give you
// something to tap so you can confirm the app installed and runs. It holds no
// secrets and has no Fragments.
//
// Build: examples/build.sh   (out of tree; no .apk lands in the repository)

package com.pentest.ch31.victim;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Vault.seed(this);
        Log.i(Vault.TAG, "MainActivity.onCreate uid=" + android.os.Process.myUid()
                + " pid=" + android.os.Process.myPid());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(48, 96, 48, 48);
        root.setBackgroundColor(Color.WHITE);

        TextView t = new TextView(this);
        t.setTextColor(Color.BLACK);
        t.setTextSize(16f);
        t.setText("CH31 victim app\n\n"
                + "This app is deliberately vulnerable. It is a lab target for\n"
                + "chapter 31 (Fragments) of the Android Pentesting Notes.\n\n"
                + "The secret lives in a private file. The intended way to see it\n"
                + "is the login screen below, which wants a four digit PIN.\n\n"
                + "Two other Activities reach Fragments by class name and are the\n"
                + "subject of the labs.");
        root.addView(t);

        Button login = new Button(this);
        login.setText("Open the login screen (the intended route)");
        login.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startActivity(new Intent(MainActivity.this, LoginActivity.class));
            }
        });
        root.addView(login);

        setContentView(root);
    }
}
