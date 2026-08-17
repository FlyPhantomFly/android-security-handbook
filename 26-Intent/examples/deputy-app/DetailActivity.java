// examples/deputy-app/DetailActivity.java
//
// A legitimate, non-exported destination. RedirectorActivityFixed's allow-list
// names this class, which is what makes the allow-list a real test rather than a
// decoration: the fixed router MAY reach it, an outside caller may NOT.
//
// Framework components must be PUBLIC. The Activity is instantiated reflectively
// by AppComponentFactory / Instrumentation.newActivity, and a package-private
// class fails at runtime with an InstantiationException that reads like a
// ClassNotFoundException. This is a real trap when you split demo classes across
// files to keep them short -- keep every manifest-declared class public.

package com.pentest.deputy;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

public class DetailActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String id = getIntent().getStringExtra("id");
        Log.i("DEPUTY", "DetailActivity (allow-listed route) id=" + id);

        TextView tv = new TextView(this);
        tv.setPadding(48, 96, 48, 48);
        tv.setText("DetailActivity\n"
                + "android:exported=\"false\"\n\n"
                + "A route the FIXED router is permitted to reach.\n"
                + "id = " + id);
        setContentView(tv);
    }
}
