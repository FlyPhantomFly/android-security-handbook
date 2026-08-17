// examples/StartupProviderPersistence/DemoActivity.kt
package com.example.startup

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView

class DemoActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        Log.i(TAG, "ACTIVITY onCreate  <-- last of the four")
        super.onCreate(savedInstanceState)

        // Read back what the provider wrote before any of this app's own code ran.
        val written = getSharedPreferences("early", 0).getLong("last_provider_init", -1L)
        setContentView(TextView(this).apply {
            setPadding(48, 48, 48, 48)
            typeface = android.graphics.Typeface.MONOSPACE
            text = "EarlyInitProvider wrote last_provider_init = $written\n" +
                   "It did that before DemoApplication.onCreate() ran.\n\n" +
                   "adb logcat -d -s StartupOrder -v time"
        })
    }

    companion object { private const val TAG = "StartupOrder" }
}
