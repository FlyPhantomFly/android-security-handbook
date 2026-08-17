// examples/StartupProviderPersistence/DemoApplication.kt
package com.example.startup

import android.app.Application
import android.content.Context
import android.util.Log

class DemoApplication : Application() {

    override fun attachBaseContext(base: Context) {
        Log.i(TAG, "APPLICATION attachBaseContext")
        super.attachBaseContext(base)
    }

    override fun onCreate() {
        Log.i(TAG, "APPLICATION onCreate  <-- providers already ran")
        super.onCreate()
    }

    companion object { private const val TAG = "StartupOrder" }
}
