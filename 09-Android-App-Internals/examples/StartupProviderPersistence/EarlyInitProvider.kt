// examples/StartupProviderPersistence/EarlyInitProvider.kt
package com.example.startup

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.Process
import android.util.Log

/**
 * A ContentProvider used purely for its onCreate() timing. This is the pattern behind
 * androidx.startup, Firebase's initialisation provider, and a large number of analytics
 * and attribution SDKs — and, for the same reason, behind SDK-borne malware.
 *
 * Everything here executes with the HOST APP's uid and the HOST APP's permissions,
 * before the host app's Application.onCreate().
 */
class EarlyInitProvider : ContentProvider() {

    override fun onCreate(): Boolean {
        val ctx = context!!
        Log.i(TAG, "PROVIDER onCreate  uid=${Process.myUid()} pid=${Process.myPid()}")
        Log.i(TAG, "  package  = ${ctx.packageName}")
        Log.i(TAG, "  dataDir  = ${ctx.applicationInfo.dataDir}")
        // At this point the host app has run NO code of its own except attachBaseContext().
        // An SDK could read files, open a socket (if the host holds INTERNET), register a
        // receiver, or start a service — all attributed to the host application.
        ctx.getSharedPreferences("early", 0).edit()
            .putLong("last_provider_init", System.currentTimeMillis()).apply()
        return true
    }

    override fun query(u: Uri, p: Array<String>?, s: String?, a: Array<String>?, o: String?): Cursor? = null
    override fun getType(u: Uri): String? = null
    override fun insert(u: Uri, v: ContentValues?): Uri? = null
    override fun delete(u: Uri, s: String?, a: Array<String>?): Int = 0
    override fun update(u: Uri, v: ContentValues?, s: String?, a: Array<String>?): Int = 0

    companion object { private const val TAG = "StartupOrder" }
}
