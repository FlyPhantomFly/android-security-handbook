// examples/vault-target/SeedProvider.java
//
// A ContentProvider that does nothing except record when its onCreate() ran.
//
// Why this file exists: ActivityThread.handleBindApplication() calls
// installContentProviders() BEFORE it calls mInstrumentation.onCreate(). A
// provider is therefore the earliest slot in an app's own code that the
// platform will run for you, which is exactly why androidx.startup,
// firebase-perf, crash reporters and several commercial packers all ship one.
// Chapter 66 section 3.6 measures the resulting ordering on a device.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.vault;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.os.SystemClock;
import android.util.Log;

public class SeedProvider extends ContentProvider {

    /** Set by onCreate, read by the probe. */
    public static volatile long sProviderOnCreateAtNs = 0L;

    @Override
    public boolean onCreate() {
        sProviderOnCreateAtNs = SystemClock.elapsedRealtimeNanos();
        Log.i(VaultApp.SEQ, "3 ContentProvider.onCreate       t=" + sProviderOnCreateAtNs);
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        return null;
    }

    @Override
    public String getType(Uri uri) {
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }
}
