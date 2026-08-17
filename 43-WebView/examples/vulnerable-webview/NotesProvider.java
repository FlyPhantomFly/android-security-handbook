// examples/vulnerable-webview/NotesProvider.java
//
// A minimal ContentProvider, present for exactly one reason: to give the
// content:// demonstrations something real on the other end.
//
// It is NOT exported (android:exported="false" in the manifest), which is the
// correct setting and is the point. An unexported provider is unreachable from
// any other app -- and it is still reachable from JavaScript running inside THIS
// app's WebView, because `setAllowContentAccess` defaults to true and the
// resolver call is made with this app's identity. "Not exported" protects you
// from other apps. It does not protect you from your own renderer.
//
// Chapter 27 owns providers: ../../../27-ContentProviders/README.md. This class
// is deliberately the simplest thing that can hold a secret and hand it back
// through openFile().

package com.pentest.ch43.vuln;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;

public class NotesProvider extends ContentProvider {

    static final String TAG = "CH43VULN";
    static final String AUTHORITY = "com.pentest.ch43.vuln.notes";
    static final String NOTE_FILE = "private-note.txt";

    @Override
    public boolean onCreate() {
        try {
            Context ctx = getContext();
            if (ctx == null) {
                return false;
            }
            File f = new File(ctx.getFilesDir(), NOTE_FILE);
            if (!f.exists()) {
                FileOutputStream out = new FileOutputStream(f);
                out.write(("private note, provider-backed: "
                        + "CH43{content_scheme_resolves_as_the_host_app}").getBytes("UTF-8"));
                out.close();
            }
        } catch (Exception e) {
            Log.w(TAG, "provider seed failed: " + e);
        }
        return true;
    }

    /**
     * openFile is what a `fetch("content://.../note")` from page JavaScript
     * ultimately reaches. WebView asks the ContentResolver for a stream; the
     * resolver dispatches here; this method returns a file descriptor; Chromium
     * reads the bytes and hands them to script.
     *
     * At no point does anything ask "which origin wanted this?".
     */
    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) {
        Log.i(TAG, "provider openFile: " + uri);
        try {
            Context ctx = getContext();
            if (ctx == null) {
                return null;
            }
            File f = new File(ctx.getFilesDir(), NOTE_FILE);
            return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (Exception e) {
            Log.w(TAG, "openFile failed: " + e);
            return null;
        }
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        Log.i(TAG, "provider query: " + uri);
        MatrixCursor c = new MatrixCursor(new String[]{"_id", "body"});
        c.addRow(new Object[]{1, "CH43{content_scheme_resolves_as_the_host_app}"});
        return c;
    }

    @Override
    public String getType(Uri uri) {
        return "text/plain";
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
