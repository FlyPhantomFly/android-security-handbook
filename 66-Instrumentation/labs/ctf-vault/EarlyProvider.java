// labs/ctf-vault/EarlyProvider.java
//
// DELIBERATELY VULNERABLE CTF FIXTURE -- chapter 66, lab 04.
//
// A ContentProvider that exists for one reason: to write fragment 1 to a private
// file BEFORE any instrumentation can get control. ActivityThread brings
// providers up inside handleBindApplication(), above the mInstrumentation
// .onCreate() call site, so by the time an entrant's code runs the file is
// already there.
//
// It is exported="false", so no other application can reach it over Binder. The
// only way to the file is to BE this uid -- which is the point of the chapter.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch66.ctf;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class EarlyProvider extends ContentProvider {

    /** Relative to the app's private files directory. */
    public static final String FRAGMENT_FILE = "fragment1.bin";

    @Override
    public boolean onCreate() {
        // Note what is written: the ENCODED bytes, not the plaintext. A shell
        // that somehow read this file would still need the key, which lives in
        // the DEX. Recovering it statically is legitimate and is one of the two
        // intended routes to fragment 1.
        File out = new File(getContext().getFilesDir(), FRAGMENT_FILE);
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(Secrets.encoded(Secrets.BLOB_1));
        } catch (IOException e) {
            Log.w(CtfApp.TAG, "stage 2: could not write fragment", e);
            return true;
        }
        Log.i(CtfApp.TAG, "stage 2: ContentProvider.onCreate, fragment written");
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
