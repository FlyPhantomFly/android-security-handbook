// examples/victim-app/SecretProvider.java
// Package: com.pentest.ch30.victim
//
// A minimal ContentProvider whose only job is to be worth stealing from.
//
// Declared in AndroidManifest.xml as:
//     android:exported="false"          <- NO other app may query it directly
//     android:grantUriPermissions="true" <- ...but a component of THIS app may
//                                           hand out a temporary, per-URI grant
//
// Those two attributes together are the entire precondition for grant
// laundering. `exported="false"` is doing its job perfectly: an attacker calling
// query() on this authority gets a SecurityException, and lab-03 measures that
// before it measures anything else. `grantUriPermissions="true"` is the capability
// that DeputyActivity then hands away by accident.
//
// The provider mechanics -- URI matching, the grant table in
// UriGrantsManagerService, persistable grants, openFile path traversal -- belong
// to 27-ContentProviders. This file is deliberately as small as a provider can
// be, because chapter 30 owns the DEPUTY, not the provider.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch30.victim;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.util.Log;

public class SecretProvider extends ContentProvider {

    private static final String TAG = "CH30";

    /** The single row this provider serves. In a real app this is a session token. */
    private static final String SECRET =
            "CH30{the_deputy_handed_you_a_grant_it_never_meant_to_give}";

    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {
        // Every reader of this provider is logged, with the uid the platform
        // stamped on the Binder transaction. This is the honest identity --
        // see 25-Binder -- and it is what makes the lab's evidence readable:
        // when the ATTACKER's uid appears here, the grant has been laundered.
        int callingUid = android.os.Binder.getCallingUid();
        Log.i(TAG, "SecretProvider.query uri=" + uri + " callingUid=" + callingUid
                + " callingPackage=" + getCallingPackage());

        MatrixCursor c = new MatrixCursor(new String[]{"_id", "secret"});
        c.addRow(new Object[]{1, SECRET});
        return c;
    }

    @Override
    public String getType(Uri uri) {
        return "vnd.android.cursor.item/vnd.com.pentest.ch30.victim.secret";
    }

    @Override public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override public int delete(Uri uri, String s, String[] a) { return 0; }
    @Override public int update(Uri uri, ContentValues v, String s, String[] a) { return 0; }
}
