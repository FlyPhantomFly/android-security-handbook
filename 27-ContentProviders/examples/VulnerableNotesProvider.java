/*
 * VulnerableNotesProvider.java — a deliberately insecure ContentProvider.
 *
 * WHAT THIS DEMONSTRATES
 *   Every provider vulnerability class the reader must be able to build, exploit
 *   and then fix, in ONE compilable file so a lab target is a copy-paste away:
 *
 *     1. SQL injection through the PROJECTION   (SELECT <here> ...)
 *     2. SQL injection through the SELECTION    (... WHERE <here>)
 *     3. SQL injection through the SORT ORDER   (... ORDER BY <here>)   <-- the one scanners miss
 *     4. SQL injection through the URI PATH      (last path segment -> WHERE _id = <here>)
 *     5. Path traversal in openFile()            (getLastPathSegment -> new File, no canonicalisation)
 *     6. Writable openFile mode passed through   (caller chooses "rwt" -> arbitrary write)
 *     7. call() as an unauthenticated RPC        (getAuthToken / execSql / setServerUrl / wipe)
 *
 *   The secure equivalent is SecureNotesProvider.java in this directory. Diff the
 *   two: every difference is a control.
 *
 * WHY A COMPETENT DEVELOPER WRITES CODE LIKE THIS
 *   Each defect below has a one-line comment explaining the reasonable-sounding
 *   decision that produced it — flexibility for the app's own UI, rawQuery's
 *   selectionArgs parameter that LOOKS like it parameterises everything, the
 *   assumption that the only caller is the developer's own code, and call() as a
 *   cheaper alternative to a bound Service. None of it is laziness; all of it is
 *   exploitable. See README section 5.
 *
 * HOW TO BUILD THE LAB TARGET
 *   Drop this class into an app module. Register it in AndroidManifest.xml:
 *
 *     <provider
 *         android:name=".VulnerableNotesProvider"
 *         android:authorities="com.example.vuln.notes.provider"
 *         android:exported="true" />        <!-- the export flag is defect #0 -->
 *
 *   Seed the database (see onCreate) so there is something to steal, install, and
 *   attack it with:  ../scripts/provider-enum.sh, ../scripts/provider-call-fuzz.py,
 *   ../scripts/hook-provider.js, and the labs in ../labs/.
 *
 * !!  DO NOT SHIP THIS. It is a training target. Every method is a finding.  !!
 *
 * AUTHORISED TESTING / EDUCATION ONLY.
 */

package com.example.vuln;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.UriMatcher;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.net.Uri;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.text.TextUtils;
import android.util.Log;

import java.io.File;
import java.io.FileNotFoundException;

public class VulnerableNotesProvider extends ContentProvider {

    private static final String TAG = "VulnNotesProvider";
    static final String AUTHORITY = "com.example.vuln.notes.provider";

    private static final int NOTES   = 1;
    private static final int NOTE_ID = 2;
    private static final int DOC     = 3;

    private static final UriMatcher M = new UriMatcher(UriMatcher.NO_MATCH);
    static {
        M.addURI(AUTHORITY, "notes",     NOTES);
        M.addURI(AUTHORITY, "notes/#",   NOTE_ID);   // # matches digits only...
        M.addURI(AUTHORITY, "notes/*",   NOTE_ID);   // ...but * lets any segment through
        M.addURI(AUTHORITY, "docs/*",    DOC);
    }

    private DbHelper helper;

    // ---------------------------------------------------------------- schema

    private static final class DbHelper extends SQLiteOpenHelper {
        DbHelper(android.content.Context c) { super(c, "vuln_notes.db", null, 1); }

        @Override public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE notes ("
                     + "_id INTEGER PRIMARY KEY, title TEXT, body TEXT, "
                     + "owner_package TEXT, created_at INTEGER)");
            // A SECOND table the provider never means to expose. Injection reaches it.
            db.execSQL("CREATE TABLE users ("
                     + "_id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)");
            db.execSQL("CREATE TABLE session ("
                     + "_id INTEGER PRIMARY KEY, token TEXT)");

            db.execSQL("INSERT INTO notes(title,body,owner_package,created_at) "
                     + "VALUES('shopping','milk and eggs','com.example.vuln',0)");
            db.execSQL("INSERT INTO users(username,password,role) "
                     + "VALUES('admin','s3cr3t-P@ss','admin')");
            db.execSQL("INSERT INTO users(username,password,role) "
                     + "VALUES('alice','hunter2','user')");
            db.execSQL("INSERT INTO session(token) VALUES('eyJ-fake-jwt-abc123')");
        }

        @Override public void onUpgrade(SQLiteDatabase db, int o, int n) { }
    }

    @Override public boolean onCreate() {
        helper = new DbHelper(getContext());
        return true;
    }

    // ------------------------------------------------------------- query()
    //
    // DEFECTS 1-4. The five ContentResolver.query parameters are stitched into a
    // raw SQL string. selectionArgs is passed to rawQuery — which binds ONLY the
    // '?' placeholders inside `selection`, and does nothing for the concatenated
    // projection, sort order, or the path-derived id. The developer wanted the
    // provider to be "flexible" for their own UI. It is flexible for everyone.

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {

        SQLiteDatabase db = helper.getReadableDatabase();

        // DEFECT 1 — projection concatenated. No bind form exists for a column list.
        String cols = (projection == null) ? "*" : TextUtils.join(", ", projection);

        // DEFECT 2 — selection concatenated. selectionArgs binds '?' only.
        String where = TextUtils.isEmpty(selection) ? "1" : selection;

        // DEFECT 3 — sort order concatenated. THE CHANNEL SCANNERS MISS.
        String order = TextUtils.isEmpty(sortOrder) ? "_id ASC" : sortOrder;

        switch (M.match(uri)) {
            case NOTE_ID:
                // DEFECT 4 — the last path segment goes straight into WHERE.
                // getLastPathSegment() is attacker-controlled; * let a non-numeric
                // segment reach here, so  notes/1 OR 1=1  is a valid "id".
                String id = uri.getLastPathSegment();
                where = "_id = " + id + " AND (" + where + ")";
                // fall through — same statement build as NOTES
            case NOTES:
                String sql = "SELECT " + cols + " FROM notes WHERE " + where
                           + " ORDER BY " + order;
                // Debug logging in a provider is itself a finding — and a gift to
                // the tester: `adb logcat -s VulnNotesProvider` reveals the SQL.
                Log.d(TAG, "SQL: " + sql);
                return db.rawQuery(sql, selectionArgs);
            default:
                // The discovery oracle: reaching this proves you are past the
                // permission check and only the PATH was wrong. See README 3.5.
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }
    }

    // ----------------------------------------------------------- openFile()
    //
    // DEFECTS 5 & 6. Intent: serve files from <files>/public/. But the name is the
    // raw last path segment (which may contain %2F-decoded slashes and ".."), it is
    // never canonicalised or checked against the base directory, and the caller's
    // mode string is honoured — so read becomes write. getLastPathSegment() on
    // content://a/docs/..%2F..%2Fdatabases%2Fapp.db returns exactly what the
    // attacker wrote. See README section 5.2.

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        if (M.match(uri) != DOC) {
            throw new FileNotFoundException("Unsupported URI: " + uri);
        }
        String name = uri.getLastPathSegment();

        // A developer who "added a traversal check". It stops literal "..", and
        // nothing else: not %2e%2e, not double encoding, not an absolute path,
        // not a symlink. Blacklists lose; only canonicalisation wins.
        if (name != null && name.contains("..")) {
            // (still broken — the encoded forms never contain literal "..")
            Log.w(TAG, "blocked literal .. in " + name);
        }

        File base = new File(getContext().getFilesDir(), "public");
        File f = new File(base, name);      // DEFECT 5 — no canonical containment check
        // DEFECT 6 — the caller picks the mode. "rwt" gives arbitrary write.
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.parseMode(mode));
    }

    // ---------------------------------------------------------------- call()
    //
    // DEFECT 7. call() gets NO automatic permission check and appears nowhere in
    // the manifest. It is the developer's private back-channel to their own widget
    // and their instrumentation tests. execSql and enableDebug were "supposed to be
    // removed before release". getAuthToken exists because the companion app needed
    // the token and this was the shortest path. See README section 5.5.

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        Bundle out = new Bundle();
        if (method == null) return null;
        switch (method) {
            case "getAuthToken":
                Cursor c = helper.getReadableDatabase()
                        .rawQuery("SELECT token FROM session LIMIT 1", null);
                if (c != null && c.moveToFirst()) { out.putString("token", c.getString(0)); }
                if (c != null) c.close();
                return out;                                  // account takeover in one call
            case "setServerUrl":
                // Persistent man-in-the-middle: point the app at the attacker.
                getContext().getSharedPreferences("cfg", 0)
                        .edit().putString("server", arg).apply();
                return out;
            case "enableDebug":
                out.putBoolean("debug", "1".equals(arg));
                return out;
            case "execSql":
                // Arbitrary read AND write of every table.
                helper.getWritableDatabase().execSQL(arg);
                return out;
            case "wipe":
                helper.getWritableDatabase().execSQL("DELETE FROM notes");
                return out;
            default:
                // Returning null (not throwing) makes an enumerating fuzzer's job
                // slightly harder — but only slightly, and it is not a control.
                return null;
        }
    }

    // ------------------------------------------- write ops (also unprotected)

    @Override public Uri insert(Uri uri, ContentValues values) {
        long id = helper.getWritableDatabase().insert("notes", null, values);
        return Uri.withAppendedPath(Uri.parse("content://" + AUTHORITY + "/notes"),
                                    String.valueOf(id));
    }

    @Override public int update(Uri uri, ContentValues values, String sel, String[] args) {
        // selection concatenated is possible here too; kept simple for the lab.
        return helper.getWritableDatabase().update("notes", values, sel, args);
    }

    @Override public int delete(Uri uri, String sel, String[] args) {
        return helper.getWritableDatabase().delete("notes", sel, args);
    }

    @Override public String getType(Uri uri) {
        // getType is unprotected by the framework. Returning a constant here is
        // fine; a DB-backed implementation would leak through an unchecked call.
        switch (M.match(uri)) {
            case NOTES:   return "vnd.android.cursor.dir/vnd.com.example.vuln.note";
            case NOTE_ID: return "vnd.android.cursor.item/vnd.com.example.vuln.note";
            default:      return null;
        }
    }
}
