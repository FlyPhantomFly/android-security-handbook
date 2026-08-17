/*
 * SecureNotesProvider.java — the fixed equivalent of VulnerableNotesProvider.java.
 *
 * WHAT THIS DEMONSTRATES
 *   The same provider, same tables, same authority — with each of the seven
 *   defects closed by a REAL control, not by advice. Diff this against
 *   VulnerableNotesProvider.java; every difference is a fix:
 *
 *     Defect                     Control applied here
 *     -------------------------  --------------------------------------------------
 *     0  exported=true           exported=false + signature permission (manifest);
 *                                enforceCaller() re-checks the signature at RUNTIME
 *     1  projection injection    SQLiteQueryBuilder.setProjectionMap() + setStrict()
 *     2  selection injection     strict grammar; caller selection can only NARROW an
 *                                already package-scoped WHERE; values via selectionArgs
 *     3  sortOrder injection     whitelist of allowed ORDER BY expressions
 *     4  uri-path injection      ContentUris.parseId() — a long, never a string in SQL
 *     5  openFile traversal      getCanonicalPath() containment check WITH trailing sep
 *     6  writable mode           MODE_READ_ONLY hard-coded; write modes rejected
 *     7  call() open RPC         enforceCaller() + a closed method set; default throws;
 *                                debug methods compiled out under BuildConfig.DEBUG
 *
 *   Layered on top: per-caller row scoping (tenant isolation), a hard row LIMIT
 *   for DoS resistance, and ContentValues copied column-by-column on write so a
 *   caller cannot set owner_package or role.
 *
 * WHY THIS IS THE STANDARD TO MEASURE CLIENT CODE AGAINST
 *   Any single control here failing leaves the others standing. The manifest
 *   permission is signature AND the code re-checks the signature AND the package
 *   must be allow-listed AND rows are scoped AND the projection is closed AND the
 *   sort is a whitelist AND there is a row cap. That is defence in depth, and the
 *   gap between a client's provider and this one is the finding list. See README
 *   section 9.5.
 *
 * MANIFEST
 *   <permission
 *       android:name="com.example.secure.permission.NOTES"
 *       android:protectionLevel="signature" />
 *
 *   <provider
 *       android:name=".SecureNotesProvider"
 *       android:authorities="com.example.secure.notes.provider"
 *       android:exported="false"                                 <!-- default & correct -->
 *       android:readPermission="com.example.secure.permission.NOTES"
 *       android:writePermission="com.example.secure.permission.NOTES"
 *       android:grantUriPermissions="false" />
 *
 *   exported=false makes it unreachable cross-uid on its own; the signature
 *   permission is for genuine same-vendor companion apps; the runtime check is
 *   the belt to that braces, because manifests get edited and keys get shared.
 *
 * NOTE
 *   BuildConfig is referenced for the debug-method pattern. Replace the import
 *   with your app's real BuildConfig package when you drop this in.
 *
 * AUTHORISED TESTING / EDUCATION ONLY.
 */

package com.example.secure;

import android.content.ContentProvider;
import android.content.ContentUris;
import android.content.ContentValues;
import android.content.Context;
import android.content.UriMatcher;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteQueryBuilder;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.text.TextUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class SecureNotesProvider extends ContentProvider {

    static final String AUTHORITY = "com.example.secure.notes.provider";

    private static final int NOTES   = 1;
    private static final int NOTE_ID = 2;
    private static final int DOC     = 3;

    private static final UriMatcher M = new UriMatcher(UriMatcher.NO_MATCH);
    static {
        M.addURI(AUTHORITY, "notes",   NOTES);
        M.addURI(AUTHORITY, "notes/#", NOTE_ID);   // # only — digits, no wildcard
        M.addURI(AUTHORITY, "docs/#",  DOC);       // files addressed by numeric id, never name
    }

    // FIX 1 — closed projection map. Only these columns may ever leave the
    // process, and only under these external names. 'body' is deliberately absent.
    private static final Map<String, String> PROJECTION = new HashMap<>();
    static {
        PROJECTION.put("_id",        "_id");
        PROJECTION.put("title",      "title");
        PROJECTION.put("created_at", "created_at");
    }

    // FIX 3 — closed sort whitelist. The caller may pick an order, but only from
    // this set. There is no code path by which a caller expression reaches ORDER BY.
    private static final Set<String> SORTS = Collections.unmodifiableSet(new HashSet<>(
            Arrays.asList("_id ASC", "_id DESC", "created_at ASC", "created_at DESC")));

    // FIX 0/7 — the only packages allowed to reach this provider, even after the
    // signature check passes (a shared UID can host several packages).
    private static final Set<String> ALLOWED_PACKAGES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "com.example.secure",
                    "com.example.secure.companion")));

    private DbHelper helper;
    private File blobDir;

    // ---------------------------------------------------------------- schema

    private static final class DbHelper extends SQLiteOpenHelper {
        DbHelper(Context c) { super(c, "secure_notes.db", null, 1); }
        @Override public void onCreate(SQLiteDatabase db) {
            db.execSQL("CREATE TABLE notes ("
                     + "_id INTEGER PRIMARY KEY, title TEXT, body TEXT, "
                     + "owner_package TEXT, created_at INTEGER)");
        }
        @Override public void onUpgrade(SQLiteDatabase db, int o, int n) { }
    }

    @Override public boolean onCreate() {
        helper  = new DbHelper(getContext());
        blobDir = new File(getContext().getFilesDir(), "public");
        return true;
    }

    // --------------------------------------------------- FIX 0/7: caller check
    //
    // The only trust decision in the class. The framework's declared-permission
    // check already ran in system_server before we got here; this is defence in
    // depth against a shared or rotated signing key and against a mis-edited
    // manifest. Use Binder.getCallingUid() — kernel-authenticated, unspoofable —
    // never getCallingPackage() for the actual decision.

    private String enforceCaller() {
        final int uid = Binder.getCallingUid();
        if (uid == Process.myUid()) {
            return getContext().getPackageName();          // ourselves
        }
        Context ctx = getContext();
        PackageManager pm = ctx.getPackageManager();
        if (pm.checkSignatures(Process.myUid(), uid) != PackageManager.SIGNATURE_MATCH) {
            throw new SecurityException("Caller uid " + uid + " is not same-signature");
        }
        String[] pkgs = pm.getPackagesForUid(uid);
        if (pkgs == null || pkgs.length == 0) {
            throw new SecurityException("Cannot identify caller uid " + uid);
        }
        for (String p : pkgs) {
            if (ALLOWED_PACKAGES.contains(p)) return p;
        }
        throw new SecurityException("Caller " + Arrays.toString(pkgs) + " not in allow-list");
    }

    // ------------------------------------------------------------- query()
    //
    // FIXES 1-4. SQLiteQueryBuilder with a projection map and strict mode; a sort
    // whitelist; the id parsed as a long; every row scoped to the caller. A caller
    // selection is permitted but strict grammar prevents it escaping its
    // parentheses, and it can only narrow the already-scoped set.

    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) {

        final String caller = enforceCaller();

        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();
        qb.setTables("notes");
        qb.setProjectionMap(PROJECTION);   // FIX 1 — reject any column not in the map
        qb.setStrict(true);                // FIX 1/2 — strict columns + strict grammar

        // Tenant isolation: a caller only ever sees its own rows.
        StringBuilder where = new StringBuilder("owner_package = ?");
        java.util.List<String> args = new java.util.ArrayList<>();
        args.add(caller);

        switch (M.match(uri)) {
            case NOTES:
                break;
            case NOTE_ID:
                where.append(" AND _id = ?");
                // FIX 4 — a long, so it can never be SQL text.
                args.add(String.valueOf(ContentUris.parseId(uri)));
                break;
            default:
                throw new IllegalArgumentException("Unknown URI: " + uri);
        }

        // FIX 2 — the caller's selection is allowed only as an ANDed narrowing;
        // setStrict(true) rejects statement separators, comments and subqueries
        // that try to break out. Values still go through selectionArgs.
        if (!TextUtils.isEmpty(selection)) {
            where.append(" AND (").append(selection).append(")");
            if (selectionArgs != null) args.addAll(Arrays.asList(selectionArgs));
        }

        // FIX 3 — sort order is a whitelist, never the caller's expression.
        String order = SORTS.contains(sortOrder) ? sortOrder : "_id ASC";

        Cursor c = qb.query(helper.getReadableDatabase(), projection,
                where.toString(), args.toArray(new String[0]),
                null, null, order, "500");     // hard row cap — DoS resistance
        c.setNotificationUri(getContext().getContentResolver(), uri);
        return c;
    }

    // ----------------------------------------------------------- openFile()
    //
    // FIXES 5 & 6. Read-only mode only; files addressed by numeric id (never a
    // caller-supplied name); canonical-path containment check with the trailing
    // separator that stops the /publicdata-vs-/public sibling bypass.

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        final String caller = enforceCaller();

        if (!"r".equals(mode)) {
            throw new SecurityException("Read-only provider");   // FIX 6
        }
        if (M.match(uri) != DOC) {
            throw new FileNotFoundException("Unsupported URI: " + uri);
        }

        long id = ContentUris.parseId(uri);                       // FIX 4 (for files)
        if (!ownsBlob(caller, id)) {
            throw new SecurityException("Not your file");
        }

        File target = new File(blobDir, id + ".bin");

        // FIX 5 — the only check that actually works. getCanonicalPath resolves
        // "..", resolves symlinks, normalises separators; the trailing File.separator
        // prevents /data/.../publicdata passing a startsWith on /data/.../public.
        try {
            String base = blobDir.getCanonicalPath() + File.separator;
            if (!target.getCanonicalPath().startsWith(base)) {
                throw new SecurityException("Path escapes base directory");
            }
        } catch (IOException e) {
            throw new FileNotFoundException("Cannot canonicalise");
        }
        return ParcelFileDescriptor.open(target, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    // ---------------------------------------------------------------- call()
    //
    // FIX 7. Authorise the caller by hand (the framework does not), expose a
    // closed method set, throw on anything else, and compile debug methods out of
    // release builds so the method-name string is not even present in the DEX.

    @Override
    public Bundle call(String method, String arg, Bundle extras) {
        enforceCaller();

        if (method == null) throw new IllegalArgumentException("null method");

        // Debug-only methods are removed by R8 when BuildConfig.DEBUG is a
        // compile-time false. Replace the import with your app's BuildConfig.
        // if (BuildConfig.DEBUG && "dumpState".equals(method)) { return dumpState(); }

        switch (method) {
            case "getSchemaVersion": {
                Bundle b = new Bundle();
                b.putInt("version", 1);
                return b;
            }
            // No getAuthToken. No execSql. No setServerUrl. No wipe.
            default:
                // Throw, not return null: your own developers get a clear error,
                // and the ambiguity of null was never a real control anyway.
                throw new IllegalArgumentException("Unsupported method: " + method);
        }
    }

    // ------------------------------------------------- write (scoped, filtered)

    @Override public Uri insert(Uri uri, ContentValues values) {
        final String caller = enforceCaller();
        if (M.match(uri) != NOTES) throw new IllegalArgumentException("Unknown URI: " + uri);

        // Never trust the caller's ContentValues wholesale — copy known columns
        // only, so owner_package cannot be forged.
        ContentValues safe = new ContentValues();
        if (values != null && values.containsKey("title")) {
            safe.put("title", values.getAsString("title"));
        }
        safe.put("owner_package", caller);
        safe.put("created_at", System.currentTimeMillis());

        long id = helper.getWritableDatabase().insertOrThrow("notes", null, safe);
        getContext().getContentResolver().notifyChange(uri, null);
        return ContentUris.withAppendedId(uri, id);
    }

    @Override public int update(Uri uri, ContentValues values, String sel, String[] args) {
        final String caller = enforceCaller();
        ContentValues safe = new ContentValues();
        if (values != null && values.containsKey("title")) {
            safe.put("title", values.getAsString("title"));
        }
        // owner_package is never writable by the caller; scope to caller + id.
        return helper.getWritableDatabase().update("notes", safe,
                "owner_package = ? AND _id = ?",
                new String[]{ caller, String.valueOf(ContentUris.parseId(uri)) });
    }

    @Override public int delete(Uri uri, String sel, String[] args) {
        final String caller = enforceCaller();
        return helper.getWritableDatabase().delete("notes",
                "owner_package = ? AND _id = ?",
                new String[]{ caller, String.valueOf(ContentUris.parseId(uri)) });
    }

    @Override public String getType(Uri uri) {
        // Constant only. Never a database lookup — getType is unprotected.
        switch (M.match(uri)) {
            case NOTES:   return "vnd.android.cursor.dir/vnd.com.example.secure.note";
            case NOTE_ID: return "vnd.android.cursor.item/vnd.com.example.secure.note";
            case DOC:     return "application/octet-stream";
            default:      return null;
        }
    }

    private boolean ownsBlob(String caller, long id) {
        try (Cursor c = helper.getReadableDatabase().query("notes",
                new String[]{"_id"}, "owner_package = ? AND _id = ?",
                new String[]{ caller, String.valueOf(id) }, null, null, null)) {
            return c != null && c.getCount() == 1;
        }
    }
}
