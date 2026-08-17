// examples/leaky-vault/NoteStore.java
//
// A SQLite store that demonstrates the single most reliable storage finding in
// the industry: DELETING A ROW DOES NOT DELETE THE BYTES.
//
// The app's logout path runs `DELETE FROM notes WHERE secret IS NOT NULL`. The
// developer is not lying when they say the app clears secrets on logout -- that
// SQL really does execute, and the table really is empty afterwards. Query it
// and you get nothing.
//
// Then run `strings notes.db-wal` and the deleted rows are all still there.
//
// WHY. SQLite in write-ahead-logging mode does not modify the main database
// file on every write. It appends the new version of each changed page to a
// companion file, <db>-wal, and readers consult the WAL first. Only at a
// CHECKPOINT are those pages folded back into the main file. Until then the WAL
// holds both the old page (with the row) and the new page (without it), because
// a page is copied wholesale, not edited in place -- and a DELETE that removes
// a row from a page rewrites the whole page, leaving the previous copy intact
// in the WAL.
//
// Even after a checkpoint, the main file keeps the bytes: SQLite marks the
// space free, it does not erase it. `PRAGMA secure_delete=ON` changes that, at
// a write-amplification cost, and is what the fixed app sets.
//
// This class is deliberately written the way real apps are written. Nothing
// here is contrived: WAL is the DEFAULT journal mode for every database opened
// through Room or SQLiteOpenHelper on API 16+, so this behaviour is what you
// will find, not what you have to arrange.
//
// Compile: see examples/build.sh. Do not ship this.

package com.pentest.ch33.vault;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

public class NoteStore extends SQLiteOpenHelper {

    private static final String DB = "notes.db";
    private static final int VERSION = 1;

    public NoteStore(Context ctx) {
        // Passing the bare name puts the file in the CE directory's databases/
        // subdirectory: /data/user/0/<pkg>/databases/notes.db. Passing an
        // absolute path instead would put it wherever you say -- which is how
        // databases end up on external storage, one of the three anti-patterns
        // 21-App-Sandbox section 3.14 lists.
        super(ctx, DB, null, VERSION);

        // WAL is requested HERE, on the helper, and not with
        // enableWriteAheadLogging() inside onConfigure().
        //
        // This is not a style preference. The first version of this file called
        // db.enableWriteAheadLogging() from onConfigure(), which is what a lot
        // of code on the internet does, and it throws IllegalStateException --
        // onConfigure runs inside a transaction, and WAL cannot be turned on
        // from inside one. getWritableDatabase() then propagated the failure,
        // every NoteStore call failed, and notes.db was left on disk with the
        // file created and the schema never committed.
        //
        // The reason this is worth a comment rather than a silent fix: the
        // symptom was a database file that EXISTS, is a valid SQLite file, has
        // journal_mode=wal in its header, and contains no tables. Nothing in
        // the app's UI reported an error. It was caught only by running the
        // app and looking at the disk -- which is the entire method this
        // chapter teaches, applied to the chapter's own example.
        setWriteAheadLoggingEnabled(true);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        // Column names are evidence. A scanner that reads sqlite_master and
        // reports "table notes declares a column named secret" is making a
        // schema-level claim, and it is right to separate that from a claim
        // about the contents. leak-hunter.py does exactly this split.
        db.execSQL("CREATE TABLE notes ("
                + "  _id     INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "  title   TEXT NOT NULL,"
                + "  body    TEXT,"
                + "  secret  TEXT,"          // the API token for a linked service
                + "  created INTEGER NOT NULL"
                + ")");
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldV, int newV) {
        db.execSQL("DROP TABLE IF EXISTS notes");
        onCreate(db);
    }

    @Override
    public void onConfigure(SQLiteDatabase db) {
        super.onConfigure(db);
        // Explicit for the sake of the lesson. Remove these lines and the
        // behaviour is identical, because secure_delete is already off by
        // default. That is the point worth internalising: the residual-data
        // behaviour is what you get by DOING NOTHING.
        //
        // rawQuery, NOT execSQL. This is the second trap this file walked into
        // and it is worth the comment for the same reason as the first.
        // secure_delete is a pragma that RETURNS A VALUE, and
        // SQLiteDatabase.execSQL refuses any statement that produces rows:
        //
        //   android.database.sqlite.SQLiteException: unknown error
        //   (code 0 SQLITE_OK): Queries can be performed using SQLiteDatabase
        //   query or rawQuery methods only.
        //
        // Thrown from onConfigure, that exception propagates out of
        // getWritableDatabase(), so EVERY database call fails -- and the error
        // text says nothing about pragmas, secure_delete, or onConfigure. The
        // observable symptom is again a notes.db that exists and has no tables.
        Cursor c = db.rawQuery("PRAGMA secure_delete = OFF", null);
        if (c != null) {
            c.moveToFirst();
            c.close();
        }
    }

    public long addNote(String title, String body, String secret) {
        ContentValues v = new ContentValues();
        v.put("title", title);
        v.put("body", body);
        v.put("secret", secret);
        v.put("created", System.currentTimeMillis());
        return getWritableDatabase().insert("notes", null, v);
    }

    /**
     * The logout path. This is honest code: it really does delete the rows, and
     * a subsequent SELECT really does return nothing.
     *
     * What it does not do -- and what nobody writing it thinks about -- is make
     * the bytes unrecoverable. Three separate mechanisms keep them:
     *
     *   1. the -wal file still holds the pre-delete pages;
     *   2. the main file's freelist still holds the page contents, because
     *      secure_delete is off;
     *   3. the -shm file indexes the WAL and survives alongside it.
     *
     * Compare Vault.clearForLogout() in examples/fixed-vault/, which does the
     * same delete and then actually removes the residue.
     */
    public int clearSecretsOnLogout() {
        SQLiteDatabase db = getWritableDatabase();
        int n = db.delete("notes", "secret IS NOT NULL", null);
        Log.d(Vault.TAG, "logout: deleted " + n + " rows carrying a secret");
        // No checkpoint. No VACUUM. No secure_delete. The SQL is correct and
        // the disk is unchanged in every way that matters to a forensic reader.
        return n;
    }

    public int countNotes() {
        Cursor c = getReadableDatabase().rawQuery("SELECT COUNT(*) FROM notes", null);
        try {
            return c.moveToFirst() ? c.getInt(0) : -1;
        } finally {
            c.close();
        }
    }
}
