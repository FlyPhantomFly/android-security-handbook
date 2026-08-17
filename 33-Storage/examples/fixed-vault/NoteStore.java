// examples/fixed-vault/NoteStore.java
//
// The same SQLite store as examples/leaky-vault/NoteStore.java, with the
// residual-data problem addressed. Diff the two files: the schema is identical,
// the inserts are identical, and the DELETE is identical. What changed is
// everything that happens around the delete.
//
// THREE MECHANISMS KEEP DELETED ROWS ON DISK, AND EACH NEEDS ITS OWN FIX
//
//   1. The write-ahead log. WAL is the default journal mode. A DELETE appends a
//      rewritten page to <db>-wal; the pre-delete page is still there until a
//      checkpoint folds it back. FIX: checkpoint with TRUNCATE, which folds the
//      WAL into the main file AND resets the WAL file to zero length.
//
//   2. Free pages in the main file. SQLite marks the space free; it does not
//      overwrite it. FIX: PRAGMA secure_delete=ON makes SQLite zero the bytes
//      of deleted content as it goes. The cost is write amplification, which on
//      a phone means battery and flash wear -- so this is a real trade-off, not
//      a free win, and it belongs on the tables that hold secrets rather than
//      globally on a large database.
//
//   3. Space that is already free. secure_delete only affects deletions from
//      the moment it is set. Rows deleted before it was enabled are still in
//      the freelist. FIX: VACUUM rebuilds the file from scratch, which is the
//      only way to reclaim pre-existing residue -- and it needs free disk space
//      roughly equal to the database size, so it can fail on a full device.
//
// AND ONE THAT NO PRAGMA FIXES
//
//   The flash translation layer. Under the filesystem, an SSD or eMMC/UFS
//   controller remaps logical blocks to physical ones and does not erase the
//   old physical block when you overwrite the logical one. Nothing running in
//   userspace can reach it. This is the reason the honest ceiling for "delete
//   this data" on a mobile device is CRYPTO-SHREDDING: encrypt it with a key
//   you can destroy, and destroy the key. See Vault.wipe() in this directory.
//
// Compile: see examples/build.sh.

package com.pentest.ch33.vaultfixed;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

import java.io.File;

public class NoteStore extends SQLiteOpenHelper {

    private static final String DB = "notes.db";
    private static final int VERSION = 1;

    private final Context ctx;

    public NoteStore(Context ctx) {
        super(ctx, DB, null, VERSION);
        this.ctx = ctx.getApplicationContext();
        // On the helper, not inside onConfigure(). See the long comment in
        // examples/leaky-vault/NoteStore.java: calling enableWriteAheadLogging()
        // from onConfigure throws, and the failure is silent enough to leave a
        // valid-but-empty database behind.
        setWriteAheadLoggingEnabled(true);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        // The schema no longer has a column called `secret` holding a live
        // credential. It holds a REFERENCE to the sealed vault record instead,
        // which means the database can be dumped in full without yielding
        // anything usable. This is the structural fix, and it is better than
        // any pragma: the residue problem is solved by there being no plaintext
        // secret to leave residue of.
        db.execSQL("CREATE TABLE notes ("
                + "  _id        INTEGER PRIMARY KEY AUTOINCREMENT,"
                + "  title      TEXT NOT NULL,"
                + "  body       TEXT,"
                + "  vault_ref  TEXT,"        // an opaque id, not a credential
                + "  created    INTEGER NOT NULL"
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
        // FIX 2. Set before any deletion happens, because it is not
        // retroactive.
        // rawQuery, not execSQL: secure_delete returns a value, and execSQL
        // throws on any statement that produces rows. See the long comment in
        // examples/leaky-vault/NoteStore.java -- thrown from onConfigure, that
        // exception makes every database call fail with an error message that
        // mentions neither pragmas nor onConfigure.
        Cursor cfg = db.rawQuery("PRAGMA secure_delete = ON", null);
        if (cfg != null) {
            cfg.moveToFirst();
            cfg.close();
        }
        // WAL stays ON -- requested in the constructor, not here. Turning it
        // off would trade a residue problem for a concurrency problem, and the
        // residue is dealt with at checkpoint time instead. Note that enabling
        // WAL and setting secure_delete are NOT in conflict; people assume they
        // are.
    }

    public long addNote(String title, String body, String vaultRef) {
        ContentValues v = new ContentValues();
        v.put("title", title);
        v.put("body", body);
        v.put("vault_ref", vaultRef);
        v.put("created", System.currentTimeMillis());
        return getWritableDatabase().insert("notes", null, v);
    }

    /**
     * The logout path, done properly.
     *
     * Compare examples/leaky-vault/NoteStore.java: the DELETE is identical. The
     * three statements after it are the fix, and the log line at the end tells
     * you whether they worked instead of assuming they did.
     */
    public int clearSecretsOnLogout() {
        SQLiteDatabase db = getWritableDatabase();
        int n = db.delete("notes", "vault_ref IS NOT NULL", null);

        // FIX 3 FIRST, THEN FIX 1. The order is not arbitrary and getting it
        // backwards is invisible.
        //
        // The first version of this method checkpointed and then vacuumed. The
        // checkpoint truncated the WAL to zero exactly as intended -- and then
        // VACUUM, which rewrites the entire database, generated a fresh WAL
        // full of pages and left it 20 KB long. Measured on the test device:
        //
        //   D CH33Fixed: logout: deleted 2 rows; wal now 20632 bytes
        //
        // The log line was what caught it, which is why it prints the size
        // instead of asserting success. Do the expensive rewrite first, then
        // fold and truncate.
        //
        // VACUUM reclaims residue from deletions made before secure_delete was
        // in force and compacts the freelist. It is expensive and needs
        // temporary space roughly equal to the database, so on a large database
        // put it on a schedule rather than on every logout.
        try {
            db.execSQL("VACUUM");
        } catch (Exception e) {
            Log.w(Vault.TAG, "VACUUM failed (low disk space?): "
                    + e.getClass().getSimpleName());
        }

        // FIX 1. TRUNCATE, not PASSIVE. A passive checkpoint folds the WAL into
        // the main file but leaves the WAL file at its existing size with its
        // existing bytes -- so the pages you just tried to remove are still
        // sitting in it. TRUNCATE resets the file to zero length. Confirm with
        //     ls -l databases/notes.db-wal
        // and expect 0.
        Cursor c = db.rawQuery("PRAGMA wal_checkpoint(TRUNCATE)", null);
        if (c != null) {
            c.moveToFirst();
            c.close();
        }

        File wal = new File(ctx.getDatabasePath(DB).getPath() + "-wal");
        Log.d(Vault.TAG, "logout: deleted " + n + " rows; wal now "
                + (wal.exists() ? wal.length() + " bytes" : "absent"));
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
