// examples/leaky-vault/ExportActivity.java
//
// A second, separately drivable "feature" so that labs/lab-02 has more than one
// exercise to snapshot around. It writes a report to a SHARED collection --
// Downloads -- rather than to app-specific storage, which is a different leak
// class from everything in Vault.java and is worth isolating.
//
// The distinction that matters:
//
//   getExternalFilesDir()   app-specific. Removed on uninstall. No permission
//                           needed. Not indexed by MediaStore. Not visible to
//                           other apps on API 30+.
//
//   Downloads / DCIM / etc  a SHARED COLLECTION. Survives uninstall. Indexed by
//                           MediaStore, so visible to any app holding a media
//                           read permission. Attributed to this package in
//                           MediaStore.MediaColumns.OWNER_PACKAGE_NAME, which
//                           is itself a privacy leak: any reader learns which
//                           app produced the file.
//
// This is the answer to the FAQ question "why did my file survive uninstall".
// Files an app writes into a shared collection are not the app's to delete.
//
// Two paths are implemented, and which one runs depends on the API level,
// because this is exactly where the API 29/30 hinge bites:
//
//   modern   MediaStore.Downloads with IS_PENDING, the sanctioned route. Needs
//            no permission at all on API 29+, because the app is writing
//            through the provider rather than at the filesystem.
//
//   legacy   Environment.getExternalStoragePublicDirectory() and a raw File.
//            This is what the app did before somebody updated it. Keeping the
//            branch is deliberate, and the result is the interesting part:
//
//            MEASURED ON API 30, from this app, which holds NO storage
//            permission: the legacy write SUCCEEDED.
//
//                -rw-rw---- 96 /sdcard/Download/legacy-ch33-vault-export.txt
//
//            Android 11 restored direct filesystem access for CREATING files in
//            the media collections; what it did not restore is reading or
//            modifying files the app does not own. So the widely repeated claim
//            that scoped storage forces every shared-collection write through
//            MediaStore is wrong on this device, and an app can still drop a
//            token into Download/ with three lines of pre-scoped-storage code.
//
//            Contrast with a write to the shared ROOT, which the probe in
//            StorageProbe.java measures failing with EPERM from the same app.
//            The root is closed; the collections are not.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch33.vault;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.MediaStore;
import android.util.Log;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;

public class ExportActivity extends Activity {

    private static final String NAME = "ch33-vault-export.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        tv.setTextSize(12);
        tv.setPadding(32, 48, 32, 32);
        setContentView(tv);

        // The payload deliberately contains the same token the vault sealed, so
        // leak-hunter.py's "plaintext beside ciphertext" grouping has something
        // real to find.
        SharedPreferences sp = getSharedPreferences("session", Context.MODE_PRIVATE);
        String token = sp.getString("auth_token", "(no token stored yet)");
        String body = "CH33 export\n"
                + "generated=" + System.currentTimeMillis() + "\n"
                + "auth_token=" + token + "\n";

        StringBuilder log = new StringBuilder();
        log.append(tryModern(body)).append("\n\n").append(tryLegacy(body));
        tv.setText(log.toString());
        Log.i(Vault.TAG, "export complete");
    }

    /**
     * The sanctioned route. Insert a row with IS_PENDING=1, write through the
     * returned URI, then clear IS_PENDING.
     *
     * IS_PENDING is the part people skip and should not. Between the insert and
     * the clear, the file exists on disk but MediaStore hides it from every
     * other app. Skipping it means other apps can see and read a half-written
     * file -- which for an export containing a token is a real, if narrow,
     * window.
     */
    private String tryModern(String body) {
        if (Build.VERSION.SDK_INT < 29) {
            return "modern path: skipped, needs API 29+";
        }
        try {
            ContentResolver cr = getContentResolver();
            ContentValues cv = new ContentValues();
            cv.put(MediaStore.MediaColumns.DISPLAY_NAME, NAME);
            cv.put(MediaStore.MediaColumns.MIME_TYPE, "text/plain");
            cv.put(MediaStore.MediaColumns.RELATIVE_PATH,
                   Environment.DIRECTORY_DOWNLOADS);
            cv.put(MediaStore.MediaColumns.IS_PENDING, 1);

            Uri collection = MediaStore.Downloads.getContentUri(
                    MediaStore.VOLUME_EXTERNAL_PRIMARY);
            Uri item = cr.insert(collection, cv);
            if (item == null) {
                return "modern path: insert() returned null";
            }
            OutputStream os = cr.openOutputStream(item);
            if (os == null) {
                return "modern path: openOutputStream() returned null for " + item;
            }
            os.write(body.getBytes("UTF-8"));
            os.close();

            cv.clear();
            cv.put(MediaStore.MediaColumns.IS_PENDING, 0);
            cr.update(item, cv, null, null);

            return "modern path: wrote " + item + "\n"
                 + "  This file is in a SHARED COLLECTION. It survives uninstall,\n"
                 + "  it is indexed, and MediaStore records that "
                 + getPackageName() + " created it.";
        } catch (Exception e) {
            return "modern path FAILED: " + e;
        }
    }

    /**
     * The pre-scoped-storage route, kept so the failure is visible.
     *
     * On API 30 with no legacy opt-out this throws. The exception message is
     * worth reading in full, because it is the clearest single statement the
     * platform makes about what changed.
     */
    private String tryLegacy(String body) {
        try {
            File dir = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS);
            File out = new File(dir, "legacy-" + NAME);
            FileOutputStream fos = new FileOutputStream(out);
            fos.write(body.getBytes("UTF-8"));
            fos.close();
            return "legacy path: wrote " + out + "\n"
                 + "  If this line appears on API 30+, the app has legacy storage\n"
                 + "  access -- check targetSdkVersion, requestLegacyExternalStorage,\n"
                 + "  and whether MANAGE_EXTERNAL_STORAGE is held.";
        } catch (Exception e) {
            return "legacy path FAILED (expected on API 30+): " + e;
        }
    }
}
