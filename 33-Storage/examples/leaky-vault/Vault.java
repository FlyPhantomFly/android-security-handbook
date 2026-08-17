// examples/leaky-vault/Vault.java
//
// The encryption in this file is CORRECT. That is the point.
//
// AES-256/GCM, a random 12-byte IV per operation, a key generated inside the
// AndroidKeyStore and never exportable. Chapter 34 would grade this Tier 1. A
// reviewer reading only this method signs it off, and a static scanner looking
// for hardcoded keys, ECB mode or a fixed IV finds nothing.
//
// And the plaintext still ends up on disk in four other places, because the
// mistakes are not in the cryptography -- they are in everything that happens
// AROUND it. That is chapter 33's whole thesis: 34-Cryptography owns whether
// the ciphertext is sound, and 33 owns where the ciphertext went and what else
// went with it.
//
// The five leaks, each marked LEAK-n below and each with a different reason a
// developer writes it:
//
//   LEAK-1  a plaintext scratch file in cache/, written before encryption
//           because "it is only temporary" and deleted afterwards -- except
//           deletion unlinks the name, not the bytes, and the delete is
//           skipped entirely on the error path.
//   LEAK-2  a plaintext "debug export" on external app-specific storage,
//           because support asked for a way to collect logs from users.
//   LEAK-3  the same secret in SharedPreferences, because a different feature
//           needed it synchronously and the vault call was asynchronous.
//   LEAK-4  the secret in Log.d, because someone was debugging LEAK-3.
//   LEAK-5  the secret in device-encrypted storage, because a boot-time
//           component needed it and DE storage was the path of least
//           resistance.
//
// None of these is exotic. Every one of them has shipped in a real app.
//
// Compile: see examples/build.sh. Do not ship this.

package com.pentest.ch33.vault;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Vault {

    public static final String TAG = "CH33Vault";

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "ch33_vault_key";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    private final Context ctx;

    public Vault(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    // -----------------------------------------------------------------------
    // The correct part
    // -----------------------------------------------------------------------

    /**
     * Fetch, or create on first use, an AES-256 key that lives inside the
     * AndroidKeyStore. The key material never enters this process's address
     * space: getKey() returns a handle, and every Cipher operation on it is
     * performed by keystore2 on the other side of a Binder call. Even a full
     * memory dump of this app does not yield the key.
     *
     * setUserAuthenticationRequired is deliberately NOT set. That is a design
     * decision, not a bug: requiring authentication per use would be stronger,
     * and 49-KeyStore covers the trade-off. It is out of scope here.
     */
    private SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        if (ks.containsAlias(KEY_ALIAS)) {
            return (SecretKey) ks.getKey(KEY_ALIAS, null);
        }
        KeyGenerator kg = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        kg.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return kg.generateKey();
    }

    /** IV || ciphertext || GCM tag. Correct, and irrelevant to every leak below. */
    private byte[] seal(String plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = c.getIV();
        byte[] body = c.doFinal(plaintext.getBytes("UTF-8"));
        byte[] out = new byte[iv.length + body.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(body, 0, out, iv.length, body.length);
        return out;
    }

    public String open(byte[] sealed) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key(),
                new GCMParameterSpec(GCM_TAG_BITS, sealed, 0, IV_BYTES));
        byte[] plain = c.doFinal(sealed, IV_BYTES, sealed.length - IV_BYTES);
        return new String(plain, "UTF-8");
    }

    // -----------------------------------------------------------------------
    // The part that undoes it
    // -----------------------------------------------------------------------

    /**
     * Store a secret. Writes the ciphertext to files/vault.bin -- and, along
     * the way, writes the plaintext to four other places.
     *
     * Read this method twice. The first read looks like a careful
     * implementation with some incidental logging. The second read is the
     * finding.
     */
    public void store(String label, String secret) {
        // ------------------------------------------------------------ LEAK-1
        // "Stage it to a temp file first so we can recover if encryption
        // fails." The staging file holds the CLEARTEXT, in cache/, at mode
        // 0600 inside the sandbox -- which sounds acceptable until you list
        // the adversaries who reach it: adb backup does not (cache/ is
        // excluded), but a device-image acquisition does, root does, and any
        // path-traversal bug in this app's own exported ContentProvider does
        // (see 27-ContentProviders).
        //
        // Worse, look at the control flow. The delete() at the end of the try
        // block does not run if seal() throws -- and seal() throws on any
        // keystore error, which is exactly the situation in which the app is
        // most likely to be examined. The failure path leaves the plaintext
        // behind permanently.
        File staging = new File(ctx.getCacheDir(), "vault-staging.tmp");
        try {
            writeBytes(staging, secret.getBytes("UTF-8"));

            byte[] sealed = seal(secret);
            writeBytes(new File(ctx.getFilesDir(), "vault.bin"), sealed);

            // And even on the happy path: delete() unlinks the directory
            // entry. It does not overwrite the data blocks, and on f2fs with
            // its log-structured layout it very often does not even mark them
            // reusable immediately. A raw partition carve recovers this. The
            // filesystem does not owe you an erase.
            //noinspection ResultOfMethodCallIgnored
            staging.delete();

        } catch (Exception e) {
            // LEAK-1 continued: nothing deletes the staging file here.
            Log.e(TAG, "store failed for " + label, e);
        }

        // ------------------------------------------------------------ LEAK-2
        // A "debug export" on external app-specific storage. No permission is
        // required to write here and none is declared, so a permission audit
        // of the manifest reports a clean app.
        //
        // getExternalFilesDir() is app-specific and is removed on uninstall,
        // which is why developers believe it is private. It is not protected
        // by this app's uid: on the disk it belongs to the media stack, and it
        // is reachable by anything holding MANAGE_EXTERNAL_STORAGE, by adb
        // shell on Android 11, and by the user with a file manager on any
        // version of Android that predates the Android/data restriction.
        try {
            File dbg = new File(ctx.getExternalFilesDir(null), "debug");
            //noinspection ResultOfMethodCallIgnored
            dbg.mkdirs();
            File out = new File(dbg, "export.json");
            OutputStreamWriter w = new OutputStreamWriter(
                    new FileOutputStream(out, true), Charset.forName("UTF-8"));
            w.write("{\"label\":\"" + label + "\",\"secret\":\"" + secret
                    + "\",\"ts\":" + System.currentTimeMillis() + "}\n");
            w.close();
        } catch (Exception e) {
            Log.w(TAG, "debug export failed", e);
        }

        // ------------------------------------------------------------ LEAK-3
        // The same value again, in SharedPreferences, because a synchronous
        // reader needed it. shared_prefs/session.xml is plain XML at mode
        // 0600. Inside the sandbox this is not readable by another app -- but
        // it IS in the default backup set, which is what turns the manifest's
        // allowBackup="true" from a candidate into a demonstrated leak.
        //
        // Note the key name. "auth_token" is what makes this trivially
        // greppable, and renaming it to "x7" would not make the app safer by
        // one byte -- it would only make the finding take an extra minute.
        SharedPreferences sp = ctx.getSharedPreferences("session", Context.MODE_PRIVATE);
        sp.edit().putString("auth_token", secret)
                 .putString("label", label)
                 .putLong("issued_at", System.currentTimeMillis())
                 .apply();

        // ------------------------------------------------------------ LEAK-4
        // Somebody was debugging LEAK-3 and never took this out. Logcat is a
        // ring buffer, but it is storage: readable by root, by anything
        // holding READ_LOGS, by a crash reporter that uploads the buffer, and
        // by `adb logcat` from any host the user has authorised. On a
        // debuggable build it is also readable by the app's own uid, which
        // means any code running in this process -- including an injected
        // library -- can retrieve it after the fact.
        Log.d(TAG, "stored secret for " + label + ": " + secret);

        // ------------------------------------------------------------ LEAK-5
        // Device-encrypted storage. A boot-time component wanted the value
        // before first unlock, and DE storage was the shortest path to making
        // that work. The consequence is that the secret is now decryptable
        // from the moment the kernel mounts /data -- before anyone enters a
        // PIN. Every threat model that assumed "the attacker has a locked
        // phone" just changed.
        //
        // 09-Android-App-Internals section 5.7 is the vulnerability class;
        // this is a concrete instance of it. Note also that DE storage is NOT
        // in the backup set, so an allowBackup-only assessment misses it
        // entirely and reports the app as clean on this axis.
        try {
            Context de = ctx.createDeviceProtectedStorageContext();
            writeBytes(new File(de.getFilesDir(), "boot-token.txt"),
                       secret.getBytes("UTF-8"));
        } catch (Exception e) {
            Log.w(TAG, "DE write failed", e);
        }
    }

    private static void writeBytes(File f, byte[] data) throws IOException {
        File parent = f.getParentFile();
        if (parent != null) {
            //noinspection ResultOfMethodCallIgnored
            parent.mkdirs();
        }
        FileOutputStream fos = new FileOutputStream(f);
        try {
            fos.write(data);
            // No fsync. write() returning means the bytes are in the page
            // cache, not on the disk. For a security example this is a detail;
            // for a durability bug it is the whole story. See README 3.5.
        } finally {
            fos.close();
        }
    }
}
