// examples/fixed-vault/Vault.java
//
// The same app, with each of the five leaks in examples/leaky-vault/Vault.java
// closed. The CRYPTOGRAPHY IS UNCHANGED -- byte for byte the same AES-256/GCM
// with an AndroidKeyStore key. Diff the two files and every difference is about
// WHERE bytes go, not about how they are protected.
//
// That is the whole argument of chapter 33 expressed as a diff.
//
// FIX-1  no plaintext staging file. Encrypt in memory and write once, to a
//        temporary name in the SAME directory, then rename. The rename is
//        atomic within a filesystem, so there is never a moment where a
//        truncated vault.bin exists -- and there is never a moment where the
//        plaintext exists on disk at all.
// FIX-2  no debug export on external storage. If diagnostics are genuinely
//        needed, they are redacted and they stay inside the sandbox.
// FIX-3  no duplicate token in SharedPreferences. The one place the secret
//        lives is files/vault.bin, sealed. What goes in prefs is a non-secret
//        label and a timestamp.
// FIX-4  no secret in Log.d. The log records that a store happened and for
//        which label, which is what a support engineer actually needs.
// FIX-5  nothing sensitive in device-encrypted storage. The boot-time
//        component gets a flag saying whether a credential EXISTS, which is
//        all it needed; the credential itself stays credential-encrypted.
//
// Plus two fixes with no counterpart in the leaky app, because they are about
// removing residue rather than about not creating it:
//
// FIX-6  wipe() overwrites before unlinking and scrubs the in-memory copy.
//        Both are weaker than they look -- read the comments, they say so.
// FIX-7  the CE directory is chosen deliberately over no_backup/ and the
//        reasoning is written down, because "put it in no_backup" is advice
//        people follow without knowing what it buys.
//
// Compile: see examples/build.sh.

package com.pentest.ch33.vaultfixed;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.KeyStore;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class Vault {

    public static final String TAG = "CH33Fixed";

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "ch33_fixed_vault_key";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    private final Context ctx;

    public Vault(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    // -----------------------------------------------------------------------
    // Unchanged from the leaky app. Deliberately.
    // -----------------------------------------------------------------------

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

    private byte[] seal(byte[] plaintext) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key());
        byte[] iv = c.getIV();
        byte[] body = c.doFinal(plaintext);
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
    // The part that changed
    // -----------------------------------------------------------------------

    /**
     * The secret is taken as a byte[] rather than a String on purpose.
     *
     * A Java String is immutable and interned by the runtime; once a password
     * is in one, you cannot overwrite it and you do not control when the
     * garbage collector reclaims it. A byte[] can be zeroed the moment you are
     * done with it. This does not make the value unrecoverable from memory --
     * 19-Memory measured that freed memory on Android is NOT zeroed and comes
     * straight back at the same address -- but it shortens the window from
     * "until the process dies" to "until this method returns", and that is a
     * real difference in a heap dump.
     */
    public void store(String label, byte[] secret) {
        File dir = ctx.getFilesDir();
        File target = new File(dir, "vault.bin");
        File tmp = new File(dir, "vault.bin.new");

        try {
            // FIX-1. Encrypt first, in memory. There is no point in the entire
            // control flow at which cleartext is on the filesystem, including
            // the error paths -- which is the part the leaky version got wrong.
            byte[] sealed = seal(secret);

            FileOutputStream fos = new FileOutputStream(tmp);
            try {
                fos.write(sealed);
                // fsync BEFORE the rename. Without it, a power loss between the
                // write and the rename can leave a zero-length vault.bin: the
                // rename is durable but the data it points at is not. This is a
                // correctness fix, not a security one, and it is included
                // because the leaky version's silence about it is the more
                // common bug.
                fos.getFD().sync();
            } finally {
                fos.close();
            }

            if (!tmp.renameTo(target)) {
                throw new IOException("atomic replace failed");
            }

            // FIX-4. What a support engineer needs is that a store happened and
            // whether it succeeded. They have never needed the value.
            Log.d(TAG, "sealed record written for label=" + label
                    + " (" + sealed.length + " bytes ciphertext)");

        } catch (Exception e) {
            // The error path deletes the partial file. The leaky version's
            // error path left its plaintext staging file behind, which meant
            // the plaintext survived precisely when something had gone wrong --
            // the moment the app is most likely to be examined.
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
            Log.e(TAG, "store failed for label=" + label + ": "
                    + e.getClass().getSimpleName());
        } finally {
            // Scrub the caller's buffer. See the doc comment above for exactly
            // how much this is and is not worth.
            Arrays.fill(secret, (byte) 0);
        }

        // FIX-3. Prefs hold metadata, not the secret. Note that the KEY NAMES
        // are now boring, which matters for a reason that has nothing to do
        // with obscurity: a reviewer scanning shared_prefs/ should be able to
        // see at a glance that nothing here is sensitive.
        SharedPreferences sp = ctx.getSharedPreferences("session", Context.MODE_PRIVATE);
        sp.edit().putString("label", label)
                 .putLong("issued_at", System.currentTimeMillis())
                 .putBoolean("has_credential", true)
                 .apply();

        // FIX-5. The boot-time component asked "is there a credential?", not
        // "what is it". A boolean in device-encrypted storage answers that
        // without moving anything sensitive outside the credential-bound key
        // hierarchy.
        try {
            Context de = ctx.createDeviceProtectedStorageContext();
            SharedPreferences deSp = de.getSharedPreferences("boot", Context.MODE_PRIVATE);
            deSp.edit().putBoolean("credential_present", true).apply();
        } catch (Exception e) {
            Log.w(TAG, "DE flag write failed", e);
        }

        // FIX-2. No external write of any kind. If diagnostics are needed they
        // go through a redacting logger into the sandbox, and the export
        // feature -- if it must exist -- hands the user a Storage Access
        // Framework picker so THEY choose the destination and the app never
        // holds a broad storage grant. See README section 3.8.
    }

    /**
     * FIX-6. Remove the record and try to remove the residue.
     *
     * Read the caveats. This method is more honest than most production code
     * and it is still weaker than it looks:
     *
     *   * Overwriting a file before unlinking it assumes the filesystem writes
     *     the new bytes to the SAME physical blocks. On f2fs -- which is what
     *     /data is on the device this chapter was measured on -- that
     *     assumption is wrong by design: f2fs is log-structured and allocates
     *     new blocks for the overwrite, leaving the originals intact until the
     *     garbage collector reaches them. The overwrite is therefore a
     *     best-effort gesture, not an erase.
     *   * The only mechanism that reliably makes the bytes unrecoverable is
     *     losing the key. Because the record was sealed with a non-exportable
     *     AndroidKeyStore key, deleting that key does exactly that -- and that
     *     is the operation this method actually relies on. Everything before it
     *     is defence in depth.
     *   * This is why "crypto-shredding" is the right model for deletion on
     *     flash storage, and why an app that stores plaintext has no equivalent
     *     move available to it.
     */
    public void wipe() {
        File target = new File(ctx.getFilesDir(), "vault.bin");
        try {
            if (target.exists()) {
                long len = target.length();
                RandomAccessFile raf = new RandomAccessFile(target, "rws");
                try {
                    byte[] zeros = new byte[4096];
                    for (long off = 0; off < len; off += zeros.length) {
                        raf.write(zeros, 0, (int) Math.min(zeros.length, len - off));
                    }
                } finally {
                    raf.close();
                }
                //noinspection ResultOfMethodCallIgnored
                target.delete();
            }
            // The move that actually counts.
            KeyStore ks = KeyStore.getInstance(KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(KEY_ALIAS)) {
                ks.deleteEntry(KEY_ALIAS);
            }
            Log.d(TAG, "vault wiped and key destroyed");
        } catch (Exception e) {
            Log.e(TAG, "wipe failed: " + e.getClass().getSimpleName());
        }

        ctx.getSharedPreferences("session", Context.MODE_PRIVATE)
           .edit().clear().commit();
        try {
            ctx.createDeviceProtectedStorageContext()
               .getSharedPreferences("boot", Context.MODE_PRIVATE)
               .edit().clear().commit();
        } catch (Exception ignored) {
            // Nothing sensitive is there, so failing to clear it is not a leak.
        }
    }

    /**
     * FIX-7. Why files/ and not no_backup/.
     *
     * getNoBackupFilesDir() is a real directory that the backup agent skips. It
     * is the right home for a file when you want backup ENABLED for the rest of
     * the app and excluded for this one thing, and it needs no rules XML.
     *
     * This app sets allowBackup="false" outright, so nothing is backed up and
     * no_backup/ buys nothing here. Using it anyway would be cargo cult: it
     * would suggest a protection that is not doing any work, and the next
     * developer would assume the file is protected BECAUSE of the directory
     * rather than because of the manifest.
     *
     * Call this if you flip allowBackup back to true.
     */
    public File preferredLocationIfBackupEnabled() {
        return new File(ctx.getNoBackupFilesDir(), "vault.bin");
    }
}
