/*
 * examples/VaultService-fixed.java
 *
 * WHAT THIS IS
 *   The corrected twin of VaultService-vulnerable.java. It implements exactly
 *   the same interface (IVaultService.aidl), so a diff between the two files
 *   is a diff of security logic and nothing else.
 *
 *   Every fix carries a comment naming the pattern it closes and the README
 *   section that explains why.
 *
 * THE SHAPE, IN FIVE STEPS
 *   Every method that needs elevated privilege follows the same order, and
 *   the order is the whole point:
 *
 *     1. CAPTURE   Binder.getCallingUidOrThrow() as the FIRST statement,
 *                  into a final local, before anything can disturb it.
 *     2. DECIDE    authorise on that value and nothing else.
 *     3. CONSTRAIN validate the TARGET of the operation -- a path, a URI, a
 *                  package name -- because authorising the caller says
 *                  nothing about what they asked for.
 *     4. ACT       clearCallingIdentity() around exactly ONE privileged
 *                  statement.
 *     5. RESTORE   in a finally block. Always. There is no other correct
 *                  shape.
 *
 * WHAT IS DELIBERATELY NOT HERE
 *   No obfuscation, no root detection, no anti-tamper. Those are other
 *   chapters and they are not what makes this service safe. What makes it
 *   safe is that every entry point authorises on a value the caller cannot
 *   influence, and validates what the caller asked for.
 *
 * HOW TO BUILD
 *   Same as the vulnerable version: Android Studio module, rename the class
 *   to VaultService, .aidl files under src/main/aidl/com/example/vault/,
 *   `android { buildFeatures { aidl true } }`.
 *
 *   And note the manifest, which is part of the fix:
 *
 *     <permission android:name="com.example.vault.permission.ACCESS_VAULT"
 *                 android:protectionLevel="signature" />
 *     <service android:name=".VaultService"
 *              android:exported="true"
 *              android:permission="com.example.vault.permission.ACCESS_VAULT" />
 *
 *   The manifest permission is checked ONCE, at bind time. It decides who may
 *   OBTAIN the IBinder. The checks in onTransact decide who may USE it, and
 *   those are different populations, because an IBinder can be passed on in
 *   an Intent extra to someone who never held the permission. You need both.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - Whether SELinux permits the call. MAC runs before any of this, in the
 *     kernel. See 22-SELinux.
 *   - Whether the design is right. A vault service exported to other apps at
 *     all is a design decision worth challenging before it is a code review.
 *   - How to protect against a caller with the same signing key. You cannot,
 *     and should not try; signature-level trust is transitive by definition.
 */

package com.example.vault;

import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.os.RemoteException;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class VaultServiceFixed extends Service {

    private static final String TAG = "VaultFixed";

    /** FIX for README 3.14 / 5.2.7: refuse oversized transactions before parsing. */
    private static final int MAX_PAYLOAD_BYTES = 64 * 1024;

    /** FIX for 5.2.7: a cheap per-caller budget, keyed on the one unforgeable value. */
    private static final int MAX_CALLS_PER_WINDOW = 100;
    private static final long RATE_WINDOW_MS = 1000L;

    /**
     * FIX for 5.2.6: authorisation is bound to PACKAGE NAMES, and each is
     * signature-checked at use. A bare uid is not enough, because uids are
     * recycled after an uninstall and a shared uid hosts several packages.
     */
    private static final Set<String> ALLOWED_PACKAGES = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList("com.example.vault.companion")));

    private File mVaultDir;
    private Path mVaultCanonical;

    /** FIX for the bonus bug: per-client state, reclaimed by a death recipient. */
    private final Map<Integer, WatcherRecord> mWatchers = new ConcurrentHashMap<>();

    private final Map<Integer, RateBucket> mBuckets = new ConcurrentHashMap<>();

    @Override
    public void onCreate() {
        super.onCreate();
        mVaultDir = new File(getFilesDir(), "vault");
        if (!mVaultDir.exists() && !mVaultDir.mkdirs()) {
            throw new IllegalStateException("cannot create vault dir");
        }
        try {
            // Resolved ONCE, at start-up, so the prefix comparison later is
            // against a stable canonical path rather than one an attacker
            // could influence by creating symlinks mid-request.
            mVaultCanonical = mVaultDir.getCanonicalFile().toPath();
        } catch (IOException e) {
            throw new IllegalStateException("cannot canonicalise vault dir", e);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private final IVaultService.Stub mBinder = new IVaultService.Stub() {

        /**
         * FIX for 3.14 and 5.2.7. Two rejections that cost almost nothing and
         * happen before a single field is parsed:
         *
         *   - a size cap, because a service that will parse anything can be
         *     used to exhaust its own 1016 KiB buffer by any caller;
         *   - a per-uid rate limit, because the thread pool is 16 deep and a
         *     caller that can occupy it can stall every other client.
         *
         * super.onTransact() then runs the generated switch, which performs
         * data.enforceInterface(DESCRIPTOR) per case (README 3.9). We do NOT
         * replace that dispatch -- overriding it by hand is how services lose
         * their interface-token check.
         */
        @Override
        public boolean onTransact(int code, android.os.Parcel data,
                                  android.os.Parcel reply, int flags)
                throws RemoteException {

            if (data.dataSize() > MAX_PAYLOAD_BYTES) {
                throw new IllegalArgumentException(
                        "payload " + data.dataSize() + " > " + MAX_PAYLOAD_BYTES);
            }
            // getCallingUidOrThrow, not getCallingUid: if we are somehow not
            // inside a transaction, we want a loud failure rather than our
            // own uid silently satisfying every check below.
            final int uid = Binder.getCallingUidOrThrow();
            if (!allowRate(uid)) {
                throw new IllegalStateException("rate limited");
            }
            return super.onTransact(code, data, reply, flags);
        }

        /* ------------------------------------------------------------------
         * FIXES PATTERN 1 (clear before the check) and the missing path
         * validation. Compare with the vulnerable version line by line.
         * ------------------------------------------------------------------ */
        @Override
        public String readSecret(String name) {
            final int uid = Binder.getCallingUidOrThrow();   // 1. CAPTURE, first statement
            enforceCaller(uid);                              // 2. DECIDE, on the real identity

            final File target = resolveInsideVault(name);    // 3. CONSTRAIN the target

            final long token = Binder.clearCallingIdentity();// 4. ACT, one statement wide
            try {
                return readFile(target);
            } catch (IOException e) {
                // Do not leak the absolute path or the underlying cause to an
                // untrusted caller -- the exception message crosses the
                // boundary in the reply parcel (README 3.7.5).
                Log.w(TAG, "read failed for uid " + uid, e);
                throw new IllegalStateException("read failed");
            } finally {
                Binder.restoreCallingIdentity(token);        // 5. RESTORE, always
            }
        }

        /* ------------------------------------------------------------------
         * FIXES PATTERN 2 (window too wide). Everything that touches
         * caller-supplied data, and every call OUT to another process, now
         * happens with the caller's own identity. Only the single privileged
         * write is inside the cleared window.
         * ------------------------------------------------------------------ */
        @Override
        public void writeSecret(String name, String value) {
            final int uid = Binder.getCallingUidOrThrow();
            enforceCaller(uid);

            if (value == null) throw new IllegalArgumentException("null value");
            if (value.length() > 8192) throw new IllegalArgumentException("value too long");

            final File target = resolveInsideVault(name);    // outside the window

            final long token = Binder.clearCallingIdentity();
            try {
                writeFile(target, value);                    // the ONE privileged statement
            } catch (IOException e) {
                Log.w(TAG, "write failed for uid " + uid, e);
                throw new IllegalStateException("write failed");
            } finally {
                Binder.restoreCallingIdentity(token);
            }

            // Calling out to other processes happens AFTER the window closes,
            // so any permission check those callees perform is evaluated
            // against us with our ordinary identity, not an elevated one.
            notifyAllWatchers(name);
        }

        /* ------------------------------------------------------------------
         * FIXES PATTERN 3 (no finally). The restore cannot be skipped now,
         * whatever deleteFile throws.
         * ------------------------------------------------------------------ */
        @Override
        public boolean deleteSecret(String name) {
            final int uid = Binder.getCallingUidOrThrow();
            enforceCaller(uid);

            final File target = resolveInsideVault(name);

            final long token = Binder.clearCallingIdentity();
            try {
                return target.exists() && target.delete();
            } finally {
                Binder.restoreCallingIdentity(token);        // reached on every path
            }
        }

        /* ------------------------------------------------------------------
         * FIXES PATTERN 4 (shared token). The token is a LOCAL. It cannot be
         * observed, overwritten or restored by another thread, which is the
         * only property that makes clear/restore safe in a pooled-thread
         * server.
         * ------------------------------------------------------------------ */
        @Override
        public String[] listSecrets() {
            final int uid = Binder.getCallingUidOrThrow();
            enforceCaller(uid);

            final long token = Binder.clearCallingIdentity();   // LOCAL, not a field
            try {
                final File[] files = mVaultDir.listFiles();
                if (files == null) return new String[0];
                final List<String> out = new ArrayList<>(files.length);
                for (File f : files) {
                    if (f.isFile()) out.add(f.getName());
                }
                return out.toArray(new String[0]);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        /* ------------------------------------------------------------------
         * A oneway method, authorised on the UID -- the only identifier that
         * is still meaningful here.
         *
         * getCallingPid() is 0 in a one-way transaction (README 3.10), so any
         * pid-based logic would be silently disabled on this method and only
         * on this method. The vulnerable version's `if (pid != 0 && ...)`
         * check is a perfect example: it looks defensive and can never fire.
         *
         * Note also that any exception thrown here is swallowed by the
         * transport and never reaches the caller. We therefore LOG the
         * refusal, because otherwise a refused one-way call is invisible from
         * both ends.
         * ------------------------------------------------------------------ */
        @Override
        public void notifyChanged(String name) {
            final int uid = Binder.getCallingUidOrThrow();
            try {
                enforceCaller(uid);
            } catch (SecurityException e) {
                // oneway: this exception cannot reach the caller. Record it.
                Log.w(TAG, "refused oneway notifyChanged from uid " + uid);
                return;
            }
            notifyAllWatchers(name);
        }

        /* ------------------------------------------------------------------
         * FIXES the callback-map leak.
         *
         * An IBinder handed to us is a capability from a process we do not
         * control, and that process can die at any moment. linkToDeath is how
         * we learn, and removing the entry in binderDied is what turns an
         * unbounded map into a bounded one.
         * ------------------------------------------------------------------ */
        @Override
        public void registerWatcher(IVaultWatcher watcher) {
            final int uid = Binder.getCallingUidOrThrow();
            enforceCaller(uid);
            if (watcher == null) throw new IllegalArgumentException("null watcher");

            final IBinder token = watcher.asBinder();
            final IBinder.DeathRecipient recipient = new IBinder.DeathRecipient() {
                @Override public void binderDied() {
                    mWatchers.remove(uid);
                    Log.i(TAG, "watcher for uid " + uid + " died; state reclaimed");
                }
            };
            try {
                token.linkToDeath(recipient, 0);
            } catch (RemoteException e) {
                // Already dead. Nothing to register.
                throw new IllegalStateException("watcher already dead");
            }

            final WatcherRecord previous =
                    mWatchers.put(uid, new WatcherRecord(watcher, token, recipient));
            if (previous != null) {
                // One registration per uid: otherwise a single caller can
                // grow the map on its own.
                try { previous.binder.unlinkToDeath(previous.recipient, 0); }
                catch (Exception ignored) { }
            }
        }
    };

    /* ====================================================================
     * Security helpers. These ARE the controls.
     * ==================================================================== */

    /**
     * FIX for 5.2.6. A uid alone is not an identity you can persist against:
     * it is recycled after an uninstall, and a shared uid hosts several
     * packages. So resolve it to packages, require one of them to be on the
     * allow-list, AND require the signature to match.
     *
     * Note the loop: getPackagesForUid() returns an ARRAY. Taking element [0]
     * and comparing it is checking an arbitrary member of a set.
     */
    private void enforceCaller(int uid) {
        if (uid == Process.myUid() || uid == Process.SYSTEM_UID) return;

        final PackageManager pm = getPackageManager();
        final String[] pkgs = pm.getPackagesForUid(uid);
        if (pkgs == null || pkgs.length == 0) {
            throw new SecurityException("uid " + uid + " has no packages");
        }
        for (String pkg : pkgs) {
            if (!ALLOWED_PACKAGES.contains(pkg)) continue;
            if (pm.checkSignatures(getPackageName(), pkg) == PackageManager.SIGNATURE_MATCH) {
                return;
            }
            // On the allow-list but wrong signature: that is worth shouting about.
            Log.e(TAG, "package " + pkg + " is allow-listed but its signature does not match");
        }
        throw new SecurityException("uid " + uid + " not permitted");
    }

    /**
     * FIX for the path traversal.
     *
     * Rejecting '/' and ".." is necessary and NOT sufficient: a symlink
     * created inside the vault by an earlier legitimate write points wherever
     * it likes. Canonicalising and re-checking the prefix is what actually
     * closes it.
     *
     * The trailing separator in the comparison matters too: without it,
     * "/data/user/0/com.example.vault/files/vaultevil" passes a naive
     * startsWith("/data/user/0/com.example.vault/files/vault") check.
     */
    private File resolveInsideVault(String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("empty name");
        }
        // The NUL check uses the numeric code point, not a character
        // literal, and that is deliberate twice over. A raw NUL byte in
        // source is not portable and breaks grep; and String.indexOf(int)
        // takes a code point, so indexOf(0) is exact and needs no escape.
        //
        // It is also not decoration. A Java String may legally contain
        // U+0000, but the C layer underneath getCanonicalPath() and open()
        // treats it as a terminator. So a name of the form
        //     safe.txt<NUL>/../../secrets
        // can pass a naive Java-side check and then open "safe.txt" -- or,
        // on a different code path, the other half. Reject the character
        // outright rather than reasoning about where truncation happens.
        if (name.indexOf('/') >= 0 || name.indexOf('\\') >= 0
                || name.indexOf(' ') >= 0 || name.indexOf(0) >= 0
                || name.contains("..")) {
            throw new IllegalArgumentException("bad name");
        }
        if (name.length() > 128) {
            throw new IllegalArgumentException("name too long");
        }
        final File f = new File(mVaultDir, name);
        try {
            final Path canonical = f.getCanonicalFile().toPath();
            if (!canonical.startsWith(mVaultCanonical)
                    || canonical.equals(mVaultCanonical)) {
                throw new IllegalArgumentException("escapes the vault");
            }
            return canonical.toFile();
        } catch (IOException e) {
            throw new IllegalArgumentException("unresolvable name");
        }
    }

    /** FIX for 5.2.7: a fixed-window counter, keyed on the unforgeable uid. */
    private boolean allowRate(int uid) {
        final long now = System.currentTimeMillis();
        final RateBucket b = mBuckets.computeIfAbsent(uid, k -> new RateBucket(now));
        synchronized (b) {
            if (now - b.windowStart >= RATE_WINDOW_MS) {
                b.windowStart = now;
                b.count.set(0);
            }
            return b.count.incrementAndGet() <= MAX_CALLS_PER_WINDOW;
        }
    }

    private String readFile(File f) throws IOException {
        if (!f.isFile()) throw new IOException("not a regular file");
        if (f.length() > MAX_PAYLOAD_BYTES) throw new IOException("secret too large");
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    private void writeFile(File f, String value) throws IOException {
        Files.write(f.toPath(), value.getBytes(StandardCharsets.UTF_8));
    }

    /** Runs with our ordinary identity, outside every cleared window. */
    private void notifyAllWatchers(String name) {
        for (Map.Entry<Integer, WatcherRecord> e : mWatchers.entrySet()) {
            try {
                e.getValue().watcher.onSecretChanged(name);   // oneway: cannot block us
            } catch (RemoteException ex) {
                mWatchers.remove(e.getKey());
            }
        }
    }

    private static final class WatcherRecord {
        final IVaultWatcher watcher;
        final IBinder binder;
        final IBinder.DeathRecipient recipient;
        WatcherRecord(IVaultWatcher w, IBinder b, IBinder.DeathRecipient r) {
            watcher = w; binder = b; recipient = r;
        }
    }

    private static final class RateBucket {
        long windowStart;
        final AtomicInteger count = new AtomicInteger();
        RateBucket(long start) { windowStart = start; }
    }
}
