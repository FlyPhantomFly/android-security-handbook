/*
 * examples/VaultService-vulnerable.java
 *
 * WHAT THIS IS
 *   A deliberately vulnerable AIDL service implementing IVaultService.aidl.
 *   It contains ALL FOUR clearCallingIdentity() misuse patterns, plus the two
 *   failures that usually accompany them (no argument validation, and a
 *   registered-callback map with no death recipient), so that each can be
 *   found, exploited and fixed in labs/lab-03-identity-boundary.md.
 *
 *   Its corrected twin is VaultService-fixed.java. The two implement exactly
 *   the same interface, so you can diff them and every difference is security.
 *
 * WHY A DEVELOPER WRITES THIS
 *   This is not a strawman. Every pattern below has a plausible origin:
 *
 *     - clearCallingIdentity() gets added because a file read threw
 *       SecurityException, and clearing identity made the error go away.
 *     - The permission check ends up AFTER the clear because the developer
 *       added the clear at the top of the method, where it is tidy.
 *     - The path is not validated because during development the only caller
 *       was the team's own companion app, which always passed a plain name.
 *     - The token becomes a field because begin() and end() were split into
 *       two AIDL methods for a "transaction" API.
 *
 * HOW TO BUILD
 *   Drop into an Android Studio module as
 *     src/main/java/com/example/vault/VaultService.java
 *   (rename the class to VaultService), alongside the two .aidl files in
 *     src/main/aidl/com/example/vault/
 *   with `android { buildFeatures { aidl true } }` in build.gradle.
 *
 *   The manifest entry that makes it reachable -- and note that it is
 *   deliberately unprotected:
 *
 *     <service android:name=".VaultService" android:exported="true" />
 *
 * HOW TO ATTACK IT
 *   See labs/lab-03-identity-boundary.md. The short version:
 *     IVaultService v = IVaultService.Stub.asInterface(binder);
 *     String stolen = v.readSecret("/data/data/com.example.vault/shared_prefs/tokens.xml");
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - How to exploit a REAL service. Real services are messier and the
 *     vulnerable path is usually one method among forty. This file is a
 *     teaching artefact: it is what you are looking for, distilled.
 *   - Anything about SELinux. MAC decides whether your transaction is
 *     delivered at all, before any of this code runs. See 22-SELinux.
 *   - Whether YOUR app has this bug. Run the greps in README section 8.
 *
 * DO NOT SHIP THIS. It is wrong on purpose.
 */

package com.example.vault;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.os.RemoteException;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class VaultServiceVulnerable extends Service {

    private static final String TAG = "VaultVuln";

    /** Where secrets are supposed to live. Nothing below actually enforces it. */
    private File mVaultDir;

    /**
     * BUG 5 (bonus): a token stored in an instance FIELD.
     *
     * Binder threads are pooled. begin() may run on thread A and end() on
     * thread B, so thread B restores thread A's caller identity onto itself.
     * A token must ALWAYS be a local variable. If your design makes that
     * impossible, the design is the bug.
     */
    private long mSharedToken;

    /**
     * BUG 6 (bonus): registered callbacks with no death recipient.
     *
     * Nothing ever removes an entry. A caller that binds, registers and dies
     * in a loop grows this map without bound, from an unprivileged app, with
     * no authentication. That is a memory-exhaustion primitive.
     */
    private final Map<Integer, IVaultWatcher> mWatchers = new HashMap<>();

    @Override
    public void onCreate() {
        super.onCreate();
        mVaultDir = new File(getFilesDir(), "vault");
        if (!mVaultDir.exists() && !mVaultDir.mkdirs()) {
            Log.w(TAG, "could not create " + mVaultDir);
        }
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private final IVaultService.Stub mBinder = new IVaultService.Stub() {

        /* ------------------------------------------------------------------
         * PATTERN 1 -- CLEAR BEFORE THE CHECK.
         *
         * clearCallingIdentity() sets this thread's calling identity to the
         * SERVICE's own uid and pid. Every getCallingUid() after it therefore
         * returns OUR uid, not the caller's.
         *
         * So the check below is asking "is the vault service allowed to talk
         * to the vault service", and the answer is always yes. It looks like
         * a permission check. It is a no-op.
         *
         * Compounded by: `name` goes straight into new File(name) with no
         * validation at all, so it may be an absolute path anywhere the
         * service's uid can read.
         *
         * EXPLOIT:
         *   v.readSecret("/data/data/com.example.vault/shared_prefs/tokens.xml")
         *   v.readSecret("/data/system/packages.xml")   // if the uid allows
         * ------------------------------------------------------------------ */
        @Override
        public String readSecret(String name) {
            final long token = Binder.clearCallingIdentity();     // <-- TOO EARLY
            try {
                final int uid = Binder.getCallingUid();           // <-- now returns OUR uid
                if (uid != Process.SYSTEM_UID && !isTrustedUid(uid)) {
                    throw new SecurityException("caller " + uid + " not permitted");
                }
                // Never reached with a hostile uid, because `uid` is ours.
                return readFileRaw(new File(name));               // <-- no path validation
            } catch (IOException e) {
                throw new IllegalStateException("read failed", e);
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        }

        /* ------------------------------------------------------------------
         * PATTERN 2 -- THE CLEARED WINDOW IS TOO WIDE.
         *
         * The identity check here is correct and happens first. The bug is
         * that the cleared window wraps the ENTIRE rest of the method,
         * including work driven by caller-supplied data:
         *
         *   - resolvePath() follows a caller-chosen name;
         *   - notifyAllWatchers() calls OUT to registered callbacks, which
         *     are other processes, while we still hold elevated identity.
         *     Any permission check those downstream calls perform now
         *     evaluates against US.
         *
         * The privileged step that actually needed the clear is one line.
         * ------------------------------------------------------------------ */
        @Override
        public void writeSecret(String name, String value) {
            final int uid = Binder.getCallingUid();
            if (!isTrustedUid(uid)) {
                throw new SecurityException("caller " + uid + " not permitted");
            }

            final long token = Binder.clearCallingIdentity();     // <-- window opens
            try {
                final File f = resolvePath(name);                 // caller-controlled
                writeFileRaw(f, value);                           // the ONE privileged step
                indexSecret(f);                                   // more caller-driven work
                notifyAllWatchers(name);                          // CALLS OUT, still elevated
                Log.i(TAG, "wrote " + f + " for uid " + uid);
            } catch (IOException e) {
                throw new IllegalStateException("write failed", e);
            } finally {
                Binder.restoreCallingIdentity(token);             // <-- window closes, far too late
            }
        }

        /* ------------------------------------------------------------------
         * PATTERN 3 -- NO finally.
         *
         * If deleteFileRaw() throws -- and it will, for a name that does not
         * exist -- restoreCallingIdentity() is never reached. The exception
         * propagates out of onTransact, is packed into an exception parcel,
         * and the thread goes back into the POOL with its identity still
         * cleared.
         *
         * The kernel re-stamps mCallingUid at the start of the next incoming
         * transaction, so the leak is not directly visible in getCallingUid().
         * What leaks is everything DERIVED from it while cleared: a cached
         * decision, a ThreadLocal, an open connection -- and, worst, a token
         * restored later out of order.
         *
         * EXPLOIT: call deleteSecret("does-not-exist") to leave the thread
         * dirty, then immediately call a method that trusts derived state.
         * ------------------------------------------------------------------ */
        @Override
        public boolean deleteSecret(String name) {
            final int uid = Binder.getCallingUid();
            if (!isTrustedUid(uid)) {
                throw new SecurityException("caller " + uid + " not permitted");
            }

            final long token = Binder.clearCallingIdentity();
            final boolean gone = deleteFileRaw(resolvePath(name));  // may throw
            Binder.restoreCallingIdentity(token);                   // <-- NOT in a finally
            return gone;
        }

        /* ------------------------------------------------------------------
         * PATTERN 4 -- RESTORING A TOKEN THAT IS NOT OURS.
         *
         * mSharedToken is an instance field written by whichever thread ran
         * last. Two callers on two pooled threads race, and the loser
         * restores the winner's caller identity onto its own thread.
         *
         * Also note what the token IS: (uid << 32) | pid. It is arithmetic,
         * not a capability. Nothing validates it. restoreCallingIdentity()
         * will happily accept a value you invented.
         * ------------------------------------------------------------------ */
        @Override
        public String[] listSecrets() {
            mSharedToken = Binder.clearCallingIdentity();          // <-- shared FIELD
            try {
                final File[] files = mVaultDir.listFiles();
                if (files == null) return new String[0];
                final List<String> out = new ArrayList<>();
                for (File f : files) out.add(f.getName());
                return out.toArray(new String[0]);
            } finally {
                Binder.restoreCallingIdentity(mSharedToken);       // <-- possibly another thread's
            }
        }

        /* ------------------------------------------------------------------
         * A oneway method. Two things follow, and neither is obvious:
         *
         *   1. getCallingPid() is 0 here, always, because the driver records
         *      no sending thread for a one-way transaction. Any check that
         *      compares the pid silently behaves differently on this method
         *      than on every other one.
         *
         *   2. The SecurityException below NEVER REACHES THE CALLER. It is
         *      logged in this process and discarded. An attacker calling this
         *      in a loop sees success every time.
         * ------------------------------------------------------------------ */
        @Override
        public void notifyChanged(String name) {
            final int uid = Binder.getCallingUid();
            final int pid = Binder.getCallingPid();               // <-- 0. Always.
            Log.i(TAG, "notifyChanged from uid=" + uid + " pid=" + pid);
            if (pid != 0 && !isTrustedPid(pid)) {                 // <-- therefore never fires
                throw new SecurityException("bad pid");           // <-- and would be swallowed
            }
            notifyAllWatchers(name);
        }

        /* ------------------------------------------------------------------
         * Accepting an IBinder without linkToDeath, and keying it on a bare
         * uid. Both are bugs. See mWatchers above.
         * ------------------------------------------------------------------ */
        @Override
        public void registerWatcher(IVaultWatcher watcher) {
            if (watcher == null) return;
            // No identity check at all on this entry point.
            synchronized (mWatchers) {
                mWatchers.put(Binder.getCallingUid(), watcher);   // no linkToDeath, ever
            }
        }
    };

    /* ====================================================================
     * Helpers. Nothing below is a security control, despite the names.
     * ==================================================================== */

    /**
     * BUG: a uid allow-list that is populated at runtime and persisted.
     * UIDs are RECYCLED after an uninstall, so a completely unrelated app
     * installed later can inherit a trusted number. Bind authorisation to
     * package name plus signing certificate instead. See the fixed version.
     */
    private boolean isTrustedUid(int uid) {
        return uid == Process.myUid() || uid == 1000 /* system */;
    }

    /** Never do this. PIDs are recyclable and racy, and 0 on oneway calls. */
    private boolean isTrustedPid(int pid) {
        return pid > 0;
    }

    /** BUG: joins an attacker-controlled name onto a directory with no checks. */
    private File resolvePath(String name) {
        return new File(mVaultDir, name);       // "../../databases/x" escapes trivially
    }

    private String readFileRaw(File f) throws IOException {
        return new String(Files.readAllBytes(Paths.get(f.getAbsolutePath())),
                          StandardCharsets.UTF_8);
    }

    private void writeFileRaw(File f, String value) throws IOException {
        Files.write(Paths.get(f.getAbsolutePath()), value.getBytes(StandardCharsets.UTF_8));
    }

    private boolean deleteFileRaw(File f) {
        if (!f.exists()) throw new IllegalArgumentException("no such secret: " + f.getName());
        return f.delete();
    }

    private void indexSecret(File f) { /* pretend this touches a database */ }

    /** Calls out to other processes. Doing this while identity is cleared is Pattern 2. */
    private void notifyAllWatchers(String name) {
        synchronized (mWatchers) {
            for (IVaultWatcher w : mWatchers.values()) {
                try {
                    w.onSecretChanged(name);
                } catch (RemoteException e) {
                    Log.w(TAG, "watcher gone -- and we never unregister it", e);
                }
            }
        }
    }
}
