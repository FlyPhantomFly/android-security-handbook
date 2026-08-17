// examples/VaultService-fixed.java
//   -> in an Android project this lives at
//      src/main/java/com/example/notesvault/VaultService.java
//
// THE FIXED HALF OF THE PAIR. Same IVaultService.aidl, same three methods, same
// build commands as VaultService-vulnerable.java. Every change is annotated
// against the README section that explains it.
//
// The four defects being fixed:
//   [1] exported with no permission            -> manifest below, FIX 1
//   [2] caller check in onBind()               -> FIX 2
//   [3] no caller check in the AIDL methods    -> FIX 3
//   [4] unvalidated input persisted            -> FIX 4
//
// ---------------------------------------------------------------------------
// FIX 1 -- THE MANIFEST. Declare a signature-level permission and require it.
//
// <permission
//     android:name="com.example.notesvault.permission.VAULT"
//     android:protectionLevel="signature"/>
//
// <service
//     android:name=".VaultService"
//     android:exported="true"
//     android:permission="com.example.notesvault.permission.VAULT">
//     <intent-filter>
//         <action android:name="com.example.notesvault.BIND_VAULT"/>
//     </intent-filter>
// </service>
//
// Three things about that, because each is a mistake people make while
// "fixing" this:
//
//   - protectionLevel MUST be "signature" (or "signature|knownSigner" with
//     android:knownCerts on API 31+). "normal" is granted at install to any app
//     that asks and is exactly equivalent to no permission. On the test device,
//     16 exported services were guarded by a normal-level permission and five
//     of those used android.permission.INTERNET. README 5.3.3.
//
//   - If NOTHING outside this app needs to bind, the correct fix is simply
//     android:exported="false" and no permission at all. Do that instead. The
//     permission version is shown because "our other app needs it" is the
//     usual real requirement.
//
//   - The manifest gate is COARSE and one-shot: it answers "may this uid bind",
//     not "may this uid call getAuthToken". FIX 3 is not optional just because
//     FIX 1 is present. A manifest merge from a library, a future refactor, or
//     a sibling app being compromised all defeat FIX 1 alone.
// ---------------------------------------------------------------------------

package com.example.notesvault;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.text.TextUtils;
import android.util.Log;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class VaultService extends Service {

    static final String TAG = "CH28VAULT";

    /** FIX 4: the endpoint may only ever be one of these hosts, over https. */
    private static final Set<String> ALLOWED_HOSTS = new HashSet<String>(
            Arrays.asList("sync.example.com", "sync-eu.example.com"));

    private SharedPreferences prefs;

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = getSharedPreferences("vault", MODE_PRIVATE);
    }

    // -----------------------------------------------------------------------
    // FIX 2 -- onBind DOES NOT CHECK THE CALLER, BECAUSE IT CANNOT.
    //
    // The vulnerable version had a getCallingUid() comparison here. It was
    // measured returning the service's OWN uid (10310) while the real caller
    // was 10291, because onBind runs on the main thread from an ActivityThread
    // message, outside any client transaction. README 3.7.
    //
    // The correct onBind is boring: return the binder, and do the authorising
    // where the transaction actually is. Two useful things it CAN do:
    //
    //   - return null for an Intent it does not recognise, which narrows the
    //     surface and is what the platform's own KeyChainService does. Measured:
    //     bindService returns TRUE and onServiceConnected never fires.
    //     From API 28 the client observes this as onNullBinding().
    //
    //   - hand out DIFFERENT binders for different actions, so a client that
    //     only needs the read-only interface never receives the writable one.
    // -----------------------------------------------------------------------
    @Override
    public IBinder onBind(Intent intent) {
        if (intent == null || !ACTION_BIND_VAULT.equals(intent.getAction())) {
            // Not an Intent we serve. Refuse it -- narrower is better, and it
            // costs nothing.
            Log.i(TAG, "onBind: unrecognised intent, returning null");
            return null;
        }
        return binder;
    }

    static final String ACTION_BIND_VAULT = "com.example.notesvault.BIND_VAULT";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // `intent` is NULL on a START_STICKY restart. Guard it on the first
        // line or do not use START_STICKY. README 3.2.
        if (intent == null) {
            Log.i(TAG, "restarted with a null Intent; nothing to do");
            stopSelf(startId);              // stopSelf(startId), not stopSelf()
            return START_NOT_STICKY;
        }
        return START_NOT_STICKY;
    }

    // -----------------------------------------------------------------------
    // FIX 3 -- THE CALLER CHECK, PER METHOD, INSIDE THE TRANSACTION.
    //
    // This is the ONLY place Binder.getCallingUid() means anything. It runs on
    // a Binder pool thread while the caller's transaction is in flight, and the
    // uid it returns was stamped by the kernel and cannot be forged --
    // demonstrated in 25-Binder, where three separate attempts to write a
    // chosen sender_euid all failed.
    //
    // MEASURED with the check removed:
    //     CH28VAULT: getAuthToken() called by uid=10291 pid=19831
    // The service sees the true attacker uid. With the check present, that call
    // throws SecurityException before reaching the token.
    // -----------------------------------------------------------------------
    private final IVaultService.Stub binder = new IVaultService.Stub() {

        @Override
        public String getAuthToken() {
            enforceSameSignature();
            return prefs.getString("access_token", null);
        }

        @Override
        public void setSyncEndpoint(String url) {
            enforceSameSignature();

            // FIX 4 -- validate, then persist the CANONICAL form, never the
            // string the caller sent.
            String safe = canonicaliseEndpoint(url);
            prefs.edit().putString("endpoint", safe).apply();
        }

        @Override
        public boolean isUnlocked() {
            // Even the harmless method gets the check. Not because this one
            // leaks anything, but because "which methods are safe" is a
            // judgement that goes stale the moment somebody adds a fourth
            // method and copies the third as a template.
            enforceSameSignature();
            return true;
        }
    };

    /**
     * FIX 3, the check itself.
     *
     * Four rules, in order of how often each is got wrong:
     *
     *  1. Use Binder.getCallingUid(), NOT a package name from an Intent extra
     *     and NOT getCallingPackage(). The uid is what the kernel
     *     authenticated. A package name is a claim the caller made.
     *
     *  2. Compare SIGNATURES, not a hard-coded uid. App uids are assigned at
     *     install time and are not stable across devices, reinstalls, or
     *     factory resets.
     *
     *  3. Handle sharedUserId. Several packages can share one uid, so the uid
     *     is the right granularity and getPackagesForUid() may return more than
     *     one name. See 21-App-Sandbox section 5.2.
     *
     *  4. Do NOT wrap this in clearCallingIdentity(). That clears the very
     *     thing you are about to read. If privileged work is needed afterwards,
     *     capture the uid FIRST, then clear, then restore in a finally.
     *     25-Binder section 3.12.
     */
    private void enforceSameSignature() {
        final int uid = Binder.getCallingUid();

        // Ourselves, or anything sharing our uid.
        if (uid == Process.myUid()) return;

        // The platform is allowed. Decide this deliberately rather than by
        // accident: if the system should NOT be able to call you, delete it.
        if (uid == Process.SYSTEM_UID) return;

        PackageManager pm = getPackageManager();
        if (pm.checkSignatures(Process.myUid(), uid) != PackageManager.SIGNATURE_MATCH) {
            // Log enough to investigate, and nothing the caller can use.
            Log.w(TAG, "refused call from uid " + uid);
            throw new SecurityException(
                    "caller uid " + uid + " is not signed with our key");
        }
    }

    /**
     * FIX 4 -- input validation for the one write method.
     *
     * The vulnerable version stored whatever string arrived. An AIDL argument
     * is external input in exactly the sense MASVS-CODE-4 means: it crossed a
     * process boundary and the sender is not you.
     *
     * Reject rather than sanitise. A URL that is nearly right is not a URL that
     * should be silently corrected -- "https://sync.example.com.evil.test/" and
     * "https://sync.example.com@evil.test/" both look plausible to a substring
     * check and neither is your server.
     */
    private static String canonicaliseEndpoint(String url) {
        if (TextUtils.isEmpty(url)) {
            throw new IllegalArgumentException("endpoint must not be empty");
        }
        Uri u = Uri.parse(url);
        if (!"https".equals(u.getScheme())) {
            throw new IllegalArgumentException("endpoint must be https");
        }
        String host = u.getHost();
        if (host == null) {
            throw new IllegalArgumentException("endpoint has no host");
        }
        host = host.toLowerCase(Locale.ROOT);
        // Exact match against an allow-list. Not endsWith(), not contains().
        if (!ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("host not permitted: " + host);
        }
        if (u.getUserInfo() != null) {
            throw new IllegalArgumentException("userinfo not permitted");
        }
        // Rebuild from validated parts rather than trusting the input string.
        return "https://" + host + (u.getPort() == -1 ? "" : ":" + u.getPort()) + "/";
    }

    // -----------------------------------------------------------------------
    // WHAT IS DELIBERATELY *NOT* HERE, AND WHY
    //
    //  - No caller check in onStartCommand. There is no authenticated caller
    //    identity available there at all. If a started service must know who
    //    started it, take a PendingIntent from the caller -- its creator
    //    identity IS authenticated by the framework. See 26-Intent.
    //
    //  - No rate limiting. It would need shared mutable state, and this
    //    interface is dispatched concurrently on the Binder thread pool
    //    (README 3.5.1). A naive counter here would be racy. If you need one,
    //    synchronise it properly or use a Messenger, which serialises.
    //
    //  - No obfuscation of the interface. It would not help: the descriptor
    //    string and the transaction codes are the wire format and survive R8
    //    by necessity. README 6.6.
    // -----------------------------------------------------------------------
}
