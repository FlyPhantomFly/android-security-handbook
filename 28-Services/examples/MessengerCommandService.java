// examples/MessengerCommandService.java
//   -> in an Android project, split into three files under
//      src/main/java/com/example/cmd/
//
// THE MESSENGER PAIR: a vulnerable command dispatcher, its fixed counterpart,
// and the attacker that beats the naive fix. Three classes in one file so the
// three can be read against each other; in a real project they would be
// separate compilation units.
//
// This is the SECOND vulnerable/fixed pair in the chapter. The first
// (VaultService-*.java) is AIDL. This one is Messenger, because the two have
// genuinely different failure modes and a tester needs to recognise both:
//
//   AIDL       concurrent, reentrant, typed, synchronous return value.
//              Classic failure: no Binder.getCallingUid() check per method.
//              Its return value goes back on the caller's own transaction and
//              CANNOT be redirected.
//
//   Messenger  serialised onto one Handler thread, asynchronous, untyped.
//              Classic failure: no msg.sendingUid check.
//              PLUS a failure AIDL does not have: msg.replyTo is a Binder
//              handle the CALLER chose, so a reply can be sent somewhere the
//              caller nominated. A correct sendingUid check does not stop it.
//
// README section 3.5 has the comparison table; 5.3.4 has the exploit.
//
// ---------------------------------------------------------------------------
// AndroidManifest.xml for the VULNERABLE version:
//
//   <service android:name=".CmdService" android:exported="true">
//       <intent-filter>
//           <action android:name="com.example.cmd.BIND"/>
//       </intent-filter>
//   </service>
//
// for the FIXED version:
//
//   <permission android:name="com.example.cmd.permission.CMD"
//               android:protectionLevel="signature"/>
//   <service android:name=".CmdServiceFixed"
//            android:exported="true"
//            android:permission="com.example.cmd.permission.CMD"/>
// ---------------------------------------------------------------------------

package com.example.cmd;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.Process;
import android.os.RemoteException;
import android.util.Log;

import java.util.HashMap;
import java.util.Map;

// ===========================================================================
// 1. VULNERABLE
// ===========================================================================
//
// Two separate defects:
//
//   [A] No authorisation at all. Every command in the switch is reachable by
//       any app that can bind, including MSG_WIPE.
//
//   [B] MSG_GET_TOKEN replies to msg.replyTo, which is a Messenger the CALLER
//       supplied. Even after [A] is fixed, a trusted-but-manipulable caller can
//       be induced to pass an attacker's Messenger through, and the token goes
//       to whoever the attacker named. This is delegated-capability leakage of
//       the same shape as a mutable PendingIntent (26-Intent).
//
class CmdService extends Service {

    static final String TAG = "CH28MSG";

    static final int MSG_SET_PIN   = 1;
    static final int MSG_WIPE      = 2;
    static final int MSG_GET_TOKEN = 3;

    private final Handler handler = new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message msg) {
            // msg.sendingUid IS populated by the framework here, from the
            // kernel-stamped Binder caller uid, in Handler$MessengerImpl.send.
            // It is simply never read.
            switch (msg.what) {

                case MSG_SET_PIN:
                    // The whole Bundle is attacker controlled if this service
                    // is exported. So is msg.what, msg.arg1, msg.arg2 and
                    // msg.obj (if Parcelable).
                    savePin(msg.getData().getString("pin"));
                    break;

                case MSG_WIPE:
                    // [A] Destructive, and reachable by anyone.
                    wipeEverything();
                    break;

                case MSG_GET_TOKEN:
                    // [A] and [B] together.
                    Bundle out = new Bundle();
                    out.putString("token", currentToken());
                    Message reply = Message.obtain(null, MSG_GET_TOKEN);
                    reply.setData(out);
                    try {
                        msg.replyTo.send(reply);      // <-- to WHOEVER was named
                    } catch (RemoteException e) {
                        Log.w(TAG, "reply failed", e);
                    }
                    break;
            }
        }
    };

    private final Messenger messenger = new Messenger(handler);

    @Override
    public IBinder onBind(Intent intent) {
        // Note what is NOT here: a caller check. Not because the author was
        // careless, but because there is nowhere useful to put one -- onBind
        // does not know who called. See VaultService-vulnerable.java, which
        // makes the mistake of trying anyway.
        return messenger.getBinder();
    }

    private void savePin(String pin) { Log.i(TAG, "savePin(" + pin + ")"); }
    private void wipeEverything()    { Log.i(TAG, "WIPED"); }
    private String currentToken()    { return "SECRET-SESSION-TOKEN"; }
}

// ===========================================================================
// 2. THE ATTACKER
// ===========================================================================
//
// Bind, then send MSG_GET_TOKEN with OUR OWN Messenger as replyTo. Runs as an
// ordinary app; the only thing needed from the target is the component name and
// the integer command values, both of which come out of a decompiled switch
// statement in seconds (README 6.2).
//
// Drop this into examples/attacker-app/ProbeActivity.java's onServiceConnected
// to run it for real.
//
class MessengerAttack {

    static final int MSG_GET_TOKEN = 3;

    static void run(Context ctx, IBinder serviceBinder) {
        Messenger target = new Messenger(serviceBinder);

        // A reply channel of OUR choosing. Nothing authenticates it.
        Messenger mine = new Messenger(new Handler(Looper.getMainLooper()) {
            @Override public void handleMessage(Message m) {
                Log.i("poc", "victim replied with token: "
                        + m.getData().getString("token"));
            }
        });

        Message m = Message.obtain(null, MSG_GET_TOKEN);
        m.replyTo = mine;
        try {
            target.send(m);
        } catch (RemoteException e) {
            Log.w("poc", "send failed", e);
        }
    }
}

// ===========================================================================
// 3. FIXED
// ===========================================================================
//
// Three changes, and the third is the one people miss.
//
class CmdServiceFixed extends Service {

    static final String TAG = "CH28MSG";

    static final int MSG_SET_PIN   = 1;
    static final int MSG_WIPE      = 2;
    static final int MSG_GET_TOKEN = 3;

    /**
     * FIX 3 support: reply channels registered through an authenticated path,
     * keyed by the uid that registered them. A caller can only ever be replied
     * to on a channel IT registered, and never on a channel it merely named in
     * a message.
     *
     * NOTE ON THREADING: a plain HashMap is correct here and would NOT be
     * correct in an AIDL service. Every access happens inside handleMessage on
     * the single Handler thread, so there is no concurrency at all. That is
     * Messenger's one genuine advantage and it is worth stating explicitly,
     * because the same code copied into an IFoo.Stub would be racy.
     * README 3.5.1.
     */
    private final Map<Integer, Messenger> replyChannels = new HashMap<Integer, Messenger>();

    private final Handler handler = new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message msg) {

            // FIX 1 -- AUTHORISE, ONCE, AT THE TOP, USING THE FRAMEWORK'S OWN
            // FIELD. msg.sendingUid was set from Binder.getCallingUid() inside
            // the send() transaction, which is the only moment it exists. It is
            // kernel-derived and unforgeable (25-Binder section 3.11).
            //
            // Do NOT call Binder.getCallingUid() here. handleMessage runs later,
            // on the looper thread, with no transaction in flight; it would
            // return this app's own uid. Same trap as onBind.
            if (!isTrusted(msg.sendingUid)) {
                Log.w(TAG, "rejecting what=" + msg.what
                         + " from uid=" + msg.sendingUid);
                return;
            }

            switch (msg.what) {

                case MSG_SET_PIN: {
                    // FIX 2 -- VALIDATE. A Bundle from another process is
                    // external input even when the sender is trusted.
                    Bundle data = msg.getData();
                    String pin = data == null ? null : data.getString("pin");
                    if (pin == null || !pin.matches("\\d{4,8}")) {
                        Log.w(TAG, "rejecting malformed pin");
                        return;
                    }
                    savePin(pin);
                    break;
                }

                case MSG_WIPE:
                    wipeEverything();
                    break;

                case MSG_GET_TOKEN: {
                    // FIX 3 -- DO NOT REPLY TO msg.replyTo.
                    //
                    // This is the fix that survives the attack in
                    // MessengerAttack above even when FIX 1 is present, because
                    // FIX 1 only proves WHO SENT the message. It says nothing
                    // about who the message told you to answer.
                    Messenger channel = replyChannels.get(msg.sendingUid);
                    if (channel == null) {
                        Log.w(TAG, "uid " + msg.sendingUid
                                 + " has no registered reply channel");
                        return;
                    }
                    Bundle out = new Bundle();
                    out.putString("token", currentToken());
                    Message reply = Message.obtain(null, MSG_GET_TOKEN);
                    reply.setData(out);
                    try {
                        channel.send(reply);
                    } catch (RemoteException e) {
                        replyChannels.remove(msg.sendingUid);   // dead client
                    }
                    break;
                }

                case MSG_REGISTER_REPLY:
                    // Registration is the ONE place a caller-supplied Messenger
                    // is accepted, and it is bound to the authenticated uid of
                    // the app that supplied it. A caller can still nominate a
                    // channel belonging to someone else -- but only ever for
                    // ITS OWN replies, which is not a leak.
                    if (msg.replyTo != null) {
                        replyChannels.put(msg.sendingUid, msg.replyTo);
                    }
                    break;
            }
        }
    };

    static final int MSG_REGISTER_REPLY = 100;

    private final Messenger messenger = new Messenger(handler);

    @Override
    public IBinder onBind(Intent intent) {
        return messenger.getBinder();
    }

    /**
     * Same rules as VaultService-fixed.java's enforceSameSignature: compare
     * signatures, not hard-coded uids; handle sharedUserId by working at uid
     * granularity; never trust a package name that arrived in a Bundle.
     */
    private boolean isTrusted(int uid) {
        if (uid == Process.myUid()) return true;
        return getPackageManager().checkSignatures(Process.myUid(), uid)
                == PackageManager.SIGNATURE_MATCH;
    }

    private void savePin(String pin) { Log.i(TAG, "savePin(ok)"); }
    private void wipeEverything()    { Log.i(TAG, "WIPED"); }
    private String currentToken()    { return "SECRET-SESSION-TOKEN"; }

    // -----------------------------------------------------------------------
    // AN HONEST NOTE ON WHICH IS BETTER
    //
    // If this interface needed a synchronous return value, AIDL would be the
    // better choice and FIX 3 would not exist as a problem: an AIDL method's
    // return value travels back on the caller's own transaction and there is
    // no reply channel to redirect. Messenger's asynchrony is what creates the
    // replyTo hazard in the first place.
    //
    // Conversely, if this interface keeps mutable state and does NOT need
    // return values, Messenger's serialisation is a real safety property you
    // would otherwise have to implement with locks. Pick on those grounds, not
    // on which one the tutorial you read used. README 3.5.
    // -----------------------------------------------------------------------
}
