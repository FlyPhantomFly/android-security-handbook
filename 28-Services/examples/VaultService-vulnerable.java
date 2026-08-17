// examples/VaultService-vulnerable.java
//   -> in an Android project this lives at
//      src/main/java/com/example/notesvault/VaultService.java
//
// THE VULNERABLE HALF OF THE PAIR. Its fixed counterpart is
// VaultService-fixed.java, which implements the SAME IVaultService.aidl.
//
// This is not a contrived example. It was compiled, installed on a physical
// Redmi M2101K6P running Android 11 / API 30, and attacked from an ordinary
// third-party app (examples/attacker-app/). The measured result is in
// examples/measured-bind-probe.txt. The attacker needed no permissions, no
// root, no AIDL file and no knowledge of this code -- only the component name.
//
// It carries FOUR separate defects, and they are numbered in the comments:
//
//   [1] exported="true" with no android:permission        -- manifest, below
//   [2] a caller check written in onBind(), which cannot work  -- README 3.7
//   [3] no caller check in any AIDL method                 -- README 5.3.1
//   [4] unvalidated input written to persistent state      -- README 5.3.1
//
// BUILD AND INSTALL (the exact commands used to measure this):
//
//   SDK=$HOME/Android/Sdk ; BT=$SDK/build-tools/35.0.1
//   AJ=$SDK/platforms/android-35/android.jar
//   mkdir -p gen classes
//   aidl --lang=java -Isrc -ogen src/com/example/notesvault/IVaultService.aidl
//   javac -source 8 -target 8 -bootclasspath $AJ -d classes \
//         src/com/example/notesvault/VaultService.java \
//         gen/com/example/notesvault/IVaultService.java
//   jar cf classes.jar -C classes .
//   $BT/d8 --lib $AJ --min-api 21 --output . classes.jar
//   $BT/aapt2 link -I $AJ --manifest AndroidManifest.xml -o unsigned.apk
//   # add classes.dex to unsigned.apk (any zip tool), then:
//   $BT/apksigner sign --ks debug.ks --out vault.apk unsigned.apk
//   adb install -r vault.apk
//
// NOTE ON d8: build-tools 34.0.0's d8 failed on the anonymous inner class with
//   "NullPointerException: Cannot invoke String.length() because <parameter1>
//    is null"
// against class files produced by JDK 24 with -source 8 -target 8. 35.0.1's d8
// compiled the identical input without complaint. If you hit that error, update
// build-tools before you rewrite your code.
//
// ---------------------------------------------------------------------------
// AndroidManifest.xml -- defect [1] is here, and it is one attribute.
//
// <service
//     android:name=".VaultService"
//     android:exported="true">                <!-- [1] no android:permission -->
//     <intent-filter>
//         <action android:name="com.example.notesvault.BIND_VAULT"/>
//     </intent-filter>
// </service>
//
// Note also that with an <intent-filter> present, REMOVING android:exported
// would not help: the default becomes true. From API 31 the attribute is
// mandatory when a filter exists, which at least forces the developer to type
// the word.
// ---------------------------------------------------------------------------

package com.example.notesvault;

import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.IBinder;
import android.os.Process;
import android.util.Log;

public class VaultService extends Service {

    static final String TAG = "CH28VAULT";

    private SharedPreferences prefs;

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = getSharedPreferences("vault", MODE_PRIVATE);
        // Seeded here only so the demonstration has something to steal.
        if (!prefs.contains("access_token")) {
            prefs.edit()
                 .putString("access_token", "eyJhbGciOiJIUzI1NiJ9.SECRET-SESSION-TOKEN")
                 .putString("endpoint", "https://sync.example.com")
                 .apply();
        }
        Log.i(TAG, "onCreate  callingUid=" + Binder.getCallingUid()
                 + "  myUid=" + Process.myUid());
    }

    // -----------------------------------------------------------------------
    // DEFECT [2]: A CALLER CHECK IN onBind() CHECKS THE APP AGAINST ITSELF.
    //
    // This reads perfectly in English -- "only let our own uid bind" -- and it
    // is completely inert. onBind is dispatched by ActivityThread on the app's
    // MAIN thread in response to a message from system_server. There is no
    // client transaction in flight, so Binder.getCallingUid() falls back to
    // Process.myUid() and the condition is always false.
    //
    // MEASURED. With an attacker at uid 10291 binding this service at uid
    // 10310, the log line below printed:
    //
    //     CH28VAULT: onBind intent=Intent { cmp=com.example.notesvault/.VaultService }
    //                callingUid=10310
    //
    // 10310 is this service's own uid. The same applies to onCreate,
    // onStartCommand, onUnbind, onRebind and onDestroy: NONE of the Service
    // lifecycle callbacks run inside the caller's transaction. README 3.7.
    // -----------------------------------------------------------------------
    @Override
    public IBinder onBind(Intent intent) {
        Log.i(TAG, "onBind intent=" + intent
                 + " callingUid=" + Binder.getCallingUid());

        if (Binder.getCallingUid() != Process.myUid()) {
            Log.w(TAG, "refusing bind from a foreign uid");   // never reached
            return null;
        }
        return binder;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Same trap as onBind. Also note that `intent` is null on a
        // START_STICKY restart, so any dereference here is a latent crash that
        // only fires after a low-memory kill. README 3.2.
        Log.i(TAG, "onStartCommand startId=" + startId + " flags=" + flags
                 + " intent=" + intent
                 + " callingUid=" + Binder.getCallingUid());
        return START_STICKY;
    }

    // -----------------------------------------------------------------------
    // DEFECTS [3] and [4]: the actual remote API.
    //
    // This anonymous inner class is the object an attacker talks to. In a
    // decompiled APK it appears as VaultService$1 -- which is where the
    // measured Frida trace shows transactions landing, NOT on VaultService.
    //
    // Every method here runs on a Binder thread pool thread, inside the
    // caller's transaction. Binder.getCallingUid() IS meaningful here. Nothing
    // calls it.
    // -----------------------------------------------------------------------
    private final IVaultService.Stub binder = new IVaultService.Stub() {

        // [3] Transaction code 1. Returns the session token to anyone.
        //
        // MEASURED: called from uid 10291 with nothing but a component name and
        // the interface descriptor, which the binder handed over on request:
        //
        //     CH28VAULT: getAuthToken() called by uid=10291 pid=19831
        //     CH28    : TOKEN-TX code=1 ok=true replyBytes=92 exception=(none)
        //               string='eyJhbGciOiJIUzI1NiJ9.SECRET-SESSION-TOKEN'
        @Override
        public String getAuthToken() {
            Log.i(TAG, "getAuthToken() called by uid=" + Binder.getCallingUid()
                     + " pid=" + Binder.getCallingPid());
            return prefs.getString("access_token", null);
        }

        // [4] Transaction code 2. A WRITE primitive with no authorisation and
        // no validation. An attacker points the victim's own sync traffic at a
        // server of their choosing, and the victim app keeps working, so
        // nothing looks wrong to the user. Persistent man-in-the-middle from an
        // app that asked for no permissions.
        @Override
        public void setSyncEndpoint(String url) {
            Log.i(TAG, "setSyncEndpoint(" + url + ") by uid="
                     + Binder.getCallingUid());
            prefs.edit().putString("endpoint", url).apply();
        }

        // Transaction code 3. Harmless in isolation -- and worth keeping in the
        // example precisely BECAUSE it is harmless. Not every reachable method
        // is a finding, and a report that grades this the same as getAuthToken
        // is a report that will be discounted. README 5.7.
        @Override
        public boolean isUnlocked() {
            Log.i(TAG, "isUnlocked() by uid=" + Binder.getCallingUid());
            return true;
        }
    };

    // -----------------------------------------------------------------------
    // A FIFTH PROBLEM THAT IS NOT A DEFECT SO MUCH AS A DESIGN HAZARD.
    //
    // These methods are dispatched CONCURRENTLY. Two clients, or one client
    // with two threads, run them at the same time on different Binder pool
    // threads. `prefs` is thread-safe; a HashMap would not have been. If this
    // service kept a nonce store, a rate limiter, or an "authorised" flag in a
    // plain field, it would be racy -- and no static reading that assumes one
    // caller would ever notice. README 3.5.1.
    // -----------------------------------------------------------------------
}
