/*
 * RootBeerUsage.java
 * ===========================================================================
 * WHAT THIS IS
 *   A worked example of the third-party library you will meet more often than
 *   any other in this area: RootBeer (com.scottyab.rootbeer).
 *
 *   It shows three things, in this order:
 *     1. How a developer actually integrates it — including the two mistakes
 *        almost every integration makes.
 *     2. What the integration looks like to you, the tester, in the APK.
 *     3. The complete bypass, and why the native half needs separate treatment.
 *
 * WHY IT MATTERS
 *   If you test ten Android apps with root detection you will meet RootBeer in
 *   several of them. Recognising it on sight, knowing exactly which methods it
 *   exposes, and knowing that its native component's JNI symbol survives R8,
 *   turns a forty-minute investigation into a two-minute one.
 *
 *   For the developer's half: RootBeer is a perfectly reasonable library used
 *   badly. Its own documentation is admirably honest that it will not stop a
 *   determined attacker and is intended to raise the bar. The failure is not
 *   the library; it is integrations that treat its boolean as truth.
 *
 * DEPENDENCY
 *   // app/build.gradle
 *   dependencies {
 *       implementation 'com.scottyab:rootbeer-lib:0.1.0'
 *   }
 *
 *   That single line pulls in both the Java classes and librootbeer.so, which
 *   is why `unzip -l app.apk | grep -i rootbeer` is a conclusive one-command
 *   test for its presence.
 *
 * HOW TO RUN THE TESTER'S SIDE
 *   # host — is it there?
 *   unzip -l app.apk | grep -i rootbeer
 *   grep -rn "scottyab\|rootbeer\|RootBeer" out/sources/ | head
 *
 *   # host — the complete bypass
 *   frida -U -f com.example.app -l rootbeer-bypass.js --no-pause
 *
 * AUTHORISATION
 *   Educational reference for chapter 37 section 3.13.
 * ===========================================================================
 */

package com.example.integrity;

import android.content.Context;
import android.util.Log;

import com.scottyab.rootbeer.RootBeer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

public final class RootBeerUsage {

    private static final String TAG = "Integrity";

    // =======================================================================
    // PART 1 — how it is usually integrated, and why that is wrong
    // =======================================================================

    /**
     * The integration you will find in the wild, in one form or another, in a
     * large fraction of apps that use this library.
     *
     * Four separate problems:
     *
     *   1. ONE BOOLEAN. isRooted() collapses thirteen distinct signals into a
     *      single value. Frida replaces this method in one line and every one
     *      of those signals becomes decoration. RootBeer's own README says as
     *      much.
     *
     *   2. LOCAL CONSEQUENCE. The caller acts on the result in the app. The
     *      consequence — finish(), a dialog, System.exit() — is itself one
     *      hook away, so an attacker need not even touch the detection.
     *
     *   3. IT DESTROYS THE SIGNAL. Blocking the user means you never learn
     *      what they would have done. A fraud model wants that behaviour data
     *      far more than it wants a block.
     *
     *   4. IT IS LOGGED. See the Log.w call. Chapter section 11 lists this as
     *      a developer mistake for a concrete reason: `adb logcat` now hands
     *      the attacker a map of exactly which control fired.
     *
     * Do not ship this. It is here so you can recognise it.
     */
    public static boolean theCommonMistake(Context ctx) {
        RootBeer rootBeer = new RootBeer(ctx);
        boolean rooted = rootBeer.isRooted();
        if (rooted) {
            Log.w(TAG, "Device is rooted - blocking");   // free intelligence
        }
        return rooted;
    }

    // =======================================================================
    // PART 2 — the best available integration
    // =======================================================================

    /**
     * The same library, used the way it should be.
     *
     * The differences that matter:
     *   - Every check is called INDIVIDUALLY, so the server receives thirteen
     *     data points rather than one bit. That is what makes the data useful
     *     to a risk model, and it means an attacker who neutralises one method
     *     produces an inconsistent report rather than a clean one.
     *   - Nothing is decided here. The caller attaches this to a request.
     *   - Nothing is logged.
     *   - The BusyBox check is separated out, because BusyBox on its own is a
     *     weak signal that produces false positives on some vendor ROMs and
     *     developer devices.
     *
     * What it still cannot do: survive a hook on this very method. That is not
     * a flaw in the integration, it is the trust boundary. See the assessment
     * at the bottom of this file.
     */
    public static JSONObject collectEvidence(Context ctx) throws JSONException {
        RootBeer rootBeer = new RootBeer(ctx);

        // Disable the library's own logging in release builds — see mistake 4.
        rootBeer.setLogging(false);

        Map<String, Boolean> checks = new LinkedHashMap<>();

        // --- filesystem — chapter section 3.1 -----------------------------
        checks.put("suBinary",            rootBeer.checkForSuBinary());
        checks.put("busyBoxBinary",       rootBeer.checkForBusyBoxBinary());
        checks.put("magiskBinary",        rootBeer.checkForMagiskBinary());

        // --- packages — chapter section 3.4 -------------------------------
        // These require a <queries> element on API 30+ or they silently
        // return false. See the manifest note below.
        checks.put("rootManagementApps",  rootBeer.detectRootManagementApps());
        checks.put("dangerousApps",       rootBeer.detectPotentiallyDangerousApps());
        checks.put("rootCloakingApps",    rootBeer.detectRootCloakingApps());

        // --- properties — chapter section 3.7 -----------------------------
        checks.put("dangerousProps",      rootBeer.checkForDangerousProps());
        checks.put("testKeys",            rootBeer.detectTestKeys());

        // --- mounts / writability — chapter sections 3.6 and 3.8 ----------
        checks.put("rwPaths",             rootBeer.checkForRWPaths());

        // --- subprocess — chapter section 3.2 -----------------------------
        checks.put("suExists",            rootBeer.checkSuExists());

        // --- the native one — chapter section 3.12 ------------------------
        // This is the check that survives a Java-only bypass, and the only
        // one in the library that costs an attacker more than seconds.
        checks.put("nativeCheck",         rootBeer.checkForRootNative());

        JSONArray signals = new JSONArray();
        int fired = 0;
        for (Map.Entry<String, Boolean> e : checks.entrySet()) {
            if (!e.getValue()) continue;
            fired++;
            signals.put(e.getKey());
        }

        JSONObject o = new JSONObject();
        o.put("library", "rootbeer");
        o.put("signals", signals);
        o.put("signalCount", fired);
        o.put("totalChecks", checks.size());
        o.put("collectedAt", System.currentTimeMillis());

        // Deliberately NOT a boolean, and deliberately NOT named "isRooted".
        // The server decides what this means.
        return o;
    }

    /**
     * How the caller should use the above.
     *
     *   JSONObject evidence = RootBeerUsage.collectEvidence(context);
     *   JSONObject body = buildTransferRequest();
     *   body.put("deviceEvidence", evidence);
     *
     *   // The integrity token is OPAQUE to us: we never decode it, never
     *   // branch on it. Its nonce came from our server and its requestHash
     *   // binds it to THIS request.
     *   api.transfer(body, integrityToken);
     *
     * The server then compares the two. A request whose RootBeer evidence is
     * completely clean but whose attested verdict lacks MEETS_DEVICE_INTEGRITY
     * contains a contradiction, and that contradiction is a stronger fraud
     * signal than either input on its own — because producing it required the
     * attacker to lie to the client, which the attestation caught.
     *
     * That cross-check is the only thing that makes client-side collection
     * worth doing at all. See chapter section 3.15.
     */

    // =======================================================================
    // PART 3 — the manifest requirement everyone forgets
    // =======================================================================
    //
    // RootBeer's package checks call PackageManager.getPackageInfo. On an app
    // targeting API 30 or above, package visibility filtering means those
    // calls throw NameNotFoundException for packages that ARE installed,
    // unless the package is declared in <queries>.
    //
    // Without this block, detectRootManagementApps(),
    // detectPotentiallyDangerousApps() and detectRootCloakingApps() return
    // false on every device, forever. Three of thirteen checks are dead and
    // nothing tells you.
    //
    //   <queries>
    //       <package android:name="com.topjohnwu.magisk" />
    //       <package android:name="eu.chainfire.supersu" />
    //       <package android:name="com.noshufou.android.su" />
    //       <package android:name="com.koushikdutta.superuser" />
    //       <package android:name="com.thirdparty.superuser" />
    //       <package android:name="com.yellowes.su" />
    //       <package android:name="com.devadvance.rootcloak" />
    //       <package android:name="com.devadvance.rootcloakplus" />
    //       <package android:name="de.robv.android.xposed.installer" />
    //       <package android:name="com.saurik.substrate" />
    //       <package android:name="com.dimonvideo.luckypatcher" />
    //       <package android:name="com.chelpus.lackypatch" />
    //       <package android:name="com.ramdroid.appquarantine" />
    //   </queries>
    //
    // NOTE FOR THE TESTER: this cuts both ways. An app that declares this
    // block has published, in its own manifest, the exact list of packages it
    // hunts for. `aapt2 dump xmltree app.apk --file AndroidManifest.xml |
    // grep -A40 queries` is free intelligence.
    //
    // And an app that does NOT declare it, while calling these methods, has a
    // control that has never functioned in production. That is a reportable
    // finding with a ten-minute fix.
    // =======================================================================

    // =======================================================================
    // PART 4 — what RootBeer looks like to you in the APK
    // =======================================================================
    //
    // RECOGNITION — any one of these is conclusive:
    //
    //   # host
    //   unzip -l app.apk | grep -i rootbeer          # librootbeer.so in lib/*/
    //   grep -rn "com.scottyab.rootbeer" out/sources/
    //   readelf --dyn-syms lib/arm64-v8a/librootbeer.so | grep Java_
    //   grep -rn "rootbeer" build.gradle app/build.gradle
    //
    // WHAT SURVIVES R8:
    //   - The native library FILENAME, librootbeer.so.
    //   - The JNI symbol Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot,
    //     because JNI symbols are resolved BY NAME at runtime and therefore
    //     cannot be renamed without breaking the link.
    //   - The path string constants inside the library and inside the DEX.
    //
    // WHAT DOES NOT SURVIVE:
    //   - The Java class and method names, if the app shades or repackages the
    //     library. Java.use("com.scottyab.rootbeer.RootBeer") then throws
    //     ClassNotFoundException while librootbeer.so is plainly present.
    //
    //   In that case, enumerate loaded classes and look for the method names,
    //   which shading usually preserves:
    //
    //     Java.perform(function () {
    //         Java.enumerateLoadedClasses({
    //             onMatch: function (n) {
    //                 try {
    //                     var C = Java.use(n);
    //                     if (C.isRooted !== undefined &&
    //                         C.checkForSuBinary !== undefined) {
    //                         console.log("[rootbeer, shaded as] " + n);
    //                     }
    //                 } catch (e) { }
    //             },
    //             onComplete: function () { }
    //         });
    //     });
    //
    //   Or simply hook the native symbol, which is unaffected by shading.
    //
    // THE METHOD MAP — chapter section 3.13 has the full table:
    //
    //   detectRootManagementApps()       -> packages          (3.4)
    //   detectPotentiallyDangerousApps() -> packages          (3.4)
    //   detectRootCloakingApps()         -> packages          (3.4)
    //   checkForSuBinary()               -> su path list      (3.1)
    //   checkForBusyBoxBinary()          -> busybox path list (3.1)
    //   checkForMagiskBinary()           -> magisk paths      (3.5)
    //   checkForDangerousProps()         -> ro.debuggable etc (3.7)
    //   detectTestKeys()                 -> Build.TAGS        (3.7)
    //   checkForRWPaths()                -> mount table       (3.6/3.8)
    //   checkSuExists()                  -> which su          (3.2)
    //   checkForRootNative()             -> librootbeer.so    (3.12)
    //   isRooted() / isRootedWithBusyBoxCheck() / isRootedWithoutBusyBoxCheck()
    //                                    -> aggregation points
    // =======================================================================

    // =======================================================================
    // PART 5 — the complete bypass
    // =======================================================================
    //
    // Save as rootbeer-bypass.js and run with:
    //   frida -U -f com.example.app -l rootbeer-bypass.js --no-pause
    //
    // Note the structure: Java surface first, native surface second, and the
    // native half is NOT optional. checkForRootNative() calls into
    // librootbeer.so and never touches the Java methods you just neutralised,
    // so a Java-only script leaves exactly one check standing — which is
    // enough for the app to keep detecting, while your log tells you
    // everything worked. That is the single most common way this bypass is
    // got wrong.
    //
    // 'use strict';
    //
    // var ROOTBEER_METHODS = [
    //     "isRooted", "isRootedWithBusyBoxCheck", "isRootedWithoutBusyBoxCheck",
    //     "isRootedWithEmulatorCheck",
    //     "detectRootManagementApps", "detectPotentiallyDangerousApps",
    //     "detectRootCloakingApps", "checkForSuBinary", "checkForBusyBoxBinary",
    //     "checkForMagiskBinary", "checkForDangerousProps", "checkForRWPaths",
    //     "detectTestKeys", "checkSuExists", "checkForRootNative",
    //     "checkForNativeLibraryReadAccess"
    // ];
    //
    // Java.perform(function () {
    //     // ---- Java surface ------------------------------------------------
    //     var neutralised = 0;
    //     try {
    //         var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
    //         ROOTBEER_METHODS.forEach(function (m) {
    //             if (RootBeer[m] === undefined) return;      // guard: version drift
    //             RootBeer[m].overloads.forEach(function (ov) {
    //                 ov.implementation = function () {
    //                     console.log("[rootbeer] " + m + "() -> false");
    //                     return false;
    //                 };
    //             });
    //             neutralised++;
    //         });
    //         console.log("[rootbeer] Java surface: " + neutralised + " method(s)");
    //     } catch (e) {
    //         console.log("[rootbeer] class not found (shaded or absent): " + e);
    //     }
    //
    //     // ---- Native surface ----------------------------------------------
    //     // Resolved by name, so this works even when the Java class was
    //     // renamed. If the library is not mapped yet, install from dlopen.
    //     var install = function () {
    //         var sym = Module.findExportByName(
    //             "librootbeer.so",
    //             "Java_com_scottyab_rootbeer_RootBeerNative_checkForRoot");
    //         if (sym === null) return false;
    //         Interceptor.replace(sym, new NativeCallback(function () {
    //             console.log("[rootbeer] native checkForRoot() -> 0");
    //             return 0;
    //         }, 'int', ['pointer', 'pointer', 'pointer']));
    //         console.log("[rootbeer] native surface neutralised at " + sym);
    //         return true;
    //     };
    //
    //     if (!install()) {
    //         var dl = Module.findExportByName(null, "android_dlopen_ext");
    //         if (dl !== null) {
    //             Interceptor.attach(dl, {
    //                 onEnter: function (a) {
    //                     this.p = null;
    //                     try { this.p = a[0].readUtf8String(); } catch (e) { }
    //                 },
    //                 onLeave: function () {
    //                     if (this.p && this.p.indexOf("librootbeer.so") !== -1) {
    //                         install();
    //                     }
    //                 }
    //             });
    //             console.log("[rootbeer] waiting for librootbeer.so via dlopen");
    //         }
    //     }
    // });
    //
    // WHY EACH PIECE IS THERE:
    //   - `if (RootBeer[m] === undefined) return;` guards against version
    //     drift. Methods have been added and removed across releases, and a
    //     script that throws on the first missing one leaves the rest of the
    //     library untouched.
    //   - `.overloads.forEach` rather than a direct assignment, because some
    //     methods have more than one signature and hooking the wrong one
    //     produces the "my hook never fires" symptom.
    //   - The dlopen fallback, because System.loadLibrary() runs during class
    //     initialisation of RootBeerNative, which may happen after your script
    //     loads. This is the single most common reason a native hook silently
    //     does nothing.
    //   - setLogDebugMessages / the native logging setter are left alone: they
    //     are harmless, and hooking things you do not need to hook is how you
    //     break the app and then blame the app.
    // =======================================================================

    // =======================================================================
    // ASSESSMENT
    //
    // FOR THE DEVELOPER
    //   RootBeer is a sensible library that packages the standard catalogue
    //   competently, and its native component is the only part that costs an
    //   attacker more than seconds. Use it for EVIDENCE COLLECTION, call the
    //   individual methods rather than isRooted(), declare <queries> so the
    //   package checks actually run, disable its logging in release, and send
    //   the results to your server alongside an integrity token whose nonce
    //   your server issued.
    //
    //   Do not gate on it. A library whose entire public surface is a set of
    //   well-known method names on a well-known class is, by construction, the
    //   easiest possible thing to neutralise — the bypass above is thirty
    //   lines and it is already written, on the internet, for everyone.
    //
    // FOR THE TESTER
    //   Presence of RootBeer is not a finding. What the app DOES with its
    //   result is. Check, in this order:
    //     1. Does the app act on it locally, or report it?
    //     2. Is <queries> present? If not, three checks are dead — report it.
    //     3. Is there an attestation integration alongside it? If so, that is
    //        where the real work is: replay the token, remove the token, and
    //        see whether the server notices.
    //     4. After bypassing, can you call the sensitive endpoint directly
    //        with no app at all? If yes, the root check was the only control
    //        and THAT is the finding worth writing.
    //
    // THE ONE-LINE VERSION
    //   RootBeer raises the bar. It does not build a wall, it does not claim
    //   to, and the trust boundary means it never could. Client-side detection
    //   is a speed bump; the boundary is your server.
    // =======================================================================

    private RootBeerUsage() { }
}
