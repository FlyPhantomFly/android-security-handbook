/*
 * =============================================================================
 * FirstApp.java - the smallest Android Activity worth reverse engineering
 * =============================================================================
 *
 * WHAT THIS IS
 *   A minimal Android Activity containing exactly the four constructs you will
 *   spend the next year looking for in other people's applications:
 *
 *     1. an entry point            -> onCreate()
 *     2. a hardcoded string        -> API_KEY
 *     3. a client-side decision    -> isPremiumUser()
 *     4. a log statement           -> Log.d(...)
 *
 *   Everything else has been removed. There is no build system, no layout XML,
 *   and no dependency on a library, because the point is not to run it - it is
 *   to have a known-good original to compare against decompiler output.
 *
 * HOW TO USE IT
 *   Read it once now. Then, after Lab 02, come back and compare it against what
 *   jadx produced for a real app. The value of this file is as a Rosetta stone:
 *   you already know what the source said, so you can learn to read what the
 *   decompiler says.
 *
 *   To actually build it, drop the class into an Android Studio project's
 *   app/src/main/java/com/example/firstapp/ directory, declare the activity in
 *   AndroidManifest.xml, and build. That is covered in ../../08-Build-System/.
 *
 * REQUIREMENTS
 *   Android SDK, API 21+ (minSdk 21 is enough for everything used here).
 *
 * SEE ALSO
 *   ../labs/lab-02-first-60-minutes.md   - pulling and opening an APK
 *   ../../12-DEX-Internals/README.md     - what this becomes as bytecode
 *   ../../30-Activities/README.md        - the Activity lifecycle in full
 *   ../../40-Obfuscation/README.md       - what R8 does to these names
 * =============================================================================
 */

package com.example.firstapp;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

/**
 * A single-screen application.
 *
 * An Activity is one screen with a user interface. Android does not call a
 * main() function the way a desktop program has one; instead the system creates
 * your Activity object and then calls lifecycle methods on it. Your code is a
 * set of callbacks, not a program with a beginning and an end. That inversion
 * of control is the single most important structural fact about Android apps,
 * and it is why "where does execution start?" has a manifest-shaped answer
 * rather than a source-shaped one.
 */
public class FirstApp extends Activity {

    /*
     * -------------------------------------------------------------------------
     * CONSTRUCT 1 OF 4 - the hardcoded string constant
     * -------------------------------------------------------------------------
     *
     * TAG is benign: it is a label used when writing to the system log. It is
     * here because it is the most common String constant in Android code and
     * you need to recognise it instantly so you can ignore it.
     *
     * API_KEY is the interesting one, and it is deliberately wrong. A secret
     * compiled into an application that ships to users is not a secret; it is a
     * published value with extra steps. Anyone who can install the app can read
     * it, because the app itself must be able to read it in order to use it.
     * There is no version of this that works: not obfuscation, not string
     * encryption, not hiding it in a native library, not fetching it at
     * runtime and caching it. Each of those raises the cost of extraction from
     * "seconds" to "an afternoon" and no further.
     *
     * 'static final' on a String with a compile-time constant value means the
     * Java compiler INLINES it. Every place API_KEY is used, the literal bytes
     * are copied into that place. The field still exists, but removing the
     * field would not remove the value. This matters when you are searching a
     * DEX file: you will often find the string in the string pool with several
     * references, rather than one clean field access.
     */
    private static final String TAG = "FirstApp";
    private static final String API_KEY = "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch00";

    /*
     * A non-final instance field. Unlike API_KEY above, this is a real field
     * read at runtime, so hooking or patching the field genuinely changes
     * behaviour. The distinction between "inlined constant" and "field read at
     * runtime" decides which attack works, and beginners routinely try to hook
     * a value that the compiler removed before the APK was built.
     */
    private boolean premiumUnlocked = false;

    /*
     * -------------------------------------------------------------------------
     * CONSTRUCT 2 OF 4 - the entry point
     * -------------------------------------------------------------------------
     *
     * onCreate() is called once when the system instantiates this Activity. It
     * is the first of your code that runs in this screen's life, which makes it
     * the first place you look in a decompiled app and the first place you hook
     * when instrumenting one.
     *
     * The 'Bundle savedInstanceState' parameter carries state the system saved
     * when it previously destroyed this Activity to reclaim memory. It is null
     * on a genuinely fresh start. It is also attacker-relevant: a Bundle that
     * survives a process death carries whatever the developer put in it.
     *
     * '@Override' is an annotation asserting that this method replaces one
     * declared in the superclass. If it does not, the compiler errors. It has
     * no runtime effect and does not appear in the compiled output.
     *
     * 'super.onCreate(savedInstanceState)' calls Activity's implementation
     * first. Omitting it throws SuperNotCalledException at runtime, because the
     * framework tracks whether you called up the chain. This is a real
     * constraint enforced by the platform, not a style convention.
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // A TextView built in code rather than inflated from a layout XML, so
        // this file has no external dependency. Real apps overwhelmingly use
        // setContentView(R.layout.something), and R.layout.something is an
        // integer resource ID that resolves through resources.arsc - which is
        // why a decompiled app shows setContentView(2131427356) rather than a
        // readable name until the resource table is decoded.
        TextView view = new TextView(this);

        /*
         * ---------------------------------------------------------------------
         * CONSTRUCT 3 OF 4 - the client-side decision
         * ---------------------------------------------------------------------
         *
         * This is the shape of the bug that pays for most mobile pentesters'
         * mortgages. A decision with real consequences - what the user is
         * allowed to do - is being made by code running on hardware the user
         * fully controls. Everything below the 'if' is reachable by anyone who
         * can flip that boolean, and flipping it is a single Smali edit or a
         * two-line Frida hook.
         *
         * The correct design is that the SERVER decides. The client may show or
         * hide a button for a nicer experience, but the server must refuse to
         * serve premium content to a non-premium account. When you find this
         * pattern in a real app, the finding is not "isPremiumUser can be
         * hooked" - hooking always works. The finding is "the server honours a
         * client-side entitlement decision", which you prove by flipping the
         * check and observing that the backend still returns the data.
         */
        if (isPremiumUser()) {
            view.setText("Welcome, premium user.");
            Log.d(TAG, "Premium path taken");
        } else {
            view.setText("Upgrade to unlock premium features.");
            Log.d(TAG, "Free path taken");
        }

        /*
         * ---------------------------------------------------------------------
         * CONSTRUCT 4 OF 4 - the log statement
         * ---------------------------------------------------------------------
         *
         * Log.d writes to logcat, the system-wide ring buffer. Since Android
         * 4.1 an ordinary app cannot read other apps' log output, but the
         * 'shell' user reached over adb can read everything, and so can anyone
         * with physical access and USB debugging enabled.
         *
         * This particular line is a deliberate mistake, and an extremely common
         * one in production applications: it writes a secret into the log. The
         * developer's reasoning is always "it's only a debug build" - and then
         * the log call ships, because the ProGuard rule that was supposed to
         * strip Log.d in release was never added, or was added and then broken
         * by a build refactor nobody noticed.
         *
         * When you assess an app, run 'adb logcat' while you exercise every
         * screen, and grep the capture for tokens, keys, session identifiers,
         * personal data, and full request bodies. It is unglamorous and it
         * finds real issues on a large fraction of engagements.
         */
        Log.d(TAG, "Initialising with key: " + API_KEY);

        setContentView(view);
    }

    /**
     * The check itself.
     *
     * Note how small the attack surface is. Three lines, one field read, one
     * comparison, one return. Everything an attacker needs to defeat this is
     * visible in the method signature: it takes nothing, it returns a boolean,
     * and therefore forcing the return value to true defeats it completely
     * regardless of what the body does. A method that consults a server and
     * returns a boolean is defeated exactly as easily as one that returns a
     * constant, which is why "make the check harder" is never the fix.
     *
     * 'equals' rather than '==' on the Strings is deliberate: '==' compares
     * object references, not contents, and would compare the identity of two
     * String objects rather than their characters. It happens to appear to work
     * for compile-time literals because the compiler interns them into a shared
     * pool. This is the single most common correctness bug in beginner Java,
     * and it has produced real authentication bypasses in shipped code.
     */
    private boolean isPremiumUser() {
        // A field read - this one is genuinely hookable at runtime.
        if (premiumUnlocked) {
            return true;
        }
        // A comparison against a stored value. In a real app this would be a
        // value read from SharedPreferences, a JWT claim, or a response field.
        String storedTier = loadTierFromStorage();
        return "premium".equals(storedTier);
    }

    /**
     * Stands in for whatever the app really does: read SharedPreferences, parse
     * a token, query a database, or call an API. The exact mechanism does not
     * change the analysis, because every one of them ends in a value the device
     * owner controls.
     */
    private String loadTierFromStorage() {
        return getSharedPreferences("app_prefs", MODE_PRIVATE)
                .getString("tier", "free");
    }
}

/*
 * =============================================================================
 * WHAT THIS LOOKS LIKE LATER - a preview, not a lesson
 * =============================================================================
 *
 * You are not expected to understand the following yet. Read it now so that
 * when you meet it in chapters 12, 40, 56 and 68 it is familiar rather than
 * frightening, and so you can see that the mapping is mechanical.
 *
 * -----------------------------------------------------------------------------
 * 1. IN JADX (decompiled Java)
 * -----------------------------------------------------------------------------
 * On an UNOBFUSCATED build, jadx output is nearly identical to what you read
 * above. Comments and local variable names are gone - neither survives
 * compilation - so parameters become p0, p1 or v0, v1, and setContentView takes
 * a numeric resource ID:
 *
 *     public class FirstApp extends Activity {
 *         private boolean premiumUnlocked = false;
 *
 *         protected void onCreate(Bundle bundle) {
 *             super.onCreate(bundle);
 *             TextView textView = new TextView(this);
 *             if (isPremiumUser()) {
 *                 textView.setText("Welcome, premium user.");
 *                 Log.d("FirstApp", "Premium path taken");
 *             } else {
 *                 ...
 *             }
 *             Log.d("FirstApp", "Initialising with key: sk_live_EXAMPLE_NOT_A_REAL_KEY_ch00");
 *             setContentView(textView);
 *         }
 *     }
 *
 * Look at that last Log.d line closely. TAG and API_KEY were 'static final'
 * String constants, so javac INLINED them. The field declarations may still
 * exist, but the literal appears at every use site. This is why grepping a DEX
 * for a suspected key often finds it several times, and why deleting a constant
 * field does not remove its value from the binary.
 *
 * After R8 with obfuscation enabled (see ../../42-R8/README.md), the same class
 * arrives as something like:
 *
 *     public class a extends Activity {
 *         private boolean a = false;
 *         protected void onCreate(Bundle bundle) { ... }
 *         private boolean a() { ... }
 *     }
 *
 * Note what did NOT change: 'onCreate' keeps its name, because it overrides a
 * framework method and renaming it would break the platform's ability to call
 * it. Framework entry points are always your anchor in an obfuscated app. The
 * string literals also survive unless a separate string-encryption pass was
 * applied, so the API key is still readable.
 *
 * -----------------------------------------------------------------------------
 * 2. IN SMALI (the human-readable form of DEX bytecode)
 * -----------------------------------------------------------------------------
 * apktool produces this. It is what you edit when you patch an app, because
 * unlike jadx's Java it can be reassembled.
 *
 *     .method private isPremiumUser()Z
 *         .registers 3
 *
 *         # read this.premiumUnlocked into register v0
 *         iget-boolean v0, p0, Lcom/example/firstapp/FirstApp;->premiumUnlocked:Z
 *
 *         # if v0 == 0, jump to the label :cond_0
 *         if-eqz v0, :cond_0
 *
 *         # otherwise return true
 *         const/4 v0, 0x1
 *         return v0
 *
 *         :cond_0
 *         invoke-direct {p0}, Lcom/example/firstapp/FirstApp;->loadTierFromStorage()Ljava/lang/String;
 *         move-result-object v1
 *         const-string v2, "premium"
 *         invoke-virtual {v2, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
 *         move-result v0
 *         return v0
 *     .end method
 *
 * Things to notice, because each is a general rule rather than a detail of this
 * example:
 *
 *   * 'Z' means boolean. DEX type descriptors are single letters for primitives
 *     (V void, Z boolean, B byte, S short, C char, I int, J long, F float,
 *     D double) and 'L<fully/qualified/Name>;' for objects. '[' prefixes an
 *     array. You will read these fluently within a week.
 *   * 'p0' is the first parameter register, and in an instance method p0 is
 *     always 'this'. 'v0', 'v1' are local registers. DEX is register-based, not
 *     stack-based like JVM bytecode - this is chapter 12's subject.
 *   * Method calls are 'invoke-*' and the result is not on a stack: you must
 *     retrieve it with 'move-result' or 'move-result-object' immediately after.
 *   * The whole method can be defeated by replacing its body with two
 *     instructions:
 *
 *         const/4 v0, 0x1
 *         return v0
 *
 *     That is a patch you can write by hand in a text editor in ten seconds.
 *     It is also why client-side entitlement checks are worthless, stated in
 *     the most concrete possible terms.
 *
 * -----------------------------------------------------------------------------
 * 3. IN FRIDA (runtime, no patching, no repackaging)
 * -----------------------------------------------------------------------------
 * Rather than editing the APK, attach to the running process and replace the
 * method's implementation:
 *
 *     // Frida REPL / -l script.js
 *     Java.perform(function () {
 *         var C = Java.use("com.example.firstapp.FirstApp");
 *         C.isPremiumUser.implementation = function () {
 *             console.log("[*] isPremiumUser() called, forcing true");
 *             return true;
 *         };
 *     });
 *
 * Same effect, no signature to break, no repackaging, and it survives an app
 * update. The trade-off is that it needs a rooted device or a repackaged app
 * with the Frida gadget embedded. Chapters 53 and 65 cover both.
 *
 * -----------------------------------------------------------------------------
 * 4. IN THE APK ON DISK
 * -----------------------------------------------------------------------------
 * Run apk-anatomy.py on the built APK and this class lives inside classes.dex,
 * in the 'dex' group. The string "sk_live_EXAMPLE_NOT_A_REAL_KEY_ch00" sits in that
 * DEX file's string pool, which is why the crudest possible attack works:
 *
 *     # host
 *     strings classes.dex | grep -i "sk_live"
 *
 * No decompiler, no runtime instrumentation, no cleverness. Try this against
 * real applications and be unpleasantly surprised by how often it works.
 * =============================================================================
 */
