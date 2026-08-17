/*
 * examples/VaultUnlockModule.java
 *
 * Chapter 63 - LSPosed.  The flagship worked example: a complete LSPosed module,
 * from entry point to hook to teardown.
 *
 * WHAT IT DOES
 *   Instruments a purpose-built lab application, com.pentest.ch63.vault, which
 *   ships with this chapter's labs.  The module demonstrates, in one file, every
 *   part of the Xposed API surface a real module actually uses:
 *
 *     1. IXposedHookLoadPackage           - the per-application entry point
 *     2. IXposedHookZygoteInit            - the once-per-Zygote entry point
 *     3. XposedHelpers.findAndHookMethod  - hooking a named method
 *     4. XC_MethodHook.beforeHookedMethod - observing and rewriting arguments
 *     5. XC_MethodHook.afterHookedMethod  - observing and rewriting the result
 *     6. param.setResult(...)             - short-circuiting the original body
 *     7. XposedBridge.hookAllMethods      - hooking every overload at once
 *     8. XposedHelpers.getObjectField     - reading private state by reflection
 *     9. XposedBridge.log                 - the module's only output channel
 *
 * ETHICS - READ THIS BEFORE YOU BUILD IT
 *   This module names exactly one package: com.pentest.ch63.vault, which YOU
 *   build from this chapter's labs.  It is a deliberately vulnerable teaching
 *   app.  Do not point this file, or anything derived from it, at software you
 *   do not own or are not explicitly authorised to test.  In particular:
 *   modules that defeat licensing, payment or anti-cheat controls in shipped
 *   third-party software are out of scope for this repository, and the OBSERVE
 *   flag below exists so that the default behaviour of this module is to watch
 *   rather than to change anything.
 *
 * BUILDING IT
 *   With the real Xposed API jar:
 *       compileOnly 'de.robv.android.xposed:api:82'
 *
 *   Offline, with no network and no Gradle, using this chapter's script:
 *       ./scripts/build-xposed-module.sh --decompile
 *   That script synthesises a minimal source-compatible stand-in for the API,
 *   compiles this file against it, converts the result to DEX with d8, and
 *   optionally decompiles it again so you can see what a module looks like to
 *   an analyst.  The stand-in is a compile-time stub only - it has no runtime
 *   behaviour and must never be packaged into the APK.  See §6 of the chapter.
 *
 * PACKAGING IT
 *   A module is an ordinary APK.  Three things make it a module:
 *     - <meta-data android:name="xposedmodule" android:value="true"/> in the
 *       manifest, alongside xposedminversion and xposeddescription;
 *     - assets/xposed_init, a plain text file naming this class;
 *     - the fact that LSPosed's manager has been told to enable it, and for
 *       which packages.
 *   See examples/AndroidManifest.xml and examples/xposed_init in this folder.
 */

package com.pentest.ch63.module;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class VaultUnlockModule implements IXposedHookLoadPackage, IXposedHookZygoteInit {

    /** The one package this module is allowed to touch. */
    private static final String TARGET = "com.pentest.ch63.vault";

    /** Prefix on every log line, so `logcat | grep CH63` finds only us. */
    private static final String TAG = "CH63";

    /**
     * OBSERVE = true  : the module logs and changes nothing.
     * OBSERVE = false : the module additionally forces the unlock decision.
     *
     * The default is deliberately the harmless one.  Chapter 65 makes the
     * argument this flag encodes: "a hook that prints an argument is worth
     * more in a report than a hook that forces a return value", because the
     * printed argument reproduces on a clean device and the forced return
     * value does not.
     */
    private static final boolean OBSERVE = true;

    // ------------------------------------------------------------------
    // Entry point 1 of 2: initZygote
    // ------------------------------------------------------------------

    /**
     * Called ONCE, in the Zygote process, before any application exists.
     *
     * What you have here:
     *   - the system class loader and every framework class Zygote preloaded;
     *   - root, in Zygote's address space, before the fork;
     *   - startupParam.modulePath, the absolute path of this module's own APK.
     *
     * What you do NOT have here:
     *   - any application's classes.  They are not loaded and their class
     *     loaders do not exist yet.  Attempting XposedHelpers.findClass on an
     *     app class here throws, and that is the single most common beginner
     *     mistake with this API.
     *   - a Context.  There is no Application object in Zygote.
     *
     * Use it for hooks on FRAMEWORK classes that must be in place before the
     * first app starts, and for reading your own module's assets.
     */
    @Override
    public void initZygote(IXposedHookZygoteInit.StartupParam startupParam) {
        XposedBridge.log(TAG + " initZygote: modulePath=" + startupParam.modulePath
                + " startsSystemServer=" + startupParam.startsSystemServer);

        // A framework-level hook, installed once, inherited by every forked
        // process.  This one only observes: it records which packages ask the
        // platform for their own signing certificates, which is the single
        // most common shape of a self-integrity check (see chapter 38).
        try {
            XposedHelpers.findAndHookMethod(
                    "android.app.ApplicationPackageManager",
                    null,                       // boot class loader
                    "getPackageInfo",
                    String.class, int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            int flags = (Integer) param.args[1];
                            // GET_SIGNATURES = 0x40, GET_SIGNING_CERTIFICATES = 0x08000000
                            if ((flags & 0x40) != 0 || (flags & 0x08000000) != 0) {
                                XposedBridge.log(TAG + " signature-query pkg=" + param.args[0]
                                        + " flags=0x" + Integer.toHexString(flags));
                            }
                        }
                    });
        } catch (Throwable t) {
            // A module MUST NOT throw out of an entry point.  An uncaught
            // Throwable here is raised inside Zygote; LSPosed catches it, but
            // the hook is silently absent afterwards and you will spend an
            // hour wondering why.  Log it instead.
            XposedBridge.log(TAG + " initZygote hook failed: " + t);
        }
    }

    // ------------------------------------------------------------------
    // Entry point 2 of 2: handleLoadPackage
    // ------------------------------------------------------------------

    /**
     * Called ONCE PER PROCESS, inside the forked application process, after
     * the process has taken the app's UID and SELinux context but before the
     * application's own code runs.
     *
     * What you have here:
     *   - lpparam.packageName   the package this process belongs to;
     *   - lpparam.processName   which may differ - see the check below;
     *   - lpparam.classLoader   the app's class loader, from which its own
     *                           classes can be resolved;
     *   - lpparam.appInfo       ApplicationInfo, including sourceDir and flags.
     *
     * What you do NOT have here:
     *   - root.  You are the app's UID now.
     *   - a Context, yet.  Application.onCreate has not run.  If you need one,
     *     hook Application.attach or Instrumentation.callApplicationOnCreate.
     */
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {

        // ---------------------------------------------------------------
        // Discipline 1: check the package name even though scope already did.
        // ---------------------------------------------------------------
        // LSPosed's per-module scope means handleLoadPackage is normally only
        // called for packages you selected.  Check anyway.  Scope is
        // configuration; this line is code, and code is what ships.  A module
        // whose behaviour depends on a checkbox somebody else ticks is a
        // module that will one day run somewhere you did not intend.
        if (!TARGET.equals(lpparam.packageName)) {
            return;
        }

        // ---------------------------------------------------------------
        // Discipline 2: know which PROCESS you are in.
        // ---------------------------------------------------------------
        // An app with android:process=":worker" components gets more than one
        // process, and handleLoadPackage fires in each.  packageName is the
        // same in all of them; processName is not.  Installing a UI hook in a
        // background process is a common way to produce a hook that installs
        // perfectly and never fires.
        XposedBridge.log(TAG + " handleLoadPackage pkg=" + lpparam.packageName
                + " process=" + lpparam.processName
                + " isFirstApplication=" + lpparam.isFirstApplication);

        hookUnlockDecision(lpparam);
        hookPinComparison(lpparam);
        hookEveryOverloadOfLog(lpparam);
    }

    // ------------------------------------------------------------------
    // Hook 1 - the decision.  before/after, and setResult.
    // ------------------------------------------------------------------

    /**
     * Target:
     *     package com.pentest.ch63.vault;
     *     public class VaultGate {
     *         public boolean isUnlocked(String pin) { ... }
     *     }
     *
     * This is the "consumer versus producer" choice chapter 65 §6.1 describes.
     * isUnlocked is the PRODUCER: hook it and every caller changes.
     */
    private void hookUnlockDecision(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                    "com.pentest.ch63.vault.VaultGate",
                    lpparam.classLoader,          // the APP's loader, not the boot loader
                    "isUnlocked",
                    String.class,                 // parameter types, in order
                    new XC_MethodHook() {

                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            // param.args is the live argument array.  Writing to
                            // it changes what the original body receives.
                            XposedBridge.log(TAG + " isUnlocked(pin=\"" + param.args[0] + "\")");

                            // param.thisObject is the receiver.  Private state is
                            // reachable through XposedHelpers without writing any
                            // reflection boilerplate yourself.
                            Object attempts = XposedHelpers.getObjectField(
                                    param.thisObject, "mFailedAttempts");
                            XposedBridge.log(TAG + "   mFailedAttempts=" + attempts);

                            if (!OBSERVE) {
                                // setResult in beforeHookedMethod SKIPS the original
                                // method body entirely.  The after-callback still
                                // runs, and param.getResult() returns what we set.
                                //
                                // This is the managed-layer equivalent of chapter
                                // 65's 8-byte "mov w0,#1 / ret" wholesale
                                // replacement: nothing calls through.
                                param.setResult(Boolean.TRUE);
                                XposedBridge.log(TAG + "   FORCED result=true (original skipped)");
                            }
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            // Runs whether or not the original body executed.
                            // getResult() is the value the caller is about to see.
                            XposedBridge.log(TAG + " isUnlocked -> " + param.getResult()
                                    + (param.hasThrowable() ? " threw " + param.getThrowable() : ""));
                        }
                    });

            XposedBridge.log(TAG + " installed hook on VaultGate.isUnlocked");

        } catch (Throwable t) {
            // NoSuchMethodError here almost always means one of three things:
            //   1. the signature is wrong (String.class vs CharSequence.class);
            //   2. the class is loaded by a different class loader (a plugin
            //      framework, a dynamic feature module, a packer);
            //   3. R8 renamed it - see chapter 42.
            XposedBridge.log(TAG + " could not hook VaultGate.isUnlocked: " + t);
        }
    }

    // ------------------------------------------------------------------
    // Hook 2 - the comparison.  Learn the secret; do not force the branch.
    // ------------------------------------------------------------------

    /**
     * Target:
     *     private boolean matches(String entered, String expected)
     *
     * A private method, and the interesting one, because the SECOND argument
     * is the correct PIN.  Reading it is worth more than flipping the boolean:
     * the PIN reproduces on a clean device with no module installed, and the
     * flipped boolean does not.  Chapter 65's CTF grades that distinction
     * Silver versus Gold and this hook is the Gold version.
     */
    private void hookPinComparison(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                    "com.pentest.ch63.vault.VaultGate",
                    lpparam.classLoader,
                    "matches",
                    String.class, String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            XposedBridge.log(TAG + " matches(entered=\"" + param.args[0]
                                    + "\", expected=\"" + param.args[1] + "\")   <-- the secret");
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + " could not hook VaultGate.matches: " + t);
        }
    }

    // ------------------------------------------------------------------
    // Hook 3 - every overload at once.
    // ------------------------------------------------------------------

    /**
     * findAndHookMethod needs the exact parameter types.  When you do not know
     * them - or when there are six overloads and you want all of them -
     * XposedBridge.hookAllMethods takes a Class and a method NAME and hooks
     * every method with that name.
     *
     * It returns a Set of Unhooks, which is how a module removes its own
     * hooks.  Keeping them is good hygiene even if you never call unhook():
     * it makes the module's blast radius explicit in the code.
     */
    private void hookEveryOverloadOfLog(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> auditor = XposedHelpers.findClass(
                    "com.pentest.ch63.vault.AuditLog", lpparam.classLoader);

            XposedBridge.hookAllMethods(auditor, "record", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    StringBuilder sb = new StringBuilder(TAG + " AuditLog.record(");
                    for (int i = 0; i < param.args.length; i++) {
                        if (i > 0) sb.append(", ");
                        sb.append(param.args[i]);
                    }
                    XposedBridge.log(sb.append(')').toString());
                }
            });

        } catch (Throwable t) {
            XposedBridge.log(TAG + " could not hook AuditLog.record: " + t);
        }
    }
}
