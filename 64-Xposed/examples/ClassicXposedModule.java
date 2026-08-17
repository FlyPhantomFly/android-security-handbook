// examples/ClassicXposedModule.java
//
// A MODULE WRITTEN AS IF IT WERE 2015, WHICH STILL RUNS TODAY.
//
// The point of this file is not the hooks. It is that NOTHING IN IT IS
// LSPosed-AWARE. Every import, every interface, every helper call is the API
// rovo89 published for classic Xposed, frozen at API version 82. This source
// would have compiled against XposedBridge.jar on an Android 5 device in 2015,
// and it loads unchanged in LSPosed on Android 15 in 2026.
//
// That is chapter 64's second reason to exist, stated as code: the framework
// died and the API did not. A pentester reads module source written to this
// API today, and the docs that source was written against describe a framework
// nobody can install.
//
// WHAT THIS DEMONSTRATES THAT 63-LSPosed's MODULES DO NOT
//   63's VaultUnlockModule is a modern module: it checks lpparam.packageName,
//   it assumes per-application scope, and it is written knowing that scope
//   exists. This one is deliberately written the OLD way, and the three
//   comments marked [GLOBAL-ERA] mark the places where the difference shows.
//   Reading the two side by side is the fastest way to feel what scope changed.
//
// TARGET
//   com.pentest.ch64.vault -- the lab application you build in
//   labs/lab-02-read-a-classic-module.md. Nothing here targets software you
//   do not own. Point a module at somebody else's application and you are, at
//   minimum, in breach of the licence it was given to you under.
//
// COMPILE
//   ../scripts/build-classic-module.sh
//   Builds out of tree against a generated, source-compatible API stub if you
//   do not have the real de.robv.android.xposed:api:82 jar. The stub is
//   EXCLUDED from the DEX, exactly as `compileOnly` would exclude the real
//   jar -- see the warning in section 3.11 of the chapter README about what
//   happens if you package it.
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch64.module;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.IXposedHookZygoteInit;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * A classic-API Xposed module.
 *
 * <p>The class name is registered in {@code assets/xposed_init}, one fully
 * qualified name per line, in plaintext. That file is why an obfuscated module
 * still tells you its entry point: the framework reads it with no knowledge of
 * any obfuscation mapping, so the name can never be renamed.
 */
public class ClassicXposedModule implements IXposedHookZygoteInit, IXposedHookLoadPackage {

    private static final String TAG = "CH64 ";

    /** The package this module was written for. */
    private static final String TARGET = "com.pentest.ch64.vault";

    /**
     * Runs ONCE, inside Zygote, before any application process exists.
     *
     * <p>[GLOBAL-ERA] In classic Xposed this was the only place where a module
     * could touch the framework classes that every process would inherit, and
     * it ran as ROOT, because Zygote is root until it forks and specialises.
     * A module that did something wrong here bricked the boot for every
     * process on the device at once -- which is the concrete mechanism behind
     * "one buggy module bootlooped the phone", the complaint that drove the
     * whole design of what came after.
     *
     * <p>The startupParam gives you your own module's path on disk and nothing
     * else. There is no Context, no package identity, and no application class
     * loader here, because none of those things exist yet.
     */
    @Override
    public void initZygote(IXposedHookZygoteInit.StartupParam startupParam) {
        XposedBridge.log(TAG + "initZygote: modulePath=" + startupParam.modulePath
                + " startsSystemServer=" + startupParam.startsSystemServer);

        // A framework-class hook installed here applies to EVERY process on the
        // device -- system_server included. Passing null as the class loader is
        // correct and only correct for boot-class-path classes.
        //
        // [GLOBAL-ERA] In 2015 this was the normal thing to do. Today it is the
        // single most expensive line a module can contain, and LSPosed will
        // only let it happen if the user has ticked the framework in scope.
        // It is left commented out deliberately; uncommenting it is a decision,
        // not a detail.
        //
        // XposedHelpers.findAndHookMethod("android.app.ActivityManager", null,
        //         "getRunningAppProcesses", XC_MethodReplacement.returnConstant(null));
    }

    /**
     * Runs ONCE PER PROCESS, in the application, before the application's own
     * code.
     *
     * <p>[GLOBAL-ERA] Note the very first line. In classic Xposed this guard
     * was not optional politeness -- it was the ONLY thing standing between
     * your module and every process on the device, because there was no scope.
     * A module that forgot it ran its hooks inside the keyboard, the launcher,
     * the dialer and system_server. Modern modules keep the guard because it
     * is correct; classic modules kept it because the alternative was chaos.
     */
    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET.equals(lpparam.packageName)) {
            return;
        }

        // Log unconditionally on the first line that runs for the target. This
        // is the single most useful habit in module development: it separates
        // "handleLoadPackage never ran" from "it ran and my hook threw", which
        // are different problems with different fixes.
        XposedBridge.log(TAG + "handleLoadPackage pkg=" + lpparam.packageName
                + " process=" + lpparam.processName
                + " uid=" + (lpparam.appInfo == null ? -1 : lpparam.appInfo.uid));

        hookTheDecision(lpparam);
        hookTheCache(lpparam);
        replaceTheAnswer(lpparam);
    }

    // -----------------------------------------------------------------
    // 1. Observe. The most valuable module you will ever write changes
    //    nothing and prints what the application was told and what it decided.
    // -----------------------------------------------------------------
    private void hookTheDecision(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                    "com.pentest.ch64.vault.VaultGate",   // target class, by NAME
                    lpparam.classLoader,                  // the app's loader -- never null here
                    "isUnlocked",                         // target method, by NAME
                    String.class,                         // its one parameter type
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            XposedBridge.log(TAG + "isUnlocked(\"" + param.args[0] + "\")");
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            XposedBridge.log(TAG + "  -> " + param.getResult());
                        }
                    });
        } catch (Throwable t) {
            // A module that throws out of handleLoadPackage loses every hook
            // AFTER the throw, silently, and the application behaves normally.
            // Catch, log, continue.
            XposedBridge.log(TAG + "hookTheDecision failed: " + t);
        }
    }

    // -----------------------------------------------------------------
    // 2. Beat a cached decision WITHOUT INSTALLING A HOOK AT ALL.
    //
    //    This is the technique every anti-hooking control misses, because
    //    there is no hook to find: no dispatcher on the stack, no altered
    //    entry point, no foreign frame. A module simply runs before the
    //    application does and writes a field.
    //
    //    XposedHelpers ignores access modifiers entirely. `private static`
    //    is a compiler concept.
    // -----------------------------------------------------------------
    private void hookTheCache(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> gate = XposedHelpers.findClassIfExists(
                    "com.pentest.ch64.vault.VaultGate", lpparam.classLoader);
            if (gate == null) {
                XposedBridge.log(TAG + "VaultGate absent -- target renamed or packed?");
                return;
            }
            Object before = XposedHelpers.getStaticObjectField(gate, "sDeviceOk");
            XposedHelpers.setStaticObjectField(gate, "sDeviceOk", Boolean.TRUE);
            XposedBridge.log(TAG + "sDeviceOk " + before + " -> "
                    + XposedHelpers.getStaticObjectField(gate, "sDeviceOk"));
        } catch (Throwable t) {
            XposedBridge.log(TAG + "hookTheCache failed: " + t);
        }
    }

    // -----------------------------------------------------------------
    // 3. Replace a body outright.
    //
    //    XC_MethodReplacement makes beforeHookedMethod and afterHookedMethod
    //    final and gives you one method whose return value IS the result. The
    //    original never runs -- so every side effect it had is gone too. A
    //    method that both returns a boolean and increments a failure counter,
    //    replaced this way, stops incrementing the counter, and an application
    //    that notices THAT has caught you.
    //
    //    This is also the call whose presence in a DEX is worth something
    //    during triage. Its ABSENCE is worth much less: 63-LSPosed measured a
    //    `static final boolean` guard eliminating an entire setResult branch at
    //    compile time, so the dangerous code was absent from the APK and one
    //    character away in the source.
    // -----------------------------------------------------------------
    private void replaceTheAnswer(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            XposedHelpers.findAndHookMethod(
                    "com.pentest.ch64.vault.RootCheck", lpparam.classLoader,
                    "isRooted",
                    XC_MethodReplacement.returnConstant(Boolean.FALSE));
            XposedBridge.log(TAG + "RootCheck.isRooted pinned to false");
        } catch (Throwable t) {
            XposedBridge.log(TAG + "replaceTheAnswer failed: " + t);
        }
    }
}
