/*
 * examples/LateClassHookModule.java
 *
 * Chapter 63 - LSPosed.  The class-loader problem, solved.
 *
 * THE PROBLEM
 *   handleLoadPackage gives you lpparam.classLoader, the application's own
 *   PathClassLoader over base.apk.  That is the right loader for the app's
 *   ordinary classes and the WRONG one - in fact, no loader is the right one
 *   yet - when the class you care about is defined later, by a loader the app
 *   builds itself:
 *
 *     - a plugin architecture that loads feature DEX on demand;
 *     - a dynamic feature module downloaded after install;
 *     - a commercial packer that decrypts the real DEX at runtime and defines
 *       it through InMemoryDexClassLoader;
 *     - any library that ships its implementation in a separate .dex asset.
 *
 *   The symptom is always the same and always misleading: ClassNotFoundError
 *   on a class you can plainly see in jadx.  The class exists in the APK.  It
 *   does not exist in the loader you asked.
 *
 * THE FIX
 *   Stop trying to resolve the class.  Hook the thing that will one day create
 *   it - ClassLoader.loadClass - and install the real hooks the moment it
 *   appears.  This is the managed-layer twin of chapter 65's timing problem for
 *   native libraries: .init_array runs inside dlopen, so a hook installed after
 *   System.loadLibrary returns is already too late, and the answer there is the
 *   same shape - hook android_dlopen_ext and act in onEnter.
 *
 * WHAT THIS FILE DEMONSTRATES
 *   1. hookAllMethods on ClassLoader.loadClass, because there are two overloads
 *      and which one the app calls is the app's business, not yours.
 *   2. A one-shot guard, because loadClass is called constantly and installing
 *      the real hook twice means the callback fires twice per invocation.
 *   3. Doing almost nothing inside the callback, because you are on the hot
 *      path of every class load in the process.
 *   4. Enumerating what actually loaded the class, which is the diagnostic you
 *      wanted in the first place.
 *   5. A fallback for the case where the class never appears at all, so the
 *      module says so instead of silently doing nothing.
 *
 * ETHICS
 *   Targets com.pentest.ch63.vault, the lab application you build from this
 *   chapter's labs.  Nothing else.
 *
 * BUILDING
 *   ./scripts/build-xposed-module.sh --decompile
 *   or, with Gradle:  compileOnly 'de.robv.android.xposed:api:82'
 */

package com.pentest.ch63.module;

import java.util.concurrent.atomic.AtomicBoolean;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class LateClassHookModule implements IXposedHookLoadPackage {

    private static final String TAG = "CH63/late";
    private static final String TARGET_PKG = "com.pentest.ch63.vault";

    /** The class that does not exist yet. */
    private static final String LATE_CLASS = "com.pentest.ch63.vault.packed.RealGate";

    /** Guards against installing the real hook more than once. */
    private final AtomicBoolean installed = new AtomicBoolean(false);

    /** Counts loadClass calls, so the module can report if the class never came. */
    private volatile long loadClassCalls = 0;

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (!TARGET_PKG.equals(lpparam.packageName)) {
            return;
        }

        XposedBridge.log(TAG + " handleLoadPackage process=" + lpparam.processName);

        // ------------------------------------------------------------------
        // Step 1: try the easy thing first, and say so when it works.
        // ------------------------------------------------------------------
        // findClassIfExists returns null rather than throwing.  Use it: a
        // ClassNotFoundError escaping into the framework is caught, but the
        // rest of your handleLoadPackage never runs and nothing says why.
        Class<?> early = XposedHelpers.findClassIfExists(LATE_CLASS, lpparam.classLoader);
        if (early != null) {
            XposedBridge.log(TAG + " " + LATE_CLASS + " was ALREADY resolvable - "
                    + "no late-binding needed on this build");
            install(early);
            return;
        }

        XposedBridge.log(TAG + " " + LATE_CLASS + " not resolvable at handleLoadPackage; "
                + "watching ClassLoader.loadClass");

        // ------------------------------------------------------------------
        // Step 2: watch every class load in the process.
        // ------------------------------------------------------------------
        // hookAllMethods, NOT findAndHookMethod: java.lang.ClassLoader declares
        //     public  Class<?> loadClass(String)
        //     protected Class<?> loadClass(String, boolean)
        // and a subclass may override either.  Which one the app's loader uses
        // is not your decision, so hook the name.
        XposedBridge.hookAllMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                loadClassCalls++;

                // Cheapest possible rejection first.  This callback runs on
                // EVERY class load in the process - thousands of times during
                // startup alone - so anything expensive here is a measurable
                // slowdown the app can time.
                if (installed.get()) {
                    return;
                }
                Object result = param.getResult();
                if (!(result instanceof Class)) {
                    return;                                  // threw, or returned null
                }
                Class<?> c = (Class<?>) result;
                if (!LATE_CLASS.equals(c.getName())) {
                    return;
                }

                // compareAndSet, not a plain check-then-set: loadClass can be
                // called concurrently from several threads and two of them can
                // arrive here at the same instant.
                if (!installed.compareAndSet(false, true)) {
                    return;
                }

                ClassLoader owner = c.getClassLoader();
                XposedBridge.log(TAG + " " + LATE_CLASS + " APPEARED after "
                        + loadClassCalls + " loadClass calls");
                XposedBridge.log(TAG + "   defined by: "
                        + (owner == null ? "<boot>" : owner.getClass().getName()));
                XposedBridge.log(TAG + "   loader chain: " + chain(owner));

                install(c);
            }
        });

        // ------------------------------------------------------------------
        // Step 3: report the negative, rather than staying silent.
        // ------------------------------------------------------------------
        // A module that installs nothing and logs nothing is indistinguishable
        // from a module that was never enabled.  Hook a late-ish lifecycle
        // point and state the outcome either way.
        try {
            XposedHelpers.findAndHookMethod("android.app.Activity", lpparam.classLoader,
                    "onResume", new XC_MethodHook() {
                        private boolean reported = false;

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            if (reported) return;
                            reported = true;
                            if (installed.get()) {
                                XposedBridge.log(TAG + " status: hooks INSTALLED");
                            } else {
                                XposedBridge.log(TAG + " status: " + LATE_CLASS
                                        + " has NOT appeared after " + loadClassCalls
                                        + " loadClass calls and the first Activity resume."
                                        + " Either the name is wrong, or the code path that"
                                        + " loads it has not run yet, or it is defined by"
                                        + " defineClass rather than loadClass.");
                            }
                        }
                    });
        } catch (Throwable t) {
            XposedBridge.log(TAG + " could not install the status probe: " + t);
        }
    }

    // ----------------------------------------------------------------------
    // The real hooks, installed once the class exists.
    // ----------------------------------------------------------------------

    private void install(Class<?> realGate) {
        try {
            XposedHelpers.findAndHookMethod(realGate, "verify", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            XposedBridge.log(TAG + " RealGate.verify(\"" + param.args[0] + "\")");
                        }

                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            XposedBridge.log(TAG + " RealGate.verify -> " + param.getResult());
                        }
                    });
            XposedBridge.log(TAG + " installed hook on RealGate.verify");
        } catch (Throwable t) {
            // The class exists but the method does not.  That is a DIFFERENT
            // failure from "class not found" and deserves a different message,
            // because the fix is different: dump the class's methods.
            XposedBridge.log(TAG + " RealGate resolved but verify(String) did not: " + t);
            dumpMethods(realGate);
        }
    }

    /**
     * When a signature does not match, print what the class actually declares.
     * This is the two-minute answer to a question that otherwise costs an hour.
     */
    private void dumpMethods(Class<?> c) {
        try {
            for (java.lang.reflect.Method m : c.getDeclaredMethods()) {
                StringBuilder sb = new StringBuilder(TAG + "   declares ");
                sb.append(m.getReturnType().getSimpleName()).append(' ')
                  .append(m.getName()).append('(');
                Class<?>[] ps = m.getParameterTypes();
                for (int i = 0; i < ps.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(ps[i].getName());
                }
                XposedBridge.log(sb.append(')').toString());
            }
        } catch (Throwable t) {
            XposedBridge.log(TAG + " could not enumerate methods: " + t);
        }
    }

    /** The loader delegation chain, parent-first, as one string. */
    private static String chain(ClassLoader cl) {
        StringBuilder sb = new StringBuilder();
        int guard = 0;
        while (cl != null && guard++ < 32) {
            if (sb.length() > 0) sb.append(" -> ");
            sb.append(cl.getClass().getSimpleName());
            cl = cl.getParent();
        }
        if (sb.length() == 0) sb.append("<boot only>");
        return sb.toString();
    }
}
