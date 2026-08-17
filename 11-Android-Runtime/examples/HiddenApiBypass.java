/*
 * ============================================================================
 *  HiddenApiBypass.java  —  Chapter 11, Android Runtime
 * ============================================================================
 *
 *  WHAT THIS DOES
 *  --------------
 *  Since API 28 (Android 9) ART refuses, at runtime, to let ordinary app code
 *  reflect on "non-SDK interfaces" - the classes, methods and fields that exist
 *  in the platform but are not part of the public SDK. This file shows:
 *
 *    1. What the enforcement looks like from the app's side (a direct
 *       reflective call that fails).
 *    2. The classic "double reflection" / meta-reflection trick, which used the
 *       fact that the check looks at WHO IS CALLING.
 *    3. dalvik.system.VMRuntime.setHiddenApiExemptions(String[]), the runtime's
 *       own escape hatch, reached through trick 2 - the combination that every
 *       hooking framework used on Android 9 and 10.
 *    4. The supported, non-tricky ways to turn enforcement off while you are
 *       testing.
 *
 *  ...and, throughout, argues the point that matters far more than the tricks:
 *  hidden API enforcement is a COMPATIBILITY mechanism, not a security
 *  boundary. Read the long note at the bottom of this file even if you skip the
 *  code.
 *
 *  HOW TO RUN IT
 *  -------------
 *  Library-style class, no UI. Add it to a project and call it from anywhere,
 *  e.g. from an Activity's onCreate:
 *
 *      Log.i("hidden", HiddenApiBypass.runDemo());
 *
 *  Then:
 *
 *      # host shell
 *      ./gradlew installDebug
 *      adb shell am start -n com.example.runtimelab/.MainActivity
 *      adb logcat -s HiddenApiBypass:I HiddenApiBypass:W
 *
 *  Watch the platform's own warnings appear in logcat while you experiment -
 *  they are the single best way to learn which APIs are on which list:
 *
 *      # host shell
 *      adb logcat | grep -i "Accessing hidden"
 *
 *  To disable enforcement entirely on a test device (SUPPORTED, no tricks -
 *  this is what you should normally do as a researcher):
 *
 *      # host shell; needs a debuggable/userdebug build or root on some devices
 *      adb shell settings put global hidden_api_policy 1
 *      # values: 0 = default policy, 1 = enforcement disabled ("just warn"),
 *      #         2 = warn, 3 = block. Restore the default with:
 *      adb shell settings delete global hidden_api_policy
 *
 *  PREREQUISITES
 *  -------------
 *   - minSdk 21+. Everything degrades gracefully: on API < 28 there is nothing
 *     to bypass and the demo says so.
 *   - No root, no permissions. This all happens inside your own process.
 *
 *  API-LEVEL CAVEATS (important - the ground moved several times)
 *  --------------------------------------------------------------
 *   - API < 28 : no enforcement at all. Reflection reaches everything.
 *   - API 28   : enforcement introduced. Lists were named light-grey / dark-grey
 *                / blacklist / whitelist at the time.
 *   - API 29+  : lists renamed and restructured to: SDK (public), unsupported
 *                (formerly light grey), max-target-<letter> (allowed only for
 *                apps whose targetSdkVersion is at or below that release), and
 *                blocked. Your app's targetSdkVersion is part of the decision,
 *                which is why "it worked in my old app" is a real and common
 *                observation.
 *   - API 30 (Android 11): the double-reflection trick was closed. Reflection
 *                calls made THROUGH reflection are attributed to the app, not to
 *                the platform, so meta-reflection alone no longer works. Modern
 *                libraries (LSPosed's HiddenApiBypass is the well-known one)
 *                instead arrange for the lookup to be attributed to a class on
 *                the boot classpath. The technique keeps changing; the PRINCIPLE
 *                below does not.
 *   - Debuggable apps and platform-signed apps are treated differently, and
 *     apps installed as "test" builds via `adb install -t` can behave
 *     differently again. Always confirm on the exact build you are attacking.
 * ============================================================================
 */

package com.example.runtimelab;

import android.os.Build;
import android.util.Log;

import java.lang.reflect.Method;

public final class HiddenApiBypass {

    private static final String TAG = "HiddenApiBypass";

    private HiddenApiBypass() {
        // Utility class.
    }

    /**
     * The API we will try to reach. android.os.SystemProperties is a real
     * platform class marked @hide: it is compiled into the framework, every
     * app process has it loaded, and it is not in android.jar, so you cannot
     * call it at compile time. It reads the same property store that
     * `adb shell getprop` prints. It is a good teaching target because it is
     * genuinely useful (ro.build.version.sdk, ro.debuggable, dalvik.vm.*) and
     * because it is exactly the kind of thing app developers try to reach.
     *
     * AOSP: frameworks/base/core/java/android/os/SystemProperties.java
     */
    private static final String TARGET_CLASS = "android.os.SystemProperties";
    private static final String TARGET_METHOD = "get";

    // ========================================================================
    //  Entry point: runs all four techniques and returns a readable report.
    // ========================================================================
    public static String runDemo() {
        StringBuilder sb = new StringBuilder();
        sb.append("API level = ").append(Build.VERSION.SDK_INT).append('\n');
        if (Build.VERSION.SDK_INT < 28) {
            sb.append("This device predates hidden API enforcement (API 28+).\n")
              .append("Plain reflection already reaches everything here.\n");
        }

        sb.append("\n[1] direct reflection: ")
          .append(describe(tryDirectReflection("ro.build.version.sdk")))
          .append('\n');

        sb.append("[2] double reflection: ")
          .append(describe(tryDoubleReflection("ro.build.version.sdk")))
          .append('\n');

        boolean exempted = tryExemptEverything();
        sb.append("[3] setHiddenApiExemptions(\"L\") applied = ").append(exempted).append('\n');

        sb.append("[4] direct reflection again after exemption: ")
          .append(describe(tryDirectReflection("ro.build.version.sdk")))
          .append('\n');

        String report = sb.toString();
        Log.i(TAG, report);
        return report;
    }

    // ========================================================================
    //  TECHNIQUE 1 - plain reflection (the thing that is being blocked)
    // ========================================================================
    /**
     * This is what an app would naively write. On API 28+ with the default
     * policy, the outcome depends on which list the member is on:
     *
     *   - "unsupported" (old light grey): the call SUCCEEDS but ART writes
     *     "Accessing hidden method Landroid/os/SystemProperties;->get..." to
     *     logcat. That warning is the platform telling you it intends to break
     *     you later.
     *   - "max-target-O" and friends: succeeds only if your targetSdkVersion is
     *     low enough; otherwise you get NoSuchMethodException.
     *   - "blocked": you get NoSuchMethodException (for methods) or
     *     NoSuchFieldException (for fields) - note that the runtime lies to you
     *     by pretending the member does not exist, rather than throwing a
     *     dedicated "you are not allowed" exception. That deliberate choice
     *     keeps apps on a well-trodden error path, and it is why a bypass looks
     *     like "the method suddenly exists again".
     *
     * WHERE THE DECISION IS MADE: ART consults the member's hiddenapi flags,
     * which are baked into the DEX of the framework at build time, and then
     * asks who the caller is. See art/runtime/hidden_api.h and
     * art/runtime/hidden_api.cc in AOSP for the domain/list logic.
     */
    public static Object tryDirectReflection(String propertyKey) {
        try {
            Class<?> sysProps = Class.forName(TARGET_CLASS);
            // getDeclaredMethod is the checked operation. Class.forName on a
            // hidden CLASS is usually fine - it is the members that are gated.
            Method get = sysProps.getDeclaredMethod(TARGET_METHOD, String.class);
            get.setAccessible(true);
            return get.invoke(null, propertyKey);
        } catch (Throwable t) {
            return t;   // returned, not thrown: the failure IS the lesson
        }
    }

    // ========================================================================
    //  TECHNIQUE 2 - double reflection ("reflection on reflection")
    // ========================================================================
    /**
     * THE IDEA, in one sentence: the hidden API check is CALLER-BASED, so make
     * the platform call itself.
     *
     * When your app calls Class.getDeclaredMethod("get", ...), ART walks back
     * one frame to see who is asking. It finds YOUR class, notices that your
     * class was loaded by a PathClassLoader (i.e. it belongs to the
     * "application" domain rather than the "core platform" domain), and applies
     * the restriction.
     *
     * Now suppose instead of calling getDeclaredMethod directly, you obtain a
     * java.lang.reflect.Method object FOR getDeclaredMethod itself, and invoke
     * that. On Android 9 and 10 the frame ART saw at the moment of the lookup
     * belonged to java.lang.Class - a boot classpath class - so the check
     * concluded "the platform is asking" and allowed everything. Two lines, and
     * the entire enforcement fell over.
     *
     * Note what did NOT happen: no memory corruption, no privilege escalation,
     * no root. The app simply confused an accounting mechanism about which frame
     * was responsible. That is the strongest possible evidence that this is not
     * a security boundary - a security boundary that a two-line trick removes
     * was never one.
     *
     * API 30 (Android 11) closed this specific hole by refusing to treat a
     * reflective invocation of a reflection method as a platform caller. The
     * code below is therefore historical on modern devices - and still exactly
     * what you will find while reverse engineering apps and SDKs built for
     * Android 9/10. Run it on an API 28 or 29 emulator to see it work.
     */
    public static Object tryDoubleReflection(String propertyKey) {
        try {
            // Step A: get a Method object that REPRESENTS Class.getDeclaredMethod.
            // This lookup itself is allowed, because getDeclaredMethod is public
            // SDK API - we are not asking for anything hidden yet.
            Method metaGetDeclaredMethod = Class.class.getDeclaredMethod(
                    "getDeclaredMethod", String.class, Class[].class);

            Class<?> sysProps = Class.forName(TARGET_CLASS);

            // Step B: invoke it reflectively. The receiver (first argument to
            // invoke) is the Class we are querying; the varargs are the
            // arguments to getDeclaredMethod itself.
            //
            // The explicit Object[] is not stylistic: invoke() takes
            // (Object obj, Object... args), and a Class[] passed bare would be
            // spread into the varargs instead of being one argument. Wrapping it
            // makes the intent unambiguous. Getting this wrong produces a very
            // confusing IllegalArgumentException about argument counts.
            Object result = metaGetDeclaredMethod.invoke(
                    sysProps,
                    new Object[]{ TARGET_METHOD, new Class[]{ String.class } });

            Method get = (Method) result;
            get.setAccessible(true);
            return get.invoke(null, propertyKey);
        } catch (Throwable t) {
            return t;
        }
    }

    // ========================================================================
    //  TECHNIQUE 3 - VMRuntime.setHiddenApiExemptions(String[])
    // ========================================================================
    /**
     * The runtime ships its own switch. dalvik.system.VMRuntime has a method
     *
     *      public void setHiddenApiExemptions(String[] signaturePrefixes)
     *
     * which tells ART "treat any member whose signature starts with one of these
     * prefixes as if it were public SDK". It exists because the platform itself
     * needs it: `am` / `adb shell` style tooling and the CTS harness set
     * exemptions when launching apps, and the property
     * `dalvik.vm.hiddenapiexemptions` feeds the same machinery through Zygote
     * when a process is forked.
     *
     * Passing the single prefix "L" exempts EVERYTHING, because every JVM type
     * signature for a class starts with 'L' (as in "Landroid/os/SystemProperties;").
     * That is the one-liner every hooking framework used.
     *
     * The catch: setHiddenApiExemptions is itself a hidden method, so you cannot
     * simply reflect on it - you need technique 2 to reach it. Hence the
     * ladder below. On Android 11+ that ladder no longer works from an ordinary
     * app, and the practical routes are: use a testing policy
     * (`settings put global hidden_api_policy 1`), run under a hooking framework
     * that already has boot-classpath execution, or use a maintained library
     * such as LSPosed's HiddenApiBypass, which arranges for the lookup to be
     * attributed to a boot classpath class.
     *
     * AOSP: libcore/libart/src/main/java/dalvik/system/VMRuntime.java
     *       and the Zygote side in
     *       frameworks/base/core/java/com/android/internal/os/Zygote.java
     *
     * ZYGOTE CONNECTION (this is the chapter's real point): exemptions are a
     * per-process property established at or after fork from Zygote. Zygote
     * preloads the framework classes ONCE and every app process is a
     * copy-on-write fork of it, so per-process knobs like this one are exactly
     * the kind of state that has to be settable after the fork. Nothing here
     * crosses a process boundary - which is why the kernel does not care about
     * it and neither should your threat model.
     */
    public static boolean tryExemptEverything() {
        // On API < 28 there is nothing to exempt; report success trivially.
        if (Build.VERSION.SDK_INT < 28) {
            return true;
        }
        try {
            // The two meta-reflection handles we need.
            Method metaForName = Class.class.getDeclaredMethod("forName", String.class);
            Method metaGetDeclaredMethod = Class.class.getDeclaredMethod(
                    "getDeclaredMethod", String.class, Class[].class);

            // Reach dalvik.system.VMRuntime through the platform's own forName,
            // so that even the class lookup is attributed to the platform.
            Class<?> vmRuntimeClass = (Class<?>) metaForName.invoke(
                    null, "dalvik.system.VMRuntime");

            // VMRuntime.getRuntime() - static, no parameters. A null Class[]
            // means "no parameter types"; note again the explicit Object[]
            // wrapper so that `null` is passed AS an argument rather than
            // being interpreted as "no arguments at all".
            Method getRuntime = (Method) metaGetDeclaredMethod.invoke(
                    vmRuntimeClass, new Object[]{ "getRuntime", null });

            // VMRuntime.setHiddenApiExemptions(String[]) - instance method.
            Method setExemptions = (Method) metaGetDeclaredMethod.invoke(
                    vmRuntimeClass,
                    new Object[]{ "setHiddenApiExemptions", new Class[]{ String[].class } });

            // getRuntime() is static, so the receiver is null.
            Object vmRuntime = getRuntime.invoke(null);

            // "L" == every class signature. Use a narrower prefix if you want to
            // exempt only one package, e.g. "Landroid/os/" - narrower is better
            // practice when you are instrumenting an app you must not perturb.
            setExemptions.invoke(vmRuntime, new Object[]{ new String[]{ "L" } });
            return true;
        } catch (Throwable t) {
            Log.w(TAG, "setHiddenApiExemptions route failed (expected on API 30+): " + t);
            return false;
        }
    }

    // ========================================================================
    //  Helper
    // ========================================================================
    private static String describe(Object outcome) {
        if (outcome instanceof Throwable) {
            Throwable t = (Throwable) outcome;
            // Unwrap InvocationTargetException so the message names the real
            // failure instead of the reflection plumbing.
            Throwable cause = t.getCause() != null ? t.getCause() : t;
            return "BLOCKED (" + cause.getClass().getName() + ": " + cause.getMessage() + ")";
        }
        return "OK -> " + outcome;
    }
}

/*
 * ============================================================================
 *  WHY HIDDEN API ENFORCEMENT IS NOT A SECURITY BOUNDARY
 * ============================================================================
 *
 *  Google has said this plainly, and the design says it louder. Work through
 *  the argument once and you will never mis-classify a "hidden API bypass" in a
 *  report again.
 *
 *  1. IT IS ENFORCED BY THE CODE IT RESTRICTS.
 *     The check lives inside ART, inside the app's own process, evaluated
 *     against the app's own stack frames. The thing being restricted and the
 *     thing doing the restricting share an address space and a UID. Any
 *     boundary of that shape is advisory. Compare with the real boundaries in
 *     Android: the UID separation enforced by the kernel, SELinux labels
 *     enforced by the LSM hooks, and permission checks performed by
 *     system_server in a DIFFERENT PROCESS across Binder. Those hold even when
 *     the app is fully attacker-controlled. This one does not, by construction.
 *
 *  2. NATIVE CODE SIDESTEPS THE PREMISE.
 *     An app may load its own .so through System.loadLibrary and execute
 *     arbitrary machine code in its own process. Once you are executing native
 *     code you are on the same side of the fence as the runtime itself: you can
 *     read and write ART's own data structures, including the flags that drive
 *     these checks. No exploit is required - loading your own native library is
 *     a completely ordinary, documented app capability.
 *
 *  3. WHAT IT ACTUALLY PROTECTS IS THE PLATFORM'S ABILITY TO CHANGE.
 *     Before API 28, thousands of popular apps reflected into framework
 *     internals. Any refactor of those internals broke real apps on real users'
 *     phones, and Android got the blame. Enforcement exists so the platform can
 *     evolve without an ecosystem-wide compatibility crisis, and so developers
 *     get a loud warning before the break rather than a crash after it. The
 *     "max-target-<letter>" lists are the clearest evidence: they grant access
 *     based on your targetSdkVersion, which is a compatibility concept and has
 *     no security meaning whatsoever.
 *
 *  4. THE FAILURE MODE IS COMPATIBILITY-SHAPED, NOT SECURITY-SHAPED.
 *     Blocked members are reported as "does not exist". A security mechanism
 *     wants a loud, auditable denial; a compatibility mechanism wants the app to
 *     take its existing not-found path and keep running. The platform chose the
 *     latter.
 *
 *  HOW TO WRITE THIS UP AS A PENTESTER
 *  -----------------------------------
 *  "The application bypasses hidden API enforcement" is, on its own, NOT a
 *  vulnerability. It is a fact about the app that becomes interesting only via
 *  what it reaches. Ask the follow-up question:
 *
 *    - Did it reach an API that leaks another app's data or a device
 *      identifier? Then the finding is the data exposure, and the bypass is the
 *      technique - and you should check whether the underlying API is itself
 *      permission-gated, because permission checks in system_server still apply
 *      no matter what your process thinks.
 *    - Did it reach an API that lets it silently persist, intercept
 *      notifications, or interfere with other apps? Same: name the capability.
 *    - Did it merely read a build property or set a window flag? Then it is a
 *      maintainability note, not a security finding.
 *
 *  Conversely, when you are the ATTACKER analysing an app, hidden API
 *  enforcement is just friction. Turn it off on your test device with
 *  `settings put global hidden_api_policy 1` and move on; do not waste an
 *  afternoon reimplementing a bypass that the platform will change again next
 *  year.
 *
 *  RELATED CHAPTERS
 *  ----------------
 *  Chapter 20 (Security Architecture) for what the real boundaries are;
 *  chapter 21 (App Sandbox) for the UID/SELinux story; chapter 15 and 16 for
 *  the native/JNI escape route mentioned in point 2.
 * ============================================================================
 */
