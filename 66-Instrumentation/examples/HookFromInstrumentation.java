// examples/HookFromInstrumentation.java
//
// PURPOSE
//   Chapter 66 section 3.17 makes a claim that section 9.4 has to back up:
//   instrumentation solves GETTING IN, and once you are in, the ordinary
//   interception techniques are available. This file is the smallest honest
//   demonstration -- a pure-Java hook, no native code, no trampoline, no ART
//   internals, installed from an Instrumentation.onCreate() and therefore in
//   place BEFORE the target's Application.onCreate() emits its first event.
//
//   The mechanism is java.lang.reflect.Proxy. It works on exactly one shape:
//   an INTERFACE-typed collaborator reachable from a field. That shape covers a
//   surprising amount of a modern app -- Retrofit services, OkHttp interceptor
//   lists, analytics sinks, dependency-injection graph entries, listener fields.
//   It does NOT cover a final class, a static method, or a native call. For
//   those you need chapter 65's machinery, and the honest framing is that this
//   file got you to the point where you could load a .so and use it.
//
// HOW TO BUILD AND RUN IT
//     1. cp HookFromInstrumentation.java vault-probe/
//     2. in vault-probe/AndroidManifest.xml set
//        android:name="com.pentest.ch66.probe.HookFromInstrumentation"
//     3. ./build-instrumentation-fixtures.sh --install
//     4. adb logcat -c
//        adb shell am instrument -w -r \
//            com.pentest.ch66.vault.test/com.pentest.ch66.probe.HookFromInstrumentation
//        adb logcat -d -s ch66hook:I ch66sink:I
//
// WAS THIS EXECUTED?
//   YES, on 2026-08-16, on the AVD sdk_gphone16k_x86_64 (Android 15 / API 35).
//   Measured result, quoted verbatim in the chapter's lab 03:
//
//     I ch66hook: installed proxy over com.pentest.ch66.vault.VaultStore.sSink
//     I ch66hook: -> event[startup, sess-7a9a3cf2bb6]
//     I ch66hook: <- event = null
//
//   Note that "ch66sink" -- the target's own logging implementation -- still
//   fires, because the proxy forwards. A hook that forwards is an observation; a
//   hook that does not is a replacement. Choose deliberately.
//
// WHY THE FIELD IS FOUND BY REFLECTION AND NOT BY IMPORT
//   The test APK must NOT contain a copy of the target's classes. Its DEX is
//   FIRST on the shared class path (chapter 66 section 3.7), so a duplicate
//   fully-qualified name shadows the target's and every field you touch is your
//   own copy's, initialised to its default. That failure is silent and produces
//   confident wrong answers. Reflection through the class loader is the only
//   safe way, and it is also the position a real assessment is in.
//
// AUTHORISED TESTING ONLY. Point this at the chapter's own vault-target fixture
// or at an application you own.

package com.pentest.ch66.probe;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class HookFromInstrumentation extends Instrumentation {

    private static final String TAG = "ch66hook";
    private static final String TARGET_CLASS = "com.pentest.ch66.vault.VaultStore";
    private static final String TARGET_FIELD = "sSink";

    /** Every call the proxy saw, in order. Reported at the end. */
    private final List<String> mCalls = Collections.synchronizedList(new ArrayList<String>());

    private String mInstallResult = "not attempted";

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);

        // This runs BEFORE the target's Application.onCreate(). That is the only
        // reason the first event is catchable at all -- see section 3.6. Install
        // the proxy here, not in onStart(), which races the application thread.
        mInstallResult = installProxy(getContext().getClassLoader());
        Log.i(TAG, mInstallResult);

        start();
    }

    @Override
    public void onStart() {
        // Give the application a moment to run its startup and emit. A real
        // probe would wait on a marker rather than sleep; this one keeps the
        // example to one idea.
        android.os.SystemClock.sleep(1500);

        Bundle results = new Bundle();
        results.putString("hook.install", mInstallResult);
        results.putString("hook.callCount", String.valueOf(mCalls.size()));
        int i = 0;
        for (String c : new ArrayList<>(mCalls)) {
            results.putString(String.format("hook.call.%02d", i++), c);
        }
        finish(Activity.RESULT_OK, results);
    }

    // ------------------------------------------------------------------------

    private String installProxy(ClassLoader cl) {
        try {
            Class<?> owner = Class.forName(TARGET_CLASS, true, cl);
            Field field = owner.getDeclaredField(TARGET_FIELD);
            field.setAccessible(true);

            final Object original = field.get(null);
            if (original == null) {
                return "field " + TARGET_FIELD + " is null; nothing to wrap";
            }

            Class<?>[] interfaces = collectInterfaces(original.getClass());
            if (interfaces.length == 0) {
                return "ERROR " + original.getClass().getName()
                        + " implements no interface; java.lang.reflect.Proxy cannot wrap it."
                        + " This is the limit of the technique -- see chapter 65.";
            }

            Object proxy = Proxy.newProxyInstance(cl, interfaces, new InvocationHandler() {
                @Override
                public Object invoke(Object p, Method method, Object[] args) throws Throwable {
                    String argText = args == null ? "[]" : Arrays.toString(args);
                    mCalls.add(method.getName() + argText);
                    Log.i(TAG, "-> " + method.getName() + argText);
                    // Forward to the real implementation. Returning a value of
                    // our own here instead would make this a replacement rather
                    // than an observation -- the same distinction chapter 65
                    // draws between a hook that calls through and one that does not.
                    Object out = method.invoke(original, args);
                    Log.i(TAG, "<- " + method.getName() + " = " + out);
                    return out;
                }
            });

            field.set(null, proxy);
            return "installed proxy over " + TARGET_CLASS + "." + TARGET_FIELD;
        } catch (Throwable t) {
            return "ERROR " + t.getClass().getSimpleName() + ": " + t.getMessage();
        }
    }

    /**
     * Walk up the class hierarchy collecting every interface. An anonymous class
     * declares its interfaces directly, but a subclass three levels down may not,
     * and Proxy needs the complete set or the cast at the assignment site fails
     * with a ClassCastException that names neither type usefully.
     */
    private static Class<?>[] collectInterfaces(Class<?> c) {
        List<Class<?>> found = new ArrayList<>();
        while (c != null && c != Object.class) {
            for (Class<?> i : c.getInterfaces()) {
                if (!found.contains(i)) {
                    found.add(i);
                }
            }
            c = c.getSuperclass();
        }
        return found.toArray(new Class<?>[0]);
    }
}
