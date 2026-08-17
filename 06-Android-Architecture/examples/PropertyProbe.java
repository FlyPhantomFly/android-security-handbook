package com.artlab.archdemo;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * PropertyProbe — read Android system properties by all three routes an app has,
 * and show that they can disagree.
 *
 * WHAT IT DEMONSTRATES
 *   ../README.md section 3.10.5 makes a claim that matters enormously for
 *   root- and emulator-detection bypass work: an app can read a property by
 *   exactly THREE routes, and a complete hook must cover all three.
 *
 *     1. android.os.SystemProperties.get()   — Java, @hide, via reflection
 *     2. __system_property_get()             — libc, from native code
 *     3. exec("/system/bin/getprop")         — shelling out
 *
 *   This app reads the same properties all three ways and highlights any
 *   disagreement. Run it clean and the columns match. Run it under a Frida
 *   script that hooks only the Java route and the columns diverge — which is
 *   precisely why "my bypass worked until the app added a native check".
 *
 *   Route 2 needs a tiny JNI stub; the Java and shell routes work standalone,
 *   which is enough to demonstrate the point. The JNI source is at the bottom
 *   of this file in a comment.
 *
 * HOW TO RUN
 *   Drop into any Android project as the launcher Activity.
 *
 *     adb logcat -s ARCHPROBE
 *
 *   Then try to defeat it:
 *
 *     frida -U -f com.artlab.archdemo -l - <<'EOF'
 *     Java.perform(function () {
 *         var SP = Java.use("android.os.SystemProperties");
 *         SP.get.overload("java.lang.String").implementation = function (k) {
 *             if (k === "ro.debuggable") return "0";
 *             return this.get(k);
 *         };
 *     });
 *     EOF
 *
 *   The Java column will read 0 while the shell column still reads the truth.
 *
 * SEE ALSO
 *   ../../37-RootDetection/  — where this matters in practice
 *   ../../53-Frida/          — hooking each route
 */
public class PropertyProbe extends Activity {

    private static final String TAG = "ARCHPROBE";

    /** Properties worth probing — the security-relevant set from README 3.10.4. */
    private static final String[] PROPERTIES = {
        "ro.build.fingerprint",
        "ro.build.type",
        "ro.build.tags",
        "ro.build.version.release",
        "ro.build.version.sdk",
        "ro.build.version.security_patch",
        "ro.debuggable",
        "ro.secure",
        "ro.adb.secure",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.veritymode",
        "ro.crypto.state",
        "ro.product.cpu.abilist",
        "ro.kernel.qemu",          // emulator marker — see ../../39-EmulatorDetection/
        "ro.hardware",
    };

    private final StringBuilder out = new StringBuilder();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView tv = new TextView(this);
        tv.setTextSize(10f);
        tv.setPadding(20, 20, 20, 20);
        setContentView(new ScrollView(this) {{ addView(tv); }});

        emit("PROPERTY PROBE — three routes, compared");
        emit("");

        int disagreements = compareRoutes();

        emit("");
        emit("=== SUMMARY ===");
        if (disagreements == 0) {
            emit("All routes agree. Either nothing is hooked, or whatever is");
            emit("hooked covers every route (which is the correct way to do it).");
        } else {
            emit(disagreements + " DISAGREEMENT(S) between routes.");
            emit("");
            emit("A property cannot genuinely have two values. A disagreement means");
            emit("something is intercepting one route and not the others — an");
            emit("incomplete hook. This is exactly what root-detection code looks");
            emit("for, and exactly why partial bypasses fail. See README 3.10.5.");
        }

        emit("");
        emit("=== BUILD CLASS (framework's own view) ===");
        emit("  Build.FINGERPRINT = " + Build.FINGERPRINT);
        emit("  Build.TAGS        = " + Build.TAGS);
        emit("  Build.TYPE        = " + Build.TYPE);
        emit("  (android.os.Build is populated from properties at class-init time,");
        emit("   so it is a FOURTH surface — cached, and hookable separately.)");

        tv.setText(out);
    }

    private void emit(String line) {
        out.append(line).append('\n');
        Log.i(TAG, line);
    }

    // ------------------------------------------------------------------ //

    private int compareRoutes() {
        emit(String.format("%-38s %-22s %-22s %s",
                "PROPERTY", "JAVA (reflection)", "SHELL (getprop)", "AGREE?"));
        emit(repeat('-', 100));

        int disagreements = 0;

        for (String prop : PROPERTIES) {
            String viaJava  = readViaSystemProperties(prop);
            String viaShell = readViaGetprop(prop);

            boolean agree = normalise(viaJava).equals(normalise(viaShell));
            if (!agree) disagreements++;

            emit(String.format("%-38s %-22s %-22s %s",
                    prop,
                    truncate(viaJava, 20),
                    truncate(viaShell, 20),
                    agree ? "yes" : "*** NO ***"));
        }

        return disagreements;
    }

    /**
     * ROUTE 1 — android.os.SystemProperties.get(), by reflection.
     *
     * SystemProperties is @hide, so apps reach it reflectively. On modern
     * Android this is subject to non-SDK interface restrictions, and a
     * failure here is itself informative — see README 4.5 and
     * ../../11-Android-Runtime/ section 3.13.
     *
     * THIS is the route most Frida bypass scripts hook. On its own that is
     * incomplete.
     */
    private String readViaSystemProperties(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class);
            Object value = get.invoke(null, key);
            return value == null ? "<null>" : value.toString();
        } catch (Throwable t) {
            return "<blocked:" + t.getClass().getSimpleName() + ">";
        }
    }

    /**
     * ROUTE 3 — shell out to /system/bin/getprop.
     *
     * Slower and noisier, but it bypasses any Java-level hook entirely because
     * a completely separate process does the reading. Root-detection code uses
     * this precisely because it is awkward to intercept.
     *
     * To hook this you must catch Runtime.exec / ProcessBuilder as well —
     * see ../../11-Android-Runtime/ section 7.4.
     */
    private String readViaGetprop(String key) {
        Process p = null;
        try {
            p = new ProcessBuilder("/system/bin/getprop", key)
                    .redirectErrorStream(true)
                    .start();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream()))) {
                String line = r.readLine();
                return line == null ? "" : line.trim();
            }
        } catch (Throwable t) {
            return "<error:" + t.getClass().getSimpleName() + ">";
        } finally {
            if (p != null) p.destroy();
        }
    }

    /*
     * ROUTE 2 — __system_property_get() from native code.
     *
     * Not implemented here because it needs an NDK module, but this is the
     * route that defeats naive bypasses most often. Add it with:
     *
     *   // native-lib.cpp
     *   #include <jni.h>
     *   #include <sys/system_properties.h>
     *
     *   extern "C" JNIEXPORT jstring JNICALL
     *   Java_com_artlab_archdemo_PropertyProbe_readNative(
     *           JNIEnv* env, jclass, jstring jkey) {
     *       const char* key = env->GetStringUTFChars(jkey, nullptr);
     *       char value[PROP_VALUE_MAX] = {0};
     *       __system_property_get(key, value);
     *       env->ReleaseStringUTFChars(jkey, key);
     *       return env->NewStringUTF(value);
     *   }
     *
     *   // and in Java:
     *   static { System.loadLibrary("native-lib"); }
     *   private static native String readNative(String key);
     *
     * Hooking THIS requires Interceptor.attach on __system_property_get in
     * libc — a native hook, not a Java one. See ../../16-JNI/ and
     * ../../65-Hooking/.
     */

    // ------------------------------------------------------------------ //

    private static String normalise(String s) {
        if (s == null) return "";
        // Treat blocked/error markers as incomparable rather than as mismatches.
        if (s.startsWith("<blocked") || s.startsWith("<error")) return "?";
        return s.trim();
    }

    private static String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() <= n ? s : s.substring(0, n - 1) + "…";
    }

    private static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }
}

/*
 * ===========================================================================
 * THE LESSON
 *
 * Three routes to the same data, three different interception points:
 *
 *   Route            Hook with                       Defeats
 *   ---------------- ------------------------------- ------------------------
 *   SystemProperties Java.use("android.os.System-    Java-only bypasses
 *                    Properties").get.implementation
 *   __system_prop_get Interceptor.attach on libc      native checks
 *   getprop exec     Runtime.exec / ProcessBuilder    shell-out checks
 *   android.os.Build Java.use("android.os.Build")     cached framework view
 *
 * A bypass that covers only the first works until the app adds a native check
 * — which is the single most common reason a "working" root-detection bypass
 * suddenly stops working.
 *
 * Full treatment: ../../37-RootDetection/README.md
 * ===========================================================================
 */
