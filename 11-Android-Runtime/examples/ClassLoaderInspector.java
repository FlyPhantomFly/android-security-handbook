/*
 * ============================================================================
 *  ClassLoaderInspector.java  —  Chapter 11, Android Runtime
 * ============================================================================
 *
 *  WHAT THIS DOES
 *  --------------
 *  Walks the ClassLoader chain of the running app, starting at the loader that
 *  loaded THIS class, and following .getParent() all the way up to
 *  BootClassLoader (the last non-null loader on Android). For every loader in
 *  that chain that is a dalvik.system.BaseDexClassLoader (which means
 *  PathClassLoader, DexClassLoader, DelegateLastClassLoader and
 *  InMemoryDexClassLoader), it reaches into the loader's private internals with
 *  reflection and prints every DEX file that loader can serve classes from.
 *
 *  The result is a complete, ground-truth answer to the question:
 *      "Which code is actually loaded into this process, and who loaded it?"
 *
 *  That question is the whole point of this chapter. An app can only execute a
 *  class if some ClassLoader in the process can produce it. If you enumerate
 *  every loader and every DEX behind every loader, nothing can execute that you
 *  have not seen. Packers, DRM wrappers, "anti-tamper" SDKs and second-stage
 *  malware all show up here as extra DEX paths that were never in the APK you
 *  downloaded.
 *
 *  HOW TO RUN IT
 *  -------------
 *  Option A — as an Activity (easiest):
 *    1. Copy this file into an Android Studio project, e.g. into
 *       app/src/main/java/com/example/runtimelab/ClassLoaderInspector.java
 *    2. Register it in AndroidManifest.xml inside <application>:
 *
 *         <activity android:name=".ClassLoaderInspector"
 *                   android:exported="true">
 *             <intent-filter>
 *                 <action android:name="android.intent.action.MAIN"/>
 *                 <category android:name="android.intent.category.LAUNCHER"/>
 *             </intent-filter>
 *         </activity>
 *
 *    3. Build and install, then run and read the report on screen:
 *
 *         # host shell
 *         ./gradlew installDebug
 *         adb shell am start -n com.example.runtimelab/.ClassLoaderInspector
 *         adb logcat -s ClassLoaderInspector:I
 *
 *  Option B — as a helper called from anywhere in an existing app:
 *
 *         android.util.Log.i("CL", ClassLoaderInspector.describeChain(
 *                 getClass().getClassLoader()));
 *
 *  PREREQUISITES
 *  -------------
 *   - Android Studio / Gradle, minSdk 21 or higher. No root, no Frida.
 *   - No special permissions: a process is always allowed to inspect itself.
 *
 *  API-LEVEL CAVEATS  (read these, they will bite you)
 *  ---------------------------------------------------
 *   - API 28 (Android 9) introduced hidden API enforcement. The fields this
 *     file reflects on (BaseDexClassLoader.pathList, DexPathList.dexElements,
 *     DexPathList.Element.dexFile) are non-SDK interfaces. Historically they
 *     sat on the greylist / "unsupported" list, so reflection still works but
 *     prints an "Accessing hidden field" warning to logcat. On a future release
 *     they may move to the blocklist and throw NoSuchFieldException. This code
 *     therefore treats every reflection hop as fallible and degrades to a
 *     readable message instead of crashing.
 *   - To make hidden API enforcement irrelevant while you are learning, disable
 *     it globally on a debug device:
 *
 *         # adb shell, requires a debuggable/userdebug build or root
 *         adb shell settings put global hidden_api_policy 1
 *         # restore the default afterwards:
 *         adb shell settings delete global hidden_api_policy
 *
 *   - InMemoryDexClassLoader exists only on API 26+ (Android 8.0). On older
 *     devices you will simply never see one in the chain.
 *   - The shape of DexPathList.Element changed over the years (it once carried
 *     zip file handles as well). We read fields defensively by name and skip
 *     anything that is not present on the device we are running on.
 * ============================================================================
 */

package com.example.runtimelab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.ScrollView;
import android.widget.TextView;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class ClassLoaderInspector extends Activity {

    /** logcat tag; filter with: adb logcat -s ClassLoaderInspector:I */
    public static final String TAG = "ClassLoaderInspector";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // getClassLoader() on a Context returns the loader that the framework
        // built for THIS app in LoadedApk.getClassLoader(). For an ordinary app
        // that is a dalvik.system.PathClassLoader whose dex path is your
        // base.apk (plus split APKs, plus any shared libraries you declared).
        String report = describeChain(getClassLoader());

        Log.i(TAG, report);

        // Show the same text on screen so the example is usable without adb.
        TextView tv = new TextView(this);
        tv.setTextSize(11f);
        tv.setPadding(24, 24, 24, 24);
        tv.setText(report);
        tv.setTextIsSelectable(true);
        ScrollView sv = new ScrollView(this);
        sv.addView(tv);
        setContentView(sv);
    }

    // ------------------------------------------------------------------
    //  The actual inspector. Static and Context-free so you can call it
    //  from a unit test, a Service, or a hooked method.
    // ------------------------------------------------------------------

    /**
     * Produces a human-readable description of the whole delegation chain.
     *
     * WHY A CHAIN AT ALL?
     * Java class loading uses "parent delegation": when you ask a loader for a
     * class it first asks its parent, and only searches its own DEX files if
     * the parent could not supply the class. That is a security-relevant design
     * decision: it makes it impossible for an app-supplied DEX to shadow
     * java.lang.String, because BootClassLoader answers first and wins.
     * (DelegateLastClassLoader deliberately inverts this order — see the notes
     * further down — which is exactly why it is interesting to an attacker.)
     */
    public static String describeChain(ClassLoader start) {
        StringBuilder out = new StringBuilder(4096);
        out.append("=== ClassLoader chain (child -> parent) ===\n");
        out.append("process pid=").append(android.os.Process.myPid())
           .append(" uid=").append(android.os.Process.myUid()).append('\n');
        out.append("pointer size hint: ")
           .append(System.getProperty("os.arch"))
           .append("  (arm64-v8a => 64-bit ART, armeabi-v7a => 32-bit ART)\n\n");

        int depth = 0;
        ClassLoader cl = start;

        while (cl != null) {
            out.append('[').append(depth).append("] ")
               .append(cl.getClass().getName()).append('\n');

            // identityHashCode, not hashCode(): two different loaders can have
            // equal hashCodes, and we care about object identity here. When you
            // later hook loadClass() with Frida you will match these numbers up.
            out.append("     identity = 0x")
               .append(Integer.toHexString(System.identityHashCode(cl)))
               .append('\n');

            out.append("     toString = ").append(safeToString(cl)).append('\n');

            // Only BaseDexClassLoader subclasses have a DexPathList. The boot
            // loader (java.lang.BootClassLoader) does NOT: the boot classpath
            // is held natively inside the runtime, which is precisely why you
            // cannot rewrite it from Java.
            appendDexPathList(out, cl);

            out.append('\n');
            cl = cl.getParent();
            depth++;
        }

        out.append('[').append(depth)
           .append("] null  <- end of chain. The loader above this line is\n")
           .append("      java.lang.BootClassLoader; its classes come from the\n")
           .append("      boot image (boot.art/boot.oat) and the bootclasspath\n")
           .append("      JARs, which live outside any app's control.\n");

        return out.toString();
    }

    /**
     * The reflection ladder. Each hop exists because the previous hop returned
     * an object whose useful state is private. There is no public API for any
     * of this, because from the platform's point of view "which DEX files back
     * this loader" is an implementation detail. From a security researcher's
     * point of view it is the single most important fact about the process.
     *
     * The ladder, in AOSP terms:
     *
     *   dalvik.system.BaseDexClassLoader          (libcore/dalvik/src/main/java/dalvik/system/BaseDexClassLoader.java)
     *       private final DexPathList pathList;
     *   dalvik.system.DexPathList                 (libcore/dalvik/src/main/java/dalvik/system/DexPathList.java)
     *       private Element[] dexElements;
     *   dalvik.system.DexPathList$Element
     *       private final DexFile dexFile;   // and, on most versions, File path
     *   dalvik.system.DexFile                     (libcore/dalvik/src/main/java/dalvik/system/DexFile.java)
     *       public String getName();         // the on-disk path, or a synthetic
     *                                        // name for in-memory DEX
     */
    private static void appendDexPathList(StringBuilder out, ClassLoader cl) {

        // HOP 1: find the field "pathList".
        //
        // We must search up the class hierarchy rather than calling
        // cl.getClass().getDeclaredField("pathList"), because the field is
        // declared on BaseDexClassLoader, not on the concrete subclass. If the
        // loader is a PathClassLoader, getDeclaredField() on PathClassLoader
        // itself would throw NoSuchFieldException: getDeclaredField only looks
        // at fields declared by that exact class.
        Field pathListField = findField(cl.getClass(), "pathList");
        if (pathListField == null) {
            // Perfectly normal for BootClassLoader and for custom loaders that
            // do not extend BaseDexClassLoader (e.g. a loader that pulls
            // classes from the network - yes, those exist in the wild).
            out.append("     (no pathList field -> not a BaseDexClassLoader;")
               .append(" nothing to enumerate)\n");
            return;
        }

        Object pathList;
        try {
            // setAccessible(true) turns off the *language-level* access check.
            // It does not turn off hidden API enforcement, which is a separate,
            // runtime-level check introduced in API 28.
            pathListField.setAccessible(true);
            pathList = pathListField.get(cl);
        } catch (Throwable t) {
            out.append("     (cannot read pathList: ").append(t).append(")\n");
            return;
        }
        if (pathList == null) {
            out.append("     (pathList is null)\n");
            return;
        }

        // HOP 2: DexPathList.dexElements — the ordered array that class lookup
        // actually walks. Order matters: findClass() returns the FIRST match,
        // so an attacker who can prepend an element to this array can shadow
        // any class the app defines. That is the core of most "DEX injection"
        // and legacy multidex-hijack techniques.
        Field dexElementsField = findField(pathList.getClass(), "dexElements");
        if (dexElementsField == null) {
            out.append("     (DexPathList has no dexElements field on this ")
               .append("Android version)\n");
            return;
        }

        Object dexElements;
        try {
            dexElementsField.setAccessible(true);
            dexElements = dexElementsField.get(pathList);
        } catch (Throwable t) {
            out.append("     (cannot read dexElements: ").append(t).append(")\n");
            return;
        }
        if (dexElements == null) {
            out.append("     (dexElements is null)\n");
            return;
        }

        // We use java.lang.reflect.Array instead of casting to Object[] because
        // the element type is the package-private class DexPathList$Element,
        // which we cannot name at compile time. Array.getLength/get work on any
        // array reference without knowing its component type.
        int n = Array.getLength(dexElements);
        out.append("     dexElements: ").append(n).append(" entry/entries\n");

        for (int i = 0; i < n; i++) {
            Object element = Array.get(dexElements, i);
            if (element == null) {
                out.append("       [").append(i).append("] <null element>\n");
                continue;
            }

            out.append("       [").append(i).append("] ");

            // HOP 3a: Element.dexFile -> DexFile, then DexFile.getName().
            //
            // Why getName() and not toString()? Because DexFile.getName()
            // returns the source path the runtime recorded. For a file-backed
            // DEX that is something like
            //   /data/app/~~AbC..==/com.example-XyZ..==/base.apk
            // For an InMemoryDexClassLoader there is no file, so ART records a
            // synthetic name such as "InMemoryDexFile[...]" or similar. Seeing a
            // synthetic name here is a loud signal: code is executing in this
            // process that never touched the filesystem, so no on-disk scan and
            // no APK-integrity check could ever have inspected it.
            String printedSomething = null;

            Field dexFileField = findField(element.getClass(), "dexFile");
            if (dexFileField != null) {
                try {
                    dexFileField.setAccessible(true);
                    Object dexFile = dexFileField.get(element);
                    if (dexFile != null) {
                        // getName() is a public method on a hidden-ish class,
                        // so we look it up reflectively rather than importing
                        // dalvik.system.DexFile (which is @removed/@hide on
                        // recent SDKs and will not compile against the public
                        // android.jar).
                        Method getName = dexFile.getClass().getMethod("getName");
                        Object name = getName.invoke(dexFile);
                        printedSomething = String.valueOf(name);
                        out.append("dexFile.getName() = ").append(printedSomething);
                    } else {
                        out.append("dexFile = null");
                    }
                } catch (Throwable t) {
                    out.append("dexFile unreadable (").append(t.getClass().getSimpleName())
                       .append(')');
                }
            } else {
                out.append("(no dexFile field)");
            }

            // HOP 3b: Element.path -> java.io.File.
            //
            // Most Android versions also keep the originating File on the
            // Element. It is worth printing alongside dexFile.getName() because
            // the two can differ: `path` is where the container (APK/JAR) is,
            // while the DexFile name can point at the extracted or in-memory
            // form. A mismatch is a strong hint that something rewrote the
            // element array after the app started.
            Field pathField = findField(element.getClass(), "path");
            if (pathField != null) {
                try {
                    pathField.setAccessible(true);
                    Object p = pathField.get(element);
                    if (p != null) {
                        out.append("   | path = ").append(p);
                    }
                } catch (Throwable ignored) {
                    // Non-fatal: the name is the important half.
                }
            }

            if (printedSomething == null) {
                out.append("   | element.toString() = ").append(safeToString(element));
            }
            out.append('\n');
        }

        // Bonus: native library search path. System.loadLibrary() resolves
        // against these directories, so an extra entry here means the app can
        // load a .so from a location you did not expect. Native code is not
        // subject to hidden API enforcement at all, which makes this list
        // security-relevant, not merely informational.
        appendNativeDirs(out, pathList, "nativeLibraryDirectories");
        appendNativeDirs(out, pathList, "systemNativeLibraryDirectories");
    }

    private static void appendNativeDirs(StringBuilder out, Object pathList, String fieldName) {
        Field f = findField(pathList.getClass(), fieldName);
        if (f == null) {
            return;
        }
        try {
            f.setAccessible(true);
            Object value = f.get(pathList);
            if (value == null) {
                return;
            }
            out.append("     ").append(fieldName).append(" = ");
            if (value.getClass().isArray()) {
                int n = Array.getLength(value);
                for (int i = 0; i < n; i++) {
                    if (i > 0) {
                        out.append(", ");
                    }
                    out.append(String.valueOf(Array.get(value, i)));
                }
            } else {
                // On several releases these are java.util.List, not arrays.
                out.append(String.valueOf(value));
            }
            out.append('\n');
        } catch (Throwable ignored) {
            // Informational only.
        }
    }

    // ------------------------------------------------------------------
    //  Small helpers
    // ------------------------------------------------------------------

    /**
     * Walks up the superclass chain looking for a declared field.
     *
     * getField() would not help here: it only finds PUBLIC fields, and every
     * field we care about is private. getDeclaredField() finds private fields
     * but only on the exact class you ask, so we must climb manually. This
     * three-line loop is the single most reused piece of code in Android
     * runtime research; you will write it again in every hooking project.
     */
    private static Field findField(Class<?> start, String name) {
        for (Class<?> c = start; c != null; c = c.getSuperclass()) {
            try {
                return c.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                // Not on this class; try the superclass.
            } catch (Throwable t) {
                // On API 28+ a blocklisted field can surface as a different
                // Throwable. Treat it as "not available" rather than crashing.
                return null;
            }
        }
        return null;
    }

    /**
     * toString() on a foreign object can throw. In an inspector you never want
     * a diagnostic to be the thing that crashes the process you are studying.
     */
    private static String safeToString(Object o) {
        try {
            return String.valueOf(o);
        } catch (Throwable t) {
            return "<toString() threw " + t.getClass().getName() + ">";
        }
    }
}

/*
 * ============================================================================
 *  WHAT A TYPICAL RESULT LOOKS LIKE, AND HOW TO READ IT
 * ============================================================================
 *
 *  [0] dalvik.system.PathClassLoader
 *       dexElements: 1 entry/entries
 *         [0] dexFile.getName() = /data/app/~~q1..==/com.example.runtimelab-Ab..==/base.apk
 *  [1] java.lang.BootClassLoader
 *       (no pathList field -> not a BaseDexClassLoader)
 *  [2] null <- end of chain
 *
 *  Two loaders is the healthy baseline for a simple app. Read anything extra
 *  as a question to answer:
 *
 *   - A THIRD loader of type DexClassLoader or InMemoryDexClassLoader means the
 *     app loads code that is not simply "the APK". Find out where that DEX came
 *     from: assets, downloaded at runtime, or decrypted in memory.
 *   - dexElements with several entries usually means split APKs (App Bundles)
 *     or legacy multidex - both benign - but it is also exactly how an attacker
 *     inserts a shadowing DEX. Compare the list against the APK's own
 *     classes*.dex set.
 *   - A DelegateLastClassLoader in the chain inverts parent delegation: it
 *     searches its OWN dex first and only then asks the parent. That is legal
 *     and sometimes necessary (plugin frameworks), but it means an app class
 *     can be shadowed by a plugin's class of the same name.
 *   - A dexFile name that is not a path (in-memory DEX) means nothing on disk
 *     represents that code. Dump it at runtime - see
 *     ../scripts/runtime-recon.js and ./hook-classloaders.js.
 *
 *  SECURITY BOUNDARY NOTE
 *  ----------------------
 *  Nothing here is a security boundary. The ClassLoader chain is a *lookup*
 *  mechanism, not an isolation mechanism. Every loader in this process runs
 *  with the same UID, the same SELinux domain and the same file access as every
 *  other loader. Separating "trusted" from "untrusted" classes by putting them
 *  in different ClassLoaders inside one process protects nothing: reflection,
 *  JNI, and simply calling getParent() cross those "boundaries" freely. The
 *  real boundary is the process, and it is drawn by the kernel (UID, SELinux),
 *  which is why Android forks a fresh process per app from Zygote in the first
 *  place.
 * ============================================================================
 */
