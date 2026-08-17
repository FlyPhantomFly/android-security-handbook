/*
 * ============================================================================
 *  DynamicDexLoader.kt  —  Chapter 11, Android Runtime
 * ============================================================================
 *
 *  WHAT THIS DOES
 *  --------------
 *  Demonstrates the two ways an Android app can execute code that was not part
 *  of the DEX the framework loaded for it at startup:
 *
 *    1. dalvik.system.DexClassLoader
 *         Loads a .dex / .jar / .apk from a FILE PATH. The file must live
 *         somewhere the app can read; since API 29 the platform strongly
 *         prefers (and in some configurations requires) that the file be in
 *         the app's own private, non-writable-by-others storage.
 *
 *    2. dalvik.system.InMemoryDexClassLoader   (API 26 / Android 8.0 and up)
 *         Loads DEX straight out of a java.nio.ByteBuffer. Nothing ever
 *         touches the filesystem. This is the mechanism behind essentially
 *         every modern commercial packer and every serious piece of Android
 *         malware that wants to defeat static analysis.
 *
 *  In both cases we then use reflection to instantiate a class from the freshly
 *  loaded DEX and call a method on it, because at compile time our app has no
 *  idea that class exists - there is nothing to type against.
 *
 *  HOW TO RUN IT
 *  -------------
 *  Step 1 - build a tiny payload class and turn it into a DEX.
 *
 *      # host shell
 *      mkdir -p /tmp/payload/com/example/payload
 *      cat > /tmp/payload/com/example/payload/Greeter.java <<'EOF'
 *      package com.example.payload;
 *      public class Greeter {
 *          public String greet(String who) {
 *              return "hello " + who + " from a dynamically loaded DEX";
 *          }
 *      }
 *      EOF
 *      cd /tmp/payload
 *      javac --release 8 com/example/payload/Greeter.java
 *      jar cf payload-classes.jar com/example/payload/Greeter.class
 *      # d8 ships in the Android SDK build-tools; adjust the version folder:
 *      $ANDROID_HOME/build-tools/34.0.0/d8 --output . payload-classes.jar
 *      # d8 produces classes.dex; give it a distinct name:
 *      mv classes.dex payload.dex
 *
 *  Step 2 - ship payload.dex with the app as an asset:
 *
 *      cp /tmp/payload/payload.dex <project>/app/src/main/assets/payload.dex
 *
 *  Step 3 - wire the Activity up in AndroidManifest.xml inside <application>:
 *
 *      <activity android:name=".DynamicDexLoader" android:exported="true">
 *          <intent-filter>
 *              <action android:name="android.intent.action.MAIN"/>
 *              <category android:name="android.intent.category.LAUNCHER"/>
 *          </intent-filter>
 *      </activity>
 *
 *  Step 4 - install, launch, read the log:
 *
 *      # host shell
 *      ./gradlew installDebug
 *      adb shell am start -n com.example.runtimelab/.DynamicDexLoader
 *      adb logcat -s DynamicDexLoader:I DynamicDexLoader:E
 *
 *  PREREQUISITES
 *  -------------
 *   - Android Studio, Kotlin plugin, minSdk 21 (the in-memory half is guarded
 *     by a runtime version check and simply skips on API < 26).
 *   - Android SDK build-tools on the host for `d8`.
 *   - No root and no permissions: an app loading its own files is ordinary.
 * ============================================================================
 */

package com.example.runtimelab

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.ScrollView
import android.widget.TextView
import dalvik.system.DexClassLoader
import dalvik.system.InMemoryDexClassLoader
import java.io.File
import java.nio.ByteBuffer

class DynamicDexLoader : Activity() {

    companion object {
        const val TAG = "DynamicDexLoader"

        /** Fully-qualified name of the class that lives inside payload.dex. */
        const val PAYLOAD_CLASS = "com.example.payload.Greeter"

        /** Method we will call on it, by name, through reflection. */
        const val PAYLOAD_METHOD = "greet"

        /** File name of the DEX inside src/main/assets/. */
        const val ASSET_NAME = "payload.dex"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val log = StringBuilder()
        fun line(s: String) {
            Log.i(TAG, s)
            log.append(s).append('\n')
        }

        line("=== Dynamic DEX loading demo ===")
        line("API level = ${Build.VERSION.SDK_INT}")
        line("app dataDir = ${applicationInfo.dataDir}")
        line("")

        // ------------------------------------------------------------------
        // Part 0 - stage the payload.
        //
        // Assets inside an APK are not files on disk in their own right; they
        // are entries in a ZIP. DexClassLoader needs a real path, so we copy
        // the asset out into the app's private files directory first. This copy
        // step is itself a fingerprint you will see in real packed apps: an APK
        // that writes a .dex/.jar/.so out of assets into filesDir at startup is
        // almost always about to load it.
        // ------------------------------------------------------------------
        val dexBytes: ByteArray = try {
            assets.open(ASSET_NAME).use { it.readBytes() }
        } catch (t: Throwable) {
            line("FATAL: could not read assets/$ASSET_NAME - did you follow step 2?")
            line("       $t")
            render(log.toString())
            return
        }
        line("payload.dex is ${dexBytes.size} bytes")
        // Every valid DEX starts with the 8-byte magic "dex\n035\0" (the version
        // digits vary: 035, 037, 038, 039, ...). Chapter 12 dissects the format;
        // here we only sanity-check that we staged the right file.
        line("magic = " + dexBytes.take(8).joinToString(" ") { b ->
            "%02x".format(b)
        })
        line("")

        demoDexClassLoader(dexBytes, ::line)
        line("")
        demoInMemoryDexClassLoader(dexBytes, ::line)

        render(log.toString())
    }

    // ======================================================================
    //  PART 1 - DexClassLoader: DEX from a file on disk
    // ======================================================================
    private fun demoDexClassLoader(dexBytes: ByteArray, line: (String) -> Unit) {
        line("--- 1. DexClassLoader (file-backed) ---")

        // Write the DEX into the app's private files dir:
        //   /data/data/<pkg>/files/payload.dex   (owner: the app's own UID)
        //
        // SECURITY POINT: the directory you load from must not be writable by
        // any other app. Loading a DEX from external storage, from a
        // world-writable directory, or from a path an IPC caller controls is a
        // classic critical finding - any app or any attacker with a foothold
        // can then swap the DEX and gain arbitrary code execution inside YOUR
        // app's UID, with your permissions, your files and your KeyStore
        // access. On API 29+ the platform additionally refuses to open some
        // writable-DEX cases outright, but do not rely on that: treat "DEX from
        // a path I do not fully control" as remote code execution, always.
        val dexFile = File(filesDir, "payload.dex")
        dexFile.writeBytes(dexBytes)
        // Belt and braces: make it read-only for ourselves too, so a bug
        // elsewhere in the app cannot rewrite the file between load attempts.
        dexFile.setWritable(false, false)
        line("wrote ${dexFile.absolutePath} (${dexFile.length()} bytes, writable=${dexFile.canWrite()})")

        try {
            val loader = DexClassLoader(
                /* dexPath = */ dexFile.absolutePath,
                // optimizedDirectory: where the runtime used to place the
                // optimized (odex/oat) output. DEPRECATED since API 26 and
                // IGNORED by the runtime; passing null is now the correct and
                // only sane choice. Older code that passed
                // getDir("dex", MODE_PRIVATE) is a legacy artefact you will
                // still see everywhere in decompiled apps.
                /* optimizedDirectory = */ null,
                // librarySearchPath: extra directories to resolve
                // System.loadLibrary() against for classes loaded by THIS
                // loader. null means "none of my own".
                /* librarySearchPath = */ null,
                // parent: the loader consulted FIRST, because of parent
                // delegation. Passing the app's own loader is what makes the
                // payload able to see android.* and our own classes. Passing
                // null here would give you the boot loader as parent, and the
                // payload would not be able to reference any of our classes.
                /* parent = */ classLoader
            )
            line("created ${loader.javaClass.name} @0x${
                Integer.toHexString(System.identityHashCode(loader))
            }")

            // loadClass() runs the delegation algorithm: ask parent, then
            // search my own DexPathList. Because our parent cannot supply
            // com.example.payload.Greeter, the search falls through to the DEX
            // we just handed over.
            val clazz = loader.loadClass(PAYLOAD_CLASS)
            line("loadClass -> $clazz")
            // The loader that "defined" the class is the one that actually read
            // the bytes. Printing it proves the class came from our new loader
            // and not from somewhere unexpected.
            line("defining loader = ${clazz.classLoader?.javaClass?.name}")

            // We cannot write `Greeter()` in Kotlin - the type does not exist at
            // compile time - so we go through java.lang.reflect.
            val instance = clazz.getDeclaredConstructor().newInstance()
            val method = clazz.getDeclaredMethod(PAYLOAD_METHOD, String::class.java)
            val result = method.invoke(instance, "DexClassLoader")
            line("invoke -> $result")
        } catch (t: Throwable) {
            // ClassNotFoundException here almost always means the payload's
            // package/class name does not match PAYLOAD_CLASS, or d8 was never
            // run. NoClassDefFoundError means the payload references a class
            // its parent loader cannot supply.
            line("DexClassLoader path FAILED: ${t.javaClass.name}: ${t.message}")
        }
    }

    // ======================================================================
    //  PART 2 - InMemoryDexClassLoader: DEX from a ByteBuffer (API 26+)
    // ======================================================================
    private fun demoInMemoryDexClassLoader(dexBytes: ByteArray, line: (String) -> Unit) {
        line("--- 2. InMemoryDexClassLoader (no file at all) ---")

        // API-LEVEL CAVEAT: dalvik.system.InMemoryDexClassLoader was added in
        // API 26 (Android 8.0). On API 21-25 the equivalent trick required
        // writing to a file first, or abusing hidden DexFile entry points.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            line("skipped: InMemoryDexClassLoader requires API 26+, this device is API ${Build.VERSION.SDK_INT}")
            return
        }

        try {
            // In a real packer these bytes would come out of an AES decryption
            // or an anti-debug-gated unpacking routine, and would never exist on
            // disk in plaintext form. We simulate the shape of that, not the
            // crypto: what matters for this chapter is where the bytes END UP.
            //
            // ByteBuffer.wrap() gives a heap buffer over our array. A packer
            // would typically use ByteBuffer.allocateDirect() plus a native
            // memcpy so the plaintext lives off-heap and is harder to find in a
            // Java heap dump. Both work identically as far as ART is concerned.
            val buffer: ByteBuffer = ByteBuffer.wrap(dexBytes)

            val loader = InMemoryDexClassLoader(buffer, classLoader)
            line("created ${loader.javaClass.name} @0x${
                Integer.toHexString(System.identityHashCode(loader))
            }")

            val clazz = loader.loadClass(PAYLOAD_CLASS)
            val instance = clazz.getDeclaredConstructor().newInstance()
            val method = clazz.getDeclaredMethod(PAYLOAD_METHOD, String::class.java)
            val result = method.invoke(instance, "InMemoryDexClassLoader")
            line("invoke -> $result")

            // Optional but instructive: after loading, wipe the plaintext DEX
            // out of the array. The code keeps running, because ART has already
            // mapped its own copy of the DEX. This is exactly why "dump the DEX
            // by scanning the Java heap" is unreliable and why you hook the
            // CONSTRUCTOR instead - see hook-classloaders.js in this folder.
            java.util.Arrays.fill(dexBytes, 0)
            val again = method.invoke(instance, "after wiping the source array")
            line("invoke after wipe -> $again")
        } catch (t: Throwable) {
            line("InMemoryDexClassLoader path FAILED: ${t.javaClass.name}: ${t.message}")
        }
    }

    private fun render(text: String) {
        val tv = TextView(this)
        tv.textSize = 11f
        tv.setPadding(24, 24, 24, 24)
        tv.setTextIsSelectable(true)
        tv.text = text
        val sv = ScrollView(this)
        sv.addView(tv)
        setContentView(sv)
    }
}

/*
 * ============================================================================
 *  SECURITY CONSEQUENCES - why this file matters more than it looks
 * ============================================================================
 *
 *  1. STATIC ANALYSIS STOPS AT THE LOADER.
 *     Decompile this APK and you will see: read an asset, build a loader, call
 *     a method by name. You will NOT see what the payload does, because the
 *     payload is not in the APK's classes.dex - and in the InMemory case it is
 *     not anywhere on disk at all. Every commercial packer (and a large share
 *     of banking trojans) is a variation on the twenty lines above. When your
 *     static tool reports "no suspicious behaviour", check first whether it
 *     ever saw the real code.
 *
 *  2. THE APK SIGNATURE COVERS THE APK, NOT THE PAYLOAD.
 *     Android's APK Signature Scheme protects the bytes inside the APK. A DEX
 *     downloaded at runtime, or decrypted from an asset, is outside that
 *     guarantee. If the app fetches it over plain HTTP, or over HTTPS without
 *     verifying anything beyond the TLS chain, then whoever can serve that
 *     response gets arbitrary code execution inside the app's UID. This is a
 *     recurring, high-severity bug bounty pattern; the fix is to sign the
 *     payload independently and verify the signature with a public key pinned
 *     inside the APK before handing bytes to any ClassLoader.
 *
 *  3. THE LOADER IS NOT A SANDBOX.
 *     A common developer misconception is that code loaded through a separate
 *     ClassLoader is somehow contained. It is not. The payload runs in the same
 *     process, same UID, same SELinux domain (untrusted_app), with the same
 *     permissions and the same access to the app's files, SharedPreferences,
 *     KeyStore-bound keys and network sessions. There is no "plugin sandbox" in
 *     ART. If you need isolation, you need a separate process - ideally one
 *     declared android:isolatedProcess="true" - because only the kernel can
 *     draw that line.
 *
 *  4. DEFENSIVE CHECKLIST FOR A REVIEWER.
 *     - Where do the bytes come from? Asset, network, ContentProvider, Intent
 *       extra, external storage?
 *     - Is the source path attacker-influenceable (any of: getExternalFilesDir,
 *       an Intent extra, a file the app chmods world-writable)?
 *     - Is the payload authenticated (signature/HMAC over the DEX, key in the
 *       APK) BEFORE the loader constructor is called, not after?
 *     - Is the staged file made read-only, and re-verified on every load rather
 *       than only on first download? (Verify-then-load with a gap in between is
 *       a time-of-check/time-of-use bug.)
 *
 *  5. HOW YOU CATCH IT AT RUNTIME.
 *     Hook the constructors. See ./hook-classloaders.js in this folder, which
 *     hooks DexClassLoader.$init, InMemoryDexClassLoader.$init and
 *     PathClassLoader.$init, and writes any in-memory ByteBuffer straight out
 *     to a .dex file you can feed to jadx. Constructor hooking beats heap
 *     scanning because the bytes are guaranteed to be plaintext and complete at
 *     exactly that moment.
 * ============================================================================
 */
