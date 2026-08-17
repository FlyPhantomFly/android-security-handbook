/*
 * PackerStub.java
 * ===========================================================================
 * WHAT THIS IS
 *   A minimal but genuine Android packer stub: an Application subclass that,
 *   in attachBaseContext, decrypts a DEX from assets, hands it to an
 *   InMemoryDexClassLoader, performs the LoadedApk ClassLoader surgery, and
 *   forwards the lifecycle to the app's real Application class.
 *
 *   Pair it with pack.py in this directory, which produces the encrypted
 *   asset. Together they let you build a target to unpack in lab 04 and
 *   lab 05.
 *
 * WHY IT MATTERS
 *   Packers are the most intimidating protection to meet and the most
 *   mechanically defeatable, and building one is the fastest way to see why
 *   both are true.
 *
 *   Intimidating: jadx opens the APK and shows forty meaningless classes. The
 *   app plainly works, so the code exists, but not anywhere you can see.
 *
 *   Defeatable: look at line 4 of attachBaseContext below. `ByteBuffer.wrap(
 *   dex)` holds a complete, valid, PLAINTEXT DEX, in this process, right
 *   there. It has to. ART cannot execute anything else. No amount of
 *   engineering on the vendor's side removes that requirement, which is why
 *   chapter 40 section 3.7.3 states:
 *
 *       Unpacking is not code-breaking. It is TIMING.
 *
 *   Writing this class is what turns that sentence from a slogan into
 *   something you know. You will place the plaintext into a ByteBuffer with
 *   your own hands and then, from the other side, take it out again.
 *
 * HOW TO RUN
 *   # host — 1. build the real app and extract its DEX
 *   ./gradlew :realapp:assembleRelease
 *   unzip -o realapp-release.apk classes.dex -d payload/
 *
 *   # 2. encrypt it
 *   python3 pack.py --in payload/classes.dex --out payload.dat
 *
 *   # 3. build the stub app with payload.dat in assets/, this class as
 *   #    <application android:name>, and the real Application class name in
 *   #    a <meta-data> entry
 *   ./gradlew :stub:assembleRelease
 *   adb install -r stub-release.apk
 *
 *   # 4. defeat it
 *   frida -U -f com.obflab.target -l ../scripts/frida-classloader-dump.js --pause
 *
 * MANIFEST
 *   <application android:name="com.obflab.stub.PackerStub" ...>
 *       <meta-data android:name="obflab.real.application"
 *                  android:value="com.obflab.target.RealApplication" />
 *       ... the real app's activities, services and receivers ...
 *   </application>
 *
 * REQUIREMENTS
 *   API 26+ for InMemoryDexClassLoader. A fallback to DexClassLoader for
 *   older devices is included and commented, because that fallback is
 *   observable and is one of the things you look for on a real target.
 *
 * AUTHORISED TESTING ONLY — teaching material for chapter 40.
 * ===========================================================================
 */

package com.obflab.stub;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;

import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;

public class PackerStub extends Application {

    private static final String TAG = "PackerStub";

    /** The encrypted payload, in assets/. */
    private static final String ASSET_NAME = "payload.dat";

    /** Where the real Application class name is stashed. */
    private static final String META_REAL_APP = "obflab.real.application";

    /**
     * The key.
     *
     * IT IS IN THE APK. There is nowhere else for it to be, because the app
     * must decrypt its own payload with no network and no user input. Every
     * packer in existence has this same property; the sophisticated ones bury
     * the key in native code, derive it from device properties, or split it
     * across several places — all of which raise cost and none of which change
     * the fact that it is present and derivable inside the process.
     */
    private static final byte[] KEY = {
        (byte) 0x5A, (byte) 0xA5, (byte) 0x3C, (byte) 0xC3,
        (byte) 0x17, (byte) 0x71, (byte) 0x2E, (byte) 0xE2
    };

    private static final byte[] MAGIC = { 'O', 'B', 'F', 'P' };

    private Application realApplication;

    // =======================================================================
    // THE RUNTIME SEQUENCE — chapter 40 section 3.7.1
    //
    //   1. ActivityThread.handleBindApplication instantiates the class named
    //      by <application android:name>. The packer rewrote that to point
    //      here, so THIS class is constructed before any of the app's code.
    //   2. attachBaseContext(Context) runs FIRST — before onCreate, before
    //      any Activity, before any content provider.
    //   3. We decrypt the payload and hand it to a ClassLoader.
    //   4. We reflectively replace LoadedApk.mClassLoader so all subsequent
    //      class resolution finds the real code.
    //   5. We instantiate the real Application and forward the lifecycle.
    //
    // Each of those five steps is a moment an analyst can be standing in, and
    // step 3 is the one where plaintext exists.
    // =======================================================================

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        long t0 = System.currentTimeMillis();
        try {
            // A real packer loads its native runtime here, and that
            // System.loadLibrary triggers .init_array, which is where the
            // anti-debug lives. See vaultcore.c in lab 05 for a working
            // example, and note that .init_array runs BEFORE JNI_OnLoad —
            // which is why hooking JNI_OnLoad to catch the decryption is
            // always too late.
            //
            // System.loadLibrary("protect");

            byte[] dex = decryptPayload(base);
            Log.i(TAG, "decrypted " + dex.length + " bytes");

            ClassLoader real = createClassLoader(base, dex);
            installClassLoader(base, real);
            startRealApplication(base, real);

            Log.i(TAG, "unpacked in " + (System.currentTimeMillis() - t0) + "ms");
        } catch (Throwable t) {
            // A real packer fails silently or kills the process. Logging here
            // is a teaching convenience; note that a packer which logs its own
            // failure has handed an analyst a map.
            Log.e(TAG, "unpack failed", t);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (realApplication != null) {
            realApplication.onCreate();
        }
    }

    // =======================================================================
    // Step 3a — decrypt
    // =======================================================================

    /**
     * Read assets/payload.dat and XOR it back to a plaintext DEX.
     *
     * Container format, produced by pack.py:
     *   offset 0   4 bytes   magic "OBFP"
     *   offset 4   4 bytes   plaintext length, little-endian
     *   offset 8   N bytes   ciphertext
     *
     * The magic exists so a corrupt asset fails loudly here rather than
     * producing a mysterious VerifyError three frames later. Real packers do
     * the same thing for the same reason, and that header is frequently the
     * first thing you find when you look at the asset in a hex editor.
     */
    private byte[] decryptPayload(Context ctx) throws Exception {
        InputStream in = ctx.getAssets().open(ASSET_NAME);
        ByteArrayOutputStream bos = new ByteArrayOutputStream(1 << 20);
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) {
            bos.write(buf, 0, n);
        }
        in.close();

        byte[] blob = bos.toByteArray();
        if (blob.length < 8) {
            throw new IllegalStateException("payload too short");
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (blob[i] != MAGIC[i]) {
                throw new IllegalStateException("bad payload magic");
            }
        }

        int len = (blob[4] & 0xFF)
                | ((blob[5] & 0xFF) << 8)
                | ((blob[6] & 0xFF) << 16)
                | ((blob[7] & 0xFF) << 24);
        if (len <= 0 || len > blob.length - 8) {
            throw new IllegalStateException("bad payload length: " + len);
        }

        byte[] dex = new byte[len];
        for (int i = 0; i < len; i++) {
            dex[i] = (byte) (blob[8 + i] ^ KEY[i % KEY.length]);
        }

        // Sanity-check that we produced something ART will accept, so a wrong
        // key fails here with a clear message rather than deep inside the
        // ClassLoader.
        if (!(dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'x' && dex[3] == '\n')) {
            throw new IllegalStateException("decryption produced non-DEX data");
        }
        return dex;
    }

    // =======================================================================
    // Step 3b — hand it to the runtime
    // =======================================================================

    /**
     * InMemoryDexClassLoader (API 26+) is the modern packer's choice because
     * the DEX never touches disk: there is no temporary file for an analyst to
     * find afterwards.
     *
     * The compensating weakness — and it is total — is that the plaintext must
     * be handed to the constructor in a ByteBuffer, so an analyst who hooks
     * that constructor receives the entire payload, gift-wrapped. See
     * ../scripts/frida-classloader-dump.js.
     *
     * The pre-26 fallback writes the DEX to the app's private directory, which
     * is worse for the packer in every way: the file exists on disk, it can be
     * pulled with `run-as`, and its presence in the app's data directory is a
     * conspicuous artefact. Packers that still support old API levels carry
     * this path, and finding it is an easy win.
     */
    private ClassLoader createClassLoader(Context base, byte[] dex) throws Exception {
        ClassLoader parent = base.getClassLoader();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return new InMemoryDexClassLoader(ByteBuffer.wrap(dex), parent);
        }

        // --- pre-API 26 fallback: the DEX must exist as a file -------------
        File dir = new File(base.getCacheDir(), "d");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IllegalStateException("cannot create " + dir);
        }
        File out = new File(dir, "p.dex");
        FileOutputStream fos = new FileOutputStream(out);
        fos.write(dex);
        fos.flush();
        fos.close();

        // Note that from API 29, loading DEX from an app-writable path is
        // restricted for apps targeting 29+. See the version matrix in
        // section 3.10.
        return new DexClassLoader(out.getAbsolutePath(),
                                  dir.getAbsolutePath(),
                                  null,
                                  parent);
    }

    // =======================================================================
    // Step 4 — the ClassLoader surgery
    // =======================================================================

    /**
     * Make the framework use our loader.
     *
     * The chain is ContextImpl -> LoadedApk (field mPackageInfo) ->
     * mClassLoader. See section 4.3 of the chapter and
     * frameworks/base/core/java/android/app/LoadedApk.java.
     *
     * These are private framework internals. The field names have been stable
     * for many releases, but a production packer probes several candidates and
     * walks the class hierarchy rather than assuming — which is why a real
     * stub contains a suspicious amount of defensive reflection, and why that
     * defensive reflection is itself a recognition signal.
     *
     * FOR THE ANALYST: hooking java.lang.reflect.Field.set and watching for a
     * field named mClassLoader catches this step regardless of how the packer
     * navigated to it. frida-classloader-dump.js does exactly that.
     */
    private void installClassLoader(Context base, ClassLoader real) throws Exception {
        Object loadedApk = null;

        // Walk up the hierarchy: the field is on ContextImpl, and `base` may
        // be a ContextWrapper around it.
        Class<?> c = base.getClass();
        while (c != null && loadedApk == null) {
            try {
                Field f = c.getDeclaredField("mPackageInfo");
                f.setAccessible(true);
                loadedApk = f.get(base);
            } catch (NoSuchFieldException ignored) {
                c = c.getSuperclass();
            }
        }
        if (loadedApk == null) {
            throw new IllegalStateException("could not locate LoadedApk");
        }

        Field mClassLoader = loadedApk.getClass().getDeclaredField("mClassLoader");
        mClassLoader.setAccessible(true);
        mClassLoader.set(loadedApk, real);

        // Some framework paths consult the thread context loader too.
        Thread.currentThread().setContextClassLoader(real);

        Log.i(TAG, "mClassLoader replaced: " + real);
    }

    // =======================================================================
    // Step 5 — hand over to the real Application
    // =======================================================================

    /**
     * Instantiate the real Application and forward the lifecycle.
     *
     * The real class name lives in a <meta-data> entry, because the packer
     * overwrote <application android:name> with its own and the framework will
     * never instantiate the original. It MUST keep that name somewhere it can
     * read, and "somewhere it can read" is also somewhere you can read. That
     * necessity is structural, exactly like the key above and the plaintext
     * DEX in step 3.
     *
     * Application.attach(Context) is hidden, so it is invoked reflectively —
     * another recognition signal, and one that hidden-API enforcement from
     * API 28 has made noisier for packers than it used to be.
     */
    private void startRealApplication(Context base, ClassLoader real) throws Exception {
        ApplicationInfo ai = base.getPackageManager()
                .getApplicationInfo(base.getPackageName(), PackageManager.GET_META_DATA);

        String realName = (ai.metaData == null)
                ? null : ai.metaData.getString(META_REAL_APP);
        if (realName == null || realName.isEmpty()) {
            Log.i(TAG, "no real Application declared; nothing to forward to");
            return;
        }

        Class<?> cls = real.loadClass(realName);
        realApplication = (Application) cls.newInstance();

        Method attach = Application.class.getDeclaredMethod("attach", Context.class);
        attach.setAccessible(true);
        attach.invoke(realApplication, base);

        // A production stub also replaces LoadedApk.mApplication and the
        // ActivityThread's mAllApplications/mInitialApplication entries so
        // that Context.getApplicationContext() returns the real instance.
        // Omitted here for readability; their absence is why this stub is a
        // teaching artefact rather than a product.

        Log.i(TAG, "real Application started: " + realName);
    }
}

/*
 * ===========================================================================
 * WHAT THIS LOOKS LIKE FROM THE OTHER SIDE
 *
 * STATIC INDICATORS (section 3.7.2) — this stub triggers:
 *   - a tiny classes.dex with a very small class_defs_size
 *   - a large, high-entropy file in assets/
 *   - an <application android:name> foreign to the app's own package
 *   - a <meta-data> element holding a class name
 *
 * WHAT A COMMERCIAL PACKER ADDS THAT THIS DOES NOT:
 *   - the decryption in native code, so the key is not in the DEX at all
 *   - anti-debug in .init_array, before JNI_OnLoad
 *   - encrypted or mangled resources
 *   - multiple layers of loading
 *   - method-level rather than whole-DEX protection, so a single memory dump
 *     yields a DEX with empty method bodies
 *   - deliberate format abuse to break apktool
 *
 * DYNAMIC INDICATORS — every step above is observable:
 *   attachBaseContext on a foreign class ......... hook Application
 *   System.loadLibrary("protect") ................ hook System.loadLibrary
 *   .init_array anti-debug ....................... hook android_dlopen_ext
 *   InMemoryDexClassLoader(ByteBuffer) ........... THE HANDOVER
 *   Field.set(mClassLoader) ...................... hook Field.set
 *   real Application instantiated ................ hook ClassLoader.loadClass
 *
 * TIME TO DEFEAT: about two minutes with
 * ../scripts/frida-classloader-dump.js, and the same two minutes against any
 * other app packed the same way.
 *
 * WHICH IS THE POINT ABOUT SHARED FATE. A packer is a PRODUCT, deployed
 * identically across thousands of applications. The first analyst to defeat it
 * publishes a general method; from then on every customer of that vendor costs
 * an attacker one command. Your application's protection level is set by the
 * attention the vendor's most-targeted customer attracts, not by your own risk
 * profile.
 *
 * That is the single most useful thing to tell a client evaluating a
 * commercial packer, and it is not something the vendor will tell them.
 * ===========================================================================
 */
