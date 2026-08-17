/*
 * AssumesHardwareKeyManager.java — THE ANTI-PATTERN. Do not ship this. Learn to recognise it.
 *
 * WHAT THIS DEMONSTRATES
 *   The same feature as StrongBoxAwareKeyFactory.java, written the way it actually appears in
 *   shipped applications. It contains five real defects, all of them common, none of them exotic:
 *
 *     D1  It requests StrongBox and catches Exception, so ANY failure lands in the fallback.
 *     D2  The fallback abandons the Keystore entirely and builds a SecretKeySpec from a device
 *         identifier, so the "key" is a value an attacker can recompute.
 *     D3  It never reads KeyInfo, so it has no idea what it got, on any device, ever.
 *     D4  Its second, TEE-level attempt silently drops the authentication binding, because the
 *         builder was retyped by hand instead of reused.
 *     D5  It reports success to the caller in a way that makes the security claim unfalsifiable:
 *         a boolean called isHardwareBacked that is set to true unconditionally.
 *
 *   Every one of these has been observed in real applications. The code is not stupid; it is
 *   DEFENSIVE. Somebody was told "never crash", and the never-crashing is the bug.
 *
 * WHY IT LOOKS FINE IN REVIEW
 *   On the author's own flagship phone, D1-D4 never fire: StrongBox may exist, generation
 *   succeeds first time, the fallback is dead code. The defect only appears on devices the
 *   author does not own, which is most of them. This is why the measurement in
 *   ../labs/lab-01-measure-every-key-type.md matters more than any code review.
 *
 * HOW TO USE IT
 *   - Compile it into a throwaway app and run ../scripts/hook-security-level.js against it. The
 *     SecretKeySpec alarm fires, the audit timer reports that KeyInfo was never read, and you get
 *     a log you can show a developer.
 *   - Compare its decompiled output against README section 6.1 shapes 1 and 2.
 *   - Diff it against StrongBoxAwareKeyFactory.java. The diff IS the remediation.
 *
 * REQUIREMENTS
 *   Android API 23+ to compile. Library class; no Activity, no manifest.
 *
 * WHAT THIS WILL *NOT* DO
 *   - It will NOT fail loudly anywhere. That is the entire point and the reason it survives to
 *     production.
 *   - It will NOT protect anything on a device without StrongBox, which is nearly all of them.
 */

package com.pentest.ch50;

import android.annotation.SuppressLint;
import android.content.Context;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.KeyStore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class AssumesHardwareKeyManager {

    private static final String TAG = "ch50.KeyManager";
    private static final String ALIAS = "vault_master_key";

    /**
     * DEFECT D5. The name is a claim and the value is a constant. Any code that reads this field
     * is being told something nobody measured. In a real app this is the field that ends up
     * quoted in the security whitepaper.
     */
    public boolean isHardwareBacked = true;

    /**
     * Get (or create) the app's master key.
     *
     * "The key is stored in the Android Keystore, hardware-backed where available."
     *  ^ this comment is the security claim. Nothing below verifies it. On the devices measured
     *    for chapter 50 the StrongBox request ALWAYS throws, so the fallback below is not an
     *    edge case -- it is the normal path.
     */
    @SuppressLint("HardwareIds")
    public SecretKey getOrCreateKey(Context context) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (ks.containsAlias(ALIAS)) {
                return (SecretKey) ks.getKey(ALIAS, null);
            }

            KeyGenerator kg = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            // First attempt: the good one, with the auth binding and the secure element.
            kg.init(new KeyGenParameterSpec.Builder(ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setUserAuthenticationRequired(true)
                    .setIsStrongBoxBacked(true)
                    .build());
            return kg.generateKey();

        } catch (Exception e) {
            // DEFECT D1. This catch is reached by StrongBoxUnavailableException on every device
            // without a secure element -- and ALSO by NoSuchAlgorithmException, by
            // InvalidAlgorithmParameterException when no lock screen is set, by ProviderException
            // when the Keystore is unhappy, and by anything else that goes wrong. One catch,
            // five very different situations, one response.
            Log.w(TAG, "StrongBox unavailable, falling back", e);
            return fallbackKey(context);
        }
    }

    /**
     * DEFECT D2 and D4 live here.
     *
     * The comment says "still hardware-backed via the TEE". The code does not do that. It builds
     * a SecretKeySpec from a SHA-256 of ANDROID_ID and the package name -- both values an
     * attacker on the device can read in one command, and both values that are identical on every
     * launch. The result is a key that:
     *
     *   - has never been near the Keystore,
     *   - lives in this process's heap as a byte[],
     *   - is recomputable by anyone who can read ANDROID_ID,
     *   - and is therefore not a secret at all.
     *
     * D4 is the second half: even the commented-out "TEE retry" below drops
     * setUserAuthenticationRequired, because the builder was retyped rather than reused. That is
     * how a fallback quietly removes the control the key existed for.
     */
    @SuppressLint("HardwareIds")
    private SecretKey fallbackKey(Context context) {
        try {
            // What SHOULD have happened here: retry the SAME spec with
            // setIsStrongBoxBacked(false) and nothing else changed. Note that even this
            // commented-out "correct" retry has lost setUserAuthenticationRequired(true) --
            // defect D4 -- which is what makes hand-retyped builders so dangerous.
            //
            // KeyGenerator kg = KeyGenerator.getInstance("AES", "AndroidKeyStore");
            // kg.init(new KeyGenParameterSpec.Builder(ALIAS, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)
            //         .setBlockModes(BLOCK_MODE_GCM)
            //         .setEncryptionPaddings(ENCRYPTION_PADDING_NONE)
            //         .build());               // <-- auth binding silently gone
            // return kg.generateKey();

            String seed = Settings.Secure.getString(
                                context.getContentResolver(), Settings.Secure.ANDROID_ID)
                        + ":" + context.getPackageName();
            byte[] material = MessageDigest.getInstance("SHA-256")
                                .digest(seed.getBytes(Charset.forName("UTF-8")));

            // The single line a reverse engineer greps for. If this constructor runs, the app has
            // raw key bytes in its heap and the whole hardware story is over.
            return new SecretKeySpec(material, "AES");

        } catch (Exception e) {
            // And if even THAT fails, return null and let the caller NPE somewhere unrelated,
            // three stack frames away, in a week's time.
            Log.e(TAG, "fallback failed", e);
            return null;
        }
    }

    /**
     * DEFECT D3, stated as plainly as it can be. There is no call to SecretKeyFactory.getKeySpec,
     * no KeyInfo, no getSecurityLevel, no isInsideSecureHardware anywhere in this class. The app
     * has therefore never established, on any device it has ever run on, whether its central
     * security claim is true.
     *
     * The fix is six lines and is in StrongBoxAwareKeyFactory.measure().
     */
    public String describeSecurityPosture() {
        return "AES-256 key in the Android Keystore, hardware-backed where available.";
    }
}
