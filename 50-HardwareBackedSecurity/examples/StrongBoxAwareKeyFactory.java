/*
 * StrongBoxAwareKeyFactory.java — how to ask for the best hardware available and degrade honestly.
 *
 * WHAT THIS DEMONSTRATES
 *   The correct shape of a key factory on a platform where the hardware you want may not exist:
 *
 *     1. Ask for StrongBox.
 *     2. Catch ONLY StrongBoxUnavailableException, and retry with EXACTLY ONE thing changed.
 *     3. Read back what you actually got, with KeyInfo.
 *     4. Report that level upward, so the SERVER decides what this device is allowed to do.
 *
 *   Step 4 is the one that turns this from a coding style into a security control. The app is not
 *   the party with something to lose, so the app does not get to decide that a software key is
 *   good enough. It measures, and it tells the truth about what it measured.
 *
 * ITS EVIL TWIN
 *   AssumesHardwareKeyManager.java in this directory is the same feature written the way it
 *   usually ships. Diff the two. Every difference is a real defect, and none of them is exotic.
 *
 * HOW TO USE IT IN AN ASSESSMENT
 *   - Read it, then read the target's decompiled key factory next to it. The differences are your
 *     findings list.
 *   - Hand it to a developer instead of a paragraph of advice.
 *   - Run ../scripts/hook-security-level.js against an app built from each file and compare the
 *     logs; the evil twin trips the SecretKeySpec alarm and this one does not.
 *
 * REQUIREMENTS
 *   Android API 23+ to compile; the StrongBox path is API 28+ and is guarded. This file is a
 *   library class with no Activity and no manifest — it is meant to be dropped into a project or
 *   read, not run standalone.
 *
 * WHAT THIS WILL *NOT* DO
 *   - It will NOT make a key unusable by an attacker who has code execution in this process.
 *     Nothing can. See 49-KeyStore/README.md section 1.3: hardware backing prevents EXTRACTION,
 *     not USE. This file is about honesty regarding storage, not about resisting instrumentation.
 *   - It will NOT give you StrongBox on a device that lacks one. All three devices measured for
 *     chapter 50 lack one. That is not a defect in this code or in those devices.
 *   - It does NOT verify attestation. That belongs on a server; see
 *     49-KeyStore/examples/04-verify-attestation.py.
 */

package com.pentest.ch50;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public final class StrongBoxAwareKeyFactory {

    private static final String TAG = "ch50.KeyFactory";
    private static final String PROVIDER = "AndroidKeyStore";

    /** What the app learned about the key it just created. This is what gets reported upward. */
    public static final class Result {
        public final String alias;
        public final int securityLevel;          // KeyProperties.SECURITY_LEVEL_*
        public final boolean strongBoxRequested;
        public final boolean strongBoxGranted;
        public final boolean authBound;
        public final boolean authEnforcedBySecureHardware;
        public final String howLevelWasDetermined;

        Result(String alias, int securityLevel, boolean requested, boolean granted,
               boolean authBound, boolean authEnforcedBySecureHardware, String how) {
            this.alias = alias;
            this.securityLevel = securityLevel;
            this.strongBoxRequested = requested;
            this.strongBoxGranted = granted;
            this.authBound = authBound;
            this.authEnforcedBySecureHardware = authEnforcedBySecureHardware;
            this.howLevelWasDetermined = how;
        }

        public String levelName() {
            switch (securityLevel) {
                case KeyProperties.SECURITY_LEVEL_SOFTWARE:            return "SOFTWARE";
                case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT: return "TRUSTED_ENVIRONMENT";
                case KeyProperties.SECURITY_LEVEL_STRONGBOX:           return "STRONGBOX";
                case KeyProperties.SECURITY_LEVEL_UNKNOWN:             return "UNKNOWN";
                case KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE:      return "UNKNOWN_SECURE";
                default:                                               return "UNRECOGNISED";
            }
        }

        /**
         * Deliberately NOT called "isSecureEnough". This class does not answer that question,
         * because the app is not the party entitled to answer it. It reports; the server decides.
         */
        public String toServerReport() {
            return "{\"alias\":\"" + alias + "\""
                 + ",\"securityLevel\":\"" + levelName() + "\""
                 + ",\"strongBoxRequested\":" + strongBoxRequested
                 + ",\"strongBoxGranted\":" + strongBoxGranted
                 + ",\"authBound\":" + authBound
                 + ",\"authEnforcedBySecureHardware\":" + authEnforcedBySecureHardware
                 + ",\"determinedBy\":\"" + howLevelWasDetermined + "\"}";
        }
    }

    private StrongBoxAwareKeyFactory() { }

    // ------------------------------------------------------------------ the policy, in one place

    /**
     * The base policy. Written once and reused verbatim for both attempts, so that the StrongBox
     * retry cannot accidentally differ in any other respect.
     *
     * If you take one habit away from this file, take this one: build the spec in a single method
     * and change ONLY the StrongBox flag between attempts. Most silent-downgrade bugs are not
     * "the developer forgot to check"; they are "the second builder was typed out again by hand
     * and lost a line".
     */
    private static KeyGenParameterSpec.Builder basePolicy(String alias, boolean requireAuth) {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                alias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            // Default is already true; stated explicitly because setting it to false is a real
            // finding (it permits caller-supplied IVs, which destroys GCM on reuse).
            .setRandomizedEncryptionRequired(true);

        if (requireAuth) {
            b.setUserAuthenticationRequired(true);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                // timeout 0 == per-use binding. The hardware ties the authorisation to ONE
                // operation, so there is no window in which unrelated in-process code can ride
                // along. A positive timeout here would be the single most consequential
                // weakening available in this whole file.
                b.setUserAuthenticationParameters(
                        0,
                        KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
            } else {
                // Deprecated at API 30, but it is the only per-use form below that.
                b.setUserAuthenticationValidityDurationSeconds(-1);
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                // Default is already true. Explicit because setting it false is a finding: an
                // attacker who reaches the settings screen enrols their own finger and inherits
                // every key that opted out.
                b.setInvalidatedByBiometricEnrollment(true);
            }
        }
        return b;
    }

    // ------------------------------------------------------------------ create

    /**
     * Create the key, preferring StrongBox, falling back to the TEE, and reporting what happened.
     *
     * @param alias       Keystore alias.
     * @param requireAuth whether the key must be bound to a user authentication.
     * @throws GeneralSecurityException if the key cannot be created at all. Note what this method
     *         does NOT do on failure: it does not substitute a different, weaker key. A key we
     *         cannot create is not a key we quietly replace.
     */
    public static Result createOrReplace(String alias, boolean requireAuth)
            throws GeneralSecurityException {

        deleteIfPresent(alias);

        boolean strongBoxWorthTrying = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P;
        boolean strongBoxGranted = false;
        SecretKey key;

        if (strongBoxWorthTrying) {
            try {
                key = generate(basePolicy(alias, requireAuth).setIsStrongBoxBacked(true).build());
                strongBoxGranted = true;
            } catch (StrongBoxUnavailableException noSecureElement) {
                // THE ONLY exception we absorb, and we say so out loud.
                //
                // Note what is NOT caught here: NoSuchAlgorithmException, InvalidAlgorithmParameter-
                // Exception, ProviderException, IllegalStateException. Those mean something else is
                // wrong -- an unsupported curve, no lock screen for an auth-bound key, a broken
                // Keystore -- and swallowing them is how apps end up with software keys they never
                // asked for. They propagate.
                Log.i(TAG, "StrongBox unavailable on this device; retrying in the TEE. "
                         + "This is NORMAL: most devices have no secure element.");
                key = generate(basePolicy(alias, requireAuth).setIsStrongBoxBacked(false).build());
            }
        } else {
            key = generate(basePolicy(alias, requireAuth).build());
        }

        // ---- the step everybody skips ----
        Result result = measure(alias, key, strongBoxWorthTrying, strongBoxGranted);

        Log.i(TAG, "key '" + alias + "' -> " + result.levelName()
                 + " (strongBox requested=" + result.strongBoxRequested
                 + " granted=" + result.strongBoxGranted
                 + ", authBound=" + result.authBound
                 + ", authEnforcedByHw=" + result.authEnforcedBySecureHardware + ")");

        if (result.securityLevel == KeyProperties.SECURITY_LEVEL_SOFTWARE) {
            // NOT an exception, and NOT a silent pass. A software Keystore key is the only thing
            // some devices can give you; refusing to run would lock out real users. What is NOT
            // acceptable is claiming hardware backing anyway.
            Log.w(TAG, "This device produced a SOFTWARE-backed key. Any claim of hardware-backed "
                     + "storage is FALSE on this device. Report it and let the server decide.");
        }
        if (requireAuth && !result.authEnforcedBySecureHardware) {
            Log.w(TAG, "Auth requirement is NOT enforced by secure hardware on this device. "
                     + "The binding is a framework promise, not a hardware one.");
        }
        return result;
    }

    private static SecretKey generate(KeyGenParameterSpec spec) throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER);
        kg.init(spec);
        return kg.generateKey();
    }

    // ------------------------------------------------------------------ measure

    /**
     * Read back what the hardware actually gave us. This is the whole point of the file.
     *
     * KeyGenParameterSpec is a REQUEST. KeyInfo is the RECEIPT. An app that reads only the first
     * has an opinion about its own security; an app that reads the second has a measurement.
     */
    public static Result measure(String alias, SecretKey key,
                                 boolean strongBoxRequested, boolean strongBoxGranted)
            throws GeneralSecurityException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), PROVIDER);
        KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);

        int level;
        String how;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            level = info.getSecurityLevel();                       // API 31+, the real answer
            how = "KeyInfo.getSecurityLevel()";
        } else {
            // API 23-30. This is a FLOOR, not a grade: it distinguishes "not pure software" from
            // "pure software" and nothing finer. It cannot see StrongBox and it cannot tell a
            // robust TEE from a minimal one.
            level = info.isInsideSecureHardware()
                    ? KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                    : KeyProperties.SECURITY_LEVEL_SOFTWARE;
            how = "KeyInfo.isInsideSecureHardware()";
        }

        boolean authEnforcedByHw = false;
        try {
            authEnforcedByHw = info.isUserAuthenticationRequirementEnforcedBySecureHardware();
        } catch (Throwable ignored) {
            // Not present on every platform. Absence is not evidence either way.
        }

        // Belt and braces, and a genuinely useful assertion: a Keystore key HAS NO BYTES.
        // If this ever returns non-null, the object is not a Keystore key at all and every
        // hardware claim about it is false.
        if (key.getEncoded() != null) {
            throw new GeneralSecurityException(
                    "getEncoded() returned key material - this key is NOT in the Keystore");
        }

        return new Result(alias, level, strongBoxRequested, strongBoxGranted,
                          info.isUserAuthenticationRequired(), authEnforcedByHw, how);
    }

    // ------------------------------------------------------------------ housekeeping

    private static void deleteIfPresent(String alias) throws GeneralSecurityException {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias);
            }
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException("could not open the Keystore", e);
        }
    }

    /**
     * Load an existing key and measure it. Use this at startup rather than assuming the key you
     * created last month is still what you think it is: a device upgrade can change the backing
     * implementation underneath a key that was generated years earlier.
     */
    public static Result inspectExisting(String alias) throws GeneralSecurityException {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            SecretKey key = (SecretKey) ks.getKey(alias, null);
            if (key == null) {
                throw new GeneralSecurityException("no such key: " + alias);
            }
            return measure(alias, key, false, false);
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException("could not open the Keystore", e);
        }
    }
}
