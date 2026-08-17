/*
 * SecurityLevelProbe.java — what security level does this device ACTUALLY give each key type?
 *
 * PURPOSE
 *   Answers, by measurement rather than by assumption, the only question that matters before you
 *   write "hardware-backed" in a report:
 *
 *       For every algorithm, key size and option an app can ask for on THIS device, what does
 *       KeyMint/Keymaster actually return — StrongBox, TEE, or software?
 *
 *   The answer differs per device AND per algorithm on the same device. A phone whose AES keys
 *   land in the TEE may put 3DES, Ed25519 or a 4096-bit RSA key in software, or refuse them
 *   outright. `KeyGenParameterSpec` is what you asked for; `KeyInfo` is what you got. This probe
 *   reads back the second.
 *
 * USAGE
 *   Driven by ../scripts/probe-security-levels.sh, which compiles, pushes and runs it. Manually:
 *
 *     # host
 *     javac -source 8 -target 8 -bootclasspath $ANDROID_HOME/platforms/android-35/android.jar \
 *           -d out SecurityLevelProbe.java
 *     d8 --lib $ANDROID_HOME/platforms/android-35/android.jar --output . out/SecurityLevelProbe.class
 *     adb push classes.dex /data/local/tmp/slprobe.dex
 *     adb shell "CLASSPATH=/data/local/tmp/slprobe.dex app_process /data/local/tmp SecurityLevelProbe"
 *
 *   Optional arguments:
 *     --keep          do not delete the generated keys (default is to delete every one)
 *     --attest        also request an attestation chain for the EC key and print it as PEM
 *     --prefix NAME   alias prefix (default ch50_probe_)
 *
 * REQUIREMENTS
 *   - adb access to a device. NO ROOT REQUIRED. NO APK INSTALL REQUIRED.
 *   - JDK, Android SDK build-tools (d8) and an android.jar on the host.
 *   - The device's SELinux policy must let the `shell` domain talk to keystore2. It does on AOSP
 *     and on every device tested so far; if it does not, you will see a ServiceSpecificException
 *     with code 6 (PERMISSION_DENIED) and you must fall back to an installed APK.
 *
 * WHAT THIS WILL *NOT* TELL YOU
 *   - It will NOT tell you the security level an *app* gets. It runs as uid 2000 (`shell`), in the
 *     shell keystore namespace. The KeyMint backend is the same physical implementation, so the
 *     per-algorithm security levels are representative — but `attestationApplicationId` will name
 *     the shell, not your target, and any OEM policy keyed on package name is not exercised.
 *   - It will NOT tell you whether the TEE is any *good*. `SECURITY_LEVEL_TRUSTED_ENVIRONMENT`
 *     means "the vendor's KeyMint said so". It is a claim about location, not about quality,
 *     patch level, or the absence of exploitable bugs in the trustlet.
 *   - It will NOT prove a key is unextractable. It reports metadata the platform gives it.
 *   - It will NOT tell you anything about the app you are testing. An app can hold software keys
 *     on a device whose hardware is perfectly capable; that mismatch is the finding, and you need
 *     the app's own keys (see ../labs/lab-01-measure-every-key-type.md) to see it.
 *   - A generation FAILURE here is ambiguous by design: it can mean "the hardware refuses", "the
 *     framework refuses", or "this API level does not have that option". The probe prints the
 *     exception class and message verbatim so you can tell them apart yourself.
 *
 * SAFETY
 *   Every key it creates carries the alias prefix and is deleted in a finally block unless --keep
 *   is given. It touches no key it did not create. It never prints private key material — there is
 *   none to print; Keystore keys have no exportable bytes.
 */

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;

import java.lang.reflect.Method;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public class SecurityLevelProbe {

    private static String PREFIX = "ch50_probe_";
    private static boolean KEEP = false;
    private static boolean ATTEST = false;

    private static final List<String> CREATED = new ArrayList<String>();

    // ---------------------------------------------------------------- bootstrap

    /**
     * app_process does not install the AndroidKeyStore JCA provider — that happens in
     * ZygoteInit/RuntimeInit on the app path. Without this, KeyStore.getInstance("AndroidKeyStore")
     * throws "AndroidKeyStore KeyStore not available" and beginners conclude the device has no
     * keystore. It does; the provider simply was never registered in this VM.
     */
    private static String installProvider() {
        String[] candidates = {
            "android.security.keystore2.AndroidKeyStoreProvider",   // Android 12+ (keystore2)
            "android.security.keystore.AndroidKeyStoreProvider"     // Android 6-11 (legacy)
        };
        for (String cls : candidates) {
            try {
                Class<?> c = Class.forName(cls);
                Method m = c.getMethod("install");
                m.invoke(null);
                return cls;
            } catch (Throwable ignored) {
                // try the next one
            }
        }
        return null;
    }

    /**
     * On Android 11 and earlier the LEGACY provider reaches back for an application Context:
     *
     *   java.lang.IllegalStateException: Failed to obtain application Context from ActivityThread
     *       at android.security.KeyStore.getApplicationContext(KeyStore.java)
     *       at android.security.keystore.AndroidKeyStoreSpi.engineLoad(AndroidKeyStoreSpi.java)
     *
     * (that trace is captured verbatim from a Redmi M2101K6P on Android 11). There is no
     * application in an app_process invocation, so we manufacture the system context instead.
     * Android 12+ / keystore2 does not need this — it talks to the daemon over Binder directly.
     *
     * Returns a one-line description of what happened, for the report header.
     */
    private static String bootstrapContext() {
        try {
            android.os.Looper.prepareMainLooper();
        } catch (Throwable ignored) {
            // already prepared
        }
        try {
            Class<?> atc = Class.forName("android.app.ActivityThread");
            Object at = atc.getMethod("systemMain").invoke(null);
            Object ctx = atc.getMethod("getSystemContext").invoke(at);
            return "ActivityThread.systemMain() -> " + (ctx == null ? "null" : ctx.getClass().getName());
        } catch (Throwable t) {
            Throwable c = t.getCause() == null ? t : t.getCause();
            return "FAILED: " + c.getClass().getName() + ": " + c.getMessage();
        }
    }

    private static String levelName(int level) {
        switch (level) {
            case 0:  return "SOFTWARE";
            case 1:  return "TRUSTED_ENVIRONMENT";
            case 2:  return "STRONGBOX";
            case -1: return "UNKNOWN";
            case -2: return "UNKNOWN_SECURE";
            default: return "UNRECOGNISED(" + level + ")";
        }
    }

    // ---------------------------------------------------------------- reporting

    private static void row(String label, String verdict, String detail) {
        System.out.println(String.format("%-34s %-22s %s", label, verdict, detail == null ? "" : detail));
    }

    /** Read back what we actually got, for a symmetric key. */
    private static void reportSecret(String label, SecretKey key) {
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = (KeyInfo) f.getKeySpec(key, KeyInfo.class);
            report(label, info, key.getEncoded());
        } catch (Throwable t) {
            row(label, "READBACK-FAILED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    /** Read back what we actually got, for an asymmetric key. */
    private static void reportPrivate(String label, PrivateKey key) {
        try {
            KeyFactory f = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo info = f.getKeySpec(key, KeyInfo.class);
            report(label, info, key.getEncoded());
        } catch (Throwable t) {
            row(label, "READBACK-FAILED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static void report(String label, KeyInfo info, byte[] encoded) {
        int level;
        String levelSource;
        try {
            // getSecurityLevel() is API 31+. On older platforms fall back to the boolean.
            Method m = KeyInfo.class.getMethod("getSecurityLevel");
            level = ((Integer) m.invoke(info)).intValue();
            levelSource = "getSecurityLevel()";
        } catch (Throwable t) {
            level = info.isInsideSecureHardware() ? 1 : 0;
            levelSource = "isInsideSecureHardware()";
        }

        StringBuilder d = new StringBuilder();
        d.append("bits=").append(info.getKeySize());
        d.append(" via=").append(levelSource);
        d.append(" origin=").append(info.isInsideSecureHardware() ? "secure-hw" : "software");
        d.append(" userAuthReq=").append(info.isUserAuthenticationRequired());
        try {
            Method m = KeyInfo.class.getMethod("isUserAuthenticationRequirementEnforcedBySecureHardware");
            d.append(" authEnforcedByHw=").append(m.invoke(info));
        } catch (Throwable ignored) { }
        // getEncoded() MUST be null for a Keystore key. If it is not, the key is not in the
        // Keystore at all and every "hardware-backed" claim about it is false.
        d.append(" getEncoded=").append(encoded == null ? "null(correct)" : ("!!" + encoded.length + " BYTES LEAKED!!"));

        row(label, levelName(level), d.toString());
    }

    // ---------------------------------------------------------------- generators

    private static void probeAes(int bits, boolean strongBox, String label) {
        String alias = PREFIX + "aes" + bits + (strongBox ? "_sb" : "");
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(bits)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE);
            if (strongBox) b.setIsStrongBoxBacked(true);
            kg.init(b.build());
            SecretKey k = kg.generateKey();
            CREATED.add(alias);
            reportSecret(label, k);
        } catch (StrongBoxUnavailableException e) {
            row(label, "STRONGBOX-ABSENT", "StrongBoxUnavailableException — this device has no secure element");
        } catch (Throwable t) {
            row(label, "REFUSED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static void probeHmac(String alg, String label) {
        String alias = PREFIX + alg.toLowerCase();
        try {
            KeyGenerator kg = KeyGenerator.getInstance(alg, "AndroidKeyStore");
            kg.init(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .build());
            SecretKey k = kg.generateKey();
            CREATED.add(alias);
            reportSecret(label, k);
        } catch (Throwable t) {
            row(label, "REFUSED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static void probe3des(String label) {
        String alias = PREFIX + "3des";
        try {
            KeyGenerator kg = KeyGenerator.getInstance("DESede", "AndroidKeyStore");
            kg.init(new KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            SecretKey k = kg.generateKey();
            CREATED.add(alias);
            reportSecret(label, k);
        } catch (Throwable t) {
            row(label, "REFUSED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static void probeRsa(int bits, boolean strongBox, String label) {
        String alias = PREFIX + "rsa" + bits + (strongBox ? "_sb" : "");
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setAlgorithmParameterSpec(new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4));
            if (strongBox) b.setIsStrongBoxBacked(true);
            kpg.initialize(b.build());
            CREATED.add(alias);
            reportPrivate(label, kpg.generateKeyPair().getPrivate());
        } catch (StrongBoxUnavailableException e) {
            row(label, "STRONGBOX-ABSENT", "StrongBoxUnavailableException");
        } catch (Throwable t) {
            row(label, "REFUSED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static void probeEc(String curve, boolean strongBox, String label) {
        String alias = PREFIX + "ec_" + curve.replace("-", "").toLowerCase() + (strongBox ? "_sb" : "");
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(curve));
            if (strongBox) b.setIsStrongBoxBacked(true);
            kpg.initialize(b.build());
            CREATED.add(alias);
            reportPrivate(label, kpg.generateKeyPair().getPrivate());
        } catch (StrongBoxUnavailableException e) {
            row(label, "STRONGBOX-ABSENT", "StrongBoxUnavailableException");
        } catch (Throwable t) {
            row(label, "REFUSED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    /**
     * Rollback resistance: the key is guaranteed destroyed on delete, so restoring an old flash
     * image cannot resurrect it. Very few devices implement it; the call throws when they do not.
     */
    private static void probeRollbackResistance() {
        String alias = PREFIX + "rollback";
        try {
            Method setter = KeyGenParameterSpec.Builder.class.getMethod("setRollbackResistant", boolean.class);
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE);
            setter.invoke(b, Boolean.TRUE);
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(b.build());
            SecretKey k = kg.generateKey();
            CREATED.add(alias);
            reportSecret("AES-256 rollback-resistant", k);
        } catch (NoSuchMethodException e) {
            row("AES-256 rollback-resistant", "NO-PUBLIC-API",
                "setRollbackResistant is @hide on this platform — only KeyMint can be asked directly");
        } catch (Throwable t) {
            Throwable c = t.getCause() == null ? t : t.getCause();
            row("AES-256 rollback-resistant", "REFUSED", c.getClass().getSimpleName() + ": " + c.getMessage());
        }
    }

    /** Hardware-enforced use counter. Rare; when present the key self-destructs after N uses. */
    private static void probeMaxUsageCount() {
        String alias = PREFIX + "maxuse";
        try {
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(new KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setMaxUsageCount(1)
                    .build());
            SecretKey k = kg.generateKey();
            CREATED.add(alias);
            reportSecret("AES-128 setMaxUsageCount(1)", k);
        } catch (Throwable t) {
            row("AES-128 setMaxUsageCount(1)", "REFUSED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    /**
     * An auth-bound key. Generation succeeding proves only that the device HAS a secure lock
     * screen; the binding is not tested until you try to use the key.
     */
    private static void probeAuthBound() {
        String alias = PREFIX + "authbound";
        try {
            KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true);
            try {
                Method m = KeyGenParameterSpec.Builder.class.getMethod(
                        "setUserAuthenticationParameters", int.class, int.class);
                m.invoke(b, Integer.valueOf(0), Integer.valueOf(3)); // 0s = per-use; 3 = BIOMETRIC_STRONG|DEVICE_CREDENTIAL
            } catch (NoSuchMethodException e) {
                b.setUserAuthenticationValidityDurationSeconds(-1);
            }
            KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            kg.init(b.build());
            SecretKey k = kg.generateKey();
            CREATED.add(alias);
            reportSecret("AES-256 auth-bound (per-use)", k);
        } catch (Throwable t) {
            Throwable c = t.getCause() == null ? t : t.getCause();
            // "Gatekeeper service not available" has TWO causes and this probe cannot tell them
            // apart. Do not guess in the output; name both and say how to settle it.
            row("AES-256 auth-bound (per-use)", "REFUSED",
                c.getClass().getSimpleName() + ": " + c.getMessage());
            if (String.valueOf(c.getMessage()).contains("Gatekeeper")) {
                row("", "^ two possible causes",
                    "(a) no lock-screen credential is set, so Gatekeeper holds no password handle "
                    + "and the Secure User ID is 0; (b) the shell domain cannot reach "
                    + "IGateKeeperService. Settle it with: adb shell dumpsys lock_settings "
                    + "| grep -E 'SID|CredentialType'  -- SID 0 / CredentialType None means (a).");
            }
        }
    }

    /** Ask for an attestation chain and report what came back, without contacting anybody. */
    private static void probeAttestation(KeyStore ks) {
        String alias = PREFIX + "attested";
        try {
            byte[] challenge = new byte[32];
            new java.security.SecureRandom().nextBytes(challenge);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            kpg.initialize(new KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setAttestationChallenge(challenge)
                    .build());
            kpg.generateKeyPair();
            CREATED.add(alias);
            Certificate[] chain = ks.getCertificateChain(alias);
            row("EC P-256 + attestation", "CHAIN-LENGTH-" + (chain == null ? 0 : chain.length),
                "challenge=" + hex(challenge));
            if (chain != null) {
                for (int i = 0; i < chain.length; i++) {
                    java.security.cert.X509Certificate x = (java.security.cert.X509Certificate) chain[i];
                    row("  cert[" + i + "]", "subject", String.valueOf(x.getSubjectDN()));
                    row("  cert[" + i + "]", "issuer", String.valueOf(x.getIssuerDN()));
                    byte[] ext = x.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");
                    row("  cert[" + i + "]", ext == null ? "no-attestation-ext" : "attestation-ext",
                        ext == null ? "" : (ext.length + " bytes"));
                }
                if (ATTEST) {
                    System.out.println("----- BEGIN CHAIN (PEM, feed to parse-attestation.py) -----");
                    for (Certificate c : chain) {
                        System.out.println("-----BEGIN CERTIFICATE-----");
                        System.out.println(base64(c.getEncoded()));
                        System.out.println("-----END CERTIFICATE-----");
                    }
                    System.out.println("----- END CHAIN -----");
                }
            }
        } catch (Throwable t) {
            row("EC P-256 + attestation", "REFUSED", t.getClass().getSimpleName() + ": " + t.getMessage());
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", Integer.valueOf(x & 0xff)));
        return s.toString();
    }

    private static String base64(byte[] b) {
        // android.util.Base64 is always present; java.util.Base64 is API 26+.
        String s = android.util.Base64.encodeToString(b, android.util.Base64.NO_WRAP);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i += 64) {
            out.append(s, i, Math.min(i + 64, s.length()));
            if (i + 64 < s.length()) out.append('\n');
        }
        return out.toString();
    }

    // ---------------------------------------------------------------- main

    public static void main(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("--keep".equals(args[i])) KEEP = true;
            else if ("--attest".equals(args[i])) ATTEST = true;
            else if ("--prefix".equals(args[i]) && i + 1 < args.length) PREFIX = args[++i];
            else if ("--wait".equals(args[i]) && i + 1 < args.length) {
                // Idle before doing anything, so that a Frida session can attach to this process
                // by name. Used to exercise ./hook-security-level.js without installing an APK.
                int secs = Integer.parseInt(args[++i]);
                System.out.println("waiting " + secs + "s for an instrumentation attach"
                                   + " (pid " + android.os.Process.myPid() + ") ...");
                try { Thread.sleep(secs * 1000L); } catch (InterruptedException ignored) { }
            }
        }

        System.out.println("=== Chapter 50 — hardware security level probe ===");
        System.out.println("uid                : " + android.os.Process.myUid());
        System.out.println("device             : " + android.os.Build.MODEL + " / " + android.os.Build.DEVICE);
        System.out.println("android            : " + android.os.Build.VERSION.RELEASE
                                                   + " (API " + android.os.Build.VERSION.SDK_INT + ")");
        System.out.println("board              : " + android.os.Build.BOARD
                                                   + "   hardware=" + android.os.Build.HARDWARE);

        String prov = installProvider();
        System.out.println("provider installed : " + (prov == null ? "FAILED" : prov));
        if (prov == null) {
            System.out.println("Cannot continue: no AndroidKeyStore provider class on this platform.");
            return;
        }
        StringBuilder provs = new StringBuilder();
        for (Provider p : Security.getProviders()) provs.append(p.getName()).append(' ');
        System.out.println("JCA providers      : " + provs.toString().trim());
        System.out.println();

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            System.out.println("context bootstrap  : not needed");
        } catch (Throwable first) {
            // Almost certainly the legacy "Failed to obtain application Context" path. Retry once
            // with a synthesised system context, and say so, rather than reporting a false negative.
            System.out.println("context bootstrap  : needed — " + first.getClass().getSimpleName()
                               + ": " + first.getMessage());
            System.out.println("                     " + bootstrapContext());
            try {
                ks = KeyStore.getInstance("AndroidKeyStore");
                ks.load(null);
            } catch (Throwable second) {
                System.out.println("Cannot open AndroidKeyStore even after bootstrap: " + second);
                return;
            }
        }

        System.out.println(String.format("%-34s %-22s %s", "KEY REQUESTED", "LEVEL ACTUALLY GOT", "DETAIL"));
        System.out.println("---------------------------------------------------------------------------------");

        try {
            probeAes(128, false, "AES-128 GCM");
            probeAes(256, false, "AES-256 GCM");
            probeAes(256, true,  "AES-256 GCM +StrongBox");
            probeHmac(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "HMAC-SHA256");
            probeHmac("HmacSHA512", "HMAC-SHA512");
            probe3des("3DES CBC/PKCS7");
            probeRsa(2048, false, "RSA-2048 PSS SHA-256");
            probeRsa(3072, false, "RSA-3072 PSS SHA-256");
            probeRsa(4096, false, "RSA-4096 PSS SHA-256");
            probeRsa(1024, false, "RSA-1024 (should be refused)");
            probeRsa(2048, true,  "RSA-2048 +StrongBox");
            probeEc("secp256r1", false, "EC P-256");
            probeEc("secp384r1", false, "EC P-384");
            probeEc("secp521r1", false, "EC P-521");
            probeEc("secp256r1", true,  "EC P-256 +StrongBox");
            probeEc("ed25519",   false, "Ed25519");
            probeEc("x25519",    false, "X25519");
            probeRollbackResistance();
            probeMaxUsageCount();
            probeAuthBound();
            probeAttestation(ks);
        } finally {
            System.out.println();
            if (KEEP) {
                System.out.println("--keep given; " + CREATED.size() + " keys left in place: " + CREATED);
            } else {
                int gone = 0;
                for (String alias : CREATED) {
                    try { ks.deleteEntry(alias); gone++; } catch (Throwable ignored) { }
                }
                System.out.println("cleanup: deleted " + gone + " of " + CREATED.size() + " probe keys");
            }
        }
    }
}
