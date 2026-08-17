// BiometricProbe.java — measure what a device's biometric stack actually reports and enforces.
//
// PURPOSE
//   Answers, on a real device and without installing an app:
//     1. Which biometric hardware does PackageManager admit to?
//     2. What does BiometricManager.canAuthenticate() return for BIOMETRIC_STRONG,
//        BIOMETRIC_WEAK, DEVICE_CREDENTIAL, and the combinations an app actually writes?
//     3. Does a KeyStore key created with setUserAuthenticationRequired(true) genuinely refuse to
//        initialise a Cipher when nobody has authenticated — and does the HARDWARE enforce that,
//        or only the framework?
//     4. What does KeyInfo report back about the binding that was requested?
//
//   Point 3 is the whole reason this chapter exists. A BiometricPrompt callback returning "success"
//   is a Java boolean; a key that throws UserNotAuthenticatedException is a hardware fact. This
//   probe measures the second thing.
//
// USAGE
//   Do not run this file directly — it is compiled and pushed by its runner:
//
//       ./probe-biometrics.sh                 # probe, print report, delete every key it created
//       ./probe-biometrics.sh --keep          # leave the keys behind (lab-02 needs them)
//       ./probe-biometrics.sh --json          # machine-readable output for diffing across devices
//
//   If you want to run it by hand, the runner ultimately does this:
//       adb push classes.dex /data/local/tmp/ch48-probe.dex
//       adb shell CLASSPATH=/data/local/tmp/ch48-probe.dex app_process /data/local/tmp BiometricProbe
//
// WHY app_process
//   app_process starts a real ART runtime with the whole framework on the classpath, running as
//   uid 2000 (shell). No root, no APK install, no Gradle. It can talk to keystore2 and to
//   system_server over Binder exactly as an app would. What it CANNOT do is show UI, so this probe
//   never displays a BiometricPrompt — it measures the key side of the contract, which is the side
//   that cannot be faked.
//
// WHAT THIS WILL *NOT* TELL YOU
//   - Nothing about the app under test. It measures the DEVICE's capability and enforcement. An app
//     can sit far below that ceiling, and that gap is the finding.
//   - It cannot prove a fingerprint sensor is Class 3. It reports what the framework claims.
//   - Running as uid 2000 is not running as an app. Where the shell package's permissions differ
//     from a third-party app's, the answer differs too. The probe prints its own uid and package so
//     you can judge; confirm anything load-bearing from an installed APK.
//
// SAFETY
//   Every key it creates is named with the CH48_PREFIX below and is deleted on exit unless --keep
//   is passed. It never touches a key it did not create, and it enumerates-then-filters rather than
//   wildcarding a delete.
//
// COMPILES AGAINST any android.jar API 30+. Everything newer than API 30 is reached by reflection,
// because chapter 50 measured a documented API-31 method throwing NoSuchMethodError on an API 30
// device — compiling against a new jar does not make an old device grow the method.

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public final class BiometricProbe {

    /** Every key this probe creates starts with this. Nothing else is ever touched. */
    private static final String CH48_PREFIX = "ch48_probe_";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

    // android.hardware.biometrics.BiometricManager.Authenticators — inlined so the file compiles
    // against an android.jar that predates the constants, and so the reader can see the bit
    // patterns rather than the names. These ARE the values; §3 of the chapter derives them.
    private static final int BIOMETRIC_STRONG      = 0x000F;   // Class 3
    private static final int BIOMETRIC_WEAK        = 0x00FF;   // Class 2 (a SUPERSET of STRONG)
    private static final int DEVICE_CREDENTIAL     = 1 << 15;  // 0x8000 — PIN/pattern/password

    private static boolean jsonMode = false;
    private static boolean keepKeys = false;
    private static final Map<String, String> results = new LinkedHashMap<String, String>();

    public static void main(String[] args) {
        for (String a : args) {
            if ("--json".equals(a)) jsonMode = true;
            if ("--keep".equals(a)) keepKeys = true;
        }

        header("DEVICE");
        record("model", prop("ro.product.model"));
        record("android.release", prop("ro.build.version.release"));
        record("android.sdk", prop("ro.build.version.sdk"));
        record("security.patch", prop("ro.build.version.security_patch"));
        record("probe.uid", String.valueOf(android.os.Process.myUid()));

        record("provider.install", installKeyStoreProvider());

        Context ctx = obtainContext();
        record("context", ctx == null ? "UNAVAILABLE" : ctx.getPackageName());

        header("HARDWARE FEATURES (PackageManager)");
        probeFeatures(ctx);

        header("BiometricManager.canAuthenticate()");
        probeCanAuthenticate(ctx);

        header("FingerprintManager (deprecated path)");
        probeFingerprintManager(ctx);

        header("KEYSTORE AUTH BINDING — the part that cannot be faked");
        probeAuthBoundKeys();

        header("CLEANUP");
        cleanup();

        if (jsonMode) emitJson();
    }

    // ---------------------------------------------------------------------------------------------
    // app_process does NOT install the AndroidKeyStore JCA provider — that happens on the app path,
    // in ZygoteInit/RuntimeInit. Without this call every KeyStore.getInstance("AndroidKeyStore")
    // throws "AndroidKeyStore KeyStore not available" and a beginner concludes the device has no
    // hardware keystore. This is chapter 50's finding, reused verbatim; see
    // ../../50-HardwareBackedSecurity/scripts/SecurityLevelProbe.java.
    // ---------------------------------------------------------------------------------------------
    private static String installKeyStoreProvider() {
        String[] candidates = {
                "android.security.keystore2.AndroidKeyStoreProvider",  // Android 12+ (keystore2)
                "android.security.keystore.AndroidKeyStoreProvider",   // Android 6-11 (legacy)
        };
        for (String cn : candidates) {
            try {
                Class<?> c = Class.forName(cn);
                Method m = c.getMethod("install");
                m.invoke(null);
                return cn;
            } catch (Throwable ignored) {
                // Wrong platform generation, or the method moved. Try the next one.
            }
        }
        return "FAILED — no AndroidKeyStoreProvider class installed; key results below are void";
    }

    // ---------------------------------------------------------------------------------------------
    // Context. app_process gives us no Application, so we borrow the system context the same way
    // every shell-side framework tool does. This is a hidden API; if it is blocked we degrade to a
    // KeyStore-only run rather than dying, because the KeyStore half needs no Context at all.
    // ---------------------------------------------------------------------------------------------
    private static Context obtainContext() {
        try {
            Class<?> looper = Class.forName("android.os.Looper");
            try {
                looper.getMethod("prepareMainLooper").invoke(null);
            } catch (Throwable ignored) {
                // Already prepared, or prepared by app_process. Not fatal.
            }
            Class<?> at = Class.forName("android.app.ActivityThread");
            Object thread = at.getMethod("systemMain").invoke(null);
            Method getCtx = at.getMethod("getSystemContext");
            return (Context) getCtx.invoke(thread);
        } catch (Throwable t) {
            note("context unavailable: " + rootCause(t));
            return null;
        }
    }

    // ---------------------------------------------------------------------------------------------
    private static void probeFeatures(Context ctx) {
        String[] features = {
                "android.hardware.fingerprint",
                "android.hardware.biometrics.face",
                "android.hardware.biometrics.iris",
                "android.hardware.strongbox_keystore",
                "android.software.device_id_attestation",
        };
        if (ctx == null) {
            // pm(1) is always reachable, so fall back to it rather than reporting nothing.
            note("no Context — read features with: adb shell pm list features | grep -i biometric");
            for (String f : features) record("feature." + f, "UNKNOWN (no Context)");
            return;
        }
        PackageManager pm = ctx.getPackageManager();
        for (String f : features) {
            record("feature." + f, String.valueOf(pm.hasSystemFeature(f)));
        }
    }

    // ---------------------------------------------------------------------------------------------
    private static void probeCanAuthenticate(Context ctx) {
        if (ctx == null) { note("skipped — no Context"); return; }
        Object bm;
        try {
            Class<?> bmClass = Class.forName("android.hardware.biometrics.BiometricManager");
            bm = ctx.getSystemService(bmClass);
            if (bm == null) { record("BiometricManager", "getSystemService returned null"); return; }
        } catch (Throwable t) {
            record("BiometricManager", "unavailable: " + rootCause(t));
            return;
        }

        // Every combination an app is realistically written with, plus the two that are subtly wrong.
        int[][] combos = {
                {BIOMETRIC_STRONG,                       0},
                {BIOMETRIC_WEAK,                         0},
                {DEVICE_CREDENTIAL,                      0},
                {BIOMETRIC_STRONG | DEVICE_CREDENTIAL,   0},
                {BIOMETRIC_WEAK   | DEVICE_CREDENTIAL,   0},
        };
        String[] names = {
                "BIOMETRIC_STRONG",
                "BIOMETRIC_WEAK",
                "DEVICE_CREDENTIAL",
                "BIOMETRIC_STRONG|DEVICE_CREDENTIAL",
                "BIOMETRIC_WEAK|DEVICE_CREDENTIAL",
        };

        Method m1 = null;
        try { m1 = bm.getClass().getMethod("canAuthenticate", int.class); } catch (Throwable ignored) { }

        if (m1 == null) {
            record("canAuthenticate(int)", "ABSENT — device predates API 30");
        } else {
            for (int i = 0; i < combos.length; i++) {
                try {
                    Object r = m1.invoke(bm, combos[i][0]);
                    int code = ((Integer) r).intValue();
                    record("canAuthenticate(" + names[i] + ")", code + "  " + decodeCanAuth(code));
                } catch (Throwable t) {
                    record("canAuthenticate(" + names[i] + ")", "THREW " + rootCause(t));
                }
            }
        }

        // The API-29 no-arg form, which thousands of apps still call. It is defined as equivalent to
        // canAuthenticate(BIOMETRIC_WEAK) — worth showing the two side by side.
        try {
            Method m0 = bm.getClass().getMethod("canAuthenticate");
            Object r = m0.invoke(bm);
            int code = ((Integer) r).intValue();
            record("canAuthenticate()  [API 29 no-arg]", code + "  " + decodeCanAuth(code));
        } catch (Throwable t) {
            record("canAuthenticate()  [API 29 no-arg]", "unavailable: " + rootCause(t));
        }
    }

    private static String decodeCanAuth(int code) {
        switch (code) {
            case  0: return "BIOMETRIC_SUCCESS — a prompt would appear and could succeed";
            case  1: return "ERROR_HW_UNAVAILABLE — hardware exists, temporarily busy/locked out";
            case 11: return "ERROR_NONE_ENROLLED — hardware exists, user has enrolled nothing";
            case 12: return "ERROR_NO_HARDWARE — no sensor of this class";
            case 15: return "ERROR_SECURITY_UPDATE_REQUIRED — sensor downgraded below the requested class";
            case -1: return "STATUS_UNKNOWN — cannot tell without trying (API 30+)";
            case -2: return "ERROR_UNSUPPORTED — this authenticator combination is not supported here";
            default: return "undocumented code";
        }
    }

    // ---------------------------------------------------------------------------------------------
    private static void probeFingerprintManager(Context ctx) {
        if (ctx == null) { note("skipped — no Context"); return; }
        try {
            Class<?> fmClass = Class.forName("android.hardware.fingerprint.FingerprintManager");
            Object fm = ctx.getSystemService(fmClass);
            if (fm == null) { record("FingerprintManager", "getSystemService returned null"); return; }
            try {
                Object hw = fmClass.getMethod("isHardwareDetected").invoke(fm);
                record("isHardwareDetected()", String.valueOf(hw));
            } catch (Throwable t) {
                record("isHardwareDetected()", "THREW " + rootCause(t));
            }
            try {
                Object en = fmClass.getMethod("hasEnrolledFingerprints").invoke(fm);
                record("hasEnrolledFingerprints()", String.valueOf(en));
            } catch (Throwable t) {
                record("hasEnrolledFingerprints()", "THREW " + rootCause(t));
            }
        } catch (Throwable t) {
            record("FingerprintManager", "unavailable: " + rootCause(t));
        }
    }

    // ---------------------------------------------------------------------------------------------
    // The measurement that matters. Six key configurations; for each we record what the framework
    // accepted at creation, what KeyInfo says was actually stored, and what happens when we try to
    // USE the key with nobody authenticated.
    // ---------------------------------------------------------------------------------------------
    private static void probeAuthBoundKeys() {
        int sdk = intProp("ro.build.version.sdk", 0);

        // name, authRequired, validitySeconds (-1 = per-use), invalidatedByEnrolment
        Object[][] specs = {
                {"baseline",        Boolean.FALSE, Integer.valueOf(-1), Boolean.TRUE },
                {"peruse",          Boolean.TRUE,  Integer.valueOf(-1), Boolean.TRUE },
                {"peruse_noinval",  Boolean.TRUE,  Integer.valueOf(-1), Boolean.FALSE},
                {"timebound_30",    Boolean.TRUE,  Integer.valueOf(30), Boolean.TRUE },
                {"timebound_1",     Boolean.TRUE,  Integer.valueOf(1),  Boolean.TRUE },
                {"timebound_86400", Boolean.TRUE,  Integer.valueOf(86400), Boolean.TRUE},
        };

        for (Object[] s : specs) {
            String alias = CH48_PREFIX + s[0];
            boolean authReq  = ((Boolean) s[1]).booleanValue();
            int     validity = ((Integer) s[2]).intValue();
            boolean inval    = ((Boolean) s[3]).booleanValue();

            String created;
            try {
                KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                        alias,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256);

                if (authReq) {
                    b.setUserAuthenticationRequired(true);
                    if (validity >= 0) {
                        // Deprecated at API 30 in favour of setUserAuthenticationParameters, but it
                        // is what the overwhelming majority of shipped apps call, so measure it.
                        b.setUserAuthenticationValidityDurationSeconds(validity);
                    }
                    b.setInvalidatedByBiometricEnrollment(inval);
                }

                KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
                kg.init(b.build());
                kg.generateKey();
                created = "OK";
            } catch (Throwable t) {
                created = "REFUSED AT CREATION: " + rootCause(t);
                record("key." + s[0] + ".create", created);
                continue;
            }
            record("key." + s[0] + ".create", created);

            // --- what does the KeyStore say it stored? ---
            try {
                KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
                ks.load(null);
                Key k = ks.getKey(alias, null);
                SecretKeyFactory f = SecretKeyFactory.getInstance(k.getAlgorithm(), ANDROID_KEYSTORE);
                KeyInfo info = (KeyInfo) f.getKeySpec((SecretKey) k, KeyInfo.class);

                record("key." + s[0] + ".authRequired", String.valueOf(info.isUserAuthenticationRequired()));
                record("key." + s[0] + ".validitySeconds",
                        String.valueOf(info.getUserAuthenticationValidityDurationSeconds()));
                record("key." + s[0] + ".enforcedBySecureHardware",
                        String.valueOf(info.isUserAuthenticationRequirementEnforcedBySecureHardware()));
                record("key." + s[0] + ".invalidatedByEnrolment",
                        String.valueOf(info.isInvalidatedByBiometricEnrollment()));

                // API 30: which authenticator classes may satisfy the key.
                record("key." + s[0] + ".authType", reflectInt(info, "getUserAuthenticationType", sdk, 30));
                // API 31: TEE vs STRONGBOX vs SOFTWARE. Chapter 50 owns this; recorded for correlation.
                record("key." + s[0] + ".securityLevel", reflectSecurityLevel(info, sdk));

            } catch (Throwable t) {
                record("key." + s[0] + ".keyinfo", "THREW " + rootCause(t));
            }

            // --- can we USE it with nobody authenticated? ---
            record("key." + s[0] + ".cipherInit", tryUse(alias));
        }
    }

    /**
     * The single most important line of output this probe produces.
     *
     * A key with setUserAuthenticationRequired(true) must refuse to initialise a Cipher unless a
     * hardware auth token proves someone authenticated recently enough. The refusal arrives as
     * UserNotAuthenticatedException, and it comes from KeyMint/Keymaster, not from Java code an
     * attacker can hook. "OK" here for an auth-required key would mean the binding is not enforced.
     */
    private static String tryUse(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            SecretKey k = (SecretKey) ks.getKey(alias, null);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, k);
            byte[] ct = c.doFinal("ch48".getBytes("UTF-8"));
            return "OK — encrypted " + ct.length + " bytes with NO authentication";
        } catch (UserNotAuthenticatedException e) {
            return "UserNotAuthenticatedException — HARDWARE REFUSED (this is the correct answer)";
        } catch (Throwable t) {
            String rc = rootCause(t);
            if (rc.contains("UserNotAuthenticated")) {
                return "UserNotAuthenticatedException (wrapped) — HARDWARE REFUSED";
            }
            if (rc.contains("KeyPermanentlyInvalidated")) {
                return "KeyPermanentlyInvalidatedException — enrolment changed since key creation";
            }
            return "THREW " + rc;
        }
    }

    // ---------------------------------------------------------------------------------------------
    private static void cleanup() {
        if (keepKeys) {
            note("--keep given: leaving " + CH48_PREFIX + "* in place. Re-run without --keep to remove.");
            return;
        }
        int removed = 0;
        List<String> failed = new ArrayList<String>();
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            List<String> victims = new ArrayList<String>();
            Enumeration<String> e = ks.aliases();
            while (e.hasMoreElements()) {
                String a = e.nextElement();
                if (a.startsWith(CH48_PREFIX)) victims.add(a);   // filter, never wildcard
            }
            Collections.sort(victims);
            for (String a : victims) {
                try { ks.deleteEntry(a); removed++; } catch (Throwable t) { failed.add(a); }
            }
        } catch (Throwable t) {
            note("cleanup failed: " + rootCause(t));
        }
        record("keysDeleted", String.valueOf(removed));
        if (!failed.isEmpty()) record("keysLEFTBEHIND", failed.toString());
    }

    // ---------------------------------------------------------------------------------------------
    // reflection helpers — every API above 30 goes through these
    // ---------------------------------------------------------------------------------------------
    private static String reflectInt(Object target, String method, int sdk, int minSdk) {
        if (sdk < minSdk) return "n/a (needs API " + minSdk + ", device is " + sdk + ")";
        try {
            Object v = target.getClass().getMethod(method).invoke(target);
            int i = ((Integer) v).intValue();
            StringBuilder sb = new StringBuilder(String.valueOf(i));
            if ((i & 0x1) != 0) sb.append(" AUTH_DEVICE_CREDENTIAL");
            if ((i & 0x2) != 0) sb.append(" AUTH_BIOMETRIC_STRONG");
            return sb.toString();
        } catch (NoSuchMethodError e) {
            return "NoSuchMethodError — documented at this API level but ABSENT on this device";
        } catch (Throwable t) {
            return "unavailable: " + rootCause(t);
        }
    }

    private static String reflectSecurityLevel(Object info, int sdk) {
        if (sdk >= 31) {
            try {
                Object v = info.getClass().getMethod("getSecurityLevel").invoke(info);
                int i = ((Integer) v).intValue();
                switch (i) {
                    case -2: return "UNKNOWN_SECURE";
                    case -1: return "UNKNOWN";
                    case  0: return "SOFTWARE";
                    case  1: return "TRUSTED_ENVIRONMENT (TEE)";
                    case  2: return "STRONGBOX";
                    default: return "code " + i;
                }
            } catch (Throwable ignored) { /* fall through to the deprecated reader */ }
        }
        try {
            Object v = info.getClass().getMethod("isInsideSecureHardware").invoke(info);
            return "isInsideSecureHardware=" + v + " (deprecated reader; API " + sdk + ")";
        } catch (Throwable t) {
            return "unavailable: " + rootCause(t);
        }
    }

    // ---------------------------------------------------------------------------------------------
    private static String prop(String key) {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class);
            Object v = get.invoke(null, key);
            String s = String.valueOf(v);
            return s.isEmpty() ? "(unset)" : s;
        } catch (Throwable t) {
            return "(unreadable)";
        }
    }

    private static int intProp(String key, int dflt) {
        try { return Integer.parseInt(prop(key).trim()); } catch (Throwable t) { return dflt; }
    }

    private static String rootCause(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) c = c.getCause();
        String msg = c.getMessage();
        return c.getClass().getName() + (msg == null ? "" : ": " + msg);
    }

    private static void header(String s) {
        if (jsonMode) return;
        System.out.println();
        System.out.println("== " + s + " " + repeat('=', Math.max(0, 74 - s.length())));
    }

    private static void record(String k, String v) {
        results.put(k, v);
        if (!jsonMode) System.out.printf("  %-42s %s%n", k, v);
    }

    private static void note(String s) {
        if (!jsonMode) System.out.println("  ! " + s);
    }

    private static String repeat(char c, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(c);
        return sb.toString();
    }

    private static void emitJson() {
        StringBuilder sb = new StringBuilder("{\n");
        int i = 0, n = results.size();
        for (Map.Entry<String, String> e : results.entrySet()) {
            sb.append("  \"").append(esc(e.getKey())).append("\": \"").append(esc(e.getValue())).append('"');
            if (++i < n) sb.append(',');
            sb.append('\n');
        }
        sb.append("}");
        System.out.println(sb);
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\t", " ");
    }

    // Kept so a reader grepping for the field-reflection idiom finds one; unused otherwise.
    @SuppressWarnings("unused")
    private static int constant(String cls, String field, int dflt) {
        try {
            Class<?> c = Class.forName(cls);
            Field f = c.getDeclaredField(field);
            f.setAccessible(true);
            return f.getInt(null);
        } catch (Throwable t) {
            return dflt;
        }
    }
}
