/*
 * labs/ctf-app/Guard.java
 * ---------------------------------------------------------------------------
 * CH38 CTF target — the guard.
 *
 * Read this AFTER you have attempted the challenge in
 * labs/lab-04-ctf-silent-integrity.md. It is shipped as source because this
 * repository never ships binaries, but reading it first turns a two-hour
 * exercise into a five-minute one and you will learn nothing.
 *
 * DESIGN NOTES (for the instructor, and for anyone building something similar)
 *
 *   1. THERE IS NO ERROR MESSAGE. Nothing in this app ever says "tampered",
 *      "integrity", or "signature". A failing check produces a wrong key and a
 *      wrong key produces garbage. The absence of a message is the difficulty.
 *
 *   2. THERE IS NO BOOLEAN AND NO BRANCH. Every check contributes a 64-bit
 *      constant by XOR when it passes, and contributes nothing when it fails.
 *      There is no `if (tampered)` anywhere to invert. Patching a comparison
 *      does not help; you must make the check actually pass, or reconstruct
 *      the state word.
 *
 *   3. THE DECOY IS DELIBERATE. isDeviceCompromised() below is dead code with
 *      an obvious name and an obvious branch. Patching it does nothing at all.
 *      This is not cruelty: it is the single most common real-world experience
 *      in this area, and meeting it in a lab is cheaper than meeting it on an
 *      engagement.
 *
 *   4. THE CHECK RUNS EARLY. EarlyProvider.onCreate() calls sweep(), and a
 *      ContentProvider's onCreate runs BEFORE Application.onCreate. See chapter
 *      38 section 3.12.
 *
 *   5. THE CONSEQUENCE IS LATE. VaultActivity does not reveal anything for
 *      several seconds after launch, and by then the state word was decided in
 *      a completely different class in a completely different lifecycle phase.
 *
 * WHAT THIS IS NOT
 *   It is not a good production design in one respect that matters: a real app
 *   must not silently produce garbage, because a false positive becomes an
 *   unreproducible support ticket. Chapter 38 section 3.14 argues both sides.
 *   Here, silence is the puzzle.
 *
 * AUTHORISED TESTING ONLY. You built this.
 * ---------------------------------------------------------------------------
 */

package com.pentest.ch38.ctf;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicLong;

final class Guard {

    // -----------------------------------------------------------------------
    // Per-check contributions. Each is XOR'd into the state word on PASS.
    //
    // These constants are in classes.dex in plain sight. That is not an
    // oversight: chapter 38 is explicit that the baseline in a client-side
    // check is never a secret. The interesting question is not "can you read
    // these" but "what do you do once you have".
    // -----------------------------------------------------------------------

    private static final long C_SIG = 0x9E3779B97F4A7C15L;
    private static final long C_DBG = 0xC2B2AE3D27D4EB4FL;
    private static final long C_TRC = 0x165667B19E3779F9L;
    private static final long C_MAP = 0x27D4EB2F165667C5L;

    /** Salt for the key derivation. Also not a secret. */
    private static final byte[] SALT = {
        'c', 'h', '3', '8', '-', 'v', 'a', 'u', 'l', 't', '-', 'v', '1'
    };

    /**
     * SHA-256 of the DER encoding of the certificate this build EXPECTS.
     *
     * Filled in by build-ctf.sh from the "developer" keystore it generates.
     * The APK you are given is signed with a DIFFERENT key, which is the whole
     * challenge. Nothing in this repository contains a key or a keystore.
     */
    private static final String EXPECTED_CERT_SHA256 = ExpectedCert.SHA256;

    private static final AtomicLong STATE = new AtomicLong(0L);

    private Guard() { }

    // -----------------------------------------------------------------------
    // Called from EarlyProvider.onCreate(), which runs before
    // Application.onCreate(). By the time any Activity exists, this is done.
    // -----------------------------------------------------------------------

    static void sweep(Context ctx) {
        long s = 0L;
        if (certOk(ctx))   s ^= C_SIG;
        if (notDebug(ctx)) s ^= C_DBG;
        if (noTracer())    s ^= C_TRC;
        if (mapsOk())      s ^= C_MAP;
        STATE.set(s);
    }

    /**
     * The key the vault is unlocked with.
     *
     * Note what is absent: any comparison of STATE against an expected value,
     * and any branch on the result. A wrong state word simply produces a
     * different key. The failure is silent by construction, not by an if.
     */
    static byte[] vaultKey() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(SALT);
            long s = STATE.get();
            for (int i = 0; i < 8; i++) {
                md.update((byte) ((s >>> (8 * i)) & 0xff));   // little-endian
            }
            return md.digest();
        } catch (Exception e) {
            return new byte[32];
        }
    }

    // -----------------------------------------------------------------------
    // The decoy.
    //
    // Obvious name, obvious branch, called by nothing. Patch it all you like.
    // -----------------------------------------------------------------------

    static boolean isDeviceCompromised(Context ctx) {
        try {
            if ((ctx.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                return true;
            }
            return new java.io.File("/system/bin/su").exists();
        } catch (Exception e) {
            return true;
        }
    }

    // =======================================================================
    // The checks. Every one returns false when it could not run: UNKNOWN is
    // not PASS. Chapter 38 section 5.7.
    // =======================================================================

    static boolean certOk(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            Signature[] sigs;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo si = pi.signingInfo;
                if (si == null) return false;
                sigs = si.hasMultipleSigners()
                        ? si.getApkContentsSigners()
                        : si.getSigningCertificateHistory();
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                @SuppressWarnings("deprecation")
                Signature[] legacy = pi.signatures;
                sigs = legacy;
            }
            if (sigs == null) return false;

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (Signature sig : sigs) {
                if (hex(md.digest(sig.toByteArray())).equals(EXPECTED_CERT_SHA256)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean notDebug(Context ctx) {
        try {
            return (ctx.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean noTracer() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    return Integer.parseInt(line.substring(10).trim()) == 0;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        } finally {
            if (r != null) { try { r.close(); } catch (Exception ignored) { } }
        }
    }

    static boolean mapsOk() {
        BufferedReader r = null;
        int n = 0;
        try {
            r = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = r.readLine()) != null) {
                n++;
                String l = line.toLowerCase(java.util.Locale.US);
                if (l.contains("frida") || l.contains("gum-js") || l.contains("linjector")) {
                    return false;
                }
            }
            // A suspiciously SHORT map is itself suspicious. A real app process
            // has thousands of mappings; chapter 38 measured 2,448.
            return n > 50;
        } catch (Exception e) {
            return false;
        } finally {
            if (r != null) { try { r.close(); } catch (Exception ignored) { } }
        }
    }

    static String hex(byte[] d) {
        StringBuilder sb = new StringBuilder(d.length * 2);
        for (byte b : d) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }
}
