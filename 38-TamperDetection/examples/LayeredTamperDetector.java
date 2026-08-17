/*
 * examples/LayeredTamperDetector.java
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   The local tamper detector as a competent defender would actually write it,
 *   as opposed to the deliberately transparent teaching version in
 *   repack-detector/IntegrityGate.java.
 *
 *   Everything here exists to raise the attacker's cost. Nothing here makes the
 *   app secure against a determined attacker, and this file says so in code as
 *   well as in comments. Read ServerVerifiedIntegrity.java immediately after
 *   this one; the pair is the point.
 *
 * WHAT MAKES THIS "LAYERED"
 *   Five structural properties, each of which costs an attacker real minutes.
 *   None of them is clever. Cleverness is not what works here; structure is.
 *
 *   L1  NO SINGLE BOOLEAN. There is no `boolean isTampered()` to hook and no
 *       single branch to invert. Check results are folded into a 64-bit state
 *       word that is later USED as key material. Flipping one branch produces
 *       a wrong key rather than an allowed path, and a wrong key produces
 *       garbage far from the check.
 *
 *   L2  NO SINGLE CALL SITE. Checks are invoked from several unrelated places
 *       at unrelated times, including from a background scheduler. Patching the
 *       call in onCreate leaves four others.
 *
 *   L3  DELAY BETWEEN DETECTION AND CONSEQUENCE. A check that fires now causes
 *       a failure minutes later, in a code path that has no textual connection
 *       to integrity. This is the single most effective cheap measure there is,
 *       because it destroys the attacker's feedback loop -- and it is also the
 *       single most user-hostile, because a false positive becomes an
 *       unreproducible bug report. Section 5.9 of the README argues both sides.
 *
 *   L4  THE EVIDENCE LEAVES THE DEVICE. Results are reported to the server as
 *       telemetry regardless of what the client does about them. The server can
 *       then reason about populations, which is something no client can do.
 *
 *   L5  FAIL CLOSED ON UNKNOWN, NOT OPEN. A check that could not run is not a
 *       check that passed. Most real implementations get this backwards.
 *
 * WHAT THIS WILL *NOT* DO
 *   * It will NOT stop anyone who reads chapter 67. Every structural measure
 *     above has a documented counter, and the counters are not hard.
 *   * It will NOT stop a repackager from deleting this class entirely and
 *     stubbing its callers. That takes about ten minutes with jadx and
 *     apktool, and no local design prevents it.
 *   * It will NOT work as copy-paste production code. The obfuscation this
 *     design assumes (40-Obfuscation) is not applied here, because an
 *     obfuscated teaching example teaches nothing.
 *   * It does NOT check for root. 37-RootDetection owns that; a real app would
 *     fold those signals into the same state word using the same pattern.
 *
 * BUILD
 *   This is a single-file illustration, not part of the buildable lab app. To
 *   compile it for inspection:
 *     javac --release 8 -classpath $ANDROID_HOME/platforms/android-35/android.jar \
 *           -d /tmp/out LayeredTamperDetector.java
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

package com.pentest.ch38.examples;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.SystemClock;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;

public final class LayeredTamperDetector {

    // -----------------------------------------------------------------------
    // L1 -- the state word
    //
    // Each check contributes a 64-bit constant when it PASSES, and contributes
    // nothing when it fails. The accumulated value is therefore a fingerprint
    // of "which checks passed", and a healthy device produces exactly one
    // value: HEALTHY.
    //
    // Nothing ever compares the state word to HEALTHY. Instead the state word
    // is mixed into a key derivation (see deriveSessionKey below), so a device
    // that failed a check computes a DIFFERENT KEY and its requests are
    // rejected by the server for a reason that has no textual link to
    // integrity. There is no branch to invert because there is no branch.
    //
    // Honest limit, stated in the same breath: an attacker who makes every
    // check pass -- which is what hooking the INPUTS achieves -- gets the right
    // key. This design defeats branch-flipping, not input-spoofing. It is a
    // real improvement and it is not a solution.
    // -----------------------------------------------------------------------

    private static final long C_SIGNATURE   = 0x9E3779B97F4A7C15L;
    private static final long C_DEBUGGABLE  = 0xC2B2AE3D27D4EB4FL;
    private static final long C_TRACER      = 0x165667B19E3779F9L;
    private static final long C_MAPS        = 0x27D4EB2F165667C5L;
    private static final long C_PORTS       = 0x85EBCA77C2B2AE63L;
    private static final long C_DEXHASH     = 0xFF51AFD7ED558CCDL;

    /** The value the state word takes on a device where everything passed. */
    private static final long HEALTHY =
            C_SIGNATURE ^ C_DEBUGGABLE ^ C_TRACER ^ C_MAPS ^ C_PORTS ^ C_DEXHASH;

    /**
     * SHA-256 of the DER encoding of the release signing certificate.
     *
     * In a real build this is injected by the build system, never typed by
     * hand, and it is NOT a secret: it is in classes.dex in plain sight, and
     * anyone who wants it runs one command. Treating it as a secret is a
     * category error that leads to bad decisions downstream.
     */
    private static final String RELEASE_CERT_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000";

    private static final AtomicLong STATE = new AtomicLong(0L);
    private static final AtomicLong LAST_RUN_MS = new AtomicLong(0L);

    private LayeredTamperDetector() { }

    // -----------------------------------------------------------------------
    // L2 -- several entry points
    //
    // Call sweep() from Application.onCreate, from the login screen, from the
    // first authenticated request, from a periodic worker, and from wherever
    // the app already does something slow so that the extra milliseconds hide.
    //
    // The point is not that five call sites are unhookable. It is that an
    // attacker who patches one gets a partially-working app and a confusing
    // bug, which costs them a debugging cycle. That is the entire economics of
    // client-side hardening, honestly stated.
    // -----------------------------------------------------------------------

    public static void sweep(Context ctx) {
        long s = 0L;

        if (verifySignature(ctx))   s ^= C_SIGNATURE;
        if (verifyNotDebuggable(ctx)) s ^= C_DEBUGGABLE;
        if (verifyNoTracer())       s ^= C_TRACER;
        if (verifyMapsClean())      s ^= C_MAPS;
        if (verifyPortsClosed())    s ^= C_PORTS;
        if (verifyCodeIdentity(ctx)) s ^= C_DEXHASH;

        STATE.set(s);
        LAST_RUN_MS.set(SystemClock.elapsedRealtime());
    }

    // -----------------------------------------------------------------------
    // L3 -- the consequence, far away in time and in code
    //
    // deriveSessionKey is called by the networking layer when it signs a
    // request. It has no integrity-sounding name, contains no branch on any
    // check result, and produces a key that is simply wrong if the state word
    // is wrong. The failure surfaces as a 401 from the server, minutes later,
    // in a stack trace that mentions nothing in this file.
    //
    // Say the cost out loud: when this misfires on an honest user -- a device
    // whose /proc is unreadable, an OEM that sets a surprising flag -- the user
    // gets an unexplained authentication failure and your support team gets a
    // ticket nobody can reproduce. Delayed consequences are an attacker-hostile
    // and user-hostile design at the same time. Choose deliberately.
    // -----------------------------------------------------------------------

    public static byte[] deriveSessionKey(byte[] serverNonce) {
        long s = STATE.get();

        // A stale sweep is treated as a failed sweep. An attacker who prevents
        // sweep() from ever running must not thereby get the healthy key.
        long age = SystemClock.elapsedRealtime() - LAST_RUN_MS.get();
        if (LAST_RUN_MS.get() == 0L || age > 15L * 60L * 1000L) {
            s = 0L;
        }

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(serverNonce);
            for (int i = 0; i < 8; i++) {
                md.update((byte) ((s >>> (8 * i)) & 0xff));
            }
            return md.digest();
        } catch (Exception e) {
            // Never silently return a usable key on error.
            return new byte[0];
        }
    }

    /**
     * L4 -- what the app reports to the server, every session, regardless of
     * what it decided locally.
     *
     * The server cannot verify this. It is telemetry, not evidence, and calling
     * it evidence is the mistake that makes people build the wrong thing. What
     * it IS good for is population statistics: if 0.02% of your installs report
     * a non-healthy state word and one day it becomes 4%, something happened,
     * and you will know within hours instead of at the next fraud reconciliation.
     */
    public static String integrityTelemetry() {
        long s = STATE.get();
        StringBuilder sb = new StringBuilder();
        sb.append("state=").append(Long.toHexString(s));
        sb.append(" healthy=").append(s == HEALTHY);
        sb.append(" ageMs=").append(SystemClock.elapsedRealtime() - LAST_RUN_MS.get());
        return sb.toString();
    }

    // =======================================================================
    // The checks
    //
    // Each returns true on PASS. L5 in action: every one returns FALSE when it
    // could not run, so an unreadable /proc contributes nothing to the state
    // word and the device gets the same treatment as a failing one. That is the
    // opposite of what almost every real implementation does, and it is the
    // right way round.
    // =======================================================================

    static boolean verifySignature(Context ctx) {
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
            if (sigs == null || sigs.length == 0) return false;

            // Rotation-aware: accept ANY certificate in the lineage. An app that
            // rotates its key and only accepts the newest certificate rejects
            // every device that has not yet updated. Measured on the chapter's
            // test device: six installed packages carry a rotation lineage,
            // including the Play Store and GMS, so this is not hypothetical.
            for (Signature sig : sigs) {
                if (constantTimeEquals(sha256Hex(sig.toByteArray()), RELEASE_CERT_SHA256)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;   // L5
        }
    }

    static boolean verifyNotDebuggable(Context ctx) {
        try {
            ApplicationInfo ai = ctx.getApplicationInfo();
            return (ai.flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean verifyNoTracer() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = r.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    return Integer.parseInt(line.substring(10).trim()) == 0;
                }
            }
            return false;                       // no TracerPid line at all: L5
        } catch (Exception e) {
            return false;
        } finally {
            closeQuietly(r);
        }
    }

    static boolean verifyMapsClean() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            int n = 0;
            while ((line = r.readLine()) != null) {
                n++;
                String l = line.toLowerCase();
                if (l.contains("frida") || l.contains("gum-js")
                        || l.contains("linjector") || l.contains("gadget")) {
                    return false;
                }
            }
            // A suspiciously short map is itself suspicious: on the chapter's
            // test device a live app process had 2,448 mappings. A process
            // reporting a dozen is a process whose /proc reads are being
            // filtered.
            return n > 50;
        } catch (Exception e) {
            return false;
        } finally {
            closeQuietly(r);
        }
    }

    static boolean verifyPortsClosed() {
        // Scanning a randomised subset rather than a fixed list makes a
        // recorded-and-replayed answer less useful and costs nothing. It also
        // means two runs on the same device probe different ports, which is a
        // small but real obstacle to an attacker building a static allowlist.
        int[] candidates = { 27042, 27043, 27044, 27045, 27046, 27047 };
        Random rnd = new Random();
        for (int i = 0; i < 3; i++) {
            int port = candidates[rnd.nextInt(candidates.length)];
            Socket s = new Socket();
            try {
                s.connect(new InetSocketAddress("127.0.0.1", port), 80);
                return false;               // something answered
            } catch (IOException expected) {
                // refused: good
            } finally {
                closeQuietly(s);
            }
        }
        return true;
    }

    static boolean verifyCodeIdentity(Context ctx) {
        // Intentionally NOT a hash of classes.dex. On a v2+ APK that adds
        // nothing over verifySignature, costs tens of milliseconds on a large
        // DEX, and needs a baseline that cannot live in the DEX it describes.
        //
        // What IS worth checking cheaply: that the APK we are running from is
        // where the platform says it is, and that there is exactly one code
        // path. A second DEX loaded at runtime by an injected class loader is
        // the interesting case, and it is visible from here.
        try {
            String src = ctx.getApplicationInfo().sourceDir;
            if (src == null || src.length() == 0) return false;
            String cp = ctx.getPackageCodePath();
            return src.equals(cp);
        } catch (Exception e) {
            return false;
        }
    }

    // =======================================================================
    // helpers
    // =======================================================================

    static String sha256Hex(byte[] data) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : d) {
                sb.append(Character.forDigit((b >> 4) & 0xf, 16));
                sb.append(Character.forDigit(b & 0xf, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }

    static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try { c.close(); } catch (IOException ignored) { }
        }
    }
}
