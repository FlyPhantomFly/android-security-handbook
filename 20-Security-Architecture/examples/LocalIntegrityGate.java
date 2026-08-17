/*
 * LocalIntegrityGate.java
 * ===========================================================================
 * THE WRONG WAY. This file is the "before" half of a before/after pair; the
 * "after" halves are ServerVerifiedGate.kt and integrity-backend.js in this
 * same directory.
 *
 * WHAT IT IS
 *   A device-integrity gate of the kind that appears in a large fraction of
 *   real banking, wallet and DRM applications. It reads platform state --
 *   Verified Boot state, bootloader lock, dm-verity mode, build tags, debug
 *   flags, patch age, install source -- scores it, and decides locally whether
 *   the user may reach a protected feature.
 *
 *   Every individual signal it reads is a genuine signal, described accurately
 *   in chapter 20 sections 3.1 to 3.8. Nothing here is a strawman. The bug is
 *   not in any one check.
 *
 * WHY IT IS WRONG
 *   The bug is architectural and it is one sentence long: *the verdict is
 *   computed by code the adversary controls, from inputs the adversary
 *   controls, and consumed by code the adversary controls.*
 *
 *   Concretely:
 *     1. Every value it reads comes from the property area, which is mapped
 *        from /dev/__properties__ and writable by root (see README section 4.5).
 *        `resetprop` changes them without a reboot.
 *     2. Even if the values were unforgeable, `evaluate()` returns a Java enum
 *        into the attacker's own process. One Frida line replaces the return
 *        value, and no amount of extra checks changes that.
 *     3. The protected asset is already on the device. Whatever the gate
 *        decides, the ciphertext and the key that opens it both shipped inside
 *        the APK. The gate is guarding a door in a building with no walls.
 *
 *   Points 1 and 2 are about *this* implementation. Point 3 is about the whole
 *   category, and it is the one that survives every improvement you could make
 *   to this file.
 *
 * WHAT IT IS STILL GOOD FOR
 *   Honest answers: telemetry, risk scoring, and support diagnostics. Send the
 *   signals to your backend as *evidence contributing to a risk score*, never
 *   as an authorisation decision. A locally-evaluated verdict raises an
 *   attacker's cost from zero to a few minutes; report it, and design it, as
 *   exactly that much.
 *
 * USED BY
 *   labs/lab-03-integrity-gate-bypass.md -- build this, discover it with
 *   scripts/integrity-observer.js, bypass it four different ways, then write
 *   the finding.
 *
 * NOT ROOT DETECTION
 *   Deliberately, this file probes no su binaries, no Magisk artefacts and no
 *   package lists. That subject belongs to chapter 37. This file is about what
 *   the *platform* asserts about itself and why an app cannot check those
 *   assertions alone.
 * ===========================================================================
 */
package com.archlab.gate;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;

import java.lang.reflect.Method;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

public final class LocalIntegrityGate {

    /** What the app does with the answer. Three states, not two, because a
     *  binary allow/deny throws away the useful middle ground. */
    public enum Verdict {
        TRUSTED,     // full feature set
        DEGRADED,    // read-only; no key export, no transfers
        UNTRUSTED    // protected feature refused entirely
    }

    /** One observation, kept as evidence rather than folded straight into a
     *  boolean, so the app can report *why* rather than just "no". */
    public static final class Signal {
        public final String name;
        public final String observed;
        public final String expected;
        public final int weight;
        public final boolean ok;

        Signal(String name, String observed, String expected, int weight) {
            this.name = name;
            this.observed = observed;
            this.expected = expected;
            this.weight = weight;
            this.ok = expected.equals(observed);
        }

        @Override public String toString() {
            return String.format(Locale.US, "%-28s %-12s expected %-12s %s (w=%d)",
                    name, observed, expected, ok ? "OK" : "MISMATCH", weight);
        }
    }

    public static final class Assessment {
        public final Verdict verdict;
        public final int score;
        public final List<Signal> signals;

        Assessment(Verdict verdict, int score, List<Signal> signals) {
            this.verdict = verdict;
            this.score = score;
            this.signals = signals;
        }
    }

    // Thresholds. Tuned by nobody in particular, which is typical.
    private static final int TRUSTED_AT  = 0;
    private static final int DEGRADED_AT = 45;

    // How stale a security patch level may be before it counts against the device.
    private static final long MAX_PATCH_AGE_DAYS = 180;

    private static final String PLAY_STORE = "com.android.vending";

    /**
     * The whole gate. Note what it returns: a Java object, in the attacker's
     * process, produced by attacker-reachable code.
     */
    public static Assessment evaluate(Context ctx) {
        List<Signal> signals = new ArrayList<Signal>();

        // ---- Verified Boot state (README section 3.1) -----------------------
        // "green" means the bootloader verified everything up to and including
        // the boot image against the OEM key. It is the single most meaningful
        // property here -- and it arrives as a string in a shared memory page.
        signals.add(new Signal("ro.boot.verifiedbootstate",
                prop("ro.boot.verifiedbootstate"), "green", 40));

        // ---- Bootloader lock state -----------------------------------------
        signals.add(new Signal("ro.boot.flash.locked",
                prop("ro.boot.flash.locked"), "1", 35));

        // ---- dm-verity mode (README section 3.2) ---------------------------
        // "logging" is the dangerous one: verity is configured, reports
        // corruption, and permits it anyway.
        signals.add(new Signal("ro.boot.veritymode",
                prop("ro.boot.veritymode"), "enforcing", 25));

        // ---- Build identity -------------------------------------------------
        // "test-keys" means the image was signed with AOSP's public test keys,
        // which anyone has. "release-keys" is the expected value on a shipped
        // device -- and is a string constant in a writable property.
        signals.add(new Signal("Build.TAGS",
                Build.TAGS == null ? "" : Build.TAGS, "release-keys", 20));

        // ---- Debug posture --------------------------------------------------
        signals.add(new Signal("ro.debuggable", prop("ro.debuggable"), "0", 20));
        signals.add(new Signal("ro.secure",     prop("ro.secure"),     "1", 10));

        // ---- Encryption -----------------------------------------------------
        signals.add(new Signal("ro.crypto.state", prop("ro.crypto.state"),
                "encrypted", 15));

        // ---- Patch currency (README section 3.8) ---------------------------
        // A real signal that has nothing to do with tampering: an honest device
        // running eighteen-month-old code is a genuine risk to the transaction.
        long ageDays = patchAgeDays();
        signals.add(new Signal("patch age <= " + MAX_PATCH_AGE_DAYS + "d",
                ageDays < 0 ? "unknown"
                            : (ageDays <= MAX_PATCH_AGE_DAYS ? "fresh" : "stale"),
                "fresh", 15));

        // ---- Install source -------------------------------------------------
        // Weak: sideloading is not compromise, and the installer name is itself
        // attacker-influenceable. Included because real gates include it.
        signals.add(new Signal("installer",
                installerOf(ctx), PLAY_STORE, 10));

        int score = 0;
        for (Signal s : signals) {
            if (!s.ok) {
                score += s.weight;
            }
        }

        Verdict v;
        if (score <= TRUSTED_AT) {
            v = Verdict.TRUSTED;
        } else if (score < DEGRADED_AT) {
            v = Verdict.DEGRADED;
        } else {
            v = Verdict.UNTRUSTED;
        }
        return new Assessment(v, score, signals);
    }

    /**
     * Reads a system property through the hidden android.os.SystemProperties
     * API. This is the exact call scripts/integrity-observer.js hooks, and the
     * reflection is what makes it visible in a Smali string search (see README
     * section 6.2).
     */
    private static String prop(String key) {
        try {
            Class<?> cls = Class.forName("android.os.SystemProperties");
            Method get = cls.getMethod("get", String.class, String.class);
            return (String) get.invoke(null, key, "");
        } catch (Throwable t) {
            // Note the failure mode: an exception yields "", which does not
            // equal the expected value, so an unreadable property counts
            // against the device. Fail-closed here is a deliberate choice --
            // and the opposite choice is a finding in its own right.
            return "";
        }
    }

    /** Days since ro.build.version.security_patch, or -1 if unparseable. */
    private static long patchAgeDays() {
        String patch = Build.VERSION.SECURITY_PATCH;
        if (patch == null || patch.isEmpty()) {
            return -1;
        }
        try {
            SimpleDateFormat fmt = new SimpleDateFormat("yyyy-MM-dd", Locale.US);
            Date then = fmt.parse(patch);
            if (then == null) {
                return -1;
            }
            long ms = System.currentTimeMillis() - then.getTime();
            return TimeUnit.MILLISECONDS.toDays(ms);
        } catch (ParseException e) {
            return -1;
        }
    }

    /** Which package installed us. Deprecated pre-API-30 call kept for range. */
    @SuppressWarnings("deprecation")
    private static String installerOf(Context ctx) {
        PackageManager pm = ctx.getPackageManager();
        String self = ctx.getPackageName();
        try {
            if (Build.VERSION.SDK_INT >= 30) {
                String s = pm.getInstallSourceInfo(self).getInitiatingPackageName();
                return s == null ? "" : s;
            }
            String s = pm.getInstallerPackageName(self);
            return s == null ? "" : s;
        } catch (Throwable t) {
            return "";
        }
    }

    /** Human-readable dump, for the diagnostics screen used in lab 03. */
    public static String describe(Assessment a) {
        StringBuilder sb = new StringBuilder();
        sb.append("verdict: ").append(a.verdict)
          .append("  (penalty score ").append(a.score).append(")\n\n");
        for (Signal s : a.signals) {
            sb.append(s).append('\n');
        }
        return sb.toString();
    }

    private LocalIntegrityGate() { }
}
