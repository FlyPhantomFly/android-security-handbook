// examples/BootStateChecker.java
//
// PURPOSE
//   The vulnerable platform-integrity check that is actually in real Android
//   apps, and the replacement that works -- side by side, in one file, so the
//   difference is a diff rather than an argument.
//
//   Chapter 61 section 5.3 and section 9.4 walk through this code.
//
// HOW TO READ IT
//   Part A  VulnerableChecker   -- what apps ship. Four defects, each labelled.
//   Part B  AttestationEvidence -- the fix. The device produces EVIDENCE;
//                                  a server reaches the VERDICT.
//   Part C  ServerSideVerifier  -- pseudocode for the half that must not run
//                                  on the device, with the checks enumerated.
//
// HOW TO COMPILE
//   This file references Android framework classes and is meant to be read and
//   dropped into an app module, not compiled standalone -- `javac` alone will
//   not resolve android.security.keystore.*. To build it:
//     - put it in app/src/main/java/com/example/bootstate/
//     - minSdk 24 or higher (setAttestationChallenge is API 24+)
//     - no third-party dependencies are required
//
// A NOTE ON HONESTY
//   Part B is strictly better than Part A, and it still has real costs: it needs
//   a server, it needs network, and it will reject some legitimate devices whose
//   attestation is absent or broken. If a team chose Part A deliberately with
//   those tradeoffs understood, the finding is Informational. If Part A is the
//   only gate on a payment or credential flow, it is a control failure. Report
//   the difference, not the pattern.

package com.example.bootstate;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

public final class BootStateChecker {

    private BootStateChecker() { }

    // =======================================================================
    // PART A -- THE VULNERABLE VERSION. DO NOT SHIP THIS.
    // =======================================================================

    /**
     * This is, near enough verbatim, what a large number of real apps do.
     *
     * FOUR DEFECTS, in descending order of severity:
     *
     *  1. THE INPUT IS ATTACKER-CONTROLLED.
     *     `ro.boot.*` properties are written by init from androidboot.* keys on
     *     the kernel command line or in bootconfig, into a shared-memory
     *     property area that root can rewrite. Magisk's `resetprop` sets
     *     ro.boot.verifiedbootstate to "green" in one command. This repository
     *     measured a device reporting "green" from getprop while its own
     *     TEE-signed key attestation, pulled seconds later, reported
     *     verifiedBootState=Unverified and deviceLocked=false. The property is
     *     attacker-controlled data on exactly the devices the check exists to
     *     detect. (See 50-HardwareBackedSecurity.)
     *
     *  2. IT FAILS OPEN.
     *     The catch block returns true. An attacker who makes the reflection
     *     THROW -- trivially, by hooking Class.forName -- passes the check
     *     without touching a single property. A security check that fails open
     *     is not a check. This defect is independent of defect 1 and survives
     *     every attempt to "harden" the property read.
     *
     *  3. THE VERDICT IS FORMED ON THE DEVICE.
     *     Even if the inputs were trustworthy, the boolean this method returns
     *     is a value in the app's own process. A one-line Frida hook or a
     *     one-instruction Smali patch replaces it. Anything the device decides,
     *     the device can be made to decide differently.
     *
     *  4. IT MISREADS AN ABSENT PROPERTY.
     *     Measured on an Android 15 / API 35 emulator: ro.boot.verifiedbootstate
     *     is the EMPTY STRING, not "orange". This version happens to fail closed
     *     on that case because it tests equals("green") -- but see
     *     isDeviceTrustworthy_worse() immediately below, which is just as common
     *     and passes on an emulator.
     */
    public static boolean isDeviceTrustworthy_VULNERABLE() {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class, String.class);
            String state = (String) get.invoke(null, "ro.boot.verifiedbootstate", "");
            String locked = (String) get.invoke(null, "ro.boot.flash.locked", "");
            return "green".equals(state) && "1".equals(locked);
        } catch (Exception e) {
            // DEFECT 2: fails OPEN.
            return true;
        }
    }

    /**
     * The same idea written "defensively", and strictly worse.
     *
     * MEASURED: on sdk_gphone16k_x86_64 (Android 15 / API 35),
     * ro.boot.verifiedbootstate is the empty string, because /proc/bootconfig
     * on that device carries no androidboot.verifiedbootstate key for init to
     * derive it from. "" is not "orange", so this returns TRUE.
     *
     * The check passes on the least trustworthy platform it could encounter.
     * See examples/measured-avd-boot-state.md section 1 and section 2.
     */
    public static boolean isDeviceTrustworthy_worse() {
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class);
            String state = (String) get.invoke(null, "ro.boot.verifiedbootstate");
            return !"orange".equals(state);
        } catch (Exception e) {
            return true;
        }
    }

    // =======================================================================
    // PART A2 -- IF YOU MUST READ PROPERTIES, READ THEM LIKE THIS
    // =======================================================================

    /**
     * There are legitimate reasons to read these values: telemetry, a risk
     * SIGNAL fed into a server-side score, or your own test tooling. If that is
     * what you are doing, this is the honest shape for it.
     *
     * The differences from Part A are all about not lying to yourself:
     *   - the return type is a tri-state, not a boolean, so "unknown" cannot be
     *     silently collapsed into "fine";
     *   - the accepted values are enumerated, so an unexpected value is
     *     UNKNOWN rather than accidentally passing;
     *   - an exception yields UNKNOWN, never a pass;
     *   - the name says REPORTED, so no caller can mistake it for a verdict.
     */
    public enum ReportedBootState {
        GREEN,          // locked, OEM-signed -- as reported
        YELLOW,         // locked, owner-supplied key -- as reported
        ORANGE,         // unlocked -- as reported
        RED,            // verification failed -- as reported
        ABSENT,         // the property is empty: nothing reported a state at all
        UNKNOWN         // unreadable, or a value not in the AVB set
    }

    public static ReportedBootState readReportedBootState() {
        String state;
        try {
            Class<?> sp = Class.forName("android.os.SystemProperties");
            Method get = sp.getMethod("get", String.class, String.class);
            state = (String) get.invoke(null, "ro.boot.verifiedbootstate", "");
        } catch (Exception e) {
            return ReportedBootState.UNKNOWN;     // never a pass
        }
        if (state == null || state.isEmpty()) {
            // Measured on an API 35 emulator. Absent is NOT "fine".
            return ReportedBootState.ABSENT;
        }
        switch (state) {
            case "green":  return ReportedBootState.GREEN;
            case "yellow": return ReportedBootState.YELLOW;
            case "orange": return ReportedBootState.ORANGE;
            case "red":    return ReportedBootState.RED;
            default:       return ReportedBootState.UNKNOWN;
        }
    }

    // =======================================================================
    // PART B -- THE FIX. THE DEVICE PRODUCES EVIDENCE, NOT A VERDICT.
    // =======================================================================

    /**
     * Generate a fresh hardware-backed key whose attestation certificate is
     * bound to a SERVER-ISSUED nonce, and return the certificate chain for the
     * server to verify.
     *
     * WHY THIS WORKS WHERE PART A DOES NOT
     *   The attestation extension inside the leaf certificate contains a
     *   RootOfTrust structure with deviceLocked and verifiedBootState fields.
     *   Those fields are populated by the TEE from a value the bootloader hands
     *   it over a channel normal-world software cannot reach, and the whole
     *   certificate is signed by a key that never leaves the TEE. Root in the
     *   normal world cannot change them, because root is not in the TEE.
     *
     * WHY THE NONCE IS NOT OPTIONAL
     *   Without a per-request server-issued challenge, a chain captured once
     *   from a compliant device replays forever. This is the single most common
     *   flaw in home-grown attestation and it makes the whole scheme worthless.
     *
     * WHY WE DO NOT PARSE IT HERE
     *   Anything the device parses, the device can lie about. Ship the bytes.
     *
     * @param serverNonce  fresh random bytes issued by YOUR server for THIS
     *                     request. Never generated on the device.
     * @return the DER-encoded certificate chain, leaf first.
     */
    public static List<byte[]> buildAttestationEvidence(byte[] serverNonce)
            throws GeneralSecurityException, IOException {

        if (serverNonce == null || serverNonce.length < 16) {
            // A short or absent nonce is a design error, not a runtime
            // condition to be tolerated. Fail loudly at development time.
            throw new IllegalArgumentException(
                    "serverNonce must be >= 16 bytes and must come from the server");
        }

        final String alias = "attest-" + System.nanoTime();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                // THE LINE THAT MATTERS: binds this attestation to this request.
                .setAttestationChallenge(serverNonce)
                .build());
        kpg.generateKeyPair();

        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain(alias);

        List<byte[]> der = new ArrayList<>();
        if (chain != null) {
            for (Certificate c : chain) {
                try {
                    der.add(c.getEncoded());
                } catch (CertificateEncodingException e) {
                    throw new GeneralSecurityException("cannot encode chain", e);
                }
            }
        }

        // The key was for one request. Do not accumulate keys in the keystore.
        try {
            ks.deleteEntry(alias);
        } catch (Exception ignored) {
            // Non-fatal: a leftover ephemeral key is untidy, not dangerous.
        }

        if (der.isEmpty()) {
            // No chain means this device cannot attest. That is a DISTINCT
            // outcome from "attested badly", and the server must be told which
            // it is -- see the note in ServerSideVerifier below.
            throw new GeneralSecurityException("device produced no attestation chain");
        }
        return der;
    }

    /** Wire encoding: base64 per certificate, joined. Any framing works. */
    public static String encodeEvidence(List<byte[]> chain) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StringBuilder sb = new StringBuilder();
        for (byte[] c : chain) {
            if (sb.length() > 0) sb.append('\n');
            sb.append(Base64.encodeToString(c, Base64.NO_WRAP));
        }
        out.close();
        return sb.toString();
    }

    /**
     * Convenience: the whole device-side flow, in the order it must happen.
     *
     * Note what is NOT here: any if-statement about the result. The device does
     * not decide. It collects and sends. Whatever the server decides comes back
     * over the same channel and is enforced by the server refusing to serve the
     * sensitive operation -- not by the client declining to ask for it.
     */
    public static String attest(Context context, byte[] serverNonce)
            throws GeneralSecurityException, IOException {
        return encodeEvidence(buildAttestationEvidence(serverNonce));
    }

    // =======================================================================
    // PART C -- THE SERVER SIDE, IN PSEUDOCODE
    // =======================================================================
    //
    // This half MUST NOT run on the device. It is written out here so the
    // checks are enumerated somewhere, not because it belongs in the app.
    //
    //   verifyAttestation(chainDer, issuedNonce, deviceId):
    //
    //     1. PARSE the chain, leaf first.
    //
    //     2. VERIFY the chain cryptographically up to a Google hardware
    //        attestation ROOT you have pinned. Not "any valid chain" -- a
    //        specific root you shipped.
    //
    //     3. CHECK REVOCATION against Google's published attestation key
    //        revocation status list. A LEAKED KEYBOX PRODUCES A CHAIN THAT
    //        VERIFIES PERFECTLY AND BELONGS TO NO REAL DEVICE. This step is
    //        load-bearing, not a formality.
    //
    //     4. EXTRACT the attestation extension (OID 1.3.6.1.4.1.11129.2.1.17)
    //        from the LEAF certificate.
    //
    //     5. CHECK attestationChallenge == issuedNonce, and that issuedNonce
    //        was issued to THIS session, recently, and has not been used
    //        before. This is what defeats replay.
    //
    //     6. CHECK attestationSecurityLevel is TRUSTED_ENVIRONMENT or
    //        STRONG_BOX -- NOT SOFTWARE.
    //        MEASURED, and this is the trap: on an emulator every key reports
    //        SOFTWARE, hardwareEnforced is empty, AND THE CHAIN STILL VERIFIES
    //        PERFECTLY. A verifier that only checks step 2 passes an emulator.
    //
    //     7. READ RootOfTrust from the hardwareEnforced authorization list:
    //            deviceLocked        (boolean)
    //            verifiedBootState   (Verified / SelfSigned / Unverified / Failed)
    //            verifiedBootKey     (the key the boot chain was verified with)
    //        These are the fields Part A was pretending to read.
    //
    //     8. ALSO READ osVersion and osPatchLevel from the same extension.
    //        They are equally non-forgeable, so this pipeline does double duty
    //        for patch compliance at no extra cost.
    //
    //     9. DECIDE, and record the decision as HISTORY, not as a boolean.
    //        "This device became unlocked on the 14th" is an incident.
    //        "This device is unlocked" is a row nobody reads.
    //
    //    10. TIER the response. Do not block unconditionally: a meaningful
    //        fraction of any engineering organisation's devices are unlocked
    //        for legitimate reasons, and a blanket block accumulates exceptions
    //        until the policy is decorative. Unlocked devices lose the highest
    //        tier and keep the rest; every state CHANGE raises an alert.
    //
    //    11. HANDLE "cannot attest" as its own bucket. Emulators, devices with
    //        software-only KeyMint, and devices with broken provisioning all
    //        land here, and it is not the same as "attested and failed".
    //
    // WHAT THIS STILL DOES NOT PROVE
    //   Attestation reports the state AT BOOT. Boot was potentially months ago.
    //   A device compromised after boot attests exactly as a clean one does.
    //   That is a real limit and it should be stated in any report that
    //   recommends attestation, because recommending it as a complete answer
    //   is its own kind of overclaim.
}
