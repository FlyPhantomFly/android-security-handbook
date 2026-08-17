/*
 * 03-key-attestation.java — request a key attestation and export the chain.
 *
 * WHAT IT DOES
 *   Generates an EC P-256 signing key in the Android Keystore with an
 *   attestation challenge supplied by the server, exports the resulting X.509
 *   certificate chain as PEM, and sends it to the server for verification.
 *
 *   It also shows how to sign subsequent requests with the attested key, which
 *   is the step that gives attestation any lasting value.
 *
 * WHY IT MATTERS
 *   Your server wants to believe a claim: "I am the genuine app, running on a
 *   genuine, locked, unmodified device, and this public key's private half is
 *   inside that device's secure hardware."
 *
 *   Made by ordinary app code, every part of that claim is a lie the attacker
 *   can tell. Root checks, signature checks, emulator checks, integrity checks —
 *   all of it is client-side code that a client-side attacker owns. See
 *   ../../37-RootDetection/.
 *
 *   Attestation escapes the circularity. The HARDWARE makes the statement,
 *   signs it with a factory-provisioned key that software cannot reach, and the
 *   signature chains to a root certificate Google published. The device's claim
 *   about itself becomes verifiable by someone who does not trust the device.
 *
 *   THE MOST IMPORTANT THING ON THIS PAGE
 *     This file does NOT verify anything. It deliberately performs no checks at
 *     all beyond confirming that a chain exists.
 *
 *     Verifying an attestation on the device is an expensive `return true;`.
 *     The whole point of the mechanism is to produce a statement a THIRD PARTY
 *     can check without trusting the device — so a device-side check hands the
 *     verifier to the attacker, who hooks it and returns true.
 *
 *     If you find an app verifying its own attestation locally, it is a finding,
 *     and an instructive one: the developers clearly understood the mechanism
 *     and then spent all the effort in the wrong place.
 *
 *     The verifier is 04-verify-attestation.py, and it runs on the server.
 *
 *   See ../README.md section 3.7, and ../labs/lab-03-attestation-analysis.md.
 *
 * HOW TO RUN
 *   1. Server issues a fresh 32-byte random challenge, stores it with a short
 *      expiry, and returns it.
 *   2. Client:
 *          byte[] challenge = api.getAttestationChallenge();
 *          String pem = KeyAttestation.attest(challenge);
 *          api.submitAttestation(pem);
 *   3. Server runs 04-verify-attestation.py's logic and, on success, binds the
 *      leaf public key to the account.
 *   4. Every subsequent request is signed by that key:
 *          byte[] sig = KeyAttestation.sign(requestBytes);
 *
 *   To inspect the chain by hand during testing:
 *       # host
 *       adb logcat -s KEYSTORELAB:I > chain.txt        # then extract the PEM
 *       openssl x509 -in leaf.pem -text -noout
 *       openssl asn1parse -in leaf.pem -strparse <offset>
 *   Or use the script: ../scripts/enumerate-keystore.js reports whether a leaf
 *   carries the attestation extension.
 *
 * REQUIREMENTS
 *   Android 7.0 (API 24) for setAttestationChallenge; API 31+ for
 *   setDevicePropertiesAttestationIncluded and PURPOSE_ATTEST_KEY. A device with
 *   hardware attestation support — many low-cost and older devices have none, or
 *   only software attestation, and YOUR FALLBACK POLICY FOR THOSE DEVICES IS
 *   WHERE THE REAL BUG USUALLY IS.
 *
 * AUTHORISED TESTING ONLY.
 */

package com.example.keystorelab;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Base64;
import android.util.Log;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public final class KeyAttestation {

    private static final String TAG = "KEYSTORELAB";
    private static final String PROVIDER = "AndroidKeyStore";
    private static final String ALIAS = "attested_identity_v1";

    /** The attestation extension OID. Present only in the LEAF certificate. */
    public static final String ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";

    private KeyAttestation() { }

    // ---------------------------------------------------------- generation --

    /**
     * Generate an attested key pair and return the whole chain as PEM.
     *
     * @param serverChallenge 32 random bytes issued by YOUR SERVER, for THIS
     *                        request, single-use, with a short expiry.
     *
     *                        Read that sentence again, because it is where
     *                        implementations fail. A constant challenge, a
     *                        client-generated challenge, or a challenge that is
     *                        never checked makes the entire attestation
     *                        REPLAYABLE: an attacker captures one chain from a
     *                        clean device and submits it forever from a
     *                        compromised one. The challenge is the ONLY
     *                        anti-replay control in the whole mechanism.
     */
    public static String attest(byte[] serverChallenge) throws Exception {
        if (serverChallenge == null || serverChallenge.length < 16) {
            throw new IllegalArgumentException(
                "challenge must be at least 16 bytes and must come from the server");
        }

        // Always regenerate. A key attested against last week's challenge proves
        // nothing about this session, and reusing an alias silently means you
        // may be exporting a stale chain.
        deleteKey();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, PROVIDER);

        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(
                ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))

                // THE LINE THAT MAKES THIS AN ATTESTATION.
                .setAttestationChallenge(serverChallenge);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // Adds brand/device/product/manufacturer/model to the hardware-
            // enforced list. Useful for fleet policy; also a privacy decision,
            // because it makes the attestation identifying. Requesting it can
            // FAIL on devices that do not support it — hence the try/catch.
            try {
                b.setDevicePropertiesAttestationIncluded(true);
            } catch (Throwable ignored) { }
        }

        // Ask for StrongBox first. The chain then reports
        // attestationSecurityLevel = StrongBox(2), which a server can require
        // for high-value operations.
        boolean strongBox = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                KeyGenParameterSpec sb = new KeyGenParameterSpec.Builder(
                        ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAlgorithmParameterSpec(
                                new java.security.spec.ECGenParameterSpec("secp256r1"))
                        .setAttestationChallenge(serverChallenge)
                        .setIsStrongBoxBacked(true)
                        .build();
                kpg.initialize(sb);
                kpg.generateKeyPair();
                strongBox = true;
            } catch (StrongBoxUnavailableException e) {
                Log.i(TAG, "StrongBox unavailable; falling back to TEE");
            } catch (Exception e) {
                Log.i(TAG, "StrongBox attempt failed: " + e.getClass().getSimpleName());
            }
        }

        if (!strongBox) {
            kpg.initialize(b.build());
            kpg.generateKeyPair();
        }

        // NOTE: we do not need to tell the server whether we used StrongBox.
        // The server reads attestationSecurityLevel out of the chain, which is
        // hardware-asserted. Anything the CLIENT says about its own security
        // level is unverifiable and should be ignored. That asymmetry is the
        // entire value of attestation, and it is why this method returns only
        // the chain.

        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        Certificate[] chain = ks.getCertificateChain(ALIAS);

        if (chain == null || chain.length == 0) {
            throw new IllegalStateException("no certificate chain — attestation unsupported?");
        }

        // A single self-signed certificate means the device produced NO real
        // attestation. Some devices, and most emulators, behave this way. Do not
        // paper over it: report it to the server and let the SERVER decide the
        // policy. Silently continuing is how a "hardware-attested" system ends
        // up trusting an emulator.
        if (chain.length == 1) {
            Log.w(TAG, "chain has ONE certificate — this device produced no attestation chain. "
                    + "The server must treat this as an unattested device.");
        }

        X509Certificate leaf = (X509Certificate) chain[0];
        byte[] ext = leaf.getExtensionValue(ATTESTATION_OID);
        Log.i(TAG, "chain length            = " + chain.length);
        Log.i(TAG, "leaf subject            = " + leaf.getSubjectDN());
        Log.i(TAG, "attestation extension   = "
                + (ext == null ? "ABSENT — no attestation on this device"
                               : ext.length + " bytes"));
        Log.i(TAG, "NOTE: this app does NOT parse that extension. Verification is the "
                + "SERVER's job — see 04-verify-attestation.py.");

        return toPem(chain);
    }

    // --------------------------------------------------------------- usage --

    /**
     * Sign a request with the attested key.
     *
     * THIS IS THE STEP EVERYONE FORGETS, and without it attestation is nearly
     * worthless. Attestation proves a key is in hardware AT ONE MOMENT. Its
     * value comes entirely from then USING that key for every subsequent
     * request, so that the server knows each request came from the same hardware
     * it verified.
     *
     * An app that attests at registration and then sends bearer tokens has
     * thrown the guarantee away: the bearer token is copyable and the attestation
     * is never referenced again. That pattern is common, and it is a legitimate
     * design finding.
     */
    public static byte[] sign(byte[] payload) throws Exception {
        KeyStore ks = KeyStore.getInstance(PROVIDER);
        ks.load(null);
        PrivateKey pk = (PrivateKey) ks.getKey(ALIAS, null);
        if (pk == null) throw new IllegalStateException("no attested key — attest() first");

        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(pk);
        s.update(payload);
        return s.sign();
    }

    /**
     * Does the attested key still exist and work? Call before signing so a
     * KeyPermanentlyInvalidatedException does not surface mid-request.
     */
    public static boolean isAttestedKeyUsable() {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            if (!ks.containsAlias(ALIAS)) return false;
            sign(new byte[]{ 0x01 });
            return true;
        } catch (Exception e) {
            Log.i(TAG, "attested key unusable: " + e.getClass().getSimpleName());
            return false;
        }
    }

    public static void deleteKey() {
        try {
            KeyStore ks = KeyStore.getInstance(PROVIDER);
            ks.load(null);
            if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS);
        } catch (Exception ignored) { }
    }

    // ----------------------------------------------------------------- pem --

    /** Encode the chain, leaf first, as PEM for transmission to the server. */
    private static String toPem(Certificate[] chain) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (Certificate c : chain) {
            sb.append("-----BEGIN CERTIFICATE-----\n");
            String b64 = Base64.encodeToString(c.getEncoded(), Base64.NO_WRAP);
            for (int i = 0; i < b64.length(); i += 64) {
                sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
            }
            sb.append("-----END CERTIFICATE-----\n");
        }
        return sb.toString();
    }
}

/*
 * =====================================================================
 * WHERE ATTESTATION IMPLEMENTATIONS ACTUALLY FAIL
 * =====================================================================
 *
 * Almost never on the client. The client side is a handful of lines and hard to
 * get wrong. Every finding worth writing is on the server, and there are five
 * recurring ones.
 *
 * 1. READING softwareEnforced INSTEAD OF hardwareEnforced.
 *    Every field in the authorization list appears TWICE. The software-enforced
 *    copy is asserted by the Android framework, which is on the attacker's side
 *    of the trust boundary. A verifier that reads rootOfTrust or origin from it,
 *    or that merges both lists into one dictionary, is trivially defeated.
 *    THIS IS THE FIRST THING TO CHECK IN ANY VERIFIER REVIEW.
 *
 * 2. NOT CHECKING THE CHALLENGE, OR ACCEPTING A CONSTANT ONE.
 *    Test it directly: submit the same chain twice. If the server accepts it the
 *    second time, every attestation it has ever seen is replayable, and an
 *    attacker needs one clean device, once.
 *
 * 3. PINNING AN INTERMEDIATE RATHER THAN THE GOOGLE ROOT.
 *    Under Remote Key Provisioning the intermediates are short-lived and rotate.
 *    Pinning one is a robustness bug that fails closed at an unpredictable
 *    future date — report it even though it is not exploitable.
 *
 * 4. NOT CHECKING attestationApplicationId.
 *    Without it, a repackaged copy of the app on the same device produces an
 *    equally valid attestation, because the hardware attests the DEVICE, not
 *    which app asked. Bind the package name AND the signing certificate digest.
 *
 * 5. VERIFYING ON THE DEVICE.
 *    An expensive `return true;`. If you find it, say so plainly.
 *
 * And the design-level one, which is not a bug in the verifier at all:
 *
 * 6. ATTESTING ONCE AND THEN USING BEARER TOKENS.
 *    The attested key must sign every subsequent request. Otherwise the
 *    guarantee applies to a single moment in the past and nothing since.
 *
 * HONEST LIMITS — put these in the report so the client does not overclaim:
 *   - Attestation says nothing about RUNTIME integrity. An attested key on a
 *     locked, verified device can still be driven by a Frida script if the
 *     attacker gets code into the process. verifiedBootState == Verified raises
 *     the attacker's cost considerably; it does not eliminate them.
 *   - Devices without secure hardware exist, and so do devices provisioned
 *     incorrectly at the factory. A hard-fail policy has real support costs,
 *     which is precisely what pushes teams to soft-fail — and soft-fail is what
 *     attackers use.
 *   - The chain proves the MANUFACTURER's claim, and inherits any compromise of
 *     that manufacturer's provisioning process or TEE. Published research has
 *     recovered attestation keys from real devices; a correct verifier fetches
 *     and honours Google's revocation status list.
 */
