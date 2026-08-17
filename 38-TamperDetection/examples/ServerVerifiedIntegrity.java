/*
 * examples/ServerVerifiedIntegrity.java
 * ---------------------------------------------------------------------------
 * PURPOSE
 *   The counterpart to LayeredTamperDetector.java: integrity as it should be
 *   designed, where the DECISION is made somewhere the attacker does not own.
 *
 *   Read this file as the answer to the question the rest of the chapter keeps
 *   raising. Every local check is a computation performed inside enemy
 *   territory. The way out is not a better local check; it is to stop asking
 *   the client to decide.
 *
 *   Concretely, four rules, and this file is a demonstration of all four:
 *
 *     R1  THE NONCE COMES FROM THE SERVER. A client-chosen nonce lets an
 *         attacker collect one good verdict on a clean device and replay it
 *         forever. This is the single most common way a Play Integrity
 *         integration is broken in the field, and it is invisible to any
 *         client-side test.
 *
 *     R2  THE VERDICT IS NEVER PARSED ON THE CLIENT. The token goes to the
 *         server as an opaque blob. An app that decodes the JWS, reads
 *         `deviceRecognitionVerdict` and branches on it has re-created the
 *         local boolean it was trying to escape, and has done so at greater
 *         cost and greater complexity.
 *
 *     R3  THE TOKEN IS BOUND TO THE REQUEST, NOT TO THE SESSION. A verdict
 *         attached to "the user logged in" is a verdict about a moment. Bind
 *         it to the specific operation whose risk you care about, by hashing
 *         the request into the nonce the server issued.
 *
 *     R4  THE SERVER ENFORCES. Not "the server tells the client to refuse".
 *         The server REFUSES. If the only consequence of a bad verdict is that
 *         the app hides a button, the control does not exist, because the API
 *         is still there and a repackaged client still calls it.
 *
 * WHAT THIS FILE IS AND IS NOT
 *   It is a faithful skeleton with the real API shapes and every decision
 *   point annotated. It is NOT a drop-in integration: the Play Integrity client
 *   library is a Play Services dependency (com.google.android.play:integrity)
 *   and this repository ships no binary dependencies, so the call is expressed
 *   against a small interface that you wire to the real SDK in one place. That
 *   also makes the file readable by someone who has never used the SDK, which
 *   is the point.
 *
 *   The platform side of device integrity -- Verified Boot, what the verdicts
 *   actually measure -- belongs to 20-Security-Architecture. The hardware key
 *   attestation alternative, including the certificate extension field by
 *   field, belongs to 49-KeyStore section 3.7. This file is about the SHAPE of
 *   a correct integration, which is what people get wrong.
 *
 * WHAT THIS WILL *NOT* DO
 *   * It will NOT stop a compromised device from using the app. It makes the
 *     SERVER able to decide whether to let it, which is a different and
 *     achievable goal.
 *   * It will NOT work offline. Any design whose integrity decision needs a
 *     server has an availability cost, and pretending otherwise is how
 *     fail-open handling gets written. Section 5.10 of the README covers what
 *     to do when the attestation service is down, and the answer depends on
 *     your business, not on your security team.
 *   * It will NOT save you from a bad server. Every check below can be
 *     implemented perfectly on the client and then ignored by an endpoint that
 *     never looks at the verdict. Test the endpoint.
 *
 * AUTHORISED TESTING ONLY.
 * ---------------------------------------------------------------------------
 */

package com.pentest.ch38.examples;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.concurrent.Callable;

public final class ServerVerifiedIntegrity {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    // -----------------------------------------------------------------------
    // The seam.
    //
    // Everything platform-specific is behind these two interfaces. Wire
    // IntegrityTokenProvider to the Play Integrity SDK, and Backend to your
    // HTTP client. Nothing else in this file changes.
    // -----------------------------------------------------------------------

    /** Produces an opaque, signed integrity token for a server-supplied nonce. */
    public interface IntegrityTokenProvider {
        /**
         * @param nonce the EXACT string the server issued. Do not modify it, do
         *              not append to it, do not re-encode it. R1.
         * @return the opaque token. Never parse it. R2.
         */
        String requestToken(String nonce) throws Exception;
    }

    /** The application's own backend. */
    public interface Backend {
        /** Ask the server for a fresh, single-use nonce bound to this operation. */
        String requestNonce(String operationId, String requestDigestHex) throws Exception;

        /**
         * Submit the operation together with the token. The RESPONSE is the
         * decision: the server either performed the operation or it did not.
         * There is no "verdict" field for the client to interpret.
         */
        String submit(String operationId, String requestBody, String integrityToken)
                throws Exception;
    }

    private final IntegrityTokenProvider provider;
    private final Backend backend;

    public ServerVerifiedIntegrity(IntegrityTokenProvider provider, Backend backend) {
        this.provider = provider;
        this.backend = backend;
    }

    // -----------------------------------------------------------------------
    // The correct flow, in one method
    // -----------------------------------------------------------------------

    /**
     * Perform a risk-bearing operation with an attested request.
     *
     * Read the ORDER carefully, because the order is the security property:
     *
     *   1. Hash the request the user actually asked for.
     *   2. Ask the SERVER for a nonce, telling it what the request digest is.
     *      The server stores (nonce -> operation, digest, expiry, single-use).
     *   3. Ask the platform for a token over that nonce.
     *   4. Send request + token together.
     *   5. The server checks the token's signature, checks that the nonce
     *      inside it is one it issued, that it has not been used, that it has
     *      not expired, and that the request digest matches what it recorded --
     *      and only then performs the operation.
     *
     * Step 2 before step 3 is what defeats replay. Step 1 feeding step 2 is
     * what defeats "attest the login, then do whatever you like".
     */
    public String performAttested(String operationId, String requestBody) throws Exception {
        // 1. Bind the token to THIS request. R3.
        String digest = sha256Hex(requestBody.getBytes(UTF8));

        // 2. Server-issued nonce. R1.
        //
        // If you find yourself generating this locally -- from a UUID, a
        // timestamp, or a random -- stop. A client-generated nonce is not a
        // nonce, it is a decoration, and the resulting integration is
        // replayable by design. This is finding #1 in section 5.11.
        String nonce = backend.requestNonce(operationId, digest);
        if (nonce == null || nonce.length() < 16) {
            throw new IllegalStateException("refusing to attest with a weak nonce");
        }

        // 3. Opaque token. R2 -- note that we never look inside it.
        String token = provider.requestToken(nonce);

        // 4/5. The server decides. There is no local branch on integrity here,
        // because there is nothing local to branch on.
        return backend.submit(operationId, requestBody, token);
    }

    // -----------------------------------------------------------------------
    // The three anti-patterns, written out so they are recognisable in the wild
    //
    // These compile. They are wrong. Each is annotated with how it fails and
    // how a tester proves it, because "this is wrong" is not a finding and
    // "here is the request that demonstrates it is wrong" is.
    // -----------------------------------------------------------------------

    /**
     * ANTI-PATTERN 1 -- client-generated nonce.
     *
     * HOW IT FAILS: the attacker obtains one valid token on a clean device,
     * then replays it from a rooted one. The server has no record of the nonce
     * and cannot tell the difference.
     *
     * HOW A TESTER PROVES IT: capture a request, replay it unchanged an hour
     * later from a different device. If it succeeds, the nonce is not
     * server-issued or not single-use. Note that this is a SERVER finding and
     * you can demonstrate it without touching the app's code at all.
     */
    public String antiPattern1_clientNonce(String requestBody) throws Exception {
        String nonce = Long.toHexString(System.currentTimeMillis())
                     + Long.toHexString(new java.util.Random().nextLong());
        String token = provider.requestToken(nonce);
        return backend.submit("op", requestBody, token);
    }

    /**
     * ANTI-PATTERN 2 -- the client parses the verdict and decides.
     *
     * HOW IT FAILS: the entire chain -- hardware root of trust, Google's
     * signature, the whole apparatus -- terminates in an `if` statement inside
     * the attacker's process. One hook on this method returns true forever.
     * This design is strictly WORSE than a naive local check, because it costs
     * a network round trip, a Play Services dependency and a lot of engineering
     * time to arrive at the same security.
     *
     * HOW A TESTER PROVES IT: hook the method and return the allowing value,
     * then confirm the privileged operation still succeeds server-side. If the
     * server never saw the token, that is your evidence.
     */
    public boolean antiPattern2_clientDecides(String nonce) throws Exception {
        String token = provider.requestToken(nonce);
        // Decoding a JWS on the client to read deviceRecognitionVerdict.
        String verdict = fakeLocalDecode(token);
        return verdict.contains("MEETS_DEVICE_INTEGRITY");
    }

    /**
     * ANTI-PATTERN 3 -- fail open.
     *
     * HOW IT FAILS: the attacker does not need to beat the attestation. They
     * need to break it. Block the Play Integrity endpoint at the network layer,
     * or run on a device without Play Services, and the catch block hands them
     * exactly what they wanted.
     *
     * HOW A TESTER PROVES IT: null-route the attestation host, or simply strip
     * the token from the request, and see whether the operation still succeeds.
     * Stripping the field is the fastest test in this whole chapter and it
     * catches an astonishing number of real integrations.
     */
    public String antiPattern3_failOpen(String operationId, String requestBody) {
        String token = null;
        try {
            String nonce = backend.requestNonce(operationId, sha256Hex(requestBody.getBytes(UTF8)));
            token = provider.requestToken(nonce);
        } catch (Exception e) {
            // "Do not block the user because our vendor is down."
            // A defensible product decision, an indefensible security control,
            // and the two must not be confused in a report: the finding is not
            // "fails open", it is "the server accepts requests with no token".
            token = null;
        }
        try {
            return backend.submit(operationId, requestBody, token);
        } catch (Exception e) {
            return null;
        }
    }

    // -----------------------------------------------------------------------
    // What the SERVER must do. Pseudocode, deliberately, because it is not
    // Android code and does not belong in an Android class -- but every tester
    // needs to be able to describe it, and every developer gets it wrong at
    // least once.
    // -----------------------------------------------------------------------
    //
    //   verify(token, requestBody, operationId):
    //       claims  = verifyJwsSignature(token, googlePublicKeys)   # or decode
    //                                                               # via the
    //                                                               # Play API
    //       assert  claims.requestDetails.requestPackageName == OUR_PACKAGE
    //       assert  claims.appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED
    //       assert  claims.appIntegrity.certificateSha256Digest in OUR_CERTS
    //       assert  MEETS_DEVICE_INTEGRITY in claims.deviceIntegrity
    //                                              .deviceRecognitionVerdict
    //
    //       nonce   = claims.requestDetails.nonce
    //       record  = nonceStore.consume(nonce)        # atomic; single use
    //       assert  record is not None                 # we issued it
    //       assert  record.operationId == operationId
    //       assert  record.requestDigest == sha256(requestBody)
    //       assert  now - record.issuedAt < 60 seconds
    //
    //       # timestampMillis in requestDetails is the platform's own clock
    //       # for the request; check it too, but never INSTEAD of the nonce.
    //       assert  abs(now - claims.requestDetails.timestampMillis) < 5 minutes
    //
    //   The three assertions people omit, in order of how often:
    //       1. nonceStore.consume  -- omitted entirely; the nonce is read and
    //          discarded. Replayable.
    //       2. certificateSha256Digest -- omitted, so a repackaged app signed
    //          by anyone still passes appRecognitionVerdict on some paths.
    //       3. requestPackageName -- omitted, so a token minted by a DIFFERENT
    //          app on the same device is accepted.
    //
    //   And the decision the server makes is graduated, not binary. A verdict
    //   is one input to a risk score, alongside account age, transfer value and
    //   device history. "Block on UNRECOGNIZED_VERSION" locks out every user
    //   whose Play Store had a bad day.

    // -----------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------

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
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** Stands in for a JWS decode. Present only so anti-pattern 2 compiles. */
    private static String fakeLocalDecode(String token) {
        return token == null ? "" : token;
    }

    /**
     * Convenience for callers that want the attested operation on a worker.
     * Nothing security-relevant; included because putting a network round trip
     * on the main thread is how the correct design gets reverted for being
     * "slow".
     */
    public Callable<String> asTask(final String operationId, final String requestBody) {
        return new Callable<String>() {
            @Override public String call() throws Exception {
                return performAttested(operationId, requestBody);
            }
        };
    }
}
