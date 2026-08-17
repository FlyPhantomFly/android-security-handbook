// examples/05-DpopInterceptor.kt
//
// PURPOSE
//   Everything else in this chapter treats the token as a bearer credential: whoever
//   holds the bytes is the user. This file changes that. It implements DPoP
//   (Demonstrating Proof of Possession at the Application Layer, RFC 9449) on the client
//   side, so a stolen token is useless without a private key that never leaves the
//   device's Keystore.
//
//   This is the enterprise-grade answer to the whole chapter, and it is the one thing
//   that genuinely alters the severity calculus. Every storage finding in this
//   repository — a token in SharedPreferences, in a backup, in a log line, in the WAL —
//   is an impact because the token alone is enough. Make it not enough and those
//   findings become, correctly, informational.
//
//   How DPoP works, in one paragraph. The client generates a keypair. On every request
//   it builds a small JWT called a "proof", whose header carries the PUBLIC key inline
//   (`jwk`) and whose claims name the HTTP method (`htm`), the URI (`htu`), a unique id
//   (`jti`), a timestamp (`iat`), and — once the client holds an access token — the
//   SHA-256 hash of that token (`ath`). It signs the proof with the PRIVATE key and
//   sends it in a `DPoP` header alongside `Authorization: DPoP <token>`. The token
//   itself carries `cnf.jkt`, the thumbprint of the public key it was bound to. The
//   server recomputes the thumbprint from the proof's `jwk`, compares it with `cnf.jkt`,
//   verifies the proof's signature, and checks that `htm`/`htu`/`iat`/`jti` match this
//   request and have not been seen before. A token replayed without the key fails at
//   the thumbprint; a proof replayed verbatim fails at `jti`.
//
// BUILD
//   Android, minSdk 23. Gradle:
//       implementation "com.squareup.okhttp3:okhttp:4.12.0"
//   No JOSE library is used, on purpose: assembling the proof by hand is three lines of
//   base64url and one Signature call, and seeing that makes the format concrete. In
//   production, use a reviewed JOSE library (Nimbus, or AppAuth's DPoP support once it
//   is stable) rather than this.
//
//   NOT compiled for this repository — it needs the Android SDK on the compile path.
//   The ECDSA-signature detail below is the one place a hand-rolled implementation
//   reliably breaks, and it is called out where it bites.
//
// WHAT THIS WILL NOT TELL YOU / WHAT DPoP DOES NOT SOLVE
//   * It does NOT stop an attacker who has code execution in the app's process. They
//     do not need to extract the key; they call the same signing routine and get valid
//     proofs. 49-KeyStore section 1.3: extraction versus use. On a rooted device with
//     Frida, DPoP buys you nothing at all, and saying otherwise in a report is wrong.
//   * It does NOT protect the token in transit against a party that also relays the
//     request — DPoP binds the token to a key, not to a channel. mTLS-bound tokens
//     (RFC 8705) bind to the TLS connection and are stronger where the estate can carry
//     client certificates.
//   * It does NOT help unless the SERVER enforces it. A server that accepts the same
//     token as `Authorization: Bearer` has not deployed DPoP, it has added a header.
//     That is the single most important test: strip the DPoP header, change the scheme
//     to Bearer, and see whether the request still succeeds.
//   * It does NOT replace short lifetimes, rotation, revocation or scope discipline.
//
// SAFETY
//   The keypair is generated on the device and never printed. Nothing here handles a
//   token belonging to anyone but the app's own user.
//
// Chapter 46 — Tokens

package com.pentest.ch46

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import okhttp3.Interceptor
import okhttp3.Response
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.util.UUID

/**
 * An OkHttp interceptor that attaches a DPoP proof to every request.
 *
 * Install it as an *application* interceptor, not a network one, so it runs once per
 * logical request and sees the final URL after any application-level rewriting. A proof
 * whose `htu` does not match the URL the server actually received is rejected, and a
 * network interceptor running before a redirect will produce exactly that.
 */
class DpopInterceptor(
    private val tokenStore: HardenedTokenStore,
    private val keyAlias: String = "dpop_key_v1"
) : Interceptor {

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val B64 = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
    }

    // ---------------------------------------------------------------------- //
    // The key.
    //
    // P-256 in the Android Keystore. Three properties are load-bearing:
    //   * setUserAuthenticationRequired is NOT set. A DPoP proof is needed on every
    //     request including background refreshes, so gating it on a biometric would
    //     break the app. Chapter 48 covers where the gate does belong.
    //   * The key is per-installation and non-exportable. On a device with a StrongBox
    //     or TEE-backed Keymint it never exists in the application processor's memory.
    //     Confirm with KeyInfo.getSecurityLevel() rather than assuming — 49-KeyStore
    //     section 3.8.
    //   * Nothing rotates it here. A real implementation must, and must handle the
    //     server's `use_dpop_nonce` error and the re-binding that follows.
    // ---------------------------------------------------------------------- //
    private fun keyPairEntry(): KeyStore.PrivateKeyEntry {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry)?.let { return it }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, KEYSTORE
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_SIGN)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .build()
        )
        generator.generateKeyPair()
        return ks.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
    }

    /**
     * The public key as a JWK, exactly as it must appear in the proof's header.
     *
     * The member order is not arbitrary. RFC 7638 defines the thumbprint as the SHA-256
     * of the JSON containing only the REQUIRED members, with no whitespace, keys sorted
     * lexicographically: for EC that is `crv`, `kty`, `x`, `y`. Get the order or the
     * whitespace wrong and your thumbprint will not equal the server's, the `cnf.jkt`
     * comparison will fail, and the error you get back will say nothing useful. This is
     * the number one cause of "DPoP does not work" and it is a JSON serialisation bug,
     * not a cryptographic one.
     */
    private fun publicJwk(pub: ECPublicKey): String {
        val point = pub.w
        val x = Base64.encodeToString(fixedWidth(point.affineX.toByteArray(), 32), B64)
        val y = Base64.encodeToString(fixedWidth(point.affineY.toByteArray(), 32), B64)
        return """{"crv":"P-256","kty":"EC","x":"$x","y":"$y"}"""
    }

    /**
     * BigInteger.toByteArray() emits a leading 0x00 when the high bit is set, and drops
     * leading zero bytes otherwise, so the result is 31, 32 or 33 bytes. JOSE requires
     * exactly the coordinate width. Skipping this normalisation produces thumbprints
     * that are correct roughly 99 times out of 100 and wrong the rest, which is the
     * worst possible failure mode: it passes testing and breaks in the field.
     */
    private fun fixedWidth(raw: ByteArray, width: Int): ByteArray {
        if (raw.size == width) return raw
        if (raw.size == width + 1 && raw[0] == 0.toByte()) return raw.copyOfRange(1, raw.size)
        val out = ByteArray(width)
        System.arraycopy(raw, 0, out, width - raw.size, raw.size)
        return out
    }

    /** RFC 7638 JWK thumbprint. This is the value that appears as `cnf.jkt` in the token. */
    fun thumbprint(): String {
        val pub = keyPairEntry().certificate.publicKey as ECPublicKey
        val digest = MessageDigest.getInstance("SHA-256").digest(publicJwk(pub).toByteArray())
        return Base64.encodeToString(digest, B64)
    }

    /**
     * Build one proof.
     *
     * @param htm the HTTP method, uppercase
     * @param htu the request URI with query and fragment REMOVED (RFC 9449 section 4.2)
     * @param accessToken if present, its SHA-256 goes in `ath`, binding this proof to
     *        this token. Omitting `ath` when a token is in play lets a proof captured
     *        from one request be reused with a different token.
     */
    private fun buildProof(htm: String, htu: String, accessToken: String?): String {
        val entry = keyPairEntry()
        val pub = entry.certificate.publicKey as ECPublicKey

        val header = """{"typ":"dpop+jwt","alg":"ES256","jwk":${publicJwk(pub)}}"""

        val claims = JSONObject().apply {
            put("jti", UUID.randomUUID().toString())   // unique: the server must reject reuse
            put("htm", htm)
            put("htu", htu)
            put("iat", System.currentTimeMillis() / 1000)
            if (accessToken != null) {
                val ath = MessageDigest.getInstance("SHA-256")
                    .digest(accessToken.toByteArray(Charsets.US_ASCII))
                put("ath", Base64.encodeToString(ath, B64))
            }
        }.toString()

        val signingInput =
            Base64.encodeToString(header.toByteArray(), B64) + "." +
            Base64.encodeToString(claims.toByteArray(), B64)

        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(entry.privateKey)
            update(signingInput.toByteArray(Charsets.US_ASCII))
            sign()
        }

        // THE TRAP. Java's Signature emits an ASN.1 DER SEQUENCE of two INTEGERs.
        // JOSE ES256 requires the raw concatenation r||s, 32 bytes each, 64 total. Send
        // the DER and every server rejects the proof with a signature error that looks
        // like a key problem. This conversion is mandatory and is omitted from most
        // blog-post implementations.
        return "$signingInput.${Base64.encodeToString(derToJose(signature, 32), B64)}"
    }

    /** ASN.1 DER SEQUENCE { INTEGER r, INTEGER s } -> fixed-width r || s. */
    private fun derToJose(der: ByteArray, width: Int): ByteArray {
        var offset = 2                                  // 0x30, total-length
        if (der[1].toInt() and 0x80 != 0) offset += der[1].toInt() and 0x7f
        require(der[offset].toInt() == 0x02) { "malformed DER signature" }
        val rLen = der[offset + 1].toInt()
        val r = der.copyOfRange(offset + 2, offset + 2 + rLen)
        val sOffset = offset + 2 + rLen
        require(der[sOffset].toInt() == 0x02) { "malformed DER signature" }
        val sLen = der[sOffset + 1].toInt()
        val s = der.copyOfRange(sOffset + 2, sOffset + 2 + sLen)
        return fixedWidth(r, width) + fixedWidth(s, width)
    }

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val token = tokenStore.accessToken()?.expose()

        // `htu` is the URI without query or fragment. Including them is a common bug and
        // the server will reject the proof, because it computes the same value from what
        // it received.
        val htu = original.url.newBuilder().query(null).fragment(null).build().toString()

        val builder = original.newBuilder()
            .header("DPoP", buildProof(original.method.uppercase(), htu, token))

        if (token != null) {
            // The scheme is `DPoP`, not `Bearer`. That distinction is the point: a server
            // that also accepts `Bearer <same token>` has not deployed DPoP.
            builder.header("Authorization", "DPoP $token")
        }

        val response = chain.proceed(builder.build())

        // RFC 9449 section 8: the server may demand a nonce, returning 401 with
        // `DPoP-Nonce`. Retry once with the nonce included as a `nonce` claim. Without
        // this the app breaks the first time the server turns nonces on.
        val nonce = response.header("DPoP-Nonce")
        if (response.code == 401 && nonce != null) {
            response.close()
            val retryProof = buildProofWithNonce(
                original.method.uppercase(), htu, token, nonce
            )
            return chain.proceed(
                original.newBuilder()
                    .header("DPoP", retryProof)
                    .apply { if (token != null) header("Authorization", "DPoP $token") }
                    .build()
            )
        }
        return response
    }

    private fun buildProofWithNonce(
        htm: String, htu: String, token: String?, nonce: String
    ): String {
        // Left as a thin wrapper so the nonce path is visible rather than hidden inside
        // buildProof's parameter list. A real implementation caches the nonce per origin
        // and includes it pre-emptively on subsequent requests.
        val proof = buildProof(htm, htu, token)
        val parts = proof.split(".")
        val claims = JSONObject(
            String(Base64.decode(parts[1], Base64.URL_SAFE or Base64.NO_WRAP))
        ).put("nonce", nonce)
        // Re-sign, because the claims changed. Anything else produces an invalid proof --
        // and an implementation that edits the payload and keeps the signature is
        // attack A8 from the gauntlet, committed by the developer against themselves.
        return buildProof(htm, htu, token).let { _ ->
            val entry = keyPairEntry()
            val pub = entry.certificate.publicKey as ECPublicKey
            val header = """{"typ":"dpop+jwt","alg":"ES256","jwk":${publicJwk(pub)}}"""
            val signingInput =
                Base64.encodeToString(header.toByteArray(), B64) + "." +
                Base64.encodeToString(claims.toString().toByteArray(), B64)
            val sig = Signature.getInstance("SHA256withECDSA").run {
                initSign(entry.privateKey)
                update(signingInput.toByteArray(Charsets.US_ASCII))
                sign()
            }
            "$signingInput.${Base64.encodeToString(derToJose(sig, 32), B64)}"
        }
    }
}

/*
 * HOW TO TEST A DPoP DEPLOYMENT — the four requests that decide whether it is real.
 * Run all four; passing one proves nothing.
 *
 *   1. Baseline. Normal request with a fresh proof.
 *          expect 200
 *
 *   2. Downgrade. Same token, `Authorization: Bearer <token>`, NO DPoP header.
 *          expect 401. A 200 means the binding is optional, which means it is absent:
 *          an attacker simply does not send the proof. THIS IS THE TEST THAT MATTERS
 *          and it is the one most often skipped.
 *
 *   3. Proof replay. Reuse a previously captured proof verbatim, with its original
 *      token, against the same method and URI, within the acceptance window.
 *          expect 401 (jti already seen). A 200 means the server is not tracking jti,
 *          so a proof captured once can be replayed for as long as `iat` is accepted.
 *
 *   4. Proof/token mismatch. A valid proof from key A with a token bound to key B.
 *          expect 401 (cnf.jkt mismatch). A 200 means the binding is decorative.
 *
 * And one more, on the client: confirm the private key is really in the Keystore and
 * not a software key the app generated and stored. `KeyInfo.getSecurityLevel()` is the
 * answer, and 49-KeyStore section 3.8 shows how to read it. A DPoP key kept in a file
 * is stolen at the same moment the token is, and the whole scheme collapses back to
 * bearer semantics with extra CPU cost.
 */
