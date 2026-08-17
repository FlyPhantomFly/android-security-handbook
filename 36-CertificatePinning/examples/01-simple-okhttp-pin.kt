// 36-CertificatePinning/examples/01-simple-okhttp-pin.kt
//
// EXAMPLE 1 of 5 -- SIMPLE.  The smallest correct OkHttp pin, and the smallest
// incorrect one, side by side.
//
// WHAT THIS SHOWS
//   How a pin is expressed, what it is a hash OF, and the single most common
//   way the first attempt is wrong.
//
// HOW TO BUILD
//   This is a fragment, not an app. Drop it into any Android module that has
//       implementation("com.squareup.okhttp3:okhttp:4.12.0")
//   or paste `goodClient()` into a plain JVM project with the same dependency
//   and call it -- OkHttp's CertificatePinner is not Android-specific, and
//   testing it on the JVM first is much faster than testing it on a device.
//
// HOW TO SEE IT WORK
//   Compute the real pin for your host first:
//       ../scripts/spki-pin.sh --host api.github.com --emit okhttp
//   Paste the value. Then run it once with the correct pin (expect 200) and
//   once with a single character changed (expect SSLPeerUnverifiedException
//   with a message that prints both the expected and the found pins).
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch36.example1

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * The correct shape.
 *
 * `sha256/` is not decoration. It names the algorithm, and OkHttp parses it:
 * anything else is rejected at configuration time, not at connection time,
 * which is a small mercy -- you find out at startup rather than in the field.
 *
 * The base64 that follows is SHA-256 over the DER-encoded SubjectPublicKeyInfo
 * of the certificate: the algorithm identifier plus the public key bit string.
 * It is NOT the hash of the certificate. That distinction is the whole reason
 * this pin survives certificate renewal -- renewal re-signs the same key, so
 * the SPKI is byte-identical and the pin still matches. See README section 3.4.
 *
 * TWO pins are configured, not one, and they are not both for the same
 * certificate. The second is the backup: a key that has been generated and
 * pinned but never used. On the day the primary key has to be replaced -- key
 * compromise, a CA that refuses to reissue, an HSM that dies -- the operator
 * switches the server to the backup key and every already-installed copy of
 * the app keeps working. Without it, the only fix is a store update that the
 * affected users may not be able to download, because your API is what their
 * app talks to.
 */
fun goodClient(): OkHttpClient {
    val pinner = CertificatePinner.Builder()
        // Primary: the SPKI of the key currently in production.
        .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        // Backup: a key held offline, never yet presented by any server.
        .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        .build()

    return OkHttpClient.Builder()
        .certificatePinner(pinner)
        .callTimeout(30, TimeUnit.SECONDS)
        .build()
}

/**
 * WRONG, version 1: one pin, on the leaf, with no backup.
 *
 * This is what almost every first implementation looks like, and it works
 * perfectly right up until the certificate is renewed. Renewal with a NEW key
 * pair -- which is what most automated issuance does by default, including the
 * common ACME clients unless told otherwise -- changes the SPKI, so the pin no
 * longer matches, so every installed copy of the app stops working
 * simultaneously. The server is healthy. The certificate is valid. The app is
 * dead. Nothing you can change server-side fixes it.
 *
 * The failure is not subtle and it is not gradual. It is every user at once,
 * at whatever hour the renewal cron ran.
 */
fun brittleClient(): OkHttpClient {
    val pinner = CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build()
    return OkHttpClient.Builder().certificatePinner(pinner).build()
}

/**
 * WRONG, version 2: pinning the wrong hash entirely.
 *
 * Someone runs `openssl x509 -fingerprint -sha256` because it is the first
 * result for "certificate hash", pastes that, and gets a value that is exactly
 * the right shape -- 32 bytes, base64, 44 characters -- and completely wrong,
 * because it is the hash of the certificate, not of the SubjectPublicKeyInfo.
 *
 * OkHttp cannot tell you this at configuration time. The pin parses. It simply
 * never matches anything, so every connection fails with
 * SSLPeerUnverifiedException and the developer concludes that pinning is broken.
 *
 * Diagnose it by reading the exception: OkHttp prints the pins it computed from
 * the actual chain next to the pins it expected. If NONE of the computed values
 * resemble your configured value, you hashed the wrong thing.
 */
fun wrongHashClient(): OkHttpClient {
    // This is a certificate fingerprint, not an SPKI pin. It will never match.
    val pinner = CertificatePinner.Builder()
        .add("api.example.com", "sha256/Q0VSVElGSUNBVEVfRklOR0VSUFJJTlRfTk9UX1NQS0k=")
        .build()
    return OkHttpClient.Builder().certificatePinner(pinner).build()
}

/**
 * WRONG, version 3: the pattern does not match the host you actually call.
 *
 * `CertificatePinner` matches the pattern against the hostname of the request.
 * A pattern with no wildcard matches exactly that host and nothing else. If the
 * app calls `cdn.example.com` and the pin set only names `api.example.com`,
 * the pinner is consulted, finds no pins for that host, and ACCEPTS -- because
 * "no pins configured for this host" means "not pinned", not "denied".
 *
 * That is the correct behaviour and it is also the most under-reported pinning
 * finding there is: the app appears to pin, the developer believes it pins, and
 * the endpoint that carries the interesting data is not pinned at all.
 *
 * `*.example.com` matches one label. `**.example.com` matches any number.
 * Neither matches the apex `example.com` itself.
 */
fun partiallyPinnedClient(): OkHttpClient {
    val pinner = CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        // cdn.example.com, analytics.example.com and example.com are NOT pinned.
        .build()
    return OkHttpClient.Builder().certificatePinner(pinner).build()
}

fun main() {
    val client = goodClient()
    val request = Request.Builder().url("https://api.example.com/v1/ping").build()
    try {
        client.newCall(request).execute().use { response ->
            println("status=${response.code}")
        }
    } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
        // The message contains, verbatim:
        //   Certificate pinning failure!
        //     Peer certificate chain:
        //       sha256/<what was actually presented>: CN=...
        //     Pinned certificates for api.example.com:
        //       sha256/<what you configured>
        // Read both lists before concluding anything. If the presented pin is
        // stable across runs and simply is not in your list, your pin is stale.
        println("PIN REJECTED: ${e.message}")
    }
}
