// 36-CertificatePinning/labs/ctf-pin-that-moved/PinGate.kt
//
// The Java half of the "pin that moved" CTF target.
//
// READ THIS ONLY AFTER YOU HAVE TRIED THE CHALLENGE, or read it and treat the
// build as an exercise in construction rather than discovery. Either is a
// legitimate way to use it -- building the target teaches a different half of
// the lesson from breaking it.
//
// WHAT IT DOES
//   Two request paths, and the whole puzzle is in the difference:
//
//     fetchDecoy()  -- OkHttp, pinned in Java, hits /flag. Anyone who gets a
//                      connection up gets the decoy flag. It proves nothing and
//                      the server says so.
//
//     claimFlag()   -- goes through the NATIVE gate in pin_gate.c, which
//                      computes the SPKI of whatever certificate it accepted
//                      and sends it as X-Accepted-Pin to /claim. The real flag
//                      comes back only when that header names the key the
//                      server is currently serving AND that key is the rotated
//                      one.
//
//   So a universal bypass gets you the decoy immediately and the real flag
//   never, because the oracle needs evidence of a specific acceptance and
//   "everything is accepted" is not evidence of anything.
//
// AUTHORISED TESTING ONLY. This is a target you build.

package com.pentest.ch36.ctf

import android.util.Log
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

private const val TAG = "ch36-ctf"

/** Set to the address of challenge_server.py. */
const val CTF_HOST = "lab.local"
const val CTF_PORT = 8443

/**
 * The Java pin set.
 *
 * Both values come from `challenge_server.py --pins`. Note carefully which two:
 *
 *   ORIGINAL -- the key the server starts on. Legitimate.
 *   DECOY    -- a key the server has NEVER served and never will.
 *
 * The decoy is here to be found. It is the loudest string in the APK, it is in
 * the DEX where every scanner looks, and it is completely useless: sending its
 * value to /claim gets a 403 with a pointed message.
 *
 * The pin that matters is not in this file.
 */
const val PIN_ORIGINAL = "sha256/REPLACE_WITH_ORIGINAL_FROM_SERVER_SETUP"
const val PIN_DECOY = "sha256/REPLACE_WITH_DECOY_FROM_SERVER_SETUP"

object CtfClient {

    private val client: OkHttpClient by lazy {
        val pinner = CertificatePinner.Builder()
            .add(CTF_HOST, PIN_ORIGINAL)
            .add(CTF_HOST, PIN_DECOY)
            .build()

        Log.i(TAG, "java pin set configured for $CTF_HOST")

        OkHttpClient.Builder()
            .certificatePinner(pinner)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Reachability check. Deliberately provided, because "did the app even try"
     * is the first question in every failed interception and the challenge
     * should not hinge on infrastructure debugging.
     */
    fun ping(): String = try {
        val req = Request.Builder().url("https://$CTF_HOST:$CTF_PORT/ping").build()
        client.newCall(req).execute().use { it.body?.string() ?: "" }
    } catch (e: Exception) {
        Log.e(TAG, "ping failed: ${e.javaClass.simpleName}: ${e.message}")
        "ERROR: ${e.message}"
    }

    /**
     * The decoy path.
     *
     * Bypass the Java pin however you like and this returns a flag. It is the
     * wrong flag. The server hands it to anybody, which is the point: a
     * response that arrives no matter what you did tells you nothing about what
     * you did.
     */
    fun fetchDecoy(): String = try {
        val req = Request.Builder().url("https://$CTF_HOST:$CTF_PORT/flag").build()
        client.newCall(req).execute().use { it.body?.string() ?: "" }
    } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
        Log.e(TAG, "java pin rejected: ${e.message}")
        "PINNED"
    } catch (e: Exception) {
        "ERROR: ${e.message}"
    }

    /**
     * The real path. Everything happens in pin_gate.c.
     *
     * The native gate:
     *   1. connects with its own BoringSSL, ignoring the system proxy,
     *   2. runs its own pin comparison against a value that is not stored as a
     *      string anywhere,
     *   3. computes the SPKI of the certificate IT accepted,
     *   4. sends that as X-Accepted-Pin to /claim.
     *
     * Step 4 is why "disable all verification" loses. The header is filled in
     * from what the gate accepted; a gate that accepts everything still has to
     * report something, and reporting the wrong thing gets a 403.
     */
    external fun claimFlag(host: String, port: Int): String

    init {
        try {
            System.loadLibrary("pingate")
            Log.i(TAG, "native gate loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "native gate missing: ${e.message}")
        }
    }
}
