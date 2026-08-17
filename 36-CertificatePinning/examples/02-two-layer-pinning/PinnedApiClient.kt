// 36-CertificatePinning/examples/02-two-layer-pinning/PinnedApiClient.kt
//
// EXAMPLE 2 of 5 -- INTERMEDIATE.  An app that pins at TWO independent layers.
//
// This is the example the whole chapter turns on. It exists so that you can
// experience, on code you wrote yourself, the failure mode that wastes more
// pentest hours than any other in mobile network testing:
//
//     You hook the Java pin. Frida says "hooked". Logcat says the pin was
//     bypassed. The proxy still shows nothing. Nothing in the output tells you
//     that a second pin, in native code, is still running.
//
// LAYER A (Java)   : okhttp3.CertificatePinner -- the pin everyone hooks.
// LAYER B (native) : an SPKI comparison inside a BoringSSL custom_verify
//                    callback in native_pin.c -- reached by no Java hook.
//
// The two layers are deliberately independent: neither knows about the other,
// and each is sufficient on its own to refuse the connection. That is exactly
// how real defence-in-depth pinning is built, and exactly why a bypass script
// that reports six successful hooks can still leave you with no traffic.
//
// BUILD
//   See README.md in this directory. Sources only -- no .so, no .apk is
//   committed anywhere in this repository.
//
// AUTHORISED TESTING ONLY. This is YOUR app; break it freely. Doing the same to
// somebody else's is a different act with different consequences -- see
// ../../README.md section 5.1.

package com.pentest.ch36.twolayer

import android.util.Log
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import java.util.concurrent.TimeUnit

private const val TAG = "ch36-twolayer"

/**
 * The host this client is pinned to. Change it to a host you control before
 * building; the pins below are placeholders and will not match anything.
 *
 * Generate real values with:
 *     ../../scripts/spki-pin.sh --host your.host --emit okhttp
 */
const val PINNED_HOST = "api.example.com"

/** Primary pin: SHA-256 of the DER SubjectPublicKeyInfo of the production key. */
const val PIN_PRIMARY = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

/** Backup pin: a key generated and pinned, never yet served. */
const val PIN_BACKUP = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

/**
 * LAYER A -- the Java pin.
 *
 * This is the layer that `okhttp3.CertificatePinner` implements, and the layer
 * that every published bypass hooks first. Two facts about it matter for the
 * rest of this example:
 *
 *  1. It runs AFTER trust validation, not instead of it. By the time
 *     CertificatePinner.check is called, the trust manager has already built
 *     and accepted a chain. A pin failure therefore proves the chain was
 *     otherwise valid -- which is why "I installed my CA and now I get a
 *     pinning error" is progress, not a setback.
 *
 *  2. It is a plain Java method call with a void return. Making it return
 *     normally is all a bypass has to do. There is no state to fake, no
 *     handshake to replay. That is not a weakness in OkHttp; it is a
 *     consequence of the check running inside a process the attacker owns.
 */
object JavaLayer {

    fun buildClient(): OkHttpClient {
        val pinner = CertificatePinner.Builder()
            .add(PINNED_HOST, PIN_PRIMARY)
            .add(PINNED_HOST, PIN_BACKUP)
            .build()

        Log.i(TAG, "layer A: OkHttp CertificatePinner configured for $PINNED_HOST")

        return OkHttpClient.Builder()
            .certificatePinner(pinner)
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()
    }
}

/**
 * LAYER B -- the native pin.
 *
 * Everything interesting happens in native_pin.c. This object is only the JNI
 * doorway to it. Note what is deliberately NOT here:
 *
 *   - The pin value is not in Kotlin, so it does not appear in the DEX and
 *     `../../scripts/pinning-surface.py` will report it under layer 7, not
 *     layer 3. Verify that for yourself; it is the point of the exercise.
 *   - There is no Java method whose return value decides anything. The decision
 *     is a C function's return value, inside a callback BoringSSL invokes. A
 *     Java hook has nothing to attach to.
 *
 * `nativeFetch` performs its own TLS connection using the statically linked
 * BoringSSL in the native library. It shares nothing with OkHttp: not the
 * socket, not the trust store, not the proxy setting. An app built this way
 * will ignore `settings put global http_proxy` entirely for these requests,
 * which is itself a diagnostic -- if some of an app's traffic appears in your
 * proxy and some does not, suspect two stacks rather than one broken hook.
 */
object NativeLayer {

    private var available = false

    init {
        available = try {
            System.loadLibrary("nativepin")
            Log.i(TAG, "layer B: libnativepin.so loaded")
            true
        } catch (e: UnsatisfiedLinkError) {
            // Deliberately non-fatal, so the app still demonstrates layer A
            // alone if you have not built the native library yet.
            Log.w(TAG, "layer B: libnativepin.so missing (${e.message}) -- " +
                       "only the Java pin is active")
            false
        }
    }

    fun isAvailable(): Boolean = available

    /** Returns the response body, or throws IOException carrying the reason. */
    @Throws(IOException::class)
    external fun nativeFetch(host: String, port: Int, path: String): String

    /**
     * Returns the pin the native layer is configured with, so the lab can
     * prove the native layer exists without decompiling anything. A real app
     * would obviously not expose this -- it is here as scaffolding.
     */
    external fun nativeConfiguredPin(): String
}

/**
 * The client the app actually uses. Both layers must accept.
 *
 * Read the failure handling carefully, because it is the honest version of
 * something most apps get wrong. Each layer's rejection is reported with the
 * LAYER NAMED. Most real apps catch a generic IOException and log "network
 * error", and that single decision is why diagnosing a pin failure from the
 * outside is so much harder than it needs to be -- for the attacker AND for
 * the developer's own support team.
 */
class PinnedApiClient {

    private val http = JavaLayer.buildClient()

    fun fetchViaJava(path: String): Result<String> {
        val request = Request.Builder()
            .url("https://$PINNED_HOST$path")
            .build()
        return try {
            http.newCall(request).execute().use { r ->
                Result.success(r.body?.string() ?: "")
            }
        } catch (e: javax.net.ssl.SSLPeerUnverifiedException) {
            Log.e(TAG, "LAYER A REJECTED (OkHttp CertificatePinner): ${e.message}")
            Result.failure(e)
        } catch (e: IOException) {
            Log.e(TAG, "LAYER A transport error (NOT a pin failure): ${e.message}")
            Result.failure(e)
        }
    }

    fun fetchViaNative(path: String): Result<String> {
        if (!NativeLayer.isAvailable()) {
            return Result.failure(IllegalStateException("native layer not built"))
        }
        return try {
            Result.success(NativeLayer.nativeFetch(PINNED_HOST, 443, path))
        } catch (e: IOException) {
            // native_pin.c throws IOException with a message beginning
            // "native pin rejected:" when the SPKI comparison fails.
            Log.e(TAG, "LAYER B REJECTED (native SPKI compare): ${e.message}")
            Result.failure(e)
        }
    }

    /**
     * Both layers, in the order an app would naturally use them.
     *
     * This is the method to call from your Activity while the bypass is
     * running. The expected experience during the lab:
     *
     *   run 1, no bypass          -> A rejects (your proxy's key is not pinned)
     *   run 2, Java bypass only   -> A accepts, B rejects. Logcat shows layer B.
     *                                Burp shows the OkHttp request and NOT the
     *                                native one. THIS is the moment worth
     *                                sitting with.
     *   run 3, Java + native      -> both accept, all traffic in the proxy.
     */
    fun fetchBoth(path: String) {
        val a = fetchViaJava(path)
        Log.i(TAG, "layer A result: ${if (a.isSuccess) "OK" else "REJECTED"}")
        val b = fetchViaNative(path)
        Log.i(TAG, "layer B result: ${if (b.isSuccess) "OK" else "REJECTED"}")

        if (a.isSuccess && b.isFailure) {
            Log.w(TAG, "Java layer bypassed, native layer still pinning. " +
                       "A bypass script would report total success here.")
        }
    }
}
