// 36-CertificatePinning/examples/04-pins-that-are-not-pins.kt
//
// EXAMPLE 4 of 5 -- REAL APPLICATION.  Five things shipped in production apps
// that the developer believed were certificate pinning, and were not.
//
// WHY THIS IS THE MOST USEFUL FILE IN THE DIRECTORY
//   You will assess far more apps that BELIEVE they pin than apps that do. The
//   difference between the two is not visible from a feature list, a
//   questionnaire answer, or an automated scanner's output -- all three will
//   say "certificate pinning: yes" for every case below.
//
//   It is visible from about ninety seconds of reading the code. This file
//   teaches you what to look for, and gives you the wording for the finding.
//
// EACH CASE HAS
//   the code, what the developer thought it did, what it actually does, how to
//   detect it statically and dynamically, and the honest severity -- which is
//   NOT always "high", and in one case is "not a finding at all".
//
// AUTHORISED TESTING ONLY.

package com.pentest.ch36.antipatterns

import android.annotation.SuppressLint
import android.util.Log
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSession
import javax.net.ssl.X509TrustManager

private const val TAG = "ch36-antipattern"

// ===========================================================================
// CASE 1 -- the empty pinner
//
// WHAT THE DEVELOPER THINKS: "we use CertificatePinner, so we pin."
// WHAT IT DOES:              nothing at all.
//
// CertificatePinner with no pins configured accepts every chain the trust
// manager already accepted. It is not a no-op that fails safe or fails
// dangerously; it is simply absent. The class is present in the DEX, so every
// static scanner reports pinning, including the naive version of this
// chapter's own detector -- which is exactly why
// ../scripts/pinning-surface.py grades an okhttp3.CertificatePinner class
// reference as LOW confidence and requires an actual base64 digest before it
// says "PIN CONFIGURED".
//
// DETECT STATICALLY:  grep the DEX for `sha256/` followed by 43 base64 chars
//                     and a '='. No hit, no pin.
// DETECT DYNAMICALLY: pin-attribution.js prints every
//                     CertificatePinner.Builder.add call at startup. Zero
//                     calls means zero pins.
// SEVERITY:           informational. The app is not pinning; whether that
//                     MATTERS is a separate question -- see case 5.
// ===========================================================================

fun case1_emptyPinner(): OkHttpClient {
    val pinner = CertificatePinner.Builder().build()   // no .add() anywhere
    return OkHttpClient.Builder().certificatePinner(pinner).build()
}

// ===========================================================================
// CASE 2 -- the pin that was disabled and never re-enabled
//
// WHAT THE DEVELOPER THINKS: "pinning is behind a flag for the staging build."
// WHAT IT DOES:              nothing, in every build, because the flag is a
//                            constant and R8 deleted the pinning branch.
//
// This is the single most common real-world case. The build flag was added so
// QA could use a proxy, and it was never wired to the build type. In the
// release APK the entire pinning branch is DEAD CODE that R8 removed, so the
// `sha256/` string is not even in the APK -- which means the app looks
// completely unpinned to a static tool, and the developer's answer to "do you
// pin?" is a sincere yes.
//
// DETECT STATICALLY:  compare the source (if you have it) against the shipped
//                     DEX. In the APK alone, look for the pin CONSTANT: if
//                     the code that builds the pinner is present but the
//                     digest strings are absent, the branch was folded away.
// DETECT DYNAMICALLY: connect through a proxy with your CA in the system
//                     store. If it works and the app claims to pin, this or
//                     case 1 is why.
// SEVERITY:           the app is unpinned. Report it as "the pinning control
//                     described in the design is not present in the shipped
//                     build", which is a documentation-versus-reality finding
//                     as much as a technical one.
// ===========================================================================

private const val ENABLE_PINNING = false      // was going to be BuildConfig.DEBUG

fun case2_deadFlag(): OkHttpClient {
    val builder = OkHttpClient.Builder()
    if (ENABLE_PINNING) {
        // R8 removes this entire block. The digest never reaches the APK.
        builder.certificatePinner(
            CertificatePinner.Builder()
                .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build()
        )
    }
    return builder.build()
}

// ===========================================================================
// CASE 3 -- the permissive TrustManager that LOOKS like pinning
//
// WHAT THE DEVELOPER THINKS: "we have a custom TrustManager for our
//                             certificate, so we pin."
// WHAT IT DOES:              accepts literally every certificate, from
//                            anybody, forever. It is not weaker pinning. It is
//                            weaker than NO pinning, because it disables the
//                            platform validation that would otherwise have
//                            protected the app.
//
// The shape is unmistakable once you have seen it: checkServerTrusted with an
// empty body. There is no throw, so there is no rejection. This usually
// started as a workaround for a self-signed staging certificate.
//
// This one belongs to chapter 35-SSL as a trust failure, and is here because
// it is CONSTANTLY reported as "pinning implemented incorrectly". It is not
// pinning at all, and the distinction changes the severity by two levels: a
// weak pin still validates the chain; this validates nothing.
//
// DETECT STATICALLY:  an X509TrustManager whose checkServerTrusted has an
//                     empty body. In smali: a method with `.locals 0` and only
//                     `return-void`. jadx shows a `{ }` body.
// DETECT DYNAMICALLY: present ANY self-signed certificate -- one you generated
//                     thirty seconds ago, for the wrong hostname, expired.
//                     If it is accepted, this is why.
// SEVERITY:           HIGH. Anyone on the network path reads and modifies all
//                     traffic, with no CA and no device access required.
// ===========================================================================

@SuppressLint("CustomX509TrustManager")
class Case3_TrustEverything : X509TrustManager {
    @SuppressLint("TrustAllX509TrustManager")
    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // empty: accepts anything
    }

    @SuppressLint("TrustAllX509TrustManager")
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        // empty: accepts anything.
        //
        // Note what a reader might mistake for validation: the developer often
        // leaves a comment here saying "our certificate is checked in
        // Case3_HostnameCheck below". It is not. A HostnameVerifier runs on a
        // chain this method has already accepted, and it checks a NAME, not a
        // key. Names are free.
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

fun case3_client(): OkHttpClient {
    val ctx = SSLContext.getInstance("TLS")
    val tm = Case3_TrustEverything()
    ctx.init(null, arrayOf<javax.net.ssl.TrustManager>(tm), java.security.SecureRandom())
    return OkHttpClient.Builder()
        .sslSocketFactory(ctx.socketFactory, tm)
        .hostnameVerifier(Case3_HostnameCheck())
        .build()
}

/**
 * The "check" the developer points at. It compares a string. An attacker with
 * any certificate for any name -- including one they issued themselves, since
 * case 3's trust manager accepts it -- sets the CN to `api.example.com` and
 * passes this.
 */
class Case3_HostnameCheck : HostnameVerifier {
    override fun verify(hostname: String?, session: SSLSession?): Boolean {
        return hostname == "api.example.com"
    }
}

// ===========================================================================
// CASE 4 -- pinning the wrong host, or the right host by the wrong name
//
// WHAT THE DEVELOPER THINKS: "the API is pinned."
// WHAT IT DOES:              pins one hostname while the credentials travel to
//                            a different one.
//
// CertificatePinner matches the pattern against the request hostname. No
// pattern for a host means NOT PINNED for that host, and the pinner accepts
// silently. That is correct behaviour and it is why this is so easy to miss:
// nothing errors, nothing logs, and the pinned host really is pinned.
//
// The variants, in rough order of how often they appear:
//   - the login/token endpoint is on auth.example.com; only api.example.com
//     is pinned
//   - `*.example.com` is pinned; the app calls the apex `example.com`, which
//     `*` does not match
//   - the app calls a regional host (api-eu.example.com) chosen at runtime
//   - a third-party SDK in the same process makes its own requests entirely
//
// DETECT STATICALLY:  enumerate every URL and host in the app, then diff
//                     against the pinned patterns. The diff is the finding.
// DETECT DYNAMICALLY: pin-attribution.js logs the host for every
//                     CertificatePinner.check call. Any host that appears in
//                     traffic and never appears in a check is unpinned.
// SEVERITY:           depends entirely on what moves over the unpinned host.
//                     The token endpoint being unpinned while the data API is
//                     pinned is a serious finding. An unpinned image CDN is
//                     usually not.
// ===========================================================================

fun case4_partialCoverage(): OkHttpClient {
    val pinner = CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
        .build()

    // Meanwhile, elsewhere in the app:
    //   POST https://auth.example.com/oauth/token     <- NOT pinned
    //   GET  https://flags.example.com/config         <- NOT pinned
    //   the analytics SDK's own OkHttpClient          <- NOT pinned, and not
    //                                                    even using this one
    return OkHttpClient.Builder().certificatePinner(pinner).build()
}

// ===========================================================================
// CASE 5 -- no pinning at all, which is often FINE
//
// This case is here because the previous four make it easy to conclude that
// every app should pin, and that an app which does not has a vulnerability.
// Neither is true, and writing it up that way is the most common bad finding
// in mobile network testing.
//
// Pinning is a control against ONE threat: a certificate that chains to a CA
// the device trusts but that you did not authorise. Mis-issuance, a compelled
// or compromised CA, a corporate MITM appliance, or an attacker who has got a
// CA into the user's trust store.
//
// If the app's threat model does not include that, standard TLS validation
// with a modern trust store is a complete, adequate control -- and pinning
// adds operational risk (see the renewal discussion in README section 3.4)
// without adding security.
//
// The correct write-up for an app with no pinning is not "vulnerability: no
// certificate pinning". It is a statement of fact plus an assessment of
// whether the threat model warrants it:
//
//   "The application relies on platform certificate validation and does not
//    pin. Cleartext is disabled and the user trust store is not consulted
//    (targetSdk 34, no <certificates src="user"/>), so interception requires
//    a certificate chaining to a system CA. For an application handling
//    [X], we consider this [adequate / insufficient because Y]."
//
// The severity of "no pinning" is a judgement about the data and the users,
// not a property of the code. See README section 5.2, and note that OWASP
// MASVS-NETWORK-2 is explicitly conditional -- it applies when the app's
// threat model requires it, not universally.
// ===========================================================================

fun case5_noPinning(): OkHttpClient {
    // Nothing here is wrong. Platform validation, system trust store,
    // cleartext disabled by the network security config.
    Log.i(TAG, "no pinning: this may be entirely appropriate")
    return OkHttpClient.Builder().build()
}
