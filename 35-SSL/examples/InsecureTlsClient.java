/*
 * examples/InsecureTlsClient.java
 *
 * THE VULNERABLE COUNTERPART. Its fix is examples/HardenedTlsClient.java, which
 * is the same file with every decision made correctly, so the two can be
 * diffed line for line.
 *
 * WHAT THIS DEMONSTRATES
 *   Four independent ways an Android app throws away transport security, all of
 *   which are found constantly in production applications, and each of which
 *   fails in a DIFFERENT way:
 *
 *     A. A TrustManager that accepts every certificate chain.
 *        -> any certificate from anyone is accepted. Full interception.
 *
 *     B. A HostnameVerifier that returns true.
 *        -> a VALID certificate for attacker.example is accepted for
 *           api.bank.example. The chain check passes honestly; the identity
 *           check is the one that was removed. This is the failure people
 *           forget exists, because "the certificate was valid" sounds fine.
 *
 *     C. Trusting the USER certificate store explicitly.
 *        -> not a bug by itself, but it re-opens what API 24 deliberately
 *           closed, and it is nearly always left in a release build by
 *           accident.
 *
 *     D. Swallowing SSLHandshakeException and retrying over cleartext.
 *        -> the app validates correctly, refuses, and then does the request
 *           anyway with no TLS at all. Every static check passes.
 *
 * WHY DEVELOPERS WRITE THIS
 *   Not stupidity. Every one of these is the shortest path out of a real
 *   problem:
 *     - the staging server has a self-signed certificate and the sprint ends
 *       on Friday;
 *     - the QA environment's certificate is issued for the load balancer's
 *       internal name, not the URL the app uses;
 *     - the corporate proxy re-signs everything with an internal CA;
 *     - "it works on my machine" because the developer installed the CA on
 *       their own device.
 *   The code is written to unblock a build, and it ships because nothing about
 *   it looks different at runtime. A permissive TrustManager produces the same
 *   green padlock and the same successful responses as a correct one, right up
 *   until somebody is on the same network as your user.
 *
 * HOW TO BUILD
 *   Do not build this on its own -- it is an Activity and needs an app around
 *   it. See examples/README.md for the no-Gradle build command, which follows
 *   the pattern in ../../30-Activities/examples/build.sh. NO APK IS SHIPPED IN
 *   THIS REPOSITORY; you build it yourself in one command.
 *
 * HOW TO CONFIRM EACH BUG AT RUNTIME
 *   frida -U -f com.pentest.ch35.insecure -l ../scripts/trace-tls-validation.js
 *   then call oracle() -- pattern A's TrustManager will be reported as having
 *   accepted a zero-length chain.
 *
 * AUTHORISED TESTING AND TEACHING ONLY. Do not copy any of this into a real
 * application. That warning is not a formality: pattern A has been copied out
 * of Stack Overflow answers into shipping banking apps more than once.
 */

package com.pentest.ch35.insecure;

import android.app.Activity;
import android.os.Bundle;
import android.os.StrictMode;
import android.util.Log;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class InsecureTlsClient extends Activity {

    private static final String TAG = "ch35.insecure";

    /**
     * The endpoint this demo talks to. Point it at your own test server, or at
     * an interception proxy, before running anything.
     */
    private static final String ENDPOINT = "https://example.com/";

    private TextView output;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        output = new TextView(this);
        setContentView(output);

        // Networking on the main thread is itself bad practice; it is done here
        // only so the demo is one file with no threading noise. StrictMode is
        // relaxed for the same reason. Do not copy this either.
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder()
                .permitAll().build());

        StringBuilder sb = new StringBuilder();
        sb.append(patternA_trustEverything()).append("\n\n");
        sb.append(patternB_verifyNothing()).append("\n\n");
        sb.append(patternC_trustUserStore()).append("\n\n");
        sb.append(patternD_fallBackToCleartext()).append("\n");
        output.setText(sb.toString());
    }

    // =====================================================================
    // PATTERN A -- the trust-everything TrustManager
    //
    // This is the single most common TLS bug in Android applications. Note
    // what makes it work: X509TrustManager.checkServerTrusted has a VOID
    // return type. There is no `return true` to write. Accepting is expressed
    // by NOT THROWING -- so an empty method body is a complete, compiling,
    // silently catastrophic implementation.
    //
    // That asymmetry is why this bug is so easy to introduce and so hard to
    // spot in review: the vulnerable version contains LESS code than the
    // correct one, and there is no keyword anywhere that says "insecure".
    // =====================================================================
    private String patternA_trustEverything() {
        try {
            TrustManager[] trustEverything = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType)
                                throws CertificateException {
                            // Empty. Accepts every client certificate.
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType)
                                throws CertificateException {
                            // Empty. THIS IS THE BUG.
                            //
                            // Returning normally means "this chain is trusted".
                            // The method is handed the chain the server sent
                            // and does not look at it. A self-signed
                            // certificate generated ten seconds ago by anyone
                            // on the path is accepted exactly as readily as a
                            // certificate from a public CA.
                            //
                            // It does not even check for a null or empty chain,
                            // which the interface contract requires. That is
                            // what makes the empty-chain oracle in
                            // ../scripts/trace-tls-validation.js decisive.
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            // Returning an empty array rather than null is what
                            // keeps this from crashing in some stacks. An empty
                            // issuer list means "I vouch for no one", which
                            // ought to mean nothing validates -- but because
                            // checkServerTrusted never consults it, it has no
                            // effect at all.
                            return new X509Certificate[0];
                        }
                    }
            };

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, trustEverything, new SecureRandom());

            // Installing it as the DEFAULT is worse than using it for one
            // connection: it silently applies to every HttpsURLConnection the
            // app makes afterwards, including ones in third-party SDKs that
            // never asked for it.
            HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());

            String body = fetch(ENDPOINT, null, null);
            return "A. trust-everything TrustManager: connected, " + body.length()
                    + " bytes. Any certificate would have worked.";
        } catch (Exception e) {
            Log.w(TAG, "pattern A failed", e);
            return "A. trust-everything TrustManager: " + e;
        }
    }

    // =====================================================================
    // PATTERN B -- the hostname verifier that verifies nothing
    //
    // Chain validation and hostname verification are two SEPARATE steps, and
    // this app breaks only the second one. That distinction matters more than
    // it looks:
    //
    //   * With pattern A, an attacker needs no certificate at all.
    //   * With pattern B, the chain is still validated properly -- the
    //     attacker needs a certificate that a real, trusted CA actually
    //     issued. But it can be a certificate for ANY name. A certificate for
    //     a domain the attacker legitimately owns, costing nothing from a
    //     free CA, is accepted for your bank's API.
    //
    // So pattern B is not "less bad". It is a full authentication bypass that
    // costs the attacker one free certificate and leaves the padlock intact.
    // =====================================================================
    private String patternB_verifyNothing() {
        try {
            // The chain IS validated here: no custom TrustManager is installed
            // for this connection, so the platform default runs and does its
            // job honestly.
            HostnameVerifier acceptAnyHostname = new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    // THIS IS THE BUG. `hostname` is the host the app asked
                    // for; `session` holds the certificate the server actually
                    // presented. Comparing them is the entire purpose of this
                    // method, and this implementation compares nothing.
                    return true;
                }
            };

            String body = fetch(ENDPOINT, null, acceptAnyHostname);
            return "B. permissive HostnameVerifier: connected, " + body.length()
                    + " bytes. A valid certificate for ANY name would have worked.";
        } catch (Exception e) {
            Log.w(TAG, "pattern B failed", e);
            return "B. permissive HostnameVerifier: " + e;
        }
    }

    // =====================================================================
    // PATTERN C -- explicitly trusting the user certificate store
    //
    // From API 24 onward the platform stopped trusting user-installed CAs by
    // default. This code puts that back, in application code, where no
    // manifest review and no network_security_config audit will find it.
    //
    // It is not automatically a vulnerability -- an enterprise MDM deployment
    // may genuinely need it -- but it is nearly always a debugging shortcut
    // that survived to release. The honest severity depends entirely on
    // whether it was intended, which is a question for the developer, not for
    // the scanner.
    //
    // Note the mechanism: the "AndroidCAStore" KeyStore type contains BOTH the
    // system and the user store. Feeding it to a TrustManagerFactory produces
    // a TrustManager that trusts everything in both -- which is precisely the
    // pre-API-24 behaviour.
    // =====================================================================
    private String patternC_trustUserStore() {
        try {
            KeyStore androidCaStore = KeyStore.getInstance("AndroidCAStore");
            androidCaStore.load(null, null);

            int count = androidCaStore.size();

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(androidCaStore);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), new SecureRandom());

            String body = fetch(ENDPOINT, context, null);
            return "C. AndroidCAStore (system + user): " + count
                    + " anchors trusted, connected, " + body.length() + " bytes."
                    + " A CA the user installed is now trusted again.";
        } catch (Exception e) {
            Log.w(TAG, "pattern C failed", e);
            return "C. AndroidCAStore: " + e;
        }
    }

    // =====================================================================
    // PATTERN D -- validate correctly, then give up and use cleartext
    //
    // The nastiest of the four, because every piece of TLS code here is
    // correct. There is no permissive TrustManager to grep for and no
    // HostnameVerifier to find. The bug is in the CATCH BLOCK: a handshake
    // failure is treated as a transient network problem and retried without
    // TLS.
    //
    // An attacker does not need a certificate at all. They need only to make
    // the TLS handshake fail -- by presenting any invalid certificate, or by
    // resetting the connection -- and the app downgrades itself.
    //
    // On API 28 and above this specific version is stopped by the platform,
    // because cleartext is blocked by default; the app gets an IOException
    // instead. That default is exactly what 44-NetworkSecurityConfig is
    // about, and an app that sets cleartextTrafficPermitted="true" removes the
    // only thing standing between this code and a plaintext password.
    // =====================================================================
    private String patternD_fallBackToCleartext() {
        try {
            String body = fetch(ENDPOINT, null, null);
            return "D. TLS succeeded, " + body.length() + " bytes (no fallback needed)";
        } catch (SSLHandshakeException handshakeFailed) {
            // THIS IS THE BUG. The handshake failed. That is the system working
            // -- it is the one signal that says "somebody is in the middle" --
            // and this code responds by removing the protection that produced
            // the signal.
            Log.w(TAG, "TLS failed, retrying over cleartext", handshakeFailed);
            try {
                String plain = ENDPOINT.replaceFirst("^https://", "http://");
                String body = fetch(plain, null, null);
                return "D. cleartext fallback: TLS was refused, sent it in plaintext"
                        + " anyway, " + body.length() + " bytes";
            } catch (Exception e) {
                return "D. cleartext fallback also failed: " + e
                        + "  (on API 28+ the platform blocks this by default)";
            }
        } catch (Exception e) {
            Log.w(TAG, "pattern D failed", e);
            return "D. " + e;
        }
    }

    // =====================================================================
    // Shared request helper. Deliberately boring.
    // =====================================================================
    private String fetch(String url, SSLContext context, HostnameVerifier verifier)
            throws Exception {
        java.net.URLConnection raw = new URL(url).openConnection();
        if (raw instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) raw;
            if (context != null) {
                https.setSSLSocketFactory(context.getSocketFactory());
            }
            if (verifier != null) {
                https.setHostnameVerifier(verifier);
            }
        }
        raw.setConnectTimeout(10000);
        raw.setReadTimeout(10000);

        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(
                new InputStreamReader(raw.getInputStream(), "UTF-8"));
        try {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } finally {
            reader.close();
        }
        return sb.toString();
    }
}
