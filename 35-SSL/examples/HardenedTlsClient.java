/*
 * examples/HardenedTlsClient.java
 *
 * THE FIXED COUNTERPART to examples/InsecureTlsClient.java. Same four
 * situations, every decision made correctly, so the two files can be diffed
 * side by side.
 *
 * THE HEADLINE, BEFORE ANY CODE
 *   The correct fix for three of the four bugs in InsecureTlsClient.java is to
 *   DELETE CODE. Not to write a better TrustManager -- to write none at all.
 *
 *       new URL(url).openConnection()
 *
 *   with no SSLContext, no TrustManager, no HostnameVerifier and no try/catch
 *   around the handshake, is already correct on every supported Android
 *   release. It validates the chain, checks the validity window, enforces
 *   basicConstraints, verifies the hostname against the certificate's SANs,
 *   and refuses cleartext by default from API 28. Every line an app adds on
 *   top of that is a line that can only make it worse.
 *
 *   This is the single most important thing in this file, and it is worth
 *   saying to a developer in exactly these terms: **the secure version is
 *   shorter than the insecure one.** The reason people write the insecure
 *   version is not that the secure one is hard; it is that they are trying to
 *   make a specific broken environment work, and reaching for the platform
 *   default feels like it is not "doing" anything.
 *
 * WHAT EACH SECTION FIXES
 *   A. trust-everything TrustManager   -> delete it; use the platform default.
 *   B. permissive HostnameVerifier     -> delete it; use the platform default.
 *   C. trusting the user store in code -> delete it; if a private CA is
 *                                         genuinely required, pin the ANCHOR
 *                                         explicitly in a private trust store,
 *                                         which is narrower than trusting
 *                                         every CA the user ever installed.
 *   D. cleartext fallback on handshake -> delete the fallback; a handshake
 *      failure                            failure is a signal, not a retryable
 *                                         network error.
 *
 * HOW TO BUILD
 *   See examples/README.md. NO APK IS SHIPPED IN THIS REPOSITORY.
 *
 * HOW TO VERIFY THE FIX
 *   Run the deliberate-bad-certificate test from labs/lab-02. A correct app
 *   REFUSES all four bad certificates. Verifying that the good path still
 *   works proves nothing on its own -- the insecure version passes that test
 *   too, which is exactly why it shipped.
 */

package com.pentest.ch35.hardened;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class HardenedTlsClient extends Activity {

    private static final String TAG = "ch35.hardened";

    private static final String ENDPOINT = "https://example.com/";

    private TextView output;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        output = new TextView(this);
        setContentView(output);

        // Unlike the insecure example, this one does NOT relax StrictMode and
        // does NOT run network calls on the main thread. That is not a TLS
        // matter, but an app that disables StrictMode to make something work
        // has usually disabled other things too, and it is worth noticing.
        new FetchTask().execute(ENDPOINT);
    }

    private class FetchTask extends AsyncTask<String, Void, String> {
        @Override
        protected String doInBackground(String... urls) {
            StringBuilder sb = new StringBuilder();
            sb.append(fixA_useThePlatformDefault(urls[0])).append("\n\n");
            sb.append(fixB_letThePlatformVerifyTheHostname(urls[0])).append("\n\n");
            sb.append(fixC_privateAnchorDoneProperly(urls[0])).append("\n\n");
            sb.append(fixD_failClosed(urls[0])).append("\n");
            return sb.toString();
        }

        @Override
        protected void onPostExecute(String result) {
            output.setText(result);
        }
    }

    // =====================================================================
    // FIX A -- use the platform default. That is the entire fix.
    //
    // Compare with InsecureTlsClient.patternA_trustEverything, which is about
    // forty lines of anonymous class. This is four lines, and it does strictly
    // more: it validates the chain against the device's configured trust
    // anchors, enforces the validity window at every link, honours
    // basicConstraints and pathLen so a leaf certificate cannot sign for
    // another host, and applies whatever the app's network_security_config
    // says -- all without the app knowing any of it exists.
    //
    // Note what is absent and must STAY absent:
    //   - no SSLContext.getInstance(...)
    //   - no context.init(...)
    //   - no setDefaultSSLSocketFactory(...)
    //   - no setSSLSocketFactory(...)
    // Each of those is a place to make a mistake, and none of them is needed.
    // =====================================================================
    private String fixA_useThePlatformDefault(String url) {
        try {
            HttpsURLConnection connection =
                    (HttpsURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);

            // Reading the negotiated parameters is not required for security.
            // It is here because being able to state what your app actually
            // negotiated -- rather than what you assume it negotiated -- is
            // the difference between an assertion and a measurement.
            connection.connect();
            String protocol = connection.getCipherSuite() != null
                    ? connection.getCipherSuite() : "(unknown)";

            String body = readAll(connection);
            connection.disconnect();

            return "A. platform default: connected, " + body.length()
                    + " bytes, cipher suite " + protocol
                    + ". A bad certificate would have thrown.";
        } catch (SSLHandshakeException e) {
            // The RIGHT behaviour: surface it, do not work around it.
            return "A. platform default REFUSED the connection: " + e.getMessage()
                    + "   (this is the system working)";
        } catch (Exception e) {
            Log.w(TAG, "fix A failed", e);
            return "A. platform default: " + e;
        }
    }

    // =====================================================================
    // FIX B -- do not install a HostnameVerifier at all.
    //
    // The platform's verifier matches the requested host against the
    // certificate's subjectAltName entries, with the wildcard rules from RFC
    // 6125: a `*` matches exactly one label, only in the leftmost position,
    // and never matches a dot. Common Name is no longer consulted; a
    // certificate carrying only a CN fails, correctly.
    //
    // If you find yourself needing a custom HostnameVerifier, the honest
    // answer is almost always that the certificate is wrong and should be
    // reissued with the right SAN. Writing a verifier to accept it is moving
    // the defect from the server, where one person can fix it once, into every
    // installed copy of the app, where nobody can.
    //
    // For the rare legitimate case -- an internal service reachable under two
    // names -- the code below shows the narrow form: delegate to the platform
    // verifier first, and only then consider a SPECIFIC additional name. It
    // never returns true unconditionally.
    // =====================================================================
    private String fixB_letThePlatformVerifyTheHostname(String url) {
        try {
            HttpsURLConnection connection =
                    (HttpsURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);

            // No setHostnameVerifier call. The default runs.
            //
            // The narrow exception, shown but NOT installed, for the case
            // where an internal host genuinely has two names:
            //
            //   HostnameVerifier defaultVerifier =
            //           HttpsURLConnection.getDefaultHostnameVerifier();
            //   connection.setHostnameVerifier(new HostnameVerifier() {
            //       @Override
            //       public boolean verify(String hostname, SSLSession session) {
            //           if (defaultVerifier.verify(hostname, session)) {
            //               return true;                    // normal path
            //           }
            //           // ONE specific alias, checked against the certificate
            //           // the server actually presented -- not a blanket yes.
            //           return defaultVerifier.verify("canonical.internal.example",
            //                                         session);
            //       }
            //   });
            //
            // Even this is a smell. It is included so that a reader who has
            // been told "never write a HostnameVerifier" can see what the
            // defensible version looks like, and how far it is from
            // `return true`.

            connection.connect();
            String peer = "(none)";
            Certificate[] certs = connection.getServerCertificates();
            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                peer = ((X509Certificate) certs[0]).getSubjectDN().toString();
            }

            String body = readAll(connection);
            connection.disconnect();

            return "B. platform hostname verification: connected, " + body.length()
                    + " bytes, peer " + peer
                    + ". A certificate for another host would have been refused.";
        } catch (SSLHandshakeException e) {
            return "B. hostname verification REFUSED: " + e.getMessage()
                    + "   (this is the system working)";
        } catch (Exception e) {
            Log.w(TAG, "fix B failed", e);
            return "B. " + e;
        }
    }

    // =====================================================================
    // FIX C -- if you really do need a private CA, trust THAT ANCHOR, not the
    // whole user store.
    //
    // The insecure version loaded "AndroidCAStore", which is the system store
    // PLUS every CA the user has ever installed. That is a superset of what
    // the app needs, and its size is controlled by whoever holds the phone --
    // including malware that persuaded the user to install a certificate, and
    // including an attacker who had the device for five minutes.
    //
    // The correct shape is the opposite: build a trust store containing
    // EXACTLY the anchors this app requires, ship the anchor inside the APK as
    // a resource, and use it. The set of things that can authenticate your
    // server is then fixed at build time and cannot be widened by anything
    // happening on the device.
    //
    // Two honest caveats:
    //
    //   1. This is TRUST CONFIGURATION, not pinning. It narrows WHICH CAs may
    //      vouch for the server; it does not fix the server's key or
    //      certificate. Pinning is a different mechanism with different
    //      failure modes and different operational cost, and it is chapter
    //      36's subject.
    //
    //   2. Doing this in code is the fallback. The better place is a
    //      network_security_config <trust-anchors> block, because it is
    //      declarative, reviewable, applies to every stack in the app
    //      including WebViews and third-party SDKs, and cannot be
    //      accidentally bypassed by a library that builds its own
    //      SSLContext. That XML is chapter 44's subject. Use it in
    //      preference to this method whenever you can.
    // =====================================================================
    private String fixC_privateAnchorDoneProperly(String url) {
        InputStream anchorStream = null;
        try {
            // The anchor ships in the APK, e.g. res/raw/private_root.crt.
            // Guarded so that this example still runs in a build that does not
            // include the resource.
            int resId = getResources().getIdentifier(
                    "private_root", "raw", getPackageName());
            if (resId == 0) {
                return "C. private anchor: res/raw/private_root.crt is not present"
                        + " in this build, so this section is skipped."
                        + " The point stands: ship the ONE anchor you need,"
                        + " never the whole user store.";
            }
            anchorStream = getResources().openRawResource(resId);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate anchor =
                    (X509Certificate) cf.generateCertificate(anchorStream);

            // A KeyStore containing exactly one entry: our anchor. Note the
            // load(null, null) -- it creates an EMPTY store. Nothing from the
            // system store and nothing from the user store is in here.
            KeyStore privateStore = KeyStore.getInstance(KeyStore.getDefaultType());
            privateStore.load(null, null);
            privateStore.setCertificateEntry("private-root", anchor);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(privateStore);

            TrustManager[] managers = tmf.getTrustManagers();

            // Worth asserting rather than assuming: the factory returns the
            // PLATFORM's X509TrustManager implementation, configured with our
            // anchors. We have replaced the anchor SET. We have not replaced,
            // weakened or reimplemented the validation LOGIC, and that
            // distinction is the whole difference between this method and
            // pattern A in the insecure file.
            if (managers.length == 0 || !(managers[0] instanceof X509TrustManager)) {
                throw new IllegalStateException(
                        "expected an X509TrustManager, got "
                                + Arrays.toString(managers));
            }
            X509TrustManager tm = (X509TrustManager) managers[0];
            int anchorCount = tm.getAcceptedIssuers().length;

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, managers, new SecureRandom());

            HttpsURLConnection connection =
                    (HttpsURLConnection) new URL(url).openConnection();
            connection.setSSLSocketFactory(context.getSocketFactory());
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            // Still no HostnameVerifier override. Narrowing the anchor set is
            // orthogonal to hostname verification, and this connection gets
            // both checks.

            connection.connect();
            String body = readAll(connection);
            connection.disconnect();

            return "C. private anchor only: " + anchorCount
                    + " trusted issuer(s), connected, " + body.length() + " bytes."
                    + " A public CA would NOT have been accepted here.";
        } catch (SSLHandshakeException e) {
            // Expected when ENDPOINT is a public host: a public CA is not in
            // our one-entry store, so validation correctly fails. That failure
            // is the demonstration.
            return "C. private anchor only: REFUSED a certificate that the system"
                    + " store would have accepted -- " + e.getMessage()
                    + "   (this is the narrowing working as intended)";
        } catch (Exception e) {
            Log.w(TAG, "fix C failed", e);
            return "C. private anchor: " + e;
        } finally {
            if (anchorStream != null) {
                try { anchorStream.close(); } catch (IOException ignored) { }
            }
        }
    }

    // =====================================================================
    // FIX D -- fail closed.
    //
    // The insecure version caught SSLHandshakeException and retried over
    // http://. The fix is not a better fallback; it is no fallback.
    //
    // The reasoning is worth spelling out, because "fail closed" sounds like
    // dogma until you look at what the two branches mean:
    //
    //   * A handshake failure means the app could not establish who it is
    //     talking to. Not "the network is slow". Not "try again later". It
    //     means the identity check failed.
    //   * Retrying without TLS does not recover from that condition. It
    //     removes the check that detected it, and then sends the data to
    //     whoever caused the failure.
    //
    // So a handshake failure is one of the very few network errors that must
    // NOT be retried differently. Retrying identically after a delay is fine
    // -- transient failures exist. Retrying with less security is not.
    //
    // The other half of the fix is telling the user something true. "Could not
    // connect" invites them to switch networks, which may be exactly what the
    // attacker wants. Saying that the server's identity could not be verified
    // gives them the one piece of information that might make them stop.
    // =====================================================================
    private String fixD_failClosed(String url) {
        try {
            HttpsURLConnection connection =
                    (HttpsURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.connect();
            String body = readAll(connection);
            connection.disconnect();
            return "D. fail-closed: TLS succeeded, " + body.length() + " bytes";
        } catch (SSLHandshakeException e) {
            // No fallback. No downgrade. No "just this once".
            Log.e(TAG, "TLS handshake failed; refusing to send anything", e);
            return "D. fail-closed: the server's identity could not be verified,"
                    + " so no data was sent. Reason: " + e.getMessage();
        } catch (IOException e) {
            // An ordinary I/O failure is a DIFFERENT condition from a handshake
            // failure, and it is fine to retry it -- over TLS, unchanged.
            Log.w(TAG, "network error (not a handshake failure)", e);
            return "D. fail-closed: network error, retryable over TLS: " + e;
        } catch (Exception e) {
            Log.w(TAG, "fix D failed", e);
            return "D. " + e;
        }
    }

    // =====================================================================
    // Shared reader. Note that it reads the ERROR stream on a non-2xx
    // response: forgetting this is how apps end up reporting a TLS problem for
    // what was really a 401.
    // =====================================================================
    private String readAll(HttpURLConnection connection) throws IOException {
        InputStream in;
        int code = connection.getResponseCode();
        if (code >= 200 && code < 400) {
            in = connection.getInputStream();
        } else {
            in = connection.getErrorStream();
            if (in == null) {
                return "";
            }
        }
        StringBuilder sb = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"));
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

    // =====================================================================
    // OPTIONAL HARDENING -- protocol and cipher floor.
    //
    // Not shown as part of any fix above, because on a current device the
    // platform default already excludes SSL 3.0, TLS 1.0 and TLS 1.1, and
    // pinning a cipher list in an app is a reliable way to break it in three
    // years when the good suites have moved on.
    //
    // It is included because there is one case where it is right: an app with
    // a long support tail that must run on old devices where TLS 1.0 is still
    // enabled by default, and whose servers require better. Setting an
    // explicit FLOOR is defensible. Setting an explicit ALLOW-LIST of cipher
    // suites is usually not.
    //
    // Call this from an SSLSocketFactory wrapper if you need it.
    // =====================================================================
    static void applyProtocolFloor(SSLSocket socket) {
        String[] wanted = { "TLSv1.3", "TLSv1.2" };
        String[] supported = socket.getSupportedProtocols();

        // Intersect with what this device actually supports. Setting a
        // protocol the platform does not know throws IllegalArgumentException,
        // and doing that in a release build is a crash, not a hardening.
        java.util.List<String> enable = new java.util.ArrayList<String>();
        for (String w : wanted) {
            for (String s : supported) {
                if (s.equals(w)) {
                    enable.add(w);
                    break;
                }
            }
        }
        if (!enable.isEmpty()) {
            socket.setEnabledProtocols(enable.toArray(new String[0]));
        }
        // Deliberately NOT calling setEnabledCipherSuites. The platform's
        // default suite list is maintained by people who track which suites
        // have been broken; a list frozen into an APK in 2026 is not.
    }

    /**
     * Diagnostic helper: report what a completed session actually negotiated.
     *
     * Included because the single most common reason a TLS "fix" is wrong is
     * that nobody measured the result. If you change anything above, print
     * this and compare it against what ../scripts/tls-posture.py says the
     * server offers.
     */
    static String describeSession(SSLSession session) {
        if (session == null) {
            return "no session";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("protocol=").append(session.getProtocol());
        sb.append(" cipher=").append(session.getCipherSuite());
        try {
            Certificate[] peer = session.getPeerCertificates();
            sb.append(" chainLength=").append(peer == null ? 0 : peer.length);
            if (peer != null && peer.length > 0 && peer[0] instanceof X509Certificate) {
                X509Certificate leaf = (X509Certificate) peer[0];
                sb.append(" leaf=").append(leaf.getSubjectDN());
                sb.append(" notAfter=").append(leaf.getNotAfter());
            }
        } catch (Exception e) {
            sb.append(" peer=<unavailable: ").append(e.getMessage()).append('>');
        }
        return sb.toString();
    }
}
