/*
 * 36-CertificatePinning/examples/02-two-layer-pinning/native_pin.c
 *
 * LAYER B of the two-layer pinning example: a certificate pin implemented
 * entirely in native code, inside a BoringSSL custom-verify callback.
 *
 * WHY THIS FILE EXISTS
 *   Every Java-level pin is a method call whose return value decides trust, in
 *   a process the attacker controls. Frida changes method return values for a
 *   living, so those pins fall over immediately. The interesting question is
 *   what happens when the decision is NOT a Java method call.
 *
 *   This is that case. `verify_pin_callback` below is invoked by BoringSSL
 *   during the handshake. There is no `Ljava/...;` anywhere in the path. A
 *   Frida script that hooks okhttp3.CertificatePinner, TrustManagerImpl,
 *   NetworkSecurityTrustManager, HostnameVerifier and SSLContext -- all six
 *   Java layers, every one reporting success -- does not touch this function.
 *
 *   Defeating it requires finding the callback in the binary and either
 *   replacing SSL_CTX_set_custom_verify, replacing the callback itself, or
 *   patching the comparison. That is a different skill, and the lab makes you
 *   use it. See ../../labs/lab-02-defeat-a-two-layer-pin.md.
 *
 * WHAT THIS IS NOT
 *   Not a hardened implementation. It is a teaching artefact and it is
 *   deliberately readable: the pin is a plain string, the comparison is a
 *   memcmp, and there is no anti-tamper. A real native pin would obfuscate the
 *   constant, inline the comparison, check it from several call sites, and
 *   verify its own code. Section 6.5 of ../../README.md covers what that looks
 *   like and why it raises the cost without changing the outcome.
 *
 *   It is also not a complete HTTP client. `native_fetch` speaks just enough
 *   HTTP/1.1 to prove that a request was made and a response came back.
 *
 * BUILD
 *   See README.md in this directory. Never commit the resulting .so.
 *
 * REQUIREMENTS
 *   Android NDK r25+ and a BoringSSL (or OpenSSL 1.1.1+) for Android. The
 *   prebuilt BoringSSL that ships inside the platform is NOT linkable by apps:
 *   /system/lib64/libssl.so is not in the NDK's public API surface and linking
 *   against it is blocked by the namespace restrictions described in
 *   ../../../17-Libraries/README.md. Build your own, or use OpenSSL's
 *   Android build. The API used here is the subset both provide, except for
 *   SSL_CTX_set_custom_verify which is BoringSSL-only -- the #ifdef below
 *   falls back to SSL_CTX_set_verify on OpenSSL, and the lab covers both.
 *
 * AUTHORISED TESTING ONLY.
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <android/log.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#define LOG_TAG "ch36-nativepin"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * The pin. SHA-256 over the DER SubjectPublicKeyInfo, base64 encoded -- byte
 * for byte the same value OkHttp uses, and the same value
 * ../../scripts/spki-pin.sh prints.
 *
 * Replace this with the pin for a host you control before building:
 *     ../../scripts/spki-pin.sh --host your.host
 *
 * Left as a plain, greppable string ON PURPOSE. Finding it with
 *     strings -a libnativepin.so | grep -E '^[A-Za-z0-9+/]{43}=$'
 * is the first step of the lab, and an obfuscated constant would teach the
 * wrong lesson at the wrong time. Section 6.5 explains what a real one does
 * instead, and why it does not change the conclusion.
 */
static const char *PIN_PRIMARY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/*
 * The backup pin, in native code for the same reason it exists in Java: so
 * that a key rotation does not require an app update. A native pin makes
 * rotation HARDER, not easier -- you cannot change it with a server-side
 * config push, and you cannot change it with a remote config flag unless you
 * built one. Anyone shipping a native pin without a backup has built a
 * time bomb whose fuse is their CA's renewal schedule.
 */
static const char *PIN_BACKUP_B64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";

/* Filled in when a verification fails, so the Java side can name the layer. */
static char g_last_error[512];
static char g_last_seen_pin[128];

/* ------------------------------------------------------------------ base64 */

/*
 * Encode `len` bytes as base64 with no line breaks, into `out`.
 * EVP_EncodeBlock is the portable choice: it exists in both BoringSSL and
 * OpenSSL and does not append a newline the way the BIO chain does.
 */
static int b64(const unsigned char *in, size_t len, char *out, size_t out_len)
{
    /* 4 output characters per 3 input bytes, plus a NUL. */
    size_t need = ((len + 2) / 3) * 4 + 1;
    if (out_len < need) return -1;
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)len);
    if (n < 0) return -1;
    out[n] = '\0';
    return n;
}

/* --------------------------------------------------------------- the pin
 *
 * spki_pin(cert, out) computes the pin for one certificate.
 *
 * i2d_X509_PUBKEY is the load-bearing call and the reason this is worth
 * reading closely. X509_get_X509_PUBKEY(cert) returns the certificate's
 * SubjectPublicKeyInfo STRUCTURE -- the AlgorithmIdentifier plus the public
 * key BIT STRING -- and i2d_ serialises exactly that structure to DER.
 *
 * The three things people hash by mistake, all of which produce a
 * plausible-looking 44-character pin that never matches:
 *
 *   i2d_X509(cert)        -> the whole certificate. That is a certificate
 *                            fingerprint. It changes on every renewal.
 *   i2d_PUBKEY(pkey)      -> also the SPKI, and actually correct, but only if
 *                            you got the EVP_PKEY from the certificate rather
 *                            than reconstructing it.
 *   the raw key bytes     -> the BIT STRING without the AlgorithmIdentifier.
 *                            Wrong, and the error is invisible until you
 *                            compare against a pin computed the standard way.
 */
static int spki_pin(X509 *cert, char *out, size_t out_len)
{
    unsigned char *der = NULL;
    int der_len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
    if (der_len <= 0 || der == NULL) return -1;

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der, (size_t)der_len, digest);
    OPENSSL_free(der);

    return b64(digest, sizeof(digest), out, out_len);
}

/* ------------------------------------------------- the verification callback
 *
 * This is layer B. BoringSSL calls it during the handshake, after it has
 * received the peer's certificate chain and BEFORE the handshake completes.
 *
 * Return values are ssl_verify_result_t:
 *     ssl_verify_ok      = 0    accept
 *     ssl_verify_invalid = 1    reject; the handshake fails
 *     ssl_verify_retry   = 2    call me again later (asynchronous verification)
 *
 * Note what this callback does NOT do: it does not validate the chain against
 * any CA. Installing it with SSL_VERIFY_NONE means BoringSSL performs no trust
 * validation of its own and delegates the entire decision here. That is a
 * genuine design choice with a real trade-off -- it makes the pin the ONLY
 * check, so a bug here is not backstopped by anything.
 *
 * A more defensible implementation calls SSL_get_verify_result() first and
 * refuses anything the library already rejected, THEN applies the pin. That is
 * one line, and it is left as a deliberate exercise in the lab rather than
 * written here, because seeing why it matters is worth more than reading it.
 */
#ifdef OPENSSL_IS_BORINGSSL
static enum ssl_verify_result_t verify_pin_callback(SSL *ssl, uint8_t *out_alert)
{
    (void)out_alert;

    STACK_OF(X509) *chain = SSL_get_peer_full_cert_chain(ssl);
    if (chain == NULL || sk_X509_num(chain) == 0) {
        snprintf(g_last_error, sizeof(g_last_error),
                 "native pin rejected: peer sent no certificates");
        LOGE("%s", g_last_error);
        return ssl_verify_invalid;
    }

    int n = (int)sk_X509_num(chain);
    LOGI("native verify: %d certificate(s) in chain", n);

    /*
     * Walk the WHOLE chain, not only the leaf.
     *
     * Accepting a match anywhere in the chain is what lets an operator pin the
     * intermediate instead of the leaf, and it is what OkHttp does too. It is
     * also the behaviour that makes a pin survive leaf renewal when the
     * intermediate is what was pinned.
     *
     * The cost of this choice is real and worth stating: pinning an
     * intermediate means anyone who can get a certificate from that
     * intermediate can impersonate you. For a public CA's intermediate, that
     * is "any customer of that CA". Pin the leaf or your own private
     * intermediate if that matters to you.
     */
    for (int i = 0; i < n; i++) {
        X509 *cert = sk_X509_value(chain, i);
        char pin[128];
        if (spki_pin(cert, pin, sizeof(pin)) < 0) {
            LOGE("native verify: could not compute SPKI for cert %d", i);
            continue;
        }
        LOGI("native verify: chain[%d] sha256/%s", i, pin);
        if (i == 0) {
            snprintf(g_last_seen_pin, sizeof(g_last_seen_pin), "sha256/%s", pin);
        }

        if (strcmp(pin, PIN_PRIMARY_B64) == 0) {
            LOGI("native verify: PRIMARY pin matched at chain[%d]", i);
            return ssl_verify_ok;
        }
        if (strcmp(pin, PIN_BACKUP_B64) == 0) {
            LOGI("native verify: BACKUP pin matched at chain[%d]", i);
            return ssl_verify_ok;
        }
    }

    snprintf(g_last_error, sizeof(g_last_error),
             "native pin rejected: no pin matched. leaf was %s", g_last_seen_pin);
    LOGE("%s", g_last_error);
    return ssl_verify_invalid;
}
#else
/*
 * OpenSSL fallback. The classic callback runs once PER CERTIFICATE rather than
 * once per chain, and `preverify_ok` carries the library's own verdict.
 *
 * Returning 1 accepts that certificate; returning 0 fails the handshake. The
 * depth tells you where you are: depth 0 is the leaf, and higher numbers move
 * towards the root. This shape is why OpenSSL pinning code so often contains a
 * subtle bug -- it is easy to accept at depth 0 and forget that the callback
 * will be called again for the issuers.
 */
static int verify_pin_callback_classic(int preverify_ok, X509_STORE_CTX *ctx)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    if (cert == NULL) return 0;

    char pin[128];
    if (spki_pin(cert, pin, sizeof(pin)) < 0) return 0;
    LOGI("native verify(classic): depth=%d preverify=%d sha256/%s",
         depth, preverify_ok, pin);
    if (depth == 0) {
        snprintf(g_last_seen_pin, sizeof(g_last_seen_pin), "sha256/%s", pin);
    }

    if (strcmp(pin, PIN_PRIMARY_B64) == 0 || strcmp(pin, PIN_BACKUP_B64) == 0) {
        return 1;
    }

    /*
     * Not a match at this depth. Accept the issuers so the walk continues, and
     * refuse only at the leaf if nothing matched. A stricter policy refuses
     * everything that does not match, which forbids pinning the leaf while an
     * intermediate is present -- a real bug that ships regularly.
     */
    if (depth > 0) return preverify_ok;

    snprintf(g_last_error, sizeof(g_last_error),
             "native pin rejected: no pin matched. leaf was %s", g_last_seen_pin);
    return 0;
}
#endif

/* ------------------------------------------------------------ TCP plumbing */

static int tcp_connect(const char *host, int port)
{
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        snprintf(g_last_error, sizeof(g_last_error), "getaddrinfo failed for %s", host);
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }

    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        snprintf(g_last_error, sizeof(g_last_error), "connect failed to %s:%d", host, port);
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    /*
     * Note there is NO proxy handling here, deliberately.
     *
     * `settings put global http_proxy` sets a system property that
     * java.net.ProxySelector consults. Native code that calls connect(2)
     * directly never sees it. This is why an app with a native networking
     * stack sends nothing to your proxy even with pinning fully disabled --
     * and why the fix is an iptables/transparent redirect, not another hook.
     * See ../../README.md section 7.6.
     */
    return fd;
}

/* --------------------------------------------------------------- JNI entry */

static void throw_ioexception(JNIEnv *env, const char *msg)
{
    jclass cls = (*env)->FindClass(env, "java/io/IOException");
    if (cls != NULL) (*env)->ThrowNew(env, cls, msg);
}

JNIEXPORT jstring JNICALL
Java_com_pentest_ch36_twolayer_NativeLayer_nativeConfiguredPin(JNIEnv *env, jobject thiz)
{
    (void)thiz;
    char buf[300];
    snprintf(buf, sizeof(buf), "primary=sha256/%s backup=sha256/%s",
             PIN_PRIMARY_B64, PIN_BACKUP_B64);
    return (*env)->NewStringUTF(env, buf);
}

JNIEXPORT jstring JNICALL
Java_com_pentest_ch36_twolayer_NativeLayer_nativeFetch(JNIEnv *env, jobject thiz,
                                                       jstring jhost, jint port,
                                                       jstring jpath)
{
    (void)thiz;
    g_last_error[0] = '\0';
    g_last_seen_pin[0] = '\0';

    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    jstring result = NULL;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        snprintf(g_last_error, sizeof(g_last_error), "SSL_CTX_new failed");
        goto done;
    }

    /*
     * Install the pin.
     *
     * This one call is what ../../scripts/pin-attribution.js watches for, and
     * what ../../../53-Frida/scripts/ssl-pinning-bypass.js replaces. Seeing
     * `mode=0` (SSL_VERIFY_NONE) together with a non-NULL callback is the
     * signature of a native pin: the library has been told not to verify, and
     * the app has taken the decision into its own code.
     */
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, verify_pin_callback);
#else
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_pin_callback_classic);
#endif

    fd = tcp_connect(host, (int)port);
    if (fd < 0) goto done;

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        snprintf(g_last_error, sizeof(g_last_error), "SSL_new failed");
        goto done;
    }
    SSL_set_fd(ssl, fd);

    /* SNI. Without it most modern hosts serve a default certificate that will
     * not match your pin, and you will spend an hour blaming the pin. */
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        if (g_last_error[0] == '\0') {
            snprintf(g_last_error, sizeof(g_last_error),
                     "handshake failed (no pin verdict recorded)");
        }
        goto done;
    }

    LOGI("native: handshake complete, pin accepted");

    {
        char req[1024];
        int reqlen = snprintf(req, sizeof(req),
                              "GET %s HTTP/1.1\r\nHost: %s\r\n"
                              "Connection: close\r\nUser-Agent: ch36-nativepin\r\n\r\n",
                              path, host);
        if (SSL_write(ssl, req, reqlen) <= 0) {
            snprintf(g_last_error, sizeof(g_last_error), "SSL_write failed");
            goto done;
        }

        char buf[8192];
        int total = 0;
        int n;
        while (total < (int)sizeof(buf) - 1 &&
               (n = SSL_read(ssl, buf + total, (int)sizeof(buf) - 1 - total)) > 0) {
            total += n;
        }
        buf[total] = '\0';
        result = (*env)->NewStringUTF(env, buf);
    }

done:
    if (ssl != NULL) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (fd >= 0) close(fd);
    if (ctx != NULL) SSL_CTX_free(ctx);
    (*env)->ReleaseStringUTFChars(env, jhost, host);
    (*env)->ReleaseStringUTFChars(env, jpath, path);

    if (result == NULL) {
        throw_ioexception(env, g_last_error[0] ? g_last_error : "native fetch failed");
    }
    return result;
}
