/*
 * 36-CertificatePinning/labs/ctf-pin-that-moved/pin_gate.c
 *
 * The native half of the "pin that moved" CTF target.
 *
 * SPOILER WARNING. This file is the answer. If you are solving the challenge,
 * close it -- you are supposed to find this behaviour in a stripped .so, not
 * read it in C.
 *
 * WHAT MAKES THIS A CHALLENGE RATHER THAN LAB 02 AGAIN
 *
 *   1. The pin is NOT a string. It is XORed with a fixed byte, so
 *      `strings | grep base64` finds nothing and the chapter's own
 *      pinning-surface.py reports only a MED-confidence verify symbol. A tool
 *      getting weaker is not the app getting stronger, and noticing that is
 *      part of the exercise.
 *
 *   2. The gate pins to a key the server is NOT serving when you start. The
 *      Java pin set names the ORIGINAL key; this gate names the ROTATED one.
 *      Until the operator rotates, the native path fails and the Java path
 *      works -- which reads exactly like "the native layer is broken".
 *
 *   3. The gate REPORTS what it accepted. Turning verification off wholesale
 *      still leaves the report to fill in, and the server checks it. There is
 *      no version of "return 0 from everything" that produces the flag.
 *
 *   The intended solution is not to disable the gate. It is to understand it.
 *
 * BUILD
 *   See README.md in this directory. Never commit the .so.
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
#include <android/log.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define LOG_TAG "ch36-ctf-native"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * The pin, XORed byte by byte with 0x5A.
 *
 * Generate the table for YOUR server's rotated key with:
 *
 *     python3 -B - <<'EOF'
 *     pin = "PASTE_ROTATED_PIN_WITHOUT_sha256/_PREFIX"
 *     print(", ".join("0x%02x" % (ord(c) ^ 0x5A) for c in pin))
 *     EOF
 *
 * This is weak obfuscation and it is meant to be. It defeats `strings`, which
 * is the point being made: the string-based half of static detection is one
 * XOR away from useless, while the STRUCTURAL half -- a verify callback, a
 * SHA-256 over an SPKI, a comparison -- survives, because you cannot obfuscate
 * away the need to do the work.
 */
static const unsigned char PIN_ROTATED_XOR[] = {
    /* 44 bytes. Replace with your own table from the snippet above. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define PIN_XOR_KEY 0x5A
#define PIN_LEN     (sizeof(PIN_ROTATED_XOR))

/* The pin the gate ACCEPTED, reported to the server. */
static char g_accepted_pin[128];
static char g_last_error[512];

/* ------------------------------------------------------------------ helpers */

static void deobfuscate_pin(char *out, size_t out_len)
{
    size_t i;
    if (out_len <= PIN_LEN) { out[0] = '\0'; return; }
    for (i = 0; i < PIN_LEN; i++) {
        out[i] = (char)(PIN_ROTATED_XOR[i] ^ PIN_XOR_KEY);
    }
    out[PIN_LEN] = '\0';
    /*
     * The deobfuscated pin exists in memory for the duration of the comparison.
     * A memory search finds it. That is not a flaw in this file; it is a
     * general property of every obfuscated constant, and it is one of the two
     * intended solution paths.
     */
}

static int b64(const unsigned char *in, size_t len, char *out, size_t out_len)
{
    size_t need = ((len + 2) / 3) * 4 + 1;
    if (out_len < need) return -1;
    int n = EVP_EncodeBlock((unsigned char *)out, in, (int)len);
    if (n < 0) return -1;
    out[n] = '\0';
    return n;
}

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

/* --------------------------------------------------------------- the gate */

#ifdef OPENSSL_IS_BORINGSSL
static enum ssl_verify_result_t gate_verify(SSL *ssl, uint8_t *out_alert)
{
    (void)out_alert;
    STACK_OF(X509) *chain = SSL_get_peer_full_cert_chain(ssl);
    if (chain == NULL || sk_X509_num(chain) == 0) {
        snprintf(g_last_error, sizeof(g_last_error), "gate: no peer certificates");
        return ssl_verify_invalid;
    }

    char expected[128];
    deobfuscate_pin(expected, sizeof(expected));

    /*
     * Only the LEAF is considered. Pinning the leaf and refusing to look at the
     * rest of the chain is a real design choice with a real consequence: it
     * cannot be satisfied by an intermediate, so an intercepting proxy cannot
     * win by having its CA in the chain. It must present a leaf whose key
     * matches.
     */
    X509 *leaf = sk_X509_value(chain, 0);
    char seen[128];
    if (spki_pin(leaf, seen, sizeof(seen)) < 0) {
        snprintf(g_last_error, sizeof(g_last_error), "gate: could not hash leaf SPKI");
        return ssl_verify_invalid;
    }

    LOGI("gate: leaf sha256/%s", seen);

    if (strcmp(seen, expected) == 0) {
        /*
         * Record what was accepted. THIS is the value the server checks, and it
         * is recorded from the certificate that was actually presented -- not
         * from the pin table. An attacker who forces this function to return
         * ssl_verify_ok unconditionally still leaves g_accepted_pin holding
         * whatever the peer really sent, and the oracle compares that against
         * the key it is serving.
         */
        snprintf(g_accepted_pin, sizeof(g_accepted_pin), "sha256/%s", seen);
        LOGI("gate: pin matched");
        return ssl_verify_ok;
    }

    snprintf(g_last_error, sizeof(g_last_error),
             "gate: pin mismatch (leaf sha256/%s)", seen);
    LOGE("%s", g_last_error);
    return ssl_verify_invalid;
}
#else
static int gate_verify_classic(int preverify_ok, X509_STORE_CTX *ctx)
{
    (void)preverify_ok;
    X509 *cert = X509_STORE_CTX_get_current_cert(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    if (cert == NULL || depth != 0) return 1;

    char expected[128], seen[128];
    deobfuscate_pin(expected, sizeof(expected));
    if (spki_pin(cert, seen, sizeof(seen)) < 0) return 0;

    LOGI("gate(classic): leaf sha256/%s", seen);
    if (strcmp(seen, expected) == 0) {
        snprintf(g_accepted_pin, sizeof(g_accepted_pin), "sha256/%s", seen);
        return 1;
    }
    snprintf(g_last_error, sizeof(g_last_error),
             "gate: pin mismatch (leaf sha256/%s)", seen);
    return 0;
}
#endif

/* ------------------------------------------------------------------ socket */

static int tcp_connect(const char *host, int port)
{
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, portstr, &hints, &res) != 0 || res == NULL) {
        snprintf(g_last_error, sizeof(g_last_error), "getaddrinfo failed: %s", host);
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { freeaddrinfo(res); return -1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        snprintf(g_last_error, sizeof(g_last_error), "connect failed: %s:%d", host, port);
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* --------------------------------------------------------------- JNI entry */

JNIEXPORT jstring JNICALL
Java_com_pentest_ch36_ctf_CtfClient_claimFlag(JNIEnv *env, jobject thiz,
                                              jstring jhost, jint port)
{
    (void)thiz;
    g_last_error[0] = '\0';
    g_accepted_pin[0] = '\0';

    const char *host = (*env)->GetStringUTFChars(env, jhost, NULL);
    char out[8192];
    out[0] = '\0';

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = NULL;
    int fd = -1;

    if (ctx == NULL) {
        snprintf(g_last_error, sizeof(g_last_error), "SSL_CTX_new failed");
        goto done;
    }

#ifdef OPENSSL_IS_BORINGSSL
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, gate_verify);
#else
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, gate_verify_classic);
#endif

    fd = tcp_connect(host, (int)port);
    if (fd < 0) goto done;

    ssl = SSL_new(ctx);
    if (ssl == NULL) goto done;
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, host);

    if (SSL_connect(ssl) != 1) {
        if (g_last_error[0] == '\0') {
            snprintf(g_last_error, sizeof(g_last_error), "handshake failed");
        }
        goto done;
    }

    if (g_accepted_pin[0] == '\0') {
        /*
         * Reached only if the handshake succeeded without gate_verify recording
         * an acceptance -- which is exactly what happens when someone replaces
         * the callback or the installer. The request still goes out; the header
         * is empty; the server answers 400. That 400 is the intended teaching
         * moment: the bypass worked and the challenge still is not solved.
         */
        snprintf(g_accepted_pin, sizeof(g_accepted_pin), "%s", "");
        LOGE("gate: handshake completed but nothing was recorded as accepted");
    }

    {
        char req[1024];
        int reqlen = snprintf(req, sizeof(req),
                              "GET /claim HTTP/1.1\r\nHost: %s\r\n"
                              "X-Accepted-Pin: %s\r\n"
                              "Connection: close\r\n\r\n",
                              host, g_accepted_pin);
        if (SSL_write(ssl, req, reqlen) <= 0) {
            snprintf(g_last_error, sizeof(g_last_error), "SSL_write failed");
            goto done;
        }
        int total = 0, n;
        while (total < (int)sizeof(out) - 1 &&
               (n = SSL_read(ssl, out + total, (int)sizeof(out) - 1 - total)) > 0) {
            total += n;
        }
        out[total] = '\0';
    }

done:
    if (ssl != NULL) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (fd >= 0) close(fd);
    if (ctx != NULL) SSL_CTX_free(ctx);
    (*env)->ReleaseStringUTFChars(env, jhost, host);

    if (out[0] == '\0') {
        return (*env)->NewStringUTF(env,
            g_last_error[0] ? g_last_error : "native gate failed");
    }
    return (*env)->NewStringUTF(env, out);
}
