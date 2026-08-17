# 35 — SSL/TLS · Cheat Sheet

Printable. No prose. See [README.md](README.md) for why each of these works.
Measurements marked **[M]** were taken on a Redmi M2101K6P (`sweetin`), Android 11 / API 30, MIUI 12.5, rooted, frida 16.1.6.

---

## The five commands that matter

```bash
# host — what the SERVER is
python3 scripts/tls-posture.py api.example.com

# host — what the CLIENT checks
frida -U -f com.example.app -l scripts/trace-tls-validation.js

# Frida REPL — is it validating at all?
oracle()

# host — where the trust anchors are on THIS device (verify, never assume)
adb shell 'ls -d /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts 2>&1'

# host — the trust-store filename of a CA (subject_hash_old, not subject_hash)
openssl x509 -inform DER -in ca.der -noout -subject_hash_old
```

---

## Version matrix — where the trust anchors live

| API | Android | System store | User store | Verified on device? |
|---|---|---|---|---|
| ≤ 13 | ≤ 3.2 | `/system/etc/security/cacerts.bks` (single BKS blob) | none | no |
| 14–23 | 4.0–6.0 | `/system/etc/security/cacerts/` | `/data/misc/keychain/cacerts-added/` (legacy single-user) | no |
| 24–33 | 7.0–13 | `/system/etc/security/cacerts/` | `/data/misc/user/<userId>/cacerts-added/` | **[M] API 30: 139 files in `/system/etc/security/cacerts`** |
| 34+ | 14+ | `/apex/com.android.conscrypt/cacerts/` (updatable APEX) | `/data/misc/user/<userId>/cacerts-added/` | no |

| Claim | Reality on API 30 **[M]** |
|---|---|
| "The store is in the Conscrypt APEX" | `/apex/com.android.conscrypt/` exists but has **no `cacerts` directory** — only `bin/ etc/ javalib/ lib/ lib64/` |
| "Certs are PEM" | **DER**, one certificate per file |
| "Filenames are `subject_hash`" | **`subject_hash_old`** (MD5-based, OpenSSL 0.9.8 algorithm) |
| "User CAs are readable over adb" | Root only. `adb shell` runs as uid 2000 and gets permission denied |

```bash
# adb shell — verify, do not assume
ls -d /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts 2>&1
ls /apex/com.android.conscrypt/                      # bin etc javalib lib lib64  [M] API 30
ls /system/etc/security/cacerts | wc -l              # 139  [M]
ls -Zd /system/etc/security/cacerts                  # u:object_r:system_security_cacerts_file:s0  [M]
su -c 'ls -Z /data/misc/user/0/cacerts-added'        # u:object_r:misc_user_data_file:s0           [M]
mount | grep cacerts                                 # tmpfs overlay + per-cert bind mounts        [M]
```

| Store | SELinux context **[M]** |
|---|---|
| `/system/etc/security/cacerts` | `u:object_r:system_security_cacerts_file:s0` |
| `/data/misc/user/0/cacerts-added` | `u:object_r:misc_user_data_file:s0` |

---

## Trust-anchor rule by targetSdk

| targetSdk | System store | User store | Source |
|---|---|---|---|
| ≤ 23 | trusted | **trusted** | pre-Nougat default |
| ≥ 24 | trusted | **not trusted** unless `network-security-config` opts in | Nougat trusted-CA change |
| any, `debuggable=true` | trusted | trusted **only** if the config declares a `debug-overrides` block | platform default builder |

**[M]** Measured on API 30 by calling `android.security.net.config.NetworkSecurityConfig.getDefaultBuilder(ApplicationInfo)` (one overload only, taking `android.content.pm.ApplicationInfo`) with synthetic values:

| targetSdk | debuggable | Anchor count | Promoted Burp CA trusted? |
|---|---|---|---|
| 23 | false / true | 139 | yes |
| 24 | false / true | 139 | yes |
| 28 | false / true | 139 | yes |
| 30 | false / true | 139 | yes |
| 34 | false / true | 139 | yes |

Reason: the CA was moved into the **system** store by a `trustusercerts` module, so the API 24 user-store rule never applies to it.

---

## Platform trust-manager delegation **[M]**

```
android.security.net.config.RootTrustManager
  -> android.security.net.config.NetworkSecurityTrustManager
    -> com.android.org.conscrypt.TrustManagerImpl
```

| Class | Behaviour on `checkServerTrusted(new X509Certificate[0], "RSA")` **[M]** |
|---|---|
| `RootTrustManager` | throws `java.lang.IllegalArgumentException: null or zero-length parameter` |
| `NetworkSecurityTrustManager` | throws `IllegalArgumentException` |
| `com.android.org.conscrypt.TrustManagerImpl` | throws `IllegalArgumentException` |
| `android.net.SSLCertificateSocketFactory$1` | **returns normally** — AOSP's own deliberately-insecure TrustManager, from `SSLCertificateSocketFactory.getInsecure()` |

---

## Protocol versions — server wire value vs Android client default

| Version | Wire | Android client default |
|---|---|---|
| SSL 3.0 | `0x0300` | disabled by default since Android 5.0 (API 21) |
| TLS 1.0 | `0x0301` | client default through Android 9; disabled by default from Android 10 (API 29) |
| TLS 1.1 | `0x0302` | client default through Android 9; disabled by default from Android 10 (API 29) |
| TLS 1.2 | `0x0303` | enabled by default from Android 5.0 (API 21) |
| TLS 1.3 | `0x0304` (in `supported_versions`, legacy field stays `0x0303`) | enabled by default from Android 10 (API 29); Conscrypt supports it earlier |

### Measured endpoints **[M]**

| Target | SSL 3.0 | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 |
|---|---|---|---|---|---|
| `badssl.com` | refused, alert 40 | accepted (8 suites) | accepted (8 suites) | accepted (20 suites) | refused |
| `www.cloudflare.com` | refused, alert 70 | refused, alert 70 | refused, alert 70 | accepted | accepted (3 suites) |

| Target | Chain **[M]** |
|---|---|
| `badssl.com` | `CN=*.badssl.com` RSA 2048 → `C=US, O=Let's Encrypt, CN=YR2` RSA 2048, CA:TRUE pathLen=0 → `C=US, O=ISRG, CN=Root YR` RSA 4096 |
| `expired.badssl.com` | expired leaf (notAfter 2015-04-12) **and** expired intermediate |

---

## TLS alert codes

| # | Name | What it actually means |
|---|---|---|
| 40 | `handshake_failure` | No cipher suite or parameter in common |
| 42 | `bad_certificate` | Certificate was corrupt or could not be parsed |
| 45 | `certificate_expired` | Validity window has passed (or not yet begun) |
| 46 | `certificate_unknown` | Unspecified certificate problem — the catch-all |
| 48 | `unknown_ca` | Chain did not terminate in a trusted anchor |
| 70 | `protocol_version` | This version is refused outright |
| 71 | `insufficient_security` | Peer requires stronger parameters than offered |
| 86 | `inappropriate_fallback` | `TLS_FALLBACK_SCSV` seen on a downgraded hello |
| 112 | `unrecognized_name` | SNI names a host this server does not serve |

| Direction | Reading |
|---|---|
| Alert **from server** | Server rejected the client's offer — protocol/cipher/SNI |
| Alert **from client** (48, 42, 45, 46) | The **app** rejected the server's certificate. This is the app validating |

---

## Reading a cipher suite

```
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 |    |     |    |    |   |   |    |
 |    |     |    |    |   |   |    +-- PRF / HKDF hash
 |    |     |    |    |   |   +------- AEAD mode (no separate MAC)
 |    |     |    |    |   +----------- key size, bits
 |    |     |    |    +--------------- record cipher
 |    |     |    +-------------------- separator
 |    |     +------------------------- authentication: cert key that signs
 |    +------------------------------- key exchange: E = ephemeral = forward secrecy
 +------------------------------------ protocol family

TLS_AES_128_GCM_SHA256          # TLS 1.3: kex and auth are negotiated separately,
                                # every suite is AEAD and forward-secret by construction
```

| Token | Field | Read it as |
|---|---|---|
| `ECDHE`, `DHE` | key exchange | forward secrecy present |
| `ECDH`, `DH`, `RSA` (first) | key exchange | **no** forward secrecy |
| `RSA`, `ECDSA` (second) | authentication | server certificate key type |
| `anon` | authentication | **no server authentication at all** — critical |
| `GCM`, `CHACHA20_POLY1305`, `CCM` | record | AEAD |
| `CBC` | record | needs a separate MAC; BEAST / Lucky 13 surface |
| `RC4`, `DES`, `3DES`, `NULL`, `EXPORT` | record | finding |
| trailing `SHA`, `SHA256`, `SHA384` | MAC or PRF hash | bare `SHA` means SHA-1 |

---

## openssl

```bash
# host — inspect
openssl x509 -in cert.pem -noout -text
openssl x509 -inform DER -in 9a5ba575.0 -noout -subject -issuer -dates -serial
openssl x509 -inform DER -in ca.der -noout -ext basicConstraints,subjectAltName,keyUsage
openssl x509 -inform DER -in ca.der -noout -fingerprint -sha256

# host — the trust-store filename  [M] a Burp CA stored as 9a5ba575.0 hashes to 9a5ba575
openssl x509 -inform DER -in ca.der -noout -subject_hash_old      # trust store uses THIS
openssl x509 -inform DER -in ca.der -noout -subject_hash          # NOT this

# host — DER <-> PEM
openssl x509 -inform DER -in ca.der -outform PEM -out ca.pem
openssl x509 -inform PEM -in ca.pem -outform DER -out ca.der

# host — SPKI pin (verified byte-identical to tls-posture.py output)  [M]
openssl x509 -in leaf.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64

# host — handshake
openssl s_client -connect api.example.com:443 -servername api.example.com -showcerts </dev/null
openssl s_client -connect api.example.com:443 -tls1_2
openssl s_client -connect api.example.com:443 -tls1_3
openssl s_client -connect api.example.com:443 -no_tls1_3
openssl s_client -connect api.example.com:443 -servername wrong.example      # provoke alert 112
openssl s_client -connect api.example.com:443 -CAfile roots.pem -verify_return_error

# host — chain arithmetic
openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem

# host — deliberate BAD certificate, then serve it (keys stay local; commit nothing)
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout bad.key -out bad.crt -subj "/CN=wrong.example"
openssl s_server -accept 8443 -cert bad.crt -key bad.key -www

# host — an EXPIRED certificate for the validity test
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -not_before 20200101000000Z \
  -not_after 20200102000000Z -keyout old.key -out old.crt -subj "/CN=api.example.com"
```

---

## adb

```bash
# host — device-wide proxy
adb shell settings put global http_proxy 192.168.1.10:8080
adb shell settings get global http_proxy
adb shell settings put global http_proxy :0
adb shell settings delete global http_proxy

# host — reverse tunnel instead of a proxy (USB only, no WiFi needed)
adb reverse tcp:8080 tcp:8080

# host — trust stores
adb shell 'ls -d /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts 2>&1'
adb shell 'ls /system/etc/security/cacerts | wc -l'
adb shell 'ls -Zd /system/etc/security/cacerts'
adb shell "su -c 'ls -l /data/misc/user/0/cacerts-added'"
adb shell 'mount | grep cacerts'
adb pull /system/etc/security/cacerts ./system-store

# host — dump one anchor
adb shell 'cat /system/etc/security/cacerts/9a5ba575.0' > 9a5ba575.0
openssl x509 -inform DER -in 9a5ba575.0 -noout -subject -subject_hash_old

# host — lock-screen state (a secure lock screen is required before Android
# will accept a user CA installation)
adb shell dumpsys trust | grep -i deviceLocked

# host — install workaround. adb install returns INSTALL_FAILED_USER_RESTRICTED
# on this MIUI device  [M]
adb push app.apk /data/local/tmp/app.apk
adb shell "su -c 'pm install -r /data/local/tmp/app.apk'"

# host — target metadata
adb shell dumpsys package com.example.app | grep -E 'targetSdk|flags|versionName'
adb shell pm path com.example.app

# host — watch the handshake fail
adb logcat -s ch35.insecure:V *:E | grep -iE 'ssl|tls|handshake|certificate|trust'
```

---

## `scripts/tls-posture.py`

```bash
# host
python3 scripts/tls-posture.py api.example.com
python3 scripts/tls-posture.py api.example.com:8443
python3 scripts/tls-posture.py --targets domains.txt
python3 scripts/tls-posture.py api.example.com --json > before.json
python3 scripts/tls-posture.py api.example.com --no-ciphers
python3 scripts/tls-posture.py api.example.com --proxy 127.0.0.1:8080
python3 scripts/tls-posture.py api.example.com --sni other.example.com
python3 scripts/tls-posture.py api.example.com --timeout 15 --delay 0.2
```

| Flag | Effect |
|---|---|
| `--targets FILE` | One `host[:port]` per line |
| `--port N` | Default port for bare targets (default 443) |
| `--timeout F` | Per-connection timeout, seconds (default 8.0) |
| `--delay F` | Sleep between probes; use against rate-limited hosts |
| `--no-ciphers` | Skip per-version cipher enumeration (the slow part) |
| `--proxy HOST:PORT` | HTTP `CONNECT` proxy |
| `--sni NAME` | Send a different SNI name than the connect host |
| `--json` | Machine-readable, for diffing two runs |

| It reports | It deliberately does **not** report |
|---|---|
| Protocols the server completes a ServerHello for | Whether the app trusts this endpoint |
| Accepted suites per version, in server preference order | Whether the app pins |
| Full chain: subject, issuer, dates, key, SANs, CA flag | Whether the chain is trusted by any store |
| SPKI pin values | Revocation, OCSP, CT |
| Findings with severity and impact | Anything about HTTP — no request is sent |

---

## `scripts/trace-tls-validation.js`

```bash
# host — defeat inlining first
adb shell cmd package compile -m verify -f com.example.app

# host — ALWAYS spawn. TLS machinery is built during startup.
# frida 16.1.6 has NO --no-pause; spawn resumes by default, --pause opts in.
frida -U -f com.example.app -l scripts/trace-tls-validation.js
frida -U -f com.example.app -l scripts/trace-tls-validation.js -o trace.txt
frida -U --pause -f com.example.app -l scripts/trace-tls-validation.js
```

```
verdict()    everything seen, classified platform / library / app
oracle()     feed each live TrustManager a zero-length chain
rescan()     re-run the backstop sweep after lazy class loading
```

| Toggle (edit at the top of the file) | Default | Effect |
|---|---|---|
| `VERBOSE` | `true` | `false` keeps only the summary |
| `DUMP_CHAINS` | `false` | `true` prints every certificate of every chain |
| `RESCAN_SECONDS` | `10` | Deferred sweep for lazily loaded classes; `0` disables |
| `SWEEP` | `true` | `false` uses choke-point hooks only |

| Output tag | Meaning |
|---|---|
| `[ctx]` | `SSLContext.getInstance` / `.init` — trust machinery being built |
| `[tmf]` | `TrustManagerFactory.init` — a custom KeyStore here replaced the anchors |
| `[chk]` | `checkServerTrusted` — `returned normally == ACCEPTED`, `threw == REJECTED` |
| `[hv ]` | `HostnameVerifier.verify` and its boolean result |
| `[tls]` | Negotiated protocol and suite per socket |
| `[web]` | `onReceivedSslError` / `SslErrorHandler.proceed()` |
| `[pin]` | Pin-evaluation class present — hand off to chapter 36, CertificatePinning |

| Oracle result | Conclusion |
|---|---|
| `threw IllegalArgumentException` | Conformant. Says nothing about whether it validates *correctly* |
| `RETURNED` | Accepted a zero-length chain. Performs no validation |
| `no live instance on the heap` | Exercise the app, then call `oracle()` again |
| 0 `checkServerTrusted` calls, app plainly online | **Native TLS stack.** Real result, not "no validation" |

---

## Validation steps — and what breaks at each

| # | Step | Broken by | Attacker then needs |
|---|---|---|---|
| 1 | Chain construction to a trust anchor | Empty `checkServerTrusted`; `AndroidCAStore`; custom `TrustManagerFactory` KeyStore | **nothing** — any self-signed cert |
| 2 | Signature verification at each link | Same as 1 | nothing |
| 3 | Validity window (`notBefore`/`notAfter`) | Same as 1 | an expired cert works |
| 4 | `basicConstraints` CA:TRUE, `pathLenConstraint` | Same as 1; historic "any leaf can sign" bugs | any leaf cert |
| 5 | Hostname / SAN match (RFC 6125) | `HostnameVerifier { return true }` | **one free, valid cert for a domain they own** |
| 6 | Revocation (OCSP / CRL) | Not performed by default on Android | a revoked but unexpired cert |
| 7 | Pin evaluation | chapter 36, CertificatePinning | — |

---

## Static analysis — find it in source

```bash
# host
apktool d target.apk -o unpacked/ && jadx -d jadx-out/ target.apk

# 1. permissive TrustManager — the empty checkServerTrusted body
grep -rn "X509TrustManager" jadx-out/sources/
grep -rzoP 'checkServerTrusted\s*\([^)]*\)\s*(throws[^{]*)?\{\s*\}' jadx-out/sources/
grep -rn "getAcceptedIssuers" jadx-out/sources/

# 2. permissive HostnameVerifier
grep -rn "HostnameVerifier\|setDefaultHostnameVerifier\|setHostnameVerifier" jadx-out/sources/
grep -rzoP 'public boolean verify\([^)]*\)\s*\{\s*return true;\s*\}' jadx-out/sources/
grep -rn "ALLOW_ALL_HOSTNAME_VERIFIER\|AllowAllHostnameVerifier" jadx-out/sources/

# 3. the AOSP-supplied insecure factory
grep -rn "SSLCertificateSocketFactory.getInsecure\|getInsecure(" jadx-out/sources/

# 4. user store re-enabled in code
grep -rn "AndroidCAStore" jadx-out/sources/

# 5. WebView error swallowing
grep -rn "onReceivedSslError" jadx-out/sources/ -A6 | grep -n "proceed()"

# 6. cleartext fallback in a catch block
grep -rn "SSLHandshakeException\|SSLPeerUnverifiedException" jadx-out/sources/ -A8 | grep -i "http://"
grep -rn "replaceFirst(\"^https\|\"http://\"" jadx-out/sources/

# 7. explicitly weak protocol requested
grep -rn 'SSLContext.getInstance("SSL"\|"SSLv3"\|"TLSv1"' jadx-out/sources/
grep -rn "setEnabledProtocols\|setEnabledCipherSuites" jadx-out/sources/

# 8. endpoints to feed tls-posture.py
grep -rhoE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+' jadx-out/sources/ | sort -u > domains.txt
grep -rn "http://" unpacked/res/values/strings.xml

# 9. the config that governs all of it (chapter 44, NetworkSecurityConfig)
grep -n "networkSecurityConfig\|usesCleartextTraffic" unpacked/AndroidManifest.xml
cat unpacked/res/xml/network_security_config.xml

# 10. native TLS — if the Java sweep found nothing
grep -rl "SSL_CTX_set_custom_verify\|SSL_get_verify_result\|boringssl" unpacked/lib/*/ 2>/dev/null
for so in unpacked/lib/*/*.so; do strings "$so" | grep -iE "SSL_|TLS1_|X509_verify"; done
```

### Smali shapes

```smali
# permissive TrustManager: a checkServerTrusted with NOTHING between the
# .prologue and return-void. There is no boolean; accepting IS returning.
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .registers 3
    return-void
.end method

# getAcceptedIssuers returning an empty array — the companion tell
.method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    const/4 v0, 0x0
    new-array v0, v0, [Ljava/security/cert/X509Certificate;
    return-object v0
.end method

# permissive HostnameVerifier
.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .registers 3
    const/4 v0, 0x1
    return v0
.end method

# installing it app-wide
invoke-static {v0}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultSSLSocketFactory(Ljavax/net/ssl/SSLSocketFactory;)V
invoke-static {v0}, Ljavax/net/ssl/HttpsURLConnection;->setDefaultHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V

# AOSP's own insecure factory
invoke-static {v0}, Landroid/net/SSLCertificateSocketFactory;->getInsecure(ILandroid/net/SSLSessionCache;)Ljavax/net/ssl/SSLSocketFactory;

# WebView: proceed() past a certificate error
invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
```

```bash
# host
grep -rn "Ljavax/net/ssl/X509TrustManager" unpacked/smali*/ | cut -d: -f1 | sort -u
grep -rn -A4 "checkServerTrusted(\[Ljava/security/cert/X509Certificate;Ljava/lang/String;)V" unpacked/smali*/ | grep -B1 "return-void"
grep -rn -A4 "verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z" unpacked/smali*/ | grep "const/4 v0, 0x1"
grep -rn "SslErrorHandler;->proceed" unpacked/smali*/
grep -rn "SSLCertificateSocketFactory;->getInsecure" unpacked/smali*/
```

| Obfuscation effect | Still findable by |
|---|---|
| Class and method names renamed by R8 | **Interface and framework method signatures are not renamed** — `checkServerTrusted(...)V` and `verify(...)Z` survive |
| Anonymous inner class becomes `a$1` | `trace-tls-validation.js` reads the class name off the live object at `SSLContext.init` |
| String encryption hides the endpoint | `[tls]` handshake lines print the peer subject at runtime |

---

## Triage — interception fails

| Symptom | Cause | Fix |
|---|---|---|
| Browser works, app shows nothing | targetSdk ≥ 24: user store not trusted | Move the CA into the **system** store, or add a `debug-overrides` config (chapter 44, NetworkSecurityConfig) |
| Nothing at all in the proxy, no errors | No device proxy set, or app ignores it | `settings put global http_proxy`; some stacks need `adb reverse` |
| `SSLHandshakeException: Trust anchor for certification path not found` | CA is not trusted by this app | The classic user-store symptom — promote the CA |
| Handshake fails **after** the CA is trusted | Pinning | chapter 36, CertificatePinning |
| App refuses to start after CA install | Instrumentation or tamper detection | chapters 37/38 |
| `oracle()` says permissive, still no traffic | Different endpoint, or a native stack | Check `[tls]` lines; hook BoringSSL |
| Zero `checkServerTrusted`, app plainly online | **Native TLS** (Flutter, Cronet, Unity, custom `.so`) | Trace `SSL_CTX_set_custom_verify` / `SSL_read` / `SSL_write` |
| Traffic appears but only for some hosts | Per-domain config, or a second HTTP client | Diff `[tls]` peer subjects against `domains.txt` |
| Proxy shows `unrecognized_name` (alert 112) | Proxy sent the wrong SNI | Set the proxy's SNI to the real host |
| App works over WiFi, dies on corporate network | Corporate MITM CA is a user CA; or an SNI/DPI middlebox | Same fix as row 1; confirm with `--sni` |
| Works on emulator, not on the device | Emulator image trusts a different anchor set | Compare `ls /system/etc/security/cacerts \| wc -l` on both |
| CA disappears after reboot | Written to a tmpfs overlay, not persisted | Use a `trustusercerts` Magisk/APatch module **[M]** |
| `adb install` → `INSTALL_FAILED_USER_RESTRICTED` | MIUI policy **[M]** | `adb push` + `su -c 'pm install -r ...'` |
| Frida hook installs but never fires | Method inlined by the optimizing compiler | `adb shell cmd package compile -m verify -f <pkg>` then force-stop |
| Frida sees nothing at startup | Attached instead of spawning | Use `-f`, not `-n` |

---

## Findings catalogue

| ID | Finding | Fastest proof |
|---|---|---|
| T-01 | `checkServerTrusted` accepts every chain | `oracle()` returns `RETURNED` |
| T-02 | `HostnameVerifier` returns `true` unconditionally | Present a valid cert for the wrong name |
| T-03 | User store trusted in app code (`AndroidCAStore`) | grep, then count anchors at runtime |
| T-04 | Cleartext fallback in a `catch (SSLHandshakeException)` | Kill the handshake, watch for `http://` |
| T-05 | WebView `SslErrorHandler.proceed()` on error | `[web]` line in the tracer |
| T-06 | `SSLCertificateSocketFactory.getInsecure()` in use | Oracle returns on `android.net.SSLCertificateSocketFactory$1` |
| T-07 | Custom `TrustManagerFactory` KeyStore replaces anchors | `[tmf]` line, entry count |
| T-08 | Deprecated protocol requested explicitly | `[ctx]` shows `SSLv3` / `TLSv1` |
| T-09 | Server accepts SSL 3.0 | `tls-posture.py` protocol row |
| T-10 | Server accepts anonymous or export or NULL suite | `tls-posture.py` cipher row |
| T-11 | Server offers static RSA key exchange (no forward secrecy) | Suite name begins `TLS_RSA_` |
| T-12 | Expired or SHA-1-signed certificate in the chain | `tls-posture.py` chain section |

---

## Severity rubric

Grade by **what the channel carries**, not by the mechanism.

| What travels on the broken channel | Base severity | Raise to | Lower to |
|---|---|---|---|
| Authentication or token endpoint — credentials, OTP, refresh token, session cookie | **Critical** | — | High only if the token is bound to a device key the attacker cannot obtain |
| PII, health, financial or location data | **High** | Critical if it includes credentials or is a regulated dataset | Medium if it is coarse and non-identifying |
| Authenticated API traffic — account state, transactions, mutating calls | **High** | Critical if it accepts unsigned mutations | Medium if strictly read-only and low-value |
| Unauthenticated but integrity-sensitive — config, feature flags, update manifests, JS/DEX loaded at runtime | **High** | **Critical** if code is executed from the response | Medium if signed and verified independently |
| Static assets — images, fonts, analytics pings | **Low** | Medium if a response can drive UI or deep links | Informational |

| Modifier | Effect |
|---|---|
| Bug reachable without root, on a normal user device | Raise one level |
| Requires the attacker to be on the path (public WiFi, hostile ISP, corporate proxy) | Keep — this is the assumed model, not a mitigation |
| Requires a user CA the attacker cannot install | Lower one level; say so explicitly |
| Pattern B only (hostname check removed) | **Do not lower.** One free valid certificate is the whole attack cost |
| Debug-only code path, proven unreachable in the release variant | Informational, with the proof |

---

## MASVS mapping

| Control | Findings |
|---|---|
| MASVS-NETWORK-1 (secure network communication) | T-01, T-02, T-04, T-05, T-06, T-08, T-09, T-10, T-11, T-12 |
| MASVS-NETWORK-2 (trust store and pinning configuration) | T-01, T-03, T-06, T-07 |
| MASVS-PLATFORM-2 (WebView) | T-05 |
| MASVS-CODE-4 (unsigned code loaded over the network) | T-04 |

---

## Rules

1. A green `tls-posture.py` report says nothing about the app. Validation happens in the **client**.
2. `checkServerTrusted` returns `void`. Accepting is *not throwing*. The vulnerable version has **less** code.
3. Chain validation and hostname verification are two separate steps and break separately.
4. A TrustManager that never threw is only interesting if you gave it something to reject.
5. Verify the trust-store path on the device. Do not repeat what a blog said about API 34.
6. Trust-store filenames are `subject_hash_old`, and the files are DER.
7. A user CA stops being trusted by default at API 24. The fix is to stop it being a *user* CA.
8. "The certificate was valid" is not a defence — valid *for whom*?
9. An alert from the client is the app working. An alert from the server is the server refusing.
10. Zero Java handshakes plus a live network is a **native stack**, not an absence of validation.
11. Never conclude from silence. Run the deliberate-bad-certificate test.
12. Report what the channel carries, not what the API is called.
