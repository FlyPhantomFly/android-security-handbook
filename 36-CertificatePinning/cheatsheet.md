# 36 — Certificate Pinning · Cheat Sheet

Dense and printable. Full explanations in [README.md](README.md).

---

## The pin

| | |
|---|---|
| Format | `sha256/` + base64(SHA-256(DER SubjectPublicKeyInfo)) |
| Length | Always 44 chars ending in exactly one `=` |
| Hashes | The **public key** (AlgorithmIdentifier + BIT STRING), **not** the certificate |
| Survives | Certificate renewal on the same key |
| Breaks on | Key rotation |
| NSC form | `<pin digest="SHA-256">BASE64</pin>` — no `sha256/` prefix, `SHA-256` is the only digest |
| OkHttp form | `.add("host", "sha256/BASE64")` — prefix required; legacy `sha1/` deprecated |

## Compute it

```bash
# from a live host
echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64

# from a certificate file
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64

# from a PRIVATE key -- this is how you make a BACKUP pin
openssl pkey -in backup.key -pubout -outform der | openssl dgst -sha256 -binary | base64

# from a CSR
openssl req -in x.csr -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64

# all of the above, labelled, plus ready-to-paste config
./scripts/spki-pin.sh --host api.example.com --emit okhttp
./scripts/spki-pin.sh --host api.example.com --emit nsc
./scripts/spki-pin.sh --key backup.key
```

**Wrong hash, right shape:** `openssl x509 -fingerprint -sha256` is the *certificate* fingerprint.
Parses as a pin, never matches, changes at every renewal.

## Generate a backup key

```bash
openssl ecparam -genkey -name prime256v1 -noout -out backup.key    # EC P-256
openssl genrsa -out backup.key 4096                                # or RSA
./scripts/spki-pin.sh --key backup.key
# then: vault it, offline, until you need it
```

---

## The layers

| # | Layer | Class / symbol | Java hookable |
|---|---|---|---|
| 1 | `SSLContext` / custom trust manager | `javax.net.ssl.SSLContext.init`, `TrustManagerFactory.getTrustManagers` | yes |
| 1b | Extensions API | `android.net.http.X509TrustManagerExtensions.checkServerTrusted` | yes |
| 2 | Conscrypt | `com.android.org.conscrypt.TrustManagerImpl` (also `org.conscrypt.`, `com.google.android.gms.org.conscrypt.`) | yes |
| 3 | OkHttp pin | `okhttp3.CertificatePinner.check`, `check$okhttp` | yes |
| 4 | Hostname (not a pin) | `javax.net.ssl.HostnameVerifier.verify` | yes |
| 5 | `<pin-set>` | `android.security.net.config.NetworkSecurityTrustManager`, `RootTrustManager` | yes |
| 6 | WebView | `android.webkit.WebViewClient.onReceivedSslError` | yes |
| 7 | Native | `SSL_CTX_set_custom_verify`, `SSL_CTX_set_verify` | **no** |
| — | Flutter root bundle | inside `libflutter.so` | **no** |
| — | Certificate Transparency | `com.appmattus.certificatetransparency.*` | partly; fails **after** the pin |

**Order:** platform validation → `<pin-set>` → hostname → OkHttp pin → CT.
**A rejection at a lower layer hides every layer above it.**

---

## Find it — static

```bash
# configured pin value (the 43-char suffix is what makes this useful)
unzip -o -j app.apk 'classes*.dex' -d /tmp/d
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' /tmp/d/*.dex | sort -u

# declared pin-set
unzip -o -j app.apk 'res/xml/*' -d /tmp/x && grep -l -a 'pin-set' /tmp/x/*
aapt2 dump xmltree --file res/xml/network_security_config.xml app.apk

# native TLS
unzip -l app.apk | grep '\.so$'
unzip -o -j app.apk 'lib/arm64-v8a/*.so' -d /tmp/l
llvm-readelf --dyn-syms /tmp/l/*.so | grep -i 'SSL_CTX_set\|i2d_X509_PUBKEY'
llvm-readelf -d /tmp/l/*.so | grep NEEDED
strings -a /tmp/l/*.so | grep -E '^[A-Za-z0-9+/]{43}=$'

# Flutter, in five seconds
unzip -l app.apk | grep -E 'libflutter\.so|libapp\.so|flutter_assets'

# trust taken over by the app
grep -a -c 'checkServerTrusted' /tmp/d/*.dex
grep -a -c 'X509TrustManagerExtensions' /tmp/d/*.dex

# bundled Conscrypt (platform-class hooks will miss it)
grep -a -c 'org/conscrypt' /tmp/d/*.dex

# Certificate Transparency
grep -a -c 'com/appmattus/certificatetransparency' /tmp/d/*.dex
```

### The tool

```bash
python3 -B scripts/pinning-surface.py --apk target.apk
python3 -B scripts/pinning-surface.py --package com.example.app
python3 -B scripts/pinning-surface.py --package com.example.app --live   # needs root
python3 -B scripts/pinning-surface.py --sweep --limit 20
python3 -B scripts/pinning-surface.py --apk target.apk --json
```

| Grade | Means |
|---|---|
| `HIGH` | A configured **pin value** |
| `MATRL` | Embedded certs/keys, purpose ambiguous |
| `MED` | The app took control of trust |
| `LOW` | A library containing pinning code is present. **Not a pin** |

---

## Find it — dynamic

```bash
# ALWAYS deoptimise first
adb shell cmd package compile -m verify -f com.example.app
adb shell am force-stop com.example.app

# ALWAYS spawn: pinning is configured during startup
frida -U -f com.example.app -l scripts/pin-attribution.js --no-pause   # WATCH
frida -U -f com.example.app -l ../53-Frida/scripts/ssl-pinning-bypass.js --no-pause   # BYPASS
objection -g com.example.app explore                                   # then: android sslpinning disable
```

### Attribution → action

| Rejected at | Meaning | Do |
|---|---|---|
| L2 Conscrypt | Your CA is not trusted | Fix the trust store. Chapter 35 |
| L5 `<pin-set>` | Declarative pin refused | Hook `NetworkSecurityTrustManager`, or edit the XML |
| L4 hostname | Name mismatch — **usually your bug** | Fix the proxy's SNI, or add an IP SAN |
| L3 `CertificatePinner` | Chain valid, pin refused | Now bypass |
| CT | Not logged | Separate control, runs after the pin |
| Nothing ran | Wrong stack | Count `.so` files. Check for Flutter |

---

## Native

| Symbol | API | Callback returns |
|---|---|---|
| `SSL_CTX_set_custom_verify(ctx, mode, cb)` | BoringSSL | `0` ok, `1` invalid, `2` retry |
| `SSL_CTX_set_verify(ctx, mode, cb)` | OpenSSL | `1` accept this cert, `0` fail. Called **per certificate** |

**Native pin signature:** `mode == 0` (`SSL_VERIFY_NONE`) with a **non-NULL** callback.

```javascript
// safest: original body still runs, bookkeeping preserved
Interceptor.attach(cbAddr, {
    onLeave: function (retval) { if (retval.toInt32() !== 0) retval.replace(0); }
});

// blunter: skips the original entirely
Interceptor.replace(cbAddr, new NativeCallback(function () { return 0; }, 'int', ['pointer','pointer']));
```

```javascript
// read plaintext regardless of pinning
['SSL_read','SSL_write'].forEach(function (n) {
    var a = Module.findExportByName(null, n);
    if (a) Interceptor.attach(a, {
        onEnter: function (args) { this.b = args[1]; },
        onLeave: function (r) { var k = r.toInt32();
            if (k > 0) console.log(Memory.readUtf8String(this.b, Math.min(k, 2048))); }
    });
});
```

**Traps:** keep every `NativeCallback` in a module-level array or the GC frees it and native code
calls freed memory. Check for **inlining** before concluding a patch failed.

---

## Flutter

| Action | Effect on Dart traffic |
|---|---|
| User CA | none |
| **System** CA | none |
| Any Java hook | none |
| Edit `network_security_config.xml` | none |
| `settings put global http_proxy` | none |

Its BoringSSL is static inside `libflutter.so` with its own compiled root list. **This is not
pinning** — it is a separate trust store — but it defeats a bypass identically.

Works: hook the native verification path in `libflutter.so` (stripped; pattern-match per engine
version), transparent redirect at the network layer, or patch the bundled PEM list.

---

## Proxy plumbing

```bash
adb shell settings put global http_proxy 192.168.1.10:8080
adb shell settings get global http_proxy
adb shell settings put global http_proxy :0                 # CLEANUP

# native connect(2) ignores the proxy setting entirely -- redirect ONE app
adb shell dumpsys package com.example.app | grep userId
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 \
    -m owner --uid-owner 10123 -j DNAT --to-destination 192.168.1.10:8080'"
adb shell "su -c 'iptables -t nat -L OUTPUT -n --line-numbers'"  # check before removing
```

Install on MIUI where `adb install` returns `INSTALL_FAILED_USER_RESTRICTED`:

```bash
adb push app.apk /data/local/tmp/a.apk
adb shell "su -c 'pm install -r /data/local/tmp/a.apk'"
```

---

## Reporting

| Situation | Line to write |
|---|---|
| No pinning, adequate | "Relies on platform validation; user store not trusted; adequate for this threat model. **No action.**" |
| No pinning, should pin | "Handles [X]; a certificate mis-issued by any of ~140 CAs permits full interception. MASVS-NETWORK-2." |
| One pin, no backup | "**Availability risk introduced by a security control.** Key rotation invalidates it for all installs simultaneously, no server-side remedy." |
| Pins the API, not the token endpoint | "Does not cover the credential exchange it was presumably intended to protect." |
| Bypassed with Frida on a rooted device | Not a finding. That is the expected property |
| **Never** | "No certificate pinning. Severity: Medium." with no threat-model sentence |

---

## Smali patterns

```smali
# permissive trust manager -- accepts everything. NOT a pin. CWE-295, HIGH.
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    return-void
.end method
```

```smali
# a real public-key pin: getPublicKey -> getEncoded -> digest -> encodeToString(0x2) -> equals -> throw
invoke-interface {v2}, Ljava/security/PublicKey;->getEncoded()[B
invoke-virtual {v1, v3}, Ljava/security/MessageDigest;->digest([B)[B
const/4 v5, 0x2                       # Base64.NO_WRAP -- 0x0 here is a BUG
invoke-static {v4, v5}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;
```

Patch options, best first: **replace the pin string with your proxy's pin** (same length, pin still
works, integrity checks pass) → remove the `Builder.add` → stub `CertificatePinner.check`.

---

## Numbers

| | |
|---|---|
| Pin length | 44 base64 chars, one trailing `=` |
| `Base64.NO_WRAP` | `2` |
| `SSL_VERIFY_NONE` | `0` |
| `ssl_verify_ok` / `invalid` / `retry` | `0` / `1` / `2` |
| NSC arrives | API 24 |
| User CAs untrusted by default | API 24+ target |
| Conscrypt becomes an APEX | API 29 |
| `X509TrustManagerExtensions` arrives | API 17 |
| Measured: apps with a pinning surface | 12 of 14 |
| Measured: apps with a configured pin value | 4 of 14 |
| Measured: apps with 4+ layers of surface | 7 of 14 |
