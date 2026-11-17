# Lab 03 — Attribute the rejection, and survive renewal

> **Difficulty:** intermediate
> **Time:** 2–3 hours
> **Prerequisites:** [Lab 01](lab-01-map-the-pinning-surface.md),
> [Lab 02](lab-02-defeat-a-two-layer-pin.md), [34-Cryptography](../../34-Cryptography/README.md),
> [53-Frida](../../53-Frida/README.md), `openssl` on the host
> **Authorisation:** you run your own server and your own app throughout. No third-party target.

---

## 1. Two halves, one idea

This lab has an attacking half and a defending half, and they are the same skill viewed from
opposite sides.

**Attacking:** when a connection fails, *which* control refused it? Not "pinning failed" — that is
where most people stop, and it is not actionable. The useful answer names the layer, and the layer
tells you what to do next.

**Defending:** the reason pinning is hard to operate is that the pin and the certificate have
different lifetimes. Get the relationship wrong and your app dies on renewal day. Understanding
exactly *what* is hashed is what makes the difference between a pin that survives renewal and one
that does not — and it is the same understanding that lets you predict, from a captured chain, which
pin an app is using.

You will run a certificate renewal against your own CA, twice: once the way that breaks a pin and
once the way that does not. Watching the same pin survive one and not the other is worth more than
any amount of reading about SPKI.

---

## 2. Objectives

By the end you can:

- [ ] Attribute a TLS rejection to a specific layer, with evidence, in under two minutes.
- [ ] Compute an SPKI pin four ways — `openssl`, in-app Java, native C, and by hand from the DER —
      and show they agree.
- [ ] Demonstrate, by measurement, that renewing a certificate on the **same key** does not change
      the pin, and renewing with a **new key** does.
- [ ] Explain what a backup pin is, why it does not weaken the pin set, and how to generate one for
      a key that has never been used.
- [ ] Explain what `<pin-set expiration>` does when it passes, and why the platform chose that
      behaviour.
- [ ] Tell a hostname-verification failure apart from a pin failure without guessing.

---

## 3. Setup — your own CA and server

Everything here happens in a scratch directory **outside this repository**. No key, certificate or
CSR generated in this lab may be committed.

```bash
# host
export LAB=/tmp/ch36-lab03
mkdir -p "$LAB" && cd "$LAB"
```

### 3.1 A CA

```bash
# host
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 \
    -subj "//CN=ch36 lab CA" -out ca.pem
```

> **Note on the double slash**
> On Git Bash for Windows, MSYS rewrites a leading `/` in an argument into a Windows path, so
> `-subj "/CN=x"` becomes something like `-subj "C:/Program Files/Git/CN=x"` and `openssl` reports a
> baffling error about the subject. `//CN=x` survives the rewrite. On Linux and macOS use a single
> slash. This cost real time while writing this chapter, which is why it is documented here rather
> than left as a surprise.

### 3.2 The server key, and its first certificate

```bash
# host
openssl ecparam -genkey -name prime256v1 -noout -out server-v1.key
openssl req -new -key server-v1.key -subj "//CN=lab.local" -out server-v1.csr
openssl x509 -req -in server-v1.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 30 -sha256 -out server-v1.pem
```

### 3.3 A backup key — generated now, used never

This is the point of the exercise and the step everyone omits.

```bash
# host
openssl ecparam -genkey -name prime256v1 -noout -out server-backup.key
```

That key has never signed anything, has never been presented by any server, and has no certificate.
It can still be pinned, right now, because a pin is over the **public key**, and a public key exists
the moment the key pair does.

```bash
# host
cd 36-CertificatePinning/scripts
./spki-pin.sh --key "$LAB/server-backup.key"
```

Write both pins down. You will need them in §6.

### 3.4 A server

Anything that serves TLS with a chosen key. `openssl s_server` is enough:

```bash
# host — terminal 1
cd "$LAB"
openssl s_server -accept 8443 -cert server-v1.pem -key server-v1.key \
    -CAfile ca.pem -www
```

Point the device at your host's IP. `lab.local` must resolve — either add it to the device's
`/etc/hosts` (needs root and a remount, so probably not worth it on a daily driver) or use
the IP and set the certificate's CN and SAN to the IP instead. The second is less realistic and much
less painful; if you take it, remember that hostname verification then checks an IP SAN, which is a
real difference in behaviour.

---

## 4. Part 1 — compute the pin four ways and prove they agree

The single most common pinning bug is hashing the wrong thing, and the fastest way to become immune
to it is to compute the right thing four different ways and watch them match.

### 4.1 With `openssl`, the long way

```bash
# host
openssl x509 -in "$LAB/server-v1.pem" -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64
```

Read what each stage does:

| Stage | Produces |
|---|---|
| `x509 -pubkey -noout` | The SubjectPublicKeyInfo, in PEM. `-noout` suppresses the certificate itself — omit it and you hash the wrong bytes |
| `pkey -pubin -outform der` | The same structure, DER encoded: `AlgorithmIdentifier` + `BIT STRING` |
| `dgst -sha256 -binary` | 32 raw bytes |
| `base64` | 44 characters ending in `=` |

### 4.2 With the chapter's script

```bash
# host
./spki-pin.sh --cert "$LAB/server-v1.pem"
```

Identical value. The script runs exactly the pipeline above; the point of running both is that you
now know the script is not doing anything you cannot do yourself.

### 4.3 From the key, and from the CSR

```bash
# host
./spki-pin.sh --key "$LAB/server-v1.key"
./spki-pin.sh --csr "$LAB/server-v1.csr"
```

**All three give the same value** — key, CSR and certificate. Verified while writing this chapter:
a freshly generated P-256 key, its CSR, and a self-signed certificate over it all produced
`sha256/9kpcM2xMdQMgIHWjnYmDX5dCfSp2YeCRGPmSxNNxFLk=`.

Sit with that for a second, because it is the entire renewal story in one observation. **The pin is a
property of the key, not of the certificate.** The certificate is a signed statement *about* the
key; renewing it produces a new statement about the same key, and the pin does not move.

### 4.4 The wrong hash, for contrast

```bash
# host
openssl x509 -in "$LAB/server-v1.pem" -noout -fingerprint -sha256
```

That is the certificate fingerprint. Same algorithm, same length, completely different value, and it
changes on every renewal. It is a legitimate thing to pin — some libraries support certificate
pinning explicitly — but it is **not** what `sha256/` means to OkHttp or to `<pin-set>`, and pasting
it in produces a pin that parses and never matches. See
[example 1, `wrongHashClient`](../examples/01-simple-okhttp-pin.kt).

### 4.5 In the app, in Java

Add this to your Lab 02 app, or run it in the Frida REPL against any process:

```javascript
// frida -U -n com.pentest.ch36.twolayer
Java.perform(function () {
    var MessageDigest = Java.use('java.security.MessageDigest');
    var Base64 = Java.use('android.util.Base64');
    // `cert` is any java.security.cert.X509Certificate
    // getPublicKey().getEncoded() returns the DER SubjectPublicKeyInfo ("X.509" format)
    var der = cert.getPublicKey().getEncoded();
    var d = MessageDigest.getInstance('SHA-256').digest(der);
    console.log('sha256/' + Base64.encodeToString(d, 2 /* NO_WRAP */));
});
```

`NO_WRAP` (value 2) matters. `Base64.DEFAULT` appends a newline, and a pin with a trailing newline
never matches one without it — a bug that survives code review every time because the two strings
look identical when printed.

That snippet is what [`pin-attribution.js`](../scripts/pin-attribution.js) runs for every certificate
it observes, which is why its output can be pasted straight into a pin set.

### 4.6 In native code

[`native_pin.c`](../examples/02-two-layer-pinning/native_pin.c) does it with
`i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der)` then `SHA256` then `EVP_EncodeBlock`. Read the
comment block above `spki_pin` — it lists the three things people serialise by mistake and what each
produces.

---

## 5. Part 2 — attribute a rejection

Now the attacking half. Start the app from Lab 02 with the pins from §3 and a proxy in the way.

### 5.1 Baseline: everything correct

```bash
# host
adb shell cmd package compile -m verify -f com.pentest.ch36.twolayer
frida -U -f com.pentest.ch36.twolayer -l ../scripts/pin-attribution.js --no-pause
```

With no proxy and correct pins, the summary should show accepts and no rejections:

```
=================== pin attribution summary ===================
  L2 com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive
      accepted 2   rejected 0
  L3 okhttp3.CertificatePinner.check
      accepted 1   rejected 0
```

**This baseline is the step people skip and it is the one that proves the most.** An app that never
calls `CertificatePinner.check` is not pinning, no matter what its DEX contains. Seeing the check
*run and accept* is the only positive proof that the control is live.

### 5.2 Break each thing in turn, one at a time

Change exactly one variable and record which box appears. Do them in this order.

| # | Change | Expect rejection at | Why |
|---|---|---|---|
| 1 | Point at the proxy, CA **not** installed | L2 Conscrypt `TrustManagerImpl` | Chain does not validate. Pinning is never reached |
| 2 | Point at the proxy, CA installed as **system** | L3 `CertificatePinner` | Chain validates; the pin does not match |
| 3 | Corrupt one character of the configured pin | L3 `CertificatePinner` | Same layer, different cause — and the message tells you which |
| 4 | Serve a certificate for the wrong CN with a valid chain | L4 `HostnameVerifier` | Name mismatch. **Not a pin failure** |
| 5 | Add a `<pin-set>` that matches nothing | L5 `NetworkSecurityTrustManager` | Platform pin, below OkHttp's. L3 never runs |
| 6 | Leave the native pin wrong, fix everything else | L7 native callback returns 1 | No Java layer is involved |

Run each and record the actual output. The table above is what *should* happen; what you measure is
what does.

### 5.3 The distinctions that matter

**Case 1 versus case 2** is the one that saves the most time. Both look like "the app will not talk
to my proxy". They mean opposite things:

- Rejection at L2 → your CA is not trusted. This is a **trust store** problem, and it is
  [35-SSL](../../35-SSL/README.md)'s subject. No amount of pinning bypass helps, because pinning is
  not what refused you.
- Rejection at L3 → your CA **is** trusted, the chain validated, and a pin refused. This is the
  pinning problem, and now a bypass is the right tool.

Getting these backwards sends people to fight the trust store when the trust store already works.

**Case 4** is the one that gets misreported. A hostname mismatch is usually *your* bug — the proxy
generated a certificate for the wrong SNI, or the app connects by IP and your certificate has no IP
SAN. `pin-attribution.js` prints it with an explicit note, because a "pinning bypass doesn't work"
that turns out to be an SNI problem is a genuinely common waste of an afternoon.

**Case 5** is the ordering lesson. `NetworkSecurityTrustManager` runs during chain validation, which
is *before* OkHttp's pin check. So an app with both a `<pin-set>` and a `CertificatePinner` shows
you only the `<pin-set>` failure — the OkHttp pin never executes, and you cannot tell from the
outside that it is there. **A rejection at a lower layer hides every layer above it.** You cannot
enumerate an app's pins by observing failures; you can only ever see the first one.

### 5.4 Read the pins out of the process

`pin-attribution.js` traces `CertificatePinner.Builder.add` at startup, which is why it insists on
spawning with `-f`:

```
[cfg ] CertificatePinner.Builder.add("lab.local", sha256/AAAA..., sha256/BBBB...)
```

That is the configured pin set, read from the live process, without decompiling anything. For an
obfuscated app where the pins are assembled at runtime from parts, this is often the *only* way to
recover them — and it is a much better answer than "the pins are obfuscated".

---

## 6. Part 3 — renewal, twice

The defending half. This is the measurement that makes SPKI pinning make sense.

### 6.1 Configure the pin

Set the app's pin set to the **v1 leaf pin** and the **backup key pin** from §3:

```kotlin
CertificatePinner.Builder()
    .add("lab.local", "sha256/<pin of server-v1.key>")
    .add("lab.local", "sha256/<pin of server-backup.key>")
    .build()
```

Confirm the app connects to `s_server` and no rejection box appears.

### 6.2 Renewal A — same key, new certificate

The certificate is about to expire. Reissue it, keeping the key:

```bash
# host
cd "$LAB"
openssl x509 -req -in server-v1.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -sha256 -out server-v1-renewed.pem

# different certificate?
openssl x509 -in server-v1.pem -noout -serial -enddate
openssl x509 -in server-v1-renewed.pem -noout -serial -enddate

# same pin?
cd 36-CertificatePinning/scripts
./spki-pin.sh --cert "$LAB/server-v1.pem"
./spki-pin.sh --cert "$LAB/server-v1-renewed.pem"
```

Different serial, different expiry, **identical pin**. Restart `s_server` with the renewed
certificate and run the app:

```bash
# host — terminal 1
openssl s_server -accept 8443 -cert server-v1-renewed.pem -key server-v1.key -CAfile ca.pem -www
```

The app connects. Nothing changed for it. **This is the property that makes SPKI pinning
operable at all.**

### 6.3 Renewal B — new key

Now the way most automated issuance does it by default:

```bash
# host
cd "$LAB"
openssl ecparam -genkey -name prime256v1 -noout -out server-v2.key
openssl req -new -key server-v2.key -subj "//CN=lab.local" -out server-v2.csr
openssl x509 -req -in server-v2.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -sha256 -out server-v2.pem
```

Restart the server with `server-v2.pem` / `server-v2.key`, and run the app.

```
################################################################
#  REJECTED BY: L3 okhttp3.CertificatePinner.check
#  host=lab.local
#  exception : Certificate pinning failure! ...
################################################################
```

**The app is dead.** The certificate is valid, signed by a CA the device trusts, for the correct
hostname, well within its validity window. The server is healthy. Every installed copy of the app
stopped working at the same instant, and no server-side change fixes it.

> **Mental Model**
> A pin is a bet that a specific private key will still be in use. Certificate renewal does not
> break that bet. Key rotation does. Every automated issuance pipeline you did not configure
> yourself rotates the key by default, because that is the safer default *for the certificate* — and
> it is the one that kills a pinned app.

### 6.4 The backup saves you

Switch the server to the **backup key** — the one generated in §3.3 that has never been used. Issue
it a certificate now:

```bash
# host
cd "$LAB"
openssl req -new -key server-backup.key -subj "//CN=lab.local" -out server-backup.csr
openssl x509 -req -in server-backup.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 365 -sha256 -out server-backup.pem
openssl s_server -accept 8443 -cert server-backup.pem -key server-backup.key -CAfile ca.pem -www
```

Run the app. **It connects**, with no update, because that key's pin was in the set all along.

That is the whole mechanism. A backup pin is not a weaker pin — an attacker still needs a private
key you chose. It is an *escape hatch you installed before you needed it*, and it is the difference
between a rotation and an outage.

### 6.5 Expiry

Finally, add a `<pin-set expiration="...">` in the past (see
[example 3's XML](../examples/03-spki-pin-with-backup/network_security_config.xml)), point the
server at a completely unpinned key, and observe: the app **connects**. The platform ignores an
expired pin set and falls back to ordinary chain validation.

That is strictly weaker security, deliberately. The platform authors chose "degrade to normal TLS"
over "brick the app with no server-side remedy", and once you have watched §6.3 happen, the choice
is hard to argue with. A `<pin-set>` with no `expiration` is a permanent commitment to a key you may
not control in three years.

---

## 7. Part 4 — write the two findings

### 7.1 The attacking finding

For your Lab 02 app, in the form a report can use:

> Transport security was assessed against an intercepting proxy with the testing CA installed in the
> system store. Chain validation succeeded (confirmed: `TrustManagerImpl.checkTrustedRecursive`
> accepted), and the connection was refused by `okhttp3.CertificatePinner` for host `lab.local` — a
> pin, not a trust failure. A second, independent pin in `libnativepin.so` refused the application's
> native requests; the two were confirmed separately by instrumenting each check without disabling
> it. Interception therefore requires defeating both layers, and a bypass addressing only the Java
> layer produces partial traffic while reporting success.

Every clause there is a measurement, and it names the layer. Compare with what you would have
written from a bypass script's output.

### 7.2 The defending finding

> The pin set for `api.example.com` contains a single pin over the current leaf certificate's public
> key, with no backup and no `expiration`. Certificate renewal that rotates the key pair — the
> default behaviour of most automated issuance — will invalidate the pin for every installed copy of
> the application simultaneously, with no server-side remedy. **Severity: this is an availability
> risk introduced by a security control, not a security weakness.** Recommended: add a pin over an
> offline backup key and set an expiration shorter than the slowest realistic update rollout.

The bolded sentence is the one that gets it fixed. A developer who reads "your pinning is
misconfigured" argues; a developer who reads "this will take your app down on renewal day" acts.

---

## 8. Hints

<details>
<summary>The pin-attribution script shows nothing at all</summary>

In order of likelihood:

1. You attached (`-n`/`-p`) instead of spawning (`-f`). Pinning is configured during application
   startup, so an attached session has missed it.
2. The app never made a request. Confirm with `adb logcat` or by watching the proxy for a TCP
   connection.
3. Hooks did not take on an AOT-compiled method. `adb shell cmd package compile -m verify -f <pkg>`
   then force-stop — [53-Frida §7.4.1](../../53-Frida/README.md).
4. The classes load lazily. Call `rpc.exports.rescan()` or wait for the 8-second deferred pass.
</details>

<details>
<summary>My four pin computations disagree</summary>

Check, in order:

- Trailing newline. `base64` on some platforms wraps at 76 characters; `openssl enc -base64` wraps
  by default. Use `openssl enc -base64 -A` or pipe through `tr -d '\n'`.
- `-noout` missing on `x509 -pubkey`, so the certificate PEM went into the hash too.
- `Base64.DEFAULT` instead of `Base64.NO_WRAP` on the Java side.
- You hashed `i2d_X509` (the certificate) instead of `i2d_X509_PUBKEY` (the SPKI) in the C version.
</details>

<details>
<summary>`s_client`/`s_server` won't do TLS 1.3, or the handshake stalls</summary>

`s_server -www` is a toy and it shows. Add `-tls1_2` to pin the version while debugging, and use
`-debug -msg` when you need to see what actually happened. If you need a realistic server, any nginx
with `ssl_certificate` and `ssl_certificate_key` works and behaves much better.
</details>

<details>
<summary>How do I know the app really used the backup pin and not something else?</summary>

`pin-attribution.js` prints the SPKI of every certificate in the presented chain. Compare it to the
backup key's pin from §3.3. If they match and the connection succeeded, the backup pin is what
accepted.
</details>

---

## 9. Cleanup

```bash
# host
rm -rf /tmp/ch36-lab03            # keys, CSRs and certificates — none of it goes in the repo
adb shell settings put global http_proxy :0
adb shell "su -c 'pm uninstall com.pentest.ch36.twolayer'"
```

Confirm nothing sensitive leaked into the repository:

```bash
# host — from the repo root.
#
# Match a PEM HEADER AT THE START OF A LINE, which is what a real key or
# certificate block looks like. A plain grep for "BEGIN CERTIFICATE" matches the
# scripts and prose that mention it as a search pattern, so it reports hits on a
# clean repository and you learn to ignore it -- which is exactly when it stops
# working. Anchor it.
grep -rn "^-----BEGIN" . 2>/dev/null               # expect no output
find . -name '*.pem' -o -name '*.key' -o -name '*.csr' -o -name '*.p12' -o -name '*.bks'
```

---

## 10. Success criteria

- [ ] Four independent computations of the same SPKI pin agree exactly.
- [ ] You produced a rejection at each of L2, L3, L4 and L7 and can say what each means.
- [ ] You can state why a rejection at L2 means "fix your CA" and one at L3 means "now bypass".
- [ ] You demonstrated a certificate renewal on the same key leaving the pin unchanged.
- [ ] You demonstrated a key rotation breaking the app, and the backup pin rescuing it **without an
      app update**.
- [ ] You observed an expired `<pin-set>` falling back to platform validation.
- [ ] You wrote both findings in §7, and the defensive one leads with availability rather than
      security.
- [ ] The scratch directory is deleted and no key or certificate is in the repository.

---

## 11. What you should take away

**"Pinning failed" is not a diagnosis.** The useful output names a layer, because the layer tells
you whether to fix your CA, write a hook, look for a second stack, or check your SNI. Attribution is
a two-minute step that replaces an hour of guessing.

**A pin is a bet on a key.** Certificates renew; keys need not rotate. A backup pin is how you keep
the option to rotate them anyway. An expiration is how you keep the option to be wrong.

---

**Next:** [Lab 04 — CTF: the pin that moved](lab-04-ctf-the-pin-that-moved.md).
