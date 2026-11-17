# 35 — SSL/TLS · FAQ

Real questions, answered directly. Including the ones people are embarrassed to ask.

Measurements marked **[M]** were taken on a Redmi M2101K6P (`sweetin`), Android 11 / API 30, MIUI
12.5, rooted, with frida 16.1.6 on the host.

---

**1. What is the actual difference between SSL and TLS?**

They are the same protocol under two names, separated by a rename that happened in 1999.

SSL (Secure Sockets Layer) was Netscape's protocol. Versions 1.0 (never released), 2.0 (1995) and
3.0 (1996) exist. When the IETF took the protocol over for standardisation, it renamed it to TLS
(Transport Layer Security) and reset the version number: TLS 1.0 is, on the wire, version 3.1 — the
direct successor to SSL 3.0.

| Name | Wire version | Year | Status |
|---|---|---|---|
| SSL 2.0 | `0x0002` | 1995 | Broken. Prohibited by RFC 6176 |
| SSL 3.0 | `0x0300` | 1996 | Broken. POODLE (CVE-2014-3566). Prohibited by RFC 7568 |
| TLS 1.0 | `0x0301` | 1999 | Deprecated by RFC 8996 |
| TLS 1.1 | `0x0302` | 2006 | Deprecated by RFC 8996 |
| TLS 1.2 | `0x0303` | 2008 | Current |
| TLS 1.3 | `0x0304` | 2018 | Current, and the one to prefer |

The word "SSL" survives everywhere because the APIs were named before the rename and were never
changed: `SSLContext`, `SSLSocket`, `SSLHandshakeException`, `openssl`, `s_client`. When someone
says "SSL" in 2026 they almost always mean TLS 1.2 or 1.3. It is not worth correcting people, but it
*is* worth knowing that an app which literally calls `SSLContext.getInstance("SSL")` or
`getInstance("SSLv3")` has asked for something specific and deprecated — that is a real finding, and
it is different from someone saying "SSL" in a meeting.

> **Definition**
> **Protocol version negotiation.** The client offers a maximum version; the server picks one it
> supports. In TLS 1.3 the version moved into the `supported_versions` extension and the legacy
> version field is frozen at `0x0303`, specifically because middleboxes had learned to reject
> anything they did not recognise in the old field.

---

**2. Why does Burp work on my browser but not on the app?**

Because they consult different lists of trusted certificate authorities, and yours went into the
list the app ignores.

When you install the Burp CA on Android through Settings, it lands in the **user store**
(`/data/misc/user/0/cacerts-added/`). Chrome and most browsers trust that store. Apps do not —
not since Android 7.0 Nougat. From `targetSdkVersion` 24 onwards, an app's default trust
configuration includes the **system** store only. Your CA is installed, visible in Settings, and
completely irrelevant to the app.

The symptom is specific and worth memorising:

```
javax.net.ssl.SSLHandshakeException:
  java.security.cert.CertPathValidatorException:
    Trust anchor for certification path not found.
```

Four fixes, in descending order of how often they are the right one:

| Fix | Needs | Notes |
|---|---|---|
| Move the CA into the **system** store | Root | The general answer. See question 4 |
| Add a `network-security-config` with a `debug-overrides` block and repackage the APK | No root, but re-signing | Chapter 44, NetworkSecurityConfig, owns the XML |
| Test with a `debuggable` build the developer gives you | Cooperation | Only works if the config declares `debug-overrides` |
| Hook the trust decision at runtime | Frida | Changes what you are measuring — use it to bypass, not to assess |

If the CA *is* in the system store and interception still fails, you are looking at pinning, which
is chapter 36, CertificatePinning.

---

**3. What is a CA, really?**

A certificate authority is a key whose signature your device has been told to believe. That is the
whole of it. There is no authority in the word beyond that decision.

Concretely: `/system/etc/security/cacerts/` is a directory of certificate files. **[M]** On the test
device there are 139 of them. Each contains a public key and a name. When a server presents a
certificate, the platform tries to build a chain of signatures from that certificate up to one of
those 139 keys. If it can, the certificate is trusted. If it cannot, it is not.

So "trusted CA" means "a file in that directory". Nothing more mystical is happening. Three
consequences follow, and they are the reason this question matters:

1. **Trust is a local decision, not a global property.** A certificate is not "valid" in the
   abstract. It is valid *relative to a trust store*. Your laptop, your phone and the app may all
   reach different conclusions about the same certificate, and all three are correct.
2. **Any CA can vouch for any name.** There is no partitioning: a CA in that directory can issue a
   certificate for your bank, and the platform will accept it. That is precisely the risk model that
   pinning exists to reduce, and it is why 139 anchors is 139 separate parties you are trusting.
3. **Adding a file adds a CA.** Which is exactly what an interception proxy does, and also exactly
   what a hostile MDM profile does. The mechanism is identical; only the intent differs.

> **Mental Model**
> A trust store is a guest list, not a lie detector. It cannot tell you whether a certificate is
> honest. It can only tell you whether someone on the list vouched for it. Your job as a tester is
> to notice who is on the list and who put them there.

---

**4. I installed my CA and it still did not help. Why?**

Because you added it to the wrong store, and the fix is not to add it harder — it is to stop it
being a *user* CA at all.

**[M]** This was measured directly on the test device. Using Frida to call
`android.security.net.config.NetworkSecurityConfig.getDefaultBuilder(ApplicationInfo)` — on API 30
there is exactly one overload, taking `android.content.pm.ApplicationInfo` — with synthetic values
for `targetSdkVersion` of 23, 24, 28, 30 and 34, and for `debuggable` both `true` and `false`, the
resulting anchor count was **139 in every single case**, and the proxy CA was trusted in every
single case.

That looks, at first, like the API 24 rule does not exist. It does. The reason the CA was trusted at
every targetSdk is that on this device it is **not in the user store at all** — a `trustusercerts`
Magisk/APatch module had promoted it into the system store. The API 24 rule says *user* CAs are not
trusted by default. It says nothing about a CA that lives in the system store, so the rule never
engaged.

That is the whole teaching point. The rule you are fighting is:

| Store the CA is in | targetSdk ≤ 23 | targetSdk ≥ 24 |
|---|---|---|
| System | trusted | trusted |
| User | trusted | **not trusted** without an explicit config |

So the operation is *promotion*, not *installation*. And promotion is awkward, because `/system` is
mounted read-only and is protected by dm-verity, so you cannot copy a file into it.

**[M]** What the module actually does, visible in `mount`, is build an overlay:

```
APatch on /system/etc/security/cacerts type tmpfs
```

followed by **139 individual bind mounts** — one per certificate. The module mounts an empty tmpfs
over the real directory (which hides all 138 stock certificates), then bind-mounts every stock
certificate back into it individually, plus the added one. The result is a directory that looks
identical to the original with one extra file, without a single byte written to the read-only
partition. It survives reboot because the module re-applies it at boot, not because anything was
persisted in `/system`.

Three more reasons a correctly-placed CA still does not help:

- **The filename is wrong.** Certificates in these stores are named by their OpenSSL
  `subject_hash_old`, and they are DER, not PEM. See question 8.
- **The app replaced its anchors.** A `TrustManagerFactory` initialised with the app's own
  `KeyStore` ignores the system store entirely. The tracer reports this as a `[tmf]` line.
- **The app pins.** Chapter 36, CertificatePinning.

---

**5. Is HTTPS enough?**

No. Three different noes, and they fail in different places.

**No, because HTTPS only protects the channel.** It says nothing about what travels on it. An app
that sends a password in a URL query string sends it perfectly securely to a server that will write
it into an access log. An app that accepts an unsigned software update over a perfect TLS connection
has an authenticated download of an attacker-influenced payload if the server is ever compromised.
TLS is transport security; it is not application security.

**No, because HTTPS in the app is only as good as the client's validation.** This is the entire
subject of this chapter. `https://` in the URL guarantees that the *protocol* runs. It guarantees
nothing about whether the app checks the certificate. An app with an empty `checkServerTrusted`
still shows `https://`, still negotiates TLS 1.3, still produces the padlock in any UI that draws
one — and accepts a certificate you generated ten seconds ago.

**No, because trust is only as narrow as the trust store.** Even with flawless validation, the app
trusts every one of the 139 anchors on the device **[M]**, plus anything a device administrator
adds. A compromised or coerced CA, or a corporate MDM profile, produces certificates the app will
accept with no complaint at all.

What HTTPS *is* enough for: it stops passive eavesdropping and casual tampering by anyone on the
path who does not control a trusted CA and cannot get code onto the device. That is a large and
genuinely valuable guarantee. It is just much narrower than "the traffic is secure".

---

**6. How do I check where the trust store is on a device, instead of trusting a blog post?**

Run one command. This is the single most useful habit in this chapter, because the location moved
recently and most written guidance is wrong for at least one Android version.

```bash
# adb shell
ls -d /apex/com.android.conscrypt/cacerts /system/etc/security/cacerts 2>&1
```

**[M]** On the test device, API 30, the answer is unambiguous:
`/system/etc/security/cacerts` exists and holds 139 files. `/apex/com.android.conscrypt/` exists —
but contains **no `cacerts` directory at all**, only `bin/ etc/ javalib/ lib/ lib64/`.

The trust store moved into the Conscrypt APEX (`/apex/com.android.conscrypt/cacerts`) in **Android
14, API 34**, so that Google could ship root-store updates through Play System Updates instead of a
full OS update. Guidance written after Android 14 tends to state the APEX path as though it were
always true; guidance written before it states the `/system` path the same way. Both are right for
some devices and wrong for yours.

| API | Where to look |
|---|---|
| 14–33 | `/system/etc/security/cacerts/` |
| 34+ | `/apex/com.android.conscrypt/cacerts/` |
| any | **Whatever the `ls` above prints.** That is the only answer that is true for the device in your hand |

The user store is `/data/misc/user/<userId>/cacerts-added/` — on a single-user device,
`/data/misc/user/0/cacerts-added/`. **[M]** It is root-only: `adb shell` runs as uid 2000 and gets
permission denied. Use `adb shell "su -c 'ls -l /data/misc/user/0/cacerts-added'"`.

---

**7. What is actually inside a certificate?**

A signed statement that one public key belongs to one set of names. Everything else is bookkeeping.

| Field | What it is | Why a tester cares |
|---|---|---|
| `subject` | Who this certificate is about | Legacy `CN` here is **not** used for hostname matching any more |
| `issuer` | Who signed it | Must match the `subject` of the next certificate up the chain |
| `serialNumber` | Unique per issuer | How revocation identifies it |
| `notBefore` / `notAfter` | Validity window | Step 3 of validation; depends on the device clock |
| `subjectPublicKeyInfo` | The public key, with its algorithm | The thing an SPKI pin hashes |
| `subjectAltName` (SAN) | The DNS names and IPs this certificate is for | **This** is what hostname verification checks |
| `basicConstraints` | `CA:TRUE/FALSE`, and `pathLenConstraint` | A leaf with `CA:FALSE` must not be able to sign anything |
| `keyUsage` / `extKeyUsage` | What the key may be used for | `serverAuth` is the one that matters here |
| signature algorithm | e.g. `sha256WithRSAEncryption` | SHA-1 or MD5 here is a finding |

What is **not** in a certificate: the private key. A certificate is public by design — the server
hands it to every client that connects, including an attacker. Reading a certificate out of an APK
or off the wire is not a finding on its own; it is the intended behaviour.

**[M]** A real chain, as reported by `tls-posture.py` against `badssl.com`:

```
CN=*.badssl.com                        RSA 2048    (leaf)
  issued by C=US, O=Let's Encrypt, CN=YR2   RSA 2048   CA:TRUE pathLen=0   (intermediate)
    issued by C=US, O=ISRG, CN=Root YR      RSA 4096                       (root)
```

---

**8. Why are the files in the trust store named things like `9a5ba575.0`?**

Because OpenSSL-style certificate directories are indexed by a hash of the subject name, so that a
validator can find a candidate issuer without reading every file in the directory. The `.0` suffix
is a collision counter: if two different CAs hash to the same value, they become `9a5ba575.0` and
`9a5ba575.1`.

The trap is *which* hash. There are two, and Android uses the older one:

```bash
# host — this one matches the filename
openssl x509 -inform DER -in ca.der -noout -subject_hash_old

# host — this one does NOT
openssl x509 -inform DER -in ca.der -noout -subject_hash
```

`subject_hash_old` is the MD5-based algorithm from OpenSSL 0.9.8; `subject_hash` is the SHA-1-based
one introduced in OpenSSL 1.0.0. Android kept the old one. **[M]** Verified on the test device: a
PortSwigger/Burp CA stored as `9a5ba575.0` produces exactly `9a5ba575` from `-subject_hash_old`.

Two more details that cost people an afternoon:

- The files are **DER**, not PEM. If you write a `-----BEGIN CERTIFICATE-----` file into the store
  it will be ignored. Convert with
  `openssl x509 -inform PEM -in ca.pem -outform DER -out ca.der`.
- The name is derived from the **subject**, so it is stable across re-issues of the same CA but
  differs for every distinct CA. Compute it; never guess it.

---

**9. Is a self-signed certificate always bad?**

No, and calling it a finding without qualification is the fastest way to look like a scanner.

Every root CA certificate in the store is self-signed. **[M]** All 139 of them. Self-signing is not
a defect; it is what "root of trust" means — the chain has to stop somewhere, and it stops at a
certificate that vouches for itself, which you accept because you decided to put it in the store,
not because of anything in the certificate.

The question is never "is it self-signed". It is **"what makes the client accept it"**:

| Situation | Verdict |
|---|---|
| Self-signed root in the device trust store | Normal. This is how PKI works |
| Self-signed leaf, accepted because the app's `TrustManager` accepts everything | **Critical.** The finding is the TrustManager, not the certificate |
| Self-signed leaf, pinned by the app, on an internal endpoint | Defensible. Pinning replaces the CA's role. Chapter 36 |
| Self-signed leaf on a staging server, with a permissive TrustManager left in the release build | Critical, and the most common real story |

Write the finding about the acceptance mechanism. "The server uses a self-signed certificate" is an
observation; "the app accepts any certificate, which is why the self-signed staging certificate
worked" is a finding.

---

**10. What is the difference between a root and an intermediate?**

Position in the chain, and where the private key is kept.

A **root** is self-signed and lives in the trust store. Its private key is the crown jewels: it is
kept offline, often in a physically guarded HSM, and is used a handful of times a decade. A **root
compromise is unrecoverable**, because every device on earth has to be updated to remove it.

An **intermediate** is signed by the root (or by another intermediate). Its private key is online
and used constantly, because it is what actually signs customers' certificates. It is *not* in your
trust store; the server sends it during the handshake.

That separation exists for exactly one reason: so the busy, exposed, online key is not the one whose
compromise cannot be fixed. If an intermediate is compromised, the CA revokes it and issues a new
one, and no device needs updating.

**[M]** In the measured `badssl.com` chain, `CN=YR2` is the intermediate: `CA:TRUE` with
`pathLen=0`, meaning it may sign leaf certificates but may not sign another CA below itself. The
root, `CN=Root YR`, is the anchor and was never sent on the wire — the client already has it.

---

**11. If the root is already trusted, why does the server still need to send the intermediate?**

Because the client has the root, not the *path* to it. Chain construction has to link the leaf to
the anchor, and the intermediate is the missing link.

The server sends leaf → intermediate. The client already holds the root. The three together form a
verifiable chain: the root's key verifies the intermediate's signature, and the intermediate's key
verifies the leaf's signature. Omit the intermediate and the client is holding a leaf signed by an
issuer it has never heard of.

This is the single most common server misconfiguration, and it has a signature symptom: **it works
in your browser and fails everywhere else.** Browsers hide it. Most fetch missing intermediates
automatically using the `authorityInfoAccess` extension's "CA Issuers" URL, and many cache
intermediates they have seen on other sites, so once you have visited any site using that CA the
chain completes from cache. Android's Conscrypt does neither by default. So the developer tests in
Chrome, sees a padlock, and ships an endpoint the app cannot reach on a fresh device.

```bash
# host — see exactly what the server sends, with no browser helpfulness
openssl s_client -connect api.example.com:443 -servername api.example.com -showcerts </dev/null

# host — or, with the chain parsed and each certificate's CA flag reported
python3 scripts/tls-posture.py api.example.com
```

If `-showcerts` prints one certificate and it is not self-signed, the intermediate is missing.

---

**12. What is SNI, and why does my proxy need it?**

**Server Name Indication** (RFC 6066) is a field in the `ClientHello` that says which hostname the
client is asking for — *before* the server sends any certificate.

It exists because of an ordering problem. Many sites share one IP address, so the server must decide
which certificate to present. But the `Host:` header, which would tell it, travels inside the
encrypted channel that does not exist yet. SNI solves this by putting the hostname in the very first
plaintext packet.

Two consequences you will meet directly:

**Your proxy must forward it.** An interception proxy terminates the client's connection and opens
its own to the real server. If it does not copy the SNI across, the server has no idea which site is
wanted and either serves a default certificate for the wrong name — which your client then rejects —
or refuses outright with **alert 112, `unrecognized_name`**. Seeing alert 112 in a proxy log almost
always means the proxy's upstream SNI is wrong.

**SNI is plaintext, so it leaks.** Anyone on the path can see every hostname you connect to, even
though the traffic itself is encrypted. That is how corporate DPI and national filtering block
individual sites without breaking TLS. Encrypted Client Hello (ECH) is the fix and is not yet
universally deployed.

```bash
# host — send a deliberately wrong SNI to see how the server reacts
python3 scripts/tls-posture.py api.example.com --sni other.example.com
openssl s_client -connect api.example.com:443 -servername wrong.example
```

---

**13. Does TLS 1.3 make any of this unnecessary?**

No. It removes a specific list of problems and leaves the ones this chapter is about entirely
untouched.

| TLS 1.3 removes | TLS 1.3 does **not** touch |
|---|---|
| Static RSA key exchange — every suite is forward-secret | Whether the client validates the certificate |
| CBC and all non-AEAD record ciphers | Whether the client checks the hostname |
| RC4, 3DES, export suites, compression | Which CAs the device trusts |
| Renegotiation | Whether the app falls back to cleartext |
| The plaintext certificate on the wire — it is now encrypted | Whether a permissive `TrustManager` was written |

The point is worth stating plainly: **an app with an empty `checkServerTrusted` is exactly as
interceptable over TLS 1.3 as over TLS 1.0.** The protocol version governs how the channel is built.
It has no opinion about whether the peer at the other end is who they claim, because that check is
delegated to code in the application.

One practical effect of the certificate being encrypted in TLS 1.3: passive traffic capture no
longer tells you which certificate a server presented. You need the client's view, which is what
`trace-tls-validation.js` gives you.

---

**14. What is the difference between trusting a CA and pinning a certificate?**

Trusting is a broad, device-wide "any of these 139 parties may vouch for anyone". Pinning is a
narrow, app-specific "for *this* host, I will accept only *this* key".

| | Trust | Pinning |
|---|---|---|
| Scope | Every host, every app on the device | One host, one app |
| Configured by | The OS image, the user, an MDM | The app developer |
| Accepts | Anything a trusted CA signed | Only the pinned key or its hash |
| Fails when | The chain reaches no anchor | The key is not the expected one, **even if the chain is perfect** |
| Runs | Validation steps 1 to 6 | After all of them |
| Breaks when | A CA is removed | The server rotates its key and the app was not updated |

The relationship is sequential, not alternative: pin evaluation happens **after** trust validation
succeeds. An app that pins still needs a valid chain first, which is why your CA being trusted is a
precondition for even reaching the pin failure. That ordering is also why "I promoted my CA and the
handshake still fails" is the classic pinning symptom.

Pinning is chapter 36, CertificatePinning. This chapter stops at the point where the platform says
"this chain terminates in a trusted anchor and the name matches".

---

**15. What does "handshake failure" actually mean?**

`handshake_failure` is **alert 40**, and it means something much narrower than the name suggests: it
means the two sides found **no cipher suite or protocol parameter in common**. It is a negotiation
failure, not a certificate failure.

That distinction is the whole value of reading the alert code instead of the exception message:

| Alert | Name | Actually means |
|---|---|---|
| 40 | `handshake_failure` | No common cipher suite or parameter |
| 42 | `bad_certificate` | The certificate was corrupt or unparsable |
| 45 | `certificate_expired` | Outside the validity window |
| 46 | `certificate_unknown` | Unspecified certificate problem — the catch-all |
| 48 | `unknown_ca` | **The chain reached no trusted anchor** |
| 70 | `protocol_version` | This protocol version is refused outright |
| 71 | `insufficient_security` | The peer wants stronger parameters than offered |
| 86 | `inappropriate_fallback` | `TLS_FALLBACK_SCSV` seen on a downgraded hello |
| 112 | `unrecognized_name` | SNI names a host this server does not serve |

Also read the **direction**. An alert *from the server* means the server rejected your client's
offer. An alert *from the client* — 48 above all — means the app rejected the server's certificate,
which is the app doing its job.

**[M]** Both cases were measured. `badssl.com` refuses SSL 3.0 with **alert 40**: it understands the
version but shares no acceptable suite at it. `www.cloudflare.com` refuses SSL 3.0, TLS 1.0 and TLS
1.1 with **alert 70**: it declines those versions outright, before cipher selection is even
considered. Two different refusals that a log line reading "handshake failed" would have flattened
into one.

Confusingly, Java's `SSLHandshakeException` is thrown for all of these, and its message is often
just `Handshake failed`. Get the alert code from `tls-posture.py`, from `openssl s_client`, or from
a packet capture — not from the exception.

---

**16. Can I intercept without root?**

Sometimes, and the honest answer is "it depends on one thing you can check in ten seconds".

| Method | Needs | Works when |
|---|---|---|
| Repackage the APK with a `network-security-config` that trusts user CAs | `apktool`, re-signing | The app has no integrity check and no pinning. Chapter 44 owns the XML |
| The app ships `debuggable=true` **and** a `debug-overrides` block | Nothing | Rare in release builds |
| The developer gives you a build with user CAs trusted | Cooperation | The normal answer on a real engagement |
| `targetSdkVersion` ≤ 23 | Nothing | Increasingly rare, and Play Store minimums keep raising the floor |
| Virtual-device or app-container approaches | A supported tool | Effectively re-signing under a different name |
| Emulator with a writable system image | No physical root | Fine for analysis; some apps detect it |

What does **not** work without root: writing to `/system/etc/security/cacerts`, reading
`/data/misc/user/0/cacerts-added` **[M]**, and running frida-server as a normal user.

Re-signing has a cost worth stating in the report: it changes the APK's signing certificate, so any
signature check, Play Integrity attestation, or hardcoded signing-hash comparison will fire. If the
app breaks after repackaging, you have found a tamper check, not a TLS problem — chapters 37 and 38.

---

**17. Does an expired certificate matter if the key is fine?**

Yes, but it is usually a Medium finding rather than the Critical that a scanner's red badge implies,
and you should be able to say why.

The mechanism the expiry protects is **revocation of last resort**. Revocation checking on Android
is not performed by default — no OCSP, no CRL — so the validity window is, in practice, the only
mechanism that eventually stops an old certificate being usable. An attacker who obtained a private
key three years ago is stopped by expiry and by nothing else.

What it does *not* mean: an expired certificate is not cryptographically weaker. The key is the same
key, the signature is the same signature. The chain still verifies. Only step 3 of validation fails.

The severity depends on what caused it:

| Cause | Severity |
|---|---|
| An operational lapse — nobody renewed it | Medium. Real availability impact, minor security impact |
| The app **accepts** it anyway | **Critical.** Now the finding is the client, not the certificate |
| An expired **intermediate**, so clients with a cached copy work and fresh devices do not | Medium, and painful to diagnose |

**[M]** `expired.badssl.com`, probed with `tls-posture.py`, flags both an expired leaf
(`notAfter 2015-04-12`) and an expired intermediate — which is exactly the second and third rows in
one target, and makes it a good fixture for the deliberate-bad-certificate test.

> **Pentester's Note**
> An expired certificate is a superb probe. Point the app at `expired.badssl.com`. If the request
> succeeds, validation step 3 is not running, which almost always means steps 1 and 2 are not either.
> It costs nothing to try and needs no proxy.

---

**18. Why does the app work over WiFi at home but not on the corporate network?**

Almost always one of three things, and they are distinguishable.

**A corporate MITM CA.** The company's proxy re-signs every TLS connection with an internal CA. That
CA is pushed to managed devices, where it typically lands as a *user* or MDM-installed CA. Browsers
accept it; apps targeting API 24+ do not, unless the MDM installs it as a device-admin-scoped CA
that the platform treats differently. Symptom: `Trust anchor for certification path not found` — the
same error as question 2, for the same reason. This is also, notably, exactly what your Burp setup
looks like to the app, which is why the two problems have one fix.

**Pinning.** If the app pins, no corporate CA can ever work, by design. Symptom: the handshake
completes and then the app rejects the connection anyway. Chapter 36.

**An SNI-filtering or DPI middlebox.** The network blocks or resets connections by hostname read
from the plaintext SNI field, or a middlebox mangles a `ClientHello` it does not understand.
Symptom: connection resets, or alert 112, and it affects some hosts and not others.

```bash
# host — run this from inside the corporate network and diff it against home
python3 scripts/tls-posture.py api.example.com --json > corporate.json
```

A chain whose root is the company's name rather than a public CA is conclusive proof of the first
case, and takes one glance at the report.

---

**19. My Frida bypass works, the script says everything is hooked, and Burp still shows nothing. Why?**

Because the app's TLS is not in Java, so there was never anything for your Java hooks to intercept.

Flutter, Cronet, Unity, React Native's newer networking layers, and any app that bundles its own
`.so` can link BoringSSL or another TLS library statically and never touch `javax.net.ssl` at all.
`Java.use('javax.net.ssl.SSLContext')` resolves fine — the class exists on every device — so the
script reports success while hooking a code path the app never executes.

The diagnostic is precise, and `trace-tls-validation.js` prints it for you:

> Zero `checkServerTrusted` calls and zero Java handshakes were seen, while the app is plainly making
> network requests.

That combination is a **result**, not a failure. It says "native TLS stack", not "the app performs
no validation". Two other things it does not mean: it does not mean your Frida setup is broken, and
it does not mean the app is safe.

Where to go next: hook the native layer — `SSL_CTX_set_custom_verify`, `SSL_get_verify_result`,
`SSL_read`/`SSL_write` in the bundled library. Chapter 53, Frida, covers the native interception
technique, and its `ssl-pinning-bypass.js` has the layered shape for it.

Two cheaper checks before you go native:

```bash
# host — is there a bundled TLS library at all?
for so in unpacked/lib/*/*.so; do strings "$so" | grep -qi "boringssl\|SSL_CTX_set" && echo "$so"; done

# host — does the app even use the system proxy? Many native stacks ignore it.
adb shell settings get global http_proxy
```

If the app ignores the device proxy setting, no amount of certificate work will help; you need a
transparent redirect (`iptables`, or a router-level rule) instead.

---

**20. The app trusts my CA and I can see traffic, so validation is broken — right?**

No, and this is the mistake that produces the most embarrassing false positives in this chapter.

You *made* the app trust your CA. Naturally it accepted your certificate — the certificate was
signed by a CA in the device's system store, so the chain terminated in a trusted anchor and
validation succeeded. Correctly. That is validation working exactly as designed.

The finding is never "I intercepted the traffic after installing my CA and rooting the device". That
describes your setup, not the app's weakness, and a competent developer will say so.

The findings are:

| Real finding | Evidence that proves it |
|---|---|
| Accepts a chain that reaches **no** trusted anchor | Self-signed certificate, no CA installed, request still succeeds |
| Accepts a valid certificate for the **wrong** hostname | A real certificate for a domain you own, presented for theirs |
| Accepts an **expired** certificate | `expired.badssl.com`, or a locally generated expired cert |
| Never validates anything at all | `oracle()` reports `RETURNED` on a zero-length chain |
| Falls back to cleartext when TLS fails | Kill the handshake; watch for an `http://` request |

Each one isolates a different validation step. Remove your CA from the trust store before running
them, or you are testing your own configuration.

> **Warning**
> A `TrustManager` that never threw during your session proves nothing whatsoever, because you never
> gave it anything to reject. Silence is not evidence. The deliberate-bad-certificate test is not
> optional — it is the only part of this chapter that produces proof.

---

**21. Is `checkServerTrusted` really the whole trust decision? It returns `void`.**

Yes, and the `void` is the reason this bug is so common.

`X509TrustManager.checkServerTrusted(X509Certificate[] chain, String authType)` has no boolean
return value. There is no `return true` to write and no `return false` to forget. **Accepting is
expressed by returning normally; rejecting is expressed by throwing `CertificateException`.**

So the complete, compiling, catastrophic implementation is:

```java
@Override
public void checkServerTrusted(X509Certificate[] chain, String authType) { }
```

Three consequences follow, and they explain why review does not catch it:

1. **The vulnerable version contains less code than the correct one.** Nothing was added; something
   was left out. Reviewers look for wrong code, not absent code.
2. **There is no keyword that says "insecure".** No `TrustAll`, no `@SuppressWarnings`, no flag. The
   method name is identical in both versions.
3. **It looks fine at runtime.** Same padlock, same successful responses, same TLS 1.3 handshake —
   right up until someone is on the path.

The interface contract also requires an `IllegalArgumentException` for a null or zero-length chain,
which an empty body does not do. **[M]** That is what makes the empty-chain oracle
decisive: `RootTrustManager`, `NetworkSecurityTrustManager` and
`com.android.org.conscrypt.TrustManagerImpl` all throw
`java.lang.IllegalArgumentException: null or zero-length parameter`,
while `android.net.SSLCertificateSocketFactory$1` — AOSP's *own* deliberately-insecure TrustManager,
returned by `SSLCertificateSocketFactory.getInsecure()` — returns normally.

> **Under the Hood**
> AOSP ships a trust-nothing `TrustManager` in the platform. `SSLCertificateSocketFactory.getInsecure()`
> is documented as insecure and exists for internal callers that handle verification themselves. When
> you find an app calling it, the app did not write the bug — it borrowed one from the framework.

---

**22. If chain validation passes, why does hostname verification matter as well?**

Because they answer two different questions, and passing one tells you nothing about the other.

Chain validation asks: **"did somebody I trust issue this certificate?"**
Hostname verification asks: **"was it issued for the host I asked for?"**

An attacker who owns `attacker.example` can obtain a genuine, free, fully valid certificate for it
from a public CA in about sixty seconds. That certificate passes chain validation perfectly — a
trusted CA really did issue it, the signatures really do verify, the dates really are current. If
the app skips hostname verification, that certificate is accepted for `api.yourbank.example`.

This is why the hostname-only bug must not be graded as the milder of the two:

| | Permissive TrustManager | Permissive HostnameVerifier |
|---|---|---|
| Attacker needs | nothing at all | one free valid certificate for a domain they own |
| Chain validation | bypassed | **passes honestly** |
| Result | full interception | full interception |
| Cost to the attacker | zero | approximately zero |

The two steps also live in different places, which is why apps break them separately: chain
validation is a `TrustManager`, hostname verification is a `HostnameVerifier` (or, for
`HttpsURLConnection`, `OkHostnameVerifier` running inside the platform's repackaged OkHttp). Fixing
one does not fix the other, and grepping for one does not find the other.

RFC 6125 governs the matching. In modern practice the check reads `subjectAltName`, **not** the
legacy `CN` field, and a wildcard matches exactly one label — `*.example.com` matches
`api.example.com` but not `a.b.example.com` and not `example.com` itself.

---

**23. What is the single fastest thing I can do on a new target?**

Two commands, four minutes, before you touch a proxy.

```bash
# host — what the servers are, from any laptop, no device needed
grep -rhoE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+' jadx-out/sources/ | sort -u > domains.txt
python3 scripts/tls-posture.py --targets domains.txt

# host — what the client checks. ALWAYS spawn; TLS is built during startup.
# frida 16.1.6 resumes on spawn by default; there is no --no-pause flag.
adb shell cmd package compile -m verify -f com.example.app
frida -U -f com.example.app -l scripts/trace-tls-validation.js
```

Then, once you have exercised the app, in the Frida REPL:

```
verdict()
oracle()
```

`verdict()` names every `TrustManager` and `HostnameVerifier` the app installed and classifies each
as platform, known library, or **app-written**. Anything in that last category is code somebody
wrote to make a trust decision, and reading it is usually the whole engagement.

`oracle()` hands each live `TrustManager` a zero-length chain. A `RETURNED` result is proof of a
permissive TrustManager that needs no proxy, no certificate and no network to demonstrate.

And then — because none of the above is proof on its own — run the deliberate-bad-certificate test.
That is the part that turns observations into a finding.
