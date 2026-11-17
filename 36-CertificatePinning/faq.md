# 36 — Certificate Pinning · FAQ

Real questions, including the ones people are embarrassed to ask. Answered directly.

---

### 1. What is pinning actually pinning? Like, what is the thing?

A public key. Specifically, a SHA-256 hash of the certificate's **SubjectPublicKeyInfo** — an
ASN.1 structure containing the algorithm identifier (which kind of key this is) and the key bytes
themselves. That hash, base64 encoded, is 44 characters ending in `=`, and it is what
`sha256/AAAA…=` means.

The app carries that hash. When a server presents a certificate, the app hashes the certificate's
key the same way and compares. If it does not match, the connection is refused — even though the
certificate might be perfectly valid, signed by a real CA, for the right hostname, and not expired.

It is **not** a hash of the certificate. That distinction matters more than almost anything else in
this chapter, and question 6 is why.

---

### 2. Why bother? Doesn't TLS already check the certificate?

TLS checks that *somebody your device trusts* signed the certificate. Your device trusts about 140
certificate authorities, and **any one of them can issue a valid certificate for any domain in the
world.** Not just for their own customers — for anybody's domain.

So the security of every TLS connection is the security of the *weakest* of those 140
organisations. That has failed repeatedly: CAs have been breached, have been compelled by
governments, and have been careless. When it fails, the resulting certificate is genuine and
your device accepts it happily.

Pinning removes the CAs from the decision for one specific host. Instead of "was this signed by
someone I trust", the question becomes "is this my key".

---

### 3. Is an app without pinning insecure?

**Usually no**, and saying otherwise is the most common bad finding in mobile security testing.

Pinning defends against one specific attacker: someone who can obtain an unauthorised but valid
certificate for your domain. If that attacker is not in the app's threat model — and for a huge
number of apps they genuinely are not — then ordinary TLS validation is a complete control, and
pinning would add operational risk (see question 8) in exchange for nothing.

OWASP's own control, MASVS-NETWORK-2, says the app performs identity pinning **when the threat model
requires it**. Not always. That qualifier is doing a lot of work and most reports drop it.

The correct write-up for an unpinned app is a factual statement plus an assessment: "relies on
platform validation; user CAs are not trusted; interception requires a system-CA certificate; for
this data and this threat model that is [adequate / insufficient because Y]".

---

### 4. Is pinning worth implementing?

Answer these three questions first. If you cannot, you are not ready.

1. **What is the backup pin, and where is the key that produces it?** A pin set with one pin has a
   single point of failure that no server-side change can fix.
2. **What happens on the day the pin is wrong?** Not "if". Name a mechanism: an expiration date, a
   signed remote config, a forced-update prompt. "We'd ship a hotfix" is not a mechanism — users who
   cannot reach your API sometimes cannot reach your update either.
3. **What does it buy *your* app?** It stops a mis-issued or attacker-installed CA. It does not stop
   a compromised server, a leaky log, a malicious SDK, or an attacker with root on the device.

Rough guidance: if the endpoints are not under your control, do not pin — you will be broken by
somebody else's routine maintenance. If the app must work behind corporate TLS inspection, do not
pin. If you handle payments, credentials or health data and you can run a proper key rotation, pin
with a backup and an expiry. If someone proposed pinning to stop users rooting their phones, correct
the premise: pinning does nothing against root.

---

### 5. Why did my bypass work yesterday and not today?

The most common causes, in rough order of frequency:

- **The app updated.** New pins, a moved layer, or pinning added in native code where it used to be
  in Java. Re-run the static map; it takes ten minutes.
- **The pins are delivered remotely.** Apps that pin at scale ship a pinning engine and fetch the
  pins from a signed config. The config changed. This is a real design (see
  [example 5](examples/05-enterprise-pin-rotation.kt)) and "it worked yesterday" is an accurate
  observation, not a mistake.
- **A staged rollout.** The same app version behaves differently for different users because
  enforcement is being ramped. You are now in the enforcing cohort.
- **You attached instead of spawning.** Pinning is configured during application startup. If the
  process was already running, the `CertificatePinner` already exists and your hook on the builder
  never fires. Use `-f`.
- **The methods were AOT-compiled.** After a while Android compiles hot methods ahead of time and
  Frida's hook may not take. `adb shell cmd package compile -m verify -f <pkg>` then force-stop.
- **Conscrypt updated.** It ships as an APEX, so it can change without an OS update, and a method
  overload your script relied on may have moved.
- **Your CA expired**, or the device's trust store was reset by an update. Check whether the failure
  is at the trust layer rather than the pin layer — they look identical from outside.

---

### 6. How do I pin without bricking my app at renewal?

Four rules, and the first two are non-negotiable:

**Pin the key, not the certificate.** Because you hash the SubjectPublicKeyInfo, a certificate
renewal that reuses the key produces an identical pin. Renewal becomes a non-event. Verified: a
key, a CSR over that key, and a certificate over that key all give the same pin value.

**Configure your issuance to reuse the key.** Most automated pipelines rotate the key by default,
because that is safer for the certificate. It is the thing that kills a pinned app. Set them not to,
deliberately, and document why.

**Always ship a backup pin.** Generate a second key today, pin it, put it in the vault, and never
use it. When the primary must be replaced — compromise, a CA that will not reissue, a dead HSM —
switch the server to the backup and every installed copy keeps working. It takes four seconds:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out backup.key
./scripts/spki-pin.sh --key backup.key
```

**Set an expiration.** In a `<pin-set>`, past the expiry Android ignores the pins and falls back to
normal validation. That is weaker, and it is much better than an app nobody can use. Choose a date
shorter than your slowest realistic update rollout.OkHttp's `CertificatePinner` has **no**
expiry mechanism — if you pin in code, you must build the escape hatch yourself.

---

### 7. Why does Frida say "hooked" but traffic still fails?

Because the script is reporting on **its hooks**, not on the app. It knows what it replaced. It
cannot know what it did not see.

Work down this list:

1. Did the app actually make a request? Check logcat, or watch for a TCP connection.
2. Is the proxy reachable from the device? Browse to it from the device's browser.
3. Did you spawn (`-f`) or attach? Attaching misses startup configuration.
4. Were the methods AOT-compiled? Deoptimise and force-stop.
5. **Which layer refused?** Stop guessing —
   [`pin-attribution.js`](scripts/pin-attribution.js) tells you in two minutes.
6. Is there a second networking stack? `unzip -l app.apk | grep '\.so$'`.
7. Is it Flutter? `unzip -l app.apk | grep flutter_assets`. If yes, see question 10.
8. Does the app bundle its own Conscrypt? Hooks on `com.android.org.conscrypt` miss `org.conscrypt`.
9. Is Certificate Transparency failing *after* the pin passed? Grep for `appmattus`.

Steps 1 to 4 resolve more cases than 5 to 9 combined, and none of them is about pinning.

---

### 8. `okhttp3.CertificatePinner` is in the DEX. Does the app pin?

No. That class ships with OkHttp unconditionally — `OkHttpClient` references it whether or not a
single pin is configured. It is in essentially every modern Android app that does networking.

Look for a **pin value**: `sha256/` followed by exactly 43 base64 characters and a `=`.

```bash
grep -a -o -h -E 'sha256/[A-Za-z0-9+/]{43}=' classes*.dex | sort -u
```

Note the difference from `grep 'sha256/'`, which matches OkHttp's own parser constant and hits on
everything. That one-character difference is the mechanism behind the "certificate pinning detected"
false positive that every automated scanner produces.

Measured across fourteen real apps on the reference device: twelve had a pinning surface, four had
a pin value.

---

### 9. What's the difference between pinning and "the app doesn't trust my CA"?

They produce the identical symptom — your proxy does not work — and they are different controls with
different fixes.

**Trust-store restriction** narrows the set of acceptable *issuers*. An app that says
`<certificates src="system"/>` (which is the default for anything targeting API 24+) refuses a CA
you installed as a user. Fix: install your CA as a **system** CA, with root or a Magisk module.

**Pinning** narrows to a specific *key*. Installing your CA anywhere does not help. Fix: bypass the
pin, or patch it to your own pin.

Telling them apart takes two minutes: run `pin-attribution.js`. A rejection at the Conscrypt trust
manager means the trust store; a rejection at `CertificatePinner` means the pin. Getting it backwards
sends you to fight a trust store that already works.

---

### 10. Nothing works on this app and it has `libflutter.so`. What now?

Flutter's Dart `HttpClient` uses a BoringSSL statically linked into `libflutter.so`, with **its own
compiled-in list of root certificates**. It does not read the Android system trust store, the user
trust store, the network security config, or the system proxy setting.

So: installing your CA does nothing. Hooking every Java layer does nothing. Editing the network
security config does nothing. `settings put global http_proxy` does nothing.

And **none of that is pinning.** It is ordinary certificate validation against a different trust
store. It defeats your bypass identically, which is why it gets reported as pinning.

What works, roughly in order of effort: hook the native verification path inside `libflutter.so`
(the symbol is stripped, so this is signature-matching per engine version and it breaks on every
engine update); force the traffic through a proxy at the network layer with a transparent redirect
(gets you the TCP stream, not past the certificate check); or patch the bundled PEM root list inside
the library to include your CA.

Identify it first, in five seconds: `unzip -l app.apk | grep flutter_assets`.

---

### 11. Should I pin the leaf, the intermediate, or the root?

| Pin | Survives leaf renewal | Who else can impersonate you |
|---|---|---|
| Leaf key | only if the key is reused | nobody |
| Your own private intermediate | yes | you |
| A public CA's intermediate | yes | **any customer of that CA** |
| A public CA root | yes | **any customer of that CA** |

Rows three and four are the trap. They feel safe because the value is stable, and they reduce your
protection to "the attacker must buy a certificate from this one CA" — which for a large commercial
CA is a purchase, not an attack. There are threat models where that is a reasonable trade; most are
not one of them.

Leaf with a backup is the usual right answer. Your own private intermediate is better if you run a
CA.

---

### 12. Is a `String.equals` pin comparison a timing vulnerability?

No, and reporting it as one costs you credibility.

The pin is a hash of a **public** key. Anyone who can connect to the server can compute it. There is
no secret to leak, so there is no timing side channel worth exploiting.

Constant-time comparison is included in this chapter's
[example 3](examples/03-spki-pin-with-backup/SpkiPinner.kt) because it costs nothing and hand-rolled
pinners get criticised for `==` — but the file says explicitly that the criticism is mostly cargo
cult. Save your findings for things that matter.

---

### 13. What actually pays in a bug bounty?

| Report | Outcome |
|---|---|
| "No certificate pinning" | Rejected. It is on almost every programme's standard out-of-scope list |
| "Pinning bypassable with Frida on a rooted device" | Rejected. That is the expected property |
| Permissive `TrustManager` accepting any certificate | **Accepted**, medium to high. That is CWE-295, not pinning |
| A pin bypass triggered by something the *network* controls | **Accepted** |
| An unauthenticated remote-config switch that disables pinning | **Accepted**, often high |
| Pinning covers the API but not the token endpoint | Sometimes accepted, depending on the data |
| A release APK shipped `debuggable` with live `<debug-overrides>` | **Accepted** |

The pattern: the payout is for a control that fails **without attacker privilege on the device**. A
bypass requiring root is not that.

---

### 14. Can pinning be bypassed without Frida?

Yes, and it is often the better route.

Unpack with `apktool`, edit the pin, rebuild, resign, install. Three variants:

- **Replace the pin string with your proxy's pin.** Same length, so nothing moves. The pin still
  works — it now pins to you. An integrity check that verifies "the pinning code is intact" passes.
  This is usually the best option and the one people think of last.
- **Remove the `Builder.add` call**, leaving an empty pin set that accepts everything.
- **Stub `okhttp3/CertificatePinner.smali`'s `check` to `return-void`.** Global; catches every call
  site.

The advantage over Frida: nothing is running on the device to detect. The disadvantage: the app may
verify its own signature ([38-TamperDetection](../38-TamperDetection/README.md)) or fail a
server-side attestation check.

---

### 15. Why is `<pin-set expiration>` a good idea if it makes pinning weaker?

Because the alternative is worse.

Past the expiry, Android ignores the pin set and falls back to ordinary chain validation. That is
strictly weaker. But without it, a pin that becomes wrong takes the app offline for every user
simultaneously, and the only fix is a store release — hours to build, days to review, weeks to reach
the long tail, and some of those users cannot download an update precisely because they cannot reach
your servers.

The platform authors chose "degrade to normal TLS" over "brick the app with no server-side remedy".
Once you have watched a key rotation kill a pinned app in
[Lab 03](labs/lab-03-attribute-the-rejection.md), the choice is easy to agree with.

---

### 16. My four ways of computing the pin disagree. Why?

In order of likelihood:

- **A trailing newline.** `base64` on some platforms wraps at 76 characters; `openssl enc -base64`
  wraps by default. Use `openssl enc -base64 -A`, or pipe through `tr -d '\n'`.
- **`Base64.DEFAULT` instead of `Base64.NO_WRAP`** on the Java side. `DEFAULT` appends a newline and
  the strings look identical when printed. Use `Base64.NO_WRAP` (value `2`).
- **Missing `-noout`** on `openssl x509 -pubkey`, so the certificate PEM went into the hash too.
- **You hashed the certificate**, with `i2d_X509` or `-fingerprint -sha256`, instead of the SPKI.
- **In C: `i2d_X509` instead of `i2d_X509_PUBKEY`.** The second is the SPKI; the first is the whole
  certificate.

---

### 17. Why does a pinning error mean my CA setup worked?

Because `CertificatePinner.check` runs **after** the trust manager already accepted the chain. The
pin is an additional constraint layered on top of validation, not a replacement for it.

So the sequence "installed my CA → now I get `Certificate pinning failure!`" means: the chain
validated, and only the pin is left. That is progress. People routinely read it as a regression and
go back to fighting the trust store, which already works.

---

### 18. Can I enumerate all of an app's pins by disabling them one at a time?

No, and this catches people out.

A rejection at a lower layer **hides every layer above it**. `NetworkSecurityTrustManager` throws
during chain validation, which happens before `CertificatePinner.check` runs at all — so an app with
both a `<pin-set>` and an OkHttp pin shows you only the `<pin-set>` failure, and you cannot tell from
outside that the second pin exists.

Map statically instead: `pinning-surface.py` reads all of them from the APK, in parallel, without
running anything.

---

### 19. Do malware authors use pinning?

Constantly, and it is one of the more useful things to know about this topic.

Banking trojans pin to their C2 so an incident responder cannot read the exfiltration on their own
analysis device. Commercial spyware pins and adds a client certificate, so you cannot even talk to
the C2 without the client key. Ad-fraud SDKs pin to their reporting endpoint so the host app's
developer cannot see what they send.

The consequence: pinning bypass is a **malware analysis** skill as much as a pentest one, and the
native techniques matter most, because malware authors know Java pins are trivially defeated.

There is a subtler version too: a pin that *reports* rather than merely refusing is a tripwire. When
you defeat a pin during an engagement, consider that the failure may have been reported before you
succeeded.

---

### 20. What is the single most useful habit from this chapter?

**Map the surface before you touch a hook.** Ten minutes of `unzip` and `grep` turns "the bypass
didn't work" — an observation with six possible causes and no way to distinguish them — into "this
app pins at layers 3 and 7, my script covers 1 through 6, so the native pin is still
running."

It is the cheapest ten minutes in mobile network testing and it is the step almost everybody skips.

---

## Still stuck?

| Symptom | Section |
|---|---|
| Nothing in the proxy at all | [README §7.7](README.md#77-when-frida-says-hooked-and-traffic-still-fails--the-checklist) |
| Half the traffic in the proxy | [README §3.7](README.md#37-flutter-and-the-tls-stack-that-ignores-you), then §3.8 |
| Which layer refused? | [README §7.2](README.md#72-pin-attributionjs--watch-do-not-bypass) |
| Native pin, stripped binary | [README §3.8](README.md#38-layers-6-and-7--native-tls), [Lab 02 §7](labs/lab-02-defeat-a-two-layer-pin.md) |
| How do I write this up? | [README §5.2](README.md#52-how-to-report-pinning-honestly) |
| Should this app pin at all? | [README §5.9](README.md#59-should-this-app-pin-a-decision-table) |
