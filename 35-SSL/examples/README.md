# 35-SSL — Examples

Two files, deliberately paired. They are the same four situations written twice: once the way
they are found in production, and once the way they should have been written.

| File | What it is |
|---|---|
| [InsecureTlsClient.java](InsecureTlsClient.java) | Four independent ways to throw away transport security, each failing differently |
| [HardenedTlsClient.java](HardenedTlsClient.java) | The same four situations, each fixed, with the reasoning for each fix in the comments |

Read them side by side. The most useful observation in this chapter comes out of the diff and
nothing else: **the secure file's fixes are mostly deletions.** Pattern A in the insecure file is
about forty lines of anonymous `X509TrustManager`; its fix is four lines that install nothing. That
inversion is the reason the bug is so common — the insecure version *looks* like effort, and the
secure version looks like having forgotten something.

---

## The four patterns

| | Insecure | What an attacker needs | Fixed by |
|---|---|---|---|
| **A** | `X509TrustManager` with an empty `checkServerTrusted` | Nothing. Any self-signed certificate generated on the spot. | Deleting it |
| **B** | `HostnameVerifier` returning `true` | One certificate, for a name they legitimately control, from any CA the device trusts | Deleting it |
| **C** | `KeyStore.getInstance("AndroidCAStore")` — system **and** user store | To get one CA installed on the device, by any means | Shipping the one anchor the app needs, or better, declaring it in a network security config |
| **D** | `catch (SSLHandshakeException)` then retry over `http://` | To make the handshake fail — which they can always do | Not retrying with less security |

Pattern **D** is the one worth dwelling on. Every line of TLS code in it is correct. There is no
permissive `TrustManager` to grep for and no `HostnameVerifier` to find. The defect is in a catch
block, and the app validates properly, refuses properly, and then sends the request in plaintext
anyway. A static scan that looks for the usual signatures reports this app as clean.

> **Warning**
> Do not copy any part of `InsecureTlsClient.java` into a real application. That is not a
> formality. Pattern A in particular has been copied out of question-and-answer sites into shipping
> financial applications more than once, because it is the top-voted answer to "how do I fix
> `javax.net.ssl.SSLHandshakeException`".

---

## Building them

**No APK is shipped in this repository, and none should ever be committed.** These are Activity
sources; they need an application around them. Build out of tree, into a scratchpad directory
outside the repository, so that no `.apk`, `.dex`, `.class` or `.jar` ever lands here.

The repository already contains a working no-Gradle build that does exactly this, and it is the one
to copy rather than re-derive:

```bash
# host
../../30-Activities/examples/build.sh
```

That script runs `aapt2 link` → `javac --release 8` → `d8` → `zipalign` → `apksigner` against
build-tools 35.0.1 and `android-35`'s `android.jar`. Two details in it are load-bearing and cost
time to rediscover:

- On Git Bash, every path handed to an SDK tool needs `cygpath -w`, or `aapt2` reports
  "failed to load XML file" for a file that plainly exists.
- XML comments must not contain `--`, which `aapt2` rejects.

If you prefer Gradle, a minimal module works too. The only thing that matters for these examples is
the manifest, and specifically what it does **not** contain.

### Manifest for the insecure app

This manifest is not shipped as a file in this repository, because it belongs to a throwaway
Android project you create outside it. Put it at the manifest path your build expects — with the
no-Gradle build above that is the path you pass to `aapt2 link --manifest`.

```xml
<!-- AndroidManifest.xml for the insecure demo -- create this in a scratchpad
     project, build out of tree, and never commit the resulting APK -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.pentest.ch35.insecure">

    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:label="ch35 insecure TLS"
        android:usesCleartextTraffic="true">
        <activity
            android:name=".InsecureTlsClient"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

`android:usesCleartextTraffic="true"` is there so that pattern D can actually demonstrate its
fallback. From API 28 the platform default is `false`, and without this attribute the cleartext
retry fails with an `IOException` before it reaches the network — which is the platform correctly
protecting an app against its own catch block. Turning it on is what makes the bug observable, and
noticing that you had to turn it on is itself the lesson. The attribute and its XML counterpart are
[44-NetworkSecurityConfig](../../44-NetworkSecurityConfig/README.md)'s subject.

### Manifest for the hardened app

Identical, minus `android:usesCleartextTraffic`, with `package="com.pentest.ch35.hardened"` and
`android:name=".HardenedTlsClient"`. Leaving the attribute out entirely is correct: the default is
already the value you want, and writing `android:usesCleartextTraffic="false"` is only useful as a
statement of intent to a future reader.

`HardenedTlsClient` fix **C** looks for an optional resource, `res/raw/private_root.crt`. If it is
absent the method reports that and skips, so the app builds and runs without it. To exercise that
path, generate your own CA in a scratchpad and drop the certificate in:

```bash
# host -- generate in a SCRATCHPAD, never inside this repository
mkdir -p /tmp/ch35 && cd /tmp/ch35
openssl req -x509 -newkey rsa:2048 -nodes -keyout private_root.key \
        -out private_root.crt -days 30 -subj "/CN=ch35 private root"
```

> **Warning**
> Never commit a private key or a certificate to this repository. Generate them in a scratchpad,
> and record the command in your notes rather than the output. The chapter's labs are written the
> same way for the same reason.

### Installing on the test device

`adb install` is refused on the MIUI device used to write this chapter with
`INSTALL_FAILED_USER_RESTRICTED`, which is an "Install via USB" policy rather than a real failure.
Root goes around it:

```bash
# host
adb push app.apk /data/local/tmp/app.apk
adb shell "su -c 'pm install -r /data/local/tmp/app.apk'"
```

---

## Exercising them

Neither example proves anything by connecting successfully. A permissive `TrustManager` and a
correct one both return the page. The difference only appears when the app is shown a certificate
it should refuse, which is the whole point of
[labs/lab-02-deliberate-bad-certificate.md](../labs/lab-02-deliberate-bad-certificate.md).

Observe what each one actually validates:

```bash
# host -- observe, do not bypass
frida -U -f com.pentest.ch35.insecure -l ../scripts/trace-tls-validation.js
```

Then, in the Frida REPL, once the Activity has run:

```javascript
// Frida REPL
oracle()
verdict()
```

`oracle()` hands every discovered `TrustManager` a zero-length certificate chain. The interface
contract requires `IllegalArgumentException` for that input, and every conformant implementation
throws it. Pattern A's anonymous class returns quietly, because its body is empty and it never looks
at its argument — which is a decisive answer that needs no proxy, no certificate and no network.

Characterise the server half separately, because a perfect client talking to a server that accepts
anonymous cipher suites is still broken:

```bash
# host
python3 -B ../scripts/tls-posture.py example.com
```

---

## Related

- [../README.md](../README.md) — the chapter, in particular sections 3 (trust anchors and
  validation), 5 (security perspective) and 9 (graded examples)
- [../labs/lab-02-deliberate-bad-certificate.md](../labs/lab-02-deliberate-bad-certificate.md) —
  the procedure that turns these files into evidence
- [../scripts/trace-tls-validation.js](../scripts/trace-tls-validation.js) — observe which
  validation an app performs, without changing it
- [../scripts/tls-posture.py](../scripts/tls-posture.py) — the server-side half
- [../../34-Cryptography/README.md](../../34-Cryptography/README.md) — the primitives these
  certificates are built from
