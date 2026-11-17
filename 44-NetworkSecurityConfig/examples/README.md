# Examples — chapter 44

Two configurations for the same imaginary application, and every command that
operates on them. The commands live here rather than inside the XML files
because **an XML comment may not contain a double hyphen** — the specification
forbids it, so a long-form command-line flag written inside `<!-- -->` breaks the
whole resource and `aapt2` reports "failed to load XML file" against a file that
plainly exists.

| File | What it is |
|---|---|
| [`permissive_network_security_config.xml`](permissive_network_security_config.xml) | Eight defects, each annotated with what it does, why a developer wrote it, and what it costs |
| [`hardened_network_security_config.xml`](hardened_network_security_config.xml) | The same three hosts with every defect closed, annotated with the reasoning |

Read them side by side. Roughly fifteen tokens separate them.

---

## Audit them with this chapter's own tool

Both are text XML rather than compiled AXML, so `targetSdkVersion` and
`android:debuggable` are not knowable from the file and must be supplied. They
change the verdict — that is the point of passing them.

```bash
# host - the permissive one, as if it shipped in a release build
python3 -B ../scripts/nsc-audit.py permissive_network_security_config.xml \
        --target-sdk 33 --debuggable false

# host - and now as if the release build were debuggable. Watch NSC-010 turn
#        into NSC-009 and change from INFO to CRITICAL.
python3 -B ../scripts/nsc-audit.py permissive_network_security_config.xml \
        --target-sdk 33 --debuggable true

# host - the hardened one
python3 -B ../scripts/nsc-audit.py hardened_network_security_config.xml \
        --target-sdk 34 --debuggable false

# host - what the auditor does with an old targetSdk and no config at all
python3 -B ../scripts/nsc-audit.py hardened_network_security_config.xml \
        --target-sdk 23 --debuggable false
```

Expected shape of the output, measured:

| File | `--debuggable` | Findings | Highest |
|---|---|---|---|
| permissive | `false` | 7 | HIGH — global cleartext, user anchors twice, expired pin-set |
| permissive | `true` | 7 | **CRITICAL** — `<debug-overrides>` becomes live |
| hardened | `false` | 5 | MEDIUM — the scoped loopback cleartext permit, correctly |

the permissive file is annotated with **eight** numbered defects but
the tool reports **seven** findings. Defects 3 and 4 land on the same element and
are reported together, because `overridePins="true"` on a user anchor is not a
separate problem from the user anchor — it is what makes it worse. Counting
findings is not counting defects, and a report that conflates the two inflates
itself.

The hardened file still produces five findings, and **four of them are INFO**.
That is deliberate. A tool that prints nothing for a good configuration teaches
you nothing about it; these four say what the policy is, when the pin-set stops
protecting anything, and which of the entries can never fire.

> **Pentester's Note**
> The `MEDIUM` on the hardened file is the loopback cleartext permit, and it is a
> false positive **in context** — `localhost`, `127.0.0.1` and `10.0.2.2` are not
> reachable from a network path. Being able to explain why your own tool's
> finding does not apply is the skill; suppressing the check so the output looks
> clean is not.

---

## Compute a real pin

The `<pin>` values in `hardened_network_security_config.xml` are placeholders.
They are correctly formed — 32 bytes, base64 — so tooling parses the file, and
they correspond to no key anywhere. **Never copy a pin out of an example.**

A pin is the base64 of SHA-256 over the DER-encoded **SubjectPublicKeyInfo**: the
public key together with its algorithm identifier. It is not a hash of the
certificate. That distinction is what lets a certificate be renewed without
breaking the pin, and it is also the thing people get wrong — producing a value
of exactly the right length that matches nothing.

```bash
# host - from a certificate file
openssl x509 -in intermediate.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64

# host - straight off a live server, for the whole chain
openssl s_client -connect api.example.com:443 -servername api.example.com \
        -showcerts </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

`nsc-audit.py` performs the same computation on any certificate an APK bundles
through `<certificates src="@raw/..."/>`, and reports whether a declared `<pin>`
actually matches it.

> **Warning**
> This repository ships **no certificates and no private keys**, and neither
> should your notes. A pin is a public hash and is safe to write down. The key it
> was computed from is not.

---

## Put one into an app you control

The full recipe is [`../labs/lab-02-make-an-app-trust-your-ca.md`](../labs/lab-02-make-an-app-trust-your-ca.md).
The two-line version, for a project you are building yourself:

```xml
<!-- app/src/main/AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ... >
```

```bash
# host - copy the hardened example in and build a debuggable variant
mkdir -p app/src/main/res/xml
cp hardened_network_security_config.xml app/src/main/res/xml/network_security_config.xml
./gradlew assembleDebug
```

The `<debug-overrides>` block in the hardened file is what makes your proxy CA
work in the debug variant, and it is inert in the release variant. Verify both
claims rather than believing them:

```bash
# host - dump what the platform actually built, inside the running app
frida -U -f com.example.app -l ../scripts/nsc-runtime.js
```

In the debug build the anchor sources for the default configuration read
`SystemCertificateSource, UserCertificateSource`. In the release build they read
`SystemCertificateSource` alone, from the identical XML.

---

## Related

| Path | Why |
|---|---|
| [`../scripts/nsc-audit.py`](../scripts/nsc-audit.py) | Extracts, resolves, decodes and audits |
| [`../scripts/nsc-runtime.js`](../scripts/nsc-runtime.js) | Asks the platform what it actually built |
| [`../README.md`](../README.md) | Section 3 for the element reference, section 5 for severity |
| [`../../32-Manifest/examples/`](../../32-Manifest/examples/) | The manifest side, including `android:networkSecurityConfig` in context |
