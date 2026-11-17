# 36 — Certificate Pinning · Examples

Five graded examples, simple to enterprise, matching [§9 of the chapter](../README.md#9-examples).
Real code, not pseudocode. Every pin value in every file is a placeholder (`AAAA…`, `BBBB…`) that
matches nothing — compute real ones with [`../scripts/spki-pin.sh`](../scripts/spki-pin.sh).

| # | Tier | File | What it teaches |
|---|---|---|---|
| 1 | Simple | [`01-simple-okhttp-pin.kt`](01-simple-okhttp-pin.kt) | What a pin *is*, and the four ways the first attempt is wrong |
| 2 | Intermediate | [`02-two-layer-pinning/`](02-two-layer-pinning/README.md) | An app pinning at **two layers** — the chapter's core artefact |
| 3 | Advanced | [`03-spki-pin-with-backup/`](03-spki-pin-with-backup/SpkiPinner.kt) | A correct hand-rolled SPKI pin with a backup, plus the declarative equivalent |
| 4 | Real application | [`04-pins-that-are-not-pins.kt`](04-pins-that-are-not-pins.kt) | Five things shipped as "pinning" that are not — including the case that is not a finding |
| 5 | Enterprise | [`05-enterprise-pin-rotation.kt`](05-enterprise-pin-rotation.kt) | Signed, rotatable, report-only-capable pinning with a kill switch |

---

## Path mapping

Two files print a path in their first comment line that differs from where they live: the comment
gives the path the file would occupy *inside an Android project*, while this repository stores
examples flat. Neither is a missing file, and a checker that reports them as absent is producing a
false positive — creating the printed paths would only duplicate the annotated copies shipped here.

| Printed in the file | Ships here |
|---|---|
| `app/src/main/res/xml/network_security_config.xml` | [`03-spki-pin-with-backup/network_security_config.xml`](03-spki-pin-with-backup/network_security_config.xml) |
| `app/src/main/cpp/native_pin.c` | [`02-two-layer-pinning/native_pin.c`](02-two-layer-pinning/native_pin.c) |

---

## Building

Only example 2 produces a binary, and its build is documented in
[`02-two-layer-pinning/README.md`](02-two-layer-pinning/README.md). It builds **outside this
repository** — no `.so`, `.apk`, `.dex`, `.class`, key or certificate is ever committed here.

> **What has been verified about `native_pin.c`, and what has not.**
> `02-two-layer-pinning/native_pin.c` and the CTF's
> [`../labs/ctf-pin-that-moved/pin_gate.c`](../labs/ctf-pin-that-moved/pin_gate.c) both **compile
> clean** with `-Wall -Wextra -O2`, cross-targeting `aarch64-linux-android21` with
> **NDK 25.2.9519653**, using the OpenSSL **3.3.2** headers for the `openssl/*` includes. Zero
> diagnostics from either file.
>
> They were **not linked**, and that is not an oversight. The NDK ships no `libssl`/`libcrypto`, and
> the platform's `/system/lib64/libssl.so` is deliberately outside the public API surface — an app
> that links it is blocked by the linker namespace rules described in
> [17-Libraries](../../17-Libraries/README.md). Producing a loadable `libnativepin.so` therefore
> requires you to supply a BoringSSL or OpenSSL **built for Android**, which is the first step of
> [`02-two-layer-pinning/README.md`](02-two-layer-pinning/README.md).
>
> So: the C is verified — every type, every call signature, every control path the compiler can see.
> The **link and the runtime behaviour are not**, and they are the parts that depend on which TLS
> library you chose. `SSL_CTX_set_custom_verify` is BoringSSL-only; the `#ifdef` in the file falls
> back to `SSL_CTX_set_verify` on OpenSSL, and the two take different callback shapes. Compiling
> against OpenSSL 3.3.2 headers exercised the fallback branch, not the BoringSSL one, so if you build
> against BoringSSL and hit a diagnostic in that `#ifdef`, it is new information — record it.

Examples 1, 3, 4 and 5 are Kotlin fragments meant to be read and pasted into a module. They compile
against `com.squareup.okhttp3:okhttp:4.12.0` and the Android SDK; example 3 needs API 17+ for
`X509TrustManagerExtensions`, and example 5 uses `org.json`, which is part of the platform.

---

## The one thing to take from this directory

Example 4, case 5. An app with no pinning is not automatically a finding. Pinning is a control
against a specific threat — a certificate that chains to a trusted CA but was not authorised by you —
and if that threat is not in the app's model, ordinary TLS validation is an adequate control and
pinning adds operational risk for nothing.

Reporting "no certificate pinning" as a vulnerability without that analysis is the most common bad
finding in mobile network testing. [§5.2](../README.md#52-how-to-report-pinning-honestly) gives the
wording that is defensible instead.
