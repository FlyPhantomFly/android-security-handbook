# Example 02 — an app that pins at two layers

Sources only. **No `.so`, no `.apk` and no key or certificate is committed** — you build the
binaries, in one command, outside this repository.

| File | Layer | What it is |
|---|---|---|
| [`PinnedApiClient.kt`](PinnedApiClient.kt) | A (Java) | `okhttp3.CertificatePinner` — the pin every bypass hooks first |
| [`native_pin.c`](native_pin.c) | B (native) | An SPKI comparison inside a BoringSSL `custom_verify` callback |

The two layers do not know about each other. Each is sufficient to refuse a connection on its own.
That is the entire point: [Lab 02](../../labs/lab-02-defeat-a-two-layer-pin.md) has you bypass layer
A, watch every hook report success, and still get no traffic — because layer B is untouched and
invisible to Java instrumentation.

---

## 1. Set the pins to something real

The pins in both files are placeholders (`AAAA…`, `BBBB…`) and will never match anything. Compute
real values for a host **you control** — your own lab server, or your Burp instance's CA:

```bash
# host
../../scripts/spki-pin.sh --host your.lab.host --emit okhttp
```

Paste the primary into `PIN_PRIMARY` in `PinnedApiClient.kt` and `PIN_PRIMARY_B64` in
`native_pin.c`. Generate a backup key and pin it too:

```bash
# host — keep backup.key OUT of this repository
openssl ecparam -genkey -name prime256v1 -noout -out /tmp/backup.key
../../scripts/spki-pin.sh --key /tmp/backup.key
```

> **Warning**
> `backup.key` is a private key. It must never be committed, and this repository's verification
> script treats a committed key as a failure. Generate it in a scratch directory outside the repo.

---

## 2. Build the native library

You need a TLS library for Android. The platform's `/system/lib64/libssl.so` is **not** linkable by
an app — it is outside the NDK's public API surface and the linker namespace refuses it, for the
reasons in [17-Libraries](../../../17-Libraries/README.md). Build BoringSSL or OpenSSL for Android
yourself, or use a prebuilt from a package you trust.

With BoringSSL built at `$BSSL` (headers in `$BSSL/include`, `libssl.a` and `libcrypto.a` in
`$BSSL/build`):

```bash
# host — NDK r25c, arm64 only, output OUTSIDE the repository
NDK=$HOME/Android/Sdk/ndk/25.2.9519653
TOOL=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin       # or windows-x86_64
OUT=/tmp/ch36-build/arm64-v8a
mkdir -p "$OUT"

"$TOOL/aarch64-linux-android24-clang" \
    -fPIC -shared -O2 -Wall -Wextra \
    -DOPENSSL_IS_BORINGSSL \
    -I"$BSSL/include" \
    -o "$OUT/libnativepin.so" \
    native_pin.c \
    "$BSSL/build/libssl.a" "$BSSL/build/libcrypto.a" \
    -llog
```

With OpenSSL instead, drop `-DOPENSSL_IS_BORINGSSL` — the file's `#else` branch uses the classic
`SSL_CTX_set_verify` API, and both paths are covered by the lab.

Confirm the pin string is where you expect it, which is also the first step of the lab:

```bash
# host
"$TOOL/llvm-strings" -a "$OUT/libnativepin.so" | grep -E '^[A-Za-z0-9+/]{43}=$'
```

Then confirm the verify symbol is reachable, because that determines whether a Frida
`Interceptor` can find it at all:

```bash
# host
"$TOOL/llvm-readelf" --dyn-syms "$OUT/libnativepin.so" | grep -i custom_verify
```

If the symbol is **absent** because BoringSSL was statically linked and the linker garbage-collected
the name, that is not a build failure — it is the realistic case, and
[`pin-attribution.js`](../../scripts/pin-attribution.js) will tell you so rather than pretending.

---

## 3. Assemble the app

Any Android module works. Minimum:

```kotlin
// app/build.gradle.kts  — fragment
android {
    defaultConfig {
        minSdk = 24
        ndk { abiFilters += "arm64-v8a" }
    }
    sourceSets["main"].jniLibs.srcDirs("/tmp/ch36-build")   // where you built it
}
dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
```

Install on the Redmi `M2101K6P` test device with the root fallback below — `adb install` is refused
by MIUI's "Install via USB" policy with a misleading `INSTALL_FAILED_USER_RESTRICTED: Install
canceled by user`, and nobody cancelled anything. It is an OEM gate, not a fault in the APK; the
device shell hits it too, and root does not. Chapter 60's [FAQ](../../../60-ADB/faq.md) §14 covers
the same failure:

```bash
# host
adb push app-debug.apk /data/local/tmp/ch36.apk
adb shell "su -c 'pm install -r /data/local/tmp/ch36.apk'"
```

---

## 4. What to observe

Run [`pinning-surface.py`](../../scripts/pinning-surface.py) against your own APK before you touch
Frida:

```bash
# host
python3 -B ../../scripts/pinning-surface.py --apk app-debug.apk
```

It should report the OkHttp pin at layer 3 **and** the native pin at layer 7 — from a DEX string and
a native string respectively. Two layers, found statically, before a single hook was installed. That
is the workflow the whole chapter argues for.
