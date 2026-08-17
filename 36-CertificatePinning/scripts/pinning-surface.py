#!/usr/bin/env python3
# 36-CertificatePinning/scripts/pinning-surface.py
#
# PURPOSE
#   Report WHICH LAYERS an app appears to pin at, BEFORE you try to bypass anything.
#
#   An Android app can enforce certificate pinning at six independent places (see
#   ../README.md section 3). A bypass that addresses one of them and misses another
#   fails in a way that looks identical to "the bypass did not work at all": every
#   hook reports success and the proxy still sees nothing. Knowing the surface first
#   turns that dead end into a one-line diagnosis.
#
#   This script is DETECTION ONLY. It installs no hooks, modifies nothing, and never
#   touches a running process's memory. It is therefore safe to point at a
#   third-party app you are NOT authorised to attack -- looking at an APK that is
#   already on your own device is not an attack. Bypassing is a different act and
#   needs different authorisation; see ../README.md section 5.1.
#
# USAGE
#   # Analyse an APK sitting on the host:
#   python3 -B pinning-surface.py --apk ./target.apk
#
#   # Pull an installed package off the attached device and analyse it:
#   python3 -B pinning-surface.py --package com.example.app
#
#   # Sweep every third-party package on the device (slow: pulls each APK):
#   python3 -B pinning-surface.py --sweep
#
#   # Add live evidence from a RUNNING process's loaded modules (needs root):
#   python3 -B pinning-surface.py --package com.example.app --live
#
#   # Machine-readable, for diffing across app versions:
#   python3 -B pinning-surface.py --apk ./target.apk --json
#
# REQUIREMENTS
#   Python 3.8+, standard library only. `adb` on PATH for --package/--sweep/--live.
#   Root on the device (`su`) only for --live. No Frida, no jadx, no apktool.
#
# WHAT THIS WILL NOT TELL YOU
#   * Whether pinning is actually ENFORCED at runtime. A string is evidence that
#     code exists, not that it executes. An app can ship okhttp3.CertificatePinner
#     in a dependency and never build a non-empty pin set. Confirm with
#     ../scripts/pin-attribution.js against a live connection.
#   * Whether the pins are CORRECT, current, or have a backup. Only the bytes of
#     the configured pin tell you that, and most of them are not recoverable
#     statically. Use ../scripts/spki-pin.sh against the real server and compare.
#   * Anything inside a packed, encrypted or runtime-downloaded DEX. This reads
#     the DEX bytes that are in the APK; ../../40-Obfuscation covers the rest.
#   * Which layer REJECTED a given connection. Static evidence cannot know that.
#     That is precisely what ../scripts/pin-attribution.js is for.
#   * Reliable results on an obfuscated app that renamed library classes. R8
#     normally keeps okhttp3 names, but -allowaccessmodification plus a custom
#     keep set can rename them; a NEGATIVE here is much weaker than a positive.
#   * Whether a `libssl.so` dependency is used for TLS at all. It may be there for
#     hashing, or for a completely unrelated protocol.
#
# AUTHORISED TESTING ONLY. Detection is not exploitation, but read section 5.1.

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

# ----------------------------------------------------------------- signatures
#
# Each signature is (layer, label, needles, note).
#   layer   - which of the six pinning layers the evidence belongs to, or a
#             supporting observation ('stack' / 'ct').
#   needles - byte strings searched for in DEX bodies, native libraries, or the
#             raw resource entries. Searching raw bytes rather than parsing DEX
#             deliberately: it costs nothing, never desynchronises from a DEX
#             version bump, and a class name in the type pool is exactly the
#             evidence we want.
#
# Absence of a needle is weak evidence. Presence is strong evidence that the CODE
# is there. Neither is evidence that it RUNS.

# CONFIDENCE is the most important column here, and the reason this script exists
# rather than a one-line grep:
#
#   HIGH  - this is a CONFIGURED PIN. A 44-character base64 digest, or a <pin-set>
#           element in a compiled resource. Something decided to pin something.
#   MATRL - embedded TRUST MATERIAL: a PEM certificate or public key compiled in.
#           Certainly there, but genuinely ambiguous. A pinned CA and a bundled
#           private trust store are byte-identical from outside. Reported as its
#           own class rather than folded into HIGH, because calling a bundled
#           root list "certificate pinning" in a report is a real, common error.
#   MED   - the app CHOSE to take control of trust (it wrote a TrustManager, it
#           called X509TrustManagerExtensions). Might be a pin; might be the exact
#           opposite -- a permissive TrustManager that accepts everything.
#   LOW   - a library that CONTAINS pinning code is on the classpath. OkHttp ships
#           okhttp3.CertificatePinner whether or not a single pin is configured,
#           so this fires on almost every modern app and means almost nothing on
#           its own. Treat a LOW hit as "there is a place a pin could live".
#
# The whole point of the distinction: reporting "app uses certificate pinning"
# because okhttp3.CertificatePinner appears in the DEX is wrong, and it is the
# single most common false positive in automated mobile scanners.

DEX_SIGNATURES = [
    ("L1", "Custom X509TrustManager", "med",
     [b"Ljavax/net/ssl/X509TrustManager;", b"checkServerTrusted"],
     "app-supplied trust decision; may be a pin, may be permissive"),

    ("L1", "SSLContext.init with own TrustManager", "med",
     [b"Ljavax/net/ssl/SSLContext;", b"Ljavax/net/ssl/TrustManagerFactory;"],
     "the app builds its own SSLContext, so platform config may not apply"),

    ("L1b", "X509TrustManagerExtensions", "med",
     [b"Landroid/net/http/X509TrustManagerExtensions;"],
     "the sanctioned pinning API: checkServerTrusted returns the cleaned chain"),

    ("L2", "Bundled Conscrypt", "med",
     [b"Lorg/conscrypt/TrustManagerImpl;", b"Lorg/conscrypt/OpenSSLProvider;"],
     "app ships its own provider; platform-class hooks will miss it"),

    ("L3", "okhttp3.CertificatePinner on the classpath", "low",
     [b"Lokhttp3/CertificatePinner;"],
     "ships with OkHttp unconditionally -- NOT evidence that a pin is configured"),

    ("L3", "OkHttp pin failure message", "low",
     [b"Certificate pinning failure!"],
     "OkHttp's own exception text, also shipped unconditionally"),

    ("L4", "Custom HostnameVerifier", "med",
     [b"Ljavax/net/ssl/HostnameVerifier;"],
     "not pinning, but rejects for a reason people misattribute to pinning"),

    ("L5", "network_security_config referenced", "low",
     [b"networkSecurityConfig", b"network_security_config"],
     "declarative config; see ../../44-NetworkSecurityConfig"),

    ("L6", "WebView SSL error handling", "med",
     [b"onReceivedSslError", b"Landroid/webkit/SslErrorHandler;"],
     "WebView has its own trust path that ignores your OkHttp hooks"),

    ("stack", "Cronet / Chromium net", "low",
     [b"Lorg/chromium/net/CronetEngine;", b"Lorg/chromium/net/"],
     "Chromium's stack: pins in native code, not in Java"),

    ("stack", "Volley", "low", [b"Lcom/android/volley/"],
     "usually delegates to HttpURLConnection"),
    ("stack", "Retrofit", "low", [b"Lretrofit2/Retrofit;"],
     "a wrapper; the pin lives in the OkHttp client below it"),
    ("stack", "Apache HttpClient", "low", [b"Lorg/apache/http/conn/ssl/"],
     "legacy stack with its own verifier"),

    ("ct", "Appmattus CertificateTransparency", "med",
     [b"Lcom/appmattus/certificatetransparency/"],
     "rejects AFTER a successful pin check; misattributed constantly"),

    ("ct", "TrustKit", "med",
     [b"Lcom/datatheorem/android/trustkit/"],
     "a pinning library with its own config and reporting"),
]

# Regex signatures. These are the HIGH-confidence ones, because they match a
# VALUE rather than a NAME. `sha256/` followed by exactly 43 base64 characters
# and a '=' is a SHA-256 digest someone typed into a pin set -- 32 bytes base64
# encoded is always 44 characters ending in one pad. The bare prefix `sha256/`
# is in OkHttp's parser and means nothing; the prefix plus a digest does not
# occur by accident.
DEX_REGEX_SIGNATURES = [
    ("L3", "CONFIGURED OkHttp/NSC pin value", "high",
     re.compile(rb"sha256/[A-Za-z0-9+/]{43}="),
     "a real 32-byte SPKI digest. Somebody configured a pin"),

    ("L3", "CONFIGURED legacy sha1 pin value", "high",
     re.compile(rb"sha1/[A-Za-z0-9+/]{27}="),
     "a 20-byte SHA-1 SPKI digest. Deprecated by OkHttp; report the algorithm"),

    ("L1", "Embedded certificate (PEM) in DEX", "material",
     re.compile(rb"-----BEGIN CERTIFICATE-----"),
     "AMBIGUOUS. Could be a pinned CA -- but a bundled private trust store, an "
     "SDK's own root list, or a test fixture look identical from here. Decide by "
     "reading the code that loads it, not by this hit"),

    ("L1", "Embedded public key (PEM) in DEX", "material",
     re.compile(rb"-----BEGIN PUBLIC KEY-----"),
     "an embedded SPKI: the shape of a hand-rolled public-key pin, but also the "
     "shape of a licence-check or update-signature key"),
]

NATIVE_SIGNATURES = [
    ("L7", "BoringSSL/OpenSSL custom verify", "med",
     [b"SSL_CTX_set_custom_verify"],
     "modern BoringSSL verification entry point -- hookable, and where a native "
     "pin is installed"),

    ("L7", "OpenSSL classic verify", "med",
     [b"SSL_CTX_set_verify"],
     "classic OpenSSL verification entry point"),

    ("L7", "TLS engine strings", "low",
     [b"BoringSSL", b"OpenSSL", b"ssl_client", b"tls13"],
     "a TLS implementation is compiled into this library"),

    ("L7", "Pin comparison helpers", "low",
     [b"X509_digest", b"SHA256_Final", b"i2d_X509_PUBKEY"],
     "SPKI hashing primitives -- the shape of a native pin, but also the shape "
     "of ordinary certificate handling"),
]

NATIVE_REGEX_SIGNATURES = [
    ("L7", "CONFIGURED pin value in a native library", "high",
     re.compile(rb"sha256/[A-Za-z0-9+/]{43}="),
     "a pin digest compiled into native code -- no Java hook will reach it"),

    ("L7", "Embedded certificate in a native library", "material",
     re.compile(rb"-----BEGIN CERTIFICATE-----"),
     "a bundled CA or pinned certificate inside the .so. Flutter's own root "
     "bundle looks exactly like this, and it is not a pin"),
]

# Library filenames that identify a whole runtime with its own TLS stack.
NATIVE_RUNTIMES = {
    "libflutter.so": ("flutter",
                      "Flutter: BoringSSL is statically linked into libflutter.so and it "
                      "uses its OWN CA bundle, ignoring the system trust store. No Java "
                      "hook and no user-CA install reaches it."),
    "libapp.so": ("flutter",
                  "Flutter application code (AOT-compiled Dart). Pins configured in Dart "
                  "live here, not in any DEX."),
    "libcronet": ("cronet", "Cronet/Chromium net stack: pinning and trust are native."),
    "libssl.so": ("openssl", "A separate OpenSSL/BoringSSL shared object."),
    "libcrypto.so": ("openssl", "OpenSSL/BoringSSL crypto half."),
    "libreactnativejni.so": ("react-native",
                             "React Native: networking normally goes through OkHttp in Java, "
                             "so Java hooks usually DO work here."),
    "libmonodroid.so": ("xamarin", "Xamarin/Mono: managed code with its own HTTP handler."),
    "libunity.so": ("unity", "Unity: UnityWebRequest, often with a bundled TLS stack."),
    "libhermes.so": ("react-native", "Hermes JS engine (React Native)."),
    "libjsc.so": ("react-native", "JavaScriptCore (older React Native)."),
}

LAYER_NAMES = {
    "L1":  "1. SSLContext / X509TrustManager",
    "L1b": "1b. X509TrustManagerExtensions",
    "L2":  "2. Conscrypt TrustManagerImpl",
    "L3":  "3. OkHttp CertificatePinner",
    "L4":  "4. HostnameVerifier",
    "L5":  "5. network_security_config <pin-set>",
    "L6":  "6. WebView",
    "L7":  "7. Native TLS (BoringSSL / OpenSSL)",
    "stack": "-- networking stack in use",
    "ct":  "-- adjacent control (fails like a pin)",
}

# The pin-set element name as it appears in a compiled AXML string pool. AAPT2
# writes the pool as UTF-8 in most builds and UTF-16LE in some; check both rather
# than parsing the chunk header, because a wrong guess here silently reports
# "no pin-set" on an app that has one.
#
# `digest` is deliberately NOT in this list. It is an ordinary English word that
# appears in unrelated resources, and including it produced a <pin-set> finding
# on apps that have none. A checker that cries wolf gets skimmed.
PINSET_NEEDLES = [
    (b"pin-set", "ASCII/UTF-8 string pool"),
    ("pin-set".encode("utf-16-le"), "UTF-16LE string pool"),
]


# --------------------------------------------------------------------- helpers

def sh(cmd, timeout=180):
    """Run a command, return (rc, stdout, stderr) as text. Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return (p.returncode,
                p.stdout.decode("utf-8", "replace"),
                p.stderr.decode("utf-8", "replace"))
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def have_adb():
    return shutil.which("adb") is not None


def adb(args, timeout=180):
    return sh(["adb"] + args, timeout=timeout)


# ------------------------------------------------------------------- analysis

class Finding:
    def __init__(self, layer, label, where, note, confidence="med", sample=None):
        self.layer = layer
        self.label = label
        self.where = where
        self.note = note
        self.confidence = confidence
        self.sample = sample

    def as_dict(self):
        d = {"layer": self.layer, "label": self.label, "confidence": self.confidence,
             "where": self.where, "note": self.note}
        if self.sample:
            d["sample"] = self.sample
        return d


def scan_bytes(blob, signatures, where, seen, out):
    """Match a literal signature list against one blob. `seen` de-dupes by label."""
    for layer, label, conf, needles, note in signatures:
        if label in seen:
            continue
        for needle in needles:
            if needle in blob:
                seen.add(label)
                out.append(Finding(layer, label, where, note, conf))
                break


def scan_regex(blob, signatures, where, seen, out, max_samples=4):
    """Match value-shaped signatures. These are the high-confidence ones."""
    for layer, label, conf, rx, note in signatures:
        if label in seen:
            continue
        hits = rx.findall(blob)
        if not hits:
            continue
        seen.add(label)
        uniq = []
        for h in hits:
            s = h.decode("ascii", "replace")
            if s not in uniq:
                uniq.append(s)
            if len(uniq) >= max_samples:
                break
        sample = "%d distinct value(s): %s" % (
            len({h for h in hits}), ", ".join(uniq))
        out.append(Finding(layer, label, where, note, conf, sample))


def analyse_apks(paths):
    """Analyse a whole app: base.apk plus every split, as one logical unit.

    Split APKs are the single most common reason a naive scanner reports
    "0 native libs" for an app that plainly ships them: on a modern device the
    base APK holds the DEX and `split_config.arm64_v8a.apk` holds lib/. Analysing
    only paths[0] would report "no native TLS" for every Flutter app installed
    from Play. Findings are de-duplicated across the whole set.
    """
    findings = []
    seen = set()
    meta = {"apks": [os.path.basename(p) for p in paths],
            "size": sum(os.path.getsize(p) for p in paths),
            "dex_count": 0, "abis": [], "native_libs": [], "runtimes": []}
    abis = set()
    native_libs = set()
    runtimes = set()
    pin_hits = []
    saw_flutter_assets = False

    for path in paths:
        try:
            z = zipfile.ZipFile(path)
        except Exception as e:                               # noqa: BLE001
            meta.setdefault("errors", []).append("%s: %s" % (os.path.basename(path), e))
            continue
        _analyse_one(z, findings, seen, meta, abis, native_libs, runtimes,
                     pin_hits, path)
        if any(n.startswith("assets/flutter_assets/") for n in z.namelist()):
            saw_flutter_assets = True
        z.close()

    meta["abis"] = sorted(abis)
    meta["native_libs"] = sorted(native_libs)
    meta["runtimes"] = sorted(runtimes)

    if pin_hits:
        where = ", ".join(sorted({h[0] for h in pin_hits})[:4])
        if len(pin_hits) > 4:
            where += " (+%d more)" % (len(pin_hits) - 4)
        findings.append(Finding(
            "L5", "CONFIGURED <pin-set> in a compiled resource", where,
            "a declared pin the app code may not know about; decode it with "
            "aapt2 dump xmltree or apktool -- see ../../44-NetworkSecurityConfig",
            "high"))

    if saw_flutter_assets:
        findings.append(Finding(
            "L7", "flutter_assets/ present", "assets/flutter_assets/",
            "confirms Flutter. Its Dart HttpClient uses a BUILT-IN CA list; "
            "installing a user CA does nothing and Java hooks do not apply. "
            "This is NOT a pin -- it is deliberately not counted as one -- but "
            "it defeats a naive bypass in exactly the same way",
            "med"))

    if not meta.get("errors") and not findings and meta["dex_count"] == 0:
        meta["error"] = "no DEX and no signatures -- is this an APK?"
    return findings, meta


def _analyse_one(z, findings, seen, meta, abis, native_libs, runtimes,
                 pin_hits, path):
    names = z.namelist()

    tag = os.path.basename(path)

    # ---- DEX: raw byte scan of every classes*.dex
    dex_names = [n for n in names if n.endswith(".dex")]
    meta["dex_count"] += len(dex_names)
    for n in dex_names:
        try:
            blob = z.read(n)
        except Exception:                                    # noqa: BLE001
            continue
        scan_bytes(blob, DEX_SIGNATURES, "%s!%s" % (tag, n), seen, findings)
        scan_regex(blob, DEX_REGEX_SIGNATURES, "%s!%s" % (tag, n), seen, findings)

    # ---- native libraries
    lib_names = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    for n in lib_names:
        abis.add(n.split("/")[1])
        native_libs.add(os.path.basename(n))

    # Only read one ABI's worth of libraries -- arm64 if present. Reading every
    # ABI multiplies the work and tells you nothing new.
    local_abis = {n.split("/")[1] for n in lib_names}
    preferred = None
    for abi in ("arm64-v8a", "armeabi-v7a", "x86_64", "x86"):
        if abi in local_abis:
            preferred = abi
            break

    for n in lib_names:
        base = os.path.basename(n)
        for key, (rt, note) in NATIVE_RUNTIMES.items():
            if base.startswith(key) or base == key:
                if rt not in runtimes:
                    runtimes.add(rt)
                    findings.append(Finding("L7", "runtime: %s (%s)" % (rt, base),
                                            "%s!%s" % (tag, n), note, "med"))
        if preferred and ("/%s/" % preferred) not in n:
            continue
        try:
            blob = z.read(n)
        except Exception:                                    # noqa: BLE001
            continue
        scan_bytes(blob, NATIVE_SIGNATURES, "%s!%s" % (tag, n), seen, findings)
        scan_regex(blob, NATIVE_REGEX_SIGNATURES, "%s!%s" % (tag, n), seen, findings)

    # ---- resources: compiled network security config
    xml_names = [n for n in names if n.startswith("res/") and n.endswith(".xml")]
    xml_names += [n for n in names if n == "resources.arsc"]
    for n in xml_names:
        try:
            blob = z.read(n)
        except Exception:                                    # noqa: BLE001
            continue
        for needle, how in PINSET_NEEDLES:
            if needle in blob:
                pin_hits.append(("%s!%s" % (tag, n), how))
                break

    # ---- manifest: is a config even referenced?
    try:
        manifest = z.read("AndroidManifest.xml")
        if b"networkSecurityConfig" in manifest or \
           "networkSecurityConfig".encode("utf-16-le") in manifest:
            if "nsc-attr" not in seen:
                seen.add("nsc-attr")
                findings.append(Finding(
                    "L5", "android:networkSecurityConfig attribute present",
                    "%s!AndroidManifest.xml" % tag,
                    "the app opts into declarative network config. Most such "
                    "configs contain no <pin-set> at all -- they exist to allow "
                    "cleartext to one host, or to trust a debug CA",
                    "low"))
        if b"usesCleartextTraffic" in manifest and "cleartext-attr" not in seen:
            seen.add("cleartext-attr")
            findings.append(Finding(
                "stack", "android:usesCleartextTraffic present",
                "%s!AndroidManifest.xml" % tag,
                "context for what the app allows over plain HTTP", "low"))
    except Exception:                                        # noqa: BLE001
        pass


def live_modules(package):
    """Loaded .so names for a running package. Requires root. Read-only."""
    rc, out, _ = adb(["shell", "pidof", package])
    pid = out.strip().split()[0] if out.strip() else None
    if not pid:
        return None, "process not running (start the app first)"

    rc, out, err = adb(["shell", "su", "-c", "'cat /proc/%s/maps'" % pid])
    if rc != 0 or not out.strip():
        rc, out, err = adb(["shell", "cat", "/proc/%s/maps" % pid])
    if not out.strip():
        return None, "could not read /proc/%s/maps (%s)" % (pid, err.strip() or "no root?")

    libs = set()
    for line in out.splitlines():
        m = re.search(r"(/\S+\.so)(?:\s|$)", line)
        if m:
            libs.add(os.path.basename(m.group(1)))
    return sorted(libs), "pid %s, %d distinct mapped .so" % (pid, len(libs))


def pull_apk(package, dest_dir):
    """Pull base.apk AND every split. Returns (list_of_local_paths, description).

    `pm path` prints one line per APK in the install. Taking only the first is the
    classic mistake: for a Play-installed app the base holds the DEX and a
    `split_config.arm64_v8a.apk` holds every native library, so a first-line-only
    scan reports "0 native libs" on an app that is entirely native.
    """
    rc, out, err = adb(["shell", "pm", "path", package])
    remote = [l.split(":", 1)[1].strip() for l in out.splitlines()
              if l.startswith("package:")]
    if not remote:
        return None, "pm path returned nothing for %s (%s)" % (package, err.strip())

    locals_ = []
    for i, r in enumerate(remote):
        local = os.path.join(dest_dir, "%s.%d.apk" % (package, i))
        adb(["pull", r, local], timeout=600)
        if os.path.exists(local):
            locals_.append(local)
    if not locals_:
        return None, "adb pull failed for every path of %s" % package
    return locals_, "%d apk(s): %s" % (len(remote), ", ".join(
        os.path.basename(r) for r in remote))


# --------------------------------------------------------------------- output

PIN_LAYERS = ("L1", "L1b", "L2", "L3", "L5", "L7")


def verdict(findings):
    """Three answers, not one, because they are genuinely different questions.

    CONFIRMED  - a pin VALUE was found: a base64 SPKI digest or a <pin-set>.
                 Somebody configured a pin. This is reportable as fact.
    MATERIAL   - embedded certificates or public keys. Something is being trusted
                 out of band. Whether that is a pin needs a human.
    SURFACE    - layers where pinning code COULD live and would have to be
                 addressed by a bypass, configured or not.

    Reporting the third as if it were the first is how "the app uses certificate
    pinning" ends up in a report about an app that pins nothing.
    """
    confirmed, material, surface = set(), set(), set()
    for f in findings:
        if f.layer not in PIN_LAYERS:
            continue
        surface.add(f.layer)
        if f.confidence == "high":
            confirmed.add(f.layer)
        elif f.confidence == "material":
            material.add(f.layer)
    return sorted(confirmed), sorted(material), sorted(surface)


def verdict_line(findings):
    confirmed, material, surface = verdict(findings)
    if confirmed:
        head = "PIN CONFIGURED at %d layer(s): %s" % (
            len(confirmed), ", ".join(LAYER_NAMES[l] for l in confirmed))
    elif material:
        head = ("no pin VALUE found, but trust material is embedded at: %s"
                % ", ".join(LAYER_NAMES[l] for l in material))
    elif surface:
        head = ("no configured pin found; surface only at %d layer(s): %s"
                % (len(surface), ", ".join(LAYER_NAMES[l] for l in surface)))
    else:
        head = "NO PINNING SURFACE DETECTED"
    return head, confirmed, material, surface


def report(target, findings, meta, live=None, live_note=""):
    print("")
    print("=" * 78)
    print("  pinning surface: %s" % target)
    print("=" * 78)

    if "error" in meta:
        print("  ERROR: %s" % meta["error"])
        return

    print("  %d dex, ABIs: %s, %d native libs"
          % (meta.get("dex_count", 0),
             ",".join(meta.get("abis", [])) or "none",
             len(meta.get("native_libs", []))))
    print("")

    if not findings:
        print("  no signatures matched.")
    else:
        by_layer = {}
        for f in findings:
            by_layer.setdefault(f.layer, []).append(f)
        for layer in ("L1", "L1b", "L2", "L3", "L4", "L5", "L6", "L7", "stack", "ct"):
            if layer not in by_layer:
                continue
            print("  [%s]" % LAYER_NAMES[layer])
            order = {"high": 0, "material": 1, "med": 2, "low": 3}
            for f in sorted(by_layer[layer], key=lambda x: order[x.confidence]):
                print("      + [%-5s] %s"
                      % (("MATRL" if f.confidence == "material"
                          else f.confidence.upper()), f.label))
                print("                where: %s" % f.where)
                if f.sample:
                    print("                value: %s" % f.sample)
                print("                note : %s" % f.note)
            print("")

    if live is not None:
        print("  [live process modules]")
        print("      %s" % live_note)
        interesting = [l for l in live
                       if any(k.replace(".so", "") in l for k in NATIVE_RUNTIMES)
                       or "ssl" in l or "crypto" in l or "conscrypt" in l]
        for l in interesting:
            print("      * %s" % l)
        if not interesting:
            print("      (no TLS-bearing module names recognised)")
        print("")

    head, confirmed, material, surface = verdict_line(findings)
    print("  VERDICT: %s" % head)
    if surface and not confirmed:
        print("")
        print("  Nothing here proves the app pins. Library code on the classpath is not")
        print("  a pin. Confirm at runtime with pin-attribution.js before writing this up.")
    if len(surface) > 1:
        print("")
        print("  A single-layer bypass WILL appear to succeed and still fail. Address the")
        print("  layers above in order and attribute the rejection with pin-attribution.js")
        print("  before disabling anything.")
    if "L7" in surface:
        print("")
        print("  NOTE: a native TLS stack is present. No Java hook reaches it.")
    print("=" * 78)


# ----------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Report which layers an Android app appears to pin at. "
                    "Detection only -- installs nothing, hooks nothing.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--apk", help="path to an APK on the host")
    g.add_argument("--package", help="installed package name (pulled via adb)")
    g.add_argument("--sweep", action="store_true",
                   help="analyse every third-party package on the device")
    ap.add_argument("--live", action="store_true",
                    help="also list loaded .so of the running process (needs root)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--limit", type=int, default=0,
                    help="with --sweep, stop after N packages")
    args = ap.parse_args()

    results = []

    if args.apk:
        if not os.path.exists(args.apk):
            print("no such file: %s" % args.apk, file=sys.stderr)
            return 2
        findings, meta = analyse_apks([args.apk])
        results.append((args.apk, findings, meta, None, ""))

    else:
        if not have_adb():
            print("adb not on PATH -- --package and --sweep need it", file=sys.stderr)
            return 2

        if args.sweep:
            rc, out, err = adb(["shell", "pm", "list", "packages", "-3"])
            pkgs = [l.split(":", 1)[1].strip() for l in out.splitlines()
                    if l.startswith("package:")]
            if args.limit:
                pkgs = pkgs[:args.limit]
        else:
            pkgs = [args.package]

        tmp = tempfile.mkdtemp(prefix="pinsurface-")
        try:
            for pkg in pkgs:
                paths, where = pull_apk(pkg, tmp)
                if paths is None:
                    print("[-] %s: %s" % (pkg, where), file=sys.stderr)
                    continue
                findings, meta = analyse_apks(paths)
                meta["device_path"] = where
                live, note = (None, "")
                if args.live:
                    live, note = live_modules(pkg)
                results.append((pkg, findings, meta, live, note))
                for p in paths:
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    if args.json:
        payload = []
        for target, findings, meta, live, note in results:
            head, confirmed, material, surface = verdict_line(findings)
            payload.append({
                "target": target,
                "meta": meta,
                "verdict": head,
                "confirmed_pin_layers": confirmed,
                "trust_material_layers": material,
                "surface_layers": surface,
                "findings": [f.as_dict() for f in findings],
                "live_modules": live,
            })
        print(json.dumps(payload, indent=2))
    else:
        for target, findings, meta, live, note in results:
            report(target, findings, meta, live, note)
        if len(results) > 1:
            print("")
            print("SUMMARY   confirmed = a pin VALUE was found")
            print("          material  = certs/keys embedded, purpose ambiguous")
            print("          surface   = layers a bypass would have to address")
            print("-" * 78)
            print("%-38s %-14s %-10s %s"
                  % ("target", "confirmed", "material", "surface"))
            for target, findings, meta, live, note in results:
                head, confirmed, material, surface = verdict_line(findings)
                print("%-38s %-14s %-10s %s"
                      % (target[:38], ",".join(confirmed) or "-",
                         ",".join(material) or "-", ",".join(surface) or "-"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
