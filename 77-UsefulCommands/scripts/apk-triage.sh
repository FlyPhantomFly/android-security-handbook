#!/usr/bin/env bash
#
# apk-triage.sh — 60-second static triage of an Android APK.
#
# WHAT IT DOES
#   Produces a single directory containing everything you need to decide what kind
#   of engagement you are in: identity and hashes, signature scheme and certificate,
#   manifest summary, exported components, network security config, native library
#   inventory, a secret-regex sweep, and a risky-API usage count.
#
#   This is a TRIAGE tool. Its output is a set of leads, not a set of findings.
#   Every hit must be validated by hand before it goes in a report. See
#   ../../52-StaticAnalysis/README.md for why that matters.
#
# HOW TO RUN
#   ./apk-triage.sh /path/to/target.apk [output-dir]
#
# REQUIREMENTS
#   apktool, aapt2, apksigner, unzip, grep, sha256sum (or shasum on macOS)
#
# EXIT CODES
#   0 success · 1 usage error · 2 missing dependency

set -uo pipefail

APK="${1:-}"
if [[ -z "$APK" || ! -f "$APK" ]]; then
    echo "usage: $0 <apk> [output-dir]" >&2
    exit 1
fi

OUT="${2:-$(basename "$APK" .apk)-triage}"
mkdir -p "$OUT"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 2; }; }
need unzip
need grep

# sha256sum is coreutils; macOS ships shasum instead.
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"
    else shasum -a 256 "$1"; fi
}

hr()  { printf '\n== %s %s\n' "$1" "$(printf '=%.0s' $(seq 1 $((60 - ${#1}))))"; }

{
hr "IDENTITY"
sha256 "$APK"
ls -l "$APK" | awk '{print "size: " $5 " bytes"}'

hr "MANIFEST SUMMARY"
if command -v aapt2 >/dev/null 2>&1; then
    aapt2 dump badging "$APK" 2>/dev/null | grep -E \
      "^(package:|sdkVersion:|targetSdkVersion:|application-label:|launchable-activity:|uses-permission)" \
      || echo "  aapt2 produced no badging output (obfuscated or malformed APK?)"
else
    echo "  aapt2 not installed — skipping"
fi

hr "SIGNATURE"
if command -v apksigner >/dev/null 2>&1; then
    apksigner verify -v --print-certs "$APK" 2>&1 | head -40
else
    echo "  apksigner not installed — skipping"
fi

hr "LARGEST ENTRIES"
# Big assets often hold an encrypted payload DEX (packer) or a JS/Flutter bundle.
unzip -l "$APK" | tail -n +4 | head -n -2 | sort -k1 -n -r | head -25

hr "NATIVE LIBRARIES"
unzip -l "$APK" | grep -E "lib/[^/]+/.*\.so" | awk '{print $1 "\t" $4}' \
    || echo "  (none — pure managed app)"

hr "FRAMEWORK FINGERPRINT"
# Identifying the app framework changes your entire approach.
unzip -l "$APK" | grep -q "libflutter.so"        && echo "  Flutter  (BoringSSL, ignores system trust store)"
unzip -l "$APK" | grep -q "libreactnative\|index.android.bundle" && echo "  React Native (inspect the JS bundle)"
unzip -l "$APK" | grep -q "libunity.so"          && echo "  Unity    (il2cpp / Mono — check global-metadata.dat)"
unzip -l "$APK" | grep -q "libmonodroid.so\|assemblies/" && echo "  Xamarin/MAUI (managed .NET assemblies)"
unzip -l "$APK" | grep -q "libhermes.so"         && echo "  Hermes bytecode (React Native)"
unzip -l "$APK" | grep -q "kotlin/kotlin.kotlin_builtins" && echo "  Kotlin"

hr "DECODING"
if command -v apktool >/dev/null 2>&1; then
    apktool d -f "$APK" -o "$OUT/apktool" >/dev/null 2>&1 \
        && echo "  decoded to $OUT/apktool" \
        || echo "  apktool FAILED — likely a packer or anti-decompilation tricks (see ../../40-Obfuscation/)"
else
    echo "  apktool not installed — the remaining sections will be limited"
fi

MANIFEST="$OUT/apktool/AndroidManifest.xml"
SMALI_DIRS=$(find "$OUT/apktool" -maxdepth 1 -type d -name 'smali*' 2>/dev/null)

hr "APPLICATION FLAGS"
if [[ -f "$MANIFEST" ]]; then
    for a in debuggable allowBackup usesCleartextTraffic networkSecurityConfig \
             testOnly extractNativeLibs requestLegacyExternalStorage sharedUserId; do
        v=$(grep -oE "android:${a}=\"[^\"]*\"" "$MANIFEST" | head -1)
        printf "  %-32s %s\n" "$a" "${v:-<not set>}"
    done
else
    echo "  no decoded manifest"
fi

hr "EXPORTED COMPONENTS"
if [[ -f "$MANIFEST" ]]; then
    grep -oE '<(activity|activity-alias|service|receiver|provider)[^>]*' "$MANIFEST" \
      | grep 'exported="true"' \
      | grep -oE 'android:name="[^"]*"' \
      | sed 's/android:name="/  /;s/"$//' \
      | sort -u \
      || echo "  none declared exported=true (check for intent-filters implying export)"
    echo "  --- components with an intent-filter (implicitly exported on older targetSdk) ---"
    grep -c '<intent-filter' "$MANIFEST" | sed 's/^/  intent-filter count: /'
fi

hr "NETWORK SECURITY CONFIG"
find "$OUT/apktool/res" -name "network_security_config*.xml" -print -exec cat {} \; 2>/dev/null \
    || echo "  none found (defaults apply — see ../../44-NetworkSecurityConfig/)"

hr "SECRET SWEEP"
if [[ -n "$SMALI_DIRS" ]]; then
    sweep() {
        local label="$1" pattern="$2"
        local hits
        hits=$(grep -rhoE "$pattern" $SMALI_DIRS "$OUT/apktool/res" "$OUT/apktool/assets" 2>/dev/null | sort -u | head -20)
        if [[ -n "$hits" ]]; then
            echo "  [$label]"
            echo "$hits" | sed 's/^/      /'
        fi
    }
    sweep "Google API key"  'AIza[0-9A-Za-z_-]{35}'
    sweep "AWS key id"      'AKIA[0-9A-Z]{16}'
    sweep "JWT"             'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
    sweep "Private key"     '-----BEGIN [A-Z ]*PRIVATE KEY-----'
    sweep "Stripe live"     'sk_live_[0-9a-zA-Z]{24}'
    sweep "Slack token"     'xox[baprs]-[0-9A-Za-z-]+'
    sweep "Firebase DB"     'https?://[a-z0-9.-]*\.firebaseio\.com'
    sweep "S3 bucket"       's3[.-][a-z0-9-]*\.amazonaws\.com'
    sweep "Cleartext URL"   'http://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]{6,}'
    echo
    echo "  NOTE: a public Firebase Web API key is BY DESIGN public and is not a"
    echo "        finding on its own. Validate every hit before reporting."
fi

hr "RISKY API USAGE"
if [[ -n "$SMALI_DIRS" ]]; then
    for p in addJavascriptInterface setJavaScriptEnabled \
             setAllowUniversalAccessFromFileURLs setAllowFileAccessFromFileURLs \
             setWebContentsDebuggingEnabled onReceivedSslError \
             checkServerTrusted HostnameVerifier \
             SecretKeySpec IvParameterSpec "getInstance" \
             DexClassLoader InMemoryDexClassLoader \
             "Runtime;->exec" "System;->loadLibrary" \
             MODE_WORLD_READABLE getExternalStorageDirectory; do
        n=$(grep -rl -- "$p" $SMALI_DIRS 2>/dev/null | wc -l | tr -d ' ')
        [[ "$n" != "0" ]] && printf "  %-40s %4s file(s)\n" "$p" "$n"
    done
fi

hr "ROOT / TAMPER / EMULATOR INDICATORS"
if [[ -n "$SMALI_DIRS" ]]; then
    for p in '"su"' "/system/xbin" "magisk" "test-keys" "RootBeer" \
             "isDeviceRooted" "getPackageInfo" "GET_SIGNAT" \
             "goldfish" "ranchu" "generic" "Genymotion" \
             "TracerPid" "ptrace" "frida"; do
        n=$(grep -ril -- "$p" $SMALI_DIRS 2>/dev/null | wc -l | tr -d ' ')
        [[ "$n" != "0" ]] && printf "  %-40s %4s file(s)\n" "$p" "$n"
    done
    echo "  (also grep the native libraries — see ../../37-RootDetection/)"
fi

hr "DONE"
echo "  Output directory: $OUT"
echo "  Next: read the manifest in full, then open in jadx-gui."

} 2>&1 | tee "$OUT/triage-report.txt"
