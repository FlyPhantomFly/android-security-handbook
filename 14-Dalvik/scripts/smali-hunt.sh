#!/usr/bin/env bash
#
# smali-hunt.sh -- run the whole chapter-14 grep catalogue against a decoded APK.
#
# WHAT IT DOES
#     Executes every search in README section 6.7 over all of an app's Smali
#     trees at once, groups the results by category, and prints a short summary
#     table at the end. Categories covered:
#
#         strings and URLs          crypto setup and key material
#         TLS trust decisions       root / emulator / tamper detection
#         reflection                dynamic code loading
#         native surface            runtime annotations that survive obfuscation
#         boolean gate methods      release logging
#         Kotlin content            debug metadata
#
# WHY YOU WOULD RUN IT
#     Because on a majority of real applications, the ranked string list plus
#     the list of boolean gate methods puts you within one screen of the thing
#     you were hired to find. This script exists so that first pass takes thirty
#     seconds and is identical every time, on every engagement, instead of being
#     whatever you happened to remember to type.
#
#     It is deliberately NOISY. Its job is to hand you a starting list, not a
#     verdict.
#
# HOW TO RUN
#     apktool d -r app.apk -o work/          # -r skips resources and is much faster
#     ./smali-hunt.sh work/
#     ./smali-hunt.sh work/ | tee hunt.txt
#     ./smali-hunt.sh work/ --strings-only
#     ./smali-hunt.sh work/ --max 40         # lines shown per category (default 25)
#
#     Works on any directory that CONTAINS smali trees, or on a smali tree
#     itself. Multidex is handled: every smali*/ directory is searched.
#
# REQUIREMENTS
#     bash, grep (GNU or BSD), sed, sort, uniq, wc. No Python, no network,
#     nothing installed. Read-only: it never writes to the tree it scans.
#
# WHAT THIS WILL *NOT* TELL YOU
#     - It will not tell you whether anything it prints is a vulnerability.
#       Every hit needs a human to open the file and read the surrounding code.
#       A `const-string "su"` might be a root check or a code comment about
#       Sudanese currency.
#     - It cannot see encrypted strings. If the const-string count is near zero,
#       the interesting constants are in fill-array-data payloads and this script
#       will only tell you how many payloads exist, not what is in them.
#     - It cannot see native code, dynamically loaded code, or anything in a
#       packed app's real payload. Dump first, then rerun on the dump.
#     - Its patterns match the standard library. An app that wraps every
#         framework call behind its own obfuscated facade will still be caught
#         (the facade must call the real API somewhere) but the hit will be in
#         one central class rather than at the interesting call sites.
#     - It does no de-duplication across trees. A library vendored twice appears
#       twice, and that is deliberate -- you want to know.

set -u

MAX=25
STRINGS_ONLY=0
ROOT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --strings-only) STRINGS_ONLY=1 ;;
        --max) shift; MAX="${1:-25}" ;;
        -h|--help)
            sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) ROOT="$1" ;;
    esac
    shift
done

if [ -z "$ROOT" ]; then
    echo "usage: $0 <decoded-apk-dir> [--max N] [--strings-only]" >&2
    exit 2
fi

if [ ! -d "$ROOT" ]; then
    echo "not a directory: $ROOT" >&2
    exit 2
fi

# Collect every smali tree. Accept either a decoded-APK root or a tree itself.
TREES=""
for d in "$ROOT"/smali "$ROOT"/smali_classes*; do
    [ -d "$d" ] && TREES="$TREES $d"
done
if [ -z "$TREES" ]; then
    # Maybe ROOT is itself a smali tree, or an arbitrary directory of .smali.
    if find "$ROOT" -name '*.smali' -print -quit 2>/dev/null | grep -q .; then
        TREES="$ROOT"
    fi
fi

if [ -z "$TREES" ]; then
    echo "no .smali files found under $ROOT" >&2
    echo "did you run: apktool d -r app.apk -o $ROOT ?" >&2
    exit 2
fi

FILE_COUNT=$(find $TREES -name '*.smali' 2>/dev/null | wc -l | tr -d ' ')

rule()   { printf '%s\n' "------------------------------------------------------------------------"; }
banner() { printf '\n'; rule; printf '%s\n' "$1"; rule; }

# section <title> <grep-args...>
# Prints up to $MAX matching lines and always prints the true total.
section() {
    title="$1"; shift
    banner "$title"
    total=$(grep -rn "$@" $TREES 2>/dev/null | wc -l | tr -d ' ')
    if [ "$total" = "0" ]; then
        echo "  (none)"
    else
        grep -rn "$@" $TREES 2>/dev/null | head -n "$MAX" | sed 's/^/  /'
        if [ "$total" -gt "$MAX" ]; then
            echo "  ... $((total - MAX)) more (total $total)"
        fi
    fi
    printf 'TOTAL %s: %s\n' "$title" "$total"
}

count_only() {
    grep -rn "$@" $TREES 2>/dev/null | wc -l | tr -d ' '
}

banner "SMALI HUNT"
printf '  root        %s\n' "$ROOT"
printf '  trees      %s\n' "$TREES"
printf '  .smali files %s\n' "$FILE_COUNT"

# ---------------------------------------------------------------------------
# 1. Strings -- always the first pass.
# ---------------------------------------------------------------------------
banner "1. STRING CONSTANTS, ranked by frequency"
grep -rhoE 'const-string(/jumbo)? [vp][0-9]+, ".*"' $TREES 2>/dev/null \
    | sed 's/.*, "//; s/"$//' \
    | grep -v '^$' \
    | sort | uniq -c | sort -rn | head -n $((MAX * 2)) | sed 's/^/  /'
CS_TOTAL=$(grep -rhoE 'const-string(/jumbo)? [vp][0-9]+, ".*"' $TREES 2>/dev/null | wc -l | tr -d ' ')
CS_UNIQ=$(grep -rhoE 'const-string(/jumbo)? [vp][0-9]+, ".*"' $TREES 2>/dev/null \
    | sed 's/.*, "//; s/"$//' | sort -u | wc -l | tr -d ' ')
printf 'TOTAL const-string sites: %s   distinct values: %s\n' "$CS_TOTAL" "$CS_UNIQ"
if [ "$CS_TOTAL" -lt 200 ] && [ "$FILE_COUNT" -gt 500 ]; then
    echo
    echo "  !! Very few string constants for an app this size."
    echo "     That is the signature of STRING ENCRYPTION -- the constants have"
    echo "     moved into fill-array-data payloads or resources. Look for a"
    echo "     static decrypt method called from everywhere (see section 5)."
fi

banner "2. URLs AND ENDPOINTS"
grep -rhoE '"[a-z]+://[^"]+"' $TREES 2>/dev/null | sort -u | head -n $((MAX * 2)) | sed 's/^/  /'
printf 'TOTAL distinct scheme:// strings: %s\n' \
    "$(grep -rhoE '"[a-z]+://[^"]+"' $TREES 2>/dev/null | sort -u | wc -l | tr -d ' ')"

if [ "$STRINGS_ONLY" = "1" ]; then
    echo
    echo "--strings-only: stopping here."
    exit 0
fi

# ---------------------------------------------------------------------------
# 3. Cryptography
# ---------------------------------------------------------------------------
section "3a. CIPHER SETUP (the const-string above each hit names the algorithm)" \
    -e 'Ljavax/crypto/Cipher;->getInstance'
section "3b. KEY AND IV CONSTRUCTION" \
    -e 'Ljavax/crypto/spec/SecretKeySpec;-><init>' \
    -e 'Ljavax/crypto/spec/IvParameterSpec;-><init>'
section "3c. DIGESTS AND MACs" \
    -e 'Ljava/security/MessageDigest;->getInstance' \
    -e 'Ljavax/crypto/Mac;->getInstance'
section "3d. ARRAY LITERALS -- where hardcoded keys actually live" \
    -e 'fill-array-data'
printf 'HINT: inspect every ".array-data 1" payload; 16 or 32 bytes is a key shape.\n'

# ---------------------------------------------------------------------------
# 4. TLS trust
# ---------------------------------------------------------------------------
section "4. TLS TRUST DECISIONS" \
    -e 'HostnameVerifier' -e 'X509TrustManager' \
    -e 'Ljavax/net/ssl/SSLContext;->init' \
    -e 'setDefaultHostnameVerifier' -e 'CertificatePinner'
printf 'HINT: a verify() that returns const/4 v0, 0x1 accepts every certificate.\n'

# ---------------------------------------------------------------------------
# 5. Anti-analysis
# ---------------------------------------------------------------------------
section "5a. ROOT DETECTION" \
    -e '"su"' -e '/system/xbin' -e '/system/bin/su' \
    -e 'Superuser' -e 'magisk' -e 'test-keys' -e 'busybox'
section "5b. EMULATOR AND DEVICE FINGERPRINTING" \
    -e 'Landroid/os/Build;->FINGERPRINT' \
    -e 'Landroid/os/Build;->MODEL' \
    -e 'Landroid/os/Build;->PRODUCT' \
    -e 'Landroid/os/Build;->HARDWARE' \
    -e 'ro.kernel.qemu' -e 'goldfish' -e 'ranchu'
section "5c. SIGNATURE AND TAMPER CHECKS" \
    -e 'GET_SIGNATURES' -e 'GET_SIGNING_CERTIFICATES' \
    -e 'signingInfo' -e '->getPackageInfo' -e 'Landroid/content/pm/Signature;'
section "5d. DEBUGGER AND FRIDA DETECTION" \
    -e 'isDebuggerConnected' -e 'Landroid/os/Debug;->' \
    -e 'frida' -e 'gum-js-loop' -e 'TracerPid'

# ---------------------------------------------------------------------------
# 6. Indirection
# ---------------------------------------------------------------------------
section "6a. REFLECTION" \
    -e 'Ljava/lang/Class;->forName' -e '->getDeclaredMethod' \
    -e '->getDeclaredField' -e 'Ljava/lang/reflect/Method;->invoke' \
    -e '->setAccessible'
section "6b. DYNAMIC CODE LOADING" \
    -e 'Ldalvik/system/DexClassLoader;' \
    -e 'Ldalvik/system/PathClassLoader;' \
    -e 'Ldalvik/system/InMemoryDexClassLoader;' \
    -e 'Ldalvik/system/DelegateLastClassLoader;' \
    -e 'Ljava/lang/System;->load' -e 'Ljava/lang/Runtime;->load'
section "6c. NATIVE METHODS -- how much logic left the DEX" \
    -e '\.method.*native'

# ---------------------------------------------------------------------------
# 7. What survives obfuscation
# ---------------------------------------------------------------------------
section "7a. RETROFIT / HTTP ANNOTATIONS (survive R8 -- read the paths)" \
    -e '\.annotation runtime Lretrofit2/http/'
section "7b. SERIALISATION FIELD NAMES (survive R8)" \
    -e 'SerializedName' -e 'Lcom/google/gson/annotations/'
section "7c. ROOM / SQL" \
    -e 'Landroidx/room/' -e 'CREATE TABLE' -e 'rawQuery' -e 'execSQL'

# ---------------------------------------------------------------------------
# 8. Patch targets and hygiene
# ---------------------------------------------------------------------------
section "8a. BOOLEAN GATE METHODS -- candidate patch targets" \
    -E '^\.method.*(is|has|check|verify|valid|allow|enable|should|can)[A-Za-z0-9_]*\(.*\)Z$'
section "8b. RELEASE LOGGING" \
    -e 'Landroid/util/Log;->'
section "8c. SHARED PREFERENCES AND FILE WRITES" \
    -e 'getSharedPreferences' -e 'Ljava/io/FileOutputStream;-><init>' \
    -e 'openFileOutput'
section "8d. WEBVIEW" \
    -e 'setJavaScriptEnabled' -e 'addJavascriptInterface' \
    -e 'setAllowFileAccess' -e 'onReceivedSslError'

# ---------------------------------------------------------------------------
# 9. Composition
# ---------------------------------------------------------------------------
banner "9. COMPOSITION"
KOTLIN=$(count_only -e 'Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter')
LINES=$(count_only -e '^\s*\.line ')
SOURCE=$(count_only -e '^\.source ')
SYNTH=$(count_only -e '^\.method.*synthetic')
METHODS=$(count_only -e '^\.method')
CLASSES=$(count_only -e '^\.class')
printf '  classes                     %s\n' "$CLASSES"
printf '  methods                     %s\n' "$METHODS"
printf '  synthetic methods           %s\n' "$SYNTH"
printf '  Kotlin null-checks          %s\n' "$KOTLIN"
printf '  .line directives            %s\n' "$LINES"
printf '  .source directives          %s\n' "$SOURCE"
if [ "$LINES" -gt 1000 ]; then
    echo
    echo "  !! Debug line-number metadata is present in quantity."
    echo "     Release builds normally strip it. Reportable under MASVS-CODE."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
banner "SUMMARY"
printf '  %-34s %s\n' "const-string sites"        "$CS_TOTAL"
printf '  %-34s %s\n' "distinct string values"    "$CS_UNIQ"
printf '  %-34s %s\n' "fill-array-data payloads"  "$(count_only -e 'fill-array-data')"
printf '  %-34s %s\n' "cipher setup sites"        "$(count_only -e 'Ljavax/crypto/Cipher;->getInstance')"
printf '  %-34s %s\n' "TLS trust sites"           "$(count_only -e 'HostnameVerifier' -e 'X509TrustManager' -e 'SSLContext;->init')"
printf '  %-34s %s\n' "reflection sites"          "$(count_only -e 'Class;->forName' -e 'getDeclaredMethod' -e 'reflect/Method;->invoke')"
printf '  %-34s %s\n' "classloader references"    "$(count_only -e 'Ldalvik/system/.*ClassLoader')"
printf '  %-34s %s\n' "native methods"            "$(count_only -e '\.method.*native')"
printf '  %-34s %s\n' "boolean gate methods"      "$(grep -rnE '^\.method.*(is|has|check|verify|valid|allow|enable|should|can)[A-Za-z0-9_]*\(.*\)Z$' $TREES 2>/dev/null | wc -l | tr -d ' ')"
printf '  %-34s %s\n' "Log call sites"            "$(count_only -e 'Landroid/util/Log;->')"

cat <<'EOF'

NEXT STEPS
  1. Read the ranked string list above. It tells you what the app talks about.
  2. Read the boolean gate methods (8a). They tell you what the app decides.
  3. For anything interesting, open the class in jadx for comprehension, then in
     Smali for detail.
  4. Confirm your hypothesis with a Frida hook BEFORE you patch anything:
         frida -U -f <package> -l scripts/trace-method.js --no-pause
  5. Profile the whole app for context:
         python3 scripts/smali_stats.py <root> --heuristics

Every line above is a lead, not a finding.
EOF
