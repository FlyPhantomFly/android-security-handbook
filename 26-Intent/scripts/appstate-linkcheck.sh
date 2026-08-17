#!/usr/bin/env bash
#
# appstate-linkcheck.sh — report Android App Links VERIFICATION STATE for a
#                         package, using the command set that exists on the
#                         device's platform version.
#
# PURPOSE
#     `android:autoVerify="true"` in a manifest is a REQUEST, not a state. The
#     platform decides, at install time, whether to grant the app exclusive
#     handling of a domain, by fetching
#     https://<host>/.well-known/assetlinks.json over TLS and checking that it
#     names the package and the SIGNING CERTIFICATE of the installed APK.
#
#     That decision is invisible in the APK. An app with autoVerify and a missing
#     or wrong assetlinks.json behaves exactly like an ordinary deep link: any
#     other app may declare the same filter, and a chooser dialog is the only
#     thing between the user and an attacker. THAT is the finding, and you can
#     only see it on a device.
#
# THE VERSION SPLIT — the reason this script exists
#     Android 12 (API 31) replaced the legacy IntentFilterVerification subsystem
#     with DomainVerificationService, and the command set changed completely.
#     Measured on a Redmi running Android 11 / API 30:
#
#         $ adb shell pm get-app-links
#         Unknown command: get-app-links
#
#     Carrying `pm get-app-links` into an Android 11 engagement produces a
#     confident "verification state could not be determined", which is wrong.
#     This script detects ro.build.version.sdk and runs the right family:
#
#         API 31+ : pm get-app-links, pm verify-app-links, dumpsys package
#                   domain-verification
#         API <=30: pm get-app-link (singular), dumpsys package
#                   domain-preferred-apps
#
# USAGE
#     ./appstate-linkcheck.sh <package>                 # one package
#     ./appstate-linkcheck.sh --all                     # every package with domains
#     ./appstate-linkcheck.sh <package> --reverify      # force re-verification (31+)
#     ./appstate-linkcheck.sh <package> --hosts         # also fetch each assetlinks.json
#     ./appstate-linkcheck.sh <package> --apk t.apk     # compare the hosted fingerprint
#                                                       # against the APK's signer
#     ADB_SERIAL=emulator-5554 ./appstate-linkcheck.sh com.example.target
#
# REQUIREMENTS
#     bash, adb, and a device. `curl` and `python3` only for --hosts.
#     `apksigner` (Android build-tools) only for --apk.
#     Nothing is written to disk except an optional temp file under $TMPDIR.
#
# WHAT THIS WILL *NOT* TELL YOU
#     * Whether the deep link is a vulnerability. An unverified App Link is a
#       finding only when something behind it matters -- an OAuth redirect, a
#       session hand-off, a state change. A marketing landing page is not.
#     * Whether another app is ACTUALLY competing for the domain right now. Use
#       `cmd package query-activities -a android.intent.action.VIEW -d <url>`,
#       or scripts/intent-surface-map.py, for that.
#     * Whether a CUSTOM SCHEME is exclusive. It never is. There is no
#       verification mechanism for non-http(s) schemes and there cannot be --
#       there is nobody to ask who owns "myapp://". See 45-OAuth lab-03.
#     * What state the domain was in at the time of an incident. Verification
#       state changes on install, update, and user action.
#     * Anything on API <=30 about CRYPTOGRAPHIC verification. The legacy table
#       reports always/ask/never/undefined, and "always" can be a USER preference
#       rather than a successful assetlinks.json check. Say so in the report.
#
# AUTHORISED TESTING ONLY.

set -u

ADB=(adb)
if [ -n "${ADB_SERIAL:-}" ]; then ADB=(adb -s "$ADB_SERIAL"); fi

PKG=""
DO_ALL=0
DO_REVERIFY=0
DO_HOSTS=0
APK=""

usage() {
    sed -n '3,60p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --all)      DO_ALL=1 ;;
        --reverify) DO_REVERIFY=1 ;;
        --hosts)    DO_HOSTS=1 ;;
        --apk)      shift; APK="${1:-}" ;;
        -h|--help)  usage ;;
        -*)         echo "unknown option: $1" >&2; exit 2 ;;
        *)          PKG="$1" ;;
    esac
    shift
done

if [ -z "$PKG" ] && [ "$DO_ALL" -eq 0 ]; then usage; fi

# ---- device -------------------------------------------------------------- #

state=$("${ADB[@]}" get-state 2>/dev/null | tr -d '\r')
if [ "$state" != "device" ]; then
    echo "error: no device (adb get-state = '${state:-none}')" >&2
    exit 1
fi

# `adb shell` hands the whole command line to the DEVICE's sh, which re-parses
# it. Quote every argument for that shell, not just for this one.
dsh() { "${ADB[@]}" shell "$*" 2>&1 | tr -d '\r'; }

SDK=$(dsh getprop ro.build.version.sdk | tr -d '[:space:]')
REL=$(dsh getprop ro.build.version.release | tr -d '[:space:]')
BRAND=$(dsh getprop ro.product.brand | tr -d '[:space:]')

echo "=============================================================================="
echo " App Links verification state"
echo " device: $BRAND  Android $REL  API $SDK"
if [ "$SDK" -ge 31 ] 2>/dev/null; then
    echo " subsystem: DomainVerificationService (API 31+)"
else
    echo " subsystem: legacy IntentFilterVerification (API <= 30)"
    echo " NOTE: 'pm get-app-links' (plural) DOES NOT EXIST on this platform."
fi
echo "=============================================================================="
echo ""

# ---- modern path (API 31+) ------------------------------------------------ #

modern_one() {
    local p="$1"
    if [ "$DO_REVERIFY" -eq 1 ]; then
        echo "--- forcing re-verification ---"
        dsh "pm verify-app-links --re-verify '$p'"
        sleep 3
    fi
    echo "--- pm get-app-links $p ---"
    dsh "pm get-app-links '$p'"
    echo ""
    echo "How to read it:"
    echo "  verified        the platform fetched assetlinks.json and it matched."
    echo "                  This domain routes to this app EXCLUSIVELY. Not a finding."
    echo "  none            never verified. If the manifest declares autoVerify,"
    echo "                  THIS IS THE FINDING -- the app believes it has"
    echo "                  exclusivity and does not."
    echo "  legacy_failure  the old verifier failed. Same consequence as 'none'."
    echo "  <number>        an internal failure code (network, parse, mismatch)."
    echo "                  Quote the code in the report."
    echo "  Selection state / user selection"
    echo "                  the USER chose this app. That is a preference, not"
    echo "                  verification, and it can be reset. Say so explicitly."
}

modern_all() {
    echo "--- dumpsys package domain-verification ---"
    dsh "dumpsys package domain-verification"
}

# ---- legacy path (API <= 30) ---------------------------------------------- #

legacy_one() {
    local p="$1"
    echo "--- pm get-app-link $p   (singular: the API<=30 command) ---"
    dsh "pm get-app-link '$p'"
    echo ""
    echo "--- dumpsys package domain-preferred-apps  (entry for $p) ---"
    dsh "dumpsys package domain-preferred-apps" \
        | awk -v pkg="$p" '
            /^  Package: /   { inblock = ($2 == pkg) }
            inblock          { print }
          '
    echo ""
    echo "How to read it:"
    echo "  always      links route here. On this platform that can be a USER or OEM"
    echo "              preference rather than a successful assetlinks.json check --"
    echo "              do not report it as 'verified'."
    echo "  ask         a chooser appears. A competing app CAN win. If the manifest"
    echo "              declares autoVerify, this is the finding."
    echo "  never       never routed here."
    echo "  undefined   no decision recorded; behaves like 'ask'."
    echo ""
    echo "  A bare '*' in the Domains list is a WILDCARD HOST. It can never be"
    echo "  verified (there is no domain to fetch assetlinks.json from), so the"
    echo "  filter behind it is an ordinary deep link accepting arbitrary hosts."
}

legacy_all() {
    echo "--- dumpsys package domain-preferred-apps ---"
    dsh "dumpsys package domain-preferred-apps"
}

# ---- host extraction and assetlinks fetch --------------------------------- #

hosts_for() {
    local p="$1"
    if [ "$SDK" -ge 31 ] 2>/dev/null; then
        dsh "pm get-app-links '$p'" \
            | sed -n 's/^ *\([A-Za-z0-9.*-]*\.[A-Za-z][A-Za-z]*\):.*/\1/p' \
            | sort -u
    else
        dsh "dumpsys package domain-preferred-apps" \
            | awk -v pkg="$p" '
                /^  Package: /  { inblock = ($2 == pkg) }
                inblock && /^  Domains: / { $1=""; print }
              ' \
            | tr ' ' '\n' | sed '/^$/d' | sort -u
    fi
}

fetch_assetlinks() {
    local p="$1"
    command -v curl >/dev/null 2>&1 || { echo "curl not found; skipping --hosts"; return; }

    local apk_digest=""
    if [ -n "$APK" ]; then
        if command -v apksigner >/dev/null 2>&1; then
            apk_digest=$(apksigner verify --print-certs "$APK" 2>/dev/null \
                | grep -i 'SHA-256 digest' | head -1 \
                | sed 's/.*: *//' | tr 'a-f' 'A-F' \
                | sed 's/\(..\)/\1:/g; s/:$//')
            echo "APK signing certificate SHA-256: ${apk_digest:-<could not read>}"
            echo ""
        else
            echo "apksigner not on PATH; cannot compare fingerprints"
            echo ""
        fi
    fi

    for h in $(hosts_for "$p"); do
        case "$h" in
            \*|"") echo "[$h] wildcard host -- unverifiable by design, skipping"; continue ;;
        esac
        local url="https://${h}/.well-known/assetlinks.json"
        echo "--- $url ---"
        body=$(curl -sS --max-time 12 -L -w '\nHTTP %{http_code} (final: %{url_effective})\n' \
               "$url" 2>&1)
        echo "$body" | head -40
        if command -v python3 >/dev/null 2>&1; then
            echo "$body" | sed '/^HTTP /d' | python3 -c '
import json,sys
raw = sys.stdin.read().strip()
try:
    doc = json.loads(raw)
except Exception as exc:
    print("  !! not valid JSON: %s" % exc); raise SystemExit
pkgs = []
for st in doc if isinstance(doc, list) else [doc]:
    tgt = st.get("target", {})
    rel = st.get("relation", [])
    if "delegate_permission/common.handle_all_urls" not in rel:
        print("  !! statement lacks delegate_permission/common.handle_all_urls")
    if tgt.get("namespace") != "android_app":
        continue
    pkgs.append((tgt.get("package_name"),
                 [f.upper() for f in tgt.get("sha256_cert_fingerprints", [])]))
if not pkgs:
    print("  !! no android_app statement -- this file cannot verify any app")
for name, fps in pkgs:
    print("  package_name: %s" % name)
    for f in fps:
        print("  fingerprint : %s" % f)
'
        fi
        if [ -n "$apk_digest" ]; then
            if echo "$body" | tr 'a-f' 'A-F' | grep -qF "$apk_digest"; then
                echo "  MATCH: the hosted file lists this APK's signing certificate."
            else
                echo "  MISMATCH: the hosted file does NOT list this APK's certificate."
                echo "  This is the single most common cause of a failed App Link:"
                echo "  the fingerprint was taken from a DEBUG build, or the app is"
                echo "  re-signed by Play App Signing and the digest changed."
            fi
        fi
        echo ""
    done
}

# ---- run ------------------------------------------------------------------ #

if [ "$DO_ALL" -eq 1 ]; then
    if [ "$SDK" -ge 31 ] 2>/dev/null; then modern_all; else legacy_all; fi
    exit 0
fi

if ! dsh "pm list packages '$PKG'" | grep -q "package:$PKG$"; then
    echo "warning: '$PKG' does not look installed on this device."
    echo ""
fi

if [ "$SDK" -ge 31 ] 2>/dev/null; then modern_one "$PKG"; else legacy_one "$PKG"; fi

echo ""
echo "--- who else claims these hosts right now? ---"
for h in $(hosts_for "$PKG"); do
    case "$h" in \*|"") continue ;; esac
    n=$(dsh "cmd package query-activities -a android.intent.action.VIEW \
        -c android.intent.category.BROWSABLE -d 'https://${h}/'" | head -1)
    printf '  %-45s %s\n' "$h" "$n"
done
echo "  (more than one candidate means the link is CONTESTED unless it is verified)"

if [ "$DO_HOSTS" -eq 1 ]; then
    echo ""
    echo "=============================================================================="
    echo " assetlinks.json as served"
    echo "=============================================================================="
    fetch_assetlinks "$PKG"
fi

echo ""
echo "Reminder: a CUSTOM SCHEME (myapp://) has no verification mechanism at all and"
echo "never appears in any of the tables above. It is unowned by design. If the app"
echo "uses one for an OAuth redirect or a session hand-off, see 45-OAuth lab-03."
