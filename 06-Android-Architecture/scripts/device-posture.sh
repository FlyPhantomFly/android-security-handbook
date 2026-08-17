#!/usr/bin/env bash
#
# device-posture.sh — assess an Android device's boot-chain and trust posture.
#
# WHAT IT DOES
#   Runs the security-relevant property checks from ../README.md sections 3.10.4
#   and 5.3, and prints a VERDICT per row rather than raw getprop output — so the
#   result is report-ready instead of something you still have to interpret.
#
#   It also separates two things people constantly conflate:
#     - findings about the DEVICE AS SHIPPED  (real findings)
#     - consequences of YOUR OWN rooting      (methodology, not findings)
#
#   Pass --test-device to mark the second category explicitly.
#
# HOW TO RUN
#   ./device-posture.sh
#   ./device-posture.sh --test-device        # you rooted it yourself; suppress those findings
#   ./device-posture.sh --json
#   ./device-posture.sh -s <serial>          # specific device
#
# REQUIREMENTS
#   adb on PATH, one device connected. No root required.
#
# EXIT CODES
#   0 clean · 1 usage/no device · 2 at least one HIGH or CRITICAL observation

set -uo pipefail

TEST_DEVICE=0
JSON=0
ADB_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --test-device) TEST_DEVICE=1; shift ;;
        --json)        JSON=1; shift ;;
        -s)            ADB_ARGS+=(-s "$2"); shift 2 ;;
        -h|--help)     sed -n '3,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

adbsh() { adb "${ADB_ARGS[@]}" shell "$@" 2>/dev/null | tr -d '\r'; }

if [[ -z "$(adb "${ADB_ARGS[@]}" get-state 2>/dev/null)" ]]; then
    echo "error: no device. Check 'adb devices'." >&2
    exit 1
fi

WORST=0
declare -a ROWS

# note <severity> <property> <value> <verdict>
note() {
    local sev="$1" prop="$2" val="$3" verdict="$4"
    ROWS+=("$sev|$prop|$val|$verdict")
    case "$sev" in
        CRITICAL) [[ $WORST -lt 4 ]] && WORST=4 ;;
        HIGH)     [[ $WORST -lt 3 ]] && WORST=3 ;;
        MEDIUM)   [[ $WORST -lt 2 ]] && WORST=2 ;;
        LOW)      [[ $WORST -lt 1 ]] && WORST=1 ;;
    esac
}

P() { adbsh "getprop $1"; }

# ------------------------------------------------------------- identity ----

FINGERPRINT="$(P ro.build.fingerprint)"
RELEASE="$(P ro.build.version.release)"
SDK="$(P ro.build.version.sdk)"
PATCHLEVEL="$(P ro.build.version.security_patch)"
MODEL="$(P ro.product.model)"
MANUF="$(P ro.product.manufacturer)"
ABILIST="$(P ro.product.cpu.abilist)"

# --------------------------------------------------------- build variant ---

BUILD_TYPE="$(P ro.build.type)"
BUILD_TAGS="$(P ro.build.tags)"
DEBUGGABLE="$(P ro.debuggable)"
SECURE="$(P ro.secure)"
ADB_SECURE="$(P ro.adb.secure)"

if [[ "$BUILD_TAGS" == *"test-keys"* ]]; then
    note CRITICAL "ro.build.tags" "$BUILD_TAGS" \
"Signed with the PUBLIC AOSP test keys. Anyone can sign an APK that receives every
   signature-level platform permission and can use sharedUserId=android.uid.system.
   Complete compromise of the permission model."
else
    note OK "ro.build.tags" "$BUILD_TAGS" "Release keys."
fi

if [[ "$DEBUGGABLE" == "1" ]]; then
    note CRITICAL "ro.debuggable" "1" \
"Every app on this device is debuggable. run-as works for ANY package, JDWP is
   attachable to any process, and adb root is available. On a production device
   this is a full compromise of the app sandbox from a USB cable."
else
    note OK "ro.debuggable" "$DEBUGGABLE" "Production value."
fi

if [[ "$SECURE" == "0" ]]; then
    note CRITICAL "ro.secure" "0" "adbd starts as root."
else
    note OK "ro.secure" "$SECURE" "adbd runs as shell."
fi

if [[ "$ADB_SECURE" == "0" ]]; then
    note HIGH "ro.adb.secure" "0" "Any USB host gets a shell with no authorisation prompt."
else
    note OK "ro.adb.secure" "$ADB_SECURE" "ADB requires host key authorisation."
fi

case "$BUILD_TYPE" in
    user)  note OK   "ro.build.type" "$BUILD_TYPE" "Production build variant." ;;
    *)     note HIGH "ro.build.type" "$BUILD_TYPE" \
"Non-production build variant shipping. Expect relaxed defaults throughout." ;;
esac

# ------------------------------------------------------------ boot chain ---

VBSTATE="$(P ro.boot.verifiedbootstate)"
LOCKED="$(P ro.boot.flash.locked)"
VERITY="$(P ro.boot.veritymode)"
DEVSTATE="$(P ro.boot.vbmeta.device_state)"

OWN_DOING=""
[[ $TEST_DEVICE -eq 1 ]] && OWN_DOING=" [YOUR OWN TEST DEVICE — methodology, not a finding]"

case "$VBSTATE" in
    green)  note OK "ro.boot.verifiedbootstate" "green" "Locked, verified with the OEM key." ;;
    yellow) note MEDIUM "ro.boot.verifiedbootstate" "yellow" \
"Locked but verified with a USER-supplied key. Custom OS with a self-signed chain.$OWN_DOING" ;;
    orange) if [[ $TEST_DEVICE -eq 1 ]]; then
                note OK "ro.boot.verifiedbootstate" "orange" \
"Bootloader unlocked — expected on your own test device. Record in Test Environment,
   do NOT report as a finding."
            else
                note HIGH "ro.boot.verifiedbootstate" "orange" \
"Bootloader UNLOCKED. No boot integrity guarantee; anyone with physical access can
   flash a modified image."
            fi ;;
    red)    note CRITICAL "ro.boot.verifiedbootstate" "red" "Verification FAILED." ;;
    "")     note LOW "ro.boot.verifiedbootstate" "<absent>" \
"Property not set. Common on emulators and some vendors — verify by other means." ;;
    *)      note MEDIUM "ro.boot.verifiedbootstate" "$VBSTATE" "Unrecognised value." ;;
esac

if [[ "$LOCKED" == "0" ]]; then
    if [[ $TEST_DEVICE -eq 1 ]]; then
        note OK "ro.boot.flash.locked" "0" "Unlocked test device — methodology."
    else
        note HIGH "ro.boot.flash.locked" "0" "Bootloader unlocked."
    fi
elif [[ -n "$LOCKED" ]]; then
    note OK "ro.boot.flash.locked" "$LOCKED" "Bootloader locked."
fi

case "$VERITY" in
    enforcing) note OK "ro.boot.veritymode" "enforcing" "dm-verity enforcing." ;;
    "")        note LOW "ro.boot.veritymode" "<absent>" "Not reported; check by other means." ;;
    *)         note HIGH "ro.boot.veritymode" "$VERITY" \
"dm-verity NOT enforcing. System-partition modification will not be blocked." ;;
esac

# --------------------------------------------------------------- SELinux ---

ENFORCE="$(adbsh getenforce)"
if [[ "$ENFORCE" == "Enforcing" ]]; then
    note OK "SELinux" "Enforcing" "MAC active."
else
    note HIGH "SELinux" "$ENFORCE" \
"SELinux not enforcing. Removes the strongest post-exploitation constraint on the
   platform. See ../../22-SELinux/."
fi

# -------------------------------------------------------------- crypto ----

CRYPTO_STATE="$(P ro.crypto.state)"
CRYPTO_TYPE="$(P ro.crypto.type)"
if [[ "$CRYPTO_STATE" == "encrypted" ]]; then
    note OK "ro.crypto.state" "encrypted ($CRYPTO_TYPE)" "Userdata encrypted."
elif [[ -n "$CRYPTO_STATE" ]]; then
    note HIGH "ro.crypto.state" "$CRYPTO_STATE" "Userdata NOT encrypted."
fi

# --------------------------------------------------------- patch levels ---

if [[ -n "$PATCHLEVEL" ]]; then
    TODAY=$(date +%Y-%m)
    PATCH_YM="${PATCHLEVEL:0:7}"
    MONTHS=$(( ( $(date -d "${TODAY}-01" +%s 2>/dev/null || date +%s) - \
                 $(date -d "${PATCH_YM}-01" +%s 2>/dev/null || date +%s) ) / 2592000 ))
    if [[ "$MONTHS" -gt 6 ]]; then
        note HIGH "ro.build.version.security_patch" "$PATCHLEVEL" \
"Roughly $MONTHS months behind. Known, public, unpatched vulnerabilities apply."
    elif [[ "$MONTHS" -gt 3 ]]; then
        note MEDIUM "ro.build.version.security_patch" "$PATCHLEVEL" \
"Roughly $MONTHS months behind current."
    else
        note OK "ro.build.version.security_patch" "$PATCHLEVEL" "Reasonably current."
    fi
fi

# Mainline / Play system update level — the SECOND patch level people forget.
MODULE_VER="$(adbsh "cmd package dump com.google.android.modulemetadata 2>/dev/null | grep -m1 versionName")"
if [[ -n "$MODULE_VER" ]]; then
    note INFO "Play system update" "$(echo "$MODULE_VER" | tr -s ' ')" \
"Governs the Mainline components (media, DNS, TLS, Bluetooth, Wi-Fi). Record BOTH
   patch levels — the platform one alone is not a complete statement."
else
    note INFO "Play system update" "<not reported>" \
"No modulemetadata package. Non-GMS build, or Mainline not present."
fi

# ------------------------------------------------------------- USB / adb ---

USBCFG="$(P persist.sys.usb.config)"
if [[ "$USBCFG" == *adb* ]]; then
    note INFO "persist.sys.usb.config" "$USBCFG" \
"ADB is in the persistent USB config. Expected on a dev device; a finding on a
   kiosk, POS or embedded deployment."
fi

ADB_ENABLED="$(adbsh 'settings get global adb_enabled')"
note INFO "adb_enabled" "$ADB_ENABLED" "Developer options / USB debugging state."

# ---------------------------------------------------------------- root ----

if [[ "$(adbsh 'command -v su >/dev/null && echo yes || echo no')" == "yes" ]]; then
    if [[ $TEST_DEVICE -eq 1 ]]; then
        note OK "su binary" "present" "Your own root — methodology."
    else
        note HIGH "su binary" "present" "Device is rooted."
    fi
fi

MAGISK="$(adbsh 'ls /data/adb/magisk 2>/dev/null | head -1')"
[[ -n "$MAGISK" ]] && note INFO "Magisk" "present" "Systemless root installed."

# ---------------------------------------------------------------- output ---

if [[ $JSON -eq 1 ]]; then
    echo "{"
    echo "  \"fingerprint\": \"$FINGERPRINT\","
    echo "  \"release\": \"$RELEASE\", \"sdk\": \"$SDK\","
    echo "  \"security_patch\": \"$PATCHLEVEL\","
    echo "  \"observations\": ["
    for i in "${!ROWS[@]}"; do
        IFS='|' read -r sev prop val verdict <<< "${ROWS[$i]}"
        printf '    {"severity":"%s","property":"%s","value":"%s"}%s\n' \
            "$sev" "$prop" "$val" "$([[ $i -lt $((${#ROWS[@]}-1)) ]] && echo ,)"
    done
    echo "  ]"
    echo "}"
    exit $([[ $WORST -ge 3 ]] && echo 2 || echo 0)
fi

echo
echo "=============================================================="
echo " DEVICE TRUST POSTURE"
echo "=============================================================="
printf '  %-22s %s\n' "Manufacturer"   "$MANUF"
printf '  %-22s %s\n' "Model"          "$MODEL"
printf '  %-22s %s\n' "Android"        "$RELEASE (API $SDK)"
printf '  %-22s %s\n' "ABIs"           "$ABILIST"
printf '  %-22s %s\n' "Fingerprint"    "$FINGERPRINT"
[[ $TEST_DEVICE -eq 1 ]] && echo "  MODE: --test-device (your own rooting is not reported as findings)"

echo
echo "--------------------------------------------------------------"
printf ' %-9s %-32s %s\n' "SEVERITY" "PROPERTY" "VALUE"
echo "--------------------------------------------------------------"
for order in CRITICAL HIGH MEDIUM LOW INFO OK; do
    for row in "${ROWS[@]}"; do
        IFS='|' read -r sev prop val verdict <<< "$row"
        [[ "$sev" != "$order" ]] && continue
        printf ' %-9s %-32s %s\n' "$sev" "$prop" "$val"
        if [[ "$sev" != "OK" ]]; then
            echo "$verdict" | sed 's/^/           /'
        fi
    done
done

echo
echo "--------------------------------------------------------------"
case $WORST in
    4) echo " VERDICT: CRITICAL observations present." ;;
    3) echo " VERDICT: HIGH observations present." ;;
    2) echo " VERDICT: MEDIUM observations present." ;;
    *) echo " VERDICT: no significant boot-chain observations." ;;
esac
cat <<'EOF'

 REPORTING REMINDER
   Findings about the device AS SHIPPED are real findings.
   Consequences of YOUR OWN rooting belong in the Test Environment
   section, not in the findings list. Confusing the two damages a
   report's credibility. See ../README.md section 5.3.
EOF
echo

exit $([[ $WORST -ge 3 ]] && echo 2 || echo 0)
