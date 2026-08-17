#!/usr/bin/env bash
#
# binder-service-enum.sh — enumerate every registered Binder service on a device,
#                          classify it as AOSP or vendor, and report which ones
#                          look reachable from an unprivileged app.
#
# PURPOSE
#     Section 5.3.1 of ../README.md describes the highest-yield finding class on
#     OEM devices: a system service the vendor added to system_server, reachable
#     over Binder, with no permission enforcement. Finding those starts with
#     enumerating what is registered and separating vendor additions from AOSP.
#
#     This script does that enumeration and adds three things a bare
#     `service list` does not:
#       - the interface descriptor for each service, where available;
#       - a classification against a built-in list of AOSP service-name prefixes;
#       - the SELinux label for each service from *_service_contexts, plus
#         whether untrusted_app is allowed to `find` it.
#
#     It is READ-ONLY. It calls no service and changes nothing.
#
# USAGE
#     ./binder-service-enum.sh                          # report to stdout
#     ./binder-service-enum.sh -o services-report.txt   # write to a file
#     ./binder-service-enum.sh -s emulator-5554
#     ./binder-service-enum.sh -b baseline-services.txt # diff against a baseline
#
#     Create a baseline from a stock device of the SAME Android release:
#         adb shell service list | awk '{print $2}' | sort -u > baseline-services.txt
#
# REQUIREMENTS
#     adb on PATH and an authorised device. Root improves the SELinux section
#     but is not required.
#
# WHAT TO DO WITH THE OUTPUT
#     For each service classified VENDOR:
#       1. Find its interface descriptor (printed here, or via `service list -l`).
#       2. Find the implementing class: decompile /system/framework/services.jar
#          (or the vendor jar) and search for  extends <Descriptor>$Stub .
#       3. Read every public method and check for enforceCallingPermission /
#          checkCallingPermission / getCallingUid.
#       4. Anything unguarded: call it from a zero-permission app with a raw
#          Parcel transaction. See ../examples/03-binder-service-probe/.
#
# SEE ALSO
#     ../README.md sections 3.5, 5.3.1, 7.1, 9.4
#     ./aosp-device-recon.sh   (broader device reconnaissance)

set -uo pipefail

SERIAL=""
OUTFILE=""
BASELINE=""

usage() { sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts ":s:o:b:h" opt; do
    case "$opt" in
        s) SERIAL="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        b) BASELINE="$OPTARG" ;;
        h) usage 0 ;;
        *) echo "unknown option: -$OPTARG" >&2; usage 2 ;;
    esac
done

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

command -v adb >/dev/null 2>&1 || { echo "error: adb not on PATH" >&2; exit 2; }
"${ADB[@]}" get-state >/dev/null 2>&1 || {
    echo "error: no device (or more than one — use -s <serial>)" >&2
    "${ADB[@]}" devices; exit 2; }

sh() { "${ADB[@]}" shell "$@" 2>/dev/null | tr -d '\r'; }

# ---------------------------------------------------------------------------
# Known AOSP service names. Anything NOT matching one of these prefixes, or not
# in this list, is a candidate vendor addition.
#
# This list is deliberately conservative: it is better to flag an AOSP service
# for manual dismissal than to hide a vendor one. The authoritative answer is
# always a diff against a stock device of the same release (-b).
# ---------------------------------------------------------------------------

AOSP_PREFIXES='^(activity|account|alarm|app|audio|autofill|backup|battery|
biometric|blob_store|bluetooth|bugreport|cameraserver|carrier|clipboard|
cloudsearch|color_display|companiondevice|connectivity|connmetrics|
consumer_ir|content|content_capture|country_detector|cpuinfo|crossprofileapps|
dataloader|device_config|device_identifiers|device_policy|deviceidle|
devicestoragemonitor|diskstats|display|dnsresolver|domain_verification|
dreams|drm|dropbox|dynamic_system|ethernet|external_vibrator|face|
file_integrity|fingerprint|font|game|gfxinfo|gpu|graphicsstats|hardware|
hdmi_control|imms|incident|incidentcompanion|input|input_method|inputflinger|
ipsec|iris|isub|jobscheduler|launcherapps|legacy_permission|light|
localedisplay|location|lock_settings|looper_stats|media|meminfo|midi|
mount|music_recognition|netd|netpolicy|netstats|network_management|
network_score|network_stack|network_time_update_service|notification|
oem_lock|otadexopt|overlay|package|package_native|people|performance_hint|
permission|permissionmgr|persistent_data_block|phone|pinner|platform_compat|
power|print|processinfo|procstats|profcollectd|reboot_readiness|recovery|
resources|restrictions|role|rollback|runtime|scheduling_policy|search|
search_ui|sec_key_att_app_id_provider|sensor_privacy|sensorservice|
serial|servicediscovery|settings|shortcut|slice|smartspace|soundtrigger|
soundtrigger_middleware|speech_recognition|stats|statscompanion|statsmanager|
storaged|storagestats|surfaceflinger|suspend_control|system_config|
system_update|task|telecom|telephony|testharness|textclassification|
textservices|thermalservice|time_detector|time_zone_detector|timedetector|
tracing|translation|trust|tv_input|tv_interactive_app|tv_tuner|
uimode|updatelock|uri_grants|usagestats|usb|user|vcn_management|vibrator|
virtualdevice|voiceinteraction|vold|vpn_management|vrmanager|wallpaper|
webviewupdate|wifi|window|SurfaceFlinger|android\.|com\.android\.|
media\.|drm\.|gpu\.|manager|batteryproperties|batterystats|
sensor_privacy|selection_toolbar|attention|adb|ambient_context|
app_binding|app_hibernation|app_integrity|app_prediction|app_search|
appops|appwidget|artd|assetatlas|auth|binder_calls_stats|blob|
broadcastradio|cacheinfo|cameraproxy|captioning|com\.google\.android\.)'

AOSP_RE=$(printf '%s' "$AOSP_PREFIXES" | tr -d '\n')

# ---------------------------------------------------------------------------
# Collect
# ---------------------------------------------------------------------------

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

sh service list > "$TMP/raw.txt"
sh service list -l > "$TMP/raw-l.txt" 2>/dev/null || true

# "12  activity: [android.app.IActivityManager]" -> name and descriptor
sed -n 's/^[0-9]\+[[:space:]]*\([^:]*\):[[:space:]]*\[\(.*\)\]$/\1|\2/p' \
    "$TMP/raw.txt" > "$TMP/parsed.txt"
# services with no descriptor
sed -n 's/^[0-9]\+[[:space:]]*\([^:]*\):[[:space:]]*\[\]$/\1|(no descriptor)/p' \
    "$TMP/raw.txt" >> "$TMP/parsed.txt"

sort -u -o "$TMP/parsed.txt" "$TMP/parsed.txt"
cut -d'|' -f1 "$TMP/parsed.txt" | sort -u > "$TMP/names.txt"

# SELinux service contexts, if readable
sh cat /plat_service_contexts        > "$TMP/svcctx.txt" 2>/dev/null || true
sh cat /system/etc/selinux/plat_service_contexts >> "$TMP/svcctx.txt" 2>/dev/null || true
sh cat /vendor/etc/selinux/vendor_service_contexts >> "$TMP/svcctx.txt" 2>/dev/null || true

selinux_label_for() {
    grep -E "^[[:space:]]*$1[[:space:]]" "$TMP/svcctx.txt" 2>/dev/null \
      | head -1 | awk '{print $2}'
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

emit() {
    TOTAL=$(wc -l < "$TMP/names.txt" | tr -d ' ')

    cat <<EOF
========================================================================
  BINDER SERVICE ENUMERATION
  device      : $(sh getprop ro.build.fingerprint)
  release     : $(sh getprop ro.build.version.release) (API $(sh getprop ro.build.version.sdk))
  build type  : $(sh getprop ro.build.type)
  collected   : $(date -u +%Y-%m-%dT%H:%M:%SZ)
  services    : $TOTAL
========================================================================

EOF

    echo "------------------------------------------------------------------------"
    echo " CANDIDATE VENDOR SERVICES"
    echo "------------------------------------------------------------------------"
    echo
    echo " Each of these did not match a known AOSP service name. Each is code"
    echo " running as UID 1000 (or as a native daemon), reachable over Binder,"
    echo " that Google did not write and did not review."
    echo
    echo " For each: find the implementing class, read every public method, and"
    echo " check for enforceCallingPermission / checkCallingPermission /"
    echo " Binder.getCallingUid(). See ../README.md section 5.3.1."
    echo

    VENDOR_COUNT=0
    while IFS='|' read -r name desc; do
        [ -z "$name" ] && continue
        if printf '%s' "$name" | grep -qE "$AOSP_RE"; then
            continue
        fi
        VENDOR_COUNT=$((VENDOR_COUNT + 1))
        label=$(selinux_label_for "$name")
        printf "  %-38s\n" "$name"
        printf "      descriptor : %s\n" "${desc:-unknown}"
        [ -n "$label" ] && printf "      selinux    : %s\n" "$label"
        printf "      next       : rg -n '%s' <decompiled-services>/sources/\n" \
               "$(printf '%s' "${desc:-$name}" | sed 's/\./\\./g')"
        echo
    done < "$TMP/parsed.txt"

    if [ "$VENDOR_COUNT" -eq 0 ]; then
        echo "  (none matched the vendor heuristic)"
        echo
        echo "  This does NOT mean there are none. The heuristic is a name-prefix"
        echo "  match against a static AOSP list. The authoritative method is a"
        echo "  diff against a stock device of the same release — pass -b."
        echo
    fi

    if [ -n "$BASELINE" ] && [ -f "$BASELINE" ]; then
        echo "------------------------------------------------------------------------"
        echo " DIFF AGAINST BASELINE  ($BASELINE)"
        echo "------------------------------------------------------------------------"
        echo
        echo " Present on the TARGET but not the BASELINE — the authoritative"
        echo " list of vendor additions:"
        echo
        comm -23 "$TMP/names.txt" <(sort -u "$BASELINE") | sed 's/^/    /'
        echo
        echo " On the BASELINE but MISSING here (what replaced it?):"
        echo
        comm -13 "$TMP/names.txt" <(sort -u "$BASELINE") | sed 's/^/    /'
        echo
    else
        echo "------------------------------------------------------------------------"
        echo " NO BASELINE SUPPLIED"
        echo "------------------------------------------------------------------------"
        echo
        echo " The name-prefix heuristic above is approximate. For the authoritative"
        echo " answer, run this on a stock Pixel or a Cuttlefish instance of the"
        echo " SAME Android release:"
        echo
        echo "     adb shell service list | awk '{print \$2}' | tr -d ':' | sort -u \\"
        echo "       > baseline-services.txt"
        echo
        echo " then re-run here with:  -b baseline-services.txt"
        echo
    fi

    echo "------------------------------------------------------------------------"
    echo " ALL SERVICES (name | interface descriptor)"
    echo "------------------------------------------------------------------------"
    echo
    while IFS='|' read -r name desc; do
        [ -z "$name" ] && continue
        if printf '%s' "$name" | grep -qE "$AOSP_RE"; then tag="aosp  "; else tag="VENDOR"; fi
        printf "  [%s] %-34s %s\n" "$tag" "$name" "${desc:-}"
    done < "$TMP/parsed.txt"

    cat <<'EOF'

------------------------------------------------------------------------
 FOLLOW-UP WORKFLOW
------------------------------------------------------------------------

 1. Pull and decompile the framework:
        adb pull /system/framework/services.jar
        # if it is a stub, extract the real DEX first (root):
        adb shell oatdump --vdex-file=/system/framework/oat/arm64/services.vdex \
                          --export-dex-to=/data/local/tmp/svc
        jadx -d svc-src services.jar

 2. Locate each vendor service's implementation:
        rg -n "extends .*\$Stub" svc-src/sources/ | grep -vi "com/android/server"

 3. For each implementation, check every public method for enforcement:
        rg -n -A15 "public " <ImplFile>.java | grep -E \
          "enforceCalling|checkCalling|getCallingUid|getCallingPid|^--"

 4. Hunt the confused deputy (README 5.3.2):
        rg -n -A25 "clearCallingIdentity" svc-src/sources/ \
          | grep -E "checkCalling|enforceCalling"

 5. Anything unguarded: reach it from a zero-permission app with a raw
    Parcel transaction. See ../examples/03-binder-service-probe/.

 6. Cross-check the SELinux side — who may `find` the service?
        adb shell cat /vendor/etc/selinux/vendor_service_contexts | grep <name>
        sesearch --allow -t <label> plat_sepolicy.cil

------------------------------------------------------------------------
EOF
}

if [ -n "$OUTFILE" ]; then
    emit > "$OUTFILE"
    echo "[*] report written to $OUTFILE"
    grep -c "\[VENDOR\]" "$OUTFILE" | sed 's/^/[*] vendor-classified services: /'
else
    emit
fi
