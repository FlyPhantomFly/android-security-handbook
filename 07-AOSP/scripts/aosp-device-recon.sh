#!/usr/bin/env bash
#
# aosp-device-recon.sh — collect the AOSP-relevant identity and attack surface of
#                        an Android device into one evidence file.
#
# PURPOSE
#     Section 7.1 of ../README.md lists about thirty commands you should run at
#     the start of every device engagement. People skip them under time
#     pressure, and then cannot answer basic questions later: which AOSP release
#     should I be reading, how stale is the vendor partition, what did the OEM
#     add to system_server, which apps share the platform signing key.
#
#     This script runs all of them, timestamps the output, and writes a single
#     directory you can attach to a report. It is read-only: it changes nothing
#     on the device.
#
# USAGE
#     ./aosp-device-recon.sh                     # default output dir
#     ./aosp-device-recon.sh -o ./evidence/dev1  # explicit output dir
#     ./aosp-device-recon.sh -s emulator-5554    # a specific adb device
#     ./aosp-device-recon.sh -b ./baseline/      # diff services against a baseline
#
#     To create a baseline, run the script against a stock Pixel or a Cuttlefish
#     instance of the SAME Android release, then pass that output dir with -b.
#
# REQUIREMENTS
#     adb on PATH, a connected and authorised device.
#     Root is NOT required. Sections that need root are attempted and skipped
#     cleanly if unavailable.
#
# OUTPUT
#     <outdir>/
#       00-summary.txt          the one-page answer
#       01-properties.txt       every ro.* property that matters
#       02-services.txt         service list (+ -l descriptors if available)
#       03-dumpsys-list.txt     every dumpable service
#       04-packages-system.txt  preinstalled packages
#       05-apex-modules.txt     Mainline module versions
#       06-permissions.txt      dangerous permissions and vendor-defined ones
#       07-selinux.txt          enforcement state and recent denials
#       08-service-diff.txt     (with -b) vendor-added services
#       09-root-only/           artefacts that needed root
#
# SEE ALSO
#     ../README.md sections 5.1, 7.1, 8.4
#     ../cheatsheet.md "Device reconnaissance"

set -uo pipefail

OUTDIR="aosp-recon-$(date +%Y%m%d-%H%M%S)"
SERIAL=""
BASELINE=""

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while getopts ":o:s:b:h" opt; do
    case "$opt" in
        o) OUTDIR="$OPTARG" ;;
        s) SERIAL="$OPTARG" ;;
        b) BASELINE="$OPTARG" ;;
        h) usage 0 ;;
        *) echo "unknown option: -$OPTARG" >&2; usage 2 ;;
    esac
done

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

command -v adb >/dev/null 2>&1 || { echo "error: adb not on PATH" >&2; exit 2; }

if ! "${ADB[@]}" get-state >/dev/null 2>&1; then
    echo "error: no device (or more than one — use -s <serial>)" >&2
    "${ADB[@]}" devices
    exit 2
fi

mkdir -p "$OUTDIR/09-root-only"
echo "[*] writing to $OUTDIR"

sh() { "${ADB[@]}" shell "$@" 2>/dev/null; }

have_root() {
    [ "$(sh id -u 2>/dev/null | tr -d '\r')" = "0" ]
}

# ---------------------------------------------------------------------------
# 01 — identity
# ---------------------------------------------------------------------------

echo "[*] 01 properties"
{
    echo "=== Collected $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
    echo
    echo "--- identity ---"
    for p in \
        ro.build.fingerprint ro.build.id ro.build.display.id \
        ro.build.version.release ro.build.version.sdk ro.build.version.codename \
        ro.build.version.security_patch ro.vendor.build.security_patch \
        ro.build.type ro.build.tags ro.build.date \
        ro.product.manufacturer ro.product.brand ro.product.model ro.product.device \
        ro.product.name ro.board.platform ro.hardware
    do
        printf "%-42s = %s\n" "$p" "$(sh getprop "$p" | tr -d '\r')"
    done

    echo
    echo "--- security posture ---"
    for p in \
        ro.debuggable ro.secure ro.adb.secure \
        ro.boot.verifiedbootstate ro.boot.veritymode ro.boot.flash.locked \
        ro.crypto.state ro.crypto.type \
        ro.control_privapp_permissions \
        ro.product.cpu.abilist ro.zygote
    do
        printf "%-42s = %s\n" "$p" "$(sh getprop "$p" | tr -d '\r')"
    done

    echo
    echo "--- kernel ---"
    sh uname -a
    sh cat /proc/version

    echo
    echo "--- selinux ---"
    printf "getenforce = %s\n" "$(sh getenforce | tr -d '\r')"

    echo
    echo "--- hidden api policy (record this; it changes app behaviour) ---"
    printf "hidden_api_policy = %s\n" "$(sh settings get global hidden_api_policy | tr -d '\r')"

    echo
    echo "--- full property dump ---"
    sh getprop
} > "$OUTDIR/01-properties.txt"

# ---------------------------------------------------------------------------
# 02 — registered Binder services (the attack surface)
# ---------------------------------------------------------------------------

echo "[*] 02 services"
{
    echo "=== service list ==="
    sh service list
    echo
    echo "=== service list -l (interface descriptors, if supported) ==="
    sh service list -l
} > "$OUTDIR/02-services.txt"

# A normalised, sortable list for diffing.
sh service list \
  | sed -n 's/^[0-9]\+\s*\([A-Za-z0-9_.\-]*\).*$/\1/p' \
  | grep -v '^$' | sort -u > "$OUTDIR/02-services-names.txt"

echo "[*] 03 dumpsys -l"
sh dumpsys -l > "$OUTDIR/03-dumpsys-list.txt"

# ---------------------------------------------------------------------------
# 04 — preinstalled packages
# ---------------------------------------------------------------------------

echo "[*] 04 packages"
{
    echo "=== system packages ==="
    sh pm list packages -s -f
    echo
    echo "=== third-party packages ==="
    sh pm list packages -3 -f
    echo
    echo "=== disabled packages ==="
    sh pm list packages -d
} > "$OUTDIR/04-packages-system.txt"

echo "[*] 05 apex / mainline modules"
{
    echo "=== apex modules (these update via Play, independently of the OS) ==="
    sh pm list packages --apex-only
    echo
    echo "=== module metadata ==="
    sh dumpsys package com.google.android.modulemetadata | head -30
    echo
    echo "=== apex mounts ==="
    sh ls -l /apex/
} > "$OUTDIR/05-apex-modules.txt"

# ---------------------------------------------------------------------------
# 06 — permissions
# ---------------------------------------------------------------------------

echo "[*] 06 permissions"
{
    echo "=== dangerous permissions, by group ==="
    sh pm list permissions -d -g
    echo
    echo "=== NON-AOSP permission definitions (vendor / preinstalled apps) ==="
    echo "    Anything here with protectionLevel=normal that gates a"
    echo "    privileged capability is a finding. See README 5.3.3."
    sh pm list permissions -f \
      | grep -iE "^\s*permission:(com\.|vendor\.|oem\.)" \
      | grep -viE "com\.android\.|com\.google\.android\.gms" || true
    echo
    echo "=== full permission dump with protection levels ==="
    sh pm list permissions -f
} > "$OUTDIR/06-permissions.txt"

# ---------------------------------------------------------------------------
# 07 — SELinux
# ---------------------------------------------------------------------------

echo "[*] 07 selinux"
{
    printf "getenforce = %s\n\n" "$(sh getenforce | tr -d '\r')"
    echo "=== recent AVC denials from logcat ==="
    sh logcat -d -b all | grep -i "avc:" | tail -80
    echo
    echo "=== policy files present ==="
    sh ls -l /system/etc/selinux/ /vendor/etc/selinux/ 2>/dev/null
} > "$OUTDIR/07-selinux.txt"

# ---------------------------------------------------------------------------
# 08 — service diff against a baseline
# ---------------------------------------------------------------------------

if [ -n "$BASELINE" ] && [ -f "$BASELINE/02-services-names.txt" ]; then
    echo "[*] 08 service diff against baseline"
    {
        echo "=== Services present on the TARGET but not on the BASELINE ==="
        echo
        echo "Every name below is code the vendor added to the device. It runs"
        echo "as UID 1000 in system_server (or as a native daemon), is reachable"
        echo "over Binder, and was never reviewed by Google. This is the"
        echo "highest-value starting point on an OEM engagement."
        echo "See ../README.md section 5.3.1."
        echo
        comm -23 "$OUTDIR/02-services-names.txt" "$BASELINE/02-services-names.txt"
        echo
        echo "=== Services on the BASELINE but MISSING from the target ==="
        echo "(A removed AOSP service is also interesting: what replaced it?)"
        echo
        comm -13 "$OUTDIR/02-services-names.txt" "$BASELINE/02-services-names.txt"
    } > "$OUTDIR/08-service-diff.txt"
else
    if [ -n "$BASELINE" ]; then
        echo "[!] baseline $BASELINE/02-services-names.txt not found — skipping diff"
    else
        cat > "$OUTDIR/08-service-diff.txt" <<'EOF'
No baseline supplied.

To enumerate the vendor's added attack surface, run this script against a stock
device of the SAME Android release (a Pixel, or a Cuttlefish instance you built),
then re-run against the target with:

    ./aosp-device-recon.sh -b <baseline-output-dir>

The diff of `service list` is the fastest way to find OEM-added system services.
See ../README.md section 5.3.1 and 7.1.
EOF
    fi
fi

# ---------------------------------------------------------------------------
# 09 — root-only artefacts
# ---------------------------------------------------------------------------

if have_root; then
    echo "[*] 09 root-only artefacts"
    sh cat /data/system/packages.xml   > "$OUTDIR/09-root-only/packages.xml"    2>/dev/null
    sh cat /data/system/appops.xml     > "$OUTDIR/09-root-only/appops.xml"      2>/dev/null
    sh ls -la /data/tombstones/        > "$OUTDIR/09-root-only/tombstones.txt"  2>/dev/null
    sh ls -la /data/system/dropbox/    > "$OUTDIR/09-root-only/dropbox.txt"     2>/dev/null
    sh cat /vendor/etc/selinux/vendor_service_contexts \
                                       > "$OUTDIR/09-root-only/vendor_service_contexts.txt" 2>/dev/null
    sh ls -la /system/priv-app/        > "$OUTDIR/09-root-only/priv-app.txt"    2>/dev/null
    sh cat /system/etc/permissions/privapp-permissions-platform.xml \
                                       > "$OUTDIR/09-root-only/privapp-permissions.txt" 2>/dev/null
else
    echo "[!] not root — skipping /data/system artefacts"
    echo "not root; skipped" > "$OUTDIR/09-root-only/SKIPPED.txt"
fi

# ---------------------------------------------------------------------------
# 00 — the one-page summary
# ---------------------------------------------------------------------------

echo "[*] 00 summary"
{
    FP=$(sh getprop ro.build.fingerprint | tr -d '\r')
    REL=$(sh getprop ro.build.version.release | tr -d '\r')
    SDK=$(sh getprop ro.build.version.sdk | tr -d '\r')
    BID=$(sh getprop ro.build.id | tr -d '\r')
    SPL=$(sh getprop ro.build.version.security_patch | tr -d '\r')
    VSPL=$(sh getprop ro.vendor.build.security_patch | tr -d '\r')
    TYPE=$(sh getprop ro.build.type | tr -d '\r')
    DBG=$(sh getprop ro.debuggable | tr -d '\r')
    SEC=$(sh getprop ro.secure | tr -d '\r')
    ENF=$(sh getenforce | tr -d '\r')
    VBS=$(sh getprop ro.boot.verifiedbootstate | tr -d '\r')
    LOCK=$(sh getprop ro.boot.flash.locked | tr -d '\r')
    HAP=$(sh settings get global hidden_api_policy | tr -d '\r')
    NSVC=$(wc -l < "$OUTDIR/02-services-names.txt" | tr -d ' ')

    cat <<EOF
========================================================================
  AOSP DEVICE RECONNAISSANCE
  collected $(date -u +%Y-%m-%dT%H:%M:%SZ)
========================================================================

IDENTITY
  fingerprint          : $FP
  android release      : $REL   (API $SDK)
  build id             : $BID
  build type           : $TYPE
  registered services  : $NSVC

  >> Map the build id to an AOSP tag at
  >> https://source.android.com/docs/setup/reference/build-numbers
  >> and SET THAT BRANCH in cs.android.com before reading any source.

PATCH LEVEL
  system  security_patch : $SPL
  vendor  security_patch : $VSPL
EOF

    if [ -n "$VSPL" ] && [ "$VSPL" != "$SPL" ]; then
        cat <<EOF

  >> ** THE TWO PATCH LEVELS DIFFER. **
  >> The vendor partition holds the camera, modem, GPU and DSP HALs, which
  >> is where the severe device-specific bugs are. A stale vendor partition
  >> is a reportable finding on its own. See README 5.3.4.
EOF
    fi

    cat <<EOF

SECURITY POSTURE
  ro.build.type        : $TYPE
  ro.debuggable        : $DBG
  ro.secure            : $SEC
  SELinux              : $ENF
  verified boot state  : $VBS
  bootloader locked    : $LOCK
  hidden_api_policy    : $HAP
EOF

    if [ "$DBG" = "1" ] && [ "$TYPE" != "userdebug" ] && [ "$TYPE" != "eng" ]; then
        echo
        echo "  >> ro.debuggable=1 on a build that does not claim to be userdebug/eng."
    fi
    if [ "$TYPE" = "userdebug" ] || [ "$TYPE" = "eng" ]; then
        cat <<EOF

  >> ** THIS IS A $TYPE BUILD. **
  >> ro.debuggable=1 means \`run-as\` works on EVERY application on this
  >> device and \`adb root\` is available. If this is a production handset,
  >> kiosk, set-top box or in-vehicle unit, stop and write this up before
  >> testing anything else. See README 5.2.
EOF
    fi
    if [ "$ENF" != "Enforcing" ]; then
        echo
        echo "  >> ** SELinux is NOT enforcing. ** This alone is a critical finding"
        echo "  >> on a production device."
    fi
    if [ "$HAP" != "null" ] && [ -n "$HAP" ]; then
        echo
        echo "  >> hidden_api_policy is set to '$HAP' (not the default)."
        echo "  >> Record this: it changes app behaviour. Reset with"
        echo "  >> 'adb shell settings delete global hidden_api_policy'."
    fi

    cat <<EOF

NEXT STEPS
  1. Baseline the service list against a stock device of the SAME release:
         ./aosp-device-recon.sh -o baseline/        (on the stock device)
         ./aosp-device-recon.sh -o target/ -b baseline/
     Everything in 08-service-diff.txt is vendor code as UID 1000.

  2. Group every preinstalled APK by signing certificate to map the trust
     domains on this device (README 8.3).

  3. Pull and decompile /system/framework/services.jar and diff it against
     AOSP for the matching tag (README 6.2). Extract from services.vdex
     first if the jar is a stub.

  4. Read 06-permissions.txt for vendor-defined permissions with
     protectionLevel=normal (README 5.3.3).

FILES
$(cd "$OUTDIR" && ls -1 | sed 's/^/  /')
========================================================================
EOF
} > "$OUTDIR/00-summary.txt"

cat "$OUTDIR/00-summary.txt"
echo
echo "[*] done. evidence in: $OUTDIR"
