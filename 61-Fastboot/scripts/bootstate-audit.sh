#!/usr/bin/env bash
# scripts/bootstate-audit.sh
#
# PURPOSE
#   Establish a device's boot / bootloader / partition posture from a RUNNING
#   Android, without rebooting it and without touching the bootloader.
#
#   It answers, with the evidence printed next to every verdict:
#     - is the bootloader locked, and how much do we trust that answer?
#     - what did the bootloader actually tell the kernel? (cmdline / bootconfig)
#     - is this an A/B device, and which slot is live?
#     - are partitions dynamic, and what is the real device-mapper stack?
#     - is dm-verity actually running, or merely described?
#
#   Every command it runs is a READ. It never reboots, never flashes, never
#   erases, and never changes a property. It is safe on a device you do not own,
#   with the single caveat that running `adb shell` at all is an action you
#   should be authorised to take.
#
# USAGE
#   ./scripts/bootstate-audit.sh                    # the only attached device
#   ./scripts/bootstate-audit.sh -s emulator-5554   # a specific device
#   ./scripts/bootstate-audit.sh -o evidence.txt    # also write a transcript
#   ./scripts/bootstate-audit.sh --no-root          # skip every root-only probe
#
# REQUIREMENTS
#   adb on PATH, and a device in state "device" (not "unauthorized"/"offline").
#   Root is optional; root-only sections are clearly labelled and skipped
#   cleanly when unavailable.
#
# EXIT CODES
#   0 audit completed
#   1 no usable device, or adb missing
#
# A NOTE ON `su`, MEASURED IN THIS REPOSITORY
#   Root invocation is not portable. A Magisk-style `su` takes `su -c '<cmd>'`;
#   the Android emulator's `su` takes `su 0 <cmd>` and FAILS on `-c` in a way
#   that reads as "not rooted". A previous chapter here nearly recorded a rooted
#   emulator as unrooted for exactly that reason. This script probes both forms
#   and reports which one worked.

set -uo pipefail

SERIAL=""
OUTFILE=""
USE_ROOT=1

while [ $# -gt 0 ]; do
    case "$1" in
        -s) SERIAL="$2"; shift 2 ;;
        -o) OUTFILE="$2"; shift 2 ;;
        --no-root) USE_ROOT=0; shift ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

command -v adb >/dev/null 2>&1 || { echo "adb not found on PATH" >&2; exit 1; }

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

# ---------------------------------------------------------------------------
# Output plumbing
# ---------------------------------------------------------------------------

if [ -n "$OUTFILE" ]; then
    exec > >(tee "$OUTFILE") 2>&1
fi

hr()      { printf '%s\n' "------------------------------------------------------------------"; }
section() { echo; hr; echo "== $*"; hr; }
kv()      { printf '  %-34s %s\n' "$1" "${2:-<empty>}"; }
note()    { printf '  ... %s\n' "$*"; }

# ---------------------------------------------------------------------------
# Device sanity
# ---------------------------------------------------------------------------

STATE="$("${ADB[@]}" get-state 2>/dev/null | tr -d '\r')"
if [ "$STATE" != "device" ]; then
    echo "No device in state 'device' (got '${STATE:-none}')." >&2
    echo "Attached:" >&2
    adb devices -l >&2
    exit 1
fi

prop() { "${ADB[@]}" shell getprop "$1" 2>/dev/null | tr -d '\r'; }
sh_()  { "${ADB[@]}" shell "$1" 2>&1 | tr -d '\r'; }

# ---------------------------------------------------------------------------
# Root detection -- both invocation styles
# ---------------------------------------------------------------------------

ROOT_STYLE=""
if [ "$USE_ROOT" = 1 ]; then
    if [ "$("${ADB[@]}" shell "su -c id -u" 2>/dev/null | tr -d '\r ')" = "0" ]; then
        ROOT_STYLE="dashc"
    elif [ "$("${ADB[@]}" shell "su 0 id -u" 2>/dev/null | tr -d '\r ')" = "0" ]; then
        ROOT_STYLE="zero"
    elif [ "$("${ADB[@]}" shell "id -u" 2>/dev/null | tr -d '\r ')" = "0" ]; then
        ROOT_STYLE="already"
    fi
fi

# Run a command as root using whichever style works. Prints nothing if no root.
root_sh() {
    case "$ROOT_STYLE" in
        dashc)   "${ADB[@]}" shell "su -c '$1'" 2>&1 | tr -d '\r' ;;
        zero)    "${ADB[@]}" shell "su 0 sh -c '$1'" 2>&1 | tr -d '\r' ;;
        already) "${ADB[@]}" shell "$1" 2>&1 | tr -d '\r' ;;
        *)       return 1 ;;
    esac
}

# ---------------------------------------------------------------------------

echo "=================================================================="
echo " Boot-state audit -- chapter 61 (Fastboot)"
echo " Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo " READ-ONLY. Nothing below reboots, flashes, erases or writes."
echo "=================================================================="

section "1. Device identity"
kv "serial"          "$("${ADB[@]}" get-serialno 2>/dev/null | tr -d '\r')"
kv "ro.product.model"        "$(prop ro.product.model)"
kv "ro.product.device"       "$(prop ro.product.device)"
kv "ro.product.cpu.abi"      "$(prop ro.product.cpu.abi)"
kv "ro.build.version.release" "$(prop ro.build.version.release)"
kv "ro.build.version.sdk"    "$(prop ro.build.version.sdk)"
kv "ro.build.type"           "$(prop ro.build.type)"
kv "ro.build.fingerprint"    "$(prop ro.build.fingerprint)"
kv "ro.bootloader"           "$(prop ro.bootloader)"
case "$ROOT_STYLE" in
    dashc)   kv "root"   "yes  (su -c form)" ;;
    zero)    kv "root"   "yes  (su 0 form -- emulator style)" ;;
    already) kv "root"   "yes  (adb shell is already uid 0)" ;;
    *)       kv "root"   "no, or not requested -- root-only probes will be skipped" ;;
esac

section "2. Lock state and Verified Boot -- SELF-REPORTED, see the caveat"
VBS="$(prop ro.boot.verifiedbootstate)"
LOCKED="$(prop ro.boot.flash.locked)"
DEVSTATE="$(prop ro.boot.vbmeta.device_state)"

kv "ro.boot.verifiedbootstate"        "$VBS"
kv "ro.boot.flash.locked"             "$LOCKED"
kv "ro.boot.vbmeta.device_state"      "$DEVSTATE"
kv "ro.boot.veritymode"               "$(prop ro.boot.veritymode)"
kv "ro.boot.vbmeta.digest"            "$(prop ro.boot.vbmeta.digest)"
kv "ro.boot.vbmeta.size"              "$(prop ro.boot.vbmeta.size)"
kv "ro.boot.vbmeta.hash_alg"          "$(prop ro.boot.vbmeta.hash_alg)"
kv "ro.boot.vbmeta.avb_version"       "$(prop ro.boot.vbmeta.avb_version)"
kv "ro.boot.avb_version"              "$(prop ro.boot.avb_version)"
kv "ro.boot.vbmeta.invalidate_on_error" "$(prop ro.boot.vbmeta.invalidate_on_error)"
kv "ro.oem_unlock_supported"          "$(prop ro.oem_unlock_supported)"
kv "sys.oem_unlock_allowed"           "$(prop sys.oem_unlock_allowed)"
kv "ro.secure"                        "$(prop ro.secure)"
kv "ro.debuggable"                    "$(prop ro.debuggable)"

echo
case "$VBS" in
    green)  note "VERDICT: reports GREEN -- locked, OEM-signed, verified." ;;
    yellow) note "VERDICT: reports YELLOW -- locked with an OWNER-supplied key." ;;
    orange) note "VERDICT: reports ORANGE -- bootloader UNLOCKED." ;;
    red)    note "VERDICT: reports RED -- verification FAILED. Investigate." ;;
    "")     note "VERDICT: the property is ABSENT, which is not a boot state."
            note "         The bootloader never reported one. Measured on the"
            note "         Android emulator, which has no bootloader at all."
            note "         An app checking !equals(\"orange\") PASSES here." ;;
    *)      note "VERDICT: unrecognised value '$VBS'." ;;
esac
echo
note "CAVEAT, and it is the whole point: every value above is a property that"
note "root can rewrite (Magisk's resetprop does it in one command). This is"
note "orientation for a device you control, NOT an assurance claim. The only"
note "non-forgeable statement of lock state is the deviceLocked field inside a"
note "hardware key attestation certificate -- see 50-HardwareBackedSecurity."

section "3. What the bootloader ACTUALLY told the kernel"
CMDLINE="$(sh_ 'cat /proc/cmdline')"
if echo "$CMDLINE" | grep -qi 'permission denied'; then
    note "/proc/cmdline: Permission denied to the shell user."
    note "(Measured on API 35: this is normal, and it is also denied to apps.)"
    if [ -n "$ROOT_STYLE" ]; then
        RC="$(root_sh 'cat /proc/cmdline' | tr ' ' '\n' | grep -i androidboot)"
        if [ -n "$RC" ]; then
            note "retrying as root:"
            echo "$RC" | sed 's/^/    /'
        else
            note "as root: readable, but it carries NO androidboot.* parameters."
            note "         On such a device the parameters are in bootconfig"
            note "         instead -- see below. Both are valid; newer devices"
            note "         prefer bootconfig because the cmdline has a length cap."
        fi
    fi
else
    echo "$CMDLINE" | tr ' ' '\n' | grep -i androidboot | sed 's/^/    /'
    [ -z "$(echo "$CMDLINE" | grep -i androidboot)" ] && \
        note "no androidboot.* parameters on the cmdline"
fi

echo
BOOTCFG="$(sh_ 'cat /proc/bootconfig')"
if echo "$BOOTCFG" | grep -qi 'permission denied\|No such file'; then
    note "/proc/bootconfig not readable by the shell user"
    if [ -n "$ROOT_STYLE" ]; then
        note "retrying as root -- the androidboot.* keys init derives ro.boot.* from:"
        root_sh 'cat /proc/bootconfig' | grep -i androidboot | \
            grep -viE 'adb.pubkey' | sed 's/^/    /'
    fi
else
    echo "$BOOTCFG" | grep -i androidboot | grep -viE 'adb.pubkey' | sed 's/^/    /'
fi

echo
note "Cross-check: an ro.boot.X property is EMPTY exactly when androidboot.X is"
note "absent above. If ro.boot.verifiedbootstate is empty, look for"
note "androidboot.verifiedbootstate here -- it will not be there."

section "4. A/B slots"
SLOT="$(prop ro.boot.slot_suffix)"
kv "ro.boot.slot_suffix"   "$SLOT"
kv "ro.build.ab_update"    "$(prop ro.build.ab_update)"
kv "ro.virtual_ab.enabled" "$(prop ro.virtual_ab.enabled)"
kv "ro.virtual_ab.compression.enabled" "$(prop ro.virtual_ab.compression.enabled)"

echo
if [ -n "$ROOT_STYLE" ]; then
    NSLOTS="$(root_sh 'bootctl get-number-slots' 2>/dev/null)"
    CURSLOT="$(root_sh 'bootctl get-current-slot' 2>/dev/null)"
    kv "bootctl get-number-slots" "$NSLOTS"
    kv "bootctl get-current-slot" "$CURSLOT"
    if echo "$NSLOTS" | grep -qi 'failed'; then
        note "No boot control HAL. On a phone that means non-A/B; on the"
        note "emulator it means there is no bootloader at all."
    fi
else
    note "bootctl needs root -- skipped"
fi

echo
if [ -z "$SLOT" ]; then
    note "VERDICT: NOT an A/B device (no slot suffix). Partitions have no _a/_b."
else
    note "VERDICT: A/B device, slot '$SLOT' is live."
    note "         'fastboot flash X' would target THIS slot. Record it before"
    note "         and after any flash -- a slot switch is the usual reason a"
    note "         patch appears to have 'stopped working'."
fi

section "5. Partition layout"
kv "ro.boot.dynamic_partitions"          "$(prop ro.boot.dynamic_partitions)"
kv "ro.boot.dynamic_partitions_retrofit" "$(prop ro.boot.dynamic_partitions_retrofit)"
echo
echo "  /dev/block/by-name/:"
BYNAME="$(sh_ 'ls -l /dev/block/by-name/ 2>&1')"
if echo "$BYNAME" | grep -qi 'permission denied'; then
    [ -n "$ROOT_STYLE" ] && BYNAME="$(root_sh 'ls -l /dev/block/by-name/')"
fi
echo "$BYNAME" | sed 's/^/    /'

echo
for p in boot init_boot recovery misc super vbmeta metadata userdata vendor_boot dtbo; do
    if echo "$BYNAME" | grep -qE "(^| )$p( |$|_a|_b)|/$p$| $p -> "; then
        printf '  %-14s present\n' "$p"
    else
        printf '  %-14s ABSENT\n' "$p"
    fi
done
echo
note "'misc' is the Bootloader Control Block -- the mailbox 'adb reboot"
note "bootloader' writes into. A device with no 'misc' cannot be sent to"
note "fastboot mode that way. 'boot' absent means the kernel does not come"
note "from flash at all, which is the emulator's situation."

section "6. Device-mapper -- what the kernel is ACTUALLY doing (ground truth)"
if [ -z "$ROOT_STYLE" ]; then
    note "root required -- skipped."
    note "Without root you can still see the mounts:"
    sh_ 'grep -E " (/|/system|/vendor|/product|/system_ext|/metadata) " /proc/mounts' | sed 's/^/    /'
else
    echo "  dm devices (non-APEX):"
    root_sh 'dmctl list devices' 2>/dev/null | grep -v '^com\.android\.' | sed 's/^/    /'
    echo
    for d in system system-verity vendor vendor-verity product product-verity \
             system_ext system_dlkm; do
        T="$(root_sh "dmctl table $d" 2>/dev/null)"
        if [ -n "$T" ] && ! echo "$T" | grep -qi 'not found\|No such\|error'; then
            echo "  --- $d ---"
            echo "$T" | grep -v '^Targets in' | sed 's/^/    /'
        fi
    done
    echo
    echo "  lpdump (what the super METADATA claims):"
    root_sh 'lpdump' 2>/dev/null | head -40 | sed 's/^/    /'
    echo
    note "If lpdump fails while dmctl works, believe dmctl. The kernel is what"
    note "is actually serving reads; the metadata is a description of it."
    echo
    echo "  mounts:"
    root_sh 'grep -E " (/|/system|/vendor|/product|/system_ext|/metadata) " /proc/mounts' | sed 's/^/    /'
fi

section "7. dm-verity"
kv "ro.boot.veritymode" "$(prop ro.boot.veritymode)"
if [ -n "$ROOT_STYLE" ]; then
    VER="$(root_sh 'dmctl list devices' 2>/dev/null | grep -i verity)"
    if [ -n "$VER" ]; then
        echo "  verity devices present:"
        echo "$VER" | sed 's/^/    /'
        note "VERDICT: dm-verity is RUNNING for the partitions listed."
    else
        note "VERDICT: no dm-verity device-mapper devices exist."
        note "         Either verity is disabled, or this build does not use it."
        note "         Note that a vbmeta may carry hashtree DESCRIPTORS for"
        note "         partitions that have no verity MAPPING -- descriptors"
        note "         present is not the same as verity enforced."
    fi
else
    note "root required to enumerate dm devices -- skipped"
fi

section "8. Next steps"
cat <<'EOF'
  This audit reports what the DEVICE says about itself. To get evidence rather
  than claims:

    1. Pull a hardware key attestation and read deviceLocked / verifiedBootState
       from the attestation extension, verified server-side.
         -> 50-HardwareBackedSecurity
    2. Pull the vbmeta partition and read its flags from the bytes:
         adb shell 'su 0 dd if=/dev/block/by-name/vbmeta bs=1 count=$SIZE 2>/dev/null | base64' \
           | base64 -d > vbmeta.img
         python3 -B scripts/vbmeta-flags.py show vbmeta.img
       where $SIZE is the ro.boot.vbmeta.size reported in section 2.
    3. Hash boot / init_boot against the OEM factory image for this exact
       fingerprint. That turns "is it modified?" into arithmetic.

  Nothing in this script, or in those steps, changes device state.
EOF

echo
hr
echo "audit complete"
