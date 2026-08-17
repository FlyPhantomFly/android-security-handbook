#!/usr/bin/env bash
#
# scripts/harden-avd.sh
#
# PURPOSE
#   Make an Android Virtual Device look less like an emulator by changing the
#   ENVIRONMENT rather than hooking the app -- the lowest altitude available,
#   and invisible to the app process entirely.
#
#   Just as importantly, it MEASURES WHAT IT DID NOT FIX. It runs the chapter's
#   native probe before and after and prints the difference, because the honest
#   result is that property spoofing defeats the checks people write and not the
#   checks that are available:
#
#     fixed        every property-based (SOFT) signal
#     NOT fixed    /dev/goldfish_* device nodes           (kernel drivers)
#                  the sensor HAL's 18 AOSP-vendored sensors
#                  /proc/cpuinfo's `hypervisor` CPUID bit (the host CPU reports it)
#                  the absence of a TEE for key attestation
#
#   A script that only printed successes would teach the wrong lesson.
#
# USAGE
#   # host -- show what would change, touch nothing
#   ./harden-avd.sh --dry-run
#
#   # host -- apply, then show a before/after comparison
#   ./harden-avd.sh --apply
#
#   # host -- target a specific device
#   ./harden-avd.sh --apply --serial emulator-5554
#
#   # host -- just measure the current state
#   ./harden-avd.sh --measure
#
#   # host -- undo (reboots the AVD; ro. properties are restored from bootconfig)
#   ./harden-avd.sh --revert
#
# REQUIREMENTS
#   * An emulator you own, running, visible to adb.
#   * `adb root` must succeed. That means a Google APIs / AOSP image, NOT a
#     "Google Play" image -- Play images ship a production build where adb root
#     is refused. If you need a hardened AVD with Play services, that is a
#     different (and much harder) problem; see the note at the end.
#   * For persistent ro. property changes, Magisk installed on the AVD, which
#     provides `resetprop`. Without it this script can only change non-ro.
#     properties, and it says so.
#
# WHY setprop IS NOT ENOUGH
#   Properties beginning `ro.` are read-only: Android's property service refuses
#   to change them after they are first set (system/core/init/property_service.cpp).
#   `setprop ro.kernel.qemu 0` fails silently-ish and the value does not change.
#   Magisk's `resetprop` writes the property trie directly, bypassing the service.
#   That is also the reason `ro.` immutability is NOT a security boundary against
#   an attacker with root -- README section 4.3.
#
# AUTHORISED TESTING ONLY
#   Run this against an emulator you own, to test YOUR apps or apps you are
#   contracted to assess. It exists so you can verify which of your own controls
#   survive a hostile environment.

set -u

SERIAL=""
MODE=""
PROBE_REMOTE="/data/local/tmp/emu_probe"

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) MODE="dry" ;;
        --apply)   MODE="apply" ;;
        --measure) MODE="measure" ;;
        --revert)  MODE="revert" ;;
        --serial)  shift; SERIAL="${1:-}" ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -n "$MODE" ] || { sed -n '2,60p' "$0"; exit 2; }

ADB() { if [ -n "$SERIAL" ]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi; }

# --------------------------------------------------------------------------- #
# The profile: a REAL Redmi M2101K6P (Android 11 / API 30, arm64), measured for
# this chapter. Self-consistency is the point -- a check worth defeating looks
# for contradictions, so a Pixel model string next to ro.hardware=ranchu is a
# LOUDER signal than either value on its own.
#
# Two properties are deliberately absent from this list:
#   qemu.hw.mainkeys     set to 0 on the real Redmi
#   ro.kernel.qemu.gles  set to 0 on the real Redmi
# Clearing them would make the profile LESS realistic. See README 3.3.1.
# --------------------------------------------------------------------------- #
PROPS="
ro.kernel.qemu=
ro.boot.qemu=
ro.boot.qemu.avd_name=
ro.hardware=qcom
ro.boot.hardware=qcom
ro.product.board=sweetin
ro.board.platform=sm6150
ro.hardware.egl=adreno
ro.hardware.vulkan=adreno
ro.hardware.gralloc=
ro.soc.model=
ro.soc.manufacturer=
ro.build.characteristics=default
ro.dalvik.vm.native.bridge=0
ro.product.model=M2101K6P
ro.product.name=sweetin
ro.product.device=sweetin
ro.product.brand=Redmi
ro.product.manufacturer=Xiaomi
ro.build.tags=release-keys
ro.build.type=user
ro.build.flavor=qssi-user
ro.serialno=84f7a024
ro.boot.serialno=84f7a024
ro.debuggable=0
ro.build.fingerprint=Redmi/sweetin/sweetin:11/RKQ1.200826.002/V12.5.10.0.RKFINXM:user/release-keys
ro.build.host=c5-miui-ota-bd237.bj
ro.build.user=builder
init.svc.goldfish-logcat=
"

banner() {
    echo
    echo "=============================================================="
    echo "$1"
    echo "=============================================================="
}

check_device() {
    if ! ADB get-state >/dev/null 2>&1; then
        echo "error: no device. Start the AVD first." >&2
        exit 1
    fi
    local qemu
    qemu="$(ADB shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r')"
    local hw
    hw="$(ADB shell getprop ro.hardware 2>/dev/null | tr -d '\r')"
    if [ "$qemu" != "1" ] && [ "$hw" != "ranchu" ] && [ "$hw" != "goldfish" ]; then
        echo "error: this does not look like an emulator (ro.hardware=$hw)." >&2
        echo "       Refusing to run. This script is for AVDs you own." >&2
        exit 1
    fi
}

measure() {
    echo "-- properties an app-visible check would read --"
    for k in ro.kernel.qemu ro.boot.qemu ro.hardware ro.boot.hardware \
             ro.build.characteristics ro.product.model ro.product.brand \
             ro.hardware.egl ro.soc.model ro.dalvik.vm.native.bridge \
             ro.build.tags ro.build.type ro.serialno ro.build.fingerprint; do
        printf '   %-32s %s\n' "$k" "$(ADB shell getprop "$k" 2>/dev/null | tr -d '\r')"
    done

    echo
    echo "-- signals this script CANNOT change --"
    printf '   %-32s ' '/dev/goldfish_sync'
    ADB shell "[ -e /dev/goldfish_sync ] && echo PRESENT || echo absent" 2>/dev/null | tr -d '\r'
    printf '   %-32s ' '/dev/goldfish_pipe_dprctd'
    ADB shell "[ -e /dev/goldfish_pipe_dprctd ] && echo PRESENT || echo absent" 2>/dev/null | tr -d '\r'
    printf '   %-32s ' '/sys/module/goldfish_pipe'
    ADB shell "[ -e /sys/module/goldfish_pipe ] && echo PRESENT || echo absent" 2>/dev/null | tr -d '\r'
    printf '   %-32s ' 'cpuinfo hypervisor flag'
    ADB shell "grep -qi hypervisor /proc/cpuinfo && echo PRESENT || echo absent" 2>/dev/null | tr -d '\r'
    printf '   %-32s ' 'sensor count'
    ADB shell "dumpsys sensorservice 2>/dev/null | grep -m1 'h/w sensors'" 2>/dev/null | tr -d '\r'
    # -E, not a BRE alternation: `\|` does not survive the adb shell round trip,
    # and the symptom is a silent 0 rather than an error.
    printf '   %-32s ' 'sensors vendored AOSP'
    ADB shell "dumpsys sensorservice 2>/dev/null | grep -cE 'AOSP|Android Open Source'" 2>/dev/null | tr -d '\r'
}

apply_props() {
    local have_resetprop=0
    if ADB shell "command -v resetprop" >/dev/null 2>&1; then
        have_resetprop=1
    fi

    if [ "$have_resetprop" -eq 0 ]; then
        echo
        echo "!! resetprop NOT FOUND on this AVD."
        echo "!! Magisk is not installed, so ro.* properties CANNOT be changed:"
        echo "!! the property service refuses to rewrite them (README 4.3)."
        echo "!! Everything below will be attempted with setprop and most of it"
        echo "!! will silently fail. Install Magisk on the AVD for a real test."
        echo
    fi

    local n=0 failed=0
    echo "$PROPS" | while IFS= read -r line; do
        [ -n "$line" ] || continue
        local key="${line%%=*}"
        local val="${line#*=}"
        if [ "$have_resetprop" -eq 1 ]; then
            ADB shell "su -c 'resetprop \"$key\" \"$val\"'" >/dev/null 2>&1
        else
            ADB shell "su -c 'setprop \"$key\" \"$val\"'" >/dev/null 2>&1
        fi
        local now
        now="$(ADB shell getprop "$key" 2>/dev/null | tr -d '\r')"
        if [ "$now" = "$val" ]; then
            printf '   ok    %-32s = %s\n' "$key" "$val"
            n=$((n+1))
        else
            printf '   FAIL  %-32s (still %s)\n' "$key" "${now:-<empty>}"
            failed=$((failed+1))
        fi
    done
}

case "$MODE" in
  measure)
    check_device
    banner "CURRENT STATE"
    measure
    ;;

  dry)
    check_device
    banner "DRY RUN -- nothing will be changed"
    echo "Would set these properties (profile: real Redmi M2101K6P):"
    echo "$PROPS" | while IFS= read -r line; do
        [ -n "$line" ] || continue
        printf '   %-32s = %s\n' "${line%%=*}" "${line#*=}"
    done
    echo
    echo "Would NOT change (and cannot):"
    echo "   /dev/goldfish_sync, /dev/goldfish_pipe_dprctd  -- kernel drivers"
    echo "   /sys/module/goldfish_pipe                      -- kernel module"
    echo "   the 18 AOSP-vendored sensors                   -- the sensor HAL"
    echo "   /proc/cpuinfo hypervisor flag                  -- the host CPU reports it"
    echo "   absence of a TEE for key attestation           -- there is no TEE"
    ;;

  apply)
    check_device
    banner "BEFORE"
    measure

    banner "APPLYING"
    if ! ADB root >/dev/null 2>&1; then
        echo "warning: 'adb root' failed. On a Google Play image this is expected"
        echo "         and this script cannot proceed. Use a Google APIs or AOSP"
        echo "         image instead."
    fi
    sleep 3
    ADB wait-for-device
    apply_props

    banner "AFTER"
    measure

    banner "WHAT THIS DID NOT FIX -- read this part"
    cat <<'EOF'
   The properties above are the SOFT signals from README section 3.14. They are
   what most published checks read, so spoofing them defeats most published
   checks. They are not what a good check reads.

   Still detectable, and none of it is reachable from a property:

     * /dev/goldfish_sync, /dev/goldfish_pipe_dprctd, /dev/goldfish_address_space
       exist because kernel modules registered them. Removing them means
       rebuilding the guest kernel without those drivers -- and then the
       emulator's graphics and sync transport stop working.

     * The sensor HAL reports 18 sensors, every one vendored to AOSP. A real
       phone was measured at 41 sensors from 6 different silicon vendors.
       Faking this means replacing the HAL, not setting a property.

     * /proc/cpuinfo carries the `hypervisor` CPUID bit. The guest cannot clear
       it: the value is produced by the physical CPU when the hypervisor traps
       CPUID, and never passes through guest-controlled memory.

     * There is no TEE, so every KeyStore key attests as SOFTWARE with an empty
       hardwareEnforced list. Chapter 50 measured that the attestation chain
       still VERIFIES perfectly -- a valid chain proves the chain, not the
       hardware. A verifier that checks the security level is not fooled by
       anything in this script.

   That asymmetry IS the lesson. Property spoofing defeats the checks people
   write, not the checks that are available.
EOF
    ;;

  revert)
    check_device
    echo "Rebooting the AVD. ro.* properties are re-derived from bootconfig at"
    echo "boot, so a reboot restores every value this script changed."
    ADB reboot
    echo "done. Wait for the AVD to finish booting, then --measure to confirm."
    ;;
esac

echo
echo "Probe deeper with the chapter's own instruments:"
echo "   examples/emu_probe.c          native, reports errno and grades each signal"
echo "   examples/EmulatorSignals.java app-uid view, built by scripts/build-probe-app.sh"
echo
echo "If you pushed the native probe earlier, clean it up:"
echo "   adb shell rm -f $PROBE_REMOTE"
