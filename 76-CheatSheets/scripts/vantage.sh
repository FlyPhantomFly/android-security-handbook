#!/usr/bin/env bash
# 76-CheatSheets/scripts/vantage.sh
#
# PURPOSE
#   Run one probe from all three vantages on an attached device -- `shell` (uid
#   2000), root, and an app uid -- and print the three answers side by side.
#
#   This repository's most-repeated finding is that a detection probe verified from
#   `adb shell` has not been verified. The failure is silent in BOTH directions: a
#   signal that fires only for `shell` reads as a working check, and a signal
#   invisible to `shell` reads as absent. Four chapters hit it independently. This
#   script is that lesson as a tool, so a cheat-sheet row can carry the vantage it
#   was measured from instead of assuming one.
#
#   It also auto-detects which `su` form the device takes, because that difference
#   is itself a source of wrong conclusions: an AVD's AOSP `su` rejects `-c` with
#   `su: invalid uid/gid '-c'`, which reads as NOT ROOTED.
#
# USAGE
#   ./vantage.sh --file /system/xbin/su
#   ./vantage.sh --file /proc/self/mountinfo --pkg com.example.debuggable
#   ./vantage.sh --cmd 'getprop | wc -l'
#   ./vantage.sh --cmd 'getprop ro.kernel.qemu' --pkg com.example.debuggable
#   ./vantage.sh --posture                    # device identity + su form, then exit
#
#   --pkg must name a DEBUGGABLE package for the app column to work; that is what
#   `run-as` requires. Without it the app column reports "no --pkg" rather than
#   silently reporting the shell's answer, which is the whole point.
#
# WAS THIS EXECUTED?
#   YES. Run on 2026-08-16 against `sdk_gphone16k_x86_64` (emulator-5554,
#   Android 15 / API 35, x86_64, userdebug, rooted with Magisk 30.7), with
#   --pkg com.devuser.helloworld (DEBUGGABLE, uid 10207). Results, each of which
#   independently reproduces a finding this repository measured elsewhere -- the
#   root-check vantage rule in `37-RootDetection`, and the property-visibility
#   census in `39-EmulatorDetection`:
#
#     probe                          shell        root         app
#     /system/xbin/su                readable     readable     PERMISSION DENIED
#     /proc/self/mountinfo (magisk)  3 lines      3 lines      3 lines
#     getprop | wc -l                678          1062         638
#     ro.boottime.* count            0            111          0
#     ro.kernel.qemu                 1            1            1
#
#   The first row is the classic root check returning FALSE on a device that is
#   genuinely rooted. The second is the loudest root signal, and it needs no
#   permissions at all. The third and fourth reproduce, to the property, figures
#   that a sibling chapter had to publish a correction for.
#
# DELIBERATELY NOT USED HERE
#   `set -o pipefail`. Combined with `head` or `grep -q` it reports failure on
#   SUCCESS via SIGPIPE -- measured at exit 141 for `yes | head -3`. Every check
#   below tests CONTENT, not exit status.
#
#   Every `adb` call carries `< /dev/null`. `adb shell` inherits stdin, so inside a
#   loop fed by a pipe it eats the loop's input; a three-row loop measured here
#   printed ONE row and exited 0.
#
# EXIT STATUS
#   0 on success, 1 when no device is attached or arguments are wrong.

set -u

SERIAL=""
PKG=""
PROBE_FILE=""
PROBE_CMD=""
POSTURE_ONLY=0

usage() {
    sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --serial) SERIAL="$2"; shift 2 ;;
        --pkg)    PKG="$2";    shift 2 ;;
        --file)   PROBE_FILE="$2"; shift 2 ;;
        --cmd)    PROBE_CMD="$2";  shift 2 ;;
        --posture) POSTURE_ONLY=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

ADB="adb"
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

# --- device present? -------------------------------------------------------
# `adb devices` prints a header even with nothing attached, so count DATA rows.
# Testing the exit status here would pass with zero devices.
DEVCOUNT=$($ADB devices < /dev/null | sed -n '2,$p' | grep -c 'device$' || true)
if [ "$DEVCOUNT" -eq 0 ]; then
    echo "no device attached (adb devices shows no 'device' row)" >&2
    exit 1
fi
if [ "$DEVCOUNT" -gt 1 ] && [ -z "$SERIAL" ]; then
    echo "more than one device attached; pass --serial" >&2
    $ADB devices -l < /dev/null >&2
    exit 1
fi

# --- identity --------------------------------------------------------------
MODEL=$($ADB shell getprop ro.product.model < /dev/null | tr -d '\r')
REL=$($ADB shell getprop ro.build.version.release < /dev/null | tr -d '\r')
SDK=$($ADB shell getprop ro.build.version.sdk < /dev/null | tr -d '\r')
TYPE=$($ADB shell getprop ro.build.type < /dev/null | tr -d '\r')
SEL=$($ADB shell getenforce < /dev/null | tr -d '\r')

# --- which su form does this device take? ----------------------------------
# `su 0 <cmd>`  : AOSP su, every userdebug build, every AVD
# `su -c <cmd>` : Magisk su on a phone
# Content, not exit status: both forms "succeed" in ways that print an error.
SU_FORM="none"
if $ADB shell "su 0 id" < /dev/null 2>/dev/null | grep -q 'uid=0'; then
    SU_FORM="su0"
elif $ADB shell "su -c id" < /dev/null 2>/dev/null | grep -q 'uid=0'; then
    SU_FORM="suc"
fi

as_root() {   # as_root '<sh command>'
    case "$SU_FORM" in
        su0) $ADB shell "su 0 sh -c '$1'" < /dev/null 2>&1 ;;
        suc) $ADB shell "su -c 'sh -c \"$1\"'" < /dev/null 2>&1 ;;
        *)   echo "NO ROOT" ;;
    esac
}
as_shell() {  # as_shell '<sh command>'
    $ADB shell "sh -c '$1'" < /dev/null 2>&1
}
as_app() {    # as_app '<sh command>'
    if [ -z "$PKG" ]; then echo "no --pkg"; return; fi
    $ADB shell "run-as $PKG sh -c '$1'" < /dev/null 2>&1
}

echo "device      : $MODEL"
echo "android     : $REL / API $SDK ($TYPE)"
echo "selinux     : $SEL"
echo "su form     : $SU_FORM   (su0 = 'su 0 <cmd>', suc = 'su -c <cmd>', none = not rooted)"
if [ -n "$PKG" ]; then
    APPID=$($ADB shell "run-as $PKG id" < /dev/null 2>&1 | tr -d '\r')
    echo "app vantage : $PKG -> $APPID"
else
    echo "app vantage : (none -- pass --pkg <debuggable package> for the third column)"
fi
echo

[ "$POSTURE_ONLY" -eq 1 ] && exit 0

if [ -z "$PROBE_FILE" ] && [ -z "$PROBE_CMD" ]; then
    echo "nothing to probe: pass --file or --cmd (or --posture)" >&2
    exit 1
fi

report() {   # report <label> <sh command>
    label="$1"; cmd="$2"
    printf '%-26s %s\n' "probe" "$label"
    printf '  %-8s %s\n' "shell"  "$(as_shell  "$cmd" | tr '\n' ' ' | cut -c1-100)"
    printf '  %-8s %s\n' "root"   "$(as_root   "$cmd" | tr '\n' ' ' | cut -c1-100)"
    printf '  %-8s %s\n' "app"    "$(as_app    "$cmd" | tr '\n' ' ' | cut -c1-100)"
    echo
}

if [ -n "$PROBE_FILE" ]; then
    # Three separate questions, because File.exists() collapses all three to
    # `false` and that collapse is how a detector ends up with zero discriminating
    # power. ENOENT (absent), EACCES (present but forbidden) and readable are
    # different findings.
    report "ls -l $PROBE_FILE"        "ls -l $PROBE_FILE"
    report "test -e $PROBE_FILE"      "test -e $PROBE_FILE && echo EXISTS || echo NOT-VISIBLE"
    report "test -r $PROBE_FILE"      "test -r $PROBE_FILE && echo READABLE || echo NOT-READABLE"
fi

if [ -n "$PROBE_CMD" ]; then
    report "$PROBE_CMD" "$PROBE_CMD"
fi

cat <<'NOTE'
Reading this table
  - Three different answers is the normal case, not an anomaly.
  - `NOT-VISIBLE` from the app with `readable` from the shell is the classic root
    check returning false on a rooted device. Report the app row.
  - Identical answers in all three columns mean the probe needs no privilege --
    which makes it a BETTER detection signal, not a worse one.
  - `run-as` requires a DEBUGGABLE package. A refusal here is a limit of the
    measurement, not a property of the device; say which it was.
NOTE
