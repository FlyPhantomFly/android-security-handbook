#!/usr/bin/env bash
# scripts/am-instrument-matrix.sh
#
# PURPOSE
#   Settle, by measurement rather than by folklore, what actually gates
#   `am instrument`. Three variables are crossed:
#
#       target       android:debuggable  true / false
#       test APK     signing key         same as target / different
#       caller       identity            shell (uid 2000) / root (uid 0) / app uid
#
#   and one extra row for android:testOnly="true", which is an install-time gate
#   rather than an instrument-time one.
#
#   The received wisdom this script exists to test is: "you can only instrument a
#   debuggable app". That claim is measurably wrong in both directions on the
#   device this chapter was written against, and the real gate is somewhere else.
#   Run it yourself and read the ERROR TEXT, which names the check by name.
#
# USAGE
#   # host -- build the fixtures first
#   ../examples/build-instrumentation-fixtures.sh
#
#   # host -- then run the matrix (OUTDIR must match the build)
#   OUTDIR=/tmp/ch66-build ./am-instrument-matrix.sh
#
#   # host -- one row only
#   OUTDIR=/tmp/ch66-build ./am-instrument-matrix.sh --row 3
#
# WAS THIS SCRIPT EXECUTED?
#   YES. Run on 2026-08-16 against the AVD sdk_gphone16k_x86_64 (Android 15 /
#   API 35, x86_64, userdebug, Magisk 30.7). Its output is reproduced verbatim in
#   README.md section 3.9 and in labs/lab-02. Note that this AVD reports
#   ro.debuggable=1: the script prints that property first, because a userdebug
#   build takes a more permissive branch in several platform checks and any
#   result gathered here must be read with that in mind.
#
# WHAT IT CHANGES ON THE DEVICE
#   Installs and uninstalls com.pentest.ch66.vault and com.pentest.ch66.vault.test
#   repeatedly, and force-stops the target (which `am instrument` does anyway).
#   It writes nothing to /data/local/tmp and leaves no residue: the final step
#   uninstalls both packages unless --keep is passed.
#
# AUTHORISED TESTING ONLY. Both packages are chapter fixtures. Do not point this
# at an application you do not own.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch66-build}"

TARGET_PKG="com.pentest.ch66.vault"
TEST_PKG="com.pentest.ch66.vault.test"
RUNNER="$TEST_PKG/com.pentest.ch66.probe.VaultProbe"

# adb mangles absolute remote paths under MSYS; see the build script's header.
export MSYS_NO_PATHCONV=1

ROW_FILTER=""
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --row) ROW_FILTER="${2:-}"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown argument: $1"; exit 2 ;;
    esac
done

p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

need() {
    [ -f "$OUTDIR/$1.apk" ] || {
        echo "error: $OUTDIR/$1.apk missing. Run examples/build-instrumentation-fixtures.sh first."
        exit 2
    }
}
for a in vault-debuggable vault-release probe-sigA probe-sigB probe-testonly; do need "$a"; done

echo "device:"
adb devices -l | sed -n '2p'
printf '  model            %s\n' "$(adb shell getprop ro.product.model | tr -d '\r')"
printf '  sdk              %s\n' "$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
printf '  ro.build.type    %s\n' "$(adb shell getprop ro.build.type | tr -d '\r')"
printf '  ro.debuggable    %s  <- a userdebug build relaxes several platform checks\n' \
        "$(adb shell getprop ro.debuggable | tr -d '\r')"
echo

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
install_apk() {   # install_apk <artefact> [extra pm flags]
    local a="$1"; shift
    adb install -r "$@" "$(p "$OUTDIR/$a.apk")" 2>&1 | grep -vE '^Performing|^$' | tail -1
}

fresh_probe() {   # uninstall then install, because a signature change cannot be an upgrade
    adb uninstall "$TEST_PKG" >/dev/null 2>&1
    install_apk "$1" >/dev/null
}

target_flags() {
    adb shell dumpsys package "$TARGET_PKG" 2>/dev/null \
        | grep -m1 -E '^\s+flags=' | tr -d '\r' | sed 's/^ *//'
}

# Run the instrumentation and reduce it to ONE line: either the verdict from a
# known result key, or the SecurityException reason.
#
# Deliberately NOT using `set -o pipefail` anywhere in this script. Two agents in
# this repository lost time to pipefail turning an early-exiting `head`/`grep -q`
# into a spurious SIGPIPE failure. We test CONTENT, not exit status.
run_instr() {     # run_instr <as-shell|as-root|as-app> [extra am flags]
    local who="$1"; shift
    local cmd="am instrument -w -r $* $RUNNER"
    local out
    case "$who" in
        as-shell) out="$(adb shell "$cmd" 2>&1)" ;;
        # su on this AVD takes `su 0 <cmd>`, NOT `su -c <cmd>`; the -c form
        # fails with "invalid uid/gid '-c'" and reads as "not rooted".
        as-root)  out="$(adb shell "su 0 $cmd" 2>&1)" ;;
        as-app)   out="$(adb shell "run-as $TARGET_PKG $cmd" 2>&1)" ;;
        *) echo "bad caller: $who"; return 1 ;;
    esac

    local verdict
    verdict="$(printf '%s' "$out" | grep -m1 'read.prefs.api_key=')"
    if [ -n "$verdict" ]; then
        printf '   RESULT   OK   %s\n' "$(printf '%s' "$verdict" | tr -d '\r')"
        printf '            %s\n' "$(printf '%s' "$out" | grep -m1 'INSTRUMENTATION_CODE' | tr -d '\r')"
        return 0
    fi
    verdict="$(printf '%s' "$out" | grep -m1 -E 'Permission Denial|SecurityException|Unable to find|error:|Exception')"
    printf '   RESULT   REFUSED\n'
    printf '            %s\n' "$(printf '%s' "${verdict:-<no diagnostic>}" | cut -c1-220 | tr -d '\r')"
    return 1
}

row() {
    [ -z "$ROW_FILTER" ] && return 0
    [ "$ROW_FILTER" = "$1" ] && return 0
    return 1
}

# --------------------------------------------------------------------------- #
# ROW 1  debuggable target, matching signature, caller = shell
# --------------------------------------------------------------------------- #
if row 1; then
echo "ROW 1  target=debuggable  probe=sigA(match)   caller=shell"
install_apk vault-debuggable >/dev/null; fresh_probe probe-sigA
echo "   target $(target_flags)"
run_instr as-shell
echo
fi

# --------------------------------------------------------------------------- #
# ROW 2  NON-debuggable target, matching signature, caller = shell
#        The row that kills "you can only instrument a debuggable app".
# --------------------------------------------------------------------------- #
if row 2; then
echo "ROW 2  target=release     probe=sigA(match)   caller=shell"
install_apk vault-release >/dev/null
echo "   target $(target_flags)"
run_instr as-shell
echo
fi

# --------------------------------------------------------------------------- #
# ROW 3  NON-debuggable target, MISMATCHED signature, caller = shell
# --------------------------------------------------------------------------- #
if row 3; then
echo "ROW 3  target=release     probe=sigB(differ)  caller=shell"
install_apk vault-release >/dev/null; fresh_probe probe-sigB
echo "   target $(target_flags)"
run_instr as-shell
echo
fi

# --------------------------------------------------------------------------- #
# ROW 4  DEBUGGABLE target, MISMATCHED signature, caller = shell
#        The decisive cell. If android:debuggable waived the signature check,
#        this row would succeed. Read the result carefully.
# --------------------------------------------------------------------------- #
if row 4; then
echo "ROW 4  target=debuggable  probe=sigB(differ)  caller=shell"
install_apk vault-debuggable >/dev/null
echo "   target $(target_flags)"
run_instr as-shell
echo
fi

# --------------------------------------------------------------------------- #
# ROW 5  DEBUGGABLE target, MISMATCHED signature, caller = ROOT
# --------------------------------------------------------------------------- #
if row 5; then
echo "ROW 5  target=debuggable  probe=sigB(differ)  caller=root"
run_instr as-root
echo
fi

# --------------------------------------------------------------------------- #
# ROW 6  NON-debuggable target, MISMATCHED signature, caller = ROOT
# --------------------------------------------------------------------------- #
if row 6; then
echo "ROW 6  target=release     probe=sigB(differ)  caller=root"
install_apk vault-release >/dev/null
echo "   target $(target_flags)"
run_instr as-root
echo
fi

# --------------------------------------------------------------------------- #
# ROW 7  matching signature, caller = the TARGET APP's own uid, via run-as.
#        run-as needs a debuggable target, so this row uses one. It answers a
#        question the other rows cannot: is `am instrument` a shell privilege?
# --------------------------------------------------------------------------- #
if row 7; then
echo "ROW 7  target=debuggable  probe=sigA(match)   caller=app uid (run-as)"
install_apk vault-debuggable >/dev/null; fresh_probe probe-sigA
echo "   target $(target_flags)"
run_instr as-app
echo
fi

# --------------------------------------------------------------------------- #
# ROW 8  android:testOnly="true" -- an INSTALL-time gate, not an instrument gate
# --------------------------------------------------------------------------- #
if row 8; then
echo "ROW 8  install probe-testonly (android:testOnly=\"true\")"
adb uninstall "$TEST_PKG" >/dev/null 2>&1
printf '   plain install : %s\n' "$(install_apk probe-testonly)"
printf '   with -t       : %s\n' "$(install_apk probe-testonly -t)"
printf '   pm list       : %s\n' "$(adb shell pm list instrumentation | tr -d '\r')"
echo
fi

# --------------------------------------------------------------------------- #
# cleanup
# --------------------------------------------------------------------------- #
if [ "$KEEP" -eq 0 ]; then
    echo "cleanup:"
    adb uninstall "$TEST_PKG"   2>&1 | tail -1 | sed 's/^/   /'
    adb uninstall "$TARGET_PKG" 2>&1 | tail -1 | sed 's/^/   /'
    printf '   pm list instrumentation -> %s\n' \
        "$(adb shell pm list instrumentation | tr -d '\r' | wc -l) rows"
else
    echo "--keep: fixtures left installed. Remove them with"
    echo "   ../examples/build-instrumentation-fixtures.sh --uninstall"
fi
