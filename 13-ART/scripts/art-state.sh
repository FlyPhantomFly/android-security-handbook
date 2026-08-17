#!/usr/bin/env bash
#
# art-state.sh — inspect and control a package's ART compilation state.
#
# WHAT IT DOES
#   One tool for every ART state question you need answered during an
#   engagement, plus the two commands you will use most:
#
#     report   full ART state: filter, artifacts, profile, module version
#     verify   force everything into the interpreter (hooks become reliable)
#     speed    force full AOT compilation (reproduce a user-like device)
#     reset    delete compiled artifacts
#     extract  pull DEX out of the VDEX and copy it to the host
#     profile  snapshot and dump the execution profile
#
#   The `verify` subcommand is the single highest-value action in Android
#   dynamic analysis: it makes every method interpreted, so Java hooks land
#   at every call site instead of being defeated by inlining.
#   See ../README.md sections 3.9, 3.10 and 3.17.
#
# HOW TO RUN
#   ./art-state.sh report  com.example.target
#   ./art-state.sh verify  com.example.target
#   ./art-state.sh speed   com.example.target
#   ./art-state.sh reset   com.example.target
#   ./art-state.sh extract com.example.target [outdir]
#   ./art-state.sh profile com.example.target
#
# REQUIREMENTS
#   adb on PATH. Root on the device for `extract` and for the richer parts of
#   `report`; everything else works unprivileged.
#
# EXIT CODES
#   0 ok · 1 usage · 2 package not installed · 3 root required

set -uo pipefail

CMD="${1:-}"
PKG="${2:-}"

usage() {
    sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

[[ -z "$CMD" || -z "$PKG" ]] && usage

# ----------------------------------------------------------------- helpers ---

hr() { printf '\n== %s %s\n' "$1" "$(printf '=%.0s' $(seq 1 $((58 - ${#1}))))"; }

adbsh() { adb shell "$@" 2>/dev/null | tr -d '\r'; }

have_root() {
    [[ "$(adbsh 'command -v su >/dev/null && echo yes || echo no')" == "yes" ]]
}

su_sh() {
    if have_root; then adb shell "su -c '$1'" 2>/dev/null | tr -d '\r'
    else return 3; fi
}

check_installed() {
    if [[ -z "$(adbsh "pm path $PKG")" ]]; then
        echo "error: package $PKG is not installed" >&2
        exit 2
    fi
}

resolve_paths() {
    APK="$(adbsh "pm path $PKG" | head -1 | sed 's/package://')"
    DIR="$(dirname "$APK")"
    # Determine the instruction-set directory rather than assuming arm64.
    ISA="$(adbsh "ls $DIR/oat/ 2>/dev/null" | head -1)"
    [[ -z "$ISA" ]] && ISA="arm64"
    OATDIR="$DIR/oat/$ISA"
}

find_oatdump() {
    for c in /apex/com.android.art/bin/oatdump \
             /apex/com.android.art/bin/oatdump64 \
             /system/bin/oatdump; do
        if [[ -n "$(adbsh "ls $c 2>/dev/null")" ]]; then echo "$c"; return; fi
    done
    echo ""
}

# ------------------------------------------------------------------ report ---

do_report() {
    check_installed
    resolve_paths
    OATDUMP="$(find_oatdump)"

    hr "PACKAGE"
    echo "  package : $PKG"
    echo "  apk     : $APK"
    echo "  oat dir : $OATDIR"
    echo "  isa     : $ISA"
    adbsh "dumpsys package $PKG | grep -E 'versionName|versionCode|targetSdk|minSdk'" \
        | sed 's/^\s*/  /'

    hr "DEVICE / RUNTIME"
    for p in ro.build.version.release ro.build.version.sdk \
             ro.build.version.security_patch ro.product.cpu.abi \
             dalvik.vm.usejit dalvik.vm.usejitprofiles \
             dalvik.vm.dex2oat-filter dalvik.vm.image-dex2oat-filter \
             dalvik.vm.heapgrowthlimit dalvik.vm.heapsize; do
        printf '  %-36s %s\n' "$p" "$(adbsh "getprop $p")"
    done
    printf '  %-36s %s\n' "root" "$(have_root && echo yes || echo no)"

    hr "ART MAINLINE MODULE"
    # ART internals differ per module version even on the same Android release.
    # Always record this in an engagement report. See README section 3.26.
    local artver
    artver="$(adbsh "dumpsys package com.google.android.art | grep -m1 versionName")"
    [[ -z "$artver" ]] && artver="$(adbsh "dumpsys package com.android.art | grep -m1 versionName")"
    echo "  ${artver:-<not reported — likely a non-modular build>}"

    hr "COMPILATION STATE (PackageManager view)"
    adbsh "dumpsys package dexopt | grep -A6 \"\\[$PKG\\]\"" | sed 's/^/  /'

    hr "ARTIFACTS ON DISK"
    if have_root; then
        su_sh "ls -la $OATDIR" | sed 's/^/  /'
    else
        echo "  (root required to list $OATDIR)"
    fi

    hr "OAT HEADER (authoritative)"
    if have_root && [[ -n "$OATDUMP" ]]; then
        su_sh "$OATDUMP --oat-file=$OATDIR/base.odex --header-only 2>/dev/null" \
            | grep -iE 'oat-version|instruction-set|dex-file-count|compiler-filter|dex2oat-cmdline|concurrent-copying|native-debuggable' \
            | sed 's/^/  /'
        echo
        echo "  --- interpretation ---"
        local filt
        filt="$(su_sh "$OATDUMP --oat-file=$OATDIR/base.odex --header-only 2>/dev/null" \
                | grep -i 'compiler-filter' | head -1 | sed 's/.*= *//')"
        case "$filt" in
            verify|extract|assume-verified)
                echo "  $filt -> NOTHING COMPILED. All methods interpreted."
                echo "  Java hooks will land reliably. Ideal analysis state." ;;
            speed)
                echo "  $filt -> EVERYTHING COMPILED with aggressive inlining."
                echo "  Small methods may be inlined; hooks on them may silently miss."
                echo "  Consider: $0 verify $PKG" ;;
            speed-profile|space-profile)
                echo "  $filt -> PROFILE-SELECTED methods compiled."
                echo "  Mixed state. Hot methods are compiled and may be inlined."
                echo "  Consider: $0 verify $PKG" ;;
            *)
                echo "  $filt" ;;
        esac
    else
        echo "  (needs root and oatdump)"
        [[ -z "$OATDUMP" ]] && echo "  oatdump not found on device"
    fi

    hr "PROFILE"
    adbsh "cmd package snapshot-profile $PKG" >/dev/null
    local prof="/data/misc/profman/${PKG}-primary.prof"
    if have_root; then
        su_sh "ls -la $prof 2>/dev/null" | sed 's/^/  /'
    else
        adbsh "ls -la $prof 2>/dev/null" | sed 's/^/  /'
    fi
    echo "  (dump it with: $0 profile $PKG)"

    hr "DONE"
}

# ------------------------------------------------------------ state changes ---

do_verify() {
    check_installed
    echo "[*] Forcing $PKG to compiler-filter=verify (everything interpreted)"
    adbsh "cmd package compile -m verify -f $PKG"
    adbsh "am force-stop $PKG"
    echo "[+] Done. Java hooks should now land at every call site."
    echo
    adbsh "dumpsys package dexopt | grep -A4 \"\\[$PKG\\]\"" | sed 's/^/    /'
    echo
    echo "    Restore performance later with: $0 speed $PKG"
}

do_speed() {
    check_installed
    echo "[*] Forcing $PKG to compiler-filter=speed (full AOT, inlining)"
    adbsh "cmd package compile -m speed -f $PKG"
    adbsh "am force-stop $PKG"
    echo "[+] Done. This approximates a heavily-optimised user device."
    echo
    adbsh "dumpsys package dexopt | grep -A4 \"\\[$PKG\\]\"" | sed 's/^/    /'
}

do_reset() {
    check_installed
    echo "[*] Deleting compiled artifacts for $PKG"
    adbsh "cmd package compile --reset $PKG"
    adbsh "am force-stop $PKG"
    echo "[+] Done — returned to the post-install state."
    echo
    adbsh "dumpsys package dexopt | grep -A4 \"\\[$PKG\\]\"" | sed 's/^/    /'
}

# ----------------------------------------------------------------- extract ---

do_extract() {
    check_installed
    resolve_paths
    OUT="${3:-./dex_${PKG}}"
    OATDUMP="$(find_oatdump)"

    if ! have_root; then
        echo "error: root is required to read $OATDIR" >&2
        exit 3
    fi
    if [[ -z "$OATDUMP" ]]; then
        echo "error: oatdump not found on device" >&2
        exit 3
    fi

    echo "[*] Extracting DEX from $OATDIR/base.vdex"
    echo "    (the VDEX is where an installed app's bytecode actually lives)"

    su_sh "rm -rf /data/local/tmp/dex_out; mkdir -p /data/local/tmp/dex_out"
    su_sh "$OATDUMP --vdex-file=$OATDIR/base.vdex --export-dex-to=/data/local/tmp/dex_out"
    su_sh "chmod -R 777 /data/local/tmp/dex_out"

    echo "[*] Files produced on device:"
    su_sh "ls -la /data/local/tmp/dex_out" | sed 's/^/    /'

    mkdir -p "$OUT"
    adb pull /data/local/tmp/dex_out "$OUT" >/dev/null 2>&1
    echo "[+] Pulled to $OUT"
    ls -la "$OUT" 2>/dev/null | sed 's/^/    /'
    echo
    echo "    Decompile with:  jadx -d ${OUT}_decompiled ${OUT}/**/*.dex"
}

# ----------------------------------------------------------------- profile ---

do_profile() {
    check_installed
    resolve_paths
    echo "[*] Snapshotting profile for $PKG"
    adbsh "cmd package snapshot-profile $PKG"

    local prof="/data/misc/profman/${PKG}-primary.prof"
    local profman="/apex/com.android.art/bin/profman"

    echo "[*] Dumping (methods listed here ACTUALLY EXECUTED on this device)"
    if have_root; then
        su_sh "$profman --dump-only --profile-file=$prof --apk=$APK --dex-location=base.apk" \
            | head -100 | sed 's/^/    /'
    else
        adbsh "$profman --dump-only --profile-file=$prof" | head -100 | sed 's/^/    /'
    fi
    echo
    echo "    An empty profile means the app has not run enough yet."
    echo "    Launch it, use it for a minute, then re-run this command."
}

# -------------------------------------------------------------------- main ---

case "$CMD" in
    report)  do_report ;;
    verify)  do_verify ;;
    speed)   do_speed ;;
    reset)   do_reset ;;
    extract) do_extract "$@" ;;
    profile) do_profile ;;
    *)       echo "unknown command: $CMD" >&2; usage ;;
esac
