#!/usr/bin/env bash
# scripts/lsposed-footprint.sh
#
# PURPOSE
#   Establish, in one run, the device posture that every claim about LSPosed
#   depends on — and print it in a form you can paste into the methodology
#   section of a report.
#
#   It answers seven questions, in dependency order, because each one is
#   meaningless without the ones above it:
#
#     1. Which device is this, and at what API level?
#     2. Is it rooted, and by what?              (Magisk / KernelSU / APatch / AOSP su)
#     3. Is ZYGISK enabled?                      (LSPosed cannot exist without it)
#     4. Which Magisk/Zygisk modules are installed?
#     5. Is LSPosed among them, and is lspd in system_server?
#     6. What can an APP UID actually see of all this?
#     7. What would a naive detector conclude, and would it be right?
#
#   Question 6 is the one this script exists for.  Almost every published
#   root/hook-detection list is written from `adb shell`, which is uid 2000 in
#   the `shell` SELinux domain and is NOT an app.  This repository's standing
#   rule is: prove reachability from an app, not from the shell.  This script
#   runs the same probe set three ways — root, shell, and an app uid via
#   `run-as` — and prints the three answers side by side.
#
# USAGE
#   ./lsposed-footprint.sh [options]
#
#     --serial SERIAL     adb -s SERIAL.  Default: the only attached device,
#                         or fail loudly if there is more than one.  ALWAYS
#                         pass this if more than one device is attached — a
#                         silent wrong-device attach is the worst kind, because
#                         every subsequent measurement is internally consistent
#                         and about the wrong target.
#     --as-package PKG    A DEBUGGABLE package to run the app-uid probes
#                         through.  Without it, section 6 is skipped and says
#                         so rather than substituting shell results.
#     --json              Emit machine-readable output instead of the report.
#     --no-root           Skip every probe that needs root.
#     -h, --help          This text.
#
# EXAMPLES
#   ./lsposed-footprint.sh --serial emulator-5554
#   ./lsposed-footprint.sh --serial emulator-5554 --as-package com.pentest.ch63.vault
#   ./lsposed-footprint.sh --json > posture.json
#
# WHAT IT DOES NOT DO
#   It installs nothing, enables nothing, and writes nothing to the device.
#   Every command is a read.  That is deliberate: posture enumeration runs on
#   devices you have not been given permission to change.
#
# NOTE ON `su`
#   Two calling conventions exist and they are not compatible:
#       su -c '<command>'      most physical devices, Magisk's su
#       su 0 <command>         the AOSP emulator's su
#   The `-c` form fails on an emulator with `su: invalid uid/gid '-c'`, which
#   reads as "not rooted" and has caused at least one chapter in this
#   repository to nearly record a rooted device as unrooted.  This script tries
#   BOTH and reports which one worked.
#
set -uo pipefail

SERIAL=""
AS_PKG=""
JSON=0
NO_ROOT=0

usage() { sed -n '2,55p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --serial)      SERIAL="${2:-}"; shift 2 ;;
        --as-package)  AS_PKG="${2:-}"; shift 2 ;;
        --json)        JSON=1; shift ;;
        --no-root)     NO_ROOT=1; shift ;;
        -h|--help)     usage ;;
        *) printf 'unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
    esac
done

command -v adb >/dev/null 2>&1 || { echo "adb not on PATH" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Device selection.  Refuse to guess.
# ---------------------------------------------------------------------------
if [ -z "$SERIAL" ]; then
    n=$(adb devices | awk 'NR>1 && $2=="device"' | wc -l | tr -d ' ')
    if [ "$n" = 0 ]; then echo "no device in state 'device'" >&2; exit 2; fi
    if [ "$n" != 1 ]; then
        echo "more than one device attached; pass --serial. Attached:" >&2
        adb devices -l >&2
        exit 2
    fi
    SERIAL=$(adb devices | awk 'NR>1 && $2=="device" {print $1; exit}')
fi

A() { adb -s "$SERIAL" "$@"; }
sh_() { A shell "$@" 2>&1; }

# ---------------------------------------------------------------------------
# Root, and which su convention works.
# ---------------------------------------------------------------------------
SU_STYLE="none"
if [ "$NO_ROOT" = 0 ]; then
    if A shell 'su 0 id' 2>/dev/null | grep -q 'uid=0'; then
        SU_STYLE="su0"
    elif A shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
        SU_STYLE="suc"
    fi
fi

# Run a command as root using whichever convention works.  Empty output and a
# non-zero status if there is no root.
R() {
    case "$SU_STYLE" in
        su0) A shell "su 0 sh -c '$*'" 2>&1 ;;
        suc) A shell "su -c '$*'"      2>&1 ;;
        *)   return 1 ;;
    esac
}

# Run a command as the app uid, through run-as.  Requires --as-package.
APP() {
    [ -n "$AS_PKG" ] || return 1
    A shell "run-as $AS_PKG sh -c '$*'" 2>&1
}

# ---------------------------------------------------------------------------
# Collection.
# ---------------------------------------------------------------------------
MODEL=$(sh_ getprop ro.product.model      | tr -d '\r')
SDK=$(sh_   getprop ro.build.version.sdk  | tr -d '\r')
RELEASE=$(sh_ getprop ro.build.version.release | tr -d '\r')
ABI=$(sh_   getprop ro.product.cpu.abi    | tr -d '\r')
BTYPE=$(sh_ getprop ro.build.type         | tr -d '\r')
FP=$(sh_    getprop ro.build.fingerprint  | tr -d '\r')

# Which rooting stack?  Note that these are not mutually exclusive and that
# 62-Magisk records a device where the SELinux context said `magisk` while the
# actual implementation was APatch.  Report the evidence, not a verdict.
ROOT_KIND="unknown"
MAGISK_VER=""
MAGISK_BIN=""
if [ "$SU_STYLE" != "none" ]; then
    for cand in /debug_ramdisk/magisk /sbin/magisk /data/adb/magisk/magisk magisk; do
        v=$(R "$cand -v" 2>/dev/null | tr -d '\r')
        case "$v" in
            *MAGISK*) MAGISK_VER="$v"; MAGISK_BIN="$cand"; ROOT_KIND="magisk"; break ;;
        esac
    done
    [ -z "$MAGISK_VER" ] && {
        if R 'ls /data/adb/ksu' >/dev/null 2>&1; then ROOT_KIND="kernelsu"
        elif R 'ls /data/adb/ap'  >/dev/null 2>&1; then ROOT_KIND="apatch"
        else ROOT_KIND="su-present-unidentified"; fi
    }
fi
MAGISK_CODE=""
[ -n "$MAGISK_BIN" ] && MAGISK_CODE=$(R "$MAGISK_BIN -V" | tr -d '\r')

# Zygisk.  TWO independent checks, because the settings row can simply be
# absent, which means "default", not "off".
ZYG_ROW=""
ZYG_MAPS=""
ZYGOTE_PID=""
if [ "$SU_STYLE" != "none" ] && [ -n "$MAGISK_BIN" ]; then
    # NOTE ON QUOTING.  R() wraps its argument in SINGLE quotes for the device
    # shell, so any pattern here must use DOUBLE quotes.  A single-quoted
    # alternation such as 'a|b' terminates the outer quoting early and the `|`
    # is then read by the device shell as a PIPE — which silently turns
    # `grep -icE 'a|b' file` into `grep -icE a` piped into `b file`.  That bug
    # produced "b: inaccessible or not found" in an early run of this script
    # and would otherwise have been mistaken for a missing path.
    ZYG_ROW=$(R "$MAGISK_BIN --sqlite \"select * from settings\"" | tr -d '\r' | grep -i zygisk)
    ZYGOTE_PID=$(R 'pidof zygote64' | tr -d '\r' | awk '{print $1}')
    [ -z "$ZYGOTE_PID" ] && ZYGOTE_PID=$(R 'pidof zygote' | tr -d '\r' | awk '{print $1}')
    if [ -n "$ZYGOTE_PID" ]; then
        ZYG_MAPS=$(R "grep -icE \"zygisk\" /proc/$ZYGOTE_PID/maps" | tr -d '\r')
    fi
fi
ZYGISK="off-or-unknown"
if [ -n "$ZYG_MAPS" ] && [ "$ZYG_MAPS" != "0" ]; then ZYGISK="ON (mapped in zygote)"
elif printf '%s' "$ZYG_ROW" | grep -qE 'value *= *1'; then ZYGISK="settings row says ON but no mapping in zygote — investigate"
elif [ "$SU_STYLE" != "none" ]; then ZYGISK="off (no zygisk mapping in zygote, no settings row)"
fi

# Module store.
MODULES=""
MODULE_COUNT=0
if [ "$SU_STYLE" != "none" ]; then
    MODULES=$(R 'for d in /data/adb/modules/*/; do [ -d "$d" ] || continue; n=$(basename $d); v=$(grep -h "^name=" $d/module.prop 2>/dev/null | head -1); echo "$n | $v"; done' | tr -d '\r' | grep -v '^\s*$')
    MODULE_COUNT=$(printf '%s' "$MODULES" | grep -c . || true)
fi

# LSPosed specifically.
LSP_MODULE=$(printf '%s' "$MODULES" | grep -ciE 'lsposed|riru.*ed|edxposed' || true)
LSP_DIRS=""
LSPD_IN_SS=""
SS_PID=""
if [ "$SU_STYLE" != "none" ]; then
    LSP_DIRS=$(R 'ls -d /data/adb/lspd /data/adb/lspd.db /data/adb/modules/*lsposed* 2>/dev/null' | tr -d '\r' | grep -v 'No such' || true)
    SS_PID=$(R 'pidof system_server' | tr -d '\r' | awk '{print $1}')
    # Double quotes — see the quoting note in the Zygisk block above.
    [ -n "$SS_PID" ] && LSPD_IN_SS=$(R "grep -icE \"lspd|lsposed|xposed\" /proc/$SS_PID/maps" | tr -d '\r')
fi

# Installed packages that a naive detector would look for.
PKGS=$(sh_ 'pm list packages' | tr -d '\r' | grep -iE 'lsposed|xposed|magisk|kernelsu|apatch' || true)

# ---------------------------------------------------------------------------
# The three-viewpoint probe.  This is the part that matters.
# ---------------------------------------------------------------------------
PROBE_PATHS="/data/adb /data/adb/modules /data/adb/lspd /debug_ramdisk /debug_ramdisk/magisk /sbin/su /system/xbin/su /system/bin/su /system/framework/XposedBridge.jar"

# Classify a path from one viewpoint: PRESENT / EACCES / ENOENT / n-a
classify_shell() {
    out=$(A shell "ls -ld '$1'" 2>&1 | tr -d '\r')
    case "$out" in
        *"No such file"*)      echo "ENOENT" ;;
        *"Permission denied"*) echo "EACCES" ;;
        *)                     echo "PRESENT" ;;
    esac
}
classify_app() {
    [ -n "$AS_PKG" ] || { echo "n-a"; return; }
    out=$(A shell "run-as $AS_PKG ls -ld '$1'" 2>&1 | tr -d '\r')
    case "$out" in
        *"No such file"*)      echo "ENOENT" ;;
        *"Permission denied"*) echo "EACCES" ;;
        *"not debuggable"*|*"Unknown package"*|*"not an application"*) echo "run-as-refused" ;;
        *)                     echo "PRESENT" ;;
    esac
}
classify_root() {
    [ "$SU_STYLE" != "none" ] || { echo "n-a"; return; }
    out=$(R "ls -ld '$1'" | tr -d '\r')
    case "$out" in
        *"No such file"*)      echo "ENOENT" ;;
        *"Permission denied"*) echo "EACCES" ;;
        *)                     echo "PRESENT" ;;
    esac
}

# mountinfo is readable by everyone and is the single loudest signal.
MOUNT_SHELL=$(A shell "grep -icE 'magisk|zygisk|lsposed' /proc/self/mountinfo" 2>&1 | tr -d '\r')
MOUNT_APP="n-a"
[ -n "$AS_PKG" ] && MOUNT_APP=$(A shell "run-as $AS_PKG sh -c \"grep -icE 'magisk|zygisk|lsposed' /proc/self/mountinfo\"" 2>&1 | tr -d '\r')

# ---------------------------------------------------------------------------
# Output.
# ---------------------------------------------------------------------------
if [ "$JSON" = 1 ]; then
    esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\n' ' '; }
    printf '{\n'
    printf '  "serial": "%s",\n'        "$(esc "$SERIAL")"
    printf '  "model": "%s",\n'         "$(esc "$MODEL")"
    printf '  "sdk": "%s",\n'           "$(esc "$SDK")"
    printf '  "release": "%s",\n'       "$(esc "$RELEASE")"
    printf '  "abi": "%s",\n'           "$(esc "$ABI")"
    printf '  "build_type": "%s",\n'    "$(esc "$BTYPE")"
    printf '  "su_style": "%s",\n'      "$(esc "$SU_STYLE")"
    printf '  "root_kind": "%s",\n'     "$(esc "$ROOT_KIND")"
    printf '  "magisk_version": "%s",\n' "$(esc "$MAGISK_VER")"
    printf '  "magisk_code": "%s",\n'   "$(esc "$MAGISK_CODE")"
    printf '  "zygisk": "%s",\n'        "$(esc "$ZYGISK")"
    printf '  "module_count": %s,\n'    "${MODULE_COUNT:-0}"
    printf '  "lsposed_module_hits": %s,\n' "${LSP_MODULE:-0}"
    printf '  "lspd_in_system_server": "%s",\n' "$(esc "${LSPD_IN_SS:-n-a}")"
    printf '  "mountinfo_hits_shell": "%s",\n' "$(esc "$MOUNT_SHELL")"
    printf '  "mountinfo_hits_app": "%s",\n'   "$(esc "$MOUNT_APP")"
    printf '  "paths": {\n'
    first=1
    for p in $PROBE_PATHS; do
        [ $first = 1 ] || printf ',\n'; first=0
        printf '    "%s": {"root": "%s", "shell": "%s", "app": "%s"}' \
            "$p" "$(classify_root "$p")" "$(classify_shell "$p")" "$(classify_app "$p")"
    done
    printf '\n  }\n}\n'
    exit 0
fi

hr() { printf '%s\n' "----------------------------------------------------------------------"; }

printf '\n'
hr
printf 'LSPosed / Zygisk footprint — %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
hr
printf '\n== 1. DEVICE ==\n'
printf '  serial        %s\n' "$SERIAL"
printf '  model         %s\n' "$MODEL"
printf '  release/sdk   %s / %s\n' "$RELEASE" "$SDK"
printf '  abi           %s\n' "$ABI"
printf '  build type    %s\n' "$BTYPE"
printf '  fingerprint   %s\n' "$FP"

printf '\n== 2. ROOT ==\n'
case "$SU_STYLE" in
    su0)  printf '  su convention  su 0 <cmd>      (the AOSP/emulator form)\n' ;;
    suc)  printf '  su convention  su -c "<cmd>"   (Magisk / most phones)\n' ;;
    none) printf '  su convention  NONE — no root, or both forms refused\n' ;;
esac
printf '  root kind      %s\n' "$ROOT_KIND"
[ -n "$MAGISK_VER" ]  && printf '  magisk -v      %s\n' "$MAGISK_VER"
[ -n "$MAGISK_CODE" ] && printf '  magisk -V      %s\n' "$MAGISK_CODE"
[ -n "$MAGISK_BIN" ]  && printf '  magisk binary  %s\n' "$MAGISK_BIN"
if [ "$SU_STYLE" = "none" ]; then
    printf '\n  [!] Both su conventions failed.  That is USUALLY "not rooted", but\n'
    printf '      verify before you record it: an emulator whose su takes `su 0`\n'
    printf '      fails the `-c` form with an error that reads like absence.\n'
fi

printf '\n== 3. ZYGISK  (LSPosed cannot run without it) ==\n'
printf '  verdict        %s\n' "$ZYGISK"
printf '  settings row   %s\n' "${ZYG_ROW:-<absent — means DEFAULT, not OFF>}"
printf '  zygote pid     %s\n' "${ZYGOTE_PID:-<unknown>}"
printf '  zygisk in maps %s\n' "${ZYG_MAPS:-<not checked>}"

printf '\n== 4. MODULE STORE ==\n'
if [ "$SU_STYLE" = "none" ]; then
    printf '  <needs root>\n'
elif [ "${MODULE_COUNT:-0}" = 0 ]; then
    printf '  /data/adb/modules is EMPTY — no Magisk/Zygisk modules installed\n'
else
    printf '%s\n' "$MODULES" | sed 's/^/  /'
fi

printf '\n== 5. LSPOSED ==\n'
printf '  module-store hits    %s\n' "${LSP_MODULE:-0}"
printf '  lsp paths            %s\n' "${LSP_DIRS:-<none>}"
printf '  system_server pid    %s\n' "${SS_PID:-<unknown>}"
printf '  lspd/xposed in its maps  %s\n' "${LSPD_IN_SS:-<not checked>}"
printf '  packages a naive detector would find:\n'
if [ -z "$PKGS" ]; then printf '    <none>\n'; else printf '%s\n' "$PKGS" | sed 's/^/    /'; fi

printf '\n== 6. WHAT EACH VIEWPOINT CAN SEE ==\n'
if [ -z "$AS_PKG" ]; then
    printf '  [!] No --as-package given, so the APP column is "n-a".\n'
    printf '      Shell is uid 2000 in the `shell` SELinux domain and is NOT an app.\n'
    printf '      Do not publish a shell result as an app-reachable detection signal.\n\n'
fi
printf '  %-40s %-10s %-10s %-10s\n' "PATH" "ROOT" "SHELL" "APP"
printf '  %-40s %-10s %-10s %-10s\n' "----" "----" "-----" "---"
for p in $PROBE_PATHS; do
    printf '  %-40s %-10s %-10s %-10s\n' "$p" \
        "$(classify_root "$p")" "$(classify_shell "$p")" "$(classify_app "$p")"
done
printf '\n  Note: the table uses `ls -ld`, i.e. STAT the path, not LIST it.  A\n'
printf '  directory can be stat-able and unlistable at the same time —\n'
printf '  /debug_ramdisk is mode 0711 on the reference device, so every column\n'
printf '  reads PRESENT while `ls /debug_ramdisk` is refused to shell and app\n'
printf '  alike.  Path-guessing beats directory listing, and that is exactly\n'
printf '  how an app uid can read /debug_ramdisk/magisk.\n'
printf '\n  /proc/self/mountinfo lines matching magisk|zygisk|lsposed:\n'
printf '    shell: %s\n' "$MOUNT_SHELL"
printf '    app  : %s\n' "$MOUNT_APP"

printf '\n== 7. WHAT A NAIVE DETECTOR WOULD CONCLUDE ==\n'
naive_adb=$(classify_app /data/adb)
printf '  new File("/data/adb").exists()  from an app -> '
case "$naive_adb" in
    EACCES) printf 'FALSE  (path exists, access refused — the check is WRONG)\n' ;;
    ENOENT) printf 'false  (genuinely absent)\n' ;;
    PRESENT) printf 'true\n' ;;
    *)      printf '%s\n' "$naive_adb" ;;
esac
printf '  reason: File.exists() maps BOTH ENOENT and EACCES to false.  A check\n'
printf '          written that way cannot distinguish "absent" from "forbidden",\n'
printf '          and /data/adb is forbidden to every app on a rooted device.\n'
printf '\n  The signal that DOES survive an app uid with no permissions at all is\n'
printf '  /proc/self/mountinfo (see section 6).  It proves the ROOT SUBSTRATE,\n'
printf '  not LSPosed — those are different questions with different answers.\n'
hr
printf '\n'
