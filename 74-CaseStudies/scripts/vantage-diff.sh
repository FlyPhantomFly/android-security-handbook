#!/usr/bin/env bash
#
# vantage-diff.sh -- run the same question from root, from `shell`, and from an
#                    app uid, and print the three answers side by side.
#
# WHY THIS EXISTS
#   This repository's most repeated finding is that a measurement's ANSWER depends
#   on who asked. A detection probe verified from `adb shell` has not been
#   verified: `shell` is uid 2000, in the `shell` group, in the `shell` SELinux
#   domain, with a different visible property set and different group memberships
#   from any application.
#
#   This script is the instrument behind chapter 74 cases D and E. Case E -- a
#   published property count that does not reproduce -- was found by running
#   `--props` for the first time.
#
# USAGE
#   ./vantage-diff.sh -p <debuggable-pkg> [-s <serial>] --file <path>
#   ./vantage-diff.sh -p <debuggable-pkg> [-s <serial>] --cmd  "<command>"
#   ./vantage-diff.sh -p <debuggable-pkg> [-s <serial>] --prop <property>
#   ./vantage-diff.sh -p <debuggable-pkg> [-s <serial>] --props
#   ./vantage-diff.sh -p <debuggable-pkg> [-s <serial>] --paths <file-of-paths>
#   ./vantage-diff.sh --find-package [-s <serial>]
#
#   --file   stat one path from each vantage; classify PRESENT / ABSENT / FORBIDDEN
#   --paths  the same over a newline-separated list (comments with # are skipped)
#   --cmd    run an arbitrary command from each vantage and show all three outputs
#   --prop   read one property from each vantage
#   --props  diff the full property NAME SETS -- shell-only and app-only
#
# EXECUTED?
#   YES. Run against the AVD `sdk_gphone16k_x86_64` (emulator-5554, Android 15 /
#   API 35, Magisk 30.7) on 2026-08-16. Every table in chapter 74 sections 3.4.2
#   and 3.5.4, and every block in examples/reproduction-log.md sections 2 and 3,
#   is this script's output. All five modes were exercised.
#
# REQUIREMENTS
#   - adb on PATH.
#   - Root on the device for the root column. If root is unavailable the column
#     reads `n/a` and the rest of the script still works -- the shell/app
#     comparison is the important one and needs no privilege.
#   - ONE DEBUGGABLE PACKAGE for the app column. Use --find-package to locate one.
#
# THE CAVEAT THAT MUST TRAVEL WITH EVERY RESULT
#   The app column uses `run-as`, which gives the `runas_app` SELinux domain --
#   NOT `untrusted_app`, which is what a normally-installed application gets.
#   They are not the same domain.
#
#     A REFUSAL in the app column generalises: a real app has no more access.
#     A SUCCESS  in the app column does NOT: confirm with a purpose-built probe
#                APK before publishing it as a detection signal.
#
#   The script prints this on every run. Do not delete it from your notes.
#
# TWO TRAPS THIS SCRIPT HANDLES SO YOU DO NOT HAVE TO
#   1. `su -c '<cmd>'` versus `su 0 <cmd>`. Physical devices with Magisk take the
#      first; the AOSP emulator takes the second and rejects the first with
#      "su: invalid uid/gid '-c'", which reads exactly like an unrooted device.
#      Both are probed; whichever answers is used.
#   2. `adb shell` inherits stdin, so an `adb` call inside a `while read` loop
#      eats the loop's input. The loop then processes ONE item and exits cleanly,
#      looking exactly like a device with nothing on it. Every adb invocation
#      below redirects stdin from /dev/null.
#
# NOTE ON `set -o pipefail`
#   Deliberately NOT set. Combined with early-exit consumers (`head`, `grep -q`)
#   it turns successful matches into spurious failures, which has cost this
#   repository real debugging time twice. This script tests CONTENT, not exit
#   status.

set -u

SERIAL=""
PKG=""
MODE=""
ARG=""
ROOTFORM=""

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '3,60p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# ---------------------------------------------------------------- arguments --
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--serial)     SERIAL="${2:-}"; shift 2 ;;
        -p|--package)    PKG="${2:-}";    shift 2 ;;
        --file)          MODE="file";   ARG="${2:-}"; shift 2 ;;
        --paths)         MODE="paths";  ARG="${2:-}"; shift 2 ;;
        --cmd)           MODE="cmd";    ARG="${2:-}"; shift 2 ;;
        --prop)          MODE="prop";   ARG="${2:-}"; shift 2 ;;
        --props)         MODE="props";  shift ;;
        --find-package)  MODE="find";   shift ;;
        -h|--help)       usage 0 ;;
        *)               die "unknown argument: $1  (try --help)" ;;
    esac
done

[ -n "$MODE" ] || usage 1
command -v adb > /dev/null 2>&1 || die "adb is not on PATH"

# ------------------------------------------------------------ adb wrappers ---
# Every one redirects stdin. See trap 2 in the header.
A() {
    if [ -n "$SERIAL" ]; then
        adb -s "$SERIAL" shell "$@" < /dev/null 2>&1
    else
        adb shell "$@" < /dev/null 2>&1
    fi
}

detect_devices() {
    local n
    if [ -n "$SERIAL" ]; then return 0; fi
    n=$(adb devices < /dev/null 2>/dev/null | grep -c '	device$')
    if [ "$n" -gt 1 ]; then
        printf 'error: %s devices attached and no -s given.\n' "$n" >&2
        printf 'A silent wrong-device attach is the worst kind: every subsequent\n' >&2
        printf 'measurement is internally consistent and about the wrong target.\n\n' >&2
        adb devices -l < /dev/null >&2
        exit 1
    fi
    [ "$n" -eq 0 ] && die "no device attached"
}

# Probe both su conventions. See trap 1 in the header.
detect_root() {
    if A "su 0 id" | grep -q 'uid=0'; then
        ROOTFORM="zero"
    elif A "su -c id" | grep -q 'uid=0'; then
        ROOTFORM="dashc"
    else
        ROOTFORM="none"
    fi
}

as_root() {
    case "$ROOTFORM" in
        zero)  A "su 0 sh -c '$1'" ;;
        dashc) A "su -c 'sh -c \"$1\"'" ;;
        none)  printf 'n/a (no root)' ;;
    esac
}

as_shell() { A "$1"; }

as_app() {
    [ -n "$PKG" ] || { printf 'n/a (no -p package)'; return; }
    A "run-as $PKG sh -c '$1'"
}

# --------------------------------------------------------------- helpers -----
# Collapse a raw ls/stat result into one of four words. This is the whole point:
# `File.exists()` collapses ENOENT and EACCES into a single `false`, and the
# information that matters is in the distinction it discards.
classify() {
    case "$1" in
        *"No such file or directory"*) printf 'ABSENT'    ;;
        *"Permission denied"*)         printf 'FORBIDDEN' ;;
        *"n/a"*)                       printf 'n/a'       ;;
        "")                            printf 'ERROR'     ;;
        *)                             printf 'PRESENT'   ;;
    esac
}

banner() {
    printf '\n'
    printf '========================================================================\n'
    printf ' vantage-diff  --  %s\n' "$1"
    printf ' device : %s\n' "${SERIAL:-<only device attached>}"
    printf ' root   : %s\n' "$(case $ROOTFORM in
                                 zero)  echo 'yes (su 0 <cmd>)';;
                                 dashc) echo 'yes (su -c)';;
                                 *)     echo 'NO -- root column will read n/a';;
                               esac)"
    printf ' app    : %s\n' "${PKG:-<none given -- app column will read n/a>}"
    printf '========================================================================\n'
}

caveat() {
    cat <<'EOF'

------------------------------------------------------------------------
CAVEAT -- carry this with every result above.

The app column is `run-as`, i.e. the `runas_app` SELinux domain. A normally
installed application runs as `untrusted_app`, which is NOT the same domain.

  A REFUSAL in the app column generalises to a real app -- it has no more
  access than runas_app, so a FORBIDDEN here is FORBIDDEN there.

  A SUCCESS does NOT generalise. Confirm with a purpose-built probe APK
  before publishing it as a detection signal.

Any path reading FORBIDDEN from the app is a path an app-side
`new File(p).exists()` can only ever answer `false` about -- whatever is
actually there. Such a check has no discriminating power.
------------------------------------------------------------------------
EOF
}

# ----------------------------------------------------------------- modes -----
mode_find() {
    printf 'Debuggable third-party packages (usable with -p):\n\n'
    A "pm list packages -3" | tr -d '\r' | sed 's/^package://' | while IFS= read -r p; do
        [ -n "$p" ] || continue
        if A "run-as $p id" | grep -q 'uid='; then
            printf '  OK           %s\n' "$p"
        else
            printf '  not usable   %s\n' "$p"
        fi
    done
    printf '\nIf none is usable, build a minimal debuggable APK, or run the shell\n'
    printf 'column alone and label every result as a shell measurement.\n'
}

mode_file() {
    local p="$1" r s a
    r=$(as_root  "ls -ld $p" | tr -d '\r')
    s=$(as_shell "ls -ld $p" | tr -d '\r')
    a=$(as_app   "ls -ld $p" | tr -d '\r')
    printf '%-40s  %-10s %-10s %-10s\n' "$p" \
        "$(classify "$r")" "$(classify "$s")" "$(classify "$a")"
}

mode_paths() {
    local f="$1"
    [ -f "$f" ] || die "no such file: $f"
    printf '%-40s  %-10s %-10s %-10s\n' "PATH" "ROOT" "SHELL" "APP"
    printf '%-40s  %-10s %-10s %-10s\n' "----" "----" "-----" "---"
    # Read the whole list first: see trap 2. Reading into an array-free loop over
    # a here-string keeps adb away from the loop's stdin entirely.
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        mode_file "$line"
    done <<EOF
$(cat "$f")
EOF
}

mode_cmd() {
    local c="$1"
    printf -- '--- as root ------------------------------------------------------\n'
    as_root  "$c" | tr -d '\r'
    printf -- '--- as shell (uid 2000) ------------------------------------------\n'
    as_shell "$c" | tr -d '\r'
    printf -- '--- as app uid (run-as) ------------------------------------------\n'
    as_app   "$c" | tr -d '\r'
}

mode_prop() {
    local p="$1" r s a
    r=$(as_root  "getprop $p" | tr -d '\r')
    s=$(as_shell "getprop $p" | tr -d '\r')
    a=$(as_app   "getprop $p" | tr -d '\r')
    printf '%-34s | %-20s | %-20s | %s\n' "PROPERTY" "ROOT" "SHELL" "APP"
    printf '%-34s | %-20s | %-20s | %s\n' \
        "$p" "${r:-(empty)}" "${s:-(empty)}" "${a:-(empty)}"
    printf '\nSELinux type: %s\n' "$(as_shell "getprop -Z $p" | tr -d '\r')"
    printf '\nAn (empty) in the APP column for a property that is populated for\n'
    printf 'root or shell means detection code inside an app cannot read it.\n'
    printf 'Written the usual way -- "1".equals(get(p)) -- such a check FAILS OPEN.\n'
}

mode_props() {
    local tmp shell_f app_f root_f
    tmp=$(mktemp -d) || die "mktemp failed"
    shell_f="$tmp/shell.txt"; app_f="$tmp/app.txt"; root_f="$tmp/root.txt"

    as_shell "getprop" | tr -d '\r' | sed -n 's/^\[\([^]]*\)\].*/\1/p' | sort -u > "$shell_f"
    as_app   "getprop" | tr -d '\r' | sed -n 's/^\[\([^]]*\)\].*/\1/p' | sort -u > "$app_f"
    as_root  "getprop" | tr -d '\r' | sed -n 's/^\[\([^]]*\)\].*/\1/p' | sort -u > "$root_f"

    printf 'unique property NAMES visible per vantage\n'
    printf '  root  : %s\n' "$(wc -l < "$root_f"  | tr -d ' ')"
    printf '  shell : %s\n' "$(wc -l < "$shell_f" | tr -d ' ')"
    printf '  app   : %s\n' "$(wc -l < "$app_f"   | tr -d ' ')"

    printf '\nNames are counted, not output lines. A count of LINES is inflated by\n'
    printf 'multi-line values and is not comparable between runs.\n'

    printf '\n--- visible to SHELL, invisible to the APP -----------------------\n'
    comm -23 "$shell_f" "$app_f" | tee "$tmp/shell_only.txt"
    printf '  (%s names)\n' "$(wc -l < "$tmp/shell_only.txt" | tr -d ' ')"

    printf '\n--- visible to the APP, invisible to SHELL -----------------------\n'
    comm -13 "$shell_f" "$app_f" | tee "$tmp/app_only.txt"
    printf '  (%s names)\n' "$(wc -l < "$tmp/app_only.txt" | tr -d ' ')"

    printf '\nCONTROL: the app-only count SHOULD be 0. The app domain holds strictly\n'
    printf 'fewer property-read permissions than shell, so its view must be a\n'
    printf 'subset. A non-zero value there means THIS MEASUREMENT is broken --\n'
    printf 'check it before you read anything into the other column.\n'

    printf '\n--- integrity properties commonly read by detection code ---------\n'
    printf '%-34s | %-20s | %-20s | %s\n' "PROPERTY" "ROOT" "SHELL" "APP"
    for p in ro.debuggable ro.secure ro.build.tags ro.build.type \
             partition.system.verified ro.serialno \
             ro.boot.verifiedbootstate ro.boot.veritymode ro.boot.flash.locked; do
        r=$(as_root  "getprop $p" | tr -d '\r')
        s=$(as_shell "getprop $p" | tr -d '\r')
        a=$(as_app   "getprop $p" | tr -d '\r')
        printf '%-34s | %-20s | %-20s | %s\n' \
            "$p" "${r:-(empty)}" "${s:-(empty)}" "${a:-(empty)}"
    done

    rm -rf "$tmp"
}

# ------------------------------------------------------------------ main -----
detect_devices
detect_root

case "$MODE" in
    find)  banner "find a debuggable package"; mode_find ;;
    file)  banner "single path"
           printf '%-40s  %-10s %-10s %-10s\n' "PATH" "ROOT" "SHELL" "APP"
           printf '%-40s  %-10s %-10s %-10s\n' "----" "----" "-----" "---"
           mode_file "$ARG"; caveat ;;
    paths) banner "path list"; mode_paths "$ARG"; caveat ;;
    cmd)   banner "command: $ARG"; mode_cmd "$ARG"; caveat ;;
    prop)  banner "property: $ARG"; mode_prop "$ARG"; caveat ;;
    props) banner "full property namespace diff"; mode_props; caveat ;;
esac
