#!/usr/bin/env bash
# 73-Labs/scripts/lab-doctor.sh
#
# PURPOSE
#   Triage for "the lab does not work". It runs the checks that resolve the most
#   cases soonest, in that order, and prints a verdict you can paste into a
#   divergence report.
#
#   This is the most common reader experience in this repository and it is
#   barely addressed anywhere, because each chapter reasonably assumes its own
#   lab works. The aggregator can afford to assume it does not.
#
#   The checks, in the order this repository's own divergence record says they
#   pay off:
#
#     1. Is a device attached, and WHICH one?      most "it does not work"
#     2. Which `su` form does it take?             reads exactly like "no root"
#     3. Does frida-server actually RUN?           a host version proves nothing
#     4. Is the lab's declared setup your setup?   header versus reality
#     5. Do the paths the lab promises exist?      a broken lab, not a broken you
#     6. Is your vantage the lab's vantage?        the number one cause
#
# USAGE
#   # host -- general triage, no lab in mind
#   ./lab-doctor.sh
#
#   # host -- triage a specific lab, comparing its header to your setup
#   ./lab-doctor.sh --lab ../../27-ContentProviders/labs/lab-01-enumerate.md
#
#   # host -- also check every path the lab promises
#   ./lab-doctor.sh --lab <path> --paths
#
#   # host -- skip device checks (offline)
#   ./lab-doctor.sh --no-device
#
# WAS THIS EXECUTED?
#   YES. Run on 2026-08-16 from Git Bash on Windows 11 against the AVD
#   `sdk_gphone16k_x86_64` (emulator-5554, Android 15 / API 35, rooted with
#   Magisk 30.7), both with and without --lab. Measured output is reproduced in
#   ../labs/lab-03-write-a-lab-that-survives.md section 7.
#
#   On that run it reported, correctly: device attached; `su 0 <cmd>` is the
#   working form and `su -c` fails with `su: invalid uid/gid '-c'`; frida-server
#   present but CANNOT LINK; no bootloader partitions.
#
# WHY THERE IS NO `set -e` AND NO `set -o pipefail`
#   Every check here is EXPECTED to fail sometimes -- that is the whole point of
#   a diagnostic. `set -e` would abort on the first informative failure.
#   `set -o pipefail` additionally turns `... | head -1` into a spurious failure
#   when head closes the pipe early and the writer gets SIGPIPE, which has cost
#   this repository real time. Every check below tests CONTENT, never an exit
#   status.
#
# EXIT STATUS
#   0 if no blocking problem was found; 1 if at least one check reported a
#   problem that would stop a lab from running.

set -u

LAB=""
CHECK_PATHS=0
NO_DEVICE=0
PROBLEMS=0

while [ $# -gt 0 ]; do
    case "$1" in
        --lab)        shift; LAB="${1:-}" ;;
        --paths)      CHECK_PATHS=1 ;;
        --no-device)  NO_DEVICE=1 ;;
        -h|--help)    sed -n '2,60p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

HERE="$(cd "$(dirname "$0")" && pwd)"
CHAPTER="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

hdr()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  [ ok ] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; PROBLEMS=$((PROBLEMS + 1)); }
note() { printf '         %s\n' "$*"; }

# --------------------------------------------------------------------------- #
# 1. Which device, if any
# --------------------------------------------------------------------------- #
SERIAL=""
if [ "$NO_DEVICE" -eq 1 ]; then
    hdr "1. device  (skipped, --no-device)"
elif ! command -v adb >/dev/null 2>&1; then
    hdr "1. device"
    bad "adb is not on PATH"
    note "Nothing device-side can be diagnosed. See 00-Introduction lab 01."
else
    hdr "1. device"
    LIST="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device" {print $1}')"
    COUNT="$(printf '%s\n' "$LIST" | grep -c '[^[:space:]]')"
    if [ "$COUNT" -eq 0 ]; then
        bad "no device in \`adb devices\`"
        note "Start your emulator or reconnect the handset, then re-run."
    else
        SERIAL="$(printf '%s\n' "$LIST" | head -1)"
        ok "$COUNT attached; using $SERIAL"
        if [ "$COUNT" -gt 1 ]; then
            note "MORE THAN ONE DEVICE. Most labs omit -s <serial> and will pick"
            note "whichever adb prefers. Set ANDROID_SERIAL, or pass -s yourself."
            note "A silent wrong-device attach is the worst kind: every"
            note "measurement after it is internally consistent and about the"
            note "wrong target."
        fi
        MODEL="$(adb -s "$SERIAL" shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
        API="$(adb -s "$SERIAL" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
        REL="$(adb -s "$SERIAL" shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')"
        ABI="$(adb -s "$SERIAL" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
        TYPE="$(adb -s "$SERIAL" shell getprop ro.build.type 2>/dev/null | tr -d '\r')"
        note "$MODEL  Android $REL / API $API  $ABI  $TYPE"
        note "Quote that line in any divergence report."
    fi
fi

# --------------------------------------------------------------------------- #
# 2. The su form. Getting this wrong reads exactly like "not rooted".
# --------------------------------------------------------------------------- #
SU_FORM=""
if [ -n "$SERIAL" ]; then
    hdr "2. root, and which su form"
    ZERO="$(adb -s "$SERIAL" shell "su 0 id" 2>&1 | tr -d '\r')"
    DASH="$(adb -s "$SERIAL" shell "su -c id" 2>&1 | tr -d '\r')"
    # Test CONTENT, not exit status: both forms can exit 0 while failing.
    if printf '%s' "$ZERO" | grep -q 'uid=0'; then
        SU_FORM="su 0 <cmd>"
        ok "rooted; working form is:  su 0 <cmd>"
        note "\`su -c\` on this device says: $(printf '%s' "$DASH" | head -1)"
    elif printf '%s' "$DASH" | grep -q 'uid=0'; then
        SU_FORM="su -c <cmd>"
        ok "rooted; working form is:  adb shell \"su -c 'cmd'\""
        note "\`su 0\` on this device says: $(printf '%s' "$ZERO" | head -1)"
    else
        bad "no root by either form"
        note "su 0  -> $(printf '%s' "$ZERO" | head -1)"
        note "su -c -> $(printf '%s' "$DASH" | head -1)"
        note "If you believe this device IS rooted, that is the finding: one of"
        note "the two forms above is the one your rooting stack wants."
    fi
    note "NEVER write \`adb shell su -c 'cmd'\` unquoted. The outer shell strips"
    note "the quotes and su eats the flag."
fi

# --------------------------------------------------------------------------- #
# 3. frida-server, tested by running it
# --------------------------------------------------------------------------- #
if [ -n "$SERIAL" ]; then
    hdr "3. frida"
    if command -v frida >/dev/null 2>&1; then
        ok "host frida $(frida --version 2>&1 | head -1)"
    else
        note "no host frida; every Frida lab is out of reach regardless"
    fi
    LS="$(adb -s "$SERIAL" shell "ls /data/local/tmp" 2>&1 | tr -d '\r')"
    if printf '%s' "$LS" | grep -q 'frida-server'; then
        if [ -n "$SU_FORM" ] && [ "$SU_FORM" = "su 0 <cmd>" ]; then
            VER="$(adb -s "$SERIAL" shell "su 0 /data/local/tmp/frida-server --version" 2>&1 | tr -d '\r')"
        else
            VER="$(adb -s "$SERIAL" shell "/data/local/tmp/frida-server --version" 2>&1 | tr -d '\r')"
        fi
        if printf '%s' "$VER" | grep -q 'CANNOT LINK'; then
            bad "frida-server is present but does NOT run"
            note "$(printf '%s' "$VER" | grep 'CANNOT LINK' | head -1)"
            note "This is a frida-version problem, not a root problem. Replace"
            note "the binary with a build matching this image's linker."
            note "NOTE: \`frida-ps -U\` may STILL list processes. It is not a test."
        elif printf '%s' "$VER" | grep -qE '^[0-9]+\.[0-9]+'; then
            ok "frida-server runs: $(printf '%s' "$VER" | head -1)"
        else
            bad "frida-server present but its version output is unrecognisable"
            note "$(printf '%s' "$VER" | tail -1)"
        fi
    else
        note "no frida-server in /data/local/tmp"
    fi
fi

# --------------------------------------------------------------------------- #
# 4. The lab's own declared setup, against yours
# --------------------------------------------------------------------------- #
if [ -n "$LAB" ]; then
    hdr "4. the lab's declared contract"
    if [ ! -f "$LAB" ]; then
        bad "no such lab: $LAB"
    else
        ok "reading $LAB"
        grep -m1 -iE '^\s*>?\s*\*\*(Difficulty|Level)' "$LAB" | sed 's/^/         /'
        grep -m1 -iE '^\s*>?\s*\*\*Time'                "$LAB" | sed 's/^/         /'
        grep -m1 -iE '^\s*>?\s*\*\*Requires'            "$LAB" | sed 's/^/         /'
        grep -m1 -iE '^\s*>?\s*\*\*Device used'         "$LAB" | sed 's/^/         /'

        VERIFIED="$(grep -m1 -iE '^\s*>?\s*\*\*Device used' "$LAB")"
        if [ -z "$VERIFIED" ]; then
            note "This lab does not say which device it was verified on."
            note "That limits what a divergence against it can establish."
        elif [ -n "${API:-}" ]; then
            if printf '%s' "$VERIFIED" | grep -q "API $API"; then
                ok "your API level matches the one the lab was verified on"
            else
                note "Your device is API $API. The lab names a different one."
                note "That is cause 2 in the divergence ranking, and it is"
                note "enough on its own to explain a different result."
            fi
        fi

        hdr "4b. what the index derives from this lab"
        if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi
        # The index keys labs by their path relative to the repository root, so
        # a relative --lab argument has to be resolved to absolute FIRST. Doing
        # the prefix strip on the raw argument silently produced a
        # "no indexed lab matching ../27-..." error for every relative path.
        ABS_LAB="$(cd "$(dirname "$LAB")" && pwd)/$(basename "$LAB")"
        REL_LAB="${ABS_LAB#"$ROOT"/}"
        "$PY" -B "$HERE/build-lab-index.py" --why "$REL_LAB" 2>&1 | sed 's/^/         /'
    fi
fi

# --------------------------------------------------------------------------- #
# 5. Paths the lab promises
# --------------------------------------------------------------------------- #
if [ -n "$LAB" ] && [ "$CHECK_PATHS" -eq 1 ] && [ -f "$LAB" ]; then
    hdr "5. paths the lab names"
    LABDIR="$(cd "$(dirname "$LAB")" && pwd)"
    MISSING=0
    # Markdown links only. A path inside a code fence is deliberately NOT
    # checked here: in a fence a path is usually an illustration rather than a
    # promise, and telling the two apart needs context this script does not
    # have. That distinction is real -- a chapter can pass every mechanical
    # check and still promise a file it never wrote, because the promise is a
    # path in a code comment rather than a markdown link, and the link checker
    # never sees it.
    grep -oE '\]\([^)#][^)]*\)' "$LAB" | sed 's/^](//; s/)$//' | while read -r target; do
        case "$target" in
            http*|mailto:*) continue ;;
        esac
        clean="${target%%#*}"
        [ -z "$clean" ] && continue
        if [ ! -e "$LABDIR/$clean" ]; then
            printf '  [FAIL] broken link: %s\n' "$clean"
            MISSING=$((MISSING + 1))
        fi
    done
    if [ "$MISSING" -eq 0 ]; then
        ok "no broken markdown links found in this lab"
    fi
    note "Relative depth reminder: a file in labs/ is TWO levels below the repo"
    note "root, so a link to another chapter is ../../NN-Chapter/README.md"
fi

# --------------------------------------------------------------------------- #
# 6. Vantage -- the number one cause, and the one no script can settle
# --------------------------------------------------------------------------- #
hdr "6. vantage"
note "This is the most common cause of a divergence in this repository, and"
note "nothing here can check it for you. Answer in writing:"
note ""
note "  Which identity did the lab measure from?   app / shell / root / in-app"
note "  Which identity are YOU measuring from?"
note ""
note "\`adb shell\` is uid 2000 and is neither an app nor root. A result taken"
note "from one chair and reported as though from another is wrong even when"
note "every command succeeded."

# --------------------------------------------------------------------------- #
hdr "verdict"
if [ "$PROBLEMS" -eq 0 ]; then
    echo "  no blocking problem found."
    echo "  If the lab still does not reproduce, the verdict is"
    echo "  'DIVERGED, cause not established'. Write it up with"
    echo "  ../examples/divergence-report.md and change nothing."
    exit 0
else
    echo "  $PROBLEMS blocking problem(s) above."
    echo "  Fix those before recording a divergence: a lab that could not have"
    echo "  run has not been tested."
    exit 1
fi
