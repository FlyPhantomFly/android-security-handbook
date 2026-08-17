#!/usr/bin/env bash
# 76-CheatSheets/examples/03-session-preflight.sh
#
# PURPOSE
#   Thirty seconds at the start of a session that removes four whole categories of
#   wrong answer for the rest of the day:
#
#     1. WHICH DEVICE is attached, and is it the one you think?
#     2. WHAT API LEVEL and build type -- a version-gated claim on the wrong
#        device is worse than no claim.
#     3. WHICH `su` FORM this device takes -- the wrong one fails in the shape of
#        "not rooted", which silently invalidates everything after it.
#     4. DOES YOUR QUOTING SURVIVE `adb shell` -- if not, every compound command
#        you run today will drop its first half and exit 0.
#
#   It also checks the things that are cheap to check and expensive to assume: the
#   system CA store, the lock state, the page size, and whether the tools you are
#   about to reach for actually exist on this host.
#
#   Nothing here is destructive. It reads; it never writes to the device.
#
# USAGE
#   bash examples/03-session-preflight.sh
#   bash examples/03-session-preflight.sh --serial emulator-5554
#   bash examples/03-session-preflight.sh --pkg com.example.debuggable
#
# WAS THIS EXECUTED?
#   YES. Run on 2026-08-16 against `sdk_gphone16k_x86_64` (emulator-5554,
#   Android 15 / API 35, x86_64, userdebug, rooted with Magisk 30.7), with
#   --pkg com.devuser.helloworld. Output is reproduced at the bottom of
#   this file so you can compare shapes without a device attached.
#
# DELIBERATE OMISSIONS -- each one is a measured trap, not an oversight
#   * No `set -o pipefail`. Combined with `head` or `grep -q` it reports failure
#     ON SUCCESS via SIGPIPE, measured at exit 141. Every check below tests
#     CONTENT.
#   * Every `adb` call carries `< /dev/null`. `adb shell` inherits stdin, so in a
#     loop fed by a pipe it drinks the loop's input -- a three-row loop measured
#     here printed ONE row and exited 0.
#   * Every device-side command with quoting or a pipe is wrapped in DOUBLE quotes
#     for `adb shell`, because adb re-splits argv and the device shell re-parses.
#
# EXIT STATUS
#   0 when a device was found and every check ran. 1 when no device is attached,
#   or when the quoting self-test fails -- that one is fatal on purpose, because
#   continuing past it produces plausible wrong answers rather than errors.

set -u

SERIAL=""
PKG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --serial) SERIAL="$2"; shift 2 ;;
        --pkg)    PKG="$2";    shift 2 ;;
        -h|--help) sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

ADB="adb"
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

hr() { printf '%s\n' "------------------------------------------------------------"; }
row() { printf '  %-26s %s\n' "$1" "$2"; }

# ---------------------------------------------------------------- 1. device
hr; echo "1. DEVICE"

# `adb devices` exits 0 with nothing attached and prints a header regardless, so
# count DATA rows. Testing the exit status here passes with zero devices.
LIST=$($ADB devices -l < /dev/null | sed -n '2,$p' | grep 'device ' || true)
COUNT=$(printf '%s\n' "$LIST" | grep -c 'device ' || true)

if [ "$COUNT" -eq 0 ]; then
    echo "  NO DEVICE ATTACHED."
    echo "  ('adb devices' exits 0 with nothing attached -- silence is not success here.)"
    exit 1
fi
printf '%s\n' "$LIST" | sed 's/^/  /'
if [ "$COUNT" -gt 1 ] && [ -z "$SERIAL" ]; then
    echo
    echo "  MORE THAN ONE DEVICE. Pass --serial, or every command below is ambiguous."
    echo "  This is also how a Frida session silently attaches to the wrong device."
    exit 1
fi

# ---------------------------------------------------------------- 2. build
hr; echo "2. BUILD"
row "model"        "$($ADB shell getprop ro.product.model      < /dev/null | tr -d '\r')"
row "release"      "$($ADB shell getprop ro.build.version.release < /dev/null | tr -d '\r')"
row "sdk"          "$($ADB shell getprop ro.build.version.sdk  < /dev/null | tr -d '\r')"
row "type"         "$($ADB shell getprop ro.build.type         < /dev/null | tr -d '\r')"
row "ro.debuggable" "$($ADB shell getprop ro.debuggable        < /dev/null | tr -d '\r')"
row "fingerprint"  "$($ADB shell getprop ro.build.fingerprint  < /dev/null | tr -d '\r')"
row "selinux"      "$($ADB shell getenforce                    < /dev/null | tr -d '\r')"
row "page size"    "$($ADB shell getconf PAGE_SIZE             < /dev/null | tr -d '\r')"

BTYPE=$($ADB shell getprop ro.build.type < /dev/null | tr -d '\r')
if [ "$BTYPE" != "user" ]; then
    echo
    echo "  NOTE: this is a '$BTYPE' build. REFUSALS measured here are solid -- a"
    echo "  permissive build cannot manufacture a refusal -- but SUCCESSES that could"
    echo "  depend on permissiveness are upper bounds. Say so in the write-up."
fi

PGSZ=$($ADB shell getconf PAGE_SIZE < /dev/null | tr -d '\r')
if [ "$PGSZ" = "16384" ]; then
    echo
    echo "  NOTE: 16 KiB pages. Naively-linked NDK binaries exit 139 (SIGSEGV) here,"
    echo "  and no error message names the cause. Build with:"
    echo "      -Wl,-z,max-page-size=16384"
fi

# ---------------------------------------------------------------- 3. su form
hr; echo "3. ROOT -- which su form does this device take?"

SU_FORM="none"
if $ADB shell "su 0 id" < /dev/null 2>/dev/null | grep -q 'uid=0'; then
    SU_FORM="su 0 <cmd>"
elif $ADB shell "su -c id" < /dev/null 2>/dev/null | grep -q 'uid=0'; then   # lint:allow
    SU_FORM="su -c <cmd>"
fi
row "working form" "$SU_FORM"

case "$SU_FORM" in
    "su 0 <cmd>")
        row "context" "$($ADB shell "su 0 id" < /dev/null | tr -d '\r' | sed 's/.*context=//')"
        echo
        echo "  'su -c' on this device returns:"
        # lint:allow -- printing the failing form's message is the point of this check
        printf '      %s\n' "$($ADB shell "su -c id" < /dev/null 2>&1 | tr -d '\r' | head -1)"
        echo "  ...which reads as NOT ROOTED and is not. Use 'su 0'."
        ;;
    "su -c <cmd>")
        echo "  Magisk-style su. Note that 'adb shell' still re-splits argv, so flags"
        echo "  AFTER the command are eaten by su: 'su -c magisk -v' prints SU's version."
        ;;
    none)
        echo "  No root, or su is present and grants nothing. Both forms were tried."
        echo "  Everything below marked 'root' is unavailable; that is a limit of the"
        echo "  measurement, not a property of the app."
        ;;
esac

# Magisk substrate -- readable from every vantage, needs no privilege at all.
MAGISK_MOUNTS=$($ADB shell 'grep -c magisk /proc/self/mountinfo' < /dev/null 2>/dev/null | tr -d '\r')
row "magisk mountinfo rows" "${MAGISK_MOUNTS:-0}"

# ---------------------------------------------------------------- 4. quoting
hr; echo "4. QUOTING SELF-TEST -- fatal if it fails"

GOOD=$($ADB shell "sh -c 'echo A; echo B'" < /dev/null | tr -d '\r' | tr '\n' ' ')
row "quoted form" "[$GOOD]"
BAD=$($ADB shell sh -c 'echo A; echo B' < /dev/null | tr -d '\r' | tr '\n' ' ')   # lint:allow
row "unquoted form" "[$BAD]"

case "$GOOD" in
    *A*B*) echo "  OK -- quoting survives when the whole command is double-quoted." ;;
    *)
        echo "  FAILED. The device did not receive both commands even when quoted."
        echo "  Stop here: every compound command today will drop half of itself"
        echo "  and exit 0."
        exit 1
        ;;
esac
case "$BAD" in
    *A*) : ;;
    *)   echo "  (And the unquoted form dropped 'echo A', exactly as documented.)" ;;
esac

# ---------------------------------------------------------------- 5. environment
hr; echo "5. ENVIRONMENT TRAPS"

CACERTS=$($ADB shell mount < /dev/null 2>/dev/null | grep cacerts | head -1 | tr -d '\r')
if [ -n "$CACERTS" ]; then
    echo "  SYSTEM CA STORE IS MOUNTED OVER:"
    printf '      %s\n' "$CACERTS"
    echo "  A successful intercept on this device does NOT prove the app trusts"
    echo "  user-installed CAs -- the proxy CA may be in the SYSTEM store."
else
    row "cacerts mount" "none (stock system store)"
fi

LOCKED=$($ADB shell "dumpsys trust" < /dev/null 2>/dev/null | grep -o 'deviceLocked=[01]' | head -1)
row "lock state" "${LOCKED:-unknown}"
case "$LOCKED" in
    deviceLocked=1)
        echo "  SCREEN IS LOCKED. On some OEM builds this silently refuses every"
        echo "  activity start that ORIGINATES FROM AN APP, while 'am start' from the"
        echo "  shell still works -- so half your commands succeed and the pattern"
        echo "  looks random. Unlock the screen; do not disable the lock screen."
        ;;
esac

# ---------------------------------------------------------------- 6. app vantage
hr; echo "6. APP VANTAGE"
if [ -z "$PKG" ]; then
    echo "  No --pkg given. Every result below would be a SHELL measurement, and the"
    echo "  shell holds privileges an app does not. Pass a debuggable package."
else
    APPID=$($ADB shell "run-as $PKG id" < /dev/null 2>&1 | tr -d '\r')
    case "$APPID" in
        uid=*)
            row "run-as" "$APPID"
            ;;
        *"not debuggable"*)
            row "run-as" "REFUSED -- package is not debuggable"
            ;;
        *"not an application"*)
            row "run-as" "REFUSED -- debuggable SYSTEM app (a different condition)"
            ;;
        *)
            row "run-as" "$APPID"
            ;;
    esac
    FLAGS=$($ADB shell "dumpsys package $PKG" < /dev/null 2>/dev/null \
            | grep -m1 'pkgFlags=\[' | tr -d '\r' | sed 's/^ *//')
    [ -n "$FLAGS" ] && row "flags" "$FLAGS"
fi

# ---------------------------------------------------------------- 7. host tools
hr; echo "7. HOST TOOLS"
for t in adb aapt2 apktool apksigner jadx frida objection python3 java sqlite3 unzip; do
    if command -v "$t" > /dev/null 2>&1; then
        row "$t" "$(command -v "$t")"
    else
        row "$t" "ABSENT"
    fi
done

if command -v frida > /dev/null 2>&1; then
    echo
    echo "  REMINDER: 'frida-ps -U' succeeding proves your ADB connection, NOT that"
    echo "  Frida can instrument anything. It enumerates over adb with no server."
    echo "  The test is an attach:  frida -U -n <proc> -e 'console.log(1)'"
fi

hr
echo "Preflight complete. Record this block in the engagement notes -- a claim whose"
echo "device you cannot name is a claim you cannot defend."

# ---------------------------------------------------------------------------
# MEASURED OUTPUT, 2026-08-16, sdk_gphone16k_x86_64 / emulator-5554 (abridged):
#
#   1. DEVICE
#     emulator-5554  device product:sdk_gphone16k_x86_64 model:sdk_gphone16k_x86_64
#                    device:emu64xa16k transport_id:2
#   2. BUILD
#     model                      sdk_gphone16k_x86_64
#     release                    15
#     sdk                        35
#     type                       userdebug
#     ro.debuggable              1
#     fingerprint                google/sdk_gphone16k_x86_64/emu64xa16k:15/
#                                AE3A.240806.043/12960925:userdebug/dev-keys
#     selinux                    Enforcing
#     page size                  16384
#     NOTE: this is a 'userdebug' build ...
#     NOTE: 16 KiB pages ...
#   3. ROOT
#     working form               su 0 <cmd>
#     context                    u:r:su:s0
#     'su -c' on this device returns:
#         su: invalid uid/gid '-c'
#     magisk mountinfo rows      3
#   4. QUOTING SELF-TEST
#     quoted form                [A B ]
#     unquoted form              [ B ]
#     OK -- quoting survives when the whole command is double-quoted.
#     (And the unquoted form dropped 'echo A', exactly as documented.)
#   5. ENVIRONMENT TRAPS
#     cacerts mount              none (stock system store)
#     lock state                 deviceLocked=0
#   6. APP VANTAGE
#     run-as                     uid=10207(u0_a207) ... context=u:r:runas_app:
#                                s0:c207,c256,c512,c768
#     flags                      pkgFlags=[ DEBUGGABLE HAS_CODE
#                                ALLOW_CLEAR_USER_DATA TEST_ONLY ALLOW_BACKUP ]
#   7. HOST TOOLS
#     adb, aapt2, jadx, frida, objection, python3, java, sqlite3, unzip present;
#     apktool and apksigner ABSENT on this host.
# ---------------------------------------------------------------------------
