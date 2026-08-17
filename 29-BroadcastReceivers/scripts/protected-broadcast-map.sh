#!/usr/bin/env bash
#
# protected-broadcast-map.sh -- work out which broadcast actions an ordinary app
#                               CANNOT forge on the device in front of you.
#
# PURPOSE
#   An exported receiver listening for BOOT_COMPLETED is not a finding, because
#   BOOT_COMPLETED is a <protected-broadcast>: ActivityManagerService refuses to
#   dispatch it for any sender that is not the system, before any receiver is
#   consulted. An exported receiver listening for
#   com.example.REFRESH_CONFIG IS a lead, because nothing stops you sending it.
#
#   Telling those two apart is the single most common mistake in a broadcast
#   assessment, and the answer is device-specific: the set is not a constant in
#   the SDK, it is the union of every <protected-broadcast> element declared by
#   every SYSTEM package installed on that device. An OEM framework adds its
#   own. A carrier build adds more. A list typed from memory is wrong on
#   any device you did not build yourself.
#
#   This script builds the list from the device, two independent ways:
#
#     STATIC  (default, NO side effects)
#             Pull the platform's own framework-res.apk -- the APK whose package
#             name is "android" and whose manifest declares the platform's
#             protected broadcasts -- and read every <protected-broadcast> out
#             of it with aapt2. Optionally do the same for every other system
#             APK, since those contribute to the same set.
#
#     DYNAMIC (--verify, SENDS BROADCASTS)
#             Ask the platform directly, by attempting to send. A protected
#             action comes back as
#               SecurityException: Permission Denial: not allowed to send
#               broadcast <action> from pid=<n>, uid=2000
#             An unprotected one comes back as "Broadcast completed". This is
#             authoritative -- it is the enforcement path itself -- but an
#             unprotected attempt is REALLY DELIVERED to every receiver on the
#             device.
#
#   Where the two disagree, the dynamic answer wins, and the disagreement is
#   itself interesting: it means an action is guarded by a service-specific
#   check rather than by the protected-broadcast list.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * Whether a receiver for an unprotected action is exploitable. Forgeable is
#     a precondition. You still need a receiver that acts on it, and an
#     observable consequence.
#   * Whether YOUR APP may send it. The protected-broadcast check keys off the
#     caller uid: system (1000), root (0) and a handful of other platform uids
#     pass; uid 2000 (adb shell) does NOT, and neither does any ordinary app.
#     Measured on Android 11 / API 30: shell was refused BOOT_COMPLETED and root
#     was allowed LOCALE_CHANGED. So a shell "denied" means an app is denied
#     too, and a shell "allowed" means an app is allowed too.
#   * Actions guarded some OTHER way. android.appwidget.action.APPWIDGET_UPDATE
#     is NOT in the framework's protected-broadcast list on the measured device,
#     yet shell was still refused -- with a different message, "from unknown
#     caller", raised by AppWidgetService rather than by AMS. A static list
#     under-reports. Only --verify catches these.
#   * Receiver-side permissions. An action can be perfectly forgeable while the
#     receiver requires a permission you cannot hold. Read the
#     requiredPermission column from receiver-surface.py as well.
#   * Anything about a manifest you have not looked at. This reads the
#     PLATFORM's manifest, not the target app's. For a target app's
#     declarations, use 32-Manifest/scripts/manifest-audit.py.
#
# HOW TO RUN
#   # host -- build the static list from the platform framework (no side effects)
#   ./protected-broadcast-map.sh
#
#   # host -- classify a list of actions against it
#   ./protected-broadcast-map.sh --check actions.txt
#
#   # host -- include every other system APK's contribution (slow, thorough)
#   ./protected-broadcast-map.sh --all-system
#
#   # host -- ask the platform itself. THIS SENDS BROADCASTS.
#   ./protected-broadcast-map.sh --check actions.txt --verify --i-will-send
#
#   # host -- one action, quickly
#   ./protected-broadcast-map.sh --is android.intent.action.BOOT_COMPLETED
#
#   # feed it the runtime surface from the sibling script
#   python3 receiver-surface.py --third-party --json \
#     | python3 -c 'import json,sys;[print(a) for r in json.load(sys.stdin)["receivers"] for f in r["filters"] for a in f["actions"]]' \
#     | sort -u > actions.txt
#   ./protected-broadcast-map.sh --check actions.txt
#
# REQUIREMENTS
#   bash, adb on PATH with a device attached, and aapt2 for the static mode.
#   aapt2 ships in every Android SDK build-tools directory and inside apktool's
#   install. Point at it with AAPT2=/path/to/aapt2 if it is not on PATH.
#   No root required. Nothing is written outside the working directory, which
#   defaults to a temp directory that is removed on exit.
#
# EXIT CODES
#   0  ran successfully
#   1  no device, or a required tool is missing
#   2  bad usage
#
# AUTHORISED TESTING ONLY. --verify --i-will-send DISPATCHES REAL BROADCASTS.

set -u

AAPT2="${AAPT2:-}"
MODE="static"
CHECK_FILE=""
SINGLE=""
ALL_SYSTEM=0
VERIFY=0
CONFIRMED=0
KEEP=0
SERIAL_ARGS=()

die() { echo "error: $*" >&2; exit "${2:-2}"; }

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --check)        CHECK_FILE="${2:-}"; shift 2 ;;
        --is)           SINGLE="${2:-}"; shift 2 ;;
        --all-system)   ALL_SYSTEM=1; shift ;;
        --verify)       VERIFY=1; shift ;;
        --i-will-send)  CONFIRMED=1; shift ;;
        --keep)         KEEP=1; shift ;;
        -s)             SERIAL_ARGS=(-s "${2:-}"); shift 2 ;;
        -h|--help)      usage ;;
        *)              die "unknown option: $1" ;;
    esac
done

# --------------------------------------------------------------------------- #
#  preconditions
# --------------------------------------------------------------------------- #

command -v adb >/dev/null 2>&1 || die "adb not on PATH" 1

DEV_COUNT=$(adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" devices | grep -cw device || true)
if [ "$DEV_COUNT" -eq 0 ]; then
    die "no device attached (adb devices shows none in state 'device')" 1
fi

API=$(adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" shell getprop ro.build.version.sdk | tr -d '\r\n')
REL=$(adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" shell getprop ro.build.version.release | tr -d '\r\n')
MODEL=$(adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" shell getprop ro.product.model | tr -d '\r\n')

echo "=== device ==================================================================="
echo "  model=$MODEL  Android $REL  API $API"
echo ""

if [ -z "$AAPT2" ]; then
    if command -v aapt2 >/dev/null 2>&1; then
        AAPT2="$(command -v aapt2)"
    else
        for cand in \
            "$HOME/AppData/Local/Android/Sdk/build-tools"/*/aapt2 \
            "$HOME/Android/Sdk/build-tools"/*/aapt2 \
            "/c/Program Files (x86)/apktool/Resources/aapt2" \
            "/usr/lib/android-sdk/build-tools"/*/aapt2
        do
            [ -x "$cand" ] && AAPT2="$cand" && break
        done
    fi
fi

WORK="$(mktemp -d 2>/dev/null || echo "./pbmap.$$")"
mkdir -p "$WORK"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

LIST="$WORK/protected.txt"
: > "$LIST"

# --------------------------------------------------------------------------- #
#  static extraction
#
#  The platform's own manifest lives in framework-res.apk, package "android".
#  Every <protected-broadcast android:name="..."/> in it is an action that
#  ActivityManagerService will refuse to dispatch on behalf of a non-system
#  caller. Other system packages may declare their own; --all-system collects
#  those too.
# --------------------------------------------------------------------------- #

extract_from_apk() {
    # $1 = local apk path, $2 = label for the log
    [ -s "$1" ] || return 0
    "$AAPT2" dump xmltree --file AndroidManifest.xml "$1" 2>/dev/null \
        | grep -A2 'E: protected-broadcast' \
        | grep -oE 'android:name\(0x[0-9a-f]+\)="[^"]+"' \
        | sed 's/.*="//; s/"$//' \
        | sort -u > "$WORK/one.txt"
    local n
    n=$(wc -l < "$WORK/one.txt" | tr -d ' ')
    if [ "$n" -gt 0 ]; then
        printf '  %-58s %5s protected action(s)\n' "$2" "$n"
        cat "$WORK/one.txt" >> "$LIST"
    fi
}

build_static_list() {
    if [ -z "$AAPT2" ] || [ ! -x "$AAPT2" ]; then
        echo "  !! aapt2 not found. Set AAPT2=/path/to/aapt2, or use --verify."
        echo "     aapt2 ships in \$ANDROID_HOME/build-tools/<ver>/ and inside apktool."
        return 1
    fi
    echo "=== static extraction (no broadcasts sent) ==================================="
    echo "  aapt2: $AAPT2"
    echo ""

    # Two Windows/Git-Bash traps, both silent failures rather than errors:
    #   1. MSYS rewrites an argument that looks like a Unix absolute path, so
    #      the DEVICE path /system/framework/framework-res.apk arrives at adb as
    #      C:/Program Files/Git/system/framework/framework-res.apk and the pull
    #      fails with "failed to stat remote object". MSYS_NO_PATHCONV=1 stops
    #      the rewriting, and is simply ignored on Linux and macOS.
    #   2. adb (a native Windows binary) cannot write to an MSYS-style absolute
    #      host path either, so pull into the working directory by relative name.
    ( cd "$WORK" && MSYS_NO_PATHCONV=1 adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" \
        pull /system/framework/framework-res.apk framework-res.apk >/dev/null 2>&1 )
    extract_from_apk "$WORK/framework-res.apk" "framework-res.apk (package \"android\")"

    if [ "$ALL_SYSTEM" -eq 1 ]; then
        echo ""
        echo "  scanning every other system APK -- this takes a few minutes..."
        MSYS_NO_PATHCONV=1 adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" shell \
            'ls /system/priv-app/*/*.apk /system/app/*/*.apk /system_ext/priv-app/*/*.apk 2>/dev/null' \
            | tr -d '\r' > "$WORK/apks.txt"
        local i=0
        while IFS= read -r remote; do
            [ -n "$remote" ] || continue
            i=$((i + 1))
            ( cd "$WORK" && MSYS_NO_PATHCONV=1 adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" \
                pull "$remote" "sys$i.apk" >/dev/null 2>&1 )
            extract_from_apk "$WORK/sys$i.apk" "$(basename "$remote")"
            rm -f "$WORK/sys$i.apk"
        done < "$WORK/apks.txt"
    else
        echo ""
        echo "  Only the platform framework was read. Other SYSTEM packages can"
        echo "  declare <protected-broadcast> too, and OEM builds do. Use"
        echo "  --all-system for the full union, or --verify for the truth."
    fi

    sort -u "$LIST" -o "$LIST"
    echo ""
    echo "  total distinct protected actions found: $(wc -l < "$LIST" | tr -d ' ')"
    echo ""
    return 0
}

# --------------------------------------------------------------------------- #
#  dynamic verification
# --------------------------------------------------------------------------- #

probe_one() {
    # echoes: PROTECTED | FORGEABLE | DENIED-OTHER | UNKNOWN
    local action="$1"
    local out
    out=$(adb "${SERIAL_ARGS[@]+"${SERIAL_ARGS[@]}"}" shell "am broadcast -a '$action'" 2>&1 | tr -d '\r')
    case "$out" in
        *"not allowed to send broadcast"*) echo "PROTECTED" ;;
        *"Broadcast completed"*)           echo "FORGEABLE" ;;
        *SecurityException*)               echo "DENIED-OTHER" ;;
        *)                                 echo "UNKNOWN" ;;
    esac
}

# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #

if [ "$VERIFY" -eq 1 ] && [ "$CONFIRMED" -eq 0 ]; then
    echo "!! --verify requires --i-will-send."
    echo "   Verification works by ATTEMPTING TO SEND each action. An action that"
    echo "   turns out not to be protected is therefore really delivered, to every"
    echo "   registered receiver on the device. On a phone with real apps and real"
    echo "   data that is a state change you did not intend."
    echo ""
    VERIFY=0
fi

build_static_list || true

if [ -n "$SINGLE" ]; then
    echo "=== $SINGLE ==="
    if grep -qxF "$SINGLE" "$LIST" 2>/dev/null; then
        echo "  static : PROTECTED -- declared <protected-broadcast> by the platform."
        echo "           An ordinary app cannot forge it. A receiver listening for it"
        echo "           alone is NOT a finding."
    else
        echo "  static : not in the platform's protected list."
        echo "           If nothing else guards it, any app can send it."
    fi
    if [ "$VERIFY" -eq 1 ]; then
        echo "  dynamic: $(probe_one "$SINGLE")"
    fi
    echo ""
    exit 0
fi

if [ -n "$CHECK_FILE" ]; then
    [ -r "$CHECK_FILE" ] || die "cannot read $CHECK_FILE"
    echo "=== classification of $CHECK_FILE ============================================"
    echo ""
    printf '  %-62s %-10s %s\n' "ACTION" "STATIC" "DYNAMIC"
    printf '  %s\n' "----------------------------------------------------------------------------------"
    forgeable=0; protected=0; total=0
    while IFS= read -r action; do
        action="$(echo "$action" | tr -d '\r' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -n "$action" ] || continue
        case "$action" in \#*) continue ;; esac
        total=$((total + 1))
        if grep -qxF "$action" "$LIST" 2>/dev/null; then
            st="PROTECTED"; protected=$((protected + 1))
        else
            st="forgeable"; forgeable=$((forgeable + 1))
        fi
        dy="-"
        [ "$VERIFY" -eq 1 ] && dy="$(probe_one "$action")"
        printf '  %-62s %-10s %s\n' "$action" "$st" "$dy"
    done < "$CHECK_FILE"
    echo ""
    echo "  $total action(s): $protected protected, $forgeable not in the platform list."
    echo ""
    echo "  The $forgeable in the second group are the ones worth your time. For each,"
    echo "  find who listens:"
    echo "    python3 receiver-surface.py --action <action>"
    echo "    adb shell cmd package query-receivers --brief -a <action>"
    echo "  and then show that sending it changes something. Until you do, it is a"
    echo "  lead and not a finding."
    exit 0
fi

echo "=== the list ================================================================="
cat "$LIST"
echo ""
echo "  Rerun with --check <file> to classify a set of actions, or --is <action>"
echo "  for one. Add --verify --i-will-send to ask the platform instead of its"
echo "  manifest -- remembering that verification dispatches."
