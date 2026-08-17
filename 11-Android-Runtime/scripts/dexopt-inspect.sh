#!/bin/sh
# =============================================================================
#  dexopt-inspect.sh  —  Chapter 11, Android Runtime
# =============================================================================
#
#  WHAT THIS DOES
#  --------------
#  Reports how a given installed package is COMPILED on the connected device,
#  and lets you recompile it with a different compilation filter so you can see
#  the interpreter / JIT / AOT trade-off with your own eyes.
#
#  Concretely it prints:
#
#    1. Whether the package exists, its APK path and its data directory.
#    2. The compilation status per ABI - the "compilation filter" and the
#       "compilation reason" - from `dumpsys package dexopt` and `pm dump`.
#    3. The contents of the package's oat/ directory (the .odex/.oat/.vdex/.art
#       artefacts that dex2oat produced).
#    4. The dalvik.vm.* system properties that control the runtime: heap sizes,
#       the default compiler filter, JIT settings, and any hidden API
#       exemptions configured at the Zygote level.
#    5. The zygote processes, because every app process on the device is a fork
#       of one of them.
#
#  With --recompile it drives `cmd package compile` and then re-prints the
#  status so you can confirm the change took effect.
#
#  HOW TO RUN IT
#  -------------
#      # host shell
#      chmod +x dexopt-inspect.sh
#      ./dexopt-inspect.sh com.example.target
#
#      # pick a device when several are connected
#      ./dexopt-inspect.sh -s emulator-5554 com.example.target
#
#      # force full ahead-of-time compilation, then look again
#      ./dexopt-inspect.sh --recompile speed com.example.target
#
#      # drop back to the "verify only" filter, i.e. interpret + JIT
#      ./dexopt-inspect.sh --recompile verify com.example.target
#
#      # save a report
#      ./dexopt-inspect.sh com.example.target > dexopt-report.txt
#
#  PREREQUISITES
#  -------------
#   - adb on the host PATH, and exactly one authorised device (or use -s).
#   - The target package installed on that device.
#   - Root is NOT required for the status output. Listing the oat/ directory
#     usually DOES require root on Android 11+, because /data/app subdirectories
#     are not traversable by the shell user any more; the script says so
#     instead of failing silently.
#   - --recompile needs no root: `cmd package compile` is available to the shell
#     user on standard builds.
#
#  WHY YOU CARE (the security-relevant part)
#  ------------------------------------------
#  The compilation filter changes what exists on disk and therefore what you can
#  analyse and what you can tamper with:
#
#    * With "verify" (the default for most installs) there is little or no
#      native code on disk; the DEX is interpreted and hot methods are JIT
#      compiled into an anonymous, non-writable executable mapping. Patch the
#      DEX and your patch runs immediately.
#    * With "speed" the app has real AOT native code in a .odex/.oat file. If
#      you patch the DEX but the runtime still trusts the stale AOT artefact,
#      your patch appears not to work - a genuinely common and maddening
#      confusion when you start out. Recompiling, or clearing the profile, is
#      the fix.
#    * "speed-profile" compiles only the methods in the collected profile, so
#      the same app on two phones can have different native code. Do not assume
#      an artefact you dumped from one device matches another.
#
#  The filter is a performance decision, not a security control: no filter makes
#  code unreadable, and none of them authenticates anything. Chapter 13 covers
#  what dex2oat actually emits; this script stays at the "which one is in force"
#  level.
# =============================================================================

set -u

PROG="$(basename "$0")"
SERIAL=""
RECOMPILE=""
PKG=""

# The filters accepted by `cmd package compile -m`. Availability varies by
# platform version: "quicken" was removed in Android 12 (API 31), and
# "assume-verified" / "extract" are not present on every build. The script
# validates against this list to catch typos, and the device has the final say.
VALID_FILTERS="assume-verified extract verify quicken space-profile space speed-profile speed everything-profile everything"

usage() {
    cat <<EOF
$PROG - inspect and control the AOT compilation state of an installed package

usage:
  $PROG [-s SERIAL] [--recompile FILTER] <package.name>
  $PROG -h

options:
  -s SERIAL            adb device serial (as printed by 'adb devices')
  --recompile FILTER   run 'cmd package compile -m FILTER -f <pkg>' first
                       valid filters: $VALID_FILTERS
  -h, --help           this text

examples:
  $PROG com.android.settings
  $PROG --recompile speed com.example.target
  $PROG -s emulator-5554 com.example.target
EOF
}

# ---------------------------------------------------------------------------
#  Argument parsing. POSIX sh has no getopts long-option support, so we walk
#  the arguments by hand. This stays portable to dash, busybox ash and bash.
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -s)
            [ $# -ge 2 ] || { echo "$PROG: -s needs a serial" >&2; exit 2; }
            SERIAL="$2"
            shift 2
            ;;
        --recompile)
            [ $# -ge 2 ] || { echo "$PROG: --recompile needs a filter" >&2; exit 2; }
            RECOMPILE="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "$PROG: unknown option '$1'" >&2
            usage >&2
            exit 2
            ;;
        *)
            if [ -n "$PKG" ]; then
                echo "$PROG: more than one package given" >&2
                exit 2
            fi
            PKG="$1"
            shift
            ;;
    esac
done

if [ -z "$PKG" ]; then
    usage >&2
    exit 2
fi

command -v adb >/dev/null 2>&1 || {
    echo "$PROG: adb not found on PATH" >&2
    exit 1
}

# ---------------------------------------------------------------------------
#  adb wrappers. Defining these once keeps the -s handling in a single place.
#  We strip carriage returns, because adb shell output is CRLF-terminated and
#  the stray \r breaks string comparisons and makes reports look corrupted.
# ---------------------------------------------------------------------------
adb_do() {
    if [ -n "$SERIAL" ]; then
        adb -s "$SERIAL" "$@"
    else
        adb "$@"
    fi
}

sh_dev() {
    # $1 is a complete shell command line to run ON THE DEVICE.
    adb_do shell "$1" 2>/dev/null | tr -d '\r'
}

hr() {
    echo "-------------------------------------------------------------------"
}

section() {
    echo ""
    hr
    echo "  $1"
    hr
}

# ---------------------------------------------------------------------------
#  0. Device sanity
# ---------------------------------------------------------------------------
section "0. device"

DEVSTATE="$(adb_do get-state 2>/dev/null | tr -d '\r')"
if [ "$DEVSTATE" != "device" ]; then
    echo "adb state is '${DEVSTATE:-none}'. Connect a device, or pass -s SERIAL."
    echo "Devices currently visible:"
    adb devices -l
    exit 1
fi

echo "serial       : $(adb_do get-serialno | tr -d '\r')"
echo "model        : $(sh_dev 'getprop ro.product.model')"
echo "android      : $(sh_dev 'getprop ro.build.version.release') (API $(sh_dev 'getprop ro.build.version.sdk'))"
echo "abi          : $(sh_dev 'getprop ro.product.cpu.abi')"
echo "abilist      : $(sh_dev 'getprop ro.product.cpu.abilist')"
echo "adb root?    : $(sh_dev 'id -u') (0 means the shell is root)"

# ---------------------------------------------------------------------------
#  1. Does the package exist, and where does it live?
# ---------------------------------------------------------------------------
section "1. package: $PKG"

# `pm list packages` matches substrings, so we compare the exact line.
FOUND="$(sh_dev "pm list packages" | sed 's/^package://' | grep -x -- "$PKG" || true)"
if [ -z "$FOUND" ]; then
    echo "package '$PKG' is not installed on this device."
    echo "close matches:"
    sh_dev "pm list packages" | sed 's/^package://' | grep -i -- "$PKG" || echo "  (none)"
    exit 1
fi
echo "installed    : yes"

# `cmd package path` prints one 'package:/path/to/base.apk' line per split.
APK_LINES="$(sh_dev "cmd package path $PKG" | sed 's/^package://')"
echo "apk path(s)  :"
echo "$APK_LINES" | sed 's/^/               /'

# The first line is the base APK; its directory is the install directory, and
# the oat/ subdirectory of that is where dex2oat writes its output.
BASE_APK="$(echo "$APK_LINES" | head -n 1)"
INSTALL_DIR="$(dirname "$BASE_APK")"
echo "install dir  : $INSTALL_DIR"
echo "oat dir      : $INSTALL_DIR/oat"

# ---------------------------------------------------------------------------
#  2. Optional recompilation, done BEFORE we report status so the report shows
#     the new state.
# ---------------------------------------------------------------------------
if [ -n "$RECOMPILE" ]; then
    section "2. recompiling with filter '$RECOMPILE'"

    # Validate against the known list. This is a typo check, not a policy: the
    # device may support fewer filters than we list.
    OK=""
    for f in $VALID_FILTERS; do
        if [ "$f" = "$RECOMPILE" ]; then
            OK="yes"
            break
        fi
    done
    if [ -z "$OK" ]; then
        echo "'$RECOMPILE' is not a filter this script recognises."
        echo "valid: $VALID_FILTERS"
        exit 2
    fi

    # -m FILTER : the compiler filter to use.
    # -f        : force, i.e. compile even if the current state already matches.
    # Add --check-prof false on some builds if a profile-guided filter refuses
    # to run because no profile has been collected yet.
    echo "running: cmd package compile -m $RECOMPILE -f $PKG"
    sh_dev "cmd package compile -m $RECOMPILE -f $PKG"
    echo ""
    echo "If that printed 'Failure', the usual causes are:"
    echo "  - the filter is not supported on this Android version"
    echo "    (for example 'quicken' was removed in Android 12 / API 31);"
    echo "  - a profile-guided filter was requested but no profile exists yet;"
    echo "  - the package is a system app on a read-only partition."
fi

# ---------------------------------------------------------------------------
#  3. Compilation status
#
#  Two sources, because their formats differ across releases and one of them is
#  usually readable when the other is not:
#
#    dumpsys package dexopt   - a compact global list, one block per package.
#    pm dump <pkg>            - the full package record, which contains a
#                               "Dexopt state:" section on modern builds.
#
#  What to look for in the output:
#    [status=speed-profile]   the current compiler filter,
#    [reason=install]         why it was compiled that way (install, bg-dexopt,
#                             first-boot, cmdline, inactive, boot-after-ota...),
#    [primary-abi]            which ABI this artefact is for.
# ---------------------------------------------------------------------------
section "3. compilation status (dumpsys package dexopt)"

# The dexopt dump lists packages in bracketed blocks. We print the block that
# starts with our package name: from the matching line until the next line that
# starts at column 0 with '[' - awk is the portable way to express that.
DEXOPT_BLOCK="$(sh_dev "dumpsys package dexopt" | awk -v pkg="$PKG" '
    # A package block header looks like: [com.example.target]
    /^\[/ {
        inblock = ($0 == "[" pkg "]")
    }
    inblock { print }
')"

if [ -n "$DEXOPT_BLOCK" ]; then
    echo "$DEXOPT_BLOCK"
else
    echo "(no block found in 'dumpsys package dexopt' - the format differs on"
    echo " this Android version; falling back to a grep)"
    sh_dev "dumpsys package dexopt" | grep -A 6 -- "$PKG" || echo "  (nothing)"
fi

section "3b. compilation status (pm dump)"
# pm dump is enormous; we take only the Dexopt state section and a few
# neighbouring lines that carry the filter and reason.
sh_dev "pm dump $PKG" | awk '
    /Dexopt state:/ { show = 1 }
    show { print }
    # Stop when the next top-level section starts.
    show && /^[A-Za-z].*:$/ && !/Dexopt state:/ { if (++seen > 1) exit }
' | head -n 40

echo ""
echo "If the sections above are empty, ask for the filter directly:"
echo "  adb shell dumpsys package $PKG | grep -iE 'dexopt|status=|filter='"

# ---------------------------------------------------------------------------
#  4. On-disk artefacts
# ---------------------------------------------------------------------------
section "4. oat/ directory contents"

echo "listing $INSTALL_DIR/oat"
OAT_LS="$(sh_dev "ls -lR $INSTALL_DIR/oat")"
if [ -n "$OAT_LS" ]; then
    echo "$OAT_LS"
else
    echo "(empty or not listable)"
    echo ""
    echo "On Android 11+ the shell user cannot traverse /data/app subdirectories,"
    echo "so this is expected without root. Options:"
    echo "  adb root                 # userdebug/eng builds only"
    # The outer quotes around the whole su invocation are load-bearing: adb
    # shell joins its arguments with spaces, so `adb shell su -c "ls -lR DIR"`
    # arrives at the device as `su -c ls -lR DIR` and su -c runs only `ls`.
    echo "  adb shell \"su -c 'ls -lR $INSTALL_DIR/oat'\""
    echo ""
    echo "What you would see, and what each extension means:"
    echo "  <abi>/base.odex   AOT-compiled native code produced by dex2oat"
    echo "  <abi>/base.vdex   verified DEX container: the DEX plus the results"
    echo "                    of verification, so the runtime can skip re-doing it"
    echo "  <abi>/base.art    app image: pre-initialised heap objects mapped in"
    echo "                    at startup to shorten cold start"
fi

echo ""
echo "profile files (drive speed-profile compilation):"
sh_dev "ls -l /data/misc/profiles/cur/0/$PKG 2>/dev/null" || true
sh_dev "ls -l /data/misc/profiles/ref/$PKG 2>/dev/null" || true
echo "(these are also usually root-only; the current profile is what"
echo " 'cmd package bg-dexopt-job' consumes when it recompiles in the background)"

# ---------------------------------------------------------------------------
#  5. Runtime configuration properties
# ---------------------------------------------------------------------------
section "5. dalvik.vm.* properties"

# getprop with no argument prints everything in [key]: [value] form. We filter
# to the runtime's namespace and sort so successive runs diff cleanly.
sh_dev "getprop" | grep -E '^\[(dalvik\.vm|ro\.dalvik\.vm|persist\.device_config\.runtime)' | sort

echo ""
echo "the ones that matter most:"
echo "  dalvik.vm.image-dex2oat-filter  filter used for the boot image"
echo "  dalvik.vm.dex2oat-filter        default filter for apps"
echo "  dalvik.vm.usejit                whether the JIT is enabled at all"
echo "  dalvik.vm.usejitprofiles        whether profiles are collected for"
echo "                                  profile-guided compilation"
echo "  dalvik.vm.heapgrowthlimit       the per-app heap cap - the number an"
echo "                                  app hits when it throws OutOfMemoryError"
echo "  dalvik.vm.heapsize              the cap for largeHeap=true apps"
echo "  dalvik.vm.hiddenapiexemptions   signature prefixes exempted from hidden"
echo "                                  API enforcement for every forked app;"
echo "                                  a non-empty value here is worth noting"

echo ""
echo "hidden API policy currently in force (0/1/2/3, empty means default):"
echo "  global setting = $(sh_dev 'settings get global hidden_api_policy')"

# ---------------------------------------------------------------------------
#  6. Zygote
# ---------------------------------------------------------------------------
section "6. zygote processes"

# Every app process is a fork of a zygote. A 64-bit device runs two: zygote64
# and zygote, and an app is forked from whichever matches its native ABI.
# `ps -A` exists on Android 7+ (toybox); older devices need plain `ps`.
ZYGOTES="$(sh_dev "ps -A -o PID,PPID,USER,NAME" | grep -i zygote)"
if [ -z "$ZYGOTES" ]; then
    ZYGOTES="$(sh_dev "ps" | grep -i zygote)"
fi
if [ -n "$ZYGOTES" ]; then
    echo "$ZYGOTES"
else
    echo "(could not list processes - some builds restrict ps for the shell user)"
fi

echo ""
echo "target app processes (if running):"
sh_dev "ps -A -o PID,PPID,USER,NAME" | grep -- "$PKG" || echo "  (not running)"
echo ""
echo "The PPID of a running app process is the zygote it was forked from."
echo "That fork is why every app starts with the framework classes already"
echo "loaded and initialised: they were preloaded once, in the zygote, and are"
echo "shared copy-on-write with every app on the device."

section "done"
echo "next steps:"
echo "  - compare 'verify' and 'speed' by recompiling and re-reading section 3;"
echo "  - attach Frida and run ./runtime-recon.js to see which artefacts are"
echo "    actually mapped into the running process;"
echo "  - if a DEX patch of yours seems not to take effect, recompile the"
echo "    package so no stale AOT artefact is left behind."
