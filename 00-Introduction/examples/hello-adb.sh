#!/bin/sh
# =============================================================================
# hello-adb.sh — your first conversation with an Android device
# =============================================================================
#
# WHAT THIS DOES
#   Enumerates a connected Android device using nothing but adb. It prints the
#   Android version, the API level, the CPU architecture, the list of apps the
#   user installed, and the battery state. Nothing here modifies the device.
#
# WHY IT EXISTS
#   Before you attack anything you must be able to describe it. Every finding
#   you ever write will begin with "on <device> running Android <version>
#   (API <level>, <abi>)". This script is that sentence, generated for you, and
#   every line is commented so you learn the commands rather than run them
#   blindly.
#
# HOW TO RUN
#   sh 00-Introduction/examples/hello-adb.sh
#   sh 00-Introduction/examples/hello-adb.sh emulator-5554   # pick a device
#
# REQUIREMENTS
#   - adb on your PATH (see labs/lab-01-build-your-lab.md)
#   - exactly one device connected and authorised, OR a serial passed as $1
#   - a POSIX shell: sh, dash, bash, zsh, or Git Bash / WSL on Windows
#
# SAFETY
#   Read-only. It runs no command that writes to the device. Run it against
#   devices you own. See labs/lab-03-legal-scope-triage.md.
# =============================================================================

# 'set -e' makes the script stop at the first command that fails, instead of
# ploughing on and printing confusing results based on a failed step.
# 'set -u' makes referencing an unset variable an error rather than an empty
# string, which catches typos in variable names.
set -eu

# -----------------------------------------------------------------------------
# Device selection
# -----------------------------------------------------------------------------

# adb can talk to several devices at once. When more than one is attached, every
# command must say which one with '-s <serial>'. We build that flag here once:
# if the caller passed a serial as the first argument we use it, otherwise we
# leave the flag empty and let adb pick the single attached device.
# "${1:-}" means "the first argument, or an empty string if there isn't one" —
# needed because 'set -u' would otherwise abort on an unset $1.
if [ -n "${1:-}" ]; then
    ADB_TARGET="-s $1"
else
    ADB_TARGET=""
fi

# A tiny wrapper so we never forget the target flag. Every adb call below goes
# through this function. '$@' forwards all arguments exactly as received,
# preserving quoting, which matters when an argument contains spaces.
adb_run() {
    # shellcheck disable=SC2086  # ADB_TARGET must word-split into two tokens
    adb $ADB_TARGET "$@"
}

# A helper that prints a section heading, purely so the output is readable.
section() {
    printf '\n=== %s ===\n' "$1"
}

# -----------------------------------------------------------------------------
# Step 0 — is adb even installed?
# -----------------------------------------------------------------------------

# 'command -v' asks the shell where a program lives. It is the portable way to
# test "is this on PATH?" — 'which' is not POSIX and behaves differently across
# systems. We send both stdout and stderr to /dev/null because we only care
# about the exit status, not the path it would print.
if ! command -v adb >/dev/null 2>&1; then
    echo "ERROR: adb is not on your PATH."
    echo "Install Android SDK platform-tools, then reopen your terminal."
    echo "See: 00-Introduction/labs/lab-01-build-your-lab.md"
    exit 1
fi

# -----------------------------------------------------------------------------
# Step 1 — which devices can we see?
# -----------------------------------------------------------------------------

section "Attached devices"

# 'adb devices' asks the local adb SERVER (a background process on your host,
# listening on 127.0.0.1:5037) for its list of known devices. The '-l' flag adds
# the long form: product, model, and device codename.
# Note the server is started automatically by this command if it is not running.
adb devices -l

# Count the devices so we can give a useful error rather than letting adb fail
# later with 'more than one device/emulator'.
#   - 'adb devices' prints a header line we must skip -> 'tail -n +2'
#   - blank lines are filtered out with grep
#   - only lines whose second column is exactly 'device' are usable; 'offline'
#     and 'unauthorized' devices are listed but cannot receive commands
DEVICE_COUNT=$(adb devices | tail -n +2 | grep -c '[[:space:]]device$' || true)

if [ "$DEVICE_COUNT" -eq 0 ]; then
    echo ""
    echo "ERROR: no device is in the 'device' state."
    echo "  * 'unauthorized' -> unlock the phone and accept the USB debugging prompt"
    echo "  * 'offline'      -> run: adb kill-server && adb start-server"
    echo "  * nothing listed -> check the cable carries data, and that USB"
    echo "                      debugging is enabled in Developer options"
    exit 1
fi

if [ "$DEVICE_COUNT" -gt 1 ] && [ -z "$ADB_TARGET" ]; then
    echo ""
    echo "ERROR: $DEVICE_COUNT devices attached. Pass a serial:"
    echo "  sh $0 <serial-from-the-list-above>"
    exit 1
fi

# -----------------------------------------------------------------------------
# Step 2 — what operating system is this?
# -----------------------------------------------------------------------------

section "Platform"

# 'getprop' reads Android's system property store: a shared key/value map
# populated at boot from build files and by init, and readable by any process.
# It is the fastest way to fingerprint a device, and it is also the first thing
# an app's emulator-detection code reads (see 39-EmulatorDetection).
#
# ro.build.version.release -> the marketing version, e.g. "14"
# ro.build.version.sdk     -> the API level, e.g. "34". THIS is the number that
#                             actually determines platform behaviour. Always
#                             quote the API level in findings, not just "14".
printf 'Android release : %s\n' "$(adb_run shell getprop ro.build.version.release | tr -d '\r')"
printf 'API level (SDK) : %s\n' "$(adb_run shell getprop ro.build.version.sdk | tr -d '\r')"

# 'tr -d "\r"' strips the carriage return that adb's shell adds to every line.
# Without it, the CR lands in your variables and quietly corrupts comparisons
# and file names. This is the single most common beginner bug with adb output.

# ro.product.cpu.abi      -> the primary ABI, e.g. "arm64-v8a"
# ro.product.cpu.abilist  -> every ABI the device can run, comma-separated
# The ABI decides which lib/<abi>/*.so directory inside an APK is used, and
# which frida-server build you must push.
printf 'Primary ABI     : %s\n' "$(adb_run shell getprop ro.product.cpu.abi | tr -d '\r')"
printf 'All ABIs        : %s\n' "$(adb_run shell getprop ro.product.cpu.abilist | tr -d '\r')"

# Manufacturer, model, and the build fingerprint. The fingerprint is a single
# string that uniquely identifies a build, and it belongs in every report.
printf 'Manufacturer    : %s\n' "$(adb_run shell getprop ro.product.manufacturer | tr -d '\r')"
printf 'Model           : %s\n' "$(adb_run shell getprop ro.product.model | tr -d '\r')"
printf 'Build fingerprint: %s\n' "$(adb_run shell getprop ro.build.fingerprint | tr -d '\r')"

# ro.debuggable is 1 on eng/userdebug builds and 0 on production 'user' builds.
# ro.secure is 0 when adbd may run as root. Together they tell you instantly
# whether 'adb root' will work.
printf 'ro.debuggable   : %s\n' "$(adb_run shell getprop ro.debuggable | tr -d '\r')"
printf 'ro.secure       : %s\n' "$(adb_run shell getprop ro.secure | tr -d '\r')"

# -----------------------------------------------------------------------------
# Step 3 — who are we on the device?
# -----------------------------------------------------------------------------

section "Identity of the adb shell"

# 'id' prints the Unix user and group of the process running the command. On a
# production build this is uid=2000(shell). UID 2000 is more privileged than an
# app (apps get UIDs from 10000 up) but is NOT root: it cannot read another
# app's private data directory. That boundary is the app sandbox (see 21).
adb_run shell id

# -----------------------------------------------------------------------------
# Step 4 — what is installed?
# -----------------------------------------------------------------------------

section "User-installed packages (pm list packages -3)"

# 'pm' is the package manager command-line front end. It talks over Binder to
# the PackageManagerService inside system_server.
#   -3  restrict to third-party packages, i.e. anything not shipped in the
#       system image. This is almost always what you want: the system list is
#       200+ entries of noise.
# 'sed' strips the "package:" prefix that pm prints on every line, and 'sort'
# makes the output stable so you can diff two runs.
adb_run shell pm list packages -3 | tr -d '\r' | sed 's/^package://' | sort

# Count them, so the reader sees at a glance whether this is a clean device.
PKG_COUNT=$(adb_run shell pm list packages -3 | tr -d '\r' | grep -c . || true)
printf '\nTotal third-party packages: %s\n' "$PKG_COUNT"

# -----------------------------------------------------------------------------
# Step 5 — battery and charging state
# -----------------------------------------------------------------------------

section "Battery (dumpsys battery)"

# 'dumpsys' asks a named system service to print its internal state. Every
# system service implements a dump() method, and dumpsys is how you read it.
# It is one of the highest-value commands on the platform: 'dumpsys package
# <name>', 'dumpsys activity', and 'dumpsys window' are used constantly during
# assessments. Here we use the simplest service as an introduction.
#
# We filter to the four fields that are actually informative, because the raw
# output is long. 'grep -E' enables extended regular expressions so we can use
# the alternation operator without escaping it.
adb_run shell dumpsys battery \
    | tr -d '\r' \
    | grep -E 'level|scale|status|temperature|powered' \
    || echo "(battery service produced no matching output)"

# Interpreting the fields:
#   level       current charge in units of 'scale' (scale is normally 100)
#   status      2=charging 3=discharging 4=not charging 5=full
#   temperature tenths of a degree Celsius, so 315 means 31.5 C
#   *powered    which source is supplying power
#
# Why a security person cares: battery temperature and charge level are among
# the signals apps use to distinguish a real phone from an emulator, because
# emulators historically reported implausibly constant values.

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------

section "Summary"

# Reassemble the one sentence every report starts with.
printf 'Target: %s %s, Android %s (API %s), %s\n' \
    "$(adb_run shell getprop ro.product.manufacturer | tr -d '\r')" \
    "$(adb_run shell getprop ro.product.model | tr -d '\r')" \
    "$(adb_run shell getprop ro.build.version.release | tr -d '\r')" \
    "$(adb_run shell getprop ro.build.version.sdk | tr -d '\r')" \
    "$(adb_run shell getprop ro.product.cpu.abi | tr -d '\r')"

echo ""
echo "Next: resolve a package to its APK and pull it —"
echo "  sh 00-Introduction/scripts/pull-apk.sh <package-name>"

# Exit 0 explicitly. A script's exit code is its return value to whatever ran
# it, and 0 conventionally means success.
exit 0
