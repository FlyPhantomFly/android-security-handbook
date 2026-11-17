#!/usr/bin/env bash
# probe-security-levels.sh — build, push and run SecurityLevelProbe.java on an attached device.
#
# PURPOSE
#   One command that answers "what security level does THIS device actually give each key type?".
#   It compiles SecurityLevelProbe.java against android.jar, converts it to DEX with d8, pushes the
#   DEX to /data/local/tmp, and runs it inside a real Android VM via app_process.
#
#   The point of app_process is that it needs NO ROOT and NO APK INSTALL. You get a genuine ART
#   runtime with the full framework on the classpath, running as uid 2000 (shell), able to talk to
#   keystore2 over Binder exactly as an app would.
#
# USAGE
#   ./probe-security-levels.sh                    # probe, print the table, delete every probe key
#   ./probe-security-levels.sh --attest           # also print the attestation chain as PEM
#   ./probe-security-levels.sh --keep             # leave the keys behind (for lab-01)
#   ANDROID_SERIAL=<serial> ./probe-security-levels.sh     # pick a device when several are attached
#
#   Environment overrides:
#     ANDROID_HOME     Android SDK root       (default: $HOME/AppData/Local/Android/Sdk on Windows,
#                                                       $HOME/Android/Sdk elsewhere)
#     ANDROID_JAR      explicit path to an android.jar
#     BUILD_TOOLS      explicit path to a build-tools directory containing d8
#     WORKDIR          scratch build directory (default: a mktemp -d OUTSIDE this repository)
#
# REQUIREMENTS
#   bash, adb on PATH, a JDK (javac), Android SDK build-tools (d8), an android.jar (API 31+ so that
#   KeyInfo.getSecurityLevel() resolves at compile time), and a device with USB debugging on.
#   No root. No frida. No installed app.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - Nothing about the app you are testing. It measures the DEVICE's capability ceiling. An app can
#     sit far below that ceiling, and that gap is the finding — see ../labs/lab-01-measure-every-key-type.md.
#   - It cannot distinguish "the TEE refused" from "the framework refused before asking the TEE".
#     The probe prints exception text verbatim so you can judge; do not let this script judge for you.
#   - It says nothing about the QUALITY of the TEE. TRUSTED_ENVIRONMENT is a location, not a grade.
#   - On a device whose SELinux policy denies the shell domain access to keystore2 it will fail with
#     a permission error, and you must fall back to an installed APK.
#
# SAFETY
#   Builds OUT OF TREE: no .class, .dex or .apk is written anywhere inside this repository.
#   The probe deletes every key it creates unless you pass --keep. It never touches a key it did
#   not create. It removes its own DEX from the device at the end.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/SecurityLevelProbe.java"
DEVICE_DEX="/data/local/tmp/ch50-slprobe.dex"

die() { echo "error: $*" >&2; exit 1; }

# --- locate the SDK ------------------------------------------------------------------------------
if [ -z "${ANDROID_HOME:-}" ]; then
    if [ -d "$HOME/AppData/Local/Android/Sdk" ]; then
        ANDROID_HOME="$HOME/AppData/Local/Android/Sdk"
    elif [ -d "$HOME/Android/Sdk" ]; then
        ANDROID_HOME="$HOME/Android/Sdk"
    elif [ -d "$HOME/Library/Android/sdk" ]; then
        ANDROID_HOME="$HOME/Library/Android/sdk"
    fi
fi

if [ -z "${ANDROID_JAR:-}" ]; then
    # Highest-numbered platform wins; we need API 31+ for KeyInfo.getSecurityLevel().
    ANDROID_JAR="$(ls -d "$ANDROID_HOME"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
fi
[ -n "${ANDROID_JAR:-}" ] && [ -f "$ANDROID_JAR" ] || die "no android.jar found; set ANDROID_JAR"

if [ -z "${BUILD_TOOLS:-}" ]; then
    BUILD_TOOLS="$(ls -d "$ANDROID_HOME"/build-tools/* 2>/dev/null | sort -V | tail -1)"
fi
[ -n "${BUILD_TOOLS:-}" ] && [ -d "$BUILD_TOOLS" ] || die "no build-tools found; set BUILD_TOOLS"

D8="$BUILD_TOOLS/d8"
[ -x "$D8" ] || D8="$BUILD_TOOLS/d8.bat"
[ -f "$D8" ] || die "d8 not found in $BUILD_TOOLS"

command -v adb  >/dev/null || die "adb not on PATH"
command -v javac >/dev/null || die "javac not on PATH"
[ -f "$SRC" ] || die "SecurityLevelProbe.java not next to this script"

# --- one device, identified out loud --------------------------------------------------------------
# `adb get-state` fails whenever more than one entry is listed — including an *offline* emulator
# that you cannot use anyway. Pick the single online device ourselves before giving up.
if ! adb get-state >/dev/null 2>&1 && [ -z "${ANDROID_SERIAL:-}" ]; then
    ONLINE="$(adb devices | tr -d '\r' | awk '$2=="device"{print $1}')"
    COUNT="$(printf '%s\n' "$ONLINE" | grep -c . )"
    if [ "$COUNT" = "1" ]; then
        ANDROID_SERIAL="$ONLINE"; export ANDROID_SERIAL
        echo "note: several adb entries, exactly one online — using $ANDROID_SERIAL"
    else
        die "need exactly one online device (found $COUNT) — set ANDROID_SERIAL"
    fi
fi
adb get-state >/dev/null 2>&1 || die "device not ready"
MODEL="$(adb shell getprop ro.product.model | tr -d '\r')"
SDKV="$(adb shell getprop ro.build.version.sdk | tr -d '\r')"
REL="$(adb shell getprop ro.build.version.release | tr -d '\r')"
echo "device: $MODEL   Android $REL (API $SDKV)"
[ "$SDKV" -ge 23 ] 2>/dev/null || echo "warning: API $SDKV predates KeyGenParameterSpec; results will be thin"

# --- build, strictly out of tree -------------------------------------------------------------------
WORKDIR="${WORKDIR:-$(mktemp -d 2>/dev/null || mktemp -d -t ch50)}"
case "$WORKDIR" in
    *Android-Security-Handbook*) die "refusing to build inside the repository ($WORKDIR)";;
esac
trap 'rm -rf "$WORKDIR"' EXIT
echo "build dir: $WORKDIR"

javac -nowarn -source 8 -target 8 -bootclasspath "$ANDROID_JAR" -d "$WORKDIR/classes" "$SRC" \
    || die "javac failed"
"$D8" --lib "$ANDROID_JAR" --output "$WORKDIR" "$WORKDIR"/classes/*.class \
    || die "d8 failed"
[ -f "$WORKDIR/classes.dex" ] || die "d8 produced no classes.dex"

# --- push and run ----------------------------------------------------------------------------------
# Git Bash on Windows rewrites any argument that looks like a POSIX path, so `/data/local/tmp`
# arrives at adb as `C:/Program Files/Git/data/local/tmp` and the push fails with a baffling
# "remote secure_mkdirs failed". MSYS_NO_PATHCONV=1 disables that — but it disables it for the
# LOCAL argument too, and the local argument genuinely needs converting. So convert it by hand
# with cygpath and turn the rewriting off for everything else.
LOCAL_DEX="$WORKDIR/classes.dex"
if command -v cygpath >/dev/null 2>&1; then LOCAL_DEX="$(cygpath -w "$LOCAL_DEX")"; fi
export MSYS_NO_PATHCONV=1
adb push "$LOCAL_DEX" "$DEVICE_DEX" >/dev/null || die "adb push failed"
echo

adb shell "CLASSPATH=$DEVICE_DEX app_process /data/local/tmp SecurityLevelProbe $*"
RC=$?

adb shell "rm -f $DEVICE_DEX" >/dev/null 2>&1
echo
echo "removed $DEVICE_DEX from the device"
exit $RC
