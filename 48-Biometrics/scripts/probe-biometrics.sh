#!/usr/bin/env bash
# probe-biometrics.sh — build, push and run BiometricProbe.java on an attached device.
#
# PURPOSE
#   One command that answers "does this device actually ENFORCE biometric auth binding, or does it
#   only display a prompt?". It compiles ../scripts/BiometricProbe.java against android.jar,
#   converts it to DEX with d8, pushes the DEX to /data/local/tmp, and runs it inside a real Android
#   VM via app_process. Then it deletes both the DEX and every key the probe created.
#
#   The interesting line in the output is `key.peruse.cipherInit`. If it reads
#   "UserNotAuthenticatedException" the hardware is enforcing the binding. If it reads "OK" the
#   binding is decorative and every biometric gate on the device built on that key is a UI event.
#
# USAGE
#   ./probe-biometrics.sh                       # probe, print the table, delete every probe key
#   ./probe-biometrics.sh --json                # machine-readable, for diffing two devices
#   ./probe-biometrics.sh --keep                # leave keys behind (labs/lab-02 needs them)
#   ANDROID_SERIAL=<serial> ./probe-biometrics.sh    # pick a device when several are attached
#
#   Environment overrides:
#     ANDROID_HOME   Android SDK root  (default: $HOME/AppData/Local/Android/Sdk on Windows,
#                                                $HOME/Android/Sdk elsewhere)
#     ANDROID_JAR    explicit path to an android.jar (API 30+)
#     BUILD_TOOLS    explicit path to a build-tools directory containing d8
#     WORKDIR        scratch build directory (default: mktemp -d, OUTSIDE this repository)
#
# REQUIREMENTS
#   bash, adb on PATH, a JDK (javac), Android SDK build-tools (d8), an android.jar at API 30 or
#   above, and a device with USB debugging enabled. No root. No frida. No installed app.
#
# COMPANION
#   ../scripts/hook-biometric-prompt.js does the opposite job — it attacks an installed app's
#   prompt from the inside. Run this one first: it tells you whether the device is even capable of
#   enforcing what the app claims, which decides whether a successful hook is a finding or noise.
#
# SAFETY
#   Builds OUT OF TREE: no .class or .dex is written anywhere inside this repository.
#   Removes /data/local/tmp/ch48-probe.dex on exit, including on failure.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/BiometricProbe.java"
DEVICE_DEX="/data/local/tmp/ch48-probe.dex"

die() { echo "error: $*" >&2; exit 1; }

# --- locate the SDK -------------------------------------------------------------------------------
if [ -z "${ANDROID_HOME:-}" ]; then
    if   [ -d "$HOME/AppData/Local/Android/Sdk" ]; then ANDROID_HOME="$HOME/AppData/Local/Android/Sdk"
    elif [ -d "$HOME/Android/Sdk" ];               then ANDROID_HOME="$HOME/Android/Sdk"
    elif [ -d "$HOME/Library/Android/sdk" ];       then ANDROID_HOME="$HOME/Library/Android/sdk"
    fi
fi

if [ -z "${ANDROID_JAR:-}" ]; then
    ANDROID_JAR="$(ls -d "${ANDROID_HOME:-/nonexistent}"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"
fi
[ -n "${ANDROID_JAR:-}" ] && [ -f "$ANDROID_JAR" ] || die "no android.jar found; set ANDROID_JAR"

if [ -z "${BUILD_TOOLS:-}" ]; then
    BUILD_TOOLS="$(ls -d "${ANDROID_HOME:-/nonexistent}"/build-tools/* 2>/dev/null | sort -V | tail -1)"
fi
[ -n "${BUILD_TOOLS:-}" ] && [ -d "$BUILD_TOOLS" ] || die "no build-tools found; set BUILD_TOOLS"

D8="$BUILD_TOOLS/d8"
[ -x "$D8" ] || D8="$BUILD_TOOLS/d8.bat"
[ -f "$D8" ] || die "d8 not found in $BUILD_TOOLS"

command -v adb   >/dev/null || die "adb not on PATH"
command -v javac >/dev/null || die "javac not on PATH"
[ -f "$SRC" ]               || die "BiometricProbe.java not next to this script"

# --- exactly one device, named out loud -----------------------------------------------------------
# `adb get-state` fails whenever more than one entry is listed, including an offline emulator you
# could not use anyway. Pick the single online device ourselves before giving up.
if ! adb get-state >/dev/null 2>&1 && [ -z "${ANDROID_SERIAL:-}" ]; then
    ONLINE="$(adb devices | tr -d '\r' | awk '$2=="device"{print $1}')"
    COUNT="$(printf '%s\n' "$ONLINE" | grep -c . )"
    if [ "$COUNT" = "1" ]; then
        ANDROID_SERIAL="$ONLINE"; export ANDROID_SERIAL
        echo "note: several adb entries, exactly one online - using $ANDROID_SERIAL"
    else
        die "need exactly one online device (found $COUNT) - set ANDROID_SERIAL"
    fi
fi
adb get-state >/dev/null 2>&1 || die "device not ready"

MODEL="$(adb shell getprop ro.product.model      | tr -d '\r')"
SDKV="$(adb shell getprop ro.build.version.sdk   | tr -d '\r')"
REL="$(adb shell getprop ro.build.version.release| tr -d '\r')"
echo "device: $MODEL   Android $REL (API $SDKV)"
[ "$SDKV" -ge 23 ] 2>/dev/null || die "API $SDKV predates KeyGenParameterSpec; nothing to measure"
if [ "$SDKV" -lt 29 ] 2>/dev/null; then
    echo "warning: API $SDKV predates BiometricManager.canAuthenticate; the KeyStore half still works"
fi

# --- lock state, because it silently changes the answer -------------------------------------------
# A key with a time-bound validity window is satisfiable by ANY recent unlock, including the one you
# just did to look at the screen. Report the state rather than let it corrupt the reading.
LOCKED="$(adb shell dumpsys trust 2>/dev/null | tr -d '\r' | grep -o 'deviceLocked=[01]' | head -1)"
[ -n "$LOCKED" ] && echo "trust: $LOCKED   (an unlocked device satisfies time-bound keys)"

# --- build, strictly out of tree ------------------------------------------------------------------
WORKDIR="${WORKDIR:-$(mktemp -d 2>/dev/null || mktemp -d -t ch48)}"
case "$WORKDIR" in
    *Android-Security-Handbook*) die "refusing to build inside the repository ($WORKDIR)";;
esac
cleanup_host() { rm -rf "$WORKDIR"; }
trap 'cleanup_host' EXIT
echo "build dir: $WORKDIR"

# -source/-target rather than --release: `--release` refuses to coexist with `-bootclasspath`
# ("option --boot-class-path cannot be used together with --release"), and we need the bootclasspath
# so that android.* resolves and the JDK's own java.* does not shadow the stubs. `-Xlint:-options`
# suppresses the "source value 8 is obsolete" nag that JDK 21+ prints on every invocation.
# d8 accepts class file version 52 happily.
javac -nowarn -Xlint:-options -source 8 -target 8 -bootclasspath "$ANDROID_JAR" \
      -d "$WORKDIR/classes" "$SRC" 2>"$WORKDIR/javac.err" \
    || { sed -n '1,25p' "$WORKDIR/javac.err" >&2; die "javac failed"; }

"$D8" --lib "$ANDROID_JAR" --min-api "$SDKV" --output "$WORKDIR" "$WORKDIR"/classes/*.class \
    || die "d8 failed"
[ -f "$WORKDIR/classes.dex" ] || die "d8 produced no classes.dex"

# --- push and run ---------------------------------------------------------------------------------
# Git Bash on Windows rewrites any argument that looks like a POSIX path, so /data/local/tmp arrives
# at adb as C:/Program Files/Git/data/local/tmp and the push fails with a baffling
# "remote secure_mkdirs failed". MSYS_NO_PATHCONV=1 disables that - but it disables it for the LOCAL
# argument too, which genuinely needs converting. Convert that one by hand with cygpath.
LOCAL_DEX="$WORKDIR/classes.dex"
if command -v cygpath >/dev/null 2>&1; then LOCAL_DEX="$(cygpath -w "$LOCAL_DEX")"; fi
export MSYS_NO_PATHCONV=1

adb push "$LOCAL_DEX" "$DEVICE_DEX" >/dev/null || die "adb push failed"
remove_dex() { adb shell "rm -f $DEVICE_DEX" >/dev/null 2>&1; cleanup_host; }
trap 'remove_dex' EXIT
echo

adb shell "CLASSPATH=$DEVICE_DEX app_process /data/local/tmp BiometricProbe $*"
RC=$?

echo
echo "removed $DEVICE_DEX from the device"
exit $RC
