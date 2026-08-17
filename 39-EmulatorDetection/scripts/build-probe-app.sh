#!/usr/bin/env bash
#
# scripts/build-probe-app.sh
#
# PURPOSE
#   Build, install and run examples/EmulatorSignals.java as a real Android app,
#   so that chapter 39's tables describe what an APP can see rather than what
#   `adb shell` can see. Those are different, and the difference is the point:
#   the shell is uid 2000 in the SELinux domain u:r:shell:s0 with extra
#   supplementary groups, while an app is an app uid in u:r:untrusted_app:s0.
#   Several signals this chapter grades DEAD are readable from the shell and
#   not from an app.
#
#   No Gradle, no Android Studio, no network. Just the SDK build-tools and a
#   JDK: aapt2 link -> javac -> d8 -> zipalign -> apksigner.
#
# USAGE
#   # host -- build only, into a temp directory
#   ./build-probe-app.sh
#
#   # host -- build, install, launch, and print the report from logcat
#   ./build-probe-app.sh --install --run
#
#   # host -- target a specific device when several are attached
#   ./build-probe-app.sh --install --run --serial emulator-5554
#
#   # host -- choose where build artefacts go
#   OUTDIR=/tmp/ch39 ./build-probe-app.sh --install --run
#
#   # host -- remove the app again
#   ./build-probe-app.sh --uninstall
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an SDK with build-tools
#     (aapt2, d8, zipalign, apksigner) and at least one platform android.jar.
#     The newest of each is chosen automatically.
#   * A JDK with javac and keytool.
#   * adb on PATH for --install / --run / --uninstall.
#
# NO ARTEFACTS IN THE REPOSITORY
#   .apk, .dex and .class are on this repository's artefact blocklist. This
#   script therefore builds entirely OUT OF TREE, under $OUTDIR, and writes
#   nothing next to the sources. Ship sources; let the reader build.
#
# AUTHORISED TESTING ONLY
#   The probe app requests no permissions, opens no sockets and writes nothing
#   outside its own private directory. Install it on a device you own.

set -u

PKG="com.pentest.ch39"
ACT="$PKG/.EmulatorSignals"
TAG="CH39"

HERE="$(cd "$(dirname "$0")" && pwd)"
SRCDIR="$(cd "$HERE/../examples" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch39-build}"

DO_INSTALL=0
DO_RUN=0
DO_UNINSTALL=0
SERIAL=""

while [ $# -gt 0 ]; do
    case "$1" in
        --install)   DO_INSTALL=1 ;;
        --run)       DO_RUN=1; DO_INSTALL=1 ;;
        --uninstall) DO_UNINSTALL=1 ;;
        --serial)    shift; SERIAL="${1:-}" ;;
        -h|--help)   sed -n '2,50p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

# adb wrapper that honours --serial.
ADB() {
    if [ -n "$SERIAL" ]; then adb -s "$SERIAL" "$@"; else adb "$@"; fi
}

# On Git Bash / MSYS the SDK tools are native Windows binaries and do not
# understand /c/Users/... paths. cygpath converts; elsewhere this is identity.
# Without it aapt2 reports "failed to load XML file" on a file that plainly
# exists, which is a genuinely confusing hour to lose.
p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

if [ "$DO_UNINSTALL" -eq 1 ]; then
    echo "uninstalling $PKG"
    ADB uninstall "$PKG" || ADB shell "su -c 'pm uninstall $PKG'" || true
    exit 0
fi

# --------------------------------------------------------------------------- #
# Locate the SDK and the JDK
# --------------------------------------------------------------------------- #
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" \
             "${LOCALAPPDATA:-}/Android/Sdk"; do
        [ -d "$c" ] && SDK="$c" && break
    done
fi
[ -d "${SDK:-}" ] || { echo "error: set ANDROID_HOME to your Android SDK" >&2; exit 2; }

BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
AJ="$(ls -d "$SDK"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] || { echo "error: no build-tools under $SDK" >&2; exit 2; }
[ -n "$AJ" ] || { echo "error: no platform android.jar under $SDK" >&2; exit 2; }

# build-tools ship .bat wrappers on Windows and extensionless scripts elsewhere.
pick() { if [ -x "$BT/$1" ]; then echo "$BT/$1"; else echo "$BT/$1.bat"; fi; }
AAPT2="$(pick aapt2)"; D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"
[ -x "$AAPT2" ]    || AAPT2="$BT/aapt2.exe"
[ -x "$ZIPALIGN" ] || ZIPALIGN="$BT/zipalign.exe"

echo "SDK          $SDK"
echo "build-tools  $(basename "$BT")"
echo "android.jar  $AJ"
echo "out          $OUTDIR"

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR/res" "$OUTDIR/classes" "$OUTDIR/dex" "$OUTDIR/src/com/pentest/ch39"

# --------------------------------------------------------------------------- #
# Manifest
#
# minSdkVersion 21 so the same APK installs on the API 30 phone and the API 35
# emulator this chapter was measured on. No <uses-permission> at all: every
# signal the probe reads is permission-free, which is itself a finding worth
# stating -- an app needs no special privilege to fingerprint the device it is
# running on.
#
# android:debuggable="true" so that `run-as` works and you can pull the report
# out of the app's private directory. That is a lab convenience, not a pattern
# to copy into anything real.
#
# XML comments must not contain a double hyphen; aapt2 rejects the file.
# --------------------------------------------------------------------------- #
cat > "$OUTDIR/AndroidManifest.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.pentest.ch39">

    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />

    <application
        android:label="CH39 Emulator Signals"
        android:debuggable="true"
        android:allowBackup="false">
        <activity
            android:name=".EmulatorSignals"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
EOF

cp "$SRCDIR/EmulatorSignals.java" "$OUTDIR/src/com/pentest/ch39/"

# --------------------------------------------------------------------------- #
# 1. aapt2 link -- compile resources and produce a base APK with the manifest
# --------------------------------------------------------------------------- #
echo "==> aapt2 link"
"$AAPT2" link \
    -I "$(p "$AJ")" \
    --manifest "$(p "$OUTDIR/AndroidManifest.xml")" \
    --java "$(p "$OUTDIR/src")" \
    -o "$(p "$OUTDIR/base.apk")" \
    || { echo "aapt2 link failed" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 2. javac -- compile to .class
#
# --release 8 keeps d8 happy without arguing about newer class file versions.
# Newer JDKs warn that release 8 is deprecated; that warning is filtered because
# it is noise, not a problem.
# --------------------------------------------------------------------------- #
echo "==> javac"
find "$OUTDIR/src" -name '*.java' > "$OUTDIR/sources.txt"
javac --release 8 \
      -classpath "$(p "$AJ")" \
      -d "$(p "$OUTDIR/classes")" \
      @"$(p "$OUTDIR/sources.txt")" 2>&1 \
    | grep -v 'source value 8 is obsolete\|target value 8 is obsolete\|To suppress warnings about obsolete\|warning: \[options\]' \
    || true

if ! find "$OUTDIR/classes" -name '*.class' | head -1 | grep -q class; then
    echo "javac produced no classes" >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
# 3. d8 -- .class to classes.dex
# --------------------------------------------------------------------------- #
echo "==> d8"
CLASSES="$(find "$OUTDIR/classes" -name '*.class')"
# shellcheck disable=SC2086
"$D8" --min-api 21 --lib "$(p "$AJ")" \
      --output "$(p "$OUTDIR/dex")" $CLASSES \
    || { echo "d8 failed" >&2; exit 1; }

# --------------------------------------------------------------------------- #
# 4. Assemble, align, sign
# --------------------------------------------------------------------------- #
# aapt2 produced base.apk containing the manifest and resources; classes.dex has
# to be added to that zip. Git Bash ships no `zip`, so fall back to the JDK's
# `jar`, which every machine that can run javac already has. `jar uf` updates an
# existing archive in place and stores the entry at the archive root, which is
# where the package manager expects classes.dex.
echo "==> assemble"
cp "$OUTDIR/base.apk" "$OUTDIR/unsigned.apk"
if command -v zip >/dev/null 2>&1; then
    ( cd "$OUTDIR/dex" && zip -q "$OUTDIR/unsigned.apk" classes.dex ) \
        || { echo "zip failed" >&2; exit 1; }
elif command -v jar >/dev/null 2>&1; then
    jar uf "$(p "$OUTDIR/unsigned.apk")" -C "$(p "$OUTDIR/dex")" classes.dex \
        || { echo "jar failed" >&2; exit 1; }
else
    echo "need either 'zip' or the JDK's 'jar' to assemble the APK" >&2
    exit 1
fi

echo "==> zipalign"
"$ZIPALIGN" -f -p 4 "$(p "$OUTDIR/unsigned.apk")" "$(p "$OUTDIR/aligned.apk")" \
    || { echo "zipalign failed" >&2; exit 1; }

echo "==> keystore + apksigner"
KS="$OUTDIR/debug.keystore"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -v -keystore "$(p "$KS")" -storepass android \
        -keypass android -alias ch39 -keyalg RSA -keysize 2048 -validity 3650 \
        -dname "CN=ch39-probe, OU=lab, O=lab, L=lab, S=lab, C=GB" >/dev/null 2>&1 \
        || { echo "keytool failed" >&2; exit 1; }
fi
"$APKSIGNER" sign --ks "$(p "$KS")" --ks-pass pass:android \
    --key-pass pass:android --ks-key-alias ch39 \
    --out "$(p "$OUTDIR/ch39-probe.apk")" "$(p "$OUTDIR/aligned.apk")" \
    || { echo "apksigner failed" >&2; exit 1; }

APK="$OUTDIR/ch39-probe.apk"
echo "built: $APK ($(wc -c < "$APK") bytes)"

[ "$DO_INSTALL" -eq 1 ] || exit 0

# --------------------------------------------------------------------------- #
# 5. Install
#
# MIUI returns INSTALL_FAILED_USER_RESTRICTED for adb install and for pm install
# from the device shell, regardless of the APK, because "Install via USB" is
# disabled at the vendor level. It is NOT a dead end: root is not subject to the
# gate. Chapter 30 measured this; the fallback below is the same one.
# --------------------------------------------------------------------------- #
echo "==> install"
if ADB install -r -t "$(p "$APK")" 2>&1 | tee "$OUTDIR/install.log" \
        | grep -q 'Success'; then
    echo "installed via adb install"
elif grep -q 'INSTALL_FAILED_USER_RESTRICTED' "$OUTDIR/install.log"; then
    echo "adb install blocked by vendor policy; retrying through root"
    ADB push "$(p "$APK")" /data/local/tmp/ch39-probe.apk >/dev/null
    if ADB shell "su -c 'pm install -r -t /data/local/tmp/ch39-probe.apk'" \
            2>&1 | grep -q 'Success'; then
        echo "installed via su -c pm install"
    else
        echo "install failed even with root; see $OUTDIR/install.log" >&2
        exit 1
    fi
    ADB shell rm -f /data/local/tmp/ch39-probe.apk
else
    echo "install failed; see $OUTDIR/install.log" >&2
    cat "$OUTDIR/install.log" >&2
    exit 1
fi

[ "$DO_RUN" -eq 1 ] || exit 0

# --------------------------------------------------------------------------- #
# 6. Run and collect
#
# The logcat buffer is cleared first so the report is not mixed with an older
# run's output. `am start -W` waits for the launch to complete before returning,
# which removes the need for a fixed sleep.
# --------------------------------------------------------------------------- #
echo "==> run"
ADB logcat -c 2>/dev/null || true
ADB shell am start -W -n "$ACT" >/dev/null 2>&1
# The Activity does all its work in onCreate, but logcat delivery is
# asynchronous. A short settle beats a race.
sleep 2
echo "---------------- report ----------------"
ADB logcat -d -s "$TAG:I" -v raw
echo "----------------------------------------"
echo
echo "Leave the app installed to re-run it, or remove it with:"
echo "  $0 --uninstall${SERIAL:+ --serial $SERIAL}"
