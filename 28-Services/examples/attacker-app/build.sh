#!/usr/bin/env bash
#
# examples/attacker-app/build.sh -- build and install the service prober WITHOUT
#                                   Gradle, Android Studio, or a network.
#
# WHAT IT DOES
#     Turns ProbeActivity.java + AndroidManifest.xml into a signed, installable
#     APK using only the Android SDK build-tools and a JDK. No Gradle wrapper to
#     download, no dependency resolution, no internet. The whole pipeline is
#     five commands and it is worth understanding, because it is what Gradle is
#     doing under several layers of abstraction:
#
#         javac      .java   -> .class
#         d8         .class  -> classes.dex
#         aapt2 link manifest-> unsigned.apk   (resources + binary manifest)
#         zip        add classes.dex to the apk
#         apksigner  sign it
#
#     The same script builds the victim (examples/VaultService-*.java) if you
#     point TARGET at it -- see VICTIM below.
#
# HOW TO RUN
#     # host, from inside examples/attacker-app/
#     sh build.sh                       # build only, leaves out/probe.apk
#     sh build.sh install               # build, then install
#     sh build.sh install root          # build, then install via `su` (see below)
#
#     ANDROID_HOME=/path/to/Sdk sh build.sh      # if the SDK is elsewhere
#
# REQUIREMENTS
#     - Android SDK build-tools 35.0.1 or newer, and an android.jar from any
#       recent platform. 34.0.0's d8 FAILED on this source with
#           "NullPointerException: Cannot invoke String.length()
#            because <parameter1> is null"
#       against class files from JDK 24 with -source 8 -target 8. 35.0.1
#       compiled the identical input cleanly. If you see that error, update
#       build-tools before you touch the code.
#     - A JDK with javac, jar and keytool. JDK 17 or newer is fine.
#     - `zip` or Python 3 (the script uses whichever is present).
#     - adb, only for the install step.
#
# WHAT THIS WILL *NOT* DO
#     - It does not build resources. There are none: no layouts, no drawables,
#       no strings.xml. Add `--dir res` to the aapt2 line if you add any.
#     - It does not produce a release-quality APK. The signing key is generated
#       here, on the spot, with a hard-coded password. That is correct for a
#       throwaway test tool and wrong for anything else.
#     - It does not handle multidex, R8, or libraries. One class, no deps.
#     - It cannot get past an OEM install restriction on its own. See the
#       INSTALL FAILURES section at the bottom.

set -eu

TARGET_PKG="com.pentest.ch28probe"
TARGET_CLS="ProbeActivity"

# The repository stores ProbeActivity.java FLAT, next to this script; an Android
# project would store it at src/com/pentest/ch28probe/. Accept either, and if it
# is flat, stage a package-shaped tree in out/src so javac is happy -- javac
# requires the directory layout to match the package declaration.
if [ -f "$TARGET_CLS.java" ]; then
    SRC_FLAT=1
    SRC_DIR="out/src/${TARGET_PKG//./\/}"
else
    SRC_FLAT=0
    SRC_DIR="src/${TARGET_PKG//./\/}"
    [ -f "$SRC_DIR/$TARGET_CLS.java" ] || {
        echo "cannot find $TARGET_CLS.java here or in $SRC_DIR" >&2; exit 1; }
fi

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
[ -d "$SDK" ] || SDK="$HOME/AppData/Local/Android/Sdk"

# Pick the newest build-tools present.
BT_DIR="$SDK/build-tools"
BT="$(ls -1 "$BT_DIR" 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] || { echo "no build-tools under $BT_DIR" >&2; exit 1; }
BT="$BT_DIR/$BT"

# Pick the newest platform android.jar present.
PLAT_DIR="$SDK/platforms"
PLAT="$(ls -1 "$PLAT_DIR" 2>/dev/null | sort -V | tail -1)"
[ -n "$PLAT" ] || { echo "no platforms under $PLAT_DIR" >&2; exit 1; }
AJ="$PLAT_DIR/$PLAT/android.jar"

# Windows hosts have .exe / .bat wrappers; POSIX hosts do not.
# -f, not -x: a .bat on a Windows filesystem mounted through Git Bash is not
# reported as executable, so -x silently falls through to the extensionless name
# and the build dies with "No such file or directory".
ext() { if [ -f "$1.exe" ]; then echo "$1.exe"; elif [ -f "$1.bat" ]; then echo "$1.bat";
        elif [ -f "$1" ]; then echo "$1"; else echo "$1"; fi; }
AAPT2="$(ext "$BT/aapt2")"
D8="$(ext "$BT/d8")"
APKSIGNER="$(ext "$BT/apksigner")"

echo "SDK          $SDK"
echo "build-tools  $BT"
echo "android.jar  $AJ"

OUT=out
rm -rf "$OUT"
mkdir -p "$OUT/classes"

if [ "$SRC_FLAT" = "1" ]; then
    mkdir -p "$SRC_DIR"
    cp "$TARGET_CLS.java" "$SRC_DIR/$TARGET_CLS.java"
fi

# ---------------------------------------------------------------- 1. javac
# -source/-target 8 because Android's dexer wants Java 8 class files unless you
# opt into desugaring. The three "obsolete options" warnings are expected.
echo "[1/5] javac"
javac -source 8 -target 8 -bootclasspath "$AJ" \
      -d "$OUT/classes" \
      "$SRC_DIR/$TARGET_CLS.java" 2>&1 | grep -v "bootstrap class path\|obsolete" || true

# ---------------------------------------------------------------- 2. d8
# d8 takes a jar more reliably than a list of loose .class files, and this
# source has an anonymous inner class (the ServiceConnection), which is exactly
# where the 34.0.0 bug above bit.
echo "[2/5] d8"
( cd "$OUT/classes" && jar cf ../classes.jar . )
"$D8" --lib "$AJ" --min-api 21 --output "$OUT" "$OUT/classes.jar"

# ---------------------------------------------------------------- 3. aapt2
# Produces the APK container with the binary AndroidManifest.xml in it.
echo "[3/5] aapt2 link"
"$AAPT2" link -I "$AJ" --manifest AndroidManifest.xml -o "$OUT/unsigned.apk"

# ---------------------------------------------------------------- 4. add dex
echo "[4/5] adding classes.dex"
cp "$OUT/unsigned.apk" "$OUT/withdex.apk"
if command -v zip >/dev/null 2>&1; then
    ( cd "$OUT" && zip -q withdex.apk classes.dex )
else
    python3 -B - "$OUT" <<'PY'
import sys, zipfile, os
out = sys.argv[1]
z = zipfile.ZipFile(os.path.join(out, 'withdex.apk'), 'a', zipfile.ZIP_DEFLATED)
z.write(os.path.join(out, 'classes.dex'), 'classes.dex')
z.close()
PY
fi

# ---------------------------------------------------------------- 5. sign
echo "[5/5] apksigner"
if [ ! -f "$OUT/debug.ks" ]; then
    keytool -genkeypair -keystore "$OUT/debug.ks" -alias k \
            -storepass android -keypass android \
            -keyalg RSA -keysize 2048 -validity 3650 \
            -dname "CN=ch28probe" 2>/dev/null
fi
"$APKSIGNER" sign --ks "$OUT/debug.ks" \
    --ks-pass pass:android --key-pass pass:android \
    --out "$OUT/probe.apk" "$OUT/withdex.apk" 2>&1 | grep -vi "warning" || true

ls -l "$OUT/probe.apk"
echo "built $OUT/probe.apk"

# ---------------------------------------------------------------- install
if [ "${1:-}" = "install" ]; then
    # MSYS_NO_PATHCONV stops Git Bash on Windows from rewriting the DEVICE path
    # /data/local/tmp into C:/Program Files/Git/data/local/tmp. Harmless on
    # Linux and macOS, where the variable is simply unused.
    export MSYS_NO_PATHCONV=1
    if [ "${2:-}" = "root" ]; then
        # For devices that refuse ordinary adb install. See below.
        adb push "$OUT/probe.apk" /data/local/tmp/ch28probe.apk
        adb shell "su -c 'pm install -r -t /data/local/tmp/ch28probe.apk'"
    else
        adb install -r "$OUT/probe.apk"
    fi
    adb shell "dumpsys package $TARGET_PKG | grep -E 'userId=|targetSdk'"
fi

# ===========================================================================
# VICTIM
#
# To build examples/VaultService-vulnerable.java (or -fixed) the same way,
# you need one extra step first, because it has an AIDL interface:
#
#   aidl --lang=java -Isrc -ogen src/com/example/notesvault/IVaultService.aidl
#
# and then add gen/com/example/notesvault/IVaultService.java to the javac line.
#
# ON WINDOWS, PASS BACKSLASH PATHS TO aidl.exe. Forward slashes are rejected:
#   ERROR: src/com/example/notesvault/IVaultService.aidl:3.1-10:
#          directory src/ is not found in any of the import paths:
#           - src\
# even though src/ plainly exists. This works:
#   aidl.exe --lang=java "-Isrc\" -ogen "src\com\example\notesvault\IVaultService.aidl"
#
# ===========================================================================
# INSTALL FAILURES YOU WILL ACTUALLY HIT
#
# INSTALL_FAILED_USER_RESTRICTED: Install canceled by user
#     An OEM restriction, not an Android one, and not a problem with your APK.
#     Measured on the Redmi M2101K6P used for this chapter: every attempt to
#     install a NEW package over adb was refused, while installing an UPDATE to
#     an already-present package went through. On MIUI the fix is Developer
#     options -> "Install via USB", which requires being signed in to a Mi
#     account. `sh build.sh install root` is the workaround if the device is
#     rooted -- and note that root is being used only to INSTALL. The app then
#     runs as an ordinary unprivileged app, which is what every measurement in
#     the chapter depends on.
#
# INSTALL_FAILED_INVALID_APK: ... code is missing
#     classes.dex did not make it into the APK. Step 2 or step 4 failed
#     silently. Check that out/classes.dex exists and is non-empty.
#
# INSTALL_FAILED_UPDATE_INCOMPATIBLE
#     A previous build is installed with a different signing key. `adb uninstall
#     com.pentest.ch28probe` first. Deleting out/debug.ks between builds causes
#     this.
