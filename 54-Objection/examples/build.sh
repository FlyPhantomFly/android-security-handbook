#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build and install examples/target-app/ -- the chapter 54 measuring
#   instrument -- using only the Android SDK build-tools and a JDK. No Gradle,
#   no Android Studio, no network.
#
#   The repository ships SOURCES, never built APKs. `.apk`, `.dex` and `.class`
#   are on the artefact blocklist, so this script builds OUT OF TREE: everything
#   lands under $OUTDIR and nothing is written next to the sources.
#
#   The build pipeline is the one proven in 30-Activities/examples/build.sh:
#       aapt2 link -> javac --release 8 -> d8 -> zip in classes.dex
#                  -> zipalign -> apksigner
#
# USAGE
#   # host -- build only
#   ./build.sh
#
#   # host -- build and install on the attached device
#   ./build.sh --install
#
#   # host -- choose where artefacts go
#   OUTDIR=/tmp/ch54 ./build.sh --install
#
#   # host -- remove the app from the device
#   ./build.sh --uninstall
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an SDK that has build-tools
#     (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#   * A JDK with javac and keytool.
#   * `adb` on PATH for --install / --uninstall.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * Whether objection works. That is labs/lab-01's job. This script only puts
#     a target on the device.
#   * Whether the device is rooted. The app reports what its five checks see,
#     which is a different question -- that gap is the whole chapter.
#   * It will NOT get past an OEM install restriction on its own. On the MIUI
#     device this chapter was written against, `adb install` returns
#     INSTALL_FAILED_USER_RESTRICTED for any APK. The script detects that exact
#     failure and retries through root, which is what works there.
#
# AUTHORISED TESTING ONLY. This app exists to be instrumented. Install it on a
# device you own and uninstall it when you are finished.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch54-build}"
PKG="com.pentest.ch54.target"
PKGPATH="com/pentest/ch54/target"

# On Git Bash / MSYS the SDK tools are native Windows binaries and do NOT
# understand /c/Users/... paths. cygpath converts; elsewhere this is identity.
# Without it aapt2 reports "failed to load XML file" on a file that plainly
# exists, which is a confusing hour to lose.
p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

# --------------------------------------------------------------------------- #
# Locate the SDK
# --------------------------------------------------------------------------- #
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "$LOCALAPPDATA/Android/Sdk"; do
        [ -d "$c" ] && SDK="$c" && break
    done
fi
[ -d "${SDK:-}" ] || { echo "error: set ANDROID_HOME to your Android SDK"; exit 2; }

BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
AJ="$(ls -d "$SDK"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] || { echo "error: no build-tools under $SDK"; exit 2; }
[ -n "$AJ" ] || { echo "error: no platform android.jar under $SDK"; exit 2; }

# build-tools ship .bat wrappers on Windows and extensionless scripts elsewhere.
pick() { [ -x "$BT/$1" ] && echo "$BT/$1" || echo "$BT/$1.bat"; }
AAPT2="$(pick aapt2)"; D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"
[ -x "$AAPT2" ]    || AAPT2="$BT/aapt2.exe"
[ -x "$ZIPALIGN" ] || ZIPALIGN="$BT/zipalign.exe"

echo "SDK         $SDK"
echo "build-tools $(basename "$BT")"
echo "android.jar $AJ"
echo "outdir      $OUTDIR"
echo

# --------------------------------------------------------------------------- #
# Uninstall path needs no build
# --------------------------------------------------------------------------- #
if [ "${1:-}" = "--uninstall" ]; then
    adb uninstall "$PKG" 2>&1 | tail -1
    adb shell "su -c 'pm uninstall $PKG'" 2>&1 | tail -1
    exit 0
fi

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# A throwaway signing key. It exists so the package manager accepts the file,
# and for nothing else.
# --------------------------------------------------------------------------- #
KS="$OUTDIR/debug.ks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$KS" -storepass android -keypass android \
        -alias ch54 -dname "CN=CH54 Lab,O=Android Security Handbook" \
        -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
        || { echo "error: keytool failed -- is a JDK on PATH?"; exit 2; }
    echo "generated throwaway signing key at $KS"
fi

# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #
SRC="$HERE/target-app"
WORK="$OUTDIR/target-app"

echo "=== building $PKG ==="
rm -rf "$WORK"
mkdir -p "$WORK/src/$PKGPATH" "$WORK/classes"
cp "$SRC"/*.java "$WORK/src/$PKGPATH/"

"$AAPT2" link -o "$(p "$WORK/base.apk")" -I "$(p "$AJ")" \
    --manifest "$(p "$SRC/AndroidManifest.xml")" \
    --min-sdk-version 21 --target-sdk-version 30 || exit 1

javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$WORK/classes" \
    "$WORK/src/$PKGPATH"/*.java 2>&1 | grep -vE 'obsolete|Xlint|^[0-9]+ warning'

classfiles=()
while IFS= read -r f; do classfiles+=("$(p "$f")"); done < <(find "$WORK/classes" -name '*.class')
[ "${#classfiles[@]}" -gt 0 ] || { echo "error: javac produced no classes"; exit 1; }

"$D8" --lib "$(p "$AJ")" --min-api 21 --output "$(p "$WORK")" "${classfiles[@]}" || exit 1

# Add classes.dex to the resource-only APK aapt2 produced. `zip -j` would do,
# but zip is not always present on Windows; python is.
( cd "$WORK" && python3 -B -c "
import zipfile, shutil
shutil.copy('base.apk', 'unaligned.apk')
z = zipfile.ZipFile('unaligned.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('classes.dex', 'classes.dex')
z.close()
" ) || exit 1

"$ZIPALIGN" -f -p 4 "$(p "$WORK/unaligned.apk")" "$(p "$WORK/aligned.apk")" || exit 1
"$APKSIGNER" sign --ks "$(p "$KS")" --ks-pass pass:android --key-pass pass:android \
    --out "$(p "$WORK/target-app.apk")" "$(p "$WORK/aligned.apk")" 2>&1 | grep -v WARNING

echo "built $WORK/target-app.apk"
echo

# --------------------------------------------------------------------------- #
# Install
# --------------------------------------------------------------------------- #
if [ "${1:-}" = "--install" ]; then
    APK="$WORK/target-app.apk"
    out="$(adb install -r "$APK" 2>&1)"
    if echo "$out" | grep -q Success; then
        echo "installed $PKG"
    elif echo "$out" | grep -q INSTALL_FAILED_USER_RESTRICTED; then
        echo "adb install refused: INSTALL_FAILED_USER_RESTRICTED"
        echo "  This is an OEM restriction ('Install via USB'), not a fault in the APK."
        echo "  Trying the root path..."
        adb push "$APK" /data/local/tmp/ch54-target.apk >/dev/null 2>&1
        out="$(adb shell "su -c 'pm install -r /data/local/tmp/ch54-target.apk'" 2>&1)"
        adb shell rm -f /data/local/tmp/ch54-target.apk >/dev/null 2>&1
        if echo "$out" | grep -q Success; then
            echo "installed $PKG via root"
        else
            echo "  root install also failed:"; echo "$out" | head -3; exit 1
        fi
    else
        echo "install failed:"; echo "$out" | head -5; exit 1
    fi

    echo
    echo "next:"
    echo "  adb logcat -c && adb shell am start -n $PKG/.MainActivity && adb logcat -d -s CH54"
    echo "  objection -g $PKG explore"
fi
