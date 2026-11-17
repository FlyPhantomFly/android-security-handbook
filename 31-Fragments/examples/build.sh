#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build the two lab APKs for chapter 31 -- examples/victim-app/ and
#   examples/attacker-app/ -- from the sources in this directory, using only the
#   Android SDK build-tools and a JDK. No Gradle, no Android Studio, no network.
#
#   The repository ships SOURCES, never built APKs. `.apk`, `.dex` and `.class`
#   are on the artefact blocklist, so this script builds OUT OF TREE: everything
#   it produces lands under $OUTDIR (default: a temp directory), and nothing is
#   written next to the sources.
#
#   The structure is deliberately the same as 30-Activities/examples/build.sh,
#   including its root-install fallback, so that a reader who has built one
#   chapter's apps can build the other without relearning anything.
#
# USAGE
#   # host -- build only
#   ./build.sh
#
#   # host -- build and install both apps on the attached device
#   ./build.sh --install
#
#   # host -- build with a legacy targetSdkVersion, to test the KITKAT branch of
#   #         PreferenceActivity.isValidFragment (see labs/lab-02)
#   TARGET_SDK=17 ./build.sh --install
#
#   # host -- choose where artefacts go
#   OUTDIR=/tmp/ch31 ./build.sh --install
#
#   # host -- remove both apps from the device
#   ./build.sh --uninstall
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an Android SDK that has
#     build-tools (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#     The script picks the newest of each it can find.
#   * A JDK with javac and keytool.
#   * `adb` on PATH for --install.
#
# WAS THIS EXECUTED?
#   YES. Run on 2026-08-16 against Android SDK build-tools 35.0.1, platform
#   android-35 and JDK 24.0.2, targeting the AVD `sdk_gphone16k_x86_64`
#   (Android 15 / API 35, x86_64, rooted with Magisk 30.7). Both APKs built and
#   installed; every attack in labs 01 to 05 was run from them. The measured
#   results are in README section 5 and section 7.
#
# AUTHORISED TESTING ONLY. These apps are deliberately vulnerable. Install them
# on a device you own, and uninstall them when you are done:
#   ./build.sh --uninstall

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch31-build}"
MIN_SDK="${MIN_SDK:-21}"
TARGET_SDK="${TARGET_SDK:-35}"

# --uninstall must not need an SDK, a JDK or a signing key. Handling it before
# anything else is not a style preference: the first version of this script fell
# through to the keystore step and refused to clean up the device when the JDK
# was not on PATH, which is exactly when you most want the cleanup to work.
if [ "${1:-}" = "--uninstall" ]; then
    adb uninstall com.pentest.ch31.victim   2>&1 | tail -1
    adb uninstall com.pentest.ch31.attacker 2>&1 | tail -1
    echo "removed both lab apps."
    exit 0
fi

# On Git Bash / MSYS the SDK tools are native Windows binaries and do NOT
# understand /c/Users/... paths. cygpath converts; everywhere else this is the
# identity function. Without it aapt2 reports "failed to load XML file" on a
# file that plainly exists.
p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

# --------------------------------------------------------------------------- #
# Locate the SDK
# --------------------------------------------------------------------------- #
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "${LOCALAPPDATA:-}/Android/Sdk"; do
        [ -d "$c" ] && SDK="$c" && break
    done
fi
[ -d "${SDK:-}" ] || { echo "error: set ANDROID_HOME to your Android SDK"; exit 2; }

BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
AJ="$(ls -d "$SDK"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] || { echo "error: no build-tools under $SDK"; exit 2; }
[ -n "$AJ" ] || { echo "error: no platform android.jar under $SDK"; exit 2; }

pick() { [ -x "$BT/$1" ] && echo "$BT/$1" || echo "$BT/$1.bat"; }
AAPT2="$(pick aapt2)"; D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"
[ -x "$AAPT2" ]    || AAPT2="$BT/aapt2.exe"
[ -x "$ZIPALIGN" ] || ZIPALIGN="$BT/zipalign.exe"

echo "SDK         $SDK"
echo "build-tools $(basename "$BT")"
echo "android.jar $AJ"
echo "minSdk      $MIN_SDK"
echo "targetSdk   $TARGET_SDK"
echo "outdir      $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# A throwaway signing key
# --------------------------------------------------------------------------- #
KS="$OUTDIR/debug.ks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$KS" -storepass android -keypass android \
        -alias ch31 -dname "CN=CH31 Lab,O=Android Security Handbook" \
        -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
        || { echo "error: keytool failed -- is a JDK on PATH?"; exit 2; }
    echo "generated throwaway signing key at $KS"
fi

# --------------------------------------------------------------------------- #
# build <app-dir-name> <java-package-path>
# --------------------------------------------------------------------------- #
build_app() {
    local app="$1" pkgpath="$2"
    local src="$HERE/$app"
    local work="$OUTDIR/$app"

    echo "=== building $app ==="
    rm -rf "$work"
    mkdir -p "$work/src/$pkgpath" "$work/classes"

    cp "$src"/*.java "$work/src/$pkgpath/" 2>/dev/null

    "$AAPT2" link -o "$(p "$work/base.apk")" -I "$(p "$AJ")" \
        --manifest "$(p "$src/AndroidManifest.xml")" \
        --min-sdk-version "$MIN_SDK" --target-sdk-version "$TARGET_SDK" || return 1

    # --release 8 keeps d8 happy without a desugaring config. `-nowarn` is not
    # cosmetic here: PreferenceActivity and android.app.Fragment are both
    # deprecated, and that is the chapter's subject, not a defect.
    javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$work/classes" \
        "$work/src/$pkgpath"/*.java 2>&1 | grep -vE 'deprecat|obsolete|Xlint|^[0-9]+ warning'

    if [ ! -d "$work/classes/$pkgpath" ]; then
        echo "error: javac produced no classes for $app"
        return 1
    fi

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done < <(find "$work/classes" -name '*.class')
    "$D8" --lib "$(p "$AJ")" --min-api "$MIN_SDK" --output "$(p "$work")" "${classfiles[@]}" || return 1

    # Add classes.dex to the resource-only APK aapt2 produced. `zip -j` would
    # do, but zip is not always present on Windows; python is.
    ( cd "$work" && python3 -B -c "
import zipfile, shutil
shutil.copy('base.apk', 'unaligned.apk')
z = zipfile.ZipFile('unaligned.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('classes.dex', 'classes.dex')
z.close()
" ) || return 1

    "$ZIPALIGN" -f -p 4 "$(p "$work/unaligned.apk")" "$(p "$work/aligned.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$KS")" --ks-pass pass:android --key-pass pass:android \
        --out "$(p "$work/$app.apk")" "$(p "$work/aligned.apk")" 2>&1 | grep -v WARNING

    echo "built $work/$app.apk"
    echo
}

install_apk() {
    local apk="$1" name="$2"
    local out
    out="$(adb install -r "$apk" 2>&1)"
    if echo "$out" | grep -q Success; then
        echo "installed $name"
        return 0
    fi
    if echo "$out" | grep -q INSTALL_FAILED_USER_RESTRICTED; then
        echo "adb install refused: INSTALL_FAILED_USER_RESTRICTED"
        echo "  This is an OEM restriction ('Install via USB'), not a fault in the APK."
        echo "  Trying the root path..."
        adb push "$apk" /data/local/tmp/ch31.apk >/dev/null 2>&1
        # NOTE the quoting. `adb shell su -c '...'` loses everything after the
        # first word; the whole command must be one argument to adb shell.
        # On the API 35 AVD, Magisk's su wants `su 0 <cmd>` and rejects `-c`,
        # so both forms are tried.
        out="$(adb shell "su -c 'pm install -r /data/local/tmp/ch31.apk'" 2>&1)"
        if ! echo "$out" | grep -q Success; then
            out="$(adb shell "su 0 pm install -r /data/local/tmp/ch31.apk" 2>&1)"
        fi
        adb shell rm -f /data/local/tmp/ch31.apk >/dev/null 2>&1
        if echo "$out" | grep -q Success; then
            echo "installed $name via root"
            return 0
        fi
        echo "  root install also failed:"
        echo "$out" | head -3
        return 1
    fi
    echo "install of $name failed:"
    echo "$out" | head -5
    return 1
}

build_app victim-app   com/pentest/ch31/victim   || exit 1
build_app attacker-app com/pentest/ch31/attacker || exit 1

case "${1:-}" in
    --install)
        install_apk "$OUTDIR/victim-app/victim-app.apk"     "com.pentest.ch31.victim"
        install_apk "$OUTDIR/attacker-app/attacker-app.apk" "com.pentest.ch31.attacker"
        ;;
esac

echo "done. APKs are under $OUTDIR -- nothing was written into the repository."
