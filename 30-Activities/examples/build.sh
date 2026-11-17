#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build the two lab APKs for chapter 30 -- examples/victim-app/ and
#   examples/hijacker-app/ -- from the sources in this directory, using only the
#   Android SDK build-tools and a JDK. No Gradle, no Android Studio, no network.
#
#   The repository ships SOURCES, never built APKs. `.apk`, `.dex` and `.class`
#   are on the artefact blocklist, so this script builds OUT OF TREE: everything
#   it produces lands under $OUTDIR (default: a temp directory), and nothing is
#   written next to the sources.
#
# USAGE
#   # host -- build only
#   ./build.sh
#
#   # host -- build and install both apps on the attached device
#   ./build.sh --install
#
#   # host -- choose where artefacts go
#   OUTDIR=/tmp/ch30 ./build.sh --install
#
#   # host -- remove both apps from the device
#   ./build.sh --uninstall
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an Android SDK that has
#     build-tools (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#     The script picks the newest of each it can find.
#   * A JDK with javac and keytool. JDK 8 through 24 all work; newer JDKs emit a
#     deprecation warning for `--release 8`, which is harmless and is filtered.
#   * `adb` on PATH for --install.
#
# WHAT THIS WILL *NOT* DO FOR YOU
#   * It will NOT get past an OEM install restriction. On the MIUI device this
#     chapter was written against, both `adb install` and `pm install` return
#     INSTALL_FAILED_USER_RESTRICTED regardless of the APK, because "Install via
#     USB" is disabled at the vendor level. The script detects that specific
#     failure and tells you the two ways out: enable the toggle in Developer
#     options (needs a signed-in account on MIUI), or, on a device you have
#     rooted, install through root -- which is what --install tries second.
#   * It will NOT produce a release-quality APK. The signing key is generated on
#     the spot with a fixed password; it exists so the package manager accepts
#     the file, and for nothing else.
#   * It will NOT tell you whether the attack works. That is labs/lab-02's job,
#     and the answer is version- and device-dependent -- measure it.
#
# AUTHORISED TESTING ONLY. These apps are deliberately vulnerable. Install them
# on a device you own, and uninstall them when you are done.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch30-build}"

# On Git Bash / MSYS the SDK tools are native Windows binaries and do NOT
# understand /c/Users/... paths. cygpath converts; everywhere else this is the
# identity function. Without it aapt2 reports "failed to load XML file" on a
# file that plainly exists, which is a confusing hour to lose.
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
[ -x "$AAPT2" ] || AAPT2="$BT/aapt2.exe"
[ -x "$ZIPALIGN" ] || ZIPALIGN="$BT/zipalign.exe"

echo "SDK        $SDK"
echo "build-tools $(basename "$BT")"
echo "android.jar $AJ"
echo "outdir     $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# A throwaway signing key
# --------------------------------------------------------------------------- #
KS="$OUTDIR/debug.ks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$KS" -storepass android -keypass android \
        -alias ch30 -dname "CN=CH30 Lab,O=Android Security Handbook" \
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

    # Lay the flat source files out into the package directory javac expects.
    cp "$src"/*.java "$work/src/$pkgpath/" 2>/dev/null

    # The two deputy files are shared teaching artefacts and live one level up,
    # so the README can point at a single annotated copy rather than a duplicate.
    if [ "$app" = "victim-app" ]; then
        cp "$HERE/DeputyActivity.java"      "$work/src/$pkgpath/"
        cp "$HERE/DeputyActivityFixed.java" "$work/src/$pkgpath/"
    fi

    "$AAPT2" link -o "$(p "$work/base.apk")" -I "$(p "$AJ")" \
        --manifest "$(p "$src/AndroidManifest.xml")" \
        --min-sdk-version 21 --target-sdk-version 30 || return 1

    javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$work/classes" \
        "$work/src/$pkgpath"/*.java 2>&1 | grep -vE 'obsolete|Xlint|^[0-9]+ warning'

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done < <(find "$work/classes" -name '*.class')
    "$D8" --lib "$(p "$AJ")" --min-api 21 --output "$(p "$work")" "${classfiles[@]}" || return 1

    # Add classes.dex to the resource-only APK aapt2 produced. `zip -j` would do,
    # but zip is not always present on Windows; python is.
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
        adb push "$apk" /data/local/tmp/ch30.apk >/dev/null 2>&1
        out="$(adb shell "su -c 'pm install -r /data/local/tmp/ch30.apk'" 2>&1)"
        adb shell rm -f /data/local/tmp/ch30.apk >/dev/null 2>&1
        if echo "$out" | grep -q Success; then
            echo "installed $name via root"
            return 0
        fi
        echo "  root install also failed:"
        echo "$out" | head -3
        echo "  Enable Developer options -> Install via USB, or use a device without"
        echo "  the restriction. Nothing in this chapter's labs works without both"
        echo "  apps installed."
        return 1
    fi
    echo "install of $name failed:"
    echo "$out" | head -5
    return 1
}

build_app victim-app   com/pentest/ch30/victim   || exit 1
build_app hijacker-app com/pentest/ch30/attacker || exit 1

case "${1:-}" in
    --install)
        install_apk "$OUTDIR/victim-app/victim-app.apk"     "com.pentest.ch30.victim"
        install_apk "$OUTDIR/hijacker-app/hijacker-app.apk" "com.pentest.ch30.attacker"
        ;;
    --uninstall)
        adb uninstall com.pentest.ch30.victim   2>&1 | tail -1
        adb uninstall com.pentest.ch30.attacker 2>&1 | tail -1
        ;;
esac

echo "done. APKs are under $OUTDIR -- nothing was written into the repository."
