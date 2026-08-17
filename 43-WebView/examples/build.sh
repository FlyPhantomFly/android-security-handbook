#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build chapter 43's three lab APKs from the sources in this directory, using
#   only the Android SDK build-tools and a JDK. No Gradle, no Android Studio, no
#   network access.
#
#       webview-probe/       measures WebSettings defaults across targetSdkVersion
#       vulnerable-webview/  deliberately vulnerable WebView host (labs 01, 02, 04)
#       hardened-webview/    the same app with every defect fixed
#
#   The repository ships SOURCES, never built APKs. `.apk`, `.dex` and `.class`
#   are on the artefact blocklist, so this script builds OUT OF TREE: everything
#   it produces lands under $OUTDIR, and nothing is written next to the sources.
#   The signing key is generated on the spot into $OUTDIR too -- no key or
#   certificate is ever committed.
#
# USAGE
#   # host -- build all three
#   ./build.sh
#
#   # host -- build and install on the attached device
#   ./build.sh --install
#
#   # host -- build and install one app only
#   ./build.sh --install vulnerable-webview
#
#   # host -- choose where artefacts go
#   OUTDIR=/tmp/ch43 ./build.sh --install
#
#   # host -- remove all three from the device
#   ./build.sh --uninstall
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an Android SDK with
#     build-tools (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#     The newest of each is used.
#   * A JDK with javac and keytool.
#   * `adb` on PATH for --install / --uninstall.
#
# WHAT THIS WILL *NOT* DO FOR YOU
#   * It will NOT get past an OEM install restriction on its own. On the MIUI
#     device this chapter was written against, `adb install` and `pm install`
#     both return INSTALL_FAILED_USER_RESTRICTED for any APK, because "Install
#     via USB" is disabled at the vendor level. The script detects that exact
#     failure and retries through root, which does work on a rooted device.
#   * It will NOT produce a release-quality APK. The key exists so the package
#     manager accepts the file and for nothing else.
#   * It will NOT tell you whether an attack works. That is what labs/ is for,
#     and several of the answers are device- and WebView-version-dependent.
#
# GIT BASH / MSYS NOTES -- two traps that cost real time
#   1. The SDK tools are native Windows binaries and do not understand
#      /c/Users/... paths. Every path handed to them goes through cygpath -w.
#      Without it aapt2 reports "failed to load XML file" on a file that plainly
#      exists.
#   2. `adb push` MANGLES its remote argument under MSYS: /data/local/tmp
#      becomes C:/Program Files/Git/data/local/tmp and the push fails with
#      "remote secure_mkdirs failed". Set MSYS_NO_PATHCONV=1 for adb calls that
#      carry an absolute device path, which this script does.
#
#   XML comments must not contain a double hyphen; aapt2 rejects the file.
#
# AUTHORISED TESTING ONLY. vulnerable-webview is deliberately insecure. Install
# it on a device you own, and uninstall it when you are finished.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch43-build}"

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

pick() {
    for cand in "$BT/$1" "$BT/$1.bat" "$BT/$1.exe"; do
        [ -f "$cand" ] && { echo "$cand"; return; }
    done
    echo "$BT/$1"
}
AAPT2="$(pick aapt2)"; D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"

echo "SDK         $SDK"
echo "build-tools $(basename "$BT")"
echo "android.jar $AJ"
echo "outdir      $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# A throwaway signing key. Generated into $OUTDIR, outside the repository.
# --------------------------------------------------------------------------- #
KS="$OUTDIR/debug.ks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$(p "$KS")" -storepass android -keypass android \
        -alias ch43 -dname "CN=CH43 Lab,O=Android Pentesting Notes" \
        -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
        || { echo "error: keytool failed -- is a JDK on PATH?"; exit 2; }
    echo "generated throwaway signing key at $KS"
fi

# --------------------------------------------------------------------------- #
# build <app-dir> <java-package-path> <target-sdk>
#
# Each app directory holds flat .java files, an AndroidManifest.xml, and
# optionally network_security_config.xml and *.html. The script lays them out
# into the res/ and assets/ trees aapt2 expects.
# --------------------------------------------------------------------------- #
build_app() {
    local app="$1" pkgpath="$2" target="$3"
    local src="$HERE/$app"
    local work="$OUTDIR/$app"

    [ -d "$src" ] || { echo "skip $app (no such directory)"; return 0; }

    echo "=== building $app (targetSdk $target) ==="
    rm -rf "$work"
    mkdir -p "$work/src/$pkgpath" "$work/classes" "$work/res/xml" "$work/assets" "$work/compiled"

    cp "$src"/*.java "$work/src/$pkgpath/" 2>/dev/null

    local link_res=""
    if [ -f "$src/network_security_config.xml" ]; then
        cp "$src/network_security_config.xml" "$work/res/xml/network_security_config.xml"
        "$AAPT2" compile --dir "$(p "$work/res")" -o "$(p "$work/compiled/res.zip")" || return 1
        link_res="$work/compiled/res.zip"
    fi

    local link_assets=""
    if ls "$src"/*.html >/dev/null 2>&1; then
        cp "$src"/*.html "$work/assets/"
        link_assets="$work/assets"
    fi

    local -a linkargs
    linkargs=(link -o "$(p "$work/base.apk")" -I "$(p "$AJ")"
              --manifest "$(p "$src/AndroidManifest.xml")"
              --min-sdk-version 21 --target-sdk-version "$target")
    [ -n "$link_assets" ] && linkargs+=(-A "$(p "$link_assets")")
    [ -n "$link_res" ]    && linkargs+=("$(p "$link_res")")

    "$AAPT2" "${linkargs[@]}" || return 1

    javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$work/classes")" \
        "$work/src/$pkgpath"/*.java 2>&1 | grep -vE 'deprecat|obsolete|Xlint|^Note:|warning'

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done < <(find "$work/classes" -name '*.class')
    [ ${#classfiles[@]} -gt 0 ] || { echo "error: javac produced no classes for $app"; return 1; }

    "$D8" --lib "$(p "$AJ")" --min-api 21 --output "$(p "$work")" "${classfiles[@]}" || return 1

    # zip is not always present on Windows; python is.
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
    out="$(MSYS_NO_PATHCONV=1 adb install -r "$(p "$apk")" 2>&1)"
    if echo "$out" | grep -q Success; then
        echo "installed $name"
        return 0
    fi
    if echo "$out" | grep -q INSTALL_FAILED_USER_RESTRICTED; then
        echo "adb install refused: INSTALL_FAILED_USER_RESTRICTED"
        echo "  This is an OEM policy ('Install via USB'), not a fault in the APK."
        echo "  Retrying through root..."
        MSYS_NO_PATHCONV=1 adb push "$(p "$apk")" /data/local/tmp/ch43.apk >/dev/null 2>&1
        out="$(MSYS_NO_PATHCONV=1 adb shell "su -c 'pm install -r /data/local/tmp/ch43.apk'" 2>&1)"
        MSYS_NO_PATHCONV=1 adb shell rm -f /data/local/tmp/ch43.apk >/dev/null 2>&1
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

APPS_DIR=("webview-probe" "vulnerable-webview" "hardened-webview")
APPS_PKG=("com/pentest/ch43/probe" "com/pentest/ch43/vuln" "com/pentest/ch43/safe")
APPS_ID=("com.pentest.ch43.probe" "com.pentest.ch43.vuln" "com.pentest.ch43.safe")
# targetSdk 30 for all three. It is the device this chapter was measured on, and
# it is the level at which setAllowFileAccess defaults to false -- so the
# vulnerable app's explicit setAllowFileAccess(true) is visibly a re-enable
# rather than an inherited default.
APPS_TARGET=(30 30 30)

MODE="${1:-}"
ONLY="${2:-}"

case "$MODE" in
    --uninstall)
        for id in "${APPS_ID[@]}"; do
            MSYS_NO_PATHCONV=1 adb uninstall "$id" 2>&1 | tail -1
        done
        exit 0
        ;;
esac

for i in "${!APPS_DIR[@]}"; do
    [ -n "$ONLY" ] && [ "$ONLY" != "${APPS_DIR[$i]}" ] && continue
    build_app "${APPS_DIR[$i]}" "${APPS_PKG[$i]}" "${APPS_TARGET[$i]}" || exit 1
done

if [ "$MODE" = "--install" ]; then
    for i in "${!APPS_DIR[@]}"; do
        [ -n "$ONLY" ] && [ "$ONLY" != "${APPS_DIR[$i]}" ] && continue
        app="${APPS_DIR[$i]}"
        install_apk "$OUTDIR/$app/$app.apk" "${APPS_ID[$i]}"
    done
fi

echo "done. APKs are under $OUTDIR -- nothing was written into the repository."
