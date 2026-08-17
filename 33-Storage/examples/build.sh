#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build chapter 33's two example apps -- examples/leaky-vault/ and
#   examples/fixed-vault/ -- from the sources beside this script, using only the
#   Android SDK build-tools and a JDK. No Gradle, no Android Studio, no network,
#   no androidx.
#
#   The repository ships SOURCES, never built APKs: .apk, .dex and .class are on
#   the artefact blocklist. This script therefore builds OUT OF TREE. Everything
#   it produces lands under $OUTDIR (a temp directory by default) and nothing is
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
#   OUTDIR=/tmp/ch33 ./build.sh --install
#
#   # host -- remove both apps and their data from the device
#   ./build.sh --uninstall
#
#   # host -- drive a full session on the leaky app, for labs/lab-02
#   ./build.sh --exercise
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an Android SDK with
#     build-tools (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#     The newest of each is used.
#   * A JDK with javac and keytool. JDK 8 through 24 work; newer JDKs warn about
#     --release 8, which is harmless and filtered.
#   * python3 (used only to add classes.dex to the APK zip, because `zip` is not
#     reliably present on Windows).
#   * adb on PATH for --install / --exercise / --uninstall.
#
# WHAT THIS WILL *NOT* DO FOR YOU
#   * It will NOT get past an OEM install restriction on its own. On the MIUI
#     device this chapter was measured against, `adb install` and a plain
#     `pm install` both return INSTALL_FAILED_USER_RESTRICTED regardless of the
#     APK, because "Install via USB" is disabled at the vendor level. The script
#     detects that exact failure and falls back to installing through root,
#     which does work on a rooted device. If you have neither the toggle nor
#     root, nothing in labs 02 and 04 can run.
#   * It will NOT produce a release-quality APK. The signing key is generated on
#     the spot with a fixed password so the package manager accepts the file.
#   * It will NOT compile a res/ directory. Both apps build their UI in code on
#     purpose, so that aapt2 only ever has a manifest to link and the build stays
#     a dozen lines. examples/fixed-vault/backup_rules.xml is consequently NOT
#     wired in -- read its header, which explains how to wire it in a real
#     project and why it is shipped as reference rather than as a live file.
#   * It will NOT tell you whether the leaks are present. That is what
#     scripts/storage-map.sh, scripts/leak-hunter.py and labs/lab-02 are for.
#     Measure; do not take the source comments' word for it.
#
# AUTHORISED TESTING ONLY. leaky-vault is deliberately vulnerable. Install both
# on a device you own and run --uninstall when you are finished; the leaky app
# writes a file into the shared Downloads collection that OUTLIVES its own
# uninstall, and --uninstall removes that too.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch33-build}"

LEAKY_PKG="com.pentest.ch33.vault"
FIXED_PKG="com.pentest.ch33.vaultfixed"

# On Git Bash / MSYS the SDK tools are native Windows binaries and do not
# understand /c/Users/... paths. cygpath converts; elsewhere this is the
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
echo "outdir      $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# A throwaway signing key
# --------------------------------------------------------------------------- #
KS="$OUTDIR/debug.ks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$(p "$KS")" -storepass android -keypass android \
        -alias ch33 -dname "CN=CH33 Lab,O=Android Pentesting Notes" \
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

    # javac wants the sources laid out under their package directory; the repo
    # stores them flat so the README can link to one annotated copy each.
    cp "$src"/*.java "$work/src/$pkgpath/" 2>/dev/null

    "$AAPT2" link -o "$(p "$work/base.apk")" -I "$(p "$AJ")" \
        --manifest "$(p "$src/AndroidManifest.xml")" \
        --min-sdk-version 23 --target-sdk-version 30 || return 1

    # --release 8 keeps d8 happy on every build-tools version and avoids the
    # "invalid source release" class of failure on newer JDKs.
    javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$work/classes")" \
        "$work/src/$pkgpath"/*.java 2>&1 \
        | grep -vE 'obsolete|Xlint|^[0-9]+ warning|deprecat' || true

    if ! find "$work/classes" -name '*.class' | grep -q .; then
        echo "error: javac produced no classes for $app"
        return 1
    fi

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done \
        < <(find "$work/classes" -name '*.class')
    "$D8" --lib "$(p "$AJ")" --min-api 23 --output "$(p "$work")" "${classfiles[@]}" || return 1

    # Add classes.dex to the resource-only APK that aapt2 produced.
    ( cd "$work" && python3 -B -c "
import zipfile, shutil
shutil.copy('base.apk', 'unaligned.apk')
z = zipfile.ZipFile('unaligned.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('classes.dex', 'classes.dex')
z.close()
" ) || return 1

    "$ZIPALIGN" -f -p 4 "$(p "$work/unaligned.apk")" "$(p "$work/aligned.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$KS")" --ks-pass pass:android --key-pass pass:android \
        --out "$(p "$work/$app.apk")" "$(p "$work/aligned.apk")" 2>&1 | grep -v WARNING || true

    if [ ! -f "$work/$app.apk" ]; then
        echo "error: apksigner produced no output for $app"
        return 1
    fi
    echo "built $work/$app.apk"
    echo
}

# --------------------------------------------------------------------------- #
# install, with the MIUI fallback. MIUI's "Install via USB" policy refuses
# `adb install` with INSTALL_FAILED_USER_RESTRICTED ("Install canceled by user",
# which is untrue) even for a correctly built and signed APK. The device shell
# hits the same gate; root does not. Neither
# `settings put global verifier_verify_adb_installs 0` nor `pm install -i
# com.android.shell` makes any difference, so the fallback below pushes to
# /data/local/tmp and installs as root instead.
# --------------------------------------------------------------------------- #
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
        echo "  Nobody cancelled anything, despite what the message says."
        echo "  Trying the root path..."
        adb push "$apk" /data/local/tmp/ch33.apk >/dev/null 2>&1
        out="$(adb shell "su -c 'pm install -r /data/local/tmp/ch33.apk'" 2>&1)"
        adb shell rm -f /data/local/tmp/ch33.apk >/dev/null 2>&1
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

# --------------------------------------------------------------------------- #
# --exercise: a reproducible session, for the filesystem diff in labs/lab-02
#
# Every step is an `am start`, so the sequence is identical on every run. A lab
# whose "exercise the app" step is "tap around for a bit" cannot produce a diff
# anyone can reproduce.
# --------------------------------------------------------------------------- #
exercise() {
    local pkg="${1:-$LEAKY_PKG}"
    local act="$pkg/.VaultActivity"
    echo "=== exercising $pkg ==="

    local locked
    locked="$(adb shell dumpsys trust 2>/dev/null | grep -o 'deviceLocked=[01]' | head -1)"
    if [ "$locked" = "deviceLocked=1" ]; then
        echo "  WARNING: the device reports $locked."
        echo "  On some OEM builds an app cannot start an activity while the"
        echo "  keyguard is up, and half these steps will silently do nothing."
        echo "  Unlock the screen and re-run."
    fi

    for a in store notes logout probe; do
        echo "  am start --es action $a"
        adb shell "am start -n $act --es action $a" >/dev/null 2>&1
        sleep 2
    done
    if [ "$pkg" = "$LEAKY_PKG" ]; then
        echo "  am start ExportActivity"
        adb shell "am start -n $pkg/.ExportActivity" >/dev/null 2>&1
        sleep 2
    fi
    echo "  done. Take your 'after' snapshot now."
}

case "${1:-}" in
    --uninstall)
        adb uninstall "$LEAKY_PKG" 2>&1 | tail -1
        adb uninstall "$FIXED_PKG" 2>&1 | tail -1
        echo "removing the shared-collection file the leaky app left behind..."
        # This is the point of the exercise: uninstalling the app does NOT
        # remove what it wrote into Downloads, because a shared collection is
        # not the app's storage. See faq.md, "why did my file survive uninstall".
        adb shell "content delete --uri content://media/external/downloads --where \"_display_name='ch33-vault-export.txt'\"" 2>&1 | head -2
        adb shell "rm -f /sdcard/Download/ch33-vault-export.txt /sdcard/Download/legacy-ch33-vault-export.txt" 2>&1 | head -2
        exit 0
        ;;
    --exercise)
        exercise "${2:-$LEAKY_PKG}"
        exit 0
        ;;
esac

build_app leaky-vault com/pentest/ch33/vault      || exit 1
build_app fixed-vault com/pentest/ch33/vaultfixed || exit 1

case "${1:-}" in
    --install)
        install_apk "$OUTDIR/leaky-vault/leaky-vault.apk" "$LEAKY_PKG"
        install_apk "$OUTDIR/fixed-vault/fixed-vault.apk" "$FIXED_PKG"
        ;;
esac

echo "done. APKs are under $OUTDIR -- nothing was written into the repository."
