#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build chapter 67's two demonstration applications from the sources in this
#   directory, using only the Android SDK build-tools, a JDK and (optionally)
#   the NDK. No Gradle, no Android Studio, no network access.
#
#     guarded-app/   every decision taken on the device. Four tiers of control
#                    (native constructor, JNI_OnLoad, Java reads, Java verdict)
#                    and five distinct responses, so that each control has a
#                    different death signature.
#
#     server-app/    the SAME application with one change: the decision is
#                    taken by the server and the secret never exists on the
#                    device until the server sends it. This is the control
#                    group. If you cannot tell the two apart from the outside,
#                    you have not understood the chapter.
#
#   The guarded app is built TWICE: once as a release build and once with
#   android:debuggable="true" patched into the manifest, because one of its own
#   controls asks that question and you need both answers.
#
# USAGE
#   # host - build everything into a scratch directory
#   ./build.sh
#
#   # host - build and install the release guarded app
#   ./build.sh --install
#
#   # host - install the debuggable variant instead (same package, replaces it)
#   ./build.sh --install-debuggable
#
#   # host - install the server-side comparison app
#   ./build.sh --install-server
#
#   # host - remove both packages
#   ./build.sh --uninstall
#
#   # host - choose where build artefacts go
#   OUTDIR=/tmp/ch67 ./build.sh --install
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an SDK with build-tools
#     (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#   * A JDK with javac and keytool.
#   * python3, for the zip surgery that adds classes.dex and the .so.
#   * adb for the --install targets.
#   * OPTIONAL: an NDK under $SDK/ndk/*. Without it the native tier is simply
#     not packaged and the app reports "native tier absent" - which is a state
#     the labs deliberately ask you to recognise, so this is not a failure.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * Whether any control in the app actually fires on YOUR device. It will
#     not. Root, instrumentation and debugger state are properties of the
#     device and the session, not of the build. Run scripts/bypass-triage.py
#     to find out, and expect several controls to report "present, did not
#     fire" on a stock phone - that is the correct answer, not a broken build.
#   * Whether the install succeeded for the reason you think. Some OEM builds
#     refuse `adb install` with INSTALL_FAILED_USER_RESTRICTED regardless of
#     the APK; the script detects that specific failure and says so.
#   * Anything about a real application. These are teaching artefacts.
#
# AUTHORISED TESTING ONLY. These apps are built to be defeated. Install them on
# a device you own and uninstall them when you are finished.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch67-build}"
PKG_GUARDED="com.pentest.ch67.guarded"
PKG_SERVER="com.pentest.ch67.server"

# On Git Bash / MSYS the SDK tools are native Windows binaries and do not
# understand /c/Users/... paths. cygpath converts; elsewhere this is identity.
p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

# --------------------------------------------------------------------------- #
# Locate the SDK, the build-tools and a platform jar
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

pick() { [ -x "$BT/$1" ] && echo "$BT/$1" || echo "$BT/$1.bat"; }
AAPT2="$(pick aapt2)"; D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"
[ -x "$AAPT2" ]    || AAPT2="$BT/aapt2.exe"
[ -x "$ZIPALIGN" ] || ZIPALIGN="$BT/zipalign.exe"

# --------------------------------------------------------------------------- #
# Locate an NDK clang for arm64. Optional.
# --------------------------------------------------------------------------- #
CC64=""
NDK="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)"
if [ -n "$NDK" ]; then
    for hostdir in "$NDK"/toolchains/llvm/prebuilt/*; do
        for cand in "$hostdir/bin/aarch64-linux-android21-clang" \
                    "$hostdir/bin/aarch64-linux-android21-clang.cmd"; do
            [ -f "$cand" ] && CC64="$cand" && break 2
        done
    done
fi

echo "SDK          $SDK"
echo "build-tools  $(basename "$BT")"
echo "android.jar  $AJ"
if [ -n "$CC64" ]; then echo "ndk clang    $CC64"; else echo "ndk clang    NOT FOUND - native tier will be absent"; fi
echo "outdir       $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# A throwaway signing key. It exists so the package manager accepts the file.
# --------------------------------------------------------------------------- #
KS="$OUTDIR/debug.ks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$(p "$KS")" -storepass android -keypass android \
        -alias ch67 -dname "CN=CH67 Lab,O=Android Security Handbook" \
        -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
        || { echo "error: keytool failed - is a JDK on PATH?"; exit 2; }
    echo "generated throwaway signing key at $KS"
fi

# --------------------------------------------------------------------------- #
# build_native <outdir>
# --------------------------------------------------------------------------- #
build_native() {
    local work="$1"
    [ -n "$CC64" ] || return 1
    mkdir -p "$work/lib/arm64-v8a"
    "$CC64" -shared -fPIC -O2 -Wall -Wextra \
        -o "$work/lib/arm64-v8a/libch67guard.so" \
        "$HERE/guarded-app/native_guard.c" -llog || return 1
    echo "  native: built lib/arm64-v8a/libch67guard.so"
    return 0
}

# --------------------------------------------------------------------------- #
# build_app <src-dir> <pkgpath> <variant-name> <debuggable:0|1> <with-native:0|1>
# --------------------------------------------------------------------------- #
build_app() {
    local src="$HERE/$1" pkgpath="$2" variant="$3" dbg="$4" native="$5"
    local work="$OUTDIR/$variant"

    echo "=== building $variant ==="
    rm -rf "$work"
    mkdir -p "$work/src/$pkgpath" "$work/classes"

    cp "$src"/*.java "$work/src/$pkgpath/" 2>/dev/null

    # The debuggable variant differs from the release variant in exactly one
    # attribute. Patching it here, rather than shipping two manifests, keeps
    # that promise checkable.
    local manifest="$work/AndroidManifest.xml"
    if [ "$dbg" = "1" ]; then
        sed 's#<application#<application android:debuggable="true"#' \
            "$src/AndroidManifest.xml" > "$manifest"
        echo "  manifest: android:debuggable=\"true\" patched in"
    else
        cp "$src/AndroidManifest.xml" "$manifest"
    fi

    "$AAPT2" link -o "$(p "$work/base.apk")" -I "$(p "$AJ")" \
        --manifest "$(p "$manifest")" \
        --min-sdk-version 21 --target-sdk-version 33 || return 1

    javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$work/classes")" \
        "$work/src/$pkgpath"/*.java 2>&1 | grep -vE 'obsolete|Xlint|^[0-9]+ warning'

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done < <(find "$work/classes" -name '*.class')
    [ "${#classfiles[@]}" -gt 0 ] || { echo "  error: javac produced no classes"; return 1; }
    "$D8" --lib "$(p "$AJ")" --min-api 21 --output "$(p "$work")" "${classfiles[@]}" || return 1

    local have_native=0
    if [ "$native" = "1" ]; then
        if build_native "$work"; then have_native=1; else echo "  native: skipped"; fi
    fi

    # aapt2 emits a resource-only APK. Add classes.dex, and the .so if we have
    # one. `zip` is not reliably present on Windows; python3 is.
    ( cd "$work" && HAVE_NATIVE="$have_native" python3 -B -c "
import os, shutil, zipfile
shutil.copy('base.apk', 'unaligned.apk')
z = zipfile.ZipFile('unaligned.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('classes.dex', 'classes.dex')
if os.environ.get('HAVE_NATIVE') == '1':
    z.write('lib/arm64-v8a/libch67guard.so', 'lib/arm64-v8a/libch67guard.so')
z.close()
" ) || return 1

    "$ZIPALIGN" -f -p 4 "$(p "$work/unaligned.apk")" "$(p "$work/aligned.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$KS")" --ks-pass pass:android --key-pass pass:android \
        --out "$(p "$work/$variant.apk")" "$(p "$work/aligned.apk")" 2>&1 | grep -v WARNING

    echo "built $work/$variant.apk"
    echo
}

install_apk() {
    local apk="$1" name="$2" out
    out="$(adb install -r "$(p "$apk")" 2>&1)"
    if echo "$out" | grep -q Success; then echo "installed $name"; return 0; fi
    if echo "$out" | grep -q INSTALL_FAILED_USER_RESTRICTED; then
        echo "adb install refused: INSTALL_FAILED_USER_RESTRICTED"
        echo "  This is an OEM 'Install via USB' policy, not a fault in the APK."
        echo "  Trying the root path (harmless if there is no root)..."
        adb push "$(p "$apk")" /data/local/tmp/ch67.apk >/dev/null 2>&1
        out="$(adb shell "su -c 'pm install -r /data/local/tmp/ch67.apk'" 2>&1)"
        adb shell rm -f /data/local/tmp/ch67.apk >/dev/null 2>&1
        echo "$out" | grep -q Success && { echo "installed $name via root"; return 0; }
        echo "  root install also failed:"; echo "$out" | head -3
        return 1
    fi
    echo "install of $name failed:"; echo "$out" | head -5
    return 1
}

# --------------------------------------------------------------------------- #
build_app guarded-app com/pentest/ch67/guarded guarded-release    0 1 || exit 1
build_app guarded-app com/pentest/ch67/guarded guarded-debuggable 1 1 || exit 1
build_app server-app  com/pentest/ch67/server  server-app         0 0 || exit 1

case "${1:-}" in
    --install)
        install_apk "$OUTDIR/guarded-release/guarded-release.apk" "$PKG_GUARDED (release)"
        ;;
    --install-debuggable)
        install_apk "$OUTDIR/guarded-debuggable/guarded-debuggable.apk" "$PKG_GUARDED (debuggable)"
        ;;
    --install-server)
        install_apk "$OUTDIR/server-app/server-app.apk" "$PKG_SERVER"
        ;;
    --uninstall)
        adb uninstall "$PKG_GUARDED" 2>&1 | tail -1
        adb uninstall "$PKG_SERVER"  2>&1 | tail -1
        ;;
esac

echo "done. Everything is under $OUTDIR - nothing was written into the repository."
