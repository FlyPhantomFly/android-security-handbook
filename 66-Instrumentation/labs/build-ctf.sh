#!/usr/bin/env bash
# labs/build-ctf.sh
#
# PURPOSE
#   Build chapter 66 lab 04's two APKs from the sources in labs/ctf-vault and
#   labs/ctf-probe, using only the Android SDK build-tools and a JDK. No Gradle.
#
#       ctf-vault.apk   the deliberately vulnerable CTF target
#       ctf-probe.apk   the entrant's test APK, signed with the SAME key
#
#   Signing both with one key is not a convenience, it is the challenge working
#   as designed: chapter 66 section 3.9 measured that ActivityManagerService
#   checks the signature relationship and does NOT care about android:debuggable.
#   The CTF target is deliberately not debuggable, so run-as is not a route in.
#
# USAGE
#   # host -- build only
#   ./build-ctf.sh
#
#   # host -- build and install both
#   ./build-ctf.sh --install
#
#   # host -- choose an output directory (keep using the SAME one; the signing
#   #         key is generated there on first run and reused after)
#   OUTDIR=/tmp/ch66ctf ./build-ctf.sh --install
#
#   # host -- remove both packages from the device
#   ./build-ctf.sh --uninstall
#
#   # host -- run the entrant's probe
#   adb shell am instrument -w -r \
#       com.pentest.ch66.ctf.test/com.pentest.ch66.ctf.probe.CtfProbe
#
# WAS THIS SCRIPT EXECUTED?
#   YES. Run on 2026-08-16 against the AVD sdk_gphone16k_x86_64 (Android 15 /
#   API 35, x86_64, userdebug) with build-tools 35.0.1, platform android-35 and
#   JDK 24.0.2. Both APKs built and installed; the reference solution recorded in
#   lab-04's instructor note was run against them and produced the flag.
#
# THE REPOSITORY SHIPS SOURCES, NEVER BINARIES.
#   Everything lands under $OUTDIR, outside the repository, and the throwaway
#   signing key is generated there too.
#
# AUTHORISED TESTING ONLY. ctf-vault is a deliberately vulnerable application.
# Install it only on a device you own, and run --uninstall when you are done.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch66ctf}"

CTF_PKG="com.pentest.ch66.ctf"
TEST_PKG="com.pentest.ch66.ctf.test"

export MSYS_NO_PATHCONV=1

p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

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
PY="python3"; command -v python3 >/dev/null 2>&1 || PY="python"

MODE="${1:-}"

if [ "$MODE" = "--uninstall" ]; then
    adb uninstall "$TEST_PKG" 2>&1 | tail -1
    adb uninstall "$CTF_PKG"  2>&1 | tail -1
    echo "remaining instrumentations:"
    adb shell pm list instrumentation | tr -d '\r' | sed 's/^/   /'
    exit 0
fi

echo "SDK          $SDK"
echo "build-tools  $(basename "$BT")"
echo "outdir       $OUTDIR"
echo

mkdir -p "$OUTDIR"

# One key. Both APKs. Generated on first run into $OUTDIR and reused afterwards,
# which is why you must keep using the same OUTDIR -- a fresh directory produces
# a fresh key and the two APKs stop matching.
KS="$OUTDIR/ctf.ks"
if [ ! -f "$KS" ]; then
    keytool -genkeypair -keystore "$(p "$KS")" -storepass android -keypass android \
        -alias ch66ctf -dname "CN=CH66 CTF,O=Android Pentesting Notes" \
        -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
        || { echo "error: keytool failed -- is a JDK on PATH?"; exit 2; }
    echo "generated throwaway signing key at $KS"
fi

# build <name> <src-dir> <java-package-path>
build() {
    local name="$1" src="$2" pkgpath="$3"
    local work="$OUTDIR/$name"
    echo "=== $name ==="
    rm -rf "$work"
    mkdir -p "$work/src/$pkgpath" "$work/classes"

    cp "$src"/*.java "$work/src/$pkgpath/" 2>/dev/null || {
        echo "error: no .java files under $src"; return 1; }

    "$AAPT2" link -o "$(p "$work/base.apk")" -I "$(p "$AJ")" \
        --manifest "$(p "$src/AndroidManifest.xml")" \
        --min-sdk-version 24 --target-sdk-version 35 || return 1

    javac --release 8 -nowarn -classpath "$(p "$AJ")" \
        -d "$(p "$work/classes")" "$work/src/$pkgpath"/*.java \
        2>&1 | grep -vE 'deprecat|obsolete|Xlint|^Note:|bootstrap class path'

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done \
        < <(find "$work/classes" -name '*.class')
    [ ${#classfiles[@]} -gt 0 ] || { echo "error: javac produced no classes"; return 1; }

    "$D8" --lib "$(p "$AJ")" --min-api 24 --output "$(p "$work")" "${classfiles[@]}" || return 1

    ( cd "$work" && "$PY" -B -c "
import zipfile, shutil
shutil.copy('base.apk', 'unaligned.apk')
z = zipfile.ZipFile('unaligned.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('classes.dex', 'classes.dex')
z.close()
" ) || return 1

    "$ZIPALIGN" -f -p 4 "$(p "$work/unaligned.apk")" "$(p "$work/aligned.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$KS")" --ks-pass pass:android --key-pass pass:android \
        --ks-key-alias ch66ctf \
        --out "$(p "$OUTDIR/$name.apk")" "$(p "$work/aligned.apk")" 2>&1 | grep -v WARNING

    echo "built $OUTDIR/$name.apk"
    echo
}

build ctf-vault "$HERE/ctf-vault" com/pentest/ch66/ctf || exit 1
build ctf-probe "$HERE/ctf-probe" com/pentest/ch66/ctf/probe || exit 1

echo "=== self-check ==="
printf 'ctf-vault debuggable attrs : '
"$AAPT2" dump xmltree --file AndroidManifest.xml "$(p "$OUTDIR/ctf-vault.apk")" 2>/dev/null \
    | grep -c 'debuggable' | tr -d '\r'
echo "(0 is correct -- the CTF target is deliberately NOT debuggable)"
echo "both APKs must share this digest:"
for a in ctf-vault ctf-probe; do
    printf '  %-10s ' "$a"
    "$APKSIGNER" verify --print-certs "$(p "$OUTDIR/$a.apk")" 2>/dev/null \
        | grep -i 'SHA-256 digest' | head -1
done
echo

if [ "$MODE" = "--install" ]; then
    echo "=== installing ==="
    adb install -r "$(p "$OUTDIR/ctf-vault.apk")" 2>&1 | tail -1
    adb uninstall "$TEST_PKG" >/dev/null 2>&1
    adb install -r "$(p "$OUTDIR/ctf-probe.apk")" 2>&1 | tail -1
    echo
    adb shell pm list instrumentation | tr -d '\r'
    echo
    echo "run it with:"
    echo "  adb shell am instrument -w -r $TEST_PKG/com.pentest.ch66.ctf.probe.CtfProbe"
fi

echo "done. Artefacts are under $OUTDIR -- nothing was written into the repository."
