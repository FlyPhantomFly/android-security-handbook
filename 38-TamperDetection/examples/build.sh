#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build the chapter 38 self-integrity demonstration app from the sources in
#   examples/repack-detector/, using only the Android SDK build-tools and a JDK.
#   No Gradle, no Android Studio, no network.
#
#   Then, on demand, REPACKAGE it exactly the way an attacker would: strip the
#   signature, re-sign with a different key, and install the result. That second
#   half is the point. Lab 01 uses it to answer a question the chapter cannot
#   answer by argument alone -- does a runtime self-signature check actually
#   fire when the APK is re-signed?
#
#   The repository ships SOURCES, never built APKs. `.apk`, `.dex`, `.class` and
#   keystores are all on the artefact blocklist, so this script builds OUT OF
#   TREE: everything it produces lands under $OUTDIR (default: a temp directory
#   outside the repository), and nothing is written next to the sources.
#
# USAGE
#   # host -- build the clean, correctly signed APK
#   ./build.sh
#
#   # host -- build, then produce the repackaged (attacker-signed) APK too
#   ./build.sh --repack
#
#   # host -- build both and install the CLEAN one
#   ./build.sh --install
#
#   # host -- install the REPACKAGED one (uninstalls the clean one first, because
#   #         Android refuses an update signed by a different key)
#   ./build.sh --install-repacked
#
#   # host -- remove the app
#   ./build.sh --uninstall
#
#   # host -- choose where artefacts go
#   OUTDIR=/tmp/ch38 ./build.sh --repack
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an Android SDK that has
#     build-tools (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#     The script picks the newest of each it can find.
#   * A JDK with javac and keytool. JDK 8 through 24 all work.
#   * python3 -- used to rewrite the zip, because `zip` is not always present on
#     Windows. Invoked with -B so no __pycache__ is ever created.
#   * adb on PATH for the install targets.
#
# WHAT THIS WILL *NOT* DO FOR YOU
#   * It will NOT get past an OEM install restriction. On MIUI devices both
#     `adb install` and `pm install` can return INSTALL_FAILED_USER_RESTRICTED
#     regardless of the APK, because "Install via USB" is disabled at the vendor
#     level. The script detects that specific failure and falls back to a root
#     install if root is available. If neither works, that is a device policy
#     problem, not an APK problem.
#   * It will NOT produce a release-quality APK. Both signing keys are generated
#     on the spot with a fixed password. They exist so the package manager
#     accepts the file, and for nothing else. NEITHER KEY IS EVER WRITTEN INTO
#     THE REPOSITORY.
#   * It will NOT tell you that the app is secure. The app is a teaching
#     artefact whose entire purpose is to be defeated in labs 01 and 04.
#   * It will NOT build the native tier. examples/tamper_check.c needs the NDK
#     and is built separately by labs/lab-02-jni-onload-anti-analysis.md, so
#     that a machine without an NDK can still complete lab 01.
#
# AUTHORISED TESTING ONLY. Install on a device you own; uninstall when done.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch38-build}"
PKG="com.pentest.ch38.integrity"
PKGPATH="com/pentest/ch38/integrity"

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

pick() { if [ -x "$BT/$1" ]; then echo "$BT/$1"; else echo "$BT/$1.bat"; fi; }
AAPT2="$(pick aapt2)"; D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"
[ -x "$AAPT2" ]    || AAPT2="$BT/aapt2.exe"
[ -x "$ZIPALIGN" ] || ZIPALIGN="$BT/zipalign.exe"

echo "SDK          $SDK"
echo "build-tools  $(basename "$BT")"
echo "android.jar  $AJ"
echo "outdir       $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# Two throwaway signing keys: the "developer" and the "attacker"
#
# This is the whole experiment in two commands. The developer key signs the
# genuine build; the attacker key signs the repackaged build. The app compares
# the certificate it sees at runtime against the SHA-256 of the DEVELOPER
# certificate, which is injected into the source below.
# --------------------------------------------------------------------------- #
DEV_KS="$OUTDIR/dev.ks"
ATK_KS="$OUTDIR/attacker.ks"

make_key() {
    local ks="$1" alias="$2" cn="$3"
    [ -f "$ks" ] && return 0
    keytool -genkeypair -keystore "$(p "$ks")" -storepass android -keypass android \
        -alias "$alias" -dname "CN=$cn,O=Android Security Handbook" \
        -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
        || { echo "error: keytool failed -- is a JDK on PATH?"; exit 2; }
    echo "generated throwaway key: $ks (alias $alias)"
}

make_key "$DEV_KS" ch38dev "CH38 Developer"
make_key "$ATK_KS" ch38atk "CH38 Repackager"

# The SHA-256 fingerprint keytool prints is the SHA-256 of the DER encoding of
# the X.509 certificate. android.content.pm.Signature.toByteArray() returns
# exactly those same DER bytes, so the two hashes are directly comparable. That
# equivalence is not obvious and is worth checking once yourself:
#   keytool -list -v ... | grep SHA256    ==    sha256(Signature.toByteArray())
fingerprint() {
    local ks="$1" alias="$2"
    keytool -list -v -keystore "$(p "$ks")" -storepass android -alias "$alias" 2>/dev/null \
        | grep -i 'SHA256:' | head -1 \
        | sed 's/.*SHA256: *//' | tr -d ': \r' | tr 'A-F' 'a-f'
}

DEV_FP="$(fingerprint "$DEV_KS" ch38dev)"
ATK_FP="$(fingerprint "$ATK_KS" ch38atk)"
[ ${#DEV_FP} -eq 64 ] || { echo "error: could not read developer fingerprint (got '$DEV_FP')"; exit 2; }

echo "developer cert SHA-256  $DEV_FP"
echo "attacker  cert SHA-256  $ATK_FP"
echo

# --------------------------------------------------------------------------- #
# Build the clean APK
# --------------------------------------------------------------------------- #
WORK="$OUTDIR/work"
SRC="$HERE/repack-detector"

build_clean() {
    echo "=== building clean APK ==="
    rm -rf "$WORK"
    mkdir -p "$WORK/src/$PKGPATH" "$WORK/classes"

    cp "$SRC"/*.java "$WORK/src/$PKGPATH/"

    # Generate the expected-signature constant. This file is NOT in the
    # repository, deliberately: it holds a value derived from a key that is
    # generated on your machine, and committing either would be wrong.
    cat > "$WORK/src/$PKGPATH/ExpectedSignature.java" <<EOF
package $PKG;

/**
 * GENERATED BY build.sh -- do not edit, do not commit.
 *
 * SHA-256 of the DER encoding of the certificate that signed this build.
 * In a real app this constant is the entire secret of the self-signature
 * check, and it is not secret at all: it sits in classes.dex in plain sight.
 * See README section 6.2 for what it looks like in JADX and in Smali.
 */
final class ExpectedSignature {
    static final String SHA256 = "$DEV_FP";
    private ExpectedSignature() { }
}
EOF

    "$AAPT2" link -o "$(p "$WORK/base.apk")" -I "$(p "$AJ")" \
        --manifest "$(p "$SRC/AndroidManifest.xml")" \
        --min-sdk-version 21 --target-sdk-version 33 || return 1

    javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$WORK/classes")" \
        "$WORK/src/$PKGPATH"/*.java 2>&1 | grep -vE 'obsolete|Xlint|^[0-9]+ warning|deprecat' || true

    [ -f "$WORK/classes/$PKGPATH/MainActivity.class" ] || { echo "error: javac produced no classes"; return 1; }

    local classfiles=()
    while IFS= read -r f; do classfiles+=("$(p "$f")"); done < <(find "$WORK/classes" -name '*.class')
    "$D8" --lib "$(p "$AJ")" --min-api 21 --output "$(p "$WORK")" "${classfiles[@]}" || return 1

    ( cd "$WORK" && python3 -B -c "
import zipfile, shutil
shutil.copy('base.apk', 'unaligned.apk')
z = zipfile.ZipFile('unaligned.apk', 'a', zipfile.ZIP_DEFLATED)
z.write('classes.dex', 'classes.dex')
z.close()
" ) || return 1

    "$ZIPALIGN" -f -p 4 "$(p "$WORK/unaligned.apk")" "$(p "$WORK/aligned.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$DEV_KS")" --ks-pass pass:android --key-pass pass:android \
        --out "$(p "$OUTDIR/clean.apk")" "$(p "$WORK/aligned.apk")" 2>&1 | grep -v WARNING

    echo "built $OUTDIR/clean.apk"
    "$APKSIGNER" verify -v "$(p "$OUTDIR/clean.apk")" | sed 's/^/    /'
    echo
}

# --------------------------------------------------------------------------- #
# Repackage: strip the signature and re-sign with the attacker key
#
# This is the minimal, honest version of what apktool does. We do not even
# modify the code -- the ONLY difference between clean.apk and repacked.apk is
# the signing key. That isolation is what makes lab 01 a clean experiment: if
# the check fires, it fired because of the key and nothing else.
# --------------------------------------------------------------------------- #
build_repacked() {
    echo "=== repackaging with the attacker key ==="
    [ -f "$OUTDIR/clean.apk" ] || { echo "error: build the clean APK first"; return 1; }

    ( cd "$WORK" && python3 -B -c "
import zipfile, sys, os
src = os.path.join(os.environ['OUTDIR'], 'clean.apk')
dst = os.path.join(os.environ['OUTDIR'], 'stripped.apk')
zin  = zipfile.ZipFile(src, 'r')
zout = zipfile.ZipFile(dst, 'w', zipfile.ZIP_DEFLATED)
dropped = []
for item in zin.infolist():
    n = item.filename
    if n.startswith('META-INF/') and n.upper().endswith(('.RSA', '.DSA', '.EC', '.SF', '.MF')):
        dropped.append(n)
        continue
    zout.writestr(item, zin.read(n))
zout.close(); zin.close()
print('    dropped v1 signature entries:', dropped)
print('    note: the v2/v3 APK Signing Block is not a zip entry at all - it sits')
print('          between the entries and the central directory, and rewriting the')
print('          zip discards it automatically.')
" ) || return 1

    "$ZIPALIGN" -f -p 4 "$(p "$OUTDIR/stripped.apk")" "$(p "$OUTDIR/stripped-aligned.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$ATK_KS")" --ks-pass pass:android --key-pass pass:android \
        --out "$(p "$OUTDIR/repacked.apk")" "$(p "$OUTDIR/stripped-aligned.apk")" 2>&1 | grep -v WARNING

    echo "built $OUTDIR/repacked.apk"
    "$APKSIGNER" verify -v --print-certs "$(p "$OUTDIR/repacked.apk")" \
        | grep -iE 'Verified using|SHA-256 digest|Signer' | sed 's/^/    /'
    echo
}

# --------------------------------------------------------------------------- #
# Install helpers
# --------------------------------------------------------------------------- #
install_apk() {
    local apk="$1" out
    [ -f "$apk" ] || { echo "error: $apk does not exist"; return 1; }
    out="$(adb install -r "$apk" 2>&1)"
    if echo "$out" | grep -q Success; then echo "installed $(basename "$apk")"; return 0; fi

    if echo "$out" | grep -q INSTALL_FAILED_UPDATE_INCOMPATIBLE; then
        echo "INSTALL_FAILED_UPDATE_INCOMPATIBLE -- a different key already owns $PKG."
        echo "  This is the platform refusing a signature change, and it is a RESULT,"
        echo "  not an error: it is the reason a repackager must change the package"
        echo "  name or uninstall first. Uninstalling and retrying..."
        adb uninstall "$PKG" >/dev/null 2>&1
        out="$(adb install -r "$apk" 2>&1)"
        if echo "$out" | grep -q Success; then echo "installed $(basename "$apk") after uninstall"; return 0; fi
    fi

    if echo "$out" | grep -q INSTALL_FAILED_USER_RESTRICTED; then
        echo "adb install refused: INSTALL_FAILED_USER_RESTRICTED"
        echo "  This is an OEM restriction ('Install via USB'), not a fault in the APK."
        echo "  Trying the root path..."
        adb push "$apk" /data/local/tmp/ch38.apk >/dev/null 2>&1
        out="$(adb shell "su -c 'pm install -r /data/local/tmp/ch38.apk'" 2>&1)"
        adb shell rm -f /data/local/tmp/ch38.apk >/dev/null 2>&1
        if echo "$out" | grep -q Success; then echo "installed via root"; return 0; fi
    fi

    echo "install failed:"; echo "$out" | head -5; return 1
}

export OUTDIR

case "${1:-}" in
    --repack)
        build_clean || exit 1
        build_repacked || exit 1
        ;;
    --install)
        build_clean || exit 1
        install_apk "$OUTDIR/clean.apk"
        ;;
    --install-repacked)
        build_clean || exit 1
        build_repacked || exit 1
        install_apk "$OUTDIR/repacked.apk"
        ;;
    --uninstall)
        adb uninstall "$PKG" 2>&1 | tail -1
        ;;
    *)
        build_clean || exit 1
        ;;
esac

echo "done. Everything is under $OUTDIR -- nothing was written into the repository."
