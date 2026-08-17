#!/usr/bin/env bash
# 73-Labs/examples/build-chain-target.sh
#
# PURPOSE
#   Build the deliberately-insecure target used by Lab 02 (the cross-chapter
#   chain) and Lab 04 (the CTF), from the sources in examples/chain-target/,
#   using only the Android SDK build-tools and a JDK. No Gradle, no Android
#   Studio, no network.
#
#   The repository ships SOURCES, never built APKs. `.apk`, `.dex` and `.class`
#   are on the artefact blocklist, so this script builds OUT OF TREE: everything
#   it produces lands under $OUTDIR and nothing is written next to the sources.
#   The signing key is generated on the spot into $OUTDIR too; no key or
#   certificate is ever committed.
#
# USAGE
#   # host -- build only
#   ./build-chain-target.sh
#
#   # host -- build and install on the attached device
#   ./build-chain-target.sh --install
#
#   # host -- build at a targetSdk below the install floor, to reproduce the
#   #         `adb install` refusal and the shell bypass. See MEASURED below.
#   ./build-chain-target.sh --target-sdk 23 --install
#
#   # host -- choose where artefacts go
#   OUTDIR=/tmp/ch73 ./build-chain-target.sh --install
#
#   # host -- remove from the device
#   ./build-chain-target.sh --uninstall
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an SDK with build-tools
#     (aapt2, d8, zipalign, apksigner) and one platform android.jar.
#   * A JDK with javac and keytool.
#   * adb on PATH for --install / --uninstall.
#
# WAS THIS EXECUTED?
#   YES. Built and installed on 2026-08-16 against the AVD
#   `sdk_gphone16k_x86_64` (emulator-5554, Android 15 / API 35, x86_64,
#   userdebug, rooted with Magisk 30.7), with build-tools 35.0.1, android-35's
#   android.jar and JDK 24.0.2, from Git Bash on Windows 11.
#
# MEASURED -- the install floor, and the two ways past it
#   Built with `--target-sdk 23`, this exact APK is refused:
#
#       adb: failed to install ...: Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION:
#       App package must target at least SDK version 24, but found 23]
#
#   Two things get past it, and they are not equivalent:
#
#       adb install --bypass-low-target-sdk-block app.apk     # works
#       adb shell pm install --bypass-low-target-sdk-block /data/local/tmp/app.apk
#
#   The first is the one to reach for. The second matters on devices where
#   `adb install` is blocked by an OEM policy rather than by the SDK floor --
#   this repository has measured `INSTALL_FAILED_USER_RESTRICTED` on a MIUI
#   handset, where the working form is a root install from the device shell:
#
#       adb push app.apk /data/local/tmp/app.apk
#       adb shell "su -c 'pm install -r /data/local/tmp/app.apk'"
#
#   On the API 35 AVD that last form does not work, because its `su` is AOSP's
#   and rejects `-c`; there the root form is `su 0 pm install -r <path>`. This
#   script detects which su form the device accepts before using either.
#
# GIT BASH / MSYS NOTES -- two traps that cost real time
#   1. The SDK tools are native Windows binaries and do not understand
#      /c/Users/... paths. Every path handed to them goes through cygpath -w.
#      Without it aapt2 reports "failed to load XML file" on a file that plainly
#      exists.
#   2. `adb push` mangles an absolute remote path under MSYS: /data/local/tmp
#      becomes C:/Program Files/Git/data/local/tmp. MSYS_NO_PATHCONV=1 fixes it,
#      which this script sets for every adb call carrying a device path.
#
#   An XML comment must not contain a double hyphen; aapt2 rejects the file.
#
# AUTHORISED TESTING ONLY. This app is deliberately insecure. Install it on a
# device you own and uninstall it when you are finished.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
SRCDIR="$HERE/chain-target"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch73-chain-build}"
PKG="com.pentest.ch73.chain"
TARGET_SDK=35
MIN_SDK=24
DO_INSTALL=0
DO_UNINSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --install)     DO_INSTALL=1 ;;
        --uninstall)   DO_UNINSTALL=1 ;;
        --target-sdk)  shift; TARGET_SDK="${1:-35}" ;;
        --out)         shift; OUTDIR="${1:-$OUTDIR}" ;;
        -h|--help)     sed -n '2,90p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

# minSdk must not exceed targetSdk, or aapt2 refuses the link.
if [ "$TARGET_SDK" -lt "$MIN_SDK" ]; then
    MIN_SDK="$TARGET_SDK"
fi

say() { printf '\n=== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Convert a path for a native Windows tool. A no-op everywhere else.
p() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

adbq() { MSYS_NO_PATHCONV=1 adb "$@"; }

# --------------------------------------------------------------------------- #
# Uninstall path exits early
# --------------------------------------------------------------------------- #
if [ "$DO_UNINSTALL" -eq 1 ]; then
    say "uninstalling $PKG"
    adbq uninstall "$PKG" || true
    adbq shell "pm list packages $PKG"
    exit 0
fi

# --------------------------------------------------------------------------- #
# Locate the SDK and pick the newest build-tools and platform
# --------------------------------------------------------------------------- #
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    for guess in "$LOCALAPPDATA/Android/Sdk" "$HOME/Android/Sdk" \
                 "$HOME/Library/Android/sdk"; do
        [ -d "$guess" ] && SDK="$guess" && break
    done
fi
[ -n "$SDK" ] && [ -d "$SDK" ] || die "no Android SDK; set ANDROID_HOME"

BT="$(ls -1 "$SDK/build-tools" 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] || die "no build-tools under $SDK"
BTDIR="$SDK/build-tools/$BT"

PLATFORM="$(ls -1 "$SDK/platforms" 2>/dev/null | sort -V | tail -1)"
[ -n "$PLATFORM" ] || die "no platform under $SDK"
ANDROID_JAR="$SDK/platforms/$PLATFORM/android.jar"
[ -f "$ANDROID_JAR" ] || die "no android.jar at $ANDROID_JAR"

# On Windows these carry .exe or .bat; resolve once so the rest reads cleanly.
pick() {
    for cand in "$BTDIR/$1" "$BTDIR/$1.exe" "$BTDIR/$1.bat"; do
        [ -f "$cand" ] && { printf '%s' "$cand"; return 0; }
    done
    die "$1 not found in $BTDIR"
}
AAPT2="$(pick aapt2)"
D8="$(pick d8)"
ZIPALIGN="$(pick zipalign)"
APKSIGNER="$(pick apksigner)"

command -v javac >/dev/null 2>&1 || die "javac not on PATH"
command -v keytool >/dev/null 2>&1 || die "keytool not on PATH"

say "toolchain"
echo "  SDK          $SDK"
echo "  build-tools  $BT"
echo "  platform     $PLATFORM"
echo "  javac        $(javac -version 2>&1)"
echo "  targetSdk    $TARGET_SDK   minSdk $MIN_SDK"
echo "  OUTDIR       $OUTDIR"

# --------------------------------------------------------------------------- #
# Build, entirely under OUTDIR
# --------------------------------------------------------------------------- #
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR/classes" "$OUTDIR/dex" "$OUTDIR/res" "$OUTDIR/gen"

# aapt2 will not accept a manifest whose targetSdk is set only in the file when
# we also want to vary it, so the manifest is copied and rewritten in OUTDIR.
# The sources in the repository are never modified.
MANIFEST="$OUTDIR/gen/AndroidManifest.xml"
sed -e "s|<uses-permission|<uses-sdk android:minSdkVersion=\"$MIN_SDK\" android:targetSdkVersion=\"$TARGET_SDK\" />\n    <uses-permission|" \
    "$SRCDIR/AndroidManifest.xml" > "$MANIFEST"
grep -q "uses-sdk" "$MANIFEST" || die "failed to inject uses-sdk into the manifest copy"

say "aapt2 link"
"$AAPT2" link \
    --manifest "$(p "$MANIFEST")" \
    -I "$(p "$ANDROID_JAR")" \
    --java "$(p "$OUTDIR/gen")" \
    -o "$(p "$OUTDIR/base.apk")" \
    || die "aapt2 link failed"

say "javac"
# The argfile holds one QUOTED, host-native path per line. Both halves matter:
# this repository lives under a directory containing a space, and an unquoted
# path splits there, which javac reports as `invalid flag: /c/Users/<you>/...`.
: > "$OUTDIR/sources.txt"
find "$SRCDIR/src" "$OUTDIR/gen" -name '*.java' | while read -r f; do
    printf '"%s"\n' "$(p "$f" | sed 's|\\|/|g')" >> "$OUTDIR/sources.txt"
done
[ -s "$OUTDIR/sources.txt" ] || die "no .java sources found under $SRCDIR/src"
javac -source 8 -target 8 -nowarn \
    -bootclasspath "$(p "$ANDROID_JAR")" \
    -classpath "$(p "$ANDROID_JAR")" \
    -d "$(p "$OUTDIR/classes")" \
    @"$(p "$OUTDIR/sources.txt")" \
    || die "javac failed"

say "d8"
CLASSES="$(find "$OUTDIR/classes" -name '*.class' | while read -r f; do p "$f"; echo; done)"
# shellcheck disable=SC2086
"$D8" --min-api "$MIN_SDK" --output "$(p "$OUTDIR/dex")" \
    --lib "$(p "$ANDROID_JAR")" $CLASSES \
    || die "d8 failed"

say "package"
cp "$OUTDIR/base.apk" "$OUTDIR/unsigned.apk"

# aapt2 emits a resources-only APK; classes.dex has to be added to that zip.
# `zip` is NOT present on a default Windows + Git Bash machine -- this build
# failed there first time round -- so fall back to Python's zipfile, then to
# the JDK's own jar. All three produce a zip the package manager accepts.
add_dex() {
    if command -v zip >/dev/null 2>&1; then
        ( cd "$OUTDIR/dex" && zip -q "$OUTDIR/unsigned.apk" classes.dex ) && return 0
    fi
    if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
        PY="$(command -v python3 || command -v python)"
        "$PY" -B -c "import sys,zipfile
apk, dex = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk, 'a', zipfile.ZIP_DEFLATED) as z:
    z.write(dex, 'classes.dex')
" "$(p "$OUTDIR/unsigned.apk")" "$(p "$OUTDIR/dex/classes.dex")" && return 0
    fi
    if command -v jar >/dev/null 2>&1; then
        ( cd "$OUTDIR/dex" && jar uf "$(p "$OUTDIR/unsigned.apk")" classes.dex ) && return 0
    fi
    return 1
}
add_dex || die "could not add classes.dex to the apk (no zip, python3 or jar)"

say "zipalign and sign"
"$ZIPALIGN" -f -p 4 "$(p "$OUTDIR/unsigned.apk")" "$(p "$OUTDIR/aligned.apk")" \
    || die "zipalign failed"

KEYSTORE="$OUTDIR/debug.keystore"
keytool -genkeypair -v -keystore "$(p "$KEYSTORE")" -storepass android \
    -keypass android -alias ch73 -keyalg RSA -keysize 2048 -validity 365 \
    -dname "CN=ch73-lab, OU=labs, O=android-pentesting-notes, C=GB" \
    >/dev/null 2>&1 || die "keytool failed"

APK="$OUTDIR/chain-target.apk"
"$APKSIGNER" sign --ks "$(p "$KEYSTORE")" --ks-pass pass:android \
    --key-pass pass:android --ks-key-alias ch73 \
    --out "$(p "$APK")" "$(p "$OUTDIR/aligned.apk")" \
    || die "apksigner failed"

"$APKSIGNER" verify --print-certs "$(p "$APK")" | head -4

say "built"
ls -l "$APK"
echo "  nothing was written inside the repository; everything is under $OUTDIR"

[ "$DO_INSTALL" -eq 1 ] || exit 0

# --------------------------------------------------------------------------- #
# Install, with the three fallbacks this repository has measured
# --------------------------------------------------------------------------- #
command -v adb >/dev/null 2>&1 || die "adb not on PATH"
adbq get-state >/dev/null 2>&1 || die "no device in adb devices"

say "install"
OUT="$(adbq install -r "$(p "$APK")" 2>&1)"
echo "$OUT"

if echo "$OUT" | grep -q "Success"; then
    :
elif echo "$OUT" | grep -q "INSTALL_FAILED_DEPRECATED_SDK_VERSION"; then
    say "targetSdk is below the install floor; retrying with the documented bypass"
    OUT="$(adbq install -r --bypass-low-target-sdk-block "$(p "$APK")" 2>&1)"
    echo "$OUT"
elif echo "$OUT" | grep -q "INSTALL_FAILED_USER_RESTRICTED"; then
    say "OEM install restriction; retrying through the device shell as root"
    adbq push "$(p "$APK")" /data/local/tmp/ch73-chain.apk
    # Which su form does this device accept? AOSP's su (AVDs, userdebug builds)
    # takes 'su 0 <cmd>' and rejects '-c' with "su: invalid uid/gid '-c'";
    # Magisk's su on a physical device accepts '-c'. Neither form is universal,
    # and getting it wrong reads as "not rooted". See Lab 01 and README 3.7.
    if adbq shell "su 0 id" 2>&1 | grep -q "uid=0"; then
        adbq shell "su 0 pm install -r /data/local/tmp/ch73-chain.apk"
    else
        adbq shell "su -c 'pm install -r /data/local/tmp/ch73-chain.apk'"
    fi
else
    die "install failed in a way this script does not know: $OUT"
fi

say "installed?"
adbq shell "pm list packages $PKG"
adbq shell "pm dump $PKG | grep -m1 -i versionName" || true

cat <<'EOF'

Next: Lab 02 begins at the STATIC stage, before you touch the device again.
  ../labs/lab-02-the-chain-no-chapter-can-host.md

Uninstall when finished:
  ./build-chain-target.sh --uninstall
EOF
