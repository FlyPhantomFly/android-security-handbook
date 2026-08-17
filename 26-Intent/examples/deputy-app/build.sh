#!/usr/bin/env bash
#
# build.sh — build the deputy (victim) and attacker APKs for labs 01 and 04,
#            with no Gradle, no wrapper download and no network access.
#
# PURPOSE
#     This repository ships SOURCE, never APKs. Two reasons: a built APK is an
#     opaque binary in a teaching repo, and an intentionally vulnerable APK that
#     somebody can install without reading anything is a liability. You build it,
#     which also means you can change it -- lab 01 asks you to bump targetSdk and
#     watch a build break, which is only possible if you own the build.
#
#     The pipeline is the one every Android build runs underneath Gradle:
#
#         aapt2 link   ->  AndroidManifest.xml + resources -> base APK
#         javac        ->  .java  -> .class
#         d8           ->  .class -> classes.dex
#         (zip)        ->  put classes.dex into the APK
#         zipalign     ->  4-byte align
#         apksigner    ->  v1+v2+v3 signature
#
# USAGE
#     ./build.sh                       # build both APKs into ./out/
#     ./build.sh --install             # ...and install them
#     ./build.sh --target-sdk 31       # rebuild at API 31 (see the note below)
#     ./build.sh --clean
#     SDK_ROOT=/path/to/Android/Sdk ./build.sh
#     BUILD_TOOLS=35.0.1 PLATFORM=android-35 ./build.sh
#
# REQUIREMENTS
#     * Android SDK build-tools (aapt2, d8, zipalign, apksigner) and one platform
#       android.jar. Set SDK_ROOT if it is not in the usual place.
#     * A JDK with javac and keytool (any JDK 11+; the sources target Java 8
#       bytecode so d8 is happy).
#     * python3, only for the one zip-append step -- `zip` is not installed
#       everywhere and `jar uf` adds a META-INF that then has to be removed.
#     * NO network access. NO Gradle.
#
# THE --target-sdk 31 EXPERIMENT (lab 04, and the best 30 seconds in this chapter)
#     Build at 30: TokenFactory.blankCheque() compiles and produces a MUTABLE
#     PendingIntent, because mutable is the default below API 31.
#     Build at 31: the same code still compiles -- the mandate is a RUNTIME check
#     -- but the app throws IllegalArgumentException the moment it tries to create
#     the token, with a message naming the two flags you must choose between.
#     Watching that happen explains the API 31 mandate better than any paragraph.
#
# WHAT THIS WILL *NOT* DO
#     * It will not install on a device that blocks adb installs. Several OEM
#       builds (MIUI, some ColorOS and OneUI) refuse with
#       INSTALL_FAILED_USER_RESTRICTED unless a developer-options toggle tied to a
#       vendor account is enabled. This was MEASURED on the device used to write
#       this chapter. Use an emulator if yours does that; the labs say so in place.
#     * It will not produce a release-quality APK. The signing key is generated
#       here, on the spot, with a fixed password. It is a debug key and nothing
#       else. Do not reuse it.
#     * It will not resolve R8/ProGuard, resources beyond the manifest, or
#       multi-dex. The apps are deliberately tiny so none of that is needed.
#
# AUTHORISED TESTING ONLY. The deputy app is intentionally vulnerable.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES="$(cd "$HERE/.." && pwd)"
ATTACKER="$EXAMPLES/attacker-app"
OUT="$HERE/out"

TARGET_SDK="${TARGET_SDK:-30}"
DO_INSTALL=0

while [ $# -gt 0 ]; do
    case "$1" in
        --install)    DO_INSTALL=1 ;;
        --target-sdk) shift; TARGET_SDK="${1:?--target-sdk needs a number}" ;;
        --clean)      rm -rf "$OUT"; echo "cleaned $OUT"; exit 0 ;;
        -h|--help)    sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)            echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

# ---- locate the SDK ------------------------------------------------------- #

if [ -z "${SDK_ROOT:-}" ]; then
    for cand in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" \
                "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" \
                "$HOME/AppData/Local/Android/Sdk" \
                "/c/Users/$USER/AppData/Local/Android/Sdk"; do
        [ -n "$cand" ] && [ -d "$cand/build-tools" ] && { SDK_ROOT="$cand"; break; }
    done
fi
: "${SDK_ROOT:?set SDK_ROOT to your Android SDK directory}"

if [ -z "${BUILD_TOOLS:-}" ]; then
    BUILD_TOOLS="$(ls -1 "$SDK_ROOT/build-tools" | sort -V | tail -1)"
fi
BT="$SDK_ROOT/build-tools/$BUILD_TOOLS"

if [ -z "${PLATFORM:-}" ]; then
    PLATFORM="$(ls -1 "$SDK_ROOT/platforms" | sort -V | tail -1)"
fi
ANDROID_JAR="$SDK_ROOT/platforms/$PLATFORM/android.jar"

# On Windows the tools are .exe/.bat; everywhere else they have no extension.
ext=""
[ -x "$BT/aapt2" ] || ext=".exe"
AAPT2="$BT/aapt2$ext"
ZIPALIGN="$BT/zipalign$ext"

# d8 and apksigner are Java programs behind a shell/batch wrapper. On Windows the
# .bat wrapper LOSES QUOTING on any argument containing a space, so a repository
# checked out under a path like "C:\...\Android Learning\..." produces a baffling
#     com.android.tools.r8.internal.Ke: Unsupported source file type
#     java.nio.file.NoSuchFileException: Learning\...\TokenActivity.class
# -- the path silently truncated at the space. Invoking the jars directly through
# `java -cp` bypasses the wrapper entirely and quotes correctly on every platform.
# This is a real trap, it cost an hour, and the fix is two lines.
run_d8() {
    if [ -f "$BT/lib/d8.jar" ]; then
        java -cp "$BT/lib/d8.jar" com.android.tools.r8.D8 "$@"
    elif [ -x "$BT/d8" ]; then
        "$BT/d8" "$@"
    else
        "$BT/d8.bat" "$@"
    fi
}
run_apksigner() {
    if [ -f "$BT/lib/apksigner.jar" ]; then
        java -jar "$BT/lib/apksigner.jar" "$@"
    elif [ -x "$BT/apksigner" ]; then
        "$BT/apksigner" "$@"
    else
        "$BT/apksigner.bat" "$@"
    fi
}

echo "SDK_ROOT    = $SDK_ROOT"
echo "build-tools = $BUILD_TOOLS"
echo "platform    = $PLATFORM"
echo "targetSdk   = $TARGET_SDK"
echo ""

for t in "$AAPT2" "$ZIPALIGN" "$ANDROID_JAR"; do
    [ -e "$t" ] || { echo "missing: $t" >&2; exit 1; }
done
command -v javac  >/dev/null || { echo "javac not on PATH" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not on PATH" >&2; exit 1; }

mkdir -p "$OUT"

# ---- a throwaway debug key ------------------------------------------------ #

KS="$OUT/debug.keystore"
if [ ! -f "$KS" ]; then
    echo "[*] generating a throwaway debug key (password: android)"
    keytool -genkeypair -keystore "$KS" -storepass android -keypass android \
        -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1
fi

# ---- the build function --------------------------------------------------- #

# build_apk <name> <manifest-dir> <out-apk> <source files...>
build_apk() {
    local name="$1"; shift
    local mdir="$1"; shift
    local apk="$1"; shift

    local work="$OUT/$name"
    rm -rf "$work"
    mkdir -p "$work/classes" "$work/dex"

    # The manifest is copied so targetSdk can be rewritten without touching the
    # file in the repository.
    sed "s/android:targetSdkVersion=\"[0-9]*\"/android:targetSdkVersion=\"$TARGET_SDK\"/" \
        "$mdir/AndroidManifest.xml" > "$work/AndroidManifest.xml"

    echo "[*] $name: aapt2 link"
    "$AAPT2" link -o "$work/base.apk" -I "$ANDROID_JAR" \
        --manifest "$work/AndroidManifest.xml"

    echo "[*] $name: javac ($# source file(s))"
    javac -nowarn -source 8 -target 8 \
        -bootclasspath "$ANDROID_JAR" -cp "$ANDROID_JAR" \
        -d "$work/classes" "$@" 2>&1 | grep -v '^Note:' || true

    echo "[*] $name: d8"
    # Collect the class files into an array so that a path containing a space
    # survives -- word splitting on $(find ...) would break the same way the .bat
    # wrapper does.
    local classes=()
    while IFS= read -r c; do classes+=("$c"); done \
        < <(find "$work/classes" -name '*.class')
    run_d8 --lib "$ANDROID_JAR" --min-api 24 --output "$work/dex" "${classes[@]}"

    echo "[*] $name: package + align + sign"
    cp "$work/base.apk" "$work/unsigned.apk"
    python3 - "$work/unsigned.apk" "$work/dex/classes.dex" <<'PY'
import sys, zipfile
apk, dex = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as z:
    z.write(dex, "classes.dex")
PY
    "$ZIPALIGN" -f -p 4 "$work/unsigned.apk" "$work/aligned.apk"
    run_apksigner sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
        --out "$apk" "$work/aligned.apk" 2>&1 | grep -vi 'warning' || true

    echo "[+] $apk"
}

# ---- deputy --------------------------------------------------------------- #
#
# The two Redirector classes live one directory up, in examples/, because the
# README walks through them line by line and they are the chapter's centrepiece.
# Compiling them from there keeps ONE copy of each -- a second copy under
# deputy-app/ would drift out of sync with the prose, which is exactly the failure
# this repository has had to repair before.

build_apk deputy "$HERE" "$OUT/deputy.apk" \
    "$HERE/MainActivity.java" \
    "$HERE/SecretActivity.java" \
    "$HERE/DetailActivity.java" \
    "$HERE/SettingsActivity.java" \
    "$HERE/TokenActivity.java" \
    "$HERE/VaultActivity.java" \
    "$EXAMPLES/RedirectorActivity.java" \
    "$EXAMPLES/RedirectorActivityFixed.java"

# ---- attacker ------------------------------------------------------------- #

build_apk attacker "$ATTACKER" "$OUT/attacker.apk" \
    "$ATTACKER/ExploitActivity.java"

# ---- done ----------------------------------------------------------------- #

echo ""
echo "=============================================================================="
echo " built:"
echo "   $OUT/deputy.apk     (com.pentest.deputy   -- the victim)"
echo "   $OUT/attacker.apk   (com.pentest.attacker -- the exploit)"
echo "=============================================================================="
echo ""
echo " install:"
echo "   adb install -r $OUT/deputy.apk"
echo "   adb install -r $OUT/attacker.apk"
echo ""
echo " if that fails with INSTALL_FAILED_USER_RESTRICTED your device's vendor build"
echo " is blocking adb installs (MIUI does this by default). Use an emulator:"
echo "   emulator -avd <name>   # from the Android SDK"
echo ""
echo " then, in one terminal:"
echo "   adb logcat -c && adb logcat -s ATTACKER:I DEPUTY:* AndroidRuntime:E ActivityTaskManager:E"
echo " and in another:"
echo "   adb shell \"am start -n com.pentest.attacker/.ExploitActivity\""
echo " then press the button on screen."
echo ""

if [ "$DO_INSTALL" -eq 1 ]; then
    echo "[*] installing"
    adb install -r "$OUT/deputy.apk"
    adb install -r "$OUT/attacker.apk"
fi
