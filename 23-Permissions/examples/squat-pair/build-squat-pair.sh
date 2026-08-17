#!/usr/bin/env bash
#
# build-squat-pair.sh -- build the four permission-squatting demo APKs from source.
#
# WHAT IT DOES
#     Turns the four manifests in this directory into four installable APKs,
#     signed with THREE DIFFERENT KEYS, so that no signature relationship exists
#     between the attacker and either victim. The keys are generated on first
#     run into ./out/ and are throwaway.
#
#         squatter.apk  com.squat.first   key A   declares READ_NOTES at normal
#         victim.apk    com.victim.notes  key B   declares READ_NOTES at signature
#         suite.apk     com.victim.suite  key B   USES READ_NOTES, declares nothing
#         probe.apk     com.third.probe   key C   USES READ_NOTES, nothing else
#
#     None of the four contains a single line of code. android:hasCode="false"
#     means no classes.dex is produced at all, which is why this builds with
#     aapt2 and apksigner alone -- no Gradle, no Android Studio, no network.
#
# WHY THE BUILD LIVES OUTSIDE THE REPOSITORY
#     Everything it produces goes to ./out/, which must never be committed. An
#     APK in a git repository is a liability and this repository's artefact
#     blocklist covers .apk, .dex and .jar. Ship the sources plus this script;
#     the reader produces the binaries in one command.
#
# WHAT THIS WILL *NOT* DO
#     - It will not install anything. That is deliberate: installing an app
#       that squats a permission name is a change to the device, and the order
#       you install in IS the experiment. Do it by hand, in the order the lab
#       tells you, so you see each result.
#     - It will not clean up after you. Uninstall all four when you are done:
#           adb uninstall com.squat.first
#           adb uninstall com.victim.notes
#           adb uninstall com.victim.suite
#           adb uninstall com.third.probe
#     - It will not tell you whether the squat worked. Read the device:
#           adb shell dumpsys package permission com.victim.notes.permission.READ_NOTES
#     - It will not work on a device whose vendor build blocks sideloading, or
#       where "Install unknown apps" is off for adb.
#
# REQUIREMENTS
#     - Android SDK build-tools (aapt2, zipalign, and lib/apksigner.jar).
#       Tested with 35.0.1.
#     - An android.jar platform. Tested with android-35.
#     - A JDK, for keytool and to run apksigner.jar.
#     - bash. On Windows, Git Bash works.
#
#     Set ANDROID_SDK_ROOT, or let the script guess the usual locations.
#
# HOW TO RUN
#     export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
#     ./build-squat-pair.sh
#     ls out/*.apk
#
#     # then, in this order, watching each result:
#     adb install -r out/squatter.apk
#     adb shell pm list permissions -f -g | grep -A4 READ_NOTES
#     adb install -r out/victim.apk        # expect INSTALL_FAILED_DUPLICATE_PERMISSION
#     adb install -r out/suite.apk         # expect Success
#     adb install -r out/probe.apk         # expect Success, and granted=true
#
# AUTHORISED TESTING ONLY. Build and install on a device you own.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"

# --- locate the SDK -------------------------------------------------------
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
    for candidate in "$HOME/Android/Sdk" \
                     "$HOME/Library/Android/sdk" \
                     "${LOCALAPPDATA:-}/Android/Sdk"; do
        if [ -d "$candidate" ]; then SDK="$candidate"; break; fi
    done
fi
if [ -z "$SDK" ] || [ ! -d "$SDK" ]; then
    echo "[-] Android SDK not found. Set ANDROID_SDK_ROOT and re-run." >&2
    exit 2
fi

# Newest build-tools directory present.
BT="$(ls -d "$SDK"/build-tools/*/ 2>/dev/null | sort -V | tail -1 || true)"
BT="${BT%/}"
if [ -z "$BT" ]; then
    echo "[-] No build-tools under $SDK/build-tools. Install one with sdkmanager." >&2
    exit 2
fi

# Newest platform android.jar present.
PLAT="$(ls "$SDK"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1 || true)"
if [ -z "$PLAT" ]; then
    echo "[-] No android.jar under $SDK/platforms. Install a platform with sdkmanager." >&2
    exit 2
fi

# apksigner ships as a .bat on Windows; the jar works everywhere.
APKSIGNER_JAR="$BT/lib/apksigner.jar"
if [ ! -f "$APKSIGNER_JAR" ]; then
    echo "[-] $APKSIGNER_JAR not found." >&2
    exit 2
fi

echo "[*] build-tools : $BT"
echo "[*] platform    : $PLAT"
mkdir -p "$OUT"

# --- three throwaway signing keys ----------------------------------------
for k in a b c; do
    if [ ! -f "$OUT/key-$k.jks" ]; then
        echo "[*] generating throwaway key $k"
        keytool -genkeypair -keystore "$OUT/key-$k.jks" -alias k \
            -storepass android -keypass android -keyalg RSA -keysize 2048 \
            -validity 3650 -dname "CN=squat-lab-key-$k, OU=lab, O=lab, C=GB" \
            >/dev/null 2>&1
    fi
done

# --- build one APK from one manifest -------------------------------------
# $1 manifest file   $2 output name   $3 key letter   $4 permission description
build_one() {
    manifest="$1"; name="$2"; key="$3"; desc="$4"
    work="$OUT/work-$name"
    rm -rf "$work"
    mkdir -p "$work/res/values"

    # Per-app description, so `pm list permissions -f` visibly shows which
    # definition won the ownership race.
    sed "s|>READ_NOTES definition -- REPLACED PER APP BY build-squat-pair.sh<|>$desc<|" \
        "$HERE/strings.xml" > "$work/res/values/strings.xml"

    "$BT/aapt2" compile --dir "$work/res" -o "$work/res.zip"
    "$BT/aapt2" link -o "$work/unsigned.apk" \
        -I "$PLAT" --manifest "$HERE/$manifest" "$work/res.zip"
    "$BT/zipalign" -f 4 "$work/unsigned.apk" "$OUT/$name.apk"
    java -jar "$APKSIGNER_JAR" sign \
        --ks "$OUT/key-$key.jks" --ks-pass pass:android --key-pass pass:android \
        "$OUT/$name.apk" 2>/dev/null
    rm -rf "$work"
    echo "[+] $OUT/$name.apk   (key $key)"
}

build_one squatter-AndroidManifest.xml     squatter a "Squatter definition of READ_NOTES"
build_one victim-AndroidManifest.xml       victim   b "Victim definition of READ_NOTES"
build_one victim-suite-AndroidManifest.xml suite    b "unused - suite app declares nothing"
build_one probe-AndroidManifest.xml        probe    c "unused - probe declares nothing"

echo
echo "[*] Four APKs in $OUT. Nothing has been installed."
echo "[*] Install them in the order given in ../../labs/lab-02-squatting.md and"
echo "[*] read the device after each step. The ORDER is the experiment."
