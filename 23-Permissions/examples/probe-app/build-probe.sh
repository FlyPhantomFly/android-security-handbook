#!/usr/bin/env bash
#
# build-probe.sh -- build the unprivileged probe APK from source.
#
# WHAT IT DOES
#     javac -> d8 -> aapt2 link -> zipalign -> apksigner, with no Gradle, no
#     Android Studio and no network access. Output goes to ./out/, which is
#     git-ignored and must never be committed.
#
# WHY NOT GRADLE
#     Because a Gradle project is a hundred files and a dependency download, and
#     this is one activity. A reader who cannot run Gradle on an assessment
#     laptop can still run this. It also makes the build steps visible, which
#     matters if you are going to modify the probe - and you should, constantly,
#     because the probe is a scratchpad rather than a finished tool.
#
# WHAT THIS WILL *NOT* DO
#     - It will not install anything. `adb install -r out/probe-app.apk`.
#     - It will not add your target to <queries>. Edit AndroidManifest.xml
#       first. A probe that cannot see the target reports a false negative that
#       looks exactly like a permission denial.
#     - It will not sign with a key that means anything. The keystore is
#       generated on first run and is throwaway. The probe is deliberately
#       unrelated to every target.
#     - It will not produce a release-quality APK. No ProGuard, no shrinking,
#       no multidex. It does not need any of that.
#
# REQUIREMENTS
#     Android SDK build-tools (aapt2, d8, zipalign, lib/apksigner.jar), an
#     android.jar platform, and a JDK. Set ANDROID_SDK_ROOT or let it guess.
#
#     javac needs a --release the platform's android.jar is compatible with.
#     The script uses 11, which every recent JDK supports and which d8 accepts.
#
# HOW TO RUN
#     export ANDROID_SDK_ROOT="$HOME/Android/Sdk"
#     ./build-probe.sh
#     adb install -r out/probe-app.apk
#
#     adb logcat -c
#     adb shell am start -n com.probe.unprivileged/.ProbeActivity \
#         --es probe query --es target 'content://com.victim.suite.notes/x'
#     adb logcat -d -s PROBE:V
#
# AUTHORISED TESTING ONLY.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
WORK="$OUT/work"

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [ -z "$SDK" ]; then
    for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "${LOCALAPPDATA:-}/Android/Sdk"; do
        if [ -d "$c" ]; then SDK="$c"; break; fi
    done
fi
[ -n "$SDK" ] && [ -d "$SDK" ] || { echo "[-] Set ANDROID_SDK_ROOT" >&2; exit 2; }

BT="$(ls -d "$SDK"/build-tools/*/ 2>/dev/null | sort -V | tail -1 || true)"; BT="${BT%/}"
[ -n "$BT" ] || { echo "[-] no build-tools under $SDK" >&2; exit 2; }

PLAT="$(ls "$SDK"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1 || true)"
[ -n "$PLAT" ] || { echo "[-] no android.jar under $SDK/platforms" >&2; exit 2; }

# d8 and apksigner ship as .bat wrappers on Windows; the jars work everywhere.
D8_JAR="$BT/lib/d8.jar"
APKSIGNER_JAR="$BT/lib/apksigner.jar"
[ -f "$D8_JAR" ]        || { echo "[-] missing $D8_JAR" >&2; exit 2; }
[ -f "$APKSIGNER_JAR" ] || { echo "[-] missing $APKSIGNER_JAR" >&2; exit 2; }

echo "[*] build-tools : $BT"
echo "[*] platform    : $PLAT"

rm -rf "$WORK"
mkdir -p "$WORK/classes" "$WORK/dex" "$OUT"

# --- 1. resources ---------------------------------------------------------
mkdir -p "$WORK/res/values"
cat > "$WORK/res/values/strings.xml" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">UnprivilegedProbe</string>
</resources>
EOF

# --- 2. java -> class -----------------------------------------------------
echo "[*] javac"
javac --release 11 -nowarn \
      -classpath "$PLAT" \
      -d "$WORK/classes" \
      "$HERE/ProbeActivity.java"

# --- 3. class -> dex ------------------------------------------------------
# Use an array, not a space-joined string. This repository lives under a path
# containing a space ("Android Learning"), and an unquoted $CLASSES silently
# splits it into two nonexistent paths. d8's error for that is forty lines of
# R8 stack trace that says NoSuchFileException on half a directory name.
echo "[*] d8"
CLASSES=()
while IFS= read -r f; do CLASSES+=("$f"); done < <(find "$WORK/classes" -name '*.class')
[ "${#CLASSES[@]}" -gt 0 ] || { echo "[-] javac produced no classes" >&2; exit 2; }
java -cp "$D8_JAR" com.android.tools.r8.D8 \
     --lib "$PLAT" --min-api 23 --output "$WORK/dex" "${CLASSES[@]}"

# --- 4. link --------------------------------------------------------------
echo "[*] aapt2"
"$BT/aapt2" compile --dir "$WORK/res" -o "$WORK/res.zip"
"$BT/aapt2" link -o "$WORK/base.apk" \
    -I "$PLAT" --manifest "$HERE/AndroidManifest.xml" "$WORK/res.zip"

# --- 5. add the dex and sign ----------------------------------------------
# aapt2 link does not accept a .dex, so classes.dex is added to the archive
# afterwards. `zip` is absent from a stock Git Bash install, so Python does it:
# python3 is already a requirement for this chapter's scripts.
echo "[*] packaging"
python3 - "$WORK/base.apk" "$WORK/dex/classes.dex" <<'PY'
import sys, zipfile
apk, dex = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as z:
    z.write(dex, "classes.dex")
PY

"$BT/zipalign" -f 4 "$WORK/base.apk" "$OUT/probe-app.apk"

if [ ! -f "$OUT/probe-key.jks" ]; then
    echo "[*] generating throwaway key"
    keytool -genkeypair -keystore "$OUT/probe-key.jks" -alias k \
        -storepass android -keypass android -keyalg RSA -keysize 2048 \
        -validity 3650 -dname "CN=probe-lab-key, OU=lab, O=lab, C=GB" >/dev/null 2>&1
fi

java -jar "$APKSIGNER_JAR" sign \
     --ks "$OUT/probe-key.jks" --ks-pass pass:android --key-pass pass:android \
     "$OUT/probe-app.apk" 2>/dev/null

rm -rf "$WORK"

echo
echo "[+] $OUT/probe-app.apk"
echo "[*] Install:  adb install -r $OUT/probe-app.apk"
echo "[*] Remember: edit <queries> in AndroidManifest.xml for YOUR target and rebuild,"
echo "[*]           or the probe will report a false negative that looks like a denial."
