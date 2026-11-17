#!/usr/bin/env bash
# labs/ctf-vault/build.sh
#
# PURPOSE
#   Build the CH41 CTF challenge APK from the sources in this directory, using
#   only the Android SDK build-tools and a JDK. One build, one rules file
#   (rules.pro), R8 in its default (full) mode.
#
# USAGE
#   # host
#   export ANDROID_HOME=~/Android/Sdk
#   OUTDIR=/tmp/ch41ctf ./build.sh
#
#   Then work on $OUTDIR/classes.dex and $OUTDIR/app.apk. Do NOT read the
#   sources for the answer -- the whole exercise is that the sources and the
#   artefact disagree.
#
# REQUIREMENTS
#   ANDROID_HOME (or ANDROID_SDK_ROOT) pointing at an SDK with build-tools
#   (aapt2, zipalign, apksigner, dexdump) and one platform android.jar, plus a
#   JDK with javac and keytool. Python 3 is used to add the DEX to the archive
#   so that `zip` is not required.
#
# WHAT THIS WILL *NOT* DO
#   * It will NOT install anything. Nothing here touches a device. The flag is
#     recoverable entirely by static analysis of the built DEX and APK; running
#     the app is optional and, for fragment 5, actively misleading.
#   * It will NOT tell you the answer. See SOLUTION.md, and read it last.
#   * It will NOT leave any artefact inside the repository. Everything is
#     written to $OUTDIR, which defaults to a temp directory.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch41-ctf}"

p() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
if [ -z "$SDK" ]; then
    for c in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "$LOCALAPPDATA/Android/Sdk"; do
        [ -d "$c" ] && SDK="$c" && break
    done
fi
[ -d "${SDK:-}" ] || { echo "error: set ANDROID_HOME to your Android SDK"; exit 2; }

BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
AJ="$(ls -d "$SDK"/platforms/*/android.jar 2>/dev/null | sort -V | tail -1)"
[ -n "$BT" ] && [ -n "$AJ" ] || { echo "error: incomplete SDK under $SDK"; exit 2; }

pick() { if [ -x "$BT/$1" ]; then echo "$BT/$1"; elif [ -f "$BT/$1.bat" ]; then echo "$BT/$1.bat"; else echo "$BT/$1.exe"; fi; }
AAPT2="$(pick aapt2)"; ZIPALIGN="$(pick zipalign)"; APKSIGNER="$(pick apksigner)"; DEXDUMP="$(pick dexdump)"
D8JAR="$BT/lib/d8.jar"

echo "build-tools $(basename "$BT")"
echo "R8          $(java -cp "$(p "$D8JAR")" com.android.tools.r8.R8 --version 2>&1 | head -1)"
echo "outdir      $OUTDIR"
echo

rm -rf "$OUTDIR"; mkdir -p "$OUTDIR/gen" "$OUTDIR/classes" "$OUTDIR/rescomp"

keytool -genkeypair -keystore "$(p "$OUTDIR/debug.ks")" -storepass android -keypass android \
    -alias ch41ctf -dname "CN=CH41 CTF,O=Android Security Handbook" \
    -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
    || { echo "error: keytool failed"; exit 2; }

"$AAPT2" compile --dir "$(p "$HERE/res")" -o "$(p "$OUTDIR/rescomp/res.zip")" || exit 1
"$AAPT2" link -o "$(p "$OUTDIR/base.apk")" -I "$(p "$AJ")" \
    --manifest "$(p "$HERE/AndroidManifest.xml")" \
    --java "$(p "$OUTDIR/gen")" \
    --min-sdk-version 21 --target-sdk-version 33 \
    "$(p "$OUTDIR/rescomp/res.zip")" || exit 1

SRCS=()
while IFS= read -r f; do SRCS+=("$(p "$f")"); done < <(find "$HERE/java" "$OUTDIR/gen" -name '*.java')
javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$OUTDIR/classes")" "${SRCS[@]}" 2>&1 \
    | grep -vE 'obsolete|bootstrap|Xlint|^[0-9]+ warning' || true
[ -f "$OUTDIR/classes/com/pentest/ch41/ctf/Gate.class" ] || { echo "error: javac produced nothing"; exit 1; }

CLASSFILES=()
while IFS= read -r f; do CLASSFILES+=("$(p "$f")"); done < <(find "$OUTDIR/classes" -name '*.class' | sort)

java -cp "$(p "$D8JAR")" com.android.tools.r8.R8 \
    --lib "$(p "$AJ")" --min-api 21 --release \
    --pg-conf "$(p "$HERE/rules.pro")" \
    --pg-map-output "$(p "$OUTDIR/mapping.txt")" \
    --pg-conf-output "$(p "$OUTDIR/configuration.txt")" \
    --output "$(p "$OUTDIR")" "${CLASSFILES[@]}" || exit 1

cp "$OUTDIR/base.apk" "$OUTDIR/app-unaligned.apk"
( cd "$OUTDIR" && python3 -B -c "
import glob, zipfile
with zipfile.ZipFile('app-unaligned.apk','a',zipfile.ZIP_DEFLATED) as z:
    for d in sorted(glob.glob('classes*.dex')):
        z.write(d, d)
" ) || exit 1
"$ZIPALIGN" -f 4 "$(p "$OUTDIR/app-unaligned.apk")" "$(p "$OUTDIR/app.apk")" || exit 1
"$APKSIGNER" sign --ks "$(p "$OUTDIR/debug.ks")" --ks-pass pass:android \
    --min-sdk-version 21 "$(p "$OUTDIR/app.apk")" >/dev/null 2>&1 || exit 1
rm -f "$OUTDIR/app-unaligned.apk" "$OUTDIR/app.apk.idsig"

echo "built: $OUTDIR/app.apk"
echo
echo "Classes that reached the DEX:"
"$DEXDUMP" -d "$(p "$OUTDIR/classes.dex")" 2>/dev/null \
    | grep "Class descriptor" | sed "s/.*'\(.*\)'.*/  \1/" | sort
echo
echo "Now:"
echo "  python3 -B ../../scripts/what-survived.py $OUTDIR/app.apk --rules rules.pro"
echo "  python3 -B ../../scripts/proguard-rules-audit.py rules.pro"
echo "  strings -a $OUTDIR/classes.dex | sort -u | less"
