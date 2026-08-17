#!/usr/bin/env bash
# examples/keeplab/build.sh
#
# PURPOSE
#   Build the SAME small Android application three times and leave the three
#   results side by side so you can diff what survived:
#
#     A  no-rules      minifyEnabled false  -- D8 only, nothing shrunk or renamed
#     B  tightened     minifyEnabled true   -- R8 + examples/02-tightened-rules.pro
#     C  over-broad    minifyEnabled true   -- R8 + examples/01-overbroad-rules.pro
#
#   Build C is the point of the exercise. It has minification switched ON and
#   produces a DEX that is, for the app's own code, indistinguishable from build
#   A. That is what an over-broad -keep costs, and it is why "minifyEnabled
#   true" in a build file proves nothing on its own.
#
# USAGE
#   # host -- build all three
#   ./build.sh
#
#   # host -- choose where artefacts go (default: a temp dir OUTSIDE the repo)
#   OUTDIR=/tmp/ch41 ./build.sh
#
#   # host -- build, then report on each
#   ./build.sh && python3 -B ../../scripts/what-survived.py \
#       "$OUTDIR/b-tightened/app.apk" --rules ../02-tightened-rules.pro
#
# REQUIREMENTS
#   * ANDROID_HOME or ANDROID_SDK_ROOT pointing at an Android SDK with
#     build-tools (aapt2, d8, zipalign, apksigner, dexdump) and one platform
#     android.jar. The newest of each is used.
#   * A JDK with javac and keytool. Written and run against JDK 24.
#   * R8 itself: the R8 classes ship INSIDE build-tools/<ver>/lib/d8.jar. There
#     is no separate r8.jar in the SDK and there is no ProGuard binary at all --
#     see "ProGuard is not installed" below.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * It will NOT run real ProGuard. ProGuard is a separate Guardsquare
#     product and is not part of the Android SDK; nothing in a modern AGP build
#     invokes it. This script uses R8, which is what your `proguard-rules.pro`
#     is actually fed to. The RULES LANGUAGE is shared, which is why the
#     exercise is still about ProGuard; the ENGINE is not. Where the two
#     engines differ in how they interpret a rule, the README says so
#     explicitly rather than letting this script imply equivalence.
#   * It will NOT reproduce your app's build. AGP passes R8 far more than your
#     rules file -- the generated manifest keeps, the AAPT rules, and every
#     dependency's consumer rules. Section 8 of the README shows how to dump
#     the real, merged configuration from a Gradle build.
#   * It will NOT tell you whether an app is "obfuscated enough". There is no
#     such measurement. It tells you what names are in a DEX; deciding whether
#     that matters is your job and the README's section 5 argues it should
#     usually be reported as a hardening gap, not a vulnerability.
#   * It does NOT install anything. Nothing here touches a device.
#
# The repository ships SOURCES ONLY. This script writes every .class, .dex and
# .apk it produces to $OUTDIR, which defaults to a temp directory outside the
# repository tree. Nothing lands next to the sources.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES="$(cd "$HERE/.." && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch41-keeplab}"

# On Git Bash / MSYS the SDK tools are native Windows binaries and do not
# understand /c/Users/... paths. cygpath converts; elsewhere this is identity.
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

pick() { if [ -x "$BT/$1" ]; then echo "$BT/$1"; elif [ -f "$BT/$1.bat" ]; then echo "$BT/$1.bat"; else echo "$BT/$1.exe"; fi; }
AAPT2="$(pick aapt2)"; ZIPALIGN="$(pick zipalign)"
APKSIGNER="$(pick apksigner)"; DEXDUMP="$(pick dexdump)"
D8JAR="$BT/lib/d8.jar"
[ -f "$D8JAR" ] || { echo "error: no lib/d8.jar in $BT -- R8 lives inside it"; exit 2; }

echo "SDK          $SDK"
echo "build-tools  $(basename "$BT")"
echo "android.jar  $AJ"
echo "R8           $(java -cp "$(p "$D8JAR")" com.android.tools.r8.R8 --version 2>&1 | head -1)"
echo "outdir       $OUTDIR"
echo

rm -rf "$OUTDIR"
mkdir -p "$OUTDIR/gen" "$OUTDIR/classes" "$OUTDIR/rescomp"

# --------------------------------------------------------------------------- #
# A throwaway signing key. It exists so the package manager would accept the
# file; it is not a credential and it is regenerated on every run.
# --------------------------------------------------------------------------- #
KS="$OUTDIR/debug.ks"
keytool -genkeypair -keystore "$(p "$KS")" -storepass android -keypass android \
    -alias ch41 -dname "CN=CH41 Keep Lab,O=Android Pentesting Notes" \
    -validity 10000 -keyalg RSA -keysize 2048 >/dev/null 2>&1 \
    || { echo "error: keytool failed -- is a JDK on PATH?"; exit 2; }

# --------------------------------------------------------------------------- #
# 1. Resources: compile, then link. The link step also emits R.java.
# --------------------------------------------------------------------------- #
echo "--- aapt2 compile + link ---"
"$AAPT2" compile --dir "$(p "$HERE/res")" -o "$(p "$OUTDIR/rescomp/res.zip")" || exit 1
"$AAPT2" link -o "$(p "$OUTDIR/base.apk")" -I "$(p "$AJ")" \
    --manifest "$(p "$HERE/AndroidManifest.xml")" \
    --java "$(p "$OUTDIR/gen")" \
    --min-sdk-version 21 --target-sdk-version 33 \
    "$(p "$OUTDIR/rescomp/res.zip")" || exit 1

# --------------------------------------------------------------------------- #
# 2. javac. --release 8 keeps the class files inside D8's comfort zone; newer
#    JDKs warn about it, which is harmless and filtered.
# --------------------------------------------------------------------------- #
echo "--- javac ---"
SRCS=()
while IFS= read -r f; do SRCS+=("$(p "$f")"); done < <(find "$HERE/java" "$OUTDIR/gen" -name '*.java')
javac --release 8 -nowarn -classpath "$(p "$AJ")" -d "$(p "$OUTDIR/classes")" "${SRCS[@]}" 2>&1 \
    | grep -vE 'obsolete|bootstrap|Xlint|^[0-9]+ warning' || true
[ -f "$OUTDIR/classes/com/pentest/ch41/MainActivity.class" ] || { echo "error: javac produced nothing"; exit 1; }

CLASSFILES=()
while IFS= read -r f; do CLASSFILES+=("$(p "$f")"); done < <(find "$OUTDIR/classes" -name '*.class' | sort)
echo "compiled ${#CLASSFILES[@]} class files"

# --------------------------------------------------------------------------- #
# package <variant-dir>  -- wrap a dex directory into a signed APK
# --------------------------------------------------------------------------- #
# `zip` is not present in every Git Bash install, so the DEX is added with
# Python's zipfile module instead -- one less thing to install.
package() {
    local v="$1"
    cp "$OUTDIR/base.apk" "$OUTDIR/$v/app-unaligned.apk"
    ( cd "$OUTDIR/$v" && python3 -B -c "
import glob, zipfile
with zipfile.ZipFile('app-unaligned.apk', 'a', zipfile.ZIP_DEFLATED) as z:
    for d in sorted(glob.glob('classes*.dex')):
        z.write(d, d)
" ) || return 1
    "$ZIPALIGN" -f 4 "$(p "$OUTDIR/$v/app-unaligned.apk")" "$(p "$OUTDIR/$v/app.apk")" || return 1
    "$APKSIGNER" sign --ks "$(p "$KS")" --ks-pass pass:android \
        --min-sdk-version 21 "$(p "$OUTDIR/$v/app.apk")" || return 1
    rm -f "$OUTDIR/$v/app-unaligned.apk" "$OUTDIR/$v/app.apk.idsig"
}

# --------------------------------------------------------------------------- #
# BUILD A -- minifyEnabled false. D8 translates; it never renames or removes.
# --------------------------------------------------------------------------- #
echo
echo "=== BUILD A: no rules (D8, minifyEnabled false) ==="
mkdir -p "$OUTDIR/a-norules"
java -cp "$(p "$D8JAR")" com.android.tools.r8.D8 \
    --lib "$(p "$AJ")" --min-api 21 --release \
    --output "$(p "$OUTDIR/a-norules")" "${CLASSFILES[@]}" || exit 1
package a-norules || exit 1

# --------------------------------------------------------------------------- #
# BUILD B -- minifyEnabled true, tightened rules.
#
# --pg-map-output writes mapping.txt. In a Gradle build it lands at
# app/build/outputs/mapping/<variant>/mapping.txt. It is a BUILD ARTEFACT and
# must never be shipped inside the APK; this script writes it beside the APK,
# not into it.
# --------------------------------------------------------------------------- #
echo
echo "=== BUILD B: tightened rules (R8, minifyEnabled true) ==="
mkdir -p "$OUTDIR/b-tightened"
java -cp "$(p "$D8JAR")" com.android.tools.r8.R8 \
    --lib "$(p "$AJ")" --min-api 21 --release \
    --pg-conf "$(p "$EXAMPLES/02-tightened-rules.pro")" \
    --pg-map-output "$(p "$OUTDIR/b-tightened/mapping.txt")" \
    --pg-conf-output "$(p "$OUTDIR/b-tightened/configuration.txt")" \
    --output "$(p "$OUTDIR/b-tightened")" "${CLASSFILES[@]}" || exit 1
package b-tightened || exit 1

# --------------------------------------------------------------------------- #
# BUILD C -- minifyEnabled true, over-broad rules. Same flag, same engine,
# same effort in the build log. Compare the output with build A.
# --------------------------------------------------------------------------- #
echo
echo "=== BUILD C: over-broad rules (R8, minifyEnabled true) ==="
mkdir -p "$OUTDIR/c-overbroad"
java -cp "$(p "$D8JAR")" com.android.tools.r8.R8 \
    --lib "$(p "$AJ")" --min-api 21 --release \
    --pg-conf "$(p "$EXAMPLES/01-overbroad-rules.pro")" \
    --pg-map-output "$(p "$OUTDIR/c-overbroad/mapping.txt")" \
    --pg-conf-output "$(p "$OUTDIR/c-overbroad/configuration.txt")" \
    --output "$(p "$OUTDIR/c-overbroad")" "${CLASSFILES[@]}" || exit 1
package c-overbroad || exit 1

# --------------------------------------------------------------------------- #
# 3. The diff. Everything below is measurement, not build.
# --------------------------------------------------------------------------- #
echo
echo "=============================================================="
echo " WHAT SURVIVED"
echo "=============================================================="

names() {
    # Every type descriptor and every method name in the app's own package,
    # straight out of the DEX. dexdump -f is the header; -d is disassembly.
    "$DEXDUMP" -d "$(p "$OUTDIR/$1/classes.dex")" 2>/dev/null
}

# Measure the DEX, not the APK. apksigner pads the APK Signing Block so the ZIP
# central directory starts on a 4096-byte boundary, which rounds all three of
# these tiny APKs to exactly the same file size even though their classes.dex
# files differ by more than 2x. Anyone comparing `ls -l *.apk` on a small build
# will conclude that minification did nothing. Compare classes.dex.
for v in a-norules b-tightened c-overbroad; do
    dex="$OUTDIR/$v/classes.dex"
    apk="$OUTDIR/$v/app.apk"
    classes=$(names "$v" | grep -c "^  Class descriptor" || true)
    own=$(names "$v" | grep "^  Class descriptor" | grep -c "Lcom/pentest/ch41/" || true)
    methods=$(names "$v" | grep -c "^      name          : " || true)
    printf '%-14s dex=%7s B  apk=%7s B  classes=%3s  own-pkg=%3s  named-members=%4s\n' \
        "$v" "$(wc -c < "$dex" | tr -d ' ')" "$(wc -c < "$apk" | tr -d ' ')" \
        "$classes" "$own" "$methods"
done
echo "(the three APK sizes are equal on purpose -- see the comment above this loop)"

echo
echo "--- class descriptors in com.pentest.ch41, per build ---"
for v in a-norules b-tightened c-overbroad; do
    echo "[$v]"
    names "$v" | grep "^  Class descriptor" | sed "s/.*'\(.*\)'.*/  \1/" | sort
done

echo
echo "--- is the string 'staging-token-do-not-ship' still in the DEX? ---"
for v in a-norules b-tightened c-overbroad; do
    if grep -qa 'staging-token-do-not-ship' "$OUTDIR/$v/classes.dex"; then
        echo "  $v: YES  (DeadCode was kept)"
    else
        echo "  $v: no   (DeadCode was shrunk away)"
    fi
done

echo
echo "--- resource names, which no build affects ---"
"$AAPT2" dump resources "$(p "$OUTDIR/c-overbroad/app.apk")" 2>/dev/null \
    | grep -oE '(string|id|layout)/[a-z_]+' | sort -u | sed 's/^/  /'

echo
echo "mapping.txt for B: $OUTDIR/b-tightened/mapping.txt"
echo "mapping.txt for C: $OUTDIR/c-overbroad/mapping.txt"
echo
echo "Next: python3 -B ../../scripts/what-survived.py \"$OUTDIR/b-tightened/app.apk\" \\"
echo "         --rules \"$EXAMPLES/02-tightened-rules.pro\""
