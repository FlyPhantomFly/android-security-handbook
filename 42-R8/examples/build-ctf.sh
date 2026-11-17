#!/usr/bin/env bash
#
# build-ctf.sh -- build the lab-04 challenge binary from CtfVaultGuardian.kt.
#
# PURPOSE
#     Produces the artefacts labs/lab-04-ctf-the-leaked-key.md works on:
#
#       $OUT/out/dex/classes.dex     the "APK" the player analyses
#       $OUT/out/dex/mapping.txt     the LEAKED mapping file (the challenge premise)
#       $OUT/out/cf/ctf-r8.jar       a runnable build, so the player can crash it
#       $OUT/out/cf/crash.txt        a genuine obfuscated stack trace
#       $OUT/out/cf/mapping.txt      the mapping matching the runnable build
#
#     Build it yourself rather than shipping binaries: the repository must never
#     contain .dex, .jar or .class files, and a player who builds the target
#     learns something before the challenge even starts.
#
# USAGE
#     ./build-ctf.sh [OUTPUT_DIR]        # default: ./ctf-build, outside the repo
#
#     Then start the lab. Do NOT read CtfVaultGuardian.kt first -- it is the
#     answer key, and the lab tells you when to come back and check your work.
#
# REQUIREMENTS
#     Identical to build-r8-demo.sh: Android SDK build-tools (R8 lives inside
#     lib/d8.jar), a platform android.jar, a JDK 21 or LOWER (R8 8.6.x cannot
#     read class files above Java 21), and the Kotlin compiler jars from the
#     Gradle cache. Set JAVA21 to point at a suitable JDK if your default is
#     newer -- Android Studio ships one at <studio>/jbr.
#
# WHAT THIS WILL *NOT* TELL YOU
#     - It does not build an APK: no manifest, no resources, no signing. The
#       challenge is about R8's output, not about packaging.
#     - It does not verify your answer. The lab has the checks, and the source
#       file has the ground truth.
#     - The obfuscated names it produces (a.g, a.b, ...) are specific to this
#       input and this R8 version. If your output differs from the lab's
#       transcript, that is expected and is itself one of the lab's lessons:
#       R8 name assignment is not stable.
#     - It proves nothing about R8 versions other than the one it runs, which
#       it prints. Quote that version alongside any result.

set -euo pipefail

OUT="${1:-$(pwd)/ctf-build}"

if [ -f "$(dirname "$OUT")/STYLE-GUIDE.md" ] || \
   printf '%s' "$OUT" | grep -qi "Android-Security-Handbook"; then
    echo "REFUSING: $OUT is inside the notes repository." >&2
    echo "Build artefacts must never be committed. Choose a path outside the repo." >&2
    exit 2
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"/{classes,out/dex,out/cf}
cd "$OUT"

SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}}"
[ -d "$SDK" ] || SDK="$HOME/Android/Sdk"
[ -d "$SDK" ] || { echo "Set ANDROID_HOME to your Android SDK." >&2; exit 1; }

D8JAR="$(ls -1 "$SDK"/build-tools/*/lib/d8.jar 2>/dev/null | sort | tail -1 || true)"
ANDROID_JAR="$(ls -1 "$SDK"/platforms/android-*/android.jar 2>/dev/null | sort | tail -1 || true)"
[ -n "$D8JAR" ] && [ -n "$ANDROID_JAR" ] || {
    echo "Need build-tools/*/lib/d8.jar and platforms/android-*/android.jar under $SDK" >&2
    exit 1; }

pick_java() {
    for cand in "${JAVA21:-}" \
                "/c/Program Files/Android/Android Studio/jbr/bin/java.exe" \
                "$HOME/.jdks"/*/bin/java "$(command -v java || true)"; do
        [ -n "$cand" ] && [ -x "$cand" ] || continue
        v="$("$cand" -version 2>&1 | head -1 | sed -E 's/.*"([0-9]+).*/\1/')"
        if [ "${v:-0}" -le 21 ] 2>/dev/null; then echo "$cand"; return; fi
    done
    command -v java
}
JAVA="$(pick_java)"
JAVA_HOME_DIR="$(dirname "$(dirname "$JAVA")")"
echo "== java: $("$JAVA" -version 2>&1 | head -1)"
"$JAVA" -cp "$D8JAR" com.android.tools.r8.R8 --version

find_jar() { find "$HOME/.gradle/caches" -name "$1" 2>/dev/null | grep -v -- -sources | head -1; }
KC="${KOTLIN_COMPILER_JAR:-$(find_jar 'kotlin-compiler-embeddable-2*.jar')}"
STD="${KOTLIN_STDLIB_JAR:-$(find_jar 'kotlin-stdlib-2*.jar')}"
ANNJ="$(find_jar 'annotations-13.0.jar')"
COR="$(find_jar 'kotlinx-coroutines-core-jvm-1.6*.jar')"
TRV="$(find_jar 'trove4j-1.0*.jar')"
DMN="$(find_jar 'kotlin-daemon-embeddable-2*.jar')"
[ -n "$KC" ] && [ -n "$STD" ] || {
    echo "Kotlin compiler jars not found; set KOTLIN_COMPILER_JAR / KOTLIN_STDLIB_JAR." >&2
    exit 1; }

echo "== compiling CtfVaultGuardian.kt"
"$JAVA" -cp "$KC:$STD:$ANNJ:$COR:$TRV:$DMN" \
    org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
    -no-stdlib -classpath "$STD" -jvm-target 1.8 \
    -d classes "$SRC_DIR/CtfVaultGuardian.kt" 2>&1 | grep -viE "unsafe|^warning: " || true

python3 - "$OUT" <<'PY'
import os, sys, zipfile
out = sys.argv[1]
root = os.path.join(out, "classes")
with zipfile.ZipFile(os.path.join(out, "ctf.jar"), "w", zipfile.ZIP_DEFLATED) as z:
    for d, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(d, f)
            z.write(p, os.path.relpath(p, root).replace(os.sep, "/"))
print("ctf.jar written")
PY

echo "== R8 -> dex (the challenge target)"
"$JAVA" -cp "$D8JAR" com.android.tools.r8.R8 \
    --release --min-api 33 --lib "$ANDROID_JAR" \
    --pg-conf "$SRC_DIR/rules-ctf.pro" \
    --pg-map-output out/dex/mapping.txt --output out/dex \
    ctf.jar "$STD" "$ANNJ" 2>&1 | grep -viE "manifest.mf" || true

echo "== R8 -> classfile (runnable, for the stack trace)"
"$JAVA" -cp "$D8JAR" com.android.tools.r8.R8 --classfile --release \
    --lib "$JAVA_HOME_DIR" \
    --pg-conf "$SRC_DIR/rules-ctf.pro" \
    --pg-map-output out/cf/mapping.txt --output out/cf/ctf-r8.jar \
    ctf.jar "$STD" "$ANNJ" 2>&1 | grep -viE "manifest.mf" || true

echo "== running the obfuscated challenge binary"
"$JAVA" -cp out/cf/ctf-r8.jar com.pentest.ch42.ctf.CtfEntryPoint --verify \
    >out/cf/stdout.txt 2>out/cf/crash.txt || true
cat out/cf/stdout.txt
echo "-- obfuscated stack trace (out/cf/crash.txt) --"
cat out/cf/crash.txt

cat <<EOF

Challenge artefacts ready in $OUT:
  out/dex/classes.dex   analyse this
  out/dex/mapping.txt   the "leaked" mapping file
  out/cf/crash.txt      the obfuscated stack trace
  out/cf/mapping.txt    the mapping matching the runnable build

Start at labs/lab-04-ctf-the-leaked-key.md. Recover three flag segments and
assemble CH42{SEG1-SEG2-SEG3}.
EOF
