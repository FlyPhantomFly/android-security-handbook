#!/usr/bin/env bash
#
# build-r8-demo.sh -- build LicenceVault.kt four times with R8 and diff the results.
#
# PURPOSE
#     Produces, from one Kotlin source file, the four builds chapter 42 compares:
#
#       out/full           full mode,   baseline rules      -> @Metadata STRIPPED
#       out/compat         compat mode, -keepattributes     -> @Metadata STRIPPED
#       out/meta2-full     full mode,   kotlin.Metadata kept -> @Metadata REWRITTEN
#       out/meta2-compat   compat mode, kotlin.Metadata kept -> @Metadata REWRITTEN
#
#     plus out/cf/app-r8.jar, a RUNNABLE classfile build used to generate a real
#     obfuscated stack trace for the retrace lab.
#
#     Every mapping.txt and every classes.dex in this chapter was produced by
#     this script. Nothing here is hand-written or illustrative.
#
# USAGE
#     ./build-r8-demo.sh [OUTPUT_DIR]
#
#     OUTPUT_DIR defaults to ./r8-demo-build and is created if missing.
#     ALWAYS build outside the notes repository -- this script refuses to write
#     into a directory that looks like the repo, because .dex/.jar/.class files
#     must never be committed.
#
#     Then:
#       python3 -B ../scripts/kotlin-metadata-recover.py "$OUT/out/full/classes.dex"
#       python3 -B ../scripts/mapping-reader.py "$OUT/out/full/mapping.txt" stats
#
# REQUIREMENTS
#     - A JDK. R8 8.6.x cannot READ class files newer than Java 21, so if your
#       default `java` is 22+ this script looks for a JDK 17/21 to compile with.
#       Android Studio ships one at <studio>/jbr.
#     - Android SDK build-tools (any of 34.0.0+). R8 lives inside lib/d8.jar --
#       there is no separate r8.jar in the SDK. Set ANDROID_HOME or SDK_ROOT.
#     - A platform android.jar (any recent android-NN).
#     - kotlin-compiler-embeddable + kotlin-stdlib jars. The script finds them in
#       the Gradle cache; set KOTLIN_HOME to a kotlinc install to override.
#
# WHAT THIS WILL *NOT* TELL YOU
#     - It does not build an APK. There is no manifest, no resources and no
#       signing here, so it cannot tell you anything about resource shrinking,
#       AAPT2 rules, or how AGP wires R8 up. It isolates the R8 step on purpose;
#       an AGP build hides exactly the flags this chapter is about.
#     - It does not reproduce YOUR app's obfuscation. R8 name assignment depends
#       on the whole program, so the names here are specific to this input.
#     - It proves nothing about R8 versions other than the one it happens to run.
#       Print the version it used (the script does) before quoting any result.
#     - Nothing here is a security control demonstration. All four builds are
#       equally reversible; they differ only in how much work it takes.

set -euo pipefail

OUT="${1:-$(pwd)/r8-demo-build}"

# --- refuse to pollute the notes repository ---------------------------------
if [ -f "$(dirname "$OUT")/STYLE-GUIDE.md" ] || \
   printf '%s' "$OUT" | grep -qi "Android-Security-Handbook"; then
    echo "REFUSING: $OUT is inside the notes repository." >&2
    echo "Build artefacts (.dex, .jar, .class) must never be committed." >&2
    echo "Pass an output directory outside the repo, e.g. /tmp/r8-demo" >&2
    exit 2
fi

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"/{classes,out}
cd "$OUT"

# --- locate the SDK ----------------------------------------------------------
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}}"
[ -d "$SDK" ] || SDK="$HOME/Android/Sdk"
[ -d "$SDK" ] || { echo "Set ANDROID_HOME to your Android SDK." >&2; exit 1; }

D8JAR="$(ls -1 "$SDK"/build-tools/*/lib/d8.jar 2>/dev/null | sort | tail -1 || true)"
[ -n "$D8JAR" ] || { echo "No build-tools/*/lib/d8.jar under $SDK." >&2; exit 1; }
ANDROID_JAR="$(ls -1 "$SDK"/platforms/android-*/android.jar 2>/dev/null | sort | tail -1 || true)"
[ -n "$ANDROID_JAR" ] || { echo "No platforms/android-*/android.jar under $SDK." >&2; exit 1; }

# --- locate a JDK R8 can read -----------------------------------------------
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
echo "== java : $JAVA ($("$JAVA" -version 2>&1 | head -1))"
echo "== d8jar: $D8JAR"
"$JAVA" -cp "$D8JAR" com.android.tools.r8.R8 --version

# --- locate the Kotlin compiler ---------------------------------------------
find_jar() { find "$HOME/.gradle/caches" -name "$1" 2>/dev/null | grep -v -- -sources | head -1; }
KC="${KOTLIN_COMPILER_JAR:-$(find_jar 'kotlin-compiler-embeddable-*.jar')}"
STD="${KOTLIN_STDLIB_JAR:-$(find_jar 'kotlin-stdlib-2*.jar')}"
ANNJ="$(find_jar 'annotations-13.0.jar')"
COR="$(find_jar 'kotlinx-coroutines-core-jvm-1.6*.jar')"
TRV="$(find_jar 'trove4j-1.0*.jar')"
DMN="$(find_jar 'kotlin-daemon-embeddable-2*.jar')"
[ -n "$KC" ] && [ -n "$STD" ] || {
    echo "Could not find kotlin-compiler-embeddable / kotlin-stdlib in the Gradle cache." >&2
    echo "Set KOTLIN_COMPILER_JAR and KOTLIN_STDLIB_JAR, or install kotlinc." >&2; exit 1; }
echo "== kotlinc: $KC"

# --- 1. compile Kotlin -------------------------------------------------------
echo "== compiling LicenceVault.kt"
"$JAVA" -cp "$KC:$STD:$ANNJ:$COR:$TRV:$DMN" \
    org.jetbrains.kotlin.cli.jvm.K2JVMCompiler \
    -no-stdlib -classpath "$STD" -jvm-target 1.8 \
    -d classes "$SRC_DIR/LicenceVault.kt" 2>&1 | grep -vi "^warning: .*Unsafe" || true

python3 - "$OUT" <<'PY'
import os, sys, zipfile
out = sys.argv[1]
with zipfile.ZipFile(os.path.join(out, "app.jar"), "w", zipfile.ZIP_DEFLATED) as z:
    root = os.path.join(out, "classes")
    for d, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(d, f)
            z.write(p, os.path.relpath(p, root).replace(os.sep, "/"))
print("app.jar written")
PY

# --- 2. the four R8 builds ---------------------------------------------------
run_r8() {
    name="$1"; rules="$2"; shift 2
    mkdir -p "out/$name"
    echo "== R8 $name ($* )"
    "$JAVA" -cp "$D8JAR" com.android.tools.r8.R8 "$@" \
        --release --min-api 33 --lib "$ANDROID_JAR" \
        --pg-conf "$rules" \
        --pg-map-output "out/$name/mapping.txt" \
        --output "out/$name" \
        app.jar "$STD" "$ANNJ" 2>&1 | grep -viE "manifest.mf" || true
}
run_r8 full           "$SRC_DIR/rules-baseline.pro"
run_r8 compat         "$SRC_DIR/rules-baseline.pro"      --pg-compat
run_r8 meta2-full     "$SRC_DIR/rules-keep-metadata.pro"
run_r8 meta2-compat   "$SRC_DIR/rules-keep-metadata.pro" --pg-compat

# --- 3. a runnable build, for a REAL obfuscated stack trace ------------------
mkdir -p out/cf
"$JAVA" -cp "$D8JAR" com.android.tools.r8.R8 --classfile --release \
    --lib "$(dirname "$(dirname "$JAVA")")" \
    --pg-conf "$SRC_DIR/rules-baseline.pro" \
    --pg-map-output out/cf/mapping.txt \
    --output out/cf/app-r8.jar \
    app.jar "$STD" "$ANNJ" 2>&1 | grep -viE "manifest.mf" || true

echo "== running the obfuscated build to capture a genuine stack trace"
"$JAVA" -cp out/cf/app-r8.jar com.pentest.ch42.vault.VaultEntryPoint --crash \
    >out/cf/stdout.txt 2>out/cf/crash.txt || true
cat out/cf/crash.txt

# --- 4. summary --------------------------------------------------------------
echo
RECOVER="$SRC_DIR/../scripts/kotlin-metadata-recover.py"
printf '%-16s %10s %10s %14s  %s\n' BUILD DEX_BYTES MAP_LINES META_CLASSES VERDICT
for b in full compat meta2-full meta2-compat; do
    dex="out/$b/classes.dex"
    # Count classes that actually CARRY the annotation, not occurrences of the
    # type-descriptor string -- the string appears once in the DEX string table
    # however many classes reference it, which is why grep is the wrong tool.
    read -r n v <<<"$(python3 -B "$RECOVER" "$dex" --rewrite-check 2>/dev/null \
        | awk '/^classes/{n=$3} /^verdict/{v=$3} END{print n+0, (v==""?"?":v)}')"
    printf '%-16s %10s %10s %14s  %s\n' "$b" "$(wc -c <"$dex")" \
        "$(wc -l <"out/$b/mapping.txt")" "$n" "$v"
done
echo
echo "Now run:"
echo "  python3 -B $SRC_DIR/../scripts/kotlin-metadata-recover.py $OUT/out/meta2-compat/classes.dex --members"
echo "  python3 -B $SRC_DIR/../scripts/mapping-reader.py $OUT/out/cf/mapping.txt retrace $OUT/out/cf/crash.txt"
