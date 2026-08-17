#!/usr/bin/env bash
#
# examples/01-source-to-java/build.sh
#
# PURPOSE
#   Build the same Java source twice -- once as a release DEX (no debug info) and once as a
#   debug DEX (with debug info) -- then decompile both with jadx. The three files
#   AccountVault.java, decompiled-release.java and decompiled-debug.java are the
#   source -> DEX -> Java triple that chapter 56 section 6.2 walks line by line.
#
# USAGE
#   ./build.sh                 # build into ./_build (git-ignored; nothing lands in the repo)
#   ./build.sh /some/other/dir # build somewhere else entirely
#
#   Then compare:
#     diff -u decompiled-release.java "$OUT/out-release/sources/com/pentest/ch56/AccountVault.java"
#
# REQUIREMENTS
#   - A JDK. Any recent one; javac is invoked with --release 8.
#   - Android SDK build-tools with d8 and dexdump. Set ANDROID_HOME or edit BUILD_TOOLS below.
#   - An android.jar from any platform (only used as d8's --lib; nothing Android-specific is
#     referenced by the source, so the exact API level does not matter).
#   - jadx 1.5.x. Set JADX or JADX_JAR, or have `jadx` on PATH. See the note about
#     Windows jadx-gui-only installations below.
#
# WHAT THIS WILL NOT TELL YOU
#   - It will not tell you what YOUR app's build produces. Your app goes through R8, not bare
#     d8, and R8 inlines, merges, renames and rewrites. This example deliberately skips R8 so
#     that every difference you see is attributable to javac, d8 or jadx alone.
#   - It will not tell you that jadx is correct in general. It shows one class, decompiled
#     accurately. See examples/02-when-jadx-is-wrong for the other half of the story.
#   - It builds no APK and installs nothing. There is no device involvement at all.
#
# ARTEFACT POLICY
#   Everything is written under $OUT (default ./_build), which is outside the tracked file
#   set. No .class, .dex, .jar or .apk is ever written into the repository.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/_build}"

# ---------------------------------------------------------------- toolchain discovery

ANDROID_HOME="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}}"

if [ -n "${BUILD_TOOLS:-}" ]; then
    :
elif [ -d "$ANDROID_HOME/build-tools" ]; then
    BUILD_TOOLS="$ANDROID_HOME/build-tools/$(ls -1 "$ANDROID_HOME/build-tools" | sort -V | tail -1)"
else
    echo "error: cannot find Android build-tools. Set ANDROID_HOME or BUILD_TOOLS." >&2
    exit 1
fi

# d8 ships as d8.bat on Windows and d8 on Unix.
if   [ -x "$BUILD_TOOLS/d8" ];     then D8="$BUILD_TOOLS/d8"
elif [ -f "$BUILD_TOOLS/d8.bat" ]; then D8="$BUILD_TOOLS/d8.bat"
else echo "error: no d8 in $BUILD_TOOLS" >&2; exit 1
fi

ANDROID_JAR="${ANDROID_JAR:-}"
if [ -z "$ANDROID_JAR" ]; then
    for p in "$ANDROID_HOME"/platforms/*/android.jar; do
        [ -f "$p" ] && ANDROID_JAR="$p"
    done
fi
[ -n "$ANDROID_JAR" ] || { echo "error: no android.jar found; set ANDROID_JAR" >&2; exit 1; }

# jadx. Three shapes are supported, in order of preference:
#   1. $JADX          -- an explicit path to a jadx launcher
#   2. $JADX_JAR      -- an explicit path to a jadx jar; invoked via jadx.cli.JadxCLI
#   3. jadx on PATH
#
# IMPORTANT (see chapter 56 section 1.3): the Windows jadx-gui installer ships only
# jadx.exe and lib/jadx-gui-<ver>-all.jar. That jadx.exe answers --version and --help but
# opens the GUI and blocks for any real invocation. On such an install, set:
#   export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"
run_jadx() {
    if   [ -n "${JADX:-}" ];     then "$JADX" "$@"
    elif [ -n "${JADX_JAR:-}" ]; then java -cp "$JADX_JAR" jadx.cli.JadxCLI "$@"
    elif command -v jadx >/dev/null 2>&1; then jadx "$@"
    else echo "error: jadx not found. Set JADX or JADX_JAR." >&2; exit 1
    fi
}

# On Windows/Git Bash the SDK tools need native paths. cygpath exists there and not elsewhere.
winpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }

# ---------------------------------------------------------------- build

echo "build-tools : $BUILD_TOOLS"
echo "android.jar : $ANDROID_JAR"
echo "output      : $OUT"
run_jadx --version 2>/dev/null | sed 's/^/jadx        : /' || true
echo

rm -rf "$OUT"
mkdir -p "$OUT"/{classes-release,classes-debug,dex-release,dex-debug}

# javac -g:none strips the LocalVariableTable; javac -g keeps it.
echo "[1/4] javac --release 8 -g:none  (release)"
javac --release 8 -g:none -d "$OUT/classes-release" "$HERE/AccountVault.java" 2>&1 \
    | grep -v "^warning:\|obsolete\|^[0-9]* warning" || true

echo "[2/4] javac --release 8 -g       (debug)"
javac --release 8 -g -d "$OUT/classes-debug" "$HERE/AccountVault.java" 2>&1 \
    | grep -v "^warning:\|obsolete\|^[0-9]* warning" || true

# d8 --release drops debug_info_item; d8 --debug keeps it.
# NOTE: d8 8.6.x refuses class files newer than major version 61-ish. That is exactly why
# javac is invoked with --release 8 above. If you see "Unsupported class file major version",
# your javac emitted a newer class format than your d8 understands.
echo "[3/4] d8 --release / d8 --debug"
"$D8" --release --min-api 30 --lib "$(winpath "$ANDROID_JAR")" \
      --output "$(winpath "$OUT/dex-release")" \
      $(for f in "$OUT"/classes-release/com/pentest/ch56/*.class; do winpath "$f"; done)

"$D8" --debug   --min-api 30 --lib "$(winpath "$ANDROID_JAR")" \
      --output "$(winpath "$OUT/dex-debug")" \
      $(for f in "$OUT"/classes-debug/com/pentest/ch56/*.class; do winpath "$f"; done)

echo "[4/4] jadx"
run_jadx -q -d "$OUT/out-release" "$OUT/dex-release/classes.dex"
run_jadx -q -d "$OUT/out-debug"   "$OUT/dex-debug/classes.dex"

# ---------------------------------------------------------------- the measurements

echo
echo "=== DEX sizes and string-pool counts ==========================================="
for d in dex-release dex-debug; do
    printf '%-12s %7s bytes  ' "$d" "$(wc -c < "$OUT/$d/classes.dex")"
    if [ -x "$BUILD_TOOLS/dexdump" ] || [ -f "$BUILD_TOOLS/dexdump.exe" ]; then
        "$BUILD_TOOLS/dexdump" -f "$OUT/$d/classes.dex" 2>/dev/null \
            | grep string_ids_size | tr -s ' '
    else
        echo
    fi
done

echo
echo "=== do the original local variable names survive? =============================="
for d in dex-release dex-debug; do
    printf '%-12s' "$d"
    for name in candidate equal limit; do
        n=$(strings -a "$OUT/$d/classes.dex" 2>/dev/null | grep -cx "$name" || true)
        printf ' %s=%s' "$name" "$n"
    done
    echo
done

echo
echo "=== decompiled output ==========================================================="
echo "release : $OUT/out-release/sources/com/pentest/ch56/AccountVault.java"
echo "debug   : $OUT/out-debug/sources/com/pentest/ch56/AccountVault.java"
echo
echo "Compare against the captured copies in this directory:"
echo "  diff -u decompiled-release.java $OUT/out-release/sources/com/pentest/ch56/AccountVault.java"
echo "  diff -u decompiled-debug.java   $OUT/out-debug/sources/com/pentest/ch56/AccountVault.java"
echo
echo "(The only expected difference is the '/* loaded from: */' header comment, which"
echo " records the absolute path of the DEX and therefore differs on every machine.)"
