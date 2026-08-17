#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build 01-reference-jni-lib.cpp into the two libraries this chapter's
#   Rosetta-stone method needs, with no Gradle, no Android Studio and no
#   network:
#
#       libreference-unstripped.so   the ANSWER KEY -- every function named
#       libreference.so              what you will actually be handed
#
#   The whole method in section 3 is: analyse the stripped one, then check each
#   guess against the unstripped one. You cannot do that with a single build,
#   and building twice by hand is where people quietly skip the second half.
#
#   The script then prints the four things worth looking at before Ghidra is
#   even open -- the exported Java_* names, the count of symbols the strip
#   removed, the .init_array entry, and the RegisterNatives table's strings --
#   because each is a lookup you will otherwise do inside Ghidra more slowly.
#
# USAGE
#   # host -- build both, arm64
#   ./build.sh
#
#   # host -- 32-bit ARM, whose calling convention and relocations differ
#   ABI=armeabi-v7a ./build.sh
#
#   # host -- choose where the binaries go
#   OUTDIR=/tmp/ch57 ./build.sh
#
#   Then, in Ghidra: File -> Import File, once for each .so, into the SAME
#   project so you can have both open side by side.
#
# REQUIREMENTS
#   * An Android NDK. Set NDK_HOME, or ANDROID_NDK_HOME, or let the script find
#     the newest one under $ANDROID_HOME/ndk. Verified with r25c
#     (25.2.9519653): the source compiles clean under -Wall -Wextra.
#   * Nothing else. No JDK, no device.
#
# WHERE IT BUILDS
#   Into $OUTDIR, default ${TMPDIR:-/tmp}/ch57-build -- OUTSIDE this
#   repository. `.so` is on the artefact blocklist. If you change OUTDIR, keep
#   it out of the tree.
#
# WHAT THIS WILL NOT DO
#   * It will NOT produce an APK. The library is a reversing target, not an
#     app; the matching Java class is printed at the bottom of the source if
#     you want to wrap it in one.
#   * It will NOT strip the same way every toolchain does. --strip-all removes
#     .symtab; it does NOT remove .dynsym, which is why the Java_* exports
#     survive and the static helpers do not. That asymmetry is the single most
#     important fact in section 3 and the script prints it rather than
#     asserting it.
#
# AUTHORISED TESTING ONLY -- though this is your own code, so go ahead.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch57-build}"
ABI="${ABI:-arm64-v8a}"
API="${API:-21}"
SRC="$HERE/01-reference-jni-lib.cpp"

NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [ -z "$NDK" ]; then
    SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${LOCALAPPDATA:-}/Android/Sdk}}"
    NDK="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -d "${NDK:-}" ] || { echo "error: no NDK found. Set NDK_HOME to your NDK root."; exit 2; }

HOSTTAG="$(ls "$NDK/toolchains/llvm/prebuilt" 2>/dev/null | head -1)"
TC="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
[ -d "$TC" ] || { echo "error: no toolchain under $NDK/toolchains/llvm/prebuilt"; exit 2; }

case "$ABI" in
    arm64-v8a)   TRIPLE="aarch64-linux-android$API" ;;
    armeabi-v7a) TRIPLE="armv7a-linux-androideabi$API" ;;
    x86_64)      TRIPLE="x86_64-linux-android$API" ;;
    x86)         TRIPLE="i686-linux-android$API" ;;
    *) echo "error: unknown ABI '$ABI'"; exit 2 ;;
esac

CXX="$TC/$TRIPLE-clang++"
NM="$TC/llvm-nm"
READELF="$TC/llvm-readelf"
STRINGS="$TC/llvm-strings"
OBJDUMP="$TC/llvm-objdump"

echo "NDK      $NDK"
echo "ABI      $ABI  ($TRIPLE)"
echo "outdir   $OUTDIR"
echo

mkdir -p "$OUTDIR"

# -O2 deliberately. A release APK is built at -O2, and the whole value of this
# library as a reference is that it shows you what -O2 does to code you wrote --
# the inlining, the folded constants, the jump table. Building it at -O0 would
# produce a target that looks nothing like the ones you will be given.
CFLAGS="-shared -fPIC -O2 -Wall -Wextra"

echo "building unstripped (the answer key)..."
"$CXX" $CFLAGS -o "$OUTDIR/libreference-unstripped.so" "$SRC" -llog || exit 1

echo "building stripped (the target)..."
"$CXX" $CFLAGS -Wl,--strip-all -o "$OUTDIR/libreference.so" "$SRC" -llog || exit 1
echo

# --------------------------------------------------------------------------- #
# What the strip did and did not do.
# --------------------------------------------------------------------------- #
count() { "$NM" "$1" 2>/dev/null | wc -l | tr -d ' '; }
dcount() { "$NM" -D --defined-only "$1" 2>/dev/null | wc -l | tr -d ' '; }

echo "1. what --strip-all removed"
printf '   unstripped: %s symbols in .symtab, %s in .dynsym\n' \
    "$(count "$OUTDIR/libreference-unstripped.so")" \
    "$(dcount "$OUTDIR/libreference-unstripped.so")"
printf '   stripped  : %s symbols in .symtab, %s in .dynsym\n' \
    "$(count "$OUTDIR/libreference.so")" \
    "$(dcount "$OUTDIR/libreference.so")"
echo "   .dynsym is UNCHANGED. Stripping cannot remove it -- the dynamic"
echo "   linker needs it to resolve Java_* at dlopen time. Everything with"
echo "   internal linkage lost its name; everything exported kept it."
echo

echo "2. the exports that survived the strip"
"$NM" -D --defined-only "$OUTDIR/libreference.so" | grep ' T Java_' | sed 's/^/   /'
echo "   Read the mangling: __ separates an overload's parameter types, _1 is"
echo "   an escaped underscore in a package name, _3 is '['. So"
echo "   Java_com_example_my_1pkg_Helper_compute is com.example.my_pkg.Helper."
echo

echo "3. the .init_array constructor -- runs before JNI_OnLoad, before Java"
"$READELF" -x .init_array "$OUTDIR/libreference.so" 2>/dev/null | sed 's/^/   /'
echo "   Those bytes are ZERO on disk, and that is not an empty section."
echo "   .init_array holds an absolute address, which is unknown until the"
echo "   library is mapped, so the linker leaves it blank and emits an"
echo "   R_AARCH64_RELATIVE relocation carrying the real offset as its addend:"
IA_ADDR="$("$READELF" -S "$OUTDIR/libreference.so" 2>/dev/null \
    | grep -A1 '\.init_array' | tr -s ' ' | grep -oE '[0-9a-f]{16}' | head -1)"
if [ -n "${IA_ADDR:-}" ]; then
    "$READELF" -r "$OUTDIR/libreference.so" 2>/dev/null \
        | grep -i "^$IA_ADDR" | sed 's/^/     /'
    echo "     (offset $IA_ADDR is .init_array; the last column is the addend --"
    echo "      the file offset of the constructor, which is the value the"
    echo "      loader writes into those eight zero bytes.)"
fi
echo "   Ghidra applies relocations on import, so it shows the pointer and"
echo "   follows it; a plain hexdump does not. Section 11 tells you to read"
echo "   .init_array first -- this is why it says to read it in Ghidra rather"
echo "   than with readelf. In the stripped build the target is a nameless"
echo "   FUN_; in the unstripped one it is library_init."
echo

echo "4. strings the dynamic-registration half leaves behind"
"$STRINGS" -a "$OUTDIR/libreference.so" | grep -E '^(hidden|\(|com/|onNative)' | sed 's/^/   /'
echo "   Three method names (hiddenAdd, hiddenSecret, hiddenVerify) and their"
echo "   three signatures are all present, because RegisterNatives takes them"
echo "   as plain strings -- yet NONE of the three has an exported symbol in"
echo "   the list printed under 2. Names with no symbol, and code with no name."
echo "   Pairing the two is what ../scripts/RecoverRegisterNatives.py does."
echo "   Also visible: com/example/ref/Reference from FindClass, and the"
echo "   ThrowNew message 'onNativeEvent not found' -- an error string is"
echo "   often the most informative thing in a stripped library."
echo

echo "done. Both libraries are under $OUTDIR -- nothing was written into the"
echo "repository. Import them into one Ghidra project and work stripped-first."
echo
echo "  disassemble a single function without leaving the shell:"
echo "    $OBJDUMP -d --disassemble-symbols=JNI_OnLoad \\"
echo "      $OUTDIR/libreference-unstripped.so"
