#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build every native example in this directory with the Android NDK, with
#   -Wall -Wextra, and then MEASURE the three claims the chapter makes about
#   the resulting binaries:
#
#       1. static registration  -> Java_* symbols appear in `nm -D`
#       2. dynamic registration -> only JNI_OnLoad / JNI_OnUnload appear
#       3. the XOR-obscured class name in dynamic_registration.c
#
#   Claim 3 is the interesting one and the reason this script exists rather
#   than a one-line compile command. It is TRUE at -O0, -O1, -Os and -Oz and
#   FALSE at -O2, because clang constant-folds the de-obfuscation loop and
#   writes 24 of the 25 plaintext characters straight into .rodata. The script
#   builds that one library at all five levels and prints what `strings` finds
#   at each, so the reader sees the difference instead of taking it on trust.
#   See "the -O2 result" in README.md in this directory.
#
#   Six libraries are produced:
#
#       libhellojni.so    hello_jni.c            example 9.1
#       libsafe.so        safe_jni.c             example 9.2, hardened
#       libunsafe.so      unsafe_jni.c           example 9.3a, DELIBERATELY SOFT
#       libfixed.so       fixed_jni.c            example 9.3b, hardened
#       libguard.so       dynamic_registration.c example 9.4
#       libenterprise.so  enterprise_bridge.cpp  example 9.5b, C++17, hardened
#
# USAGE
#   # host -- build everything for arm64 and run the symbol checks
#   ./build.sh
#
#   # host -- build for 32-bit ARM instead
#   ABI=armeabi-v7a ./build.sh
#
#   # host -- choose where the binaries go
#   OUTDIR=/tmp/ch16 ./build.sh
#
#   # host -- build only, skip the measurements
#   ./build.sh --no-verify
#
# REQUIREMENTS
#   * An Android NDK. Set NDK_HOME, or ANDROID_NDK_HOME, or let the script find
#     the newest one under $ANDROID_HOME/ndk. NDK r21 or newer; the repository's
#     own runs used r25c (25.2.9519653).
#   * Nothing else. No JDK, no Gradle, no device, no network.
#
# WHERE IT BUILDS
#   Into $OUTDIR, which defaults to a directory OUTSIDE this repository
#   (${TMPDIR:-/tmp}/ch16-build). `.so` and `.o` are on the repository's
#   artefact blocklist and must never land next to the sources. If you change
#   OUTDIR, keep it out of the tree.
#
# WHAT THIS WILL NOT DO
#   * It will NOT build an APK or touch a device. The Java sides of these
#     examples need a project; examples/README.md says how to assemble one.
#   * It will NOT tell you whether unsafe_jni.c is exploitable on your device.
#     That is labs/lab-02, and the answer is allocator- and device-dependent.
#
# AUTHORISED TESTING ONLY. libunsafe.so is deliberately vulnerable and is built
# with the stack protector OFF on purpose. Load it only in a throwaway app.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch16-build}"
ABI="${ABI:-arm64-v8a}"
API="${API:-21}"

# --------------------------------------------------------------------------- #
# Locate the NDK and pick the compiler triple for the requested ABI.
# --------------------------------------------------------------------------- #
NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [ -z "$NDK" ]; then
    SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${LOCALAPPDATA:-}/Android/Sdk}}"
    NDK="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -d "${NDK:-}" ] || {
    echo "error: no NDK found. Set NDK_HOME to your NDK root, for example:"
    echo "       export NDK_HOME=\$ANDROID_HOME/ndk/25.2.9519653"
    exit 2
}

# The prebuilt directory is named for the HOST, not the target.
HOSTTAG="$(ls "$NDK/toolchains/llvm/prebuilt" 2>/dev/null | head -1)"
TC="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
[ -d "$TC" ] || { echo "error: no toolchain under $NDK/toolchains/llvm/prebuilt"; exit 2; }

case "$ABI" in
    arm64-v8a)   TRIPLE="aarch64-linux-android$API" ;;
    armeabi-v7a) TRIPLE="armv7a-linux-androideabi$API" ;;
    x86_64)      TRIPLE="x86_64-linux-android$API" ;;
    x86)         TRIPLE="i686-linux-android$API" ;;
    *) echo "error: unknown ABI '$ABI' (arm64-v8a, armeabi-v7a, x86_64, x86)"; exit 2 ;;
esac

CC="$TC/$TRIPLE-clang"
CXX="$TC/$TRIPLE-clang++"
[ -x "$CC" ] || [ -f "$CC.cmd" ] || [ -f "$CC" ] || {
    echo "error: $CC not found. Is API level $API available in this NDK?"
    exit 2
}

NM="$TC/llvm-nm"
STRINGS="$TC/llvm-strings"
READELF="$TC/llvm-readelf"

echo "NDK      $NDK"
echo "ABI      $ABI  ($TRIPLE)"
echo "outdir   $OUTDIR"
echo

mkdir -p "$OUTDIR"

# --------------------------------------------------------------------------- #
# Flag sets.
#
# WARN is applied to every target. A file that does not compile clean under
# -Wall -Wextra is not a verified example, and this chapter ships them as if
# they were, so the script fails loudly rather than continuing.
#
# HARDEN is what a real library should use. SOFT is the deliberate opposite,
# used for unsafe_jni.c ONLY, so that its overflows corrupt memory visibly
# instead of being converted into a clean abort by the stack canary. Keeping
# hardening ON is the more realistic test; see README.md section 5.2 on the
# severity conversation that difference produces.
# --------------------------------------------------------------------------- #
WARN="-Wall -Wextra"
HARDEN="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now -Wl,-z,noexecstack"
SOFT="-O0 -fno-stack-protector -U_FORTIFY_SOURCE"

FAILED=0

build() {
    local out="$1" compiler="$2" src="$3"; shift 3
    printf '  %-18s ' "$out"
    if "$compiler" -shared -fPIC $WARN "$@" -o "$OUTDIR/$out" "$HERE/$src" 2>"$OUTDIR/$out.log"; then
        if [ -s "$OUTDIR/$out.log" ]; then
            echo "BUILT WITH WARNINGS"
            sed 's/^/      /' "$OUTDIR/$out.log"
            FAILED=1
        else
            echo "clean"
        fi
    else
        echo "FAILED"
        sed 's/^/      /' "$OUTDIR/$out.log"
        FAILED=1
    fi
}

echo "building (${WARN}):"
build libhellojni.so   "$CC"  hello_jni.c             -O2
build libsafe.so       "$CC"  safe_jni.c              $HARDEN
build libunsafe.so     "$CC"  unsafe_jni.c            $SOFT
build libfixed.so      "$CC"  fixed_jni.c             $HARDEN
build libguard.so      "$CC"  dynamic_registration.c  -O2
build libenterprise.so "$CXX" enterprise_bridge.cpp   -std=c++17 -fvisibility=hidden -static-libstdc++ $HARDEN
echo

if [ "${1:-}" = "--no-verify" ]; then
    [ "$FAILED" -eq 0 ] || exit 1
    echo "done. Binaries are under $OUTDIR -- nothing was written into the repository."
    exit 0
fi

# --------------------------------------------------------------------------- #
# Claim 1 -- static registration exports Java_* symbols.
# --------------------------------------------------------------------------- #
echo "1. static registration: exported Java_* symbols in libhellojni.so"
"$NM" -D --defined-only "$OUTDIR/libhellojni.so" | grep ' T Java_' | sed 's/^/   /'
echo "   Expect four, including describe___3B with THREE underscores -- the"
echo "   mangling of the [B (byte[]) parameter. See README.md section 3.4."
echo

# --------------------------------------------------------------------------- #
# Claim 2 -- dynamic registration exports almost nothing.
# --------------------------------------------------------------------------- #
echo "2. dynamic registration: exported text symbols in libguard.so"
"$NM" -D --defined-only "$OUTDIR/libguard.so" | grep ' T ' | sed 's/^/   /'
echo "   Expect JNI_OnLoad and JNI_OnUnload and nothing else. The three"
echo "   implementations are static, so they have no name in .dynsym at all."
echo
echo "   The signatures still leak, because RegisterNatives needs them at runtime:"
"$STRINGS" -a "$OUTDIR/libguard.so" | grep -E '^\([A-Z[L]' | sed 's/^/   /'
echo "   Note (L%s/%s/String;)Z rather than (Ljava/lang/String;)Z -- the file"
echo "   assembles that one with snprintf, which is why it is not whole here."
echo

# --------------------------------------------------------------------------- #
# Claim 3 -- and this is where the chapter used to be wrong.
#
# dynamic_registration.c XORs "com/example/jnidemo/Guard" with 0x5A so that the
# class name does not appear in `strings`. That works -- at every optimisation
# level except the one the chapter told you to use.
# --------------------------------------------------------------------------- #
echo "3. does the XOR-obscured class name survive into .rodata?"
echo "   Same source, five optimisation levels, one grep:"
echo
for O in 0 1 2 s z; do
    "$CC" -shared -fPIC "-O$O" $WARN -o "$OUTDIR/probe-O$O.so" \
        "$HERE/dynamic_registration.c" 2>/dev/null || continue
    hit="$("$STRINGS" -a "$OUTDIR/probe-O$O.so" | grep -i 'com/example')"
    if [ -z "$hit" ]; then
        printf '   -O%-2s  hidden\n' "$O"
    else
        printf '   -O%-2s  LEAKED: %s\n' "$O" "$hit"
    fi
done
echo
echo "   At -O2 clang evaluates the de-obfuscation loop at compile time and"
echo "   materialises the answer: a 16-byte and an 8-byte load from .rodata"
echo "   for the first 24 characters, plus 'd' as an immediate (mov w8, #100)"
echo "   for the 25th. That is why the leaked string is 'Guar' and not 'Guard'"
echo "   -- one character short, which is exactly the shape to recognise."
echo "   Confirm it yourself:"
echo
echo "     $READELF -x .rodata $OUTDIR/probe-O2.so | head -5"
echo "     $TC/llvm-objdump -d --disassemble-symbols=JNI_OnLoad $OUTDIR/probe-O2.so"
echo
echo "   The lesson is not 'use -Os'. It is that a string-obscuring scheme the"
echo "   optimiser can evaluate is not a string-obscuring scheme, and that you"
echo "   cannot know which it is without looking at the binary you shipped."
echo

if [ "$FAILED" -ne 0 ]; then
    echo "one or more targets did not build clean -- see the messages above."
    exit 1
fi

echo "done. Binaries are under $OUTDIR -- nothing was written into the repository."
