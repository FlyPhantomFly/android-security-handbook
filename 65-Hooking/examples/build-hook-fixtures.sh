#!/usr/bin/env bash
#
# build-hook-fixtures.sh -- build every C fixture in this directory for arm64,
#                           OUTSIDE the repository, and optionally push and run
#                           them on a connected device.
#
# WHAT IT DOES
#   Compiles:
#       libguard.so         the hook target (examples/libguard.c)
#       libinline.so        the target whose check function is inlined
#       trampoline-hook     hand-written inline hook with relocation
#       plt-got-hook        PLT/GOT slot swap
#       hook-that-fails     a correct hook on a function nobody calls
#
#   Everything lands in $OUT (default: a scratch directory outside this repo).
#   No .so, .o or executable is ever written into the repository -- they are on
#   the artefact blocklist. Ship sources, build binaries.
#
# HOW TO RUN
#   # build only
#   ./build-hook-fixtures.sh
#
#   # build, push to the device, and run all three demos
#   ./build-hook-fixtures.sh --run
#
#   # point at a different NDK or output directory
#   ANDROID_NDK=/path/to/ndk OUT=/tmp/hookfix ./build-hook-fixtures.sh --run
#
# REQUIREMENTS
#   - Android NDK r21 or newer. Tested with 25.2.9519653 (clang 14.0.7).
#     The script looks for aarch64-linux-android21-clang under
#     $ANDROID_NDK/toolchains/llvm/prebuilt/*/bin, and falls back to $PATH.
#   - For --run: adb, and an arm64 device or emulator. NO ROOT REQUIRED and no
#     frida-server. Everything runs as the shell user out of /data/local/tmp.
#
# THE ONE THING THAT WILL GO WRONG
#   Direct execve of a binary in /data/local/tmp is refused on many vendor
#   builds ("No such device or address", errno ENXIO, exit 126) because the
#   filesystem is mounted with restrictive flags. The workaround is to invoke
#   the dynamic linker and hand it the executable:
#
#       adb shell /system/bin/linker64 /data/local/tmp/trampoline-hook
#
#   This script always uses that form. It is not a root bypass; the linker is a
#   normal executable in a directory that permits execution, and it will happily
#   load a program for you. Documented in ../../18-ARM/README.md section 7.7.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - Whether the hooks are CORRECT on your device. It builds and runs them and
#     prints what happened. Read the output; the demos print before/after values
#     precisely so you do not have to trust an exit code.
#   - Anything about armeabi-v7a. All fixtures are arm64 only, deliberately:
#     Thumb's variable-length encoding makes fixed-size prologue patching wrong
#     in ways that do not announce themselves.
#   - Whether your device allows W^X relaxation. mprotect(PROT_WRITE|PROT_EXEC)
#     on a file-backed private mapping can be refused by SELinux policy on some
#     builds. trampoline-hook prints "mprotect RWX refused" and retries without
#     PROT_EXEC if that happens.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-${TMPDIR:-/tmp}/ch65-hook-fixtures}"
API="${API:-21}"

# ---------------------------------------------------------------- find clang
find_clang() {
    local ndk="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
    if [ -z "$ndk" ] && [ -d "$HOME/Android/Sdk/ndk" ]; then
        ndk="$(ls -d "$HOME/Android/Sdk/ndk"/* 2>/dev/null | tail -1)"
    fi
    if [ -z "$ndk" ] && [ -d "$HOME/AppData/Local/Android/Sdk/ndk" ]; then
        ndk="$(ls -d "$HOME/AppData/Local/Android/Sdk/ndk"/* 2>/dev/null | tail -1)"
    fi
    if [ -n "$ndk" ]; then
        for c in "$ndk"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android${API}-clang; do
            [ -x "$c" ] && { echo "$c"; return 0; }
        done
        # Windows hosts ship a .cmd wrapper and no extensionless file
        for c in "$ndk"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android${API}-clang.cmd; do
            [ -f "$c" ] && { echo "$c"; return 0; }
        done
    fi
    command -v "aarch64-linux-android${API}-clang" 2>/dev/null && return 0
    return 1
}

CC="$(find_clang)" || {
    echo "ERROR: could not find aarch64-linux-android${API}-clang." >&2
    echo "       Set ANDROID_NDK to your NDK root and try again." >&2
    exit 1
}

echo "compiler : $CC"
echo "output   : $OUT"
mkdir -p "$OUT" || exit 1

# ---------------------------------------------------------------- build
#
# On Git Bash / MSYS the NDK clang is a native Windows binary and does not
# understand /c/Users/... paths, so every path handed to it must go through
# `cygpath -w`. This is the same trap 30-Activities/examples/build.sh hit with
# aapt2. On Linux and macOS winpath is the identity function.
winpath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

build_lib() {
    echo "  CC  $1.so"
    "$CC" -shared -O2 -fPIC -Wall -Wextra \
          -o "$(winpath "$OUT/$1.so")" "$(winpath "$HERE/$1.c")" || exit 1
}
build_exe() {
    echo "  CC  $1"
    "$CC" -O1 -Wall -Wextra \
          -o "$(winpath "$OUT/$1")" "$(winpath "$HERE/$1.c")" -ldl || exit 1
}

echo "building:"
build_lib libguard
build_lib libinline
build_exe trampoline-hook
build_exe plt-got-hook
build_exe hook-that-fails

echo
echo "built into $OUT:"
ls -l "$OUT"

# Show the prologues the labs talk about, if a disassembler is available.
OBJDUMP="$(dirname "$CC")/llvm-objdump"
[ -x "$OBJDUMP" ] || OBJDUMP="$(dirname "$CC")/llvm-objdump.exe"
if [ -x "$OBJDUMP" ]; then
    echo
    echo "=== guard_check / guard_level prologues (what you are about to patch) ==="
    "$OBJDUMP" -d --section=.text "$OUT/libguard.so" 2>/dev/null |
        sed -n '/<guard_check>:/,/^$/p;/<guard_level>:/,/^$/p'
    echo "=== does anything CALL lic_is_valid? (empty output == inlined away) ==="
    "$OBJDUMP" -d "$OUT/libinline.so" 2>/dev/null | grep "bl.*<lic_is_valid>" || echo "  (nothing)"
fi

# ---------------------------------------------------------------- run
[ "${1:-}" = "--run" ] || { echo; echo "Done. Re-run with --run to push and execute on a device."; exit 0; }

command -v adb >/dev/null || { echo "ERROR: adb not on PATH" >&2; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "ERROR: no device" >&2; exit 1; }

echo
echo "=== device ==="
adb shell getprop ro.product.model
adb shell getprop ro.build.version.sdk

for f in libguard.so libinline.so trampoline-hook plt-got-hook hook-that-fails; do
    adb push "$OUT/$f" "/data/local/tmp/$f" >/dev/null || exit 1
done
adb shell chmod 755 /data/local/tmp/trampoline-hook /data/local/tmp/plt-got-hook \
                    /data/local/tmp/hook-that-fails

for demo in trampoline-hook plt-got-hook hook-that-fails; do
    echo
    echo "################ $demo ################"
    adb shell "/system/bin/linker64 /data/local/tmp/$demo"
done

echo
echo "Cleaning up the device."
adb shell rm -f /data/local/tmp/libguard.so /data/local/tmp/libinline.so \
                /data/local/tmp/trampoline-hook /data/local/tmp/plt-got-hook \
                /data/local/tmp/hook-that-fails
