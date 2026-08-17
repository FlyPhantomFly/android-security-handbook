#!/usr/bin/env bash
#
# build-ctf.sh -- build the lab-04 CTF target and harness for arm64, outside
#                 the repository, and optionally push them to a device.
#
# WHAT IT DOES
#   Compiles libvault.c into libvault.so and vault-runner.c into vault-runner,
#   into $OUT (default: a scratch directory outside this repo). Binaries are on
#   this repository's artefact blocklist and must never be committed.
#
#   With --run it also pushes both to /data/local/tmp and executes the runner
#   once with a deliberately wrong pin, so you can see the baseline before you
#   start attacking it.
#
# HOW TO RUN
#   ./build-ctf.sh
#   ./build-ctf.sh --run
#   ANDROID_NDK=/path/to/ndk OUT=/tmp/ch65ctf ./build-ctf.sh --run
#
#   Your own solver goes in the same directory and links against nothing:
#     $CC -O1 -o solver solver.c -ldl
#     adb push solver /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/solver
#     adb shell /system/bin/linker64 /data/local/tmp/solver
#
# REQUIREMENTS
#   Android NDK (tested 25.2.9519653 / clang 14.0.7), adb, an arm64 device.
#   No root, no frida-server.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - The solution. It builds the challenge and gets out of the way.
#   - Whether your solver is "correct". Getting the flag by patching the
#     baseline checksum in writable memory also works and teaches something
#     real; the lab's grading rubric distinguishes solutions by what they
#     prove, not by whether the flag appeared.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-${TMPDIR:-/tmp}/ch65-ctf}"
API="${API:-21}"

find_clang() {
    local ndk="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
    if [ -z "$ndk" ] && [ -d "$HOME/Android/Sdk/ndk" ]; then
        ndk="$(ls -d "$HOME/Android/Sdk/ndk"/* 2>/dev/null | tail -1)"
    fi
    if [ -z "$ndk" ] && [ -d "$HOME/AppData/Local/Android/Sdk/ndk" ]; then
        ndk="$(ls -d "$HOME/AppData/Local/Android/Sdk/ndk"/* 2>/dev/null | tail -1)"
    fi
    if [ -n "$ndk" ]; then
        for c in "$ndk"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android${API}-clang \
                 "$ndk"/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android${API}-clang.cmd; do
            [ -f "$c" ] && { echo "$c"; return 0; }
        done
    fi
    command -v "aarch64-linux-android${API}-clang" 2>/dev/null && return 0
    return 1
}

CC="$(find_clang)" || {
    echo "ERROR: no aarch64-linux-android${API}-clang. Set ANDROID_NDK." >&2
    exit 1
}

# Git Bash / MSYS: the NDK clang is a native Windows binary and needs Windows
# paths. cygpath is absent on Linux and macOS, where this is the identity.
winpath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

echo "compiler : $CC"
echo "output   : $OUT"
mkdir -p "$OUT" || exit 1

echo "  CC  libvault.so"
"$CC" -shared -O2 -fPIC -Wall -Wextra \
      -o "$(winpath "$OUT/libvault.so")" "$(winpath "$HERE/libvault.c")" || exit 1

echo "  CC  vault-runner"
"$CC" -O1 -Wall -Wextra \
      -o "$(winpath "$OUT/vault-runner")" "$(winpath "$HERE/vault-runner.c")" -ldl || exit 1

echo
ls -l "$OUT"

echo
echo "=== the pin is not in the file (this SHOULD find nothing useful) ==="
strings "$OUT/libvault.so" 2>/dev/null | grep -Ei 'pin|flag|CH65|[0-9]{4}-' || echo "  (nothing)"

[ "${1:-}" = "--run" ] || { echo; echo "Done. Re-run with --run to push and try it."; exit 0; }

command -v adb >/dev/null || { echo "ERROR: adb not on PATH" >&2; exit 1; }
adb get-state >/dev/null 2>&1 || { echo "ERROR: no device" >&2; exit 1; }

adb push "$OUT/libvault.so"  /data/local/tmp/libvault.so  >/dev/null || exit 1
adb push "$OUT/vault-runner" /data/local/tmp/vault-runner >/dev/null || exit 1
adb shell chmod 755 /data/local/tmp/vault-runner

echo
echo "=== baseline: a wrong pin ==="
adb shell "/system/bin/linker64 /data/local/tmp/vault-runner 0000"
echo
echo "The challenge is loaded on the device. Write your solver and go."
echo "Clean up when finished:"
echo "  adb shell rm -f /data/local/tmp/libvault.so /data/local/tmp/vault-runner"
