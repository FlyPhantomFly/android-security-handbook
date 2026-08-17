#!/usr/bin/env bash
#
# build.sh -- build every chapter-59 target, OUT OF TREE.
#
# PURPOSE
#   Compiles the C sources in this directory into the binaries the labs use. This
#   repository ships sources and never built binaries, so this script deliberately writes
#   nothing into the repository: everything lands in $HOME/ch59-build (or the directory you
#   pass as the first argument).
#
# USAGE
#   ./build.sh                  # -> $HOME/ch59-build
#   ./build.sh /tmp/ch59        # -> /tmp/ch59
#   NDK=/path/to/ndk ./build.sh # override NDK auto-detection
#
# REQUIREMENTS
#   Android NDK r21 or newer, providing aarch64-linux-android21-clang and the LLVM
#   binutils (llvm-readelf, llvm-nm, llvm-objdump, llvm-strings). Developed and measured
#   against NDK 25.2.9519653.
#
# OUTPUTS (in the build directory)
#   libr2target.so       -O2 shared library  -- the main lab target
#   libr2target-O0.so    -O0 shared library  -- for the string-folding comparison (lab 02)
#   libr2hardened.so     -O2 shared library  -- the volatile-key fix
#   r2gate               -O2 AArch64 PIE     -- the patching target (lab 03)
#   ctfvault             -O2 AArch64 PIE     -- the lab 04 CTF challenge
#   build-report.txt     a summary of what was built and the key measurements
#
# NOTE ON 16 KiB PAGES
#   r2gate and ctfvault are linked with -Wl,-z,max-page-size=16384. Without it, binaries built by NDK
#   r25c SEGFAULT at load on 16 KiB-page Android images (including current AVDs) with no
#   error message that points at page size. Verified independently by chapters 39 and 70.
#
set -euo pipefail

OUT="${1:-$HOME/ch59-build}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------------------
# Locate the NDK toolchain
# ---------------------------------------------------------------------------------------
find_ndk_bin() {
    if [ -n "${NDK:-}" ]; then
        for host in linux-x86_64 darwin-x86_64 windows-x86_64; do
            if [ -d "$NDK/toolchains/llvm/prebuilt/$host/bin" ]; then
                echo "$NDK/toolchains/llvm/prebuilt/$host/bin"; return 0
            fi
        done
        echo "NDK is set to '$NDK' but no toolchains/llvm/prebuilt/*/bin found there" >&2
        return 1
    fi
    for root in \
        "$HOME/Android/Sdk/ndk" \
        "$HOME/Library/Android/sdk/ndk" \
        "$LOCALAPPDATA/Android/Sdk/ndk" \
        "/c/Users/$USER/AppData/Local/Android/Sdk/ndk" \
        "$ANDROID_SDK_ROOT/ndk" \
        "$ANDROID_HOME/ndk"
    do
        [ -d "$root" ] || continue
        for ver in $(ls -1 "$root" 2>/dev/null | sort -rV); do
            for host in linux-x86_64 darwin-x86_64 windows-x86_64; do
                if [ -d "$root/$ver/toolchains/llvm/prebuilt/$host/bin" ]; then
                    echo "$root/$ver/toolchains/llvm/prebuilt/$host/bin"; return 0
                fi
            done
        done
    done
    return 1
}

if ! NDK_BIN="$(find_ndk_bin)"; then
    cat >&2 <<'EOF'
ERROR: could not find an Android NDK.

Install one (Android Studio -> SDK Manager -> SDK Tools -> NDK), or point this script at
an existing install:

    NDK=/path/to/android-ndk-r25c ./build.sh

This script will not fall back to the host compiler: the whole point of these targets is
that they are AArch64 Android binaries.
EOF
    exit 1
fi

CC="$NDK_BIN/aarch64-linux-android21-clang"
READELF="$NDK_BIN/llvm-readelf"
NM="$NDK_BIN/llvm-nm"
OBJDUMP="$NDK_BIN/llvm-objdump"
STRINGS="$NDK_BIN/llvm-strings"

for t in "$CC" "$READELF" "$NM" "$OBJDUMP" "$STRINGS"; do
    if [ ! -x "$t" ] && [ ! -x "$t.exe" ] && [ ! -f "$t" ]; then
        echo "ERROR: missing required tool: $t" >&2
        exit 1
    fi
done

mkdir -p "$OUT"
echo "NDK toolchain : $NDK_BIN"
echo "Output        : $OUT"
echo

WARN="-Wall -Wextra"

# ---------------------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------------------
echo "[1/5] libr2target.so      (-O2 shared)"
"$CC" $WARN -O2 -fPIC -shared -o "$OUT/libr2target.so"    "$SRC/01-r2-target.c"

echo "[2/5] libr2target-O0.so   (-O0 shared, for the string comparison)"
"$CC" $WARN -O0 -fPIC -shared -o "$OUT/libr2target-O0.so" "$SRC/01-r2-target.c"

echo "[3/5] libr2hardened.so    (-O2 shared, volatile key)"
"$CC" $WARN -O2 -fPIC -shared -o "$OUT/libr2hardened.so"  "$SRC/02-r2-target-hardened.c"

echo "[4/5] r2gate              (-O2 AArch64 PIE, 16 KiB page safe)"
"$CC" $WARN -O2 -pie -Wl,-z,max-page-size=16384 \
      -o "$OUT/r2gate" "$SRC/01-r2-target.c"

echo "[5/5] ctfvault            (-O2 AArch64 PIE, the lab 04 challenge)"
"$CC" $WARN -O2 -pie -Wl,-z,max-page-size=16384 \
      -o "$OUT/ctfvault" "$SRC/03-ctf-vault.c"

echo
echo "Build complete. Zero warnings expected above; if you saw any, report them."
echo

# ---------------------------------------------------------------------------------------
# Report: reproduce the chapter's key measurements so the reader sees them immediately
# ---------------------------------------------------------------------------------------
REPORT="$OUT/build-report.txt"
{
    echo "chapter 59 build report"
    echo "generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "toolchain: $NDK_BIN"
    echo
    echo "=== sizes ==="
    ls -l "$OUT"/libr2target.so "$OUT"/libr2target-O0.so \
          "$OUT"/libr2hardened.so "$OUT"/r2gate "$OUT"/ctfvault 2>/dev/null || true
    echo
    echo "=== MEASUREMENT 1: does the XOR-ed path survive optimisation? ==="
    echo "-- libr2target.so (-O2), expect the plaintext to LEAK:"
    "$STRINGS" -n 4 "$OUT/libr2target.so"    | grep -i 'xbin' || echo "   (not found)"
    echo "-- libr2target-O0.so (-O0), expect NOTHING:"
    "$STRINGS" -n 4 "$OUT/libr2target-O0.so" | grep -i 'xbin' || echo "   (not found)"
    echo "-- libr2hardened.so (-O2, volatile key), expect NOTHING:"
    "$STRINGS" -n 4 "$OUT/libr2hardened.so"  | grep -i 'xbin' || echo "   (not found)"
    echo
    echo "=== MEASUREMENT 2: exported symbols of the main target ==="
    echo "(note that dyn_gate is ABSENT -- it is registered at runtime)"
    "$NM" -D --defined-only "$OUT/libr2target.so" || true
    echo
    echo "=== MEASUREMENT 3: .text virtual address vs file offset (the patching trap) ==="
    "$READELF" -S "$OUT/r2gate" | sed 's/^ *\[ *[0-9]*\] *//' | grep -E '^\.text ' || true
    echo "(subtract: file offset = vaddr - (sh_addr - sh_offset))"
    echo
    echo "=== MEASUREMENT 4: the gate's control flow -- read this before patching ==="
    "$OBJDUMP" -d "$OUT/r2gate" --disassemble-symbols=lt_gate 2>/dev/null || true
    echo
    echo "=== symbol addresses for the patching labs ==="
    "$NM" "$OUT/r2gate" 2>/dev/null | grep -E ' T lt_' || true
    echo
    echo "=== lab 04 challenge: ctfvault symbols (no further hints here) ==="
    "$NM" "$OUT/ctfvault" 2>/dev/null | grep -E ' T vault_' || true
} > "$REPORT" 2>&1

cat "$REPORT"
echo
echo "Report written to: $REPORT"
echo
cat <<EOF
Next steps
  Lab 01  labs/lab-01-the-command-language.md      -- learn the grammar on libr2target.so
  Lab 02  labs/lab-02-triage-a-real-library.md     -- triage, and reproduce MEASUREMENT 1
  Lab 03  labs/lab-03-patching-and-the-wrong-function.md -- patch r2gate, discover it fails
  Lab 04  labs/lab-04-ctf-the-gate-that-was-not-there.md -- the CTF

To run r2gate on a device:
  adb push $OUT/r2gate /data/local/tmp/ch59_r2gate
  adb shell chmod 755 /data/local/tmp/ch59_r2gate
  adb shell /data/local/tmp/ch59_r2gate somekey
Clean up afterwards:
  adb shell rm -f '/data/local/tmp/ch59_*'
EOF
