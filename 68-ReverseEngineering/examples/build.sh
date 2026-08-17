#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build chapter 68's reverse-engineering fixture from the two C sources in
#   this directory, using only the Android NDK:
#
#       libinvestigate.so    the target library -- four deliberate traps
#       investigate          an arm64 CLI runner that links against it
#
#   The point of building it yourself is that it makes the labs *gradeable*.
#   Every claim you form about this binary can be checked against the source
#   sitting next to it, which is the only setting in which you can honestly
#   measure your own reverse engineering. On a real target you never get the
#   answer key; here you do, and you should not look at it until lab 02 tells
#   you to.
#
#   The repository ships SOURCES, never built binaries. `.so` and `.o` are on
#   the artefact blocklist, so this script builds OUT OF TREE: everything it
#   produces lands under $OUTDIR and nothing is written next to the sources.
#
# USAGE
#   # host -- build both, default OUTDIR
#   ./build.sh
#
#   # host -- choose where artefacts go
#   OUTDIR=/tmp/ch68 ./build.sh
#
#   # host -- build, push to the device and run it once
#   ./build.sh --push
#
#   # host -- build at -O0 as well, so you can compare inlining decisions
#   ./build.sh --both-opt
#
#   # host -- remove the pushed files from the device
#   ./build.sh --clean-device
#
# REQUIREMENTS
#   * ANDROID_NDK, ANDROID_NDK_HOME, or ANDROID_HOME/ndk/<version> pointing at
#     an NDK r21 or newer. This chapter was written against r25.2.9519653.
#   * `adb` on PATH for --push / --clean-device.
#
# A NOTE ON RUNNING IT ON THE DEVICE
#   The vendor build on the Redmi M2101K6P this chapter was measured on blocks
#   execve() under /data/local/tmp -- the push succeeds, chmod +x succeeds, and
#   the run is refused. The workaround, used by --push below, is to invoke the
#   dynamic linker explicitly, which LOADS the executable instead of exec'ing it:
#
#       adb shell /system/bin/linker64 /data/local/tmp/ch68/investigate measure
#
#   If your device does not have that restriction, chmod +x and run it directly.
#   Check which case you are in before concluding the binary is broken -- a
#   "Permission denied" from the shell and a broken binary look identical from
#   the outside, and telling them apart is the whole habit this chapter teaches.

set -u

OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch68-build}"
DEVDIR="/data/local/tmp/ch68"
HERE="$(cd "$(dirname "$0")" && pwd)"
PUSH=0
BOTH_OPT=0
CLEAN_DEVICE=0

for arg in "$@"; do
  case "$arg" in
    --push)         PUSH=1 ;;
    --both-opt)     BOTH_OPT=1 ;;
    --clean-device) CLEAN_DEVICE=1 ;;
    -h|--help)      sed -n '2,52p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- locate NDK
find_ndk() {
  if [ -n "${ANDROID_NDK:-}" ] && [ -d "$ANDROID_NDK" ]; then
    echo "$ANDROID_NDK"; return 0
  fi
  if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    echo "$ANDROID_NDK_HOME"; return 0
  fi
  local sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/AppData/Local/Android/Sdk}}"
  if [ -d "$sdk/ndk" ]; then
    # newest NDK present
    ls -1 "$sdk/ndk" 2>/dev/null | sort -V | tail -1 | while read -r v; do
      echo "$sdk/ndk/$v"
    done
    return 0
  fi
  return 1
}

NDK="$(find_ndk || true)"
if [ -z "${NDK:-}" ] || [ ! -d "$NDK" ]; then
  echo "ERROR: no NDK found. Set ANDROID_NDK to your NDK root." >&2
  exit 1
fi

# The prebuilt host triple differs per platform; take whichever exists.
BIN=""
for host in windows-x86_64 linux-x86_64 darwin-x86_64; do
  if [ -d "$NDK/toolchains/llvm/prebuilt/$host/bin" ]; then
    BIN="$NDK/toolchains/llvm/prebuilt/$host/bin"; break
  fi
done
if [ -z "$BIN" ]; then
  echo "ERROR: no llvm prebuilt toolchain under $NDK/toolchains/llvm/prebuilt/" >&2
  exit 1
fi

CC="$BIN/aarch64-linux-android21-clang"
[ -x "$CC" ] || CC="$CC.cmd"          # Windows wrapper
OBJDUMP="$BIN/llvm-objdump"
NM="$BIN/llvm-nm"
READELF="$BIN/llvm-readelf"

echo "NDK      : $NDK"
echo "compiler : $CC"
echo "outdir   : $OUTDIR"

if [ "$CLEAN_DEVICE" = "1" ]; then
  echo "removing $DEVDIR from the device"
  adb shell "rm -rf $DEVDIR" || true
  exit 0
fi

mkdir -p "$OUTDIR"

# ------------------------------------------------------------------- build
build_at() {
  local opt="$1" suffix="$2"
  echo
  echo "=== building at $opt ==="
  "$CC" -Wall -Wextra "$opt" -fPIC -shared \
        -o "$OUTDIR/libinvestigate$suffix.so" "$HERE/libinvestigate.c" || return 1
  "$CC" -Wall -Wextra "$opt" \
        -o "$OUTDIR/investigate$suffix" "$HERE/investigate-main.c" \
        -L"$OUTDIR" -linvestigate$suffix || return 1
  echo "built: $OUTDIR/libinvestigate$suffix.so"
  echo "built: $OUTDIR/investigate$suffix"
}

build_at -O2 "" || { echo "BUILD FAILED" >&2; exit 1; }
if [ "$BOTH_OPT" = "1" ]; then
  build_at -O0 "-O0" || { echo "BUILD FAILED at -O0" >&2; exit 1; }
fi

# ------------------------------------------------- report the traps, measured
echo
echo "=== what the build actually produced ==="
echo "-- exported symbols (the map a symbol-based tool gets)"
"$NM" -D --defined-only "$OUTDIR/libinvestigate.so" | grep ' T ' || true

echo
echo "-- call sites targeting iv_check_license (TRAP 1)"
# NOTE THE (@plt)? -- this is not decoration, it was measured. llvm-objdump
# renders a call through the PLT as `bl 0x1ac0 <iv_derive_seed@plt>`, so the
# obvious pattern `bl.*<name>` reports ZERO for a function that is definitely
# called. Built at -O0, iv_derive_seed scores exact=0 / with-plt=1. Chapter 68
# section 8.3 records this as a false negative in its own showcase experiment.
n=$("$OBJDUMP" -d "$OUTDIR/libinvestigate.so" | grep -cE 'bl.*<iv_check_license(@plt)?>' || true)
echo "   $n  (if this is 0, nothing in the library calls it)"
echo "   cross-check -- every bl target in the library:"
"$OBJDUMP" -d "$OUTDIR/libinvestigate.so" | grep -oE 'bl[[:space:]]+0x[0-9a-f]+ <[^>]+>' \
  | sort | uniq -c | sed 's/^/     /' || true

echo
echo "-- is gate_is_open a symbol at all? (TRAP 2)"
if "$NM" "$OUTDIR/libinvestigate.so" 2>/dev/null | grep -q 'gate_is_open'; then
  echo "   present -- your compiler did not inline it; the lab still works,"
  echo "   but read the note in lab 02 about compiler-dependent findings."
else
  echo "   absent -- inlined into iv_open_vault, as the source predicted"
fi

echo
echo "-- flag-shaped strings in the file (TRAP 4)"
strings -a "$OUTDIR/libinvestigate.so" 2>/dev/null | grep -E 'CH68\{' || \
  echo "   (none found by this grep)"

echo
echo "-- .rodata size, for the record"
"$READELF" -S "$OUTDIR/libinvestigate.so" 2>/dev/null | grep -E '\.rodata' || true

# -------------------------------------------------------------------- push
if [ "$PUSH" = "1" ]; then
  echo
  echo "=== pushing to $DEVDIR ==="
  # MSYS_NO_PATHCONV=1 is not optional on Git Bash for Windows. Without it the
  # MSYS layer "helpfully" rewrites the device-side argument /data/local/tmp/ch68
  # into C:/Program Files/Git/data/local/tmp/ch68 before adb ever sees it, and
  # the failure reads `remote secure_mkdirs failed: No such file or directory`
  # -- which looks like a device permission problem and is not one. This cost
  # real time while writing the chapter; it is exactly the class of symptom
  # section 3.11 calls "the error message names the wrong layer".
  export MSYS_NO_PATHCONV=1
  adb shell "mkdir -p $DEVDIR"
  adb push "$OUTDIR/libinvestigate.so" "$DEVDIR/" >/dev/null
  adb push "$OUTDIR/investigate"       "$DEVDIR/" >/dev/null
  adb shell "chmod 755 $DEVDIR/investigate" || true
  echo "running it once, through the linker:"
  adb shell "LD_LIBRARY_PATH=$DEVDIR /system/bin/linker64 $DEVDIR/investigate measure" \
    || echo "(non-zero exit -- that is a result, not necessarily a failure)"
fi

echo
echo "done. Artefacts are in $OUTDIR and nothing was written into the repository."
