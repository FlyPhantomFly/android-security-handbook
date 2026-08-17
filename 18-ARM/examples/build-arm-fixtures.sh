#!/usr/bin/env bash
# build-arm-fixtures.sh -- turn the three .c files in this directory into every
#                          binary chapter 18 disassembles, patches or runs.
#
# PURPOSE
#     Every instruction listing printed in chapter 18 came out of llvm-objdump
#     run against a file this script produced. Nothing was written from memory.
#     Run this and you can reproduce each listing, byte for byte, on the same
#     NDK -- and see for yourself where a different NDK diverges.
#
#     The same source is built several ways on purpose, because the single most
#     common beginner mistake with disassembly is to believe that the code you
#     see is a property of the source. It is not. It is a property of the
#     source, the target, the optimisation level and the compiler version, and
#     comparing these outputs is the fastest way to internalise that.
#
# USAGE
#     # host, Git Bash / WSL / Linux / macOS
#     export ANDROID_HOME="$HOME/Android/Sdk"     # or wherever the SDK lives
#     ./build-arm-fixtures.sh                     # writes to ./out
#     ./build-arm-fixtures.sh /tmp/ch18           # or a directory you name
#
#     Then:
#     python3 ../scripts/arm64-patch.py out/liblicence.so --list-symbols
#     python3 ../scripts/arm64-patch.py out/liblicence.so \
#             --symbol lc_is_licensed --show
#     python3 ../scripts/find-check-shapes.py out/liblicence.so
#
# REQUIREMENTS
#     The Android NDK, r21 or newer. Set ANDROID_HOME, NDK_HOME or NDK_BIN.
#     Nothing else -- no Gradle, no CMake, no Android Studio, no device to
#     BUILD. A device or emulator is needed only to RUN licence-runner, and
#     lab-03 explains that half.
#
#     Verified with NDK 25.2.9519653 (clang 14.0.7, LLVM 14.0.7git) on a
#     Windows host under Git Bash, targeting API 21. Every address printed in
#     the chapter comes from that combination. A different NDK will give you
#     the same SHAPES at different addresses, and occasionally a different
#     instruction selection; the chapter says so wherever it matters.
#
# OUTPUT, and why each one exists
#     libpatterns64.so          arm64, -O2, canary on. The pattern catalogue.
#     libpatterns64-O0.so       arm64, -O0. Textbook prologues, no cleverness.
#     libpatterns64-nocanary.so arm64, -O2, -fno-stack-protector. The A/B for
#                               "what does the canary actually add".
#     libpatterns32-arm.so      armeabi-v7a in ARM state (-marm). 4-byte
#                               instructions, even symbol addresses.
#     libpatterns32-thumb.so    armeabi-v7a in Thumb state (-mthumb). 2- and
#                               4-byte instructions, and st_value with the LOW
#                               BIT SET. This pair is the whole Thumb lesson.
#     liblicence.so             arm64. The patch target for labs 02 and 03.
#     licence-runner            arm64 Android executable that dlopen()s the
#                               above, so a patch can be PROVEN, not asserted.
#
# WHAT THIS SCRIPT WILL *NOT* DO
#     - Write anything into the repository. Everything lands in the output
#       directory you choose, which must not be inside the repo: compiled
#       binaries are build artefacts and this repository commits none.
#     - Produce an APK or an installable app. 10-APK-Internals covers that;
#       nothing in this chapter needs one.
#     - Run anything. It cannot: the outputs are ARM binaries and your build
#       host almost certainly is not ARM. Pushing and running is lab-03.
#     - Guarantee byte-identical output to the chapter on a different NDK.
#       It prints the version it used so you can tell.

set -euo pipefail

OUT="${1:-./out}"
API="${API_LEVEL:-21}"

find_ndk_bin() {
  if [ -n "${NDK_BIN:-}" ]; then echo "$NDK_BIN"; return; fi
  local roots=()
  [ -n "${NDK_HOME:-}" ] && roots+=("$NDK_HOME")
  [ -n "${ANDROID_NDK_HOME:-}" ] && roots+=("$ANDROID_NDK_HOME")
  if [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    while IFS= read -r d; do roots+=("$d"); done < <(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -r)
  fi
  if [ -d "$HOME/AppData/Local/Android/Sdk/ndk" ]; then
    while IFS= read -r d; do roots+=("$d"); done \
      < <(ls -d "$HOME"/AppData/Local/Android/Sdk/ndk/* 2>/dev/null | sort -r)
  fi
  local r host
  for r in "${roots[@]:-}"; do
    for host in linux-x86_64 darwin-x86_64 windows-x86_64; do
      if [ -d "$r/toolchains/llvm/prebuilt/$host/bin" ]; then
        echo "$r/toolchains/llvm/prebuilt/$host/bin"; return
      fi
    done
  done
  return 1
}

NDK_BIN="$(find_ndk_bin || true)"
if [ -z "$NDK_BIN" ]; then
  cat >&2 <<'ERR'
Could not find the NDK.

Set one of these and try again:
  export ANDROID_HOME="$HOME/Android/Sdk"       # with an ndk/<version> inside
  export NDK_HOME="$HOME/Android/Sdk/ndk/25.2.9519653"
  export NDK_BIN="<...>/toolchains/llvm/prebuilt/<host>/bin"

There is no substitute. A host gcc or clang will happily compile these files
for x86-64, and then every listing in chapter 18 will disagree with yours for
a reason that has nothing to do with the chapter.
ERR
  exit 2
fi

# On Windows the compiler drivers are .cmd wrappers; elsewhere they are not.
suffix=""
[ -f "$NDK_BIN/aarch64-linux-android${API}-clang.cmd" ] && suffix=".cmd"
CC64="$NDK_BIN/aarch64-linux-android${API}-clang${suffix}"
CC32="$NDK_BIN/armv7a-linux-androideabi${API}-clang${suffix}"
OBJDUMP="$NDK_BIN/llvm-objdump"
READELF="$NDK_BIN/llvm-readelf"
[ -f "$OBJDUMP.exe" ] && OBJDUMP="$OBJDUMP.exe"
[ -f "$READELF.exe" ] && READELF="$READELF.exe"

for t in "$CC64" "$CC32"; do
  [ -x "$t" ] || [ -f "$t" ] || { echo "missing: $t" >&2; exit 2; }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"

echo "NDK bin : $NDK_BIN"
echo "output  : $OUT"
echo "clang   : $("$CC64" --version 2>/dev/null | head -1)"
echo "objdump : $("$OBJDUMP" --version 2>/dev/null | sed -n 2p | tr -d '\r')"
echo

say() { printf '  %-28s %s\n' "$1" "$2"; }

# ---------------------------------------------------------------------------
# 1. The pattern catalogue, three ways.
# ---------------------------------------------------------------------------
"$CC64" -shared -fPIC -O2 -fstack-protector-strong -Wall -Wextra \
  -Wl,-z,max-page-size=16384 \
  -o "$OUT/libpatterns64.so" "$HERE/patterns.c"
say libpatterns64.so "arm64, -O2, canary on"

"$CC64" -shared -fPIC -O0 -fstack-protector-strong \
  -Wl,-z,max-page-size=16384 \
  -o "$OUT/libpatterns64-O0.so" "$HERE/patterns.c"
say libpatterns64-O0.so "arm64, -O0, textbook prologues"

"$CC64" -shared -fPIC -O2 -fno-stack-protector \
  -Wl,-z,max-page-size=16384 \
  -o "$OUT/libpatterns64-nocanary.so" "$HERE/patterns.c"
say libpatterns64-nocanary.so "arm64, -O2, canary OFF"

# ---------------------------------------------------------------------------
# 2. The 32-bit pair. -marm and -mthumb differ in more than instruction width:
#    compare the two files' symbol tables and look at the low bit of st_value.
# ---------------------------------------------------------------------------
"$CC32" -shared -fPIC -O2 -marm -fstack-protector-strong -Wall -Wextra \
  -o "$OUT/libpatterns32-arm.so" "$HERE/patterns.c"
say libpatterns32-arm.so "armeabi-v7a, ARM state"

"$CC32" -shared -fPIC -O2 -mthumb -fstack-protector-strong -Wall -Wextra \
  -o "$OUT/libpatterns32-thumb.so" "$HERE/patterns.c"
say libpatterns32-thumb.so "armeabi-v7a, Thumb state"

# ---------------------------------------------------------------------------
# 3. The patch target and its runner.
#    -fvisibility=hidden is deliberate: it is what a competent release build
#    uses, and it means only the LC_EXPORT functions reach .dynsym.
# ---------------------------------------------------------------------------
"$CC64" -shared -fPIC -O2 -fvisibility=hidden -fstack-protector-strong \
  -Wall -Wextra -Wl,-z,max-page-size=16384 \
  -o "$OUT/liblicence.so" "$HERE/licence-check.c"
say liblicence.so "arm64 patch target"

"$CC64" -O2 -fPIE -pie -Wall -Wextra \
  -o "$OUT/licence-runner" "$HERE/licence-runner.c" -ldl
say licence-runner "arm64 Android executable"

# ---------------------------------------------------------------------------
# 4. The one comparison worth printing here, because it is the whole reason
#    the -marm/-mthumb pair exists.
# ---------------------------------------------------------------------------
echo
echo "Thumb vs ARM -- st_value for the same three functions:"
printf '  %-24s %-12s %s\n' "symbol" "ARM state" "Thumb state"
for sym in pat_leaf_add pat_cbz pat_boolean_check; do
  a=$("$READELF" --dyn-syms "$OUT/libpatterns32-arm.so"   2>/dev/null \
      | awk -v s="$sym" '$8==s {print $2}' | head -1)
  t=$("$READELF" --dyn-syms "$OUT/libpatterns32-thumb.so" 2>/dev/null \
      | awk -v s="$sym" '$8==s {print $2}' | head -1)
  printf '  %-24s 0x%-10s 0x%s\n' "$sym" "${a:-?}" "${t:-?}"
done
echo "  The Thumb column is ODD. That low bit is not an address --"
echo "  it is the instruction-set state to enter. README section 3.13."

cat <<NEXT

Done. Start here:

  # what is in the patch target, and where
  python3 ../scripts/arm64-patch.py $OUT/liblicence.so --list-symbols
  python3 ../scripts/arm64-patch.py $OUT/liblicence.so --symbol lc_is_licensed --show

  # the pattern catalogue, as the chapter prints it
  $OBJDUMP -d --no-show-raw-insn $OUT/libpatterns64.so | less

  # the same function with and without the canary
  $OBJDUMP -d --no-show-raw-insn $OUT/libpatterns64.so          | sed -n '/pat_stack_canary/,/^$/p'
  $OBJDUMP -d --no-show-raw-insn $OUT/libpatterns64-nocanary.so | sed -n '/pat_stack_canary/,/^$/p'

  # -O2 versus -O0 on the same source
  $OBJDUMP -d --no-show-raw-insn $OUT/libpatterns64-O0.so | sed -n '/pat_nonleaf/,/^$/p'
NEXT
