#!/usr/bin/env bash
# build-memory-fixtures.sh -- turn the three .c files in this directory into
#                             the set of binaries every lab in chapter 19 uses.
#
# PURPOSE
#     The chapter's central claim is that the SAME source behaves differently
#     depending on which allocator and which checker the process is running
#     under. You cannot verify that by reading; you verify it by building one
#     source several ways and running the same command against each build.
#     This script produces that set.
#
#     It also does the one thing that trips people up: an HWASan binary needs
#     its runtime library, libclang_rt.hwasan-aarch64-android.so, alongside it.
#     The script copies it out of the NDK for you and the push command below
#     sends it to the device. Without it you get a linker error on the device
#     that looks nothing like a sanitiser problem.
#
# USAGE
#     # host, with the NDK installed, from inside 19-Memory/examples/
#     export ANDROID_HOME="$HOME/Android/Sdk"        # or wherever it lives
#     ./build-memory-fixtures.sh                     # writes to ./out/
#     ./build-memory-fixtures.sh /tmp/ch19-fixtures  # or a directory you name
#
#     Then push everything and run it:
#
#     # host
#     adb push out/. /data/local/tmp/ch19/
#     adb shell chmod 755 /data/local/tmp/ch19/heap-bugs \
#                         /data/local/tmp/ch19/heap-bugs-hwasan \
#                         /data/local/tmp/ch19/heap-bugs-fixed \
#                         /data/local/tmp/ch19/heap-bugs-fixed-hwasan \
#                         /data/local/tmp/ch19/mem-landmarks
#
#     # adb shell
#     /data/local/tmp/ch19/heap-bugs layout
#     LD_LIBRARY_PATH=/data/local/tmp/ch19 \
#         /data/local/tmp/ch19/heap-bugs-hwasan uaf
#
# REQUIREMENTS
#     The Android NDK, r21 or newer. It is the only C toolchain that produces
#     an Android ELF; a host gcc gives you a glibc binary no device will load.
#     Set ANDROID_HOME, NDK_HOME or NDK_BIN.
#
#     Verified with NDK r25c (clang 14.0.7) on a Windows host under Git Bash,
#     targeting API 29, arm64-v8a, and run on a stock Android 13 (API 33)
#     arm64 device over adb. Every fixture below built clean with -Wall -Wextra
#     and every one of them ran.
#
# OUTPUT, and why each one exists
#     heap-bugs                 stock build. Whatever allocator the device has
#                               -- Scudo on Android 11+ -- with no checker.
#     heap-bugs-hwasan          the same source under HWAddressSanitizer.
#                               This is the pair that proves detection works.
#     heap-bugs-asan            the same source under classic ASan, for the
#                               32-bit and non-AArch64 case where HWASan is
#                               unavailable. Much larger and much slower.
#     heap-bugs-fixed           the remediated source. Must exit 0.
#     heap-bugs-fixed-hwasan    the remediated source under HWASan. Must exit 0
#                               AND print no sanitiser report. This is the
#                               control: a sanitiser that is silent on both
#                               builds is not working.
#     mem-landmarks             address space, page size, page protections.
#     heap-bugs-arm32           armeabi-v7a. 32-bit processes get NO pointer
#                               tagging and no HWASan, which is a real and
#                               under-appreciated difference.
#     libclang_rt.hwasan-aarch64-android.so
#                               the HWASan runtime, copied from the NDK.
#
# WHAT THIS SCRIPT WILL *NOT* DO
#     - Build an APK or an app. These are command-line executables, run through
#       adb shell. An app process is forked from the Zygote and behaves
#       differently in exactly the way section 3.5 describes, which is why the
#       labs use both.
#     - Enable MTE. MTE is a property of the DEVICE and of how the process is
#       started, not of this build. See README section 3.13 and the cheatsheet:
#       you turn it on with a manifest attribute, a system property or
#       `am compat`, not with a compiler flag. NDK r25c does accept
#       `-fsanitize=memtag`, but it does NOT accept
#       `-fsanitize-memtag-mode=sync` and does NOT emit the .note.android.memtag
#       ELF note that the Android loader reads -- both need a newer NDK. The
#       script therefore does not pretend to produce an MTE fixture.
#     - Write anything into the repository. Everything lands in the output
#       directory you choose, which should not be inside the repo: compiled
#       binaries are build artefacts and this repository commits none.
#     - Sign, package or install anything.

set -euo pipefail

OUT="${1:-./out}"
API="${API_LEVEL:-29}"

# ---------------------------------------------------------------------------
# Locate the NDK. Same logic as 15-Native-Code/examples/build-fixtures.sh, on
# purpose -- if you have made one work you have made both work.
# ---------------------------------------------------------------------------
find_ndk_root() {
  if [ -n "${NDK_HOME:-}" ]; then echo "$NDK_HOME"; return; fi
  if [ -n "${ANDROID_NDK_HOME:-}" ]; then echo "$ANDROID_NDK_HOME"; return; fi
  if [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
    ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -r | head -1
    return
  fi
  return 1
}

if [ -n "${NDK_BIN:-}" ]; then
  NDK_ROOT="$(cd "$NDK_BIN/../../../.." && pwd)"
else
  NDK_ROOT="$(find_ndk_root || true)"
fi

if [ -z "${NDK_ROOT:-}" ] || [ ! -d "$NDK_ROOT" ]; then
  cat >&2 <<'ERR'
Could not find the NDK.

Set one of these and try again:
  export ANDROID_HOME="$HOME/Android/Sdk"       # with an ndk/<version> inside
  export NDK_HOME="$HOME/Android/Sdk/ndk/25.2.9519653"
  export NDK_BIN="<...>/toolchains/llvm/prebuilt/<host>/bin"

There is no substitute. Only the NDK's clang emits an Android ELF, and only
its clang ships the HWASan runtime for AArch64 Android.
ERR
  exit 2
fi

HOST=""
for h in linux-x86_64 darwin-x86_64 windows-x86_64; do
  if [ -d "$NDK_ROOT/toolchains/llvm/prebuilt/$h/bin" ]; then HOST="$h"; break; fi
done
[ -n "$HOST" ] || { echo "no prebuilt toolchain under $NDK_ROOT" >&2; exit 2; }

PREBUILT="$NDK_ROOT/toolchains/llvm/prebuilt/$HOST"
NDK_BIN="$PREBUILT/bin"

# On Windows the compiler drivers are .cmd wrappers; elsewhere they are not.
suffix=""
[ -f "$NDK_BIN/aarch64-linux-android${API}-clang.cmd" ] && suffix=".cmd"
CC64="$NDK_BIN/aarch64-linux-android${API}-clang${suffix}"
CC32="$NDK_BIN/armv7a-linux-androideabi${API}-clang${suffix}"

[ -f "$CC64" ] || { echo "missing compiler: $CC64" >&2; exit 2; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"

echo "NDK      : $NDK_ROOT"
echo "host tag : $HOST"
echo "API      : $API"
echo "output   : $OUT"
echo

say() { printf '  %-32s %s\n' "$1" "$2"; }

# ---------------------------------------------------------------------------
# 1. The stock build. No sanitiser, no extra hardening beyond the NDK's
#    defaults -- which already include full RELRO and -fstack-protector-strong,
#    a fact worth checking with 15-Native-Code's elf-harden-check.py rather
#    than taking on trust.
# ---------------------------------------------------------------------------
"$CC64" -Wall -Wextra -O1 \
  -o "$OUT/heap-bugs" "$HERE/heap-bugs.c"
say heap-bugs "stock: device allocator, no checker"

# ---------------------------------------------------------------------------
# 2. HWAddressSanitizer. Three flags matter:
#      -fsanitize=hwaddress    instrument every load and store with a tag check
#      -fno-omit-frame-pointer keep frame pointers so the reports have stacks
#      -g                      line numbers in those stacks
#    HWASan is AArch64-only. There is no 32-bit build of this fixture, and
#    that is not an oversight -- see fixture 7.
# ---------------------------------------------------------------------------
"$CC64" -Wall -Wextra -O1 -g -fno-omit-frame-pointer \
  -fsanitize=hwaddress \
  -o "$OUT/heap-bugs-hwasan" "$HERE/heap-bugs.c"
say heap-bugs-hwasan "HWASan: tag check on every access"

# ---------------------------------------------------------------------------
# 3. Classic AddressSanitizer, for comparison. ASan uses a shadow map with a
#    redzone around every allocation rather than a tag, costs roughly 2x CPU
#    and 3x memory, and works on architectures HWASan does not. Compare the
#    file sizes: this is the cost of shadow memory made visible.
# ---------------------------------------------------------------------------
"$CC64" -Wall -Wextra -O1 -g -fno-omit-frame-pointer \
  -fsanitize=address \
  -o "$OUT/heap-bugs-asan" "$HERE/heap-bugs.c"
say heap-bugs-asan "ASan: redzones and shadow memory"

# ---------------------------------------------------------------------------
# 4 and 5. The remediated source, both ways. The HWASan build of the FIXED
#    source is the control for the whole exercise: it must run to completion,
#    exit 0, and print nothing from the sanitiser.
# ---------------------------------------------------------------------------
"$CC64" -Wall -Wextra -O1 \
  -o "$OUT/heap-bugs-fixed" "$HERE/heap-bugs-fixed.c"
say heap-bugs-fixed "remediated source, stock build"

"$CC64" -Wall -Wextra -O1 -g -fno-omit-frame-pointer \
  -fsanitize=hwaddress \
  -o "$OUT/heap-bugs-fixed-hwasan" "$HERE/heap-bugs-fixed.c"
say heap-bugs-fixed-hwasan "remediated source under HWASan (control)"

# ---------------------------------------------------------------------------
# 6. Address space, page size and page protections.
# ---------------------------------------------------------------------------
"$CC64" -Wall -Wextra -O1 \
  -o "$OUT/mem-landmarks" "$HERE/mem-landmarks.c"
say mem-landmarks "address space, pages, mprotect"

# ---------------------------------------------------------------------------
# 7. The 32-bit build. Run `heap-bugs-arm32 layout` next to `heap-bugs layout`
#    on the same device and the difference jumps out: the 64-bit build prints
#    heap pointers beginning 0xb4, the 32-bit build does not, because pointer
#    tagging needs a spare top byte and a 32-bit pointer has none. Neither MTE
#    nor HWASan is available to a 32-bit process either. If a target ships a
#    32-bit ABI, its native code is running with materially fewer memory-safety
#    features, and that belongs in your report.
# ---------------------------------------------------------------------------
if [ -f "$CC32" ]; then
  "$CC32" -Wall -Wextra -O1 \
    -o "$OUT/heap-bugs-arm32" "$HERE/heap-bugs.c"
  say heap-bugs-arm32 "armeabi-v7a: no tagging, no HWASan"
else
  echo "  (skipping arm32: $CC32 not found)"
fi

# ---------------------------------------------------------------------------
# 8. The HWASan runtime. The instrumented binaries have it as a DT_NEEDED
#    entry; without it on the device you get
#      "library libclang_rt.hwasan-aarch64-android.so not found"
#    which reads like a packaging problem and is really just a missing push.
# ---------------------------------------------------------------------------
RT=""
for cand in "$PREBUILT"/lib64/clang/*/lib/linux/libclang_rt.hwasan-aarch64-android.so \
            "$PREBUILT"/lib/clang/*/lib/linux/libclang_rt.hwasan-aarch64-android.so; do
  [ -f "$cand" ] && RT="$cand"
done
if [ -n "$RT" ]; then
  cp "$RT" "$OUT/"
  say libclang_rt.hwasan-aarch64-android.so "HWASan runtime, from the NDK"
else
  echo "  WARNING: HWASan runtime not found under $PREBUILT" >&2
  echo "           the -hwasan binaries will not start on the device" >&2
fi

# Same for ASan, which needs its own runtime.
RTA=""
for cand in "$PREBUILT"/lib64/clang/*/lib/linux/libclang_rt.asan-aarch64-android.so \
            "$PREBUILT"/lib/clang/*/lib/linux/libclang_rt.asan-aarch64-android.so; do
  [ -f "$cand" ] && RTA="$cand"
done
if [ -n "$RTA" ]; then
  cp "$RTA" "$OUT/"
  say libclang_rt.asan-aarch64-android.so "ASan runtime, from the NDK"
fi

cat <<'NEXT'

Done. The comparisons worth running first, in this order:

  # adb shell, after pushing
  cd /data/local/tmp/ch19

  # 1. what the allocator does when nothing is watching
  ./heap-bugs layout

  # 2. the same source, same command, with tag checking on.
  #    The read of freed memory at the end of `layout` now aborts.
  LD_LIBRARY_PATH=. ./heap-bugs-hwasan layout

  # 3. a use-after-free that the stock build does not notice at all
  ./heap-bugs uaf
  LD_LIBRARY_PATH=. ./heap-bugs-hwasan uaf

  # 4. two bugs the stock allocator DOES catch, and what it says
  ./heap-bugs dfree
  ./heap-bugs invfree

  # 5. the control: the fixed source must be silent under HWASan
  LD_LIBRARY_PATH=. ./heap-bugs-fixed-hwasan selftest ; echo "exit=$?"

  # 6. page protections, enforced by hardware rather than by a check
  ./mem-landmarks wx
  ./mem-landmarks guard

If step 5 prints a sanitiser report, the fix is wrong and you have found a bug
in this repository -- please read heap-bugs-fixed.c and say which case failed.
If step 2 prints NOTHING different from step 1, your HWASan build is not
actually instrumented; check that the runtime library was pushed.
NEXT
