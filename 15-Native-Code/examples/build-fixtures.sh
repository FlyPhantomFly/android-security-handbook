#!/usr/bin/env bash
# build-fixtures.sh -- turn the two .c files in this directory into the set of
#                      ELF files every lab in chapter 15 uses.
#
# PURPOSE
#     One source file compiled several ways is the cleanest possible
#     demonstration that hardening is a build flag, not a property of code.
#     This script produces that set, plus a small APK containing two of the
#     libraries, so the --apk mode of the checker has something to read.
#
# USAGE
#     # host, with the NDK installed
#     export ANDROID_HOME="$HOME/Android/Sdk"          # or wherever it lives
#     ./build-fixtures.sh                              # writes to ./out/
#     ./build-fixtures.sh /tmp/ch15-fixtures           # or a directory you name
#
#     Then:
#     python3 ../scripts/elf-harden-check.py out/*.so
#     python3 ../scripts/elf-inspect.py out/libdemo-hard.so --all
#     python3 ../scripts/elf-harden-check.py --apk out/fixture.apk
#
# REQUIREMENTS
#     The Android NDK, r21 or newer -- that is the only C toolchain that can
#     produce an Android ELF, and it is a download rather than a build. Set
#     ANDROID_HOME or NDK_HOME, or pass NDK_BIN=<path to the prebuilt bin dir>.
#     Python 3 for the APK step. No Gradle, no CMake, no Android Studio.
#
#     Verified with NDK r25c (clang 14.0.7) on a Windows host under Git Bash,
#     targeting API 21, producing arm64-v8a and armeabi-v7a. Other NDK versions
#     will give different addresses and the same checklist results.
#
# OUTPUT, and why each one exists
#     libdemo-default.so          compiler driver defaults, nothing added
#     libdemo-hard.so             every mitigation on
#     libdemo-weak.so             every mitigation deliberately off
#     libdemo-hard-stripped.so    libdemo-hard.so after llvm-strip
#     libdemo-arm32.so            the same source as armeabi-v7a, 32-bit ELF
#     libjnisurface.so            two visible JNI exports, four hidden ones
#     libnoshdr.so                section header table removed, as packers do
#     fixture.apk                 all three ZIP storage outcomes: stored and
#                                 16 KiB-aligned, stored but unaligned, deflated
#
# WHAT THIS SCRIPT WILL *NOT* DO
#     - Produce an installable app. fixture.apk is a ZIP with the right shape
#       for the tooling in this chapter, not a signed, installable package.
#       10-APK-Internals covers building a real one.
#     - Write anything into the repository. Everything lands in the output
#       directory you choose, which should not be inside the repo: compiled
#       binaries are build artefacts and this repository commits none.
#     - Detect that your NDK is too old. If the flags below are rejected, read
#       the error; the flag names have been stable for years.

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

There is no substitute: only the NDK's clang can emit an Android ELF, and a
host gcc will produce a glibc binary that no Android device will load.
ERR
  exit 2
fi

# On Windows the drivers are .cmd wrappers; on Linux and macOS they are not.
suffix=""
[ -f "$NDK_BIN/aarch64-linux-android${API}-clang.cmd" ] && suffix=".cmd"
CC64="$NDK_BIN/aarch64-linux-android${API}-clang${suffix}"
CC32="$NDK_BIN/armv7a-linux-androideabi${API}-clang${suffix}"
STRIP="$NDK_BIN/llvm-strip"
[ -f "$STRIP.exe" ] && STRIP="$STRIP.exe"

for t in "$CC64" "$CC32"; do
  [ -x "$t" ] || [ -f "$t" ] || { echo "missing: $t" >&2; exit 2; }
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT"
echo "NDK bin : $NDK_BIN"
echo "output  : $OUT"
echo

say() { printf '  %-28s %s\n' "$1" "$2"; }

# 1. compiler-driver defaults. Note what you get for free and what you do not.
"$CC64" -shared -fPIC -O2 \
  -o "$OUT/libdemo-default.so" "$HERE/hardening-demo.c"
say libdemo-default.so "driver defaults only"

# 2. the release build a reviewer should be asking for.
"$CC64" -shared -fPIC -O2 \
  -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,max-page-size=16384 \
  -o "$OUT/libdemo-hard.so" "$HERE/hardening-demo.c"
say libdemo-hard.so "every mitigation on"

# 3. everything off. -Wl,-z,execstack is the one that is a real defect.
"$CC64" -shared -fPIC -O1 \
  -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
  -Wl,-z,norelro -Wl,-z,lazy -Wl,-z,execstack \
  -o "$OUT/libdemo-weak.so" "$HERE/hardening-demo.c"
say libdemo-weak.so "every mitigation off"

# 4. what shipping actually looks like: hardened AND stripped.
cp "$OUT/libdemo-hard.so" "$OUT/libdemo-hard-stripped.so"
"$STRIP" "$OUT/libdemo-hard-stripped.so"
say libdemo-hard-stripped.so "hardened, then stripped"

# 5. the 32-bit ABI. Different ELF class, different relocation format (REL,
#    not RELA), and that difference bites when you read .init_array by hand.
"$CC32" -shared -fPIC -O2 -fstack-protector-strong \
  -Wl,-z,max-page-size=16384 \
  -o "$OUT/libdemo-arm32.so" "$HERE/hardening-demo.c"
say libdemo-arm32.so "armeabi-v7a, ELF32, REL relocations"

# 6. the export-table fixture.
"$CC64" -shared -fPIC -O2 -Wl,-z,max-page-size=16384 \
  -o "$OUT/libjnisurface.so" "$HERE/jni-surface.c"
"$STRIP" "$OUT/libjnisurface.so"
say libjnisurface.so "2 visible JNI exports, 4 hidden"

# 7. a library with no section header table, which is what a packer leaves you.
python3 - "$OUT/libjnisurface.so" "$OUT/libnoshdr.so" <<'PY'
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, 'rb').read())
if d[:4] != b"\x7fELF" or d[4] != 2:
    raise SystemExit("expected a 64-bit ELF")
struct.pack_into('<Q', d, 0x28, 0)          # e_shoff  = 0
struct.pack_into('<HHH', d, 0x3A, 64, 0, 0) # shentsize, shnum, shstrndx
open(dst, 'wb').write(bytes(d))
PY
say libnoshdr.so "section headers removed"

# 8. an APK-shaped ZIP: one STORED entry, one DEFLATED entry.
# 8. an APK-shaped ZIP holding all THREE storage outcomes, because only one of
#    them can actually be mapped in place:
#      a) STORED and page-aligned   -> mappable from inside the APK
#      b) STORED but NOT aligned    -> still has to be extracted. The case that
#                                      catches real apps out, because the
#                                      manifest looks correct
#      c) DEFLATED                  -> has to be extracted
python3 - "$OUT" <<'PY'
import os, struct, sys, zipfile
out = sys.argv[1]
apk = os.path.join(out, 'fixture.apk')
ALIGN = 16384


def data_offset(z, name):
    """Where the entry's bytes actually start: 30 + name + LOCAL extra."""
    info = z.getinfo(name)
    keep = z.fp.tell()
    z.fp.seek(info.header_offset)
    head = z.fp.read(30)
    n_len, e_len = struct.unpack_from('<HH', head, 26)
    z.fp.seek(keep)
    return info.header_offset + 30 + n_len + e_len


with zipfile.ZipFile(apk, 'w') as z:
    z.writestr('AndroidManifest.xml', b'(not a real binary manifest)')
    # (b) stored, deliberately left unaligned
    z.write(os.path.join(out, 'libjnisurface.so'),
            'lib/arm64-v8a/libjnisurface.so', zipfile.ZIP_STORED)
    # (c) compressed
    z.write(os.path.join(out, 'libdemo-arm32.so'),
            'lib/armeabi-v7a/libdemo-arm32.so', zipfile.ZIP_DEFLATED)
    # (a) stored AND 16 KiB aligned -- exactly how zipalign does it: pad the
    # entry's LOCAL EXTRA FIELD until its data lands on a page boundary. The
    # extra field uses Android's own alignment header id (0xd935) so that the
    # padding is a well-formed extra field rather than raw filler.
    name = 'lib/arm64-v8a/libdemo-hard.so'
    src = os.path.join(out, 'libdemo-hard.so')
    zinfo = zipfile.ZipInfo.from_file(src, name)
    zinfo.compress_type = zipfile.ZIP_STORED
    pad = (-(z.fp.tell() + 30 + len(name))) % ALIGN
    while pad < 4:                       # an extra field needs a 4-byte header
        pad += ALIGN
    zinfo.extra = struct.pack('<HH', 0xD935, pad - 4) + b'\x00' * (pad - 4)
    with open(src, 'rb') as fh:
        z.writestr(zinfo, fh.read())

with zipfile.ZipFile(apk) as z:
    for n in z.namelist():
        if n.endswith('.so'):
            info = z.getinfo(n)
            off = data_offset(z, n)
            print('  %-46s %-9s offset %-8d %s'
                  % (n, 'STORED' if info.compress_type == 0 else 'DEFLATED',
                     off, 'ALIGNED 16K' if off % ALIGN == 0 else 'unaligned'))
print("  %-28s %s" % ('fixture.apk', 'all three storage outcomes'))
PY

cat <<NEXT

Done. Now compare them:

  python3 ../scripts/elf-harden-check.py $OUT/libdemo-default.so \\
                                         $OUT/libdemo-hard.so \\
                                         $OUT/libdemo-weak.so | grep '^\\['

  python3 ../scripts/elf-inspect.py $OUT/libdemo-hard.so --dynsyms
  python3 ../scripts/elf-inspect.py $OUT/libdemo-hard-stripped.so --symbols
  python3 ../scripts/elf-inspect.py $OUT/libdemo-arm32.so --init
  python3 ../scripts/elf-harden-check.py --apk $OUT/fixture.apk

The interesting comparisons:
  - default vs hard: the canary and __*_chk symbols appear, and the imports
    list SHRINKS, because strcpy became __strcpy_chk.
  - hard vs hard-stripped: .symtab disappears; .dynsym does not.
  - arm64 vs arm32 --init: the arm64 slot is zero and the address is in the
    relocation addend. The arm32 slot holds the address directly.
NEXT
