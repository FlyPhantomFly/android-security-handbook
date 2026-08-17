#!/usr/bin/env bash
# examples/build.sh
#
# PURPOSE
#   Build chapter 58's reversing target, out of tree, with no Gradle, no
#   Android Studio, no device and no network -- and then print the ground
#   truth that lets you check any disassembler's answer against the compiler's.
#
#   It produces four artefacts:
#
#     libcrcutil.a                 a STATIC ARCHIVE holding three library
#                                  functions. This is what a FLIRT signature
#                                  would be built from -- see
#                                  ../scripts/01-make-flirt-pat.py
#     libsession-unstripped.so     the ANSWER KEY: every function named
#     libsession.so                the TARGET: --strip-all applied
#     ground-truth.txt             the llvm-objdump / llvm-readelf output this
#                                  chapter quotes, regenerated on your machine
#
#   The chapter's claim is that you can do every lab here with IDA, with
#   Ghidra, with radare2, or with nothing but llvm-objdump -- and compare. That
#   claim only holds if the target is one you built, so build it.
#
# USAGE
#   # host -- default: arm64-v8a into ${TMPDIR:-/tmp}/ch58-build
#   ./build.sh
#
#   # host -- choose the output directory (keep it OUTSIDE the repository)
#   OUTDIR=/tmp/ch58 ./build.sh
#
#   # host -- 32-bit ARM, whose jump-table idiom and calling convention differ
#   ABI=armeabi-v7a ./build.sh
#
#   # host -- x86_64, for the 16 KiB-page emulator
#   ABI=x86_64 ./build.sh
#
#   # host -- also emit an -O0 build, so you can see what optimisation did
#   BOTH_OPT=1 ./build.sh
#
# REQUIREMENTS
#   An Android NDK. Set NDK_HOME, or ANDROID_NDK_HOME, or ANDROID_NDK_ROOT, or
#   let the script pick the newest one under $ANDROID_HOME/ndk. Nothing else --
#   no JDK, no device, no IDA.
#
#   Verified with NDK 25.2.9519653 (clang 14.0.7, target
#   aarch64-unknown-linux-android21) on a Windows host under Git Bash. Both
#   sources compile clean under -Wall -Wextra.
#
# WHERE IT BUILDS
#   Into $OUTDIR, default ${TMPDIR:-/tmp}/ch58-build -- OUTSIDE this
#   repository. `.so`, `.o` and `.a` are on the artefact blocklist and this
#   repository ships sources only. If you change OUTDIR, keep it out of the
#   tree.
#
# EXECUTION STATUS
#   EXECUTED. This script was run to completion on the host described above and
#   its output is what examples/03-ground-truth-aarch64.md quotes.
#
# AUTHORISED TESTING ONLY -- though this is your own code, so go ahead.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${OUTDIR:-${TMPDIR:-/tmp}/ch58-build}"
ABI="${ABI:-arm64-v8a}"
API="${API:-21}"
BOTH_OPT="${BOTH_OPT:-0}"

SRC_MAIN="$HERE/01-session-target.c"
SRC_UTIL="$HERE/02-crcutil.c"

# --------------------------------------------------------------------------- #
# Locate the NDK.
# --------------------------------------------------------------------------- #
NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [ -z "$NDK" ]; then
    SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${LOCALAPPDATA:-$HOME/AppData/Local}/Android/Sdk}}"
    NDK="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -d "${NDK:-}" ] || { echo "error: no NDK found. Set NDK_HOME to your NDK root." >&2; exit 2; }

HOSTTAG="$(ls "$NDK/toolchains/llvm/prebuilt" 2>/dev/null | head -1)"
TC="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
[ -d "$TC" ] || { echo "error: no toolchain under $NDK/toolchains/llvm/prebuilt" >&2; exit 2; }

case "$ABI" in
    arm64-v8a)   TRIPLE="aarch64-linux-android$API" ;;
    armeabi-v7a) TRIPLE="armv7a-linux-androideabi$API" ;;
    x86_64)      TRIPLE="x86_64-linux-android$API" ;;
    x86)         TRIPLE="i686-linux-android$API" ;;
    *) echo "error: unknown ABI '$ABI'" >&2; exit 2 ;;
esac

# On Windows the driver is a .cmd wrapper; on Linux and macOS it is not.
CC="$TC/$TRIPLE-clang"
[ -x "$CC" ] || CC="$TC/$TRIPLE-clang.cmd"
[ -e "$CC" ] || { echo "error: no compiler at $TC/$TRIPLE-clang" >&2; exit 2; }

sfx=""
[ -x "$TC/llvm-nm.exe" ] && sfx=".exe"
AR="$TC/llvm-ar$sfx"
NM="$TC/llvm-nm$sfx"
READELF="$TC/llvm-readelf$sfx"
OBJDUMP="$TC/llvm-objdump$sfx"
STRINGS="$TC/llvm-strings$sfx"

echo "NDK      $NDK"
echo "ABI      $ABI  ($TRIPLE)"
echo "outdir   $OUTDIR"
"$CC" --version 2>/dev/null | head -1 | sed 's/^/clang    /'
echo

mkdir -p "$OUTDIR"
GT="$OUTDIR/ground-truth.txt"

# -O2 deliberately, and everywhere. A release Android library is -O2, and the
# whole value of this fixture is that it shows what -O2 does to code you wrote:
# the inlining, the jump table, the tail call, the folded constants. Building
# it at -O0 produces a target that looks nothing like the ones you are given.
CFLAGS="-O2 -Wall -Wextra -fPIC"
LDFLAGS="-shared"

# The 16 KiB-page emulator segfaults naively-linked binaries -- measured
# independently by chapters 39 and 70. The flag costs nothing on 4 KiB devices.
case "$ABI" in
    arm64-v8a|x86_64) LDFLAGS="$LDFLAGS -Wl,-z,max-page-size=16384" ;;
esac

# --------------------------------------------------------------------------- #
# 1. The static archive. This is the "somebody else wrote this" half.
# --------------------------------------------------------------------------- #
echo "building libcrcutil.a (the library half)..."
"$CC" $CFLAGS -c -o "$OUTDIR/02-crcutil.o" "$SRC_UTIL" || exit 1
rm -f "$OUTDIR/libcrcutil.a"
"$AR" rcs "$OUTDIR/libcrcutil.a" "$OUTDIR/02-crcutil.o" || exit 1

# --------------------------------------------------------------------------- #
# 2. The two libraries.
# --------------------------------------------------------------------------- #
echo "building libsession-unstripped.so (the answer key)..."
"$CC" $CFLAGS $LDFLAGS -o "$OUTDIR/libsession-unstripped.so" \
    "$SRC_MAIN" "$OUTDIR/libcrcutil.a" || exit 1

echo "building libsession.so (the target)..."
"$CC" $CFLAGS $LDFLAGS -Wl,--strip-all -o "$OUTDIR/libsession.so" \
    "$SRC_MAIN" "$OUTDIR/libcrcutil.a" || exit 1

if [ "$BOTH_OPT" = "1" ]; then
    echo "building libsession-O0.so (the comparison)..."
    "$CC" -O0 -Wall -Wextra -fPIC $LDFLAGS -o "$OUTDIR/libsession-O0.so" \
        "$SRC_MAIN" "$SRC_UTIL" || exit 1
fi
echo

# --------------------------------------------------------------------------- #
# The report.
#
# Everything below is emitted by ONE function and piped through ONE `tee`.
# An earlier version of this script used a `say`/`run` pair that each opened
# `tee -a` separately, and on a Windows host under Git Bash the interleaving
# silently DROPPED whole headings from the saved file while still printing
# them to the terminal -- so the artefact and the terminal disagreed. One
# stream, one tee. Section 11 of the README records it as a mistake worth
# knowing, because a report you did not read back is not evidence.
# --------------------------------------------------------------------------- #
indent() { sed 's/^/   /'; }

report() {
echo "==================================================================="
echo " GROUND TRUTH -- $ABI, NDK $(basename "$NDK"), $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "==================================================================="
echo

# ------------------------------------------------------------------------- #
echo "1. WHAT THE STRIP REMOVED"
echo "-------------------------"
u_sym=$("$NM" "$OUTDIR/libsession-unstripped.so" 2>/dev/null | wc -l | tr -d ' ')
s_sym=$("$NM" "$OUTDIR/libsession.so" 2>/dev/null | wc -l | tr -d ' ')
u_dyn=$("$NM" -D --defined-only "$OUTDIR/libsession-unstripped.so" 2>/dev/null | wc -l | tr -d ' ')
s_dyn=$("$NM" -D --defined-only "$OUTDIR/libsession.so" 2>/dev/null | wc -l | tr -d ' ')
echo "   unstripped : $u_sym symbols total, $u_dyn defined in .dynsym"
echo "   stripped   : $s_sym symbols total, $s_dyn defined in .dynsym"
echo
echo "   .dynsym is untouched -- the dynamic linker needs it. Everything with"
echo "   internal linkage lost its name. Note what that means: the three"
echo "   functions from libcrcutil.a keep their names because they were"
echo "   compiled with default visibility, while session_slow_path and"
echo "   session_fatal lose theirs. VISIBILITY, not origin, decides."
echo

# ------------------------------------------------------------------------- #
echo "2. THE EXPORTS THAT SURVIVED THE STRIP"
echo "--------------------------------------"
"$NM" -D --defined-only "$OUTDIR/libsession.so" 2>/dev/null | grep -E ' (T|t) ' | indent
echo
echo "   session_check_magic is exported and, at -O2, is called by NOTHING"
echo "   inside this library -- its body was inlined into every caller."
echo "   Patch it and nothing changes. Chapter 18 section 5.4 measured that"
echo "   exact failure on a different fixture; this one reproduces it."
echo

# ------------------------------------------------------------------------- #
echo "3. THE FUNCTIONS THE STRIP HID (read from the answer key)"
echo "---------------------------------------------------------"
"$NM" --defined-only "$OUTDIR/libsession-unstripped.so" 2>/dev/null \
    | grep -E ' (t|T) ' | sort | indent
echo
echo "   ch58_crc32, ch58_fnv1a64 and ch58_hex came from libcrcutil.a --"
echo "   somebody else's code, statically linked. Telling library code from"
echo "   application code with no symbols is what FLIRT signatures are for;"
echo "   build a pattern file for this archive with"
echo "   ../scripts/01-make-flirt-pat.py."
echo

# ------------------------------------------------------------------------- #
echo "4. THE JUMP TABLE -- session_step's twelve-case switch"
echo "------------------------------------------------------"
echo "   MEASURED, and it is not the idiom most references print. clang 14"
echo "   emitted a BYTE table -- one byte per case, counting 4-byte"
echo "   instruction words from an 'adr' anchor -- not a table of 32-bit"
echo "   offsets:"
echo
echo "       adrp  x9, <page>            ; page of the byte table"
echo "       add   x9, x9, #<lo12>"
echo "       adr   x10, #16              ; the anchor the offsets count FROM"
echo "       ldrb  w11, [x9, x8]         ; one BYTE, indexed by the opcode"
echo "       add   x10, x10, x11, lsl #2"
echo "       br    x10"
echo
echo "   Consequences for you: the table is 12 bytes, not 48; it does not"
echo "   look like pointers in a hex dump; and a tool that only recognises"
echo "   word-sized tables will not find it. Yours:"
echo
"$OBJDUMP" -d --disassemble-symbols=session_step \
    "$OUTDIR/libsession-unstripped.so" 2>/dev/null | indent
echo

# ------------------------------------------------------------------------- #
echo "5. THE INDIRECT CALL -- digest_table"
echo "------------------------------------"
n_blr=$("$OBJDUMP" -d "$OUTDIR/libsession-unstripped.so" 2>/dev/null \
    | grep -cE '[[:space:]]blr[[:space:]]' )
echo "   blr instructions in the library: $n_blr   (expect at least 1)"
echo
echo "   If this reads 0, the optimiser folded the table. That is exactly"
echo "   what happened on the first build of this fixture, when digest_table"
echo "   was 'static const': clang proved the contents and replaced every"
echo "   indirect call with a direct one, so the construct the fixture claims"
echo "   to teach was not in the binary at all. The exported setter"
echo "   session_set_digest is what prevents it."
echo
"$OBJDUMP" -d "$OUTDIR/libsession-unstripped.so" 2>/dev/null \
    | grep -B4 -E '[[:space:]]blr[[:space:]]' | indent
echo

# ------------------------------------------------------------------------- #
echo "6. THE TAIL CALL -- session_dispatch to session_slow_path"
echo "---------------------------------------------------------"
"$OBJDUMP" -d --disassemble-symbols=session_dispatch \
    "$OUTDIR/libsession-unstripped.so" 2>/dev/null | indent
echo
echo "   A 'b' rather than 'bl' plus 'ret' means session_slow_path returns"
echo "   directly to session_dispatch's caller. In a call graph this is still"
echo "   an edge; in a listing the function looks like it simply stops."
echo

# ------------------------------------------------------------------------- #
echo "7. THE SPECIALISED INLINE -- session_slow_path"
echo "----------------------------------------------"
"$OBJDUMP" -d --disassemble-symbols=session_slow_path \
    "$OUTDIR/libsession-unstripped.so" 2>/dev/null | indent
echo
echo "   session_slow_path calls session_step with in = NULL, and clang"
echo "   inlines a copy SPECIALISED on that fact: cases 6, 7 and 8 can never"
echo "   reach the digest table, so they collapse into the shared error"
echo "   return and several entries of the second jump table point at the"
echo "   same address. One function, two call sites, two different machine"
echo "   -code shapes. Compare the two byte tables in section 9."
echo

# ------------------------------------------------------------------------- #
echo "8. THE INLINED PREDICATE -- session_check_magic"
echo "-----------------------------------------------"
"$OBJDUMP" -d --disassemble-symbols=session_check_magic \
    "$OUTDIR/libsession-unstripped.so" 2>/dev/null | indent
echo
n_direct=$("$OBJDUMP" -d "$OUTDIR/libsession-unstripped.so" 2>/dev/null \
    | grep -cE 'bl[[:space:]]+.*<session_check_magic(@plt)?>' )
echo "   direct calls to session_check_magic anywhere in the library: $n_direct"
echo
echo "   Chapter 68 section 8.3 measured that a bare '<name>' grep produces a"
echo "   FALSE NEGATIVE on PLT-routed calls, so the pattern above carries the"
echo "   optional (@plt)? group. Confirmed here: this library's calls to its"
echo "   own exported functions DO go through the PLT, because default"
echo "   visibility makes them interposable. Look for '@plt' in section 4."
echo

# ------------------------------------------------------------------------- #
echo "9. THE TWO JUMP TABLES, AS BYTES"
echo "--------------------------------"
"$READELF" -x .rodata "$OUTDIR/libsession-unstripped.so" 2>/dev/null \
    | head -6 | indent
echo
echo "   Twelve bytes per table. A repeated value means two opcodes share a"
echo "   case body -- which in the second table is the specialisation from"
echo "   section 7, visible as a number rather than inferred."
echo

# ------------------------------------------------------------------------- #
echo "10. RELOCATED POINTERS -- zero on disk, real at run time"
echo "--------------------------------------------------------"
"$READELF" -r "$OUTDIR/libsession-unstripped.so" 2>/dev/null \
    | grep -iE 'relativ|jump_slot' | head -16 | indent
echo
echo "   Every R_AARCH64_RELATIVE entry is a pointer whose value is the"
echo "   ADDEND, not the bytes in the file. A tool that does not apply"
echo "   relocations shows you zeroes. Check yours before concluding that a"
echo "   table is empty."
echo

# ------------------------------------------------------------------------- #
echo "11. THE STRINGS THAT ARE NOT THERE"
echo "----------------------------------"
hit=$("$STRINGS" -a "$OUTDIR/libsession.so" 2>/dev/null \
    | grep -cE '/system/bin/su|ro\.debuggable')
echo "   matches for '/system/bin/su' and 'ro.debuggable': $hit   (expect 0)"
echo
echo "   BUT A ZERO HERE IS NOT ENOUGH, and this check nearly shipped wrong."
echo "   'the plaintext is absent' is satisfied both by 'it is encrypted' and"
echo "   by 'the compiler deleted the whole thing'. An earlier build of this"
echo "   fixture was the second case: clang inlined the decoder, folded the"
echo "   XOR at compile time, proved the caller's comparison always true, and"
echo "   removed BOTH arrays. The check above passed for the wrong reason."
echo
echo "   So confirm the CIPHERTEXT is present, not just the plaintext absent:"
ct=$("$READELF" -x .rodata "$OUTDIR/libsession.so" 2>/dev/null \
    | grep -cE '75292329|28357[43]|3e3f382f')
echo "   encoded-array byte runs found in .rodata: $ct   (expect at least 1)"
"$READELF" -x .rodata "$OUTDIR/libsession.so" 2>/dev/null | indent
echo
echo "   Both plaintexts exist only on the stack inside session_seal, only"
echo "   after session_reveal has run -- and session_reveal carries"
echo "   __attribute__((noinline)) precisely so that remains true."
echo
echo "   What IS in the file as text, because ch58_hex needs it:"
"$STRINGS" -a "$OUTDIR/libsession.so" 2>/dev/null | grep -E '^0123456789' | indent
echo
echo "   Finding that string and following its cross-references is how you"
echo "   locate the hex encoder without reading one instruction."
echo

# ------------------------------------------------------------------------- #
echo "12. THE STRUCT, AS OFFSETS -- the answer key for lab 02"
echo "-------------------------------------------------------"
echo "   +0x00 magic       uint32     +0x04 flags       uint32"
echo "   +0x08 issued_at   uint64     +0x10 key[16]     uint8"
echo "   +0x20 user[32]    char       +0x40 crc         uint32"
echo "   +0x44 state       int32      +0x48 step_count  uint32"
echo "   +0x4c reserved    uint32     ---- sizeof = 0x50"
echo
echo "   magic is 0x5345534E and it is never contiguous in the code: it"
echo "   arrives as 'mov w9, #21326' plus 'movk w9, #21317, lsl #16' --"
echo "   0x534E then 0x5345. Grepping the binary for the four bytes of that"
echo "   constant finds nothing. Chapter 18 section 3.3 covers the encoding."
echo

echo "==================================================================="
echo "done. Everything is under $OUTDIR; nothing was written into the repo."
echo
echo "next:"
echo "  build a FLIRT pattern file from the static archive:"
echo "    python3 -B ../scripts/01-make-flirt-pat.py $OUTDIR/libcrcutil.a"
echo
echo "  disassemble anything without opening a GUI:"
echo "    $OBJDUMP -d --disassemble-symbols=session_seal \\"
echo "      $OUTDIR/libsession-unstripped.so"
echo
echo "  then open $OUTDIR/libsession.so in whichever tool you own and see how"
echo "  much of the above you can recover WITHOUT looking at the answer key."
echo "==================================================================="
}

report 2>&1 | tee "$GT"

echo
echo "ground truth saved to $GT"
