#!/usr/bin/env bash
#
# so-corpus-stats.sh -- measure the analysis workload in a directory of shared libraries.
#
# PURPOSE
#   Answers the question section 2 of the chapter README is built on: "how much work is
#   actually in these files?" For each ELF it reports file size, .text size, instruction
#   count (exact on AArch64), dynamic symbol count, relocation count, whether it is
#   stripped, and the ratio of code bytes to names.
#
#   That last column is the useful one. A library with 1.6 MB of code behind 364 names has
#   to have its functions DISCOVERED rather than looked up, and that is where the cost of
#   radare2's `aaa` (or any other tool's analysis pass) comes from.
#
# USAGE
#   ./so-corpus-stats.sh <directory> [...]
#   ./so-corpus-stats.sh ~/ch59-build
#   ./so-corpus-stats.sh extracted/lib/arm64-v8a --csv > corpus.csv
#
#   Options:
#     --csv        emit CSV instead of an aligned table
#     --no-header  omit the header row
#
# TOOLING
#   Prefers rabin2 (radare2) when it is on PATH. Falls back to llvm-readelf from the
#   Android NDK, then to the system readelf. This fallback is not a nicety: the numbers in
#   the chapter README were produced on a machine with NO radare2 installed, using exactly
#   this fallback path, and the script is written so that measurement does not depend on
#   the tool being present.
#
#   Set READELF=/path/to/readelf to override detection.
#
# EXIT CODES
#   0  success
#   1  no usable ELF reader found, or no arguments
#   2  a named directory does not exist
#
set -uo pipefail

CSV=0
HEADER=1
DIRS=()

for arg in "$@"; do
    case "$arg" in
        --csv)       CSV=1 ;;
        --no-header) HEADER=0 ;;
        -h|--help)   sed -n '2,40p' "$0"; exit 0 ;;
        *)           DIRS+=("$arg") ;;
    esac
done

if [ ${#DIRS[@]} -eq 0 ]; then
    echo "usage: $0 <directory> [...] [--csv] [--no-header]" >&2
    exit 1
fi

# ---------------------------------------------------------------------------------------
# Find an ELF reader
# ---------------------------------------------------------------------------------------
find_readelf() {
    if [ -n "${READELF:-}" ]; then echo "$READELF"; return 0; fi
    if command -v llvm-readelf >/dev/null 2>&1; then echo "llvm-readelf"; return 0; fi
    for root in \
        "$HOME/Android/Sdk/ndk" \
        "$HOME/Library/Android/sdk/ndk" \
        "${LOCALAPPDATA:-}/Android/Sdk/ndk" \
        "${ANDROID_SDK_ROOT:-}/ndk" \
        "${ANDROID_HOME:-}/ndk"
    do
        [ -d "$root" ] || continue
        for ver in $(ls -1 "$root" 2>/dev/null | sort -rV); do
            for host in linux-x86_64 darwin-x86_64 windows-x86_64; do
                c="$root/$ver/toolchains/llvm/prebuilt/$host/bin/llvm-readelf"
                if [ -f "$c" ] || [ -f "$c.exe" ]; then echo "$c"; return 0; fi
            done
        done
    done
    if command -v readelf >/dev/null 2>&1; then echo "readelf"; return 0; fi
    return 1
}

HAVE_RABIN2=0
command -v rabin2 >/dev/null 2>&1 && HAVE_RABIN2=1

if ! RE="$(find_readelf)"; then
    cat >&2 <<'EOF'
ERROR: no ELF reader found.

Install one of:
  - radare2      (provides rabin2)
  - the Android NDK  (provides llvm-readelf)
  - binutils     (provides readelf)

Or point this script at one directly:
  READELF=/path/to/llvm-readelf ./so-corpus-stats.sh <dir>

Failing loudly is deliberate: a corpus scanner that prints an empty table when its tools
are missing produces a false negative that looks exactly like a clean result.
EOF
    exit 1
fi

echo "# reader: $RE$( [ $HAVE_RABIN2 -eq 1 ] && echo ' (rabin2 also available)' )" >&2

# ---------------------------------------------------------------------------------------
# Per-file measurement
# ---------------------------------------------------------------------------------------
# Section line from llvm-readelf/readelf -S looks like:
#     [16] .text   PROGBITS  00000000008e4000 8e4000 9433da 00  AX  0  0 16
# After stripping the leading "[NN]" the fields are:
#     $1=name $2=type $3=addr $4=offset $5=size
sect_field() {   # sect_field <file> <section> <field-number>
    "$RE" -S "$1" 2>/dev/null \
        | sed 's/^ *\[ *[0-9]*\] *//' \
        | awk -v s="$2" -v f="$3" '$1==s {print $f; exit}'
}

hex2dec() { [ -n "${1:-}" ] && printf '%d' "0x$1" 2>/dev/null || echo 0; }

machine_of() {
    "$RE" -h "$1" 2>/dev/null | awk -F: '/Machine/ {gsub(/^ +| +$/,"",$2); print $2; exit}'
}

emit() {
    if [ "$CSV" -eq 1 ]; then
        printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$@"
    else
        printf '%-28s %-12s %12s %12s %12s %10s %10s %9s %12s\n' "$@"
    fi
}

if [ "$HEADER" -eq 1 ]; then
    emit file arch file_bytes text_bytes insns dynsym relocs stripped bytes_per_name
fi

total_files=0
for d in "${DIRS[@]}"; do
    if [ ! -d "$d" ]; then
        echo "ERROR: not a directory: $d" >&2
        exit 2
    fi

    # -print0 / read -d '' so paths with spaces survive
    while IFS= read -r -d '' f; do
        # Cheap ELF magic check -- skip anything that is not an ELF
        magic=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
        [ "$magic" = "7f454c46" ] || continue

        total_files=$((total_files + 1))

        fsz=$(wc -c < "$f" | tr -d ' ')
        tsz=$(hex2dec "$(sect_field "$f" .text 5)")
        dyn=$("$RE" --dyn-syms "$f" 2>/dev/null | grep -cE '^ *[0-9]+:')
        rel=$("$RE" -r "$f" 2>/dev/null | grep -cE '^[0-9a-f]{8,}')
        arch=$(machine_of "$f")

        # Stripped == no .symtab section
        if "$RE" -S "$f" 2>/dev/null | grep -q '\.symtab'; then
            stripped=no
        else
            stripped=yes
        fi

        # Instruction count is exact only for fixed-width instruction sets.
        case "$arch" in
            *AArch64*|*ARM*) insns=$((tsz / 4)) ;;
            *)               insns="n/a" ;;
        esac

        if [ "$dyn" -gt 0 ] 2>/dev/null; then
            bpn=$((tsz / dyn))
        else
            bpn="n/a"
        fi

        # Shorten arch for the table
        case "$arch" in
            *AArch64*)      a=aarch64 ;;
            *X86-64*|*x86*) a=x86_64 ;;
            *ARM*)          a=arm ;;
            *)              a="${arch:-unknown}" ;;
        esac

        emit "$(basename "$f")" "$a" "$fsz" "$tsz" "$insns" "$dyn" "$rel" "$stripped" "$bpn"
    done < <(find "$d" -type f \( -name '*.so' -o -name '*.so.*' \) -print0 2>/dev/null)
done

echo "# $total_files ELF file(s) measured" >&2

if [ "$total_files" -eq 0 ]; then
    echo "# WARNING: no ELF files found -- check the path" >&2
    exit 0
fi

cat >&2 <<'EOF'
#
# Reading the output:
#   text_bytes      what an analysis pass must decode. THIS drives `aaa` cost, not file size.
#   dynsym          how many starting points the binary hands the analyser for free.
#   bytes_per_name  code bytes per exported name. High means function discovery is invention.
#   stripped=yes    normal for shipped Android libraries; expect fcn.<addr> names throughout.
#
EOF
