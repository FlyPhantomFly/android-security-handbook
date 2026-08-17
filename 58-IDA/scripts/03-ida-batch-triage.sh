#!/usr/bin/env bash
# scripts/03-ida-batch-triage.sh
#
# PURPOSE
#   Sweep every native library in one or more APKs and produce a single table
#   answering the only questions worth asking before you open a GUI:
#
#     which ABIs ship?  which library is stripped?  which has Java_* exports?
#     which has JNI_OnLoad and NO exports (so binding is dynamic)?  which
#     imports ptrace, dlopen, mprotect?  how big is each?
#
#   It has TWO backends and they answer the same questions:
#
#     --backend ida    drives `idat` headlessly with 02-ida-android-annotate.py
#     --backend llvm   uses only llvm-readelf / llvm-nm from the NDK
#
#   The llvm backend exists because IDA costs money and this triage does not
#   need it. That is the chapter's argument in one script: reach for the
#   expensive interactive tool when you have chosen a function to read, not to
#   decide which file to open.
#
# USAGE
#   # host -- sweep an APK with the free backend
#   ./03-ida-batch-triage.sh --backend llvm app.apk
#
#   # host -- several APKs, or a directory of .so files
#   ./03-ida-batch-triage.sh --backend llvm *.apk
#   ./03-ida-batch-triage.sh --backend llvm /tmp/ch58
#
#   # host -- the IDA backend, if you have a licence
#   IDAT=/opt/idapro-9.0/idat ./03-ida-batch-triage.sh --backend ida app.apk
#
#   # host -- keep the extracted libraries for a follow-up session
#   WORK=/tmp/sweep KEEP=1 ./03-ida-batch-triage.sh --backend llvm app.apk
#
# EXECUTION STATUS
#   PARTIALLY EXECUTED.
#     * The llvm backend WAS executed, against the libraries built by
#       examples/build.sh and against system libraries pulled from an
#       Android 15 / API 35 emulator. Its output is quoted in the README's
#       section 8.
#     * The ida backend was NOT executed. IDA Pro is commercial software and is
#       not installed on the machine where this chapter was written. The
#       invocation below follows Hex-Rays' documented command line
#       (`-A` autonomous, `-S` script, `-L` log, `-c` fresh database) but has
#       never been run here. If it fails for you, that is a finding worth
#       recording rather than a defect to hide.
#
# REQUIREMENTS
#   llvm backend : an Android NDK (for llvm-readelf / llvm-nm), unzip, awk
#   ida backend  : the above, plus an IDA installation with a decompiler and a
#                  processor module for the target ABI. Set IDAT to the
#                  text-mode binary -- `idat64` before IDA 9.0, `idat` from 9.0
#                  where the 32/64 split was removed.
#
# AUTHORISED TESTING ONLY. Sweep applications you built, own, or are
# contractually permitted to analyse.

set -u

BACKEND="llvm"
WORK="${WORK:-${TMPDIR:-/tmp}/ch58-sweep.$$}"
KEEP="${KEEP:-0}"
IDAT="${IDAT:-}"
ABI_FILTER="${ABI_FILTER:-arm64-v8a}"
HERE="$(cd "$(dirname "$0")" && pwd)"

usage() {
    sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

TARGETS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --backend) BACKEND="${2:-}"; shift 2 ;;
        --abi)     ABI_FILTER="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *)         TARGETS+=("$1"); shift ;;
    esac
done
[ ${#TARGETS[@]} -gt 0 ] || usage

# --------------------------------------------------------------------------- #
# Toolchain discovery -- identical ladder to examples/build.sh.
# --------------------------------------------------------------------------- #
NDK="${NDK_HOME:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
if [ -z "$NDK" ]; then
    SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-${LOCALAPPDATA:-$HOME/AppData/Local}/Android/Sdk}}"
    NDK="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -d "${NDK:-}" ] || { echo "error: no NDK found; set NDK_HOME" >&2; exit 2; }
HOSTTAG="$(ls "$NDK/toolchains/llvm/prebuilt" 2>/dev/null | head -1)"
TC="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
sfx=""; [ -x "$TC/llvm-nm.exe" ] && sfx=".exe"
NM="$TC/llvm-nm$sfx"
READELF="$TC/llvm-readelf$sfx"

mkdir -p "$WORK"
trap '[ "$KEEP" = "1" ] || rm -rf "$WORK"' EXIT

# --------------------------------------------------------------------------- #
# Gather .so files from APKs and directories alike.
# --------------------------------------------------------------------------- #
LIBS="$WORK/libs.txt"
: > "$LIBS"

for t in "${TARGETS[@]}"; do
    if [ -d "$t" ]; then
        find "$t" -name '*.so' -type f 2>/dev/null >> "$LIBS"
    elif [ "${t##*.}" = "apk" ] || [ "${t##*.}" = "aab" ] || [ "${t##*.}" = "zip" ]; then
        d="$WORK/$(basename "$t" | tr -c 'A-Za-z0-9._-' '_')"
        mkdir -p "$d"
        # `unzip -o -q` and NOT apktool: we want the raw .so, and decoding
        # resources is minutes of work for information we are not using.
        unzip -o -q "$t" 'lib/*' -d "$d" 2>/dev/null
        find "$d" -name '*.so' -type f 2>/dev/null >> "$LIBS"
    elif [ "${t##*.}" = "so" ]; then
        echo "$t" >> "$LIBS"
    else
        echo "skipping $t (not an apk, a directory, or a .so)" >&2
    fi
done

n=$(wc -l < "$LIBS" | tr -d ' ')
[ "$n" -gt 0 ] || { echo "no .so files found" >&2; exit 1; }
echo "found $n shared object(s)" >&2

# --------------------------------------------------------------------------- #
# The llvm backend -- EXECUTED.
# --------------------------------------------------------------------------- #
sweep_llvm() {
    printf '%-38s %-12s %8s %5s %6s %5s %s\n' \
        LIBRARY ABI SIZE STRIP "Java_*" ONLOAD "NOTABLE IMPORTS"
    printf '%s\n' "----------------------------------------------------------------------------------------------------"

    while IFS= read -r so; do
        [ -n "$so" ] || continue
        base="$(basename "$so")"

        # Derive the ABI from the ELF header's e_machine, NOT from the
        # directory name. Chapter 15 tabulates the mapping. Doing it this way
        # means the script works on a loose .so, on a library pulled from a
        # device, and on one whose parent directory is called anything at all
        # -- an earlier version filtered on the directory name and silently
        # reported ZERO libraries for exactly that reason.
        mach="$("$READELF" -h "$so" 2>/dev/null | awk -F: '/Machine/{print $2}' | tr -d ' ')"
        case "$mach" in
            *AArch64*|*ARM64*) abi="arm64-v8a" ;;
            *ARM*)             abi="armeabi-v7a" ;;
            *X86-64*|*x86-64*) abi="x86_64" ;;
            *386*|*IA-32*)     abi="x86" ;;
            *RISC-V*)          abi="riscv64" ;;
            *)                 abi="?" ;;
        esac
        if [ -n "$ABI_FILTER" ] && [ "$ABI_FILTER" != "all" ] \
           && [ "$abi" != "$ABI_FILTER" ]; then
            continue
        fi

        size="$(wc -c < "$so" | tr -d ' ')"

        # A .symtab section present means NOT stripped. Chapter 15 owns why
        # .dynsym survives regardless.
        if "$READELF" -S "$so" 2>/dev/null | grep -q '\.symtab'; then
            strip="no"
        else
            strip="YES"
        fi

        jni=$("$NM" -D --defined-only "$so" 2>/dev/null | grep -c ' T Java_')
        onload=$("$NM" -D --defined-only "$so" 2>/dev/null | grep -c ' T JNI_OnLoad')

        # Undefined symbols are what this library asks the world for. The list
        # is a reading order, not a verdict -- see chapter 38 on why a
        # detector that fires on everything is broken.
        notable=$("$NM" -D -u "$so" 2>/dev/null \
            | grep -oE '\b(ptrace|dlopen|dlsym|mprotect|fork|kill|syscall|prctl|popen|system|inotify_init|__system_property_get|getauxval)\b' \
            | sort -u | tr '\n' ',' | sed 's/,$//')

        flag=""
        if [ "$jni" = "0" ] && [ "$onload" != "0" ]; then
            flag="  <- DYNAMIC binding"
        fi

        printf '%-38s %-12s %8s %5s %6s %5s %s%s\n' \
            "${base:0:38}" "$abi" "$size" "$strip" "$jni" "$onload" "${notable:-  -}" "$flag"
    done < "$LIBS"

    echo
    echo "READING THE TABLE"
    echo "  STRIP=YES + Java_*=0 + ONLOAD=1  the interesting case. Nothing names"
    echo "                                   the native methods; the map is built"
    echo "                                   at run time by RegisterNatives."
    echo "  STRIP=no                         somebody shipped .symtab. Start here;"
    echo "                                   it is the cheapest library in the set."
    echo "  ptrace in NOTABLE                one call site is anti-debug, several"
    echo "                                   may be a debugger of its own. Look"
    echo "                                   before concluding. Chapter 38 measured"
    echo "                                   only 1 of 18 real APKs importing it."
    echo "  mprotect                         memory made writable: a packer, a"
    echo "                                   JIT, or self-modifying code."
    echo
    echo "  Nothing in this table is a finding. It is an ORDER in which to spend"
    echo "  the next two hours. See chapter 68 for the method that consumes it."
}

# --------------------------------------------------------------------------- #
# The ida backend -- REVIEWED, NOT EXECUTED.
# --------------------------------------------------------------------------- #
sweep_ida() {
    if [ -z "$IDAT" ]; then
        for cand in idat idat64 /opt/idapro/idat64 /opt/idapro/idat \
                    "/c/Program Files/IDA Professional 9.0/idat.exe"; do
            if command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ]; then
                IDAT="$cand"; break
            fi
        done
    fi
    if [ -z "$IDAT" ]; then
        echo "error: no IDA text-mode binary found." >&2
        echo "  Set IDAT to it, e.g. IDAT=/opt/idapro-9.0/idat" >&2
        echo "  Before IDA 9.0 the 64-bit loader is a separate binary, idat64." >&2
        echo "  If you do not have a licence, use --backend llvm: it answers the" >&2
        echo "  same triage questions and the chapter argues you should be using" >&2
        echo "  it for this step anyway." >&2
        exit 3
    fi

    OUT="$WORK/annot"
    mkdir -p "$OUT"
    script="$HERE/02-ida-android-annotate.py"
    [ -f "$script" ] || { echo "error: $script not found" >&2; exit 2; }

    while IFS= read -r so; do
        [ -n "$so" ] || continue
        base="$(basename "$so")"
        json="$OUT/$base.json"
        log="$OUT/$base.log"

        # -A  autonomous: never prompt. Without it a batch run blocks forever on
        #     the first dialogue and you will not see why.
        # -c  create a fresh database, discarding any .i64 next to the file.
        # -S  run the script AFTER auto-analysis. Quote it as one argument;
        #     everything inside the quotes reaches the script as idc.ARGV.
        # -L  log file. Read it when a run produces no JSON.
        # -o  put the database somewhere that is not next to the target, so a
        #     sweep does not litter the extracted APK tree with .i64 files.
        "$IDAT" -A -c \
                -o"$OUT/$base.i64" \
                -S"\"$script\" --out \"$json\"" \
                -L"$log" \
                "$so" >/dev/null 2>&1
        rc=$?

        if [ -f "$json" ]; then
            echo "[ok]   $base   (exit $rc)"
        else
            echo "[FAIL] $base   (exit $rc) -- read $log"
        fi
    done < "$LIBS"

    echo
    echo "JSON reports under $OUT"
    echo "Merge them:  jq -s '.' $OUT/*.json"
    echo
    echo "NOTE: the .i64 databases under $OUT can contain the target's bytes."
    echo "Treat them as you would treat the binary itself -- see the README's"
    echo "section 5 on why an .idb is not a safe thing to email."
}

case "$BACKEND" in
    llvm) sweep_llvm ;;
    ida)  sweep_ida ;;
    *)    echo "unknown backend '$BACKEND' (want: llvm, ida)" >&2; exit 2 ;;
esac
