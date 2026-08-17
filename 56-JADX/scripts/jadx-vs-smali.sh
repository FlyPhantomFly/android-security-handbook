#!/usr/bin/env bash
#
# jadx-vs-smali.sh -- put one method's decompiled Java next to the bytecode it came from.
#
# PURPOSE
#   Chapter 56's rule is "read Java to find, read Smali to be certain", and the friction that
#   stops people following it is that being certain takes four separate commands with four
#   different tools. This is one command.
#
#   For a single class (and optionally a single method) it prints, in order:
#
#     1. jadx's normal output          -- what you have been reading
#     2. jadx's LITERAL output         -- the same method with every readability pass off:
#                                         no method inlining, no anonymous-class inlining,
#                                         no constant substitution, no string-switch folding.
#                                         Differences between 1 and 2 are jadx's editorialising.
#     3. jadx -m fallback              -- register-level near-disassembly with catch ranges.
#                                         jadx asserts almost nothing here, so it cannot lie
#                                         to you about control flow.
#     4. real Smali                    -- from baksmali or apktool, if either is installed
#     5. dexdump -d                    -- byte offsets and raw opcodes, if the SDK is present
#
#   Steps 1-3 need nothing but jadx. Steps 4-5 are skipped with a note if the tools are absent.
#
# USAGE
#   ./jadx-vs-smali.sh app.apk com.example.auth.TokenManager
#   ./jadx-vs-smali.sh app.apk com.example.auth.TokenManager buildAuthHeader
#   ./jadx-vs-smali.sh classes.dex com.example.Foo bar --keep    # keep the work dir
#
#   Also accepts a .smali file directly, which is how the chapter's own examples are driven:
#   ./jadx-vs-smali.sh ../examples/02-when-jadx-is-wrong/Accumulate.smali com.pentest.ch56.Acc accumulate
#
# REQUIREMENTS
#   - jadx 1.5.x. Discovery order: $JADX, then $JADX_JAR (invoked as
#     `java -cp <jar> jadx.cli.JadxCLI`), then `jadx` on PATH.
#     On a Windows jadx-gui-only install:
#       export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"
#   - OPTIONAL: baksmali or apktool, for step 4.
#   - OPTIONAL: Android SDK build-tools on PATH or $ANDROID_HOME, for step 5.
#
# WHAT THIS WILL NOT TELL YOU
#   - It will NOT tell you which of the five renderings is right. It puts them side by side so
#     that YOU can. Where they disagree, the instruction listing wins -- that is the point.
#   - It does NOT verify jadx's output by recompiling it. No tool in this chapter does; the
#     absence of that check is exactly why silent failures stay silent (see section 6.6).
#   - The method extraction is textual (brace and `.end method` matching). A method whose body
#     contains an unbalanced brace inside a string literal can confuse step 1's extraction.
#     If output looks truncated, drop the method argument and read the whole class.
#   - It says nothing about runtime. A method that is never called still prints beautifully.
#
# CHAPTER
#   ../README.md sections 3.7, 4.4, 6.3, 9.3.
#   The instruction set itself is ../../14-Dalvik/README.md -- this script gets you there,
#   it does not teach it.

set -uo pipefail

usage() {
    sed -n '2,50p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 1
}

[ $# -ge 2 ] || usage

INPUT="$1"; CLASS="$2"; METHOD="${3:-}"
KEEP=0
for a in "$@"; do [ "$a" = "--keep" ] && KEEP=1; done

[ -f "$INPUT" ] || { echo "error: no such file: $INPUT" >&2; exit 1; }

WORK="$(mktemp -d 2>/dev/null || echo "./jvs-$$")"
mkdir -p "$WORK"
cleanup() { [ "$KEEP" -eq 1 ] && echo "work dir kept: $WORK" || rm -rf "$WORK"; }
trap cleanup EXIT

CLASS_PATH="${CLASS//.//}"

run_jadx() {
    if   [ -n "${JADX:-}" ];     then "$JADX" "$@"
    elif [ -n "${JADX_JAR:-}" ]; then java -cp "$JADX_JAR" jadx.cli.JadxCLI "$@"
    elif command -v jadx >/dev/null 2>&1; then jadx "$@"
    else echo "error: jadx not found. Set JADX or JADX_JAR." >&2; exit 1
    fi
}

banner() {
    echo
    echo "================================================================================"
    echo "$*"
    echo "================================================================================"
}

# Print a whole .java file, or just one method from it, minus the machine-specific header.
emit_java() {
    local dir="$1" file
    file="$(find "$dir" -type f -name "$(basename "$CLASS_PATH").java" 2>/dev/null | head -1)"
    if [ -z "$file" ]; then
        file="$(find "$dir" -type f -name '*.java' 2>/dev/null | head -1)"
    fi
    if [ -z "$file" ]; then
        echo "(jadx produced no .java under $dir -- wrong class name, or jadx skipped it)"
        return 0
    fi
    if [ -z "$METHOD" ]; then
        grep -v "^/\* loaded from:" "$file"
        return 0
    fi
    # Print from the first line mentioning the method name up to the matching closing brace.
    awk -v m="$METHOD" '
        index($0, m) && !started { started = 1 }
        started {
            print
            n += gsub(/\{/, "{")
            n -= gsub(/\}/, "}")
            if (n <= 0 && /\}/) exit
        }
    ' "$file"
}

echo "input : $INPUT"
echo "class : $CLASS"
[ -n "$METHOD" ] && echo "method: $METHOD"
echo "jadx  : $(run_jadx --version 2>/dev/null || echo unknown)"

# ------------------------------------------------------------------ 1. normal jadx output
run_jadx -q --single-class "$CLASS" -d "$WORK/normal" "$INPUT" 2>/dev/null
banner "1. jadx, default settings -- what you have been reading"
emit_java "$WORK/normal"

# ------------------------------------------------------------------ 2. literal output
run_jadx -q --single-class "$CLASS" \
         --no-inline-methods --no-inline-anonymous \
         --no-replace-consts --no-restore-switch-over-string \
         --no-finally --comments-level warn \
         -d "$WORK/literal" "$INPUT" 2>/dev/null
banner "2. jadx, readability passes OFF -- differences from (1) are jadx's editorialising"
echo "   flags: --no-inline-methods --no-inline-anonymous --no-replace-consts"
echo "          --no-restore-switch-over-string --no-finally"
emit_java "$WORK/literal"

# ------------------------------------------------------------------ 3. fallback mode
run_jadx -q --single-class "$CLASS" -m fallback -d "$WORK/fb" "$INPUT" 2>/dev/null
banner "3. jadx -m fallback -- near-disassembly. jadx asserts almost nothing here."
emit_java "$WORK/fb"

# ------------------------------------------------------------------ 4. real Smali
banner "4. Smali"
SMALI_FILE=""
if command -v baksmali >/dev/null 2>&1 && [[ "$INPUT" == *.dex ]]; then
    baksmali d "$INPUT" -o "$WORK/smali" >/dev/null 2>&1
    SMALI_FILE="$WORK/smali/$CLASS_PATH.smali"
elif command -v apktool >/dev/null 2>&1 && [[ "$INPUT" == *.apk ]]; then
    apktool d -f -o "$WORK/apktool" "$INPUT" >/dev/null 2>&1
    SMALI_FILE="$(find "$WORK/apktool" -path "*/$CLASS_PATH.smali" 2>/dev/null | head -1)"
elif [[ "$INPUT" == *.smali ]]; then
    SMALI_FILE="$INPUT"
fi

if [ -n "$SMALI_FILE" ] && [ -f "$SMALI_FILE" ]; then
    if [ -n "$METHOD" ]; then
        sed -n "/^\.method .*[ >]$METHOD(/,/^\.end method/p" "$SMALI_FILE"
        # Fall back to a looser match if the strict one found nothing.
        if ! grep -q "^\.method .*[ >]$METHOD(" "$SMALI_FILE"; then
            sed -n "/^\.method .*$METHOD/,/^\.end method/p" "$SMALI_FILE"
        fi
    else
        cat "$SMALI_FILE"
    fi
else
    echo "(skipped: no baksmali or apktool on PATH, and the input is not a .smali file)"
    echo
    echo " Install one of them, or use step 3 above -- fallback mode is a faithful rendering"
    echo " of control flow, it just drops the opcode mnemonics. For PATCHING you need real"
    echo " Smali and apktool; see ../../14-Dalvik/README.md section 6.3."
fi

# ------------------------------------------------------------------ 5. dexdump
banner "5. dexdump -- opcodes and file offsets"
DEXDUMP=""
if command -v dexdump >/dev/null 2>&1; then
    DEXDUMP="dexdump"
elif [ -n "${ANDROID_HOME:-}" ]; then
    for d in "$ANDROID_HOME"/build-tools/*/dexdump*; do
        [ -x "$d" ] && DEXDUMP="$d"
    done
fi

if [[ "$INPUT" == *.smali ]]; then
    echo "(skipped: the input is Smali, so there is no DEX file to dump."
    echo " Step 4 above already showed you the instruction stream, and it IS the input.)"
elif [ -n "$DEXDUMP" ]; then
    DEXFILE="$INPUT"
    if [[ "$INPUT" == *.apk ]]; then
        (cd "$WORK" && unzip -o -q "$(cd "$(dirname "$INPUT")" && pwd)/$(basename "$INPUT")" 'classes*.dex') 2>/dev/null
        DEXFILE="$WORK/classes.dex"
    fi
    if [ -f "$DEXFILE" ]; then
        if [ -n "$METHOD" ]; then
            "$DEXDUMP" -d "$DEXFILE" 2>/dev/null \
                | sed -n "/^ *[0-9a-f]*:.*$CLASS.$METHOD/,/^ *catches/p" | head -120
        else
            "$DEXDUMP" -d "$DEXFILE" 2>/dev/null \
                | sed -n "/Class descriptor  : 'L$CLASS_PATH;'/,/^ *source_file_idx/p" | head -200
        fi
    else
        echo "(skipped: could not extract a .dex from $INPUT)"
    fi
else
    echo "(skipped: no dexdump on PATH and \$ANDROID_HOME is unset)"
fi

banner "How to read this"
cat <<'EOF'
  (1) vs (2)  Every difference is a readability transformation jadx applied. A constant name
              that vanishes into a literal, a method body that appears in its caller, a
              string switch that unfolds into hashCode + equals -- none of those were in the
              bytecode in that form.

  (2) vs (3)  Every difference is STRUCTURE jadx inferred. Loops, if/else nesting and
              try/catch shape are asserted in (2) and merely annotated in (3).

  (3) vs (4)  Fallback mode drops opcode mnemonics and renames registers to rN. If (3) and
              (4) disagree about control flow, trust (4) and file a jadx issue.

  (4) vs (5)  dexdump adds file offsets and exact instruction encodings. This is the level
              at which arguments end.

  If your finding survives all five, write it down. If it changes between (1) and (3), your
  finding was about jadx, not about the app.
EOF
