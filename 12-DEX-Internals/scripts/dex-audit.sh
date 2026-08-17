#!/usr/bin/env bash
#
# dex-audit.sh — repeatable DEX-level audit of an APK.
#
# WHAT IT DOES
#   Runs the triage from ../README.md section 8 across EVERY classes*.dex in an
#   APK — not just the first, which is the mistake that makes people conclude a
#   feature is absent when it is sitting in classes2.dex.
#
#   For each DEX it reports:
#     - magic and version, and what that version implies
#     - header table sizes, with a warning near the 64K reference limit
#     - structural integrity: header_size, endian_tag, checksum, signature
#     - MAP COVERAGE — uncovered regions mean a hidden payload
#     - string pool extraction with the high-value regex sweep
#     - hardcoded byte arrays (candidate keys)
#     - native method count, as a measure of how much logic left the DEX
#     - obfuscation assessment from class-name length distribution
#
# HOW TO RUN
#   ./dex-audit.sh target.apk
#   ./dex-audit.sh target.apk /path/to/output-dir
#   ./dex-audit.sh /path/to/classes.dex          # a bare DEX also works
#
# REQUIREMENTS
#   Required : unzip, python3, awk, grep
#   Optional : dexdump, baksmali (much better output when present)
#
#   dexdump ships in the Android SDK build-tools. baksmali:
#     https://github.com/google/smali
#
# EXIT CODES
#   0 ok · 1 usage · 2 input unreadable
#
# NOTE
#   Everything this reports is a LEAD, not a finding. A 16-byte array is a key
#   candidate, not a key. Validate before reporting — see ../../52-StaticAnalysis/.

set -uo pipefail

INPUT="${1:-}"
OUTDIR="${2:-}"

if [[ -z "$INPUT" || ! -f "$INPUT" ]]; then
    sed -n '3,32p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER="$SCRIPT_DIR/../examples/dex_parser.py"
ARRAYS="$SCRIPT_DIR/../examples/find_array_literals.py"

[[ -z "$OUTDIR" ]] && OUTDIR="$(basename "${INPUT%.*}")-dexaudit"
mkdir -p "$OUTDIR"

hr()  { printf '\n===== %s %s\n' "$1" "$(printf '=%.0s' $(seq 1 $((60 - ${#1}))))"; }
sub() { printf '\n--- %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- collect ---

DEXDIR="$OUTDIR/dex"
mkdir -p "$DEXDIR"

if [[ "$INPUT" == *.dex ]]; then
    cp "$INPUT" "$DEXDIR/"
else
    unzip -o "$INPUT" 'classes*.dex' -d "$DEXDIR" >/dev/null 2>&1 || {
        echo "error: no classes*.dex found in $INPUT" >&2; exit 2; }
fi

DEXFILES=("$DEXDIR"/classes*.dex)
if [[ ! -e "${DEXFILES[0]}" ]]; then
    echo "error: no DEX files extracted" >&2; exit 2
fi

{
hr "INPUT"
echo "  file    : $INPUT"
if have sha256sum; then sha256sum "$INPUT" | awk '{print "  sha256  : " $1}'
elif have shasum;    then shasum -a 256 "$INPUT" | awk '{print "  sha256  : " $1}'; fi
echo "  dex files: ${#DEXFILES[@]}"
for f in "${DEXFILES[@]}"; do
    printf '    %-16s %12s bytes\n' "$(basename "$f")" "$(wc -c < "$f" | tr -d ' ')"
done

if [[ ${#DEXFILES[@]} -gt 1 ]]; then
    echo
    echo "  MULTIDEX. All ${#DEXFILES[@]} files are analysed below."
    echo "  Index numbers are PER FILE — method@0x100 in classes.dex and in"
    echo "  classes2.dex are unrelated. See README section 3.28."
fi

# ------------------------------------------------------------- per DEX -----

for DEX in "${DEXFILES[@]}"; do
    NAME="$(basename "$DEX")"
    hr "$NAME"

    sub "magic and version"
    MAGIC=$(head -c 8 "$DEX" | tr -d '\0')
    printf '  %s\n' "$MAGIC"
    VER="${MAGIC:4:3}"
    case "$VER" in
        035) echo "  version 035 — the long-standing baseline" ;;
        037) echo "  version 037 — Android 7.0; default/static interface methods" ;;
        038) echo "  version 038 — Android 8.0; invoke-polymorphic, invoke-custom, method handles" ;;
        039) echo "  version 039 — Android 9; hidden-API data, const-method-handle" ;;
        *)   echo "  version $VER — unrecognised. Verify with dexdump." ;;
    esac

    sub "header and structural integrity"
    if [[ -f "$PARSER" ]]; then
        python3 "$PARSER" "$DEX" --verify-header 2>&1 | sed 's/^/  /'
    else
        echo "  dex_parser.py not found at $PARSER"
    fi

    sub "map coverage (the packer detector)"
    if [[ -f "$PARSER" ]]; then
        python3 "$PARSER" "$DEX" --map-coverage 2>&1 \
            | grep -vE '^\s*~?\s*0x[0-9a-f]{8}-0x[0-9a-f]{8}\s+TYPE_' \
            | sed 's/^/  /'
        echo "  (per-section ranges suppressed; run --map-coverage directly for the full list)"
    fi

    sub "string pool — high-value patterns"
    if [[ -f "$PARSER" ]]; then
        python3 "$PARSER" "$DEX" --strings 2>/dev/null \
            | sed 's/^\s*\[[ 0-9]*\] //' > "$OUTDIR/$NAME.strings.txt"
        COUNT=$(wc -l < "$OUTDIR/$NAME.strings.txt" | tr -d ' ')
        echo "  $COUNT strings written to $NAME.strings.txt"
        echo
        for pat_desc in \
            'https\?://[^ "]\{8,\}|URLs' \
            'AIza[0-9A-Za-z_-]\{35\}|Google API key' \
            'AKIA[0-9A-Z]\{16\}|AWS access key id' \
            'eyJ[A-Za-z0-9_-]\{10,\}\.[A-Za-z0-9_-]\{10,\}|JWT' \
            '-----BEGIN [A-Z ]*PRIVATE KEY-----|private key' \
            '[a-z0-9.-]*\.firebaseio\.com|Firebase DB' \
            's3[.-][a-z0-9-]*\.amazonaws\.com|S3 bucket' \
            'AES/[A-Z]*/[A-Za-z0-9]*|cipher transformation' \
            ; do
            pat="${pat_desc%%|*}"; desc="${pat_desc##*|}"
            hits=$(grep -aoE "$pat" "$OUTDIR/$NAME.strings.txt" 2>/dev/null | sort -u | head -8)
            if [[ -n "$hits" ]]; then
                echo "  [$desc]"
                echo "$hits" | sed 's/^/      /'
            fi
        done
        echo
        echo "  NOTE: a public Firebase Web API key is BY DESIGN public and is"
        echo "        not a finding on its own. Validate every hit."
    fi

    sub "hardcoded byte arrays (candidate keys)"
    if [[ -f "$ARRAYS" ]]; then
        python3 "$ARRAYS" "$DEX" --keys-only 2>&1 \
            | head -60 | sed 's/^/  /'
    else
        echo "  find_array_literals.py not found at $ARRAYS"
    fi

    sub "class and method inventory"
    if have dexdump; then
        dexdump -f "$DEX" 2>/dev/null \
            | grep -E 'string_ids_size|type_ids_size|proto_ids_size|field_ids_size|method_ids_size|class_defs_size' \
            | sed 's/^/  /'
    fi

    if have baksmali; then
        baksmali list classes "$DEX" 2>/dev/null | sort > "$OUTDIR/$NAME.classes.txt"
        CLS=$(wc -l < "$OUTDIR/$NAME.classes.txt" | tr -d ' ')
        echo "  $CLS classes written to $NAME.classes.txt"

        sub "obfuscation assessment"
        echo "  class-name length distribution (short names = heavy renaming):"
        awk -F'/' '{print $NF}' "$OUTDIR/$NAME.classes.txt" \
            | sed 's/;$//' | awk '{print length($0)}' \
            | sort -n | uniq -c | head -12 | sed 's/^/    /'
        SHORT=$(awk -F'/' '{print $NF}' "$OUTDIR/$NAME.classes.txt" \
                | sed 's/;$//' | awk 'length($0)<=2' | wc -l | tr -d ' ')
        if [[ "$CLS" -gt 0 ]]; then
            PCT=$(( SHORT * 100 / CLS ))
            echo "    $SHORT of $CLS classes ($PCT%) have names of 1-2 characters"
            if [[ "$PCT" -gt 40 ]]; then
                echo "    -> aggressive obfuscation. See ../../41-ProGuard/ for what survives."
            elif [[ "$PCT" -gt 10 ]]; then
                echo "    -> partial obfuscation, likely library code only."
            else
                echo "    -> little or no name obfuscation."
            fi
        fi
    else
        echo "  baksmali not installed — class inventory and obfuscation"
        echo "  assessment skipped. Install from https://github.com/google/smali"
    fi
done

# ------------------------------------------------------------- summary -----

hr "NEXT STEPS"
cat <<'EOF'
  1. Read the strings file in full. It is the single richest source of
     endpoints, error messages and feature hints:
         less <outdir>/classes.dex.strings.txt

  2. If map coverage reported uncovered regions, investigate them. A
     legitimate d8 output has none. See README sections 3.22 and 5.2.

  3. For each candidate key, find what it is USED for before reporting:
         baksmali d classes.dex -o smali/
         grep -rn 'SecretKeySpec\|IvParameterSpec' smali/

  4. Confirm at runtime rather than guessing:
         frida -U -f <pkg> -l ../../34-Cryptography/scripts/jca-dump.js

  5. If the installed app may differ from this APK, extract the DEX the
     device is actually running (README section 7.1):
         oatdump --vdex-file=<...>/base.vdex --export-dex-to=/data/local/tmp/dex_out

  Everything above is a LEAD. Validate before it enters a report.
EOF

hr "DONE"
echo "  Output directory: $OUTDIR"

} 2>&1 | tee "$OUTDIR/audit-report.txt"
