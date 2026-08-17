#!/usr/bin/env bash
#
# find-reflection.sh — locate every reflection and dynamic-code-loading site in
#                      an Android application and group them into a triage
#                      worksheet.
#
# WHAT IT DOES
#   Disassembles an APK to Smali (or reuses a Smali tree you already have) and
#   searches it for the eight fingerprints that matter, reporting each group
#   separately with the reason it matters and the next question to ask:
#
#     1  Class.forName                    dynamic class resolution
#     2  member lookup                    getDeclaredMethod / getDeclaredField / ...
#     3  setAccessible(true)              deliberate access-control bypass
#     4  Method.invoke                    the reflective call itself
#     5  ClassLoader construction         DexClassLoader, PathClassLoader,
#                                         InMemoryDexClassLoader and friends
#     6  System.loadLibrary / load        logic pushed into native code
#     7  decoders next to the above       Base64 / Cipher, i.e. hidden names
#     8  const-string literals matching   http, api[_-]?key, secret, token,
#                                         password
#
#   For every Class.forName and member-lookup hit it also looks at the
#   instructions immediately above and reports whether the argument arrived as
#   a const-string (LITERAL — you have the name for free) or as a
#   move-result-object (COMPUTED — the name is being hidden, and that is the
#   part worth your afternoon). Finally it lists the files that appear in the
#   most categories, because co-location of all these fingerprints inside one
#   class is the single strongest static signal of deliberate concealment.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - Whether any hit is malicious. Every dependency-injection framework, every
#     JSON library and every AndroidX compatibility shim uses reflection. The
#     finding is never "the app uses reflection"; it is "the app resolves a
#     name it computed at runtime".
#   - What a COMPUTED name resolves to. This is a grep, not a symbolic
#     execution engine. Working out the value is your job, by hand from the
#     disassembly or dynamically with Frida.
#   - Anything happening in native code. A JNI call to GetMethodID does exactly
#     what Method.invoke does and leaves no Smali fingerprint at all.
#   - Anything inside a DEX that is decrypted at runtime by a packer, inside
#     assets/, or inside a downloaded payload.
#   - Reflection performed on your behalf by a library whose bytecode was
#     inlined or renamed by R8 — the call sites survive, the readable names do
#     not.
#
# USAGE
#   ./find-reflection.sh target.apk               # disassemble, then search
#   ./find-reflection.sh --smali smali_out        # search an existing tree
#   ./find-reflection.sh target.apk --out work/   # choose the work directory
#   ./find-reflection.sh --smali smali_out --max 500
#   ./find-reflection.sh --help
#
#   Exit status: 0 searched successfully (with or without hits),
#                1 bad arguments or unreadable input,
#                2 no disassembler available for APK mode.
#
# REQUIREMENTS
#   bash, plus the POSIX tools find, grep, sed, sort, uniq, awk, xargs.
#   APK mode additionally needs apktool OR baksmali on your PATH.
#   --smali mode needs no external tools at all, which is the fallback when
#   neither disassembler is installed.
#
#   On Windows run this from Git Bash or WSL. Windows PowerShell cannot execute
#   it; the Python companion dump-strings.py, next to this file, is the
#   cross-platform half of the pair.
#
# RELATED
#   ../README.md section 3.11              reflection, and why it exists
#   ../labs/lab-03-reflection-hunt.md      the CTF this script automates step 2 of
#   ../examples/ReflectionDemo.java        the same constructs from the developer side
#   ../../40-Obfuscation/README.md         what commercial packers add on top
#
# AUTHORISED TESTING ONLY. Only run this against applications you own or have
# written permission to test.

set -u

SELF="$(basename "$0")"
VERSION="1.0"

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------

TARGET=""
SMALI_DIR=""
OUT_DIR=""
MAX_DETAIL=200
MODE=""

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'
Options
  --smali DIR     search an existing baksmali/apktool output tree instead of
                  disassembling an APK. Needs no external tools.
  --out DIR       where to put the disassembly in APK mode
                  (default: a fresh directory under $TMPDIR)
  --max N         show at most N detailed hits per category (default 200);
                  totals are always reported in full
  -h, --help      this message

Examples
  ./find-reflection.sh target.apk
  ./find-reflection.sh --smali smali_out
  bash find-reflection.sh --smali smali_out | tee reflection-triage.txt
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --smali)
            if [ $# -lt 2 ]; then
                echo "$SELF: --smali needs a directory" >&2
                exit 1
            fi
            SMALI_DIR="$2"
            MODE="smali"
            shift 2
            ;;
        --out)
            if [ $# -lt 2 ]; then
                echo "$SELF: --out needs a directory" >&2
                exit 1
            fi
            OUT_DIR="$2"
            shift 2
            ;;
        --max)
            if [ $# -lt 2 ]; then
                echo "$SELF: --max needs a number" >&2
                exit 1
            fi
            MAX_DETAIL="$2"
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "$SELF: unknown option '$1'. Try --help." >&2
            exit 1
            ;;
        *)
            if [ -n "$TARGET" ]; then
                echo "$SELF: more than one target given ('$TARGET' and '$1')." >&2
                exit 1
            fi
            TARGET="$1"
            MODE="${MODE:-apk}"
            shift
            ;;
    esac
done

case "$MAX_DETAIL" in
    ''|*[!0-9]*)
        echo "$SELF: --max must be a whole number, got '$MAX_DETAIL'" >&2
        exit 1
        ;;
esac

if [ -z "$MODE" ]; then
    echo "$SELF: nothing to do." >&2
    echo "  Give an APK:            $SELF target.apk" >&2
    echo "  Or an existing tree:    $SELF --smali smali_out" >&2
    echo "  Full help:              $SELF --help" >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Resolve the Smali tree
# --------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

no_disassembler() {
    cat >&2 <<'EOF'
error: APK mode needs a disassembler, and neither apktool nor baksmali is on
       your PATH.

  Install ONE of them:

    apktool   (handles multidex, resources and the manifest in one step)
      Linux / macOS via package manager:
        sudo apt install apktool          # Debian, Ubuntu
        brew install apktool              # macOS
      Or download the wrapper script and jar from
        https://apktool.org/docs/install

    baksmali  (just the DEX disassembler, one jar, no dependencies)
      Download baksmali-<version>.jar from
        https://github.com/google/smali/releases
      Then either put a wrapper on your PATH:
        printf '#!/bin/sh\nexec java -jar /path/to/baksmali.jar "$@"\n' \
          > ~/bin/baksmali && chmod +x ~/bin/baksmali
      or disassemble by hand and use --smali:
        unzip -o target.apk 'classes*.dex' -d dexes/
        java -jar baksmali.jar d dexes/classes.dex -o smali_out
        ./find-reflection.sh --smali smali_out

  If you already have a Smali tree from any tool, skip disassembly entirely:
        ./find-reflection.sh --smali <that directory>
EOF
}

WORK=""
CLEANUP_WORK=0

if [ "$MODE" = "apk" ]; then
    if [ ! -f "$TARGET" ]; then
        echo "$SELF: '$TARGET' is not a readable file." >&2
        echo "  If you meant an already-disassembled tree, use --smali instead." >&2
        exit 1
    fi

    if [ -n "$OUT_DIR" ]; then
        WORK="$OUT_DIR"
        mkdir -p "$WORK" || exit 1
    else
        WORK="$(mktemp -d "${TMPDIR:-/tmp}/find-reflection.XXXXXX")" || exit 1
        CLEANUP_WORK=0   # deliberately kept: you will want to grep it afterwards
    fi

    if have apktool; then
        echo "[*] Disassembling with apktool into $WORK ..." >&2
        if ! apktool d -f -o "$WORK/apktool" "$TARGET" >"$WORK/apktool.log" 2>&1; then
            echo "$SELF: apktool failed. Its output is in $WORK/apktool.log" >&2
            echo "  Common causes: an unsupported resource table, or a framework" >&2
            echo "  resource the app depends on. You can bypass resources entirely" >&2
            echo "  with baksmali, or disassemble by hand and use --smali." >&2
            exit 1
        fi
        SMALI_DIR="$WORK/apktool"
    elif have baksmali; then
        echo "[*] Disassembling with baksmali into $WORK ..." >&2
        mkdir -p "$WORK/dexes"
        if have unzip; then
            unzip -o -q "$TARGET" 'classes*.dex' -d "$WORK/dexes" || true
        elif have python3; then
            python3 - "$TARGET" "$WORK/dexes" <<'PY'
import re, sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(src) as z:
    for name in z.namelist():
        if re.match(r'^classes\d*\.dex$', name):
            z.extract(name, dst)
PY
        else
            echo "$SELF: need unzip or python3 to pull classes*.dex out of the APK." >&2
            exit 2
        fi

        found=0
        for dex in "$WORK/dexes"/classes*.dex; do
            [ -f "$dex" ] || continue
            found=$((found + 1))
            base="$(basename "$dex" .dex)"
            baksmali d "$dex" -o "$WORK/smali_$base" >>"$WORK/baksmali.log" 2>&1 \
                || echo "$SELF: baksmali failed on $dex, see $WORK/baksmali.log" >&2
        done
        if [ "$found" -eq 0 ]; then
            echo "$SELF: no classes*.dex at the root of '$TARGET'." >&2
            echo "  That is what a packer looks like. List the archive with" >&2
            echo "  'unzip -l $TARGET | grep -i dex' and disassemble by hand." >&2
            exit 1
        fi
        SMALI_DIR="$WORK"
    else
        no_disassembler
        exit 2
    fi
fi

if [ ! -d "$SMALI_DIR" ]; then
    echo "$SELF: '$SMALI_DIR' is not a directory." >&2
    exit 1
fi

# --------------------------------------------------------------------------
# Build the file list once. Everything below reads it.
# --------------------------------------------------------------------------

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/find-reflection-scratch.XXXXXX")" || exit 1
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# Everything from here runs INSIDE the Smali tree and uses relative paths. That
# is not tidiness: grep prints "path:line:text", and on Windows an absolute path
# begins "C:/", so an absolute path would put a colon where the line number is
# supposed to be and every field would be parsed one position out.
cd "$SMALI_DIR" || exit 1
SMALI_DISPLAY="$(pwd)"

LIST="$SCRATCH/files.nul"
find . -type f -name '*.smali' -print0 >"$LIST" 2>/dev/null
FILE_COUNT="$(tr -dc '\0' <"$LIST" | wc -c | tr -d ' ')"

if [ "${FILE_COUNT:-0}" -eq 0 ]; then
    echo "$SELF: no .smali files under '$SMALI_DIR'." >&2
    echo "  Point --smali at the directory that CONTAINS the smali/ folders," >&2
    echo "  or at a smali/ folder itself. An apktool output directory has" >&2
    echo "  smali/, smali_classes2/ and so on inside it." >&2
    exit 1
fi

# search KEY REGEX  -> writes file:line:text hits to $SCRATCH/KEY.hits
search() {
    key="$1"
    pattern="$2"
    xargs -0 grep -nE -- "$pattern" /dev/null <"$LIST" >"$SCRATCH/$key.hits" 2>/dev/null
    return 0
}

# Fingerprints. These are Smali forms; the same constructs in JADX output read
# as ordinary Java, which is why the Smali is the ground truth.
search forname   'Ljava/lang/Class;->forName'
search lookup    '->(getDeclaredMethod|getMethod|getDeclaredField|getField|getDeclaredConstructor|getConstructor)\('
search access    '->setAccessible\(Z\)V'
search invoke    'Ljava/lang/reflect/(Method|Constructor);->(invoke|newInstance)'
search loader    '(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|BaseDexClassLoader|DelegateLastClassLoader|DexFile;->load)'
search native    'L(java/lang/System|java/lang/Runtime);->(loadLibrary|load)\('
search decode    '(Landroid/util/Base64;->decode|Ljava/util/Base64\$Decoder;->decode|Ljavax/crypto/Cipher;->doFinal|Ljavax/crypto/Cipher;->getInstance)'

# Interesting literals: const-string lines whose value looks like a secret or
# an endpoint. Two stages, because "const-string" alone matches half the app.
xargs -0 grep -nE -- 'const-string(/jumbo)? ' /dev/null <"$LIST" 2>/dev/null \
    | grep -Ei 'https?://|api[_-]?key|apikey|secret|token|password|passwd|bearer' \
    >"$SCRATCH/literals.hits" 2>/dev/null

count_of() {
    if [ -s "$SCRATCH/$1.hits" ]; then
        wc -l <"$SCRATCH/$1.hits" | tr -d ' '
    else
        echo 0
    fi
}

# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

RULE="=============================================================================="
THIN="------------------------------------------------------------------------------"

printf '\n%s\n' "$RULE"
printf ' REFLECTION AND DYNAMIC-LOADING TRIAGE   (find-reflection.sh %s)\n' "$VERSION"
printf '%s\n' "$RULE"
if [ "$MODE" = "apk" ]; then
    printf ' target      : %s\n' "$TARGET"
    printf ' disassembly : %s   (kept — grep it for follow-up)\n' "$SMALI_DISPLAY"
else
    printf ' smali tree  : %s\n' "$SMALI_DISPLAY"
fi
printf ' smali files : %s\n' "$FILE_COUNT"
printf ' generated   : %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf '%s\n' "$RULE"

# report KEY "TITLE" "WHY" "TRIAGE QUESTION" [backtrace]
report() {
    key="$1"; title="$2"; why="$3"; question="$4"; backtrace="${5:-no}"
    total="$(count_of "$key")"

    printf '\n%s\n' "$THIN"
    printf ' %s\n' "$title"
    printf ' hits: %s\n' "$total"
    printf '%s\n' "$THIN"
    printf '   why it matters : %s\n' "$why"
    printf '   ask of each    : %s\n' "$question"

    if [ "$total" -eq 0 ]; then
        printf '\n   No hits.\n'
        return 0
    fi

    printf '\n'
    shown=0
    while IFS= read -r hit; do
        shown=$((shown + 1))
        if [ "$shown" -gt "$MAX_DETAIL" ]; then
            printf '   ... %s more hit(s) suppressed; re-run with --max %s\n' \
                "$((total - MAX_DETAIL))" "$total"
            break
        fi

        file="${hit%%:*}"
        rest="${hit#*:}"
        line="${rest%%:*}"
        text="${rest#*:}"

        # Strip the leading whitespace Smali indents instructions with.
        text="$(printf '%s' "$text" | sed 's/^[[:space:]]*//')"
        printf '   %s:%s\n       %s\n' "${file#./}" "$line" "$text"

        if [ "$backtrace" = "yes" ]; then
            start=$((line - 8))
            [ "$start" -lt 1 ] && start=1
            window="$(sed -n "${start},${line}p" "$file" 2>/dev/null)"
            literal="$(printf '%s\n' "$window" | grep -E 'const-string(/jumbo)? ' | tail -1)"
            if [ -n "$literal" ]; then
                literal="$(printf '%s' "$literal" | sed 's/^[[:space:]]*//')"
                printf '       LITERAL   the name is right there: %s\n' "$literal"
            else
                printf '       COMPUTED  no const-string in the preceding 8 lines —\n'
                printf '                 trace the register backwards; this is the interesting case\n'
            fi
        fi
    done <"$SCRATCH/$key.hits"
    return 0
}

report forname "1. Class.forName — dynamic class resolution" \
    "Resolving a class by name defeats the static call graph." \
    "is the argument a const-string, or is it computed?" yes

report lookup "2. Member lookup — getDeclaredMethod / getDeclaredField" \
    "Names a method or field that the call graph will not show." \
    "same question: literal name, or assembled at runtime?" yes

report access "3. setAccessible(true) — access-control bypass" \
    "Deliberately disables the private/protected check." \
    "what is being reached that the API deliberately hid?"

report invoke "4. Method.invoke / Constructor.newInstance" \
    "The reflective call itself; the edge the call graph is missing." \
    "which object and which arguments reach it?"

report loader "5. ClassLoader construction — code from outside the APK" \
    "Turns code signing into an input-validation problem. Always investigate." \
    "where does the loaded file come from, and is it integrity-checked?"

report native "6. System.loadLibrary / System.load" \
    "Logic moved into native code, where DEX analysis cannot follow it." \
    "does the JNI surface include anything the Java side was hiding?"

report decode "7. Decoders — Base64 and Cipher" \
    "On its own, routine. Directly above a forName, it is string obfuscation." \
    "does its output feed a class name, a method name, or a URL?"

report literals "8. const-string literals that look like secrets" \
    "The plaintext the obfuscation did not cover." \
    "is this a real credential, a field name, or a log message?"

# --------------------------------------------------------------------------
# Co-location: the strongest single signal
# --------------------------------------------------------------------------

: >"$SCRATCH/colocation.txt"
for key in forname lookup access invoke loader native decode; do
    if [ -s "$SCRATCH/$key.hits" ]; then
        cut -d: -f1 <"$SCRATCH/$key.hits" | sort -u >>"$SCRATCH/colocation.txt"
    fi
done

printf '\n%s\n' "$RULE"
printf ' CO-LOCATION — files hitting the most categories\n'
printf '%s\n' "$RULE"
printf '   A compatibility shim calls forName with a literal and stops there. A\n'
printf '   class that resolves a computed name, looks up a computed member,\n'
printf '   disables the access check and invokes it — all in one file — is hiding\n'
printf '   something on purpose. Start at the top of this list.\n\n'

if [ -s "$SCRATCH/colocation.txt" ]; then
    sort "$SCRATCH/colocation.txt" | uniq -c | sort -rn | head -25 \
        | while IFS= read -r row; do
            n="$(printf '%s' "$row" | awk '{print $1}')"
            f="$(printf '%s' "$row" | awk '{$1=""; sub(/^ /, ""); print}')"
            printf '   %s of 7 categories   %s\n' "$n" "${f#./}"
          done
else
    printf '   No reflection fingerprints at all.\n\n'
    printf '   That is unusual for a real application and is itself worth a look.\n'
    printf '   Either the app is genuinely small, or the DEX you disassembled is a\n'
    printf '   loader stub and the real code is decrypted at runtime. Check the APK\n'
    printf '   for large opaque files under assets/ and lib/, and read\n'
    printf '   ../../40-Obfuscation/README.md.\n'
fi

# --------------------------------------------------------------------------
# Summary and next steps
# --------------------------------------------------------------------------

printf '\n%s\n' "$RULE"
printf ' SUMMARY\n'
printf '%s\n' "$RULE"
printf '   %-46s %s\n' "1. Class.forName"                "$(count_of forname)"
printf '   %-46s %s\n' "2. member lookup"                 "$(count_of lookup)"
printf '   %-46s %s\n' "3. setAccessible(true)"           "$(count_of access)"
printf '   %-46s %s\n' "4. Method.invoke / newInstance"   "$(count_of invoke)"
printf '   %-46s %s\n' "5. ClassLoader construction"      "$(count_of loader)"
printf '   %-46s %s\n' "6. System.loadLibrary / load"     "$(count_of native)"
printf '   %-46s %s\n' "7. Base64 / Cipher decoders"      "$(count_of decode)"
printf '   %-46s %s\n' "8. suspicious const-string"       "$(count_of literals)"

cat <<'EOF'

   NEXT STEPS, in the order that pays
     1. Work the COMPUTED hits in category 1 first. For each, open the file at
        the reported line and trace the register that supplies the argument
        backwards until you reach a const-string, a decoder, or a field.
     2. Then category 5. A ClassLoader over a downloaded or decrypted file is
        a finding on its own, regardless of what it loads.
     3. Confirm dynamically. One Frida hook on Class.forName and one on
        Method.invoke, logging every argument, defeats every static trick in
        this list, because whatever transformation the app applied must be
        undone before the runtime is called. See ../../53-Frida/README.md.
     4. Nothing here is a finding until you can name the method it lives in and
        say what it does. "The app uses reflection" is not a report line.

EOF

exit 0
