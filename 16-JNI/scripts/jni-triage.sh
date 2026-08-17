#!/usr/bin/env bash
#
# jni-triage.sh -- offline inventory of an APK's Java-to-native bridge.
#
# WHAT IT DOES
#     Runs the triage sequence from ../README.md section 8.5 against one APK
#     and prints five reports:
#
#       1. every native method declared in the DEX, with its descriptor
#       2. every exported Java_* symbol in every shipped .so, demangled
#       3. which libraries export JNI_OnLoad (dynamic registration likely)
#       4. the JNI signature and class-name string constants in each .so
#       5. THE DIFF: native methods with no matching exported symbol
#
#     Report 5 is the point of the script. Every method in it is either
#     dynamically registered -- go recover it at runtime with
#     scripts/dump-registernatives.js -- or is declared and never implemented.
#
# WHY OFFLINE FIRST
#     Because it costs nothing, needs no device, and tells you where to spend
#     the expensive runtime work. An app whose entire native surface shows up
#     in report 2 needs no dynamic recovery at all. An app with an empty
#     report 2 and a populated report 3 is telling you it expected analysis.
#
# HOW TO RUN
#     ./jni-triage.sh app.apk
#     ./jni-triage.sh app.apk --abi arm64-v8a
#     ./jni-triage.sh app.apk --keep      # leave the work directory in place
#
# REQUIREMENTS
#     bash, unzip, and Python 3 (for the demangler next to this script).
#     apktool  -- for the DEX side. Without it, reports 1 and 5 are skipped.
#     nm and strings from binutils or llvm  -- for reports 2, 3 and 4.
#                     On a Mac, `brew install binutils` and use gnm/gstrings,
#                     or use the NDK's llvm-nm and llvm-strings.
#     Set NM=... and STRINGS=... to override the tool names.
#
# WHAT THIS WILL NOT TELL YOU
#     - Anything about dynamically registered methods beyond their existence.
#       Their name, signature and address live only in memory. This script
#       cannot see them; dump-registernatives.js can.
#     - Whether a native method is ever actually called.
#     - Whether a symbol in report 2 is the real implementation or a stub.
#     - Which ABI the device will actually load. It reports every ABI shipped.
#     - Anything about a packed app whose real library is decrypted at
#       runtime. The .so in the APK may be a loader, not the payload.
#     - The return type of a demangled long-form symbol; JNI does not encode
#       it. Cross-reference report 1 for that.

set -u

APK=""
ABI_FILTER=""
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --abi)  ABI_FILTER="${2:-}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h|--help)
      sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) APK="$1"; shift ;;
  esac
done

if [ -z "$APK" ] || [ ! -f "$APK" ]; then
  echo "usage: $0 <app.apk> [--abi arm64-v8a] [--keep]" >&2
  exit 1
fi

NM="${NM:-nm}"
STRINGS="${STRINGS:-strings}"
PY="${PY:-python3}"
HERE="$(cd "$(dirname "$0")" && pwd)"
MANGLER="$HERE/jni_mangle.py"

have() { command -v "$1" >/dev/null 2>&1; }

WORK="$(mktemp -d 2>/dev/null || mktemp -d -t jnitriage)"
cleanup() { [ "$KEEP" -eq 1 ] || rm -rf "$WORK"; }
trap cleanup EXIT

echo "=============================================================="
echo " JNI triage: $APK"
echo " work dir  : $WORK"
echo "=============================================================="

# ---------------------------------------------------------------- 0. unpack
unzip -oq "$APK" 'lib/*' -d "$WORK/libs" 2>/dev/null || true
SO_LIST="$(find "$WORK/libs" -name '*.so' 2>/dev/null | sort)"
if [ -n "$ABI_FILTER" ]; then
  SO_LIST="$(printf '%s\n' "$SO_LIST" | grep "/$ABI_FILTER/" || true)"
fi

if [ -z "$SO_LIST" ]; then
  echo
  echo "[!] No .so files under lib/ in this APK."
  echo "    Either the app has no native code, or it downloads its libraries"
  echo "    at runtime (look for System.load with an absolute path)."
fi

# ------------------------------------------------- 1. native methods in DEX
echo
echo "== 1. Native methods declared in the DEX =="
DEX_METHODS="$WORK/dex_natives.txt"
: > "$DEX_METHODS"

if have apktool; then
  apktool d -f -o "$WORK/smali" "$APK" >/dev/null 2>&1 || true
  if [ -d "$WORK/smali" ]; then
    # Reconstruct pkg.Class from the smali file path, then the method line.
    find "$WORK/smali" -name '*.smali' -print0 2>/dev/null \
    | xargs -0 grep -l 'native' 2>/dev/null \
    | while IFS= read -r f; do
        cls="$(printf '%s' "$f" \
               | sed -E 's#^.*/smali[^/]*/##; s#\.smali$##; s#/#.#g')"
        grep -E '^\.method .*\bnative\b' "$f" 2>/dev/null \
        | sed -E "s#^\.method (.*)\$#${cls}\t\1#"
      done | sort -u > "$DEX_METHODS"
  fi
fi

if [ -s "$DEX_METHODS" ]; then
  awk -F'\t' '{printf "  %-52s %s\n", $1, $2}' "$DEX_METHODS"
  echo "  ---"
  echo "  total: $(wc -l < "$DEX_METHODS" | tr -d ' ')"
else
  if have apktool; then
    echo "  (none found)"
  else
    echo "  (skipped: apktool not on PATH -- reports 1 and 5 need it)"
  fi
fi

# --------------------------------------------- 2. exported Java_* symbols
echo
echo "== 2. Exported Java_* symbols (static registration) =="
SYMS="$WORK/symbols.txt"
: > "$SYMS"

if have "$NM"; then
  for so in $SO_LIST; do
    rel="${so#"$WORK/libs/"}"
    got="$("$NM" -D --defined-only "$so" 2>/dev/null | awk '$2=="T" || $2=="t" {print $3}' \
           | grep '^Java_' | sort -u || true)"
    if [ -n "$got" ]; then
      echo "  [$rel]"
      printf '%s\n' "$got" | while IFS= read -r s; do
        echo "      $s"
        printf '%s\n' "$s" >> "$SYMS"
        if [ -f "$MANGLER" ] && have "$PY"; then
          "$PY" "$MANGLER" --demangle "$s" 2>/dev/null \
            | awk -F': *' '/^class/{c=$2} /^method/{m=$2} /^parameters/{p=$2} \
                            END{if(c!="") printf "          -> %s.%s  %s\n", c, m, p}'
        fi
      done
    fi
  done
  [ -s "$SYMS" ] || echo "  (none -- see report 3)"
else
  echo "  (skipped: '$NM' not on PATH; set NM=llvm-nm or NM=gnm)"
fi

# ------------------------------------------- 3. dynamic registration signal
echo
echo "== 3. Libraries exporting JNI_OnLoad (dynamic registration likely) =="
if have "$NM"; then
  any=0
  for so in $SO_LIST; do
    rel="${so#"$WORK/libs/"}"
    if "$NM" -D "$so" 2>/dev/null | grep -q 'JNI_OnLoad'; then
      nsym="$("$NM" -D --defined-only "$so" 2>/dev/null | grep -c ' Java_' || true)"
      echo "  $rel   (exported Java_* symbols: $nsym)"
      any=1
    fi
  done
  [ "$any" -eq 1 ] || echo "  (none)"
  echo
  echo "  A library here with 0 exported Java_* symbols registers everything"
  echo "  dynamically. Recover it at runtime:"
  echo "      frida -U -f <pkg> -l $HERE/dump-registernatives.js --no-pause"
else
  echo "  (skipped: '$NM' not on PATH)"
fi

# ------------------------------------------------ 4. JNI string constants
echo
echo "== 4. JNI signature and class-name constants =="
if have "$STRINGS"; then
  for so in $SO_LIST; do
    rel="${so#"$WORK/libs/"}"
    sigs="$("$STRINGS" -a "$so" 2>/dev/null | grep -E '^\([A-Z\[L]' | sort -u | head -40 || true)"
    cls="$("$STRINGS" -a "$so" 2>/dev/null \
           | grep -E '^[a-z][a-z0-9]*(/[A-Za-z0-9_$]+)+$' | sort -u | head -40 || true)"
    if [ -n "$sigs" ] || [ -n "$cls" ]; then
      echo "  [$rel]"
      [ -n "$cls" ]  && printf '%s\n' "$cls"  | sed 's/^/      class:  /'
      [ -n "$sigs" ] && printf '%s\n' "$sigs" | sed 's/^/      sig:    /'
    fi
  done
  echo
  echo "  These survive dynamic registration: RegisterNatives needs the name"
  echo "  and signature as plain strings. FindClass takes 'pkg/Class' with no"
  echo "  L or ';'; a descriptor in a signature is 'Lpkg/Class;'."
else
  echo "  (skipped: '$STRINGS' not on PATH)"
fi

# -------------------------------------------------------------- 5. the diff
echo
echo "== 5. Native methods with NO matching exported symbol =="
if [ -s "$DEX_METHODS" ] && [ -f "$MANGLER" ] && have "$PY"; then
  MISSING=0
  # Rebuild each declared method's expected short symbol and look for it.
  while IFS="$(printf '\t')" read -r cls decl; do
    name="$(printf '%s' "$decl" | sed -E 's/^.*[[:space:]]([A-Za-z0-9_$<>]+)\(.*$/\1/')"
    [ -n "$name" ] || continue
    short="$("$PY" "$MANGLER" --mangle "${cls}.${name}" 2>/dev/null \
             | awk -F': *' '/^short symbol/{print $2}')"
    [ -n "$short" ] || continue
    if ! grep -q "^${short}" "$SYMS" 2>/dev/null; then
      echo "  $cls.$name"
      echo "      expected symbol: $short   -- NOT FOUND"
      MISSING=$((MISSING + 1))
    fi
  done < "$DEX_METHODS"
  if [ "$MISSING" -eq 0 ]; then
    echo "  (none -- every declared native method has an exported symbol)"
  else
    echo "  ---"
    echo "  $MISSING method(s) unaccounted for. Each is either dynamically"
    echo "  registered or never implemented. Next step:"
    echo "      frida -U -f <pkg> -l $HERE/dump-registernatives.js --no-pause"
  fi
else
  echo "  (skipped: needs both report 1 and the demangler)"
fi

echo
echo "=============================================================="
[ "$KEEP" -eq 1 ] && echo " kept: $WORK"
echo " done"
echo "=============================================================="
