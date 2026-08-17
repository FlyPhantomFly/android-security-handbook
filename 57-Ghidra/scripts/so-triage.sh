#!/usr/bin/env bash
#
# so-triage.sh — command-line triage of every native library in an APK corpus.
#
# WHAT IT DOES
#   Extracts the native libraries from one or many APKs and produces:
#     1. A CSV inventory: hash, size, ABI, stripped?, JNI surface, dangerous
#        imports, notable strings.
#     2. A per-library text report with the full symbol and string detail.
#     3. Optionally, a Ghidra headless pass over only the libraries that the
#        cheap signals flagged as interesting.
#
# WHY YOU RUN THIS BEFORE OPENING GHIDRA
#   Ghidra's analysis of a large ARM64 library takes minutes and its GUI takes
#   a human. readelf and strings take milliseconds and take nobody. The whole
#   point of triage is to reduce forty applications to the five libraries a
#   person should actually look at.
#
#   The valuable output is not the absolute inventory. It is the DIFF between
#   this quarter's CSV and last quarter's: a new dangerous import, a library
#   that stopped being stripped, a jump in JNI surface. Those deltas are where
#   review effort belongs.
#
#   See ../README.md sections 8.1 and 9.5.
#
# USAGE
#   ./so-triage.sh <apk-or-directory> [output-dir]
#
#   ./so-triage.sh app-release.apk
#   ./so-triage.sh ./apk-corpus/ ./triage-out
#   GHIDRA_HOME=/opt/ghidra DEEP=1 ./so-triage.sh ./apk-corpus/ ./triage-out
#
# ENVIRONMENT
#   GHIDRA_HOME   Ghidra installation directory. Required only when DEEP=1.
#   DEEP          Set to 1 to run analyzeHeadless over flagged libraries.
#   ABI           Restrict to one ABI (default: all found).
#   SCRIPTS       Directory holding FindJNI.py (default: this script's directory).
#
# REQUIREMENTS
#   unzip, readelf (binutils), nm, strings, sha256sum, file
#   Optional: analyzeHeadless (Ghidra) when DEEP=1
#
# AUTHORISED TESTING ONLY. Analyse only binaries you own or are contracted to
# assess.

set -uo pipefail

# --------------------------------------------------------------------------- #
# arguments and environment
# --------------------------------------------------------------------------- #

TARGET="${1:?usage: so-triage.sh <apk-or-directory> [output-dir]}"
OUT="${2:-./so-triage-out}"
SCRIPTS="${SCRIPTS:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
DEEP="${DEEP:-0}"
ABI_FILTER="${ABI:-}"

mkdir -p "$OUT"
CSV="$OUT/inventory.csv"

# Pass stdin through, or emit "$*" if stdin was empty.
#
# The report below is a series of `producer | grep ... | head -N | sed ...`
# pipelines. Writing `|| echo "  (none)"` on the end of one of those is a trap:
# this script sets pipefail, so as soon as grep matches more than N lines head
# closes the pipe, grep dies of SIGPIPE with status 141, pipefail promotes that
# to the pipeline, and "(none)" is printed DIRECTLY BENEATH the N results that
# were just listed. The reader of the report then sees a full list of exports
# followed by the word "(none)". or_else tests the CONTENT instead, which is
# the question actually being asked.
or_else() {
  local out
  out="$(cat)"
  if [ -n "$out" ]; then printf '%s\n' "$out"; else printf '%s\n' "$*"; fi
}

# Dangerous or otherwise informative imports. Each tells you something about
# how to read the library, so they are grouped in the report.
IMPORTS_ANTI='ptrace|prctl|syscall|personality|sigaction'
IMPORTS_LOAD='dlopen|dlsym|android_dlopen_ext|mprotect|memfd_create|dl_iterate_phdr'
IMPORTS_EXEC='system|popen|execve|execl|execvp|posix_spawn|fork'
IMPORTS_FS='fopen|openat|access|faccessat|lstat|readlink|opendir'
IMPORTS_PROP='__system_property_get|__system_property_find'
IMPORTS_CRYPTO='HMAC_|EVP_|AES_|RAND_bytes|SSL_CTX_set_verify|SSL_CTX_set_custom_verify'
IMPORTS_ALL="$IMPORTS_ANTI|$IMPORTS_LOAD|$IMPORTS_EXEC|$IMPORTS_FS|$IMPORTS_PROP|$IMPORTS_CRYPTO"

STRINGS_INTERESTING='(^|/)su$|busybox|magisk|supersu|kernelsu|frida|gum-js|xposed|zygisk|TracerPid|/proc/self/(maps|status)|ro\.debuggable|ro\.secure|-----BEGIN|^https?://'

# --------------------------------------------------------------------------- #
# preflight
# --------------------------------------------------------------------------- #

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[-] required tool not found: $1" >&2
    return 1
  }
}

MISSING=0
for t in unzip readelf nm strings sha256sum file; do
  need "$t" || MISSING=1
done
[ "$MISSING" -eq 1 ] && exit 1

if [ "$DEEP" = "1" ]; then
  if [ -z "${GHIDRA_HOME:-}" ] || [ ! -x "$GHIDRA_HOME/support/analyzeHeadless" ]; then
    echo "[-] DEEP=1 requires GHIDRA_HOME to point at a Ghidra installation" >&2
    exit 1
  fi
  if [ ! -f "$SCRIPTS/FindJNI.py" ]; then
    echo "[-] FindJNI.py not found in $SCRIPTS (set SCRIPTS=...)" >&2
    exit 1
  fi
fi

# --------------------------------------------------------------------------- #
# collect the APK list
# --------------------------------------------------------------------------- #

APKS=()
if [ -d "$TARGET" ]; then
  while IFS= read -r -d '' a; do APKS+=("$a"); done \
    < <(find "$TARGET" -maxdepth 2 -type f -name '*.apk' -print0)
elif [ -f "$TARGET" ]; then
  APKS+=("$TARGET")
else
  echo "[-] not a file or directory: $TARGET" >&2
  exit 1
fi

if [ "${#APKS[@]}" -eq 0 ]; then
  echo "[-] no APKs found under $TARGET" >&2
  exit 1
fi

echo "[*] ${#APKS[@]} APK(s) to triage"
echo "[*] output -> $OUT"

printf 'apk,abi,library,sha256,size_bytes,stripped,jni_static,jni_onload,init_array,'
printf 'imports_anti,imports_load,imports_exec,imports_prop,imports_crypto,strings_flagged,verdict\n' \
  > "$CSV"

# --------------------------------------------------------------------------- #
# per-library analysis
# --------------------------------------------------------------------------- #

analyse_so() {
  local apkname="$1" abi="$2" so="$3"
  local name sha size stripped jnic onload initn
  local anti load exec_ prop crypto strflag verdict report

  name="$(basename "$so")"
  sha="$(sha256sum "$so" | cut -d' ' -f1)"
  size="$(stat -c%s "$so" 2>/dev/null || stat -f%z "$so")"

  # A .symtab section means the library was NOT stripped, which hands the
  # analyst every internal function name for free.
  if readelf -S "$so" 2>/dev/null | grep -q '\.symtab'; then
    stripped="no"
  else
    stripped="yes"
  fi

  # Statically registered JNI entry points.
  jnic="$(readelf --dyn-syms "$so" 2>/dev/null | grep -c ' Java_' || true)"

  # Dynamic registration indicator.
  if readelf --dyn-syms "$so" 2>/dev/null | grep -q 'JNI_OnLoad'; then
    onload="yes"
  else
    onload="no"
  fi

  # .init_array entries run at dlopen time, BEFORE JNI_OnLoad.
  initn="$(readelf -S "$so" 2>/dev/null \
           | awk '/\.init_array/ {getline; print strtonum("0x" $1)}' | head -1)"
  initn="${initn:-0}"

  # Imported functions by category. Undefined symbols are what the library
  # calls out to.
  local und
  und="$(readelf --dyn-syms "$so" 2>/dev/null | grep ' UND ' || true)"

  count_in() { echo "$und" | grep -coE "$1" || true; }
  anti="$(count_in "$IMPORTS_ANTI")"
  load="$(count_in "$IMPORTS_LOAD")"
  exec_="$(count_in "$IMPORTS_EXEC")"
  prop="$(count_in "$IMPORTS_PROP")"
  crypto="$(count_in "$IMPORTS_CRYPTO")"

  strflag="$(strings -a -n 5 "$so" 2>/dev/null | grep -cE "$STRINGS_INTERESTING" || true)"

  # The verdict is the whole point: it decides whether a human looks at this.
  verdict="skip"
  if [ "$jnic" -gt 0 ] || [ "$onload" = "yes" ]; then verdict="review"; fi
  if [ "$anti" -gt 0 ] || [ "$load" -gt 0 ] || [ "$exec_" -gt 0 ]; then verdict="priority"; fi
  if [ "$strflag" -gt 3 ] && [ "$verdict" != "priority" ]; then verdict="review"; fi

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$apkname" "$abi" "$name" "$sha" "$size" "$stripped" \
    "$jnic" "$onload" "$initn" \
    "$anti" "$load" "$exec_" "$prop" "$crypto" "$strflag" "$verdict" >> "$CSV"

  # ---- per-library detail report ----------------------------------------- #
  report="$OUT/$apkname/$abi-$name.txt"
  mkdir -p "$(dirname "$report")"

  {
    echo "==============================================================="
    echo " $apkname / $abi / $name"
    echo "==============================================================="
    echo " sha256   : $sha"
    echo " size     : $size bytes"
    echo " stripped : $stripped"
    echo " verdict  : $verdict"
    echo ""
    echo "--- file ---"
    file "$so"
    echo ""
    echo "--- ELF header ---"
    readelf -h "$so" 2>/dev/null | sed 's/^/  /'
    echo ""
    echo "--- needed libraries (DT_NEEDED) ---"
    readelf -d "$so" 2>/dev/null | grep NEEDED | sed 's/^/  /' || echo "  (none)"
    echo ""
    echo "--- statically registered JNI entry points ---"
    if [ "$jnic" -gt 0 ]; then
      nm -D --defined-only "$so" 2>/dev/null | grep ' T Java_' | sed 's/^/  /'
    else
      echo "  (none)"
      if [ "$onload" = "yes" ]; then
        echo "  JNI_OnLoad IS present -> registration is DYNAMIC."
        echo "  Recover the table with RecoverRegisterNatives.py, or at runtime"
        echo "  with ../../53-Frida/scripts/native-tracer.js"
      fi
    fi
    echo ""
    echo "--- other exported functions ---"
    nm -D --defined-only "$so" 2>/dev/null | grep ' T ' | grep -v ' Java_' \
      | head -60 | sed 's/^/  /' | or_else "  (none)"
    echo ""
    echo "--- imported functions of interest ---"
    echo "$und" | grep -oE "$IMPORTS_ALL" | sort | uniq -c | sort -rn | sed 's/^/  /' \
      || echo "  (none)"
    echo ""
    echo "--- all imports ---"
    echo "$und" | awk '{print $8}' | sort -u | head -120 | sed 's/^/  /'
    echo ""
    echo "--- strings of interest ---"
    strings -a -n 5 "$so" 2>/dev/null | grep -nE "$STRINGS_INTERESTING" \
      | head -80 | sed 's/^/  /' | or_else "  (none)"
    echo ""
    echo "--- JNI signature fragments (hint at the Java surface) ---"
    strings -a -n 4 "$so" 2>/dev/null \
      | grep -E '^\(\[?[BCDFIJSZL].*\)' | head -40 | sed 's/^/  /' | or_else "  (none)"
    echo ""
    echo "--- longest strings (often endpoints, keys, or format strings) ---"
    strings -a -n 24 "$so" 2>/dev/null | head -40 | sed 's/^/  /'
  } > "$report" 2>&1

  echo "    $abi/$name  [$verdict]  jni=$jnic onload=$onload anti=$anti load=$load"

  # ---- optional deep pass ------------------------------------------------- #
  if [ "$DEEP" = "1" ] && [ "$verdict" != "skip" ]; then
    local projdir ghidra_out
    projdir="$(mktemp -d)"
    ghidra_out="$OUT/$apkname/$abi-$name.ghidra.txt"
    echo "        running Ghidra headless (this takes minutes)..."
    "$GHIDRA_HOME/support/analyzeHeadless" "$projdir" "triage_$$" \
        -import "$so" \
        -scriptPath "$SCRIPTS" \
        -postScript FindJNI.py \
        -analysisTimeoutPerFile 900 \
        -max-cpu 4 \
        -deleteProject \
        > "$ghidra_out" 2>&1 \
      || echo "        [!] Ghidra analysis failed; see $ghidra_out" >&2
    rm -rf "$projdir"
  fi
}

# --------------------------------------------------------------------------- #
# main loop
# --------------------------------------------------------------------------- #

for apk in "${APKS[@]}"; do
  apkname="$(basename "$apk" .apk)"
  echo ""
  echo "[*] $apkname"

  work="$(mktemp -d)"
  # -qq to stay quiet; failures here just mean the APK has no native libs.
  unzip -qq -o "$apk" 'lib/*' -d "$work" 2>/dev/null || true

  if [ ! -d "$work/lib" ]; then
    echo "    (no native libraries)"
    rm -rf "$work"
    continue
  fi

  found=0
  for abidir in "$work"/lib/*/; do
    [ -d "$abidir" ] || continue
    abi="$(basename "$abidir")"
    if [ -n "$ABI_FILTER" ] && [ "$abi" != "$ABI_FILTER" ]; then continue; fi

    for so in "$abidir"*.so; do
      [ -f "$so" ] || continue
      analyse_so "$apkname" "$abi" "$so"
      found=$((found + 1))
    done
  done

  [ "$found" -eq 0 ] && echo "    (no .so files matched)"
  rm -rf "$work"
done

# --------------------------------------------------------------------------- #
# summary
# --------------------------------------------------------------------------- #

echo ""
echo "==============================================================="
echo " Triage complete"
echo "==============================================================="
echo " inventory : $CSV"
echo " reports   : $OUT/<apk>/<abi>-<lib>.txt"
echo ""
echo " Libraries by verdict:"
awk -F, 'NR>1 {print "   " $NF}' "$CSV" | sort | uniq -c | sort -rn
echo ""
echo " PRIORITY libraries (open these in Ghidra first):"
awk -F, 'NR>1 && $NF=="priority" {printf "   %-28s %-14s %s\n", $1, $2, $3}' "$CSV" \
  || echo "   (none)"
echo ""
echo " Next steps:"
echo "   1. Open a priority library in Ghidra."
echo "   2. Define JNIEnv immediately  (../README.md section 3.8)."
echo "   3. If jni_static is 0 and jni_onload is yes, run:"
echo "        RecoverRegisterNatives.py"
echo "   4. Confirm the library is ACTUALLY LOADED before investing further:"
echo "        adb shell cat /proc/\$(pidof <pkg>)/maps | grep '\\.so'"
echo ""
echo " The valuable query next quarter is the DIFF:"
echo "   diff previous/inventory.csv $CSV"
