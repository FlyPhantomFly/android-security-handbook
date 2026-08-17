#!/usr/bin/env bash
# so-triage.sh -- ninety seconds of native-library triage, before any GUI.
#
# PURPOSE
#     Answer the five questions that decide what you do next with a .so, in the
#     order you need them:
#
#       1. What is it?           architecture, size, hash, SONAME
#       2. What does it need?    DT_NEEDED, and what it imports
#       3. What does it offer?   exports, and specifically JNI entry points
#       4. How is it hardened?   the full chapter 15 checklist
#       5. What is it hiding?    string density, .init_array, packer markers
#
#     Opening a decompiler before answering these wastes an hour. The output is
#     designed to be pasted into notes as-is.
#
# USAGE
#     ./so-triage.sh libnative.so
#     ./so-triage.sh target_extracted/lib/arm64-v8a/*.so
#     ./so-triage.sh --apk target.apk           # triage every library inside
#
# REQUIREMENTS
#     bash, and Python 3 for the two scripts alongside this one. `readelf`,
#     `nm`, `objdump` and `strings` are USED IF PRESENT and skipped cleanly if
#     not -- on Windows, in a minimal container, or on a corporate laptop they
#     usually are not, which is why the Python fallbacks exist. `unzip` or
#     Python is needed for --apk.
#
# WHAT THIS WILL *NOT* TELL YOU
#     - Whether anything found is a vulnerability. It is triage: it tells you
#       where to look, never what to conclude. Every severity judgement in this
#       chapter is made by a human with README section 5.7 open.
#     - What the code does. No disassembly.
#     - Which third-party libraries are statically linked in, or their versions.
#       That is 17-Libraries/scripts/lib-fingerprint.py, and it is worth running
#       straight after this.
#     - Anything at run time. Nothing here executes the target.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null 2>&1 || PY=python
have() { command -v "$1" >/dev/null 2>&1; }

rule() { printf '%s\n' "------------------------------------------------------------------"; }
head2() { printf '\n== %s\n' "$1"; }

# Pass stdin through, or emit "$*" if stdin was empty.
#
# Do not write `... | grep X | head -30 || echo "none"` here. This script sets
# pipefail, so the moment grep matches more than 30 lines head closes the pipe,
# grep dies of SIGPIPE with status 141, pipefail promotes it to the pipeline,
# and the "none" message prints DIRECTLY BENEATH the thirty results that were
# just listed -- which, for the JNI check below, means announcing "this is not a
# JNI library" under a list of its JNI exports. or_else tests the CONTENT.
or_else() {
  local out
  out="$(cat)"
  if [ -n "$out" ]; then printf '%s\n' "$out"; else printf '%s\n' "$*"; fi
}

triage_one() {
  local SO="$1"
  printf '\n'
  rule
  printf '%s\n' "$SO"
  rule

  head2 "1. Identity"
  if have sha256sum; then sha256sum "$SO"
  elif have shasum; then shasum -a 256 "$SO"
  else "$PY" - "$SO" <<'PY'
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest(), sys.argv[1])
PY
  fi
  if have file; then file "$SO"; fi
  ls -l "$SO" 2>/dev/null | awk '{print "  size:", $5, "bytes"}'

  head2 "2. ELF header, segments and dependencies"
  if have readelf; then
    readelf -h "$SO" | grep -E 'Class|Data|Type|Machine|Entry'
    readelf -lW "$SO" | grep -E 'LOAD|GNU_STACK|GNU_RELRO|DYNAMIC'
    readelf -d "$SO" | grep -E 'NEEDED|SONAME|RPATH|RUNPATH'
  else
    echo "  (readelf not installed -- using elf-inspect.py)"
    "$PY" "$HERE/elf-inspect.py" "$SO" --header --segments 2>/dev/null | \
      grep -E 'e_type|e_machine|e_entry|LOAD|GNU_STACK|GNU_RELRO'
    "$PY" "$HERE/elf-inspect.py" "$SO" --dynamic 2>/dev/null | \
      grep -E 'NEEDED|SONAME|RPATH|RUNPATH'
  fi

  head2 "3. What it offers: exports and JNI entry points"
  if have readelf; then
    echo "  Java_* exports:"
    readelf --dyn-syms -W "$SO" 2>/dev/null | grep ' Java_' | head -30 | \
      or_else "    none -- registration is dynamic, or this is not a JNI library"
    readelf --dyn-syms -W "$SO" 2>/dev/null | grep -c 'JNI_OnLoad' | \
      awk '{print "  JNI_OnLoad present:", ($1>0 ? "yes" : "no")}'
  else
    "$PY" "$HERE/elf-inspect.py" "$SO" --dynsyms --defined-only --grep Java_ \
      2>/dev/null | head -30
    "$PY" "$HERE/elf-inspect.py" "$SO" --dynsyms --grep JNI_OnLoad 2>/dev/null | \
      grep -c JNI_OnLoad | awk '{print "  JNI_OnLoad present:", ($1>0?"yes":"no")}'
  fi

  head2 "4. Hardening checklist"
  "$PY" "$HERE/elf-harden-check.py" "$SO" 2>&1 | sed -n '/^\[/p'
  echo "  (run elf-harden-check.py --verbose for the evidence behind each line)"

  head2 "5. What it might be hiding"
  if have strings; then
    local nstr bytes
    nstr=$(strings -a -n 6 "$SO" 2>/dev/null | wc -l | tr -d ' ')
    bytes=$(wc -c < "$SO" | tr -d ' ')
    echo "  $nstr strings of 6+ chars in $bytes bytes"
    echo "  markers:"
    strings -a -n 5 "$SO" 2>/dev/null | \
      grep -aE '^/system|^/sbin|^/data/|su$|magisk|zygisk|frida|gum-js|xposed|LSPosed|ro\.debuggable|ro\.secure|TracerPid|/proc/self/(maps|status)|libhoudini|^https?://' | \
      sort -u | head -25 | or_else "    none of the usual markers"
  else
    echo "  (strings not installed -- reading .rodata with elf-inspect.py)"
    "$PY" "$HERE/elf-inspect.py" "$SO" --strings --min 6 2>/dev/null | \
      grep -aE 'system/|/sbin|magisk|frida|xposed|ro\.debuggable|TracerPid|proc/self|https?://' | \
      head -25
  fi
  echo "  constructors that run before JNI_OnLoad:"
  # Only the .preinit_array/.init_array block -- .fini_array runs at unload and
  # is a different question, so printing it here would be misleading.
  "$PY" "$HERE/elf-inspect.py" "$SO" --init 2>/dev/null | awk '
      /DT_INIT / { print; next }
      /preinit_array at|[^i]init_array at/ { show=1; print; next }
      /fini_array at/ { show=0 }
      show && /^ +\[[0-9]+\]/ { print }
  ' || echo "    none"

  head2 "Next"
  cat <<'NEXT'
  - Read every .init_array entry first: it runs before anything else.
  - Take any Java_* export back to the Java class it names (56-JADX).
  - If there are no Java_* exports but JNI_OnLoad exists, recover the
    RegisterNatives table at run time (57-Ghidra section 7.2).
  - Fingerprint the bundled third-party libraries next:
    17-Libraries/scripts/lib-fingerprint.py
  - Only then open a decompiler.
NEXT
}

main() {
  if [ "$#" -eq 0 ]; then
    echo "usage: $0 <library.so> [more.so ...]" >&2
    echo "       $0 --apk <app.apk>" >&2
    exit 2
  fi
  if [ "$1" = "--apk" ]; then
    local apk="${2:?--apk needs a path}"
    local tmp
    tmp="$(mktemp -d 2>/dev/null || echo "./so-triage-$$")"
    mkdir -p "$tmp"
    # Python, not unzip, on purpose. Under Git Bash / MSYS on Windows the
    # argument `lib/*` is path-mangled before unzip ever sees it and the
    # extraction silently matches nothing. zipfile has no such problem, and
    # Python is already a hard requirement of this script.
    "$PY" - "$apk" "$tmp" <<'PY'
import sys, zipfile
apk, out = sys.argv[1], sys.argv[2]
n_found = 0
with zipfile.ZipFile(apk) as z:
    for n in z.namelist():
        if n.startswith('lib/') and n.endswith('.so'):
            z.extract(n, out)
            n_found += 1
print("  extracted %d native libraries" % n_found)
PY
    local found=0
    while IFS= read -r f; do
      found=1
      triage_one "$f"
    done < <(find "$tmp" -name '*.so' 2>/dev/null | sort)
    [ "$found" -eq 0 ] && echo "no lib/**/*.so entries in $apk"
    echo
    echo "extracted libraries left in $tmp"
    return 0
  fi
  for f in "$@"; do
    [ -f "$f" ] || { echo "skipping $f (not a file)"; continue; }
    triage_one "$f"
  done
}

main "$@"
