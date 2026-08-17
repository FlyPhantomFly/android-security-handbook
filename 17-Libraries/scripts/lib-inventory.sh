#!/usr/bin/env bash
#
# lib-inventory.sh -- Phase 1 and Phase 2 of the chapter 17 methodology:
#                     enumerate EVERY library in an APK, from every angle
#                     README section 8 describes, and say which angle each
#                     answer came from.
#
# WHAT IT DOES
#   README section 8.1 prints the first few lines of this script inline and
#   then says "scripts/lib-inventory.sh handles the fallbacks". This is that
#   script, and the fallbacks are the point. Android library tooling is a pile
#   of optional binaries -- baksmali, dexdump, apktool, aapt2, jadx, readelf --
#   and on any given machine you have some subset. A tool that only works with
#   all of them is a tool you cannot rely on at the start of an engagement.
#
#   So every enumeration in here has a chain, and the report says which link
#   of the chain produced the answer, because "apktool was not installed"
#   changes how much weight you should give a section.
#
#     Container listing   unzip -> zipinfo -> python3 zipfile
#     Class inventory     baksmali -> dexdump -f -> apkanalyzer -> jadx
#                         -> ./lib-fingerprint.py (pure Python DEX parse)
#     Manifest            apktool -> aapt2 dump xmltree
#                         -> 10-APK-Internals/examples/parse_axml.py
#                         -> raw string scan of the binary XML, clearly
#                            labelled as the guess that it is
#     Native analysis     readelf -> llvm-readelf -> objdump
#                         -> ./lib-fingerprint.py (pure Python ELF parse)
#     Hashing             sha256sum -> shasum -> certutil -> python3
#
#   Everything it emits is EVIDENCE, filed under $OUT/, one file per angle,
#   so that the next build can be diffed against this one. See README section
#   9.5 on why the diff, not the report, is what makes this repeatable.
#
#   Sections produced:
#     00-identity        hashes and sizes of every input
#     01-inputs          the splits, and a warning if you passed only one
#     02-native          per-.so: ABI, DT_NEEDED, build ID, compiler,
#                        hardening, statically linked third-party code
#     03-stamps          META-INF/*.version -- the cheapest exact versions
#     04-extra-code      code in assets/ and res/raw/ that is not classes.dex
#     05-managed         class inventory, collapsed to package prefixes and
#                        annotated with the vendor each prefix belongs to
#     06-manifest        providers, authorities, permissions, meta-data,
#                        exported components -- the SDK surface that survives
#                        obfuscation
#     07-code-loading    DexClassLoader / System.load / dlopen indicators
#     08-summary         counts, the tools that were missing, and what each
#                        missing tool cost you
#
# WHAT THIS WILL *NOT* TELL YOU
#   - What is actually LOADED. Every line here comes from a file on disk. A
#     .so in lib/ may never be dlopen'd and a class in the DEX may never be
#     resolved. The authority is /proc/<pid>/maps on a running process --
#     README section 7.1. Reachability is what turns an inventory row into a
#     finding, and this script cannot see it.
#   - The version of most libraries. It reports the stamps and banners it can
#     read literally. Everything else needs triangulation: run
#     ./lib-fingerprint.py, which implements README section 3.7.
#   - Whether anything here is a vulnerability. No CVE database is consulted.
#     An outdated library is not a finding on its own -- see ../faq.md.
#   - Anything about a split you did not pass. Run it over every path that
#     `adb shell pm path <pkg>` printed, or use --pm to have it pull them.
#   - Anything hidden by a packer. If the DEX is encrypted in an asset, this
#     will faithfully report a nearly empty class list and a large opaque
#     asset. That combination is the signal; chapter 40 is where you take it.
#   - Whether a package prefix means what it says. The vendor annotations in
#     section 05 are a lookup table, and a table is a starting point, not an
#     authority. Malware imitates well-known prefixes; shading relocates real
#     ones. Corroborate before you name a vendor in a report -- ../labs/
#     lab-05-ctf-library-that-lied.md is that lesson.
#
# HOW TO RUN
#     # host
#     ./lib-inventory.sh app.apk
#     bash lib-inventory.sh app.apk                 # if the execute bit is gone
#
#     # every split, which is what you should normally do
#     ./lib-inventory.sh base.apk split_config.arm64_v8a.apk split_config.en.apk
#     ./lib-inventory.sh /path/to/splits/*.apk
#
#     # pull the splits off the device first, then inventory them
#     ./lib-inventory.sh --pm com.example.target
#
#     # somewhere other than ./inventory/<name>/<timestamp>
#     ./lib-inventory.sh -o /tmp/work app.apk
#
# REQUIREMENTS
#   bash and coreutils. Everything else is optional and the script says what
#   it lost when a tool is absent. python3 is strongly recommended: it is the
#   last link of four different fallback chains, and with it present this
#   script produces a useful inventory on a machine with no Android tooling
#   installed at all.
#
# RELATED
#   ../README.md section 8.1        the five-phase methodology this automates
#   ../README.md section 8.2        the grep and readelf commands it wraps
#   ../README.md section 9.5        the diff-driven enterprise pipeline
#   ./lib-fingerprint.py            phase 2: which VERSION, with evidence
#   ../labs/lab-01-library-inventory.md   the lab this was written for
#   ../../10-APK-Internals/scripts/apk-recon.sh   container-level recon
#   ../../10-APK-Internals/examples/parse_axml.py the manifest fallback parser
#
# AUTHORISED TESTING ONLY. Only run this against applications you have written
# permission to test.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FINGERPRINT="${SCRIPT_DIR}/lib-fingerprint.py"
AXML_PARSER="${SCRIPT_DIR}/../../10-APK-Internals/examples/parse_axml.py"

MISSING=""       # newline-separated "tool: what you lost"
ROUTES=""        # newline-separated "section: which fallback produced it"
OUT=""
INPUTS=""        # newline-separated apk paths
PKG=""

# ---------------------------------------------------------------------------
# Plumbing
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

note_missing() { MISSING="${MISSING}${1}: ${2}"$'\n'; }
note_route()   { ROUTES="${ROUTES}${1}: ${2}"$'\n'; }

say() { printf '%s\n' "$*"; }
hdr() { printf '\n== %s\n' "$*"; }

# Pass stdin through, or emit "$*" if stdin was empty.
#
# This exists because `pipeline || say "(none)"` is not a reliable way to say
# "print a placeholder when there was nothing to show". This script sets
# `pipefail` (line 107), so the pipeline's status is the first non-zero status
# in it, and there are two ways that goes wrong:
#
#   1. NO FALLBACK WHEN THERE SHOULD BE ONE. If no stage reports emptiness with
#      a non-zero status -- `readelf -p .comment "$so" | sed -n '3p'` is the
#      case below -- every stage exits 0, so the `||` branch is unreachable and
#      the script prints NOTHING where it promised "(none)".
#
#   2. A FALLBACK WHEN THERE SHOULD NOT BE. `grep ... | head -40 | sed ...`
#      looks safe, but as soon as grep matches more than 40 lines head closes
#      the pipe, grep dies of SIGPIPE with status 141, pipefail promotes that to
#      the pipeline, and "(none)" is printed DIRECTLY BENEATH the forty results
#      that were just listed. Verified: `seq 1 2000000 | grep -E '[0-9]' |
#      head -3` exits 141 under pipefail.
#
# Both failures are silent and both are worst exactly when the output matters.
# or_else decides on the CONTENT it actually received, which is the question
# being asked, rather than on an exit status that was never about content.
or_else() {
    local out
    out="$(cat)"
    if [ -n "$out" ]; then printf '%s\n' "$out"; else printf '%s\n' "$*"; fi
}

PY=""
if have python3; then PY=python3
elif have python; then PY=python
else
    note_missing "python3" \
        "four fallback chains lose their last link: DEX class listing, ELF \
analysis, binary manifest decoding and zip reading all degrade to the \
weakest available option"
fi

# --- zip abstraction -------------------------------------------------------
# Three ways to list a zip, three ways to read one entry. Everything else in
# this script is written against these two functions.

zlist() {   # zlist <apk>  -> entry names, one per line
    local apk="$1"
    if have unzip; then
        unzip -Z1 "$apk" 2>/dev/null && return 0
    fi
    if have zipinfo; then
        zipinfo -1 "$apk" 2>/dev/null && return 0
    fi
    if [ -n "$PY" ]; then
        "$PY" -c 'import sys,zipfile
try:
    z=zipfile.ZipFile(sys.argv[1])
except Exception as e:
    sys.stderr.write("zip open failed: %s\n"%e); sys.exit(1)
for n in z.namelist(): print(n)' "$apk" 2>/dev/null && return 0
    fi
    return 1
}

zread() {   # zread <apk> <entry> -> bytes on stdout
    local apk="$1" entry="$2"
    if have unzip; then
        unzip -p "$apk" "$entry" 2>/dev/null && return 0
    fi
    if [ -n "$PY" ]; then
        "$PY" -c 'import sys,zipfile
z=zipfile.ZipFile(sys.argv[1])
sys.stdout.buffer.write(z.read(sys.argv[2]))' "$apk" "$entry" 2>/dev/null && return 0
    fi
    return 1
}

zextract() {  # zextract <apk> <destdir> [pattern]
    local apk="$1" dest="$2" pat="${3:-}"
    mkdir -p "$dest"
    if have unzip; then
        if [ -n "$pat" ]; then
            unzip -o -q "$apk" "$pat" -d "$dest" 2>/dev/null && return 0
        else
            unzip -o -q "$apk" -d "$dest" 2>/dev/null && return 0
        fi
    fi
    if [ -n "$PY" ]; then
        "$PY" -c 'import sys,zipfile,fnmatch,os
apk,dest = sys.argv[1],sys.argv[2]
pat = sys.argv[3] if len(sys.argv)>3 else ""
z=zipfile.ZipFile(apk)
for n in z.namelist():
    if n.endswith("/"): continue
    if pat and not fnmatch.fnmatch(n,pat): continue
    # Refuse absolute paths and ..: a malicious APK can name entries that
    # escape the extraction directory (10-APK-Internals calls this zip slip).
    tgt=os.path.normpath(os.path.join(dest,n))
    if not os.path.abspath(tgt).startswith(os.path.abspath(dest)):
        sys.stderr.write("skipped traversal entry: %s\n"%n); continue
    os.makedirs(os.path.dirname(tgt),exist_ok=True)
    open(tgt,"wb").write(z.read(n))' "$apk" "$dest" "$pat" 2>/dev/null && return 0
    fi
    return 1
}

sha256_of() {
    local f="$1"
    if have sha256sum; then sha256sum "$f" | awk '{print $1}'; return; fi
    if have shasum; then shasum -a 256 "$f" | awk '{print $1}'; return; fi
    if have certutil; then
        certutil -hashfile "$f" SHA256 2>/dev/null | sed -n '2p' | tr -d ' \r'
        return
    fi
    if [ -n "$PY" ]; then
        "$PY" -c 'import hashlib,sys
print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$f"
        return
    fi
    echo "(no hashing tool available)"
}

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

usage() {
    sed -n '2,90p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage 0 ;;
        -o|--out)  shift; OUT="${1:-}" ;;
        --pm)      shift; PKG="${1:-}" ;;
        -*)        say "unknown option: $1"; usage 1 ;;
        *)         INPUTS="${INPUTS}${1}"$'\n' ;;
    esac
    shift
done

# --pm: pull every split off the device. This is the case people get wrong.
if [ -n "$PKG" ]; then
    if ! have adb; then
        say "error: --pm needs adb on PATH"
        exit 2
    fi
    PULLDIR="${OUT:-inventory}/pulled-$PKG"
    mkdir -p "$PULLDIR"
    say "== pulling every APK path for $PKG"
    PATHS="$(adb shell pm path "$PKG" 2>/dev/null | tr -d '\r' | sed 's/^package://')"
    if [ -z "$PATHS" ]; then
        say "error: pm path returned nothing. Is $PKG installed on the "
        say "       connected device? Is the device authorised (adb devices)?"
        exit 2
    fi
    while IFS= read -r p; do
        [ -z "$p" ] && continue
        base="$(basename "$p")"
        say "   $p"
        adb pull "$p" "$PULLDIR/$base" >/dev/null 2>&1 \
            && INPUTS="${INPUTS}${PULLDIR}/${base}"$'\n' \
            || say "   ! pull failed for $p"
    done <<EOF
$PATHS
EOF
fi

INPUTS="$(printf '%s' "$INPUTS" | sed '/^$/d')"
if [ -z "$INPUTS" ]; then
    say "error: no APK given."
    say "usage: lib-inventory.sh [-o OUTDIR] app.apk [split.apk ...]"
    say "       lib-inventory.sh --pm com.example.target"
    exit 2
fi

FIRST="$(printf '%s\n' "$INPUTS" | head -1)"
NAME="$(basename "$FIRST" .apk)"
STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo manual)"
OUT="${OUT:-inventory}/$NAME/$STAMP"
mkdir -p "$OUT"

# ---------------------------------------------------------------------------
# 00 -- identity
# ---------------------------------------------------------------------------

{
say "# 00 identity"
while IFS= read -r apk; do
    [ -z "$apk" ] && continue
    if [ ! -f "$apk" ]; then
        say "MISSING FILE: $apk"
        continue
    fi
    size="$(wc -c < "$apk" | tr -d ' ')"
    say "$(sha256_of "$apk")  ${size}  ${apk}"
done <<EOF
$INPUTS
EOF
} | tee "$OUT/00-identity.txt"

# ---------------------------------------------------------------------------
# 01 -- inputs and splits
# ---------------------------------------------------------------------------

{
say "# 01 inputs"
n_inputs="$(printf '%s\n' "$INPUTS" | sed '/^$/d' | wc -l | tr -d ' ')"
say "APKs given: $n_inputs"
printf '%s\n' "$INPUTS"

# A base.apk sitting next to split_*.apk that you did NOT pass is the single
# most common way to produce an inventory that is quietly wrong: native
# libraries live in split_config.<abi>.apk on a bundle build.
dir="$(dirname "$FIRST")"
siblings="$(ls "$dir" 2>/dev/null | grep -E '^split[_.-].*\.apk$' || true)"
if [ -n "$siblings" ]; then
    say ""
    say "SPLITS FOUND NEXT TO THE INPUT:"
    printf '%s\n' "$siblings" | sed 's/^/  /'
    passed_all=1
    while IFS= read -r s; do
        [ -z "$s" ] && continue
        printf '%s\n' "$INPUTS" | grep -q "$s" || passed_all=0
    done <<EOF
$siblings
EOF
    if [ "$passed_all" -eq 0 ]; then
        say ""
        say "  *** You did not pass all of them. On an App Bundle build the"
        say "  *** native libraries are in split_config.<abi>.apk and the"
        say "  *** resources are in split_config.<lang>.apk. An inventory"
        say "  *** built from base.apk alone will report ZERO .so files and"
        say "  *** be wrong. Pass every split, or use --pm."
    fi
else
    say ""
    say "No sibling split_*.apk files in $dir."
    say "If the app is installed, confirm with: adb shell pm path <package>"
fi
} | tee "$OUT/01-inputs.txt"

# ---------------------------------------------------------------------------
# 02 -- native libraries
# ---------------------------------------------------------------------------

READELF=""
for cand in readelf llvm-readelf eu-readelf; do
    if have "$cand"; then READELF="$cand"; break; fi
done
if [ -z "$READELF" ]; then
    if [ -n "$PY" ] && [ -f "$FINGERPRINT" ]; then
        note_route "02-native" "lib-fingerprint.py ELF parser (no readelf on PATH)"
    else
        note_missing "readelf (binutils / llvm)" \
            "no ELF analysis at all: no DT_NEEDED, no build IDs, no symbol \
families, so statically linked OpenSSL/zlib/SQLite inside a .so stays invisible"
    fi
else
    note_route "02-native" "$READELF"
fi

RAW="$OUT/raw"
mkdir -p "$RAW"

{
say "# 02 native libraries"
say ""
say "## every .so, per input"
found_any=0
while IFS= read -r apk; do
    [ -z "$apk" ] || [ ! -f "$apk" ] && continue
    listing="$(zlist "$apk")" || { say "  ! cannot list $apk"; continue; }
    sos="$(printf '%s\n' "$listing" | grep -E '^lib/[^/]+/.*\.so$' | sort)"
    abis="$(printf '%s\n' "$listing" | grep -oE '^lib/[^/]+/' | sort -u)"
    say ""
    say "### $apk"
    if [ -z "$sos" ]; then
        say "  (no lib/*/*.so entries)"
    else
        found_any=1
        printf '%s\n' "$sos" | sed 's/^/  /'
        say "  ABIs: $(printf '%s' "$abis" | tr '\n' ' ')"
    fi
done <<EOF
$INPUTS
EOF

if [ "$found_any" -eq 0 ]; then
    say ""
    say "No native libraries in any input. Three explanations, and they are"
    say "not equally likely:"
    say "  1. the app is pure managed code (common for simple apps);"
    say "  2. the .so files are in a split you did not pass (see 01);"
    say "  3. the app loads native code at RUNTIME from its data directory,"
    say "     which is the most interesting of the three. Section 07 looks"
    say "     for the System.load and dlopen call sites that would prove it."
fi

say ""
say "## per-library detail"
while IFS= read -r apk; do
    [ -z "$apk" ] || [ ! -f "$apk" ] && continue
    zextract "$apk" "$RAW/$(basename "$apk")" 'lib/*' >/dev/null 2>&1
done <<EOF
$INPUTS
EOF

find "$RAW" -name '*.so' 2>/dev/null | sort | while IFS= read -r so; do
    say ""
    say "### $so"
    say "  size: $(wc -c < "$so" | tr -d ' ') bytes"
    if [ -n "$READELF" ]; then
        say "  -- header"
        "$READELF" -h "$so" 2>/dev/null | grep -E 'Class|Type:|Machine' \
            | sed 's/^/    /'
        say "  -- DT_NEEDED (what it expects the platform to provide)"
        "$READELF" -d "$so" 2>/dev/null | grep NEEDED | sed 's/^/    /' \
            | or_else "    (none)"
        say "  -- build ID (identifies this exact build; README 3.7 T4)"
        "$READELF" -n "$so" 2>/dev/null | grep -A1 'Build ID' | tail -1 \
            | sed 's/^/    /' | or_else "    (none -- itself a signal)"
        say "  -- compiler (.comment)"
        "$READELF" -p .comment "$so" 2>/dev/null | sed -n '3p' | sed 's/^/    /' \
            | or_else "    (none)"
        say "  -- hardening"
        if "$READELF" -l "$so" 2>/dev/null | grep -q GNU_RELRO; then
            say "    RELRO=yes"; else say "    RELRO=NO"; fi
        if "$READELF" -d "$so" 2>/dev/null | grep -qE 'BIND_NOW|FLAGS.*NOW'; then
            say "    BINDNOW=yes"; else say "    BINDNOW=NO"; fi
        if "$READELF" --dyn-syms "$so" 2>/dev/null | grep -q '__stack_chk_fail'; then
            say "    CANARY=yes"; else say "    CANARY=NO"; fi
        say "  -- constructors (.init_array: runs inside dlopen, BEFORE"
        say "     JNI_OnLoad -- see ../labs/lab-04-constructor-hook.md)"
        "$READELF" -S --wide "$so" 2>/dev/null | grep -E '\.init_array|\.preinit_array' \
            | sed 's/^/    /' | or_else "    (none)"
        say "  -- statically linked third-party code (README 3.7 T3)"
        syms="$("$READELF" --dyn-syms --wide "$so" 2>/dev/null | awk '{print $8}')"
        printf '%s\n' "$syms" | grep -qE '^(SSL_|EVP_|X509_)' && say "    OpenSSL or BoringSSL"
        printf '%s\n' "$syms" | grep -qE '^png_'      && say "    libpng"
        printf '%s\n' "$syms" | grep -qE '^(jpeg_|tj)' && say "    libjpeg / libjpeg-turbo"
        printf '%s\n' "$syms" | grep -qE '^sqlite3_'  && say "    SQLite"
        printf '%s\n' "$syms" | grep -qE '^curl_'     && say "    libcurl"
        printf '%s\n' "$syms" | grep -qE '^(av_|avcodec_|avformat_)' && say "    FFmpeg"
        printf '%s\n' "$syms" | grep -qE '^(BZ2_|lzma_|ZSTD_|LZ4_)' && say "    a compression library"
        printf '%s\n' "$syms" | grep -qE '^inflate'   && say "    zlib"
        printf '%s\n' "$syms" | grep -q  '^av_register_all$' \
            && say "    FFmpeg older than 4.0 (av_register_all was deprecated in 4.0)"
        say "  -- JNI shape"
        printf '%s\n' "$syms" | grep -q '^JNI_OnLoad$' \
            && say "    JNI_OnLoad present: natives may be bound with RegisterNatives," \
            && say "    so an absence of Java_* symbols does NOT mean an absence of JNI"
        printf '%s\n' "$syms" | grep -oE '^Java_[A-Za-z0-9_]+' | sort -u | head -20 \
            | sed 's/^/    /'
    elif [ -n "$PY" ] && [ -f "$FINGERPRINT" ]; then
        say "  (readelf absent -- using the pure-Python ELF parser)"
        "$PY" "$FINGERPRINT" "$so" 2>&1 | sed -n '/=== EVIDENCE ===/,/=== SIGNALS/p' \
            | sed 's/^/    /'
    else
        say "  (no ELF tooling available: install binutils, or python3 so that"
        say "   lib-fingerprint.py can do it)"
    fi
    say "  -- version banners (README 3.7 T1)"
    if have strings; then
        strings -a -n 6 "$so" 2>/dev/null | grep -aoiE \
          'OpenSSL [0-9][^ ]*|libcurl/[0-9.]+|FFmpeg version [^ ]+|libpng version [0-9.]+|inflate [0-9.]+ Copyright|libjpeg-turbo version [0-9.]+' \
          | sort -u | sed 's/^/    /' | or_else "    (none found)"
    elif [ -n "$PY" ]; then
        "$PY" -c 'import re,sys
b=open(sys.argv[1],"rb").read()
pats=[rb"OpenSSL [0-9][^\x00 ]*",rb"libcurl/[0-9.]+",rb"FFmpeg version [^\x00 ]+",
      rb"libpng version [0-9.]+",rb"inflate [0-9.]+ Copyright",
      rb"libjpeg-turbo version [0-9.]+"]
seen=set()
for p in pats:
    for m in re.findall(p,b):
        s=m.decode("utf-8","replace")
        if s not in seen:
            seen.add(s); print("   ",s)
if not seen: print("    (none found)")' "$so"
    else
        say "    (no strings and no python3)"
    fi
done
} | tee "$OUT/02-native.txt"

# ---------------------------------------------------------------------------
# 03 -- version stamps (README 3.7 technique 5)
# ---------------------------------------------------------------------------

{
say "# 03 version stamps (META-INF/*.version)"
say ""
say "These are literal strings the build system wrote. When present they are"
say "the cheapest exact versions you will ever get. They are also a plain"
say "text file inside a zip, so a repackager can edit them -- corroborate"
say "anything that matters with ./lib-fingerprint.py."
say ""
total=0
while IFS= read -r apk; do
    [ -z "$apk" ] || [ ! -f "$apk" ] && continue
    listing="$(zlist "$apk")" || continue
    stamps="$(printf '%s\n' "$listing" | grep -E '^META-INF/.*\.version$' | sort)"
    [ -z "$stamps" ] && continue
    say "## $apk"
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        val="$(zread "$apk" "$f" 2>/dev/null | tr -d '\r\n')"
        printf '  %-64s %s\n' "${f#META-INF/}" "$val"
        total=$((total + 1))
    done <<EOF
$stamps
EOF
done <<EOF
$INPUTS
EOF
if [ "$total" -eq 0 ]; then
    say "(none)"
    say ""
    say "No stamps. Either this build strips META-INF, or it ships no AndroidX"
    say "or Google artifacts that write them. Absence is not evidence of"
    say "absence of those libraries -- check the class inventory in 05."
fi
} | tee "$OUT/03-stamps.txt"

# ---------------------------------------------------------------------------
# 04 -- code that is not classes.dex and not lib/
# ---------------------------------------------------------------------------

{
say "# 04 extra code in assets and resources"
say ""
say "Anything here is a second place code can come from, and therefore a"
say "second place to repeat this entire inventory. A .dex or .so in assets/"
say "is ring 3 in README section 2's model, and ring 3 is usually the"
say "finding."
say ""
hits=0
while IFS= read -r apk; do
    [ -z "$apk" ] || [ ! -f "$apk" ] && continue
    listing="$(zlist "$apk")" || continue
    extra="$(printf '%s\n' "$listing" \
        | grep -iE '^(assets|res/raw)/.*\.(dex|jar|apk|zip|so|bundle|js|lua|wasm|bin|dat)$' | sort)"
    if [ -n "$extra" ]; then
        say "## $apk"
        printf '%s\n' "$extra" | sed 's/^/  /'
        hits=1
    fi
    # Framework markers -- these change what the rest of the analysis means.
    fw="$(printf '%s\n' "$listing" | grep -E \
        '^(assets/bin/Data/|flutter_assets/|assets/index\.android\.bundle|lib/[^/]+/libflutter\.so|lib/[^/]+/libunity\.so|lib/[^/]+/libil2cpp\.so|lib/[^/]+/libhermes\.so|lib/[^/]+/libreactnative)' \
        | head -8)"
    if [ -n "$fw" ]; then
        say "## $apk -- cross-platform framework markers"
        printf '%s\n' "$fw" | sed 's/^/  /'
        say "  A framework app keeps most of its logic OUTSIDE the DEX. The"
        say "  managed class inventory in 05 will look small and boring and"
        say "  will be telling you the truth about the wrong layer."
    fi
done <<EOF
$INPUTS
EOF
[ "$hits" -eq 0 ] && say "(no executable-looking assets found)"
} | tee "$OUT/04-extra-code.txt"

# ---------------------------------------------------------------------------
# 05 -- managed class inventory  (the fallback chain README 8.1 refers to)
# ---------------------------------------------------------------------------

CLASSLIST="$OUT/05-classes.txt"
: > "$CLASSLIST"
CLASS_ROUTE=""

list_classes_for() {   # list_classes_for <apk> -> dotted class names on stdout
    local apk="$1"
    if have baksmali; then
        if baksmali list classes "$apk" 2>/dev/null | sed 's#^L##; s#;$##' \
             | tr '/' '.' | grep . ; then
            CLASS_ROUTE="baksmali list classes"; return 0
        fi
    fi
    if have dexdump; then
        # dexdump -f prints one "Class descriptor" line per class.
        local tmp; tmp="$(mktemp -d 2>/dev/null || echo "$OUT/dexdump-tmp")"
        mkdir -p "$tmp"
        if zextract "$apk" "$tmp" 'classes*.dex' >/dev/null 2>&1; then
            if find "$tmp" -name 'classes*.dex' -exec dexdump -f {} \; 2>/dev/null \
                 | grep -oE "Class descriptor +: +'L[^']+'" \
                 | sed "s#.*'L##; s#;'\$##" | tr '/' '.' | grep . ; then
                CLASS_ROUTE="dexdump -f"; rm -rf "$tmp"; return 0
            fi
        fi
        rm -rf "$tmp"
    fi
    if have apkanalyzer; then
        if apkanalyzer dex packages --defined-only "$apk" 2>/dev/null \
             | awk '$1=="C"{print $NF}' | grep . ; then
            CLASS_ROUTE="apkanalyzer dex packages"; return 0
        fi
    fi
    if have jadx; then
        local tmp; tmp="$OUT/jadx-tmp"
        if jadx --no-src -d "$tmp" "$apk" >/dev/null 2>&1; then
            if find "$tmp" -name '*.java' 2>/dev/null \
                 | sed "s#^$tmp/sources/##; s#\.java\$##" | tr '/' '.' | grep . ; then
                CLASS_ROUTE="jadx --no-src tree walk"; rm -rf "$tmp"; return 0
            fi
        fi
        rm -rf "$tmp"
    fi
    if [ -n "$PY" ] && [ -f "$FINGERPRINT" ]; then
        if "$PY" "$FINGERPRINT" "$apk" --list-classes 2>/dev/null | grep . ; then
            CLASS_ROUTE="lib-fingerprint.py --list-classes (pure Python DEX parse)"
            return 0
        fi
    fi
    return 1
}

while IFS= read -r apk; do
    [ -z "$apk" ] || [ ! -f "$apk" ] && continue
    list_classes_for "$apk" >> "$CLASSLIST" 2>/dev/null
done <<EOF
$INPUTS
EOF

sort -u -o "$CLASSLIST" "$CLASSLIST" 2>/dev/null

if [ -s "$CLASSLIST" ]; then
    note_route "05-managed" "${CLASS_ROUTE:-unknown}"
else
    note_missing "baksmali / dexdump / apkanalyzer / jadx / python3" \
        "no managed class inventory, which is the single biggest gap this \
script can have: third-party Java and Kotlin code is most of a modern app"
fi

# The Phase 2 prefix-to-vendor map from README section 8.1. Extend it as you
# work; it becomes one of your most valuable personal assets. It is a lookup
# table, not an authority -- confirm the vendor from strings and endpoints
# before you name them in a report.
vendor_for() {
    case "$1" in
        okhttp3*|okio*)                  echo "OkHttp / Okio (HTTP)";;
        retrofit2*)                      echo "Retrofit (HTTP)";;
        com.google.gson*)                echo "Gson (JSON)";;
        com.squareup.moshi*)             echo "Moshi (JSON)";;
        com.fasterxml.jackson*)          echo "Jackson (JSON)";;
        io.reactivex*|rx.*)              echo "RxJava (async)";;
        kotlinx.coroutines*)             echo "Coroutines (async)";;
        kotlin.*|kotlinx.*)              echo "Kotlin runtime";;
        androidx.*)                      echo "Jetpack / AndroidX";;
        android.support.*)               echo "legacy Support Library";;
        com.google.android.gms.ads*)     echo "Google Mobile Ads (advertising)";;
        com.google.android.gms*)         echo "Google Play services";;
        com.google.firebase.crashlytics*) echo "Crashlytics (crash reporting)";;
        com.google.firebase*)            echo "Firebase";;
        com.google.android.datatransport*) echo "Firebase/GMS transport (telemetry)";;
        com.crashlytics*)                echo "Crashlytics, Fabric era";;
        com.bumptech.glide*)             echo "Glide (image loading)";;
        coil*)                           echo "Coil (image loading)";;
        com.squareup.picasso*)           echo "Picasso (image loading)";;
        com.facebook.drawee*|com.facebook.imagepipeline*) echo "Fresco (image loading)";;
        com.facebook.react*)             echo "React Native (framework)";;
        io.flutter*)                     echo "Flutter (framework)";;
        com.unity3d.ads*)                echo "Unity Ads (advertising)";;
        com.unity3d*)                    echo "Unity (game engine)";;
        org.cocos2dx*)                   echo "Cocos2d-x (game engine)";;
        com.google.android.exoplayer2*)  echo "ExoPlayer (media)";;
        androidx.media3*)                echo "Media3 (media)";;
        com.google.protobuf*)            echo "Protocol Buffers (serialisation)";;
        io.grpc*)                        echo "gRPC (RPC)";;
        org.apache.commons*)             echo "Apache Commons (utility)";;
        org.bouncycastle*|org.spongycastle*) echo "BouncyCastle / SpongyCastle (crypto)";;
        com.google.crypto.tink*)         echo "Tink (crypto)";;
        net.sqlcipher*)                  echo "SQLCipher (encrypted DB)";;
        io.realm*)                       echo "Realm (database)";;
        androidx.room*)                  echo "Room (database)";;
        com.j256.ormlite*)               echo "ORMLite (database)";;
        io.sentry*)                      echo "Sentry (crash reporting)";;
        com.bugsnag*)                    echo "Bugsnag (crash reporting)";;
        com.microsoft.appcenter*)        echo "App Center (crash + analytics)";;
        com.amplitude*)                  echo "Amplitude (analytics)";;
        com.mixpanel*)                   echo "Mixpanel (analytics)";;
        com.segment.analytics*)          echo "Segment (analytics)";;
        com.appsflyer*)                  echo "AppsFlyer (attribution)";;
        com.adjust.sdk*)                 echo "Adjust (attribution)";;
        com.applovin*)                   echo "AppLovin (advertising)";;
        com.ironsource*)                 echo "ironSource (advertising)";;
        com.stripe.android*)             echo "Stripe (payments)";;
        com.braintreepayments*)          echo "Braintree (payments)";;
        com.paypal*)                     echo "PayPal (payments)";;
        com.android.billingclient*)      echo "Play Billing (payments)";;
        com.facebook.android*|com.facebook.login*) echo "Facebook SDK (social/login)";;
        net.openid.appauth*)             echo "AppAuth (OAuth)";;
        com.auth0*)                      echo "Auth0 (auth)";;
        com.onesignal*)                  echo "OneSignal (push)";;
        com.urbanairship*|com.airship*)  echo "Airship (push/engagement)";;
        com.braze*|com.appboy*)          echo "Braze (engagement)";;
        zendesk*|com.zendesk*)           echo "Zendesk (support)";;
        com.intercom*)                   echo "Intercom (support)";;
        com.google.android.play.core*)   echo "Play Core (dynamic features)";;
        *)                               echo "";;
    esac
}

{
say "# 05 managed class inventory"
say ""
if [ ! -s "$CLASSLIST" ]; then
    say "No class inventory could be produced. See 08 for what was missing."
else
    total="$(wc -l < "$CLASSLIST" | tr -d ' ')"
    say "Classes defined across all inputs: $total"
    say "Route taken: ${CLASS_ROUTE:-unknown}"
    say ""
    if [ "$total" -lt 400 ]; then
        say "Fewer than 400 classes is small for a commercial app. Consider:"
        say "  - a packer (the real DEX is decrypted at runtime; chapter 40);"
        say "  - a cross-platform framework (see 04);"
        say "  - a split you did not pass (see 01)."
        say ""
    fi
    say "## top package prefixes, annotated"
    say ""
    printf '%s\n' "  count  package                                        vendor"
    sed 's/\.[^.]*$//' "$CLASSLIST" | awk -F. '{
        n = (NF > 3 ? 3 : NF); s = $1;
        for (i = 2; i <= n; i++) s = s "." $i;
        print s
    }' | sort | uniq -c | sort -rn | head -60 | while read -r count pkg; do
        v="$(vendor_for "$pkg")"
        printf '%7s  %-46s %s\n' "$count" "$pkg" "$v"
    done
    say ""
    say "A blank vendor column is not 'nothing'. It is either the app's own"
    say "code, or a library not in the table -- and the second case is the"
    say "one worth ten minutes. Take the prefix, grep the DEX for its"
    say "strings and endpoints, and search for the vendor."
    say ""
    say "## every distinct second-level package (full list)"
    sed 's/\.[^.]*$//' "$CLASSLIST" | awk -F. 'NF>=2{print $1"."$2}' \
        | sort | uniq -c | sort -rn | sed 's/^/  /'
fi
} | tee "$OUT/05-managed.txt"

# ---------------------------------------------------------------------------
# 06 -- manifest surface
# ---------------------------------------------------------------------------

MANIFEST_TXT="$OUT/06-manifest-decoded.txt"
: > "$MANIFEST_TXT"
MANIFEST_ROUTE="none"

decode_manifest() {   # decode_manifest <apk> -> readable manifest on stdout
    local apk="$1"
    if have apktool; then
        local d="$OUT/apktool-$(basename "$apk" .apk)"
        if apktool d -f "$apk" -o "$d" >/dev/null 2>&1 \
           && [ -f "$d/AndroidManifest.xml" ]; then
            cat "$d/AndroidManifest.xml"
            MANIFEST_ROUTE="apktool d"
            return 0
        fi
    fi
    if have aapt2; then
        if aapt2 dump xmltree --file AndroidManifest.xml "$apk" 2>/dev/null | grep -q .; then
            aapt2 dump xmltree --file AndroidManifest.xml "$apk" 2>/dev/null
            MANIFEST_ROUTE="aapt2 dump xmltree"
            return 0
        fi
    fi
    if have aapt; then
        if aapt dump xmltree "$apk" AndroidManifest.xml 2>/dev/null | grep -q .; then
            aapt dump xmltree "$apk" AndroidManifest.xml 2>/dev/null
            MANIFEST_ROUTE="aapt dump xmltree"
            return 0
        fi
    fi
    if [ -n "$PY" ] && [ -f "$AXML_PARSER" ]; then
        if "$PY" "$AXML_PARSER" --extract "$apk" 2>/dev/null | grep -q .; then
            "$PY" "$AXML_PARSER" --extract "$apk" 2>/dev/null
            MANIFEST_ROUTE="10-APK-Internals/examples/parse_axml.py"
            return 0
        fi
    fi
    # Last resort. Binary AXML stores every name as UTF-16 or UTF-8 in a
    # string pool, so the strings ARE recoverable even with no parser -- but
    # you lose the structure entirely: which attribute belonged to which
    # element, and what its typed value was. Labelled as the guess it is.
    if zread "$apk" AndroidManifest.xml >/dev/null 2>&1; then
        zread "$apk" AndroidManifest.xml 2>/dev/null \
            | tr -d '\000' | tr -c '[:print:]\n' '\n' | grep -E '.{4,}' | sort -u
        MANIFEST_ROUTE="raw string scan of binary AXML (STRUCTURE LOST)"
        return 0
    fi
    return 1
}

while IFS= read -r apk; do
    [ -z "$apk" ] || [ ! -f "$apk" ] && continue
    decode_manifest "$apk" >> "$MANIFEST_TXT" 2>/dev/null
done <<EOF
$INPUTS
EOF
note_route "06-manifest" "$MANIFEST_ROUTE"

{
say "# 06 manifest surface"
say ""
say "Route taken: $MANIFEST_ROUTE"
if [ "$MANIFEST_ROUTE" = "raw string scan of binary AXML (STRUCTURE LOST)" ]; then
    say ""
    say "*** No manifest decoder was available, so this section is a string"
    say "*** dump. The names below are real -- they came out of the binary"
    say "*** XML string pool -- but the STRUCTURE is gone: you cannot tell"
    say "*** which element an attribute belonged to, and you cannot read"
    say "*** android:exported at all. Install apktool or aapt2, or use"
    say "*** ../../10-APK-Internals/examples/parse_axml.py, before you draw"
    say "*** any conclusion from this."
fi
say ""
say "## initialisation providers -- the obfuscation-proof SDK inventory"
say ""
say "ContentProviders are created BEFORE Application.onCreate, so SDKs"
say "declare a no-op provider to bootstrap themselves. The merged manifest"
say "is therefore a reliable list of every SDK that starts itself, and"
say "authorities cannot be obfuscated because the system resolves them as"
say "strings. README section 3.5 explains the mechanism."
say ""
grep -oE '<provider[^>]*android:name="[^"]*"' "$MANIFEST_TXT" 2>/dev/null \
    | sort -u | sed 's/^/  /' || true
grep -oE 'android:authorities="[^"]*"' "$MANIFEST_TXT" 2>/dev/null \
    | sort -u | sed 's/^/  /' || true
grep -oE 'authorities[^ ]*="[^"]*"' "$MANIFEST_TXT" 2>/dev/null \
    | sort -u | sed 's/^/  /' || true
say ""
say "Count them. Ten to thirty is normal in a large consumer app, and every"
say "one is a vendor whose code runs before the app's own code does."
say ""
say "## permissions"
grep -oE 'android\.permission\.[A-Z_]+' "$MANIFEST_TXT" 2>/dev/null \
    | sort -u | sed 's/^/  /' | or_else "  (none found)"
say ""
say "## meta-data (SDK API keys, app IDs, feature switches, and which"
say "   environment the build points at)"
# Two forms, tried in order: the compact self-closing element that aapt2's text
# dump usually produces, then the multi-line form. The choice has to be made on
# whether the first grep MATCHED, which is why this is an if and not a chain of
# `||` -- see the or_else comment near the top of the file.
META="$(grep -oE '<meta-data[^>]*/>' "$MANIFEST_TXT" 2>/dev/null | sort -u)"
if [ -z "$META" ]; then
    META="$(grep -A3 'meta-data' "$MANIFEST_TXT" 2>/dev/null | head -60)"
fi
printf '%s\n' "$META" | sed 's/^/  /' | or_else "  (none found)"
say ""
say "## exported components"
grep -oE '<(activity|service|receiver|provider)[^>]*android:exported="true"[^>]*' \
    "$MANIFEST_TXT" 2>/dev/null | sort -u | sed 's/^/  /' | or_else "  (none found)"
say ""
say "## components contributed by well-known SDK prefixes"
for p in com.facebook com.google.firebase com.google.android.gms com.appsflyer \
         io.sentry com.onesignal com.braze com.appboy com.adjust com.applovin \
         com.ironsource androidx.startup com.microsoft.appcenter; do
    hit="$(grep -oE '"'"$p"'[^"]*"' "$MANIFEST_TXT" 2>/dev/null | sort -u | head -8)"
    if [ -n "$hit" ]; then
        say "  == $p"
        printf '%s\n' "$hit" | sed 's/^/    /'
    fi
done
} | tee "$OUT/06-manifest.txt"

# ---------------------------------------------------------------------------
# 07 -- runtime code loading indicators
# ---------------------------------------------------------------------------

{
say "# 07 runtime code loading indicators"
say ""
say "Ring 3 in README section 2: code the app obtains after it was installed."
say "It is rare, and when it is present it is usually the most severe row in"
say "the whole inventory, because it means the app's behaviour is not fixed"
say "by the artifact you are holding."
say ""
say "## DEX-level references to the loading APIs"
LOADERS='Ldalvik/system/DexClassLoader|Ldalvik/system/PathClassLoader|Ldalvik/system/InMemoryDexClassLoader|Ldalvik/system/BaseDexClassLoader|Ljava/lang/System;->load|Ljava/lang/Runtime;->load'
found_loader=0
while IFS= read -r apk; do
    [ -z "$apk" ] || [ ! -f "$apk" ] && continue
    listing="$(zlist "$apk")" || continue
    printf '%s\n' "$listing" | grep -E '^classes[0-9]*\.dex$' | while IFS= read -r d; do
        [ -z "$d" ] && continue
        hits="$(zread "$apk" "$d" 2>/dev/null | tr -c '[:print:]' '\n' \
                | grep -oE "$LOADERS" | sort | uniq -c | sort -rn)"
        if [ -n "$hits" ]; then
            say "  $apk!$d"
            printf '%s\n' "$hits" | sed 's/^/    /'
        fi
    done
    if grep -q . <<EOF2
$(printf '%s\n' "$listing" | grep -E '^classes[0-9]*\.dex$')
EOF2
    then found_loader=1; fi
done <<EOF
$INPUTS
EOF
say ""
say "A hit is a REFERENCE, not a call. Every app that loads a split or a"
say "dynamic feature module touches these classes legitimately. What makes"
say "it a finding is the SOURCE of the bytes: a file in external storage, a"
say "download, or a decrypted asset. Confirm at runtime with the maps sweep"
say "in README section 7.1 and the dlopen trace in section 7.2."
say ""
say "## classes named for known dynamic-loading and plugin frameworks"
if [ -s "$CLASSLIST" ]; then
    grep -iE '(dexclassloader|pluginmanager|hotfix|tinker|robust|andfix|sophix|dynamicfeature|virtualapp|replugin|shadow\.core)' \
        "$CLASSLIST" | head -40 | sed 's/^/  /' | or_else "  (none)"
else
    say "  (no class inventory; see 05)"
fi
} | tee "$OUT/07-code-loading.txt"

# ---------------------------------------------------------------------------
# 08 -- summary
# ---------------------------------------------------------------------------

count_lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }

{
say "# 08 summary"
say ""
say "Inputs                : $(printf '%s\n' "$INPUTS" | sed '/^$/d' | wc -l | tr -d ' ')"
say "Native libraries      : $(find "$RAW" -name '*.so' 2>/dev/null | wc -l | tr -d ' ')"
say "Classes defined       : $(count_lines "$CLASSLIST")"
say "Version stamps        : $(grep -cE '^  ' "$OUT/03-stamps.txt" 2>/dev/null || echo 0)"
say ""
say "## routes taken"
if [ -n "$ROUTES" ]; then printf '%s' "$ROUTES" | sed 's/^/  /'; else say "  (none recorded)"; fi
say ""
say "## tooling that was NOT available, and what it cost you"
if [ -n "$MISSING" ]; then
    printf '%s' "$MISSING" | sed 's/^/  - /'
else
    say "  (nothing was missing)"
fi
say ""
say "## what to do next"
say ""
say "  1. Versions, with evidence:"
say "         python3 $FINGERPRINT <apk>"
say "         python3 $FINGERPRINT <apk> --prefix okhttp3 --refs ./refs"
say "     Phase 1 is done; that is phase 2. README section 3.7."
say ""
say "  2. Reachability. Nothing above proves anything RUNS. Launch the app"
say "     and read /proc/<pid>/maps and the loaded class list -- README"
say "     section 7.1. A library that is present but unreachable is an"
say "     inventory row, not a finding."
say ""
say "  3. Attribution. Proxy the app and map every host to an SDK, then"
say "     read the payloads -- README section 7.3, and the lab at"
say "     ../labs/lab-03-sdk-audit.md."
say ""
say "  4. Rate each row with the rubric in README section 8.1 phase 4, and"
say "     produce the one-row-per-library table in phase 5. That table is"
say "     the deliverable; everything in $OUT is the evidence behind it."
say ""
say "  5. If you have the source, run the Gradle side too -- README section"
say "     8.3. The transitive tree will contain things this inventory cannot"
say "     see, and this inventory will contain things the tree cannot."
say ""
say "Evidence written to $OUT"
say "Diff the next build against it with:  diff -ru $OUT <next>"
} | tee "$OUT/08-summary.txt"
