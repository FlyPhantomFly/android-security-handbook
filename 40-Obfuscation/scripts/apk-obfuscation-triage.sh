#!/usr/bin/env bash
#
# apk-obfuscation-triage.sh
# ---------------------------------------------------------------------------
# WHAT IT DOES
#   Runs the whole of Phase 1 of the deobfuscation methodology (chapter 40
#   section 6.1) in one command and prints the triage table that decides
#   everything downstream.
#
#   It answers, with evidence rather than impressions:
#
#     1. Is it PACKED?          tiny classes.dex + large high-entropy asset
#                               + a foreign <application android:name>
#     2. Are names OBFUSCATED?  class-name length distribution over the DEX
#     3. Are strings ENCRYPTED? string-pool entropy, URL count, printable ratio
#     4. Is there NATIVE code?  .so inventory, JNI exports, telling NEEDED libs
#     5. Is there ANTI-ANALYSIS? ptrace / TracerPid / frida / magisk markers
#     6. Do the TOOLS work?     does apktool succeed on a file that installs?
#
# WHY IT MATTERS
#   Twenty minutes of triage saves days. The single most expensive mistake in
#   this area is starting to read a decompiled stub, or grinding through
#   control-flow flattening in a method whose strings you have not recovered
#   yet — both of which are choices you would not have made if you had spent
#   two minutes establishing what you were actually looking at.
#
#   The output table is also, verbatim, the first table in your report. A
#   client's "is our app protected?" is answered by these six rows and nothing
#   else.
#
# HOW TO RUN
#   # host
#   ./apk-obfuscation-triage.sh target.apk
#   ./apk-obfuscation-triage.sh target.apk --deep     # also run apktool + jadx
#   ./apk-obfuscation-triage.sh target.apk --keep     # keep the work directory
#
# REQUIREMENTS
#   Required : bash, unzip, python3, awk
#   Optional : aapt2 (manifest), readelf/llvm-readelf (native), apktool, jadx,
#              baksmali. Every optional tool is probed and its absence is
#              reported rather than silently skipping a check.
#
# AUTHORISED TESTING ONLY.
# ---------------------------------------------------------------------------

set -u

APK=""
DEEP=0
KEEP=0

usage() {
    cat <<'USAGE'
usage: apk-obfuscation-triage.sh <app.apk> [--deep] [--keep]

  --deep   also run apktool and jadx (slow, but answers "do the tools work")
  --keep   do not delete the working directory
USAGE
    exit 1
}

for arg in "$@"; do
    case "$arg" in
        --deep) DEEP=1 ;;
        --keep) KEEP=1 ;;
        -h|--help) usage ;;
        *) APK="$arg" ;;
    esac
done

[ -z "$APK" ] && usage
[ -f "$APK" ] || { echo "no such file: $APK" >&2; exit 1; }

# --------------------------------------------------------------------------
# Presentation helpers
# --------------------------------------------------------------------------

BOLD=""; DIM=""; RESET=""
if [ -t 1 ]; then
    BOLD="$(printf '\033[1m')"; DIM="$(printf '\033[2m')"; RESET="$(printf '\033[0m')"
fi

section() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$RESET"; }
note()    { printf '   %s%s%s\n' "$DIM" "$1" "$RESET"; }

have() { command -v "$1" >/dev/null 2>&1; }

# Findings accumulate here and are printed as the verdict table at the end.
VERDICT_PACKED="unknown"
VERDICT_NAMES="unknown"
VERDICT_STRINGS="unknown"
VERDICT_NATIVE="unknown"
VERDICT_ANTI="unknown"
VERDICT_TOOLS="not tested"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/apktriage.XXXXXX")"
cleanup() { [ "$KEEP" -eq 0 ] && rm -rf "$WORK"; }
trap cleanup EXIT

# --------------------------------------------------------------------------
section "0. Identity"
# --------------------------------------------------------------------------

printf '   file      : %s\n' "$APK"
printf '   size      : %s bytes\n' "$(wc -c < "$APK" | tr -d ' ')"

if have sha256sum; then
    printf '   sha256    : %s\n' "$(sha256sum "$APK" | awk '{print $1}')"
elif have shasum; then
    printf '   sha256    : %s\n' "$(shasum -a 256 "$APK" | awk '{print $1}')"
else
    note "no sha256sum/shasum — record the hash by other means; it goes in the report"
fi

if have apksigner; then
    printf '   signer    :\n'
    apksigner verify --print-certs "$APK" 2>/dev/null \
        | grep -E 'Signer #1 (certificate DN|certificate SHA-256)|Verified using' \
        | sed 's/^/     /'
else
    note "apksigner not found — signer identity not recorded"
fi

note "If 'pm path' on the device printed several APKs, this is a split install."
note "Analysing only base.apk and concluding a feature is absent is a classic error."

# --------------------------------------------------------------------------
section "1. Packing indicators"
# --------------------------------------------------------------------------

unzip -o -q "$APK" -d "$WORK/ext" 2>/dev/null

# ---- DEX inventory and class_defs_size -----------------------------------
DEX_COUNT=$(find "$WORK/ext" -maxdepth 1 -name 'classes*.dex' | wc -l | tr -d ' ')
printf '   DEX files : %s\n' "$DEX_COUNT"

if [ "$DEX_COUNT" -eq 0 ]; then
    note "NO classes.dex at the archive root. Either the DEX is hidden elsewhere"
    note "or this is not an APK. Check for appended data past the central directory."
    VERDICT_PACKED="suspicious (no root DEX)"
fi

TOTAL_CLASSES=0
SMALLEST_DEFS=999999

for dex in "$WORK/ext"/classes*.dex; do
    [ -f "$dex" ] || continue
    read -r DSIZE DEFS DSTRINGS DVER <<EOF
$(python3 - "$dex" <<'PY'
import struct, sys, os
p = sys.argv[1]
with open(p, "rb") as f:
    h = f.read(0x70)
size = os.path.getsize(p)
if len(h) < 0x70 or h[:4] != b"dex\n":
    print("0 0 0 bad")
else:
    ver = h[4:7].decode("ascii", "replace")
    string_ids_size = struct.unpack_from("<I", h, 0x38)[0]
    class_defs_size = struct.unpack_from("<I", h, 0x60)[0]
    print(f"{size} {class_defs_size} {string_ids_size} {ver}")
PY
)
EOF
    printf '   %-16s %9s bytes  %6s classes  %6s strings  v%s\n' \
        "$(basename "$dex")" "$DSIZE" "$DEFS" "$DSTRINGS" "$DVER"
    TOTAL_CLASSES=$((TOTAL_CLASSES + DEFS))
    [ "$DEFS" -lt "$SMALLEST_DEFS" ] && SMALLEST_DEFS="$DEFS"
done

printf '   total classes: %s\n' "$TOTAL_CLASSES"
note "class_defs_size lives at offset 0x60 of the DEX header (see 12-DEX-Internals)."

PACK_SCORE=0
PACK_WHY=""

if [ "$TOTAL_CLASSES" -gt 0 ] && [ "$TOTAL_CLASSES" -lt 60 ]; then
    PACK_SCORE=$((PACK_SCORE + 2))
    PACK_WHY="$PACK_WHY; only $TOTAL_CLASSES classes in total"
fi

# ---- large, high-entropy assets ------------------------------------------
printf '\n   Largest non-code entries:\n'
unzip -l "$APK" 2>/dev/null \
    | awk 'NR>3 && $1+0 > 200000 && $4 !~ /\.dex$/ && $4 !~ /\.so$/ {print $1, $4}' \
    | sort -rn | head -12 | sed 's/^/     /'

printf '\n   Entropy of candidate payloads (8.00 = indistinguishable from random):\n'
ENTROPY_HIT=0
while IFS= read -r f; do
    [ -f "$f" ] || continue
    E=$(python3 - "$f" <<'PY'
import math, sys
d = open(sys.argv[1], "rb").read(4 * 1024 * 1024)
if not d:
    print("0.00"); raise SystemExit
counts = [0] * 256
for b in d:
    counts[b] += 1
n = len(d)
h = -sum((c / n) * math.log2(c / n) for c in counts if c)
print(f"{h:.2f}")
PY
)
    SZ=$(wc -c < "$f" | tr -d ' ')
    REL="${f#"$WORK/ext/"}"
    printf '     %5s  %10s  %s\n' "$E" "$SZ" "$REL"
    HIGH=$(python3 -c "import sys; print(1 if float(sys.argv[1]) > 7.8 else 0)" "$E")
    if [ "$HIGH" = "1" ] && [ "$SZ" -gt 200000 ]; then
        ENTROPY_HIT=$((ENTROPY_HIT + 1))
    fi
done <<EOF
$(find "$WORK/ext/assets" "$WORK/ext/res/raw" -type f -size +200k 2>/dev/null | head -20)
EOF

if [ "$ENTROPY_HIT" -gt 0 ]; then
    PACK_SCORE=$((PACK_SCORE + 2))
    PACK_WHY="$PACK_WHY; $ENTROPY_HIT large high-entropy asset(s)"
    note "High entropy means encrypted OR already compressed. A .png or .zip is"
    note "expected to be near 8.00; an unexplained .dat or .jar is the payload."
fi

# ---- the application class -----------------------------------------------
printf '\n   <application android:name> and meta-data:\n'
APPNAME=""
if have aapt2; then
    aapt2 dump xmltree "$APK" --file AndroidManifest.xml 2>/dev/null \
        > "$WORK/manifest.txt" || true
    APPNAME=$(grep -A6 'E: application' "$WORK/manifest.txt" 2>/dev/null \
        | grep -m1 'A: android:name' \
        | sed 's/.*="\([^"]*\)".*/\1/')
    if [ -n "$APPNAME" ]; then
        printf '     application: %s\n' "$APPNAME"
    else
        printf '     application: (none declared — the default android.app.Application)\n'
    fi
    grep -B1 -A3 'E: meta-data' "$WORK/manifest.txt" 2>/dev/null \
        | grep -E 'android:(name|value)' | head -20 | sed 's/^/     /'
    printf '\n   Package and target SDK:\n'
    grep -E 'package=|compileSdkVersion|targetSdkVersion' "$WORK/manifest.txt" \
        2>/dev/null | head -5 | sed 's/^/     /'
else
    note "aapt2 not found — cannot read the binary manifest."
    note "Install Android build-tools, or use: apktool d -f $APK -o out && cat out/AndroidManifest.xml"
fi

PKG=$(grep -m1 'A: package=' "$WORK/manifest.txt" 2>/dev/null \
      | sed 's/.*package="\([^"]*\)".*/\1/')

if [ -n "$APPNAME" ] && [ -n "$PKG" ]; then
    APPROOT=$(printf '%s' "$APPNAME" | cut -d. -f1-2)
    PKGROOT=$(printf '%s' "$PKG" | cut -d. -f1-2)
    if [ "$APPROOT" != "$PKGROOT" ] && \
       [ "${APPNAME#android.}" = "$APPNAME" ] && \
       [ "${APPNAME#androidx.}" = "$APPNAME" ]; then
        PACK_SCORE=$((PACK_SCORE + 2))
        PACK_WHY="$PACK_WHY; application class '$APPNAME' is foreign to package '$PKG'"
        note "A foreign <application android:name> is the packer stub. The ORIGINAL"
        note "application class is normally stashed in a <meta-data> entry above."
    fi
fi

if [ "$PACK_SCORE" -ge 4 ]; then
    VERDICT_PACKED="PACKED (score $PACK_SCORE)${PACK_WHY}"
elif [ "$PACK_SCORE" -ge 2 ]; then
    VERDICT_PACKED="possibly packed (score $PACK_SCORE)${PACK_WHY}"
else
    VERDICT_PACKED="not packed"
fi

# --------------------------------------------------------------------------
section "2. Identifier renaming — class-name length distribution"
# --------------------------------------------------------------------------

# Class names live in the DEX string pool as type descriptors, "Lcom/x/y;".
# Extracting them from the raw file with a permissive regex is good enough for
# a distribution: we are measuring shape, not enumerating precisely.
python3 - "$WORK/ext" <<'PY'
import glob, os, re, sys, collections

root = sys.argv[1]
pat = re.compile(rb'L([A-Za-z0-9_$/]{1,200});')
names = set()
for dex in sorted(glob.glob(os.path.join(root, "classes*.dex"))):
    data = open(dex, "rb").read()
    for m in pat.finditer(data):
        names.add(m.group(1).decode("ascii", "replace"))

if not names:
    print("   (no type descriptors extracted — unusual; is this really a DEX?)")
    raise SystemExit

SKIP = ("java/", "javax/", "android/", "androidx/", "kotlin/", "kotlinx/",
        "dalvik/", "libcore/", "sun/", "org/w3c/", "org/xml/", "org/json/",
        "org/apache/", "com/google/android/gms/", "com/google/android/material/")

app = [n for n in names if not n.startswith(SKIP)]
if not app:
    app = list(names)

simple = [n.split("/")[-1] for n in app]
hist = collections.Counter(min(len(s), 12) for s in simple)

short = sum(1 for s in simple if len(s) <= 2)
med   = sum(1 for s in simple if 3 <= len(s) <= 5)
long_ = sum(1 for s in simple if len(s) > 5)
total = len(simple)

print(f"   application-ish classes examined: {total}")
print("   simple-name length histogram (12 = 12 or more):")
for k in sorted(hist):
    bar = "#" * min(60, hist[k] * 60 // max(hist.values()))
    print(f"     {k:>2}  {hist[k]:>6}  {bar}")

pct_short = 100 * short / total if total else 0
print()
print(f"   <=2 chars : {short:>6}  ({pct_short:.1f}%)")
print(f"   3-5 chars : {med:>6}")
print(f"   >5 chars  : {long_:>6}")

# Flat-package detection: -repackageclasses puts everything in one package.
pkgs = collections.Counter("/".join(n.split("/")[:-1]) for n in app)
top_pkg, top_n = (pkgs.most_common(1) or [("", 0)])[0]
if total and top_n / total > 0.6:
    print(f"   NOTE: {100*top_n//total}% of classes are in a single package "
          f"'{top_pkg or '(default)'}' — consistent with -repackageclasses")

if pct_short > 50:
    verdict = "HEAVILY RENAMED"
elif pct_short > 15:
    verdict = "renamed (partial coverage — keep rules or libraries excluded)"
else:
    verdict = "not renamed, or renaming disabled"
print()
print(f"   VERDICT: {verdict}")
print(f"__VERDICT_NAMES__{verdict}")
PY

VERDICT_NAMES=$( { python3 - "$WORK/ext" <<'PY'
import glob, os, re, sys
root = sys.argv[1]
pat = re.compile(rb'L([A-Za-z0-9_$/]{1,200});')
names = set()
for dex in sorted(glob.glob(os.path.join(root, "classes*.dex"))):
    for m in pat.finditer(open(dex, "rb").read()):
        names.add(m.group(1).decode("ascii", "replace"))
SKIP = ("java/", "javax/", "android/", "androidx/", "kotlin/", "kotlinx/",
        "dalvik/", "libcore/", "sun/", "org/w3c/", "org/xml/", "org/json/",
        "org/apache/", "com/google/android/gms/", "com/google/android/material/")
app = [n for n in names if not n.startswith(SKIP)] or list(names)
simple = [n.split("/")[-1] for n in app]
if not simple:
    print("unknown"); raise SystemExit
pct = 100 * sum(1 for s in simple if len(s) <= 2) / len(simple)
print("HEAVILY RENAMED" if pct > 50 else
      ("renamed (partial)" if pct > 15 else "not renamed"))
PY
} 2>/dev/null )

note "Renaming is normal and expected. What matters for the report is COVERAGE:"
note "a large '>5 chars' bucket means keep rules are too broad, and the classes"
note "that kept their names are exactly the ones the developer cared about."

# --------------------------------------------------------------------------
section "3. String encryption — string-pool character statistics"
# --------------------------------------------------------------------------

python3 - "$WORK/ext" <<'PY'
import glob, math, os, re, sys, collections

root = sys.argv[1]
# Printable ASCII runs of length >= 5 approximate the DEX string pool well
# enough for a statistical verdict without a full parser.
run = re.compile(rb'[\x20-\x7e]{5,}')

strings = []
for dex in sorted(glob.glob(os.path.join(root, "classes*.dex"))):
    data = open(dex, "rb").read()
    strings.extend(m.group(0).decode("ascii", "replace") for m in run.finditer(data))

if not strings:
    print("   no printable strings recovered at all — strongly suggests encryption")
    raise SystemExit

n = len(strings)
urls   = [s for s in strings if re.search(r'https?://', s)]
paths  = [s for s in strings if s.startswith('/') and len(s) > 6]
words  = [s for s in strings if re.fullmatch(r'[A-Za-z][A-Za-z0-9 _.,:\-/]{4,}', s)]
b64ish = [s for s in strings if re.fullmatch(r'[A-Za-z0-9+/=]{24,}', s)]
hexish = [s for s in strings if re.fullmatch(r'[0-9a-fA-F]{24,}', s)]

print(f"   printable runs      : {n}")
print(f"   http(s) URLs        : {len(urls)}")
print(f"   absolute paths      : {len(paths)}")
print(f"   word-like strings   : {len(words)}  ({100*len(words)//n}%)")
print(f"   base64-looking      : {len(b64ish)}")
print(f"   long hex strings    : {len(hexish)}")

if urls:
    print("\n   sample URLs:")
    for u in sorted(set(urls))[:8]:
        print(f"     {u[:110]}")

# Shannon entropy over the characters of the pool. Natural-language and
# identifier text sits around 4.0-4.7 bits/char; ciphertext rendered as base64
# or raw bytes runs higher and much flatter.
blob = "".join(strings)
counts = collections.Counter(blob)
tot = len(blob)
H = -sum((c/tot) * math.log2(c/tot) for c in counts.values())
print(f"\n   character entropy   : {H:.2f} bits/char")
print("     ~4.0-4.7 = ordinary code and text")
print("     >5.2     = the pool is dominated by ciphertext-looking data")

score = 0
why = []
if len(urls) == 0:
    score += 2; why.append("no URLs anywhere")
if 100*len(words)//n < 25:
    score += 2; why.append("few word-like strings")
if len(b64ish) + len(hexish) > n // 10:
    score += 2; why.append("large fraction of base64/hex blobs")
if H > 5.2:
    score += 1; why.append(f"high character entropy ({H:.2f})")

if score >= 4:
    v = "STRINGS ENCRYPTED (" + ", ".join(why) + ")"
elif score >= 2:
    v = "possibly encrypted (" + ", ".join(why) + ")"
else:
    v = "strings in the clear"
print(f"\n   VERDICT: {v}")
PY

VERDICT_STRINGS=$( { python3 - "$WORK/ext" <<'PY'
import glob, os, re, sys
root = sys.argv[1]
run = re.compile(rb'[\x20-\x7e]{5,}')
s = []
for dex in sorted(glob.glob(os.path.join(root, "classes*.dex"))):
    s.extend(m.group(0).decode("ascii", "replace") for m in run.finditer(open(dex, "rb").read()))
if not s:
    print("ENCRYPTED (no printable strings)"); raise SystemExit
urls = sum(1 for x in s if re.search(r'https?://', x))
words = sum(1 for x in s if re.fullmatch(r'[A-Za-z][A-Za-z0-9 _.,:\-/]{4,}', x))
print("ENCRYPTED" if (urls == 0 and 100*words//len(s) < 25) else
      ("possibly encrypted" if urls == 0 else "in the clear"))
PY
} 2>/dev/null )

note "Zero URLs in a networked app is the single loudest string-encryption signal."
note "Counter (section 3.2): hook or directly invoke the decryptor —"
note "  frida -U -f PKG -l frida-string-decryptor.js --pause"

# --------------------------------------------------------------------------
section "4. Native code"
# --------------------------------------------------------------------------

SO_LIST=$(find "$WORK/ext/lib" "$WORK/ext/assets" -name '*.so' 2>/dev/null | sort)
SO_COUNT=$(printf '%s\n' "$SO_LIST" | grep -c '\.so$' || true)

if [ -z "$SO_LIST" ]; then
    printf '   no native libraries\n'
    VERDICT_NATIVE="none"
else
    printf '   %s native library file(s):\n' "$SO_COUNT"
    printf '%s\n' "$SO_LIST" | sed "s|$WORK/ext/|     |"

    # A .so under assets/ rather than lib/ is loaded with System.load(path)
    # to avoid the installer extracting it — a packer habit worth flagging.
    if printf '%s\n' "$SO_LIST" | grep -q '/assets/'; then
        printf '\n'
        note "A .so in assets/ rather than lib/ is loaded manually with System.load()."
        note "That is a packer/protector habit: it dodges tools that only look in lib/."
        PACK_SCORE=$((PACK_SCORE + 1))
    fi

    READELF=""
    have llvm-readelf && READELF="llvm-readelf"
    have readelf && READELF="readelf"

    if [ -n "$READELF" ]; then
        printf '\n   JNI exports and NEEDED libraries:\n'
        printf '%s\n' "$SO_LIST" | while IFS= read -r so; do
            [ -f "$so" ] || continue
            REL="${so#"$WORK/ext/"}"
            JNI=$($READELF --dyn-syms "$so" 2>/dev/null | awk '{print $8}' \
                  | grep -c '^Java_' || true)
            ONLOAD=$($READELF --dyn-syms "$so" 2>/dev/null | grep -c 'JNI_OnLoad' || true)
            INIT=$($READELF -S "$so" 2>/dev/null | grep -c '\.init_array' || true)
            printf '     %-52s Java_*=%-4s JNI_OnLoad=%-2s init_array=%s\n' \
                "$REL" "$JNI" "$ONLOAD" "$INIT"
            $READELF -d "$so" 2>/dev/null | grep NEEDED \
                | sed 's/.*\[\(.*\)\]/       needs \1/'
        done
        printf '\n'
        note "Few or no Java_* exports + JNI_OnLoad present + a big .init_array"
        note "means everything is registered at runtime and the anti-debug runs"
        note "in .init_array, BEFORE JNI_OnLoad. Spawn-gate; do not attach."
        note "NEEDED libcrypto/libssl means the app does its own TLS — check"
        note "for native certificate pinning (see ../../36-CertificatePinning/)."
    else
        note "readelf not found — install binutils or llvm to inspect the .so files"
    fi
    VERDICT_NATIVE="$SO_COUNT file(s)"
fi

# --------------------------------------------------------------------------
section "5. Anti-analysis markers"
# --------------------------------------------------------------------------

MARKERS='ptrace|TracerPid|/proc/self/status|frida|gum-js|gadget|xposed|substrate|lsposed|riru|zygisk|magisk|supersu|/system/xbin/su|goldfish|ranchu|qemu|isDebuggerConnected|android:debuggable'

ANTI_TOTAL=0
printf '   Marker hits per file (DEX and native):\n'
for f in "$WORK/ext"/classes*.dex $SO_LIST; do
    [ -f "$f" ] || continue
    N=$(strings -a "$f" 2>/dev/null | grep -ciE "$MARKERS" || true)
    if [ "${N:-0}" -gt 0 ]; then
        printf '     %-52s %s\n' "${f#"$WORK/ext/"}" "$N"
        ANTI_TOTAL=$((ANTI_TOTAL + N))
    fi
done

if [ "$ANTI_TOTAL" -eq 0 ]; then
    printf '     (none found)\n'
    note "Absence here is weak evidence. Encrypted strings hide these markers too;"
    note "cross-read this against the section 3 verdict before concluding anything."
    VERDICT_ANTI="none visible"
else
    printf '\n   Which markers:\n'
    for f in "$WORK/ext"/classes*.dex $SO_LIST; do
        [ -f "$f" ] || continue
        strings -a "$f" 2>/dev/null | grep -oiE "$MARKERS" | sort -u \
            | sed "s|^|     ${f#"$WORK/ext/"}: |"
    done | sort -u | head -30
    VERDICT_ANTI="$ANTI_TOTAL marker hit(s)"
fi

# --------------------------------------------------------------------------
section "6. Control-flow flattening — a cheap statistical proxy"
# --------------------------------------------------------------------------

# packed-switch / sparse-switch payloads are what a flattener's dispatcher
# compiles to. Counting the switch payload markers in the raw DEX is a crude
# but surprisingly usable proxy without disassembling.
python3 - "$WORK/ext" <<'PY'
import glob, os, struct, sys

root = sys.argv[1]
# 0x0100 = packed-switch payload ident, 0x0200 = sparse-switch payload ident.
packed = sparse = 0
for dex in sorted(glob.glob(os.path.join(root, "classes*.dex"))):
    d = open(dex, "rb").read()
    packed += d.count(b"\x00\x01")
    sparse += d.count(b"\x00\x02")
print(f"   packed-switch-ish markers : {packed}")
print(f"   sparse-switch-ish markers : {sparse}")
print("   (crude: these byte pairs occur elsewhere too. Treat a HIGH count as a")
print("    hint to open three non-trivial methods in jadx and look for the")
print("    canonical shape:  while (true) { switch (state) { ... } }  )")
PY

note "The reliable test is visual. Open three methods; if you see an infinite"
note "loop whose entire body is a switch on an int local, it is flattened."
note "Counter (section 3.3.2): build the state-transition table, or ask first"
note "whether you need to understand the method or only to predict it."

# --------------------------------------------------------------------------
section "7. Anti-tool tricks — do the tools actually work?"
# --------------------------------------------------------------------------

if [ "$DEEP" -eq 1 ]; then
    if have apktool; then
        printf '   running apktool...\n'
        if apktool d -f -o "$WORK/apktool_out" "$APK" > "$WORK/apktool.log" 2>&1; then
            printf '     apktool: OK\n'
            VERDICT_TOOLS="apktool OK"
        else
            printf '     apktool: FAILED\n'
            tail -12 "$WORK/apktool.log" | sed 's/^/       /'
            VERDICT_TOOLS="apktool FAILED"
            note "A file that installs on a device but breaks apktool is deliberate"
            note "format abuse (section 3.8). Android's parsers are more permissive"
            note "than third-party ones. Work in Smali via baksmali, or dump from"
            note "memory; do NOT conclude the APK is corrupt."
        fi
    else
        note "apktool not installed — cannot test"
    fi

    if have jadx; then
        printf '   running jadx (this can be slow)...\n'
        if jadx -d "$WORK/jadx_out" --no-res "$APK" > "$WORK/jadx.log" 2>&1; then
            ERRS=$(grep -ci 'error' "$WORK/jadx.log" || true)
            printf '     jadx: completed with %s error line(s)\n' "$ERRS"
            VERDICT_TOOLS="$VERDICT_TOOLS; jadx completed ($ERRS errors)"
        else
            printf '     jadx: FAILED\n'
            tail -12 "$WORK/jadx.log" | sed 's/^/       /'
            VERDICT_TOOLS="$VERDICT_TOOLS; jadx FAILED"
            note "Try: jadx -J-Xmx8g --show-bad-code --deobf"
        fi
    else
        note "jadx not installed — cannot test"
    fi
else
    note "skipped (pass --deep to run apktool and jadx)"
fi

# --------------------------------------------------------------------------
section "VERDICT — Phase 1 triage table"
# --------------------------------------------------------------------------

printf '\n'
printf '   | %-22s | %s\n' "Question" "Answer"
printf '   |%s|%s\n' "------------------------" "----------------------------------------"
printf '   | %-22s | %s\n' "1. Packed?"          "$VERDICT_PACKED"
printf '   | %-22s | %s\n' "2. Names obfuscated?" "$VERDICT_NAMES"
printf '   | %-22s | %s\n' "3. Strings encrypted?" "$VERDICT_STRINGS"
printf '   | %-22s | %s\n' "4. Native code?"      "$VERDICT_NATIVE"
printf '   | %-22s | %s\n' "5. Anti-analysis?"    "$VERDICT_ANTI"
printf '   | %-22s | %s\n' "6. Tools work?"       "$VERDICT_TOOLS"
printf '\n'

cat <<'NEXT'
   NEXT STEPS (chapter 40 section 6.1)

     Packed?              -> Phase 3 first. Do not read a stub.
                             frida -U -f PKG -l frida-classloader-dump.js --pause
                             fallback: frida-dexdump-lite.js after the UI appears

     Strings encrypted?   -> Phase 4, before ANY control-flow work.
                             frida -U -f PKG -l frida-string-decryptor.js --pause
                             then: annotate-smali-strings.py

     Strings in the clear -> go straight to grepping them. Endpoints, keys,
                             crypto configuration and root-check paths are the
                             four buckets that pay.

     Anti-analysis found  -> spawn-gate, never attach. Expect .init_array
                             checks that run before JNI_OnLoad.
                             See ../../67-BypassingProtections/README.md

     Native code present  -> frida-trace the JNI boundary BEFORE opening Ghidra.
                             The boundary is plaintext by construction.

   Record this table in your notes. It is the first table in your report, and
   it is what "is our app protected?" actually means.
NEXT

[ "$KEEP" -eq 1 ] && printf '\n   working directory kept: %s\n' "$WORK"
exit 0
