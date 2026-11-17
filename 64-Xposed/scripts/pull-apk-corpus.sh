#!/usr/bin/env bash
# scripts/pull-apk-corpus.sh
#
# PURPOSE
#   Pull every installed APK off a device into a flat, package-named directory,
#   so that scripts/xposed-detection-scan.py (or any other static tool) has a
#   real corpus to work on.
#
#   The chapter needs this because its central measurement -- "how much
#   Xposed-detection code is actually shipping?" -- is only as good as the
#   corpus it was asked of, and a corpus you cannot rebuild is a number nobody
#   can check. README section 8.4 is explicit about what this chapter's own
#   corpus could and could not support; this script is how you build a better
#   one.
#
# WHY NOT JUST GREP ON THE DEVICE
#   You can, and README section 8.5 shows the one-liner. It has a MEASURED
#   blind spot: a raw grep over a .apk only sees an UNCOMPRESSED classes.dex.
#   Preinstalled APKs store their DEX uncompressed so Android can mmap it, but
#   APKs in /data/app -- sideloaded and Play-updated ones -- often deflate it.
#
#   Measured on the API 35 AVD used for this chapter: 234 classes*.dex STORED,
#   16 DEFLATED, and ALL SIXTEEN were in /data/app. Ten of them were Chrome's.
#   The device-side shortcut would silently have skipped the single largest
#   third-party application present. Pull, then scan.
#
# USAGE
#   ./pull-apk-corpus.sh [options]
#
#     --serial SERIAL      adb -s SERIAL. ALWAYS pass this when more than one
#                          device is attached; a silent wrong-device attach is
#                          the worst kind, because every subsequent measurement
#                          is internally consistent and about the wrong target.
#     --out DIR            Destination. MUST be outside this repository --
#                          .apk is on the artefact blocklist.
#                          Default: ${TMPDIR:-/tmp}/ch64-corpus
#     --third-party-only   Only packages from `pm list packages -3`. THIS IS
#                          USUALLY WHAT YOU WANT on a real phone: it is the
#                          population that actually ships anti-instrumentation
#                          code.
#     --max-mib N          Skip APKs larger than N MiB. Default: no limit.
#     --manifest FILE      Also write a package|path|size manifest. Default:
#                          <out>/MANIFEST.txt
#     --dry-run            List what would be pulled, pull nothing.
#     -h, --help           This text.
#
# EXAMPLES
#   ./pull-apk-corpus.sh --serial emulator-5554
#   ./pull-apk-corpus.sh --serial <phone> --third-party-only --out /tmp/apks
#   ./pull-apk-corpus.sh --dry-run --third-party-only
#
# WHAT IT DOES NOT DO
#   It writes nothing to the device, installs nothing, and changes no setting.
#   Every operation is a read. Split APKs are handled: each split is pulled
#   with a suffix, because a package's code is frequently NOT all in base.apk
#   -- chapter 38 measured one large app showing ZERO controls in base.apk
#   purely because its code shipped in splits.
#
# EXECUTION STATUS
#   EXECUTED. Run against sdk_gphone16k_x86_64 (Android 15 / API 35) on
#   2026-08-16: 243 packages listed, 237 APKs pulled, 2,507 MiB. The six that
#   did not pull are RRO overlay and resource-only packages, which carry no
#   DEX. Its output is the corpus every number in README section 8 came from,
#   and it was deleted afterwards.
#
# MSYS / GIT BASH NOTE
#   `adb pull` MANGLES an absolute device path under MSYS: /system/app/... is
#   rewritten to C:/Program Files/Git/system/app/... and the pull fails with a
#   message naming a path you never typed. MSYS_NO_PATHCONV=1 fixes the remote
#   argument; the LOCAL argument must then be a Windows-style path, because adb
#   is a native binary and cannot create a directory called /c/Users/...
#   This script handles both.
#
# AUTHORISED TESTING ONLY. Pulling every APK off a device copies software that
# is licensed, not owned. Do it on a device you control, keep the corpus local,
# and delete it when the analysis is done.

set -u

SERIAL=""
OUT_DIR=""
THIRD_ONLY=0
MAX_MIB=0
MANIFEST=""
DRY=0

usage() { sed -n '2,60p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --serial)           SERIAL="${2:-}"; shift 2 ;;
        --out)              OUT_DIR="${2:-}"; shift 2 ;;
        --third-party-only) THIRD_ONLY=1; shift ;;
        --max-mib)          MAX_MIB="${2:-0}"; shift 2 ;;
        --manifest)         MANIFEST="${2:-}"; shift 2 ;;
        --dry-run)          DRY=1; shift ;;
        -h|--help)          usage ;;
        *) printf '[FATAL] unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
    esac
done

export MSYS_NO_PATHCONV=1

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

die()  { printf '\n[FATAL] %s\n' "$*" >&2; exit 2; }
info() { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }

COUNT="$("${ADB[@]}" devices | grep -c 'device$' || true)"
[ "$COUNT" -eq 0 ] && die "no device in state 'device'. Run: adb devices -l"
if [ "$COUNT" -gt 1 ] && [ -z "$SERIAL" ]; then
    "${ADB[@]}" devices -l >&2
    die "$COUNT devices attached and no --serial given. Refusing to guess."
fi

MODEL="$("${ADB[@]}" shell getprop ro.product.model < /dev/null 2>/dev/null | tr -d '\r')"
SDKV="$("${ADB[@]}" shell getprop ro.build.version.sdk < /dev/null 2>/dev/null | tr -d '\r')"
info "device: ${SERIAL:-<only attached>}  model=$MODEL  api=$SDKV"

[ -n "$OUT_DIR" ] || OUT_DIR="${TMPDIR:-/tmp}/ch64-corpus"
mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR"
case "$(cd "$OUT_DIR" && pwd)" in
    *Android-Security-Handbook*)
        die "refusing to write APKs inside the repository: $OUT_DIR
     .apk is on the artefact blocklist and this repo ships sources only." ;;
esac
[ -n "$MANIFEST" ] || MANIFEST="$OUT_DIR/MANIFEST.txt"

# adb is a native binary on Windows and cannot create /c/Users/... -- give it a
# Windows-style local path.
if command -v cygpath >/dev/null 2>&1; then
    LOCAL_OUT="$(cygpath -m "$OUT_DIR")"
else
    LOCAL_OUT="$OUT_DIR"
fi

# ---------------------------------------------------------------------------
# Enumerate. `pm list packages -f` gives path=package, one per line. A package
# with splits produces one line PER APK, all with the same package name, which
# is why the pulled filename carries a counter.
# ---------------------------------------------------------------------------
LISTCMD='pm list packages -f'
[ "$THIRD_ONLY" = 1 ] && LISTCMD='pm list packages -f -3'

LIST="$OUT_DIR/.pkglist.txt"
"${ADB[@]}" shell "$LISTCMD" < /dev/null 2>/dev/null | tr -d '\r' \
    | sed 's/^package://' > "$LIST"

TOTAL="$(grep -c . "$LIST" || true)"
[ "$TOTAL" -gt 0 ] || die "pm list packages returned nothing"
info "$TOTAL APK entries listed$([ "$THIRD_ONLY" = 1 ] && echo ' (third-party only)')"

# ---------------------------------------------------------------------------
# Sizes, in ONE device-side pass. Doing a `stat` per package over adb is
# minutes; doing it in a single device-side shell loop is seconds.
# ---------------------------------------------------------------------------
SIZES="$OUT_DIR/.sizes.txt"
"${ADB[@]}" shell "$LISTCMD"' | sed "s/^package://" | while IFS= read -r l; do
        a=${l%=*}; p=${l##*=}; s=$(stat -c %s "$a" 2>/dev/null || echo 0)
        echo "$s|$p|$a"
    done' < /dev/null 2>/dev/null | tr -d '\r' > "$SIZES"

: > "$MANIFEST"
PULLED=0
SKIPPED=0
FAILED=0
BYTES=0

while IFS='|' read -r size pkg path; do
    [ -n "$pkg" ] || continue
    if [ "$MAX_MIB" -gt 0 ] && [ "$size" -gt $((MAX_MIB * 1048576)) ]; then
        SKIPPED=$((SKIPPED + 1))
        printf 'SKIP  %s|%s|%s\n' "$pkg" "$path" "$size" >> "$MANIFEST"
        continue
    fi

    # Splits: same package, several APKs. Suffix after the first.
    base="$pkg"
    n=0
    while [ -f "$OUT_DIR/$base.apk" ]; do
        n=$((n + 1)); base="$pkg.split$n"
    done

    if [ "$DRY" = 1 ]; then
        printf 'WOULD %-58s %10s  %s\n' "$pkg" "$size" "$path"
        PULLED=$((PULLED + 1))
        continue
    fi

    if "${ADB[@]}" pull "$path" "$LOCAL_OUT/$base.apk" > /dev/null 2>&1; then
        PULLED=$((PULLED + 1))
        BYTES=$((BYTES + size))
        printf 'OK    %s|%s|%s\n' "$pkg" "$path" "$size" >> "$MANIFEST"
    else
        FAILED=$((FAILED + 1))
        printf 'FAIL  %s|%s|%s\n' "$pkg" "$path" "$size" >> "$MANIFEST"
    fi
done < "$SIZES"

rm -f "$LIST" "$SIZES"

echo
if [ "$DRY" = 1 ]; then
    ok "dry run: $PULLED would be pulled, $SKIPPED skipped by --max-mib"
    exit 0
fi

ok "pulled  : $PULLED"
[ "$SKIPPED" -gt 0 ] && info "skipped : $SKIPPED (over --max-mib $MAX_MIB)"
if [ "$FAILED" -gt 0 ]; then
    warn "failed  : $FAILED -- see $MANIFEST"
    warn "          Failures are usually RRO overlay or resource-only packages"
    warn "          (*.auto_generated_rro_*, *.overlay). They carry no DEX, so"
    warn "          they are not a gap in a code sweep. CHECK the manifest"
    warn "          rather than assuming that; a failure on a real app is."
fi
ok "bytes   : $BYTES ($((BYTES / 1048576)) MiB)"
ok "corpus  : $OUT_DIR"
ok "manifest: $MANIFEST"

cat <<EOF

Next:
    python3 -B "\$(dirname "\$0")/xposed-detection-scan.py" "$OUT_DIR" \\
        --recursive --substring-audit

And when you are done, DELETE THE CORPUS. It is somebody's licensed software
sitting on your disk:
    rm -rf "$OUT_DIR"
EOF
