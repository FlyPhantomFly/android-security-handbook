#!/usr/bin/env bash
# scripts/pull-apk-corpus.sh
#
# PURPOSE
#   Build the APK corpus that fragment-injection-scan.py reads, by pulling every
#   installed package off the attached device.
#
#   64-Xposed ships a script with the same job and this one is deliberately
#   close to it, with two differences that came out of running it here:
#
#     * it reports the DENOMINATOR honestly, splitting "installed" from
#       "pulled" and naming every package it could not pull, because a corpus
#       sweep that quotes a total it did not verify is the exact failure mode
#       this repository keeps recording;
#     * it counts STORED versus DEFLATED classes*.dex entries, because a
#       device-side `grep` over .apk files is blind to the compressed ones and
#       64-Xposed measured that blind spot landing entirely on the sideloaded
#       and Play-updated apps -- the ones worth scanning.
#
# USAGE
#   # host
#   ./pull-apk-corpus.sh /path/to/corpus
#   ./pull-apk-corpus.sh /path/to/corpus -s emulator-5554
#
#   Then:
#   python3 -B fragment-injection-scan.py /path/to/corpus --recursive
#
#   DELETE THE CORPUS WHEN YOU ARE DONE. It is a few gigabytes of other
#   people's code and it does not belong in this repository -- `.apk` is on the
#   artefact blocklist, so pick a directory OUTSIDE the repo.
#
# EXECUTION STATUS
#   EXECUTED on 2026-08-16 against the AVD `sdk_gphone16k_x86_64`
#   (Android 15 / API 35). Result: 247 packages installed, 241 pulled,
#   6 failures -- all six were `auto_generated_rro_*` / `*.overlay` runtime
#   resource overlays, which carry no DEX at all and therefore cost the sweep
#   nothing. 254 classes*.dex entries, 234 STORED and 20 DEFLATED. The corpus
#   was deleted afterwards.
#
# AUTHORISED TESTING ONLY. Pull from a device you own.

set -u

OUT="${1:-}"
[ -n "$OUT" ] || { echo "usage: $0 <output-dir> [-s serial]"; exit 2; }
shift
ADB="adb"
if [ "${1:-}" = "-s" ]; then ADB="adb -s $2"; fi

mkdir -p "$OUT" || exit 2
case "$OUT" in
    *Android-Pentesting-Notes*)
        echo "refusing to write APKs inside the repository -- pick a directory outside it"
        exit 2 ;;
esac

LIST="$OUT/.pkglist"
$ADB shell 'pm list packages -f' </dev/null 2>/dev/null | tr -d '\r' \
    | sed 's/^package://' > "$LIST"

total=0; ok=0; fail=0
FAILED=""
while IFS= read -r line; do
    [ -z "$line" ] && continue
    apk="${line%=*}"
    pkg="${line##*=}"
    total=$((total + 1))
    # </dev/null on every adb call inside a read loop: adb inherits stdin and
    # will otherwise consume the loop's own input, so the loop runs once and
    # exits cleanly, looking exactly like a device with one package on it.
    if $ADB pull "$apk" "$OUT/$pkg.apk" >/dev/null 2>&1 </dev/null; then
        ok=$((ok + 1))
    else
        fail=$((fail + 1))
        FAILED="$FAILED $pkg"
    fi
done < "$LIST"
rm -f "$LIST"

echo
echo "installed packages : $total"
echo "pulled             : $ok"
echo "could not pull     : $fail"
if [ "$fail" -gt 0 ]; then
    echo "  the ones that failed, named so the denominator is checkable:"
    for f in $FAILED; do echo "    $f"; done
    echo "  (runtime resource overlays carry no DEX and cost a DEX sweep nothing;"
    echo "   anything else in that list is a real gap in your corpus)"
fi

echo
echo "classes*.dex compression split (STORED entries are the ones a device-side"
echo "grep over .apk files can see; DEFLATED ones are invisible to it):"
python3 -B - "$OUT" <<'PY'
import glob, os, sys, zipfile
stored = deflated = apks = 0
for p in sorted(glob.glob(os.path.join(sys.argv[1], "*.apk"))):
    apks += 1
    try:
        with zipfile.ZipFile(p) as z:
            for i in z.infolist():
                n = i.filename
                if n.startswith("classes") and n.endswith(".dex"):
                    if i.compress_type == zipfile.ZIP_STORED:
                        stored += 1
                    else:
                        deflated += 1
    except Exception as e:
        print("  unreadable: %s (%s)" % (os.path.basename(p), e))
print("  apks=%d  classes*.dex=%d  STORED=%d  DEFLATED=%d"
      % (apks, stored + deflated, stored, deflated))
PY

echo
echo "corpus is in $OUT -- delete it when you are finished."
