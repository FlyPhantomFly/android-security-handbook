#!/usr/bin/env bash
#
# session.sh — open a reproducible dynamic-analysis session against a target package.
#
# WHAT IT DOES
#   Captures the device environment, the package record, and a baseline snapshot of
#   the app's data directory; starts frida-server if it is present; clears logcat and
#   begins recording; then launches the app. Everything is written to a timestamped
#   evidence directory so that a colleague can reproduce and verify your findings.
#
#   Reproducibility is the difference between a hobbyist's session and a
#   professional's. See ../README.md section 9.
#
# HOW TO RUN
#   ./session.sh com.example.target [evidence-root]
#   ...exercise the app...
#   ./session.sh --stop com.example.target [evidence-root]
#
# REQUIREMENTS
#   adb on PATH; optionally frida-server at /data/local/tmp/frida-server on the device.
#   Root is optional — the script degrades gracefully without it.

set -uo pipefail

STOP=0
if [[ "${1:-}" == "--stop" ]]; then STOP=1; shift; fi

PKG="${1:-}"
if [[ -z "$PKG" ]]; then
    echo "usage: $0 [--stop] <package> [evidence-root]" >&2
    exit 1
fi
ROOT="${2:-evidence}"
DIR="$ROOT/$PKG"

# ---------------------------------------------------------------- stop mode ---
if [[ "$STOP" == "1" ]]; then
    LATEST=$(ls -1d "$DIR"/*/ 2>/dev/null | tail -1)
    if [[ -z "$LATEST" ]]; then echo "no session found under $DIR" >&2; exit 1; fi
    if [[ -f "$LATEST/logcat.pid" ]]; then
        kill "$(cat "$LATEST/logcat.pid")" 2>/dev/null && echo "stopped logcat capture"
        rm -f "$LATEST/logcat.pid"
    fi
    echo "== Post-session snapshot =="
    if adb shell 'command -v su >/dev/null' 2>/dev/null; then
        adb shell "su -c 'tar czf /sdcard/_after.tgz -C /data/data/$PKG . 2>/dev/null'" || true
        adb pull /sdcard/_after.tgz "$LATEST/data-after.tgz" >/dev/null 2>&1 && echo "  data-after.tgz"
        adb shell rm -f /sdcard/_after.tgz
    else
        adb shell "run-as $PKG sh -c 'tar czf - .'" > "$LATEST/data-after.tgz" 2>/dev/null \
            && echo "  data-after.tgz (via run-as)" \
            || echo "  could not snapshot data (not rooted, app not debuggable)"
    fi
    echo
    echo "Session closed: $LATEST"
    echo "Diff the snapshots:"
    echo "  mkdir -p /tmp/b /tmp/a"
    echo "  tar xzf $LATEST/data-before.tgz -C /tmp/b 2>/dev/null"
    echo "  tar xzf $LATEST/data-after.tgz  -C /tmp/a 2>/dev/null"
    echo "  diff -rq /tmp/b /tmp/a"
    exit 0
fi

# --------------------------------------------------------------- start mode ---
STAMP=$(date +%Y%m%d-%H%M%S)
EV="$DIR/$STAMP"
mkdir -p "$EV"

echo "== Waiting for device =="
adb wait-for-device

echo "== Device environment =="
{
    for p in ro.build.fingerprint ro.build.version.release ro.build.version.sdk \
             ro.build.version.security_patch ro.build.tags ro.build.type \
             ro.product.model ro.product.manufacturer ro.product.cpu.abi \
             ro.boot.verifiedbootstate ro.boot.flash.locked ro.debuggable ro.secure; do
        echo "$p = $(adb shell getprop $p | tr -d '\r')"
    done
    echo "selinux = $(adb shell getenforce | tr -d '\r')"
    echo "rooted  = $(adb shell 'command -v su >/dev/null && echo yes || echo no' | tr -d '\r')"
} | tee "$EV/device.txt"

echo
echo "== Package record =="
if ! adb shell pm path "$PKG" >/dev/null 2>&1; then
    echo "  package $PKG is not installed" >&2
    exit 1
fi
adb shell pm path "$PKG" | tee "$EV/apk-paths.txt"
adb shell dumpsys package "$PKG" > "$EV/dumpsys-package.txt"
echo "  dumpsys-package.txt written ($(wc -l < "$EV/dumpsys-package.txt") lines)"

# Pull the APK(s) so the static and dynamic evidence refer to the same binary.
echo
echo "== Pulling APK(s) =="
mkdir -p "$EV/apk"
while read -r line; do
    p="${line#package:}"; p="$(echo "$p" | tr -d '\r')"
    [[ -z "$p" ]] && continue
    adb pull "$p" "$EV/apk/" >/dev/null 2>&1 && echo "  $(basename "$p")"
done < <(adb shell pm path "$PKG")
( cd "$EV/apk" && (sha256sum * 2>/dev/null || shasum -a 256 * 2>/dev/null) ) > "$EV/apk/SHA256SUMS"

echo
echo "== Exported component summary =="
grep -E "^\s+(Activity|Service|Receiver|Provider)|exported=true|filter" "$EV/dumpsys-package.txt" \
    | head -60 | tee "$EV/exported-summary.txt" >/dev/null
echo "  exported-summary.txt written"

echo
echo "== Baseline data snapshot =="
if adb shell 'command -v su >/dev/null' 2>/dev/null; then
    adb shell "su -c 'tar czf /sdcard/_before.tgz -C /data/data/$PKG . 2>/dev/null'" || true
    adb pull /sdcard/_before.tgz "$EV/data-before.tgz" >/dev/null 2>&1 && echo "  data-before.tgz"
    adb shell rm -f /sdcard/_before.tgz
else
    adb shell "run-as $PKG sh -c 'tar czf - .'" > "$EV/data-before.tgz" 2>/dev/null \
        && echo "  data-before.tgz (via run-as)" \
        || echo "  could not snapshot (not rooted, app not debuggable) — continuing"
fi

echo
echo "== frida-server =="
if adb shell 'ls /data/local/tmp/frida-server' >/dev/null 2>&1; then
    adb shell "su -c 'pgrep -f frida-server >/dev/null || (chmod 755 /data/local/tmp/frida-server; /data/local/tmp/frida-server &)'" >/dev/null 2>&1 || true
    sleep 1
    if command -v frida-ps >/dev/null 2>&1; then
        frida-ps -U >/dev/null 2>&1 && echo "  running and reachable" \
            || echo "  present but not reachable — check version match with 'frida --version'"
    else
        echo "  started (frida-ps not installed on host)"
    fi
else
    echo "  not present at /data/local/tmp/frida-server — skipping"
fi

echo
echo "== Starting log capture =="
adb logcat -c
adb logcat -G 16M >/dev/null 2>&1 || true
( adb logcat -v threadtime > "$EV/logcat.txt" 2>&1 & echo $! > "$EV/logcat.pid" )
echo "  recording to logcat.txt (pid $(cat "$EV/logcat.pid"))"

echo
echo "== Launching =="
adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 2
adb shell dumpsys window | grep -i mCurrentFocus | tee "$EV/first-screen.txt"

cat <<EOF

--------------------------------------------------------------------
Session open:  $EV

Now exercise the application. Useful in another terminal:

  adb logcat --pid=\$(adb shell pidof -s $PKG)
  frida -U -n $PKG -l your-script.js
  objection -g $PKG explore

When finished:

  $0 --stop $PKG $ROOT
--------------------------------------------------------------------
EOF
