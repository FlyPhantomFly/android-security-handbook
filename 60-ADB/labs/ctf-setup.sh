#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ctf-setup.sh -- build the "unattended terminal" scenario for
#                 lab-04-ctf-unattended-terminal.md on a DISPOSABLE target.
#
# WHAT IT DOES
#   Plants four artefacts on an emulator so that the CTF has something to
#   find. Every one of them mirrors a real thing you would meet on a badly
#   configured kiosk:
#
#     1. a kiosk "provisioning" directory under /data/local/tmp
#     2. a plausible operator config file with a credential in it
#     3. an install session that was created and written but NEVER committed,
#        leaving a staged APK in /data/app/vmdl<session>.tmp
#     4. a marker file recording when the fleet was provisioned
#
#   It changes NOTHING about the device's ADB posture. It does not run
#   `adb tcpip`, does not touch /data/misc/adb, and does not modify any
#   property. The emulator is already in the misconfigured state the CTF
#   describes (ro.adb.secure=0), which is the whole point -- that state is
#   shipped, not created here.
#
# HOW TO RUN
#   # host -- against an EMULATOR you can throw away
#   ./ctf-setup.sh -s emulator-5554
#
#   # tear it all down again
#   ./ctf-setup.sh -s emulator-5554 --teardown
#
#   # print the flags (instructor mode -- do not run this before you solve it)
#   ./ctf-setup.sh -s emulator-5554 --spoilers
#
# REQUIREMENTS
#   bash, `adb` on PATH, and an emulator. For artefact 3 you need an APK to
#   stage; the script builds a throwaway one if the SDK build-tools are
#   available, and falls back to staging a copy of an existing system APK
#   otherwise (which is fine -- the CTF is about finding the staging
#   directory, not about the APK's contents).
#
# WHAT THIS WILL *NOT* DO
#   - Run on a physical device. It refuses unless the serial starts with
#     "emulator-", because artefact 3 leaves an orphaned install session and
#     artefact 1 writes to /data/local/tmp. Neither is something to do to a
#     phone you use.
#   - Create the vulnerability. The emulator ships ro.adb.secure=0 and a
#     listening TCP port; this script does not make the device less secure and
#     will not do so if you ask it to.
#   - Simulate authentication. If you want the A_AUTH branch, you need a
#     device with ro.adb.secure=1, and that is a different exercise.
#   - Clean up after a failed run automatically. Use --teardown.
# ---------------------------------------------------------------------------

set -uo pipefail

# Git Bash on Windows rewrites anything that looks like a Unix path when it is
# passed to a native .exe, which turns /data/local/tmp into C:/Program Files/...
# and turns a working script into a baffling one. Turn it off for the whole
# script, and convert paths explicitly where a Windows binary needs one.
export MSYS_NO_PATHCONV=1

winpath() {  # -> a path the SDK's native tools will accept
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

SERIAL=""
MODE="setup"

while [ $# -gt 0 ]; do
  case "$1" in
    -s) SERIAL="$2"; shift 2 ;;
    --teardown) MODE="teardown"; shift ;;
    --spoilers) MODE="spoilers"; shift ;;
    -h|--help) sed -n '2,45p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$SERIAL" ]; then
  SERIAL="$(adb devices | awk 'NR>1 && $2=="device" {print $1; exit}')"
fi

case "$SERIAL" in
  emulator-*) : ;;
  *)
    echo "REFUSING to run against '$SERIAL'." >&2
    echo "This script leaves an orphaned install session and writes to" >&2
    echo "/data/local/tmp. Use an emulator: -s emulator-5554" >&2
    exit 1
    ;;
esac

ADB=(adb -s "$SERIAL")
KIOSK=/data/local/tmp/kiosk

FLAG1_NOTE='CH60{banner_is_<ro.product.device>}'
FLAG2='CH60{unauthenticated_shell_on_a_public_network}'
FLAG3='CH60{staged_but_never_committed}'
FLAG4_NOTE='CH60{keys_<count>_last_<YYYY-MM-DD>}'

# ---------------------------------------------------------------------------

if [ "$MODE" = "spoilers" ]; then
  cat <<EOF
FLAG 1  computed from the banner:      $FLAG1_NOTE
        e.g. for an emulator reporting ro.product.device=emu64xa16k the
        answer is CH60{banner_is_emu64xa16k}
FLAG 2  planted in $KIOSK/operator.json:
        $FLAG2
FLAG 3  planted in the staged APK's assets, and in the staging directory:
        $FLAG3
FLAG 4  computed from /data/misc/adb: $FLAG4_NOTE
        On an emulator with ro.adb.secure=0 the correct answer is that
        adb_keys is EMPTY OR ABSENT and the count is 0 -- which is the point.
FLAG 5  no string. It is the written finding; see the rubric in the lab.
EOF
  exit 0
fi

if [ "$MODE" = "teardown" ]; then
  echo "== tearing down =="
  "${ADB[@]}" shell "rm -rf $KIOSK" 2>/dev/null
  "${ADB[@]}" shell 'for s in $(cmd package install-list 2>/dev/null | grep -oE "sessionId=[0-9]+" | cut -d= -f2); do cmd package install-abandon $s; done' 2>/dev/null
  # Sessions created by this script are recorded so they can be abandoned
  # even on builds where install-list does not exist.
  if [ -f .ctf-sessions ]; then
    while read -r s; do
      [ -n "$s" ] && "${ADB[@]}" shell "cmd package install-abandon $s" 2>/dev/null
    done < .ctf-sessions
    rm -f .ctf-sessions
  fi
  "${ADB[@]}" uninstall com.pentest.ch60.kiosk 2>/dev/null
  echo "done. Verify with:  adb -s $SERIAL shell ls /data/local/tmp"
  exit 0
fi

# ---------------------------------------------------------------------------
echo "== target =="
"${ADB[@]}" shell 'getprop ro.product.device; getprop ro.adb.secure; getprop ro.debuggable' | tr -d '\r'
echo ""

echo "== artefact 1+2: the kiosk provisioning directory =="
"${ADB[@]}" shell "mkdir -p $KIOSK" >/dev/null

"${ADB[@]}" shell "cat > $KIOSK/operator.json" <<EOF
{
  "_comment": "Generated by the fleet provisioning tool. Do not edit by hand.",
  "site": "Northgate Centre - Level 2 - Unit 14",
  "terminal_id": "NGC-L2-014",
  "provisioned": "2026-03-02T09:41:00Z",
  "support": {
    "note": "Debug access left enabled so support can reach units remotely.",
    "adb_over_network": true,
    "port": 5555
  },
  "operator_pin": "4417",
  "flag": "$FLAG2"
}
EOF

"${ADB[@]}" shell "cat > $KIOSK/provisioning.log" <<'EOF'
2026-03-02 09:38:11  fleet-tool  connecting to terminal over adb
2026-03-02 09:38:14  fleet-tool  device banner read, model matched profile 'kiosk-v3'
2026-03-02 09:39:02  fleet-tool  pushing operator.json
2026-03-02 09:39:55  fleet-tool  install-create  (session opened)
2026-03-02 09:40:31  fleet-tool  install-write   8538 bytes streamed
2026-03-02 09:40:31  fleet-tool  ERROR: link lost before install-commit
2026-03-02 09:41:00  fleet-tool  giving up, marking terminal provisioned anyway
EOF

"${ADB[@]}" shell "ls -l $KIOSK" | tr -d '\r'
echo ""

echo "== artefact 3: an install session that was never committed =="

APK=""
SDK="${ANDROID_HOME:-$HOME/AppData/Local/Android/Sdk}"
BT="$(ls -d "$SDK"/build-tools/* 2>/dev/null | sort -V | tail -1)"
WORK="$(mktemp -d 2>/dev/null || echo /tmp/ch60ctf)"
mkdir -p "$WORK"

if [ -n "$BT" ] && [ -x "$BT/aapt2" -o -x "$BT/aapt2.exe" ] ; then
  echo "  building a throwaway APK with $BT"
  mkdir -p "$WORK/assets"
  printf '%s\n' "$FLAG3" > "$WORK/assets/flag.txt"
  cat > "$WORK/AndroidManifest.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.pentest.ch60.kiosk"
    android:versionCode="3" android:versionName="3.0">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="30" />
    <application android:label="Kiosk Terminal" android:hasCode="false" />
</manifest>
XML
  AAPT2="$BT/aapt2"; [ -x "$AAPT2" ] || AAPT2="$BT/aapt2.exe"
  ZA="$BT/zipalign";  [ -x "$ZA" ]   || ZA="$BT/zipalign.exe"
  AS="$BT/apksigner"; [ -x "$AS" ]   || AS="$BT/apksigner.bat"
  ANDROID_JAR="$(ls -d "$SDK"/platforms/android-*/android.jar 2>/dev/null | sort -V | tail -1)"

  cd "$WORK" || exit 1
  BUILDLOG="$WORK/build.log"

  "$AAPT2" link -o unsigned.apk \
      --manifest "$(winpath "$WORK/AndroidManifest.xml")" \
      -I "$(winpath "$ANDROID_JAR")" -A "$(winpath "$WORK/assets")" \
      --min-sdk-version 21 --target-sdk-version 30 >"$BUILDLOG" 2>&1 \
    || echo "  aapt2 failed -- see $BUILDLOG"

  if [ -f unsigned.apk ]; then
    "$ZA" -p -f 4 unsigned.apk aligned.apk >>"$BUILDLOG" 2>&1 \
      || echo "  zipalign failed -- see $BUILDLOG"
  fi

  if [ -f aligned.apk ]; then
    "$AS" sign --ks "$(winpath "$HOME/.android/debug.keystore")" \
        --ks-pass pass:android \
        --ks-key-alias androiddebugkey --key-pass pass:android \
        --out kiosk.apk aligned.apk >>"$BUILDLOG" 2>&1 \
      || echo "  apksigner failed -- see $BUILDLOG"
  fi

  cd - >/dev/null || true
  if [ -f "$WORK/kiosk.apk" ]; then
    APK="$WORK/kiosk.apk"
    echo "  built $(wc -c < "$APK" | tr -d ' ') bytes, signed with the debug keystore"
  fi
fi

if [ -z "$APK" ]; then
  echo "  build-tools not usable; staging a copy of an on-device APK instead."
  echo "  (artefact 3's flag then lives only in the .stage_marker file)"
  REMOTE="$("${ADB[@]}" shell 'pm path android' | tr -d '\r' | sed 's/^package://')"
  if [ -n "$REMOTE" ]; then
    "${ADB[@]}" pull "$REMOTE" "$WORK/kiosk.apk" >/dev/null 2>&1 && APK="$WORK/kiosk.apk"
  fi
fi

if [ ! -f "$APK" ]; then
  echo "  FAILED to obtain an APK to stage. Artefact 3 will be skipped." >&2
else
  SIZE=$(wc -c < "$APK" | tr -d ' ')
  SESSION="$("${ADB[@]}" shell "cmd package install-create -r -S $SIZE" \
             | tr -d '\r' | grep -oE '\[[0-9]+\]' | tr -d '[]')"
  if [ -n "$SESSION" ]; then
    echo "$SESSION" >> .ctf-sessions
    # The LOCAL path must be one adb.exe understands; MSYS_NO_PATHCONV means
    # bash will not translate it for us, so do it explicitly.
    "${ADB[@]}" push "$(winpath "$APK")" /data/local/tmp/.stage.apk >/dev/null 2>&1
    "${ADB[@]}" shell "cmd package install-write -S $SIZE $SESSION base /data/local/tmp/.stage.apk" \
      | tr -d '\r' | sed 's/^/  /'
    "${ADB[@]}" shell 'rm -f /data/local/tmp/.stage.apk'
    echo "  session $SESSION written and DELIBERATELY NOT COMMITTED"
    echo "  staged at /data/app/vmdl$SESSION.tmp"
    "${ADB[@]}" shell "cat > $KIOSK/.stage_marker" <<EOF
$FLAG3
EOF
    "${ADB[@]}" shell "chmod 600 $KIOSK/.stage_marker" 2>/dev/null
  else
    echo "  could not create an install session" >&2
  fi
fi
[ -f "$WORK/build.log" ] && cp "$WORK/build.log" ./ctf-build.log 2>/dev/null
rm -rf "$WORK"
echo ""

echo "== artefact 4: fleet marker =="
"${ADB[@]}" shell "cat > $KIOSK/fleet.txt" <<'EOF'
fleet: northgate-kiosks
image: kiosk-v3 (2026-03-02)
note:  every terminal in this fleet was imaged from the same master.
       whatever is true of this one is true of all forty-one.
EOF
"${ADB[@]}" shell "ls -la $KIOSK" | tr -d '\r'

echo ""
echo "=========================================================="
echo "Scenario is live on $SERIAL."
echo "Open labs/lab-04-ctf-unattended-terminal.md and start at Flag 1."
echo "Tear down afterwards:  ./ctf-setup.sh -s $SERIAL --teardown"
echo "=========================================================="
