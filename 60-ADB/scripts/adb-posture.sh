#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# adb-posture.sh -- report the ADB attack surface of a device you are holding:
#                   what adbd is, what privilege it runs at, whether it is
#                   reachable over the network, and which host keys are
#                   permanently authorised to drive it.
#
# WHY THIS EXISTS
#   "ADB is enabled" is not a finding. "ADB is enabled, listening on TCP,
#   with four authorised host keys and no screen lock, on a device sitting in
#   a shop window" is a critical one. The difference is entirely in the facts
#   this script collects. It exists so that an ADB finding in your report is
#   backed by measurements rather than by the observation that `adb devices`
#   printed something.
#
# WHAT IT REPORTS
#   1.  adbd's identity     -- uid, SELinux domain, binary path (APEX or not),
#                              its argv, and its capability sets.
#   2.  The build's stance  -- ro.secure, ro.debuggable, ro.build.type,
#                              ro.adb.secure, and whether `adb root` can work.
#   3.  Network exposure    -- service.adb.tcp.port, persist.adb.tcp.port,
#                              adb_wifi_enabled, and any listening socket that
#                              looks like adbd.
#   4.  Authorised keys     -- how many entries are in
#                              /data/misc/adb/adb_keys, when adb_temp_keys.xml
#                              last saw each of them, and the DAC and MAC
#                              labels on both. It prints COUNTS AND METADATA,
#                              never key bytes.
#   5.  The shell identity  -- uid, groups, SELinux context, and the
#                              capability bounding set of the shell you get.
#   6.  A severity call     -- with the reasoning shown, so you can disagree
#                              with it.
#
# HOW TO RUN
#   # host, one device attached
#   ./adb-posture.sh
#
#   # a specific device
#   ./adb-posture.sh -s 84f7a024
#
#   # include the root-only checks (uses `su -c`; only on a device you rooted)
#   ./adb-posture.sh --root
#
#   # machine readable, one key=value per line, for diffing a fleet
#   ./adb-posture.sh --kv
#
# REQUIREMENTS
#   bash, `adb` on PATH, one device attached and already authorised. Nothing
#   else. Every check is READ-ONLY: this script never sets a property, never
#   enables TCP mode, never writes to /data/misc/adb, and never restarts adbd.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - WHOSE keys are authorised. adb_keys stores public keys and a free-text
#     comment the host chose; nothing binds either to a person, and the
#     comment is trivially forged. A count of 4 tells you four hosts can
#     connect. It cannot tell you they are four hosts you trust.
#   - Whether a key is currently in use. There is no "last used" field in
#     adb_keys itself; adb_temp_keys.xml carries a lastConnection timestamp,
#     but only for keys the framework is tracking for auto-revocation.
#   - Whether TCP mode was left on deliberately. service.adb.tcp.port is
#     cleared by a reboot; persist.adb.tcp.port is not. Seeing the persist
#     form set is much stronger evidence of an intentional, permanent
#     exposure -- the script says which one it found.
#   - Anything about a device you cannot already talk to. This is a posture
#     check for a device in your hand, not a scanner. If you want to know
#     whether port 5555 is open across a network, that is a port scan, it is
#     a different activity, and it needs written authorisation.
#   - Whether the OEM changed the rules. Several vendors gate installs,
#     wireless debugging or `adb root` with their own policies that no
#     property reveals. Where a check cannot be answered the script prints
#     "unknown" rather than guessing.
# ---------------------------------------------------------------------------

set -uo pipefail

SERIAL=""
USE_ROOT=0
KV=0

while [ $# -gt 0 ]; do
  case "$1" in
    -s) SERIAL="$2"; shift 2 ;;
    --root) USE_ROOT=1; shift ;;
    --kv) KV=1; shift ;;
    -h|--help) sed -n '2,70p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

sh_() { "${ADB[@]}" shell "$@" 2>/dev/null | tr -d '\r'; }
prop() { sh_ getprop "$1"; }

emit() {  # emit KEY "value"
  if [ "$KV" = "1" ]; then printf '%s=%s\n' "$1" "$2"
  else printf '  %-34s %s\n' "$1" "$2"; fi
}
head_() { [ "$KV" = "1" ] || { echo; echo "== $* =="; }; }

if ! "${ADB[@]}" get-state >/dev/null 2>&1; then
  echo "no device (adb get-state failed). Attach one and authorise it." >&2
  exit 1
fi

# --------------------------------------------------------------------------
head_ "Device"
emit device.model          "$(prop ro.product.model)"
emit device.fingerprint    "$(prop ro.build.fingerprint)"
emit device.release        "$(prop ro.build.version.release)"
emit device.sdk            "$(prop ro.build.version.sdk)"
emit device.security_patch "$(prop ro.build.version.security_patch)"
emit device.abi            "$(prop ro.product.cpu.abi)"

# --------------------------------------------------------------------------
head_ "Build stance -- what adbd is ALLOWED to be"
RO_SECURE="$(prop ro.secure)"
RO_DEBUGGABLE="$(prop ro.debuggable)"
BUILD_TYPE="$(prop ro.build.type)"
ADB_SECURE="$(prop ro.adb.secure)"

emit build.ro.secure       "${RO_SECURE:-unset}"
emit build.ro.debuggable   "${RO_DEBUGGABLE:-unset}"
emit build.type            "${BUILD_TYPE:-unknown}"
emit build.tags            "$(prop ro.build.tags)"
emit build.ro.adb.secure   "${ADB_SECURE:-unset}"

# `adb root` is honoured only where ro.debuggable is 1. On a user build adbd
# refuses and says so, without restarting -- which is why running it is a
# read-only probe and not a state change.
if [ "$RO_DEBUGGABLE" = "1" ]; then
  emit adb.root.permitted "yes (ro.debuggable=1) -- adb root will restart adbd as uid 0"
else
  emit adb.root.permitted "no (ro.debuggable=$RO_DEBUGGABLE) -- adb root will be refused; root comes from su instead"
fi

if [ "$ADB_SECURE" = "1" ]; then
  emit adb.authentication "REQUIRED -- adbd sends A_AUTH and verifies a signature"
else
  emit adb.authentication "NOT REQUIRED -- any host that can reach adbd is trusted immediately"
fi

# --------------------------------------------------------------------------
head_ "adbd itself"
ADBD_LINE="$(sh_ "ps -A -o PID,USER,LABEL,NAME" | awk '$4 ~ /(^|\/)adbd$/ {print; exit}')"
if [ -z "$ADBD_LINE" ]; then
  emit adbd.process "NOT FOUND in ps (unexpected -- you are talking to it)"
else
  emit adbd.pid    "$(echo "$ADBD_LINE" | awk '{print $1}')"
  emit adbd.user   "$(echo "$ADBD_LINE" | awk '{print $2}')"
  emit adbd.selinux "$(echo "$ADBD_LINE" | awk '{print $3}')"
fi
emit adbd.init.state "$(prop init.svc.adbd)"

# The parent of your shell IS adbd. This is the cheapest proof that an
# `adb shell` process is not an app: it was forked by a native daemon, it has
# no zygote in its ancestry, and no Application object was ever created.
PPCMD="$(sh_ 'cat /proc/$(cut -d" " -f4 /proc/$$/stat)/cmdline' | tr '\0' ' ')"
emit shell.parent "${PPCMD:-unknown}"

case "$PPCMD" in
  */apex/com.android.adbd/*) emit adbd.origin "APEX (com.android.adbd) -- updatable without an OS update" ;;
  */system/bin/adbd*)        emit adbd.origin "/system/bin/adbd -- not modularised on this build" ;;
  *)                         emit adbd.origin "unknown" ;;
esac

# --------------------------------------------------------------------------
head_ "Network exposure"
TCP_PORT="$(prop service.adb.tcp.port)"
PERSIST_PORT="$(prop persist.adb.tcp.port)"
WIFI_DBG="$(sh_ settings get global adb_wifi_enabled)"
ADB_ENABLED="$(sh_ settings get global adb_enabled)"

emit settings.adb_enabled       "${ADB_ENABLED:-unknown}"
emit settings.adb_wifi_enabled  "${WIFI_DBG:-unknown}"
emit tcp.service.adb.tcp.port   "${TCP_PORT:-unset (USB only until next adb tcpip)}"
emit tcp.persist.adb.tcp.port   "${PERSIST_PORT:-unset}"

LISTEN="$(sh_ 'cat /proc/net/tcp /proc/net/tcp6 2>/dev/null' \
          | awk '$4=="0A" {print $2}' | awk -F: '{print strtonum("0x" $2)}' \
          | sort -un | tr '\n' ' ')"
emit tcp.listening.ports "${LISTEN:-none visible to the shell user}"
case " $LISTEN " in
  *" 5555 "*) emit tcp.5555 "OPEN -- the classic adb-over-TCP port is listening" ;;
  *)          emit tcp.5555 "not listening" ;;
esac

# A listening socket beats a property. The emulator is the case that proves
# it: its adbd listens on 5555 with service.adb.tcp.port unset, because the
# emulator's adbd is started in TCP mode by the emulator itself rather than by
# the property trigger. Trust what is listening, not what is configured.
EXPOSED=0
[ -n "$TCP_PORT" ] && [ "$TCP_PORT" != "-1" ] && EXPOSED=1
[ -n "$PERSIST_PORT" ] && [ "$PERSIST_PORT" != "-1" ] && EXPOSED=1
[ "$WIFI_DBG" = "1" ] && EXPOSED=1
case " $LISTEN " in *" 5555 "*) EXPOSED=1 ;; esac

emit tcp.exposed "$([ "$EXPOSED" = "1" ] && echo YES || echo no)"

# --------------------------------------------------------------------------
head_ "Authorised host keys (counts and metadata only -- never key bytes)"

KEYDIR_LS="$(sh_ 'ls -ldZ /data/misc/adb 2>&1')"
emit keys.dir "$KEYDIR_LS"

if echo "$KEYDIR_LS" | grep -q 'Permission denied'; then
  emit keys.readable.as.shell "NO -- and that is correct"
  emit keys.why "the shell domain is denied even a dir search on adb_keys_file; DAC on /data/misc/adb is 02750 system:shell, so the group bit says yes and SELinux says no. Confirm with: adb shell 'dmesg | grep adb_keys' on a device where you can read the kernel log."
else
  emit keys.readable.as.shell "YES -- unusual; check the SELinux policy on this build"
fi

if [ "$USE_ROOT" = "1" ]; then
  ROOT_ID="$(sh_ 'su -c id' | head -1)"
  if echo "$ROOT_ID" | grep -q 'uid=0'; then
    emit keys.count       "$(sh_ "su -c 'wc -l < /data/misc/adb/adb_keys'" | tr -d ' ')"
    emit keys.bytes       "$(sh_ "su -c 'wc -c < /data/misc/adb/adb_keys'" | tr -d ' ')"
    emit keys.mode        "$(sh_ "su -c 'ls -lZ /data/misc/adb/adb_keys'")"
    # Field widths only. A 2048-bit adb public key is a 524-byte struct, so
    # every entry's base64 field is 700 characters. Anything else is worth a
    # second look, and none of this reveals the key.
    emit keys.field.widths "$(sh_ "su -c 'awk \"{print length(\\\$1)}\" /data/misc/adb/adb_keys'" | tr '\n' ' ')"
    TEMP="$(sh_ "su -c 'cat /data/misc/adb/adb_temp_keys.xml'" 2>/dev/null)"
    emit keys.temp.entries "$(printf '%s' "$TEMP" | grep -c '<adbKey ')"
    printf '%s\n' "$TEMP" | grep -oE 'lastConnection="[0-9]+"' | while read -r L; do
      MS="${L#lastConnection=\"}"; MS="${MS%\"}"
      emit keys.temp.lastConnection "$MS  ($(date -d "@$((MS/1000))" 2>/dev/null || echo 'epoch ms'))"
    done
  else
    emit keys.count "unknown -- su did not return uid=0"
  fi
else
  emit keys.count "not read (needs root; re-run with --root on a device you rooted)"
fi

# --------------------------------------------------------------------------
head_ "The shell identity you are actually driving"
emit shell.id       "$(sh_ id)"
emit shell.selinux  "$(sh_ 'id -Z')"
emit shell.caps     "$(sh_ 'grep -E "^Cap(Eff|Bnd)" /proc/self/status' | tr '\n' ' ')"
emit shell.package  "$(sh_ 'dumpsys package com.android.shell' | grep -m1 'userId=' | tr -d ' ')"
emit shell.runtime.perms.granted \
     "$(sh_ 'dumpsys package com.android.shell' \
        | awk '/runtime permissions:/{f=1;next} /^ *User [0-9]+:/{f=0} f' \
        | grep -c 'granted=true')"

# --------------------------------------------------------------------------
head_ "Severity call"
if [ "$KV" = "1" ]; then
  emit severity.exposed "$EXPOSED"
  exit 0
fi

echo
if [ "$EXPOSED" = "1" ]; then
  cat <<'EOF'
  ADB IS REACHABLE OVER THE NETWORK ON THIS DEVICE.

  Rate this on the device's role, not on the fact itself:
    * a test device on your own bench            -> methodology note, not a finding
    * a developer's daily phone on office wifi   -> medium; document and turn it off
    * a kiosk, till, signage panel, TV, vehicle
      head unit or any unattended device         -> high to critical

  The reason it is critical on an unattended device is that ADB over TCP plus
  an authorised key is a remote shell as uid 2000 with 180-odd platform
  permissions, and on many embedded builds ro.debuggable is 1, which makes it
  a remote shell as root. If ro.adb.secure is 0 as well, no key is needed at
  all -- anyone who can route a packet to the port owns the device.
EOF
else
  cat <<'EOF'
  ADB is USB-only on this device right now.

  "USB debugging is enabled" on its own is NOT a finding on a test device and
  should not be written up as one. It becomes a finding when it is combined
  with something: an unattended device an attacker can physically reach, a
  build where ro.adb.secure is 0, an authorised key on a host you do not
  control, or a screen lock that is absent so the authorisation dialog can be
  accepted by whoever is holding it.
EOF
fi

cat <<'EOF'

  Whatever you conclude, record it with the evidence above attached, and say
  which device role you assumed. A severity without a stated role is a guess.
EOF
