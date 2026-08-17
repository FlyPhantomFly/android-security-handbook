#!/usr/bin/env bash
# token-storage-sweep.sh — find where an Android app keeps its tokens at rest, and grade
# each hit by how reachable it actually is.
#
# PURPOSE
#   Chapter 45 gets you a token off the wire. This script answers the next question:
#   is there a copy of it sitting on the device, and who can reach it? It walks an app's
#   private storage, the shared external volumes, the backup surface, AccountManager and
#   logcat, and prints every candidate with the evidence needed to decide whether it is a
#   finding or noise.
#
#   It deliberately grades REACHABILITY, not just presence. A token in an app's own
#   private directory on a locked, unrooted, stock device is where a token is supposed to
#   live. The same token in /sdcard, or in a world-readable file, or in a logcat line, is
#   a different thing entirely. The distinction is the whole of chapter 33 section 5.3
#   and chapter 46 section 5.10, and a sweep that ignores it produces a report full of
#   "SharedPreferences contains a token" that a competent reviewer will reject.
#
# USAGE
#   ./token-storage-sweep.sh com.example.target
#   ./token-storage-sweep.sh com.example.target --serial 80062527052150
#   ./token-storage-sweep.sh com.example.target --logcat 60     # also watch logcat 60s
#   ./token-storage-sweep.sh --host-dir ./pulled-data           # sweep an extracted copy
#
# REQUIREMENTS
#   bash, adb on PATH, a connected device. Optional: `jq` for prettier JSON, `python3`
#   for the analyser hand-off. No root REQUIRED, but see the honesty section below.
#
# ACCESS LEVELS -- read this before believing an empty result
#   The sweep can only see what the shell it runs in can see. Measured on the i9000S
#   (Android 13 / API 33) attached while this chapter was written:
#
#       $ adb shell su -c id
#       /system/bin/sh: su: inaccessible or not found
#       $ adb shell run-as com.synergyenf ls
#       run-as: package not debuggable: com.synergyenf
#       $ adb shell ls -ld /data/data/com.synergyenf
#       ls: /data/data/com.synergyenf: Permission denied
#
#   All three doors were shut, which is the correct behaviour of a stock device and the
#   normal starting position on a real engagement. In that state this script reports on
#   external storage, the manifest-derived backup surface, logcat, and nothing else --
#   and it says so rather than printing "no tokens found". The three ways in, in
#   increasing order of intrusiveness:
#       1. `run-as` -- works only if the app is android:debuggable="true"
#       2. `adb backup` -- works only if allowBackup is true AND the OEM still supports it
#       3. root -- works always, and changes the device's posture, so record that you
#          used it as methodology rather than reporting it as a finding
#
# WHAT THIS WILL NOT TELL YOU
#   * It will not tell you a token is SAFE. A negative result on an unrooted device means
#     the shell could not look, not that nothing is there.
#   * It will not tell you the token is exploitable. A token you find in your OWN test
#     account's app data, on a device you control, is not a finding on its own -- see
#     README section 5.10. It becomes one when it is reachable by another app, survives
#     logout, is over-scoped, or is long-lived.
#   * It cannot see tokens that exist only in process memory. An app that keeps its
#     access token in a Kotlin field and never persists it produces nothing here and is
#     doing the right thing. Use scripts/token-hooks.js for the in-memory picture.
#   * It cannot decrypt EncryptedSharedPreferences. It will tell you the file is Tink
#     ciphertext, which is itself useful: it means the plaintext copy, if one exists, is
#     somewhere else -- and chapter 33 section 5.4 is about how often one does.
#   * Its regexes will produce false positives. A base64 blob is not a token. Every hit
#     is a lead; feed it to scripts/jwt-analyse.py before writing anything down.
#
# SAFETY
#   Read-only. It runs no `rm`, no `pm clear`, no `settings put`, and installs nothing.
#   It does not exfiltrate: everything stays on the host running it. Chapter 46's standing
#   rule still applies -- only sweep an app whose account is yours and inside scope. On a
#   daily-driver phone, sweep only the app you are testing; do not enumerate everything.
#
# Chapter 46 — Tokens

set -uo pipefail

PKG=""
SERIAL=""
LOGCAT_SECONDS=0
HOST_DIR=""

usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --serial)    SERIAL="$2"; shift 2 ;;
        --logcat)    LOGCAT_SECONDS="$2"; shift 2 ;;
        --host-dir)  HOST_DIR="$2"; shift 2 ;;
        -h|--help)   usage ;;
        *)           PKG="$1"; shift ;;
    esac
done

ADB="adb"
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

# Patterns. Kept deliberately broad on the first pass and narrowed by hand afterwards,
# because a sweep that only matches "eyJ" misses every opaque token in the estate.
JWT_RE='eyJ[A-Za-z0-9_-]\{6,\}\.[A-Za-z0-9_-]\{4,\}\.'
KEY_RE='access_token\|refresh_token\|id_token\|id-token\|idToken\|accessToken\|refreshToken\|Bearer \|authorization\|auth_token\|authToken\|session_token\|sessionId\|JSESSIONID\|apiKey\|api_key\|AuthState'

hr()   { printf '%s\n' "------------------------------------------------------------------------"; }
head1() { hr; printf '  %s\n' "$1"; hr; }
note() { printf '  [ ] %s\n' "$1"; }
hit()  { printf '  [!] %s\n' "$1"; }

# --------------------------------------------------------------------------- #
# Host-directory mode: sweep a copy you already pulled.
# --------------------------------------------------------------------------- #
if [ -n "$HOST_DIR" ]; then
    head1 "Sweeping extracted copy: $HOST_DIR"
    note "This mode makes no device calls. Reachability CANNOT be assessed from a copy --"
    note "file modes and SELinux labels do not survive a pull. Grade reachability on the"
    note "device, then analyse content here."
    echo
    grep -rIl "$JWT_RE" "$HOST_DIR" 2>/dev/null | while read -r f; do
        hit "JWT-shaped string in $f"
        grep -oh "$JWT_RE[A-Za-z0-9_-]*" "$f" 2>/dev/null | sort -u | head -5 | sed 's/^/        /'
    done
    grep -rIl "$KEY_RE" "$HOST_DIR" 2>/dev/null | while read -r f; do
        note "token-related keyword in $f"
    done
    echo
    note "Next: python3 -B ../scripts/jwt-analyse.py --file <that file> --scan"
    exit 0
fi

[ -z "$PKG" ] && usage

# --------------------------------------------------------------------------- #
# 0. Establish what access we actually have. Do this FIRST and print it, so every
#    later "nothing found" is read against the right baseline.
# --------------------------------------------------------------------------- #
head1 "0. Access level -- read this before believing anything below"

if ! $ADB get-state >/dev/null 2>&1; then
    echo "  no device. $ADB get-state failed."; exit 2
fi

MODEL=$($ADB shell getprop ro.product.model 2>/dev/null | tr -d '\r')
SDK=$($ADB shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')
note "device        $MODEL, API $SDK"

# Try BOTH su conventions. Magisk's su takes `su -c <command>`; an AOSP emulator's
# su takes a uid and rejects -c with `su: invalid uid/gid '-c'`, which reads exactly
# like "not rooted". Probing only one form reports a rooted device as unrooted, and
# every "nothing found" below then becomes a false negative.
HAVE_ROOT=0
ROOT_FORM=""
if $ADB shell 'su -c id' 2>/dev/null | grep -q 'uid=0'; then
    HAVE_ROOT=1; ROOT_FORM="-c"; note "root          YES (su -c works)"
elif $ADB shell 'su 0 id' 2>/dev/null | grep -q 'uid=0'; then
    HAVE_ROOT=1; ROOT_FORM="0";  note "root          YES (su 0 works)"
else
    note "root          no  ($($ADB shell 'su -c id' 2>&1 | tr -d '\r' | head -1))"
fi

HAVE_RUNAS=0
if $ADB shell "run-as $PKG id" 2>/dev/null | grep -q 'uid='; then
    HAVE_RUNAS=1; note "run-as        YES (the app is debuggable)"
else
    note "run-as        no  ($($ADB shell "run-as $PKG ls" 2>&1 | tr -d '\r' | head -1))"
fi

UID_LINE=$($ADB shell "dumpsys package $PKG" 2>/dev/null | grep -m1 'userId=' | tr -d '\r')
note "package       ${UID_LINE:-not installed}"
BACKUP=$($ADB shell "dumpsys package $PKG" 2>/dev/null | grep -m1 'ALLOW_BACKUP' | tr -d '\r')
note "backup flag   ${BACKUP:-ALLOW_BACKUP not in pkgFlags -- allowBackup is false}"

if [ "$HAVE_ROOT" = 0 ] && [ "$HAVE_RUNAS" = 0 ]; then
    echo
    hit "NO ACCESS TO PRIVATE STORAGE. Sections 1 and 2 below will find nothing, and that"
    hit "is a fact about this shell, not about the app. Do not write 'no tokens stored'."
fi

SH="$ADB shell"
if [ "$HAVE_ROOT" = 1 ]; then
    # The OUTER quotes are load-bearing: adb shell joins its arguments with
    # spaces, so `adb shell su -c 'a b'` arrives as `su -c a b`.
    if [ "$ROOT_FORM" = "-c" ]; then
        RUN() { $ADB shell "su -c '$*'" 2>/dev/null | tr -d '\r'; }
    else
        RUN() { $ADB shell "su 0 $*"    2>/dev/null | tr -d '\r'; }
    fi
elif [ "$HAVE_RUNAS" = 1 ]; then
    RUN() { $ADB shell "run-as $PKG $*" 2>/dev/null | tr -d '\r'; }
else
    RUN() { :; }
fi

DATA="/data/data/$PKG"

# --------------------------------------------------------------------------- #
# 1. Private storage
# --------------------------------------------------------------------------- #
echo
head1 "1. Private storage -- $DATA"
if [ "$HAVE_ROOT" = 1 ] || [ "$HAVE_RUNAS" = 1 ]; then
    note "directory tree:"
    RUN "ls -laR $DATA" | sed 's/^/        /' | head -80

    echo
    note "files whose CONTENT matches a token pattern:"
    for sub in shared_prefs files databases cache no_backup app_webview; do
        RUN "grep -rlI '$KEY_RE' $DATA/$sub" 2>/dev/null | while read -r f; do
            [ -z "$f" ] && continue
            MODE=$(RUN "stat -c '%A %U:%G' $f")
            hit "$f   ($MODE)"
            RUN "grep -o '$JWT_RE[A-Za-z0-9_-]*' $f" | sort -u | head -3 | sed 's/^/        /'
        done
    done

    echo
    note "reachability of every hit -- this is the part that decides severity:"
    note "  a file is reachable by another app only if EVERY ancestor directory grants"
    note "  o+x AND SELinux permits it. Check both, per chapter 33 section 5.3:"
    RUN "ls -ldZ $DATA $DATA/shared_prefs $DATA/databases" | sed 's/^/        /'

    echo
    note "SQLite: rows deleted at logout survive in the WAL. Check the sidecars, not"
    note "  just the .db -- chapter 33 measured 4 'deleted' secrets still readable in a"
    note "  61,832-byte -wal file."
    RUN "ls -la $DATA/databases/" | grep -E 'wal|shm|journal' | sed 's/^/        /'

    echo
    note "EncryptedSharedPreferences leaves Tink ciphertext. A file whose values are"
    note "  base64 blobs starting with a Tink key-id prefix is encrypted; the interesting"
    note "  question is then whether an UNencrypted copy exists elsewhere in the tree."
    RUN "grep -l 'androidx.security.crypto' $DATA/shared_prefs/*.xml" | sed 's/^/        /'
else
    note "skipped -- no root and the app is not debuggable"
fi

# --------------------------------------------------------------------------- #
# 2. AccountManager
# --------------------------------------------------------------------------- #
echo
head1 "2. AccountManager"
note "AccountManager stores auth tokens in a system database keyed by account type."
note "An app that calls addAccountExplicitly/setAuthToken has moved its tokens OUT of"
note "its own sandbox and into a shared one. Which other apps can read them depends on"
note "the account type's signature and the caller's permissions."
$SH "dumpsys account" 2>/dev/null | tr -d '\r' | grep -iE "Account \{|$PKG" | head -20 | sed 's/^/        /'
if [ "$HAVE_ROOT" = 1 ]; then
    note "accounts.db (root only) -- authtokens table:"
    RUN "ls -la /data/system_ce/0/accounts_ce.db /data/system_de/0/accounts_de.db" | sed 's/^/        /'
fi

# --------------------------------------------------------------------------- #
# 3. External storage -- readable without root on any device
# --------------------------------------------------------------------------- #
echo
head1 "3. External storage"
note "Anything here left the sandbox. On API 30+ scoped storage narrows WHO can read it,"
note "but a token written to a shared collection is still a different severity from one"
note "in /data/data. Chapter 33 owns the mechanics."
for d in "/sdcard/Android/data/$PKG" "/sdcard/Download" "/sdcard"; do
    OUT=$($SH "ls -la $d 2>/dev/null" | tr -d '\r' | head -12)
    [ -n "$OUT" ] && { note "$d"; echo "$OUT" | sed 's/^/        /'; }
done
$SH "grep -rlI '$JWT_RE' /sdcard/Android/data/$PKG 2>/dev/null" | tr -d '\r' | while read -r f; do
    [ -n "$f" ] && hit "JWT-shaped string in $f -- OUTSIDE the private sandbox"
done

# --------------------------------------------------------------------------- #
# 4. Logcat
# --------------------------------------------------------------------------- #
echo
head1 "4. Logcat"
note "A token in a log line is readable by anything holding READ_LOGS, by any crash"
note "reporter, and by anyone with adb. It is the single most common way a token that"
note "was stored correctly escapes anyway."
if [ "$LOGCAT_SECONDS" -gt 0 ]; then
    PID=$($SH "pidof -s $PKG" 2>/dev/null | tr -d '\r')
    if [ -n "$PID" ]; then
        note "watching pid $PID for ${LOGCAT_SECONDS}s -- drive a login NOW"
        $ADB logcat --pid="$PID" -v time > /tmp/ch46-logcat.$$ 2>/dev/null &
        LOGPID=$!
        sleep "$LOGCAT_SECONDS"
        kill $LOGPID 2>/dev/null
        if grep -qE "$JWT_RE|Bearer |access_token" /tmp/ch46-logcat.$$; then
            hit "TOKEN MATERIAL IN LOGCAT:"
            grep -oE "$JWT_RE[A-Za-z0-9_-]*|Bearer [A-Za-z0-9._~+/=-]+" /tmp/ch46-logcat.$$ \
                | sort -u | head -10 | sed 's/^/        /'
        else
            note "nothing matched in ${LOGCAT_SECONDS}s. Repeat across a full login, a"
            note "refresh (wait for the access token to expire), and a logout."
        fi
        rm -f /tmp/ch46-logcat.$$
    else
        note "process not running -- start the app and re-run with --logcat"
    fi
else
    note "skipped. Re-run with --logcat 60 and drive a login while it watches."
    note "Or capture the buffer that is already there:"
    note "    adb logcat -d | grep -oE 'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*'"
fi

# --------------------------------------------------------------------------- #
# 5. Backup surface
# --------------------------------------------------------------------------- #
echo
head1 "5. Backup surface"
note "If allowBackup is true, the token may leave the device entirely -- to adb backup"
note "where supported, and to Google's servers via Auto Backup. Chapter 21 owns the"
note "exploitation chain; here the question is only whether the TOKEN is in scope."
$SH "dumpsys package $PKG" 2>/dev/null | tr -d '\r' | grep -E 'ALLOW_BACKUP|dataDir' | sed 's/^/        /'
note "Look for android:fullBackupContent / android:dataExtractionRules in the manifest:"
note "    a correct app excludes its token store explicitly. If the rules file does not"
note "    mention shared_prefs, the token store is being backed up."

# --------------------------------------------------------------------------- #
# 6. Process memory
# --------------------------------------------------------------------------- #
echo
head1 "6. Process memory"
if [ "$HAVE_ROOT" = 1 ]; then
    PID=$($SH "pidof -s $PKG" 2>/dev/null | tr -d '\r')
    note "pid $PID -- a token held only in memory is CORRECT design, not a finding."
    note "Reading it requires code execution in the process, which is a rooted-device"
    note "capability. Severity accordingly: see 49-KeyStore section 1.3 on extraction"
    note "versus use. Use scripts/token-hooks.js rather than a raw memory dump."
else
    note "requires root. On an unrooted device this is out of reach, which is the point:"
    note "an in-memory-only token has a materially smaller attack surface than a stored"
    note "one, and that difference is worth saying in the report."
fi

echo
hr
printf '  Next steps\n'
hr
note "1. Feed every hit to the analyser, which never transmits anything:"
note "     python3 -B scripts/jwt-analyse.py --file <pulled-file> --scan"
note "2. Grade each hit by REACHABILITY, not by presence. See README section 5.10."
note "3. Test the token you found: replay after logout, replay from another IP, check"
note "   its lifetime, check its scope. A token you cannot use is not an impact."
note "4. Record which access level produced each result. A finding from a rooted device"
note "   needs that caveat attached, every time."
