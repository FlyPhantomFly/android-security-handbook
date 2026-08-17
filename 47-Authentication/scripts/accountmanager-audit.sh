#!/usr/bin/env bash
# 47-Authentication/scripts/accountmanager-audit.sh
#
# PURPOSE
#   Audit the platform account database - what AccountManager is actually holding
#   on a device, who can see it, and which packages have been granted visibility.
#
#   It answers questions no API and no `dumpsys` will answer honestly:
#     * how many bearer tokens are cached on this device, and how long they live
#     * whether any authenticator is using the PLAINTEXT `password` column
#     * which packages each account is visible to
#     * the account modification history, with timestamps and caller uids
#
# USAGE
#   ./accountmanager-audit.sh                 # auto-select the only device
#   ./accountmanager-audit.sh -s <serial>     # pick a device
#   ./accountmanager-audit.sh -s <serial> -u 10    # a secondary/work profile user
#   ./accountmanager-audit.sh --no-root       # unprivileged pass only
#
# REQUIREMENTS
#   adb on PATH. python3 on the HOST (the databases are parsed here, not on the
#   device - most devices have no sqlite3 binary; this was measured).
#   Root on the device for the database pass; the dumpsys pass works as shell.
#
# PRIVACY - READ THIS
#   This script NEVER PRINTS A CREDENTIAL VALUE. Tokens, passwords and extras
#   values are reduced to a length, a prefix of at most 4 characters, and a
#   shape classification. That is deliberate: an audit tool that prints live
#   bearer tokens puts them in your terminal scrollback, in any screen recording
#   you are making, and eventually in a report.
#
#   It copies the databases to a temp directory on the HOST and DELETES THEM on
#   exit, including on interrupt. Run it against a device you own or are
#   authorised to assess.
#
# WHAT IT MEASURED ON THE REFERENCE DEVICE (Redmi M2101K6P, Android 11 / API 30)
#   4 accounts, 114 cached auth tokens (all non-NULL, 153-957 chars, ZERO JWTs,
#   105 of them Google `ya29` access tokens), 376 extras rows of which 131 were
#   token expiry timestamps - 106 of them already in the past. One account had a
#   352-character value in the plaintext `password` column.

set -uo pipefail

# --------------------------------------------------------------------------
# PORTABILITY: `adb pull` has TWO path arguments with OPPOSITE requirements on
# Git Bash / MSYS2, and getting one right breaks the other. This cost two
# debugging cycles; it is recorded here so nobody repeats them.
#
#   THE DEVICE PATH must stay POSIX. By default MSYS rewrites any argument
#   beginning with `/` into a Windows path, so
#       adb pull /data/local/tmp/x.db
#   reaches adb.exe as
#       adb pull 'C:/Program Files/Git/data/local/tmp/x.db'
#   and fails with "failed to stat remote object" naming a path you never typed.
#
#   THE HOST PATH must become NATIVE. adb.exe is a Windows binary: it cannot
#   write to `/tmp/tmp.XXXX/ce.db`, because that directory does not exist from
#   Windows' point of view.
#
# So setting MSYS_NO_PATHCONV=1 globally fixes the first and BREAKS THE SECOND -
# which looks identical to the original failure and sends you in a circle. The
# fix is to suppress conversion globally and convert the HOST side explicitly.
# --------------------------------------------------------------------------
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

# Convert a host path to whatever form the local adb binary expects.
host_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        printf '%s' "$1"
    fi
}

SERIAL=""
USER_ID=0
USE_ROOT=1

usage() {
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -s|--serial)  SERIAL="$2"; shift 2 ;;
        -u|--user)    USER_ID="$2"; shift 2 ;;
        --no-root)    USE_ROOT=0; shift ;;
        -h|--help)    usage ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

WORK="$(mktemp -d 2>/dev/null || mktemp -d -t ch47)"
cleanup() {
    rm -rf "$WORK"
    # Remove anything we staged on the device, whether or not we got that far.
    "${ADB[@]}" shell "su -c 'rm -f /data/local/tmp/ch47_acc_*.db'" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM

hr() { printf '%.0s-' $(seq 1 74); echo; }

# --------------------------------------------------------------------------
echo "=============================================================================="
echo " 47-Authentication  /  AccountManager audit"
echo "=============================================================================="

DEVCOUNT=$("${ADB[@]}" devices | grep -c "device$" || true)
if [ "$DEVCOUNT" -eq 0 ]; then
    echo "No device in 'device' state. Check 'adb devices -l'." >&2
    exit 1
fi

echo
echo "## Device"
hr
for p in ro.product.model ro.product.manufacturer ro.build.version.release \
         ro.build.version.sdk ro.product.cpu.abi; do
    printf '  %-30s %s\n' "$p" "$("${ADB[@]}" shell getprop $p | tr -d '\r')"
done

# Device posture. Chapter 47 section 4.4 explains why this matters: on a device
# with no screen lock, every claim about device-credential step-up is untestable.
echo
echo "## Device posture (affects what any local-auth claim can mean)"
hr
CRED=$("${ADB[@]}" shell "dumpsys lock_settings 2>/dev/null | grep -m1 CredentialType" | tr -d '\r')
printf '  %s\n' "${CRED:-  (lock_settings not readable as this identity)}"
LOCKED=$("${ADB[@]}" shell "dumpsys trust 2>/dev/null | grep -o 'deviceLocked=[01]' | head -1" | tr -d '\r')
printf '  %s\n' "${LOCKED:-deviceLocked=?}"
printf '  autofill_service = %s\n' \
    "$("${ADB[@]}" shell settings get secure autofill_service | tr -d '\r')"
CREDSVC=$("${ADB[@]}" shell "service list 2>/dev/null | grep -c ' credentials:'" | tr -d '\r')
if [ "${CREDSVC:-0}" -gt 0 ]; then
    printf '  platform CredentialManager service: PRESENT (API 34+)\n'
else
    printf '  platform CredentialManager service: ABSENT (expected below API 34)\n'
fi

# --------------------------------------------------------------------------
# Pass 1 - unprivileged. Works as uid 2000 and leaks more than people expect.
# --------------------------------------------------------------------------
echo
echo "## Pass 1: unprivileged (uid 2000) - dumpsys account"
hr
echo "  NOTE: account names are masked by the framework in this output. The"
echo "  masking is UNCONDITIONAL - running dumpsys through su produces"
echo "  byte-identical masked output. It is not a permission check. Account"
echo "  TYPES and the authenticator inventory are NOT masked."
echo
"${ADB[@]}" shell "dumpsys account 2>/dev/null" | tr -d '\r' | \
    sed -n '/^User /,/Account visibility/p' | head -60 | sed 's/^/  /'

echo
echo "  -- registered authenticators (which app owns which account type) --"
"${ADB[@]}" shell "dumpsys account 2>/dev/null" | tr -d '\r' | \
    grep -o 'AuthenticatorDescription {type=[^}]*}, ComponentInfo{[^}]*}' | \
    sed 's/^/  /' || echo "  (none listed)"

if [ "$USE_ROOT" -eq 0 ]; then
    echo
    echo "## Pass 2 skipped (--no-root)."
    echo "   The database pass is where the real answers are. Without it you"
    echo "   cannot see token counts, lifetimes, or the password column."
    exit 0
fi

# --------------------------------------------------------------------------
# Pass 2 - the databases.
# --------------------------------------------------------------------------
echo
echo "## Pass 2: the databases (requires root)"
hr

if ! "${ADB[@]}" shell "su -c id" 2>/dev/null | grep -q 'uid=0'; then
    echo "  Root not available. Re-run with --no-root, or on a rooted device."
    echo "  Measured permissions on the reference device:"
    echo "      -rw-rw---- system system u:object_r:system_data_file:s0 accounts_ce.db"
    echo "  Mode 0660 system:system plus SELinux. Neither an app nor the adb"
    echo "  shell can read it; root can. That is the entire protection."
    exit 0
fi

CE="/data/system_ce/${USER_ID}/accounts_ce.db"
DE="/data/system_de/${USER_ID}/accounts_de.db"

echo "  source: $CE"
echo "  source: $DE"
"${ADB[@]}" shell "su -c 'ls -laZ $CE $DE'" 2>/dev/null | tr -d '\r' | sed 's/^/    /'

"${ADB[@]}" shell "su -c 'cp $CE /data/local/tmp/ch47_acc_ce.db 2>/dev/null; \
                          cp $DE /data/local/tmp/ch47_acc_de.db 2>/dev/null; \
                          chmod 644 /data/local/tmp/ch47_acc_*.db'" >/dev/null 2>&1

# Errors are NOT suppressed here. An earlier revision sent them to /dev/null and
# a genuine path bug presented as "the database could not be decrypted", which is
# a completely different diagnosis. If a pull fails, you want to see why.
"${ADB[@]}" pull /data/local/tmp/ch47_acc_ce.db "$(host_path "$WORK/ce.db")" 2>&1 | sed 's/^/    /'
"${ADB[@]}" pull /data/local/tmp/ch47_acc_de.db "$(host_path "$WORK/de.db")" 2>&1 | sed 's/^/    /'
"${ADB[@]}" shell "su -c 'rm -f /data/local/tmp/ch47_acc_*.db'" >/dev/null 2>&1

if [ ! -s "$WORK/ce.db" ]; then
    echo
    echo "  Could not retrieve the CE database for user ${USER_ID}. Two causes,"
    echo "  and the pull output above distinguishes them:"
    echo "    * 'failed to stat remote object' -> the file is not there. A locked"
    echo "      device with file-based encryption has not decrypted the CE"
    echo "      directory yet; unlock the device and retry."
    echo "    * a host path error -> your adb is a native Windows binary and the"
    echo "      shell rewrote a path. host_path() at the top of this script is"
    echo "      the fix; check that cygpath is available."
    exit 1
fi

# --------------------------------------------------------------------------
# Parse on the HOST. Most devices have no sqlite3 binary (measured: the
# reference device reports 'sqlite3: inaccessible or not found' even as root).
# --------------------------------------------------------------------------
# host_path() again, and for the same reason: on Windows the `python3` on PATH
# is frequently a NATIVE Windows interpreter, which cannot open `/tmp/...`
# either. Anything that is not a shell builtin needs the converted form.
python3 -B - "$(host_path "$WORK/ce.db")" "$(host_path "$WORK/de.db")" <<'PY'
import sys, sqlite3, collections, time, os

ce_path, de_path = sys.argv[1], sys.argv[2]

def shape(v):
    """Classify a credential WITHOUT disclosing it."""
    if v is None:
        return "NULL"
    n = len(v)
    if v.count('.') == 2 and v.startswith('ey'):
        kind = "JWT-shaped"
    elif v.startswith('ya29'):
        kind = "Google OAuth2 access token (ya29)"
    elif all(c in '0123456789abcdefABCDEF' for c in v) and n >= 32:
        kind = "hex blob"
    else:
        kind = "opaque"
    return "%s, %d chars, prefix=%r" % (kind, n, v[:4])

ce = sqlite3.connect(ce_path)
print()
print("  ### accounts (CE)")
rows = list(ce.execute("select _id, type, password from accounts"))
print("    %d account(s)" % len(rows))
pw_users = 0
for _id, typ, pw in rows:
    if pw is None:
        print("      id=%-3d type=%-45s password: NULL" % (_id, typ[:45]))
    else:
        pw_users += 1
        print("      id=%-3d type=%-45s password: PRESENT, %d chars  <-- PLAINTEXT COLUMN"
              % (_id, typ[:45], len(pw)))
if pw_users:
    print()
    print("    FINDING CANDIDATE: %d authenticator(s) use accounts.password." % pw_users)
    print("    That column is TEXT in an unencrypted SQLite file. Common wisdom is")
    print("    that setPassword is legacy and unused; it is not. See README 5.10")
    print("    for what is and is not reportable here.")

print()
print("  ### authtokens (CE) - the cached bearer credentials")
toks = list(ce.execute("select accounts_id, type, authtoken from authtokens"))
print("    %d row(s)" % len(toks))
if toks:
    lens = [len(t) for (_, _, t) in toks if t]
    kinds = collections.Counter()
    per_account = collections.Counter()
    for aid, typ, tok in toks:
        per_account[aid] += 1
        if tok:
            kinds[shape(tok).split(',')[0]] += 1
    if lens:
        print("    non-NULL: %d   length min=%d max=%d mean=%d"
              % (len(lens), min(lens), max(lens), sum(lens)//len(lens)))
    print("    per account id: %s" % dict(per_account))
    print("    shapes:")
    for k, n in kinds.most_common():
        print("      %-40s x%d" % (k, n))
    if kinds and not any('JWT' in k for k in kinds):
        print()
        print("    NOTE: no JWT-shaped tokens. 46-Tokens' first analysis step is")
        print("    'count the dots' for exactly this reason - the field is full of")
        print("    OPAQUE credentials, which cannot be forged offline at all.")

    print()
    print("    token TYPE strings are capability names, not secrets. Sample:")
    for (typ,) in list(ce.execute("select distinct type from authtokens limit 5")):
        print("      %s" % typ[:100])
    print("    If a type embeds '<package>:<cert-sha1>:' the authenticator has")
    print("    scoped the cached token to one build of one app - see README 3.4.")

print()
print("  ### extras (CE) - keys only, values never printed")
ex = list(ce.execute("select key, value from extras"))
print("    %d row(s)" % len(ex))
now = int(time.time())
exp_future = exp_past = 0
max_ttl = None
for k, v in ex:
    if k.startswith('EXP:'):
        try:
            t = int(v)
        except (TypeError, ValueError):
            continue
        if t > now:
            exp_future += 1
            ttl = t - now
            if max_ttl is None or ttl > max_ttl:
                max_ttl = ttl
        else:
            exp_past += 1
if exp_future or exp_past:
    print("    token expiry rows: %d live, %d EXPIRED-BUT-RETAINED"
          % (exp_future, exp_past))
    if max_ttl is not None:
        print("    longest remaining lifetime: %d s (~%d min)" % (max_ttl, max_ttl // 60))
    if exp_past:
        print("    Expired tokens are retained indefinitely. For a defender that is")
        print("    unnecessary retention; for a forensic analyst it is an")
        print("    authentication HISTORY.")

interesting = [k for k, _ in ex if any(
    s in k.lower() for s in ('password', 'token', 'binding', 'credential'))]
if interesting:
    print("    extras keys worth reading (names only):")
    for k in sorted(set(interesting))[:12]:
        print("      %s" % k[:88])

# ---- DE database -----------------------------------------------------------
if os.path.exists(de_path) and os.path.getsize(de_path) > 0:
    de = sqlite3.connect(de_path)
    print()
    print("  ### visibility (DE) - who may SEE each account (API 26+)")
    names = {0: "UNDEFINED", 1: "VISIBLE", 2: "USER_MANAGED_VISIBLE",
             3: "NOT_VISIBLE", 4: "USER_MANAGED_NOT_VISIBLE"}
    vis = list(de.execute("select accounts_id, _package, value from visibility"))
    print("    %d grant(s)" % len(vis))
    for aid, pkg, val in vis[:25]:
        print("      account=%-3s %-45s %s" % (aid, pkg[:45], names.get(val, val)))
    if len(vis) > 25:
        print("      ... and %d more" % (len(vis) - 25))
    print("    GET_ACCOUNTS grants NOTHING on API 26+. This table is the real")
    print("    access-control list, and it is set by the AUTHENTICATOR.")

    print()
    print("  ### meta (DE) - account type to authenticator uid binding")
    for k, v in de.execute("select key, value from meta"):
        if k.startswith('auth_uid_for_type:'):
            print("      %-55s uid %s" % (k.replace('auth_uid_for_type:', '')[:55], v))
    print("    This binding is the anti-hijack control: a second app cannot claim")
    print("    an account type that is already owned.")

    print()
    print("  ### debug_table (DE) - account modification history")
    hist = list(de.execute(
        "select _id, action_type, time, caller_uid from debug_table order by time"))
    print("    %d row(s)  [accountId, action, timestamp, caller uid]" % len(hist))
    for _id, action, t, uid in hist[-15:]:
        print("      %-4s %-32s %-20s uid=%s" % (_id, action, t, uid))
    print("    For an incident investigation this is often the only dated record")
    print("    of when an account was added to a device, and by what.")

print()
print("  ### what this pass CANNOT tell you")
print("    Whether any of these tokens still WORK. That requires presenting one")
print("    to its issuer, which is out of scope for an audit script and is a")
print("    decision for the engagement. Presence is not validity.")
PY

echo
hr
echo " Done. Temp copies removed from host and device."
echo " Reminder: a token found on a ROOTED device is not by itself a finding."
echo " Root reads everything. See README 5.10 for what is reportable."
