#!/usr/bin/env bash
# =============================================================================
# selinux-posture.sh -- report the complete SELinux posture of a connected
#                       Android device, and of one app on it.
#
# WHAT IT DOES
#   Answers, from the device rather than from documentation, the questions you
#   should ask before you write a single sentence about SELinux on a target:
#
#     1.  Is the kernel enforcing, and is MLS/MCS compiled in at all?
#     2.  What policy version, and does it deny unknown classes?
#     3.  Which policy files are on the device, and where did they come from
#         (platform / system_ext / product / vendor / odm)?
#     4.  Which domains are running, and how many processes in each?
#     5.  Which domains are PERMISSIVE -- the single highest-value question on
#         a production build.
#     6.  For one named package: its uid, its process context, its MCS
#         categories, and the arithmetic that produced them, checked against
#         the uid the package manager reports.
#     7.  What its data directory is labelled, if that is readable.
#     8.  Which seapp_contexts line selected its domain, with the reasoning.
#     9.  How many avc denials the device has logged, grouped, so you can see
#         at a glance whether anything is unusual.
#
# HOW TO RUN
#     ./selinux-posture.sh                       # device-wide posture only
#     ./selinux-posture.sh com.example.target    # plus that package
#     ./selinux-posture.sh com.example.target -s R58ABC   # pick a device
#     ./selinux-posture.sh --no-logcat com.example.target
#
#   Runs on the HOST. Needs adb on PATH and exactly one device authorised
#   (or -s). No root required -- every step that needs root is attempted,
#   and clearly reported as unavailable rather than silently skipped.
#
# REQUIREMENTS
#   bash 4+, adb, and awk/sed/grep on the host. Works from Git Bash on
#   Windows, from macOS, and from Linux. Nothing is installed on the device.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - Whether any denial it counts is a finding. It is almost certainly not.
#     A healthy stock Android 13 device logged 6,101 avc records in one
#     uptime while this chapter was being written, all benign. Use
#     avc-decode.py to triage, and read README section 5.9 before reporting.
#   - What rules the policy actually contains. Reading the binary policy
#     requires `security:read_policy`, which a stock shell does not have --
#     the script proves this by trying and showing you the denial. To search
#     rules you need the binary policy off the device (root, or the OTA image)
#     plus sepolicy-analyze / sesearch on the host.
#   - Whether a domain being permissive is exploitable. Permissive means
#     "policy would have refused, and did not". Whether that matters depends
#     entirely on what the domain can then reach.
#   - Anything about DAC. A file you cannot read may be blocked by Unix
#     permissions, by SELinux, or by both, and this script only sees one of
#     them. Always run `ls -l` alongside `ls -Z`. DAC is 21-App-Sandbox.
#   - Whether the device's policy has been modified. Comparing the on-device
#     policy against the AOSP release it claims to be is a real technique and
#     it is out of scope here; 62-Magisk covers policy patching.
# =============================================================================

set -o pipefail

ADB_SERIAL=""
PKG=""
DO_LOGCAT=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s) ADB_SERIAL="$2"; shift 2 ;;
        --no-logcat) DO_LOGCAT=0; shift ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
        -*) echo "unknown option: $1" >&2; exit 2 ;;
        *)  PKG="$1"; shift ;;
    esac
done

adb_() {
    if [[ -n "$ADB_SERIAL" ]]; then
        adb -s "$ADB_SERIAL" "$@"
    else
        adb "$@"
    fi
}

# Run a command on the device and return its stdout with CRs stripped.
#
# The arguments are JOINED INTO ONE STRING before being handed to `adb shell`.
# That is deliberate and it is not cosmetic. Two things break otherwise:
#
#   1. `adb shell` does not preserve argument quoting -- it concatenates argv
#      and hands the result to the device's /system/bin/sh anyway. Building the
#      string ourselves makes that explicit rather than accidental. This is the
#      same trap that silently broke a script in chapter 09.
#   2. On Git Bash / MSYS under Windows, a bare argument that looks like a Unix
#      path is REWRITTEN into a Windows path before adb ever sees it, so
#      `adb shell cat /sys/fs/selinux/enforce` reaches the device as
#      `cat C:/Program Files/Git/sys/fs/selinux/enforce` and returns nothing at
#      all -- with exit status 0 from the pipeline, so it looks like an empty
#      file rather than an error. Passing one already-joined string avoids it.
sh_() { adb_ shell "$*" 2>/dev/null | tr -d '\r'; }

hr()  { printf '%s\n' "------------------------------------------------------------------------"; }
hdr() { printf '\n========================================================================\n%s\n========================================================================\n' "$1"; }

command -v adb >/dev/null 2>&1 || { echo "adb not found on PATH" >&2; exit 1; }

DEVCOUNT=$(adb devices | awk 'NR>1 && $2=="device"' | wc -l | tr -d ' ')
if [[ -z "$ADB_SERIAL" && "$DEVCOUNT" != "1" ]]; then
    echo "Expected exactly one authorised device; found $DEVCOUNT. Use -s SERIAL." >&2
    adb devices >&2
    exit 1
fi

# ---------------------------------------------------------------------------
hdr "1. DEVICE"
# ---------------------------------------------------------------------------
printf '%-28s %s\n' "model"          "$(sh_ getprop ro.product.model)"
printf '%-28s %s\n' "android release" "$(sh_ getprop ro.build.version.release)"
printf '%-28s %s\n' "api level"      "$(sh_ getprop ro.build.version.sdk)"
printf '%-28s %s\n' "security patch" "$(sh_ getprop ro.build.version.security_patch)"
printf '%-28s %s\n' "build type"     "$(sh_ getprop ro.build.type)"
printf '%-28s %s\n' "ro.debuggable"  "$(sh_ getprop ro.debuggable)"
printf '%-28s %s\n' "first api level" "$(sh_ getprop ro.product.first_api_level)"
printf '%-28s %s\n' "vendor sepolicy vers" "$(sh_ cat /vendor/etc/selinux/plat_sepolicy_vers.txt)"

# ---------------------------------------------------------------------------
hdr "2. ENFORCEMENT STATE"
# ---------------------------------------------------------------------------
ENFORCE=$(sh_ getenforce)
printf '%-28s %s\n' "getenforce"     "$ENFORCE"
printf '%-28s %s\n' "/sys/fs/selinux/enforce" "$(sh_ cat /sys/fs/selinux/enforce)"
printf '%-28s %s\n' "ro.boot.selinux" "$(sh_ getprop ro.boot.selinux)"
printf '%-28s %s\n' "policy version"  "$(sh_ cat /sys/fs/selinux/policyvers)"
printf '%-28s %s\n' "MLS compiled in" "$(sh_ cat /sys/fs/selinux/mls)"
printf '%-28s %s\n' "deny_unknown"    "$(sh_ cat /sys/fs/selinux/deny_unknown)"
printf '%-28s %s\n' "checkreqprot"    "$(sh_ cat /sys/fs/selinux/checkreqprot)"
NCLASS=$(sh_ 'ls /sys/fs/selinux/class | wc -l')
printf '%-28s %s\n' "object classes"  "$NCLASS"

hr
case "$ENFORCE" in
  Enforcing)
    echo "Enforcing. Every denial below FAILED. This is the only state a"
    echo "production device should ever be in."
    ;;
  Permissive)
    echo "*** GLOBALLY PERMISSIVE ***"
    echo "SELinux is computing decisions and LOGGING them, and enforcing NONE"
    echo "of them. Every 'denied' record on this device SUCCEEDED. The MAC"
    echo "layer is, for practical purposes, absent. On a production build this"
    echo "is a finding on its own -- see README section 5.4."
    ;;
  Disabled|"")
    echo "SELinux reports Disabled or did not answer. On modern Android a"
    echo "truly disabled SELinux means a modified kernel or an unusual boot"
    echo "path; verify before believing it."
    ;;
esac
[[ "$(sh_ cat /sys/fs/selinux/mls)" == "0" ]] && {
    hr
    echo "*** MLS IS NOT COMPILED IN ***"
    echo "Without MLS there are no MCS categories, and every untrusted_app"
    echo "process is interchangeable with every other as far as type"
    echo "enforcement is concerned. App-vs-app isolation would then rest"
    echo "entirely on DAC. Treat this as a serious platform finding."
}

# ---------------------------------------------------------------------------
hdr "3. POLICY FILES ON THE DEVICE"
# ---------------------------------------------------------------------------
echo "Compiled policy and the context-mapping files that feed it. Sizes are"
echo "informative: plat_sepolicy.cil is the whole platform policy in CIL."
hr
for d in /system/etc/selinux /system_ext/etc/selinux /product/etc/selinux \
         /vendor/etc/selinux /odm/etc/selinux; do
    out=$(sh_ "ls -l $d 2>/dev/null")
    if [[ -n "$out" ]]; then
        printf '%s:\n' "$d"
        printf '%s\n' "$out" | sed 's/^/    /'
    fi
done

hr
echo "seapp_contexts -- the file that decides which domain an app process"
echo "gets. Read top to bottom; the MOST SPECIFIC match wins, not the first."
hr
sh_ 'cat /system/etc/selinux/plat_seapp_contexts 2>/dev/null' | sed 's/^/    /'
VSEAPP=$(sh_ 'cat /vendor/etc/selinux/vendor_seapp_contexts 2>/dev/null')
if [[ -n "$VSEAPP" ]]; then
    hr
    echo "vendor_seapp_contexts -- vendor additions. These matter: a vendor"
    echo "line can put an app into a domain the platform never intended."
    hr
    printf '%s\n' "$VSEAPP" | sed 's/^/    /'
fi

hr
echo "Can this shell read the binary policy?"
POLOUT=$(adb_ shell 'cat /sys/fs/selinux/policy > /dev/null 2>&1; echo $?' 2>/dev/null | tr -d '\r')
if [[ "$POLOUT" == "0" ]]; then
    echo "    YES -- security:read_policy is granted to this domain."
    echo "    Pull it with:  adb pull /sys/fs/selinux/policy ./policy.bin"
    echo "    Then:          sepolicy-analyze policy.bin permissive"
else
    echo "    NO -- refused. The class is 'security', the permission is"
    echo "    'read_policy', and the target type is 'kernel'. Look for:"
    echo "        avc: denied { read_policy } ... tclass=security"
    echo "    This is normal and expected on a stock shell. To analyse rules"
    echo "    you need the policy from an OTA image or from a rooted device."
fi

# ---------------------------------------------------------------------------
hdr "4. RUNNING DOMAINS"
# ---------------------------------------------------------------------------
echo "Every distinct SELinux TYPE currently running, with a process count."
echo "The type is the third colon-separated field of the context."
hr
sh_ 'ps -A -Z' | awk 'NR>1 {split($1,a,":"); if (a[3] != "") print a[3]}' \
    | sort | uniq -c | sort -rn | awk '{printf "    %-6s %s\n", $1, $2}'

hr
echo "App-domain processes, with their full contexts. Note which carry MCS"
echo "categories and which do not -- that difference is seapp_contexts'"
echo "levelFrom= setting, and it is the whole of app-vs-app MAC isolation."
hr
sh_ 'ps -A -Z' | awk 'NR>1 && ($1 ~ /_app/ || $1 ~ /app_zygote/ || $1 ~ /sdk_sandbox/) \
    {printf "    %-44s %-10s %s\n", $1, $2, $NF}' | sort

# ---------------------------------------------------------------------------
hdr "5. PERMISSIVE DOMAINS"
# ---------------------------------------------------------------------------
echo "A domain can be permissive even when the KERNEL is enforcing. Policy"
echo "marks it with 'permissive <domain>;' and the kernel then logs its"
echo "denials and allows them anyway. AOSP forbids this on user builds; a"
echo "vendor shipping one is a real finding."
hr
echo "Direct enumeration requires reading the binary policy, which this shell"
echo "cannot do. The reliable indirect method is the permissive= field on"
echo "audit records -- permissive=1 means that record's domain is permissive."
hr
if [[ "$DO_LOGCAT" == "1" ]]; then
    PERMLINES=$(adb_ logcat -d -b all 2>/dev/null | tr -d '\r' | grep -a "permissive=1" | head -40)
    if [[ -n "$PERMLINES" ]]; then
        echo "    *** RECORDS WITH permissive=1 FOUND ***"
        printf '%s\n' "$PERMLINES" | sed 's/^/    /'
        echo
        echo "    Each of these operations SUCCEEDED. Extract the scontext"
        echo "    types and list them as permissive domains in your report."
    else
        echo "    No permissive=1 records in the current log buffer."
        echo "    That is evidence, not proof: a permissive domain that has"
        echo "    not been exercised logs nothing."
    fi
else
    echo "    (skipped: --no-logcat)"
fi

# ---------------------------------------------------------------------------
hdr "6. DENIAL SUMMARY"
# ---------------------------------------------------------------------------
if [[ "$DO_LOGCAT" == "1" ]]; then
    RAW=$(adb_ logcat -d -b all 2>/dev/null | tr -d '\r' | grep -a "avc:" )
    TOTAL=$(printf '%s\n' "$RAW" | grep -ac "avc:" || true)
    echo "Total avc records in the log buffers: ${TOTAL:-0}"
    hr
    echo "Grouped by (scontext type -> tcontext type : tclass), most frequent"
    echo "first. A large count is a LOOP, not an escalation."
    hr
    printf '%s\n' "$RAW" \
      | grep -ao 'scontext=[^ ]* tcontext=[^ ]* tclass=[^ ]*' \
      | sed -E 's/scontext=[^:]*:[^:]*:([^:]*)[^ ]* tcontext=[^:]*:[^:]*:([^:]*)[^ ]* tclass=(.*)/\1 -> \2 : \3/' \
      | sort | uniq -c | sort -rn | head -30 | awk '{printf "    %-8s %s\n", $1, substr($0, index($0,$2))}'
    hr
    echo "Triage every one of these with:"
    echo "    adb logcat -d -b all | python3 avc-decode.py - --group"
    echo "and read README section 5.9 before calling any of them a finding."
else
    echo "(skipped: --no-logcat)"
fi

# ---------------------------------------------------------------------------
if [[ -z "$PKG" ]]; then
    hdr "7. PACKAGE"
    echo "No package given. Re-run as:  $0 <package.name>"
    echo
    exit 0
fi

hdr "7. PACKAGE: $PKG"
# ---------------------------------------------------------------------------
UIDLINE=$(sh_ "pm list packages -U" | grep -a "package:${PKG} " )
if [[ -z "$UIDLINE" ]]; then
    UIDLINE=$(sh_ "pm list packages -U" | grep -a "package:${PKG}$\|package:${PKG} ")
fi
if [[ -z "$UIDLINE" ]]; then
    echo "Package not found, or not visible to the shell. Check the name with:"
    echo "    adb shell pm list packages | grep -i <fragment>"
    exit 1
fi
# NOTE the variable is APP_UID, not UID. `UID` is readonly in bash, and
# assigning to it fails with "readonly variable" while leaving the shell's own
# UID in place -- so the arithmetic below would silently run on the HOST user's
# uid and print a confident, completely wrong category set. That happened
# during development and is exactly the kind of bug that survives review,
# because the output still looks plausible.
APP_UID=$(printf '%s\n' "$UIDLINE" | sed -E 's/.*uid:([0-9]+).*/\1/')
printf '%-28s %s\n' "package"  "$PKG"
printf '%-28s %s\n' "uid"      "$APP_UID"

USERID=$(( APP_UID / 100000 ))
APPID_RAW=$(( APP_UID % 100000 ))
if   (( APPID_RAW >= 90000 )); then APPID=$(( APPID_RAW - 90000 )); RANGE="isolated (AID_ISOLATED_START)"
elif (( APPID_RAW >= 20000 )); then APPID=$(( APPID_RAW - 20000 )); RANGE="sdk sandbox (AID_SDK_SANDBOX_PROCESS_START)"
elif (( APPID_RAW >= 10000 )); then APPID=$(( APPID_RAW - 10000 )); RANGE="application (AID_APP_START)"
else APPID=$APPID_RAW; RANGE="system/native AID (no subtraction)"
fi
CAT_A=$(( APPID & 255 ))
CAT_B=$(( 256 + (APPID >> 8) ))
CAT_C=$(( 512 + (USERID & 255) ))
CAT_D=$(( 768 + (USERID >> 8) ))

hr
echo "MCS ARITHMETIC -- predicted from the uid alone"
hr
printf '    %-34s %s\n' "uid"                       "$APP_UID"
printf '    %-34s %s\n' "userid = uid / 100000"     "$USERID"
printf '    %-34s %s\n' "raw appid = uid % 100000"  "$APPID_RAW"
printf '    %-34s %s\n' "range"                     "$RANGE"
printf '    %-34s %s\n' "appid after subtraction"   "$APPID"
echo
printf '    %-34s c%d\n' "appid & 0xff"             "$CAT_A"
printf '    %-34s c%d\n' "256 + (appid >> 8)"       "$CAT_B"
printf '    %-34s c%d\n' "512 + (userid & 0xff)"    "$CAT_C"
printf '    %-34s c%d\n' "768 + (userid >> 8)"      "$CAT_D"
echo
echo "    levelFrom=all  predicts  s0:c${CAT_A},c${CAT_B},c${CAT_C},c${CAT_D}"
echo "    levelFrom=user predicts  s0:c${CAT_C},c${CAT_D}"
echo "    levelFrom=app  predicts  s0:c${CAT_A},c${CAT_B}"
echo "    (none)         predicts  s0"

hr
echo "OBSERVED PROCESS CONTEXTS"
hr
PROCS=$(sh_ 'ps -A -Z' | grep -a -- "$PKG")
if [[ -z "$PROCS" ]]; then
    echo "    No process running. Launch the app and re-run:"
    echo "        adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1"
else
    printf '%s\n' "$PROCS" | awk '{printf "    %-46s %-10s %s\n", $1, $2, $NF}'
    OBS=$(printf '%s\n' "$PROCS" | awk 'NR==1{print $1}')
    OBSLEVEL="${OBS#*:*:*:}"
    OBSTYPE=$(printf '%s\n' "$OBS" | cut -d: -f3)
    echo
    printf '    %-22s %s\n' "domain (type)" "$OBSTYPE"
    printf '    %-22s %s\n' "observed level" "$OBSLEVEL"
    if [[ "$OBSLEVEL" == "s0:c${CAT_A},c${CAT_B},c${CAT_C},c${CAT_D}" ]]; then
        echo "    MATCH: levelFrom=all. Both pairs present; per-app isolation is on."
    elif [[ "$OBSLEVEL" == "s0:c${CAT_C},c${CAT_D}" ]]; then
        echo "    MATCH: levelFrom=user. Only the USER pair is present, so every"
        echo "    process in this domain on this Android user shares a level and"
        echo "    MCS does NOT separate them from each other."
    elif [[ "$OBSLEVEL" == "s0" ]]; then
        echo "    MATCH: no levelFrom. No categories at all -- this domain is not"
        echo "    category-isolated, and separation rests on type enforcement."
    else
        echo "    NO MATCH against any levelFrom form. Either the uid changed"
        echo "    since the process started, or this is a vendor seapp_contexts"
        echo "    rule. Worth investigating."
    fi
fi

hr
echo "DATA DIRECTORY LABEL"
hr
DD=$(sh_ "dumpsys package $PKG" | grep -a -m1 'dataDir=' | sed -E 's/.*dataDir=([^ ]+).*/\1/')
[[ -z "$DD" ]] && DD="/data/data/$PKG"
printf '    dataDir  %s\n' "$DD"
LS=$(sh_ "ls -ldZ $DD")
if [[ -n "$LS" ]]; then
    printf '    %s\n' "$LS"
else
    echo "    Not readable from this shell. Expected: /data/data is 0711 and"
    echo "    the shell domain has no rule permitting getattr on"
    echo "    app_data_file. Try, on a debuggable build:"
    echo "        adb shell run-as $PKG ls -ldZ ."
    RA=$(sh_ "run-as $PKG ls -ldZ . 2>&1")
    [[ -n "$RA" ]] && printf '    run-as: %s\n' "$RA"
fi

hr
echo "WHICH seapp_contexts LINE SELECTED THIS DOMAIN"
hr
PRIV=$(sh_ "dumpsys package $PKG" | grep -acE 'pkgFlags=.*SYSTEM|privileged' )
TSDK=$(sh_ "dumpsys package $PKG" | grep -a -m1 'targetSdk=' | sed -E 's/.*targetSdk=([0-9]+).*/\1/')
printf '    %-22s %s\n' "targetSdk" "${TSDK:-unknown}"
echo
echo "    Matching is by SPECIFICITY, not file order. libselinux sorts the"
echo "    parsed rules and the most specific match wins. The inputs are:"
echo "        user=            _app | _isolated | _sdksandbox | a named uid"
echo "        seinfo=          from mac_permissions.xml, keyed on signing cert"
echo "        name=            package name, with * wildcards"
echo "        isPrivApp=       is it in a priv-app directory"
echo "        isEphemeralApp=  instant app"
echo "        fromRunAs=       did run-as create this process"
echo "        minTargetSdkVersion="
echo
echo "    Candidate lines from this device's seapp_contexts that could match"
echo "    a plain third-party app with targetSdk ${TSDK:-?}:"
sh_ 'cat /system/etc/selinux/plat_seapp_contexts 2>/dev/null' \
  | grep -a '^user=_app' | grep -av 'name=' | sed 's/^/        /'
echo
echo "    Read the minTargetSdkVersion= values above against targetSdk"
echo "    ${TSDK:-?}: the highest minTargetSdkVersion that is <= the app's"
echo "    targetSdk is the one that applies. That is why an old app lands in"
echo "    untrusted_app_25 or untrusted_app_27 and gets permissions a modern"
echo "    app does not -- see README section 3.10."

hdr "DONE"
echo "Next steps:"
echo "  adb logcat -d -b all | python3 avc-decode.py - --group --scontext ${OBSTYPE:-untrusted_app}"
echo "  README section 3.7 for the MCS arithmetic, 5.9 for denial severity."
