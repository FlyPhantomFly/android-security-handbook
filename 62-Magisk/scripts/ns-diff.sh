#!/system/bin/sh
#
# ns-diff.sh — compare one process's mount namespace against the global one.
#
# Purpose
#   Answer the question "what does this app actually see at these paths?" by
#   diffing the target process's mount table against init's, and by entering the
#   target's namespace and looking at the paths that matter for testing. This is
#   the measurement behind Magisk's DenyList: DenyList removes Magisk's bind
#   mounts from a target process's namespace, and this script shows you exactly
#   which ones went and what the app sees as a result.
#
# Usage
#   Push to the device and run AS ROOT, on the device:
#     adb push ns-diff.sh /data/local/tmp/
#     adb shell "su -c 'chmod 755 /data/local/tmp/ns-diff.sh'"
#     adb shell "su -c '/data/local/tmp/ns-diff.sh com.example.target'"
#
#   The OUTER quotes are load-bearing. adb shell joins its arguments with spaces
#   before the device sees them, so `adb shell su -c 'a b'` arrives as
#   `su -c a b` and su -c runs only `a`. Verified on an AVD: `adb shell sh -c
#   'echo A; echo B'` prints a blank line and B, while `adb shell "sh -c 'echo
#   A; echo B'"` prints A and B.
#
#   Arguments:
#     <package-or-pid>   package name (first matching process is used) or a numeric pid
#     -v                 also print the full removed/added mount lines, not just counts
#
# Requirements
#   * A rooted Android device. Root is required to read /proc/<pid>/mountinfo for
#     another uid and to call setns().
#   * nsenter. Recent toybox ships one; if not, Magisk's busybox does, and this
#     script finds it automatically.
#   * The target process must be RUNNING. A namespace exists only while its
#     process does.
#
# What this will NOT tell you
#   * Whether the app detects root. It reports what the app can see; whether the
#     app looks, and what it concludes, is a different question --
#     see chapter 37-RootDetection.
#   * Whether the namespace looks like a STOCK device's namespace. Removing a
#     mount is not the same as never having made it. To answer that you need a
#     mountinfo capture from an unrooted device on the same build, taken before
#     you rooted it. This script cannot conjure that baseline.
#   * Anything about properties, the SELinux policy, package visibility, or
#     hardware attestation. None of those live in a mount namespace and none of
#     them are affected by DenyList.
#   * Anything about processes that have already exited, or about a namespace
#     that no live process holds open.
#   * Whether a mount is Magisk's. It matches on well-known substrings, which is
#     a heuristic; read the full lines with -v before drawing conclusions.

set -u

VERBOSE=0
TARGET=""

for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        -h|--help)
            sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) TARGET="$arg" ;;
    esac
done

if [ -z "$TARGET" ]; then
    echo "usage: ns-diff.sh <package-name|pid> [-v]" >&2
    exit 2
fi

if [ "$(id -u)" != "0" ]; then
    echo "ERROR: must run as root. Try:  su -c '$0 $TARGET'" >&2
    exit 1
fi

# ---- locate a usable nsenter -------------------------------------------------

NS=""
if command -v nsenter >/dev/null 2>&1; then
    NS="nsenter"
elif [ -x /data/adb/magisk/busybox ]; then
    NS="/data/adb/magisk/busybox nsenter"
else
    echo "WARNING: no nsenter found. Mount-table comparison will still work;" >&2
    echo "         the 'what the app sees at path X' section will be skipped." >&2
fi

# ---- resolve the target to a pid --------------------------------------------

case "$TARGET" in
    ''|*[!0-9]*)
        PID=$(pidof -s "$TARGET" 2>/dev/null)
        if [ -z "$PID" ]; then
            echo "ERROR: no running process for '$TARGET'." >&2
            echo "       Start the app first. If it has several processes, list them with:" >&2
            echo "         ps -A | grep $TARGET" >&2
            exit 1
        fi
        ;;
    *)
        PID="$TARGET"
        ;;
esac

if [ ! -r "/proc/$PID/mountinfo" ]; then
    echo "ERROR: cannot read /proc/$PID/mountinfo (process gone, or SELinux denial)." >&2
    echo "       Check: dmesg | grep avc" >&2
    exit 1
fi

TMP=/data/local/tmp/.nsdiff.$$
mkdir -p "$TMP" || exit 1
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT INT TERM

echo "=============================================================="
echo " ns-diff: pid $PID"
if [ "$TARGET" != "$PID" ]; then echo " target spec: $TARGET"; fi
echo "=============================================================="
echo

# ---- identity ----------------------------------------------------------------

echo "== namespace identity =="
printf '  init (pid 1)      : %s\n' "$(readlink /proc/1/ns/mnt 2>/dev/null)"
printf '  this shell        : %s\n' "$(readlink /proc/self/ns/mnt 2>/dev/null)"
printf '  target (pid %s) : %s\n' "$PID" "$(readlink "/proc/$PID/ns/mnt" 2>/dev/null)"
for z in zygote zygote64; do
    zp=$(pidof -s "$z" 2>/dev/null)
    [ -n "$zp" ] && printf '  %-17s : %s\n' "$z" "$(readlink "/proc/$zp/ns/mnt" 2>/dev/null)"
done
echo
echo "  Two processes showing the same mnt:[...] value are in the SAME namespace"
echo "  and cannot differ in what they see. Different values mean nothing on their"
echo "  own -- Android gives most app processes their own namespace regardless of"
echo "  Magisk."
echo

# ---- mount tables ------------------------------------------------------------

# Field 5 of mountinfo is the mount point as seen in that namespace.
# Fields 1 and 2 (mount id, parent id) legitimately differ between namespaces,
# so they are excluded from the comparison or the output is unreadable noise.
awk '{print $5}' /proc/1/mountinfo      | sort -u > "$TMP/global.pts"
awk '{print $5}' "/proc/$PID/mountinfo" | sort -u > "$TMP/target.pts"

G_TOTAL=$(wc -l < /proc/1/mountinfo | tr -d ' ')
T_TOTAL=$(wc -l < "/proc/$PID/mountinfo" | tr -d ' ')

echo "== mount counts =="
printf '  global namespace  : %s mounts\n' "$G_TOTAL"
printf '  target namespace  : %s mounts\n' "$T_TOTAL"
echo

echo "== magisk-shaped mounts (heuristic substring match) =="
for needle in magisk worker debug_ramdisk data/adb overlay; do
    # grep -c always prints a count and exits 1 when the count is zero, so the
    # exit status is deliberately ignored here rather than defaulted.
    g=$(grep -ic "$needle" /proc/1/mountinfo 2>/dev/null)
    t=$(grep -ic "$needle" "/proc/$PID/mountinfo" 2>/dev/null)
    g=${g:-0}
    t=${t:-0}
    note=""
    if [ "$g" -gt "$t" ]; then note="<-- removed in target"; fi
    printf '  %-14s global=%-4s target=%-4s %s\n' "$needle" "$g" "$t" "$note"
done
echo

# ---- what disappeared --------------------------------------------------------

comm -23 "$TMP/global.pts" "$TMP/target.pts" > "$TMP/removed.pts"
comm -13 "$TMP/global.pts" "$TMP/target.pts" > "$TMP/added.pts"

R_N=$(wc -l < "$TMP/removed.pts" | tr -d ' ')
A_N=$(wc -l < "$TMP/added.pts" | tr -d ' ')

echo "== mount points present globally, ABSENT in the target ($R_N) =="
if [ "$R_N" = "0" ]; then
    echo "  (none -- the target sees every mount point the global namespace has)"
else
    sed 's/^/  /' "$TMP/removed.pts"
fi
echo

echo "== mount points present in the target, ABSENT globally ($A_N) =="
if [ "$A_N" = "0" ]; then
    echo "  (none)"
else
    sed 's/^/  /' "$TMP/added.pts"
    echo
    echo "  NOTE: per-app storage mounts (/storage/emulated/..., FUSE, sdcardfs)"
    echo "  routinely appear here and are Android's doing, not Magisk's. Do not"
    echo "  report them as findings."
fi
echo

if [ "$VERBOSE" = "1" ] && [ "$R_N" != "0" ]; then
    echo "== full mountinfo lines for the removed mount points =="
    while IFS= read -r mp; do
        [ -z "$mp" ] && continue
        awk -v m="$mp" '$5 == m {print "  " $0}' /proc/1/mountinfo
    done < "$TMP/removed.pts"
    echo
fi

# ---- what the target actually sees at the paths that matter ------------------

if [ -n "$NS" ]; then
    echo "== what pid $PID sees at the paths that matter =="
    for p in /system/bin/su /system/xbin/su /sbin/su /data/adb; do
        g=$(ls -ld "$p" 2>&1 | head -1)
        t=$($NS --mount="/proc/$PID/ns/mnt" -- ls -ld "$p" 2>&1 | head -1)
        printf '  %-20s\n' "$p"
        printf '      global : %s\n' "$g"
        printf '      target : %s\n' "$t"
    done

    for d in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; do
        if [ -d "$d" ]; then
            g=$(ls "$d" 2>/dev/null | wc -l | tr -d ' ')
            t=$($NS --mount="/proc/$PID/ns/mnt" -- ls "$d" 2>/dev/null | wc -l | tr -d ' ')
            printf '  %-20s global=%s entries  target=%s entries\n' "$d" "$g" "$t"
            if [ "$g" != "$t" ]; then
                echo "      ^ THE CA COLLISION: a system-CA module is mounted globally but not"
                echo "        in this process. If this is your interception target, your proxy"
                echo "        certificate is invisible to it. See chapter 62 lab 03."
            fi
        fi
    done
    echo
fi

# ---- verdict-free summary ----------------------------------------------------

echo "== summary =="
if [ "$R_N" = "0" ]; then
    echo "  No mount points were removed from this process's namespace."
    echo "  Either the process is not on the DenyList, or Magisk has no mounts to remove,"
    echo "  or the process was forked before it was added to the list (force-stop and"
    echo "  restart it, then re-run)."
else
    echo "  $R_N mount point(s) were removed from this process's namespace relative to init."
    echo "  This is consistent with DenyList being active for this process. It is NOT"
    echo "  evidence that the app cannot detect root -- see the header of this script."
fi
echo
echo "  Reminder: this tool measures visibility, not detectability, and says nothing"
echo "  about properties, SELinux policy contents, package visibility, or attestation."
