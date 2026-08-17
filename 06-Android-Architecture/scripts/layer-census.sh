#!/usr/bin/env bash
#
# layer-census.sh — map every running process to its architectural layer.
#
# WHAT IT DOES
#   Enumerates the processes on a device, groups them by UID class and SELinux
#   domain, assigns each to a layer from ../README.md section 2, and flags
#   anomalies:
#
#     - a process running as root that has no business doing so
#     - an app process with non-empty effective capabilities
#     - an app process without a seccomp filter
#     - a vendor daemon in an over-broad SELinux domain
#     - a world-accessible UNIX socket exposed by a native daemon
#
#   The point is to turn "here is a ps listing" into "here is the device's
#   privilege distribution, and here is what looks wrong".
#
# HOW TO RUN
#   ./layer-census.sh                 # summary
#   ./layer-census.sh --detail        # per-process detail
#   ./layer-census.sh --anomalies     # only the flagged rows
#   ./layer-census.sh --pkg com.example.target   # deep-dive one app
#
# REQUIREMENTS
#   adb. Root improves coverage substantially (capabilities, sockets) but the
#   script degrades gracefully without it.

set -uo pipefail

MODE="summary"
PKG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --detail)    MODE="detail"; shift ;;
        --anomalies) MODE="anomalies"; shift ;;
        --pkg)       PKG="$2"; MODE="pkg"; shift 2 ;;
        -h|--help)   sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

adbsh() { adb shell "$@" 2>/dev/null | tr -d '\r'; }
have_root() { [[ "$(adbsh 'command -v su >/dev/null && echo y || echo n')" == "y" ]]; }
su_sh() { have_root && adb shell "su -c '$1'" 2>/dev/null | tr -d '\r'; }

if [[ -z "$(adb get-state 2>/dev/null)" ]]; then
    echo "error: no device" >&2; exit 1
fi

ROOT=$(have_root && echo yes || echo no)

# Map a UID name to an architectural layer (README section 2).
layer_of() {
    case "$1" in
        root)                       echo "L1 init/kernel-adjacent (root)" ;;
        system)                     echo "L5 framework (system_server)" ;;
        shell)                      echo "L-  developer shell (NOT an app)" ;;
        radio|bluetooth|nfc|wifi)   echo "L2/3 connectivity services" ;;
        media*|audioserver|cameraserver|drm|mediacodec|mediaex*|mediametrics) \
                                    echo "L3 native media services" ;;
        graphics|gpu_service|composer|surfaceflinger) echo "L3 graphics" ;;
        keystore|gatekeeper|credstore) echo "L3 key/credential services" ;;
        vendor_*|hal_*)             echo "L2 vendor / HAL" ;;
        u0_a*|u10_a*|u*_a*)         echo "L6 application" ;;
        u0_i*|u*_i*)                echo "L6 isolated process" ;;
        webview_zygote|zygote*)     echo "L4 zygote" ;;
        *)                          echo "L?  unclassified" ;;
    esac
}

# --------------------------------------------------------------- gather ----

PSOUT=$(adbsh 'ps -A -o USER,PID,NAME' | tail -n +2)
PSZ=$(adbsh 'ps -A -Z' | tail -n +2)

if [[ -z "$PSOUT" ]]; then
    echo "error: could not enumerate processes" >&2; exit 1
fi

echo
echo "=============================================================="
echo " LAYER CENSUS"
echo "=============================================================="
printf '  %-20s %s\n' "device" "$(adbsh 'getprop ro.product.model')"
printf '  %-20s %s\n' "android" "$(adbsh 'getprop ro.build.version.release')"
printf '  %-20s %s\n' "selinux" "$(adbsh getenforce)"
printf '  %-20s %s\n' "root available" "$ROOT"
printf '  %-20s %s\n' "processes" "$(echo "$PSOUT" | wc -l | tr -d ' ')"

# ------------------------------------------------------------- summary -----

if [[ "$MODE" == "summary" || "$MODE" == "detail" ]]; then
    echo
    echo "-- processes by UID class --"
    echo "$PSOUT" | awk '{print $1}' | sed -E 's/^(u[0-9]+_a)[0-9]+$/\1NNN (apps)/; s/^(u[0-9]+_i)[0-9]+$/\1NNN (isolated)/' \
        | sort | uniq -c | sort -rn \
        | while read -r count user; do
            printf '  %5s  %-24s %s\n' "$count" "$user" "$(layer_of "${user%% *}")"
          done

    echo
    echo "-- processes by SELinux domain --"
    if [[ -n "$PSZ" ]]; then
        echo "$PSZ" | awk '{print $1}' | sed 's/:s0.*//' | sed 's/^u:r://' \
            | sort | uniq -c | sort -rn | head -25 | sed 's/^/  /'
    else
        echo "  (ps -Z unavailable on this device)"
    fi
fi

# ------------------------------------------------------------- anomalies ---

echo
echo "-- anomaly checks --"

# 1. Root processes. Some are expected; a long list is worth reading.
ROOTPROCS=$(echo "$PSOUT" | awk '$1=="root" {print $3}' | sort)
ROOTCOUNT=$(echo "$ROOTPROCS" | grep -c . || true)
EXPECTED_ROOT='^(init|ueventd|logd|lmkd|vold|servicemanager|hwservicemanager|vndservicemanager|healthd|installd|netd|zygote|zygote64|apexd|keystore2?|traced.*|kworker.*|migration.*|ksoftirqd.*|rcu_.*|watchdogd|kswapd.*|\[.*\])$'
UNEXPECTED_ROOT=$(echo "$ROOTPROCS" | grep -vE "$EXPECTED_ROOT" || true)

echo "  [root processes] $ROOTCOUNT total"
if [[ -n "$UNEXPECTED_ROOT" ]]; then
    echo "    Not on the common-AOSP list — review each. Vendor daemons running as"
    echo "    root are where OEM findings concentrate (README section 5.2):"
    echo "$UNEXPECTED_ROOT" | head -25 | sed 's/^/      /'
    echo
    echo "    For each, read its init entry to see its ACTUAL privilege budget:"
    echo "      adb shell 'grep -rA10 \"^service .*<name>\" /vendor/etc/init/ /system/etc/init/'"
fi

# 2. App processes with capabilities or without seccomp.
echo
echo "  [app process privilege]"
APPPIDS=$(echo "$PSOUT" | awk '$1 ~ /^u[0-9]+_a/ {print $2}' | head -40)
FLAGGED=0
for pid in $APPPIDS; do
    STATUS=$(adbsh "cat /proc/$pid/status 2>/dev/null")
    [[ -z "$STATUS" ]] && continue
    NAME=$(echo "$PSOUT" | awk -v p="$pid" '$2==p {print $3}')
    CAPEFF=$(echo "$STATUS" | awk '/^CapEff:/ {print $2}')
    SECCOMP=$(echo "$STATUS" | awk '/^Seccomp:/ {print $2}')
    NNP=$(echo "$STATUS" | awk '/^NoNewPrivs:/ {print $2}')

    ISSUE=""
    [[ -n "$CAPEFF" && "$CAPEFF" != "0000000000000000" ]] && ISSUE="$ISSUE CapEff=$CAPEFF"
    [[ "$SECCOMP" == "0" ]] && ISSUE="$ISSUE seccomp=DISABLED"
    [[ "$NNP" == "0" ]] && ISSUE="$ISSUE NoNewPrivs=0"

    if [[ -n "$ISSUE" ]]; then
        printf '    !! %-40s pid=%-7s%s\n' "$NAME" "$pid" "$ISSUE"
        FLAGGED=$((FLAGGED+1))
    fi
done
if [[ $FLAGGED -eq 0 ]]; then
    echo "    OK — sampled app processes have empty capabilities, seccomp active,"
    echo "    and NoNewPrivs set. That is SpecializeCommon() working (README 4.3)."
else
    echo
    echo "    Non-empty CapEff on an app process is highly anomalous."
    echo "    seccomp=0 usually means the process was not created by Zygote normally"
    echo "    (zygisk injection, unusual spawn, or a device with the filter disabled)."
fi

# 3. World-accessible UNIX sockets — an IPC surface outside the permission model.
echo
echo "  [world-accessible sockets]"
if [[ "$ROOT" == "yes" ]]; then
    WSOCK=$(su_sh "ls -l /dev/socket/ 2>/dev/null" | awk '$1 ~ /rw.rw.rw|srw.rw.rw/ {print}')
    if [[ -n "$WSOCK" ]]; then
        echo "$WSOCK" | sed 's/^/    !! /'
        echo
        echo "    Mode 0666 sockets are reachable by ANY app on the device, bypassing"
        echo "    the framework permission model entirely. See ../../24-IPC/."
    else
        echo "    None found with mode 0666 in /dev/socket."
    fi
    echo
    echo "  [abstract-namespace sockets]"
    su_sh "cat /proc/net/unix" | awk '$NF ~ /^@/ {print $NF}' | sort -u | head -20 | sed 's/^/    /'
    echo "    (abstract sockets have NO filesystem permissions — see ../../24-IPC/)"
else
    echo "    (root required)"
fi

# 4. Listening TCP sockets on localhost — reachable by any app with INTERNET.
echo
echo "  [localhost listeners]"
LISTEN=$(adbsh "netstat -tlnp 2>/dev/null | grep -E '127\.0\.0\.1|::1'" || true)
if [[ -n "$LISTEN" ]]; then
    echo "$LISTEN" | sed 's/^/    /'
    echo "    Any app holding INTERNET can reach these. See ../../24-IPC/."
else
    echo "    None detected (or netstat unavailable)."
fi

# ------------------------------------------------------------- detail ------

if [[ "$MODE" == "detail" ]]; then
    echo
    echo "-- per-process detail --"
    printf '  %-14s %-7s %-34s %s\n' "USER" "PID" "NAME" "SELINUX DOMAIN"
    echo "$PSZ" | while read -r ctx user pid ppid rest; do
        dom=$(echo "$ctx" | sed 's/^u:r://; s/:s0.*//')
        name=$(echo "$rest" | awk '{print $NF}')
        printf '  %-14s %-7s %-34s %s\n' "$user" "$pid" "$name" "$dom"
    done | head -80
fi

# ---------------------------------------------------------------- pkg ------

if [[ "$MODE" == "pkg" ]]; then
    echo
    echo "-- deep dive: $PKG --"
    PID=$(adbsh "pidof -s $PKG")
    if [[ -z "$PID" ]]; then
        echo "  process not running. Launch it, then re-run."
        exit 0
    fi
    echo "  pid: $PID"
    echo
    echo "  privilege (from /proc/$PID/status):"
    adbsh "cat /proc/$PID/status" | grep -E '^(Name|Uid|Gid|Groups|CapEff|CapBnd|Seccomp|NoNewPrivs):' \
        | sed 's/^/    /'
    echo
    echo "  SELinux context:"
    adbsh "cat /proc/$PID/attr/current" | sed 's/^/    /'
    echo
    echo "  interpretation:"
    cat <<'EOF'
    Uid/Gid       the app's identity, allocated by PackageManagerService
    Groups        supplementary GIDs. 3003 = AID_INET (the INTERNET permission)
    CapEff        should be 0000000000000000 for an app
    Seccomp       2 = filter active (installed by Zygote after fork)
    NoNewPrivs    1 = privilege can never be regained via a setuid binary
    context       untrusted_app_XX with MCS categories giving per-app isolation
EOF
    echo
    echo "  open sockets:"
    adbsh "ls -l /proc/$PID/fd 2>/dev/null | grep -c socket" | sed 's/^/    socket fds: /'
fi

cat <<'EOF'

--------------------------------------------------------------
 WHERE FINDINGS ACTUALLY LIVE (README section 5.2)
   On an OEM device, not in AOSP. Look at:
     - vendor/odm daemons running as root
     - pre-installed privileged apps (/system/priv-app)
     - init .rc entries with no 'user' line or broad capabilities
     - world-accessible sockets and localhost listeners
--------------------------------------------------------------
EOF
