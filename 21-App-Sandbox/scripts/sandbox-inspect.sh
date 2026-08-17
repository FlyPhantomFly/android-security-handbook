#!/system/bin/sh
#
# sandbox-inspect.sh — read a process's complete sandbox state and interpret it.
#
# WHAT IT DOES
#   Given a package name or a PID, prints every kernel-enforced constraint on
#   that process — UID and the arithmetic behind it, supplementary GIDs with
#   their meanings, all five capability sets, seccomp mode, no_new_privs, the
#   SELinux context broken into its parts, the mount flags on /data, and the
#   mode and label of the app's data directory — and then EXPLAINS each value
#   rather than just printing it.
#
#   It also prints the same fields for the calling shell, side by side, because
#   the difference between the two is the single most important methodological
#   fact in this chapter.
#
# WHY IT MATTERS
#   /proc/<pid>/status is the ground truth. Framework APIs, dumpsys output and
#   decompiled source all describe what an app INTENDS. This file describes what
#   the kernel will actually enforce. When they disagree, the kernel wins.
#
#   The interpretation matters as much as the values. "Groups: 3003" is only
#   useful if you know that 3003 is AID_INET and therefore that this line IS the
#   INTERNET permission — a Linux group membership, not a framework check, and
#   consequently not something you can hook away from inside the process.
#
#   See ../README.md sections 3.1 to 3.9, and ../labs/lab-01-mapping-the-sandbox.md.
#
# HOW TO RUN
#   # host
#   adb push sandbox-inspect.sh /data/local/tmp/
#   adb shell sh /data/local/tmp/sandbox-inspect.sh com.example.target
#
#   # adb shell
#   sh /data/local/tmp/sandbox-inspect.sh com.example.target
#   sh /data/local/tmp/sandbox-inspect.sh 12401          # by PID
#   sh /data/local/tmp/sandbox-inspect.sh --all          # every app process
#   sh /data/local/tmp/sandbox-inspect.sh --self         # the shell itself
#
#   # adb shell as root  (only needed for the data-directory and packages.list
#   #                     sections; everything else works unprivileged)
#   su -c 'sh /data/local/tmp/sandbox-inspect.sh com.example.target'
#
# REQUIREMENTS
#   Android 8+ device or emulator. Toybox shell (the Android default). No root
#   required for the core output; sections that need it say so and degrade
#   gracefully. Nothing is installed and nothing is modified — this script only
#   reads.
#
# REACHABILITY DISCIPLINE
#   This script runs in YOUR shell, which is UID 2000 in the SELinux domain
#   `shell`. Reading an app's /proc entry from here tells you about the APP.
#   But anything you can DO from this shell tells you nothing about what an app
#   can do. If you need to answer "can an app reach X", install a probe APK —
#   see ../examples/attacker-app/ and ../labs/lab-03-attacker-app.md.
#
# AUTHORISED TESTING ONLY.

TARGET="$1"

# ---------------------------------------------------------------- helpers ---

hr()  { echo "------------------------------------------------------------------"; }
h1()  { echo; echo "=================================================================="; \
        echo "  $1"; echo "=================================================================="; }
h2()  { echo; echo "--- $1 ---"; }
kv()  { printf '  %-26s %s\n' "$1" "$2"; }
note(){ printf '      %s\n' "$1"; }

field() {   # field <pid> <Key>   -> the value after "Key:"
    grep -E "^$2:" "/proc/$1/status" 2>/dev/null | sed "s/^$2:[[:space:]]*//"
}

have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------ GID meanings ---

gid_meaning() {
    case "$1" in
        1000) echo "AID_SYSTEM" ;;
        1007) echo "AID_LOG — read the system log" ;;
        1015) echo "AID_SDCARD_RW" ;;
        1023) echo "AID_MEDIA_RW" ;;
        1028) echo "AID_SDCARD_R" ;;
        1077) echo "AID_EXT_DATA_RW" ;;
        1078) echo "AID_EXT_OBB_RW" ;;
        2000) echo "AID_SHELL — this is the adb shell user" ;;
        3001) echo "AID_NET_BT_ADMIN — Bluetooth administration" ;;
        3002) echo "AID_NET_BT — Bluetooth sockets" ;;
        3003) echo "AID_INET — *** THIS IS THE INTERNET PERMISSION ***" ;;
        3004) echo "AID_NET_RAW — raw sockets (SOCK_RAW)" ;;
        3005) echo "AID_NET_ADMIN — network configuration" ;;
        3006) echo "AID_NET_BW_STATS — read bandwidth statistics" ;;
        3007) echo "AID_NET_BW_ACCT — change bandwidth accounting" ;;
        3009) echo "AID_READPROC — read other processes' /proc entries" ;;
        3010) echo "AID_WAKELOCK — take kernel wakelocks" ;;
        3011) echo "AID_UHID" ;;
        9997) echo "AID_EVERYBODY — a group every app is in" ;;
        9998) echo "AID_MISC" ;;
        9999) echo "AID_NOBODY" ;;
        *)
            # Derived per-app GIDs. These are computed, not table-driven.
            if [ "$1" -ge 20000 ] 2>/dev/null && [ "$1" -le 29999 ] 2>/dev/null; then
                echo "derived per-app GID (20000 + appId) — external storage / SDK sandbox range"
            elif [ "$1" -ge 50000 ] 2>/dev/null && [ "$1" -le 59999 ] 2>/dev/null; then
                echo "derived per-app 'shared' GID (50000 + appId)"
            elif [ "$1" -ge 10000 ] 2>/dev/null && [ "$1" -le 19999 ] 2>/dev/null; then
                echo "an application GID"
            else
                echo "(not in this script's table — check android_filesystem_config.h)"
            fi ;;
    esac
}

uid_class() {
    u="$1"
    a=$(( u % 100000 ))
    if   [ "$u" -eq 0 ];                                  then echo "AID_ROOT — the superuser"
    elif [ "$u" -eq 1000 ];                               then echo "AID_SYSTEM — system_server and friends"
    elif [ "$u" -eq 2000 ];                               then echo "AID_SHELL — the adb shell user, NOT an app"
    elif [ "$a" -ge 10000 ] && [ "$a" -le 19999 ];        then echo "ordinary application"
    elif [ "$a" -ge 20000 ] && [ "$a" -le 29999 ];        then echo "SDK sandbox (Privacy Sandbox) — host app is uid $(( a - 10000 ))"
    elif [ "$a" -ge 90000 ] && [ "$a" -le 98999 ];        then echo "ISOLATED process, forked from an App Zygote"
    elif [ "$a" -ge 99000 ] && [ "$a" -le 99999 ];        then echo "ISOLATED process (android:isolatedProcess)"
    elif [ "$u" -lt 10000 ];                              then echo "a platform/daemon UID"
    else                                                       echo "unclassified"
    fi
}

# ------------------------------------------------------------ the reporter ---

inspect_pid() {
    PID="$1"
    [ -r "/proc/$PID/status" ] || { echo "  cannot read /proc/$PID/status"; return 1; }

    NAME=$(field "$PID" Name)
    CMD=$(tr '\0' ' ' < "/proc/$PID/cmdline" 2>/dev/null | sed 's/ *$//')
    [ -z "$CMD" ] && CMD="$NAME"

    h1 "pid $PID   $CMD"

    # ---- identity -------------------------------------------------------
    h2 "1. IDENTITY  (README section 3.1)"
    UIDLINE=$(field "$PID" Uid)
    GIDLINE=$(field "$PID" Gid)
    RUID=$(echo "$UIDLINE" | awk '{print $1}')
    kv "Uid (r/e/s/fs)" "$UIDLINE"
    kv "Gid (r/e/s/fs)" "$GIDLINE"
    if [ -n "$RUID" ]; then
        kv "userId  (uid / 100000)" "$(( RUID / 100000 ))"
        kv "appId   (uid % 100000)" "$(( RUID % 100000 ))"
        kv "class" "$(uid_class "$RUID")"
        if [ "$(( RUID / 100000 ))" -gt 0 ]; then
            note "userId > 0 means a secondary user or a WORK PROFILE. Different"
            note "data directory, different CE key, a genuinely separate sandbox."
        fi
    fi
    note "All four Uid values identical is normal for an app: Zygote called"
    note "setresuid() with one value and the app cannot change it (seccomp"
    note "blocks the whole setuid family)."

    # ---- groups ---------------------------------------------------------
    h2 "2. SUPPLEMENTARY GROUPS  (README section 3.9)"
    GROUPS=$(field "$PID" Groups)
    kv "Groups" "${GROUPS:-<none>}"
    HAS_INET=0
    for g in $GROUPS; do
        printf '      %-8s %s\n' "$g" "$(gid_meaning "$g")"
        [ "$g" = "3003" ] && HAS_INET=1
    done
    echo
    if [ "$HAS_INET" = "1" ]; then
        note "GID 3003 present => this process HOLDS android.permission.INTERNET."
    else
        note "GID 3003 ABSENT => this process CANNOT create AF_INET/AF_INET6"
        note "sockets. socket() returns EACCES from the KERNEL, before any DNS"
        note "lookup. Hooking java.net.Socket in this process cannot change that."
    fi

    # ---- capabilities ---------------------------------------------------
    h2 "3. CAPABILITIES  (README section 3.6)"
    ALLZERO=1
    for k in CapInh CapPrm CapEff CapBnd CapAmb; do
        v=$(field "$PID" "$k")
        kv "$k" "${v:-<absent>}"
        case "$v" in 0000000000000000|"") : ;; *) ALLZERO=0 ;; esac
    done
    echo
    if [ "$ALLZERO" = "1" ]; then
        note "All five sets empty — the expected state for an application."
        note "CapBnd (the BOUNDING set) empty is the load-bearing one: it is a"
        note "hard upper limit on what this process, or anything it execve()s,"
        note "may ever hold. No capability can be acquired by any route."
    else
        note "NON-EMPTY capability set. This is not an ordinary application."
        note "Identify what it actually is before drawing any conclusion."
    fi

    # ---- seccomp --------------------------------------------------------
    h2 "4. SECCOMP AND NO_NEW_PRIVS  (README section 3.5)"
    SEC=$(field "$PID" Seccomp)
    SECF=$(field "$PID" Seccomp_filters)
    NNP=$(field "$PID" NoNewPrivs)
    kv "Seccomp" "${SEC:-<absent>}"
    kv "Seccomp_filters" "${SECF:-<absent>}"
    kv "NoNewPrivs" "${NNP:-<absent>}"
    echo
    case "$SEC" in
        2) note "2 = SECCOMP_MODE_FILTER. A BPF filter is attached. The setuid"
           note "family, capset, chroot/pivot_root/mount, the kernel keyring,"
           note "perf_event_open and module loading are unreachable from here."
           note "NOTE: seccomp does NOT block ptrace — an app may ptrace itself."
           note "Cross-app ptrace is stopped by DAC + SELinux + Yama instead." ;;
        1) note "1 = SECCOMP_MODE_STRICT. Unusual on Android." ;;
        0) note "0 = NO seccomp filter. This process is NOT sandboxed like an app."
           note "If this is your shell, that is expected and it is exactly why an"
           note "experiment run here does not answer 'can an app do X'." ;;
        *) note "Field unavailable on this kernel build." ;;
    esac
    [ "$NNP" = "1" ] && note "NoNewPrivs=1: the kernel will refuse any privilege-raising execve()."

    # ---- selinux --------------------------------------------------------
    h2 "5. SELINUX CONTEXT  (README section 3.4)"
    CTX=$(cat "/proc/$PID/attr/current" 2>/dev/null | tr -d '\0')
    kv "context" "${CTX:-<unreadable>}"
    if [ -n "$CTX" ]; then
        SEUSER=$(echo "$CTX" | cut -d: -f1)
        SEROLE=$(echo "$CTX" | cut -d: -f2)
        SETYPE=$(echo "$CTX" | cut -d: -f3)
        SELEVEL=$(echo "$CTX" | cut -d: -f4-)
        kv "  user" "$SEUSER"
        kv "  role" "$SEROLE"
        kv "  type (domain)" "$SETYPE"
        kv "  level:categories" "$SELEVEL"
        echo
        case "$SETYPE" in
            untrusted_app*) note "Ordinary third-party app. NOTE: every third-party app shares"
                            note "this domain, so type enforcement alone cannot tell two apps"
                            note "apart. The MCS categories above are what separate them." ;;
            isolated_app*)  note "ISOLATED process. No permissions, no network, no data dir,"
                            note "and a tiny Binder allowlist. The strongest sandbox the"
                            note "platform offers an app developer." ;;
            sdk_sandbox*)   note "SDK Runtime (Privacy Sandbox) process." ;;
            platform_app)   note "Signed with the platform key." ;;
            priv_app)       note "A privileged app from /system/priv-app." ;;
            system_app)     note "Runs with AID_SYSTEM." ;;
            shell)          note "This is the adb shell domain — NOT an application." ;;
            runas_app)      note "Inside run-as. You have the app's UID but a DIFFERENT SELinux"
                            note "domain and no seccomp filter. Good for reading the app's files;"
                            note "NOT a faithful reproduction of the app's sandbox." ;;
        esac
    fi

    # ---- namespaces and fds --------------------------------------------
    h2 "6. MISC"
    kv "threads" "$(field "$PID" Threads)"
    kv "open fds" "$(ls "/proc/$PID/fd" 2>/dev/null | wc -l | tr -d ' ')"
    kv "mnt namespace" "$(readlink "/proc/$PID/ns/mnt" 2>/dev/null || echo '<unreadable>')"
    kv "net namespace" "$(readlink "/proc/$PID/ns/net" 2>/dev/null || echo '<unreadable>')"
    note "Apps share the network namespace with the rest of the device. That is"
    note "why abstract-namespace UNIX sockets are reachable by every app — see"
    note "../../24-IPC/."
}

inspect_package_files() {
    PKG="$1"
    h2 "7. ON-DISK STATE  (README sections 3.2 and 3.3)"

    for D in "/data/data/$PKG" "/data/user/0/$PKG" "/data/user_de/0/$PKG"; do
        if [ -e "$D" ]; then
            OUT=$(ls -ldZ "$D" 2>&1)
            printf '  %s\n' "$OUT"
        fi
    done
    case "$(ls -ldZ "/data/data/$PKG" 2>&1)" in
        *"Permission denied"*|*"No such file"*)
            note "Cannot stat the data directory from this context. Expected without"
            note "root: it is mode 0700 and you are not the owner. That the DIRECTORY"
            note "denies you is the point — the missing execute bit means no file"
            note "inside can be reached regardless of its own mode." ;;
    esac

    APK=$(pm path "$PKG" 2>/dev/null | head -1 | sed 's/package://')
    if [ -n "$APK" ]; then
        echo
        kv "APK" "$APK"
        ls -lZ "$APK" 2>/dev/null | sed 's/^/  /'
        note "Mode 0644, owner system: WORLD-READABLE, by design. Any app on the"
        note "device can read it. Nothing shipped inside an APK is secret."
    fi

    echo
    if [ -r /data/system/packages.list ]; then
        h2 "8. packages.list ENTRY (root only)"
        LINE=$(grep -E "^$PKG " /data/system/packages.list 2>/dev/null)
        if [ -n "$LINE" ]; then
            echo "  $LINE"
            echo
            printf '  %-8s %s\n' "field 1" "package name          : $(echo "$LINE" | awk '{print $1}')"
            printf '  %-8s %s\n' "field 2" "uid                   : $(echo "$LINE" | awk '{print $2}')"
            printf '  %-8s %s\n' "field 3" "DEBUGGABLE flag       : $(echo "$LINE" | awk '{print $3}')   <- what run-as reads"
            printf '  %-8s %s\n' "field 4" "data directory        : $(echo "$LINE" | awk '{print $4}')"
            printf '  %-8s %s\n' "field 5" "seinfo (seapp_contexts): $(echo "$LINE" | awk '{print $5}')"
            printf '  %-8s %s\n' "field 6" "supplementary GIDs    : $(echo "$LINE" | awk '{print $6}')"
            printf '  %-8s %s\n' "field 7" "profileableFromShell  : $(echo "$LINE" | awk '{print $7}')"
            printf '  %-8s %s\n' "field 8" "long version code     : $(echo "$LINE" | awk '{print $8}')"
        fi
    fi

    echo
    h2 "9. MANIFEST-LEVEL RISK FLAGS (from dumpsys, no root needed)"
    dumpsys package "$PKG" 2>/dev/null | \
        grep -iE 'userId=|sharedUser|flags=\[|privateFlags=|dataDir=|primaryCpuAbi|versionName' | \
        head -12 | sed 's/^ */  /'
    SHARED=$(dumpsys package "$PKG" 2>/dev/null | grep -i 'sharedUser')
    if [ -n "$SHARED" ]; then
        echo
        note "*** sharedUserId IS SET. ***"
        note "Analyse this app at the granularity of the whole shared-UID GROUP,"
        note "not the individual app. The weakest member defines the security of"
        note "all of them. Find the siblings:"
        note "    pm list packages -U | grep ':$(dumpsys package "$PKG" 2>/dev/null | grep -oE 'userId=[0-9]+' | head -1 | cut -d= -f2)\\b'"
    fi
}

environment_report() {
    h1 "DEVICE AND SHELL GROUND TRUTH"
    kv "android release" "$(getprop ro.build.version.release)"
    kv "sdk" "$(getprop ro.build.version.sdk)"
    kv "security patch" "$(getprop ro.build.version.security_patch)"
    kv "build type" "$(getprop ro.build.type)"
    kv "ro.debuggable" "$(getprop ro.debuggable)"
    kv "fingerprint" "$(getprop ro.build.fingerprint)"
    kv "selinux mode" "$(getenforce 2>/dev/null || echo '<unknown>')"
    echo
    case "$(getprop ro.build.type)" in
        userdebug|eng)
            note "*** NOT a production build. ***"
            note "ro.debuggable=1 makes run-as work on EVERY package and changes"
            note "several other behaviours. Never generalise a finding from this"
            note "device to a user build without re-confirming it there." ;;
    esac

    h2 "YOUR SHELL — compare every line against the app's"
    kv "id" "$(id)"
    kv "Uid" "$(field $$ Uid)"
    kv "Groups" "$(field $$ Groups)"
    kv "CapBnd" "$(field $$ CapBnd)"
    kv "Seccomp" "$(field $$ Seccomp)"
    kv "NoNewPrivs" "$(field $$ NoNewPrivs)"
    kv "selinux" "$(cat /proc/$$/attr/current 2>/dev/null | tr -d '\0')"
    echo
    note "You are UID 2000 in the domain 'shell', with NO seccomp filter and a"
    note "NON-empty capability bounding set. You are not an app. Anything you"
    note "prove you can do here says nothing about what an installed app can do."
    note "To answer that question, install a probe APK:"
    note "    ../examples/attacker-app/  and  ../labs/lab-03-attacker-app.md"

    h2 "MOUNT FLAGS ON THE WRITABLE PARTITIONS"
    mount 2>/dev/null | grep -E ' /data | /storage | /sdcard ' | sed 's/^/  /'
    note "Expect nosuid (setuid bit ignored) and nodev. With an empty capability"
    note "bounding set and NoNewPrivs, that is three independent reasons an app"
    note "cannot escalate by dropping a setuid binary. Any one would suffice."
}

# ------------------------------------------------------------------- main ---

echo
echo "=================================================================="
echo "  sandbox-inspect — Chapter 21, The Android Application Sandbox"
echo "=================================================================="

environment_report

case "$TARGET" in
    ""|-h|--help)
        h1 "USAGE"
        echo "  sh sandbox-inspect.sh <package>     inspect every process of a package"
        echo "  sh sandbox-inspect.sh <pid>         inspect one process"
        echo "  sh sandbox-inspect.sh --all         every app process on the device"
        echo "  sh sandbox-inspect.sh --self        just this shell"
        echo
        echo "  Root is optional. Sections that need it say so."
        exit 0 ;;
    --self)
        inspect_pid $$
        exit 0 ;;
    --all)
        h1 "ALL APPLICATION PROCESSES"
        # ps -A -Z gives context + user + pid + name in one pass.
        ps -A -Z 2>/dev/null | grep -E 'untrusted_app|isolated_app|sdk_sandbox|priv_app|platform_app|system_app' \
            | sed 's/^/  /'
        echo
        note "Inspect any one of them by PID:  sh $0 <pid>"
        exit 0 ;;
esac

# Numeric argument => a PID. Otherwise a package name.
case "$TARGET" in
    ''|*[!0-9]*)
        PIDS=$(pidof "$TARGET" 2>/dev/null)
        if [ -z "$PIDS" ]; then
            # Catch processes named "<pkg>:worker" too.
            PIDS=$(ps -A -o PID,NAME 2>/dev/null | awk -v p="$TARGET" '$2 ~ "^"p {print $1}')
        fi
        if [ -z "$PIDS" ]; then
            h1 "NO RUNNING PROCESS FOR $TARGET"
            note "The app is not running. Start it, then re-run:"
            note "    am start -n $TARGET/.MainActivity"
            note "Static state is still available below."
        fi
        for P in $PIDS; do inspect_pid "$P"; done
        inspect_package_files "$TARGET"
        ;;
    *)
        inspect_pid "$TARGET"
        ;;
esac

h1 "READ THIS BEFORE WRITING ANYTHING DOWN"
cat <<'EOF'
  Everything above was observed from a shell running as UID 2000 in the SELinux
  domain `shell`, with no seccomp filter. That identity holds privileges no
  installed application has.

  Reading an app's /proc entry from here tells you about THE APP, and is sound.
  Performing an operation from here and concluding "an app can do this" is NOT
  sound, and is the most common methodological error in mobile testing.

  Run both experiments. Record both results. The difference is the finding.
      ../labs/lab-03-attacker-app.md
      ../examples/attacker-app/
EOF
echo
