#!/usr/bin/env bash
#
# enumerate-ipc-surface.sh — enumerate one app's COMPLETE IPC surface.
#
# WHAT IT DOES
#   Collects, in one pass, every channel through which an installed application
#   can be reached by another application on the same device:
#
#     0  META        device fingerprint, patch level, package uid/pid, targetSdk
#     1  COMPONENTS  exported activities, services, receivers and providers,
#                    with the guarding permission and its protectionLevel
#     2  PERMS       every permission the app declares, and whether it is a real
#                    control (only `signature` is)
#     3  BINDER      registered binder services (system-wide) and the app's own
#                    binder state from debugfs when it is readable
#     4  UNIX-FS     filesystem-named UNIX sockets, including /dev/socket, with
#                    their MODE BITS — 0666 entries are flagged
#     5  UNIX-ABS    ABSTRACT-namespace UNIX sockets from /proc/net/unix. These
#                    have no inode, no owner and no mode bits at all
#     6  TCP         listening TCP/UDP sockets with the hex address decoded, the
#                    owning uid resolved to a package, and 0.0.0.0 flagged
#     7  FDS         open file descriptors of the app's process
#     8  SHM         ashmem / memfd / dmabuf mappings
#     9  FILES       data-directory modes and SELinux labels (needs root)
#
#   It then prints a FINDINGS block that pulls the three things most often
#   missed to the top: mode-0666 sockets, abstract-namespace sockets, and
#   localhost listeners.
#
#   Output goes to stdout and, in parallel, to a directory of section files plus
#   a combined ipc-surface.txt whose "### SECTION: NAME" markers are the input
#   format for ipc-surface-report.py.
#
# WHY IT MATTERS
#   Four of those nine sections are invisible to every manifest-driven tool.
#   `android:exported` describes the mediated surface — Intents, providers,
#   broadcasts, bound services — and nothing else. Abstract sockets, localhost
#   listeners, shared memory and file modes appear in no manifest, in no
#   `aapt2 dump badging` output and in no MobSF report. They are where the
#   findings that change a report's executive summary tend to live.
#   See ../README.md sections 2.2, 3.9-3.13 and 3.22 step 3.
#
# HOW TO RUN
#   # host
#   ./enumerate-ipc-surface.sh com.example.target
#   ./enumerate-ipc-surface.sh com.example.target ./out-target
#   ./enumerate-ipc-surface.sh --all-sockets com.example.target   # device-wide
#
#   Then:
#   python3 ipc-surface-report.py ./out-target/ipc-surface.txt --md report.md
#
# REQUIREMENTS
#   adb on PATH, exactly one device connected, the target INSTALLED and ideally
#   RUNNING (launch it first — a socket that is opened lazily does not exist
#   until the code path runs). Root is optional: without it, sections 3, 7 and 9
#   are partial and the script says so rather than printing silence.
#
# READ THIS BEFORE YOU REPORT ANYTHING THIS PRINTS
#   Everything here is collected from `adb shell`, which runs as UID 2000 in the
#   SELinux domain `shell`. That identity can see and reach things an ordinary
#   application cannot. This script tells you a channel EXISTS. It does not tell
#   you an unprivileged app can USE it. Prove that separately, from a real APK:
#   ../examples/attacker-app/. See ../README.md section 3.22 step 4.
#
# EXIT CODES
#   0 ok · 1 usage · 2 no device · 3 package not installed

set -uo pipefail

# ------------------------------------------------------------------- usage ---

ALL_SOCKETS=0
while [[ "${1:-}" == --* ]]; do
    case "$1" in
        --all-sockets) ALL_SOCKETS=1; shift ;;
        -h|--help)     sed -n '3,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

PKG="${1:-}"
OUT="${2:-./ipc-surface-${PKG}}"

if [[ -z "$PKG" ]]; then
    sed -n '3,60p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

# ----------------------------------------------------------------- helpers ---

adbsh()  { adb shell "$@" 2>/dev/null | tr -d '\r'; }
have_root() { [[ "$(adbsh 'id -u')" == "0" ]] || \
              [[ -n "$(adbsh 'command -v su')" ]]; }
rootsh() {
    if [[ "$(adbsh 'id -u')" == "0" ]]; then adbsh "$1"
    elif [[ -n "$(adbsh 'command -v su')" ]]; then adb shell "su -c '$1'" 2>/dev/null | tr -d '\r'
    else echo ""; fi
}

COMBINED=""
SECTION_NAME=""

section() {
    SECTION_NAME="$1"
    {
        echo ""
        echo "### SECTION: $1"
        echo "# $2"
        echo "$(printf '=%.0s' $(seq 1 72))"
    } | tee -a "$COMBINED"
}

emit() { printf '%s\n' "$*" | tee -a "$COMBINED"; }

# Collected for the FINDINGS block at the end.
F_WORLD_SOCKETS=()
F_ABSTRACT=()
F_LISTENERS=()
F_ANY_IFACE=()
F_EXPORTED_NOPERM=()

# ------------------------------------------------------------ preflight ------

if [[ -z "$(adb devices | sed -n '2p')" ]]; then
    echo "error: no device connected (adb devices is empty)" >&2
    exit 2
fi

if [[ -z "$(adbsh "pm path $PKG")" ]]; then
    echo "error: package $PKG is not installed on this device" >&2
    exit 3
fi

mkdir -p "$OUT"
COMBINED="$OUT/ipc-surface.txt"
: > "$COMBINED"

PID="$(adbsh "pidof -s $PKG")"
UID_="$(adbsh "dumpsys package $PKG | grep -m1 userId=" | tr -dc '0-9')"

# ------------------------------------------------------------- 0. META -------

section "META" "ground truth — record every line of this in the report"

emit "package            : $PKG"
emit "uid                : ${UID_:-unknown}"
emit "pid                : ${PID:-<not running — LAUNCH THE APP AND RE-RUN>}"
emit "apk                : $(adbsh "pm path $PKG" | head -1 | sed 's/package://')"
emit "android release    : $(adbsh 'getprop ro.build.version.release')"
emit "sdk                : $(adbsh 'getprop ro.build.version.sdk')"
emit "security patch     : $(adbsh 'getprop ro.build.version.security_patch')"
emit "fingerprint        : $(adbsh 'getprop ro.build.fingerprint')"
emit "abi                : $(adbsh 'getprop ro.product.cpu.abi')"
emit "selinux            : $(adbsh 'getenforce')"
emit "shell uid          : $(adbsh 'id')"
emit "root available     : $(have_root && echo yes || echo no)"
adbsh "dumpsys package $PKG" | grep -m4 -E "versionName|versionCode|targetSdk|minSdk" \
    | sed 's/^[[:space:]]*/target             : /' | tee -a "$COMBINED"

emit ""
emit "NOTE: the app's targetSdk — not this device's SDK level — decides which"
emit "      platform mitigations apply to it. An app targeting API 22 running"
emit "      on Android 14 still gets a decade of legacy behaviour."

if [[ -z "$PID" ]]; then
    emit ""
    emit "WARNING: the app is not running. Sockets that are opened lazily do not"
    emit "         exist yet, and sections 4-8 will be empty or misleading."
    emit "         Run:  adb shell monkey -p $PKG -c android.intent.category.LAUNCHER 1"
    emit "         exercise the app for a minute, then re-run this script."
fi

# ------------------------------------------------- 1. COMPONENTS -------------

section "COMPONENTS" "the MEDIATED surface — the only part a manifest tool sees"

adbsh "dumpsys package $PKG" > "$OUT/dumpsys-package.txt"

emit "-- exported declarations (raw) --"
grep -nE "exported=true" "$OUT/dumpsys-package.txt" | tee -a "$COMBINED"

emit ""
emit "-- resolver tables --"
for pair in "Activity Resolver Table:activities" \
            "Receiver Resolver Table:receivers" \
            "Service Resolver Table:services" \
            "Provider Resolver Table:providers"; do
    hdr="${pair%%:*}"; name="${pair##*:}"
    awk -v h="$hdr" '
        $0 ~ h {p=1}
        p && /Resolver Table:/ && $0 !~ h {p=0}
        p {print}
    ' "$OUT/dumpsys-package.txt" > "$OUT/$name.txt"
    emit "  $name: $(wc -l < "$OUT/$name.txt") lines -> $OUT/$name.txt"
done

emit ""
emit "-- provider authorities (the content:// prefixes to test) --"
grep -oE "authority=[^ ]+" "$OUT/dumpsys-package.txt" | sort -u | tee -a "$COMBINED"

emit ""
emit "-- components with an intent-filter but no explicit exported attribute --"
emit "   (implicitly exported below targetSdk 31; mandatory from 31)"
grep -nE "filter |Action:|Category:|Scheme:" "$OUT/dumpsys-package.txt" | head -60 \
    | tee -a "$COMBINED"

while read -r line; do
    [[ -z "$line" ]] && continue
    F_EXPORTED_NOPERM+=("$line")
done < <(grep -E "exported=true" "$OUT/dumpsys-package.txt" | grep -v "permission=" | head -40)

# ------------------------------------------------- 2. PERMISSIONS ------------

section "PERMS" "protection levels — only 'signature' is a real control"

emit "-- permissions DECLARED by the app --"
adbsh "dumpsys package $PKG" | awk '/declared permissions:/,/^$/' | tee -a "$COMBINED"

emit ""
emit "-- protection level of each declared permission --"
for perm in $(adbsh "dumpsys package $PKG" \
        | awk '/declared permissions:/,/^$/' \
        | grep -oE "[a-zA-Z0-9_.]+\.permission\.[A-Z_0-9]+" | sort -u); do
    lvl="$(adbsh "pm list permissions -f -g" | grep -A6 "permission:$perm" \
            | grep -m1 -i "protectionLevel" | sed 's/^[[:space:]]*//')"
    [[ -z "$lvl" ]] && lvl="$(adbsh "dumpsys package permission $perm" \
            | grep -m1 -i protection | sed 's/^[[:space:]]*//')"
    case "$lvl" in
        *signature*) verdict="REAL CONTROL — same signing key only" ;;
        *dangerous*) verdict="WEAK — a malicious app will simply ask the user" ;;
        *normal*)    verdict="NOT A CONTROL — granted silently to any app that asks" ;;
        *)           verdict="unresolved — check manually" ;;
    esac
    emit "  $perm"
    emit "      ${lvl:-<protectionLevel not resolved>}"
    emit "      -> $verdict"
done

emit ""
emit "-- permissions the app HOLDS --"
adbsh "dumpsys package $PKG" | awk '/requested permissions:/,/^$/' | tee -a "$COMBINED"

# ---------------------------------------------------- 3. BINDER --------------

section "BINDER" "registered binder services and this process's binder state"

emit "-- servicemanager registry (system-wide) --"
adbsh "service list" > "$OUT/service-list.txt"
emit "  $(wc -l < "$OUT/service-list.txt") services -> $OUT/service-list.txt"
grep -iE "$PKG|$(echo "$PKG" | awk -F. '{print $NF}')" "$OUT/service-list.txt" \
    | tee -a "$COMBINED"
emit "  (an ordinary app cannot addService() to servicemanager; SELinux and"
emit "   the service_contexts policy decide who may register a name. An app's"
emit "   own AIDL services are reached by bindService, not by name.)"

emit ""
emit "-- bound services of this package --"
adbsh "dumpsys activity services $PKG" | head -80 | tee -a "$COMBINED"

emit ""
emit "-- kernel binder state --"
BSTATE="$(rootsh "cat /sys/kernel/debug/binder/proc/${PID:-0} 2>/dev/null" | head -40)"
if [[ -n "$BSTATE" ]]; then
    emit "$BSTATE"
else
    emit "  (unavailable: debugfs not mounted, or unreadable under SELinux even"
    emit "   to root. Normal on production kernels — try it and move on.)"
fi

# ------------------------------------------- 4. UNIX SOCKETS (FILESYSTEM) ----

section "UNIX-FS" "filesystem-named UNIX sockets — DAC and SELinux apply"

emit "-- /dev/socket (system socket directory) --"
adbsh "ls -lZ /dev/socket 2>/dev/null" | tee -a "$COMBINED" > "$OUT/dev-socket.txt"

emit ""
emit "-- world-writable (0666) or world-readable entries in /dev/socket --"
while read -r line; do
    [[ -z "$line" ]] && continue
    mode="$(echo "$line" | awk '{print $1}')"
    name="$(echo "$line" | awk '{print $NF}')"
    # srw-rw-rw-  == 0666 == every process on the device may connect
    if [[ "$mode" == *"rw-rw-rw-"* ]]; then
        emit "  !! MODE 0666  $name   -> $line"
        F_WORLD_SOCKETS+=("/dev/socket/$name  ($mode)")
    elif [[ "$mode" =~ ^s.{6}rw ]] || [[ "$mode" =~ ^s.{7}w ]]; then
        emit "  !  other-writable  $name  -> $line"
        F_WORLD_SOCKETS+=("/dev/socket/$name  ($mode)")
    fi
done < <(adbsh "ls -l /dev/socket 2>/dev/null" | tail -n +2)

emit ""
emit "-- filesystem-named sockets in /proc/net/unix (paths, not @names) --"
adbsh "cat /proc/net/unix" > "$OUT/proc-net-unix.txt"
grep -E "/" "$OUT/proc-net-unix.txt" | grep -v " @" | tail -n +1 | head -80 \
    | tee -a "$COMBINED"

emit ""
emit "-- sockets inside the app's own data directory (the SAFE design) --"
rootsh "find /data/data/$PKG -type s -exec ls -lZ {} \; 2>/dev/null" | tee -a "$COMBINED"
emit "  A socket inside /data/data/<pkg>/ with the default 0700 directory mode"
emit "  is genuinely private: no other app can traverse the directory. That is"
emit "  a correct design, and worth saying so in a report."

# ------------------------------------- 5. UNIX SOCKETS (ABSTRACT NAMESPACE) --

section "UNIX-ABS" "ABSTRACT-namespace sockets — NO permissions exist at all"

emit "An abstract-namespace AF_UNIX socket is named by a string in a"
emit "kernel-global namespace, not by a filesystem path. It has NO inode, NO"
emit "owner, NO group and NO mode bits. There is not even a permission to get"
emit "wrong. Any process in the same network namespace — on Android, every app"
emit "on the device — can connect() if it knows or guesses the name, subject"
emit "only to SELinux."
emit ""
emit "android.net.LocalServerSocket(\"name\") uses this namespace BY DEFAULT."
emit "The easiest thing an Android developer can write is also the most exposed."
emit ""

if [[ $ALL_SOCKETS -eq 1 ]]; then
    ABS="$(grep " @" "$OUT/proc-net-unix.txt")"
    emit "-- ALL abstract sockets on the device (--all-sockets) --"
else
    ABS="$(grep " @" "$OUT/proc-net-unix.txt")"
    emit "-- all abstract sockets (filter by hand; the owner is not in this file) --"
fi

if [[ -z "$ABS" ]]; then
    emit "  (none found — unusual; confirm /proc/net/unix was readable)"
else
    printf '%s\n' "$ABS" | tee -a "$COMBINED"
    while read -r line; do
        [[ -z "$line" ]] && continue
        name="$(echo "$line" | awk '{print $NF}')"
        inode="$(echo "$line" | awk '{print $(NF-1)}')"
        F_ABSTRACT+=("$name (inode $inode)")
    done < <(printf '%s\n' "$ABS")
fi

emit ""
emit "-- attributing an abstract socket to a process --"
emit "   /proc/net/unix does NOT name the owner. Map the INODE to a process by"
emit "   walking /proc/<pid>/fd, which needs root:"
if [[ -n "$PID" ]]; then
    rootsh "ls -l /proc/$PID/fd 2>/dev/null | grep socket" | tee -a "$COMBINED"
    emit "   (the socket:[NNNN] numbers above are inodes; match them against the"
    emit "    inode column of /proc/net/unix)"
else
    emit "   (app not running — cannot attribute)"
fi

emit ""
emit "-- names worth probing even if they are not listed --"
emit "   chrome_devtools_remote          <- WebView inspector; full CDP access"
emit "   webview_devtools_remote_$PKG"
emit "   ${PKG}, ${PKG}.ipc, ${PKG}_ipc, ${PKG}.bridge"
emit "   Probe them with ../scripts/abstract-socket-probe.py"

# ------------------------------------------------------- 6. TCP LISTENERS ----

section "TCP" "localhost and all-interface listeners"

emit "A listening socket on 127.0.0.1 is reachable by any app holding INTERNET."
emit "INTERNET is protectionLevel=normal: granted silently at install, never"
emit "shown to the user, held by essentially every app. \"Only localhost\""
emit "therefore means \"every app on the device\"."
emit ""
emit "A socket bound to 0.0.0.0 is additionally reachable from the local"
emit "network. new ServerSocket(port) and NanoHTTPD(port) both do that BY"
emit "DEFAULT, which is why the second mistake so often hides inside the first."
emit ""

adbsh "cat /proc/net/tcp"  > "$OUT/proc-net-tcp.txt"
adbsh "cat /proc/net/tcp6" >> "$OUT/proc-net-tcp.txt"
adbsh "cat /proc/net/udp"  > "$OUT/proc-net-udp.txt"

emit "-- decoded listeners (st=0A is TCP_LISTEN) --"
emit ""
printf '%-24s %-10s %-8s %s\n' "LOCAL ADDRESS" "UID" "INODE" "NOTE" | tee -a "$COMBINED"

DECODED="$(awk '
    function hex2dec(h,  i,c,v,n) {
        n = 0
        h = toupper(h)
        for (i = 1; i <= length(h); i++) {
            c = substr(h, i, 1)
            v = index("0123456789ABCDEF", c) - 1
            n = n * 16 + v
        }
        return n
    }
    NR > 1 && $4 == "0A" {
        split($2, a, ":")
        ip = a[1]; port = hex2dec(a[2])
        if (length(ip) == 8) {
            # IPv4, little-endian hex: 0100007F -> 127.0.0.1
            o1 = hex2dec(substr(ip,7,2)); o2 = hex2dec(substr(ip,5,2))
            o3 = hex2dec(substr(ip,3,2)); o4 = hex2dec(substr(ip,1,2))
            addr = o1 "." o2 "." o3 "." o4
        } else {
            addr = (ip ~ /^0+1?$/ || ip == "00000000000000000000000000000000") \
                   ? "[::]" : "[v6:" substr(ip,1,8) "...]"
        }
        note = ""
        if (addr == "0.0.0.0" || addr == "[::]") note = "!! ALL INTERFACES — reachable from the local network"
        else if (addr == "127.0.0.1" || addr == "[::1]") note = "!  loopback — reachable by any app with INTERNET"
        printf "%-24s %-10s %-8s %s\n", addr ":" port, $8, $10, note
    }
' "$OUT/proc-net-tcp.txt")"

if [[ -z "$DECODED" ]]; then
    emit "  (no listening TCP sockets found)"
else
    printf '%s\n' "$DECODED" | tee -a "$COMBINED"
fi

emit ""
emit "-- owner resolution (uid -> package) --"
for u in $(printf '%s\n' "$DECODED" | awk '{print $2}' | sort -u | grep -E '^[0-9]+$'); do
    pkgs="$(adbsh "cmd package list packages --uid $u" | sed 's/package://' | tr '\n' ' ')"
    emit "  uid $u  ->  ${pkgs:-<system or unassigned>}"
    if [[ "$pkgs" == *"$PKG"* ]]; then
        emit "      ^^ THIS IS THE TARGET"
    fi
done

while read -r l; do
    [[ -z "$l" ]] && continue
    case "$l" in
        *"ALL INTERFACES"*) F_ANY_IFACE+=("$(echo "$l" | awk '{print $1}') uid=$(echo "$l" | awk '{print $2}')") ;;
        *"loopback"*)       F_LISTENERS+=("$(echo "$l" | awk '{print $1}') uid=$(echo "$l" | awk '{print $2}')") ;;
    esac
done < <(printf '%s\n' "$DECODED")

emit ""
emit "-- netstat view (process attribution, when the build provides it) --"
adbsh "netstat -tulpn 2>/dev/null" | head -40 | tee -a "$COMBINED"

# ------------------------------------------------------------- 7. FDS --------

section "FDS" "what the process actually has open"

if [[ -n "$PID" ]]; then
    rootsh "ls -l /proc/$PID/fd 2>/dev/null" > "$OUT/fds.txt"
    [[ ! -s "$OUT/fds.txt" ]] && adbsh "ls -l /proc/$PID/fd 2>/dev/null" > "$OUT/fds.txt"
    if [[ -s "$OUT/fds.txt" ]]; then
        emit "-- sockets --";  grep -i "socket"  "$OUT/fds.txt" | tee -a "$COMBINED"
        emit "-- pipes --";    grep -i "pipe"    "$OUT/fds.txt" | tee -a "$COMBINED"
        emit "-- binder --";   grep -iE "binder|hwbinder|vndbinder" "$OUT/fds.txt" | tee -a "$COMBINED"
        emit "-- ashmem/memfd/dmabuf --"
        grep -iE "ashmem|memfd|dmabuf" "$OUT/fds.txt" | tee -a "$COMBINED"
        emit "-- databases and regular files --"
        grep -iE "\.db|\.xml|/data/" "$OUT/fds.txt" | head -40 | tee -a "$COMBINED"
    else
        emit "  (cannot read /proc/$PID/fd — needs root on modern releases)"
    fi
else
    emit "  (app not running)"
fi

# ------------------------------------------------------------- 8. SHM --------

section "SHM" "shared memory mappings"

emit "Shared memory is referenced by a file descriptor and shared over Binder."
emit "Whoever holds the fd has whatever access its mode allows, and because"
emit "both sides see the same bytes at the same instant, a validity check on"
emit "the contents is NOT durable: the peer can change them between your check"
emit "and your use. That TOCTOU is the archetypal shared-memory bug."
emit ""
if [[ -n "$PID" ]]; then
    rootsh "grep -E 'ashmem|memfd|dmabuf|jit-code-cache' /proc/$PID/maps 2>/dev/null" \
        | head -40 | tee -a "$COMBINED"
else
    emit "  (app not running)"
fi

# ------------------------------------------------------------ 9. FILES -------

section "FILES" "data-directory modes and SELinux labels"

emit "-- the data directory itself --"
rootsh "ls -ldZ /data/data/$PKG" | tee -a "$COMBINED"
emit "   0700 (drwx------) is the modern default and is correct."
emit "   0711 or 0755 lets other apps TRAVERSE, which re-enables a"
emit "   world-readable file inside."
emit ""
emit "-- world-readable or world-writable files in the sandbox --"
WR="$(rootsh "find /data/data/$PKG -type f \( -perm -o+r -o -perm -o+w \) 2>/dev/null" | head -40)"
if [[ -n "$WR" ]]; then
    printf '%s\n' "$WR" | tee -a "$COMBINED"
    emit "   !! Any file listed here is readable by other apps IF they can"
    emit "      traverse the directories above it. Check the directory mode too."
else
    emit "   (none, or root unavailable)"
fi
emit ""
emit "-- shared_prefs --"
rootsh "ls -laZ /data/data/$PKG/shared_prefs 2>/dev/null" | tee -a "$COMBINED"

# --------------------------------------------------------- FINDINGS ----------

section "FINDINGS" "the three categories that manifest tools cannot see"

emit ""
emit "########################################################################"
emit "#  1. WORLD-ACCESSIBLE FILESYSTEM SOCKETS (mode 0666 and friends)"
emit "########################################################################"
if [[ ${#F_WORLD_SOCKETS[@]} -eq 0 ]]; then
    emit "  none found"
else
    for s in "${F_WORLD_SOCKETS[@]}"; do emit "  !! $s"; done
    emit ""
    emit "  A socket whose mode is 0666 can be connected to by every process"
    emit "  whose SELinux domain permits it. The mode bits are the ONLY DAC"
    emit "  control on a filesystem-named socket, and 0666 removes it."
    emit "  Severity depends entirely on the protocol behind it: connect and"
    emit "  find out before assigning one."
fi

emit ""
emit "########################################################################"
emit "#  2. ABSTRACT-NAMESPACE SOCKETS (no permissions exist for these AT ALL)"
emit "########################################################################"
if [[ ${#F_ABSTRACT[@]} -eq 0 ]]; then
    emit "  none found"
else
    for s in "${F_ABSTRACT[@]}"; do emit "  !! $s"; done
    emit ""
    emit "  There is no mode bit to inspect here, because there is no file."
    emit "  Every one of these is reachable by every app on the device that"
    emit "  knows the name, subject only to SELinux. Attribute each to a"
    emit "  process via /proc/<pid>/fd, then speak to it with"
    emit "  abstract-socket-probe.py, then judge severity from what the"
    emit "  protocol allows."
fi

emit ""
emit "########################################################################"
emit "#  3. LOCALHOST AND ALL-INTERFACE LISTENERS"
emit "########################################################################"
if [[ ${#F_ANY_IFACE[@]} -gt 0 ]]; then
    for s in "${F_ANY_IFACE[@]}"; do
        emit "  !!! $s   BOUND TO ALL INTERFACES — also reachable from WiFi"
    done
fi
if [[ ${#F_LISTENERS[@]} -gt 0 ]]; then
    for s in "${F_LISTENERS[@]}"; do
        emit "  !!  $s   loopback — reachable by any app holding INTERNET"
    done
fi
if [[ ${#F_ANY_IFACE[@]} -eq 0 && ${#F_LISTENERS[@]} -eq 0 ]]; then
    emit "  none found"
else
    emit ""
    emit "  Next steps for each:"
    emit "    curl -s http://127.0.0.1:<port>/            # is it HTTP?"
    emit "    curl -s http://<device-ip>:<port>/          # network-reachable?"
    emit "    check Host / Origin header handling         # DNS rebinding"
    emit "  A browser-reachable localhost service is exploitable from a plain"
    emit "  web page with no malicious app involved at all."
fi

emit ""
emit "########################################################################"
emit "#  REACHABILITY DISCIPLINE — read before writing any of this up"
emit "########################################################################"
emit ""
emit "  Every line above came from adb shell: UID 2000, SELinux domain shell."
emit "  That identity holds privileges no installed application has."
emit ""
emit "  This script proves a channel EXISTS."
emit "  It does NOT prove an unprivileged app can USE it."
emit ""
emit "  Before any finding leaves your machine, reproduce it from an ordinary"
emit "  application UID:"
emit "      cd ../examples/attacker-app && gradle assembleDebug"
emit "      adb install -r build/outputs/apk/debug/attacker-app-debug.apk"
emit "      adb shell am start -n com.attacker.poc/.ProbeActivity --es target $PKG"
emit "      adb logcat -s poc:I"
emit ""
emit "  Then record BOTH results side by side. A channel reachable from shell"
emit "  but not from an app is a shell privilege, not an app vulnerability,"
emit "  and saying so is what makes your other findings believable."

# ------------------------------------------------------------- wrap up -------

emit ""
emit "### END"
emit ""
echo "artifacts written to: $OUT/"
echo "  combined      : $COMBINED"
echo "  next step     : python3 ipc-surface-report.py $COMBINED --md $OUT/report.md"
