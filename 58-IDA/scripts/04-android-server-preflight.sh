#!/usr/bin/env bash
# scripts/04-android-server-preflight.sh
#
# PURPOSE
#   Establish, BEFORE you start fighting IDA's remote debugger, whether the
#   device can host it at all -- and then deploy it if it can.
#
#   IDA's Android debugging works by pushing a small server binary to the
#   device, running it, forwarding a TCP port over adb, and connecting IDA to
#   the forwarded port. Every step of that has a device-side precondition, and
#   when one is unmet the failure surfaces as a generic "could not connect" or
#   a hang. This script checks each precondition separately and names the one
#   that failed, which turns an afternoon into five minutes.
#
#   It has two modes:
#     preflight   (default)  read-only checks. Writes nothing to the device.
#     deploy                 push and launch the server. Requires --server.
#
# USAGE
#   # host -- just tell me whether this will work
#   ./04-android-server-preflight.sh
#
#   # host -- a specific device, when several are attached
#   ./04-android-server-preflight.sh -s emulator-5554
#
#   # host -- push and start the server (needs a real IDA installation)
#   ./04-android-server-preflight.sh deploy \
#       --server "/opt/idapro-9.0/dbgsrv/android_server" --port 23946
#
#   # host -- tidy up afterwards
#   ./04-android-server-preflight.sh clean
#
#   Then in IDA:  Debugger > Attach > Remote ARM Linux/Android debugger
#                 Hostname 127.0.0.1, Port 23946
#
# WHICH SERVER BINARY
#   IDA ships these under <IDA>/dbgsrv/ (names verified against Hex-Rays'
#   remote-debugging documentation):
#
#     android_server        AArch64  -- arm64-v8a, the normal Android case
#     android_server32      ARM      -- armeabi-v7a
#     android_x64_server    x86-64   -- x86_64 emulator images
#     android_x86_server    x86      -- x86 emulator images
#
#   Pick by the ABI the TARGET PROCESS runs as, not by what the device
#   advertises. An x86_64 emulator with native-bridge translation will happily
#   run an arm64 app, and the debugger must match the app.
#
# EXECUTION STATUS
#   PARTIALLY EXECUTED.
#     * Every check in `preflight` WAS executed, against an
#       `sdk_gphone16k_x86_64` AVD running Android 15 / API 35. The measured
#       results are quoted in the README's section 7, including one that
#       contradicts most published guides -- see the ptrace_scope check.
#     * `deploy` was NOT executed. It needs an `android_server` binary, which
#       ships only with an IDA licence, and IDA is not installed on the machine
#       where this chapter was written. The command line follows Hex-Rays'
#       documented options; it has never been run here.
#
# WHAT THIS WILL NOT DO
#   * It will not disable SELinux, and it will not tell you to. `setenforce 0`
#     on a device you are testing changes the thing you are testing.
#   * It will not touch anything under /data/local/tmp that it did not create.
#     Other work lives there.
#   * It will not attach to a process. That is IDA's job and yours.
#
# AUTHORISED TESTING ONLY. Debugging another party's application may be
# prohibited by contract or by law regardless of your intent.

set -u

MODE="preflight"
SERIAL=""
SERVER=""
PORT="${PORT:-23946}"
DEVDIR="/data/local/tmp/ch58ida"        # OURS. Nothing else in tmp is touched.

while [ $# -gt 0 ]; do
    case "$1" in
        preflight|deploy|clean) MODE="$1"; shift ;;
        -s|--serial) SERIAL="${2:-}"; shift 2 ;;
        --server)    SERVER="${2:-}"; shift 2 ;;
        --port)      PORT="${2:-}"; shift 2 ;;
        -h|--help)   sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

ADB="adb"
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

# Git Bash rewrites any argument that looks like a Unix path into a Windows
# path before adb sees it, so `/system/lib64/x` becomes `C:/Program
# Files/Git/system/lib64/x` and adb reports the remote file missing. Chapter 68
# documented this. MSYS_NO_PATHCONV=1 fixes the REMOTE path -- and breaks the
# LOCAL one, because adb.exe wants a Windows path for that. So scope it to the
# remote argument only, and convert local paths explicitly.
sh_() { MSYS_NO_PATHCONV=1 $ADB shell "$@"; }
win_() { command -v cygpath >/dev/null 2>&1 && cygpath -w "$1" || echo "$1"; }

ok()   { printf '  [ ok ] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; FAILED=$((FAILED+1)); }
warn() { printf '  [warn] %s\n' "$*"; }
note() { printf '         %s\n' "$*"; }

FAILED=0

# --------------------------------------------------------------------------- #
preflight() {
    echo "=================================================================="
    echo " IDA android_server preflight"
    echo "=================================================================="
    echo

    echo "1. device"
    devs=$($ADB devices | awk 'NR>1 && $2=="device"{print $1}')
    n=$(echo "$devs" | grep -c . || true)
    if [ "$n" = "0" ]; then
        bad "no device in 'adb devices' state 'device'"
        return
    fi
    if [ "$n" != "1" ] && [ -z "$SERIAL" ]; then
        bad "$n devices attached and no -s given. Every command below would go"
        note "to an arbitrary one. Chapter 68 measured a whole session"
        note "silently targeting the wrong device; name it explicitly."
        return
    fi
    model=$(sh_ getprop ro.product.model | tr -d '\r')
    sdk=$(sh_ getprop ro.build.version.sdk | tr -d '\r')
    rel=$(sh_ getprop ro.build.version.release | tr -d '\r')
    abis=$(sh_ getprop ro.product.cpu.abilist | tr -d '\r')
    ok "$model  Android $rel / API $sdk"
    note "ABI list: $abis"
    case "$abis" in
        *arm64-v8a*x86_64*|*x86_64*arm64-v8a*)
            warn "this device advertises BOTH x86_64 and arm64-v8a."
            note "It has a native bridge (libndk_translation.so on AVDs). An"
            note "app may run as either. Choose the server binary by what the"
            note "TARGET PROCESS is, read from /proc/<pid>/maps, not by this list."
            ;;
    esac
    echo

    echo "2. root"
    id=$(sh_ 'su 0 id' 2>/dev/null | tr -d '\r')
    case "$id" in
        *uid=0*) ok "root via 'su 0': $id" ;;
        *)
            id2=$(sh_ 'su -c id' 2>/dev/null | tr -d '\r')
            case "$id2" in
                *uid=0*) ok "root via 'su -c': $id2" ;;
                *)
                    bad "no root."
                    note "IDA's android_server can still debug a DEBUGGABLE app"
                    note "through run-as, but it cannot attach to an arbitrary"
                    note "process. Most real targets are not debuggable."
                    ;;
            esac
            ;;
    esac
    note "note: AVDs take 'su 0 <cmd>'. AOSP's su rejects the -c form with"
    note "  su: invalid uid/gid '-c'"
    note "which reads as 'not rooted' even though 'su 0 id' returns uid=0 on"
    note "the same device seconds later. Magisk's su on a physical device"
    note "accepts -c, so neither form is universal -- try both."
    echo

    echo "3. ptrace"
    scope=$(sh_ 'cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null' | tr -d '\r')
    if [ -z "$scope" ]; then
        ok "no /proc/sys/kernel/yama/ptrace_scope on this device"
        note "MEASURED on an API 35 AVD: the file is ABSENT. Many published"
        note "Android debugging guides tell you to write 0 to it. On a device"
        note "with no Yama LSM there is nothing to write and the advice is"
        note "noise -- if attachment fails here, ptrace_scope is not why."
    elif [ "$scope" = "0" ]; then
        ok "ptrace_scope = 0 (unrestricted)"
    else
        warn "ptrace_scope = $scope"
        note "1 = only a parent may attach; 2 = admin only; 3 = nobody."
        note "Root can still attach at 1 and 2. Do not lower it globally on a"
        note "device whose behaviour you are measuring."
    fi
    echo

    echo "4. SELinux"
    enf=$(sh_ getenforce | tr -d '\r')
    if [ "$enf" = "Enforcing" ]; then
        warn "SELinux is Enforcing"
        note "This is the normal, correct state and you should leave it alone."
        note "A server launched from the 'su' domain usually has the ptrace"
        note "permissions it needs. If an attach is refused with no useful"
        note "error, look for an AVC:"
        note "    adb shell 'su 0 dmesg -T' | grep -i avc | tail"
        note "DO NOT run setenforce 0 to make a test pass. Chapter 22 owns why:"
        note "you would be measuring a device that no longer resembles the one"
        note "your finding is about."
    else
        warn "SELinux is $enf -- this device is NOT in its shipping state."
        note "Anything you measure about access control here is about this"
        note "device, not about Android."
    fi
    echo

    echo "5. a writable, executable directory"
    if sh_ "mkdir -p $DEVDIR && echo ok" 2>/dev/null | grep -q ok; then
        ok "$DEVDIR is writable"
    else
        bad "cannot create $DEVDIR"
    fi
    # Some vendor builds mount /data/local/tmp noexec, or block execve there by
    # policy. Chapters 22 and 68 both hit this on a retail Redmi. The workaround
    # is to invoke through the linker: /system/bin/linker64 <path> <args>.
    sh_ "printf '#!/system/bin/sh\necho execok\n' > $DEVDIR/t.sh; chmod 755 $DEVDIR/t.sh" >/dev/null 2>&1
    if sh_ "$DEVDIR/t.sh" 2>/dev/null | grep -q execok; then
        ok "execution from $DEVDIR works"
    else
        warn "cannot execute from $DEVDIR"
        note "Some vendor builds block execve() under /data/local/tmp. Run the"
        note "server through the linker instead:"
        note "    su 0 /system/bin/linker64 $DEVDIR/android_server -p$PORT"
    fi
    sh_ "rm -f $DEVDIR/t.sh" >/dev/null 2>&1
    echo

    echo "6. the port"
    if $ADB forward "tcp:$PORT" "tcp:$PORT" >/dev/null 2>&1; then
        ok "adb forward tcp:$PORT -> tcp:$PORT established"
        $ADB forward --list | sed 's/^/         /'
        $ADB forward --remove "tcp:$PORT" >/dev/null 2>&1
        note "removed again; deploy will re-establish it"
    else
        bad "adb forward failed on port $PORT"
        note "Another process may hold it. Pick another with --port."
    fi
    note "23946 is IDA's default remote-debugger port."
    echo

    echo "7. what is already there"
    note "listing /data/local/tmp so you do not collide with somebody else's"
    note "work -- and so you can see what a previous session left behind:"
    sh_ "ls -1 /data/local/tmp" 2>/dev/null | sed 's/^/         /'
    echo

    echo "=================================================================="
    if [ "$FAILED" = "0" ]; then
        echo " preflight passed. Deploy with:"
        echo "   $0 deploy --server <IDA>/dbgsrv/android_server --port $PORT"
    else
        echo " $FAILED check(s) failed. Fix those before touching IDA --"
        echo " the debugger's error messages will not tell you which one."
    fi
    echo "=================================================================="
}

# --------------------------------------------------------------------------- #
deploy() {
    [ -n "$SERVER" ] || { echo "error: --server <path to android_server> required" >&2; exit 2; }
    [ -f "$SERVER" ] || { echo "error: $SERVER not found" >&2; exit 2; }

    echo "pushing $(basename "$SERVER") to $DEVDIR ..."
    sh_ "mkdir -p $DEVDIR"
    $ADB push "$(win_ "$SERVER")" "$DEVDIR/android_server" || exit 1
    sh_ "chmod 755 $DEVDIR/android_server"

    # Options, from Hex-Rays' remote-debugging documentation:
    #   -p<port>   listen on this port          (default 23946)
    #   -P<pass>   require a password
    #   -v         verbose
    #   -t         plain, unencrypted TCP
    #   -i<addr>   bind address (default: any)
    #
    # Bind to loopback and forward over adb rather than listening on the
    # network. A debugger server bound to 0.0.0.0 on a phone is a remote code
    # execution service on whatever Wi-Fi the phone is on, with your session
    # attached to it. That is not a hypothetical: it is what the flag does.
    echo "starting on 127.0.0.1:$PORT (loopback only) ..."
    sh_ "su 0 sh -c 'cd $DEVDIR && nohup ./android_server -i127.0.0.1 -p$PORT >$DEVDIR/server.log 2>&1 &'"
    sleep 1
    sh_ "cat $DEVDIR/server.log" 2>/dev/null | sed 's/^/  /'

    $ADB forward "tcp:$PORT" "tcp:$PORT" >/dev/null 2>&1 \
        && echo "forwarded localhost:$PORT -> device:$PORT"

    cat <<EOF

Now, in IDA:
  Debugger > Attach > Remote ARM Linux/Android debugger
    Hostname   127.0.0.1
    Port       $PORT
  ...then pick the process. If the list is empty, the server is not running as
  root; check $DEVDIR/server.log.

BEFORE you attach, know what attaching costs you:
  * /proc/<pid>/status TracerPid becomes non-zero and any app that reads it
    knows. See chapter 38.
  * A second ptrace attach will fail: one tracer per process. If frida-server
    is already attached, detach it first.
  * The app may not crash. It may take a different branch. That is worse.

Clean up with:  $0 clean
EOF
}

# --------------------------------------------------------------------------- #
clean() {
    echo "stopping any android_server and removing ONLY $DEVDIR ..."
    sh_ "su 0 pkill -f android_server" >/dev/null 2>&1
    sh_ "rm -rf $DEVDIR"
    $ADB forward --remove "tcp:$PORT" >/dev/null 2>&1
    echo "done. Nothing outside $DEVDIR was touched."
    sh_ "ls -1 /data/local/tmp" 2>/dev/null | sed 's/^/  remaining: /'
}

case "$MODE" in
    preflight) preflight ;;
    deploy)    deploy ;;
    clean)     clean ;;
esac
