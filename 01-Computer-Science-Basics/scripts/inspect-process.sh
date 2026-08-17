#!/bin/sh
# =============================================================================
# inspect-process.sh -- a readable report on one live process, from /proc
# Chapter 01 -- Computer Science Basics
# =============================================================================
#
# WHAT IT DOES
#   Takes a PID (or a process name it resolves to a PID) and prints a single
#   structured report assembled entirely from the /proc pseudo-filesystem:
#
#     1. IDENTITY   cmdline, exe, cwd, and the important /proc/<pid>/status
#                   fields: State, PPid, TracerPid, Uid/Gid, Threads, Seccomp.
#     2. MEMORY     VmSize / VmRSS / VmSwap, plus total PSS from smaps when it
#                   is readable.
#     3. MAPS       /proc/<pid>/maps summarised two ways -- a count and total
#                   size per permission string, and a count and total size per
#                   region KIND (main stack, thread stacks, native heap, ART
#                   heap, shared-library code, shared-library data, mapped APK
#                   and DEX artefacts, device mappings, guard pages, and plain
#                   anonymous memory). Every writable+executable region is
#                   listed individually, because those are the interesting ones.
#     4. FDS        Open file descriptors, counted by category and then listed.
#     5. ENV        Size of the environment block and the number of variables.
#
#   Nothing is modified. The script only reads.
#
# HOW TO RUN
#
#   On Linux or WSL:
#       sh inspect-process.sh 12345
#       sh inspect-process.sh firefox
#       sh inspect-process.sh $$                 # the shell you are typing in
#
#   On an Android device over adb:
#       adb push inspect-process.sh /data/local/tmp/
#       adb shell sh /data/local/tmp/inspect-process.sh com.example.target
#
#   As the app itself on a non-rooted device, for a debuggable build:
#       adb shell run-as com.example.target sh /data/local/tmp/inspect-process.sh \
#           com.example.target
#
#   Options:
#       -h, --help        this help
#       -q, --quiet-maps  skip the per-region maps walk (much faster on an app
#                         with several thousand mappings)
#       -n N              list at most N file descriptors (default 40)
#
#   Testing without a real process:
#       PROC_ROOT=/path/to/fake/proc sh inspect-process.sh 999
#
# REQUIREMENTS
#   A POSIX shell. Nothing else is required: no awk, no bash, no perl, no
#   python. It is written this way on purpose, because Android's shell is mksh
#   with toybox and older devices may not have awk at all. `tr` and `wc` are
#   used when present and skipped when not.
#
#   Permissions: /proc/<pid>/maps, /proc/<pid>/fd, /proc/<pid>/smaps and
#   /proc/<pid>/environ are readable only by the process's own UID or by root.
#   Every read here is guarded, so an unprivileged run produces a partial
#   report rather than a pile of errors.
#
# PERFORMANCE NOTE
#   The maps walk is a pure-shell loop. A desktop process with 200 mappings is
#   instant; a real Android app with 4000 mappings takes a few seconds on
#   device. Use -q when you only want identity and descriptors.
#
# SEE ALSO
#   ../labs/lab-02-processes-memory-maps.md  -- do all of this by hand first
#   ../../19-Memory/README.md                -- what the regions actually contain
#   ../../53-Frida/README.md                 -- why rwx regions matter
# =============================================================================

PROC="${PROC_ROOT:-/proc}"
FD_LIMIT=40
SKIP_MAPS=0
TARGET=""

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------

rule() {
    echo "=============================================================================="
}

thin() {
    echo "------------------------------------------------------------------------------"
}

section() {
    echo ""
    rule
    echo " $1"
    rule
}

kv() {
    # kv <label> <value>
    printf '  %-22s %s\n' "$1" "$2"
}

warn() {
    printf '  !! %s\n' "$1"
}

usage() {
    echo "usage: sh inspect-process.sh [-q] [-n COUNT] <pid | process-name>"
    echo ""
    echo "  -q, --quiet-maps   skip the per-region maps walk"
    echo "  -n COUNT           list at most COUNT file descriptors (default 40)"
    echo "  -h, --help         this help"
    echo ""
    echo "  PROC_ROOT=<dir>    read from <dir> instead of /proc (for testing)"
    exit "${1:-0}"
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)       usage 0 ;;
        -q|--quiet-maps) SKIP_MAPS=1 ;;
        -n)              shift; FD_LIMIT="$1" ;;
        -*)              echo "unknown option: $1"; usage 1 ;;
        *)               TARGET="$1" ;;
    esac
    shift
done

[ -n "$TARGET" ] || usage 1

# -----------------------------------------------------------------------------
# Resolve the target to a PID.
#
# Three strategies, in order of reliability:
#   1. It is already all digits -> use it.
#   2. `pidof` exists -> ask it (present in toybox on Android and in most
#      Linux distributions).
#   3. Fall back to scanning /proc/*/cmdline ourselves, which always works.
# -----------------------------------------------------------------------------

resolve_pid() {
    _rp_want="$1"

    case "$_rp_want" in
        ''|*[!0-9]*) ;;                 # not purely digits, keep going
        *) echo "$_rp_want"; return 0 ;;
    esac

    if command -v pidof >/dev/null 2>&1; then
        _rp_got=$(pidof "$_rp_want" 2>/dev/null)
        if [ -n "$_rp_got" ]; then
            # pidof may return several; take the first.
            for _rp_p in $_rp_got; do echo "$_rp_p"; return 0; done
        fi
    fi

    # Manual scan. cmdline is NUL-separated, so a plain grep does not work
    # reliably; compare the first argument only.
    for _rp_dir in "$PROC"/[0-9]*; do
        [ -d "$_rp_dir" ] || continue
        [ -r "$_rp_dir/cmdline" ] || continue
        _rp_cmd=$(tr '\0' '\n' < "$_rp_dir/cmdline" 2>/dev/null | head -n 1)
        [ -n "$_rp_cmd" ] || continue
        case "$_rp_cmd" in
            "$_rp_want"|*/"$_rp_want")
                echo "${_rp_dir##*/}"
                return 0
                ;;
        esac
    done

    return 1
}

PID=$(resolve_pid "$TARGET")

if [ -z "$PID" ]; then
    echo "could not resolve '$TARGET' to a running process."
    echo "try: ps -A | grep $TARGET"
    exit 1
fi

D="$PROC/$PID"

if [ ! -d "$D" ]; then
    echo "no such process: $PID (looked in $D)"
    exit 1
fi

# -----------------------------------------------------------------------------
# 1. IDENTITY
# -----------------------------------------------------------------------------

rule
echo " process report for pid $PID   (source: $D)"
rule

section "1. IDENTITY"

if [ -r "$D/cmdline" ]; then
    if command -v tr >/dev/null 2>&1; then
        CMDLINE=$(tr '\0' ' ' < "$D/cmdline" 2>/dev/null)
    else
        CMDLINE=$(cat "$D/cmdline" 2>/dev/null)
    fi
    [ -n "$CMDLINE" ] || CMDLINE="(empty -- this is a kernel thread)"
    kv "cmdline" "$CMDLINE"
else
    warn "cmdline unreadable"
fi

if [ -r "$D/comm" ]; then
    kv "comm" "$(cat "$D/comm" 2>/dev/null)"
fi

if [ -L "$D/exe" ]; then
    EXE=$(readlink "$D/exe" 2>/dev/null)
    kv "exe" "${EXE:-(unreadable -- needs the owning UID or root)}"
fi

if [ -L "$D/cwd" ]; then
    CWD=$(readlink "$D/cwd" 2>/dev/null)
    kv "cwd" "${CWD:-(unreadable)}"
fi

if [ -r "$D/status" ]; then
    echo ""
    echo "  from $D/status:"
    while IFS= read -r line; do
        case "$line" in
            Name:*|State:*|Tgid:*|Ngid:*|Pid:*|PPid:*|TracerPid:*|\
Uid:*|Gid:*|FDSize:*|Groups:*|Threads:*|Seccomp:*|SigBlk:*|SigIgn:*|SigCgt:*|\
NoNewPrivs:*|CapEff:*)
                printf '    %s\n' "$line"
                ;;
        esac
    done < "$D/status"

    # TracerPid deserves an explicit call-out: it is the single most-checked
    # anti-debugging field on Android.
    TRACER=$(while IFS= read -r l; do
                 case "$l" in TracerPid:*) echo "${l#TracerPid:}"; break ;; esac
             done < "$D/status")
    TRACER=$(echo "$TRACER")            # trim surrounding whitespace
    if [ -n "$TRACER" ] && [ "$TRACER" != "0" ]; then
        echo ""
        warn "TracerPid is $TRACER -- something is ptrace-attached to this process."
        warn "That is a debugger, a Frida gadget, or an anti-debug self-attach."
    fi
else
    warn "status unreadable -- you are not this process's UID and not root"
fi

if [ -d "$D/task" ]; then
    THREADS=0
    for t in "$D"/task/[0-9]*; do
        [ -d "$t" ] && THREADS=$((THREADS + 1))
    done
    echo ""
    kv "threads (from task/)" "$THREADS"
    echo "  thread names:"
    COUNT=0
    for t in "$D"/task/[0-9]*; do
        [ -r "$t/comm" ] || continue
        COUNT=$((COUNT + 1))
        [ "$COUNT" -gt 12 ] && continue
        printf '    tid %-8s %s\n' "${t##*/}" "$(cat "$t/comm" 2>/dev/null)"
    done
    [ "$COUNT" -gt 12 ] && echo "    ... and $((COUNT - 12)) more"
fi

# -----------------------------------------------------------------------------
# 2. MEMORY TOTALS
# -----------------------------------------------------------------------------

section "2. MEMORY TOTALS"

if [ -r "$D/status" ]; then
    while IFS= read -r line; do
        case "$line" in
            VmPeak:*|VmSize:*|VmLck:*|VmHWM:*|VmRSS:*|RssAnon:*|RssFile:*|\
RssShmem:*|VmData:*|VmStk:*|VmExe:*|VmLib:*|VmSwap:*)
                printf '    %s\n' "$line"
                ;;
        esac
    done < "$D/status"
else
    warn "status unreadable"
fi

echo ""
echo "    VmSize is address space RESERVED; VmRSS is physical memory actually"
echo "    resident. VmRSS counts every shared page in full, so it overstates"
echo "    what this process really costs. PSS below divides each shared page"
echo "    among its sharers and is the honest number."

if [ -r "$D/smaps_rollup" ]; then
    echo ""
    echo "  from smaps_rollup:"
    while IFS= read -r line; do
        case "$line" in
            Rss:*|Pss:*|Private_Clean:*|Private_Dirty:*|Shared_Clean:*|\
Shared_Dirty:*|Swap:*)
                printf '    %s\n' "$line"
                ;;
        esac
    done < "$D/smaps_rollup"
elif [ -r "$D/smaps" ]; then
    PSS=0
    while IFS= read -r line; do
        case "$line" in
            Pss:*)
                v=${line#Pss:}
                v=${v% kB}
                # strip whitespace without relying on sed
                for w in $v; do v="$w"; break; done
                case "$v" in ''|*[!0-9]*) ;; *) PSS=$((PSS + v)) ;; esac
                ;;
        esac
    done < "$D/smaps"
    echo ""
    kv "total PSS" "$PSS kB (summed from smaps)"
else
    echo ""
    warn "neither smaps_rollup nor smaps is readable -- PSS unavailable"
fi

# -----------------------------------------------------------------------------
# 3. MAPS
# -----------------------------------------------------------------------------

section "3. MEMORY MAP SUMMARY"

if [ ! -r "$D/maps" ]; then
    warn "maps unreadable. On Android use one of:"
    warn "  adb root                                   (emulator / userdebug)"
    warn "  adb shell run-as <pkg> ...                 (debuggable app)"
    # The outer quotes are load-bearing: adb shell joins its arguments with
    # spaces, so `adb shell su -c 'cat FILE'` arrives as `su -c cat FILE`.
    warn "  adb shell \"su -c 'cat ...'\"                 (rooted device)"
elif [ "$SKIP_MAPS" = "1" ]; then
    TOTAL=0
    while IFS= read -r line; do TOTAL=$((TOTAL + 1)); done < "$D/maps"
    kv "total regions" "$TOTAL"
    echo "  (per-region walk skipped because -q was given)"
else
    # Permission-string tallies.
    P_RX=0;  P_RX_SZ=0        # r-xp  executable code
    P_R=0;   P_R_SZ=0         # r--p  read-only data
    P_RW=0;  P_RW_SZ=0        # rw-p  writable private
    P_RWS=0; P_RWS_SZ=0       # rw-s  writable shared
    P_NONE=0; P_NONE_SZ=0     # ---p  guard / reservation
    P_RWX=0; P_RWX_SZ=0       # rwx   writable AND executable
    P_OTHER=0; P_OTHER_SZ=0

    # Region-kind tallies.
    K_STACK=0;   K_STACK_SZ=0
    K_TSTACK=0;  K_TSTACK_SZ=0
    K_NHEAP=0;   K_NHEAP_SZ=0
    K_JHEAP=0;   K_JHEAP_SZ=0
    K_SOCODE=0;  K_SOCODE_SZ=0
    K_SODATA=0;  K_SODATA_SZ=0
    K_APP=0;     K_APP_SZ=0
    K_DEV=0;     K_DEV_SZ=0
    K_FILE=0;    K_FILE_SZ=0
    K_ANON=0;    K_ANON_SZ=0
    TOTAL=0;     TOTAL_SZ=0

    RWX_LIST=""

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        TOTAL=$((TOTAL + 1))

        range=${line%% *}
        start=${range%%-*}
        end=${range##*-}

        # Arithmetic expansion understands 0x-prefixed constants in every
        # POSIX shell we care about, including mksh on Android.
        size=$(( 0x$end - 0x$start ))
        [ "$size" -ge 0 ] 2>/dev/null || size=0
        TOTAL_SZ=$((TOTAL_SZ + size))

        # Split the line into fields. Paths containing spaces are rejoined
        # with single spaces, which is fine for a summary.
        # shellcheck disable=SC2086
        set -- $line
        perms="$2"
        path=""
        if [ $# -ge 6 ]; then
            shift 5
            path="$*"
        fi

        # ---- tally by permission ------------------------------------------
        case "$perms" in
            r-xp|r-xs) P_RX=$((P_RX+1));   P_RX_SZ=$((P_RX_SZ+size)) ;;
            r--p|r--s) P_R=$((P_R+1));     P_R_SZ=$((P_R_SZ+size)) ;;
            rw-p)      P_RW=$((P_RW+1));   P_RW_SZ=$((P_RW_SZ+size)) ;;
            rw-s)      P_RWS=$((P_RWS+1)); P_RWS_SZ=$((P_RWS_SZ+size)) ;;
            ---p|---s) P_NONE=$((P_NONE+1)); P_NONE_SZ=$((P_NONE_SZ+size)) ;;
            rwx*)
                P_RWX=$((P_RWX+1)); P_RWX_SZ=$((P_RWX_SZ+size))
                RWX_LIST="$RWX_LIST
    $range  $perms  ${path:-<anonymous>}  ($size bytes)"
                ;;
            *) P_OTHER=$((P_OTHER+1)); P_OTHER_SZ=$((P_OTHER_SZ+size)) ;;
        esac

        # ---- tally by kind -------------------------------------------------
        case "$path" in
            "[stack]")
                K_STACK=$((K_STACK+1)); K_STACK_SZ=$((K_STACK_SZ+size)) ;;
            "[anon:stack_and_tls"*|"[stack:"*)
                K_TSTACK=$((K_TSTACK+1)); K_TSTACK_SZ=$((K_TSTACK_SZ+size)) ;;
            "[heap]"|"[anon:libc_malloc"*|"[anon:scudo"*|"[anon:GWP-ASan"*)
                K_NHEAP=$((K_NHEAP+1)); K_NHEAP_SZ=$((K_NHEAP_SZ+size)) ;;
            *dalvik*|*"[anon:dalvik"*)
                K_JHEAP=$((K_JHEAP+1)); K_JHEAP_SZ=$((K_JHEAP_SZ+size)) ;;
            *.so|*.so\ \(deleted\))
                case "$perms" in
                    r-x*|rwx*) K_SOCODE=$((K_SOCODE+1)); K_SOCODE_SZ=$((K_SOCODE_SZ+size)) ;;
                    *)         K_SODATA=$((K_SODATA+1)); K_SODATA_SZ=$((K_SODATA_SZ+size)) ;;
                esac
                ;;
            *.apk|*.dex|*.odex|*.vdex|*.art|*.oat|*.jar)
                K_APP=$((K_APP+1)); K_APP_SZ=$((K_APP_SZ+size)) ;;
            /dev/*)
                K_DEV=$((K_DEV+1)); K_DEV_SZ=$((K_DEV_SZ+size)) ;;
            "")
                K_ANON=$((K_ANON+1)); K_ANON_SZ=$((K_ANON_SZ+size)) ;;
            *)
                K_FILE=$((K_FILE+1)); K_FILE_SZ=$((K_FILE_SZ+size)) ;;
        esac
    done < "$D/maps"

    kv "total regions" "$TOTAL"
    kv "total mapped bytes" "$TOTAL_SZ ($((TOTAL_SZ / 1024)) kB)"

    echo ""
    echo "  by permission:"
    printf '    %-8s %8s  %14s  %s\n' "perms" "count" "bytes" "meaning"
    thin
    printf '    %-8s %8s  %14s  %s\n' "r-xp" "$P_RX"   "$P_RX_SZ"   "executable code, not writable"
    printf '    %-8s %8s  %14s  %s\n' "r--p" "$P_R"    "$P_R_SZ"    "read-only data, rodata, mapped files"
    printf '    %-8s %8s  %14s  %s\n' "rw-p" "$P_RW"   "$P_RW_SZ"   "writable private: heap, stacks, .data"
    printf '    %-8s %8s  %14s  %s\n' "rw-s" "$P_RWS"  "$P_RWS_SZ"  "writable SHARED: ashmem, memfd, Binder"
    printf '    %-8s %8s  %14s  %s\n' "---p" "$P_NONE" "$P_NONE_SZ" "guard pages and reservations"
    printf '    %-8s %8s  %14s  %s\n' "rwx*" "$P_RWX"  "$P_RWX_SZ"  "WRITABLE AND EXECUTABLE -- see below"
    printf '    %-8s %8s  %14s  %s\n' "other" "$P_OTHER" "$P_OTHER_SZ" "anything else"

    echo ""
    echo "  by region kind:"
    printf '    %-24s %8s  %14s\n' "kind" "count" "bytes"
    thin
    printf '    %-24s %8s  %14s\n' "main stack"          "$K_STACK"  "$K_STACK_SZ"
    printf '    %-24s %8s  %14s\n' "thread stacks"       "$K_TSTACK" "$K_TSTACK_SZ"
    printf '    %-24s %8s  %14s\n' "native heap (malloc)" "$K_NHEAP" "$K_NHEAP_SZ"
    printf '    %-24s %8s  %14s\n' "ART / dalvik heap"   "$K_JHEAP"  "$K_JHEAP_SZ"
    printf '    %-24s %8s  %14s\n' ".so code"            "$K_SOCODE" "$K_SOCODE_SZ"
    printf '    %-24s %8s  %14s\n' ".so data / rodata"   "$K_SODATA" "$K_SODATA_SZ"
    printf '    %-24s %8s  %14s\n' "apk/dex/odex/vdex/art" "$K_APP"  "$K_APP_SZ"
    printf '    %-24s %8s  %14s\n' "device mappings"     "$K_DEV"    "$K_DEV_SZ"
    printf '    %-24s %8s  %14s\n' "other mapped files"  "$K_FILE"   "$K_FILE_SZ"
    printf '    %-24s %8s  %14s\n' "pure anonymous"      "$K_ANON"   "$K_ANON_SZ"

    echo ""
    if [ "$P_RWX" -gt 0 ]; then
        warn "$P_RWX writable+executable region(s) found:"
        echo "$RWX_LIST"
        echo ""
        echo "    A normal process has none. Legitimate producers of rwx memory are"
        echo "    ART's JIT code cache and some packers that decrypt code at runtime."
        echo "    The other common producer is an injected instrumentation engine:"
        echo "    Frida allocates executable memory for its trampolines. Scanning"
        echo "    /proc/self/maps for rwx is one of the cheapest and most widely"
        echo "    deployed Frida-detection checks in commercial Android apps."
        echo "    See ../../53-Frida/README.md and ../../67-BypassingProtections/README.md."
    else
        echo "  No writable+executable regions. W^X is intact in this process."
    fi
fi

# -----------------------------------------------------------------------------
# 4. FILE DESCRIPTORS
# -----------------------------------------------------------------------------

section "4. OPEN FILE DESCRIPTORS"

if [ ! -r "$D/fd" ] || [ ! -x "$D/fd" ]; then
    warn "fd/ unreadable -- needs the owning UID or root"
else
    F_SOCK=0; F_PIPE=0; F_ANON=0; F_DEV=0; F_APP=0; F_REG=0; F_OTHER=0; F_TOTAL=0
    FD_LINES=""

    for f in "$D"/fd/*; do
        [ -e "$f" ] || [ -L "$f" ] || continue
        F_TOTAL=$((F_TOTAL + 1))
        n=${f##*/}
        tgt=$(readlink "$f" 2>/dev/null)
        [ -n "$tgt" ] || tgt="<unreadable>"

        case "$tgt" in
            socket:*)      F_SOCK=$((F_SOCK+1)) ;;
            pipe:*)        F_PIPE=$((F_PIPE+1)) ;;
            anon_inode:*)  F_ANON=$((F_ANON+1)) ;;
            /dev/*)        F_DEV=$((F_DEV+1)) ;;
            /data/*)       F_APP=$((F_APP+1)) ;;
            /*)            F_REG=$((F_REG+1)) ;;
            *)             F_OTHER=$((F_OTHER+1)) ;;
        esac

        if [ "$F_TOTAL" -le "$FD_LIMIT" ]; then
            FD_LINES="$FD_LINES
    $(printf '%4s' "$n") -> $tgt"
        fi
    done

    kv "total descriptors" "$F_TOTAL"
    echo ""
    printf '    %-24s %s\n' "sockets"                  "$F_SOCK"
    printf '    %-24s %s\n' "pipes"                    "$F_PIPE"
    printf '    %-24s %s\n' "anon_inode (epoll etc.)"  "$F_ANON"
    printf '    %-24s %s\n' "/dev/* (binder, ashmem)"  "$F_DEV"
    printf '    %-24s %s\n' "/data/* (app storage)"    "$F_APP"
    printf '    %-24s %s\n' "other regular files"      "$F_REG"
    printf '    %-24s %s\n' "unclassified"             "$F_OTHER"

    echo ""
    echo "  listing (first $FD_LIMIT):"
    echo "$FD_LINES"
    if [ "$F_TOTAL" -gt "$FD_LIMIT" ]; then
        echo "    ... and $((F_TOTAL - FD_LIMIT)) more (raise the limit with -n)"
    fi

    echo ""
    echo "    /dev/binder means this process talks to the Android framework."
    echo "    Socket inodes can be resolved against /proc/net/tcp and"
    echo "    /proc/net/tcp6 -- the address columns there are hex, which is"
    echo "    exactly the skill from lab-01. Open files under /data/data/<pkg>/"
    echo "    are the app's own databases and preferences, and are usually the"
    echo "    fastest route to stored tokens. See ../../33-Storage/README.md."
fi

# -----------------------------------------------------------------------------
# 5. ENVIRONMENT
# -----------------------------------------------------------------------------

section "5. ENVIRONMENT BLOCK"

if [ ! -r "$D/environ" ]; then
    warn "environ unreadable -- needs the owning UID or root"
else
    if command -v wc >/dev/null 2>&1; then
        ENV_BYTES=$(wc -c < "$D/environ" 2>/dev/null)
        for w in $ENV_BYTES; do ENV_BYTES="$w"; break; done
        kv "environment size" "${ENV_BYTES:-0} bytes"
    fi

    if command -v tr >/dev/null 2>&1; then
        ENV_COUNT=0
        # tr turns the NUL separators into newlines so the shell can read them.
        while IFS= read -r ev; do
            [ -n "$ev" ] || continue
            ENV_COUNT=$((ENV_COUNT + 1))
        done <<EOF
$(tr '\0' '\n' < "$D/environ" 2>/dev/null)
EOF
        kv "variable count" "$ENV_COUNT"

        echo ""
        echo "  variable names only (values are deliberately not printed, because"
        echo "  environments routinely contain secrets):"
        SHOWN=0
        while IFS= read -r ev; do
            [ -n "$ev" ] || continue
            SHOWN=$((SHOWN + 1))
            [ "$SHOWN" -gt 25 ] && continue
            printf '    %s\n' "${ev%%=*}"
        done <<EOF
$(tr '\0' '\n' < "$D/environ" 2>/dev/null)
EOF
        [ "$SHOWN" -gt 25 ] && echo "    ... and $((SHOWN - 25)) more"
    else
        warn "tr not available -- cannot split the NUL-separated environment"
    fi

    echo ""
    echo "    The environment is captured at exec() time and is inherited across"
    echo "    fork(). On Android an app process inherits zygote's environment, so"
    echo "    it is short and dull. A process with LD_PRELOAD or LD_LIBRARY_PATH"
    echo "    set to something unusual has been tampered with, and that is exactly"
    echo "    what some injection techniques look like from the outside."
fi

# -----------------------------------------------------------------------------
# Footer
# -----------------------------------------------------------------------------

section "NEXT STEPS"
cat <<'EOF'
  Read the raw files yourself -- this report is a convenience, not a substitute:

    cat /proc/<pid>/status
    cat /proc/<pid>/maps
    ls -l /proc/<pid>/fd
    cat /proc/<pid>/smaps
    cat /proc/<pid>/limits
    ls  /proc/<pid>/task/

  Then work through ../labs/lab-02-processes-memory-maps.md, which walks the
  same ground by hand and explains every field.
EOF
echo ""
