#!/bin/sh
# =============================================================================
# first-shell.sh -- orient yourself in an unfamiliar shell, in one command
# Chapter 02 -- Linux Basics
# =============================================================================
#
# PURPOSE
#   The first five minutes in an unfamiliar shell are always the same five
#   questions, and a beginner does not yet know they are the questions:
#
#       1. WHO AM I      uid, gid, supplementary groups, and what they permit
#       2. WHERE AM I    cwd, hostname, kernel, and whether this is Android
#       3. WHAT SHELL    which shell, which coreutils, which flags will work
#       4. WHAT CAN I    where can I write, where can I execute, what is
#                        mounted noexec/nosuid/ro, what is my umask
#       5. WHAT IS HERE  the filesystem layout, the Android partitions, the
#                        setuid inventory, and the SELinux state
#
#   This script answers all five and explains what each answer means. It is a
#   teaching aid for lab 01, and it is genuinely useful as the first command
#   you run on a device you have not seen before.
#
#   It reads. It does not write, install, download, modify or delete anything.
#   The single exception is one write-probe: it creates a zero-byte file in a
#   candidate scratch directory and immediately removes it, to find out where
#   you can actually write. It says so before doing it and skips it with -n.
#
# USAGE
#   On Linux or WSL:
#       sh first-shell.sh
#       sh first-shell.sh -q          # short: sections 1 to 4 only
#       sh first-shell.sh -n          # never write anything, not even a probe
#
#   On an Android device over adb:
#       adb push first-shell.sh /data/local/tmp/
#       adb shell sh /data/local/tmp/first-shell.sh
#
#   As an app's own UID, on a debuggable build:
#       adb shell run-as com.example.app sh /data/local/tmp/first-shell.sh
#
#   Options:
#       -q, --quick    skip the slow sections (setuid scan, partition walk)
#       -n, --no-write skip the write probe entirely
#       -h, --help     this help
#
# REQUIREMENTS
#   A POSIX shell and nothing else. No awk, no bash, no perl, no python.
#   It is written this way deliberately: Android's shell is mksh with toybox,
#   and an old or minimal device may not have the tools you assume. Optional
#   commands (getprop, getenforce, stat, id, find) are used when present and
#   skipped with a note when not.
#
#   No privilege is required. Running it as root shows more; running it as an
#   ordinary user shows what an ordinary user can see, which is usually the
#   more interesting question.
#
# WHAT THIS SCRIPT WILL NOT TELL YOU
#   - It will not tell you whether a device is rooted. It lists setuid
#     binaries in the usual places; interpreting that list is your job, and a
#     modern systemless root leaves NO setuid binary on disk at all, so an
#     empty list proves nothing.
#   - It will not tell you whether an app is secure. It describes the shell
#     you are standing in, not any application.
#   - It will not find everything. As an unprivileged user most of the
#     filesystem is unreadable to you, and that is the correct behaviour, not
#     a failure of the script.
#   - It will not distinguish a DAC denial from an SELinux denial. It reports
#     the SELinux mode; for a specific denial you need `dmesg | grep avc` as
#     root.
#   - It cannot see into another process's namespace. Every mount and path it
#     reports is as YOUR process sees them, which on Android may differ from
#     what an app sees. Lab 03 explains why.
#   - It is not a substitute for doing lab 01 by hand. It prints answers; the
#     lab teaches you to derive them.
#
# SEE ALSO
#   ../labs/lab-01-filesystem-and-permissions.md    -- derive all of this yourself
#   ../labs/lab-02-processes-proc-and-signals.md    -- the /proc half
#   ../cheatsheet.md                                -- the commands, condensed
# =============================================================================

QUICK=0
NOWRITE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -q|--quick)    QUICK=1 ;;
        -n|--no-write) NOWRITE=1 ;;
        -h|--help)
            echo "usage: sh first-shell.sh [-q|--quick] [-n|--no-write]"
            echo "  -q  skip the slow sections (setuid scan, partition walk)"
            echo "  -n  skip the write probe"
            exit 0
            ;;
        *) echo "unknown option: $1"; exit 1 ;;
    esac
    shift
done

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------

rule()    { echo "=============================================================================="; }
thin()    { echo "------------------------------------------------------------------------------"; }
section() { echo ""; rule; echo " $1"; rule; }
kv()      { printf '  %-24s %s\n' "$1" "$2"; }
note()    { printf '    %s\n' "$1"; }
warn()    { printf '  !! %s\n' "$1"; }

have()    { command -v "$1" >/dev/null 2>&1; }

# `stat` differs between GNU and toybox; fall back to ls when it misbehaves.
mode_of() {
    _p="$1"
    if have stat; then
        _m=$(stat -c '%a' "$_p" 2>/dev/null)
        if [ -n "$_m" ]; then echo "$_m"; return 0; fi
    fi
    ls -ld "$_p" 2>/dev/null | { read -r _l _rest; echo "$_l"; }
}

# -----------------------------------------------------------------------------
# Is this Android?
# -----------------------------------------------------------------------------

IS_ANDROID=0
if [ -d /system/bin ] && [ -e /system/build.prop -o -d /apex ]; then
    IS_ANDROID=1
fi
if have getprop; then IS_ANDROID=1; fi

rule
if [ "$IS_ANDROID" = "1" ]; then
    echo " first-shell.sh -- orientation report   (this looks like ANDROID)"
else
    echo " first-shell.sh -- orientation report   (this looks like desktop LINUX)"
fi
rule

# =============================================================================
# 1. WHO AM I
# =============================================================================

section "1. WHO AM I"

if have id; then
    kv "id" "$(id 2>/dev/null)"
    kv "uid" "$(id -u 2>/dev/null)"
    kv "gid" "$(id -g 2>/dev/null)"
    kv "groups" "$(id -G 2>/dev/null)"
else
    warn "no id command -- reading /proc/self/status instead"
    grep -E '^(Uid|Gid|Groups):' /proc/self/status 2>/dev/null | sed 's/^/    /'
fi

echo ""
note "The four numbers on a Uid line are: real, effective, saved-set and"
note "filesystem UID. File permission checks use the FILESYSTEM uid, which"
note "normally tracks the effective one. If they differ, a setuid binary is"
note "running or a daemon has dropped privileges part-way."

if [ "$IS_ANDROID" = "1" ]; then
    U=$(id -u 2>/dev/null)
    echo ""
    echo "  what this UID means on Android:"
    case "$U" in
        0)    note "0     = root. Note that SELinux still applies to you." ;;
        1000) note "1000  = system. Very privileged, but not root." ;;
        2000) note "2000  = shell. This is what plain 'adb shell' gives you." ;;
        *)
            if [ "$U" -ge 10000 ] 2>/dev/null && [ "$U" -le 19999 ] 2>/dev/null; then
                note "$U = an ordinary app UID (appId $((U - 10000)), user 0)."
            elif [ "$U" -ge 99000 ] 2>/dev/null && [ "$U" -le 99999 ] 2>/dev/null; then
                note "$U = an isolated process. Almost no permissions at all."
            elif [ "$U" -ge 100000 ] 2>/dev/null; then
                note "$U = user $((U / 100000)), appId $((U % 100000 - 10000))."
                note "      uid = userId * 100000 + appId. A big number is NOT privilege."
            else
                note "$U = a platform AID. See android_filesystem_config.h in AOSP."
            fi
            ;;
    esac
    echo ""
    if id -G 2>/dev/null | grep -qw 3003; then
        note "You are in group 3003 (AID_INET): network access is permitted."
        note "On Android the INTERNET permission IS this Linux group."
    else
        note "You are NOT in group 3003 (AID_INET). No network for this identity."
    fi
fi

if [ -r /proc/self/attr/current ]; then
    echo ""
    kv "SELinux context" "$(cat /proc/self/attr/current 2>/dev/null | tr -d '\000')"
fi

if [ -r /proc/self/status ]; then
    echo ""
    echo "  from /proc/self/status:"
    grep -E '^(Umask|Seccomp|NoNewPrivs|CapEff|CapBnd):' /proc/self/status 2>/dev/null \
        | sed 's/^/    /'
    note ""
    note "Seccomp 2 means a syscall filter is installed (normal for an Android"
    note "app process). CapEff all zeros means no capabilities -- no slice of"
    note "root's power at all."
fi

# =============================================================================
# 2. WHERE AM I
# =============================================================================

section "2. WHERE AM I"

kv "cwd" "$(pwd 2>/dev/null)"
kv "home" "${HOME:-<unset>}"
have hostname && kv "hostname" "$(hostname 2>/dev/null)"
[ -r /proc/sys/kernel/hostname ] && kv "kernel hostname" "$(cat /proc/sys/kernel/hostname 2>/dev/null)"
have uname && kv "kernel" "$(uname -a 2>/dev/null)"
[ -r /proc/version ] && kv "/proc/version" "$(cut -c1-70 < /proc/version 2>/dev/null)"

if [ "$IS_ANDROID" = "1" ] && have getprop; then
    echo ""
    echo "  device properties:"
    for p in ro.product.model ro.product.manufacturer ro.build.version.release \
             ro.build.version.sdk ro.build.type ro.build.tags ro.debuggable \
             ro.secure ro.boot.verifiedbootstate; do
        v=$(getprop "$p" 2>/dev/null)
        [ -n "$v" ] && printf '    %-32s %s\n' "$p" "$v"
    done
    echo ""
    note "ro.build.type: 'user' is a production build; 'userdebug' and 'eng'"
    note "allow far more. ro.debuggable=1 and ro.secure=0 mean 'adb root' will"
    note "work. verifiedbootstate 'green' means the bootloader is locked and"
    note "the boot chain verified; 'orange' means it is unlocked."
fi

if have getenforce; then
    echo ""
    kv "SELinux mode" "$(getenforce 2>/dev/null)"
    note "Enforcing means a second, independent permission layer is active."
    note "A 'permission denied' with correct file modes is usually SELinux."
elif [ -r /sys/fs/selinux/enforce ]; then
    E=$(cat /sys/fs/selinux/enforce 2>/dev/null)
    kv "SELinux enforce" "$E (1 = enforcing)"
fi

# =============================================================================
# 3. WHAT SHELL AND WHAT TOOLS
# =============================================================================

section "3. WHAT SHELL AND WHAT TOOLS"

kv "\$0" "$0"
kv "\$SHELL" "${SHELL:-<unset>}"
if [ -e /system/bin/sh ]; then
    kv "/system/bin/sh" "$(ls -l /system/bin/sh 2>/dev/null)"
    note "On Android this is normally a symlink to mksh -- NOT bash."
    note "Bash syntax ([[ ]], arrays, \$'...') may not work here."
fi
if [ -e /bin/sh ]; then
    kv "/bin/sh" "$(ls -l /bin/sh 2>/dev/null)"
fi

echo ""
kv "PATH" "${PATH:-<unset>}"
note "A bare command name is searched along PATH, left to right. A name"
note "containing a slash is not searched at all -- which is why ./script.sh"
note "needs the ./ and why a privileged program should always use absolute"
note "paths for helpers."

echo ""
echo "  which implementation is present:"
for c in ls cat grep find sed awk ps id stat mount df xxd od strings \
         tr cut sort uniq head tail wc readlink base64 nc socat python3; do
    if have "$c"; then
        printf '    %-10s %s\n' "$c" "$(command -v "$c" 2>/dev/null)"
    else
        printf '    %-10s -- MISSING\n' "$c"
    fi
done

if have toybox; then
    echo ""
    kv "toybox" "$(command -v toybox)"
    note "Android's commands are toybox applets, not GNU coreutils. Flags"
    note "differ. Check any command with: toybox <cmd> --help"
fi
if have busybox; then
    kv "busybox" "$(command -v busybox)"
fi

echo ""
kv "umask" "$(umask 2>/dev/null)"
note "umask REMOVES bits from files you create. 022 gives 0644 files and"
note "0755 directories; 077 gives 0600 and 0700. Android's zygote sets a"
note "restrictive umask so app files default to owner-only."

# =============================================================================
# 4. WHERE CAN I WRITE AND EXECUTE
# =============================================================================

section "4. WHERE CAN I WRITE AND EXECUTE"

echo "  mount flags that override file permissions:"
if [ -r /proc/mounts ]; then
    printf '    %-28s %-8s %s\n' "MOUNT POINT" "TYPE" "FLAGS"
    thin
    while IFS= read -r line; do
        set -- $line
        [ $# -ge 4 ] || continue
        _mp="$2"; _ty="$3"; _fl="$4"
        case "$_mp" in
            /|/data|/system|/system_ext|/product|/vendor|/apex|/tmp|/sdcard|\
/storage|/storage/emulated|/data/local/tmp|/home|/var|/dev|/mnt)
                printf '    %-28s %-8s %s\n' "$_mp" "$_ty" "$(echo "$_fl" | cut -c1-40)"
                ;;
        esac
    done < /proc/mounts
    echo ""
    note "ro       = read-only. No file mode can make it writable."
    note "noexec   = binaries here cannot be executed, whatever their mode."
    note "nosuid   = setuid bits here are IGNORED by the kernel."
    note "That trio is why /data/local/tmp is the place to push tools and"
    note "/sdcard is not."
else
    warn "/proc/mounts unreadable"
fi

echo ""
echo "  candidate scratch directories:"
for d in /data/local/tmp /tmp /var/tmp "$HOME" /sdcard/Download .; do
    [ -d "$d" ] || continue
    printf '    %-22s %s\n' "$d" "$(ls -ld "$d" 2>/dev/null | cut -c1-58)"
done

if [ "$NOWRITE" = "1" ]; then
    echo ""
    note "write probe skipped (-n given)."
else
    echo ""
    echo "  write probe -- creating and immediately deleting one empty file:"
    for d in /data/local/tmp /tmp "$HOME" .; do
        [ -d "$d" ] || continue
        _probe="$d/.first_shell_probe.$$"
        if ( : > "$_probe" ) 2>/dev/null; then
            _m=$(mode_of "$_probe")
            rm -f "$_probe" 2>/dev/null
            printf '    %-22s WRITABLE   (new files get mode %s)\n' "$d" "$_m"
        else
            printf '    %-22s not writable by this uid\n' "$d"
        fi
    done
    note ""
    note "The mode shown is your umask in action. Compare it with section 3."
fi

# =============================================================================
# 5. WHAT IS HERE
# =============================================================================

if [ "$QUICK" = "1" ]; then
    section "5. WHAT IS HERE  (skipped: -q given)"
    echo ""
    exit 0
fi

section "5. WHAT IS HERE"

echo "  top of the tree:"
ls -l / 2>/dev/null | head -30 | sed 's/^/    /'

if [ "$IS_ANDROID" = "1" ]; then
    echo ""
    echo "  Android partitions and key paths:"
    printf '    %-26s %s\n' "PATH" "MODE AND OWNERSHIP"
    thin
    for p in /system /system_ext /product /vendor /odm /apex /data /metadata \
             /data/app /data/data /data/user /data/user_de /data/local/tmp \
             /data/system /data/misc /sdcard /storage /dev/socket /proc /sys; do
        if [ -e "$p" ]; then
            printf '    %-26s %s\n' "$p" "$(ls -ld "$p" 2>/dev/null | cut -c1-50)"
        else
            printf '    %-26s (absent)\n' "$p"
        fi
    done
    echo ""
    note "/data/data at drwxrwx--x is the anti-enumeration control: you can"
    note "enter a package directory you know the name of, but not list them."
    note "/data/data/<pkg> at drwx------ owned by the app's uid IS the sandbox."

    echo ""
    echo "  /dev/socket -- the classic-IPC endpoints:"
    if [ -d /dev/socket ]; then
        ls -l /dev/socket 2>/dev/null | head -20 | sed 's/^/    /'
        note ""
        note "A world-connectable socket (srw-rw-rw-) is only safe if the"
        note "daemon behind it checks SO_PEERCRED. See lab 03."
    else
        note "not present or not readable"
    fi
fi

echo ""
echo "  setuid and setgid binaries in the usual places:"
if have find; then
    if [ "$IS_ANDROID" = "1" ]; then
        SEARCH="/system /system_ext /product /vendor /apex /sbin /data/local"
    else
        SEARCH="/bin /sbin /usr /opt"
    fi
    FOUND=0
    for s in $SEARCH; do
        [ -d "$s" ] || continue
        find "$s" -perm -4000 -type f 2>/dev/null | while IFS= read -r f; do
            printf '    setuid  %s\n' "$(ls -l "$f" 2>/dev/null | cut -c1-72)"
        done
        FOUND=1
    done
    [ "$FOUND" = "1" ] || note "nothing searched"
    echo ""
    note "-perm -4000 with a LEADING MINUS means 'has at least these bits'."
    note "Without the minus it means 'exactly this mode', which matches almost"
    note "nothing. That is the most common find mistake there is."
    note ""
    note "An empty list does NOT mean the device is unmodified. Systemless"
    note "root puts no setuid binary on disk at all -- it uses a mount"
    note "namespace instead. See lab 03 and lab 04."
else
    warn "no find command -- cannot scan"
fi

# =============================================================================
# Footer
# =============================================================================

section "NEXT STEPS"
cat <<'EOF'
  This report is a convenience. Derive every line of it yourself:

    id                                   who am I
    ls -ld /data /data/data              r versus x on a directory
    stat -c '%a %A %U %G %n' <file>      octal and symbolic mode together
    cat /proc/mounts                     ro / noexec / nosuid
    umask                                what bits your new files lose
    find / -perm -4000 -type f 2>/dev/null   the setuid inventory
    getenforce                           the second permission layer

  Then work through, in order:

    ../labs/lab-01-filesystem-and-permissions.md
    ../labs/lab-02-processes-proc-and-signals.md
    ../labs/lab-03-ipc-sockets-and-namespaces.md
    ../labs/lab-04-ctf-the-hidden-flag.md
EOF
echo ""
