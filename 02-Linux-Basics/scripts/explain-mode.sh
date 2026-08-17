#!/bin/sh
# =============================================================================
# explain-mode.sh -- convert and explain UNIX permission modes, both directions
# Chapter 02 -- Linux Basics
# =============================================================================
#
# PURPOSE
#   Reading `drwxr-xr-x` as 755, and 0640 as `-rw-r-----`, has to become
#   automatic. Until it is, this script is the answer key: give it a mode in
#   either notation, or the path of a real file, and it prints
#
#       the octal number, including the special-bit digit
#       the ten-character string as `ls -l` would show it
#       what each of the three classes may actually DO -- separately for a
#       file and for a directory, because r/w/x mean different things
#       a warning for the modes that are findings in an Android assessment
#
#   It also converts the other way (symbolic to octal), applies a umask so you
#   can predict what a newly created file will get, and drills you with
#   practice problems and their answers.
#
#   It reads. Given a path it calls stat (or ls) on it. It never changes a
#   mode, creates a file, or writes anything anywhere.
#
# USAGE
#   sh explain-mode.sh 755                 # octal -> string + explanation
#   sh explain-mode.sh 4755                # with the special-bit digit
#   sh explain-mode.sh rwxr-xr-x           # symbolic -> octal
#   sh explain-mode.sh -rw-r--r--          # leading type character is fine
#   sh explain-mode.sh drwxrwx--x          # so is a directory
#   sh explain-mode.sh /etc/passwd         # explain a real file
#   sh explain-mode.sh --umask 022 666     # what a 0666 request becomes
#   sh explain-mode.sh --drill             # ten practice problems + answers
#   sh explain-mode.sh --table             # the reference tables
#
#   On an Android device:
#       adb push explain-mode.sh /data/local/tmp/
#       adb shell sh /data/local/tmp/explain-mode.sh /data/local/tmp
#
# REQUIREMENTS
#   A POSIX shell. Nothing else. No awk, no bc, no python. `stat` is used when
#   present for the file mode and `ls -ld` is the fallback, so it works on a
#   stock Android device with only toybox.
#
# WHAT THIS SCRIPT WILL NOT TELL YOU
#   - It will not tell you whether a mode is SAFE. Safety depends on who owns
#     the file, which group it is in, which UIDs exist on the system, what is
#     mounted over it, and what SELinux says. 0644 on an APK is correct and
#     0644 on a private key is a finding; the number alone cannot distinguish
#     them.
#   - It knows nothing about SELinux, capabilities, ACLs or seccomp. Those are
#     separate layers that can deny an access the mode permits, and (for
#     capabilities) permit one the mode denies. `ls -Z` and `getenforce` are
#     the tools for the second layer.
#   - It does not consider the mount flags. A file at mode 4755 on a partition
#     mounted `nosuid` is not setuid in practice, and one at 0777 on a `ro`
#     mount is not writable. Check /proc/mounts.
#   - It does not check the directories above the file. You need `x` on every
#     component of the path to reach it at all, so a 0666 file inside a 0700
#     directory is unreachable by anyone but the directory's owner.
#   - It will not do your drills for you. --drill prints the answers, but the
#     point is to write yours down first.
#
# SEE ALSO
#   ../labs/lab-01-filesystem-and-permissions.md       -- derive it by hand
#   ../examples/permission-arithmetic-drill.md         -- thirty worked problems
#   ../cheatsheet.md
# =============================================================================

# -----------------------------------------------------------------------------
# Conversion primitives
# -----------------------------------------------------------------------------

# digit_to_rwx <octal-digit> -> rwx string
digit_to_rwx() {
    case "$1" in
        0) echo "---" ;;
        1) echo "--x" ;;
        2) echo "-w-" ;;
        3) echo "-wx" ;;
        4) echo "r--" ;;
        5) echo "r-x" ;;
        6) echo "rw-" ;;
        7) echo "rwx" ;;
        *) echo "???" ;;
    esac
}

# rwx_to_digit <3-char string> -> octal digit
rwx_to_digit() {
    _s="$1"
    _n=0
    case "$_s" in
        r*) _n=$((_n + 4)) ;;
    esac
    case "$_s" in
        ?w*) _n=$((_n + 2)) ;;
    esac
    case "$_s" in
        ??x|??s|??t) _n=$((_n + 1)) ;;
    esac
    echo "$_n"
}

# -----------------------------------------------------------------------------
# Rendering
# -----------------------------------------------------------------------------

# render <special> <owner> <group> <other> [type-char]
render() {
    _sp="$1"; _o="$2"; _g="$3"; _t="$4"; _tc="${5:--}"

    _os=$(digit_to_rwx "$_o")
    _gs=$(digit_to_rwx "$_g")
    _ts=$(digit_to_rwx "$_t")

    # setuid -> owner x becomes s (or S if x was off)
    case "$_sp" in
        4|5|6|7)
            case "$_os" in
                ??x) _os="$(printf '%s' "$_os" | cut -c1-2)s" ;;
                *)   _os="$(printf '%s' "$_os" | cut -c1-2)S" ;;
            esac
            ;;
    esac
    # setgid -> group x becomes s (or S)
    case "$_sp" in
        2|3|6|7)
            case "$_gs" in
                ??x) _gs="$(printf '%s' "$_gs" | cut -c1-2)s" ;;
                *)   _gs="$(printf '%s' "$_gs" | cut -c1-2)S" ;;
            esac
            ;;
    esac
    # sticky -> other x becomes t (or T)
    case "$_sp" in
        1|3|5|7)
            case "$_ts" in
                ??x) _ts="$(printf '%s' "$_ts" | cut -c1-2)t" ;;
                *)   _ts="$(printf '%s' "$_ts" | cut -c1-2)T" ;;
            esac
            ;;
    esac

    printf '%s%s%s%s\n' "$_tc" "$_os" "$_gs" "$_ts"
}

class_meaning() {
    # class_meaning <label> <digit>
    _lbl="$1"; _d="$2"
    _r=""; _w=""; _x=""
    case "$_d" in 4|5|6|7) _r="yes" ;; *) _r="no" ;; esac
    case "$_d" in 2|3|6|7) _w="yes" ;; *) _w="no" ;; esac
    case "$_d" in 1|3|5|7) _x="yes" ;; *) _x="no" ;; esac
    printf '    %-8s r=%-3s w=%-3s x=%-3s |  file: %-34s |  dir: %s\n' \
        "$_lbl" "$_r" "$_w" "$_x" \
        "$(file_words "$_r" "$_w" "$_x")" \
        "$(dir_words "$_r" "$_w" "$_x")"
}

file_words() {
    _out=""
    [ "$1" = "yes" ] && _out="read"
    [ "$2" = "yes" ] && _out="${_out:+$_out, }write"
    [ "$3" = "yes" ] && _out="${_out:+$_out, }execute"
    echo "${_out:-nothing}"
}

dir_words() {
    _out=""
    [ "$1" = "yes" ] && _out="list names"
    [ "$2" = "yes" ] && _out="${_out:+$_out, }create/delete/rename entries"
    [ "$3" = "yes" ] && _out="${_out:+$_out, }traverse"
    echo "${_out:-nothing}"
}

# -----------------------------------------------------------------------------
# The explanation
# -----------------------------------------------------------------------------

explain_octal() {
    _m="$1"; _tc="${2:--}"

    # normalise to four digits
    case "${#_m}" in
        3) _sp=0; _o=$(printf '%s' "$_m" | cut -c1); _g=$(printf '%s' "$_m" | cut -c2); _t=$(printf '%s' "$_m" | cut -c3) ;;
        4) _sp=$(printf '%s' "$_m" | cut -c1); _o=$(printf '%s' "$_m" | cut -c2); _g=$(printf '%s' "$_m" | cut -c3); _t=$(printf '%s' "$_m" | cut -c4) ;;
        *) echo "  not a 3- or 4-digit octal mode: $_m"; return 1 ;;
    esac

    _str=$(render "$_sp" "$_o" "$_g" "$_t" "$_tc")

    echo ""
    echo "=============================================================================="
    printf '  octal %s%s%s%s   string %s\n' "$_sp" "$_o" "$_g" "$_t" "$_str"
    echo "=============================================================================="
    echo ""
    echo "  arithmetic:"
    printf '    owner  %s = %s\n' "$_o" "$(digit_to_rwx "$_o")"
    printf '    group  %s = %s\n' "$_g" "$(digit_to_rwx "$_g")"
    printf '    other  %s = %s\n' "$_t" "$(digit_to_rwx "$_t")"
    [ "$_sp" != "0" ] && printf '    special %s (4=setuid 2=setgid 1=sticky, added together)\n' "$_sp"

    echo ""
    echo "  what each class may do:"
    class_meaning "owner" "$_o"
    class_meaning "group" "$_g"
    class_meaning "other" "$_t"

    echo ""
    echo "  the rule people get wrong:"
    echo "    Exactly ONE class is used. If your euid is the owner you get the"
    echo "    owner bits and the group and other bits are never consulted --"
    echo "    even when they are more permissive. That is why mode 0466 means"
    echo "    the owner cannot write a file that everyone else can."

    # special bits
    case "$_sp" in
        4|5|6|7)
            echo ""
            echo "  SETUID is set:"
            echo "    On a FILE: it runs with the file OWNER's effective uid, not the"
            echo "    caller's. This is how /usr/bin/passwd edits /etc/shadow, and how"
            echo "    Android's /system/bin/run-as drops into an app's uid. A setuid"
            echo "    binary reachable by an attacker is the classic local privilege"
            echo "    escalation target."
            echo "    On a DIRECTORY: ignored on Linux."
            echo "    On Android: IGNORED entirely on any partition mounted nosuid,"
            echo "    which includes /data and /sdcard. Check /proc/mounts."
            ;;
    esac
    case "$_sp" in
        2|3|6|7)
            echo ""
            echo "  SETGID is set:"
            echo "    On a FILE: it runs with the file's group as effective gid."
            echo "    On a DIRECTORY: new entries inherit the directory's group"
            echo "    instead of the creating process's. Used for shared workspaces."
            ;;
    esac
    case "$_sp" in
        1|3|5|7)
            echo ""
            echo "  STICKY is set:"
            echo "    On a DIRECTORY: only an entry's owner (or root) may delete or"
            echo "    rename it, even though the directory is writable by others."
            echo "    Without it, w on a directory lets anyone delete anyone's files,"
            echo "    because deleting is modifying the DIRECTORY, not the file."
            echo "    This is /tmp at 1777, and /data/local/tmp on some builds."
            ;;
    esac

    # findings
    _warned=0
    case "$_t" in
        2|3|6|7)
            echo ""
            echo "  !! WORLD-WRITABLE."
            echo "     Any uid on the system can modify this. On Android that means"
            echo "     any installed app. If it is a config, another app controls"
            echo "     behaviour; if it is executable and later run, another app has"
            echo "     code execution inside this uid. In an app's private storage"
            echo "     this is always a finding."
            _warned=1
            ;;
    esac
    case "$_t" in
        4|5|6|7)
            echo ""
            echo "  !  WORLD-READABLE."
            echo "     Correct for an APK (0644, and APKs are not secret). A finding"
            echo "     for anything under /data/data/<pkg>/ that holds tokens, keys,"
            echo "     credentials or personal data."
            _warned=1
            ;;
    esac
    if [ "$_sp$_o$_g$_t" = "0777" ] || [ "$_sp$_o$_g$_t" = "0666" ]; then
        echo ""
        echo "  !! This is the mode produced by 'chmod 777' or 'chmod 666'."
        echo "     It is almost never the correct fix for a permission error."
        echo "     Diagnose which layer denied you first: file mode, missing x on a"
        echo "     parent directory, SELinux, a ro/noexec/nosuid mount, or seccomp."
    fi
    [ "$_warned" = "0" ] && {
        echo ""
        echo "  No world access. Nothing outside the owner and group can reach it"
        echo "  through these bits."
    }
    echo ""
}

# -----------------------------------------------------------------------------
# Symbolic -> octal
# -----------------------------------------------------------------------------

explain_symbolic() {
    _s="$1"
    _tc="-"
    case "${#_s}" in
        10)
            _tc=$(printf '%s' "$_s" | cut -c1)
            _s=$(printf '%s' "$_s" | cut -c2-10)
            ;;
        9) : ;;
        *) echo "  not a 9- or 10-character mode string: $_s"; return 1 ;;
    esac

    _os=$(printf '%s' "$_s" | cut -c1-3)
    _gs=$(printf '%s' "$_s" | cut -c4-6)
    _ts=$(printf '%s' "$_s" | cut -c7-9)

    _o=$(rwx_to_digit "$_os")
    _g=$(rwx_to_digit "$_gs")
    _t=$(rwx_to_digit "$_ts")

    _sp=0
    case "$_os" in ??s|??S) _sp=$((_sp + 4)) ;; esac
    case "$_gs" in ??s|??S) _sp=$((_sp + 2)) ;; esac
    case "$_ts" in ??t|??T) _sp=$((_sp + 1)) ;; esac

    echo ""
    echo "  input string : $_tc$_os$_gs$_ts"
    printf '  type         : %s\n' "$(type_word "$_tc")"
    explain_octal "$_sp$_o$_g$_t" "$_tc"
}

type_word() {
    case "$1" in
        -) echo "- regular file" ;;
        d) echo "d directory" ;;
        l) echo "l symbolic link (its own mode is meaningless; the target's matters)" ;;
        c) echo "c character device" ;;
        b) echo "b block device" ;;
        s) echo "s UNIX-domain socket" ;;
        p) echo "p named pipe (FIFO)" ;;
        *) echo "$1 (unknown)" ;;
    esac
}

# -----------------------------------------------------------------------------
# A real file
# -----------------------------------------------------------------------------

explain_path() {
    _p="$1"
    echo ""
    echo "  path  : $_p"
    _ls=$(ls -ld "$_p" 2>/dev/null)
    if [ -z "$_ls" ]; then
        echo "  cannot stat it. Either it does not exist, or you lack x on a"
        echo "  directory along the path. Walk the path:"
        echo "    ls -ld / $(echo "$_p" | sed 's#/[^/]*$##')"
        return 1
    fi
    echo "  ls -ld: $_ls"

    _str=$(printf '%s' "$_ls" | cut -c1-10)
    if command -v stat >/dev/null 2>&1; then
        _oct=$(stat -c '%a' "$_p" 2>/dev/null)
        [ -n "$_oct" ] && echo "  stat  : mode $_oct"
    fi
    explain_symbolic "$_str"

    if [ -L "$_p" ]; then
        echo "  NOTE: this is a symbolic link. Its own mode is always lrwxrwxrwx"
        echo "  and means nothing. What matters is the target:"
        echo "    readlink    $_p   ->  $(readlink "$_p" 2>/dev/null)"
        echo "    readlink -f $_p   ->  $(readlink -f "$_p" 2>/dev/null)"
    fi
}

# -----------------------------------------------------------------------------
# umask
# -----------------------------------------------------------------------------

apply_umask() {
    _um="$1"; _req="$2"
    _r=""
    _i=1
    while [ "$_i" -le 3 ]; do
        _ud=$(printf '%s' "$_um" | cut -c$(( ${#_um} - 3 + _i )))
        _rd=$(printf '%s' "$_req" | cut -c$(( ${#_req} - 3 + _i )))
        # result digit = requested AND NOT umask, per bit
        _n=0
        for _b in 4 2 1; do
            _has=0; _mask=0
            case "$_rd" in
                7) _has=1 ;;
                6) [ "$_b" != "1" ] && _has=1 ;;
                5) [ "$_b" != "2" ] && _has=1 ;;
                4) [ "$_b" = "4" ] && _has=1 ;;
                3) [ "$_b" != "4" ] && _has=1 ;;
                2) [ "$_b" = "2" ] && _has=1 ;;
                1) [ "$_b" = "1" ] && _has=1 ;;
            esac
            case "$_ud" in
                7) _mask=1 ;;
                6) [ "$_b" != "1" ] && _mask=1 ;;
                5) [ "$_b" != "2" ] && _mask=1 ;;
                4) [ "$_b" = "4" ] && _mask=1 ;;
                3) [ "$_b" != "4" ] && _mask=1 ;;
                2) [ "$_b" = "2" ] && _mask=1 ;;
                1) [ "$_b" = "1" ] && _mask=1 ;;
            esac
            [ "$_has" = "1" ] && [ "$_mask" = "0" ] && _n=$((_n + _b))
        done
        _r="$_r$_n"
        _i=$((_i + 1))
    done
    echo "$_r"
}

do_umask() {
    _um="$1"; _req="$2"
    _res=$(apply_umask "$_um" "$_req")
    echo ""
    echo "  umask     $_um"
    echo "  requested $_req"
    echo "  result    $_res        (kernel applies: requested AND NOT umask)"
    echo ""
    echo "  A umask can only REMOVE bits, never add them. It is inherited"
    echo "  across fork() and execve(), which is why a native helper spawned"
    echo "  by an Android app inherits zygote's protective default."
    explain_octal "$_res"
}

# -----------------------------------------------------------------------------
# Reference tables and drills
# -----------------------------------------------------------------------------

do_table() {
    cat <<'EOF'

  THE NINE BITS
  -------------
    r = 4    w = 2    x = 1        rwx = 7   rw- = 6   r-x = 5   r-- = 4

    letter   on a FILE                  on a DIRECTORY
    r        read the contents          list the names inside
    w        modify the contents        create / delete / rename entries
    x        execute it as a program    TRAVERSE it (use it in a path)

  THE FOURTH DIGIT
  ----------------
    4000 setuid   shown as s in the owner x slot (S if x was off)
    2000 setgid   shown as s in the group x slot
    1000 sticky   shown as t in the other x slot (T if x was off)

  MODES YOU WILL SEE ON ANDROID
  -----------------------------
    0644  -rw-r--r--   base.apk, most of /system. APKs are not secret.
    0600  -rw-------   openFileOutput(MODE_PRIVATE). Never widen this.
    0700  drwx------   /data/data/<pkg>. This IS the app sandbox.
    0755  -rwxr-xr-x   /system/bin/*, and directories generally.
    0771  drwxrwx--x   /data/local/tmp -- shell writes, others traverse.
    0711  drwx--x--x   traverse but never enumerate.
    1777  drwxrwxrwt   world-writable, sticky. /tmp on desktop.
    4755  -rwsr-xr-x   setuid root. /system/bin/run-as, /usr/bin/passwd.
    0666  -rw-rw-rw-   a finding, in an app's private storage.
    0777  -rwxrwxrwx   a finding, always.

  THE FIVE GATES AN OPEN() MUST PASS
  ----------------------------------
    1. x on EVERY directory in the path
    2. the mode bits of the ONE matching class (owner, else group, else other)
    3. SELinux: source domain allowed this on the target type
    4. mount flags: ro / noexec / nosuid
    5. seccomp: the syscall itself is permitted

    All five produce "Permission denied". Only the first two are visible in
    ls -l. That is why diagnosing the layer matters more than the number.

EOF
}

do_drill() {
    cat <<'EOF'

  TEN PRACTICE PROBLEMS
  ---------------------
  Write your answers down first. The answers are below the line.

   A. -rw-r--r--     ->  octal?
   B. drwxrwx--x     ->  octal?
   C. -rwsr-xr-x     ->  octal?
   D. drwxrwxrwt     ->  octal?
   E. -r--r-----     ->  octal?

   F. 0700           ->  string?
   G. 0751           ->  string?
   H. 2775           ->  string?
   I. 0466           ->  string?  and can the OWNER write it?
   J. 1777           ->  string?  and who may delete a file inside?

  ----------------------------------------------------------------------------
  ANSWERS

   A. 644     4+2=6, 4, 4
   B. 771     the shape of /data/local/tmp
   C. 4755    setuid: the owner x became s
   D. 1777    sticky: the other x became t
   E. 440

   F. -rwx------
   G. -rwxr-x--x
   H. -rwxrwsr-x   setgid directory: new entries inherit its group
   I. -r--rw-rw-   NO. The owner matches first and gets r-- only. One class
                   is chosen, not merged, so the owner is LESS able than
                   everyone else. This is the rule people get wrong.
   J. drwxrwxrwt   Only the owner of each entry, because of the sticky bit.
                   Without it, anyone with w on the directory could delete
                   anyone's file, since deleting modifies the DIRECTORY.

  Thirty more, with the reasoning written out, are in
  ../examples/permission-arithmetic-drill.md

EOF
}

# -----------------------------------------------------------------------------
# Dispatch
# -----------------------------------------------------------------------------

usage() {
    cat <<'EOF'
usage: sh explain-mode.sh <mode | mode-string | path>
       sh explain-mode.sh --umask <umask> <requested-mode>
       sh explain-mode.sh --drill
       sh explain-mode.sh --table

examples:
  sh explain-mode.sh 755
  sh explain-mode.sh 4755
  sh explain-mode.sh drwxr-xr-x
  sh explain-mode.sh /data/local/tmp
  sh explain-mode.sh --umask 022 666
EOF
}

[ $# -ge 1 ] || { usage; exit 1; }

case "$1" in
    -h|--help) usage; exit 0 ;;
    --table)   do_table; exit 0 ;;
    --drill)   do_drill; exit 0 ;;
    --umask)
        [ $# -eq 3 ] || { echo "usage: --umask <umask> <requested-mode>"; exit 1; }
        do_umask "$2" "$3"
        exit 0
        ;;
esac

ARG="$1"

# A path wins if it exists, so `explain-mode.sh 755` still works even in a
# directory that happens to contain a file called 755.
if [ -e "$ARG" ] || [ -L "$ARG" ]; then
    case "$ARG" in
        */*|.|..) explain_path "$ARG"; exit $? ;;
    esac
fi

case "$ARG" in
    ''|*[!0-7]*) : ;;                       # not pure octal
    *) explain_octal "$ARG"; exit $? ;;
esac

case "$ARG" in
    *[rwxstST-]*)
        case "${#ARG}" in
            9|10) explain_symbolic "$ARG"; exit $? ;;
        esac
        ;;
esac

if [ -e "$ARG" ] || [ -L "$ARG" ]; then
    explain_path "$ARG"
    exit $?
fi

echo "Could not interpret '$ARG' as an octal mode, a mode string, or a path."
echo ""
usage
exit 1
