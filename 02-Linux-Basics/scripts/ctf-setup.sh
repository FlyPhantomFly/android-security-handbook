#!/bin/sh
# =============================================================================
# ctf-setup.sh -- builds (and tears down) the Lab 04 challenge environment
# Chapter 02 -- Linux Basics
# =============================================================================
#
# PURPOSE
#   Lab 04 ("CTF: The Hidden Flag") needs a target. This script builds one
#   inside a single directory that you own, using only ordinary Linux
#   mechanisms taught in labs 01-03:
#
#     stage 1  a directory with execute but not read permission, plus a log
#              file that leaks the name of a file inside it
#     stage 2  a live process carrying a secret in its environment
#     stage 3  a live process holding an unlinked (deleted) file open
#     stage 4  a chain of symbolic links that must be canonicalised
#     stage 5  a bind mount hiding a directory behind a decoy
#              (created only if you can use sudo; skipped cleanly if not)
#
#   Everything it creates lives under one directory and is removed by
#   `clean`. It starts three harmless background shell loops and, on stage 5,
#   one bind mount. Nothing else on the system is touched.
#
# USAGE
#   sh ctf-setup.sh build      # create the challenge and start the daemons
#   sh ctf-setup.sh status     # show what exists right now
#   sh ctf-setup.sh answers    # SPOILERS: print every flag and how to get it
#   sh ctf-setup.sh clean      # stop the daemons, unmount, delete everything
#
#   Choose where it lives (defaults shown):
#     LAB04_DIR=$HOME/ctf-lab04            sh ctf-setup.sh build   # Linux/WSL
#     LAB04_DIR=/data/local/tmp/ctf-lab04  sh ctf-setup.sh build   # Android
#
#   On Android:
#     adb push ctf-setup.sh /data/local/tmp/
#     adb shell sh /data/local/tmp/ctf-setup.sh build
#
# REQUIREMENTS
#   A POSIX shell (bash, dash, or Android's mksh) and the following commands:
#   mkdir, chmod, ln, rm, printf, cat, sleep, grep, tail. `base64` is used
#   when present and a marked plain-text form is used when it is not.
#
#   Stage 5 additionally needs `mount --bind`, which needs root. The script
#   tries `sudo` and then plain `mount`; if neither works it says so, skips
#   stage 5, and the rest of the challenge still works.
#
# SAFETY
#   - Every path it writes is under $LAB04_DIR. It refuses to run unless that
#     is an absolute path, refuses a short list of dangerous values, and
#     refuses to delete any directory that does not contain the marker file
#     .lab04-marker that it wrote itself.
#   - The three daemons are `while :; do sleep 5; done` shell loops. They use
#     no measurable CPU and are killed by `clean`.
#   - Nothing is downloaded, nothing is installed, no system file is edited,
#     and no permission outside $LAB04_DIR is changed.
#   - `clean` refuses to delete the directory if it cannot first remove the
#     stage 5 mount, rather than deleting around a live mount point.
#
# WHAT THIS SCRIPT WILL NOT TELL YOU
#   - It will not tell you whether YOUR system is configured the way the lab
#     assumes. If `sudo` is unavailable, or unprivileged user namespaces are
#     restricted, stage 5 is skipped and the script says so -- that is a
#     property of your machine, not a bug here.
#   - It will not verify your solution. There is no scoring, no checker and
#     no hint system. `answers` prints the flags; nothing compares them to
#     anything you typed.
#   - It will not teach you the concepts. It builds a target. The explanation
#     is in ../labs/lab-04-ctf-the-hidden-flag.md and in labs 01 to 03.
#   - It does NOT model a real Android app. The stages are deliberately clean
#     demonstrations of single mechanisms. A real target mixes them, buries
#     them in native code, and does not label the stages.
#   - It cannot guarantee the daemons survive your terminal closing. They are
#     ordinary background jobs. If `status` reports one is gone, run `clean`
#     and then `build` again.
#
# SEE ALSO
#   ../labs/lab-04-ctf-the-hidden-flag.md   -- the challenge itself
#   ../labs/lab-01-filesystem-and-permissions.md
#   ../labs/lab-02-processes-proc-and-signals.md
#   ../labs/lab-03-ipc-sockets-and-namespaces.md
# =============================================================================

set -u

# -----------------------------------------------------------------------------
# Where everything lives
# -----------------------------------------------------------------------------

pick_default_dir() {
    if [ -n "${HOME:-}" ] && [ -d "${HOME:-}" ] && [ -w "${HOME:-}" ]; then
        echo "$HOME/ctf-lab04"
    else
        echo "/data/local/tmp/ctf-lab04"
    fi
}

DIR="${LAB04_DIR:-$(pick_default_dir)}"
RT="$DIR/.runtime"
MARKER="$DIR/.lab04-marker"
HIDDEN="$DIR/store/rev-2/final"      # the directory stage 5 mounts over

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------

rule() { echo "=============================================================================="; }
say()  { printf '  %s\n' "$1"; }
ok()   { printf '  [ok]   %s\n' "$1"; }
skip() { printf '  [skip] %s\n' "$1"; }
warn() { printf '  [!!]   %s\n' "$1"; }

usage() {
    cat <<EOF
usage: sh ctf-setup.sh <build|status|answers|clean>

  build     create the challenge under $DIR and start its daemons
  status    report what currently exists
  answers   SPOILERS -- print every flag and the intended route to it
  clean     stop the daemons, remove the stage 5 mount, delete $DIR

  LAB04_DIR=<path>   put the challenge somewhere else
EOF
    exit "${1:-0}"
}

# -----------------------------------------------------------------------------
# Guard rails. Nothing destructive runs until these pass.
# -----------------------------------------------------------------------------

sanity_check_dir() {
    case "$DIR" in
        /*) : ;;
        *)  warn "LAB04_DIR must be an absolute path (got '$DIR')"; exit 1 ;;
    esac
    case "$DIR" in
        "/"|"/usr"|"/etc"|"/var"|"/home"|"/root"|"/system"|"/data"|"/vendor"|"/tmp")
            warn "refusing to operate on '$DIR'"
            exit 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# The flags. Each one names the mechanism it teaches.
# -----------------------------------------------------------------------------

F1='FLAG{x_traverses__r_lists}'
F2='FLAG{environ_is_nul_separated}'
F3='FLAG{unlinked_but_still_open}'
F4='FLAG{canonicalise_before_you_trust}'
F5='FLAG{a_mount_hides_a_path_not_an_inode}'

STAGE1_FILE='k3y_2f9a.txt'

# -----------------------------------------------------------------------------
# base64 is nice to have, not required
# -----------------------------------------------------------------------------

encode() {
    # encode <string> -> base64 when available, else a clearly marked plain form
    if command -v base64 >/dev/null 2>&1; then
        printf '%s\n' "$1" | base64 2>/dev/null || printf 'PLAIN:%s\n' "$1"
    else
        printf 'PLAIN:%s\n' "$1"
    fi
}

# -----------------------------------------------------------------------------
# build
# -----------------------------------------------------------------------------

do_build() {
    sanity_check_dir

    if [ -e "$DIR" ]; then
        warn "$DIR already exists. Run 'clean' first."
        exit 1
    fi

    rule
    echo " building the Lab 04 challenge in $DIR"
    rule

    mkdir -p "$DIR" || { warn "cannot create $DIR"; exit 1; }
    printf 'lab04\n' > "$MARKER"
    mkdir -p "$RT/decoy" "$DIR/logs" "$DIR/stage1" "$DIR/vault" \
             "$DIR/store/rev-1" "$HIDDEN"

    # ---- the brief ----------------------------------------------------------
    cat > "$DIR/BRIEF.txt" <<EOF
Lab 04 -- The Hidden Flag
=========================

Five flags are hidden in and around this directory. Each one is protected by a
different Linux mechanism, and each one is recoverable with commands you have
already used in labs 01, 02 and 03.

  $DIR

You need no root, no exploit, and no tool that is not already installed. You
need to read carefully, and to know what "permission denied" actually means.

Every flag has the form FLAG{something_lowercase_with_underscores}.

Start by listing this directory and reading everything you can read.
There is a logs/ directory. Logs are written by developers, for developers,
and they say more than they were meant to.

Rules:
  - Nothing outside $DIR is part of the challenge.
  - You never need to delete or modify anything to make progress, except in
    the final stage, where you will need to change your own view of the
    filesystem.
  - If you get stuck, the hints are in
    ../labs/lab-04-ctf-the-hidden-flag.md -- in collapsed blocks, so you can
    take them one at a time.
EOF

    # ---- stage 1: x-without-r, plus a leaked name in a log ------------------
    cat > "$DIR/stage1/$STAGE1_FILE" <<EOF
$F1

Stage 1 solved. You could not list this directory, but you could enter it,
because 'x' on a directory means traverse and 'r' means enumerate. Android
sets /data/data to drwxrwx--x for exactly this reason: an app can reach a
package directory whose name it already knows, but no app can obtain the list
of installed packages by reading the directory.

The name leaked out of a log file, which is how it usually happens in real
life.

STAGE 2
-------
A process belonging to you is running right now with a secret in its
environment. Its command line contains the string "lab04-stage2".

Find the process. Read its environment. Remember what separates the entries.
EOF
    chmod 0444 "$DIR/stage1/$STAGE1_FILE"

    cat > "$DIR/logs/app.log" <<EOF
I/Boot    ( 1201): starting cache warmer, revision 3
D/Cache   ( 1201): using base directory $DIR
I/Cache   ( 1201): 0 entries loaded from cold storage
D/Config  ( 1201): reading $DIR/logs/app.log
W/AppCache( 1201): could not open $DIR/stage1/$STAGE1_FILE (ENOENT), regenerating
I/AppCache( 1201): regenerated ok, 1 entry
D/Vault   ( 1201): resolving $DIR/vault/latest
W/Vault   ( 1201): $DIR/vault/flag.txt has mode 0000, skipping
I/Vault   ( 1201): 2 revisions available under $DIR/store
D/Daemon  ( 1201): supervisor started, 3 workers
I/Daemon  ( 1201): worker lab04-stage2 up
I/Daemon  ( 1201): worker lab04-stage3 up
D/Daemon  ( 1201): worker lab04-stage3 opened its state file and unlinked it
I/Daemon  ( 1201): worker lab04-stage5 up
I/Boot    ( 1201): warm-up complete
EOF
    chmod 0644 "$DIR/logs/app.log"
    chmod 0111 "$DIR/stage1"          # --x--x--x : traverse, but do not list
    ok "stage 1 built (directory mode 0111, name leaked in logs/app.log)"

    # ---- stage 2: a secret in a process environment -------------------------
    cat > "$RT/lab04-stage2.sh" <<'EOF'
#!/bin/sh
# Lab 04 stage 2 daemon. Holds a secret in its environment and does nothing.
while :; do sleep 5; done
EOF
    chmod 0755 "$RT/lab04-stage2.sh"

    S2="$F2 -- stage 3: a process with lab04-stage3 in its command line is holding a deleted file open. Look at its file descriptors."
    # stdio is detached so the daemon does not hold the invoking shell's pipes
    # open -- otherwise `sh ctf-setup.sh build | tee log` never finishes.
    LAB04_STAGE2_SECRET="$S2" sh "$RT/lab04-stage2.sh" </dev/null >/dev/null 2>&1 &
    P2=$!
    echo "$P2" >> "$RT/pids"
    ok "stage 2 built (daemon pid $P2 carries LAB04_STAGE2_SECRET)"

    # ---- stage 3: an unlinked file held open --------------------------------
    cat > "$RT/.s3seed" <<EOF
$F3

Stage 3 solved. The file you just read has no name. Its last directory entry
was removed while this process still held it open, so the link count reached
zero but the inode did not go away -- and /proc/<pid>/fd/3 still points at it.

Copying /proc/<pid>/fd/N is how you recover a temporary file that an app
deleted "to be safe", and it is why deleting a file is not the same as
destroying its contents.

STAGE 4
-------
Look in $DIR/vault.

There is a flag.txt there with mode 0000. It is a decoy, but read it anyway
once you have made it readable -- it will tell you so itself.

The real path runs through 'latest'. Follow it properly. A symbolic link
stores a path as text and is resolved fresh at every open, so a chain of them
can end up somewhere you did not expect. Resolve it all the way down before
you trust where you are.
EOF
    cat > "$RT/lab04-stage3.sh" <<EOF
#!/bin/sh
# Lab 04 stage 3 daemon. Opens its state file on descriptor 3, unlinks it, and
# then waits. The data survives only through the open descriptor.
exec 3< "$RT/.s3seed"
rm -f "$RT/.s3seed"
while :; do sleep 5; done
EOF
    chmod 0755 "$RT/lab04-stage3.sh"
    sh "$RT/lab04-stage3.sh" </dev/null >/dev/null 2>&1 &
    P3=$!
    echo "$P3" >> "$RT/pids"
    ok "stage 3 built (daemon pid $P3 holds a deleted file on fd 3)"

    # ---- stage 4: a symlink chain -------------------------------------------
    cat > "$DIR/vault/flag.txt" <<EOF
Not the flag.

This file is a decoy, and the fact that you could remove its mode 0000 with a
single chmod is the point: chmod is available to the OWNER of a file, so a
mode alone protects nothing against its owner. It protects against other
UIDs -- which is exactly what Android's one-UID-per-app model relies on.

The real path is reached through 'latest'.
EOF
    chmod 0000 "$DIR/vault/flag.txt"

    encode "Not the flag -- this is revision 1, and it is stale. Revisions move forward." \
        > "$DIR/store/rev-1/flag.b64"

    S4="$F4 -- final stage: read final/final.b64 from here. If what you get back is not a flag, then the directory you are reading is not the directory you think it is. Compare what you see against /proc/mounts, and remember that a mount hides a path, not an inode."
    encode "$S4" > "$DIR/store/rev-2/flag.b64"

    ln -s "rev-2"          "$DIR/store/rev-3"
    ln -s "../store/rev-3" "$DIR/vault/latest"
    ok "stage 4 built (vault/latest -> ../store/rev-3 -> rev-2)"

    # ---- stage 5: a bind mount hiding the real directory --------------------
    # Write the real final flag FIRST, then start a process whose cwd is that
    # directory, and only then put the decoy on top of the path.
    encode "$F5" > "$HIDDEN/final.b64"

    encode "Not the flag. Something is mounted over this directory. The real contents are still there, underneath -- nothing was deleted. /proc/mounts knows. Lab 03 part E showed you two ways to reach what a mount is covering." \
        > "$RT/decoy/final.b64"

    cat > "$RT/decoy/README" <<'EOF'
If you are reading this, you are looking at a bind mount, not at the real
directory. Nothing has been deleted. Nothing is being faked. The kernel is
telling you the truth about a different view of the filesystem.
EOF

    cat > "$RT/lab04-stage5.sh" <<EOF
#!/bin/sh
# Lab 04 stage 5 daemon. Its current working directory is the real hidden
# directory, captured before the bind mount was created. /proc/<pid>/cwd
# therefore still reaches the real directory while a mount covers the path.
cd "$HIDDEN" || exit 1
while :; do sleep 5; done
EOF
    chmod 0755 "$RT/lab04-stage5.sh"
    sh "$RT/lab04-stage5.sh" </dev/null >/dev/null 2>&1 &
    P5=$!
    echo "$P5" >> "$RT/pids"
    sleep 1

    MOUNTED=0
    if command -v mount >/dev/null 2>&1; then
        if command -v sudo >/dev/null 2>&1 && \
           sudo -n mount --bind "$RT/decoy" "$HIDDEN" 2>/dev/null; then
            MOUNTED=1
        elif command -v sudo >/dev/null 2>&1 && [ -t 0 ] && \
             sudo mount --bind "$RT/decoy" "$HIDDEN"; then
            MOUNTED=1
        elif mount --bind "$RT/decoy" "$HIDDEN" 2>/dev/null; then
            MOUNTED=1
        fi
    fi

    if [ "$MOUNTED" = "1" ]; then
        echo "yes" > "$RT/mounted"
        ok "stage 5 built (bind mount over store/rev-2/final, cwd daemon pid $P5)"
    else
        skip "stage 5 NOT built -- could not create a bind mount."
        say  "       You are not root, and sudo is unavailable or was refused."
        say  "       Stages 1 to 4 work normally, and stage 5's flag is simply"
        say  "       sitting in the open at store/rev-2/final/final.b64."
        say  "       To see the mechanism it would have taught, do lab 03 part E"
        say  "       on a machine where you have sudo."
    fi

    echo ""
    rule
    echo " ready"
    rule
    say "Read the brief:   cat $DIR/BRIEF.txt"
    say "Check state:      sh ctf-setup.sh status"
    say "Give up:          sh ctf-setup.sh answers"
    say "Tear down:        sh ctf-setup.sh clean"
    echo ""
}

# -----------------------------------------------------------------------------
# status
# -----------------------------------------------------------------------------

do_status() {
    rule
    echo " Lab 04 challenge status"
    rule
    say "directory: $DIR"

    if [ ! -e "$MARKER" ]; then
        warn "not built. Run: sh ctf-setup.sh build"
        exit 0
    fi

    echo ""
    echo "  daemons:"
    if [ -r "$RT/pids" ]; then
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            if [ -d "/proc/$p" ]; then
                nm=$(cat "/proc/$p/comm" 2>/dev/null)
                printf '    pid %-8s alive   (%s)\n' "$p" "${nm:-?}"
            else
                printf '    pid %-8s GONE    -- run clean, then build again\n' "$p"
            fi
        done < "$RT/pids"
    else
        say "  no pid file"
    fi

    echo ""
    echo "  stage 5 mount:"
    if [ -f "$RT/mounted" ]; then
        if grep -q "$HIDDEN" /proc/mounts 2>/dev/null; then
            say "  present -- store/rev-2/final is covered by a bind mount"
        else
            say "  recorded as created, but no longer present in /proc/mounts"
        fi
    else
        say "  not created on this machine (no privilege). Stages 1-4 only."
    fi
    echo ""
}

# -----------------------------------------------------------------------------
# answers
# -----------------------------------------------------------------------------

do_answers() {
    rule
    echo " SPOILERS -- Lab 04 flags and intended routes"
    rule
    cat <<EOF

  STAGE 1  $F1
     mechanism: 'x' on a directory permits traversal, 'r' permits listing.
     route:     ls $DIR/stage1        -> Permission denied
                grep -r stage1 $DIR/logs/
                cat $DIR/stage1/$STAGE1_FILE

  STAGE 2  $F2
     mechanism: a process environment is readable through /proc, and its
                entries are separated by NUL bytes, not spaces.
     route:     ps -ef | grep lab04-stage2
                tr '\\0' '\\n' < /proc/<pid>/environ | grep LAB04

  STAGE 3  $F3
     mechanism: removing a name does not destroy an inode that a process
                still holds open.
     route:     ps -ef | grep lab04-stage3
                ls -l /proc/<pid>/fd          (look for "(deleted)")
                cat /proc/<pid>/fd/3

  STAGE 4  $F4
     mechanism: a symlink stores a path as text and is resolved at every
                open; chains must be canonicalised before they are trusted.
     route:     ls -l $DIR/vault/latest
                readlink -f $DIR/vault/latest
                base64 -d "\$(readlink -f $DIR/vault/latest)/flag.b64"

  STAGE 5  $F5
     mechanism: a bind mount hides a PATH. The inodes underneath are
                untouched, and a process that already holds a reference to
                them can still reach them.
     route A:   grep final /proc/mounts            (see the mount)
                sudo unshare --mount /bin/sh
                umount $HIDDEN                     (inside that namespace only)
                base64 -d $HIDDEN/final.b64
     route B:   ps -ef | grep lab04-stage5
                ls -l /proc/<pid>/cwd
                base64 -d /proc/<pid>/cwd/final.b64
     route C:   sudo umount $HIDDEN                (correct, but it changes the
                                                    machine for every process.
                                                    In an assessment, prefer A)

EOF
}

# -----------------------------------------------------------------------------
# clean
# -----------------------------------------------------------------------------

do_clean() {
    sanity_check_dir

    if [ ! -e "$MARKER" ]; then
        warn "$DIR has no .lab04-marker -- refusing to delete it."
        warn "If you built the challenge somewhere else, set LAB04_DIR."
        exit 1
    fi

    rule
    echo " tearing down $DIR"
    rule

    if [ -r "$RT/pids" ]; then
        while IFS= read -r p; do
            [ -n "$p" ] || continue
            if [ -d "/proc/$p" ]; then
                kill "$p" 2>/dev/null && ok "stopped pid $p"
            fi
        done < "$RT/pids"
    fi

    if grep -q "$HIDDEN" /proc/mounts 2>/dev/null; then
        if command -v sudo >/dev/null 2>&1 && sudo umount "$HIDDEN" 2>/dev/null; then
            ok "unmounted $HIDDEN"
        elif umount "$HIDDEN" 2>/dev/null; then
            ok "unmounted $HIDDEN"
        else
            warn "could NOT unmount $HIDDEN -- refusing to delete around a live mount."
            warn "Run this yourself, then rerun clean:"
            warn "  sudo umount $HIDDEN"
            exit 1
        fi
    fi

    chmod -R u+rwX "$DIR" 2>/dev/null
    rm -rf "$DIR" && ok "removed $DIR"

    if grep -q "$DIR" /proc/mounts 2>/dev/null; then
        warn "something is still mounted under $DIR -- check /proc/mounts"
    fi
    echo ""
}

# -----------------------------------------------------------------------------
# dispatch
# -----------------------------------------------------------------------------

[ $# -ge 1 ] || usage 1

case "$1" in
    build)   do_build ;;
    status)  do_status ;;
    answers) do_answers ;;
    clean)   do_clean ;;
    -h|--help|help) usage 0 ;;
    *)       echo "unknown command: $1"; usage 1 ;;
esac
