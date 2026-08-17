#!/usr/bin/env bash
# storage-map.sh -- print every place one Android package can legally put a byte,
#                   say which of them actually exist on this device, and show the
#                   ownership, mode and SELinux label of each.
#
# PURPOSE
#   Before you can say "the app leaks data", you have to be able to enumerate
#   where the app's data could possibly be. Nearly every incomplete storage
#   assessment in the wild is incomplete for the same reason: the tester recursed
#   /data/data and stopped. That misses device-encrypted storage, which is a
#   different tree and not a subdirectory of the credential-encrypted one; it
#   misses the app-specific external directory, which is not protected by the
#   app's uid at all; it misses the media directory, which is indexed and
#   therefore visible to other apps; and it misses the ART profile, the OBB
#   directory and anything the app wrote to a shared collection.
#
#   This script prints the whole map, marks what exists, and for each existing
#   root reports:
#
#       exists / missing / unreadable-without-root
#       owner uid:gid and octal mode
#       SELinux label, including the MCS categories that isolate this app
#       file count and total bytes
#       every world-readable and world-writable file inside it
#       whether the DAC path to each such file is actually walkable
#
# USAGE
#   # host -- the common case
#   ./storage-map.sh com.example.app
#
#   # a specific device, a secondary user, and a shorter report
#   ./storage-map.sh com.example.app --serial 84f7a024 --user 0 --brief
#
#   # skip the su attempts entirely (useful to see what an unprivileged
#   # attacker on this device could enumerate)
#   ./storage-map.sh com.example.app --no-root
#
#   # also enumerate what this package owns in MediaStore, which the filesystem
#   # cannot tell you
#   ./storage-map.sh com.example.app --media
#
# REQUIREMENTS
#   * adb on PATH, one device attached (or --serial).
#   * Root on the device for the /data roots. Without it the script still runs
#     and prints what shell can see, which on Android 11 is more than people
#     expect -- shell holds ext_data_rw (1078) and can list Android/data.
#   * Nothing else. Pure adb and toybox.
#
# WHAT THIS WILL *NOT* TELL YOU
#   * Whether any of it is a finding. It is a map, not a verdict. A file being
#     world-readable is only a finding if something can reach it, and only
#     matters if what is in it matters. The script reports reachability, and
#     stops there.
#   * Whether another APP can read a world-readable file. That is a DAC answer
#     plus an SELinux answer, and the script only computes the first. Two apps
#     with different MCS categories cannot read each other regardless of mode
#     bits. The labels are printed so you can compare them; a real answer needs
#     a second app, which is what labs/lab-03 builds.
#   * What the app wrote into shared collections (Downloads, DCIM, Pictures).
#     Those files are not under any path derived from the package name. --media
#     asks MediaStore, which does track the owner, and that is the only reliable
#     way to attribute them.
#   * Anything about a second profile or a work profile unless you pass --user.
#
# AUTHORISED TESTING ONLY.

set -u

PKG=""
SERIAL=""
USERID=0
BRIEF=0
NOROOT=0
MEDIA=0

while [ $# -gt 0 ]; do
    case "$1" in
        --serial)  SERIAL="$2"; shift 2 ;;
        --user)    USERID="$2"; shift 2 ;;
        --brief)   BRIEF=1; shift ;;
        --no-root) NOROOT=1; shift ;;
        --media)   MEDIA=1; shift ;;
        -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
        -*)        echo "unknown option: $1" >&2; exit 2 ;;
        *)         PKG="$1"; shift ;;
    esac
done

[ -n "$PKG" ] || { echo "usage: $0 <package> [--serial S] [--user N] [--brief] [--no-root] [--media]" >&2; exit 2; }

ADB="adb"
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

# ---------------------------------------------------------------------------
# Talking to the device.
#
# `adb shell` does NOT preserve the host shell's quoting: it joins its arguments
# with spaces and hands the result to the device's sh. So
#     adb shell su -c "ls -l /data/data"
# arrives as
#     su -c ls -l /data/data
# and su executes only `ls`, silently, with the rest becoming su's own args.
# Chapter 09 documents losing an afternoon to exactly this. Every command below
# is therefore passed as ONE argument with the su quoting written explicitly,
# and every pipeline's exit status is taken from the command we care about
# rather than from the last stage of the pipe.
# ---------------------------------------------------------------------------
sh_dev() {
    $ADB shell "$1" 2>/dev/null
}

# ROOT_FORM is the su argument convention this device wants. Magisk's su takes
# `su -c <command>`; an AOSP emulator's su takes a uid and rejects -c with
# `su: invalid uid/gid '-c'`, which reads exactly like "not rooted". Assuming one
# convention turns a rooted device into a blind run, and every empty result below
# into a false negative. Both are tried, once, and the winner is remembered.
ROOT_FORM=""
if [ "$NOROOT" != "1" ]; then
    case "$($ADB shell 'su -c id' 2>&1)" in
        *uid=0*) ROOT_FORM="-c" ;;
        *) case "$($ADB shell 'su 0 id' 2>&1)" in
               *uid=0*) ROOT_FORM="0" ;;
           esac ;;
    esac
fi

sh_root() {
    if [ "$NOROOT" = "1" ] || [ -z "$ROOT_FORM" ]; then
        sh_dev "$1"
    elif [ "$ROOT_FORM" = "-c" ]; then
        $ADB shell "su -c '$1'" 2>/dev/null
    else
        $ADB shell "su 0 sh -c '$1'" 2>/dev/null
    fi
}

HAVE_ROOT=0
if [ "$NOROOT" != "1" ]; then
    [ "$(sh_root 'id -u' | tr -d '\r')" = "0" ] && HAVE_ROOT=1
fi

MODEL=$(sh_dev 'getprop ro.product.model' | tr -d '\r')
REL=$(sh_dev 'getprop ro.build.version.release' | tr -d '\r')
SDK=$(sh_dev 'getprop ro.build.version.sdk' | tr -d '\r')

echo "=============================================================================="
echo " STORAGE MAP  --  $PKG"
echo "=============================================================================="
echo "  device        $MODEL   Android $REL / API $SDK"
echo "  user          $USERID"
if [ "$HAVE_ROOT" = "1" ]; then
    echo "  privilege     root (su)"
else
    echo "  privilege     shell uid $(sh_dev 'id -u' | tr -d '\r') -- /data roots will be unreadable"
fi

APPID=$(sh_root "dumpsys package $PKG | grep -m1 userId=" | tr -d '\r' | sed 's/.*userId=//' | tr -d ' ')
echo "  app uid       ${APPID:-(not installed?)}"
if ! sh_dev "pm list packages" | tr -d '\r' | grep -qx "package:$PKG"; then
    echo
    echo "  WARNING: pm does not list this package for the current user."
    echo "           Everything below will read as 'missing'. Check the name:"
    echo "             adb shell pm list packages | grep -i <fragment>"
fi
echo

# ---------------------------------------------------------------------------
# The roots. Order matters: the first two are inside the uid sandbox, the next
# three are not, and the last is not app data at all.
# ---------------------------------------------------------------------------
map_root() {
    local label="$1" path="$2" note="$3" needs_root="$4"

    local reader="sh_dev"
    [ "$needs_root" = "1" ] && reader="sh_root"

    local head
    head=$($reader "ls -ldZ $path" | tr -d '\r')

    echo "------------------------------------------------------------------------------"
    printf "%-10s %s\n" "$label" "$path"
    echo "------------------------------------------------------------------------------"
    echo "  $note"
    echo

    if [ -z "$head" ]; then
        if [ "$needs_root" = "1" ] && [ "$HAVE_ROOT" != "1" ]; then
            echo "  UNREADABLE  -- needs root, and this shell does not have it."
            echo "                Absence here is NOT evidence the directory is empty."
        else
            echo "  MISSING     -- the directory does not exist."
            echo "                For CE this means the app has never run; for the"
            echo "                external roots it means the app has never asked for"
            echo "                them (they are created lazily, on first call to"
            echo "                getExternalFilesDir() and friends)."
        fi
        echo
        return
    fi

    echo "  $head"

    local count bytes
    count=$($reader "find $path -type f 2>/dev/null | wc -l" | tr -d '\r ')
    bytes=$($reader "du -sk $path 2>/dev/null | cut -f1" | tr -d '\r ')
    echo
    echo "  files         ${count:-?}"
    echo "  kilobytes     ${bytes:-?}"

    if [ "$BRIEF" = "1" ]; then
        echo
        return
    fi

    echo
    echo "  immediate children:"
    $reader "ls -lda $path/* 2>/dev/null" | tr -d '\r' | sed 's/^/    /' | head -30

    # Every file another uid could open, and whether the path to it is walkable.
    echo
    echo "  world-readable or world-writable files:"
    local wr
    wr=$($reader "find $path -type f \\( -perm -o+r -o -perm -o+w \\) 2>/dev/null" | tr -d '\r')
    if [ -z "$wr" ]; then
        echo "    (none)"
    else
        echo "$wr" | head -40 | while IFS= read -r f; do
            [ -z "$f" ] && continue
            local mode reach dir
            mode=$($reader "stat -c %A $f" | tr -d '\r')
            # Walk every ancestor up to /data or /storage and require o+x on
            # each. This is the difference between a finding and a false
            # positive: open(2) resolves one component at a time, and a single
            # ancestor without o+x makes the file unreachable no matter what its
            # own mode says.
            reach="yes"
            dir=$(dirname "$f")
            while [ "$dir" != "/" ] && [ "$dir" != "." ] && [ "$dir" != "/data" ] && [ "$dir" != "/storage" ]; do
                local dm
                dm=$($reader "stat -c %a $dir" | tr -d '\r ')
                case "$dm" in
                    *1|*3|*5|*7) : ;;
                    "")          reach="unknown"; break ;;
                    *)           reach="no (blocked at $dir mode $dm)"; break ;;
                esac
                dir=$(dirname "$dir")
            done
            echo "    $mode  $f"
            echo "        DAC-reachable by another uid: $reach"
        done
    fi
    echo
}

CE="/data/user/$USERID/$PKG"
DE="/data/user_de/$USERID/$PKG"
EXT="/storage/emulated/$USERID/Android/data/$PKG"
EXTMEDIA="/storage/emulated/$USERID/Android/media/$PKG"
OBB="/storage/emulated/$USERID/Android/obb/$PKG"
PROF="/data/misc/profiles/cur/$USERID/$PKG"

map_root "CE" "$CE" \
  "Credential-encrypted internal storage. getFilesDir(), getCacheDir(), shared_prefs/, databases/.
  Locked until the user unlocks the device once after boot. Inside the uid sandbox.
  /data/data/$PKG is the same directory reached by a second name -- see README 3.2." 1

map_root "DE" "$DE" \
  "Device-encrypted internal storage. createDeviceProtectedStorageContext().
  Readable from the moment /data mounts, BEFORE any unlock. Anything sensitive here is
  available to a before-first-unlock forensic acquisition. See 09-Android-App-Internals 3.11." 1

map_root "EXT" "$EXT" \
  "External app-specific storage. getExternalFilesDir(), getExternalCacheDir().
  No permission needed to write. NOT protected by the app's uid -- on the disk it belongs to
  the media stack. Removed on uninstall. Reachable by MANAGE_EXTERNAL_STORAGE holders." 0

map_root "EXT-MEDIA" "$EXTMEDIA" \
  "getExternalMediaDirs(). Same as above but INDEXED BY MEDIASTORE, so its contents are
  visible to any app holding a media read permission. The worst of both worlds and the one
  people forget." 0

map_root "OBB" "$OBB" \
  "Expansion files. Usually empty outside games." 0

map_root "PROFILE" "$PROF" \
  "ART's execution profile for this app. Not app data, but written during a session, and it
  records which methods ran. See 13-ART." 1

# ---------------------------------------------------------------------------
# Shared collections. Nothing here is under a path derived from the package
# name, so the filesystem cannot attribute it. MediaStore can.
# ---------------------------------------------------------------------------
if [ "$MEDIA" = "1" ]; then
    echo "------------------------------------------------------------------------------"
    echo "MEDIASTORE  --  files this package owns in shared collections"
    echo "------------------------------------------------------------------------------"
    echo "  The filesystem has no idea which app created /sdcard/Download/x.pdf."
    echo "  MediaStore records it in owner_package_name. This is the only reliable"
    echo "  attribution for anything written outside the app's own directories --"
    echo "  and it is also, in itself, a privacy surface: the column tells any"
    echo "  reader which app downloaded which file."
    echo
    sh_dev "content query --uri content://media/external/file --projection _id:_data:owner_package_name:is_pending --where \"owner_package_name='$PKG'\"" \
        | tr -d '\r' | sed 's/^/    /' | head -40
    echo
    echo "  (Empty output means either no rows, or that this shell cannot read the"
    echo "  provider. 'No result found.' is MediaProvider answering; a blank line is not.)"
    echo
fi

echo "=============================================================================="
echo "READ THIS BEFORE WRITING ANYTHING DOWN"
echo "=============================================================================="
cat <<'NOTE'
  1. Every world-readable file above is a CANDIDATE, not a finding. Check three
     things in order: is the DAC path walkable (printed above); do the SELinux
     categories permit the reader (compare the labels -- an app_data_file with
     categories c<N>,c<256+M> is isolated from every other app); and does the
     file contain anything worth reading.

  2. A file at mode 0600 inside the app's own directory is the CORRECT outcome.
     Reporting it as "sensitive data stored in plaintext" without naming an
     adversary who can reach it is the single most common bad storage finding.

  3. The absence of a root above is meaningful only if you had the privilege to
     look. Re-read the privilege line at the top of this report.

  4. This map covers the app's OWN paths. It cannot see what the app wrote into
     Downloads, DCIM or Documents. Run with --media, and read README section 3.7.
NOTE
