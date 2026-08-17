#!/usr/bin/env bash
# scripts/fastboot-recon.sh
#
# PURPOSE
#   Non-destructive reconnaissance of a device that is ALREADY in fastboot mode,
#   plus an offline audit of your host's fastboot tooling that needs no device
#   at all.
#
#   It issues only `getvar` reads and `flashing get_unlock_ability`. It contains
#   a hard allow-list, and it will refuse to run any command not on that list --
#   including if you edit the variable list to try to smuggle one in. There is
#   no flag, environment variable or argument that makes this script flash,
#   erase, format, boot, unlock, lock or reboot anything. That is a deliberate
#   design property, not an oversight.
#
# USAGE
#   ./scripts/fastboot-recon.sh --host-audit
#       No device needed. Reports your fastboot version, the getvar names the
#       shipped binary knows, the five protocol response prefixes, and the
#       helper binaries that `fastboot format` depends on. This is how the
#       tables in chapter 61 section 3.3 and section 8.3 were produced.
#
#   ./scripts/fastboot-recon.sh
#       Full read-only recon of an attached fastboot-mode device.
#
#   ./scripts/fastboot-recon.sh -s SERIAL      # target one device
#   ./scripts/fastboot-recon.sh -o recon.txt   # also write a transcript
#   ./scripts/fastboot-recon.sh -p PARTITION   # additionally probe one partition
#
# BEFORE YOU RUN THE DEVICE MODE
#   Putting a device into fastboot mode is itself a state change: it interrupts
#   the boot, may consume a bootloader control block message, and returns an
#   encrypted device to its pre-unlock state. Do it only on a device you own or
#   are explicitly authorised to reboot. This script will NOT put a device into
#   fastboot mode for you.
#
# REQUIREMENTS
#   `fastboot` on PATH. On Linux, a device in fastboot mode usually needs a udev
#   rule or root for the host to claim the USB interface; "no permissions" from
#   `fastboot devices` means that, not a device fault.
#
# EXIT CODES
#   0 completed
#   1 fastboot missing, or no device in fastboot mode
#   2 an internal safety check refused a command (should never happen)

set -uo pipefail

SERIAL=""
OUTFILE=""
EXTRA_PART=""
HOST_ONLY=0

while [ $# -gt 0 ]; do
    case "$1" in
        -s) SERIAL="$2"; shift 2 ;;
        -o) OUTFILE="$2"; shift 2 ;;
        -p) EXTRA_PART="$2"; shift 2 ;;
        --host-audit) HOST_ONLY=1; shift ;;
        -h|--help) sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

command -v fastboot >/dev/null 2>&1 || {
    echo "fastboot not found on PATH." >&2
    echo "Install Google's platform-tools; do NOT use a distro package that is" >&2
    echo "years old -- protocol features and partition names have changed." >&2
    exit 1
}

[ -n "$OUTFILE" ] && exec > >(tee "$OUTFILE") 2>&1

hr()      { printf '%s\n' "------------------------------------------------------------------"; }
section() { echo; hr; echo "== $*"; hr; }
kv()      { printf '  %-30s %s\n' "$1" "${2:-<no answer>}"; }
note()    { printf '  ... %s\n' "$*"; }

FB=(fastboot)
[ -n "$SERIAL" ] && FB=(fastboot -s "$SERIAL")

# ---------------------------------------------------------------------------
# The safety gate. Every device command goes through this function, and this
# function only permits reads.
# ---------------------------------------------------------------------------

# Verbs that may ever reach a device from this script.
is_allowed() {
    case "$1" in
        getvar) return 0 ;;
        flashing)
            # ONLY the read. Not lock, unlock, lock_critical, unlock_critical.
            [ "${2:-}" = "get_unlock_ability" ] && return 0
            return 1 ;;
        *) return 1 ;;
    esac
}

run_fb() {
    if ! is_allowed "$@"; then
        echo "REFUSED by the safety gate: 'fastboot $*'" >&2
        echo "This script only issues reads. If you need a destructive command," >&2
        echo "type it yourself, deliberately, having read chapter 61." >&2
        exit 2
    fi
    "${FB[@]}" "$@" 2>&1
}

# `fastboot getvar X` prints "X: value" on stdout/stderr plus a timing line.
getvar() {
    run_fb getvar "$1" | sed -n "s/^$1: //p" | head -1 | tr -d '\r'
}

# ---------------------------------------------------------------------------
# Host audit -- needs no device
# ---------------------------------------------------------------------------

host_audit() {
    section "Host tooling"
    kv "fastboot binary" "$(command -v fastboot)"
    fastboot --version 2>&1 | sed 's/^/  /'

    FBBIN="$(command -v fastboot)"
    # Git Bash resolves `fastboot` to a path with no .exe, which bash can stat
    # but a native tool cannot open. Prefer the real filename when it exists.
    [ -f "${FBBIN}.exe" ] && FBBIN="${FBBIN}.exe"

    # Two Windows/Git-Bash traps are handled here. Both cost real time the first
    # time you meet them, and both fail INVISIBLY -- the report fills up with
    # "not found" against a binary that plainly contains every string:
    #
    #  1. NATIVE TOOLS CANNOT OPEN AN MSYS PATH. `command -v fastboot` yields
    #     /c/Program Files (x86)/... which bash's own `[ -f ]` accepts happily,
    #     while a Windows python or Windows `strings` reports "No such file".
    #     `cygpath -w` is the fix; this repository has hit the same trap with
    #     the SDK build tools.
    #  2. SYSINTERNALS `strings.exe` emits a banner and CRLF line endings, so an
    #     anchored grep matches nothing -- "OKAY\r" is not "OKAY". Hence tr -d.
    FBNATIVE="$FBBIN"
    if command -v cygpath >/dev/null 2>&1; then
        FBNATIVE="$(cygpath -w "$FBBIN" 2>/dev/null || echo "$FBBIN")"
    fi

    # Python first, deliberately: exact, portable, and it never disagrees with
    # itself across platforms. `strings` is the fallback.
    STR=""
    if command -v python3 >/dev/null 2>&1; then
        STR="$(python3 -c '
import re, sys
d = open(sys.argv[1], "rb").read()
sys.stdout.write("\n".join(m.group().decode("ascii")
                 for m in re.finditer(rb"[\x20-\x7e]{4,}", d)))
' "$FBNATIVE" 2>/dev/null)"
    fi
    if [ -z "$STR" ] && command -v strings >/dev/null 2>&1; then
        STR="$(strings -a "$FBNATIVE" 2>/dev/null | tr -d '\r')"
        [ -z "$STR" ] && STR="$(strings "$FBBIN" 2>/dev/null | tr -d '\r')"
    fi
    # A banner-only capture is not a successful extraction. Require a string
    # every fastboot binary contains before trusting the result.
    #
    # This is a `case` and not `grep -q` on purpose, and the reason is a trap
    # worth knowing: under `set -o pipefail`, `printf ... | grep -q PATTERN`
    # can report FAILURE on a SUCCESSFUL match. grep -q exits the instant it
    # matches, printf then dies on SIGPIPE, and pipefail propagates printf's
    # non-zero status as the pipeline's. The check inverts itself exactly when
    # it should pass. A shell glob has no pipe and no such hazard.
    case "$STR" in
        *max-download-size*) ;;
        *) STR="" ;;
    esac

    if [ -z "$STR" ]; then
        section "Binary extraction"
        note "Could not extract strings from $FBBIN."
        note "Install GNU binutils' strings, or python3, and re-run."
    else
        section "getvar names this binary knows"
        note "Extracted from the shipped binary, not copied from documentation."
        printf '%s\n' "$STR" | grep -E \
'^(max-download-size|partition-type:|partition-size:|slot-count|current-slot|has-slot:|is-userspace|is-logical:|super-partition-name|snapshot-update-status|serialno|product|secure|unlocked|version|version-bootloader|version-baseband|logical-block-size|erase-block-size|off-mode-charge|battery-voltage|hw-revision|variant)$' \
            | sort -u | sed 's/^/    /'

        section "Protocol response prefixes"
        note "The five four-byte prefixes every fastboot response begins with."
        note "INFO and TEXT do NOT end a transaction; the host keeps reading."
        # grep -c and not grep -q: -c reads all of its input, so there is no
        # early exit, no SIGPIPE on the writer, and no pipefail interaction.
        # See the longer note on that trap further up.
        for p in OKAY FAIL DATA INFO TEXT; do
            exact="$(printf '%s\n' "$STR" | grep -cx -- "$p" || true)"
            anywhere="$(printf '%s\n' "$STR" | grep -c -- "$p" || true)"
            if [ "${exact:-0}" -gt 0 ]; then
                printf '    %-6s present as a standalone string\n' "$p"
            elif [ "${anywhere:-0}" -gt 0 ]; then
                printf '    %-6s present, inside a longer run (%s hits)\n' "$p" "$anywhere"
            else
                printf '    %-6s not found\n' "$p"
            fi
        done
        note "A four-byte token often sits adjacent to other printable bytes, so"
        note "'inside a longer run' is the expected result for most of them and"
        note "is not a negative finding. All five are defined by the protocol."

        section "vbmeta rewriting"
        note "Proof that --disable-verity edits the vbmeta header in place"
        note "rather than asking the device to do anything special:"
        printf '%s\n' "$STR" | grep -i 'Rewriting vbmeta struct' | sed 's/^/    /'
        note "That edit invalidates the image's own AVB hash -- demonstrate it"
        note "with: python3 -B scripts/vbmeta-flags.py set vbmeta.img out.img --disable-verity"

        section "Helper binaries that 'fastboot format' shells out to"
        note "'format' builds the filesystem ON THE HOST and then flashes it."
        printf '%s\n' "$STR" | grep -E '^/?(mke2fs|make_f2fs)|MKE2FS_CONFIG' \
            | sort -u | head -10 | sed 's/^/    /'
        echo
        for helper in mke2fs make_f2fs; do
            found="$(ls "$(dirname "$FBBIN")"/${helper}* 2>/dev/null | head -3)"
            if [ -n "$found" ]; then
                echo "$found" | sed 's/^/    present: /'
            else
                printf '    MISSING: %s -- `fastboot format` will fail with an\n' "$helper"
                printf '             error that looks like it came from the device.\n'
            fi
        done
    fi

    section "Destructive commands this script will never issue"
    cat <<'EOF'
    flash          flash:raw      flashall       update
    erase          format         wipe-super     set_active
    boot           continue       reboot         oem
    flashing lock  flashing unlock
    flashing lock_critical        flashing unlock_critical
    create-logical-partition      delete-logical-partition
    resize-logical-partition      snapshot-update

  Each of the above changes device state; several destroy data; two can brick a
  device outright. They are documented in chapter 61 -- but you type them, not
  this script.
EOF
}

host_audit
[ "$HOST_ONLY" = 1 ] && { echo; hr; echo "host audit complete (no device contacted)"; exit 0; }

# ---------------------------------------------------------------------------
# Device recon
# ---------------------------------------------------------------------------

section "Devices in fastboot mode"
DEVS="$("${FB[@]}" devices -l 2>&1 | tr -d '\r')"
if [ -z "$(echo "$DEVS" | tr -d '[:space:]')" ]; then
    cat <<'EOF'
  No device in fastboot mode.

  Note that this is SILENT SUCCESS, not an error: `fastboot devices` with
  nothing attached prints nothing and exits 0 (measured). If you expected a
  device here, check in this order:

    1. Is it actually in fastboot mode? A device running Android is invisible
       to fastboot -- it uses a different USB interface. `adb devices` and
       `fastboot devices` are mutually exclusive views of the same cable.
    2. Is the cable a DATA cable? A charge-only cable enumerates power and
       nothing else, and produces exactly this symptom.
    3. On Linux: do you have a udev rule, or are you root? Missing permissions
       usually show as "no permissions" but can show as nothing at all.
    4. On Windows: is the bootloader interface driver bound?

  For an offline audit that needs no device:  ./scripts/fastboot-recon.sh --host-audit
EOF
    exit 1
fi
echo "$DEVS" | sed 's/^/    /'

section "Identity"
for v in product serialno variant hw-revision version version-bootloader version-baseband; do
    kv "$v" "$(getvar "$v")"
done

section "Lock state -- SELF-REPORTED by the bootloader"
UNLOCKED="$(getvar unlocked)"
SECURE="$(getvar secure)"
kv "unlocked" "$UNLOCKED"
kv "secure"   "$SECURE"
echo
UA="$(run_fb flashing get_unlock_ability | tr -d '\r')"
echo "  flashing get_unlock_ability:"
echo "$UA" | sed 's/^/    /'
echo
case "$UNLOCKED" in
    yes) note "VERDICT: bootloader reports UNLOCKED. Verified Boot is advisory"
         note "         here; flash/erase/boot are accepted." ;;
    no)  note "VERDICT: bootloader reports LOCKED. flash, erase, format and boot"
         note "         will all be refused, which is the correct behaviour." ;;
    *)   note "VERDICT: no answer. Some bootloaders do not implement 'unlocked';"
         note "         try 'fastboot getvar all' and look for a vendor spelling." ;;
esac
echo
note "This is the bootloader answering a question about itself. On a device"
note "whose bootloader has been replaced, it says whatever the replacement"
note "says. The non-forgeable version is the deviceLocked field inside a"
note "hardware key attestation -- see 50-HardwareBackedSecurity."

section "Download buffer and slots"
MAXDL="$(getvar max-download-size)"
kv "max-download-size" "$MAXDL"
if [ -n "$MAXDL" ]; then
    DEC="$(printf '%d' "$MAXDL" 2>/dev/null || echo "")"
    [ -n "$DEC" ] && note "= $DEC bytes = $((DEC / 1024 / 1024)) MiB. Images larger than this"
    [ -n "$DEC" ] && note "  are split into several sparse images (chapter 61 section 3.5)."
fi
echo
for v in slot-count current-slot is-userspace super-partition-name snapshot-update-status; do
    kv "$v" "$(getvar "$v")"
done
echo
IUS="$(getvar is-userspace)"
case "$IUS" in
    yes) note "You are talking to fastbootd (userspace). It can flash LOGICAL"
         note "partitions but CANNOT change the lock state." ;;
    no)  note "You are talking to the BOOTLOADER. It owns the lock state but"
         note "cannot flash logical partitions inside super." ;;
    *)   note "No is-userspace answer -- likely a pre-Android-10 bootloader." ;;
esac
echo
SUS="$(getvar snapshot-update-status)"
if [ -n "$SUS" ] && [ "$SUS" != "none" ]; then
    note "WARNING: snapshot-update-status is '$SUS', not 'none'."
    note "         A virtual A/B update is staged or merging. Flashing now is"
    note "         one of the reliable ways to need a full factory image."
fi

section "Storage geometry"
for v in logical-block-size erase-block-size off-mode-charge battery-voltage; do
    kv "$v" "$(getvar "$v")"
done

section "Partition probe"
PARTS="boot init_boot recovery vbmeta vbmeta_system dtbo super system vendor product misc"
[ -n "$EXTRA_PART" ] && PARTS="$PARTS $EXTRA_PART"
printf '  %-16s %-10s %-14s %-20s %s\n' "partition" "has-slot" "is-logical" "size" "type"
for p in $PARTS; do
    HS="$(getvar "has-slot:$p")"
    IL="$(getvar "is-logical:$p")"
    SZ="$(getvar "partition-size:$p")"
    TY="$(getvar "partition-type:$p")"
    [ -z "$HS$IL$SZ$TY" ] && continue
    printf '  %-16s %-10s %-14s %-20s %s\n' "$p" "${HS:--}" "${IL:--}" "${SZ:--}" "${TY:--}"
done
echo
note "is-logical=yes means the partition lives inside 'super' and can only be"
note "flashed from fastbootd. The host tool reboots you there automatically."
note "has-slot=yes means you must think about which slot you are targeting."

section "Everything the bootloader will name"
note "getvar all answers as a stream of INFO lines then a final OKAY."
note "It is not guaranteed complete -- a bootloader may implement variables it"
note "does not enumerate. Vendor-specific names here are the interesting part."
run_fb getvar all | sed 's/^/    /'

section "Next steps -- and what this script will not do"
cat <<'EOF'
  Read-only follow-up:
    - Boot the device normally and run ./scripts/bootstate-audit.sh, which sees
      far more than fastboot mode exposes.
    - Pull a hardware key attestation (50-HardwareBackedSecurity) and compare
      deviceLocked against the 'unlocked' value above. Disagreement is a finding.
    - `fastboot oem help` on some devices enumerates the vendor command surface.
      That IS a read on most implementations -- but `oem` is vendor-defined with
      no specification, so this script will not issue it for you. If you run it,
      know that you are invoking undocumented code.

  Anything that writes -- unlock, flash, erase, format, boot, set_active -- is
  yours to type, on a device you own, having read chapter 61 and downloaded the
  matching factory image first.
EOF

echo
hr
echo "recon complete -- no device state was modified"
