#!/bin/sh
# =============================================================================
# pull-apk.sh - resolve a package to its APK(s), pull every split, and hash them
# =============================================================================
#
# WHAT THIS DOES
#   Given a package name (or a fragment of one), this script:
#     1. resolves the fragment to a real package name, offering choices if the
#        fragment matches more than one installed package
#     2. asks the device where that package's APK files live, with 'pm path'
#     3. pulls EVERY path returned, not just base.apk - modern apps installed
#        from an App Bundle are split across several APK files, and analysing
#        only base.apk silently loses native libraries, resources and language
#        assets
#     4. writes them into a per-package output directory
#     5. prints the SHA-256 of each file, because the hash of the binary you
#        analysed is evidence and belongs in your notes and your report
#
# WHY IT EXISTS
#   'adb pull $(adb shell pm path com.foo)' looks like it works and quietly
#   breaks on split APKs, on packages that do not exist, and on paths with
#   carriage returns in them. Every one of those failure modes is handled here,
#   and each is commented so you learn why it is a failure mode at all.
#
# HOW TO RUN
#   sh 00-Introduction/scripts/pull-apk.sh com.example.app
#   sh 00-Introduction/scripts/pull-apk.sh com.example.app ~/work/engagement
#   sh 00-Introduction/scripts/pull-apk.sh calculator            # search term
#   sh 00-Introduction/scripts/pull-apk.sh -s emulator-5554 com.example.app
#
# ARGUMENTS
#   -s <serial>   target a specific device when several are attached
#   <package>     exact package name, or a fragment to search for
#   [outdir]      output root; defaults to ./pulled-apks
#
# EXIT CODES
#   0  at least one APK pulled successfully
#   1  package not found, ambiguous, or pull failed
#   2  bad usage or adb missing
#
# REQUIREMENTS
#   - adb on PATH, one authorised device attached (or -s given)
#   - a POSIX shell; on Windows use Git Bash or WSL
#   - sha256sum, shasum, or openssl for hashing (any one of the three)
#
# SAFETY AND SCOPE
#   Pulling an APK reads a world-readable file from the device. It does not
#   modify anything. Do it only to devices you own and for apps you are
#   permitted to analyse - see ../labs/lab-03-legal-scope-triage.md.
#
# SEE ALSO
#   ../labs/lab-02-first-60-minutes.md
#   ../examples/apk-anatomy.py   - run this on what you just pulled
# =============================================================================

set -u

ADB_TARGET=""
OUTROOT="./pulled-apks"

usage() {
    echo "usage: sh $0 [-s <serial>] <package-name-or-search-term> [output-dir]" >&2
    echo "" >&2
    echo "examples:" >&2
    echo "  sh $0 com.android.calculator2" >&2
    echo "  sh $0 -s emulator-5554 com.example.app ~/work/lab02" >&2
    exit 2
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------

# A hand-rolled loop rather than getopts, because we need to accept an optional
# positional output directory after the package name and getopts stops at the
# first non-option argument anyway.
while [ $# -gt 0 ]; do
    case "$1" in
        -s)
            [ $# -ge 2 ] || usage
            ADB_TARGET="-s $2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "ERROR: unknown option: $1" >&2
            usage
            ;;
        *)
            break
            ;;
    esac
done

[ $# -ge 1 ] || usage
QUERY="$1"
[ $# -ge 2 ] && OUTROOT="$2"

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

adb_run() {
    # shellcheck disable=SC2086  # ADB_TARGET must word-split into two tokens
    adb $ADB_TARGET "$@"
}

# adb's shell adds a carriage return to every line. Left in place it corrupts
# path comparisons and produces filenames with an invisible CR in them, which is
# maddening to debug. Strip it from everything that comes off the device.
strip_cr() {
    tr -d '\r'
}

# Pick whichever SHA-256 implementation this machine has. Linux has sha256sum,
# macOS has shasum, and almost everything has openssl.
sha256_of() {
    file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$file" | sed 's/.*= //'
    else
        echo "(no sha256 tool found: install coreutils or openssl)"
    fi
}

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------

if ! command -v adb >/dev/null 2>&1; then
    echo "ERROR: adb is not on your PATH." >&2
    echo "       See ../labs/lab-01-build-your-lab.md" >&2
    exit 2
fi

DEVICE_COUNT=$(adb devices | tail -n +2 | grep -c '[[:space:]]device$' || true)
if [ "${DEVICE_COUNT:-0}" -eq 0 ]; then
    echo "ERROR: no authorised device attached." >&2
    echo "       'adb devices' shows:" >&2
    adb devices >&2
    exit 1
fi
if [ "${DEVICE_COUNT:-0}" -gt 1 ] && [ -z "$ADB_TARGET" ]; then
    echo "ERROR: ${DEVICE_COUNT} devices attached. Choose one with -s <serial>:" >&2
    adb devices >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Step 1 - resolve the query to exactly one package name
# -----------------------------------------------------------------------------

echo "[*] Resolving '${QUERY}' ..."

# Ask the package manager for every package, strip the 'package:' prefix, and
# filter. We do the filtering on the HOST rather than passing a filter to pm,
# because pm's own filtering is a substring match with surprising behaviour and
# it is not available on every Android version.
ALL_PACKAGES=$(adb_run shell pm list packages 2>/dev/null | strip_cr | sed 's/^package://' | sort)

if [ -z "$ALL_PACKAGES" ]; then
    echo "ERROR: 'pm list packages' returned nothing. Is the device unlocked?" >&2
    exit 1
fi

# First try an exact match. A user who typed a full package name should never be
# forced through a disambiguation prompt just because it is a prefix of another.
PACKAGE=$(printf '%s\n' "$ALL_PACKAGES" | grep -x -F "$QUERY" || true)

if [ -z "$PACKAGE" ]; then
    # No exact match: treat the argument as a case-insensitive substring search.
    #
    # This is done with a shell 'case' rather than 'grep -i -F' on purpose.
    # Combining -i and -F is not reliable across every grep build in the wild,
    # and a plain 'grep -i' would treat the query as a regular expression - so
    # the dots in a package name would match any character and quietly produce
    # false matches. Lowercasing both sides and using a glob is exact, portable,
    # and needs no external program.
    QUERY_LC=$(printf '%s' "$QUERY" | tr '[:upper:]' '[:lower:]')
    MATCHES=$(printf '%s\n' "$ALL_PACKAGES" | while IFS= read -r candidate; do
        [ -z "$candidate" ] && continue
        candidate_lc=$(printf '%s' "$candidate" | tr '[:upper:]' '[:lower:]')
        case "$candidate_lc" in
            *"$QUERY_LC"*) printf '%s\n' "$candidate" ;;
        esac
    done)
    MATCH_COUNT=$(printf '%s' "$MATCHES" | grep -c . || true)

    if [ "${MATCH_COUNT:-0}" -eq 0 ]; then
        echo "ERROR: no installed package matches '${QUERY}'." >&2
        echo "" >&2
        echo "Hints:" >&2
        echo "  * package names are case-sensitive and are NOT the app's display name" >&2
        echo "  * list user-installed apps with:  adb shell pm list packages -3" >&2
        echo "  * the app may be installed for a different Android user profile;" >&2
        echo "    try:  adb shell pm list packages --user 10" >&2
        exit 1
    elif [ "${MATCH_COUNT:-0}" -gt 1 ]; then
        echo "ERROR: '${QUERY}' matches ${MATCH_COUNT} packages. Be more specific:" >&2
        printf '%s\n' "$MATCHES" | sed 's/^/    /' >&2
        exit 1
    fi
    PACKAGE="$MATCHES"
fi

echo "[+] Package: ${PACKAGE}"

# -----------------------------------------------------------------------------
# Step 2 - ask where its APK files are
# -----------------------------------------------------------------------------

# 'pm path' prints one 'package:<path>' line per APK belonging to the package.
# A single line means a monolithic APK. Several lines mean the app was installed
# as splits: a base.apk plus configuration splits for density, language, and
# ABI. Pulling only base.apk is the classic silent mistake this script exists to
# prevent.
PATHS=$(adb_run shell pm path "$PACKAGE" 2>/dev/null | strip_cr | sed 's/^package://' | grep -v '^[[:space:]]*$' || true)

if [ -z "$PATHS" ]; then
    echo "ERROR: 'pm path ${PACKAGE}' returned no paths." >&2
    echo "       The package is listed but has no APK the shell user can see." >&2
    echo "       This happens with packages installed for another user profile," >&2
    echo "       and with some system packages on hardened builds." >&2
    exit 1
fi

PATH_COUNT=$(printf '%s\n' "$PATHS" | grep -c . || true)
echo "[+] ${PATH_COUNT} APK path(s) on device:"
printf '%s\n' "$PATHS" | sed 's/^/      /'

if [ "${PATH_COUNT:-1}" -gt 1 ]; then
    echo ""
    echo "    NOTE: this is a SPLIT installation. All of these files together"
    echo "    constitute the application. Analysing base.apk alone will miss"
    echo "    native libraries, resources, and localised strings."
fi

# -----------------------------------------------------------------------------
# Step 3 - create the output directory
# -----------------------------------------------------------------------------

OUTDIR="${OUTROOT}/${PACKAGE}"
mkdir -p "$OUTDIR" || {
    echo "ERROR: cannot create ${OUTDIR}" >&2
    exit 1
}
echo ""
echo "[*] Output directory: ${OUTDIR}"

# -----------------------------------------------------------------------------
# Step 4 - pull every path
# -----------------------------------------------------------------------------

PULLED=0
FAILED=0
MANIFEST="${OUTDIR}/PULLED.txt"

# Record provenance alongside the files. Six months from now, "where did this
# APK come from and when" is a question you will be asked and will not remember.
{
    echo "package      : ${PACKAGE}"
    echo "pulled at    : $(date -u '+%Y-%m-%dT%H:%M:%SZ') UTC"
    echo "device       : $(adb_run shell getprop ro.product.model 2>/dev/null | strip_cr)"
    echo "android      : $(adb_run shell getprop ro.build.version.release 2>/dev/null | strip_cr) (API $(adb_run shell getprop ro.build.version.sdk 2>/dev/null | strip_cr))"
    echo "fingerprint  : $(adb_run shell getprop ro.build.fingerprint 2>/dev/null | strip_cr)"
    echo "abi          : $(adb_run shell getprop ro.product.cpu.abi 2>/dev/null | strip_cr)"
    echo ""
    echo "files:"
} > "$MANIFEST"

echo ""
# Read the path list line by line. A 'while read' over a here-document keeps the
# loop in the current shell, so PULLED and FAILED survive the loop - piping into
# 'while' would run it in a subshell and the counters would reset to zero.
while IFS= read -r devpath; do
    [ -z "$devpath" ] && continue

    # Use the file's own basename so splits keep their distinguishing names
    # (base.apk, split_config.arm64_v8a.apk, split_config.en.apk, ...).
    fname=$(basename "$devpath")

    # If two paths somehow share a basename, disambiguate rather than silently
    # overwriting - overwriting evidence is worse than an ugly filename.
    dest="${OUTDIR}/${fname}"
    n=1
    while [ -e "$dest" ]; do
        dest="${OUTDIR}/$(printf '%s' "$fname" | sed 's/\.apk$//').${n}.apk"
        n=$((n + 1))
    done

    printf '[*] Pulling %s\n' "$devpath"
    if adb_run pull "$devpath" "$dest" >/dev/null 2>&1; then
        size=$(wc -c < "$dest" | tr -d ' ')
        hash=$(sha256_of "$dest")
        printf '    -> %s\n' "$dest"
        printf '       size   : %s bytes\n' "$size"
        printf '       sha256 : %s\n' "$hash"
        printf '  %s\n    device path : %s\n    size        : %s bytes\n    sha256      : %s\n' \
            "$(basename "$dest")" "$devpath" "$size" "$hash" >> "$MANIFEST"
        PULLED=$((PULLED + 1))
    else
        printf '    !! FAILED to pull %s\n' "$devpath"
        printf '       Most likely: the file is not readable by the shell user.\n'
        printf '       Installed APKs under /data/app are world-readable; some\n'
        printf '       vendor and system paths are not.\n'
        printf '  FAILED: %s\n' "$devpath" >> "$MANIFEST"
        FAILED=$((FAILED + 1))
    fi
done <<EOF
$PATHS
EOF

# -----------------------------------------------------------------------------
# Step 5 - report
# -----------------------------------------------------------------------------

echo ""
echo "==============================================================================="
echo " ${PACKAGE}"
echo "==============================================================================="
echo " pulled : ${PULLED}"
echo " failed : ${FAILED}"
echo " output : ${OUTDIR}"
echo " record : ${MANIFEST}"
echo "==============================================================================="

if [ "$PULLED" -eq 0 ]; then
    echo "ERROR: nothing was pulled." >&2
    exit 1
fi

echo ""
echo "Next steps:"
echo "  python3 00-Introduction/examples/apk-anatomy.py ${OUTDIR}/base.apk"
echo "  apktool d ${OUTDIR}/base.apk -o ${OUTDIR}/decoded"
echo "  jadx -d ${OUTDIR}/out ${OUTDIR}/base.apk"
echo ""
echo "Record the sha256 values above in your engagement notes. The hash is how"
echo "you prove, later, which binary your findings were made against."

exit 0
