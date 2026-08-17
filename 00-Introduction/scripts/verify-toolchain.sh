#!/bin/sh
# =============================================================================
# verify-toolchain.sh - prove your Android security workstation actually works
# =============================================================================
#
# WHAT THIS DOES
#   Checks for every tool Lab 01 installs, prints a PASS/FAIL table with the
#   detected version of each, and prints a platform-appropriate install hint for
#   anything missing. It also warns about the two environment problems that
#   cause the most wasted hours: an unset or wrong JAVA_HOME, and a Python
#   virtualenv that is not activated.
#
# WHY IT EXISTS
#   Nearly every "Frida doesn't work" report is really a toolchain problem, and
#   the error message never says so. Running one command that either says
#   "everything is fine" or names the exact broken thing removes an entire class
#   of wasted evening.
#
# HOW TO RUN
#   sh 00-Introduction/scripts/verify-toolchain.sh
#   sh 00-Introduction/scripts/verify-toolchain.sh --quiet    # table only
#
#   On Windows use Git Bash or WSL. PowerShell cannot run this file directly.
#
# EXIT CODES
#   0  every CRITICAL tool is present
#   1  at least one CRITICAL tool is missing
#   2  bad usage
#
#   Critical tools are java, adb, python3, and unzip: without them nothing in
#   this repository works. frida, jadx, and apktool are reported as WARN when
#   missing, because you can complete Lab 02's first half without them.
#
# REQUIREMENTS
#   A POSIX shell (sh, dash, bash, zsh). No other dependencies - deliberately,
#   because this script must run on a machine where nothing is installed yet.
#
# SEE ALSO
#   ../labs/lab-01-build-your-lab.md
# =============================================================================

set -u

QUIET=0
if [ "${1:-}" = "--quiet" ]; then
    QUIET=1
elif [ -n "${1:-}" ]; then
    echo "usage: sh $0 [--quiet]" >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Platform detection - so install hints match the machine the user is on
# -----------------------------------------------------------------------------

case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux*)             PLATFORM="linux" ;;
    Darwin*)            PLATFORM="macos" ;;
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows" ;;
    *)                  PLATFORM="unknown" ;;
esac

# Return the install hint appropriate to this platform for a given tool.
hint_for() {
    tool="$1"
    case "$tool:$PLATFORM" in
        java:linux)       echo "sudo apt install -y openjdk-21-jdk" ;;
        java:macos)       echo "brew install --cask temurin@21" ;;
        java:windows)     echo "winget install --id EclipseAdoptium.Temurin.21.JDK -e" ;;
        adb:linux)        echo "sudo apt install -y android-sdk-platform-tools" ;;
        adb:macos)        echo "brew install --cask android-platform-tools" ;;
        adb:windows)      echo "winget install --id Google.PlatformTools -e" ;;
        python3:linux)    echo "sudo apt install -y python3 python3-pip python3-venv" ;;
        python3:macos)    echo "brew install python@3.12" ;;
        python3:windows)  echo "winget install --id Python.Python.3.12 -e" ;;
        frida:*)          echo "pip install frida-tools   (inside your virtualenv)" ;;
        jadx:linux)       echo "download the release ZIP from the jadx project and add bin/ to PATH" ;;
        jadx:macos)       echo "brew install jadx" ;;
        jadx:windows)     echo "choco install jadx -y" ;;
        apktool:linux)    echo "sudo apt install -y apktool" ;;
        apktool:macos)    echo "brew install apktool" ;;
        apktool:windows)  echo "choco install apktool -y" ;;
        unzip:linux)      echo "sudo apt install -y unzip" ;;
        unzip:macos)      echo "unzip ships with macOS; check your PATH" ;;
        unzip:windows)    echo "choco install unzip -y  (or use PowerShell's Expand-Archive)" ;;
        *)                echo "see ../labs/lab-01-build-your-lab.md" ;;
    esac
}

# -----------------------------------------------------------------------------
# Result accumulation
# -----------------------------------------------------------------------------

CRITICAL_MISSING=0
OPTIONAL_MISSING=0
ROWS=""

# Append one row to the buffered table. Fields are separated by a vertical bar
# because no version string or path contains one.
add_row() {
    ROWS="${ROWS}$1|$2|$3|$4
"
}

# extract_version <command...>
#   Runs a version command and reduces its output to a single readable line.
#   Version commands are wildly inconsistent: some print to stdout, some to
#   stderr, some print a banner first. We merge both streams, take the first
#   non-empty line, and trim it.
extract_version() {
    out=$("$@" 2>&1 </dev/null | tr -d '\r' | grep -m1 -v '^[[:space:]]*$')
    if [ -z "$out" ]; then
        echo "(no version output)"
    else
        # Trim to a sensible width so the table stays aligned.
        echo "$out" | cut -c1-46
    fi
}

# check <name> <critical:yes|no> <command...>
check() {
    name="$1"; shift
    critical="$1"; shift
    binary="$1"

    if command -v "$binary" >/dev/null 2>&1; then
        version=$(extract_version "$@")
        add_row "$name" "PASS" "$version" "$(command -v "$binary")"
    else
        if [ "$critical" = "yes" ]; then
            CRITICAL_MISSING=$((CRITICAL_MISSING + 1))
            add_row "$name" "FAIL" "not on PATH" "$(hint_for "$name")"
        else
            OPTIONAL_MISSING=$((OPTIONAL_MISSING + 1))
            add_row "$name" "WARN" "not on PATH" "$(hint_for "$name")"
        fi
    fi
}

# -----------------------------------------------------------------------------
# The checks
# -----------------------------------------------------------------------------

# java: 'java -version' famously writes to STDERR, which is why extract_version
# merges the streams. javac is checked separately below because having java but
# not javac means a JRE was installed instead of a JDK.
check java    yes java    -version
check adb     yes adb     version
check unzip   yes unzip   -v

# python3 does not exist as a name on some Windows installs, where the binary is
# 'python'. Try both before declaring failure.
if command -v python3 >/dev/null 2>&1; then
    check python3 yes python3 --version
elif command -v python >/dev/null 2>&1; then
    check python3 yes python --version
else
    CRITICAL_MISSING=$((CRITICAL_MISSING + 1))
    add_row "python3" "FAIL" "not on PATH" "$(hint_for python3)"
fi

check frida   no  frida   --version
check jadx    no  jadx    --version
check apktool no  apktool --version

# -----------------------------------------------------------------------------
# Render the table
# -----------------------------------------------------------------------------

FMT="%-10s %-6s %-48s %s\n"

echo ""
echo "==============================================================================="
echo " TOOLCHAIN VERIFICATION - platform: $PLATFORM"
echo "==============================================================================="
printf "$FMT" "TOOL" "STATUS" "VERSION / PROBLEM" "PATH OR FIX"
echo "-------------------------------------------------------------------------------"

# Read the buffered rows back. IFS is set to the field separator for the
# duration of the read, and '-r' stops backslashes being interpreted.
printf '%s' "$ROWS" | while IFS='|' read -r a b c d; do
    [ -z "$a" ] && continue
    printf "$FMT" "$a" "$b" "$c" "$d"
done

echo "-------------------------------------------------------------------------------"

# -----------------------------------------------------------------------------
# Environment checks - the problems that are not "is it installed"
# -----------------------------------------------------------------------------

if [ "$QUIET" -eq 0 ]; then
    echo ""
    echo "ENVIRONMENT"
    echo "-------------------------------------------------------------------------------"

    # JDK vs JRE. 'javac' is the compiler and ships only with a JDK. jadx and
    # apktool nominally need only a JRE, but the diagnostic tools you will want
    # later, and several build steps, need the JDK.
    if command -v javac >/dev/null 2>&1; then
        echo "  [ok]   javac found - you have a JDK, not just a JRE"
    else
        echo "  [warn] javac NOT found - you installed a JRE. Install a full JDK:"
        echo "         $(hint_for java)"
    fi

    # JAVA_HOME. Many Java tools ignore PATH and read this variable. A stale
    # value pointing at a deleted JDK produces errors that never mention Java.
    if [ -n "${JAVA_HOME:-}" ]; then
        if [ -x "${JAVA_HOME}/bin/java" ]; then
            echo "  [ok]   JAVA_HOME = ${JAVA_HOME}"
        else
            echo "  [warn] JAVA_HOME is set to ${JAVA_HOME}"
            echo "         but ${JAVA_HOME}/bin/java does not exist or is not executable."
            echo "         Point JAVA_HOME at the JDK ROOT - the directory containing bin/,"
            echo "         not bin/ itself."
        fi
    else
        echo "  [warn] JAVA_HOME is not set. Most tools cope, apktool sometimes does not."
    fi

    # Virtualenv. VIRTUAL_ENV is exported by the activate script. If it is unset
    # then 'pip install' writes to the system Python, which is how people end up
    # with a frida the shell cannot find.
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        echo "  [ok]   Python virtualenv active: ${VIRTUAL_ENV}"
    else
        echo "  [warn] No Python virtualenv is active. Frida installs are version-"
        echo "         sensitive; create and activate one before pip install:"
        echo "           python3 -m venv ~/androidsec && . ~/androidsec/bin/activate"
    fi

    # ADB server and connected devices. Not a toolchain failure if nothing is
    # attached, but worth reporting because it is the next thing you will need.
    if command -v adb >/dev/null 2>&1; then
        devs=$(adb devices 2>/dev/null | tail -n +2 | grep -c '[[:space:]]device$' || true)
        unauth=$(adb devices 2>/dev/null | tail -n +2 | grep -c 'unauthorized$' || true)
        if [ "${devs:-0}" -gt 0 ]; then
            echo "  [ok]   ${devs} device(s) attached and authorised"
        elif [ "${unauth:-0}" -gt 0 ]; then
            echo "  [warn] ${unauth} device(s) attached but UNAUTHORIZED."
            echo "         Unlock the device and accept the USB debugging prompt."
        else
            echo "  [info] No device attached. That is fine for a setup check."
        fi
    fi

    # Duplicate adb binaries are a classic cause of 'adb server version doesn't
    # match this client'. We walk PATH by hand rather than using 'which -a' or
    # 'type -a', neither of which is portable across dash, bash and zsh.
    adb_found=""
    adb_dupes=0
    old_ifs=$IFS
    IFS=:
    for dir in $PATH; do
        [ -z "$dir" ] && dir="."
        # Count at most one hit per directory. On Windows shells "adb" and
        # "adb.exe" resolve to the same file, so counting both would report a
        # duplicate that does not exist.
        for candidate in "$dir/adb" "$dir/adb.exe"; do
            if [ -x "$candidate" ]; then
                adb_dupes=$((adb_dupes + 1))
                adb_found="${adb_found}           ${candidate}
"
                break
            fi
        done
    done
    IFS=$old_ifs

    if [ "$adb_dupes" -gt 1 ]; then
        echo "  [warn] More than one adb is on your PATH:"
        printf '%s' "$adb_found"
        echo "         The first one wins. Mismatched client/server versions cause"
        echo "         'adb server version (NN) doesn't match this client'."
    fi
fi

# -----------------------------------------------------------------------------
# Verdict
# -----------------------------------------------------------------------------

echo ""
if [ "$CRITICAL_MISSING" -eq 0 ] && [ "$OPTIONAL_MISSING" -eq 0 ]; then
    echo "RESULT: PASS - every tool is present. Continue to:"
    echo "        00-Introduction/labs/lab-02-first-60-minutes.md"
    exit 0
elif [ "$CRITICAL_MISSING" -eq 0 ]; then
    echo "RESULT: PASS with ${OPTIONAL_MISSING} warning(s)."
    echo "        Critical tools are present. Install the WARN rows before Lab 02"
    echo "        step 10 (jadx) and before any patching work (apktool)."
    exit 0
else
    echo "RESULT: FAIL - ${CRITICAL_MISSING} critical tool(s) missing."
    echo "        Fix the FAIL rows above, open a NEW terminal, and run this again."
    echo "        A shell keeps the environment it started with, so an already-open"
    echo "        terminal will not see a PATH change made by an installer."
    exit 1
fi
