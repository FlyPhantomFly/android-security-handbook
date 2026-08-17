#!/usr/bin/env bash
#
# apk-recon.sh — first-contact reconnaissance on an APK you have just pulled
#                off a device, in the order chapter 10 says to do it.
#
# WHAT IT DOES
#   Answers, for one or more APKs, the seven questions from ../README.md
#   section 12 ("the first sixty seconds") and prints them as one report:
#
#     1. Identity        SHA-256, size, first four bytes
#     2. Container       every ZIP-level attack class (../scripts/apk-container-triage.py)
#     3. Signing         which schemes, which certificate, is it the debug key
#     4. Manifest        package, SDK levels, debuggable, exported components
#     5. Contents        where the bulk is, which ABIs, build leftovers
#     6. Findings        the lines worth putting in a report
#     7. Next steps      what to run once this has finished
#
#   Android tooling is used when it is on PATH and the Python parsers in
#   ../examples/ are used when it is not, so the script produces a useful
#   report on a machine with nothing but Python installed. Every section says
#   which route it took, because "aapt2 was not available" changes how much
#   weight section 4 deserves.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - What the platform actually parsed. Everything here reads the FILE. The
#     authority is `adb shell dumpsys package <pkg>` after installing on a
#     device you are willing to install it on. Section 4 says so again.
#   - Whether the app is safe. This is reconnaissance: it tells you what you
#     are holding and where to look next. No section of it is an assessment.
#   - Anything about the code. `classes*.dex` is counted, never read. Use
#     ../../12-DEX-Internals/examples/dex_parser.py and jadx for that.
#   - Anything about splits you did not pull. Run it on EVERY path
#     `adb shell pm path <pkg>` printed, not only base.apk. Section 5 warns
#     when the manifest declares splits and you gave it one file.
#   - Whether a signature is VALID, unless apksigner is installed. The Python
#     fallback reads structure only and says so.
#
# HOW TO RUN
#     # host
#     ./apk-recon.sh base.apk
#     ./apk-recon.sh base.apk split_config.arm64_v8a.apk
#     ./apk-recon.sh *.apk > recon.txt
#     bash apk-recon.sh base.apk          # if the execute bit is missing
#
#   From the chapter directory, exactly as the chapter prints it:
#     bash scripts/apk-recon.sh app.apk
#
# REQUIREMENTS
#   bash, plus python3 for the fallback parsers. Uses, when present:
#   apksigner, aapt2, unzip, zipinfo, sha256sum (or shasum), file, xxd.
#   Nothing is fatal if it is missing.
#
# RELATED
#   ../README.md section 12              the first sixty seconds
#   ../cheatsheet.md                     every command this wraps
#   ../examples/parse_apk_zip.py         the container parser
#   ../examples/parse_signing_block.py   the signing block parser
#   ../examples/parse_axml.py            the manifest parser
#
# AUTHORISED TESTING ONLY.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES="${SCRIPT_DIR}/../examples"

PY="${PYTHON:-}"
if [ -z "$PY" ]; then
    if command -v python3 >/dev/null 2>&1; then
        PY=python3
    elif command -v python >/dev/null 2>&1; then
        PY=python
    fi
fi

have() { command -v "$1" >/dev/null 2>&1; }

rule() { printf '%s\n' "------------------------------------------------------------"; }

section() {
    printf '\n'
    rule
    printf '%s\n' "$1"
    rule
}

note() { printf '  %s\n' "$1"; }

FINDINGS=()
finding() { FINDINGS+=("$1"); }

sha256_of() {
    if have sha256sum; then
        sha256sum "$1" | awk '{print $1}'
    elif have shasum; then
        shasum -a 256 "$1" | awk '{print $1}'
    elif [ -n "$PY" ]; then
        "$PY" -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" "$1"
    else
        echo "(no sha256 tool available)"
    fi
}

size_of() {
    if have stat; then
        stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || wc -c < "$1"
    else
        wc -c < "$1"
    fi
}

head_bytes() {
    if have xxd; then
        head -c 4 "$1" | xxd -p
    elif [ -n "$PY" ]; then
        "$PY" -c "import sys;print(open(sys.argv[1],'rb').read(4).hex())" "$1"
    else
        echo "????????"
    fi
}

# --------------------------------------------------------------------------

recon_one() {
    apk="$1"
    FINDINGS=()

    printf '\n'
    printf '%s\n' "============================================================"
    printf '%s\n' "  APK RECON — ${apk}"
    printf '%s\n' "============================================================"

    # ---- 1. identity ------------------------------------------------------
    section "1. IDENTITY"
    note "path        : ${apk}"
    note "size        : $(size_of "$apk") bytes"
    note "sha256      : $(sha256_of "$apk")"
    magic="$(head_bytes "$apk")"
    note "first 4     : ${magic}"
    if [ "$magic" != "504b0304" ]; then
        note "              ^^ NOT the ZIP local file header signature"
        finding "first four bytes are ${magic}, not 504b0304 — data is prepended (Janus shape, CVE-2017-13156)"
        if [ "$magic" = "6465780a" ]; then
            note "              those bytes are ASCII 'dex\\n' — a DEX is prepended"
        fi
    fi
    if have file; then
        note "file(1)     : $(file -b "$apk")"
    fi

    # ---- 2. container -----------------------------------------------------
    section "2. CONTAINER — ZIP-level attack classes"
    if [ -n "$PY" ] && [ -f "${SCRIPT_DIR}/apk-container-triage.py" ]; then
        "$PY" "${SCRIPT_DIR}/apk-container-triage.py" "$apk" 2>&1 | sed 's/^/  /'
        if "$PY" "${SCRIPT_DIR}/apk-container-triage.py" "$apk" >/dev/null 2>&1; then
            :
        else
            finding "container triage flagged at least one attack class — see section 2"
        fi
    else
        note "python3 not found; falling back to shell checks"
        if have zipinfo; then
            dupes="$(zipinfo -1 "$apk" 2>/dev/null | sort | uniq -d)"
            if [ -n "$dupes" ]; then
                note "duplicate entry names:"
                printf '%s\n' "$dupes" | sed 's/^/    /'
                finding "duplicate entry names present — Master Key class (CVE-2013-4787)"
            else
                note "no duplicate entry names"
            fi
            slip="$(zipinfo -1 "$apk" 2>/dev/null | grep -E '(^/|\.\./)')"
            if [ -n "$slip" ]; then
                note "unsafe entry names:"
                printf '%s\n' "$slip" | sed 's/^/    /'
                finding "entry names contain traversal sequences — ZipSlip shape"
            fi
        else
            note "zipinfo not found either; skipping container checks"
        fi
    fi

    # ---- 3. signing -------------------------------------------------------
    section "3. SIGNING"
    if have apksigner; then
        note "route: apksigner (authoritative — this verifies cryptographically)"
        printf '\n'
        apksigner verify -v --print-certs "$apk" 2>&1 | sed 's/^/  /'
        certs="$(apksigner verify -v --print-certs "$apk" 2>/dev/null)"
        case "$certs" in
            *"CN=Android Debug"*)
                finding "signed with the public Android debug key — anyone can produce updates for this package" ;;
        esac
        v1="$(printf '%s' "$certs" | grep -c 'v1 scheme (JAR signing): true')"
        v2="$(printf '%s' "$certs" | grep -c 'v2 scheme (APK Signature Scheme v2): true')"
        v3="$(printf '%s' "$certs" | grep -c 'v3 scheme (APK Signature Scheme v3): true')"
        if [ "$v1" = "1" ] && [ "$v2" = "0" ] && [ "$v3" = "0" ]; then
            finding "v1-only signing — exposed to the Janus and Master Key classes; require v2+"
        fi
    else
        note "route: structural only (apksigner not on PATH)"
        note "NOTHING BELOW IS VERIFIED. It says which structures exist, not"
        note "that they are valid. Install Android SDK build-tools for the"
        note "real answer: apksigner verify -v --print-certs ${apk}"
        printf '\n'
        if [ -n "$PY" ] && [ -f "${EXAMPLES}/parse_signing_block.py" ]; then
            "$PY" "${EXAMPLES}/parse_signing_block.py" "$apk" 2>&1 | sed 's/^/  /'
        else
            note "(python3 or parse_signing_block.py unavailable)"
        fi
    fi

    if have unzip; then
        v1files="$(unzip -l "$apk" 2>/dev/null | grep -E 'META-INF/.*\.(SF|RSA|DSA|EC)$')"
        if [ -n "$v1files" ]; then
            note ""
            note "v1 material in META-INF:"
            printf '%s\n' "$v1files" | sed 's/^/    /'
        fi
    fi
    if [ -f "${apk}.idsig" ]; then
        note "v4 side file present: ${apk}.idsig"
    fi

    # ---- 4. manifest ------------------------------------------------------
    section "4. MANIFEST"
    if have aapt2; then
        note "route: aapt2 (libandroidfw — the same code the platform uses)"
        printf '\n'
        aapt2 dump badging "$apk" 2>/dev/null | head -25 | sed 's/^/  /'
        printf '\n'
        note "security-relevant attributes:"
        aapt2 dump xmltree "$apk" --file AndroidManifest.xml 2>/dev/null \
            | grep -iE 'debuggable|allowBackup|usesCleartextTraffic|exported|testOnly|networkSecurityConfig' \
            | sed 's/^/    /'
        if aapt2 dump xmltree "$apk" --file AndroidManifest.xml 2>/dev/null \
             | grep -qiE 'debuggable.*0xffffffff'; then
            finding "android:debuggable parses as TRUE — run-as and JDWP give full private data access"
        fi
    elif [ -n "$PY" ] && [ -f "${EXAMPLES}/parse_axml.py" ]; then
        note "route: parse_axml.py (aapt2 not on PATH)"
        printf '\n'
        "$PY" "${EXAMPLES}/parse_axml.py" --extract "$apk" 2>&1 | sed 's/^/  /'
    else
        note "no manifest reader available (need aapt2 or python3)"
    fi
    printf '\n'
    note "THE AUTHORITY IS THE DEVICE. Nothing above proves what"
    note "PackageManager parsed. Once you are willing to install it:"
    note "    adb install -r ${apk}"
    note "    adb shell dumpsys package <package> | grep -E 'flags=|privateFlags='"

    # ---- 5. contents ------------------------------------------------------
    section "5. CONTENTS"
    if have unzip; then
        note "largest entries:"
        unzip -l "$apk" 2>/dev/null | tail -n +4 | sort -k1 -nr | head -12 \
            | sed 's/^/    /'
        printf '\n'
        note "native ABIs:"
        abis="$(unzip -l "$apk" 2>/dev/null | grep -oE 'lib/[^/]+/' | sort -u)"
        if [ -n "$abis" ]; then
            printf '%s\n' "$abis" | sed 's/^/    /'
        else
            note "    none — the app ships no native libraries in this APK"
        fi
        printf '\n'
        note "build leftovers and language markers:"
        leftovers="$(unzip -l "$apk" 2>/dev/null \
            | grep -iE 'mapping\.txt|seeds\.txt|usage\.txt|\.pro$|DebugProbesKt|kotlin/|version-control-info')"
        if [ -n "$leftovers" ]; then
            printf '%s\n' "$leftovers" | sed 's/^/    /'
        else
            note "    none"
        fi
        if unzip -l "$apk" 2>/dev/null | grep -qi 'mapping\.txt'; then
            finding "mapping.txt is packaged in the APK — the obfuscation map has been shipped to the attacker"
        fi
        printf '\n'
        dexcount="$(unzip -l "$apk" 2>/dev/null | grep -cE 'classes[0-9]*\.dex')"
        note "classes*.dex entries: ${dexcount}"
        if [ "$dexcount" = "0" ]; then
            finding "no classes*.dex in this APK — either it is a split, or the code is loaded from elsewhere (packer)"
        fi
    else
        note "unzip not found; skipping the contents census"
    fi

    # ---- 6. findings ------------------------------------------------------
    section "6. FINDINGS WORTH WRITING DOWN"
    if [ "${#FINDINGS[@]}" -eq 0 ]; then
        note "Nothing flagged by this pass."
        note "That is not a clean bill of health. This script reads the"
        note "container, the signature block and the manifest. It has not"
        note "looked at one line of code."
    else
        for f in "${FINDINGS[@]}"; do
            printf '  !! %s\n' "$f"
        done
    fi

    # ---- 7. next ----------------------------------------------------------
    section "7. NEXT STEPS"
    note "a. Pull EVERY split, not just this file:"
    note "     for p in \$(adb shell pm path <pkg> | tr -d '\\r' | sed 's/^package://'); do adb pull \"\$p\" .; done"
    note "b. Read the manifest the platform's way, on a device:"
    note "     adb shell dumpsys package <pkg>"
    note "c. Decompile and read the code:"
    note "     jadx -d out ${apk}      # see ../../40-Obfuscation/README.md if it is packed"
    note "d. Walk the container yourself once, by hand:"
    note "     ../labs/lab-01-dissecting-the-apk-byte-by-byte.md"
    note "e. If any tool disagreed with another about the manifest, that is the"
    note "   finding — see ../labs/lab-04-ctf-the-lying-manifest.md"
    printf '\n'
}

# --------------------------------------------------------------------------

usage() {
    printf '%s\n' "usage: $0 <app.apk> [more.apk ...]"
    printf '%s\n' ""
    printf '%s\n' "Reconnaissance report for one or more APKs. Read the header"
    printf '%s\n' "of this file for what it does and does not tell you."
    exit 2
}

main() {
    [ "$#" -ge 1 ] || usage

    if [ -z "$PY" ]; then
        printf '%s\n' "warning: no python3 on PATH — the fallback parsers in" >&2
        printf '%s\n' "         ../examples/ cannot run. Install Python 3.8+." >&2
    fi

    rc=0
    for apk in "$@"; do
        if [ ! -f "$apk" ]; then
            printf 'error: %s: not a file\n' "$apk" >&2
            rc=2
            continue
        fi
        recon_one "$apk"
    done
    return "$rc"
}

main "$@"
