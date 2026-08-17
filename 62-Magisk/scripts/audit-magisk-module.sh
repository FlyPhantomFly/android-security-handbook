#!/usr/bin/env bash
#
# audit-magisk-module.sh — read a Magisk module ZIP and report what it would run,
#                          when it would run, and with what privilege.
#
# Purpose
#   Installing a Magisk module gives its author a root shell that executes at
#   every boot, before any security software exists, with no code signing and no
#   sandbox. There is no app-store review, no permission prompt and no revocation
#   mechanism. The only control that exists is you reading the module before you
#   install it.
#
#   This script makes that reading systematic. It unpacks the archive to a
#   temporary directory, prints every file that will be executed as root,
#   enumerates the SELinux rules and system properties the module wants, lists
#   the files it will overlay onto the system, and greps for patterns that
#   deserve an explanation. It never installs anything and never touches a
#   device.
#
# Usage
#   ./audit-magisk-module.sh <module.zip> [<module.zip> ...]
#
#     --keep        do not delete the extracted directory (it is printed at the end)
#     --quiet       omit the explanatory notes, keep the findings
#     --no-scripts  list the scripts but do not print their contents
#     --strict      exit 1 if any HIGH-severity pattern matched (for CI use)
#
#   Example:
#     ./audit-magisk-module.sh ~/Downloads/some-module.zip | tee audit.txt
#
# Requirements
#   bash 4+, unzip, grep, find, sed, awk. Optional and used if present:
#   file, readelf (or llvm-readelf), strings, sha256sum, openssl.
#   Runs entirely on the host. No device, no root, no network.
#
# What this will NOT tell you
#   * Whether the module is safe. There is no such output, deliberately. The
#     script surfaces what runs; deciding whether that is acceptable requires
#     knowing what the module claims to do, and only you know that.
#   * What a Zygisk .so does. It reports that native code exists and will be
#     loaded into every app process, and lists its imports and strings if the
#     tooling is available. Understanding it is a reverse-engineering task —
#     see chapters 15-Native-Code, 16-JNI and 57-Ghidra.
#   * What obfuscated shell does. base64-decoded, eval'd, or externally fetched
#     code is flagged as a pattern, not decoded. A module that downloads its
#     real payload at first boot will look almost empty here, and "almost empty
#     but fetches a URL" is the finding.
#   * What the module does on a device unlike yours. Scripts routinely branch on
#     API level, architecture, SoC and the presence of other modules; a static
#     read shows every branch, not the one that will execute.
#   * Whether the archive is the one the author published. It does not verify
#     signatures, because Magisk modules are not signed. It prints a sha256 so
#     you can compare against whatever the author published out of band.

set -uo pipefail

KEEP=0
QUIET=0
NO_SCRIPTS=0
STRICT=0
HIGH_HITS=0
ZIPS=()

for a in "$@"; do
    case "$a" in
        --keep)       KEEP=1 ;;
        --quiet)      QUIET=1 ;;
        --no-scripts) NO_SCRIPTS=1 ;;
        --strict)     STRICT=1 ;;
        -h|--help)
            sed -n '2,64p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) ZIPS+=("$a") ;;
    esac
done

if [ "${#ZIPS[@]}" -eq 0 ]; then
    echo "usage: audit-magisk-module.sh <module.zip> [...] [--keep] [--quiet] [--no-scripts] [--strict]" >&2
    exit 2
fi

note() { [ "$QUIET" -eq 1 ] || printf '      %s\n' "$*"; }
hr()   { printf '%s\n' "----------------------------------------------------------------------"; }
head2(){ printf '\n== %s ==\n' "$*"; }

# Pattern table. Each entry is  SEVERITY|REGEX|WHY IT MATTERS
# The "why" column is the point: a hit is a question to answer, not a verdict.
PATTERNS=(
"HIGH|curl |Fetches something from the network at boot, as root. The payload is not in this archive, so nothing you read here describes what will actually run."
"HIGH|wget |As above."
"HIGH|base64 -d|Decodes something. Shell that decodes shell is hiding from exactly this review."
"HIGH|\\beval\\b|Executes a constructed string. Combined with any decode or fetch, this is a loader."
"HIGH|pm install|Installs an application package silently, with no user interaction."
"HIGH|pm grant|Grants a runtime permission to an app without asking the user."
"HIGH|settings put secure enabled_accessibility_services|Enables an accessibility service. That is full screen-read and input-injection over the whole device."
"HIGH|/data/data/|Touches another application's private data directory."
"HIGH|/data/user/|As above."
"HIGH|magisk --sqlite|Edits Magisk's own policy database — root grants, DenyList, settings."
"HIGH|/data/adb/magisk.db|As above, directly."
"HIGH|chattr|Sets immutable/append-only attributes. Used legitimately, and also used to make files hard to remove."
"MED|iptables|Changes the device firewall."
"MED|ip6tables|Changes the device firewall."
"MED|nc |Netcat. Check what it connects to."
"MED|toybox nc|As above."
"MED|/system/bin/sh -c|Spawns a shell with a constructed command line."
"MED|am start|Launches an activity at boot."
"MED|am broadcast|Sends a broadcast at boot."
"MED|setenforce|Changes global SELinux enforcement. A module has no business doing this."
"MED|resetprop|Rewrites system properties, including read-only ones."
"MED|magiskpolicy|Modifies the loaded SELinux policy at runtime."
"MED|mount |Creates mounts by hand rather than through the system/ overlay. Legitimate technique, and also the way to make a mount that DenyList does not know about."
"MED|umount|Removes mounts by hand."
"MED|nsenter|Enters another process's namespaces."
"MED|dd if=|Raw block or file copying. Check the target — writing to a partition is a very different act from copying a file."
"LOW|logcat|Reads the system log. Usually diagnostics; occasionally exfiltration."
"LOW|getprop|Reads properties. Almost always benign."
"LOW|sleep |Delays. In post-fs-data.sh a long sleep will stall or fail the boot."
"LOW|rm -rf|Deletes recursively. Check the path."
)

# system/ overlay destinations that deserve a second look.
SENSITIVE_OVERLAY=(
"etc/security/cacerts|Adds or replaces a system CA. Every TLS connection on the device becomes interceptable by whoever holds that key."
"apex|Touches an APEX mount point — including the Conscrypt trust store on Android 14+."
"bin/|Replaces or adds a system binary that other components will execute."
"xbin/|As above."
"lib/|Replaces a system library. Loaded into other processes."
"lib64/|As above."
"framework/|Replaces framework code. Loaded into every app."
"etc/init/|Adds an init .rc file — a service that starts at boot outside Magisk's own script hooks."
"etc/hosts|Redirects name resolution device-wide."
"etc/public.libraries|Changes which native libraries apps may load."
"priv-app/|Installs a privileged application with system-level permissions."
"app/|Installs a system application."
)

audit_one() {
    local zip="$1"
    local d
    d=$(mktemp -d 2>/dev/null) || { echo "cannot create temp dir" >&2; return 1; }

    hr
    printf ' MODULE ARCHIVE: %s\n' "$zip"
    hr

    if [ ! -f "$zip" ]; then
        echo "  ERROR: no such file"
        rmdir "$d" 2>/dev/null
        return 1
    fi

    head2 "identity of the archive itself"
    ls -la "$zip" | sed 's/^/  /'
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$zip" | sed 's/^/  /'
    elif command -v openssl >/dev/null 2>&1; then
        printf '  sha256 %s\n' "$(openssl dgst -sha256 -r "$zip" | awk '{print $1}')"
    fi
    note "Magisk modules are NOT signed. This hash is only useful if the author"
    note "published one out of band for you to compare against."

    head2 "archive layout (before extraction)"
    unzip -l "$zip" | sed 's/^/  /'
    if ! unzip -l "$zip" | awk '{print $NF}' | grep -qx 'module.prop'; then
        echo "  !! module.prop is NOT at the archive root."
        note "Magisk will reject this, OR it is not a module at all. A ZIP whose"
        note "entries are all under a directory prefix is the usual cause."
    fi
    if unzip -l "$zip" | grep -qE '\.\./'; then
        echo "  !! HIGH: archive contains '..' path components (zip-slip traversal)."
        HIGH_HITS=$((HIGH_HITS + 1))
    fi

    unzip -q -o "$zip" -d "$d" 2>/dev/null || {
        echo "  ERROR: unzip failed"
        rm -rf "$d"
        return 1
    }

    head2 "module.prop"
    if [ -f "$d/module.prop" ]; then
        sed 's/^/  /' "$d/module.prop"
        local id vc
        id=$(grep -E '^id=' "$d/module.prop" | head -1 | cut -d= -f2- | tr -d '\r')
        vc=$(grep -E '^versionCode=' "$d/module.prop" | head -1 | cut -d= -f2- | tr -d '\r')
        printf '\n'
        if [ -z "$id" ]; then
            echo "  !! no id= line. Magisk will refuse this module."
        elif ! printf '%s' "$id" | grep -qE '^[a-zA-Z][a-zA-Z0-9._-]*$'; then
            echo "  !! id '$id' does not match [a-zA-Z][a-zA-Z0-9._-]* — Magisk will refuse it."
        else
            printf '  id is well-formed: installs to /data/adb/modules/%s/\n' "$id"
        fi
        if [ -z "$vc" ]; then
            echo "  !! no versionCode= line. The updater cannot compare versions."
        elif ! printf '%s' "$vc" | grep -qE '^[0-9]+$'; then
            echo "  !! versionCode '$vc' is not an integer."
        fi
    else
        echo "  !! NO module.prop — this is not a valid Magisk module."
    fi

    head2 "code that will execute as root, and when"
    printf '  %-22s %-34s %s\n' "FILE" "WHEN IT RUNS" "PRESENT"
    printf '  %-22s %-34s %s\n' "----" "------------" "-------"
    local f when present
    for pair in \
        "customize.sh|at install time, inside the installer" \
        "post-fs-data.sh|BLOCKING, before zygote starts" \
        "service.sh|late_start, in parallel with boot" \
        "boot-completed.sh|after sys.boot_completed=1" \
        "uninstall.sh|when the module is removed" \
        "update-binary|at install time (META-INF installer)" \
        "updater-script|at install time (META-INF installer)"
    do
        f=${pair%%|*}
        when=${pair#*|}
        present="-"
        if [ -f "$d/$f" ] || [ -f "$d/META-INF/com/google/android/$f" ]; then present="YES"; fi
        printf '  %-22s %-34s %s\n' "$f" "$when" "$present"
    done
    note ""
    note "Every one of these runs as uid 0. post-fs-data.sh runs before any app,"
    note "any security software, and any logging you control. A blocking script"
    note "there can also stall the boot — see chapter 62 section 3.5."

    if [ "$NO_SCRIPTS" -eq 0 ]; then
        for f in customize.sh post-fs-data.sh service.sh boot-completed.sh uninstall.sh; do
            if [ -f "$d/$f" ]; then
                head2 "contents: $f"
                cat -v "$d/$f" | sed 's/^/  /'
            fi
        done
        for f in "$d/META-INF/com/google/android/update-binary" \
                 "$d/META-INF/com/google/android/updater-script"; do
            if [ -f "$f" ]; then
                head2 "contents: ${f#"$d"/}"
                head -c 20000 "$f" | cat -v | sed 's/^/  /'
                note "(truncated at 20 KB if longer)"
            fi
        done
    fi

    head2 "SELinux rules requested"
    if [ -f "$d/sepolicy.rule" ]; then
        sed 's/^/  /' "$d/sepolicy.rule"
        if grep -qE '^[[:space:]]*permissive' "$d/sepolicy.rule"; then
            echo "  !! HIGH: makes a domain permissive. That removes every restriction on"
            echo "     that domain, not the one the module needed."
            HIGH_HITS=$((HIGH_HITS + 1))
        fi
        if grep -qE 'allow[[:space:]]+untrusted_app' "$d/sepolicy.rule"; then
            echo "  !! HIGH: grants access to the untrusted_app domain — that is EVERY"
            echo "     ordinary application on the device, not just this module."
            HIGH_HITS=$((HIGH_HITS + 1))
        fi
    else
        echo "  (none)"
    fi

    head2 "system properties it will set"
    if [ -f "$d/system.prop" ]; then
        sed 's/^/  /' "$d/system.prop"
        note "Applied with resetprop at boot, which can rewrite ro.* properties."
        note "Spoofed boot-state properties do not affect hardware attestation."
    else
        echo "  (none)"
    fi

    head2 "files overlaid onto the system"
    if [ -d "$d/system" ]; then
        find "$d/system" -type f 2>/dev/null | sed "s|^$d||" | sed 's/^/  /'
        printf '\n  count: %s\n' "$(find "$d/system" -type f 2>/dev/null | wc -l | tr -d ' ')"
        local relpath
        for pair in "${SENSITIVE_OVERLAY[@]}"; do
            relpath=${pair%%|*}
            if find "$d/system" -path "*${relpath}*" 2>/dev/null | grep -q .; then
                printf '\n  !! sensitive overlay target: %s\n' "$relpath"
                printf '     %s\n' "${pair#*|}"
            fi
        done
    else
        echo "  (no system/ directory)"
    fi
    if [ -f "$d/skip_mount" ]; then
        echo "  NOTE: skip_mount present — the system/ overlay is deliberately NOT mounted."
    fi
    if find "$d" -name '.replace' 2>/dev/null | grep -q .; then
        head2 ".replace markers (whole-directory replacement)"
        find "$d" -name '.replace' 2>/dev/null | sed "s|^$d||" | sed 's/^/  /'
        note "A .replace file makes Magisk replace the entire target directory instead"
        note "of merging into it. Everything originally in that directory disappears."
    fi

    head2 "Zygisk native code (runs inside EVERY app process)"
    if [ -d "$d/zygisk" ]; then
        find "$d/zygisk" -name '*.so' 2>/dev/null | sed "s|^$d||" | sed 's/^/  /'
        local rd=""
        command -v readelf >/dev/null 2>&1 && rd=readelf
        [ -z "$rd" ] && command -v llvm-readelf >/dev/null 2>&1 && rd=llvm-readelf
        while IFS= read -r so; do
            [ -z "$so" ] && continue
            printf '\n  --- %s\n' "${so#"$d"/}"
            command -v file >/dev/null 2>&1 && file "$so" | sed 's/^/      /'
            if [ -n "$rd" ]; then
                printf '      imports of interest:\n'
                "$rd" --dyn-syms -W "$so" 2>/dev/null \
                  | grep ' UND ' \
                  | awk '{print $NF}' \
                  | grep -iE 'socket|connect|open|exec|fork|ptrace|dlopen|mount|system|popen|inotify' \
                  | sort -u | sed 's/^/        /'
            fi
            if command -v strings >/dev/null 2>&1; then
                printf '      strings of interest:\n'
                strings -a -n 6 "$so" 2>/dev/null \
                  | grep -iE 'https?://|/data/|/system/|magisk|zygisk|\.onion|[0-9]{1,3}(\.[0-9]{1,3}){3}' \
                  | sort -u | head -40 | sed 's/^/        /'
            fi
        done < <(find "$d/zygisk" -name '*.so' 2>/dev/null)
        echo ""
        echo "  !! HIGH by construction: Zygisk code is loaded into every application"
        echo "     process on the device, including your banking apps. Native code in a"
        echo "     module is the highest-trust thing you can install."
        HIGH_HITS=$((HIGH_HITS + 1))
    else
        echo "  (none)"
    fi

    head2 "pattern scan across every text file in the module"
    local sev rx why hits any=0
    for entry in "${PATTERNS[@]}"; do
        sev=${entry%%|*}
        rx=${entry#*|};  rx=${rx%%|*}
        why=${entry##*|}
        hits=$(grep -rnE -- "$rx" "$d" 2>/dev/null \
               --include='*.sh' --include='*.prop' --include='*.rule' \
               --include='update-binary' --include='updater-script' \
               | sed "s|^$d/||" || true)
        if [ -n "$hits" ]; then
            any=1
            printf '\n  [%s] /%s/\n' "$sev" "$rx"
            printf '%s\n' "$hits" | sed 's/^/      /'
            printf '      WHY: %s\n' "$why"
            [ "$sev" = "HIGH" ] && HIGH_HITS=$((HIGH_HITS + 1))
        fi
    done
    [ "$any" -eq 0 ] && echo "  (no patterns matched)"

    head2 "everything else in the archive"
    find "$d" -type f 2>/dev/null | sed "s|^$d/||" | sort | sed 's/^/  /'
    note ""
    note "Read this list. A file that is not module.prop, not a documented script,"
    note "not under system/ and not under zygisk/ has no defined role in the module"
    note "format — which means a script put it there on purpose."

    head2 "what you still do not know"
    echo "  1. What any native code actually does."
    echo "  2. What is at the far end of any URL, and what will be executed from it."
    echo "  3. Which branch of a device-conditional script runs on YOUR device."
    echo "  4. Whether this archive is what the author published."
    echo "  5. Whether the author's account, build machine or distribution channel"
    echo "     is compromised. Reading the code answers none of these."

    if [ "$KEEP" -eq 1 ]; then
        printf '\n  extracted to: %s (kept)\n' "$d"
    else
        rm -rf "$d"
    fi
}

for z in "${ZIPS[@]}"; do
    audit_one "$z"
done

printf '\n'
hr
printf ' HIGH-severity observations: %s\n' "$HIGH_HITS"
printf ' This is a count of things that need an explanation, not a verdict.\n'
hr

if [ "$STRICT" -eq 1 ] && [ "$HIGH_HITS" -gt 0 ]; then
    exit 1
fi
exit 0
