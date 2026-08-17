#!/usr/bin/env bash
#
# hook-surface.sh -- inventory every place a native library can be hooked, and
#                    say which hook type applies to each.
#
# WHAT IT DOES
#   Runs before you pick a hook point, not after. Given a .so (or an APK, from
#   which it extracts the arm64 libraries), it reports five things:
#
#     1. IMPORTS with a JUMP_SLOT relocation
#        -> PLT/GOT hookable. One pointer write, no code patching, reversible,
#           and scoped to THIS library only.
#
#     2. RELRO / BIND_NOW status
#        -> whether the GOT is read-only once the linker has finished. Full
#           RELRO does not prevent a PLT hook, it just means you must mprotect
#           first. This line tells you which.
#
#     3. EXPORTED FUNCTIONS
#        -> inline hookable, subject to hookability.py's verdict. The script
#           pipes them through hookability.py when it is available, so you get
#           SAFE / NEEDS RELOCATION / UNSAFE per symbol rather than a bare list.
#
#     4. JNI SURFACE
#        Java_*-prefixed exports  -> statically registered, hookable by symbol
#                                    name, and the name tells you the Java class.
#        JNI_OnLoad present       -> the library MAY use RegisterNatives, in
#                                    which case the mapping exists only in
#                                    memory and only after load. That is a
#                                    fifth hook type: rewrite the table itself.
#                                    Owned by ../../16-JNI/README.md section 3.8.
#
#     5. ANTI-TAMPER HINTS
#        Imports that a library uses to notice you: mprotect, ptrace, dl_iterate_phdr,
#        __system_property_get, pthread_create near init. Their presence is not
#        a finding; it is a reason to read further. Defeating them belongs to
#        67-BypassingProtections.
#
# HOW TO RUN
#   ./hook-surface.sh libnative.so
#   ./hook-surface.sh app.apk                  # extracts arm64-v8a libs first
#   ./hook-surface.sh libnative.so --exports   # exports section only
#   READELF=/path/to/llvm-readelf ./hook-surface.sh libnative.so
#
# REQUIREMENTS
#   - llvm-readelf (ships with the NDK) or GNU readelf. The script finds the
#     NDK copy automatically if ANDROID_NDK is set.
#   - unzip, for the APK path.
#   - python3, only for the per-symbol hookability verdicts. Everything else
#     works without it.
#   No device, no root, no Frida. This reads a file.
#
# WHAT THIS WILL *NOT* TELL YOU
#   - Which of these hook points MATTERS. A library can export two hundred
#     functions and make its licensing decision in one of them. This narrows the
#     search space; it does not do the search.
#   - Whether a symbol is actually called. hookability.py's caller count covers
#     calls from within the same file only; a caller in another library is
#     invisible to both.
#   - Anything about libraries loaded at runtime from a downloaded payload,
#     which are the ones that most want hooking. Enumerate those from the live
#     process instead.
#   - Whether the anti-tamper imports are used for anti-tamper. mprotect is
#     imported by every JIT and every library that ships its own allocator.
#     Treat the section as leads, not findings.

set -u

TARGET="${1:-}"
MODE="${2:-all}"

if [ -z "$TARGET" ]; then
    sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
fi

# ------------------------------------------------------------- find readelf
find_readelf() {
    [ -n "${READELF:-}" ] && [ -x "${READELF}" ] && { echo "$READELF"; return 0; }
    local ndk="${ANDROID_NDK:-${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}}"
    if [ -z "$ndk" ] && [ -d "$HOME/Android/Sdk/ndk" ]; then
        ndk="$(ls -d "$HOME/Android/Sdk/ndk"/* 2>/dev/null | tail -1)"
    fi
    if [ -z "$ndk" ] && [ -d "$HOME/AppData/Local/Android/Sdk/ndk" ]; then
        ndk="$(ls -d "$HOME/AppData/Local/Android/Sdk/ndk"/* 2>/dev/null | tail -1)"
    fi
    if [ -n "$ndk" ]; then
        for r in "$ndk"/toolchains/llvm/prebuilt/*/bin/llvm-readelf \
                 "$ndk"/toolchains/llvm/prebuilt/*/bin/llvm-readelf.exe; do
            [ -f "$r" ] && { echo "$r"; return 0; }
        done
    fi
    command -v llvm-readelf 2>/dev/null && return 0
    command -v readelf 2>/dev/null && return 0
    return 1
}

RE="$(find_readelf)" || {
    echo "ERROR: no llvm-readelf or readelf found. Set READELF or ANDROID_NDK." >&2
    exit 1
}

HERE="$(cd "$(dirname "$0")" && pwd)"

# ------------------------------------------------------------- APK handling
LIBS=""
case "$TARGET" in
    *.apk)
        TMP="$(mktemp -d)"
        echo "extracting arm64-v8a libraries from $TARGET into $TMP"
        unzip -o -q -j "$TARGET" 'lib/arm64-v8a/*.so' -d "$TMP" 2>/dev/null
        LIBS="$(ls "$TMP"/*.so 2>/dev/null)"
        if [ -z "$LIBS" ]; then
            echo "no lib/arm64-v8a/*.so inside the APK."
            echo "The app may ship only armeabi-v7a, may have no native code at all,"
            echo "or may deliver its libraries as a split APK or a runtime download."
            exit 1
        fi
        ;;
    *)  LIBS="$TARGET" ;;
esac

# ------------------------------------------------------------- per-library
for LIB in $LIBS; do
    echo
    echo "########################################################################"
    echo "# $(basename "$LIB")"
    echo "########################################################################"

    ARCH="$("$RE" -h "$LIB" 2>/dev/null | grep -i 'Machine:' | head -1)"
    echo "$ARCH"
    case "$ARCH" in
        *AArch64*|*aarch64*) ;;
        *) echo
           echo "NOT arm64. Everything below still lists correctly, but the inline"
           echo "hooking guidance does not apply: on 32-bit ARM the encoding is"
           echo "variable-length (Thumb) and fixed-size prologue patching is unsound."
           echo "See ../../18-ARM/README.md section 3.13." ;;
    esac

    if [ "$MODE" = "all" ] || [ "$MODE" = "--imports" ]; then
        echo
        echo "== 1. PLT/GOT HOOKABLE IMPORTS (JUMP_SLOT relocations) =="
        echo "   one pointer write each; reversible; scoped to this library only"
        # Line shape (llvm-readelf and GNU readelf agree here):
        #   <offset> <info> R_AARCH64_JUMP_SLOT <symvalue> <name>[@VER] + <addend>
        # The name can carry an @VERSION suffix (e.g. strcmp@LIBC), which is
        # stripped so the output is a plain symbol list you can grep against.
        "$RE" --relocs "$LIB" 2>/dev/null |
            grep -i 'JUMP_SLOT' |
            awk '{ for (i=1;i<=NF;i++) if ($i ~ /R_AARCH64_JUMP_SLOT|JUMP_SLOT/) { n=$(i+2); sub(/@.*/,"",n); if (n != "") print "   " n; break } }' |
            sort -u | head -80
        N="$("$RE" --relocs "$LIB" 2>/dev/null | grep -ci 'JUMP_SLOT')"
        echo "   ($N JUMP_SLOT relocations total)"

        echo
        echo "== 2. RELRO / BIND_NOW =="
        RELRO="$("$RE" -l "$LIB" 2>/dev/null | grep -c 'GNU_RELRO')"
        NOW="$("$RE" -d "$LIB" 2>/dev/null | grep -Ec 'BIND_NOW|FLAGS.*NOW')"
        if [ "$RELRO" -gt 0 ] && [ "$NOW" -gt 0 ]; then
            echo "   FULL RELRO. The GOT is made read-only after relocation."
            echo "   A PLT hook still works; you must mprotect the slot's page to"
            echo "   PROT_READ|PROT_WRITE first, then restore it. Nothing here"
            echo "   prevents the hook -- it only stops an accidental one."
        elif [ "$RELRO" -gt 0 ]; then
            echo "   PARTIAL RELRO. .got is protected, .got.plt stays writable so"
            echo "   lazy binding can work. PLT hooks need no mprotect at all."
        else
            echo "   NO RELRO. The whole GOT is writable for the process lifetime."
        fi
    fi

    if [ "$MODE" = "all" ] || [ "$MODE" = "--exports" ]; then
        echo
        echo "== 3. INLINE-HOOKABLE EXPORTS =="
        if [ -f "$HERE/hookability.py" ] && command -v python3 >/dev/null 2>&1; then
            python3 -B "$HERE/hookability.py" "$LIB" --all 2>/dev/null ||
                echo "   (hookability.py could not analyse this file)"
        else
            "$RE" --dyn-syms "$LIB" 2>/dev/null |
                awk '$4 == "FUNC" && $7 != "UND" { print "   " $8 }' | sort -u | head -60
            echo "   (install python3 and keep hookability.py alongside this script"
            echo "    to get SAFE / NEEDS RELOCATION / UNSAFE per symbol)"
        fi
    fi

    if [ "$MODE" = "all" ] || [ "$MODE" = "--jni" ]; then
        echo
        echo "== 4. JNI SURFACE =="
        JSYMS="$("$RE" --dyn-syms "$LIB" 2>/dev/null | awk '{print $NF}' | grep '^Java_' | sort -u)"
        if [ -n "$JSYMS" ]; then
            echo "   statically registered (hookable by symbol name):"
            echo "$JSYMS" | sed 's/^/     /' | head -40
            echo "   The mangled name encodes the Java class and method. Decode it"
            echo "   with ../../16-JNI/scripts/jni_mangle.py."
        else
            echo "   no Java_* exports."
        fi
        if "$RE" --dyn-syms "$LIB" 2>/dev/null | grep -q 'JNI_OnLoad'; then
            echo
            echo "   JNI_OnLoad IS PRESENT."
            echo "   The library may register its natives dynamically with"
            echo "   RegisterNatives, in which case the Java-name-to-function-pointer"
            echo "   mapping exists ONLY in memory and ONLY after JNI_OnLoad has run."
            echo "   Two consequences:"
            echo "     - static analysis cannot tell you which C function backs which"
            echo "       Java method;"
            echo "     - the method table is itself a hook point -- rewrite the"
            echo "       fnPtr field and every dispatch follows you, with no code"
            echo "       patched. See ../../16-JNI/README.md section 3.8."
        else
            echo "   no JNI_OnLoad: any JNI here is statically registered."
        fi
    fi

    if [ "$MODE" = "all" ] || [ "$MODE" = "--tamper" ]; then
        echo
        echo "== 5. ANTI-TAMPER LEADS (not findings) =="
        FOUND=""
        for s in ptrace mprotect mmap dl_iterate_phdr dladdr __system_property_get \
                 pthread_create fork kill sigaction inotify_init1 openat readlink; do
            if "$RE" --dyn-syms "$LIB" 2>/dev/null | grep -qw "$s"; then
                FOUND="$FOUND $s"
            fi
        done
        if [ -n "$FOUND" ]; then
            echo "  imported:$FOUND"
            echo
            echo "  Why each one might matter to you:"
            echo "    ptrace            self-attach to deny a debugger, or PTRACE_TRACEME"
            echo "    mprotect          could be re-protecting its own text after startup,"
            echo "                      or checksumming it -- read the call sites"
            echo "    dl_iterate_phdr   enumerating loaded modules, which is how a library"
            echo "                      finds an injected agent"
            echo "    dladdr            resolving a pointer back to a module: the standard"
            echo "                      way to notice a GOT slot that points nowhere sane"
            echo "    pthread_create    a watchdog thread that re-checks periodically"
            echo
            echo "  None of these is evidence of anti-tamper on its own. Every JIT"
            echo "  imports mprotect; every crash reporter imports sigaction. Read the"
            echo "  call sites before you conclude anything."
        else
            echo "  none of the usual suspects imported."
        fi
    fi
done

echo
echo "Next step: pick a candidate and get its verdict in detail --"
echo "  python3 -B $HERE/hookability.py <lib.so> --symbol <name> -v"
