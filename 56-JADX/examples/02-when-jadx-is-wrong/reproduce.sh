#!/usr/bin/env bash
#
# examples/02-when-jadx-is-wrong/reproduce.sh
#
# PURPOSE
#   Reproduce, from scratch and in about twenty seconds, all three of jadx's failure modes
#   from chapter 56 sections 6.4-6.6:
#     1. REFUSAL          -- Irreducible.smali, and what --show-bad-code does to it
#     2. WARNED WRONGNESS -- the JADX WARN comments jadx prints for the same method
#     3. SILENCE          -- Accumulate.smali, decompiled wrongly with no warning at all,
#                            with the divergence proved by running both readings
#   Plus the --deobf demonstration from section 3.9.
#
# USAGE
#   ./reproduce.sh              # work in ./_out (git-ignored; nothing lands in the repo)
#   ./reproduce.sh /tmp/mywork  # work elsewhere
#
# REQUIREMENTS
#   - jadx 1.5.x. Set JADX (a launcher) or JADX_JAR (a jar, invoked via jadx.cli.JadxCLI),
#     or have `jadx` on PATH.
#
#     On a Windows jadx-gui-only install, jadx.exe answers --version but opens the GUI for
#     any real invocation. Use:
#       export JADX_JAR="C:/Program Files/jadx/lib/jadx-gui-1.5.3-all.jar"
#
#   - A JDK, for the Proof.java execution step.
#   - NOTHING ELSE. jadx bundles a Smali assembler, so the .smali inputs need no apktool,
#     no smali.jar and no Android SDK.
#
# WHAT THIS WILL NOT TELL YOU
#   - It will not tell you whether YOUR app has methods jadx gets wrong. Nothing can tell
#     you that from the Java alone -- which is the chapter's whole point. It teaches you
#     the shapes to be suspicious of.
#   - It will not isolate WHY the Accumulate case diverges. See VariantV4.smali for how far
#     the narrowing got and for the caveat that belongs with any report of it.
#   - Output will differ on jadx versions other than 1.5.3. That is expected and is itself
#     a lesson: record your tool version with every extract you quote.
#
# ARTEFACT POLICY
#   Everything is written under $OUT (default ./_out). No .class, .dex or .apk is written
#   into the repository. The Proof.class produced by javac lands in $OUT too.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-$HERE/_out}"

run_jadx() {
    if   [ -n "${JADX:-}" ];     then "$JADX" "$@"
    elif [ -n "${JADX_JAR:-}" ]; then java -cp "$JADX_JAR" jadx.cli.JadxCLI "$@"
    elif command -v jadx >/dev/null 2>&1; then jadx "$@"
    else echo "error: jadx not found. Set JADX or JADX_JAR." >&2; exit 1
    fi
}

# show <label> <dir> [class-file-name]
# Prints every .java under <dir> (or just the named one), minus the machine-specific
# "/* loaded from: */" header. Never fails, so `set -e` cannot kill the script when a
# jadx version puts a class somewhere this script did not predict.
show() {
    echo
    echo "--------------------------------------------------------------------------------"
    echo "$1"
    echo "--------------------------------------------------------------------------------"
    local dir="$2" name="${3:-*.java}" found=0 f
    while IFS= read -r f; do
        found=1
        grep -v "^/\* loaded from:" "$f" || true
    done < <(find "$dir" -type f -name "$name" 2>/dev/null | sort)
    [ "$found" -eq 1 ] || echo "(no output found under $dir -- jadx version difference?)"
    return 0
}

rm -rf "$OUT"; mkdir -p "$OUT"

echo "jadx version: $(run_jadx --version 2>/dev/null || echo unknown)"

# ============================================================ 1. REFUSAL
run_jadx -q -d "$OUT/irr-default"  "$HERE/Irreducible.smali"
run_jadx -q --show-bad-code -d "$OUT/irr-bad" "$HERE/Irreducible.smali"
run_jadx -q -m simple   -d "$OUT/irr-simple" "$HERE/Irreducible.smali"
run_jadx -q -m fallback -d "$OUT/irr-fb"     "$HERE/Irreducible.smali"

show "1a. REFUSAL -- default mode. Note the JADX WARN comments, the complete instruction
     dump, and the UnsupportedOperationException body." \
     "$OUT/irr-default" "Irr.java"

show "1b. THE SAME METHOD WITH --show-bad-code. The instruction dump is GONE and the body
     assigns an unused local and falls off the end without returning. This is why
     --show-bad-code is not 'the flag that shows you more'." \
     "$OUT/irr-bad" "Irr.java"

show "1c. -m simple. Linear statements with labels and gotos. Always produces something,
     because the pass list ends with ForceGenerateAll." \
     "$OUT/irr-simple" "Irr.java"

show "1d. -m fallback. Near-disassembly: registers, labels, catch ranges. The most
     trustworthy rendering jadx offers, because it asserts almost nothing." \
     "$OUT/irr-fb" "Irr.java"

# ============================================================ 3. SILENCE
run_jadx -q -d "$OUT/acc"    "$HERE/Accumulate.smali"
run_jadx -q -d "$OUT/v4"     "$HERE/VariantV4.smali"
run_jadx -q -m fallback -d "$OUT/v4-fb" "$HERE/VariantV4.smali"

show "3a. SILENCE -- Accumulate.smali. Clean, idiomatic, compiling Java. No JADX WARN
     anywhere in the file. And the catch branch returns a constant where the bytecode
     returns the partially-accumulated value plus 100." \
     "$OUT/acc" "Acc.java"

show "3b. VariantV4 -- the same program with javac+d8's exact register allocation.
     Also wrong. Compare 3c below with what jadx -m fallback prints for the compiler's
     own DEX: they are identical." \
     "$OUT/v4" "VariantV4.java"

show "3c. VariantV4 in fallback mode -- the instruction stream jadx actually read." \
     "$OUT/v4-fb" "VariantV4.java"

echo
echo "--------------------------------------------------------------------------------"
echo "3d. PROOF BY EXECUTION -- both readings, run on the JVM"
echo "--------------------------------------------------------------------------------"
javac -d "$OUT" "$HERE/Proof.java"
java -cp "$OUT" Proof

# ============================================================ --deobf
run_jadx -q -d "$OUT/obf-plain" "$HERE/Obfuscated.smali"
run_jadx -q --deobf --deobf-cfg-file-mode ignore -d "$OUT/obf-deobf" "$HERE/Obfuscated.smali"

show "4a. Obfuscated names, WITHOUT --deobf." "$OUT/obf-plain"
show "4b. The same class WITH --deobf. Note that nothing was recovered -- the names are
     merely unique, valid and greppable now, and the output is harder to read." \
     "$OUT/obf-deobf"

echo
echo "================================================================================"
echo "Everything above is in $OUT. Nothing was written into the repository."
echo "Chapter reference: ../../README.md sections 3.8, 3.9, 6.4, 6.5, 6.6, 9.3"
echo "When jadx fails, the destination is ../../../14-Dalvik/README.md"
echo "================================================================================"
