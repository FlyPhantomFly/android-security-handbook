# DecompileMatching.py — decompile every function matching a pattern to a text file.
#
# WHAT IT DOES
#   Decompiles each function whose name matches a substring or regular
#   expression and writes the resulting C to one file, annotated with the
#   function's address, size, and calling/called relationships.
#
#   The output is plain text, which is the point: it can be grepped, diffed
#   between two versions of a library, fed to semgrep, or read on a train.
#
# WHY THIS IS USEFUL AT SCALE
#   Reading a hundred libraries in the GUI is not a plan. Decompiling every
#   Java_* function across a corpus into text files and searching THOSE is:
#
#     grep -l "strcpy" out/*.c                      # unbounded copies
#     grep -l "SSL_CTX_set_verify" out/*.c          # TLS configuration
#     grep -rn "0x[0-9a-f]\{8\}" out/ | head        # embedded constants
#     diff old/libfoo.c new/libfoo.c                # what changed this release
#
#   The last one is the highest-value query in a security programme: not
#   "what does this library do" but "what did it start doing".
#
#   See ../README.md sections 8.5 and 9.5.
#
# HOW TO RUN — GUI
#   Window -> Script Manager -> run. It will prompt for the pattern and path.
#
# HOW TO RUN — HEADLESS
#   $GHIDRA_HOME/support/analyzeHeadless /tmp/proj P \
#       -import libnative.so -processor AARCH64:LE:64:v8A \
#       -scriptPath "$(pwd)/scripts" \
#       -postScript DecompileMatching.py Java_ /tmp/out/libnative.c \
#       -deleteProject
#
#   Arguments:  <pattern> <output-path> [regex]
#     pattern      substring, or a regular expression if the third arg is "regex"
#     output-path  file to write; the directory must exist
#     regex        optional literal word "regex" to treat pattern as a regex
#
#   Examples:
#     -postScript DecompileMatching.py Java_ /tmp/jni.c
#     -postScript DecompileMatching.py JNI_OnLoad /tmp/onload.c
#     -postScript DecompileMatching.py "^(FUN_|jni_)" /tmp/all.c regex
#     -postScript DecompileMatching.py "" /tmp/everything.c    # every function
#
# LANGUAGE
#   Jython 2.7 (Ghidra's bundled Python). No f-strings, no Python 3 syntax.
#
# @category Android.JNI
# @author Android-Pentesting-Notes

import os
import re
import time

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor

# --------------------------------------------------------------------------- #
# arguments
# --------------------------------------------------------------------------- #

DECOMPILE_TIMEOUT = 120      # seconds per function; large obfuscated functions need it
MAX_FUNCTIONS = 5000         # sanity bound so a mistake does not run for an hour

args = getScriptArgs()  # noqa: F821

if len(args) >= 2:
    pattern = args[0]
    outpath = args[1]
    use_regex = len(args) > 2 and args[2].lower() == "regex"
else:
    # Interactive fallback for GUI use.
    try:
        pattern = askString("DecompileMatching",  # noqa: F821
                            "Function name pattern (substring, blank = all):")
    except Exception:
        pattern = "Java_"
    try:
        outfile = askFile("Output file", "Save")  # noqa: F821
        outpath = outfile.getAbsolutePath()
    except Exception:
        outpath = "/tmp/decompiled.c"
    use_regex = False

prog = currentProgram  # noqa: F821
fm = prog.getFunctionManager()

try:
    rx = re.compile(pattern) if use_regex else None
except re.error as e:
    print("Invalid regex %r: %s" % (pattern, e))
    rx = None
    use_regex = False


def matches(name):
    if pattern == "":
        return True
    if use_regex and rx is not None:
        return rx.search(name) is not None
    return pattern in name


# --------------------------------------------------------------------------- #
# decompiler setup
# --------------------------------------------------------------------------- #

iface = DecompInterface()

# Simplification style "decompile" is the default full pipeline. Other useful
# values are "normalize" (less aggressive, closer to the P-Code) and
# "firstpass". If output looks over-simplified and you suspect the decompiler
# has folded away something you need, try "normalize" and compare.
opts = DecompileOptions()
iface.setOptions(opts)
iface.openProgram(prog)

monitor = ConsoleTaskMonitor()

# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

outdir = os.path.dirname(outpath)
if outdir and not os.path.isdir(outdir):
    try:
        os.makedirs(outdir)
    except Exception as e:
        print("Could not create %s: %s" % (outdir, e))

out = open(outpath, "w")

try:
    sha = prog.getExecutableSHA256()
except Exception:
    sha = "?"

out.write("/*\n")
out.write(" * Decompiled by DecompileMatching.py\n")
out.write(" *\n")
out.write(" *   program    : %s\n" % prog.getName())
out.write(" *   sha256     : %s\n" % sha)
out.write(" *   language   : %s\n" % prog.getLanguageID())
out.write(" *   image base : %s\n" % prog.getImageBase())
out.write(" *   pattern    : %r%s\n" % (pattern, " (regex)" if use_regex else ""))
out.write(" *   generated  : %s\n" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
out.write(" *\n")
out.write(" * THIS IS NOT SOURCE CODE. It is a reconstruction: variable names are\n")
out.write(" * invented, types are inferred, and calling conventions are assumed.\n")
out.write(" * Where this disagrees with the disassembly, the disassembly is right.\n")
out.write(" * See ../README.md section 10, 'what a decompiler cannot tell you'.\n")
out.write(" */\n\n")

# --------------------------------------------------------------------------- #
# main loop
# --------------------------------------------------------------------------- #

decompiled = 0
failed = 0
skipped = 0
started = time.time()

f = getFirstFunction()  # noqa: F821
while f is not None and decompiled + failed < MAX_FUNCTIONS:
    name = f.getName()

    if not matches(name):
        f = getFunctionAfter(f)  # noqa: F821
        continue

    # Thunks are one-line jumps; decompiling them wastes time and clutters the
    # output. Record them as a comment instead.
    if f.isThunk():
        thunked = f.getThunkedFunction(True)
        out.write("/* THUNK  %s @ %s  ->  %s */\n\n"
                  % (name, f.getEntryPoint(),
                     thunked.getName() if thunked is not None else "?"))
        skipped += 1
        f = getFunctionAfter(f)  # noqa: F821
        continue

    res = iface.decompileFunction(f, DECOMPILE_TIMEOUT, monitor)

    out.write("/* ==================================================================\n")
    out.write(" * %s\n" % name)
    out.write(" *   entry   : %s\n" % f.getEntryPoint())
    out.write(" *   size    : %d bytes\n" % f.getBody().getNumAddresses())
    out.write(" *   external: %s\n" % ("yes" if f.isExternal() else "no"))

    # Callers and callees give you the function's position in the graph, which
    # is often more informative than its body.
    try:
        callers = sorted(set([c.getName() for c in f.getCallingFunctions(monitor)]))
        callees = sorted(set([c.getName() for c in f.getCalledFunctions(monitor)]))
        if callers:
            out.write(" *   called by: %s\n" % ", ".join(callers[:12]))
            if len(callers) > 12:
                out.write(" *              ... %d more\n" % (len(callers) - 12))
        else:
            out.write(" *   called by: (nothing in this binary - entry point,\n")
            out.write(" *              exported symbol, or reached indirectly)\n")
        if callees:
            out.write(" *   calls    : %s\n" % ", ".join(callees[:12]))
            if len(callees) > 12:
                out.write(" *              ... %d more\n" % (len(callees) - 12))
    except Exception:
        pass

    out.write(" * ================================================================== */\n")

    if res.decompileCompleted():
        out.write(res.getDecompiledFunction().getC())
        out.write("\n\n")
        decompiled += 1
        print("  [+] %-60s %s" % (name, f.getEntryPoint()))
    else:
        msg = res.getErrorMessage()
        out.write("/* DECOMPILATION FAILED: %s\n" % msg)
        out.write(" *\n")
        out.write(" * A failure here is usually one of:\n")
        out.write(" *   - the function is enormous (obfuscated / flattened);\n")
        out.write(" *     raise DECOMPILE_TIMEOUT and retry\n")
        out.write(" *   - Ghidra disassembled data as code; check the Listing\n")
        out.write(" *   - the function has no proper body; try Create Function\n")
        out.write(" */\n\n")
        failed += 1
        print("  [-] %-60s FAILED: %s" % (name, msg))

    f = getFunctionAfter(f)  # noqa: F821

elapsed = time.time() - started

out.write("/*\n")
out.write(" * Summary: %d decompiled, %d failed, %d thunks skipped, %.1fs\n"
          % (decompiled, failed, skipped, elapsed))
out.write(" */\n")
out.close()
iface.dispose()

# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #

print("")
print("=" * 78)
print("DecompileMatching complete")
print("=" * 78)
print("  pattern     : %r%s" % (pattern, " (regex)" if use_regex else ""))
print("  decompiled  : %d" % decompiled)
print("  failed      : %d" % failed)
print("  thunks      : %d" % skipped)
print("  elapsed     : %.1fs" % elapsed)
print("  output      : %s" % outpath)

if decompiled == 0:
    print("")
    print("  Nothing matched. Check the pattern. To list what IS here:")
    print("    -postScript FindJNI.py")
    print("  If you expected Java_* functions and there are none, registration")
    print("  is dynamic - see RecoverRegisterNatives.py.")
else:
    print("")
    print("  Useful follow-ups on the output file:")
    print("    grep -n 'strcpy\\|strcat\\|sprintf\\|memcpy' %s" % outpath)
    print("    grep -n 'SSL_\\|X509\\|verify' %s" % outpath)
    print("    grep -n '/system/\\|/proc/\\|ptrace' %s" % outpath)
    print("    diff previous-release.c %s     # the query that matters" % outpath)
