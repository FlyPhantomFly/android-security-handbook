# RecoverRegisterNatives.py — recover a dynamically registered JNI table, statically.
#
# WHAT IT DOES
#   Finds the JNINativeMethod array that JNI_OnLoad passes to RegisterNatives,
#   decodes each { name, signature, fnPtr } entry, and RENAMES the target
#   functions to their Java names. A library that was an anonymous pile of
#   FUN_00103a10 becomes a map from Java methods to addresses.
#
#   It also applies a JNINativeMethod array data type over the table (when the
#   type is available), so the Listing pane renders it as structured data rather
#   than raw bytes.
#
# WHY THIS SCRIPT EXISTS
#   A Java `native` method binds to C in one of two ways. Static registration
#   uses a mechanically derived symbol name (Java_com_example_C_m), which
#   readelf finds instantly. Dynamic registration calls
#   RegisterNatives(env, clazz, methods, count) from JNI_OnLoad, binding
#   arbitrary functions - usually `static` in C terms, so not exported at all.
#
#   Developers choose the second precisely to break `nm`. This script un-breaks
#   it, without running the app.
#
#   See ../README.md sections 3.8 and 3.9, and ../labs/lab-02-dynamic-jni-recovery.md.
#
# STRATEGY
#   Three passes, cheapest first. Each is independent; the script reports which
#   one produced results.
#
#     PASS A  Structural scan of read-only data for pointer triples whose first
#             two members point at plausible JNI name/signature strings and
#             whose third points into an executable section. This finds the
#             table without needing to understand JNI_OnLoad at all, and it works
#             even when the decompilation of JNI_OnLoad is unreadable.
#
#     PASS B  Decompile JNI_OnLoad and look for a call through the JNIEnv table
#             at the RegisterNatives offset, reading the constant arguments.
#             Requires JNIEnv to be defined for best results.
#
#     PASS C  Report what neither pass could find, with the runtime fallback.
#
# LIMITATION - READ THIS
#   If the table is BUILT AT RUNTIME (assembled on the stack, or decrypted from
#   .rodata during JNI_OnLoad) then no static scan can find it, because it does
#   not exist in the file. That is not a failure of this script; it is a finding.
#   Recover it dynamically instead:
#       ../../53-Frida/scripts/native-tracer.js   ->   nat.jni()
#
# HOW TO RUN — GUI
#   Window -> Script Manager -> run. Renames are applied to the open program.
#
# HOW TO RUN — HEADLESS
#   $GHIDRA_HOME/support/analyzeHeadless /tmp/proj P \
#       -import libnative.so -processor AARCH64:LE:64:v8A \
#       -scriptPath "$(pwd)/scripts" \
#       -postScript RecoverRegisterNatives.py \
#       -deleteProject
#
#   Pass "dryrun" as an argument to report without renaming:
#       -postScript RecoverRegisterNatives.py dryrun
#
# LANGUAGE
#   Jython 2.7 (Ghidra's bundled Python). No f-strings, no Python 3 syntax.
#
# @category Android.JNI
# @author Android-Pentesting-Notes

import re

from ghidra.program.model.symbol import SourceType

# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #

# A valid JNI type signature. Method signatures look like "([BLjava/lang/String;)Z".
SIGNATURE_RE = re.compile(r"^\((\[*([BCDFIJSZ]|L[A-Za-z0-9_/$;]+;))*\)(\[*([BCDFIJSZV]|L[A-Za-z0-9_/$;]+;))$")

# A plausible Java method name.
NAME_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$")

MAX_TABLE_ENTRIES = 512      # sanity bound; real tables are tens of entries

args = getScriptArgs()  # noqa: F821
DRY_RUN = len(args) > 0 and args[0].lower() in ("dryrun", "dry-run", "-n")

prog = currentProgram  # noqa: F821
mem = prog.getMemory()
listing = prog.getListing()
fm = prog.getFunctionManager()
ptr_size = prog.getDefaultPointerSize()
addr_space = prog.getAddressFactory().getDefaultAddressSpace()

recovered = []


def banner(t):
    print("")
    print("=" * 78)
    print(t)
    print("=" * 78)


def line(fmt, *a):
    print(fmt % a if a else fmt)


# --------------------------------------------------------------------------- #
# low-level helpers
# --------------------------------------------------------------------------- #

def read_pointer(addr):
    """Read a pointer-sized value at addr and return it as an Address, or None."""
    try:
        raw = mem.getLong(addr) if ptr_size == 8 else (mem.getInt(addr) & 0xFFFFFFFF)
    except Exception:
        return None
    if raw == 0:
        return None
    try:
        return addr_space.getAddress(raw)
    except Exception:
        return None


def read_cstring(addr, limit=256):
    """Read a NUL-terminated ASCII string at addr, or None."""
    if addr is None:
        return None
    out = []
    a = addr
    try:
        for _ in range(limit):
            b = mem.getByte(a) & 0xFF
            if b == 0:
                break
            if b < 0x20 or b > 0x7E:
                return None          # not printable ASCII -> not a JNI string
            out.append(chr(b))
            a = a.add(1)
    except Exception:
        return None
    if len(out) == 0:
        return None
    return "".join(out)


def is_executable(addr):
    """Does addr fall inside an executable memory block?"""
    if addr is None:
        return False
    block = mem.getBlock(addr)
    return block is not None and block.isExecute()


def is_readonly_data(addr):
    """Does addr fall inside a readable, non-executable block?"""
    if addr is None:
        return False
    block = mem.getBlock(addr)
    return block is not None and block.isRead() and not block.isExecute()


def looks_like_entry(base):
    """
    Test whether the three pointers at `base` look like a JNINativeMethod:
        struct JNINativeMethod {
            const char *name;        // "decrypt"
            const char *signature;   // "(Ljava/lang/String;)Ljava/lang/String;"
            void       *fnPtr;       // -> .text
        };
    Returns (name, signature, fnAddr) or None.
    """
    p_name = read_pointer(base)
    p_sig = read_pointer(base.add(ptr_size))
    p_fn = read_pointer(base.add(ptr_size * 2))

    if p_name is None or p_sig is None or p_fn is None:
        return None
    if not is_readonly_data(p_name) or not is_readonly_data(p_sig):
        return None
    if not is_executable(p_fn):
        return None

    name = read_cstring(p_name, 128)
    sig = read_cstring(p_sig, 256)
    if name is None or sig is None:
        return None
    if not NAME_RE.match(name):
        return None
    if not SIGNATURE_RE.match(sig):
        return None

    return (name, sig, p_fn)


def java_safe(name):
    """Make a Java method name safe to use as a Ghidra symbol."""
    return re.sub(r"[^A-Za-z0-9_$]", "_", name)


# --------------------------------------------------------------------------- #
# PASS A — structural scan
# --------------------------------------------------------------------------- #

def pass_a():
    """
    Walk every readable, non-executable block looking for runs of consecutive
    JNINativeMethod-shaped entries. A run of length >= 1 whose entries are all
    valid is a candidate table; runs of length >= 2 are near-certain.
    """
    banner("PASS A - structural scan for JNINativeMethod arrays")

    tables = []
    stride = ptr_size * 3

    for block in mem.getBlocks():
        if not block.isRead() or block.isExecute() or block.isVolatile():
            continue
        # .bss has no initialised bytes to read.
        if not block.isInitialized():
            continue

        line("  scanning %-16s %s - %s (%d bytes)",
             block.getName(), block.getStart(), block.getEnd(), block.getSize())

        addr = block.getStart()
        end = block.getEnd()

        while addr.compareTo(end.subtract(stride)) < 0:
            entry = looks_like_entry(addr)
            if entry is None:
                addr = addr.add(ptr_size)
                continue

            # Found one. Walk forward while entries remain valid.
            start = addr
            entries = []
            cur = addr
            while len(entries) < MAX_TABLE_ENTRIES:
                e = looks_like_entry(cur)
                if e is None:
                    break
                entries.append(e)
                try:
                    cur = cur.add(stride)
                except Exception:
                    break

            tables.append((start, entries))
            addr = cur

    if len(tables) == 0:
        line("")
        line("  No JNINativeMethod-shaped arrays found in initialised read-only data.")
        return []

    for start, entries in tables:
        line("")
        line("  [+] candidate table at %s with %d entr%s",
             start, len(entries), "y" if len(entries) == 1 else "ies")
        for (name, sig, fn) in entries:
            target = fm.getFunctionAt(fn)
            tname = target.getName() if target is not None else "(no function defined)"
            line("      %-28s %-46s -> %s  %s", name, sig, fn, tname)
            recovered.append({
                "name": name, "sig": sig, "addr": fn,
                "table": str(start), "source": "structural",
            })

    return tables


# --------------------------------------------------------------------------- #
# PASS B — read JNI_OnLoad
# --------------------------------------------------------------------------- #

# JNINativeInterface index 215 -> byte offset 215*8 = 0x6b8 on a 64-bit target,
# 215*4 = 0x35c on 32-bit. See ../README.md section 3.8.
REGISTER_NATIVES_OFFSET = {8: 0x6b8, 4: 0x35c}


def pass_b():
    """
    Decompile JNI_OnLoad and look for the RegisterNatives call. This is a
    best-effort textual analysis: with JNIEnv defined the call appears by name,
    without it the offset appears as a constant.
    """
    banner("PASS B - reading JNI_OnLoad")

    syms = getSymbols("JNI_OnLoad", None)  # noqa: F821
    if len(syms) == 0:
        line("  JNI_OnLoad is not present.")
        line("  If PASS A also found nothing, the library may have no Java-facing")
        line("  surface at all - confirm it is even loaded by the app.")
        return

    for s in syms:
        fn = fm.getFunctionContaining(s.getAddress())
        if fn is None:
            fn = fm.getFunctionAt(s.getAddress())
        if fn is None:
            line("  JNI_OnLoad symbol at %s but no function defined there.", s.getAddress())
            line("  Try: right-click the address -> Disassemble, then Create Function.")
            continue

        line("  JNI_OnLoad @ %s  (%d bytes)",
             fn.getEntryPoint(), fn.getBody().getNumAddresses())

        try:
            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            iface = DecompInterface()
            iface.openProgram(prog)
            res = iface.decompileFunction(fn, 120, ConsoleTaskMonitor())

            if not res.decompileCompleted():
                line("  [-] decompilation failed: %s", res.getErrorMessage())
                iface.dispose()
                continue

            code = res.getDecompiledFunction().getC()
            iface.dispose()

            wanted_off = REGISTER_NATIVES_OFFSET.get(ptr_size)
            hits = []

            for ln in code.split("\n"):
                low = ln.lower()
                if "registernatives" in low:
                    hits.append(ln.strip())
                elif wanted_off is not None and hex(wanted_off) in low:
                    hits.append(ln.strip())

            if len(hits) == 0:
                line("  [-] No RegisterNatives call visible in the decompilation.")
                line("      Possible reasons:")
                line("        - JNIEnv is not defined, AND the offset was folded into")
                line("          a register-relative access the text search missed.")
                line("        - JNI_OnLoad tail-calls a helper; follow the call.")
                line("        - The table is BUILT AT RUNTIME. Recover it dynamically:")
                line("          ../../53-Frida/scripts/native-tracer.js -> nat.jni()")
            else:
                line("  [+] candidate RegisterNatives call site(s):")
                for h in hits:
                    line("        %s", h)
                line("")
                line("      Follow the THIRD argument to the JNINativeMethod array,")
                line("      then select the bytes and apply the array type. If PASS A")
                line("      already found a table, they should agree.")

        except Exception as e:
            line("  [-] decompiler unavailable: %s", str(e))

        # Whether or not we parsed the call, listing what JNI_OnLoad references
        # into read-only data is a useful lead.
        line("")
        line("  Data referenced by JNI_OnLoad (candidate table addresses):")
        shown = 0
        body = fn.getBody()
        it = listing.getInstructions(body, True)
        seen = set()
        while it.hasNext() and shown < 20:
            insn = it.next()
            for ref in insn.getReferencesFrom():
                t = ref.getToAddress()
                if not is_readonly_data(t):
                    continue
                key = str(t)
                if key in seen:
                    continue
                seen.add(key)
                probe = looks_like_entry(t)
                marker = "  <== looks like a JNINativeMethod!" if probe else ""
                line("      %s%s", t, marker)
                shown += 1


# --------------------------------------------------------------------------- #
# apply results
# --------------------------------------------------------------------------- #

def apply_names():
    """
    Rename each recovered target function to its Java method name and add a
    plate comment recording the signature. This is the step that makes the
    recovery persist in the project rather than in the console output.
    """
    banner("Applying names")

    if len(recovered) == 0:
        line("  Nothing to apply.")
        return 0

    if DRY_RUN:
        line("  DRY RUN - no changes made. Re-run without 'dryrun' to apply.")
        return 0

    applied = 0
    for r in recovered:
        fn = fm.getFunctionAt(r["addr"])
        if fn is None:
            # No function defined at the target yet. Create one - this is common
            # for a dynamically registered, non-exported function.
            try:
                fn = createFunction(r["addr"], None)  # noqa: F821
            except Exception:
                fn = None
            if fn is None:
                line("  [-] no function at %s and could not create one", r["addr"])
                continue

        new_name = "jni_" + java_safe(r["name"])
        try:
            old = fn.getName()
            fn.setName(new_name, SourceType.USER_DEFINED)
            fn.setComment("Dynamically registered JNI method\n"
                          "  Java name : %s\n"
                          "  Signature : %s\n"
                          "  Table     : %s\n"
                          "Recovered by RecoverRegisterNatives.py"
                          % (r["name"], r["sig"], r["table"]))
            line("  %s  ->  %s   (%s)", old, new_name, r["sig"])
            applied += 1
        except Exception as e:
            line("  [-] rename failed at %s: %s", r["addr"], str(e))

    return applied


# --------------------------------------------------------------------------- #
# signature decoding, for the report
# --------------------------------------------------------------------------- #

PRIMITIVES = {
    "B": "byte", "C": "char", "D": "double", "F": "float",
    "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void",
}


def decode_signature(sig):
    """Turn "([BLjava/lang/String;)Z" into "boolean f(byte[], java.lang.String)"."""
    try:
        args_part, ret_part = sig[1:].split(")", 1)
    except ValueError:
        return sig

    def decode_one(s, i):
        arrays = 0
        while i < len(s) and s[i] == "[":
            arrays += 1
            i += 1
        if i >= len(s):
            return None, i
        c = s[i]
        if c == "L":
            end = s.find(";", i)
            if end == -1:
                return None, len(s)
            t = s[i + 1:end].replace("/", ".")
            i = end + 1
        elif c in PRIMITIVES:
            t = PRIMITIVES[c]
            i += 1
        else:
            return None, i + 1
        return t + ("[]" * arrays), i

    out = []
    i = 0
    while i < len(args_part):
        t, i = decode_one(args_part, i)
        if t is None:
            break
        out.append(t)
    ret, _ = decode_one(ret_part, 0)
    return "%s f(%s)" % (ret or "?", ", ".join(out))


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

banner("RecoverRegisterNatives")
line("  program     : %s", prog.getName())
line("  language    : %s", prog.getLanguageID())
line("  pointer size: %d bytes", ptr_size)
line("  mode        : %s", "DRY RUN" if DRY_RUN else "APPLY")

pass_a()
pass_b()
applied = apply_names()

banner("Result")

if len(recovered) == 0:
    line("  No dynamically registered methods recovered statically.")
    line("")
    line("  That is a meaningful outcome, not a dead end. It means either:")
    line("    a) The library uses STATIC registration - run FindJNI.py and look")
    line("       for Java_* exports.")
    line("    b) The table is constructed at RUNTIME (built on the stack, or")
    line("       decrypted during JNI_OnLoad), which is a deliberate choice and")
    line("       worth noting in the report.")
    line("")
    line("  For (b), recover it at runtime:")
    line("    frida -U -f com.example.app \\")
    line("          -l ../../53-Frida/scripts/native-tracer.js --no-pause")
    line("    # then in the REPL:  nat.table()")
    line("  See ../README.md section 7.2.")
else:
    line("  Recovered %d JNI registration(s); renamed %d function(s).",
         len(recovered), applied)
    line("")
    line("  Java method -> native address:")
    for r in recovered:
        line("    %-24s %s", r["name"], r["addr"])
        line("        %s", decode_signature(r["sig"]))
    line("")
    line("  NEXT: set a proper signature on each. With JNIEnv defined:")
    line("    Right-click the function -> Edit Function Signature, e.g.")
    line("      jstring jni_decrypt(JNIEnv *env, jobject thiz, jstring input)")
    line("  See ../README.md section 3.8.")

print("")
print("RecoverRegisterNatives.py complete.")
