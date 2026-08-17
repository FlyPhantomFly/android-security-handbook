#!/usr/bin/env python3
"""
r2-jni-inventory.py -- enumerate the JNI attack surface of an Android native library.

PURPOSE
    A native library reachable from Java exposes its methods one of two ways, and they
    are very different search problems:

      STATIC registration   The C function is named Java_<class>_<method> and exported,
                            so it appears in .dynsym. Trivially enumerable.

      DYNAMIC registration  JNI_OnLoad calls RegisterNatives with a table of
                            {name, signature, fnPtr} records built at run time. The
                            implementing functions are usually `static` in C, so they
                            NEVER appear in any symbol table. Nothing names them.

    This script reports both, and -- importantly -- reports what it could NOT resolve,
    because the honest output of a static JNI scan is partly a list of gaps.

    See README.md sections 4.3, 6.3 and 9.3 for the full explanation, and section 7.2 for
    the Frida script that answers the dynamic case definitively in one line.

USAGE
    python3 -B r2-jni-inventory.py <library.so> [...]
    python3 -B r2-jni-inventory.py extracted/lib/arm64-v8a/*.so
    python3 -B r2-jni-inventory.py libfoo.so --json
    python3 -B r2-jni-inventory.py libfoo.so --analyse    # allow code analysis (slower)

    Options:
      --json      machine-readable output
      --analyse   run `aa` so that JNI_OnLoad can be disassembled and the
                  RegisterNatives call located. Off by default because it is the
                  expensive part -- see README.md section 3.6.
      --quiet     suppress progress on stderr

REQUIREMENTS
    radare2 on PATH and the r2pipe Python module (pip install r2pipe). Both are checked
    up front; the script exits non-zero rather than reporting an empty surface, because
    "no JNI methods found" and "the tool was not installed" must never look the same.

WHAT THIS CANNOT DO
    It cannot tell you which registered method is actually CALLED, nor what its arguments
    mean. Signatures give you types; only the Java side gives you meaning. Cross that
    boundary with JADX (chapter 56).

EXIT CODES
    0  at least one library was inspected
    1  r2pipe or radare2 missing, or bad arguments
    2  a named file does not exist or is not an ELF
"""

import argparse
import json
import os
import re
import shutil
import sys

# A JNI type signature has a very distinctive shape: it starts with '(' and its alphabet
# is restricted to the primitive codes, 'L<class>;' and '['. This regex is close to a
# perfect detector and costs nothing, because strings need no code analysis.
JNI_SIG_RE = re.compile(r"^\((\[*(?:[ZBCSIJFDV]|L[A-Za-z0-9/$_]+;))*\)"
                        r"\[*(?:[ZBCSIJFDV]|L[A-Za-z0-9/$_]+;)$")

# A plausible Java identifier, for pairing method-name strings with signatures.
JAVA_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")

# A fully-qualified class name in JNI internal form, e.g. com/example/Native
JNI_CLASS_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:/[A-Za-z_$][A-Za-z0-9_$]*)+$")

# JNIEnv function-table offsets that matter. The JNI specification fixes the order, so an
# offset IS a function name. 64-bit: offset = index * 8. See README.md section 4.2.
JNIENV_OFFSETS = {
    0x30:  "FindClass",
    0x218: "GetMethodID",
    0x548: "GetStringUTFChars",
    0x550: "ReleaseStringUTFChars",
    0x6b8: "RegisterNatives",
    0x6c0: "UnregisterNatives",
}


def die(msg, code=1):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(code)


def preflight():
    try:
        import r2pipe  # noqa: F401
    except ImportError:
        die("the r2pipe Python module is not installed.  pip install r2pipe\n"
            "  (this installs only the client; radare2 itself must also be present)")
    if shutil.which("r2") is None and shutil.which("radare2") is None:
        die("radare2 is not on PATH. r2pipe launches `r2` as a subprocess, so importing\n"
            "  the module successfully is not sufficient. Install radare2 first.")
    import r2pipe
    return r2pipe


def demangle_jni_name(sym):
    """
    Java_com_example_Native_check -> ('com.example.Native', 'check')

    The JNI mangling escapes are: '_1' for an underscore in the identifier, '_2' for ';',
    '_3' for '[', and '_0XXXX' (FOUR hex digits) for a Unicode character. The four-digit
    form is worth stating explicitly -- three is a common and wrong assumption.

    Overloaded methods append '__' plus the mangled argument signature; we split on that
    and report the left part.
    """
    if not sym.startswith("Java_"):
        return None, None
    body = sym[len("Java_"):]
    if "__" in body:
        body = body.split("__", 1)[0]

    # Walk the string honouring escapes, so that '_1' does not act as a separator.
    parts, cur, i = [], [], 0
    while i < len(body):
        c = body[i]
        if c == "_" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "1":
                cur.append("_"); i += 2; continue
            if nxt == "2":
                cur.append(";"); i += 2; continue
            if nxt == "3":
                cur.append("["); i += 2; continue
            if nxt == "0":
                # _0 followed by FOUR hex digits
                hexpart = body[i + 2:i + 6]
                if len(hexpart) == 4:
                    try:
                        cur.append(chr(int(hexpart, 16))); i += 6; continue
                    except ValueError:
                        pass
            parts.append("".join(cur)); cur = []; i += 1; continue
        cur.append(c); i += 1
    parts.append("".join(cur))

    if len(parts) < 2:
        return None, "".join(parts)
    return ".".join(parts[:-1]), parts[-1]


def inspect(r2pipe, path, do_analyse, quiet):
    if not os.path.exists(path):
        die("file does not exist: %s" % path, 2)
    try:
        with open(path, "rb") as fh:
            if fh.read(4) != b"\x7fELF":
                die("not an ELF file: %s" % path, 2)
    except OSError as exc:
        die("cannot read %s: %s" % (path, exc), 2)

    result = {
        "file": path,
        "static_methods": [],
        "has_jni_onload": False,
        "signature_strings": [],
        "class_strings": [],
        "candidate_method_names": [],
        "registernatives_calls": [],
        "notes": [],
    }

    r2 = r2pipe.open(path, flags=["-2"])
    try:
        info = (r2.cmdj("ij") or {}).get("bin", {}) or {}
        result["arch"] = info.get("arch", "")
        result["bits"] = info.get("bits", "")
        result["stripped"] = info.get("stripped", "")

        # ---- statically registered: exported Java_* symbols -------------------------
        for e in (r2.cmdj("iEj") or []):
            name = e.get("name", "") or ""
            # r2 may prefix flags; find the Java_ part wherever it starts
            idx = name.find("Java_")
            if idx < 0:
                if "JNI_OnLoad" in name:
                    result["has_jni_onload"] = True
                continue
            sym = name[idx:]
            cls, meth = demangle_jni_name(sym)
            result["static_methods"].append({
                "symbol": sym,
                "class": cls,
                "method": meth,
                "vaddr": e.get("vaddr", 0),
            })
        if not result["has_jni_onload"]:
            for e in (r2.cmdj("iEj") or []):
                if "JNI_OnLoad" in (e.get("name", "") or ""):
                    result["has_jni_onload"] = True
                    break

        # ---- dynamically registered: the string evidence ----------------------------
        for s in (r2.cmdj("izj") or []):
            text = s.get("string", "") or ""
            vaddr = s.get("vaddr", 0)
            if JNI_SIG_RE.match(text):
                result["signature_strings"].append({"string": text, "vaddr": vaddr})
            elif JNI_CLASS_RE.match(text) and "/" in text:
                result["class_strings"].append({"string": text, "vaddr": vaddr})
            elif JAVA_IDENT_RE.match(text) and 2 <= len(text) <= 64:
                result["candidate_method_names"].append({"string": text, "vaddr": vaddr})

        # ---- the RegisterNatives call itself, if analysis was permitted -------------
        if do_analyse:
            if not quiet:
                print("  running analysis (aa) ...", file=sys.stderr)
            r2.cmd("aa")
            # Disassemble JNI_OnLoad and look for the fixed JNIEnv table offsets.
            disasm = r2.cmd("pdf @ sym.JNI_OnLoad") or ""
            if not disasm.strip():
                disasm = r2.cmd("pdf @ JNI_OnLoad") or ""
            for line in disasm.splitlines():
                m = re.search(r"ldr\s+\w+,\s*\[\w+,\s*#?(\d+)\]", line)
                if not m:
                    continue
                off = int(m.group(1))
                if off in JNIENV_OFFSETS:
                    result["registernatives_calls"].append({
                        "offset": hex(off),
                        "function": JNIENV_OFFSETS[off],
                        "line": line.strip(),
                    })
        else:
            result["notes"].append(
                "code analysis skipped (--analyse not given); the RegisterNatives call "
                "site was not located")

    finally:
        try:
            r2.quit()
        except Exception:                                     # noqa: BLE001
            pass

    # ---- honest interpretation ------------------------------------------------------
    n_static = len(result["static_methods"])
    n_sigs = len(result["signature_strings"])
    if result["has_jni_onload"] and n_static == 0:
        result["notes"].append(
            "exports JNI_OnLoad and no Java_* symbols: registration is almost certainly "
            "DYNAMIC, so the implementing functions have no names anywhere in this file")
    if n_sigs and n_static == 0:
        result["notes"].append(
            "%d JNI signature string(s) present with 0 static exports -- these are the "
            "dynamically registered methods; the adjacent short identifier strings are "
            "their names" % n_sigs)
    if n_sigs > n_static:
        result["notes"].append(
            "there are more signature strings (%d) than static exports (%d): at least "
            "%d method(s) are registered at runtime"
            % (n_sigs, n_static, n_sigs - n_static))
    result["notes"].append(
        "static analysis cannot say which of these are actually CALLED. Confirm with the "
        "RegisterNatives hook in README.md section 7.2, spawning rather than attaching.")
    return result


def print_human(r):
    print("=" * 78)
    print("FILE      : %s" % r["file"])
    print("ARCH      : %s %s   stripped=%s"
          % (r.get("arch", "?"), r.get("bits", "?"), r.get("stripped", "?")))
    print("JNI_OnLoad: %s" % ("present" if r["has_jni_onload"] else "absent"))
    print()

    print("-- Statically registered (%d) --" % len(r["static_methods"]))
    if r["static_methods"]:
        for m in r["static_methods"]:
            print("   0x%08x  %s.%s"
                  % (m.get("vaddr", 0) or 0, m.get("class") or "?", m.get("method") or "?"))
            print("               symbol: %s" % m["symbol"])
    else:
        print("   (none)")
    print()

    print("-- Dynamic registration evidence --")
    print("   JNI signature strings   : %d" % len(r["signature_strings"]))
    for s in r["signature_strings"][:20]:
        print("       0x%08x  %s" % (s["vaddr"], s["string"]))
    print("   Class-name strings      : %d" % len(r["class_strings"]))
    for s in r["class_strings"][:10]:
        print("       0x%08x  %s" % (s["vaddr"], s["string"]))
    print("   Candidate method names  : %d (short identifiers; noisy)"
          % len(r["candidate_method_names"]))
    for s in r["candidate_method_names"][:15]:
        print("       0x%08x  %s" % (s["vaddr"], s["string"]))
    print()

    if r["registernatives_calls"]:
        print("-- JNIEnv table calls located in JNI_OnLoad --")
        for c in r["registernatives_calls"]:
            print("   %-6s %-22s %s" % (c["offset"], c["function"], c["line"]))
        print()

    print("-- Notes --")
    for n in r["notes"]:
        print("   * %s" % n)
    print()


def main():
    ap = argparse.ArgumentParser(
        description="Enumerate the JNI surface of Android native libraries.")
    ap.add_argument("files", nargs="+", help="shared libraries to inspect")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--analyse", action="store_true",
                    help="run `aa` so the RegisterNatives call can be located (slower)")
    ap.add_argument("--quiet", action="store_true", help="no progress on stderr")
    args = ap.parse_args()

    r2pipe = preflight()

    results = []
    for path in args.files:
        if not args.quiet:
            print("inspecting %s" % path, file=sys.stderr)
        results.append(inspect(r2pipe, path, args.analyse, args.quiet))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_human(r)
    return 0


if __name__ == "__main__":
    sys.exit(main())
