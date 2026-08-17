#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/02-ida-android-annotate.py

PURPOSE
    An IDAPython script that does, in one keypress, the six things every
    analyst does by hand in the first twenty minutes with an Android .so:

      1. Report what kind of library this is -- ABI, PIE, stripped, packed
         relocations, and whether JNI binding is static or dynamic.
      2. Name every statically registered JNI entry point in a form you can
         read, and demangle the Java class it belongs to.
      3. Mark the standard Android non-returning functions, so IDA stops
         disassembling past them and stops inventing code that is not there.
      4. Apply prototypes to the libc imports that carry type information
         worth propagating -- memcpy, strlen, malloc and friends.
      5. Inventory the indirect branches and indirect calls, because those are
         the places static analysis stops and you must decide whether to
         resolve them by hand, resolve them at run time, or accept the gap.
      6. Emit a Frida-ready offset map: name -> module+offset, so the static
         session hands the dynamic session something it can use immediately.

    Point (6) is the part most scripts skip and it is the one that pays. The
    whole reason to annotate a database is to produce hypotheses; a hypothesis
    you cannot test in the next five minutes usually does not get tested.

USAGE
    Interactive:
        File > Script file...  (Alt+F7), select this file.

    Headless -- one library:
        # host
        idat64 -A -S"02-ida-android-annotate.py --out /tmp/ch58/annot.json" \
               -L/tmp/ch58/ida.log /tmp/ch58/libsession.so

        (`idat64` is the text-mode IDA. `-A` means autonomous: do not ask
        questions. `-S` runs a script. `-L` writes a log. On IDA 9.0 and later
        the 32/64 split is gone and the binary is simply `idat`.)

    Headless -- a directory of libraries:
        see scripts/03-ida-batch-triage.sh

EXECUTION STATUS
    *** REVIEWED, NOT EXECUTED. ***

    IDA Pro is commercial software and it is NOT installed on the machine
    where this chapter was written -- verified, and stated plainly in the
    README. This script has therefore never been run. What was done instead:

      * every API call below was checked against the published IDAPython API
        reference at https://python.docs.hex-rays.com/ and against Hex-Rays'
        "IDAPython Porting Guide from IDA 8.x to 9.0"
      * the IDA 9.0 breaking changes are handled explicitly rather than
        assumed away -- see the COMPAT block below
      * the pure-Python logic that does not touch the IDA API (the JNI name
        demangler, the report formatting) WAS executed, against the symbol
        list that examples/build.sh produces, and its output is quoted in
        labs/lab-01-first-database.md

    Treat this as a reviewed draft that will need a real run. If you have a
    licence and it fails, the failure is a finding worth writing down; this
    repository would rather ship a labelled untested script than an unlabelled
    fabricated transcript.

TARGET API
    IDA 7.7 through 9.x, Python 3. The IDA 9.0 removals that matter here:
      * idaapi.get_inf_structure() is gone -> ida_ida.inf_get_*()
      * ida_struct and ida_enum are gone -> ida_typeinf / Local Types
    Both are shimmed below so one file works either side of the boundary.

AUTHORISED TESTING ONLY. Point this at binaries you built, at applications you
own, or at a target you have written permission to analyse.
"""

from __future__ import annotations

import json
import os
import sys

# --------------------------------------------------------------------------- #
# Imports. Everything here is part of IDA; this file does nothing outside it.
# --------------------------------------------------------------------------- #
try:
    import idaapi
    import idautils
    import idc
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_nalt
    import ida_segment
    import ida_ua
except ImportError:  # pragma: no cover - only reachable outside IDA
    sys.stderr.write(
        "This script must run inside IDA. Outside IDA it does nothing.\n"
        "See the header for the headless invocation.\n")
    raise SystemExit(2)

try:
    import ida_ida
except ImportError:
    ida_ida = None

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


# --------------------------------------------------------------------------- #
# COMPAT -- the IDA 8.x / 9.0 boundary, handled once.
# --------------------------------------------------------------------------- #
def min_ea() -> int:
    """Lowest mapped address. inf_get_min_ea() on 9.0+, get_inf_structure() before."""
    if ida_ida is not None and hasattr(ida_ida, "inf_get_min_ea"):
        return ida_ida.inf_get_min_ea()
    return idaapi.get_inf_structure().min_ea          # IDA 8.x and earlier


def max_ea() -> int:
    if ida_ida is not None and hasattr(ida_ida, "inf_get_max_ea"):
        return ida_ida.inf_get_max_ea()
    return idaapi.get_inf_structure().max_ea


def proc_name() -> str:
    if ida_ida is not None and hasattr(ida_ida, "inf_get_procname"):
        return ida_ida.inf_get_procname()
    return idaapi.get_inf_structure().procname


def is_64bit() -> bool:
    if ida_ida is not None and hasattr(ida_ida, "inf_is_64bit"):
        return ida_ida.inf_is_64bit()
    return idaapi.get_inf_structure().is_64bit()


# --------------------------------------------------------------------------- #
# 1. JNI symbol demangling.
#
# This is the only part of the file that is pure Python, and it is the part
# that was actually executed. The mangling rules come from the JNI
# specification; chapter 57 section 3.9 tabulates them and chapter 16 derives
# them. Reproduced here rather than imported because a script you paste into
# IDA cannot import from this repository.
#
#   .  in a package name  ->  _
#   _                     ->  _1
#   ;                     ->  _2
#   [                     ->  _3
#   non-ASCII U+XXXX      ->  _0XXXX
#   overload separator    ->  __ followed by the encoded argument signature
# --------------------------------------------------------------------------- #
def demangle_jni(sym: str):
    """'Java_com_example_my_1pkg_Cls_meth' -> ('com.example.my_pkg.Cls', 'meth', None).

    Returns (class, method, overload_signature) or None if `sym` is not a JNI
    export. The overload signature, when present, is returned raw -- decoding
    it belongs to chapter 16.
    """
    if not sym.startswith("Java_"):
        return None
    body = sym[len("Java_"):]

    overload = None
    if "__" in body:
        body, overload = body.split("__", 1)

    # Decode the escapes into tokens, remembering which underscores were
    # SEPARATORS (a bare _) and which were literal underscores (_1).
    parts = []
    cur = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "_":
            cur.append(ch)
            i += 1
            continue
        nxt = body[i + 1] if i + 1 < len(body) else ""
        if nxt == "1":
            cur.append("_")
            i += 2
        elif nxt == "2":
            cur.append(";")
            i += 2
        elif nxt == "3":
            cur.append("[")
            i += 2
        elif nxt == "0" and i + 6 <= len(body):
            try:
                cur.append(chr(int(body[i + 2:i + 6], 16)))
                i += 6
            except ValueError:
                cur.append("_")
                i += 2
        else:
            parts.append("".join(cur))
            cur = []
            i += 1
    parts.append("".join(cur))

    if len(parts) < 2:
        return None
    method = parts[-1]
    klass = ".".join(parts[:-1])
    return (klass, method, overload)


# --------------------------------------------------------------------------- #
# 2. Non-returning functions.
#
# If IDA does not know a function never returns, it keeps disassembling the
# bytes that follow a call to it -- and those bytes are usually the next
# function's prologue, or padding, or a jump table. The result is code that
# does not exist, attached to a function that does, and the decompiler
# faithfully renders the nonsense.
#
# IDA discovers most of these itself. The list below is the Android-specific
# set that is worth asserting, because a stripped library may reach them only
# through the PLT and the discovery pass can miss one.
# --------------------------------------------------------------------------- #
NORETURN = [
    "abort", "exit", "_exit", "_Exit",
    "__stack_chk_fail", "__assert", "__assert2",
    "longjmp", "siglongjmp",
    "__cxa_throw", "__cxa_rethrow", "_Unwind_Resume",
    "pthread_exit",
    "android_set_abort_message",     # not itself noreturn, but always precedes abort
    "__android_log_assert",
]

# --------------------------------------------------------------------------- #
# 3. Import prototypes worth applying.
#
# Every one of these gives the decompiler a fact it cannot derive: that the
# first argument is a pointer to bytes, that the third is a size, that the
# return is a pointer. One correct prototype on memcpy propagates types through
# every caller. This is the cheapest type information available and IDA's
# bundled type libraries usually supply it -- but a stripped library with no
# recognised libc may not get it, so assert it.
# --------------------------------------------------------------------------- #
IMPORT_PROTOS = {
    "memcpy":   "void *memcpy(void *dst, const void *src, size_t n);",
    "memmove":  "void *memmove(void *dst, const void *src, size_t n);",
    "memset":   "void *memset(void *s, int c, size_t n);",
    "memcmp":   "int memcmp(const void *a, const void *b, size_t n);",
    "strlen":   "size_t strlen(const char *s);",
    "strcmp":   "int strcmp(const char *a, const char *b);",
    "strncmp":  "int strncmp(const char *a, const char *b, size_t n);",
    "strcpy":   "char *strcpy(char *dst, const char *src);",
    "strncpy":  "char *strncpy(char *dst, const char *src, size_t n);",
    "malloc":   "void *malloc(size_t n);",
    "calloc":   "void *calloc(size_t n, size_t sz);",
    "realloc":  "void *realloc(void *p, size_t n);",
    "free":     "void free(void *p);",
    "open":     "int open(const char *path, int flags, ...);",
    "read":     "ssize_t read(int fd, void *buf, size_t n);",
    "write":    "ssize_t write(int fd, const void *buf, size_t n);",
    "dlopen":   "void *dlopen(const char *name, int flag);",
    "dlsym":    "void *dlsym(void *handle, const char *sym);",
    "ptrace":   "long ptrace(int req, int pid, void *addr, void *data);",
    "__system_property_get": "int __system_property_get(const char *name, char *value);",
}

# Imports whose mere presence is worth reporting. This is not a detection
# engine -- chapters 37, 38 and 39 own that, and chapter 38 measured that a
# detector agreeing with you about every sample is a broken detector. It is a
# reading order: these are the functions whose call sites you look at first.
INTERESTING_IMPORTS = {
    "ptrace":                "anti-debug, or a debugger of its own",
    "dlopen":                "loads something not in the dependency list",
    "dlsym":                 "resolves a symbol by name at run time",
    "__system_property_get": "reads a system property -- ro.debuggable, ro.build.tags",
    "fork":                  "anti-debug via a watchdog child",
    "kill":                  "a watchdog, or a self-terminate on detection",
    "inotify_init":          "watching a file, often /proc/self/maps",
    "syscall":               "may be bypassing the libc symbol you were going to hook",
    "prctl":                 "PR_SET_DUMPABLE, or thread naming",
    "getauxval":             "reading AT_SECURE or the hwcaps",
    "mprotect":              "makes memory writable -- self-modifying or a packer",
    "popen":                 "runs a shell command",
    "system":                "runs a shell command",
}


# --------------------------------------------------------------------------- #
class Annotator:
    def __init__(self):
        self.report = {
            "file": ida_nalt.get_root_filename(),
            "processor": proc_name(),
            "bits": 64 if is_64bit() else 32,
            "image_base": idaapi.get_imagebase(),
            "min_ea": min_ea(),
            "max_ea": max_ea(),
            "jni_static": [],
            "jni_onload": None,
            "noreturn_marked": [],
            "protos_applied": [],
            "interesting_imports": [],
            "indirect_branches": [],
            "indirect_calls": [],
            "functions": 0,
            "named_functions": 0,
            "notes": [],
        }

    # -- 1 ----------------------------------------------------------------- #
    def survey(self):
        funcs = list(idautils.Functions())
        self.report["functions"] = len(funcs)
        named = 0
        for ea in funcs:
            name = ida_funcs.get_func_name(ea) or ""
            if name and not name.startswith(("sub_", "nullsub_", "j_sub_")):
                named += 1
        self.report["named_functions"] = named

        segs = [ida_segment.get_segm_name(s) for s in
                (ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty()))
                if s is not None]
        self.report["segments"] = segs

        # The single most useful ratio in the first minute. A library with
        # 2,000 functions and 11 names is stripped; one with 2,000 and 1,900
        # shipped its symbols by accident and your afternoon just got shorter.
        if len(funcs):
            pct = 100.0 * named / len(funcs)
            self.report["notes"].append(
                "%d of %d functions carry a real name (%.1f%%)" % (named, len(funcs), pct))
            if pct < 5.0:
                self.report["notes"].append(
                    "STRIPPED: expect to work from strings, imports and structure")

    # -- 2 ----------------------------------------------------------------- #
    def do_jni(self):
        for ea, name in idautils.Names():
            if name == "JNI_OnLoad" or name.startswith("JNI_OnLoad_"):
                self.report["jni_onload"] = {"ea": ea, "name": name}
                # Give it a signature so the decompiler types the JavaVM*.
                idc.SetType(ea, "int JNI_OnLoad(void *vm, void *reserved);")
                continue
            parsed = demangle_jni(name)
            if parsed is None:
                continue
            klass, method, overload = parsed
            entry = {"ea": ea, "symbol": name, "class": klass,
                     "method": method, "overload": overload}
            self.report["jni_static"].append(entry)
            # A comment, not a rename: the mangled name is the ground truth and
            # renaming it away loses the ability to grep for it later.
            idc.set_func_cmt(ea, "JNI: %s.%s%s" %
                             (klass, method, ("  overload " + overload) if overload else ""),
                             True)

        if not self.report["jni_static"] and self.report["jni_onload"]:
            self.report["notes"].append(
                "JNI_OnLoad present with NO Java_* exports: binding is DYNAMIC. "
                "Recover the JNINativeMethod table -- see chapter 57 section 3.9, "
                "or hook RegisterNatives at run time.")
        elif not self.report["jni_static"] and not self.report["jni_onload"]:
            self.report["notes"].append(
                "No JNI entry points at all. Either this library is reached only "
                "through dlsym/dlopen from another library, or it is not the one "
                "the app actually loads. Check /proc/<pid>/maps before continuing.")

    # -- 3 ----------------------------------------------------------------- #
    def do_noreturn(self):
        for want in NORETURN:
            for ea, name in idautils.Names():
                base = name.lstrip(".")
                if base != want and base != "_" + want and base != want + "_0":
                    continue
                f = ida_funcs.get_func(ea)
                if f is None:
                    continue
                if f.flags & idaapi.FUNC_NORET:
                    continue
                f.flags |= idaapi.FUNC_NORET
                ida_funcs.update_func(f)
                self.report["noreturn_marked"].append(name)

        if self.report["noreturn_marked"]:
            self.report["notes"].append(
                "Marked %d function(s) non-returning. Re-run analysis "
                "(Options > General > Reanalyze) so the code after their call "
                "sites is withdrawn." % len(self.report["noreturn_marked"]))

    # -- 4 ----------------------------------------------------------------- #
    def do_protos(self):
        for ea, name in idautils.Names():
            base = name.lstrip("._").split("@")[0]
            decl = IMPORT_PROTOS.get(base)
            if decl and idc.SetType(ea, decl):
                self.report["protos_applied"].append(base)
            note = INTERESTING_IMPORTS.get(base)
            if note:
                xrefs = [x.frm for x in idautils.XrefsTo(ea)]
                self.report["interesting_imports"].append(
                    {"name": base, "ea": ea, "why": note, "callers": len(xrefs)})

    # -- 5 ----------------------------------------------------------------- #
    def do_indirect(self):
        """Every place static analysis stops.

        On AArch64 that is `br <reg>` (a computed branch -- a switch whose
        table was not recovered, or a jump-table-based dispatcher) and
        `blr <reg>` (a call through a pointer). On ARM32 add `bx`/`blx` with a
        register operand; on x86, `jmp`/`call` with a non-immediate operand.

        Reporting these honestly is the point. A tool that silently shows you
        nothing where control flow leaves is worse than one that says
        "I lost it here" -- and the count is a decent proxy for how much of
        this binary a purely static reading can actually cover.
        """
        indirect_branch = {"BR", "BRAA", "BRAAZ", "BRAB", "BRABZ", "BX", "JMP"}
        indirect_call = {"BLR", "BLRAA", "BLRAAZ", "BLRAB", "BLRABZ", "BLX", "CALL"}

        for fea in idautils.Functions():
            f = ida_funcs.get_func(fea)
            if f is None:
                continue
            for head in idautils.Heads(f.start_ea, f.end_ea):
                if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                    continue
                mnem = ida_ua.print_insn_mnem(head).upper()
                if not mnem:
                    continue
                op0 = idc.get_operand_type(head, 0)
                is_reg = (op0 == idc.o_reg) or (op0 == idc.o_phrase) or (op0 == idc.o_displ)
                rec = {"ea": head, "func": ida_funcs.get_func_name(fea),
                       "mnem": mnem, "text": idc.GetDisasm(head)}
                if mnem in indirect_branch and is_reg:
                    self.report["indirect_branches"].append(rec)
                elif mnem in indirect_call and is_reg:
                    self.report["indirect_calls"].append(rec)

        n = len(self.report["indirect_calls"])
        m = len(self.report["indirect_branches"])
        if n or m:
            self.report["notes"].append(
                "%d indirect call(s) and %d indirect branch(es). Each is a point "
                "where a static reading STOPS. Resolve them by hand, or resolve "
                "them at run time and bring the answer back." % (n, m))

    # -- 6 ----------------------------------------------------------------- #
    def frida_map(self):
        """name -> offset from the image base, for Interceptor.attach.

        The arithmetic that connects the two worlds, stated once:

            runtime_address = Module.findBaseAddress(lib) + (ida_ea - imagebase)

        Chapter 18 section 6.6 owns this and warns that a tool's default image
        base is not the file's virtual address. Do not hard-code a base --
        compute the delta and let Frida supply the base.
        """
        base = idaapi.get_imagebase()
        out = {}
        for ea in idautils.Functions():
            name = ida_funcs.get_func_name(ea) or ""
            if not name or name.startswith(("sub_", "nullsub_", "j_sub_")):
                continue
            out[name] = ea - base
        self.report["frida_offsets"] = {k: "0x%x" % v for k, v in sorted(out.items())}
        self.report["image_base_hex"] = "0x%x" % base

    # ---------------------------------------------------------------------- #
    def run(self, out_path=None):
        ida_auto.auto_wait()          # let the initial analysis finish first
        self.survey()
        self.do_jni()
        self.do_noreturn()
        self.do_protos()
        self.do_indirect()
        self.frida_map()

        text = self.format_text()
        print(text)
        if out_path:
            with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(self.report, fh, indent=2, sort_keys=True)
            print("[+] JSON written to %s" % out_path)
        return self.report

    def format_text(self) -> str:
        r = self.report
        L = []
        L.append("=" * 68)
        L.append(" %s   %s, %d-bit   image base %s"
                 % (r["file"], r["processor"], r["bits"], r.get("image_base_hex", "?")))
        L.append("=" * 68)
        L.append("")
        L.append("functions: %d, of which named: %d"
                 % (r["functions"], r["named_functions"]))
        L.append("")

        if r["jni_static"]:
            L.append("STATICALLY REGISTERED JNI ENTRY POINTS")
            for e in r["jni_static"]:
                L.append("   0x%08x  %s.%s%s"
                         % (e["ea"], e["class"], e["method"],
                            ("  [overload " + e["overload"] + "]") if e["overload"] else ""))
            L.append("")
        if r["jni_onload"]:
            L.append("JNI_OnLoad at 0x%08x" % r["jni_onload"]["ea"])
            L.append("")

        if r["noreturn_marked"]:
            L.append("MARKED NON-RETURNING: " + ", ".join(r["noreturn_marked"]))
            L.append("")
        if r["protos_applied"]:
            L.append("PROTOTYPES APPLIED: " + ", ".join(sorted(set(r["protos_applied"]))))
            L.append("")

        if r["interesting_imports"]:
            L.append("IMPORTS WORTH LOOKING AT FIRST")
            for e in sorted(r["interesting_imports"], key=lambda x: -x["callers"]):
                L.append("   %-24s %d call site(s)   %s"
                         % (e["name"], e["callers"], e["why"]))
            L.append("")

        if r["indirect_calls"] or r["indirect_branches"]:
            L.append("WHERE STATIC ANALYSIS STOPS")
            for e in r["indirect_calls"]:
                L.append("   call   0x%08x  in %-24s %s"
                         % (e["ea"], e["func"], e["text"]))
            for e in r["indirect_branches"]:
                L.append("   branch 0x%08x  in %-24s %s"
                         % (e["ea"], e["func"], e["text"]))
            L.append("")

        if r["notes"]:
            L.append("NOTES")
            for n in r["notes"]:
                L.append("   * " + n)
            L.append("")

        L.append("Frida offsets are in the JSON. Attach with:")
        L.append("   const m = Process.findModuleByName('%s');" % r["file"])
        L.append("   Interceptor.attach(m.base.add(0x<offset>), { ... });")
        return "\n".join(L)


# --------------------------------------------------------------------------- #
def main():
    out = None
    argv = idc.ARGV if hasattr(idc, "ARGV") else []
    for i, a in enumerate(argv):
        if a == "--out" and i + 1 < len(argv):
            out = argv[i + 1]
    if out is None:
        out = os.environ.get("CH58_ANNOT_OUT")

    rep = Annotator().run(out)

    # In headless mode, close the database and exit with a status the shell can
    # read. `1` means "nothing recognisably Android here", which is a useful
    # signal when you are sweeping a hundred libraries.
    if "-A" in " ".join(sys.argv) or os.environ.get("CH58_HEADLESS"):
        interesting = bool(rep["jni_static"] or rep["jni_onload"])
        idc.qexit(0 if interesting else 1)


if __name__ == "__main__":
    main()
